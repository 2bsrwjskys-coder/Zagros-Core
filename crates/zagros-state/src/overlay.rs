use crate::State;
use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::Arc;
use std::thread::ThreadId;
use zagros_primitives::{Address, Result, ZagrosError};
use zagros_types::AccountState;

/// 🛡️ Salt okunur EVM simülasyonu için tam izole geçici katman: paylaşılan
/// `StateDbManager`da checkpoint/revert yapılsaydı blok üreticisinin eşzamanlı
/// commit'i ezilirdi. Tüm yazmalar overlay'e, okumalar önce overlay sonra `inner`;
/// bitince overlay atılır. Journal: adres → checkpoint öncesi overlay girdisi.
type Journal = HashMap<Address, Option<Option<AccountState>>>;

pub struct SimulationOverlay {
    /// Simülasyonun okuduğu gerçek (paylaşılan) durum, YALNIZCA okuma için.
    inner: Arc<dyn State>,

    /// Overlay'e özel yazmalar: `Some` değer, `None` tombstone (inner'a düşmez).
    /// AMM rezervleri ve reward akümülatörü de LIQUIDITY_POOL_ADDRESS hesabında, buradan türer.
    accounts: DashMap<Address, Option<AccountState>>,

    /// G3: thread başına checkpoint journal yığını (`StateDbManager` ilkesi);
    /// her kayıt ilk yazılan adresin önceki overlay girdisi. İç içe checkpoint desteklenir.
    journals: DashMap<ThreadId, Vec<Journal>>,
}

impl SimulationOverlay {
    pub fn new(inner: Arc<dyn State>) -> Self {
        Self {
            inner,
            accounts: DashMap::new(),
            journals: DashMap::new(),
        }
    }

    /// G3: overlay'in inner'dan farklılaşan tüm hesapları (tombstone'lar
    /// `None`) — `State::state_root_with_overrides` girdisi.
    pub fn overrides(&self) -> Vec<(Address, Option<AccountState>)> {
        let mut out: Vec<(Address, Option<AccountState>)> = self
            .accounts
            .iter()
            .map(|e| (e.key().clone(), e.value().clone()))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    fn journal_previous(&self, canonical: &Address) {
        let tid = std::thread::current().id();
        if let Some(mut stack) = self.journals.get_mut(&tid) {
            if let Some(top) = stack.last_mut() {
                if !top.contains_key(canonical) {
                    let prev = self.accounts.get(canonical).map(|e| e.value().clone());
                    top.insert(canonical.clone(), prev);
                }
            }
        }
    }

    /// StateDbManager ile AYNI kanonik biçim, overlay ve inner'ın aynı adresi
    /// aynı anahtarla ele almasını sağlar.
    fn canonicalize(address: &Address) -> Address {
        let addr = address.trim();
        if (addr.starts_with("0x") || addr.starts_with("0X")) && addr.len() == 42 {
            return format!("0x{}", addr[2..].to_lowercase());
        }
        address.clone()
    }
}

impl State for SimulationOverlay {
    fn get_account(&self, address: &Address) -> Result<Option<AccountState>> {
        let canonical = Self::canonicalize(address);
        if let Some(entry) = self.accounts.get(&canonical) {
            return Ok(entry.value().clone());
        }
        self.inner.get_account(&canonical)
    }

    fn set_account(&self, address: &Address, state: AccountState) -> Result<()> {
        let canonical = Self::canonicalize(address);
        self.journal_previous(&canonical);
        self.accounts.insert(canonical, Some(state));
        Ok(())
    }

    fn get_balance(&self, address: &Address) -> Result<u128> {
        Ok(self.get_account(address)?.map(|a| a.balance).unwrap_or(0))
    }

    fn add_balance(&self, address: &Address, amount: u128) -> Result<()> {
        let mut account = self.get_account(address)?.unwrap_or_default();
        account
            .add_balance(amount)
            .map_err(|e| ZagrosError::DatabaseError(format!("AccountState error: {}", e)))?;
        self.set_account(address, account)
    }

    fn sub_balance(&self, address: &Address, amount: u128) -> Result<()> {
        let mut account = self
            .get_account(address)?
            .ok_or(ZagrosError::AccountNotFound)?;
        account
            .sub_balance(amount)
            .map_err(|e| ZagrosError::DatabaseError(format!("AccountState error: {}", e)))?;
        self.set_account(address, account)
    }

    fn add_zerenya_balance(&self, address: &Address, amount: u128) -> Result<()> {
        let mut account = self.get_account(address)?.unwrap_or_default();
        account.zerenya_balance = account
            .zerenya_balance
            .checked_add(amount)
            .ok_or_else(|| ZagrosError::Other("ZERENYA Bakiye taşması".into()))?;
        self.set_account(address, account)
    }

    fn sub_zerenya_balance(&self, address: &Address, amount: u128) -> Result<()> {
        let mut account = self
            .get_account(address)?
            .ok_or(ZagrosError::AccountNotFound)?;
        if account.zerenya_balance < amount {
            return Err(ZagrosError::InsufficientBalance);
        }
        account.zerenya_balance -= amount;
        self.set_account(address, account)
    }

    fn get_nonce(&self, address: &Address) -> Result<u64> {
        Ok(self.get_account(address)?.map(|a| a.nonce).unwrap_or(0))
    }

    fn increment_nonce(&self, address: &Address) -> Result<()> {
        let mut account = self
            .get_account(address)?
            .ok_or(ZagrosError::AccountNotFound)?;
        account.nonce = account
            .nonce
            .checked_add(1)
            .ok_or_else(|| ZagrosError::Other("Nonce taşması".into()))?;
        self.set_account(address, account)
    }

    fn get_validator_candidates(&self) -> Result<Vec<(Address, u128)>> {
        // Simülasyon read-only'dir; validator seçimi simüle edilmez, inner'a düş.
        self.inner.get_validator_candidates()
    }

    fn total_known_addresses(&self) -> Result<usize> {
        self.inner.total_known_addresses()
    }

    // Rezerv/reward override'ı YOK: ikisi de LIQUIDITY_POOL_ADDRESS hesabında,
    // varsayılan metotlar overlay `accounts` haritası üzerinden çalışır, inner'a dokunmaz.

    // G3: journal'lı gerçek checkpoint'ler; başarısız işlemin yarım yazmaları simüle
    // kökü bozmasın. Kimlik = yığın derinliği; yalnız en üstteki kabul edilir (fail-closed).
    fn checkpoint(&self) -> Result<usize> {
        let tid = std::thread::current().id();
        let mut stack = self.journals.entry(tid).or_default();
        stack.push(HashMap::new());
        Ok(stack.len())
    }

    fn commit_checkpoint(&self, checkpoint_id: usize) -> Result<()> {
        let tid = std::thread::current().id();
        let mut stack = self
            .journals
            .get_mut(&tid)
            .ok_or_else(|| ZagrosError::Other("overlay: acik checkpoint yok".into()))?;
        if stack.len() != checkpoint_id {
            return Err(ZagrosError::Other(format!(
                "overlay: checkpoint {} en ustte degil (derinlik {})",
                checkpoint_id,
                stack.len()
            )));
        }
        let top = stack.pop().unwrap_or_default();
        if let Some(parent) = stack.last_mut() {
            for (addr, prev) in top {
                parent.entry(addr).or_insert(prev);
            }
        }
        Ok(())
    }

    fn revert_checkpoint(&self, checkpoint_id: usize) -> Result<()> {
        let tid = std::thread::current().id();
        let mut stack = self
            .journals
            .get_mut(&tid)
            .ok_or_else(|| ZagrosError::Other("overlay: acik checkpoint yok".into()))?;
        if stack.len() != checkpoint_id {
            return Err(ZagrosError::Other(format!(
                "overlay: checkpoint {} en ustte degil (derinlik {})",
                checkpoint_id,
                stack.len()
            )));
        }
        let top = stack.pop().unwrap_or_default();
        for (addr, prev) in top {
            match prev {
                Some(entry) => {
                    self.accounts.insert(addr, entry);
                }
                None => {
                    self.accounts.remove(&addr);
                }
            }
        }
        Ok(())
    }

    /// G3: inner'ın kökü + overlay override'ları → simüle edilen bloğun
    /// gerçek `state_root`'u (INV-P2). Inner desteklemiyorsa `Err`
    /// (fail-closed; inner kökünü döndürmek yanıltıcı olurdu).
    fn state_root(&self) -> Result<[u8; 32]> {
        self.inner.state_root_with_overrides(&self.overrides())
    }

    // flush(), record_block_receipts(), prune_historical_data() trait
    // varsayılanları (no-op) burada doğru davranıştır, overlay ASLA kalıcı
    // olmamalı, o yüzden bilinçli olarak override edilmiyorlar.
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manager::StateDbManager;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use zagros_storage::{Storage, StorageEngine};

    #[derive(Default)]
    struct MemoryStorage {
        values: Mutex<HashMap<Vec<u8>, Vec<u8>>>,
    }

    impl Storage for MemoryStorage {
        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
            Ok(self.values.lock().unwrap().get(key).cloned())
        }
        fn put(&self, key: &[u8], value: &[u8]) -> Result<()> {
            self.values
                .lock()
                .unwrap()
                .insert(key.to_vec(), value.to_vec());
            Ok(())
        }
        fn delete(&self, key: &[u8]) -> Result<()> {
            self.values.lock().unwrap().remove(key);
            Ok(())
        }
        fn contains(&self, key: &[u8]) -> Result<bool> {
            Ok(self.values.lock().unwrap().contains_key(key))
        }
        fn list_keys(&self) -> Result<Vec<Vec<u8>>> {
            Ok(self.values.lock().unwrap().keys().cloned().collect())
        }
    }

    impl StorageEngine for MemoryStorage {
        fn write_batch(&self, kvs: &[(Vec<u8>, Option<Vec<u8>>)]) -> Result<()> {
            let mut values = self.values.lock().unwrap();
            for (key, value) in kvs {
                match value {
                    Some(value) => {
                        values.insert(key.clone(), value.clone());
                    }
                    None => {
                        values.remove(key);
                    }
                }
            }
            Ok(())
        }
    }

    fn addr() -> String {
        "0x1111111111111111111111111111111111111111".to_string()
    }

    #[test]
    fn overlay_writes_never_touch_the_inner_state() {
        let storage = Arc::new(MemoryStorage::default());
        let inner: Arc<dyn State> = Arc::new(StateDbManager::new(storage));
        inner
            .set_account(&addr(), AccountState::new(1_000))
            .unwrap();

        let overlay = SimulationOverlay::new(inner.clone());
        // Overlay içinde bakiyeyi değiştir + rezervleri set et.
        overlay
            .set_account(&addr(), AccountState::new(9_999))
            .unwrap();
        overlay.set_pool_reserves(42, 43).unwrap();

        // Overlay yeni değeri görür...
        assert_eq!(overlay.get_balance(&addr()).unwrap(), 9_999);
        assert_eq!(overlay.get_pool_reserves().unwrap(), (42, 43));

        // ...ama INNER (paylaşılan) durum HİÇ değişmemeli.
        assert_eq!(inner.get_balance(&addr()).unwrap(), 1_000);
        assert_eq!(inner.get_pool_reserves().unwrap(), (0, 0));
    }

    #[test]
    fn overlay_checkpoint_revert_restores_previous_entries_and_commit_keeps_them() {
        let storage = Arc::new(MemoryStorage::default());
        let inner: Arc<dyn State> = Arc::new(StateDbManager::new(storage));
        inner
            .set_account(&addr(), AccountState::new(1_000))
            .unwrap();
        let overlay = SimulationOverlay::new(inner.clone());

        // revert: overlay'de hic yokken yazilan adres tamamen silinir (inner'a duser)
        let cp = overlay.checkpoint().unwrap();
        overlay.set_account(&addr(), AccountState::new(5)).unwrap();
        overlay.revert_checkpoint(cp).unwrap();
        assert_eq!(overlay.get_balance(&addr()).unwrap(), 1_000);
        assert!(overlay.overrides().is_empty());

        // commit: kalir
        let cp = overlay.checkpoint().unwrap();
        overlay.set_account(&addr(), AccountState::new(7)).unwrap();
        overlay.commit_checkpoint(cp).unwrap();
        assert_eq!(overlay.get_balance(&addr()).unwrap(), 7);

        // ic ice: ic commit, dis revert → dis checkpoint oncesine (7) doner
        let outer = overlay.checkpoint().unwrap();
        let inner_cp = overlay.checkpoint().unwrap();
        overlay.set_account(&addr(), AccountState::new(9)).unwrap();
        overlay.commit_checkpoint(inner_cp).unwrap();
        assert_eq!(overlay.get_balance(&addr()).unwrap(), 9);
        overlay.revert_checkpoint(outer).unwrap();
        assert_eq!(overlay.get_balance(&addr()).unwrap(), 7);

        // yanlis id fail-closed
        let cp = overlay.checkpoint().unwrap();
        assert!(overlay.commit_checkpoint(cp + 1).is_err());
        overlay.commit_checkpoint(cp).unwrap();
        assert_eq!(
            inner.get_balance(&addr()).unwrap(),
            1_000,
            "inner hic degismez"
        );
    }

    #[test]
    fn overlay_state_root_equals_root_of_inner_with_same_writes_applied() {
        let storage = Arc::new(MemoryStorage::default());
        let inner: Arc<dyn State> = Arc::new(StateDbManager::new(storage));
        inner
            .set_account(&addr(), AccountState::new(1_000))
            .unwrap();
        let other = "0x2222222222222222222222222222222222222222".to_string();
        inner.set_account(&other, AccountState::new(3)).unwrap();
        let root_before = inner.state_root().unwrap();

        let overlay = SimulationOverlay::new(inner.clone());
        overlay
            .set_account(&addr(), AccountState::new(2_000))
            .unwrap();
        overlay
            .set_account(&"__SENTINEL__".to_string(), AccountState::new(1))
            .unwrap();
        let simulated = overlay.state_root().unwrap();
        assert_ne!(simulated, root_before);
        assert_eq!(
            inner.state_root().unwrap(),
            root_before,
            "inner koku degismedi"
        );

        // Ayni yazmayi inner'a gercekten uygula → ayni kok (INV-P2)
        inner
            .set_account(&addr(), AccountState::new(2_000))
            .unwrap();
        assert_eq!(inner.state_root().unwrap(), simulated);
    }

    #[test]
    fn overlay_reads_fall_through_to_inner_when_untouched() {
        let storage = Arc::new(MemoryStorage::default());
        let inner: Arc<dyn State> = Arc::new(StateDbManager::new(storage));
        inner.set_account(&addr(), AccountState::new(777)).unwrap();
        inner.set_pool_reserves(5, 6).unwrap();

        let overlay = SimulationOverlay::new(inner);
        assert_eq!(overlay.get_balance(&addr()).unwrap(), 777);
        assert_eq!(overlay.get_pool_reserves().unwrap(), (5, 6));
    }
}
