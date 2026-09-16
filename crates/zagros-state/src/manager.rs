use crate::trie::MerkleTrie;
use crate::State;
use dashmap::{DashMap, DashSet};
use sha3::{Digest, Keccak256};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use zagros_primitives::{Address, Hash, Result, ZagrosError};
use zagros_storage::StorageEngine;
use zagros_types::{AccountState, Transaction};

thread_local! {
    /// Bu thread'de aktif checkpoint. Paylaşımlı atomik DEĞİL: checkpoint →
    /// yürüt → commit/revert ömrü tek thread'de senkron koşar (Rayon closure'ı
    /// tek worker'da biter), thread-local hem doğru hem `State` API'sine
    /// checkpoint id taşımaktan az müdahaleci. İşlem thread'ler arası askıya
    /// alınırsa güvenli olmaz; `checkpoint()`'teki debug_assert bu yüzden kalmalı.
    static ACTIVE_CHECKPOINT: Cell<usize> = const { Cell::new(0) };
}

/// `cache` girdisinin içeriği: "hesap var" ya da "BİLEREK silindi, diske de
/// yansıtılmalı" (`revert_checkpoint` `None` kolu: başka thread'in `flush()`ı
/// hesabı çoktan diske yazmış olabilir).
#[derive(Clone)]
enum CacheSlot {
    // `Box`: `AccountState` ~288 bayt, `Deleted` (0 bayt) ile aynı enum'da
    // olduğu için kutulanmazsa HER `CacheSlot` (Deleted dahil) bu boyuta
    // pad'lenir (clippy::large_enum_variant).
    Present(Box<AccountState>),
    Deleted,
}

/// `cache`'teki TEK bir girdi: değer + "henüz flush edilmedi mi" bayrağı,
/// bkz. `cache` alanının doc yorumu (neden AYRI bir `dirty` haritası değil
/// de TEK bir DashMap girdisi olarak birlikte tutuluyorlar).
#[derive(Clone)]
struct CacheEntry {
    slot: CacheSlot,
    dirty: bool,
}

/// `checkpoint()`/`flush()` karşılıklı dışlaması: `open_checkpoints` çoklu
/// olabilir, `flush_active` tekil bayrak.
#[derive(Default)]
struct CheckpointGate {
    open_checkpoints: usize,
    flush_active: bool,
}

/// StateDbManager: Ağın muhasebe beyni ve Zaman Makinesi.
/// Hangi veritabanının (RocksDB, InMemory vs.) kullanıldığını BİLMEZ.
/// Sadece "Storage" arayüzü ile konuşur.
pub struct StateDbManager {
    /// RAM önbelleği. 🚨 Dokunulan HER anahtarı tutar (Receipt_/tx_body_/block_
    /// dahil), işlem sayısıyla büyür; `max_cache_entries` aşılınca
    /// `maybe_evict_cache` çalışır, dirty girdi ASLA tahliye edilmez.
    /// Atomiklik: değer + dirty TEK `CacheEntry`, tek `DashMap` yazımı; flush ve
    /// eviction shard kilidi altında `get_mut`/`remove_if` ile bölünmez çalışır.
    /// İki ayrı map olsaydı aradaki pencere sessiz veri kaybı verirdi (regresyon
    /// testi: `concurrent_flush_calls_never_silently_drop_a_racing_set_account`).
    cache: Arc<DashMap<Address, CacheEntry>>,

    /// 🛡️ İŞTE O SİHİRLİ DUVAR: Herhangi bir StorageEngine implementasyonu!
    storage: Arc<dyn StorageEngine>,

    /// Görülen tüm 0x adresleri; `state_root()`/`get_validator_candidates()`
    /// disk taraması yapmaz, indeks başlangıçta bir kez doldurulup `set_account`
    /// ile büyür. `revert_checkpoint` silmesi indeksten çıkarmaz (zararsız, küçük şişme).
    address_index: Arc<DashSet<Address>>,

    /// ⏱️ ZAMAN MAKİNESİ GÜNLÜĞÜ (Journal)
    /// Hangi checkpoint ID'sinde, hangi adresin "eski" durumu neydi?
    /// Eğer işlem patlarsa, bu eski durumları tekrar cache ve storage'a geri yükleyeceğiz.
    journal: Arc<DashMap<usize, DashMap<Address, Option<AccountState>>>>,

    /// Bir sonraki checkpoint ID'sini üretir (sadece global tekillik gerekir,
    /// bu yüzden paylaşımlı bir atomic olarak kalabilir, asıl sorun "hangi
    /// checkpoint şu an aktif" sorusuydu, bkz. ACTIVE_CHECKPOINT).
    next_checkpoint_id: AtomicUsize,

    /// Artımlı Merkle Patricia Trie; kök yalnız DEĞİŞEN hesapların yaprakları
    /// güncellenerek hesaplanır. `state_root` tek thread'li noktada çağrılır, Mutex yeter.
    trie: Mutex<MerkleTrie>,

    /// Son `state_root`'tan bu yana yaprağı güncellenmesi gereken 0x hesap
    /// adresleri (lock-free birikim). `state_root` bunu boşaltıp trie'ye yansıtır.
    trie_dirty: Arc<DashSet<Address>>,

    /// 🚨 KRİTİK (Checkpoint/Flush): salt `flush_lock` başka thread'in açık
    /// checkpoint'ini yarıda yakalayıp diske yazmayı engellemez (thread-local
    /// `ACTIVE_CHECKPOINT` görünmez); çok adımlı işlemin ara durumu diske iner,
    /// çökmede yarım kalır (ör. restart sonrası ÇİFT MINT). Bu yüzden flush ile
    /// checkpoint ömürleri karşılıklı dışlayıcı (`CheckpointGate` + `Condvar`):
    /// flush tüm açık checkpoint'leri bekler, sürerken yeni checkpoint açılmaz.
    /// Birden fazla checkpoint aynı anda açık olabilir (Scheduler paralel yolu).
    checkpoint_gate: Mutex<CheckpointGate>,
    checkpoint_gate_cv: Condvar,

    /// 🚨 `cache` üst sınırı (`maybe_evict_cache`); sınırsız cache dokunulan her
    /// anahtarı sonsuza dek RAM'de tutar.
    max_cache_entries: usize,
}

/// Varsayılan `cache` üst sınırı: ~150 bayt × 2M ≈ 300 MB, modern sunucu için
/// makul taban; `StorageConfig` üzerinden ayarlanır.
pub const DEFAULT_MAX_CACHE_ENTRIES: usize = 2_000_000;

impl StateDbManager {
    /// Adres indeksi için TEK SEFERLİK tam disk taraması yapılır; sonrası
    /// `list_keys()` çağırmaz. Tarama başarısızlığı ciddi depolama sorunudur,
    /// yarım indeksle devam etmek yerine paniklenir.
    pub fn new(storage: Arc<dyn StorageEngine>) -> Self {
        let address_index = Arc::new(DashSet::new());
        // Merkle trie'yi de diskteki mevcut 0x hesaplarından TEK SEFERLİK
        // seed'liyoruz (address_index ile aynı O(n) tarama). Böylece diskten
        // yeniden açıldığında kök, aynı hesap kümesi için AYNI kalır (kanonik).
        let mut trie = MerkleTrie::new();
        let existing_keys = storage
            .list_keys()
            .expect("StateDbManager başlatılırken mevcut anahtarlar taranamadı");
        for key in existing_keys {
            if let Ok(key_str) = String::from_utf8(key) {
                if key_str.starts_with("0x") {
                    let canonical = Self::canonicalize_address(&key_str);
                    // 🛡️ address_index ve trie ATOMİK: okunamayan 0x satırı indekste
                    // olup trie'de olmazsa restart sonrası kök SAPAR. FAIL-CLOSED:
                    // bozulmada yarım indeksle devam etmek yerine paniklenir.
                    let bytes = storage
                        .get(canonical.as_bytes())
                        .expect("0x hesap satırı okunamadı (DB bozulması?)")
                        .expect("0x anahtarı listelendi ama değeri yok (DB tutarsızlığı?)");
                    let account = AccountState::deserialize_with_migration(&bytes)
                        .expect("0x hesap satırı deserialize edilemedi (DB bozulması?)");
                    let leaf_value = Self::account_leaf_value(&account)
                        .expect("hesap yaprağı serileştirilemedi (başlangıç seed)");
                    trie.insert(Self::account_leaf_key(&canonical), leaf_value);
                    address_index.insert(canonical);
                }
            }
        }

        Self {
            cache: Arc::new(DashMap::new()),
            storage,
            address_index,
            journal: Arc::new(DashMap::new()),
            next_checkpoint_id: AtomicUsize::new(1),
            trie: Mutex::new(trie),
            trie_dirty: Arc::new(DashSet::new()),
            checkpoint_gate: Mutex::new(CheckpointGate::default()),
            checkpoint_gate_cv: Condvar::new(),
            max_cache_entries: DEFAULT_MAX_CACHE_ENTRIES,
        }
    }

    /// `cache`'in üst sınırını operatör-yapılandırılmış bir değere ayarlar
    /// (bkz. `DEFAULT_MAX_CACHE_ENTRIES` doc yorumu). `Executor::with_*`
    /// inşacı desenleriyle AYNI stil.
    pub fn with_max_cache_entries(mut self, max_cache_entries: usize) -> Self {
        self.max_cache_entries = max_cache_entries.max(1);
        self
    }

    /// Sınır aşılınca dirty olmayan girdileri kaldırıp %80'e indirir (LRU değil);
    /// gerçek kaldırma `remove_if` ile dirty kontrolünü atomik yeniden yapar.
    fn maybe_evict_cache(&self) {
        if self.cache.len() <= self.max_cache_entries {
            return;
        }
        let target = self.max_cache_entries * 4 / 5;
        let to_remove = self.cache.len().saturating_sub(target);
        if to_remove > 0 {
            let candidates: Vec<Address> = self
                .cache
                .iter()
                .filter(|entry| !entry.value().dirty)
                .map(|entry| entry.key().clone())
                .take(to_remove)
                .collect();
            for address in candidates {
                self.cache.remove_if(&address, |_key, entry| !entry.dirty);
            }
        }
    }

    /// Test-only: address_index'in boyutunu gözlemek için ([424] budama testi).
    #[cfg(test)]
    pub(crate) fn address_index_len(&self) -> usize {
        self.address_index.len()
    }

    /// `trie_dirty`'deki (son kökten beri değişen) 0x hesapların yapraklarını
    /// trie'ye işler. `state_root` ve `state_root_with_overrides` ortak yolu.
    fn sync_trie_dirty(&self, trie: &mut MerkleTrie) -> Result<()> {
        let dirty: Vec<Address> = self
            .trie_dirty
            .iter()
            .map(|entry| entry.key().clone())
            .collect();
        for address in dirty {
            self.trie_dirty.remove(&address);
            let leaf_key = Self::account_leaf_key(&address);
            match self.get_account(&address)? {
                Some(account) => trie.insert(leaf_key, Self::account_leaf_value(&account)?),
                None => trie.remove(&leaf_key),
            }
        }
        Ok(())
    }

    /// Trie yaprağı anahtarı: hesap adresinin keccak256'sı (256-bit).
    fn account_leaf_key(canonical_address: &str) -> Hash {
        let mut hasher = Keccak256::new();
        hasher.update(canonical_address.as_bytes());
        hasher.finalize().into()
    }

    /// Trie yaprağı: serileşmiş hesabın keccak256'sı. 🛡️ FAIL-CLOSED: hata
    /// yutulsaydı iki bozuk hesap aynı yaprağa çözülür, düğüm YANLIŞ kök taahhüt ederdi.
    fn account_leaf_value(account: &AccountState) -> Result<Hash> {
        let bytes = bincode::serialize(account)
            .map_err(|e| ZagrosError::DatabaseError(format!("Account serialize (leaf): {}", e)))?;
        let mut hasher = Keccak256::new();
        hasher.update(&bytes);
        Ok(hasher.finalize().into())
    }

    /// Eğer aktif bir checkpoint varsa, değişikliği yapmadan ÖNCE eski durumu günlüğe kaydet!
    fn record_old_state(&self, address: &Address) -> Result<()> {
        let current_cp = ACTIVE_CHECKPOINT.with(Cell::get);
        if current_cp > 0 {
            if let Some(cp_journal) = self.journal.get(&current_cp) {
                let canonical = Self::canonicalize_address(address);
                if !cp_journal.contains_key(&canonical) {
                    let old_state = match self.cache.get(&canonical) {
                        Some(entry) => match &entry.value().slot {
                            CacheSlot::Present(account) => Some((**account).clone()),
                            CacheSlot::Deleted => None,
                        },
                        None => match self.storage.get(canonical.as_bytes())? {
                            Some(bytes) => AccountState::deserialize_with_migration(&bytes).ok(),
                            None => None,
                        },
                    };
                    cp_journal.insert(canonical, old_state);
                }
            }
        }
        Ok(())
    }

    /// Normalize addresses so we store/read a single canonical form.
    /// Use 0x... form for all addresses.
    fn canonicalize_address(address: &Address) -> Address {
        let addr = address.trim();
        if (addr.starts_with("0x") || addr.starts_with("0X")) && addr.len() == 42 {
            // 🚨 Perf: giriş zaten kanonik formdaysa `to_lowercase` + `format!`
            // tahsisi atlanır (her state erişiminde çalışan yol); sonuç genel
            // yolla bayt birebir aynı olduğunda devreye girer.
            if addr.len() == address.len()
                && addr.as_bytes()[1] == b'x'
                && addr[2..].bytes().all(|b| !b.is_ascii_uppercase())
            {
                return address.clone();
            }
            return format!("0x{}", addr[2..].to_lowercase());
        }
        address.clone()
    }

    // K2 budama bookkeeping anahtarları (hiçbiri `0x` önekli DEĞİL, address_index
    // ve state_root dışında kalırlar).
    fn block_receipts_key(block_number: u64) -> Address {
        format!("__RCPT_BLOCK_{}__", block_number)
    }

    fn prune_cursor_key() -> Address {
        "__RCPT_PRUNE_CURSOR__".to_string()
    }

    /// K2: Bir tarihsel/bookkeeping anahtarını hem cache'ten hem diskten kaldırır.
    /// Güvenlik ağı: `0x` önekli chain-state hesaplarına ASLA dokunmaz (onlar
    /// state_root'a girer; budama yalnızca tarihsel execution kayıtları içindir).
    fn hard_delete_key(&self, key: &str) -> Result<()> {
        debug_assert!(
            !key.starts_with("0x"),
            "hard_delete_key chain-state (0x) hesabına dokunmamalı"
        );
        if key.starts_with("0x") {
            return Ok(()); // fail-safe: asla chain state silme
        }
        self.cache.remove(key);
        self.storage.delete(key.as_bytes())
    }

    /// `checkpoint_gate`'i kilitler; önceki sahip panic attıysa `into_inner` ile
    /// veriyi kurtarır, `flush()`/`checkpoint()` sonsuza dek kilitli kalmasın.
    fn lock_checkpoint_gate(&self) -> std::sync::MutexGuard<'_, CheckpointGate> {
        self.checkpoint_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Açık checkpoint sayacını düşürür, sıfırsa bekleyen `flush()`ları uyandırır.
    /// Commit ve revert'in ikisinde de çağrılır; yoksa gelecek flush'lar sonsuza dek bekler.
    fn close_checkpoint_in_gate(&self) {
        let mut gate = self.lock_checkpoint_gate();
        gate.open_checkpoints = gate.open_checkpoints.saturating_sub(1);
        if gate.open_checkpoints == 0 {
            drop(gate);
            self.checkpoint_gate_cv.notify_all();
        }
    }

    /// `flush()`'ın asıl gövdesi, `checkpoint_gate`'in `flush_active`
    /// kilidi ZATEN alınmış durumda çağrılır, bu yüzden burada YENİ bir
    /// checkpoint açılma ihtimali yoktur.
    fn flush_with_gate_claimed(&self) -> Result<()> {
        // Aday adresler yalnızca bir İPUCU, gerçek "dirty mi" kontrolü
        // aşağıda, her adres için `get_mut` ile ATOMİK olarak tekrar yapılır.
        let candidates: Vec<Address> = self
            .cache
            .iter()
            .filter(|entry| entry.value().dirty)
            .map(|entry| entry.key().clone())
            .collect();
        if candidates.is_empty() {
            return Ok(());
        }

        let mut batch = Vec::with_capacity(candidates.len());
        let mut flushed_addresses = Vec::with_capacity(candidates.len());
        for address in &candidates {
            // ATOMİK: aynı shard kilidi altında oku + `dirty` temizle, araya thread giremez.
            let Some(mut entry) = self.cache.get_mut(address) else {
                continue;
            };
            if !entry.dirty {
                continue; // aday toplama ANINDAN bu yana başka bir flush() (veya bu flush'ın kendisi, tekrar eden bir adres için) zaten temizlemiş
            }
            let value = match &entry.slot {
                CacheSlot::Present(account) => {
                    Some(bincode::serialize(account).map_err(|e| {
                        ZagrosError::DatabaseError(format!("Serialize hatası: {}", e))
                    })?)
                }
                CacheSlot::Deleted => None,
            };
            entry.dirty = false;
            drop(entry);
            batch.push((address.clone().into_bytes(), value));
            flushed_addresses.push(address.clone());
        }

        if batch.is_empty() {
            return Ok(());
        }

        if let Err(error) = self.storage.write_batch(&batch) {
            // Yazma başarısız oldu, bu adresleri dirty'ye GERİ koy (değeri
            // DEĞİL, yalnızca bayrağı, `slot` o andan beri değişmiş
            // olabilir, ona dokunmuyoruz).
            for address in &flushed_addresses {
                if let Some(mut entry) = self.cache.get_mut(address) {
                    entry.dirty = true;
                }
            }
            return Err(error);
        }
        Ok(())
    }
}

// 📜 Muhasebe Anayasasının (State Trait) Uygulanması
impl State for StateDbManager {
    fn get_account(&self, address: &Address) -> Result<Option<AccountState>> {
        let canonical = Self::canonicalize_address(address);
        if let Some(entry) = self.cache.get(&canonical) {
            return Ok(match &entry.value().slot {
                CacheSlot::Present(account) => Some((**account).clone()),
                CacheSlot::Deleted => None,
            });
        }

        match self.storage.get(canonical.as_bytes())? {
            Some(bytes) => {
                let account = AccountState::deserialize_with_migration(&bytes).map_err(|e| {
                    ZagrosError::DatabaseError(format!("Deserialize hatası: {}", e))
                })?;
                // Diskten TAZE okunan bir değer henüz dirty DEĞİL, disktekiyle
                // zaten aynı.
                self.cache.insert(
                    canonical.clone(),
                    CacheEntry {
                        slot: CacheSlot::Present(Box::new(account.clone())),
                        dirty: false,
                    },
                );
                self.maybe_evict_cache();
                Ok(Some(account))
            }
            None => Ok(None),
        }
    }

    fn set_account(&self, address: &Address, state: AccountState) -> Result<()> {
        let canonical = Self::canonicalize_address(address);
        self.record_old_state(&canonical)?; // 🛡️ DEĞİŞMEDEN ÖNCE KAYDET!
                                            // 🚨 Değer VE dirty TEK atomik `cache.insert` ile yazılır (bkz. `cache`
                                            // alanı: iki ayrı yazım arasındaki her pencere veri kaybı riski).
        self.cache.insert(
            canonical.clone(),
            CacheEntry {
                slot: CacheSlot::Present(Box::new(state)),
                dirty: true,
            },
        );
        if canonical.starts_with("0x") {
            self.address_index.insert(canonical.clone());
            // Merkle trie'nin bu 0x hesabın yaprağını bir sonraki state_root'ta
            // güncellemesi için işaretle (yalnızca DEĞİŞEN hesaplar; O(log n)).
            self.trie_dirty.insert(canonical);
        }
        self.maybe_evict_cache();
        Ok(())
    }

    // 🏛️ get/set_pool_reserves override'ı YOK: rezervler LIQUIDITY_POOL_ADDRESS
    // hesabının .balance/.zerenya_balance'ında; varsayılan metotlarla cache/
    // dirty/trie yolundan geçer, blok sonu flush'ta atomik ve köke dahil iner.

    fn get_balance(&self, address: &Address) -> Result<u128> {
        let account = self.get_account(address)?.unwrap_or_default();
        Ok(account.balance)
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
        let account = self.get_account(address)?.unwrap_or_default();
        Ok(account.nonce)
    }

    fn increment_nonce(&self, address: &Address) -> Result<()> {
        let mut account = self
            .get_account(address)?
            .ok_or(ZagrosError::AccountNotFound)?;
        // 🛡️ Fail-closed nonce artışı: `saturating_add` u64::MAX'ta replay'e izin
        // verirdi; `checked_add` taşmada hata verir.
        account.nonce = account
            .nonce
            .checked_add(1)
            .ok_or_else(|| ZagrosError::Other("Nonce taşması".into()))?;
        self.set_account(address, account)
    }

    fn get_validator_candidates(&self) -> Result<Vec<(Address, u128)>> {
        let mut candidates = BTreeMap::new();

        // address_index görülen tüm adresleri verir; cache-first `get_account` en taze değerdir.
        for entry in self.address_index.iter() {
            let address = entry.key().clone();
            if !Transaction::validate_address(&address) {
                continue;
            }
            let Some(account) = self.get_account(&address)? else {
                continue;
            };
            if !account.is_contract && account.staked_balance > 0 {
                candidates.insert(address, account.staked_balance);
            }
        }

        Ok(candidates.into_iter().collect())
    }

    fn total_known_addresses(&self) -> Result<usize> {
        Ok(self.address_index.len())
    }

    fn repair_stale_evm_default_bytecode_corruption(&self) -> Result<usize> {
        const CORRUPTION_SIGNATURE: [u8; 1] = [0x00];

        // 🚨 Önce SADECE oku: `address_index.iter()` shard kilidi açıkken
        // `set_account` aynı shard'a yazmaya çalışır, RwLock yeniden girişli
        // değil, DEADLOCK. Adresler Vec'e toplanır, ayrı geçişte yazılır.
        let mut to_repair: Vec<Address> = Vec::new();
        for entry in self.address_index.iter() {
            let address = entry.key().clone();
            let Some(account) = self.get_account(&address)? else {
                continue;
            };
            if account.is_contract && account.contract_code == CORRUPTION_SIGNATURE {
                to_repair.push(address);
            }
        }

        let mut repaired = 0usize;
        for address in to_repair {
            let Some(mut account) = self.get_account(&address)? else {
                continue;
            };
            if account.is_contract && account.contract_code == CORRUPTION_SIGNATURE {
                account.is_contract = false;
                account.contract_code = vec![];
                self.set_account(&address, account)?;
                repaired += 1;
            }
        }
        Ok(repaired)
    }

    // 🏛️ get/set_accumulated_reward_per_share override'ı YOK: akümülatör
    // LIQUIDITY_POOL_ADDRESS depolama slot'unda, varsayılan metotlarla hesap
    // yolundan geçer, state_root'a girer, atomik flush olur.

    fn checkpoint(&self) -> Result<usize> {
        debug_assert_eq!(
            ACTIVE_CHECKPOINT.with(Cell::get),
            0,
            "checkpoint() called while this thread already has an active checkpoint - \
             nested checkpoints are not supported and would silently corrupt rollback"
        );

        // 🚨 Flush aktif/beklemedeyken YENİ checkpoint açılamaz: aksi halde flush'ın
        // anlık görüntüsü bu commit'in bir kısmını içerip bir kısmını içermeyebilir.
        // Kural: checkpoint ömürleri ile flush ömürleri ASLA çakışmaz.
        let mut gate = self.lock_checkpoint_gate();
        while gate.flush_active {
            gate = self
                .checkpoint_gate_cv
                .wait(gate)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        gate.open_checkpoints += 1;
        drop(gate);

        let id = self.next_checkpoint_id.fetch_add(1, Ordering::SeqCst);
        self.journal.insert(id, DashMap::new());
        ACTIVE_CHECKPOINT.with(|cp| cp.set(id));
        Ok(id)
    }

    fn commit_checkpoint(&self, checkpoint_id: usize) -> Result<()> {
        self.journal.remove(&checkpoint_id);
        ACTIVE_CHECKPOINT.with(|cp| cp.set(0));
        self.close_checkpoint_in_gate();
        Ok(())
    }

    fn revert_checkpoint(&self, checkpoint_id: usize) -> Result<()> {
        // 🛡️ Revert YALNIZ bellekte çalışır (disk yok): fallible disk hatasıyla
        // yarım revert ya da takılı ACTIVE_CHECKPOINT olamaz, `?` yok. Rezerv ve
        // reward da hesap journal'ından geri sarılır.
        if let Some((_, cp_journal)) = self.journal.remove(&checkpoint_id) {
            for entry in cp_journal.into_iter() {
                let address = entry.0;
                let old_state = entry.1;

                match old_state {
                    Some(state) => {
                        self.cache.insert(
                            address.clone(),
                            CacheEntry {
                                slot: CacheSlot::Present(Box::new(state)),
                                dirty: true,
                            },
                        );
                    }
                    None => {
                        // 🚨 `cache.remove` DEĞİL, `Deleted` + `dirty:true` tombstone:
                        // hesap önceki bir commit'te diske yazılmış olabilir, tombstone
                        // o eski kaydı sonraki flush'ta gerçekten siler.
                        self.cache.insert(
                            address.clone(),
                            CacheEntry {
                                slot: CacheSlot::Deleted,
                                dirty: true,
                            },
                        );
                        // 🛡️ Checkpoint içinde oluşturulup geri sarılan hesap indeksten
                        // de çıkar; yoksa "oluştur→revert" trafiği indeksi sınırsız şişirir.
                        if address.starts_with("0x") {
                            self.address_index.remove(&address);
                        }
                    }
                }

                // 🛡️ Geri sarılan 0x hesabı trie_dirty'ye yeniden işaretlenir: checkpoint
                // açıkken çağrılan `state_root()` iptal edilen değeri bakmış olabilir.
                if address.starts_with("0x") {
                    self.trie_dirty.insert(address);
                }
            }
        }
        ACTIVE_CHECKPOINT.with(|cp| cp.set(0));
        self.close_checkpoint_in_gate();
        Ok(())
    }

    fn state_root(&self) -> Result<[u8; 32]> {
        let mut trie = self
            .trie
            .lock()
            .map_err(|_| ZagrosError::DatabaseError("state trie mutex poisoned".to_string()))?;
        self.sync_trie_dirty(&mut trie)?;
        Ok(trie.root_hash())
    }

    /// G3: gerçek trie'yi güncel köke getirir, sonra bir KOPYASI üzerinde
    /// override'ları uygulayıp kökü döner. Gerçek trie/cache/disk değişmez;
    /// yalnızca `0x` hesapları köke girer (`set_account` ile aynı filtre).
    fn state_root_with_overrides(
        &self,
        overrides: &[(Address, Option<AccountState>)],
    ) -> Result<[u8; 32]> {
        let mut trie = self
            .trie
            .lock()
            .map_err(|_| ZagrosError::DatabaseError("state trie mutex poisoned".to_string()))?;
        self.sync_trie_dirty(&mut trie)?;
        let mut scratch = trie.clone();
        drop(trie);
        for (address, account) in overrides {
            let canonical = Self::canonicalize_address(address);
            if !canonical.starts_with("0x") {
                continue;
            }
            let leaf_key = Self::account_leaf_key(&canonical);
            match account {
                Some(acc) => scratch.insert(leaf_key, Self::account_leaf_value(acc)?),
                None => scratch.remove(&leaf_key),
            }
        }
        Ok(scratch.root_hash())
    }

    /// Tüm dirty hesapları tek atomik batch ile yazar. 🚨 Gövdeden önce
    /// `checkpoint_gate` ile tüm açık checkpoint'leri bekler ve `flush_active`
    /// koyar: dirty adaylar hep ya tam commit edilmiş ya hiç başlamamış işleme
    /// aittir; eşzamanlı flush'lar da serileşir. Değer + dirty tek `CacheEntry`,
    /// `get_mut` ile aynı shard kilidi altında okunup `dirty=false` yapılır
    /// (ayrı map yarış penceresi taşırdı). `write_batch` başarısızsa temizlenen
    /// dirty bayrakları GERİ konur.
    fn flush(&self) -> Result<()> {
        {
            let mut gate = self.lock_checkpoint_gate();
            while gate.open_checkpoints > 0 || gate.flush_active {
                gate = self
                    .checkpoint_gate_cv
                    .wait(gate)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
            }
            gate.flush_active = true;
        }
        let result = self.flush_with_gate_claimed();
        {
            let mut gate = self.lock_checkpoint_gate();
            gate.flush_active = false;
        }
        // Gate'i bıraktıktan SONRA uyandır, hem bekleyen checkpoint()'ler
        // hem de bekleyen başka bir flush() bu değişikliği görebilsin.
        self.checkpoint_gate_cv.notify_all();
        result
    }

    // Bloğun tx_id'lerini manifest'e yazar (budama için); `0x` önekli değil, state_root'a girmez.
    fn record_block_receipts(&self, block_number: u64, tx_ids: &[Hash]) -> Result<()> {
        if tx_ids.is_empty() {
            return Ok(());
        }
        let key = Self::block_receipts_key(block_number);
        let acc = AccountState {
            contract_code: bincode::serialize(tx_ids).map_err(|e| {
                ZagrosError::DatabaseError(format!("Serialize hatası (block receipts): {}", e))
            })?,
            ..Default::default()
        };
        self.set_account(&key, acc)
    }

    // K2: `prune_before_block`'tan eski blokların dekontlarını + manifestlerini
    // batch_limit'e kadar siler. Sadece bookkeeping anahtarlarına dokunur;
    // `state_root` (0x hesaplar) DEĞİŞMEZ.
    fn prune_historical_data(&self, prune_before_block: u64, batch_limit: usize) -> Result<usize> {
        if batch_limit == 0 {
            return Ok(0);
        }
        let cursor_key = Self::prune_cursor_key();
        // 🚨 İmleç 1'den başlar: ham `block_0` `get_account`ta hata verip imleci 0'da
        // çakılı bırakırdı; genesis zaten budanamaz.
        let mut cursor = self
            .get_account(&cursor_key)?
            .map(|a| a.balance as u64)
            .unwrap_or(0)
            .max(1);
        let mut deleted = 0usize;

        while cursor < prune_before_block && deleted < batch_limit {
            let manifest_key = Self::block_receipts_key(cursor);
            let mut tx_ids: Vec<Hash> = match self.get_account(&manifest_key)? {
                Some(acc) if !acc.contract_code.is_empty() => {
                    bincode::deserialize(&acc.contract_code).map_err(|e| {
                        ZagrosError::DatabaseError(format!("Bozuk blok dekont manifesti: {}", e))
                    })?
                }
                _ => Vec::new(),
            };

            // Bloğun dekontlarını + tx gövdelerini batch limitine kadar sil;
            // `deleted` işlem sayar (iki anahtar = tek artış).
            while deleted < batch_limit {
                let Some(tx_id) = tx_ids.pop() else { break };
                self.hard_delete_key(&crate::receipt_key(&tx_id))?;
                self.hard_delete_key(&crate::tx_body_key(&tx_id))?;
                deleted += 1;
            }

            if tx_ids.is_empty() {
                // Blok tamamen budandı: manifest + header + hash-index silinir, imleç ilerler.
                self.hard_delete_key(&manifest_key)?;
                let block_key = crate::block_key(cursor);
                if let Some(header_acc) = self.get_account(&block_key)? {
                    let mut hasher = Keccak256::new();
                    hasher.update(&header_acc.contract_code);
                    let block_hash: Hash = hasher.finalize().into();
                    self.hard_delete_key(&crate::block_hash_key(&block_hash))?;
                    self.hard_delete_key(&block_key)?;
                }
                // G6: konsensüs kaydı (header v2 + QC) aynı saklama süresiyle budanır.
                self.hard_delete_key(&crate::consensus_block_key(cursor))?;
                cursor += 1;
            } else {
                // Batch limiti blok ORTASINDA doldu: kalan tx_id'leri sakla,
                // imleci ilerletme, bir sonraki çağrı buradan devam eder.
                let acc = AccountState {
                    contract_code: bincode::serialize(&tx_ids).map_err(|e| {
                        ZagrosError::DatabaseError(format!(
                            "Serialize hatası (kalan manifest): {}",
                            e
                        ))
                    })?,
                    ..Default::default()
                };
                self.set_account(&manifest_key, acc)?;
                break;
            }
        }

        // İmleci kaydet (bir sonraki flush'ta diske iner; budama idempotent
        // olduğundan bu gecikme zararsız, yeniden çalışırsa zaten silinmiş
        // anahtarları tekrar silmeye çalışır, no-op).
        let cursor_acc = AccountState {
            balance: cursor as u128,
            ..Default::default()
        };
        self.set_account(&cursor_key, cursor_acc)?;

        Ok(deleted)
    }

    fn evict_from_cache(&self, keys: &[Address]) {
        for key in keys {
            debug_assert!(
                !key.starts_with("0x"),
                "evict_from_cache chain-state (0x) hesabına dokunmamalı"
            );
            if key.starts_with("0x") {
                continue; // fail-safe: asla chain state cache'ini boşaltma
            }
            self.cache.remove(key);
        }
    }

    fn get_genesis_block_0_bytes(&self) -> Result<Option<Vec<u8>>> {
        self.storage.get(b"block_0")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use zagros_storage::Storage;

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

    // 🚨 Perf regresyonu: hızlı yol yavaş yolla bayt birebir aynı sonucu vermeli
    // (aynı adres farklı anahtara düşmesin).
    #[test]
    fn canonicalize_address_fast_path_matches_slow_path_for_every_input_shape() {
        let cases = [
            "0x1111111111111111111111111111111111111111", // zaten tam kanonik
            "0X1111111111111111111111111111111111111111", // buyuk 0X
            "0x1111111111111111111111111111111111111111 ", // sondaki bosluk
            " 0x1111111111111111111111111111111111111111", // bastaki bosluk
            "0xABCDEF1111111111111111111111111111111111", // buyuk harfli hex
            "0xaBcDeF1111111111111111111111111111111111", // karisik harf
            "not-an-address",                             // 0x-harici (degismeden donmeli)
        ];
        for raw in cases {
            let address = raw.to_string();
            let canonical = StateDbManager::canonicalize_address(&address);

            // Bagimsizca AYNI mantigi (yavas yolu) burada yeniden uygula ve
            // karsilastir.
            let trimmed = address.trim();
            let expected = if (trimmed.starts_with("0x") || trimmed.starts_with("0X"))
                && trimmed.len() == 42
            {
                format!("0x{}", trimmed[2..].to_lowercase())
            } else {
                address.clone()
            };
            assert_eq!(canonical, expected, "girdi: {raw:?}");
        }
    }

    #[test]
    fn get_after_set_returns_fresh_value_before_flush() {
        let storage = Arc::new(MemoryStorage::default());
        let state = StateDbManager::new(storage.clone());
        let address = "0x1111111111111111111111111111111111111111".to_string();

        state.set_account(&address, AccountState::new(500)).unwrap();

        // Nothing physically written yet...
        assert!(storage.get(address.as_bytes()).unwrap().is_none());
        // ...but a cache-first read still returns the fresh value.
        assert_eq!(state.get_balance(&address).unwrap(), 500);
    }

    #[test]
    fn crash_before_flush_loses_only_the_unflushed_block() {
        let storage = Arc::new(MemoryStorage::default());
        let address_a = "0x1111111111111111111111111111111111111111".to_string();
        let address_b = "0x2222222222222222222222222222222222222222".to_string();

        // "Block 1": applied and flushed.
        let state = StateDbManager::new(storage.clone());
        state
            .set_account(&address_a, AccountState::new(100))
            .unwrap();
        state.flush().unwrap();

        // "Block 2": applied but the node "crashes" before flush() runs.
        state
            .set_account(&address_b, AccountState::new(200))
            .unwrap();
        drop(state);

        // "Restart": a fresh manager reading the same physical storage should
        // see block 1's effects and none of block 2's, never a partial block.
        let reopened = StateDbManager::new(storage.clone());
        assert_eq!(reopened.get_balance(&address_a).unwrap(), 100);
        assert_eq!(reopened.get_balance(&address_b).unwrap(), 0);
    }

    #[test]
    fn flush_is_idempotent_when_nothing_is_dirty() {
        let storage = Arc::new(MemoryStorage::default());
        let state = StateDbManager::new(storage.clone());
        let address = "0x1111111111111111111111111111111111111111".to_string();

        state.set_account(&address, AccountState::new(42)).unwrap();
        state.flush().unwrap();
        // Second flush with nothing dirty must be a harmless no-op.
        state.flush().unwrap();

        assert_eq!(state.get_balance(&address).unwrap(), 42);
    }

    /// Thread-local ACTIVE_CHECKPOINT regresyonu: paylaşımlı atomik olsaydı
    /// thread'lerin checkpoint/commit/revert'i birbirini ezerdi; her thread
    /// kendi hesabını rastgele commit/revert döngüleriyle döver, hata bakiyede görünür.
    #[test]
    fn concurrent_checkpoints_on_different_threads_never_stomp_each_other() {
        let storage = Arc::new(MemoryStorage::default());
        let state = Arc::new(StateDbManager::new(storage));

        let thread_count: u64 = 8;
        let iterations = 500;

        let handles: Vec<_> = (0..thread_count)
            .map(|t| {
                let state = state.clone();
                std::thread::spawn(move || {
                    let address = format!("0x{:040x}", t + 1);
                    state
                        .set_account(&address, AccountState::new(1_000))
                        .unwrap();

                    // Deterministic per-thread xorshift PRNG, no extra crate needed.
                    let mut rng_state = t.wrapping_add(1).wrapping_mul(2_654_435_761) | 1;

                    for i in 0..iterations {
                        let checkpoint = state.checkpoint().unwrap();
                        state
                            .set_account(&address, AccountState::new(9_999))
                            .unwrap();

                        rng_state ^= rng_state << 13;
                        rng_state ^= rng_state >> 7;
                        rng_state ^= rng_state << 17;
                        let should_commit = rng_state % 2 == 0;

                        if should_commit {
                            state.commit_checkpoint(checkpoint).unwrap();
                            assert_eq!(
                                state.get_balance(&address).unwrap(),
                                9_999,
                                "thread {t} iter {i}: committed value lost to a cross-thread checkpoint stomp"
                            );
                            state
                                .set_account(&address, AccountState::new(1_000))
                                .unwrap();
                        } else {
                            state.revert_checkpoint(checkpoint).unwrap();
                            assert_eq!(
                                state.get_balance(&address).unwrap(),
                                1_000,
                                "thread {t} iter {i}: reverted value leaked from a cross-thread checkpoint stomp"
                            );
                        }
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }
    }

    // 🚨 Concurrency regresyonu: kilitsiz `flush()` + toptan `dirty.clear()`
    // yarışta yeniden dirty olan adresi bir daha asla flush etmezdi. Çok thread'li
    // `set_account` + `flush()` sonrası her adresin nihai değeri diskte olmalı.
    #[test]
    fn concurrent_flush_calls_never_silently_drop_a_racing_set_account() {
        let storage = Arc::new(MemoryStorage::default());
        let state = Arc::new(StateDbManager::new(storage.clone()));

        let thread_count: u64 = 16;
        let iterations: u128 = 200;

        let handles: Vec<_> = (0..thread_count)
            .map(|t| {
                let state = state.clone();
                std::thread::spawn(move || {
                    let address = format!("0x{:040x}", t + 1);
                    let mut rng_state = t.wrapping_add(1).wrapping_mul(2_654_435_761) | 1;
                    for i in 0..iterations {
                        state
                            .set_account(&address, AccountState::new(1_000 + i))
                            .unwrap();

                        rng_state ^= rng_state << 13;
                        rng_state ^= rng_state >> 7;
                        rng_state ^= rng_state << 17;
                        if rng_state % 3 == 0 {
                            state.flush().unwrap();
                        }
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }
        // Son süpürme; bug varsa bu da işe yaramaz (dirty önceden yanlış silinmiştir).
        state.flush().unwrap();

        for t in 0..thread_count {
            let address = format!("0x{:040x}", t + 1);
            let expected_balance = 1_000 + (iterations - 1);
            let cached_balance = state.get_balance(&address).unwrap();
            assert_eq!(
                cached_balance, expected_balance,
                "thread {t}: cache'in kendisi beklenmedik - test kurulumu hatası"
            );

            let raw_bytes = storage
                .get(address.as_bytes())
                .unwrap()
                .unwrap_or_else(|| panic!("thread {t}: adres hiç diske yazilmamis"));
            let on_disk = AccountState::deserialize_with_migration(&raw_bytes).unwrap();
            assert_eq!(
                on_disk.balance, expected_balance,
                "thread {t}: diskteki bakiye cache'ten SAPTI - bir flush() nihai \
                 set_account'u yakalayamadan dirty bayragini kaybetmis olmali"
            );
        }
    }

    /// 🚨 Checkpoint/Flush: (1) `flush()` başka thread'de açık checkpoint varken
    /// GERÇEKTEN bloke olur; (2) commit olunca iki anahtar diskte BİRLİKTE görünür
    /// (torn write yok).
    #[test]
    fn flush_blocks_until_a_racing_open_checkpoint_on_another_thread_commits() {
        use std::sync::atomic::AtomicBool;
        use std::sync::mpsc;

        let storage = Arc::new(MemoryStorage::default());
        let state = Arc::new(StateDbManager::new(storage.clone()));
        let key1 = "0x1111111111111111111111111111111111111111".to_string();
        let key2 = "0x2222222222222222222222222222222222222222".to_string();

        let (step1_done_tx, step1_done_rx) = mpsc::channel::<()>();
        let (proceed_tx, proceed_rx) = mpsc::channel::<()>();
        let flush_returned = Arc::new(AtomicBool::new(false));

        let writer_state = state.clone();
        let writer_key1 = key1.clone();
        let writer_key2 = key2.clone();
        let writer = std::thread::spawn(move || {
            let checkpoint = writer_state.checkpoint().unwrap();
            writer_state
                .set_account(&writer_key1, AccountState::new(111))
                .unwrap();
            step1_done_tx.send(()).unwrap();
            // Ana thread'in flush() cagirip GERCEKTEN beklediğini
            // gozlemleyebilmesi icin checkpoint'i bilerek acik tutuyoruz.
            proceed_rx.recv().unwrap();
            writer_state
                .set_account(&writer_key2, AccountState::new(222))
                .unwrap();
            writer_state.commit_checkpoint(checkpoint).unwrap();
        });

        step1_done_rx.recv().unwrap();

        let flusher_state = state.clone();
        let flusher_flag = flush_returned.clone();
        let flusher = std::thread::spawn(move || {
            flusher_state.flush().unwrap();
            flusher_flag.store(true, Ordering::SeqCst);
        });

        // flush() acik checkpoint'i gorup gercekten bloke oluyorsa, kisa bir
        // bekleme sonrasinda hala donmemis olmali.
        std::thread::sleep(std::time::Duration::from_millis(150));
        assert!(
            !flush_returned.load(Ordering::SeqCst),
            "flush() acik bir checkpoint varken hemen donmemeliydi - checkpoint_gate calismiyor"
        );

        proceed_tx.send(()).unwrap();
        writer.join().unwrap();
        flusher.join().unwrap();

        assert!(
            flush_returned.load(Ordering::SeqCst),
            "flush() checkpoint kapandiktan sonra donmeliydi"
        );

        let key1_on_disk = storage.get(key1.as_bytes()).unwrap();
        let key2_on_disk = storage.get(key2.as_bytes()).unwrap();
        assert!(
            key1_on_disk.is_some() && key2_on_disk.is_some(),
            "torn write: checkpoint'in yalnizca bir kismi diske yazildi (key1_var={}, key2_var={})",
            key1_on_disk.is_some(),
            key2_on_disk.is_some()
        );
    }

    #[test]
    fn state_root_picks_up_new_accounts_without_a_restart() {
        let storage = Arc::new(MemoryStorage::default());
        let state = StateDbManager::new(storage);
        let address = "0x1111111111111111111111111111111111111111".to_string();

        let root_before = state.state_root().unwrap();
        state.set_account(&address, AccountState::new(100)).unwrap();
        let root_after = state.state_root().unwrap();

        assert_ne!(
            root_before, root_after,
            "a newly created account (address_index grown incrementally) must change the root"
        );
    }

    #[test]
    fn state_root_is_identical_after_reopening_from_the_same_disk_state() {
        let storage = Arc::new(MemoryStorage::default());
        let address = "0x1111111111111111111111111111111111111111".to_string();

        let state = StateDbManager::new(storage.clone());
        state.set_account(&address, AccountState::new(100)).unwrap();
        state.flush().unwrap();
        let root_before_restart = state.state_root().unwrap();
        drop(state);

        // Fresh manager, same physical storage: address_index must be
        // correctly re-seeded from disk (not left empty) on construction.
        let reopened = StateDbManager::new(storage);
        let root_after_restart = reopened.state_root().unwrap();

        assert_eq!(root_before_restart, root_after_restart);
    }

    fn addr(i: u8) -> String {
        format!("0x{:040x}", i)
    }

    #[test]
    fn incremental_state_root_equals_a_fresh_rebuild_of_the_same_accounts() {
        // Bir dizi ekleme/güncelleme sonrası artırımlı kök, AYNI hesap kümesini
        // taze bir manager'a kurmakla elde edilen kökle birebir aynı olmalı,
        // Merkle trie'nin kanonik/deterministik olduğunun state-katmanı kanıtı.
        let storage = Arc::new(MemoryStorage::default());
        let state = StateDbManager::new(storage);

        for i in 1..=25u8 {
            state
                .set_account(&addr(i), AccountState::new(i as u128 * 100))
                .unwrap();
        }
        // Bazı hesapları güncelle (yaprak değeri değişir).
        for i in [3u8, 10, 21] {
            state
                .set_account(&addr(i), AccountState::new(999_999))
                .unwrap();
        }
        let incremental_root = state.state_root().unwrap();

        // Taze manager: yalnızca SON değerlerle kur (güncellemeleri tekrarlamadan).
        let fresh = StateDbManager::new(Arc::new(MemoryStorage::default()));
        for i in 1..=25u8 {
            let value = if [3u8, 10, 21].contains(&i) {
                999_999
            } else {
                i as u128 * 100
            };
            fresh
                .set_account(&addr(i), AccountState::new(value))
                .unwrap();
        }
        let rebuild_root = fresh.state_root().unwrap();

        assert_eq!(
            incremental_root, rebuild_root,
            "artırımlı kök, aynı son durumun taze inşasıyla eşleşmeli"
        );
    }

    #[test]
    fn changing_one_account_changes_the_root_but_leaves_others_deterministic() {
        let storage = Arc::new(MemoryStorage::default());
        let state = StateDbManager::new(storage);
        for i in 1..=10u8 {
            state
                .set_account(&addr(i), AccountState::new(i as u128))
                .unwrap();
        }
        let root1 = state.state_root().unwrap();

        // Tek bir hesabı değiştir → kök değişmeli.
        state.set_account(&addr(5), AccountState::new(500)).unwrap();
        let root2 = state.state_root().unwrap();
        assert_ne!(root1, root2);

        // Eski değere geri döndür → kök root1'e geri dönmeli (deterministik).
        state.set_account(&addr(5), AccountState::new(5)).unwrap();
        let root3 = state.state_root().unwrap();
        assert_eq!(root1, root3);
    }

    #[test]
    fn validator_candidates_exclude_non_address_bookkeeping_keys() {
        let storage = Arc::new(MemoryStorage::default());
        let state = StateDbManager::new(storage);
        let validator = "0x1111111111111111111111111111111111111111".to_string();

        state
            .set_account(
                &validator,
                AccountState {
                    staked_balance: 500,
                    ..Default::default()
                },
            )
            .unwrap();
        // A non-"0x" bookkeeping key (mirrors Receipt_*/__GLOBAL_*/Proposal_*)
        // must never be treated as a validator candidate.
        state
            .set_account(&"Receipt_deadbeef".to_string(), AccountState::new(0))
            .unwrap();

        let candidates = state.get_validator_candidates().unwrap();
        assert_eq!(candidates, vec![(validator, 500)]);
    }

    #[test]
    fn total_known_addresses_counts_every_distinct_0x_address_seen() {
        let storage = Arc::new(MemoryStorage::default());
        let state = StateDbManager::new(storage);
        assert_eq!(state.total_known_addresses().unwrap(), 0);

        state
            .set_account(
                &"0x1111111111111111111111111111111111111111".to_string(),
                AccountState::new(1),
            )
            .unwrap();
        state
            .set_account(
                &"0x2222222222222222222222222222222222222222".to_string(),
                AccountState::new(2),
            )
            .unwrap();
        // Aynı adrese ikinci bir yazma tekrar SAYILMAMALI.
        state
            .set_account(
                &"0x1111111111111111111111111111111111111111".to_string(),
                AccountState::new(99),
            )
            .unwrap();

        assert_eq!(state.total_known_addresses().unwrap(), 2);
    }

    // 🚨 Regresyon: onarım taraması `is_contract=true` + `contract_code=[0x00]`
    // imzalı hesabı EOA'ya çevirir, başka hiçbir hesaba dokunmaz.
    #[test]
    fn repair_scan_resets_only_accounts_matching_the_exact_corruption_signature() {
        let storage = Arc::new(MemoryStorage::default());
        let state = StateDbManager::new(storage);

        let corrupted = "0x1111111111111111111111111111111111111111".to_string();
        state
            .set_account(
                &corrupted,
                AccountState {
                    is_contract: true,
                    contract_code: vec![0x00],
                    balance: 500,
                    ..Default::default()
                },
            )
            .unwrap();

        let real_contract = "0x2222222222222222222222222222222222222222".to_string();
        state
            .set_account(
                &real_contract,
                AccountState::new_contract(vec![0x60, 0x00, 0xfd]),
            )
            .unwrap();

        // is_contract=false ama contract_code sinyaline sahip (dokunulmamalı,
        // is_contract bayrağı false olduğu için imza eşleşmiyor).
        let clean_eoa = "0x3333333333333333333333333333333333333333".to_string();
        state
            .set_account(&clean_eoa, AccountState::new(1_000))
            .unwrap();

        let repaired = state
            .repair_stale_evm_default_bytecode_corruption()
            .unwrap();

        assert_eq!(repaired, 1);

        let after = state.get_account(&corrupted).unwrap().unwrap();
        assert!(!after.is_contract);
        assert!(after.contract_code.is_empty());
        assert_eq!(after.balance, 500, "bakiye onarımdan etkilenmemeli");

        let contract_after = state.get_account(&real_contract).unwrap().unwrap();
        assert!(
            contract_after.is_contract,
            "gerçek kontrat dokunulmadan kalmalı"
        );
        assert_eq!(contract_after.contract_code, vec![0x60, 0x00, 0xfd]);

        // İkinci taramada artık onaracak bir şey yok (idempotent).
        assert_eq!(
            state
                .repair_stale_evm_default_bytecode_corruption()
                .unwrap(),
            0
        );
    }

    // ---- K2: Tarihsel dekont budama (pruning) ----

    /// `Executor::save_dummy_receipt` ile aynı biçimde bir dekont yazar.
    fn write_receipt(state: &StateDbManager, tx_id: &Hash) {
        let acc = AccountState {
            contract_code: b"[]".to_vec(),
            ..Default::default()
        };
        state.set_account(&crate::receipt_key(tx_id), acc).unwrap();
    }

    /// b. bloğa deterministik `count` dekont yazar + manifestini kaydeder.
    fn commit_block_with_receipts(state: &StateDbManager, block: u64, count: u8) -> Vec<Hash> {
        let tx_ids: Vec<Hash> = (0..count).map(|j| [(block as u8) * 10 + j; 32]).collect();
        for id in &tx_ids {
            write_receipt(state, id);
        }
        state.record_block_receipts(block, &tx_ids).unwrap();
        state.flush().unwrap();
        tx_ids
    }

    fn receipt_exists(state: &StateDbManager, tx_id: &Hash) -> bool {
        state
            .get_account(&crate::receipt_key(tx_id))
            .unwrap()
            .is_some()
    }

    #[test]
    fn pruning_deletes_receipts_older_than_retention_and_keeps_recent() {
        let storage = Arc::new(MemoryStorage::default());
        let state = StateDbManager::new(storage);

        let mut per_block = Vec::new();
        for block in 1..=5u64 {
            per_block.push((block, commit_block_with_receipts(&state, block, 2)));
        }

        // prune_before_block=4 => bloklar 1,2,3 (6 dekont) silinir; 4,5 korunur.
        let deleted = state.prune_historical_data(4, 1000).unwrap();
        assert_eq!(deleted, 6);

        for (block, tx_ids) in &per_block {
            let should_exist = *block >= 4;
            for id in tx_ids {
                assert_eq!(
                    receipt_exists(&state, id),
                    should_exist,
                    "blok {block} dekontu beklenen durumda değil"
                );
            }
            // Budanan blokların manifesti de silinmeli.
            let manifest = state
                .get_account(&StateDbManager::block_receipts_key(*block))
                .unwrap();
            assert_eq!(manifest.is_some(), should_exist);
        }
    }

    /// 🚨 Regresyon: budama `Receipt_` + `tx_body_` + (blok tamamen budanınca)
    /// `block_`/`block_hash_` header'ını da silmeli.
    #[test]
    fn pruning_also_deletes_archived_tx_bodies_and_block_headers() {
        let storage = Arc::new(MemoryStorage::default());
        let state = StateDbManager::new(storage);

        let tx_ids = commit_block_with_receipts(&state, 1, 2);
        for id in &tx_ids {
            let acc = AccountState {
                contract_code: b"fake-tx-body".to_vec(),
                ..Default::default()
            };
            state.set_account(&crate::tx_body_key(id), acc).unwrap();
        }
        let header = zagros_types::ArchivedBlockHeader {
            number: 1,
            parent_hash: [0u8; 32],
            state_root: [0u8; 32],
            timestamp: 1_000,
            tx_hashes: tx_ids.clone(),
        };
        let header_bytes = bincode::serialize(&header).unwrap();
        state
            .set_account(
                &crate::block_key(1),
                AccountState {
                    contract_code: header_bytes.clone(),
                    ..Default::default()
                },
            )
            .unwrap();
        let mut hasher = Keccak256::new();
        hasher.update(&header_bytes);
        let block_hash: Hash = hasher.finalize().into();
        state
            .set_account(
                &crate::block_hash_key(&block_hash),
                AccountState {
                    balance: 1,
                    ..Default::default()
                },
            )
            .unwrap();
        state.flush().unwrap();

        let deleted = state.prune_historical_data(2, 1000).unwrap();
        assert_eq!(deleted, 2);

        for id in &tx_ids {
            assert!(!receipt_exists(&state, id), "receipt silinmeli");
            assert!(
                state
                    .get_account(&crate::tx_body_key(id))
                    .unwrap()
                    .is_none(),
                "tx_body da silinmeli"
            );
        }
        assert!(
            state.get_account(&crate::block_key(1)).unwrap().is_none(),
            "block header silinmeli"
        );
        assert!(
            state
                .get_account(&crate::block_hash_key(&block_hash))
                .unwrap()
                .is_none(),
            "hash index silinmeli"
        );
    }

    #[test]
    fn pruning_respects_batch_limit_and_resumes_across_calls() {
        let storage = Arc::new(MemoryStorage::default());
        let state = StateDbManager::new(storage);

        let mut all = Vec::new();
        for block in 1..=3u64 {
            all.extend(commit_block_with_receipts(&state, block, 2)); // toplam 6
        }

        // Batch limiti 3: ilk çağrı 3 siler (blok ortasında durabilir).
        let first = state.prune_historical_data(100, 3).unwrap();
        assert_eq!(first, 3);
        // İkinci çağrı kalan 3'ü siler.
        let second = state.prune_historical_data(100, 100).unwrap();
        assert_eq!(second, 3);
        // Üçüncü çağrı: silinecek bir şey kalmadı.
        assert_eq!(state.prune_historical_data(100, 100).unwrap(), 0);

        for id in &all {
            assert!(!receipt_exists(&state, id), "tüm dekontlar silinmiş olmalı");
        }
    }

    #[test]
    fn pruning_never_changes_the_state_root() {
        let storage = Arc::new(MemoryStorage::default());
        let state = StateDbManager::new(storage);

        // Gerçek chain state (0x hesaplar).
        state
            .set_account(
                &"0x1111111111111111111111111111111111111111".to_string(),
                AccountState::new(1_000),
            )
            .unwrap();
        state
            .set_account(
                &"0x2222222222222222222222222222222222222222".to_string(),
                AccountState::new(2_000),
            )
            .unwrap();
        state.flush().unwrap();
        let root_before = state.state_root().unwrap();

        // Tarihsel dekontlar + manifestler yaz, sonra hepsini buda.
        for block in 1..=4u64 {
            commit_block_with_receipts(&state, block, 3);
        }
        let deleted = state.prune_historical_data(100, 10_000).unwrap();
        assert!(deleted > 0);
        state.flush().unwrap();

        // Chain state mührü DEĞİŞMEMELİ, budama yalnızca tarihsel kayıtları siler.
        assert_eq!(
            state.state_root().unwrap(),
            root_before,
            "budama state_root'u (chain state) DEĞİŞTİRMEMELİ"
        );
    }

    /// 🚨 Regresyon: `evict_from_cache` yalnız bellek cache'ini boşaltır, storage'a
    /// dokunmaz, sonraki `get_account` doğru değeri okur; `0x` hesaplar ASLA boşaltılmaz.
    #[test]
    fn evict_from_cache_only_clears_memory_not_storage() {
        let storage = Arc::new(MemoryStorage::default());
        let state = StateDbManager::new(storage);

        let key = "Receipt_abc".to_string();
        let acc = AccountState {
            contract_code: b"payload".to_vec(),
            ..Default::default()
        };
        state.set_account(&key, acc).unwrap();
        state.flush().unwrap();
        assert!(
            state.cache.contains_key(&key),
            "flush sonrasi cache'te kalmali"
        );

        state.evict_from_cache(std::slice::from_ref(&key));
        assert!(
            !state.cache.contains_key(&key),
            "evict_from_cache cache'ten cikarmali"
        );

        // Storage'a hâlâ dokunulmamış, get_account fallback'le doğru okumalı.
        let read_back = state.get_account(&key).unwrap().unwrap();
        assert_eq!(read_back.contract_code, b"payload".to_vec());
    }

    // 🚨 KRİTİK REGRESYON: `cache` dokunulan HER anahtarı sonsuza dek
    // tutmamalı. Bu test, `max_cache_entries` aşıldığında boyutun gerçekten
    // SINIRLI kaldığını kanıtlar.
    #[test]
    fn cache_stays_bounded_once_max_cache_entries_is_exceeded() {
        let storage = Arc::new(MemoryStorage::default());
        let state = StateDbManager::new(storage).with_max_cache_entries(100);

        for i in 0..500u32 {
            let address = format!("0x{:040x}", i);
            state.set_account(&address, AccountState::new(1)).unwrap();
            state.flush().unwrap(); // dirty bayragini temizle - artik tahliye edilebilir
        }

        assert!(
            state.cache.len() <= 100,
            "cache 100 sinirinin COK ustunde: {} (sinirsiz buyume geri geldi)",
            state.cache.len()
        );
    }

    // Sınır aşılsa bile dirty girdi ASLA tahliye edilmemeli. İki aşamalı test:
    // önce temiz doldurucular (aday havuzu), sonra `dirty_address` flush
    // edilmeden eklenip sınır aşılır; süpürme yalnız temiz adaylardan seçer.
    #[test]
    fn maybe_evict_cache_never_evicts_a_dirty_unflushed_entry() {
        let storage = Arc::new(MemoryStorage::default());
        let state = StateDbManager::new(storage.clone()).with_max_cache_entries(50);

        // Aşama 1: bol miktarda TEMİZ (flush edilmiş) doldurucu, tahliye
        // edilebilir aday havuzu oluşturur.
        for i in 0..200u32 {
            let address = format!("0x{:040x}", i + 1);
            state.set_account(&address, AccountState::new(1)).unwrap();
            state.flush().unwrap();
        }
        assert!(
            state.cache.len() <= 50,
            "aşama 1 sonunda cache zaten sınırlı olmalı: {}",
            state.cache.len()
        );

        // Aşama 2: `dirty_address`'i VE onu koruyan başka dirty doldurucuları
        // flush ETMEDEN ekle, sınırı aş, gerçek bir süpürme tetiklensin.
        let dirty_address = "0x9999999999999999999999999999999999999999".to_string();
        state
            .set_account(&dirty_address, AccountState::new(42))
            .unwrap();
        for i in 0..30u32 {
            let address = format!("0xaaaa{:036x}", i + 1);
            state.set_account(&address, AccountState::new(1)).unwrap();
            // flush() KASITLI OLARAK ÇAĞRILMIYOR, bunlar da dirty_address
            // gibi dirty kalmalı, sadece süpürmeyi TETİKLEMEK için var.
        }

        assert!(
            state.cache.contains_key(&dirty_address),
            "flush edilmemis (dirty) bir hesap tahliye edilmis - bir sonraki flush() bunu YANLISLIKLA SILERDI"
        );

        // Şimdi gerçekten flush edip diskte doğru değerle durduğunu kanıtla
        // (tahliye edilmemiş olması sadece "cache'te kaldı" değil, "hâlâ
        // doğru şekilde flush edilebilir" anlamına da gelmeli).
        state.flush().unwrap();
        let on_disk = storage.get(dirty_address.as_bytes()).unwrap().unwrap();
        let account = AccountState::deserialize_with_migration(&on_disk).unwrap();
        assert_eq!(account.balance, 42);
    }

    /// Fail-safe: `evict_from_cache`'e yanlışlıkla bir `0x` (chain-state)
    /// anahtarı verilirse debug build'de yüksek sesle panikler, `hard_delete_key`
    /// ile AYNI güvenlik ağı deseni.
    #[test]
    #[should_panic(expected = "evict_from_cache chain-state (0x) hesabına dokunmamalı")]
    fn evict_from_cache_panics_in_debug_on_a_0x_key() {
        let storage = Arc::new(MemoryStorage::default());
        let state = StateDbManager::new(storage);
        let real_account = "0x1111111111111111111111111111111111111111".to_string();
        state
            .set_account(&real_account, AccountState::new(500))
            .unwrap();
        state.evict_from_cache(&[real_account]);
    }

    // ---- FAZ1: State/rezerv tutarlılığı & atomik flush ----

    /// 🏛️ [444] Yol A: Rezervler artık LIQUIDITY_POOL_ADDRESS (0x0) HESABININ
    /// balance/zerenya_balance'ında. flush ÖNCESİ o hesap diske inmemiş olmalı; aynı
    /// örnek içi okuma tamponlanmış değeri görmeli; flush SONRASI diske inmeli.
    #[test]
    fn pool_reserves_live_in_the_pool_account_and_flush_atomically() {
        use zagros_types::LIQUIDITY_POOL_ADDRESS;
        let storage = Arc::new(MemoryStorage::default());
        let state = StateDbManager::new(storage.clone());

        state.set_pool_reserves(1_000, 2_000).unwrap();

        // Pool hesabı HENÜZ diske inmedi (hesap cache/dirty yolunda, flush bekliyor)...
        assert!(storage
            .get(LIQUIDITY_POOL_ADDRESS.as_bytes())
            .unwrap()
            .is_none());
        // ...ama okuma tamponu (cache) görür.
        assert_eq!(state.get_pool_reserves().unwrap(), (1_000, 2_000));

        // flush() sonrası pool hesabı diske iner (hesaplarla AYNI batch).
        state.flush().unwrap();
        let persisted = storage
            .get(LIQUIDITY_POOL_ADDRESS.as_bytes())
            .unwrap()
            .expect("pool account must be persisted after flush");
        let acc: AccountState = bincode::deserialize(&persisted).unwrap();
        assert_eq!((acc.balance, acc.zerenya_balance), (1_000, 2_000));

        // Ayrı ham `__pool_*` anahtarları HİÇ yazılmamalı (tek kaynak hesap).
        assert!(storage.get(b"__pool_zagros_reserve__").unwrap().is_none());
        assert!(storage.get(b"__pool_zerenya_reserve__").unwrap().is_none());
    }

    /// 🏛️ [444] Yol A'nın ASIL kazanımı: rezerv değişimi state_root'u DETERMİNİSTİK
    /// değiştirir (konsensüs artık rezerv sapmasını yakalar) ve rezerv, pool
    /// hesabının balance/zerenya_balance'ıyla trie üzerinden birebir bağlıdır.
    #[test]
    fn changing_pool_reserves_changes_the_state_root() {
        let storage = Arc::new(MemoryStorage::default());
        let state = StateDbManager::new(storage);
        state.set_pool_reserves(1_000, 1_000).unwrap();
        let root1 = state.state_root().unwrap();

        // Rezervi değiştir → kök DEĞİŞMELİ (rezerv artık köke dahil).
        state.set_pool_reserves(2_000, 500).unwrap();
        let root2 = state.state_root().unwrap();
        assert_ne!(root1, root2, "reserve change must change the state_root");

        // Aynı rezerve geri dön → kök root1'e geri dönmeli (deterministik/kanonik).
        state.set_pool_reserves(1_000, 1_000).unwrap();
        assert_eq!(state.state_root().unwrap(), root1);
    }

    /// İki ayrı örnek aynı işlemleri (rezerv dahil) uygulayınca AYNI state_root'u
    /// üretmeli, konsensüs uyumunun kanıtı.
    #[test]
    fn two_instances_with_identical_reserves_agree_on_state_root() {
        let a = StateDbManager::new(Arc::new(MemoryStorage::default()));
        let b = StateDbManager::new(Arc::new(MemoryStorage::default()));
        for state in [&a, &b] {
            state
                .set_account(
                    &"0x1111111111111111111111111111111111111111".to_string(),
                    AccountState::new(100),
                )
                .unwrap();
            state.set_pool_reserves(7_777, 8_888).unwrap();
        }
        assert_eq!(a.state_root().unwrap(), b.state_root().unwrap());

        // Yalnızca birinin rezervi saparsa kökler AYRILMALI.
        b.set_pool_reserves(7_777, 9_999).unwrap();
        assert_ne!(a.state_root().unwrap(), b.state_root().unwrap());
    }

    /// 🏛️ [444] Yol A Companion: reward akümülatörü de artık state_root'a dahil
    /// (LIQUIDITY_POOL_ADDRESS depolama slot'unda). Değişimi kökü deterministik
    /// değiştirmeli; get/set round-trip doğru olmalı.
    #[test]
    fn changing_reward_per_share_changes_the_state_root() {
        let storage = Arc::new(MemoryStorage::default());
        let state = StateDbManager::new(storage);
        state.set_accumulated_reward_per_share(1_000).unwrap();
        assert_eq!(state.get_accumulated_reward_per_share().unwrap(), 1_000);
        let root1 = state.state_root().unwrap();

        state.set_accumulated_reward_per_share(2_000).unwrap();
        assert_eq!(state.get_accumulated_reward_per_share().unwrap(), 2_000);
        let root2 = state.state_root().unwrap();
        assert_ne!(
            root1, root2,
            "reward-per-share change must change the state_root"
        );

        state.set_accumulated_reward_per_share(1_000).unwrap();
        assert_eq!(state.state_root().unwrap(), root1);

        // Ayrı ham anahtar HİÇ yazılmamalı (raw altyapısı yok).
        state.flush().unwrap();
        // storage'a erişim yok burada; get üzerinden dolaylı doğrulama yeterli.
    }

    /// Reward akümülatörü checkpoint/revert ile geri sarılmalı (artık hesap
    /// journal'ından, ayrı raw journal yok).
    #[test]
    fn reward_per_share_rolls_back_on_revert() {
        let storage = Arc::new(MemoryStorage::default());
        let state = StateDbManager::new(storage);
        state.set_accumulated_reward_per_share(500).unwrap();
        state.flush().unwrap();

        let cp = state.checkpoint().unwrap();
        state.set_accumulated_reward_per_share(9_999).unwrap();
        assert_eq!(state.get_accumulated_reward_per_share().unwrap(), 9_999);
        state.revert_checkpoint(cp).unwrap();

        assert_eq!(state.get_accumulated_reward_per_share().unwrap(), 500);
    }

    /// Rezerv ve reward AYNI 0x0 hesabında; ikisini de aynı checkpoint'te değiştirip
    /// revert edince İKİSİ birlikte geri sarılmalı (tek hesap journal girdisi).
    #[test]
    fn reserves_and_reward_revert_together_from_the_shared_pool_account() {
        let storage = Arc::new(MemoryStorage::default());
        let state = StateDbManager::new(storage);
        state.set_pool_reserves(1_000, 1_000).unwrap();
        state.set_accumulated_reward_per_share(50).unwrap();
        state.flush().unwrap();

        let cp = state.checkpoint().unwrap();
        state.set_pool_reserves(2_000, 3_000).unwrap();
        state.set_accumulated_reward_per_share(999).unwrap();
        state.revert_checkpoint(cp).unwrap();

        assert_eq!(state.get_pool_reserves().unwrap(), (1_000, 1_000));
        assert_eq!(state.get_accumulated_reward_per_share().unwrap(), 50);
    }

    #[test]
    fn crash_before_flush_loses_reserves_and_balances_together() {
        // 🛡️ FAZ1 [281]: Rezervler ve bakiyeler TEK atomik birim, flush öncesi
        // çökme ikisini de kaybettirir (yarım/desync durum OLMAZ).
        let storage = Arc::new(MemoryStorage::default());
        let addr_a = "0x1111111111111111111111111111111111111111".to_string();

        let state = StateDbManager::new(storage.clone());
        state.set_account(&addr_a, AccountState::new(100)).unwrap();
        state.set_pool_reserves(500, 600).unwrap();
        // flush YOK → "çökme"
        drop(state);

        let reopened = StateDbManager::new(storage);
        assert_eq!(reopened.get_balance(&addr_a).unwrap(), 0);
        assert_eq!(reopened.get_pool_reserves().unwrap(), (0, 0));
    }

    #[test]
    fn reverting_a_checkpoint_rolls_back_pool_reserves_in_memory() {
        // 🛡️ FAZ1 [434]: Rezerv revert'i artık salt-bellek, disk I/O yok, yarı-
        // revert yok. Checkpoint içinde değişen rezervler revert'te eski değere döner.
        let storage = Arc::new(MemoryStorage::default());
        let state = StateDbManager::new(storage);
        state.set_pool_reserves(1_000, 1_000).unwrap();
        state.flush().unwrap();

        let cp = state.checkpoint().unwrap();
        state.set_pool_reserves(9_999, 8_888).unwrap();
        assert_eq!(state.get_pool_reserves().unwrap(), (9_999, 8_888));
        state.revert_checkpoint(cp).unwrap();

        // Eski değere geri sarılmalı.
        assert_eq!(state.get_pool_reserves().unwrap(), (1_000, 1_000));
    }

    #[test]
    fn state_root_after_revert_matches_never_touched_when_root_read_mid_checkpoint() {
        // 🛡️ Checkpoint açıkken `state_root()` sonra revert: trie iptal edilen değeri
        // tutmamalı, kök hiç dokunulmamış köke eşit olmalı.
        let storage = Arc::new(MemoryStorage::default());
        let state = StateDbManager::new(storage);
        let base = "0x1111111111111111111111111111111111111111".to_string();
        let victim = "0x2222222222222222222222222222222222222222".to_string();

        state.set_account(&base, AccountState::new(100)).unwrap();
        let baseline_root = state.state_root().unwrap();

        let cp = state.checkpoint().unwrap();
        state.set_account(&victim, AccountState::new(500)).unwrap();
        // Checkpoint hâlâ aktifken kökü hesapla → victim yaprağı trie'ye baklanır.
        let _mid_root = state.state_root().unwrap();
        // Şimdi geri sar → victim hiç var olmamış gibi olmalı.
        state.revert_checkpoint(cp).unwrap();

        let root_after_revert = state.state_root().unwrap();
        assert_eq!(
            root_after_revert, baseline_root,
            "revert sonrası kök, victim hesabına hiç dokunulmamış köke eşit olmalı"
        );
    }

    // ---- FAZ2: Bellek/sınır & fail-closed ----

    #[test]
    fn reverting_a_created_account_prunes_it_from_address_index() {
        // 🛡️ FAZ2 [424]: Checkpoint içinde OLUŞTURULUP geri sarılan 0x hesap,
        // address_index'ten de çıkarılmalı, aksi halde "oluştur→revert" indeksi
        // sınırsız şişirir.
        let storage = Arc::new(MemoryStorage::default());
        let state = StateDbManager::new(storage);
        let base = "0x1111111111111111111111111111111111111111".to_string();
        state.set_account(&base, AccountState::new(1)).unwrap();
        let len_before = state.address_index_len();

        let cp = state.checkpoint().unwrap();
        let victim = "0x2222222222222222222222222222222222222222".to_string();
        state.set_account(&victim, AccountState::new(500)).unwrap();
        assert_eq!(state.address_index_len(), len_before + 1);
        // Kök checkpoint aktifken okunsa bile (trie'ye baklanır)...
        let _ = state.state_root().unwrap();
        state.revert_checkpoint(cp).unwrap();

        // ...revert sonrası indeks eski boyutuna dönmeli (sızıntı yok).
        assert_eq!(state.address_index_len(), len_before);
    }

    #[test]
    fn revert_keeps_a_preexisting_account_in_the_index() {
        // Karşı-kanıt: checkpoint BAŞINDA var olan (committed) hesap, checkpoint
        // içinde değişip revert edilince indeksten ÇIKARILMAMALI (Some dalı).
        let storage = Arc::new(MemoryStorage::default());
        let state = StateDbManager::new(storage);
        let addr = "0x1111111111111111111111111111111111111111".to_string();
        state.set_account(&addr, AccountState::new(100)).unwrap();
        state.flush().unwrap();
        let len_before = state.address_index_len();

        let cp = state.checkpoint().unwrap();
        state.set_account(&addr, AccountState::new(9_999)).unwrap();
        state.revert_checkpoint(cp).unwrap();

        assert_eq!(state.address_index_len(), len_before);
        assert_eq!(state.get_balance(&addr).unwrap(), 100);
    }

    #[test]
    fn increment_nonce_is_fail_closed_on_overflow() {
        // 🛡️ FAZ2 [343]: u64::MAX nonce'ta artış saturating DEĞİL, HATA vermeli
        // (replay güvenliği, nonce kesin artan olmalı).
        let storage = Arc::new(MemoryStorage::default());
        let state = StateDbManager::new(storage);
        let addr = "0x1111111111111111111111111111111111111111".to_string();
        state
            .set_account(
                &addr,
                AccountState {
                    nonce: u64::MAX,
                    ..Default::default()
                },
            )
            .unwrap();

        assert!(
            state.increment_nonce(&addr).is_err(),
            "nonce overflow must error, not silently saturate"
        );
    }

    #[test]
    #[should_panic(expected = "deserialize")]
    fn opening_over_a_corrupt_0x_row_fails_closed() {
        // 🛡️ FAZ2 [104]/[139]: Okunamayan/bozuk bir 0x chain-state satırıyla
        // açılış SESSİZCE yarım indeks/trie ile devam etmemeli, fail-closed panik.
        let storage = Arc::new(MemoryStorage::default());
        // Geçerli 0x anahtarı ama GEÇERSİZ (deserialize edilemez) değer.
        storage
            .put(
                b"0x1111111111111111111111111111111111111111",
                b"not-a-valid-bincode-accountstate",
            )
            .unwrap();
        // new() panik atmalı.
        let _ = StateDbManager::new(storage);
    }

    /// 🛡️ Eski format (pending_unstake alanları öncesi) hesap satırıyla açılış
    /// panik atmamalı; aksi halde gerçek bozulma ile eski format ayırt edilemez.
    #[test]
    fn opening_over_a_pre_unstake_fields_0x_row_does_not_panic() {
        #[derive(serde::Serialize)]
        struct LegacyAccountShape {
            balance: u128,
            zerenya_balance: u128,
            staked_balance: u128,
            reward_debt: u128,
            delegated_to: String,
            is_contract: bool,
            contract_code: Vec<u8>,
            // Boş map hep aynı baytlara serileşir; yer tutucu güvenle kullanılabilir.
            storage: std::collections::BTreeMap<u64, u64>,
            nonce: u64,
            storage_root: [u8; 32],
        }

        let legacy_bytes = bincode::serialize(&LegacyAccountShape {
            balance: 12_345,
            zerenya_balance: 0,
            staked_balance: 0,
            reward_debt: 0,
            delegated_to: String::new(),
            is_contract: false,
            contract_code: vec![],
            storage: std::collections::BTreeMap::new(),
            nonce: 0,
            storage_root: [0u8; 32],
        })
        .unwrap();

        let storage = Arc::new(MemoryStorage::default());
        let address = "0x2222222222222222222222222222222222222222";
        storage.put(address.as_bytes(), &legacy_bytes).unwrap();

        // new() ARTIK panik atmamalı (eski ama geçerli formatı migration ile okuyor).
        let state = StateDbManager::new(storage);
        let account = state
            .get_account(&address.to_string())
            .unwrap()
            .expect("eski formatlı hesap okunabilmeli");
        assert_eq!(account.balance, 12_345);
        assert_eq!(account.pending_unstake_amount, 0);
        assert_eq!(account.unlock_time, 0);
    }

    /// 🚨 Regresyon: ham `block_0` satırı budama imlecini 0'da çakılı bırakmamalı
    /// (bkz. `pruning_cursor` yorumu). Diğer testler ham `block_0` bırakmaz;
    /// bu test gerçek genesis koşulunu kurar.
    #[test]
    fn pruning_survives_the_raw_genesis_block_0_row_and_never_prunes_it() {
        let storage = Arc::new(MemoryStorage::default());
        // Genesis'i CLI'nin yazdığı gibi yaz: AccountState DEĞİL, ham baytlar.
        let genesis_bytes = b"ham-genesis-baytlari-AccountState-degil".to_vec();
        storage.put(b"block_0", &genesis_bytes).unwrap();

        let state = StateDbManager::new(storage.clone());
        let mut per_block = Vec::new();
        for block in 1..=3u64 {
            per_block.push(commit_block_with_receipts(&state, block, 2));
        }

        // Ham `block_0` varken bile bu çağrı Err dönmemeli (deserialize hatası yok).
        let deleted = state
            .prune_historical_data(3, 10_000)
            .expect("ham block_0 satiri budamayi ARTIK cokertmemeli");
        assert_eq!(deleted, 4, "blok 1 ve 2'nin 2'ser dekontu silinmeliydi");

        for tx_id in per_block[0].iter().chain(per_block[1].iter()) {
            assert!(!receipt_exists(&state, tx_id), "eski dekont silinmeliydi");
        }
        for tx_id in &per_block[2] {
            assert!(receipt_exists(&state, tx_id), "guncel dekont korunmaliydi");
        }

        // Genesis'e DOKUNULMAMIŞ olmalı: zincir kimliginin capasi ve blok 1'in
        // parent_hash'i bu baytlardan tureiyor (bkz. zagros-runtime).
        assert_eq!(
            storage.get(b"block_0").unwrap(),
            Some(genesis_bytes),
            "genesis block_0 ASLA budanmamali"
        );
    }

    #[test]
    fn pruning_is_a_noop_when_nothing_is_old_enough() {
        let storage = Arc::new(MemoryStorage::default());
        let state = StateDbManager::new(storage);
        for block in 1..=3u64 {
            commit_block_with_receipts(&state, block, 2);
        }
        // prune_before_block=0 => hiçbir blok yeterince eski değil.
        assert_eq!(state.prune_historical_data(0, 1000).unwrap(), 0);
    }
}
