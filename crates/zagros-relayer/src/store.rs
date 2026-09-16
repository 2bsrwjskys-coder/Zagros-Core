// Relayer kalıcı durumu (Storage trait üzerinden): idempotency (hangi Ethereum
// tx / Zagros burn zaten öneriye dönüştü) ve üstel geri çekilmeli retry kuyruğu.

use rand::Rng;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use zagros_primitives::Result as ZResult;
use zagros_storage::Storage;

const IDEM_ETH_PREFIX: &str = "idem:eth:";
const IDEM_ZAGROS_BURN_PREFIX: &str = "idem:zagros_burn:";
const IDEM_UNLOCK_SUBMITTED_PREFIX: &str = "idem:unlock_submitted:";
const RETRY_PREFIX: &str = "retry:";
/// item 13: kalıcı olarak vazgeçilen (max deneme sayısını aşan) yeniden
/// deneme girdilerinin gittiği isim alanı, operatör incelemesi için
/// SAKLANIR, sessizce SİLİNMEZ.
const DEAD_LETTER_PREFIX: &str = "deadletter:";
/// Burn tarama imleci KALICI: her restart'ta 0'a dönseydi sunucu eski burn'leri
/// budadığından imleç kalıcı CursorGapError'a takılıp çekim yönü dururdu.
const OUTBOUND_CURSOR_KEY: &str = "outbound_cursor";
/// Ethereum tarafı olay taramasının kalıcı imleci, `OUTBOUND_CURSOR_KEY`'in
/// giriş yönü eşleniği. Yalnız bellekte tutulup her restart'ta `None`'a (yani
/// config'teki `start_block`'a) sıfırlanması idempotent olduğu için GÜVENLİ
/// ama zincir yaşlandıkça maliyeti artan bir tam yeniden tarama olurdu.
const INBOUND_CURSOR_KEY: &str = "inbound_cursor";
/// item 11: bu özellikten ÖNCE yazılmış (undated) idempotency kayıtlarının
/// tek-seferlik yeniden-yazım göçünün tamamlandığını işaretleyen sentinel.
const IDEM_MIGRATION_KEY: &str = "__MIGRATION_IdempotencyMarkerBackfill__";

const RETRY_BASE_DELAY_SECS: u64 = 5;
const RETRY_MAX_DELAY_SECS: u64 = 3600;
/// Bu kadar başarısız denemeden sonra girdi "ölü mektup" olur; üstel geri
/// çekilmeyle (5 sn taban, 3600 sn tavan) saatlerce denenmiş demektir.
const MAX_RETRY_ATTEMPTS: u32 = 10;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RetryEntry {
    pub id: String,
    pub attempt: u32,
    pub next_attempt_at: u64,
    /// Opak, çağıranın tanımladığı veri (örn. bincode/JSON ile serileştirilmiş
    /// bir "bekleyen mint önerisi" ya da "bekleyen unlock gönderimi" komutu).
    pub payload: Vec<u8>,
}

/// item 13: `reschedule_retry`'nin sonucu, girdi yeniden zamanlandı mı yoksa
/// max deneme sayısını aşıp dead-letter'a mı taşındı.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryOutcome {
    Rescheduled,
    DeadLettered,
}

/// Idempotency değerlerinin şekli: ham bayt (`[1u8]` ya da proposal_id)
/// yerine ne zaman işaretlendiği de (saklama süresi hesaplanabilsin diye) tutulur.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct IdempotencyMarker {
    created_at_unix_secs: u64,
    /// Eski değer (`eth_key` için proposal_id, `burn_key`/`unlock_key` için
    /// boş/`[1u8]`), göç sırasında AYNEN korunur, anlamı değişmez.
    payload: Vec<u8>,
}

pub struct RelayerStore {
    storage: Arc<dyn Storage>,
}

impl RelayerStore {
    pub fn new(storage: Arc<dyn Storage>) -> Self {
        Self { storage }
    }

    // Idempotency: Ethereum yatırma (deposit) -> Zagros mint önerisi

    pub fn is_ethereum_deposit_handled(&self, eth_tx_hash: &str) -> ZResult<bool> {
        self.storage.contains(Self::eth_key(eth_tx_hash).as_bytes())
    }

    pub fn mark_ethereum_deposit_handled(
        &self,
        eth_tx_hash: &str,
        proposal_id: &[u8; 32],
    ) -> ZResult<()> {
        self.put_marker(&Self::eth_key(eth_tx_hash), proposal_id.to_vec())
    }

    fn eth_key(eth_tx_hash: &str) -> String {
        format!("{}{}", IDEM_ETH_PREFIX, eth_tx_hash.to_ascii_lowercase())
    }

    // Idempotency: Zagros burn -> Ethereum unlock (off-chain M-of-N öneri)

    pub fn is_zagros_burn_handled(&self, burn_tx_id: &[u8; 32]) -> ZResult<bool> {
        self.storage.contains(Self::burn_key(burn_tx_id).as_bytes())
    }

    pub fn mark_zagros_burn_handled(&self, burn_tx_id: &[u8; 32]) -> ZResult<()> {
        self.put_marker(&Self::burn_key(burn_tx_id), Vec::new())
    }

    fn burn_key(burn_tx_id: &[u8; 32]) -> String {
        format!("{}{}", IDEM_ZAGROS_BURN_PREFIX, hex::encode(burn_tx_id))
    }

    // Idempotency: öneri → Ethereum gönderimi, burn → öneri katmanından AYRI
    // işaret (restart sonrası aynı öneri için ikinci gönderim olmasın).

    pub fn is_unlock_submitted(&self, proposal_id_hex: &str) -> ZResult<bool> {
        self.storage
            .contains(Self::unlock_key(proposal_id_hex).as_bytes())
    }

    pub fn mark_unlock_submitted(&self, proposal_id_hex: &str) -> ZResult<()> {
        self.put_marker(&Self::unlock_key(proposal_id_hex), Vec::new())
    }

    fn unlock_key(proposal_id_hex: &str) -> String {
        format!(
            "{}{}",
            IDEM_UNLOCK_SUBMITTED_PREFIX,
            proposal_id_hex
                .trim_start_matches("0x")
                .to_ascii_lowercase()
        )
    }

    // item 11: idempotency saklama politikası (retention)

    fn put_marker(&self, key: &str, payload: Vec<u8>) -> ZResult<()> {
        let marker = IdempotencyMarker {
            created_at_unix_secs: crate::now_unix_secs(),
            payload,
        };
        let bytes = bincode::serialize(&marker).unwrap_or_default();
        self.storage.put(key.as_bytes(), &bytes)
    }

    fn is_idempotency_key(key: &str) -> bool {
        key.starts_with(IDEM_ETH_PREFIX)
            || key.starts_with(IDEM_ZAGROS_BURN_PREFIX)
            || key.starts_with(IDEM_UNLOCK_SUBMITTED_PREFIX)
    }

    /// `retention_secs`ten eski `IdempotencyMarker`ları siler; eski şekilli
    /// değerler ASLA silinmez (replay korumasını zayıflatmamak için; göç ayrı).
    pub fn prune_expired_idempotency_markers(
        &self,
        now: u64,
        retention_secs: u64,
    ) -> ZResult<usize> {
        let mut pruned = 0usize;
        for key in self.storage.list_keys()? {
            let key_str = String::from_utf8_lossy(&key).to_string();
            if !Self::is_idempotency_key(&key_str) {
                continue;
            }
            let Some(bytes) = self.storage.get(&key)? else {
                continue;
            };
            let Ok(marker) = bincode::deserialize::<IdempotencyMarker>(&bytes) else {
                continue; // eski/undated - dokunma.
            };
            if now.saturating_sub(marker.created_at_unix_secs) > retention_secs {
                self.storage.delete(&key)?;
                pruned += 1;
            }
        }
        Ok(pruned)
    }

    /// Eski ham bayt idempotency değerlerini `IdempotencyMarker`a TEK SEFERLİK
    /// yazar (sentinel ile sonraki çalıştırmalarda no-op); böylece her kayıt budanabilir olur.
    pub fn migrate_legacy_idempotency_markers(&self) -> ZResult<usize> {
        if self.storage.contains(IDEM_MIGRATION_KEY.as_bytes())? {
            return Ok(0);
        }
        let mut migrated = 0usize;
        for key in self.storage.list_keys()? {
            let key_str = String::from_utf8_lossy(&key).to_string();
            if !Self::is_idempotency_key(&key_str) {
                continue;
            }
            let Some(bytes) = self.storage.get(&key)? else {
                continue;
            };
            if bincode::deserialize::<IdempotencyMarker>(&bytes).is_ok() {
                continue; // zaten yeni şekil.
            }
            // Eski ham değer, AYNEN `payload` olarak sar, anlamı değişmez.
            self.put_marker(&key_str, bytes)?;
            migrated += 1;
        }
        self.storage.put(IDEM_MIGRATION_KEY.as_bytes(), &[1u8])?;
        Ok(migrated)
    }

    // Retry kuyruğu (üstel geri çekilme + jitter + dead-letter, item 13)

    /// Yeni bir yeniden deneme girdisi ekler, `attempt=0`, hemen (`now`)
    /// çalışmaya hazır.
    pub fn enqueue_retry(&self, id: &str, payload: Vec<u8>, now: u64) -> ZResult<()> {
        let entry = RetryEntry {
            id: id.to_string(),
            attempt: 0,
            next_attempt_at: now,
            payload,
        };
        self.save_retry(&entry)
    }

    /// `next_attempt_at <= now` olan tüm girdileri döner (sıraya göre değil,
    /// tarama sırasına göre, çağıran sırayı önemsemeli işlemeli).
    pub fn due_retries(&self, now: u64) -> ZResult<Vec<RetryEntry>> {
        let mut due = Vec::new();
        for key in self.storage.list_keys()? {
            let key_str = String::from_utf8_lossy(&key);
            if !key_str.starts_with(RETRY_PREFIX) {
                continue;
            }
            if let Some(bytes) = self.storage.get(&key)? {
                if let Ok(entry) = bincode::deserialize::<RetryEntry>(&bytes) {
                    if entry.next_attempt_at <= now {
                        due.push(entry);
                    }
                }
            }
        }
        Ok(due)
    }

    /// Bir denemenin başarısız olduğunu işaretler: deneme sayacını artırır,
    /// bir sonraki denemeyi üstel geri çekilme + ±%20 jitter'la (taban 5s,
    /// tavan 1 saat) zamanlar. `MAX_RETRY_ATTEMPTS`'i aşarsa girdi dead-letter'a
    /// taşınır (sonsuz yeniden deneme YOK), `RetryOutcome::DeadLettered` döner.
    pub fn reschedule_retry(&self, entry: &RetryEntry, now: u64) -> ZResult<RetryOutcome> {
        let next_attempt = entry.attempt + 1;
        if next_attempt >= MAX_RETRY_ATTEMPTS {
            self.move_to_dead_letter(entry)?;
            return Ok(RetryOutcome::DeadLettered);
        }
        let base_delay = RETRY_BASE_DELAY_SECS
            .saturating_mul(1u64.checked_shl(next_attempt).unwrap_or(u64::MAX))
            .min(RETRY_MAX_DELAY_SECS);
        // ±%20 jitter, eşzamanlı yeniden denemelerin "thundering herd"
        // oluşturmasını önler (birden çok başarısız girdi AYNI anda tekrar
        // denenmesin).
        let jitter_range = (base_delay / 5).max(1) as i64;
        let jitter: i64 = rand::thread_rng().gen_range(-jitter_range..=jitter_range);
        let delay = (base_delay as i64 + jitter).max(RETRY_BASE_DELAY_SECS as i64) as u64;
        let updated = RetryEntry {
            id: entry.id.clone(),
            attempt: next_attempt,
            next_attempt_at: now + delay,
            payload: entry.payload.clone(),
        };
        self.save_retry(&updated)?;
        Ok(RetryOutcome::Rescheduled)
    }

    /// Başarılı bir denemeden sonra kuyruktan kaldırır.
    pub fn remove_retry(&self, id: &str) -> ZResult<()> {
        self.storage.delete(Self::retry_key(id).as_bytes())
    }

    /// item 13: max deneme sayısını aşan bir girdiyi aktif kuyruktan çıkarıp
    /// `deadletter:` isim alanına taşır, SESSİZCE KAYBOLMAZ, operatör
    /// `list_dead_letters` ile inceleyebilir.
    fn move_to_dead_letter(&self, entry: &RetryEntry) -> ZResult<()> {
        let bytes = bincode::serialize(entry).unwrap_or_default();
        self.storage
            .put(Self::dead_letter_key(&entry.id).as_bytes(), &bytes)?;
        self.storage.delete(Self::retry_key(&entry.id).as_bytes())
    }

    /// Operatör görünürlüğü için: dead-letter'a taşınmış TÜM girdileri döner.
    pub fn list_dead_letters(&self) -> ZResult<Vec<RetryEntry>> {
        let mut entries = Vec::new();
        for key in self.storage.list_keys()? {
            let key_str = String::from_utf8_lossy(&key);
            if !key_str.starts_with(DEAD_LETTER_PREFIX) {
                continue;
            }
            if let Some(bytes) = self.storage.get(&key)? {
                if let Ok(entry) = bincode::deserialize::<RetryEntry>(&bytes) {
                    entries.push(entry);
                }
            }
        }
        Ok(entries)
    }

    fn save_retry(&self, entry: &RetryEntry) -> ZResult<()> {
        let bytes = bincode::serialize(entry).unwrap_or_default();
        self.storage
            .put(Self::retry_key(&entry.id).as_bytes(), &bytes)
    }

    fn retry_key(id: &str) -> String {
        format!("{}{}", RETRY_PREFIX, id)
    }

    fn dead_letter_key(id: &str) -> String {
        format!("{}{}", DEAD_LETTER_PREFIX, id)
    }

    // Outbound tarama imleci (Zagros burn -> unlock-intent) kalıcılığı

    /// Kalıcı imleci okur; hiç kaydedilmemişse (ilk çalıştırma) ya da
    /// bozuksa 0'dan başlar, `due_retries`'in bozuk girdileri sessizce
    /// atlayan davranışıyla AYNI, bu dosyaya özgü yerleşik kural.
    pub fn get_outbound_cursor(&self) -> ZResult<u128> {
        match self.storage.get(OUTBOUND_CURSOR_KEY.as_bytes())? {
            Some(bytes) => Ok(bincode::deserialize::<u128>(&bytes).unwrap_or(0)),
            None => Ok(0),
        }
    }

    /// İmleci kalıcı hale getirir, SADECE başarıyla işlenmiş bir tarama
    /// turundan sonra çağrılmalı (bkz. outbound.rs::poll_once). Başarısız/
    /// cursor-gap turları bu fonksiyonu hiç çağırmaz, imleç olduğu yerde kalır.
    pub fn set_outbound_cursor(&self, cursor: u128) -> ZResult<()> {
        let bytes = bincode::serialize(&cursor).unwrap_or_default();
        self.storage.put(OUTBOUND_CURSOR_KEY.as_bytes(), &bytes)
    }

    // item 12: Inbound (Ethereum event) tarama imleci kalıcılığı

    /// `outbound_cursor`'ın aksine varsayılan olarak `0` DEĞİL `None` döner:
    /// "hiç tarama yapılmadı" (yeni relayer, `start_block`'tan başlamalı) ile
    /// "blok 0'a kadar tarandı" ANLAMCA FARKLI, burada `0` güvenli bir
    /// varsayılan değil.
    pub fn get_inbound_cursor(&self) -> ZResult<Option<u64>> {
        match self.storage.get(INBOUND_CURSOR_KEY.as_bytes())? {
            Some(bytes) => Ok(bincode::deserialize::<u64>(&bytes).ok()),
            None => Ok(None),
        }
    }

    /// SADECE başarıyla işlenmiş bir tarama turundan sonra çağrılmalı,
    /// `set_outbound_cursor`'ın giriş-yönü eşleniği, AYNI "sadece başarıda
    /// kalıcı hale getir" sözleşmesi.
    pub fn set_inbound_cursor(&self, cursor: u64) -> ZResult<()> {
        let bytes = bincode::serialize(&cursor).unwrap_or_default();
        self.storage.put(INBOUND_CURSOR_KEY.as_bytes(), &bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Default)]
    struct MemoryStorage {
        values: Mutex<HashMap<Vec<u8>, Vec<u8>>>,
    }

    impl Storage for MemoryStorage {
        fn get(&self, key: &[u8]) -> ZResult<Option<Vec<u8>>> {
            Ok(self.values.lock().unwrap().get(key).cloned())
        }
        fn put(&self, key: &[u8], value: &[u8]) -> ZResult<()> {
            self.values
                .lock()
                .unwrap()
                .insert(key.to_vec(), value.to_vec());
            Ok(())
        }
        fn delete(&self, key: &[u8]) -> ZResult<()> {
            self.values.lock().unwrap().remove(key);
            Ok(())
        }
        fn contains(&self, key: &[u8]) -> ZResult<bool> {
            Ok(self.values.lock().unwrap().contains_key(key))
        }
        fn list_keys(&self) -> ZResult<Vec<Vec<u8>>> {
            Ok(self.values.lock().unwrap().keys().cloned().collect())
        }
    }

    fn test_store() -> RelayerStore {
        RelayerStore::new(Arc::new(MemoryStorage::default()))
    }

    #[test]
    fn ethereum_deposit_idempotency_round_trips() {
        let store = test_store();
        let tx_hash = "0xabc123";
        assert!(!store.is_ethereum_deposit_handled(tx_hash).unwrap());

        store
            .mark_ethereum_deposit_handled(tx_hash, &[7u8; 32])
            .unwrap();
        assert!(store.is_ethereum_deposit_handled(tx_hash).unwrap());

        // Case-insensitivity, Ethereum tx hashes are often mixed-case.
        assert!(store.is_ethereum_deposit_handled("0xABC123").unwrap());
    }

    #[test]
    fn zagros_burn_idempotency_round_trips() {
        let store = test_store();
        let burn_id = [9u8; 32];
        assert!(!store.is_zagros_burn_handled(&burn_id).unwrap());

        store.mark_zagros_burn_handled(&burn_id).unwrap();
        assert!(store.is_zagros_burn_handled(&burn_id).unwrap());
    }

    #[test]
    fn a_processed_event_is_never_double_handled() {
        // Simulates the scenario the whole store exists for: the same
        // Ethereum event observed twice (e.g. after a relayer restart before
        // it caught up) must only ever be turned into one mint attempt.
        let store = test_store();
        let tx_hash = "0xdouble";

        let first_seen = !store.is_ethereum_deposit_handled(tx_hash).unwrap();
        if first_seen {
            store
                .mark_ethereum_deposit_handled(tx_hash, &[1u8; 32])
                .unwrap();
        }
        let second_seen = !store.is_ethereum_deposit_handled(tx_hash).unwrap();

        assert!(
            first_seen,
            "first observation should not be pre-marked handled"
        );
        assert!(
            !second_seen,
            "second observation of the same event must be recognized as already handled"
        );
    }

    #[test]
    fn retry_queue_returns_only_due_entries() {
        let store = test_store();
        store
            .enqueue_retry("a", b"payload-a".to_vec(), 100)
            .unwrap();
        store
            .enqueue_retry("b", b"payload-b".to_vec(), 200)
            .unwrap();

        let due_at_100 = store.due_retries(100).unwrap();
        assert_eq!(due_at_100.len(), 1);
        assert_eq!(due_at_100[0].id, "a");

        let due_at_200 = store.due_retries(200).unwrap();
        assert_eq!(due_at_200.len(), 2);
    }

    #[test]
    fn reschedule_applies_exponential_backoff_and_caps_at_max_delay() {
        let store = test_store();
        store.enqueue_retry("x", vec![], 0).unwrap();
        let entry = store.due_retries(0).unwrap().into_iter().next().unwrap();
        assert_eq!(entry.attempt, 0);

        // attempt 0 -> 1: taban gecikme = 5 * 2^1 = 10s, ±%20 jitter'la (item
        // 13) [8, 12] aralığında, RETRY_BASE_DELAY_SECS(5)'in altına asla
        // düşmez.
        let outcome = store.reschedule_retry(&entry, 0).unwrap();
        assert_eq!(outcome, RetryOutcome::Rescheduled);
        let after_first = store
            .due_retries(u64::MAX)
            .unwrap()
            .into_iter()
            .find(|e| e.id == "x")
            .unwrap();
        assert_eq!(after_first.attempt, 1);
        assert!(after_first.next_attempt_at >= RETRY_BASE_DELAY_SECS);
        assert!(after_first.next_attempt_at <= 12);

        // Sonraki birkaç yeniden deneme (MAX_RETRY_ATTEMPTS=10'un ALTINDA
        // kalarak, dead-letter geçişi ayrı testte), tavanı (3600s) asla
        // aşmamalı.
        let mut current = after_first;
        for _ in 0..7 {
            let outcome = store.reschedule_retry(&current, 0).unwrap();
            assert_eq!(outcome, RetryOutcome::Rescheduled);
            current = store
                .due_retries(u64::MAX)
                .unwrap()
                .into_iter()
                .find(|e| e.id == "x")
                .unwrap();
            assert!(current.next_attempt_at <= RETRY_MAX_DELAY_SECS + RETRY_MAX_DELAY_SECS / 5);
        }
    }

    #[test]
    fn reschedule_retry_moves_entry_to_dead_letter_after_max_attempts() {
        let store = test_store();
        store.enqueue_retry("give-up", vec![42], 0).unwrap();
        let mut entry = store.due_retries(0).unwrap().into_iter().next().unwrap();

        let mut last_outcome = RetryOutcome::Rescheduled;
        for _ in 0..MAX_RETRY_ATTEMPTS {
            last_outcome = store.reschedule_retry(&entry, 0).unwrap();
            if last_outcome == RetryOutcome::DeadLettered {
                break;
            }
            entry = store
                .due_retries(u64::MAX)
                .unwrap()
                .into_iter()
                .find(|e| e.id == "give-up")
                .unwrap();
        }
        assert_eq!(last_outcome, RetryOutcome::DeadLettered);
    }

    #[test]
    fn dead_lettered_entries_are_removed_from_the_active_retry_queue() {
        let store = test_store();
        store.enqueue_retry("give-up-2", vec![], 0).unwrap();
        let mut entry = store.due_retries(0).unwrap().into_iter().next().unwrap();
        for _ in 0..MAX_RETRY_ATTEMPTS {
            if store.reschedule_retry(&entry, 0).unwrap() == RetryOutcome::DeadLettered {
                break;
            }
            entry = store
                .due_retries(u64::MAX)
                .unwrap()
                .into_iter()
                .find(|e| e.id == "give-up-2")
                .unwrap();
        }
        assert!(store
            .due_retries(u64::MAX)
            .unwrap()
            .iter()
            .all(|e| e.id != "give-up-2"));
    }

    #[test]
    fn list_dead_letters_returns_previously_dead_lettered_entries() {
        let store = test_store();
        store.enqueue_retry("give-up-3", vec![7, 8, 9], 0).unwrap();
        let mut entry = store.due_retries(0).unwrap().into_iter().next().unwrap();
        for _ in 0..MAX_RETRY_ATTEMPTS {
            if store.reschedule_retry(&entry, 0).unwrap() == RetryOutcome::DeadLettered {
                break;
            }
            entry = store
                .due_retries(u64::MAX)
                .unwrap()
                .into_iter()
                .find(|e| e.id == "give-up-3")
                .unwrap();
        }
        let dead_letters = store.list_dead_letters().unwrap();
        assert_eq!(dead_letters.len(), 1);
        assert_eq!(dead_letters[0].id, "give-up-3");
        assert_eq!(dead_letters[0].payload, vec![7, 8, 9]);
    }

    #[test]
    fn reschedule_retry_applies_jitter_within_expected_bounds() {
        let store = test_store();
        for i in 0..20 {
            store
                .enqueue_retry(&format!("jitter-{}", i), vec![], 0)
                .unwrap();
        }
        for i in 0..20 {
            let entry = store
                .due_retries(0)
                .unwrap()
                .into_iter()
                .find(|e| e.id == format!("jitter-{}", i))
                .unwrap();
            store.reschedule_retry(&entry, 0).unwrap();
            let updated = store
                .due_retries(u64::MAX)
                .unwrap()
                .into_iter()
                .find(|e| e.id == format!("jitter-{}", i))
                .unwrap();
            // taban=10s, ±%20 jitter => [8, 12], taban gecikmenin altına asla düşmez (5s).
            assert!(updated.next_attempt_at >= RETRY_BASE_DELAY_SECS);
            assert!(updated.next_attempt_at <= 12);
        }
    }

    #[test]
    fn remove_retry_takes_the_entry_out_of_the_queue() {
        let store = test_store();
        store.enqueue_retry("done", vec![], 0).unwrap();
        assert_eq!(store.due_retries(0).unwrap().len(), 1);

        store.remove_retry("done").unwrap();
        assert!(store.due_retries(0).unwrap().is_empty());
    }

    #[test]
    fn outbound_cursor_defaults_to_zero_then_persists_across_reads() {
        let store = test_store();
        assert_eq!(store.get_outbound_cursor().unwrap(), 0);

        store.set_outbound_cursor(5_000).unwrap();
        assert_eq!(store.get_outbound_cursor().unwrap(), 5_000);

        // Restart simülasyonu: aynı alttaki storage'ı yeni bir RelayerStore
        // ile "yeniden aç", imleç kaybolmamalı.
        let reopened = RelayerStore::new(store.storage.clone());
        assert_eq!(reopened.get_outbound_cursor().unwrap(), 5_000);
    }

    #[test]
    fn unlock_submission_idempotency_round_trips_and_is_case_insensitive() {
        let store = test_store();
        let proposal_id = "0xABCDEF";
        assert!(!store.is_unlock_submitted(proposal_id).unwrap());

        store.mark_unlock_submitted(proposal_id).unwrap();
        assert!(store.is_unlock_submitted(proposal_id).unwrap());
        assert!(store.is_unlock_submitted("0xabcdef").unwrap());
    }

    // item 12: Inbound cursor kalıcılığı

    #[test]
    fn inbound_cursor_defaults_to_none_then_persists_across_reads() {
        let store = test_store();
        assert_eq!(store.get_inbound_cursor().unwrap(), None);

        store.set_inbound_cursor(12_345).unwrap();
        assert_eq!(store.get_inbound_cursor().unwrap(), Some(12_345));

        let reopened = RelayerStore::new(store.storage.clone());
        assert_eq!(reopened.get_inbound_cursor().unwrap(), Some(12_345));
    }

    // item 11: idempotency saklama politikası (retention)

    #[test]
    fn idempotency_markers_now_carry_a_created_at_timestamp() {
        let store = test_store();
        store
            .mark_ethereum_deposit_handled("0xabc", &[1u8; 32])
            .unwrap();
        let bytes = store
            .storage
            .get(RelayerStore::eth_key("0xabc").as_bytes())
            .unwrap()
            .unwrap();
        let marker: IdempotencyMarker = bincode::deserialize(&bytes).unwrap();
        assert!(marker.created_at_unix_secs > 0);
        assert_eq!(marker.payload, vec![1u8; 32]);
    }

    #[test]
    fn is_ethereum_deposit_handled_is_unaffected_by_the_value_shape_change() {
        // `is_*_handled` `Storage::contains`'e dayanır (saf varlık kontrolü,
        // değeri deserialize ETMEZ), bu yüzden hem eski (ham bayt) hem yeni
        // (`IdempotencyMarker`) şekildeki değerler için AYNI şekilde çalışmalı.
        let store = test_store();
        // Eski (item-11-öncesi) ham değer, doğrudan storage'a yaz.
        store
            .storage
            .put(RelayerStore::eth_key("0xlegacy").as_bytes(), &[9u8; 32])
            .unwrap();
        assert!(store.is_ethereum_deposit_handled("0xlegacy").unwrap());

        store
            .mark_ethereum_deposit_handled("0xnew", &[1u8; 32])
            .unwrap();
        assert!(store.is_ethereum_deposit_handled("0xnew").unwrap());
    }

    #[test]
    fn prune_expired_idempotency_markers_removes_only_entries_older_than_retention() {
        let store = test_store();
        store
            .mark_ethereum_deposit_handled("0xold", &[1u8; 32])
            .unwrap();
        store
            .mark_ethereum_deposit_handled("0xfresh", &[2u8; 32])
            .unwrap();

        // "0xold"'u yapay olarak yaşlandır.
        let old_key = RelayerStore::eth_key("0xold");
        let old_marker = IdempotencyMarker {
            created_at_unix_secs: 1_000,
            payload: vec![1u8; 32],
        };
        store
            .storage
            .put(
                old_key.as_bytes(),
                &bincode::serialize(&old_marker).unwrap(),
            )
            .unwrap();

        let now = 1_000 + 40 * 86_400; // 40 gün sonra
        let pruned = store
            .prune_expired_idempotency_markers(now, 30 * 86_400)
            .unwrap();
        assert_eq!(pruned, 1);
        assert!(!store.is_ethereum_deposit_handled("0xold").unwrap());
        assert!(store.is_ethereum_deposit_handled("0xfresh").unwrap());
    }

    #[test]
    fn prune_expired_idempotency_markers_never_deletes_an_undated_legacy_style_marker() {
        let store = test_store();
        // Ham bayt (item-11-öncesi) değer doğrudan yaz, `IdempotencyMarker`
        // olarak DESERIALIZE OLMAZ.
        store
            .storage
            .put(RelayerStore::eth_key("0xlegacy").as_bytes(), &[5u8; 32])
            .unwrap();

        let pruned = store
            .prune_expired_idempotency_markers(u64::MAX, 0)
            .unwrap();
        assert_eq!(pruned, 0, "tarihsiz eski bir kayıt ASLA silinmemeli");
        assert!(store.is_ethereum_deposit_handled("0xlegacy").unwrap());
    }

    #[test]
    fn legacy_marker_migration_upgrades_old_values_to_timestamped_markers_exactly_once() {
        let store = test_store();
        store
            .storage
            .put(RelayerStore::eth_key("0xlegacy").as_bytes(), &[5u8; 32])
            .unwrap();

        let migrated_first = store.migrate_legacy_idempotency_markers().unwrap();
        assert_eq!(migrated_first, 1);
        let bytes = store
            .storage
            .get(RelayerStore::eth_key("0xlegacy").as_bytes())
            .unwrap()
            .unwrap();
        let marker: IdempotencyMarker = bincode::deserialize(&bytes).unwrap();
        assert_eq!(marker.payload, vec![5u8; 32]);

        // İkinci çağrı sentinel yüzünden no-op olmalı.
        let migrated_second = store.migrate_legacy_idempotency_markers().unwrap();
        assert_eq!(migrated_second, 0);
        assert!(store.is_ethereum_deposit_handled("0xlegacy").unwrap());
    }
}
