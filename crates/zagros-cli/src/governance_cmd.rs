//! `zagros-cli governance repair-active-count`: `__ACTIVE_PROPOSAL_COUNT__`
//! sayacını tüm `Proposal_*` kayıtlarını tarayarak yeniden hesaplayan kurtarma
//! aracı. 🚨 O(n) tam tarama, yalnız operatör tetiklemeli; normal yol lazy artış/azalışa güvenir.

use std::sync::Arc;
use zagros_state::manager::StateDbManager;
use zagros_state::State;
use zagros_storage::rocksdb_impl::RocksDbStorage;
use zagros_storage::Storage;
use zagros_types::config::ZagrosConfig;
use zagros_types::{effective_status, Proposal, ProposalStatus};

pub fn repair_active_count(config_path: &str) -> Result<(), String> {
    let config = ZagrosConfig::from_file(config_path)
        .map_err(|e| format!("{} okunamadı: {}", config_path, e))?;
    let storage = RocksDbStorage::open_with_recovery(&config.storage.db_path)
        .map_err(|e| format!("RocksDB açılamadı: {}", e))?;
    let state = StateDbManager::new(Arc::new(storage.clone()));

    let now_secs = std::time::UNIX_EPOCH
        .elapsed()
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let all_keys = storage
        .list_keys()
        .map_err(|e| format!("Anahtarlar listelenemedi: {}", e))?;

    let mut active_count: u128 = 0;
    let mut scanned = 0usize;
    let mut corrupt = 0usize;
    for key_bytes in all_keys {
        if !key_bytes.starts_with(b"Proposal_") {
            continue;
        }
        let key = match String::from_utf8(key_bytes) {
            Ok(k) => k,
            Err(_) => continue,
        };
        scanned += 1;

        let account = match state.get_account(&key) {
            Ok(Some(account)) if !account.contract_code.is_empty() => account,
            _ => continue,
        };
        let proposal = match Proposal::deserialize_with_migration(&account.contract_code) {
            Ok(p) => p,
            Err(_) => {
                corrupt += 1;
                continue;
            }
        };
        let status = effective_status(
            &proposal,
            now_secs,
            config.governance.voting_period_secs,
            config.governance.proposal_expiry_secs,
        );
        if !matches!(status, ProposalStatus::Archived | ProposalStatus::Executed) {
            active_count += 1;
        }
    }

    let mut counter_account = state
        .get_account(&zagros_executor::Executor::ACTIVE_PROPOSAL_COUNT_KEY.to_string())
        .map_err(|e| e.to_string())?
        .unwrap_or_default();
    let previous_value = counter_account.balance;
    counter_account.balance = active_count;
    state
        .set_account(
            &zagros_executor::Executor::ACTIVE_PROPOSAL_COUNT_KEY.to_string(),
            counter_account,
        )
        .map_err(|e| format!("Sayaç diske yazılamadı: {}", e))?;
    // 🚨 `set_account` yalnız cache'i günceller, RocksDB yazımı `flush()`a kadar
    // ertelenir; kısa ömürlü CLI flush çağırmadan çıkarsa düzeltme sessizce no-op olur.
    state
        .flush()
        .map_err(|e| format!("Düzeltme diske yazılamadı (flush başarısız): {}", e))?;

    println!(
        "✅ governance repair-active-count tamamlandı.\n\
         \u{20}  taranan Proposal_* kayıt sayısı: {}\n\
         \u{20}  bozuk/okunamayan kayıt sayısı: {}\n\
         \u{20}  önceki __ACTIVE_PROPOSAL_COUNT__: {}\n\
         \u{20}  yeni (doğru) __ACTIVE_PROPOSAL_COUNT__: {}",
        scanned, corrupt, previous_value, active_count
    );
    if corrupt > 0 {
        println!(
            "⚠️  {} kayıt deserialize edilemedi (bozuk olabilir) - manuel inceleme önerilir.",
            corrupt
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_test_config(config_path: &std::path::Path, db_path: &std::path::Path) {
        let mut config = ZagrosConfig::default();
        config.bridge.allow_insecure_default_authorities = true;
        config.storage.db_path = db_path.to_string_lossy().to_string();
        config.to_file(config_path).unwrap();
    }

    // 🚨 Regresyon: düzeltme gerçekten diske ulaşmalı; storage kapatılıp sıfırdan
    // açılarak doğrulanır (aynı instance'ta cache-first okuma bug'ı yakalamaz).
    #[test]
    fn repair_active_count_survives_reopening_the_storage_from_scratch() {
        let root = tempfile::tempdir().unwrap();
        let config_path = root.path().join("config.toml");
        let db_path = root.path().join("zagros-data/state");
        write_test_config(&config_path, &db_path);
        let config_path_str = config_path.to_string_lossy().to_string();

        // Bozuk/yanlış bir sayaç + SIFIR gerçek Proposal_* kaydı ile başla,
        // doğru sonuç 0 olmalı, mevcut (yanlış) değer 999.
        {
            let storage = RocksDbStorage::open_with_recovery(&db_path).unwrap();
            let state = StateDbManager::new(Arc::new(storage));
            state
                .set_account(
                    &zagros_executor::Executor::ACTIVE_PROPOSAL_COUNT_KEY.to_string(),
                    zagros_types::AccountState {
                        balance: 999,
                        ..Default::default()
                    },
                )
                .unwrap();
            state.flush().unwrap();
        }

        repair_active_count(&config_path_str).expect("repair başarısız olmamalı");

        // Storage'ı TAMAMEN kapat, sıfırdan aç, cache'e değil, gerçekten
        // diske ulaşıp ulaşmadığını kanıtlar.
        let reopened_storage = RocksDbStorage::open_with_recovery(&db_path).unwrap();
        let reopened_state = StateDbManager::new(Arc::new(reopened_storage));
        let counter = reopened_state
            .get_account(&zagros_executor::Executor::ACTIVE_PROPOSAL_COUNT_KEY.to_string())
            .unwrap()
            .expect("sayaç hesabı hiç yazılmamış");
        assert_eq!(
            counter.balance, 0,
            "duzeltme yeniden acilan (gercek) storage'a ULASMAMIS - flush() calismamis olmali"
        );
    }
}
