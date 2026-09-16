//! item 8 - `zagros-cli snapshot create|restore|list` alt-komutlarının
//! uygulaması. Node SÜREKLİ ÇALIŞAN bir işlem değil, bu komutlar tek-seferlik,
//! node kapalıyken (create için: açık olması sorun değil ama restore ASLA
//! canlı bir veri dizinine yapılmamalı) çalıştırılmak üzere tasarlandı.

use std::path::Path;
use std::sync::Arc;
use zagros_state::manager::StateDbManager;
use zagros_state::State;
use zagros_storage::rocksdb_impl::RocksDbStorage;
use zagros_storage::snapshot::{self, SnapshotMetadata};
use zagros_types::config::ZagrosConfig;

fn load_config(config_path: &str) -> Result<ZagrosConfig, String> {
    ZagrosConfig::from_file(config_path).map_err(|e| format!("{} okunamadı: {}", config_path, e))
}

pub fn create(config_path: &str) -> Result<(), String> {
    let config = load_config(config_path)?;
    let storage = RocksDbStorage::open_with_recovery(&config.storage.db_path)
        .map_err(|e| format!("RocksDB açılamadı: {}", e))?;
    let state = StateDbManager::new(Arc::new(storage.clone()));

    let block_height = state
        .get_account(&"__GLOBAL_BLOCK_HEIGHT__".to_string())
        .map_err(|e| e.to_string())?
        .map(|a| a.balance)
        .unwrap_or(0);
    let state_root = state.state_root().map_err(|e| e.to_string())?;
    let now_secs = std::time::UNIX_EPOCH
        .elapsed()
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let id = snapshot::make_snapshot_id(block_height, now_secs);
    let snapshots_root = Path::new(&config.storage.snapshots_root);
    // RocksDB checkpoint API'si HEDEF dizinin (leaf) var OLMAMASINI ister,
    // ama onu içeren KÖK dizin (`snapshots_root`) önceden var olmalı, ilk
    // snapshot alınırken bu kök henüz hiç oluşturulmamış olabilir.
    std::fs::create_dir_all(snapshots_root)
        .map_err(|e| format!("Snapshot kök dizini oluşturulamadı: {}", e))?;
    let snapshot_dir = snapshot::snapshot_dir_for(snapshots_root, &id);

    storage
        .create_snapshot(&snapshot_dir)
        .map_err(|e| format!("Snapshot oluşturulamadı: {}", e))?;

    let meta = SnapshotMetadata {
        id: id.clone(),
        created_at_unix_secs: now_secs,
        block_height,
        chain_id: zagros_types::CHAIN_ID,
        // R5: snapshot metadata'sına state_root kesin yazılır.
        state_root_hex: format!("0x{}", hex::encode(state_root)),
    };
    snapshot::write_metadata(&snapshot_dir, &meta)
        .map_err(|e| format!("Snapshot metadata yazılamadı: {}", e))?;

    println!(
        "✅ Snapshot oluşturuldu: {}\n   dizin: {}\n   blok yüksekliği: {}\n   state_root: {}",
        id,
        snapshot_dir.display(),
        block_height,
        meta.state_root_hex
    );
    Ok(())
}

pub fn list(config_path: &str) -> Result<(), String> {
    let config = load_config(config_path)?;
    let snapshots = snapshot::list_snapshots(Path::new(&config.storage.snapshots_root))
        .map_err(|e| e.to_string())?;
    if snapshots.is_empty() {
        println!(
            "Hiç snapshot yok (kök dizin: {}).",
            config.storage.snapshots_root
        );
        return Ok(());
    }
    println!(
        "{:<28} {:>12} {:>12} {:<20} STATE_ROOT",
        "ID", "BLOK", "CHAIN_ID", "OLUŞTURULMA (unix)"
    );
    for meta in snapshots {
        println!(
            "{:<28} {:>12} {:>12} {:<20} {}",
            meta.id,
            meta.block_height,
            meta.chain_id,
            meta.created_at_unix_secs,
            meta.state_root_hex
        );
    }
    Ok(())
}

pub fn restore(snapshot_id: &str, target_data_dir: &str, config_path: &str) -> Result<(), String> {
    let config = load_config(config_path)?;
    let snapshot_dir =
        snapshot::snapshot_dir_for(Path::new(&config.storage.snapshots_root), snapshot_id);
    let meta = snapshot::read_metadata(&snapshot_dir)
        .map_err(|e| format!("Snapshot metadata okunamadı ({}): {}", snapshot_id, e))?;

    let target = Path::new(target_data_dir);
    snapshot::restore_snapshot(&snapshot_dir, target)
        .map_err(|e| format!("Restore başarısız: {}", e))?;

    // R5: geri yükleme sonrası state_root doğrulaması, snapshot'ın gerçekten
    // metadata'sında iddia ettiği state'e karşılık geldiğini doğrular.
    let storage = RocksDbStorage::open(target)
        .map_err(|e| format!("Geri yüklenen veri dizini açılamadı: {}", e))?;
    let state = StateDbManager::new(Arc::new(storage));
    let actual_root = state.state_root().map_err(|e| e.to_string())?;
    let actual_root_hex = format!("0x{}", hex::encode(actual_root));
    if actual_root_hex != meta.state_root_hex {
        return Err(format!(
            "🚨 STATE ROOT UYUŞMAZLIĞI: metadata {} bekliyordu ama geri yüklenen veri {} \
             üretiyor - snapshot BOZUK olabilir, bu veriyi node'a bağlamadan önce ARAŞTIRIN.",
            meta.state_root_hex, actual_root_hex
        ));
    }

    println!(
        "✅ Snapshot '{}' başarıyla geri yüklendi -> {}\n   blok yüksekliği: {}\n   state_root doğrulandı: {}",
        snapshot_id,
        target_data_dir,
        meta.block_height,
        actual_root_hex
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test-yerel, geçerli (validate() geçen) bir `config.toml` üretir, db_path
    /// ve snapshots_root verilen geçici dizinlerin altına yönlendirilir.
    fn write_test_config(config_path: &Path, db_path: &Path, snapshots_root: &Path) {
        let mut config = ZagrosConfig::default();
        config.bridge.allow_insecure_default_authorities = true;
        config.storage.db_path = db_path.to_string_lossy().to_string();
        config.storage.snapshots_root = snapshots_root.to_string_lossy().to_string();
        config.to_file(config_path).unwrap();
    }

    #[test]
    fn create_then_list_then_restore_round_trips_through_the_cli_commands() {
        let root = tempfile::tempdir().unwrap();
        let config_path = root.path().join("config.toml");
        let db_path = root.path().join("zagros-data/state");
        let snapshots_root = root.path().join("zagros-data/snapshots");
        write_test_config(&config_path, &db_path, &snapshots_root);
        let config_path_str = config_path.to_string_lossy().to_string();

        // Snapshot almadan önce DB'yi bir kez aç/kapat (gerçek node açılışının
        // en azından RocksDB dizinini oluşturmuş olacağı senaryoyu taklit eder).
        {
            let storage = RocksDbStorage::open(&db_path).unwrap();
            let state = StateDbManager::new(Arc::new(storage));
            state
                .set_account(&"0x1111111111111111111111111111111111111111".to_string(), {
                    let mut acc = zagros_types::AccountState::default();
                    acc.balance = 123;
                    acc
                })
                .unwrap();
            state.flush().unwrap();
        }

        create(&config_path_str).expect("snapshot create başarısız olmamalı");

        let listed = snapshot::list_snapshots(&snapshots_root).unwrap();
        assert_eq!(listed.len(), 1, "tam olarak bir snapshot listelenmeli");
        let snapshot_id = listed[0].id.clone();

        let restore_target = root.path().join("restored");
        restore(
            &snapshot_id,
            &restore_target.to_string_lossy(),
            &config_path_str,
        )
        .expect("snapshot restore (doğru state_root ile) başarısız olmamalı");

        let restored_storage = RocksDbStorage::open(&restore_target).unwrap();
        let restored_state = StateDbManager::new(Arc::new(restored_storage));
        let restored_account = restored_state
            .get_account(&"0x1111111111111111111111111111111111111111".to_string())
            .unwrap()
            .expect("geri yüklenen veri, snapshot'tan önceki hesabı içermeli");
        assert_eq!(restored_account.balance, 123);
    }

    #[test]
    fn list_reports_no_snapshots_when_none_have_been_taken_yet() {
        let root = tempfile::tempdir().unwrap();
        let config_path = root.path().join("config.toml");
        write_test_config(
            &config_path,
            &root.path().join("zagros-data/state"),
            &root.path().join("zagros-data/snapshots"),
        );
        // `list` yalnızca `println!` yapar ve `Ok(())` döner, burada asıl
        // iddia, kök dizin hiç yokken bile hata VERMEMESİ.
        list(&config_path.to_string_lossy()).expect("hiç snapshot yokken list hata vermemeli");
    }
}
