//! RocksDB checkpoint tabanlı snapshot: `create_snapshot` etrafında operatör
//! katmanı (metadata, listeleme, geri yükleme). `restore_snapshot` yalnız dosya
//! kopyasıdır, canlı geri yükleme yoktur; node ÇALIŞMIYORKEN ayrı alt komutla çağrılır.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zagros_primitives::{Result, ZagrosError};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotMetadata {
    /// Sıralanabilir kimlik, `format!("{:020}_{}", block_height, unix_secs)`
    /// deseninde, `list_snapshots`'ın JSON içeriğine bakmadan dosya adına göre
    /// kronolojik sıralayabilmesi için blok yüksekliği sıfır-dolgulu.
    pub id: String,
    pub created_at_unix_secs: u64,
    pub block_height: u128,
    pub chain_id: u64,
    /// R5: snapshot anındaki state_root (hex, `0x` önekli). Geri yükleme
    /// sonrası doğrulama (`verify_restored_snapshot`) bunu kullanır.
    pub state_root_hex: String,
}

/// `id`'ye karşılık gelen snapshot dizininin tam yolu.
pub fn snapshot_dir_for(root: &Path, id: &str) -> PathBuf {
    root.join(id)
}

/// Blok yüksekliği + zaman damgasından sıralanabilir bir snapshot kimliği üretir.
pub fn make_snapshot_id(block_height: u128, unix_secs: u64) -> String {
    format!("{:020}_{}", block_height, unix_secs)
}

fn metadata_path(snapshot_dir: &Path) -> PathBuf {
    snapshot_dir.join("metadata.json")
}

/// Bir snapshot dizininin YANINA (checkpoint'in kendisiyle KARIŞMAYAN, ayrı
/// bir `metadata.json` dosyasına) metadata yazar. `create_checkpoint`
/// BAŞARILI olduktan SONRA çağrılmalı, checkpoint yarım kalırsa metadata da
/// hiç yazılmamış olur (tutarlı hata durumu).
pub fn write_metadata(snapshot_dir: &Path, meta: &SnapshotMetadata) -> Result<()> {
    let json = serde_json::to_string_pretty(meta).map_err(|e| {
        ZagrosError::DatabaseError(format!("Snapshot metadata serileştirilemedi: {}", e))
    })?;
    std::fs::write(metadata_path(snapshot_dir), json)
        .map_err(|e| ZagrosError::DatabaseError(format!("Snapshot metadata yazılamadı: {}", e)))
}

pub fn read_metadata(snapshot_dir: &Path) -> Result<SnapshotMetadata> {
    let content = std::fs::read_to_string(metadata_path(snapshot_dir))
        .map_err(|e| ZagrosError::DatabaseError(format!("Snapshot metadata okunamadı: {}", e)))?;
    serde_json::from_str(&content)
        .map_err(|e| ZagrosError::DatabaseError(format!("Snapshot metadata bozuk: {}", e)))
}

/// `root` altındaki tüm snapshot'ları, kimliğe göre (dolayısıyla kronolojik
/// olarak) sıralı döner. `root` hiç yoksa boş liste döner (henüz hiç
/// snapshot alınmamış, hata değil).
pub fn list_snapshots(root: &Path) -> Result<Vec<SnapshotMetadata>> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut entries = Vec::new();
    let read_dir = std::fs::read_dir(root)
        .map_err(|e| ZagrosError::DatabaseError(format!("Snapshot kök dizini okunamadı: {}", e)))?;
    for entry in read_dir {
        let entry = entry
            .map_err(|e| ZagrosError::DatabaseError(format!("Dizin girdisi okunamadı: {}", e)))?;
        let path = entry.path();
        if path.is_dir() && metadata_path(&path).exists() {
            entries.push(read_metadata(&path)?);
        }
    }
    entries.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(entries)
}

/// Checkpoint'i `target_data_dir`e kopyalar; hedef önceden var olmamalı (çalışan
/// node'un dizini asla ezilmez). DB açmaz; çağıran kopyadan sonra `open*` çağırır.
pub fn restore_snapshot(snapshot_path: &Path, target_data_dir: &Path) -> Result<()> {
    if target_data_dir.exists() {
        return Err(ZagrosError::DatabaseError(format!(
            "Hedef veri dizini zaten var ({}) - restore, çalışan/mevcut bir DB'nin \
             üzerine ASLA yazılmamalı. Önce hedefi taşıyın/kaldırın ya da farklı bir \
             hedef belirtin.",
            target_data_dir.display()
        )));
    }
    if !snapshot_path.exists() {
        return Err(ZagrosError::DatabaseError(format!(
            "Snapshot dizini bulunamadı: {}",
            snapshot_path.display()
        )));
    }
    copy_dir_recursive(snapshot_path, target_data_dir)
}

/// En yeni `keep_last_n` snapshot'ı bırakıp eskileri siler (otomatik snapshot
/// görevinin yanında; yoksa disk sınırsız birikir). Silinemeyen dizin atlanır, budama durmaz.
pub fn prune_old_snapshots(root: &Path, keep_last_n: usize) -> Result<usize> {
    let snapshots = list_snapshots(root)?;
    if snapshots.len() <= keep_last_n {
        return Ok(0);
    }
    let excess = snapshots.len() - keep_last_n;
    let mut removed = 0;
    for meta in &snapshots[..excess] {
        let dir = snapshot_dir_for(root, &meta.id);
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => removed += 1,
            Err(e) => {
                tracing::warn!(
                    "⚠️ Eski snapshot silinemedi ({}), atlanıyor: {}",
                    dir.display(),
                    e
                );
            }
        }
    }
    Ok(removed)
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)
        .map_err(|e| ZagrosError::DatabaseError(format!("Hedef dizin oluşturulamadı: {}", e)))?;
    let read_dir = std::fs::read_dir(src)
        .map_err(|e| ZagrosError::DatabaseError(format!("Kaynak dizin okunamadı: {}", e)))?;
    for entry in read_dir {
        let entry = entry
            .map_err(|e| ZagrosError::DatabaseError(format!("Dizin girdisi okunamadı: {}", e)))?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        let file_type = entry
            .file_type()
            .map_err(|e| ZagrosError::DatabaseError(format!("Dosya türü okunamadı: {}", e)))?;
        if file_type.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path).map_err(|e| {
                ZagrosError::DatabaseError(format!(
                    "Dosya kopyalanamadı ({} -> {}): {}",
                    src_path.display(),
                    dst_path.display(),
                    e
                ))
            })?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_metadata(id: &str) -> SnapshotMetadata {
        SnapshotMetadata {
            id: id.to_string(),
            created_at_unix_secs: 1_700_000_000,
            block_height: 42,
            chain_id: 21072026,
            state_root_hex: "0xabc123".to_string(),
        }
    }

    #[test]
    fn write_metadata_round_trips_through_json() {
        let dir = tempfile::tempdir().unwrap();
        let snapshot_dir = dir.path().join("snap1");
        std::fs::create_dir_all(&snapshot_dir).unwrap();
        let meta = sample_metadata("00000000000000000042_1700000000");
        write_metadata(&snapshot_dir, &meta).unwrap();

        let read_back = read_metadata(&snapshot_dir).unwrap();
        assert_eq!(read_back, meta);
    }

    #[test]
    fn list_snapshots_returns_metadata_sorted_by_id() {
        let root = tempfile::tempdir().unwrap();
        for (height, secs) in [
            (100u128, 1_700_000_100u64),
            (5, 1_700_000_005),
            (50, 1_700_000_050),
        ] {
            let id = make_snapshot_id(height, secs);
            let dir = snapshot_dir_for(root.path(), &id);
            std::fs::create_dir_all(&dir).unwrap();
            let mut meta = sample_metadata(&id);
            meta.block_height = height;
            write_metadata(&dir, &meta).unwrap();
        }

        let listed = list_snapshots(root.path()).unwrap();
        let heights: Vec<u128> = listed.iter().map(|m| m.block_height).collect();
        assert_eq!(
            heights,
            vec![5, 50, 100],
            "artan blok yüksekliğine göre sıralı olmalı"
        );
    }

    #[test]
    fn list_snapshots_returns_empty_for_a_root_that_does_not_exist_yet() {
        let root = tempfile::tempdir().unwrap();
        let nonexistent = root.path().join("never-created");
        assert_eq!(list_snapshots(&nonexistent).unwrap(), Vec::new());
    }

    #[test]
    fn restore_snapshot_refuses_to_overwrite_an_existing_target_dir() {
        let snapshot_src = tempfile::tempdir().unwrap();
        std::fs::write(snapshot_src.path().join("CURRENT"), b"fake sst marker").unwrap();

        let target_root = tempfile::tempdir().unwrap();
        let target = target_root.path().join("already-exists");
        std::fs::create_dir_all(&target).unwrap();

        let result = restore_snapshot(snapshot_src.path(), &target);
        assert!(
            result.is_err(),
            "var olan bir hedefin üzerine yazmaya izin verilmemeli"
        );
    }

    #[test]
    fn prune_old_snapshots_keeps_only_the_newest_n() {
        let root = tempfile::tempdir().unwrap();
        for (height, secs) in [
            (10u128, 1_700_000_010u64),
            (20, 1_700_000_020),
            (30, 1_700_000_030),
            (40, 1_700_000_040),
        ] {
            let id = make_snapshot_id(height, secs);
            let dir = snapshot_dir_for(root.path(), &id);
            std::fs::create_dir_all(&dir).unwrap();
            let mut meta = sample_metadata(&id);
            meta.block_height = height;
            write_metadata(&dir, &meta).unwrap();
        }

        let removed = prune_old_snapshots(root.path(), 2).unwrap();
        assert_eq!(removed, 2, "4 snapshot'tan en eski 2'si silinmeli");

        let remaining = list_snapshots(root.path()).unwrap();
        let heights: Vec<u128> = remaining.iter().map(|m| m.block_height).collect();
        assert_eq!(heights, vec![30, 40], "sadece en yeni 2 snapshot kalmalı");
    }

    #[test]
    fn prune_old_snapshots_is_a_noop_when_under_the_retention_limit() {
        let root = tempfile::tempdir().unwrap();
        let id = make_snapshot_id(10, 1_700_000_010);
        let dir = snapshot_dir_for(root.path(), &id);
        std::fs::create_dir_all(&dir).unwrap();
        write_metadata(&dir, &sample_metadata(&id)).unwrap();

        let removed = prune_old_snapshots(root.path(), 5).unwrap();
        assert_eq!(removed, 0);
        assert_eq!(list_snapshots(root.path()).unwrap().len(), 1);
    }

    #[test]
    fn restore_snapshot_then_open_reproduces_original_data() {
        use crate::rocksdb_impl::RocksDbStorage;
        use crate::Storage;

        let source_dir = tempfile::tempdir().unwrap();
        let storage = RocksDbStorage::open(source_dir.path()).unwrap();
        storage.put(b"restore_key", b"restore_value").unwrap();

        let snapshot_root = tempfile::tempdir().unwrap();
        let snapshot_path = snapshot_root.path().join("snap_for_restore");
        storage.create_snapshot(&snapshot_path).unwrap();

        let restore_root = tempfile::tempdir().unwrap();
        let restored_target = restore_root.path().join("restored-data");
        restore_snapshot(&snapshot_path, &restored_target).unwrap();

        let reopened = RocksDbStorage::open(&restored_target).unwrap();
        assert_eq!(
            reopened.get(b"restore_key").unwrap(),
            Some(b"restore_value".to_vec())
        );
    }
}
