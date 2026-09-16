use zagros_primitives::Result;

pub mod rocksdb_impl;
pub mod snapshot;

/// Storage Trait: Sistemin en alt katmanı.
/// Verinin ne olduğuyla ilgilenmez, sadece byte olarak okur ve yazar.
pub trait Storage: Send + Sync {
    /// Verilen anahtara (key) ait veriyi getirir
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>>;

    /// Verilen anahtara (key) veriyi (value) yazar
    fn put(&self, key: &[u8], value: &[u8]) -> Result<()>;

    /// Verilen anahtarı veritabanından siler
    fn delete(&self, key: &[u8]) -> Result<()>;

    /// Verilen anahtarın veritabanında olup olmadığını kontrol eder
    fn contains(&self, key: &[u8]) -> Result<bool>;
    /// Kayıtlı tüm anahtarları döner.
    fn list_keys(&self) -> Result<Vec<Vec<u8>>>;
}

// 1. EVRENSEL DEPOLAMA ARAYÜZÜ (STORAGE API)
pub trait StorageEngine: Storage {
    fn write_batch(&self, kvs: &[(Vec<u8>, Option<Vec<u8>>)]) -> Result<()>;

    // WAL (Write-Ahead Log) hooks: default no-ops so implementors that rely on
    // their underlying store's own durability (e.g. RocksDB's internal WAL,
    // already enabled by default) don't need a redundant hand-rolled one.
    fn append_wal(&self, _data: &[u8]) -> Result<()> {
        Ok(())
    }
    fn clear_wal(&self) -> Result<()> {
        Ok(())
    }
}
