use crate::{Storage, StorageEngine};
use rocksdb::{BlockBasedOptions, Cache, DBCompressionType, Options, WriteBatch, DB};
use std::path::Path;
use std::sync::Arc;
use zagros_primitives::{Result, ZagrosError};

/// RocksDB üretim ayarları; `0`/`0.0`/`false` = RocksDB varsayılanı, `default()`
/// bugünkü davranışla birebir aynı. Yalnız `zagros-cli` üretim açılışı gerçek ayarları kullanır.
#[derive(Debug, Clone, Default)]
pub struct RocksDbTuningOptions {
    /// LRU blok önbelleği boyutu (MB). `0` = ayarlama (RocksDB'nin küçük
    /// dahili varsayılanı kalır). `config.storage.cache_size_mb`'a bağlanır.
    pub block_cache_mb: usize,
    /// `0` = ayarlama.
    pub write_buffer_size_mb: usize,
    /// `0` = ayarlama.
    pub max_write_buffer_number: i32,
    /// `0` = ayarlama.
    pub target_file_size_base_mb: u64,
    /// `0` = ayarlama (RocksDB'nin kendi varsayılanı: sınırsıza yakın, OS
    /// limitine tabi).
    pub max_open_files: i32,
    /// `0.0` = bloom filtresi eklenmez.
    pub bloom_filter_bits_per_key: f64,
    /// İstatistik toplama, varsayılan `false` (toplamanın kendi maliyeti var).
    pub enable_statistics: bool,
    /// `0` = ayarlama.
    pub max_background_jobs: i32,
}

/// RocksDB tabanlı fiziksel depolama katmanı.
/// Sadece byte'ları bilir, ZAGROS bakiyelerinden haberi yoktur.
#[derive(Clone)]
pub struct RocksDbStorage {
    db: Arc<DB>,
}

impl RocksDbStorage {
    fn build_options(tuning: &RocksDbTuningOptions) -> Options {
        let mut opts = Options::default();
        opts.create_if_missing(true);

        // Bu ikisi tuning alanlarından BAĞIMSIZ, her zaman açık: zstd zaten
        // derlenmiş bir varsayılan özellik (Cargo.toml değişikliği gerekmedi),
        // ve level-compaction'ı dinamik-boyutlu yapmak salt bir compaction-
        // şekli iyileştirmesi, doğruluk üzerinde hiçbir etkisi yok.
        opts.set_compression_type(DBCompressionType::Zstd);
        opts.set_level_compaction_dynamic_level_bytes(true);

        if tuning.write_buffer_size_mb > 0 {
            opts.set_write_buffer_size(tuning.write_buffer_size_mb * 1024 * 1024);
        }
        if tuning.max_write_buffer_number > 0 {
            opts.set_max_write_buffer_number(tuning.max_write_buffer_number);
        }
        if tuning.target_file_size_base_mb > 0 {
            opts.set_target_file_size_base(tuning.target_file_size_base_mb * 1024 * 1024);
        }
        if tuning.max_open_files > 0 {
            opts.set_max_open_files(tuning.max_open_files);
        }
        if tuning.max_background_jobs > 0 {
            opts.set_max_background_jobs(tuning.max_background_jobs);
        }
        if tuning.enable_statistics {
            opts.enable_statistics();
        }

        if tuning.block_cache_mb > 0 || tuning.bloom_filter_bits_per_key > 0.0 {
            let mut block_opts = BlockBasedOptions::default();
            if tuning.block_cache_mb > 0 {
                let cache = Cache::new_lru_cache(tuning.block_cache_mb * 1024 * 1024);
                block_opts.set_block_cache(&cache);
                block_opts.set_cache_index_and_filter_blocks(true);
                block_opts.set_pin_l0_filter_and_index_blocks_in_cache(true);
            }
            if tuning.bloom_filter_bits_per_key > 0.0 {
                block_opts.set_bloom_filter(tuning.bloom_filter_bits_per_key, false);
            }
            opts.set_block_based_table_factory(&block_opts);
        }

        opts
    }

    /// Yeni bir RocksDB bağlantısı açar (varsayılan tuning, bugünkü
    /// davranışla birebir aynı, `create_if_missing(true)` dışında hiçbir şey
    /// ayarlanmaz).
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::open_with_tuning(path, &RocksDbTuningOptions::default())
    }

    /// `open`'ın tuning-farkında hâli, üretim açılışının (`zagros-cli`)
    /// kullandığı gerçek yol.
    pub fn open_with_tuning<P: AsRef<Path>>(
        path: P,
        tuning: &RocksDbTuningOptions,
    ) -> Result<Self> {
        let opts = Self::build_options(tuning);
        let db = DB::open(&opts, path.as_ref())
            .map_err(|e| ZagrosError::DatabaseError(format!("RocksDB açılamadı: {}", e)))?;

        Ok(Self { db: Arc::new(db) })
    }

    /// `open` başarısızsa (bozuk WAL/SST) `DB::repair` deneyip tekrar açar; o da
    /// olmazsa orijinal hata döner, çağıran panic değil kontrollü kapanmalı.
    pub fn open_with_recovery<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::open_with_recovery_and_tuning(path, &RocksDbTuningOptions::default())
    }

    /// `open_with_recovery`'nin tuning-farkında hâli.
    pub fn open_with_recovery_and_tuning<P: AsRef<Path>>(
        path: P,
        tuning: &RocksDbTuningOptions,
    ) -> Result<Self> {
        match Self::open_with_tuning(path.as_ref(), tuning) {
            Ok(storage) => Ok(storage),
            Err(open_err) => {
                tracing::warn!(
                    "⚠️ RocksDB açılamadı ({}), onarım deneniyor: {}",
                    path.as_ref().display(),
                    open_err
                );
                let mut opts = Options::default();
                opts.create_if_missing(true);
                DB::repair(&opts, path.as_ref()).map_err(|repair_err| {
                    ZagrosError::DatabaseError(format!(
                        "RocksDB açılamadı ve onarım da başarısız oldu: açılış hatası={}, onarım hatası={}",
                        open_err, repair_err
                    ))
                })?;
                tracing::info!("✅ RocksDB onarımı başarılı, yeniden açılıyor.");
                Self::open_with_tuning(path.as_ref(), tuning)
            }
        }
    }

    /// Çalışan DB'nin RocksDB checkpoint'ini (hardlink'li SST anlık görüntüsü)
    /// `path`e yazar; `path` önceden var olmamalı. Snapshot bağımsız açılabilir dizindir.
    pub fn create_snapshot<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let checkpoint = rocksdb::checkpoint::Checkpoint::new(&self.db).map_err(|e| {
            ZagrosError::DatabaseError(format!("Checkpoint objesi oluşturulamadı: {}", e))
        })?;
        checkpoint
            .create_checkpoint(path.as_ref())
            .map_err(|e| ZagrosError::DatabaseError(format!("Snapshot oluşturulamadı: {}", e)))
    }
}

// 🛡️ İşte o geçilmez duvar: Storage Trait implementasyonu!
impl Storage for RocksDbStorage {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.db
            .get(key)
            .map_err(|e| ZagrosError::DatabaseError(format!("Okuma hatası: {}", e)))
    }

    fn put(&self, key: &[u8], value: &[u8]) -> Result<()> {
        self.db
            .put(key, value)
            .map_err(|e| ZagrosError::DatabaseError(format!("Yazma hatası: {}", e)))
    }

    fn delete(&self, key: &[u8]) -> Result<()> {
        self.db
            .delete(key)
            .map_err(|e| ZagrosError::DatabaseError(format!("Silme hatası: {}", e)))
    }

    fn contains(&self, key: &[u8]) -> Result<bool> {
        // RocksDB'de key_may_exist her zaman kesin sonuç vermez, bu yüzden get ile kontrol ediyoruz.
        let result = self
            .db
            .get(key)
            .map_err(|e| ZagrosError::DatabaseError(format!("Contains hatası: {}", e)))?;
        Ok(result.is_some())
    }

    fn list_keys(&self) -> Result<Vec<Vec<u8>>> {
        use rocksdb::IteratorMode;

        let mut keys = Vec::new();
        let iter = self.db.iterator(IteratorMode::Start);
        for item in iter {
            let (key, _) =
                item.map_err(|e| ZagrosError::DatabaseError(format!("Iterator hatası: {}", e)))?;
            keys.push(key.to_vec());
        }
        Ok(keys)
    }
}

// Toplu yazım: bloğun tüm değişiklikleri tek atomik `write_batch` (tek üretim yolu).
// 🛡️ Dayanıklılık: varsayılan `WriteOptions` WAL'ı fsync etmez (OS çökmesinde
// son bloklar kaybolabilir); `set_sync(true)` blok başına bir fsync ile kaybı
// kapatır, committed bloğun kalıcılığı gecikmeden önemli.
impl StorageEngine for RocksDbStorage {
    fn write_batch(&self, kvs: &[(Vec<u8>, Option<Vec<u8>>)]) -> Result<()> {
        let mut batch = WriteBatch::default();
        for (key, value) in kvs {
            match value {
                Some(value) => batch.put(key, value),
                None => batch.delete(key),
            }
        }
        let mut write_opts = rocksdb::WriteOptions::default();
        write_opts.set_sync(true);
        self.db
            .write_opt(batch, &write_opts)
            .map_err(|e| ZagrosError::DatabaseError(format!("Toplu yazma hatası: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_with_recovery_behaves_like_open_on_a_fresh_directory() {
        let dir = tempfile::tempdir().unwrap();
        let storage = RocksDbStorage::open_with_recovery(dir.path()).unwrap();
        storage.put(b"k", b"v").unwrap();
        assert_eq!(storage.get(b"k").unwrap(), Some(b"v".to_vec()));
    }

    /// `open` başarısız olduğunda (burada: hedef yolda RocksDB'nin dizin
    /// oluşturamayacağı bir DÜZ DOSYA önceden var), `DB::repair` de aynı
    /// nedenle başarısız olur, bu durumda fonksiyon panic ETMEMELİ, temiz
    /// bir `Err` dönmeli (main.rs'teki `?` ile kontrollü kapanışın dayanağı).
    #[test]
    fn open_with_recovery_returns_err_instead_of_panicking_when_unrecoverable() {
        let dir = tempfile::tempdir().unwrap();
        let blocked_path = dir.path().join("blocked-by-a-file");
        std::fs::write(&blocked_path, b"not a rocksdb directory").unwrap();

        let result = RocksDbStorage::open_with_recovery(&blocked_path);
        assert!(result.is_err());
    }

    // items 6+7: RocksDB production tuning

    #[test]
    fn default_tuning_options_produce_byte_identical_behavior_to_plain_open() {
        // `RocksDbTuningOptions::default()` bugünkü ("sadece create_if_missing")
        // davranışla AYNI olmalı, `open`/`open_with_tuning(default)` arasında
        // gözlemlenebilir bir fark olmamalı.
        let dir1 = tempfile::tempdir().unwrap();
        let via_open = RocksDbStorage::open(dir1.path()).unwrap();
        via_open.put(b"k", b"v").unwrap();
        assert_eq!(via_open.get(b"k").unwrap(), Some(b"v".to_vec()));

        let dir2 = tempfile::tempdir().unwrap();
        let via_tuning =
            RocksDbStorage::open_with_tuning(dir2.path(), &RocksDbTuningOptions::default())
                .unwrap();
        via_tuning.put(b"k", b"v").unwrap();
        assert_eq!(via_tuning.get(b"k").unwrap(), Some(b"v".to_vec()));
    }

    #[test]
    fn open_with_tuning_applies_nonzero_fields_without_erroring() {
        let dir = tempfile::tempdir().unwrap();
        let tuning = RocksDbTuningOptions {
            block_cache_mb: 8,
            write_buffer_size_mb: 4,
            max_write_buffer_number: 2,
            target_file_size_base_mb: 4,
            max_open_files: 64,
            bloom_filter_bits_per_key: 10.0,
            enable_statistics: true,
            max_background_jobs: 2,
        };
        let storage = RocksDbStorage::open_with_tuning(dir.path(), &tuning)
            .expect("tam-dolu bir tuning seti açılışı BAŞARISIZ yapmamalı");
        storage.put(b"k", b"v").unwrap();
        assert_eq!(storage.get(b"k").unwrap(), Some(b"v".to_vec()));
    }

    #[test]
    fn reopening_existing_db_with_different_tuning_preserves_existing_data() {
        let dir = tempfile::tempdir().unwrap();

        {
            let storage =
                RocksDbStorage::open_with_tuning(dir.path(), &RocksDbTuningOptions::default())
                    .unwrap();
            storage.put(b"persisted_key", b"persisted_value").unwrap();
        }

        let tuning = RocksDbTuningOptions {
            block_cache_mb: 16,
            bloom_filter_bits_per_key: 10.0,
            ..Default::default()
        };
        let reopened = RocksDbStorage::open_with_tuning(dir.path(), &tuning)
            .expect("farklı tuning ile yeniden açmak mevcut veriyi bozmamalı");
        assert_eq!(
            reopened.get(b"persisted_key").unwrap(),
            Some(b"persisted_value".to_vec())
        );
    }

    #[test]
    fn create_snapshot_produces_an_independently_openable_directory() {
        let source_dir = tempfile::tempdir().unwrap();
        let storage = RocksDbStorage::open(source_dir.path()).unwrap();
        storage.put(b"snap_key", b"snap_value").unwrap();

        let snapshot_root = tempfile::tempdir().unwrap();
        let snapshot_path = snapshot_root.path().join("snap1");
        storage.create_snapshot(&snapshot_path).unwrap();

        let reopened = RocksDbStorage::open(&snapshot_path)
            .expect("bir snapshot dizini bağımsız olarak açılabilmeli");
        assert_eq!(
            reopened.get(b"snap_key").unwrap(),
            Some(b"snap_value".to_vec()),
            "snapshot, orijinal veriyi içeren TAM ve BAĞIMSIZ bir kopya olmalı"
        );
    }
}
