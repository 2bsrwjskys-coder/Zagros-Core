pub mod engine;

use std::sync::Arc;
use tracing::info;
use zagros_primitives::{BlockNumber, Result};
use zagros_runtime::Runtime;
use zagros_types::Transaction;

// DPoS KONSENSÜS MOTORU
pub struct ConsensusEngine {
    runtime: Arc<Runtime>,
    current_block: BlockNumber,
}

impl ConsensusEngine {
    pub fn new(runtime: Arc<Runtime>) -> Self {
        // 🚨 KALICI değerden devam: koşulsuz 0'dan başlamak ("Genesis'ten
        // başlar") node yeniden başlatıldığında diske yazılmış gerçek blok
        // yüksekliğini YOK SAYIP `__GLOBAL_BLOCK_HEIGHT__`'ı 1'e geri sarardı
        // (bkz. Runtime::current_block_height ve set_block_height).
        let current_block = runtime.current_block_height().unwrap_or(0) as BlockNumber;
        Self {
            runtime,
            current_block,
        }
    }

    /// Bir grup işlemi alır ve yeni bir blok üretir.
    pub fn produce_block(&mut self, transactions: Vec<Transaction>, timestamp: u128) -> Result<()> {
        self.current_block += 1;
        info!(
            "🧱 Blok #{} üretimi için düğmeye basıldı...",
            self.current_block
        );

        // process_block now sets the block height and flushes state itself,
        // as one atomic unit with the block's transaction effects.
        let state_root =
            self.runtime
                .process_block(self.current_block, timestamp, &transactions)?;

        info!(
            "✅ Blok #{} Konsensüs tarafından mühürlendi! Mühür: 0x{}",
            self.current_block,
            hex::encode(state_root)
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use zagros_executor::Executor;
    use zagros_scheduler::Scheduler;
    use zagros_state::State;
    use zagros_storage::{Storage, StorageEngine};

    #[derive(Default)]
    struct MemoryStorage {
        values: Mutex<HashMap<Vec<u8>, Vec<u8>>>,
    }

    impl Storage for MemoryStorage {
        fn get(&self, key: &[u8]) -> zagros_primitives::Result<Option<Vec<u8>>> {
            Ok(self.values.lock().unwrap().get(key).cloned())
        }
        fn put(&self, key: &[u8], value: &[u8]) -> zagros_primitives::Result<()> {
            self.values
                .lock()
                .unwrap()
                .insert(key.to_vec(), value.to_vec());
            Ok(())
        }
        fn delete(&self, key: &[u8]) -> zagros_primitives::Result<()> {
            self.values.lock().unwrap().remove(key);
            Ok(())
        }
        fn contains(&self, key: &[u8]) -> zagros_primitives::Result<bool> {
            Ok(self.values.lock().unwrap().contains_key(key))
        }
        fn list_keys(&self) -> zagros_primitives::Result<Vec<Vec<u8>>> {
            Ok(self.values.lock().unwrap().keys().cloned().collect())
        }
    }

    impl StorageEngine for MemoryStorage {
        fn write_batch(&self, kvs: &[(Vec<u8>, Option<Vec<u8>>)]) -> zagros_primitives::Result<()> {
            let mut values = self.values.lock().unwrap();
            for (key, value) in kvs {
                match value {
                    Some(v) => {
                        values.insert(key.clone(), v.clone());
                    }
                    None => {
                        values.remove(key);
                    }
                }
            }
            Ok(())
        }
    }

    fn test_runtime() -> (Arc<zagros_state::manager::StateDbManager>, Arc<Runtime>) {
        let state = Arc::new(zagros_state::manager::StateDbManager::new(Arc::new(
            MemoryStorage::default(),
        )));
        let executor = Arc::new(Executor::new(state.clone()));
        let scheduler = Arc::new(Scheduler::new(executor.clone()));
        let runtime = Arc::new(Runtime::new(state.clone(), executor, scheduler));
        (state, runtime)
    }

    // 🚨 Regresyon: `ConsensusEngine::new` 0'dan başlasa her restart diskteki
    // yüksekliği geri sarardı; aynı state üzerinde yeni motor önceki yükseklikten devam etmeli.
    #[test]
    fn new_consensus_engine_resumes_from_the_persisted_block_height_not_zero() {
        let (state, runtime) = test_runtime();

        // Önceki bir "oturumun" zaten blok #5'e kadar ilerlediğini simüle et.
        runtime.set_block_height(5).unwrap();
        assert_eq!(runtime.current_block_height().unwrap(), 5);

        // "Restart": aynı kalıcı state üzerinde YENİ bir ConsensusEngine.
        let mut engine_after_restart = ConsensusEngine::new(runtime.clone());
        assert_eq!(
            engine_after_restart.current_block, 5,
            "restart sonrasi ConsensusEngine kalici yukseklikten (5) DEVAM etmeli, 0'dan degil"
        );

        // Bir sonraki blok #6 olmali, 1'e "geri sarilmamali".
        engine_after_restart.produce_block(vec![], 1_000).unwrap();
        assert_eq!(
            state
                .get_account(&"__GLOBAL_BLOCK_HEIGHT__".to_string())
                .unwrap()
                .unwrap()
                .balance,
            6,
            "restart sonrasi ilk blok #6 olmali (onceki 5'in devami), 1 DEGIL"
        );
    }

    #[test]
    fn brand_new_chain_still_starts_from_block_1() {
        let (_state, runtime) = test_runtime();
        let mut engine = ConsensusEngine::new(runtime.clone());
        assert_eq!(engine.current_block, 0);

        engine.produce_block(vec![], 1_000).unwrap();
        assert_eq!(runtime.current_block_height().unwrap(), 1);
    }
}
