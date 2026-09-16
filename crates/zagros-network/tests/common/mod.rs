//! Entegrasyon testleri arasında paylaşılan yardımcılar; `tests/common/mod.rs`
//! deseni Cargo'nun "her dosya ayrı ikili" kuralından muaf.

use portable_atomic::AtomicU128;
use secp256k1::SecretKey;
use std::sync::Arc;
use zagros_executor::Executor;
use zagros_mempool::Mempool;
use zagros_runtime::Runtime;
use zagros_scheduler::Scheduler;
use zagros_state::{manager::StateDbManager, State};
use zagros_types::config::NetworkConfig;
use zagros_types::{GasCalculator, Transaction, TxType, CHAIN_ID};

pub fn test_secret_key(seed: u8) -> SecretKey {
    SecretKey::from_slice(&[seed; 32]).unwrap()
}

pub fn test_address(seed: u8) -> String {
    Transaction::address_from_secret_key(&test_secret_key(seed))
}

/// 🛡️ Native `tx.sign()` `gas_limit`/`gas_price`ı da imzalar (RPC yolunun EIP-155
/// dalından farklı); mempool'un uygulayacağı ücret imzadan ÖNCE aynı fonksiyonla
/// kilitlenir ki `admit_transaction` içindeki çağrı no-op olsun.
/// 🚨 `timestamp` blok damgasına yakın (≤300) verilmeli; yoksa tx iki node'da
/// aynı sessiz reddedilir ve state_root testleri yanıltıcı yeşil verir.
pub fn signed_transfer(mempool: &Mempool, seed: u8, nonce: u64, timestamp: u128) -> Transaction {
    let mut tx = Transaction {
        tx_id: [seed; 32],
        tx_type: TxType::Transfer,
        sender: test_address(seed),
        receiver: "0x0000000000000000000000000000000000000002".to_string(),
        amount: 1,
        payload: Vec::new(),
        signature: Vec::new(),
        timestamp,
        nonce,
        gas_limit: 21_000,
        gas_price: 1,
        chain_id: CHAIN_ID,
    };
    mempool.apply_fixed_gas_fee(&mut tx);
    tx.sign(&test_secret_key(seed));
    tx
}

pub fn lenient_gas_calculator() -> Arc<GasCalculator> {
    Arc::new(GasCalculator::new(
        Arc::new(AtomicU128::new(1)),
        Arc::new(AtomicU128::new(1_000_000_000_000_000)),
    ))
}

/// Bir test node'unun tüm bileşenleri, `Mempool` (tx-gossip için) ve
/// `Runtime` (blok-gossip/`apply_external_block` için) AYNI `state`'i
/// paylaşır, tıpkı gerçek `zagros-cli`'de olduğu gibi.
pub struct TestNode {
    pub mempool: Arc<Mempool>,
    pub runtime: Arc<Runtime>,
    // `tx_gossip.rs` bunu okumuyor (sadece mempool/runtime ilgili), sadece
    // `block_gossip.rs`'in state_root karşılaştırması için var. Paylaşılan bir
    // test yardımcısı olduğu için her iki ikili dosyanın ayrı derlemesinde
    // "kullanılmıyor" uyarısı almasın diye.
    #[allow(dead_code)]
    pub state: Arc<dyn State>,
    _tmp: tempfile::TempDir,
}

pub fn test_node() -> TestNode {
    let tmp = tempfile::tempdir().unwrap();
    let storage = Arc::new(
        zagros_storage::rocksdb_impl::RocksDbStorage::open(tmp.path().to_str().unwrap()).unwrap(),
    );
    let state: Arc<dyn State> = Arc::new(StateDbManager::new(storage));
    state.add_balance(&test_address(1), 1_000_000_000).unwrap();

    let mempool = Arc::new(Mempool::new(state.clone(), lenient_gas_calculator()));
    let executor = Arc::new(Executor::new(state.clone()));
    let scheduler = Arc::new(Scheduler::new(executor.clone()));
    let runtime = Arc::new(Runtime::new(state.clone(), executor, scheduler));

    TestNode {
        mempool,
        runtime,
        state,
        _tmp: tmp,
    }
}

pub fn test_network_config(port: u16, bootstrap: Vec<String>) -> NetworkConfig {
    NetworkConfig {
        listen_addr: format!("/ip4/127.0.0.1/tcp/{port}"),
        bootstrap_nodes: bootstrap,
        max_peers: 50,
        enable_p2p: true,
        network_id: CHAIN_ID,
        is_proposer: false,
        consensus_key_path: None,
        trusted_checkpoint: None,
        node_key_path: String::new(), // bu testte kullanılmıyor, kimlik doğrudan üretiliyor
        evidence_log_path: String::new(),
        mdns_enabled: false,
        sync_batch_size: 500,
        sentry_mode: false,
        private_peers: Vec::new(),
        external_addr: None,
        sentry_addrs: Vec::new(),
        max_peers_per_ip: 4,
        reserved_validator_slots: 32,
    }
}
