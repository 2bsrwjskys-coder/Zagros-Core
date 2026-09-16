//! Phase 0 baseline benchmark: measures real `Runtime::process_block` throughput
//! for a batch of independent, validly-signed Transfer transactions, using the
//! actual production stack (RocksDbStorage + StateDbManager + Executor + Runtime).
//! Usage: cargo run --release -p zagros-tests --bin bench_block -- [tx_count]

use std::sync::Arc;
use std::time::Instant;

use secp256k1::SecretKey;
use zagros_executor::Executor;
use zagros_runtime::Runtime;
use zagros_scheduler::Scheduler;
use zagros_state::manager::StateDbManager;
use zagros_state::State;
use zagros_storage::rocksdb_impl::RocksDbStorage;
use zagros_types::{AccountState, Transaction, TxType, CHAIN_ID, TOKEN_DECIMAL};

fn secret_key(seed: u64) -> SecretKey {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&seed.to_be_bytes());
    SecretKey::from_slice(&bytes).expect("seed produces a valid secp256k1 scalar")
}

fn address_for_seed(seed: u64) -> zagros_types::Address {
    Transaction::address_from_secret_key(&secret_key(seed))
}

/// Her işlemin kendi sender ve receiver'ı var (kümeler çakışmaz) ki scheduler
/// hepsini bağımsız saysın; tek ortak alıcı her şeyi doğru biçimde serileştirirdi.
fn signed_transfer(sender_seed: u64, tx_count: u64, timestamp: u128) -> Transaction {
    let key = secret_key(sender_seed);
    let sender = Transaction::address_from_secret_key(&key);
    let receiver = address_for_seed(tx_count + sender_seed);

    let mut tx_id = [0u8; 32];
    tx_id[0..8].copy_from_slice(&sender_seed.to_be_bytes());

    let mut tx = Transaction {
        tx_id,
        tx_type: TxType::Transfer,
        sender,
        amount: 1,
        receiver,
        payload: Vec::new(),
        signature: Vec::new(),
        timestamp,
        nonce: 0,
        gas_limit: 21_000,
        gas_price: 1,
        chain_id: CHAIN_ID,
    };
    tx.sign(&key);
    tx
}

fn main() {
    let tx_count: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(5_000);

    let data_dir = tempfile::tempdir().expect("failed to create temp dir for bench storage");
    let storage = Arc::new(RocksDbStorage::open(data_dir.path()).expect("failed to open storage"));
    let state: Arc<dyn State> = Arc::new(StateDbManager::new(storage));
    let executor = Arc::new(Executor::new(state.clone()));
    let scheduler = Arc::new(Scheduler::new(executor.clone()));
    let runtime = Runtime::new(state.clone(), executor, scheduler);

    let block_timestamp: u128 = 1_000_000;

    println!("Funding {} sender accounts...", tx_count);
    let fund_start = Instant::now();
    let mut transactions = Vec::with_capacity(tx_count as usize);
    for seed in 1..=tx_count {
        state
            .set_account(
                &address_for_seed(seed),
                AccountState::new(1_000 * TOKEN_DECIMAL),
            )
            .expect("failed to fund account");
        transactions.push(signed_transfer(seed, tx_count, block_timestamp));
    }
    println!("Funded in {:?}", fund_start.elapsed());

    println!("Processing block of {} transactions...", tx_count);
    let start = Instant::now();
    let state_root = runtime
        .process_block(1, block_timestamp, &transactions)
        .expect("process_block failed");
    let elapsed = start.elapsed();

    let tps = tx_count as f64 / elapsed.as_secs_f64();
    println!(
        "Processed {} txs in {:?} => {:.0} TPS (state_root=0x{})",
        tx_count,
        elapsed,
        tps,
        hex::encode(state_root)
    );
}
