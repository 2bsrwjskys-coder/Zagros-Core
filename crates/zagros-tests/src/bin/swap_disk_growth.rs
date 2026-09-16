//! Karışık native yük (Transfer/SwapBuy) için işlem başına disk büyümesi. Tek
//! ölçüm tek seferlik LSM yükünü (WAL, ilk SST) gösterir; iki ayrı batch ile
//! "tek seferlik yük" ve "gerçek işlem maliyeti" ayrılır.
//! Kullanım: cargo run --release -p zagros-tests --bin swap_disk_growth [--batch-size N] [--transfer-ratio 0..100]

use std::sync::Arc;

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

fn signed_swap_buy(sender_seed: u64, amount: u128, timestamp: u128) -> Transaction {
    let key = secret_key(sender_seed);
    let sender = Transaction::address_from_secret_key(&key);

    let mut tx_id = [0u8; 32];
    tx_id[0..8].copy_from_slice(&sender_seed.to_be_bytes());
    tx_id[31] = 0xB7;

    let mut tx = Transaction {
        tx_id,
        tx_type: TxType::SwapBuy,
        sender: sender.clone(),
        amount,
        receiver: sender,
        payload: Vec::new(),
        signature: Vec::new(),
        timestamp,
        nonce: 0,
        gas_limit: 1,
        gas_price: 1,
        chain_id: CHAIN_ID,
    };
    tx.sign(&key);
    tx
}

fn signed_transfer(
    sender_seed: u64,
    receiver_seed: u64,
    amount: u128,
    timestamp: u128,
) -> Transaction {
    let key = secret_key(sender_seed);
    let sender = Transaction::address_from_secret_key(&key);
    let receiver = address_for_seed(receiver_seed);

    let mut tx_id = [0u8; 32];
    tx_id[0..8].copy_from_slice(&sender_seed.to_be_bytes());
    tx_id[31] = 0xC3;

    let mut tx = Transaction {
        tx_id,
        tx_type: TxType::Transfer,
        sender,
        amount,
        receiver,
        payload: Vec::new(),
        signature: Vec::new(),
        timestamp,
        nonce: 0,
        gas_limit: 1,
        gas_price: 1,
        chain_id: CHAIN_ID,
    };
    tx.sign(&key);
    tx
}

fn dir_size_bytes(path: &std::path::Path) -> u64 {
    let mut total = 0u64;
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                total += dir_size_bytes(&p);
            } else if let Ok(meta) = entry.metadata() {
                total += meta.len();
            }
        }
    }
    total
}

/// `transfer_ratio_pct`e göre Transfer/SwapBuy karışık batch kurar;
/// `sender_seed_offset` batch'ler arası göndericileri ayrık tutar (bayat nonce dersi).
fn build_mixed_batch(
    batch_size: u64,
    sender_seed_offset: u64,
    transfer_ratio_pct: u64,
    timestamp: u128,
) -> Vec<Transaction> {
    let amount = TOKEN_DECIMAL; // 1 tam birim (18 ondalık ham skala)
    (0..batch_size)
        .map(|i| {
            let sender_seed = sender_seed_offset + i;
            // Basit periyodik dağılım: her 100'lük dilimin ilk `transfer_ratio_pct`
            // tanesi transfer, gerisi swap, transfer_ratio_pct=50 -> yaklaşık
            // yarı yarıya (sıralama değil, ORAN önemli, disk maliyeti için
            // hangi sırayla geldikleri fark etmez).
            let is_transfer = (i % 100) < transfer_ratio_pct.min(100);
            if is_transfer {
                let receiver_seed = sender_seed_offset + batch_size + i; // distinct, unfunded receiver
                signed_transfer(sender_seed, receiver_seed, amount, timestamp)
            } else {
                signed_swap_buy(sender_seed, amount, timestamp)
            }
        })
        .collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let batch_size: u64 = args
        .iter()
        .position(|a| a == "--batch-size")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(500);
    let transfer_ratio: u64 = args
        .iter()
        .position(|a| a == "--transfer-ratio")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(50);
    let num_batches: u64 = args
        .iter()
        .position(|a| a == "--num-batches")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(6);

    println!(
        "=== Zagros mixed-workload disk-growth measurement (batch_size={batch_size}, transfer_ratio={transfer_ratio}%) ===\n"
    );

    let data_dir = tempfile::tempdir().expect("failed to create temp dir for bench storage");
    let data_path = data_dir.path().to_path_buf();

    let storage = Arc::new(RocksDbStorage::open(&data_path).expect("failed to open storage"));
    let state: Arc<dyn State> = Arc::new(StateDbManager::new(storage));
    let executor = Arc::new(Executor::new(state.clone()));
    let scheduler = Arc::new(Scheduler::new(executor.clone()));
    let runtime = Runtime::new(state.clone(), executor, scheduler);

    let block_timestamp: u128 = 1_000_000;

    // Genesis-scale pool: 42M ZAGROS / 10.5K ZERENYA (matches zagros_types
    // genesis constants, not an arbitrary made-up ratio).
    state
        .set_pool_reserves(42_000_000u128 * TOKEN_DECIMAL, 10_500u128 * TOKEN_DECIMAL)
        .expect("failed to seed pool reserves");

    // Fund enough distinct accounts for ALL batches, each sender used exactly
    // once (fresh nonce=0), plus room for transfer receivers (each batch
    // reserves a 2*batch_size-wide address range regardless of transfer_ratio).
    let total_accounts = num_batches * batch_size * 2;
    println!("-- Funding {total_accounts} accounts (ZAGROS + ZERENYA balance) --");
    for seed in 1..=total_accounts {
        let mut acc = AccountState::new(100u128 * TOKEN_DECIMAL);
        acc.zerenya_balance = 100u128 * TOKEN_DECIMAL;
        state
            .set_account(&address_for_seed(seed), acc)
            .expect("failed to fund account");
    }

    // 🚨 Yalnız 2 grup yanıltıcı (compaction zamanı deterministik değil); N ardışık
    // grupla TREND'e bakmak tek "gerçek sayı" iddiasından dürüst.
    let mut previous_size = dir_size_bytes(&data_path);
    println!(
        "Disk before any batch: {} bytes ({:.2} KB)\n",
        previous_size,
        previous_size as f64 / 1024.0
    );

    for batch_num in 1..=num_batches {
        let sender_offset = (batch_num - 1) * batch_size * 2 + 1; // her grup öncekilerle AYRIK gönderici aralığı kullanır
        let batch = build_mixed_batch(
            batch_size,
            sender_offset,
            transfer_ratio,
            block_timestamp + batch_num as u128,
        );
        runtime
            .process_block(batch_num, block_timestamp + batch_num as u128, &batch)
            .unwrap_or_else(|e| panic!("process_block (batch {batch_num}) failed: {e:?}"));

        let size_after = dir_size_bytes(&data_path);
        let growth = size_after.saturating_sub(previous_size);
        println!(
            "Batch {:>2}: disk = {:>12} bytes ({:>10.2} KB) | growth = {:>10} bytes ({:>8.2} KB) => {:>8.2} bytes/tx",
            batch_num,
            size_after,
            size_after as f64 / 1024.0,
            growth,
            growth as f64 / 1024.0,
            growth as f64 / batch_size as f64
        );
        previous_size = size_after;
    }

    println!("\n=== Done. Temp data dir: {} ===", data_path.display());
}
