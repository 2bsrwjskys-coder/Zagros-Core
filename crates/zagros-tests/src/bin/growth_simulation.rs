//! Büyüme simülasyonu: disk büyümesi, RSS, blok işleme ve öneri/oy throughput'u,
//! RocksDB kapat+aç döngüsü. `--scale` CI güvenli küçük varsayılan (milyonlar saatler
//! sürer); büyüme eğilimleri bu ölçekte görünür. Snapshot ölçümü ayrı yapılır.
//! Kullanım: cargo run --release -p zagros-tests --bin growth_simulation [--scale N]

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

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

fn signed_transfer(
    sender_seed: u64,
    receiver_seed: u64,
    nonce: u64,
    timestamp: u128,
) -> Transaction {
    let key = secret_key(sender_seed);
    let sender = Transaction::address_from_secret_key(&key);
    let receiver = address_for_seed(receiver_seed);

    let mut tx_id = [0u8; 32];
    tx_id[0..8].copy_from_slice(&sender_seed.to_be_bytes());
    tx_id[8..16].copy_from_slice(&nonce.to_be_bytes());

    let mut tx = Transaction {
        tx_id,
        tx_type: TxType::Transfer,
        sender,
        amount: 1,
        receiver,
        payload: Vec::new(),
        signature: Vec::new(),
        timestamp,
        nonce,
        gas_limit: 21_000,
        gas_price: 1,
        chain_id: CHAIN_ID,
    };
    tx.sign(&key);
    tx
}

fn signed_submit_proposal(proposer_seed: u64, unique: u64, timestamp: u128) -> Transaction {
    let key = secret_key(proposer_seed);
    let sender = Transaction::address_from_secret_key(&key);

    let mut tx_id = [0u8; 32];
    tx_id[0..8].copy_from_slice(&proposer_seed.to_be_bytes());
    tx_id[16..24].copy_from_slice(&unique.to_be_bytes());
    tx_id[31] = 0xA1; // disambiguate from transfer tx_ids

    let mut tx = Transaction {
        tx_id,
        tx_type: TxType::SubmitProposal,
        sender: sender.clone(),
        amount: 0,
        receiver: sender,
        payload: format!("growth-sim proposal #{unique}").into_bytes(),
        signature: Vec::new(),
        timestamp,
        nonce: 0,
        gas_limit: 210_000,
        gas_price: 1,
        chain_id: CHAIN_ID,
    };
    tx.sign(&key);
    tx
}

fn signed_vote(
    voter_seed: u64,
    proposal_id: [u8; 32],
    unique: u64,
    timestamp: u128,
) -> Transaction {
    let key = secret_key(voter_seed);
    let sender = Transaction::address_from_secret_key(&key);

    let mut tx_id = [0u8; 32];
    tx_id[0..8].copy_from_slice(&voter_seed.to_be_bytes());
    tx_id[16..24].copy_from_slice(&unique.to_be_bytes());
    tx_id[31] = 0xB2;

    let mut payload = proposal_id.to_vec();
    payload.push(1); // support = true

    let mut tx = Transaction {
        tx_id,
        tx_type: TxType::Vote,
        sender: sender.clone(),
        amount: 0,
        receiver: sender,
        payload,
        signature: Vec::new(),
        timestamp,
        nonce: 0,
        gas_limit: 210_000,
        gas_price: 1,
        chain_id: CHAIN_ID,
    };
    tx.sign(&key);
    tx
}

fn dir_size_bytes(path: &Path) -> u64 {
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

/// Portable-enough current-process RSS via `ps` (works on both macOS/BSD and Linux).
fn current_rss_kb() -> Option<u64> {
    let pid = std::process::id();
    let output = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    String::from_utf8_lossy(&output.stdout).trim().parse().ok()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let scale: u64 = args
        .iter()
        .position(|a| a == "--scale")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(20_000);

    println!("=== Zagros growth-simulation benchmark (scale={scale}) ===");
    println!("(scale is a reduced, documented proxy for long-term growth - see file header)\n");

    let data_dir = tempfile::tempdir().expect("failed to create temp dir for bench storage");
    let data_path = data_dir.path().to_path_buf();

    let build_start = Instant::now();
    let storage = Arc::new(RocksDbStorage::open(&data_path).expect("failed to open storage"));
    let state: Arc<dyn State> = Arc::new(StateDbManager::new(storage));
    let executor = Arc::new(Executor::new(state.clone()));
    let scheduler = Arc::new(Scheduler::new(executor.clone()));
    let runtime = Runtime::new(state.clone(), executor, scheduler);
    println!(
        "Storage/executor/runtime constructed in {:?}",
        build_start.elapsed()
    );

    let block_timestamp: u128 = 1_000_000;
    let big_balance = 10_000_000u128 * TOKEN_DECIMAL;

    // Fund `scale` accounts with both balance and staked_balance so governance
    // gates (pre- or post-PR, min_stake_to_submit + fee) pass either way.
    println!("\n-- Funding {scale} accounts (balance + staked_balance) --");
    let fund_start = Instant::now();
    for seed in 1..=scale {
        let mut acc = AccountState::new(big_balance);
        acc.staked_balance = big_balance;
        state
            .set_account(&address_for_seed(seed), acc)
            .expect("failed to fund account");
    }
    println!("Funded in {:?}", fund_start.elapsed());
    println!(
        "Disk after funding: {} MB",
        dir_size_bytes(&data_path) / 1_000_000
    );
    if let Some(rss) = current_rss_kb() {
        println!("RSS after funding: {} MB", rss / 1024);
    }

    // -- Block of Transfer transactions (mempool/tx-volume + account/state growth proxy) --
    println!("\n-- Processing {scale} Transfer transactions in one block --");
    let mut transfers = Vec::with_capacity(scale as usize);
    for seed in 1..=scale {
        let receiver_seed = scale + seed; // distinct, unfunded receivers -> pure growth
        transfers.push(signed_transfer(seed, receiver_seed, 0, block_timestamp));
    }
    let transfer_start = Instant::now();
    runtime
        .process_block(1, block_timestamp, &transfers)
        .expect("process_block (transfers) failed");
    let transfer_elapsed = transfer_start.elapsed();
    println!(
        "Processed {} transfers in {:?} => {:.0} TPS",
        scale,
        transfer_elapsed,
        scale as f64 / transfer_elapsed.as_secs_f64()
    );

    // -- Governance: scale/10 proposals, one vote each (also a bridge-event-volume
    // proxy in terms of state-write volume, since a full multi-sig bridge mint/burn
    // simulation requires bridge-authority setup out of scope for this harness,
    // the write-volume/growth characteristics this PR targets are the same shape). --
    let gov_count = (scale / 10).max(1);
    println!("\n-- Submitting {gov_count} governance proposals + {gov_count} votes --");
    let mut proposals = Vec::with_capacity(gov_count as usize);
    for i in 0..gov_count {
        let proposer_seed = 1 + (i % scale);
        proposals.push(signed_submit_proposal(
            proposer_seed,
            i,
            block_timestamp + 1,
        ));
    }
    let submit_start = Instant::now();
    runtime
        .process_block(2, block_timestamp + 1, &proposals)
        .expect("process_block (proposals) failed");
    let submit_elapsed = submit_start.elapsed();
    println!(
        "Submitted {} proposals in {:?} => {:.0} proposals/sec",
        gov_count,
        submit_elapsed,
        gov_count as f64 / submit_elapsed.as_secs_f64()
    );

    let mut votes = Vec::with_capacity(gov_count as usize);
    for i in 0..gov_count {
        let voter_seed = 1 + ((i + 1) % scale); // different address than proposer where possible
        votes.push(signed_vote(
            voter_seed,
            proposals[i as usize].tx_id,
            i,
            block_timestamp + 2,
        ));
    }
    let vote_start = Instant::now();
    runtime
        .process_block(3, block_timestamp + 2, &votes)
        .expect("process_block (votes) failed");
    let vote_elapsed = vote_start.elapsed();
    println!(
        "Cast {} votes in {:?} => {:.0} votes/sec",
        gov_count,
        vote_elapsed,
        gov_count as f64 / vote_elapsed.as_secs_f64()
    );

    println!(
        "\nDisk after full load: {} MB",
        dir_size_bytes(&data_path) / 1_000_000
    );
    if let Some(rss) = current_rss_kb() {
        println!("RSS after full load: {} MB", rss / 1024);
    }

    // -- Restart: drop everything, reopen storage, confirm data survives --
    println!("\n-- Simulating restart (close + reopen RocksDB) --");
    drop(runtime);
    drop(state);
    // give RocksDB a moment to release its file lock
    std::thread::sleep(Duration::from_millis(200));

    let restart_start = Instant::now();
    let storage2 = Arc::new(RocksDbStorage::open(&data_path).expect("failed to reopen storage"));
    let state2: Arc<dyn State> = Arc::new(StateDbManager::new(storage2));
    let restart_elapsed = restart_start.elapsed();
    let check = state2
        .get_account(&address_for_seed(1))
        .expect("read after reopen failed");
    assert!(check.is_some(), "data did not survive restart");
    println!(
        "Restart (reopen + verify one account) took {:?}",
        restart_elapsed
    );

    println!("\n=== Done. Temp data dir: {} ===", data_path.display());
}
