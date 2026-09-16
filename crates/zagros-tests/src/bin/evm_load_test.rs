//! EVM (ContractCall) yük testi: `[gas] max_gas_per_block` tavanı gerçek sayıya
//! göre boyutlansın. EVM işlemleri scheduler'da koşulsuz sıralı koştuğundan
//! throughput işlem başına duvar saati maliyeti ve blok gas bütçesiyle sınırlı.
//! Senaryo: minimal sayaç kontratı deploy, `--scale` ardışık deploy (farklı
//! gönderici), `--scale` ardışık çağrı tek sıcak kontrata (en kötü durum).
//! Kullanım: cargo run --release -p zagros-tests --bin evm_load_test [--scale N]

use std::sync::Arc;
use std::time::Instant;

use secp256k1::SecretKey;
use zagros_executor::Executor;
use zagros_runtime::Runtime;
use zagros_scheduler::Scheduler;
use zagros_state::manager::StateDbManager;
use zagros_state::State;
use zagros_storage::rocksdb_impl::RocksDbStorage;
use zagros_types::{AccountState, ArchivedReceipt, Transaction, TxType, CHAIN_ID, TOKEN_DECIMAL};

fn secret_key(seed: u64) -> SecretKey {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&seed.to_be_bytes());
    SecretKey::from_slice(&bytes).expect("seed produces a valid secp256k1 scalar")
}

fn address_for_seed(seed: u64) -> zagros_types::Address {
    Transaction::address_from_secret_key(&secret_key(seed))
}

/// Minimal counter contract: `SLOAD(0); ADD(1); SSTORE(0); STOP`.
/// A cheap, single-cold-SSTORE contract call, a floor, not a ceiling, on
/// realistic EVM gas cost (a multi-write DeFi contract costs more per call).
fn counter_runtime_code() -> Vec<u8> {
    vec![
        0x60, 0x00, // PUSH1 0
        0x54, // SLOAD
        0x60, 0x01, // PUSH1 1
        0x01, // ADD
        0x60, 0x00, // PUSH1 0
        0x55, // SSTORE
        0x00, // STOP
    ]
}

/// Wraps `counter_runtime_code` in standard CODECOPY/RETURN init-code so a
/// `TxKind::Create` deploy installs it as real, callable runtime bytecode
/// (not just init-code that runs once and stops).
fn counter_init_code() -> Vec<u8> {
    let runtime = counter_runtime_code();
    let runtime_len = runtime.len() as u8; // 10 bytes, fits in PUSH1
    let prefix = vec![
        0x60,
        runtime_len, // PUSH1 <len>
        0x60,
        0x0c, // PUSH1 <offset of runtime code within this init code = 12>
        0x60,
        0x00, // PUSH1 0 (destOffset)
        0x39, // CODECOPY
        0x60,
        runtime_len, // PUSH1 <len> (size for RETURN)
        0x60,
        0x00, // PUSH1 0 (offset for RETURN)
        0xf3, // RETURN
    ];
    assert_eq!(
        prefix.len(),
        12,
        "runtime-code offset assumption baked into the bytecode above"
    );
    let mut init = prefix;
    init.extend_from_slice(&runtime);
    init
}

fn signed_contract_call(
    sender_seed: u64,
    unique: u64,
    receiver: String,
    data: Vec<u8>,
    gas_limit: u64,
    timestamp: u128,
) -> Transaction {
    let key = secret_key(sender_seed);
    let sender = Transaction::address_from_secret_key(&key);

    let mut tx_id = [0u8; 32];
    tx_id[0..8].copy_from_slice(&sender_seed.to_be_bytes());
    tx_id[16..24].copy_from_slice(&unique.to_be_bytes());
    tx_id[31] = 0xE7; // disambiguate from other benchmark tx_ids

    let mut tx = Transaction {
        tx_id,
        tx_type: TxType::ContractCall { data: data.clone() },
        sender,
        amount: 0,
        receiver,
        payload: data,
        signature: Vec::new(),
        timestamp,
        nonce: 0,
        gas_limit,
        gas_price: 1,
        chain_id: CHAIN_ID,
    };
    tx.sign(&key);
    tx
}

fn deployed_contract_address(state: &Arc<dyn State>, tx_id: [u8; 32]) -> zagros_types::Address {
    let receipt_acc = state
        .get_account(&zagros_state::receipt_key(&tx_id))
        .expect("receipt read failed")
        .expect("deploy tx must archive a receipt");
    let receipt: ArchivedReceipt =
        bincode::deserialize(&receipt_acc.contract_code).expect("receipt decode failed");
    assert!(receipt.status, "deploy tx must succeed");
    receipt
        .contract_address
        .expect("TxKind::Create deploy must produce a contract address")
}

/// `tx_ids`ten `status: true` arşivlenmiş makbuzu olanları sayar; yalnız ilk
/// işleme bakan ölçüm sistemik bir hatayı kaçırır (bayat nonce tüm batch'i reddetmişti).
fn count_successful(state: &Arc<dyn State>, tx_ids: &[[u8; 32]]) -> usize {
    tx_ids
        .iter()
        .filter(|tx_id| {
            state
                .get_account(&zagros_state::receipt_key(tx_id))
                .ok()
                .flatten()
                .and_then(|acc| bincode::deserialize::<ArchivedReceipt>(&acc.contract_code).ok())
                .map(|r| r.status)
                .unwrap_or(false)
        })
        .count()
}

fn main() {
    // `zagros-scheduler`'ın per-tx başarısızlıkları `tracing::error!` ile
    // loglaması, bir subscriber kurulu OLMADAN sessizce hiçe gider, bu bin
    // olmadan bir hata batch'i "0/N başarılı" olarak görünür ama SEBEBİ hiç
    // yazdırılmaz.
    zagros_metrics::init_telemetry();

    let args: Vec<String> = std::env::args().collect();
    let scale: u64 = args
        .iter()
        .position(|a| a == "--scale")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(3_000);

    // Matches `StorageConfig::default().block_time_ms` (see zagros-types/src/config.rs)
    // - used only for the printed gas-budget extrapolation below, not for timing.
    const BLOCK_TIME_MS: f64 = 200.0;

    println!("=== Zagros EVM (ContractCall) load test (scale={scale}) ===");
    println!("(sequential lane only - see file header for why)\n");

    let data_dir = tempfile::tempdir().expect("failed to create temp dir for bench storage");
    let data_path = data_dir.path().to_path_buf();

    let storage = Arc::new(RocksDbStorage::open(&data_path).expect("failed to open storage"));
    let state: Arc<dyn State> = Arc::new(StateDbManager::new(storage));
    let executor = Arc::new(Executor::new(state.clone()));
    let scheduler = Arc::new(Scheduler::new(executor.clone()));
    let runtime = Runtime::new(state.clone(), executor, scheduler);

    let block_timestamp: u128 = 1_000_000;
    let big_balance = 10_000_000u128 * TOKEN_DECIMAL;

    // 2*scale+1 hesap fonlanır; her aşama ayrık gönderici kullanmalı, yoksa
    // nonce=0 tekrarı bayat nonce reddi olup ölçümü sessizce bozar.
    println!("-- Funding {} accounts --", 2 * scale + 1);
    for seed in 1..=(2 * scale + 1) {
        state
            .set_account(&address_for_seed(seed), AccountState::new(big_balance))
            .expect("failed to fund account");
    }

    // -- Step 1: single deploy, to get a real contract address to hammer in step 3 --
    let init_code = counter_init_code();
    let deploy_tx = signed_contract_call(
        1,
        0,
        "0x0000000000000000000000000000000000000000".to_string(),
        init_code.clone(),
        500_000,
        block_timestamp,
    );
    let deploy_tx_id = deploy_tx.tx_id;
    runtime
        .process_block(1, block_timestamp, &[deploy_tx])
        .expect("process_block (initial deploy) failed");
    let contract_address = deployed_contract_address(&state, deploy_tx_id);
    println!("Deployed probe contract at {contract_address}\n");

    // -- Step 2: mass-deploy, `scale` distinct senders each deploy their own
    // copy of the same minimal contract in ONE block (token-factory-abuse shape). --
    println!("-- Sequentially deploying {scale} contracts (1 per sender, same block) --");
    let mut deploys = Vec::with_capacity(scale as usize);
    for seed in 2..=(scale + 1) {
        deploys.push(signed_contract_call(
            seed,
            1,
            "0x0000000000000000000000000000000000000000".to_string(),
            init_code.clone(),
            500_000,
            block_timestamp + 1,
        ));
    }
    let sample_deploy_tx_id = deploys[0].tx_id;
    let deploy_tx_ids: Vec<[u8; 32]> = deploys.iter().map(|tx| tx.tx_id).collect();
    let deploy_start = Instant::now();
    runtime
        .process_block(2, block_timestamp + 1, &deploys)
        .expect("process_block (mass deploy) failed");
    let deploy_elapsed = deploy_start.elapsed();
    let deploy_tps = scale as f64 / deploy_elapsed.as_secs_f64();
    let deploy_successes = count_successful(&state, &deploy_tx_ids);
    println!(
        "Deployed {} contracts in {:?} => {:.0} deploys/sec ({}/{} confirmed successful via receipt)",
        scale, deploy_elapsed, deploy_tps, deploy_successes, scale
    );
    assert_eq!(
        deploy_successes, scale as usize,
        "mass-deploy had silent per-tx failures - throughput number below is not trustworthy"
    );
    let sample_deploy_gas = {
        let acc = state
            .get_account(&zagros_state::receipt_key(&sample_deploy_tx_id))
            .unwrap()
            .unwrap();
        let receipt: ArchivedReceipt = bincode::deserialize(&acc.contract_code).unwrap();
        receipt.gas_used
    };
    println!("Sample deploy gas_used: {sample_deploy_gas}\n");

    // -- Step 3: hot-contract calls, `scale` distinct senders all call the
    // SAME contract from step 1 in ONE block (cannot parallelize even in
    // principle: revm is not shared across concurrent txs in this codebase). --
    println!("-- Sequentially calling 1 hot contract {scale} times (same block) --");
    let mut calls = Vec::with_capacity(scale as usize);
    for seed in (scale + 2)..=(2 * scale + 1) {
        calls.push(signed_contract_call(
            seed,
            2,
            contract_address.clone(),
            // `TxType::ContractCall` validation requires non-empty data, our
            // runtime code ignores calldata entirely, so any non-empty byte works.
            vec![0x00],
            100_000,
            block_timestamp + 2,
        ));
    }
    let sample_call_tx_id = calls[0].tx_id;
    let call_tx_ids: Vec<[u8; 32]> = calls.iter().map(|tx| tx.tx_id).collect();
    let call_start = Instant::now();
    runtime
        .process_block(3, block_timestamp + 2, &calls)
        .expect("process_block (hot contract calls) failed");
    let call_elapsed = call_start.elapsed();
    let call_tps = scale as f64 / call_elapsed.as_secs_f64();
    let call_successes = count_successful(&state, &call_tx_ids);
    println!(
        "Called hot contract {} times in {:?} => {:.0} calls/sec ({}/{} confirmed successful via receipt)",
        scale, call_elapsed, call_tps, call_successes, scale
    );
    assert_eq!(
        call_successes, scale as usize,
        "hot-contract-call batch had silent per-tx failures - throughput number above is not trustworthy"
    );
    let sample_call_gas = {
        let acc = state
            .get_account(&zagros_state::receipt_key(&sample_call_tx_id))
            .unwrap()
            .unwrap();
        let receipt: ArchivedReceipt = bincode::deserialize(&acc.contract_code).unwrap();
        receipt.gas_used
    };
    println!("Sample call gas_used: {sample_call_gas}\n");

    // -- Gas-budget extrapolation: ties the measured numbers back to the
    // `[gas] max_gas_per_block` / `target_gas_per_block` decision. --
    println!("-- Gas-budget extrapolation (block_time_ms={BLOCK_TIME_MS}) --");
    let call_gas_per_sec = call_tps * sample_call_gas as f64;
    let call_gas_per_block = call_gas_per_sec * (BLOCK_TIME_MS / 1000.0);
    println!(
        "Hot-contract-call lane: {:.0} gas/sec => {:.0} gas needed per {:.0}ms block \
         at full throughput",
        call_gas_per_sec, call_gas_per_block, BLOCK_TIME_MS
    );
    for cap in [25_000_000f64, 35_000_000f64, 50_000_000f64, 100_000_000f64] {
        let max_calls_per_block = cap / sample_call_gas as f64;
        let seconds_to_drain_block = max_calls_per_block / call_tps;
        println!(
            "  cap={:>11.0}: fits {:>7.0} hot-contract calls/block => {:.3}s of sequential \
             EVM work if a block were completely full at this cap",
            cap, max_calls_per_block, seconds_to_drain_block
        );
    }
    println!(
        "\nNote: this is a floor, not a ceiling - `counter_runtime_code` is a single cheap \
         SLOAD+SSTORE. A real multi-write DeFi contract call would use proportionally more \
         gas per tx and proportionally fewer calls/sec, but the gas/sec ceiling itself is \
         roughly bytecode-shape-independent (revm's own per-opcode cost dominates wall time \
         at this contract complexity - dispatch/signature/state-IO overhead is the rest)."
    );

    println!("\n=== Done. Temp data dir: {} ===", data_path.display());
}
