// Entegrasyon testi: gerçek `RpcServer` (RocksDB + BridgeManager) yerel portta,
// `InboundRelayer` gerçek HTTP ile; imza mesajı inşası sunucunun doğrulamasıyla
// uyumlu olmalı. Ethereum devnet yok, `TokensLockedEvent` elle kurulur.

use ed25519_dalek::SigningKey;
use ethers_core::types::{H160, H256, U256};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Duration;
use warp::Filter;
use zagros_executor::bridge::BridgeManager;
use zagros_mempool::Mempool;
use zagros_relayer::ethereum_watcher::TokensLockedEvent;
use zagros_relayer::inbound::InboundRelayer;
use zagros_relayer::store::RelayerStore;
use zagros_relayer::zagros_client::ZagrosClient;
use zagros_rpc::{EvmSimulationLimits, RpcRequest, RpcServer};
use zagros_state::manager::StateDbManager;
use zagros_storage::rocksdb_impl::RocksDbStorage;
use zagros_types::GasCalculator;

// Paralel testler farklı portlar kullansın diye basit bir sayaç, CI'da
// gerçek bir port çakışması riskini pratikte sıfıra indirir.
static NEXT_PORT: AtomicU16 = AtomicU16::new(18_700);

fn next_port() -> u16 {
    NEXT_PORT.fetch_add(1, Ordering::SeqCst)
}

fn current_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Test seed'i (1..=3), `BridgeManager::default_authorities()`'in de
/// kullandığı aynı türetme, gerçek sunucu tarafı yetkilileriyle eşleşsin diye.
fn authority_signing_key(seed: u8) -> SigningKey {
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    SigningKey::from_bytes(&bytes)
}

/// `RpcServer::start()` yerine `handle_request`i doğrudan süren POST-only warp
/// route'u (warp WS route'unun crate dışından HRTB kısıtı).
async fn spawn_test_server(port: u16) {
    let tmp_dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(RocksDbStorage::open(tmp_dir.path().to_str().unwrap()).unwrap());
    let state: Arc<dyn zagros_state::State> = Arc::new(StateDbManager::new(storage));
    let gas_calculator = Arc::new(GasCalculator::new(
        Arc::new(portable_atomic::AtomicU128::new(1)),
        Arc::new(portable_atomic::AtomicU128::new(1_000_000_000_000_000)),
    ));
    let mempool = Arc::new(Mempool::new(state.clone(), gas_calculator));
    let bridge_manager = Arc::new(std::sync::Mutex::new(
        BridgeManager::default_bridge_manager(zagros_types::CHAIN_ID),
    ));
    let tx_cache = Arc::new(dashmap::DashMap::new());

    let route = warp::post()
        .and(warp::body::bytes())
        .and_then(move |body: bytes::Bytes| {
            let state = state.clone();
            let mempool = mempool.clone();
            let tx_cache = tx_cache.clone();
            let bridge_manager = bridge_manager.clone();
            async move {
                let req: RpcRequest =
                    serde_json::from_slice(&body).expect("valid JSON-RPC request");
                let response = RpcServer::handle_request(
                    req,
                    state,
                    mempool,
                    tx_cache,
                    bridge_manager,
                    EvmSimulationLimits::default(),
                );
                Ok::<_, std::convert::Infallible>(warp::reply::json(&response))
            }
        });

    // `tmp_dir`'i görev içine taşıyoruz ki sunucu çalıştığı sürece silinmesin.
    tokio::spawn(async move {
        let _keep_alive = tmp_dir;
        warp::serve(route).run(([127, 0, 0, 1], port)).await;
    });

    // Sunucunun dinlemeye başlamasını bekle (sabit bir uyku yerine bağlantı
    // denemesi ile, daha hızlı ve daha güvenilir).
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("test RPC server did not start listening on port {port} in time");
}

/// `TempDir`'i de döner, çağıran onu test fonksiyonunun sonuna kadar canlı
/// tutmalı (drop edilirse dizin silinir ve RocksDB kullanılamaz hale gelir).
fn make_relayer(rpc_url: String, seed: u8) -> (InboundRelayer, tempfile::TempDir) {
    let signing_key = authority_signing_key(seed);
    let authority_address =
        BridgeManager::derive_address_from_public_key(&signing_key.verifying_key().to_bytes());
    let tmp_dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(RocksDbStorage::open(tmp_dir.path().to_str().unwrap()).unwrap());

    let relayer = InboundRelayer {
        client: ZagrosClient::new(rpc_url),
        store: RelayerStore::new(storage),
        signing_key,
        authority_address,
        chain_id: zagros_types::CHAIN_ID,
        source_chain_name: "Ethereum".to_string(),
        token_decimals: 6,
    };
    (relayer, tmp_dir)
}

fn sample_deposit_event() -> TokensLockedEvent {
    TokensLockedEvent {
        sender: H160::repeat_byte(0x42),
        token: H160::repeat_byte(0x99),
        amount: U256::from(5_000u64),
        auto_swap: false,
        min_amount_out: U256::zero(),
        deposit_timestamp: U256::from(current_unix_secs()),
        eth_tx_hash: H256::repeat_byte(0x11),
        block_number: 12_345,
    }
}

/// #10: `TokensLockedEvent`'i, `decode_tokens_locked`'ın GERİYE ÇÖZEBİLECEĞİ
/// gerçek bir `Log`'a kodlar, `discover_and_cosign_pending_mints`'in bağımsız
/// doğrulaması artık bunu GERÇEKTEN Ethereum'dan gelmiş gibi okuyacak.
fn build_tokens_locked_log(event: &TokensLockedEvent) -> ethers_core::types::Log {
    use ethers_core::abi::{encode, Token};
    let topic0 = zagros_relayer::ethereum_watcher::tokens_locked_event_abi().signature();
    let data = encode(&[
        Token::Uint(event.amount),
        Token::Bool(event.auto_swap),
        Token::Uint(event.min_amount_out),
        Token::Uint(event.deposit_timestamp),
    ]);
    ethers_core::types::Log {
        address: H160::repeat_byte(0xCC),
        topics: vec![topic0, H256::from(event.sender), H256::from(event.token)],
        data: ethers_core::types::Bytes::from(data),
        block_hash: None,
        block_number: Some(event.block_number.into()),
        transaction_hash: Some(event.eth_tx_hash),
        transaction_index: None,
        log_index: None,
        transaction_log_index: None,
        log_type: None,
        removed: Some(false),
    }
}

/// #10: `verify_mint_proposal_against_ethereum`'un çağırdığı `EthLogSource`'un
/// test taklidi, `receipts` haritasında olmayan bir tx_hash için `Ok(None)`
/// döner (uydurma işlem senaryosu).
struct TestEthSource {
    latest: u64,
    receipts: std::collections::HashMap<H256, Vec<ethers_core::types::Log>>,
}

impl zagros_relayer::ethereum_watcher::EthLogSource for TestEthSource {
    async fn latest_block_number(&self) -> Result<u64, String> {
        Ok(self.latest)
    }
    async fn tokens_locked_logs(
        &self,
        _from: u64,
        _to: u64,
    ) -> Result<Vec<ethers_core::types::Log>, String> {
        Ok(Vec::new())
    }
    async fn transaction_receipt_logs(
        &self,
        tx_hash: H256,
    ) -> Result<Option<Vec<ethers_core::types::Log>>, String> {
        Ok(self.receipts.get(&tx_hash).cloned())
    }
}

/// Verilen olayı, kendisini GERÇEKTEN doğrulayacak bir `TestEthSource` üretir,
/// güncel blok = olayın bloğu + 11 (12 onay derinliğini rahatça karşılar).
fn confirming_source_for(event: &TokensLockedEvent) -> TestEthSource {
    let mut receipts = std::collections::HashMap::new();
    receipts.insert(event.eth_tx_hash, vec![build_tokens_locked_log(event)]);
    TestEthSource {
        latest: event.block_number + 12,
        receipts,
    }
}

#[tokio::test]
async fn a_confirmed_deposit_becomes_a_two_of_three_signed_mint_proposal() {
    let port = next_port();
    spawn_test_server(port).await;
    let rpc_url = format!("http://127.0.0.1:{port}");

    let (proposer, _proposer_dir) = make_relayer(rpc_url.clone(), 1);
    let (co_signer, _co_signer_dir) = make_relayer(rpc_url.clone(), 2);

    let event = sample_deposit_event();
    let now = current_unix_secs();

    // 1. Relayer #1 depositi görür, önerir ve KENDİ imzasını hemen ekler.
    let proposal_id = proposer
        .handle_confirmed_deposit(&event, now)
        .await
        .expect("propose+self-sign should succeed")
        .expect("first observation must not be a no-op");

    let after_self_sign = proposer
        .client
        .get_bridge_proposal(&proposal_id)
        .await
        .unwrap();
    assert_eq!(after_self_sign["signatures_collected"], 1);
    assert_eq!(after_self_sign["can_execute"], false);

    // 2. Relayer #2, bu öneriyi KENDİSİ oluşturmadan keşfedip onaylıyor,
    // bu, bağımsız çalışan relayer'lar arasında 2-of-3 mutabakatın gerçekten
    // işlediğinin kanıtı. #10: artık KENDİ Ethereum kaynağıyla (gerçek olayla
    // eşleşen) bağımsız doğrulama yapıyor, kör imzalamıyor.
    let source = confirming_source_for(&event);
    let newly_signed = co_signer
        .discover_and_cosign_pending_mints(&source, 12, now)
        .await;
    assert_eq!(newly_signed, 1);

    let after_co_sign = proposer
        .client
        .get_bridge_proposal(&proposal_id)
        .await
        .unwrap();
    assert_eq!(after_co_sign["signatures_collected"], 2);
    // Eşik (2) karşılandı ama 24 saatlik zaman kilidi henüz dolmadı.
    assert_eq!(after_co_sign["can_execute"], false);

    // 3. Idempotency: aynı olayı ikinci kez "gördüğümüzde" no-op olmalı.
    let second_attempt = proposer
        .handle_confirmed_deposit(&event, now)
        .await
        .unwrap();
    assert!(
        second_attempt.is_none(),
        "already-handled deposit must not create a second proposal"
    );
}

/// 🛡️ `TokensLocked`taki `min_amount_out` öneriye AYNEN taşınmalı, sessizce
/// 0'a düşürülmemeli (slippage koruması gerçek veriyle beslenir).
#[tokio::test]
async fn a_deposit_with_a_nonzero_min_amount_out_carries_it_onto_the_proposal() {
    let port = next_port();
    spawn_test_server(port).await;
    let rpc_url = format!("http://127.0.0.1:{port}");

    let (proposer, _proposer_dir) = make_relayer(rpc_url.clone(), 1);
    let now = current_unix_secs();

    let mut event = sample_deposit_event();
    event.auto_swap = true;
    event.min_amount_out = U256::from(1_234_000_000_000_000_000u64); // 1.234 ZAGROS

    let proposal_id = proposer
        .handle_confirmed_deposit(&event, now)
        .await
        .expect("propose+self-sign should succeed")
        .expect("first observation must not be a no-op");

    let proposal = proposer
        .client
        .get_bridge_proposal(&proposal_id)
        .await
        .unwrap();
    assert_eq!(
        proposal["amount_out_min"], "1234000000000000000",
        "zincirdeki min_amount_out sessizce dusurulmus/degistirilmis"
    );
}

#[tokio::test]
async fn discovery_is_idempotent_when_already_signed() {
    let port = next_port();
    spawn_test_server(port).await;
    let rpc_url = format!("http://127.0.0.1:{port}");

    let (proposer, _proposer_dir) = make_relayer(rpc_url.clone(), 1);
    let now = current_unix_secs();

    let event = sample_deposit_event();
    proposer
        .handle_confirmed_deposit(&event, now)
        .await
        .unwrap()
        .expect("should create a proposal");

    // Aynı relayer kendi bekleyen önerisini tekrar keşfedip imzalamayı
    // dener, sunucu "already signed" ile reddeder, bu ZARARSIZ (0 yeni imza,
    // hata değil, panic değil). Bu, bağımsız doğrulamaya ULAŞMADAN ÖNCE
    // (already_signed_by kontrolünde) kısa devre yapar.
    let source = confirming_source_for(&event);
    let newly_signed = proposer
        .discover_and_cosign_pending_mints(&source, 12, now)
        .await;
    assert_eq!(newly_signed, 0);
}
