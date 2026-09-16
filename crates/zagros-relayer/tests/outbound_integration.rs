// Entegrasyon testi: gerçek `RpcServer` yerel portta, `OutboundRelayer` gerçek
// HTTP ile (`inbound_integration.rs` ile aynı desen, POST-only route).

use ed25519_dalek::SigningKey;
use ethers_core::types::Address as EthAddress;
use secp256k1::SecretKey;
use std::sync::Arc;
use warp::Filter;
use zagros_executor::bridge::BridgeManager;
use zagros_mempool::Mempool;
use zagros_relayer::outbound::OutboundRelayer;
use zagros_relayer::store::RelayerStore;
use zagros_relayer::zagros_client::ZagrosClient;
use zagros_rpc::{EvmSimulationLimits, RpcRequest, RpcServer};
use zagros_state::manager::StateDbManager;
use zagros_storage::rocksdb_impl::RocksDbStorage;
use zagros_types::GasCalculator;

// 🛡️ Sabit port yok: entegrasyon testleri ayrı süreçte koştuğundan sayaçlar
// çakışıp "Address already in use" veriyordu; portu işletim sistemi seçer.

fn current_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn zagros_authority_signing_key(seed: u8) -> SigningKey {
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    SigningKey::from_bytes(&bytes)
}

async fn spawn_test_server() -> (Arc<dyn zagros_state::State>, u16) {
    let tmp_dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(RocksDbStorage::open(tmp_dir.path().to_str().unwrap()).unwrap());
    let state: Arc<dyn zagros_state::State> = Arc::new(StateDbManager::new(storage));
    let returned_state = state.clone();
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

    // Port 0 = "bos bir port sec"; `bind_ephemeral` FIILEN baglanan adresi
    // doner, hazir olma beklemesine de gerek kalmaz.
    let (addr, server) = warp::serve(route).bind_ephemeral(([127, 0, 0, 1], 0));
    tokio::spawn(async move {
        let _keep_alive = tmp_dir;
        server.await;
    });
    (returned_state, addr.port())
}

/// `TempDir`'i de döner, çağıran onu test fonksiyonunun sonuna kadar canlı
/// tutmalı.
fn eth_address_from_seed(seed: u8) -> EthAddress {
    let mut eth_key_bytes = [0u8; 32];
    eth_key_bytes[0] = seed;
    let sk = SecretKey::from_slice(&eth_key_bytes).unwrap();
    let hex_addr = zagros_types::Transaction::address_from_secret_key(&sk);
    EthAddress::from_slice(&hex::decode(hex_addr.trim_start_matches("0x")).unwrap())
}

fn make_outbound_relayer(
    rpc_url: String,
    zagros_seed: u8,
    ethereum_seed: u8,
) -> (OutboundRelayer, tempfile::TempDir) {
    let zagros_signing_key = zagros_authority_signing_key(zagros_seed);
    let zagros_authority_address = BridgeManager::derive_address_from_public_key(
        &zagros_signing_key.verifying_key().to_bytes(),
    );

    let mut eth_key_bytes = [0u8; 32];
    eth_key_bytes[0] = ethereum_seed;
    let ethereum_signing_key = SecretKey::from_slice(&eth_key_bytes).unwrap();
    let ethereum_relayer_address = eth_address_from_seed(ethereum_seed);

    let tmp_dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(RocksDbStorage::open(tmp_dir.path().to_str().unwrap()).unwrap());

    let relayer = OutboundRelayer {
        client: ZagrosClient::new(rpc_url),
        store: RelayerStore::new(storage),
        zagros_signing_key,
        zagros_authority_address,
        ethereum_signing_key,
        ethereum_relayer_address,
        gateway_contract_address: EthAddress::repeat_byte(0xAA),
        unlock_token_address: EthAddress::repeat_byte(0xBB),
        // Testte ölçekleme kimlik olsun diye 18 (6-ondalık ölçeklemesi
        // zagros_types::bridge_amount testlerinde kanıtlanıyor).
        unlock_token_decimals: 18,
        ethereum_chain_id: 1,
        chain_id: zagros_types::CHAIN_ID,
        // Entegrasyon testi imzaları kanonik dev kümesiyle üretiyor.
        trusted_authorities: BridgeManager::default_bridge_manager(zagros_types::CHAIN_ID),
        auto_recover_cursor_gap: false,
    };
    (relayer, tmp_dir)
}

#[tokio::test]
async fn a_zagros_burn_becomes_a_two_of_three_signed_unlock_intent_ready_for_submission() {
    let (state, port) = spawn_test_server().await;
    let rpc_url = format!("http://127.0.0.1:{port}");

    let (proposer, _proposer_dir) = make_outbound_relayer(rpc_url.clone(), 1, 10);
    let (co_signer, _co_signer_dir) = make_outbound_relayer(rpc_url.clone(), 2, 11);

    let now = current_unix_secs();

    // #9: "burn" (unlock-intent) önerisi artık zincirin kendi görünürlük
    // indeksindeki GERÇEK bir yakmaya karşılık gelmek zorunda, bu yüzden
    // önce gerçek bir BridgeMint (teminat için) ve gerçek bir BridgeBurn
    // çalıştırıyoruz, tıpkı zagros-rpc'nin kendi testlerindeki gibi.
    let burn_secret_key = secp256k1::SecretKey::from_slice(&[77u8; 32]).unwrap();
    let burn_sender = zagros_types::Transaction::address_from_secret_key(&burn_secret_key);
    let burn_amount = 5_000u128;
    let burn_tx_id_bytes = [0xabu8; 32];
    let burn_tx_id = format!("0x{}", hex::encode(burn_tx_id_bytes));

    let mint_authority_key = secp256k1::SecretKey::from_slice(&[78u8; 32]).unwrap();
    let mint_authority = zagros_types::Transaction::address_from_secret_key(&mint_authority_key);
    state
        .set_account(
            &mint_authority,
            zagros_types::AccountState::new(1_000_000_000_000_000_000),
        )
        .unwrap();
    state
        .set_account(
            &burn_sender,
            zagros_types::AccountState::new(1_000_000_000_000_000_000),
        )
        .unwrap();

    // Teminat icin gercek bir BridgeMint (2/3 imzali), seed_mint_proposal'in
    // (zagros-executor'un private test yardimcisi, buradan erisilemez) elle
    // yeniden uretimi.
    let now_ms = (now as u128) * 1000;
    let mut mint_authorities = Vec::new();
    let mut mint_keys = Vec::new();
    for i in 1..=3u8 {
        let mut seed = [0u8; 32];
        seed[0] = 200 + i;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let address = zagros_executor::bridge::BridgeManager::derive_address_from_public_key(
            &signing_key.verifying_key().to_bytes(),
        );
        mint_authorities.push(zagros_executor::bridge::BridgeAuthority {
            address: address.clone(),
            public_key: signing_key.verifying_key().to_bytes(),
            is_active: true,
        });
        mint_keys.push((address, signing_key));
    }
    let mut mint_manager = {
        // 🛡️ Basim dogrulamasi ZINCIRDEKI yetkili kumesini okur (uretimde
        // genesis yazar), fail-closed oldugu icin testte de kurulmali.
        zagros_executor::bridge::store_bridge_authority_set(
            state.as_ref(),
            &zagros_executor::bridge::OnChainBridgeAuthoritySet {
                authorities: mint_authorities.clone(),
                required_signatures: 2,
            },
        )
        .unwrap();
        zagros_executor::bridge::BridgeManager::new(mint_authorities, 2, zagros_types::CHAIN_ID)
    };
    let mint_proposal_id = mint_manager
        .create_proposal(
            zagros_executor::bridge::BridgeTxType::Mint,
            burn_amount,
            burn_sender.clone(),
            "Ethereum".to_string(),
            "0xcollateral_source".to_string(),
            (now_ms / 1000) as u64,
            false,
            0,
            now_ms,
            state.as_ref(),
        )
        .unwrap();
    let message = zagros_executor::bridge::BridgeManager::create_signing_message(
        mint_manager.get_proposal(&mint_proposal_id).unwrap(),
        zagros_types::CHAIN_ID,
    );
    let sig_ts = (now_ms / 1000) as u64;
    let bound = zagros_executor::bridge::BridgeManager::bind_timestamp_to_message(&message, sig_ts);
    for (address, signing_key) in mint_keys.iter().take(2) {
        mint_manager
            .sign_proposal(
                &mint_proposal_id,
                address.clone(),
                ed25519_dalek::Signer::sign(signing_key, &bound)
                    .to_bytes()
                    .to_vec(),
                signing_key.verifying_key().to_bytes().to_vec(),
                sig_ts,
                now_ms,
            )
            .unwrap();
    }
    mint_manager
        .persist_proposal(state.as_ref(), &mint_proposal_id)
        .unwrap();

    // Üretim kodu (state_root çatal düzeltmesi) mint işleminin ÖNERİYİ
    // payload'ında taşımasını şart koşar (`decode_proposal_payload`, fail-closed);
    // boş payload "Kopru mint islemi oneriyi payload'inda tasimiyor" ile reddedilir.
    let mint_payload = zagros_executor::bridge::BridgeManager::encode_proposal_payload(
        mint_manager
            .get_proposal(&mint_proposal_id)
            .expect("mint onerisi manager'da olmali"),
    )
    .expect("oneri payload kodlanmali");
    let mut mint_tx = zagros_types::Transaction {
        tx_id: mint_proposal_id,
        tx_type: zagros_types::TxType::BridgeMint,
        sender: mint_authority.clone(),
        receiver: burn_sender.clone(),
        amount: burn_amount,
        payload: mint_payload,
        signature: Vec::new(),
        timestamp: now_ms,
        nonce: 0,
        gas_limit: 1,
        gas_price: 1,
        chain_id: zagros_types::CHAIN_ID,
    };
    mint_tx.sign(&mint_authority_key);
    zagros_executor::Executor::new(state.clone())
        .with_bridge_authority(mint_authority.clone())
        .with_bridge_threshold(2, 0)
        .execute_transaction(&mint_tx, mint_tx.timestamp)
        .unwrap();

    let mut burn_tx = zagros_types::Transaction {
        tx_id: burn_tx_id_bytes,
        tx_type: zagros_types::TxType::BridgeBurn,
        sender: burn_sender.clone(),
        receiver: "0x0000000000000000000000000000000000000002".to_string(),
        amount: burn_amount,
        payload: Vec::new(),
        signature: Vec::new(),
        timestamp: now as u128,
        nonce: 0,
        gas_limit: 21_000,
        gas_price: 1,
        chain_id: zagros_types::CHAIN_ID,
    };
    burn_tx.sign(&burn_secret_key);
    zagros_executor::Executor::new(state.clone())
        .execute_transaction(&burn_tx, burn_tx.timestamp)
        .unwrap();

    // 1. Relayer #1 burn'ü görür, önerir ve kendi onayını hemen ekler.
    let proposal_id = proposer
        .handle_new_burn(&burn_tx_id, &burn_sender, burn_amount, now)
        .await
        .expect("propose+self-sign should succeed")
        .expect("first observation must not be a no-op");

    let after_self_sign = proposer
        .client
        .get_bridge_proposal(&proposal_id)
        .await
        .unwrap();
    assert_eq!(after_self_sign["tx_type"], "burn");
    assert_eq!(after_self_sign["signatures_collected"], 1);

    // 2. Relayer #2, KENDİSİ oluşturmadığı bu unlock-intent önerisini
    // keşfedip onaylıyor.
    let newly_signed = co_signer.discover_and_cosign_pending_unlocks(now).await;
    assert_eq!(newly_signed, 1);

    let after_co_sign = proposer
        .client
        .get_bridge_proposal(&proposal_id)
        .await
        .unwrap();
    assert_eq!(after_co_sign["signatures_collected"], 2);
    // Eşik karşılandı ama 24 saatlik zaman kilidi dolmadığı için henüz
    // yürütülebilir değil, claim fişi üretimi bu yüzden tetiklenmemeli.
    assert_eq!(after_co_sign["can_execute"], false);

    let pending = proposer
        .client
        .get_pending_bridge_proposals()
        .await
        .unwrap();
    let prepared = proposer.build_claim_vouchers(&pending, now);
    assert!(
        prepared.is_empty(),
        "zaman kilidi dolmadan hiçbir claim fişi üretilmemeli"
    );

    // 3. Idempotency: aynı burn'ü ikinci kez "gördüğümüzde" no-op olmalı.
    let second_attempt = proposer
        .handle_new_burn(&burn_tx_id, &burn_sender, burn_amount, now)
        .await
        .unwrap();
    assert!(second_attempt.is_none());
}
