// Zagros Relayer: validator düğümünden KASITLI ayrı binary (anahtar izolasyonu,
// bağımsız lifecycle). Akış: `relayer.toml` FAIL-CLOSED doğrulanır → inbound +
// outbound döngüleri başlar → SIGINT/SIGTERM'de iptal sinyaliyle temiz kapanış.

use std::str::FromStr;
use std::sync::Arc;
use tracing::info;

use ethers_core::types::Address as EthAddress;
use zagros_metrics::init_telemetry;
use zagros_relayer::config::RelayerConfig;
use zagros_relayer::ethereum_watcher;
use zagros_relayer::inbound::InboundRelayer;
use zagros_relayer::outbound::OutboundRelayer;
use zagros_relayer::store::RelayerStore;
use zagros_relayer::zagros_client::ZagrosClient;
use zagros_storage::rocksdb_impl::RocksDbStorage;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 🔐 .env varsa yükle, API anahtarı taşıyan uç noktalar relayer.toml'da düz
    // metin durmasın diye `${VAR}` ile referans veriliyor (bkz.
    // config::expand_env_placeholders). Dosya yoksa sorun değil: değişkenler
    // ortamdan (systemd EnvironmentFile, shell export vb.) da gelebilir.
    let _ = dotenvy::dotenv();
    init_telemetry();

    info!("===========================================================");
    info!("🌉 ZAGROS RELAYER BOT (FAZ 4: canlı lifecycle) başlatılıyor...");
    info!("===========================================================");

    // 1. Yapılandırma `from_file()` içinde FAIL-CLOSED doğrulanır. Yol argümandan
    //    (varsayılan relayer.toml), aynı makinede birden fazla relayer için.
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "relayer.toml".to_string());
    info!("📄 Yapılandırma: {}", config_path);
    let mut config = RelayerConfig::from_file(&config_path)?;

    let zagros_authority_address = config
        .zagros_authority_address()
        .map_err(|e| format!("Zagros kimliği türetilemedi: {}", e))?;
    let ethereum_address_str = config
        .ethereum_address()
        .map_err(|e| format!("Ethereum kimliği türetilemedi: {}", e))?;

    info!(
        "🔑 Zagros Yetkili Adresi     : {}",
        zagros_authority_address
    );
    info!("🔑 Ethereum Relayer Adresi   : {}", ethereum_address_str);
    info!("🌐 Zagros RPC                : {}", config.zagros.rpc_url);
    info!(
        "🌐 Ethereum WS RPC           : {}",
        config.ethereum.ws_rpc_url
    );
    info!(
        "📜 Gateway Kontrat Adresi    : {}",
        config.ethereum.gateway_contract_address
    );
    info!(
        "👥 Relayer Adres Kümesi      : {} adet",
        config.ethereum.relayer_addresses.len()
    );
    info!(
        "⏱️ Zagros Tarama Aralığı     : {}s",
        config.zagros.poll_interval_secs
    );
    info!(
        "⏱️ Ethereum Tarama Aralığı   : {}s",
        config.ethereum.poll_interval_secs
    );
    info!("===========================================================");

    // Doğrulanmış kimlikler / kümeler (fail-closed, hepsi validate()'te geçti).
    let zagros_signing_key = config.zagros_secret_key().map_err(|e| e.to_string())?;
    let ethereum_signing_key = config.ethereum_secret_key().map_err(|e| e.to_string())?;
    // Sağlık kontrolü: bu relayer'ın Ethereum adresi gateway `isRelayer` kümesinde
    // olmalı (`relayer_eth_addresses()` fail-closed). Anahtar sıfırlanmadan ÖNCE çalışmalı.
    let _ = config.relayer_eth_addresses().map_err(|e| e.to_string())?;
    // item 14, R7: iki hex özel anahtar da artık türetildi, config'te düz
    // metin olarak DAHA UZUN kalmasın diye hemen sıfırla. `config` bu
    // noktadan sonra `identity` alanına bir daha ASLA erişmiyor (yalnızca
    // `ethereum`/`zagros`/`bridge`/`data_dir` bölümleri kullanılıyor).
    {
        use zeroize::Zeroize;
        config.identity.zagros_signing_key_hex.zeroize();
        config.identity.ethereum_signing_key_hex.zeroize();
    }
    let trusted_authorities = config.trusted_bridge_manager().map_err(|e| e.to_string())?;
    let ethereum_relayer_address = EthAddress::from_str(&ethereum_address_str)?;
    let gateway_contract_address = EthAddress::from_str(&config.ethereum.gateway_contract_address)?;
    let unlock_token_address = EthAddress::from_str(&config.ethereum.unlock_token_address)?;

    // Kalıcı durum (idempotency + retry).
    // 🚨 Depo yolu config'ten gelir: iki relayer aynı dizini paylaşırsa RocksDB
    // kilidi yüzünden ikincisi açılamaz (bkz. RelayerConfig::data_dir).
    let storage = Arc::new(RocksDbStorage::open(&config.data_dir)?);
    info!("💾 Yerel durum deposu açıldı ({}).", config.data_dir);

    // item 11, R8: bu özellikten ÖNCE yazılmış (undated) idempotency
    // kayıtlarını TEK SEFERLİK zaman damgalı şekle göç ettir, sentinel
    // anahtar sayesinde ilk çalıştırmadan SONRA no-op, her başlangıçta
    // güvenle çağrılabilir.
    let startup_migration_store = RelayerStore::new(storage.clone());
    match startup_migration_store.migrate_legacy_idempotency_markers() {
        Ok(0) => {}
        Ok(n) => info!(
            "🧹 item 11 göçü: {} eski (tarihsiz) idempotency kaydı zaman damgalı şekle yükseltildi.",
            n
        ),
        Err(e) => tracing::warn!("item 11 idempotency göçü başarısız oldu: {}", e),
    }

    let inbound = Arc::new(InboundRelayer {
        client: ZagrosClient::new(config.zagros.rpc_url.clone()),
        store: RelayerStore::new(storage.clone()),
        signing_key: zagros_signing_key.clone(),
        authority_address: zagros_authority_address.clone(),
        chain_id: config.bridge.chain_id,
        source_chain_name: config.bridge.source_chain_name.clone(),
        // Giriş ve çıkış ayakları AYNI ondalığı kullanmak zorunda.
        token_decimals: config.ethereum.unlock_token_decimals,
    });

    let outbound = Arc::new(OutboundRelayer {
        client: ZagrosClient::new(config.zagros.rpc_url.clone()),
        store: RelayerStore::new(storage.clone()),
        zagros_signing_key,
        zagros_authority_address,
        ethereum_signing_key,
        ethereum_relayer_address,
        gateway_contract_address,
        unlock_token_address,
        unlock_token_decimals: config.ethereum.unlock_token_decimals,
        ethereum_chain_id: config.ethereum.ethereum_chain_id,
        chain_id: config.bridge.chain_id,
        trusted_authorities,
        auto_recover_cursor_gap: config.bridge.auto_recover_cursor_gap,
    });

    // 2. Ethereum WS best-effort: bağlanamazsa servis durmaz, Zagros tarafı
    //    sürer, event pump WS gelene dek duraklar. 🚨 İlk bağlantı için artan
    //    beklemeyle 5 deneme (30 sn), restart anındaki geçici kesintiyi kapsar;
    //    kalıcı kesintide None (fail-closed korunur).
    let live_ethereum = {
        const MAX_TRY: u32 = 5;
        let mut signing_key_opt = Some(ethereum_signing_key);
        let mut relayer_addr_opt = Some(ethereum_relayer_address);
        let mut result = None;
        for attempt in 1..=MAX_TRY {
            match ethereum_watcher::connect(&config.ethereum.ws_rpc_url).await {
                Ok(provider) => {
                    info!(
                        "🔗 Ethereum WS bağlandı (deneme {}/{}) - event pump + unlock gönderimi aktif.",
                        attempt, MAX_TRY
                    );
                    result = Some(Arc::new(ethereum_watcher::LiveEthereum {
                        provider: tokio::sync::RwLock::new(provider),
                        ws_url: config.ethereum.ws_rpc_url.clone(),
                        gateway: gateway_contract_address,
                        ethereum_signing_key: signing_key_opt.take().unwrap(),
                        ethereum_relayer_address: relayer_addr_opt.take().unwrap(),
                    }));
                    break;
                }
                Err(e) if attempt < MAX_TRY => {
                    let wait = std::time::Duration::from_secs(2u64.pow(attempt));
                    tracing::warn!(
                        "⚠️ Ethereum WS bağlanamadı (deneme {}/{}: {}) - {}sn sonra yeniden denenecek.",
                        attempt, MAX_TRY, e, wait.as_secs()
                    );
                    tokio::time::sleep(wait).await;
                }
                Err(e) => {
                    tracing::warn!(
                        "⚠️ Ethereum WS {} denemede de bağlanamadı ({}) - Zagros-tarafı \
                         koordinasyon çalışacak; Ethereum event pump + unlock gönderimi ancak \
                         SÜREÇ YENİDEN BAŞLATILDIĞINDA (ve WS erişilebilir olduğunda) devreye girer.",
                        MAX_TRY, e
                    );
                }
            }
        }
        result
    };

    // 3. İptal (graceful shutdown) sinyali + arka plan döngüleri.
    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    let poll_interval = config.zagros.poll_interval_secs;
    let eth_poll_interval = config.ethereum.poll_interval_secs;
    const REORG_BUFFER_BLOCKS: u64 = 6;
    // 🚨 Tarama parametreleri config'ten: start_block kasanın deploy bloğu,
    // max_log_range sağlayıcının `eth_getLogs` limiti. Yanlış olurlarsa event
    // pump ya hiç çalışmaz ya da tüm zinciri taramaya kalkıp reddedilir.
    let scan_params = zagros_relayer::ethereum_watcher::ScanParams {
        confirmation_depth: config.ethereum.confirmation_depth,
        reorg_buffer: REORG_BUFFER_BLOCKS,
        start_block: config.ethereum.start_block,
        max_range: config.ethereum.max_log_range,
    };

    let mut handles = Vec::new();

    // 🛡️ Eş imza YALNIZ canlı Ethereum bağlantılı event-pump döngüsünün içinde;
    // bağlantı yoksa bu relayer eş imzalamaz (fail-closed).

    // 3b. Inbound, Ethereum event pump: TokensLocked → mint önerisi (yalnızca WS varsa).
    let reset_inbound_cursor = config.ethereum.reset_inbound_cursor;
    if let Some(live) = live_ethereum.clone() {
        let inbound = inbound.clone();
        let cancel_rx = cancel_rx.clone();
        handles.push(tokio::spawn(async move {
            inbound
                // 🚨 Ethereum taraması KENDİ (daha uzun) aralığını kullanır,
                // yerel Zagros taramasını hızlandırmak sağlayıcıyı yakmasın.
                .run_event_subscription_loop(
                    live.as_ref(),
                    scan_params,
                    eth_poll_interval,
                    reset_inbound_cursor,
                    cancel_rx,
                )
                .await
        }));
    }

    // 3c. Outbound: Zagros burn → co-sign → claim fişi üret → düğüme bırak.
    //     Ethereum bağlantısı gerekmez.
    {
        let outbound = outbound.clone();
        let cancel_rx = cancel_rx.clone();
        handles.push(tokio::spawn(async move {
            outbound.run_loop(poll_interval, cancel_rx).await
        }));
    }

    // 3d. İdempotency temizliği (günlük, `retention_days`).
    // ❤️ HEARTBEAT: sağlıklı relayer tamamen sessizdi, "takıldı" ile "iş yok"
    // ayırt edilemiyordu; periyodik iki imleç + Ethereum başı yazılır, izleme tazeliğe bakar.
    {
        let hb_store = RelayerStore::new(storage.clone());
        let hb_eth = live_ethereum.clone();
        let mut cancel_rx = cancel_rx.clone();
        handles.push(tokio::spawn(async move {
            const HEARTBEAT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);
            let mut ticker = tokio::time::interval(HEARTBEAT_INTERVAL);
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let inbound = hb_store.get_inbound_cursor().ok().flatten();
                        let outbound = hb_store.get_outbound_cursor().ok();
                        // WS kopmuş olabilir; heartbeat bundan ETKİLENMEZ, zincir
                        // başı "?" olarak yazılır ve imleçler yine raporlanır.
                        let head = match hb_eth.as_ref() {
                            Some(eth) => {
                                use ethers_providers::Middleware;
                                let p = eth.provider.read().await;
                                p.get_block_number().await.ok().map(|b| b.as_u64())
                            }
                            None => None,
                        };
                        let lag = match (head, inbound) {
                            (Some(h), Some(i)) => Some(h.saturating_sub(i)),
                            _ => None,
                        };
                        info!(
                            "❤️ heartbeat | eth_head={} eth_imlec={} gecikme={} zagros_imlec={}",
                            head.map(|v| v.to_string()).unwrap_or_else(|| "?".into()),
                            inbound.map(|v| v.to_string()).unwrap_or_else(|| "?".into()),
                            lag.map(|v| v.to_string()).unwrap_or_else(|| "?".into()),
                            outbound.map(|v| v.to_string()).unwrap_or_else(|| "?".into()),
                        );
                    }
                    _ = cancel_rx.changed() => {
                        if *cancel_rx.borrow() {
                            break;
                        }
                    }
                }
            }
        }));
    }

    //     siler. Düşük öncelikli bakım işi, başarısızlığı sessizce
    //     loglanır, servisin geri kalanını etkilemez.
    {
        let sweep_store = RelayerStore::new(storage.clone());
        let retention_secs = config.idempotency.retention_days.saturating_mul(86_400);
        let mut cancel_rx = cancel_rx.clone();
        handles.push(tokio::spawn(async move {
            const SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(86_400);
            let mut ticker = tokio::time::interval(SWEEP_INTERVAL);
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        match sweep_store
                            .prune_expired_idempotency_markers(zagros_relayer::now_unix_secs(), retention_secs)
                        {
                            Ok(0) => {}
                            Ok(n) => info!("🧹 item 11 süpürmesi: {} süresi dolmuş idempotency kaydı silindi.", n),
                            Err(e) => tracing::warn!("item 11 idempotency süpürmesi başarısız oldu: {}", e),
                        }
                    }
                    _ = cancel_rx.changed() => {
                        if *cancel_rx.borrow() {
                            break;
                        }
                    }
                }
            }
        }));
    }

    info!(
        "🚀 Relayer devrede - {} arka plan döngüsü çalışıyor. (Ctrl-C / SIGTERM ile durdur.)",
        handles.len()
    );

    // 4. Kapatma sinyalini bekle, sonra döngüleri TEMİZ durdur.
    wait_for_shutdown_signal().await;
    info!("🛑 Kapatma sinyali alındı - döngülere graceful shutdown gönderiliyor...");
    let _ = cancel_tx.send(true);
    for handle in handles {
        let _ = handle.await;
    }
    info!("✅ Relayer temiz bir şekilde kapandı.");

    Ok(())
}

/// SIGINT (Ctrl-C) veya SIGTERM'i bekler. Container/systemd ortamlarında SIGTERM
/// standart kapatma sinyalidir; ikisini de dinliyoruz.
async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    "SIGTERM dinleyici kurulamadı ({}), yalnızca Ctrl-C dinleniyor.",
                    e
                );
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
