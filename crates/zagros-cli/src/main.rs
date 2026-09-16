#![allow(clippy::field_reassign_with_default)]
use std::sync::Arc;
use tracing::info;
use zagros_storage::Storage;

use zagros_consensus::ConsensusEngine;
use zagros_executor::bridge::{BridgeAuthority, BridgeManager, BridgeTxType, ClaimContext};
use zagros_executor::Executor;
use zagros_mempool::Mempool;
use zagros_metrics::init_telemetry;
use zagros_rpc::RpcServer;
use zagros_runtime::{PruningConfig, Runtime};
use zagros_scheduler::Scheduler;
use zagros_state::{manager::StateDbManager, State};
use zagros_storage::rocksdb_impl::RocksDbStorage;
use zagros_types::{
    config::ZagrosConfig, format_token_amount, format_token_amount_whole, AccountState,
    GasCalculator, Transaction, TxType, CHAIN_ID, FOUNDER_ADDRESS, FOUNDER_GENESIS_ZAGROS,
    FOUNDER_GENESIS_ZERENYA, GENESIS_POOL_ZAGROS, GENESIS_POOL_ZERENYA, TOTAL_SUPPLY,
    VALIDATOR_REWARD_POOL,
};

mod governance_cmd;
pub mod replay_guard;
mod snapshot_cmd;
mod validator_cmd;

/// Argümansız çalıştırma node'u önyükler (`command` `None`); alt komutlar yalnız
/// bakım/kurtarma araçlarıdır, normal çalışma yolunu değiştirmez.
#[derive(clap::Parser)]
#[command(name = "zagros-cli", about = "Zagros Network node ve bakım araçları")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Snapshot (RocksDB checkpoint) yönetimi.
    Snapshot {
        #[command(subcommand)]
        action: SnapshotAction,
    },
    /// Governance bakım/kurtarma komutları.
    Governance {
        #[command(subcommand)]
        action: GovernanceAction,
    },
    /// Validator operatör araçları (anahtar üretimi vb).
    Validator {
        #[command(subcommand)]
        action: ValidatorAction,
    },
    /// Yapılandırma araçları.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
}

#[derive(clap::Subcommand)]
enum ConfigAction {
    /// 🛡️ Config'i node'u başlatmadan yükleyip doğrular; filo script'leri
    /// restart öncesi çağırır, hatalı satır canlı validatörü düşürmeden yakalanır. Çıkış 0 = geçerli.
    Check {
        #[arg(long, default_value = "config.toml")]
        config: String,
    },
}

#[derive(clap::Subcommand)]
enum SnapshotAction {
    /// Mevcut state'in bir snapshot'ını (RocksDB checkpoint + metadata.json) alır.
    Create {
        #[arg(long, default_value = "config.toml")]
        config: String,
    },
    /// Bir snapshot'ı yeni (ÖNCEDEN VAR OLMAYAN) bir veri dizinine geri yükler.
    Restore {
        #[arg(long)]
        snapshot_id: String,
        #[arg(long)]
        target_data_dir: String,
        #[arg(long, default_value = "config.toml")]
        config: String,
    },
    /// Mevcut snapshot'ları listeler.
    List {
        #[arg(long, default_value = "config.toml")]
        config: String,
    },
}

#[derive(clap::Subcommand)]
enum GovernanceAction {
    /// R2: `__ACTIVE_PROPOSAL_COUNT__` sayacını diskteki TÜM önerileri
    /// tarayarak sıfırdan yeniden hesaplar (state corruption recovery).
    RepairActiveCount {
        #[arg(long, default_value = "config.toml")]
        config: String,
    },
}

#[derive(clap::Subcommand)]
enum ValidatorAction {
    /// Yeni bir Ed25519 konsensüs anahtarı üretir ve 0600 izinli bir
    /// keyfile'a yazar (`network.consensus_key_path` formatı).
    GenKey {
        #[arg(long, default_value = "consensus.key")]
        out: String,
    },
    /// Konsensüs anahtarıyla EVM adresine bağlı "sahiplik kanıtı" üretir
    /// (`RegisterValidator`/rotasyon imzası, bu makinede). Node GEÇİCİ DURDURULMALI (RocksDB tek yazar).
    ProveOwnership {
        #[arg(long, default_value = "consensus.key")]
        key: String,
        #[arg(long, default_value = "config.toml")]
        config: String,
        /// Kanıtın bağlanacağı EVM cüzdan adresi (0x...).
        #[arg(long)]
        address: String,
    },
    /// `RegisterValidator` işlemi için TAM calldata'yı (seçici + kodlanmış
    /// payload) üretir, dApp'in kayıt formuna doğrudan yapıştırılacak tek
    /// satır. Node bu komut çalışırken GEÇİCİ OLARAK DURDURULMALI.
    RegisterPayload {
        #[arg(long, default_value = "consensus.key")]
        key: String,
        #[arg(long, default_value = "config.toml")]
        config: String,
        #[arg(long)]
        address: String,
        /// Sunucu sağlayıcısı beyanı (ör. "hetzner", "aws").
        #[arg(long)]
        provider: String,
        /// Bölge beyanı (ör. "eu-central-1").
        #[arg(long)]
        region: String,
        /// Sunucunun ASN numarası.
        #[arg(long)]
        asn: u32,
        /// Operatör kimliğinin 32 baytlık (64 hex karakter) hash'i, gizlilik
        /// için ham bir kimlik DEĞİL, onun hash'i beklenir.
        #[arg(long)]
        operator_id_hex: String,
    },
    /// G14 (§15): `RotateConsensusKey` calldata'sı (YENİ anahtar, zincirdeki mevcut
    /// pubkey üzerinden kanıt). Rotasyon sonraki epoch'ta etkinleşir; node GEÇİCİ DURDURULMALI.
    RotatePayload {
        /// YENİ konsensüs anahtar dosyası (önce `gen-key --out <yeni>` ile üretin).
        #[arg(long)]
        new_key: String,
        #[arg(long, default_value = "config.toml")]
        config: String,
        /// Validator hesabının EVM cüzdan adresi (0x...).
        #[arg(long)]
        address: String,
    },
}

/// 📸 Otomatik snapshot kancası (`Runtime::snapshot_hook`): her blok yolunda
/// `state.flush()` sonrası çağrılır; yalnız tek proposer döngüsünde olsaydı BFT'de çalışmazdı.
fn build_snapshot_hook(
    state: Arc<dyn State>,
    storage: Arc<RocksDbStorage>,
    snapshots_root: String,
    snapshot_interval_blocks: u64,
    max_snapshots_to_retain: usize,
) -> Arc<dyn Fn(u64) + Send + Sync> {
    // Son snapshot yüksekliği kalıcı sentinel'den; her açılışta zincir yüksekliğinden
    // tohumlansaydı sık restart edilen node'da snapshot hiç alınmazdı.
    let last_height = Arc::new(std::sync::atomic::AtomicU64::new(
        state
            .get_account(&"__SNAPSHOT_LAST_HEIGHT__".to_string())
            .ok()
            .flatten()
            .map(|a| a.balance as u64)
            .filter(|h| *h > 0)
            .or_else(|| {
                state
                    .get_account(&"__GLOBAL_BLOCK_HEIGHT__".to_string())
                    .ok()
                    .flatten()
                    .map(|a| a.balance as u64)
            })
            .unwrap_or(0),
    ));
    Arc::new(move |block_number: u64| {
        if snapshot_interval_blocks == 0 {
            return;
        }
        let prev = last_height.load(std::sync::atomic::Ordering::Relaxed);
        if block_number.saturating_sub(prev) < snapshot_interval_blocks {
            return;
        }
        let state_root = match state.state_root() {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("⚠️ Otomatik snapshot: state_root okunamadı, atlanıyor: {e}");
                return;
            }
        };
        let now_secs = std::time::UNIX_EPOCH
            .elapsed()
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let id = zagros_storage::snapshot::make_snapshot_id(block_number as u128, now_secs);
        let root_path = std::path::Path::new(&snapshots_root);
        if let Err(e) = std::fs::create_dir_all(root_path) {
            tracing::warn!("⚠️ Otomatik snapshot: kök dizin oluşturulamadı, atlanıyor: {e}");
            return;
        }
        let snapshot_dir = zagros_storage::snapshot::snapshot_dir_for(root_path, &id);
        if let Err(e) = storage.create_snapshot(&snapshot_dir) {
            tracing::warn!("⚠️ Otomatik snapshot oluşturulamadı, atlanıyor: {e}");
            return;
        }
        let meta = zagros_storage::snapshot::SnapshotMetadata {
            id: id.clone(),
            created_at_unix_secs: now_secs,
            block_height: block_number as u128,
            chain_id: zagros_types::CHAIN_ID,
            state_root_hex: format!("0x{}", hex::encode(state_root)),
        };
        if let Err(e) = zagros_storage::snapshot::write_metadata(&snapshot_dir, &meta) {
            tracing::warn!("⚠️ Otomatik snapshot metadata yazılamadı: {e}");
        }
        tracing::info!(
            "📸 Otomatik snapshot alındı: {} (blok #{})",
            id,
            block_number
        );
        last_height.store(block_number, std::sync::atomic::Ordering::Relaxed);
        // Operatör paneli (`zagros_getSnapshotStatus`) için şeffaflık kayıtları.
        let mut height_acc = AccountState::default();
        height_acc.balance = block_number as u128;
        let _ = state.set_account(&"__SNAPSHOT_LAST_HEIGHT__".to_string(), height_acc);
        let mut time_acc = AccountState::default();
        time_acc.balance = now_secs as u128;
        let _ = state.set_account(&"__SNAPSHOT_LAST_CREATED_AT__".to_string(), time_acc);
        if let Err(e) =
            zagros_storage::snapshot::prune_old_snapshots(root_path, max_snapshots_to_retain)
        {
            tracing::warn!("⚠️ Eski snapshot'lar temizlenemedi: {e}");
        }
    })
}

/// Nonce boşluğu predikatı: bloktan çekilip uygulanamayan tx yalnız gönderenin
/// güncel nonce'undan İLERİDEYSE mempool'da bekletilir, gerisi silinir.
fn tx_is_forward_nonce_gap(tx_nonce: u64, committed_sender_nonce: u64) -> bool {
    tx_nonce > committed_sender_nonce
}

/// 🚨 Köprü yetkilisi adresi `signer_secret_key_hex`ten bağımsız çözülür (follower
/// yoksa muaf mint'i reddedip state_root'ta ayrışırdı). `configured` ile `derived` UYUŞMALI, yoksa `panic!`.
fn resolve_bridge_authority(configured: Option<&str>, derived: Option<&str>) -> Option<String> {
    match (configured, derived) {
        (Some(configured), Some(derived)) => {
            if !configured.eq_ignore_ascii_case(derived) {
                panic!(
                    "config.bridge.authority_address ({}) config.bridge.signer_secret_key_hex'ten \
                     türetilen adresle ({}) UYUŞMUYOR - ikisi AYNI köprü yetkilisini işaret \
                     etmeli, node güvenlik nedeniyle BAŞLAMIYOR.",
                    configured, derived
                );
            }
            Some(configured.to_string())
        }
        (Some(configured), None) => Some(configured.to_string()),
        (None, Some(derived)) => Some(derived.to_string()),
        (None, None) => {
            tracing::warn!(
                "⚠️ Ne [bridge].authority_address ne [bridge].signer_secret_key_hex \
                 tanımlı - Executor::bridge_authority derleme-zamanı BRIDGE_AUTHORITY_ADDRESS \
                 (=FOUNDER_ADDRESS) sabitine düşüyor. Köprü zaten kullanılıyorsa bu YANLIŞ \
                 olabilir - [bridge].authority_address'i gerçek köprü yetkilisi adresiyle \
                 ayarlayın (HER node'da, proposer ve follower dahil, aynı değer)."
            );
            None
        }
    }
}

/// Operatör uyarısı: webhook'a fire-and-forget POST (üretici döngüsünü
/// bloklamaz); gövde Discord + Slack formatını birlikte taşır.
fn spawn_webhook_alert(client: reqwest::Client, url: String, message: String) {
    tokio::spawn(async move {
        let body = serde_json::json!({ "content": message, "text": message });
        if let Err(e) = client.post(&url).json(&body).send().await {
            tracing::warn!("⚠️ Uyarı webhook'u gönderilemedi ({}): {}", url, e);
        }
    });
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

/// 🛡️ Genesis state'i cache'e yazılır (`flush()` ister), `block_0` doğrudan diske.
/// SIRA KRİTİK: flush `block_0`dan ÖNCE, yoksa erken restart genesis'i atlar ve
/// kurucu bakiyesi/havuz kaybolur. Ayrı fonksiyon: RocksDB ile test edilebilsin.
fn hex_decode_32(s: &str) -> Result<[u8; 32], String> {
    let trimmed = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    let bytes = hex::decode(trimmed).map_err(|e| format!("hex cozulemedi: {e}"))?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| format!("32 bayt bekleniyordu, {} bayt geldi", v.len()))
}

fn initialize_genesis_if_needed(
    storage: &dyn Storage,
    state: &dyn zagros_state::State,
    genesis_config: &zagros_types::config::GenesisConfig,
) -> Result<bool, String> {
    // 🧠 Hafıza kaybı kalkanı: diskte block_0 varsa genesis ASLA yeniden çalışmaz.
    let should_initialize_genesis = storage
        .get(b"block_0")
        .map_err(|e| format!("block_0 okunamadı: {}", e))?
        .is_none();

    if !should_initialize_genesis {
        return Ok(false);
    }

    info!("🧬 Genesis State başlatılıyor, token mukaveleleri kuruluyor...");

    let genesis_message = "The Times 21/07/2026 Em ne hatin veguherîna pereyan. Em hatin ji nû ve pênasekirina pêbaweriyê. | The Times 03/Jan/2009 Chancellor on brink of second bailout for banks.";
    info!("📜 GENESIS MANİFESTOSU: {}", genesis_message);

    // 1. KURUCU CÜZDAN. 🚨 500 ZERENYA PAXG karşılıksızdır; havuzun 10.500'üyle karıştırılmamalı.
    let mut founder_acc = AccountState::default();
    founder_acc.balance = FOUNDER_GENESIS_ZAGROS;
    founder_acc.zerenya_balance = FOUNDER_GENESIS_ZERENYA;
    state
        .set_account(&FOUNDER_ADDRESS.to_string(), founder_acc)
        .map_err(|e| format!("Kurucu hesabı yazılamadı: {}", e))?;

    // 💥 NATIVE L1 AMM KURULUMU: rezervler doğrudan LIQUIDITY_POOL_ADDRESS
    // hesabında (state_root'a dahil); `set_pool_reserves` tek gerçek kaynak.
    state
        .set_pool_reserves(GENESIS_POOL_ZAGROS, GENESIS_POOL_ZERENYA)
        .map_err(|e| format!("Havuz rezervleri yazılamadı: {}", e))?;

    // 🚨 KRİTİK: teminat sayacı SIFIRDAN başlar, GENESIS_POOL_ZERENYA ile seed
    // edilmez: genesis havuzu yalnız AMM fiyat dengesi için var, gerçek PAXG
    // karşılığı yok; seed edilseydi teminatsız ZERENYA köprüden PAXG'ye çevrilebilirdi.
    state
        .set_account(&Executor::bridge_backed_zerenya_key(), AccountState::new(0))
        .map_err(|e| format!("Kopru teminat sayaci tohumlanamadi: {}", e))?;

    // 🛡️ 0x...02'ye yalnız ZERENYA görüntüsü, `balance`a ZAGROS yazılmaz (hayalet
    // bakiye toplamı ikiye katlardı); `totalSupply()` bu alanı okumaz.
    let mut zerenya_token_acc = AccountState::default();
    zerenya_token_acc.zerenya_balance = GENESIS_POOL_ZERENYA;
    state
        .set_account(
            &"0x0000000000000000000000000000000000000002".to_string(),
            zerenya_token_acc,
        )
        .map_err(|e| format!("ZERENYA token anlık görüntüsü yazılamadı: {}", e))?;

    info!("🌌 BÜYÜK PATLAMA (GENESIS): Çelik Kasaya (Native L1 Havuz) Fiziksel Likidite İndirildi! Fiyat: 1 ZAGROS ≈ 7,7759 mg altın");

    // ⏱️ Kurucu yetkisi saati burada başlar (işaretçi yoksa fail-closed). 🛡️ Sabit
    // `GENESIS_TIMESTAMP`: `block_0` baytlarına gömülür, node'lar arası hash sapmaz.
    let genesis_timestamp = zagros_types::GENESIS_TIMESTAMP;
    let mut genesis_timestamp_acc = AccountState::default();
    genesis_timestamp_acc.balance = genesis_timestamp;
    state
        .set_account(
            &zagros_types::GENESIS_TIMESTAMP_KEY.to_string(),
            genesis_timestamp_acc,
        )
        .map_err(|e| format!("Genesis zaman damgası yazılamadı: {}", e))?;

    // ⚖️ G8: BFT genesis kurulumu, yalnız `genesis.validators` doluysa. FAIL-CLOSED
    // (<4 validator, geçersiz anahtar, eksik multisig). `genesis_root`tan ÖNCE.
    if !genesis_config.validators.is_empty() {
        let admin_cfg = genesis_config.admin_multisig.as_ref().ok_or_else(|| {
            "genesis.validators dolu ama genesis.admin_multisig eksik - BFT genesis icin ikisi de gerekli".to_string()
        })?;
        let signers: Vec<String> = admin_cfg.signers.clone();
        let multisig = zagros_types::consensus::AdminMultisig {
            signers,
            threshold: admin_cfg.threshold,
        };
        let chain_params = zagros_types::consensus::ChainParams::genesis_defaults();
        zagros_executor::params::store_chain_params(state, &chain_params)
            .map_err(|e| format!("Genesis ChainParams yazilamadi: {}", e))?;
        zagros_executor::params::store_admin_multisig(state, &multisig)
            .map_err(|e| format!("Genesis admin multisig yazilamadi: {}", e))?;

        let mut validators = Vec::with_capacity(genesis_config.validators.len());
        for v in &genesis_config.validators {
            let pubkey_bytes = hex_decode_32(&v.consensus_pubkey_hex).map_err(|e| {
                format!(
                    "genesis validator {}: consensus_pubkey_hex gecersiz: {e}",
                    v.address
                )
            })?;
            let operator_id = hex_decode_32(&v.operator_id_hex).map_err(|e| {
                format!(
                    "genesis validator {}: operator_id_hex gecersiz: {e}",
                    v.address
                )
            })?;
            let decl = zagros_types::consensus::ValidatorDeclaration {
                provider: v.provider.clone(),
                region: v.region.clone(),
                asn: v.asn,
                operator_id,
            };
            validators.push((v.address.clone(), pubkey_bytes, decl));
        }
        zagros_executor::validator_set::install_genesis_validator_set(
            state,
            &chain_params,
            &validators,
        )
        .map_err(|e| format!("Genesis validator kumesi kurulamadi: {}", e))?;
        info!(
            "⚖️ BFT genesis: {} validator + {}-of-{} admin multisig kuruldu.",
            validators.len(),
            multisig.threshold,
            multisig.signers.len()
        );
    }

    // G13 (§16.2): replay_guard nonce'ları final+1'den başlatır, kökten ÖNCE;
    // dosya bozuksa genesis FAIL-CLOSED.
    if let Some(path) = &genesis_config.replay_guard_file {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("replay_guard dosyasi okunamadi ({path}): {e}"))?;
        let entries = replay_guard::parse_file(&content)
            .map_err(|e| format!("replay_guard ayristirma: {e:?}"))?;
        let n = replay_guard::apply_to_genesis(state, &entries)
            .map_err(|e| format!("replay_guard uygulanamadi: {e:?}"))?;
        info!("🛡️ replay_guard: {} adres final_nonce+1'den baslatildi (testnet islemleri mainnet'te OLUMSUZ).", n);
    }

    // 🛡️ DEVLET MÜHRÜNÜ OLUŞTUR VE YAZDIR
    let genesis_root = state.state_root().unwrap_or([0u8; 32]);
    info!(
        "👑 Orijinal Genesis tamamlandı! Mühür (State Root): 0x{}",
        hex::encode(genesis_root)
    );

    // 🛡️ Toplam arz invariant'ı: Founder + Havuz = MAX_SUPPLY
    // (`GENESIS_POOL_ZAGROS = MAX_SUPPLY - FOUNDER_GENESIS_ZAGROS`); release'te
    // de görülsün diye `debug_assert_eq!`'e ek koşulsuz log.
    let founder_plus_pool = FOUNDER_GENESIS_ZAGROS + GENESIS_POOL_ZAGROS;
    debug_assert_eq!(
        founder_plus_pool,
        zagros_types::MAX_SUPPLY,
        "genesis invariant ihlali: founder_zagros + pool_zagros != MAX_SUPPLY"
    );
    if founder_plus_pool == zagros_types::MAX_SUPPLY {
        info!(
            "🛡️ Genesis supply invariant verified: Founder + Pool == MAX_SUPPLY ({} ZAGROS, {} ham \
             birim) | State Root: 0x{}",
            format_token_amount_whole(founder_plus_pool),
            founder_plus_pool,
            hex::encode(genesis_root)
        );
    } else {
        // Yalnız sabit tanımları bozulursa; release'te durmak yerine yüksek
        // görünürlüklü hata logu.
        tracing::error!(
            "🚨 GENESIS SUPPLY INVARIANT İHLALİ: Founder({}) + Pool({}) != MAX_SUPPLY({}) ham \
             birim - bu, sabit tanımlarında (types/lib.rs) bir hata olduğunu gösterir, derhal \
             araştırın! State Root: 0x{}",
            FOUNDER_GENESIS_ZAGROS,
            GENESIS_POOL_ZAGROS,
            zagros_types::MAX_SUPPLY,
            hex::encode(genesis_root)
        );
    }

    // 🛡️ ZERENYA genesis invariant'ı: Founder + Havuz = GENESIS_TOTAL_ZERENYA;
    // yalnız genesis anı için, sonrası köprüyle değişir.
    let founder_plus_pool_zerenya = FOUNDER_GENESIS_ZERENYA + GENESIS_POOL_ZERENYA;
    debug_assert_eq!(
        founder_plus_pool_zerenya,
        zagros_types::GENESIS_TOTAL_ZERENYA,
        "genesis invariant ihlali: founder_zerenya + pool_zerenya != GENESIS_TOTAL_ZERENYA"
    );
    if founder_plus_pool_zerenya == zagros_types::GENESIS_TOTAL_ZERENYA {
        info!(
            "🛡️ Genesis ZERENYA invariant verified: Founder + Pool == GENESIS_TOTAL_ZERENYA ({} \
             ZERENYA, {} ham birim, {} PAXG-teminatli)",
            format_token_amount_whole(founder_plus_pool_zerenya),
            founder_plus_pool_zerenya,
            format_token_amount_whole(GENESIS_POOL_ZERENYA)
        );
    } else {
        tracing::error!(
            "🚨 GENESIS ZERENYA INVARIANT İHLALİ: Founder({}) + Pool({}) != GENESIS_TOTAL_ZERENYA({}) \
             ham birim - bu, sabit tanımlarında (types/lib.rs) bir hata olduğunu gösterir, derhal \
             araştırın!",
            FOUNDER_GENESIS_ZERENYA,
            GENESIS_POOL_ZERENYA,
            zagros_types::GENESIS_TOTAL_ZERENYA
        );
    }

    // 🛡️ block_0 yazılmadan ÖNCE genesis state'i FLUSH edilir (erken restart
    // genesis'i atlamasın). Başlık flush'tan önce inşa edilir: `genesis_hash` bu baytların keccak256'sı.
    let genesis_header = zagros_types::BlockHeader {
        number: 0,
        timestamp: genesis_timestamp,
        parent_hash: [0u8; 32],
        state_root: genesis_root,
        extra_data: genesis_message.as_bytes().to_vec(),
    };
    let genesis_bytes = bincode::serialize(&genesis_header)
        .map_err(|e| format!("Genesis bloğu serileştirilemedi: {}", e))?;

    if !genesis_config.validators.is_empty() {
        use sha3::{Digest, Keccak256};
        let mut hasher = Keccak256::new();
        hasher.update(&genesis_bytes);
        let digest = hasher.finalize();
        let mut genesis_hash = [0u8; 32];
        genesis_hash.copy_from_slice(&digest);
        zagros_executor::params::store_genesis_hash(state, &genesis_hash)
            .map_err(|e| format!("Genesis hash yazilamadi: {}", e))?;
        info!("⚖️ BFT genesis_hash: 0x{}", hex::encode(genesis_hash));
    }

    state
        .flush()
        .map_err(|e| format!("Genesis state'i diske flush edilemedi: {}", e))?;

    // 📜 BLOCK #0'I ROCKSDB'YE KAYDET (flush'tan SONRA, invariant korunur)
    storage
        .put(b"block_0", &genesis_bytes)
        .map_err(|e| format!("Genesis bloğu diske yazılamadı: {}", e))?;

    info!("📜 Genesis Bloğu (Block #0) manifestosuyla birlikte RocksDB'ye ebediyen kazındı!");
    info!("📖 Mesaj: {}", genesis_message);

    Ok(true)
}

/// Executor sürüm kararını (`decide_executor_version_action`) gerçek `State`'e
/// uygular: onaylı yükseltmede sürümü günceller, onaysız yükseltme/geri sarmada
/// başlamayı REDDEDEN `Err` döner. Ayrı fonksiyon, RocksDB ile test edilebilsin.
fn apply_executor_version_check(
    state: &dyn zagros_state::State,
    should_initialize_genesis: bool,
    acknowledged_version: Option<u32>,
) -> Result<(), String> {
    let stored_executor_version =
        match state.get_account(&zagros_types::EXECUTOR_STATE_VERSION_KEY.to_string()) {
            Ok(Some(acc)) => Some(acc.balance as u32),
            Ok(None) => None,
            Err(e) => {
                // Okuma hatası konsensüs sürüm uyuşmazlığı değil, depolama hatası:
                // uyarıp None varsayılır (okunamayan anahtar = hiç yazılmamış).
                tracing::warn!("Executor state sürümü okunamadı: {}", e);
                None
            }
        };

    match zagros_types::decide_executor_version_action(
        stored_executor_version,
        should_initialize_genesis,
        zagros_types::EXECUTOR_STATE_TRANSITION_VERSION,
        acknowledged_version,
    ) {
        zagros_types::ExecutorVersionDecision::FreshGenesis => {
            let mut acc = zagros_types::AccountState::default();
            acc.balance = zagros_types::EXECUTOR_STATE_TRANSITION_VERSION as u128;
            if let Err(e) =
                state.set_account(&zagros_types::EXECUTOR_STATE_VERSION_KEY.to_string(), acc)
            {
                tracing::warn!("Executor state sürümü diske yazılamadı: {}", e);
            }
            Ok(())
        }
        zagros_types::ExecutorVersionDecision::UpToDate => Ok(()),
        zagros_types::ExecutorVersionDecision::UpgradeAcknowledged { from } => {
            tracing::warn!(
                "🚨 KONSENSÜS DEĞİŞİKLİĞİ ONAYLANDI: diskteki state executor sürüm {} ile \
                 üretilmiş; operatör `acknowledged_executor_state_version = {}` ile bu \
                 yükseltmeyi AÇIKÇA onayladığı için devam ediliyor. Bu, state_root byte'larını \
                 etkileyen BREAKING bir değişikliktir - ağdaki TÜM node'ların eşzamanlı \
                 yükseltildiğinden EMİN OLUN.",
                from,
                zagros_types::EXECUTOR_STATE_TRANSITION_VERSION
            );
            let mut acc = zagros_types::AccountState::default();
            acc.balance = zagros_types::EXECUTOR_STATE_TRANSITION_VERSION as u128;
            if let Err(e) =
                state.set_account(&zagros_types::EXECUTOR_STATE_VERSION_KEY.to_string(), acc)
            {
                tracing::warn!("Executor state sürümü diske yazılamadı: {}", e);
            }
            Ok(())
        }
        zagros_types::ExecutorVersionDecision::UpgradeNotAcknowledged { from } => Err(format!(
            "🛑 BAŞLAMA REDDEDİLDİ - KONSENSÜS-KIRICI YÜKSELTME ONAYLANMADI:\n\
             \n\
             Diskteki state executor sürüm {from} ile üretilmiş; bu ikili dosya sürüm {current} \
             çalıştırıyor (ör. EVM storage slot temizliği - sıfır değerli slotlar artık \
             saklanmıyor, `storage.remove` kullanılıyor, `storage.insert(_, 0)` DEĞİL).\n\
             Bu, state_root byte'larını etkileyen BREAKING bir konsensüs değişikliğidir.\n\
             \n\
             Devam etmeden ÖNCE:\n\
             1. Ağdaki/filodaki TÜM node'ların AYNI ANDA sürüm {current}'e yükseltileceğinden \
                emin olun (karışık sürümlerle çalışan node'lar FARKLI state_root üretir).\n\
             2. Bunu onayladıktan SONRA, config.toml'a şunu ekleyin:\n\
             \n\
             \tacknowledged_executor_state_version = {current}\n\
             \n\
             3. Node'u tekrar başlatın.",
            from = from,
            current = zagros_types::EXECUTOR_STATE_TRANSITION_VERSION
        )),
        zagros_types::ExecutorVersionDecision::Downgrade { disk_version } => Err(format!(
            "🛑 BAŞLAMA REDDEDİLDİ - GERİ SARMA TESPİT EDİLDİ:\n\
             \n\
             Diskteki state, bu ikiliden (sürüm {current}) DAHA YENİ bir executor sürümüyle \
             (sürüm {disk_version}) dokunulmuş. Bu ikiliyle devam etmek, aynı geçmişi işleyen \
             sürüm {disk_version} bir node'unkinden FARKLI bir state_root üretebilir.\n\
             \n\
             Bu ASLA onaylanamaz/atlanamaz - tek çözüm en az sürüm {disk_version} çalıştıran \
             bir ikili dosyaya yükseltmektir.",
            current = zagros_types::EXECUTOR_STATE_TRANSITION_VERSION,
            disk_version = disk_version
        )),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use clap::Parser;
    let cli = Cli::parse();
    if let Some(command) = cli.command {
        let result = match command {
            Commands::Snapshot { action } => match action {
                SnapshotAction::Create { config } => snapshot_cmd::create(&config),
                SnapshotAction::Restore {
                    snapshot_id,
                    target_data_dir,
                    config,
                } => snapshot_cmd::restore(&snapshot_id, &target_data_dir, &config),
                SnapshotAction::List { config } => snapshot_cmd::list(&config),
            },
            Commands::Governance { action } => match action {
                GovernanceAction::RepairActiveCount { config } => {
                    governance_cmd::repair_active_count(&config)
                }
            },
            Commands::Validator { action } => match action {
                ValidatorAction::GenKey { out } => validator_cmd::gen_key(&out),
                ValidatorAction::ProveOwnership {
                    key,
                    config,
                    address,
                } => validator_cmd::prove_ownership(&key, &config, &address),
                ValidatorAction::RegisterPayload {
                    key,
                    config,
                    address,
                    provider,
                    region,
                    asn,
                    operator_id_hex,
                } => validator_cmd::register_payload(
                    &key,
                    &config,
                    &address,
                    &provider,
                    &region,
                    asn,
                    &operator_id_hex,
                ),
                ValidatorAction::RotatePayload {
                    new_key,
                    config,
                    address,
                } => validator_cmd::rotate_payload(&new_key, &config, &address),
            },
            Commands::Config { action } => match action {
                ConfigAction::Check { config } => match ZagrosConfig::from_file(&config) {
                    Ok(c) => {
                        let n = &c.network;
                        let rol = if n.sentry_mode {
                            "sentry"
                        } else if n.consensus_key_path.is_some() {
                            "validator"
                        } else {
                            "acik dugum"
                        };
                        println!(
                            "OK {config}: rol={rol} private_peers={} sentry_addrs={} external_addr={} max_peers={} per_ip={} reserved={}",
                            n.private_peers.len(),
                            n.sentry_addrs.len(),
                            n.external_addr.as_deref().unwrap_or("-"),
                            n.max_peers,
                            n.max_peers_per_ip,
                            n.reserved_validator_slots
                        );
                        Ok(())
                    }
                    Err(e) => {
                        eprintln!("HATA {config}: {e}");
                        std::process::exit(1)
                    }
                },
            },
        };
        return result.map_err(|e| -> Box<dyn std::error::Error> { e.into() });
    }

    // 📊 KUSURSUZ TERMİNAL AÇILIŞ PANELİ
    init_telemetry();
    info!("===========================================================");
    info!("⚙️  ZAGROS MAINNET KERNEL NODE ATEŞLENİYOR...");
    info!("===========================================================");
    info!("🔗 Chain ID               : {}", CHAIN_ID);
    info!(
        "🪙 Total Supply           : {} ZAGROS",
        format_token_amount_whole(TOTAL_SUPPLY)
    );
    info!("📐 Token Decimal          : 10^18");
    info!("👑 Founder Address        : {}", FOUNDER_ADDRESS);
    info!(
        "💧 L1 Native AMM Target   : {} ZAGROS / {} ZERENYA",
        format_token_amount_whole(GENESIS_POOL_ZAGROS),
        format_token_amount_whole(GENESIS_POOL_ZERENYA)
    );
    info!("===========================================================");

    // 🧠 YAPILANDIRMA YÜKLEME
    let mut config = ZagrosConfig::from_file("config.toml")?;

    // 🌉 KÖPRÜ İMZALAYICI ANAHTARI: kurucudan ayrı, yalnız onaylı mint'leri imzalar.
    // Ham baytlar `Zeroizing`, `SecretKey` geçici türetilir. 🔐 `signer_key_path`
    // 0600 dosyadan tek satır hex; ikisi birden verilirse durulur.
    if config.bridge.signer_key_path.is_some() && config.bridge.signer_secret_key_hex.is_some() {
        panic!(
            "config.bridge: signer_key_path ve signer_secret_key_hex birlikte verilemez - \
             yalnızca birini kullanın (tercih: signer_key_path)"
        );
    }
    if let Some(path) = config.bridge.signer_key_path.clone() {
        // Grup/diğerlerine okunabilir bir anahtar dosyası kabul edilmez,
        // konsensüs/node anahtarlarındaki 0600 disipliniyle aynı çizgi.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path)
                .unwrap_or_else(|e| panic!("config.bridge.signer_key_path okunamadı ({path}): {e}"))
                .permissions()
                .mode();
            if mode & 0o077 != 0 {
                panic!(
                    "config.bridge.signer_key_path ({path}) izinleri çok açık (mode {:o}) - \
                     'chmod 600' yapın",
                    mode & 0o7777
                );
            }
        }
        let mut raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("config.bridge.signer_key_path okunamadı ({path}): {e}"));
        config.bridge.signer_secret_key_hex = Some(raw.trim().to_string());
        {
            use zeroize::Zeroize;
            raw.zeroize();
        }
    }
    let bridge_signer: Option<(zeroize::Zeroizing<[u8; 32]>, String)> =
        config.bridge.signer_secret_key_hex.as_ref().map(|hex_key| {
            let hex_str = hex_key.strip_prefix("0x").unwrap_or(hex_key);
            let decoded = zeroize::Zeroizing::new(
                hex::decode(hex_str).expect("config.bridge.signer_secret_key_hex geçersiz hex"),
            );
            if decoded.len() != 32 {
                panic!(
                    "config.bridge.signer_secret_key_hex 32 bayta çözülmeli, {} bayt bulundu",
                    decoded.len()
                );
            }
            let mut key_bytes = zeroize::Zeroizing::new([0u8; 32]);
            key_bytes.copy_from_slice(&decoded);
            // Yalnızca adresi türetmek için GEÇİCİ bir SecretKey, bu blok
            // bitince hemen düşer, kalıcı bir alanda TUTULMAZ.
            let address = {
                let secret_key = secp256k1::SecretKey::from_slice(key_bytes.as_slice()).expect(
                    "config.bridge.signer_secret_key_hex geçerli bir secp256k1 anahtarı değil",
                );
                Transaction::address_from_secret_key(&secret_key)
            };
            (key_bytes, address)
        });
    // Özel anahtar türetildi (`bridge_signer`); config'te düz hex daha uzun
    // kalmasın diye hemen sıfırlanır, `signer_secret_key_hex`'e bir daha erişilmez.
    {
        use zeroize::Zeroize;
        if let Some(hex) = config.bridge.signer_secret_key_hex.as_mut() {
            hex.zeroize();
        }
        config.bridge.signer_secret_key_hex = None;
    }

    if let Some((_, address)) = &bridge_signer {
        info!("🔑 Köprü İmzalayıcı Anahtarı yüklendi: {}", address);
    } else {
        tracing::warn!(
            "⚠️ config.toml'da ne [bridge].signer_key_path ne [bridge].signer_secret_key_hex \
             tanımlı - köprü mint \
             önerileri çoklu-imza eşiğine ulaşıp zaman kilidi dolsa bile OTOMATİK \
             YÜRÜTÜLMEYECEK (öneri sunma/imzalama RPC'leri yine de normal çalışır)."
        );
    }

    // 🚨 `bridge_authority` konsensüs kritik; adres açık `authority_address`ten
    // gelir ve HER node'da aynı olmalı, yoksa follower ayrışır.
    let effective_bridge_authority: Option<String> = resolve_bridge_authority(
        config.bridge.authority_address.as_deref(),
        bridge_signer.as_ref().map(|(_, address)| address.as_str()),
    );

    // 🧠 Tekil merkezi veritabanı: `open_with_recovery_and_tuning` bozuk WAL/SST'de
    // `DB::repair` dener, olmazsa kontrollü hata; [storage] ayarları uygulanır.
    let rocksdb_tuning = zagros_storage::rocksdb_impl::RocksDbTuningOptions {
        block_cache_mb: config.storage.cache_size_mb,
        write_buffer_size_mb: config.storage.write_buffer_size_mb,
        max_write_buffer_number: config.storage.max_write_buffer_number,
        target_file_size_base_mb: config.storage.target_file_size_base_mb,
        max_open_files: config.storage.max_open_files,
        bloom_filter_bits_per_key: config.storage.bloom_filter_bits_per_key,
        enable_statistics: config.storage.enable_statistics,
        max_background_jobs: config.storage.max_background_jobs,
    };
    let storage = Arc::new(RocksDbStorage::open_with_recovery_and_tuning(
        &config.storage.db_path,
        &rocksdb_tuning,
    )?);
    let state = Arc::new(
        StateDbManager::new(storage.clone())
            .with_max_cache_entries(config.storage.max_account_cache_entries),
    );

    // 🚨 TEK SEFERLİK ONARIM: `evm.rs::commit()`'in eski hatası normal cüzdanları
    // `is_contract=true`+`[0x00]` ile damgalamıştı; diskteki bozuk hesaplar
    // onarılır (idempotent, her başlangıçta güvenli).
    match state.repair_stale_evm_default_bytecode_corruption() {
        Ok(0) => {}
        Ok(n) => info!(
            "🛠️ ONARIM: {} hesap yanlışlıkla 'kontrat' damgasından EOA'ya geri çevrildi (evm.rs commit() kök neden hatası).",
            n
        ),
        Err(e) => tracing::error!("⚠️ Onarım taraması başarısız oldu (yok sayılıyor): {:?}", e),
    }

    // 🛡️ `BridgeManager`'ın AYNI eşiği/zaman kilidini kullanacak, `Executor`'a
    // da bağlanıyor (aşağıda) ki zincir seviyesindeki BridgeMint doğrulaması
    // ile off-chain BridgeManager AYRIŞMASIN. Tek kaynak: config.toml.
    let bridge_required_signatures = if config.bridge.authorities.is_empty() {
        2
    } else {
        config.bridge.required_signatures
    };

    // 🏛️ %20 validator ödül payı adresi (boşsa kimse "qualified" değil, tümü
    // stakerlara); mempool'un `canonical_sender` kuralıyla uyumlu küçük harf.
    let block_producer_address = config.consensus.block_producer_address.to_ascii_lowercase();

    // 🛡️ `handle_request` statik (imza değişemez): yapılandırılmış producer,
    // `__GLOBAL_BLOCK_HEIGHT__` deseniyle sentinel hesabın `contract_code`'una yazılır.
    state
        .set_account(
            &"__CONFIGURED_BLOCK_PRODUCER__".to_string(),
            AccountState {
                contract_code: block_producer_address.clone().into_bytes(),
                ..Default::default()
            },
        )
        .expect("configured block_producer_address state'e yazilamadi");

    // 🛡️ Aynı desen: `daily_mint_limit` sentinel'e yazılır ki RPC
    // (`zagros_getBridgeDailyMintStatus`) Executor'ın uyguladığı tavanı okusun.
    state
        .set_account(
            &"__CONFIGURED_BRIDGE_DAILY_MINT_LIMIT__".to_string(),
            AccountState {
                contract_code: config.bridge.daily_mint_limit.to_string().into_bytes(),
                ..Default::default()
            },
        )
        .expect("configured bridge daily_mint_limit state'e yazilamadi");

    let executor = Arc::new(match &effective_bridge_authority {
        Some(address) => Executor::new(state.clone())
            .with_bridge_authority(address.clone())
            .with_bridge_threshold(bridge_required_signatures, config.bridge.timelock_secs)
            .with_bridge_daily_mint_limit(config.bridge.daily_mint_limit)
            .with_gas_target(config.gas.gas_fee_zerenya as u128)
            .with_block_producer_address(block_producer_address.clone())
            .with_governance_config(&config.governance),
        None => Executor::new(state.clone())
            .with_bridge_threshold(bridge_required_signatures, config.bridge.timelock_secs)
            .with_bridge_daily_mint_limit(config.bridge.daily_mint_limit)
            .with_gas_target(config.gas.gas_fee_zerenya as u128)
            .with_block_producer_address(block_producer_address.clone())
            .with_governance_config(&config.governance),
    });

    // 🛡️ Governance pencereleri sentinel'e yazılır; `zagros_getProposal`
    // `effective_status` hesaplarken okur.
    state
        .set_account(
            &"__CONFIGURED_GOVERNANCE_WINDOWS__".to_string(),
            AccountState {
                balance: config.governance.voting_period_secs as u128,
                staked_balance: config.governance.proposal_expiry_secs as u128,
                ..Default::default()
            },
        )
        .expect("configured governance windows state'e yazilamadi");
    // 🗳️ Aynı desen: öneri ekonomisi (bedel/depozito, kilit eşiği, aktif öneri
    // tavanı), `zagros_getGovernanceInfo` dApp'e bunları buradan sunar.
    state
        .set_account(
            &"__CONFIGURED_GOVERNANCE_ECON__".to_string(),
            AccountState {
                balance: config.governance.proposal_fee,
                staked_balance: config.governance.min_stake_to_submit,
                nonce: config.governance.max_active_proposals as u64,
                ..Default::default()
            },
        )
        .expect("configured governance econ state'e yazilamadi");
    let scheduler = Arc::new(Scheduler::new(executor.clone()));
    // Arşiv budaması config.storage'dan; `enable_pruning: false` = sonsuza dek saklanır.
    let pruning = PruningConfig {
        retention_blocks: if config.storage.enable_pruning {
            Some(config.storage.max_retained_blocks)
        } else {
            None
        },
        interval_blocks: config.storage.pruning_interval,
        batch_limit: config.storage.prune_batch_limit,
    };
    if let Some(retention) = pruning.retention_blocks {
        info!(
            "🧹 Budama AÇIK: her {} blokta bir, son {} blok korunur (çağrı başına ≤{} dekont). \
             UYARI: bu, {} bloktan eski işlem geçmişi/receipt/tx sorgularının artık dönmeyeceği anlamına gelir.",
            pruning.interval_blocks, retention, pruning.batch_limit, retention
        );
    }
    let runtime = Arc::new(
        Runtime::new(state.clone(), executor.clone(), scheduler)
            .with_pruning(pruning)
            .with_snapshot_hook(build_snapshot_hook(
                state.clone(),
                storage.clone(),
                config.storage.snapshots_root.clone(),
                config.storage.snapshot_interval_blocks,
                config.storage.max_snapshots_to_retain,
            ))
            .with_archive_height_file(config.storage.archive_height_file.clone()),
    );

    // 🌉 Köprü çoklu imza yöneticisi: yetkili listesi HER ZAMAN config'den
    // (`load_from_state` yalnız sayaç/bekleyenleri yükler).
    let bridge_authorities: Vec<BridgeAuthority> = if config.bridge.authorities.is_empty() {
        tracing::warn!(
            "⚠️ [bridge].allow_insecure_default_authorities=true VE authorities boş - \
             SADECE GELİŞTİRME amaçlı, kaynak kodda duran sabit test anahtarlarıyla \
             (BridgeManager::default_authorities) açılıyor. Bu anahtarlarla köprü \
             GERÇEK parayla ASLA çalıştırılmamalı!"
        );
        BridgeManager::default_authorities()
    } else {
        config
            .bridge
            .authorities
            .iter()
            .map(|authority| {
                let hex_str = authority
                    .public_key_hex
                    .strip_prefix("0x")
                    .unwrap_or(&authority.public_key_hex);
                let bytes = hex::decode(hex_str)
                    .expect("config.validate() zaten public_key_hex'i doğruladı");
                let mut public_key = [0u8; 32];
                public_key.copy_from_slice(&bytes);
                BridgeAuthority {
                    address: authority.address.clone(),
                    public_key,
                    is_active: authority.is_active,
                }
            })
            .collect()
    };
    // 🛡️ Köprü yetkili kümesi zincire yazılır (imzalar zincirdeki kümeye karşı
    // doğrulanır); zaten yazılmışsa dokunulmaz, değişim governance işidir.
    {
        use zagros_executor::bridge::{
            load_bridge_authority_set, store_bridge_authority_set, OnChainBridgeAuthoritySet,
        };
        if load_bridge_authority_set(state.as_ref()).is_err() {
            let onchain = OnChainBridgeAuthoritySet {
                authorities: bridge_authorities.clone(),
                required_signatures: bridge_required_signatures as u16,
            };
            store_bridge_authority_set(state.as_ref(), &onchain).map_err(|e| {
                format!("kopru yetkili kumesi zincire yazilamadi (fail-closed): {e}")
            })?;
            state
                .flush()
                .map_err(|e| format!("kopru yetkili kumesi flush edilemedi: {e}"))?;
            tracing::info!(
                "🌉 Köprü yetkili kümesi ZİNCİRE yazıldı: {} yetkili, eşik {}/{}                  (basım doğrulaması artık config'ten DEĞİL zincirden okunur)",
                onchain.authorities.len(),
                onchain.required_signatures,
                onchain.authorities.iter().filter(|a| a.is_active).count()
            );
        }
    }

    // Executor ile AYNI `bridge_required_signatures` (tek kaynak). `std::sync::Mutex`:
    // BridgeManager senkron/CPU işi, `handle_request` de senkron.
    let mut loaded_bridge_manager = BridgeManager::load_from_state(
        state.as_ref(),
        bridge_authorities,
        bridge_required_signatures,
        CHAIN_ID,
    )
    .expect("Köprü (Bridge) durumu diskten okunamadı")
    .with_timelock_secs(config.bridge.timelock_secs);

    // ⏳ Mint zaman kilidi üretimde 24 saat. 🚨 Burn → Claim akışında kilit KASITLI 0
    // (kalıcı tasarım); gerçek koruma Gateway sahipliğinin Safe'e taşınması, her açılışta hatırlatılır.
    const OWNER_MULTISIG_MIGRATION_NOTE: &str =
        "Gateway sahipliği hâlâ tek bir EOA ise (bkz. Zagros-Contracts .env) bu,          zaman kilidinin devraldığı tek gerçek korumadır - mainnet'e büyük          meblağ ile çıkmadan önce Safe/çoklu-imzaya taşıyın.";
    if config.bridge.timelock_secs == 0 {
        tracing::warn!(
            "⚠️ KÖPRÜ ZAMAN KİLİDİ KAPALI (0 sn) - kasıtlı mimari tercih, bir hata              değil. Ele geçirilmiş yetkililerin ürettiği sahte bir çekimin fark              edilip durdurulması için ZAMAN PENCERESİ YOKTUR. {}",
            OWNER_MULTISIG_MIGRATION_NOTE
        );
    } else {
        info!(
            "⏳ Köprü zaman kilidi: {} saniye. {}",
            config.bridge.timelock_secs, OWNER_MULTISIG_MIGRATION_NOTE
        );
    }

    // 🎟️ CLAIM FİŞİ KANALI: haberciler EIP-712 imzalarını düğüme bırakır, dApp
    // okur; yapılandırma eksikse kanal KAPALI (doğrulanamayan fiş saklanmaz).
    let bridge_eth = &config.bridge.ethereum;
    if bridge_eth.is_claim_voucher_enabled() {
        let relayers: Vec<[u8; 20]> = bridge_eth
            .relayer_eth_addresses
            .iter()
            .filter_map(|addr| zagros_types::eip712::parse_eth_address(addr))
            .collect();
        if relayers.len() == bridge_eth.relayer_eth_addresses.len() {
            loaded_bridge_manager = loaded_bridge_manager.with_claim_context(ClaimContext {
                chain_id: bridge_eth.chain_id,
                gateway: zagros_types::eip712::parse_eth_address(
                    &bridge_eth.gateway_contract_address,
                )
                .expect("is_claim_voucher_enabled() adresi zaten doğruladı"),
                token: zagros_types::eip712::parse_eth_address(&bridge_eth.unlock_token_address)
                    .expect("is_claim_voucher_enabled() adresi zaten doğruladı"),
                token_decimals: bridge_eth.unlock_token_decimals,
                relayers,
            });
            info!(
                "🎟️ Claim fişi kanalı AÇIK: gateway={} zincir={} haberci={}",
                bridge_eth.gateway_contract_address,
                bridge_eth.chain_id,
                bridge_eth.relayer_eth_addresses.len()
            );
        } else {
            tracing::warn!(
                "⚠️ [bridge.ethereum].relayer_eth_addresses içinde geçersiz adres var - \
                 claim fişi kanalı KAPALI kalıyor."
            );
        }
    } else {
        tracing::warn!(
            "⚠️ [bridge.ethereum] yapılandırılmamış - claim fişi kanalı KAPALI. \
             Köprü ÇIKIŞI (ZERENYA yak → PAXG çek) çalışmaz; giriş yönü etkilenmez."
        );
    }

    // Köprü imzalayıcısı mint'lerde gas'tan muaftır (mempool + executor'daki
    // `is_exempt_bridge_mint`); bilerek loglanmaz (saldırgana bilgi vermemek için).

    let bridge_manager = Arc::new(std::sync::Mutex::new(loaded_bridge_manager));
    info!("🌉 Köprü Çoklu-İmza Yöneticisi (BridgeManager) devrede!");
    info!("🧠 Merkezi State Engine (Muhasebe ve Önbellek) aktif!");

    // 🏛️ GERÇEK ANAYASAL GENESIS INFUSION
    let should_initialize_genesis =
        initialize_genesis_if_needed(storage.as_ref(), state.as_ref(), &config.genesis)
            .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    // 📊 ANLIK BİLANÇO: genesis TAMAMLANDIKTAN SONRA okunur (önce okunsa
    // hesaplar henüz yokken "0.00" görünürdü).
    let founder_state = state
        .get_account(&FOUNDER_ADDRESS.to_string())
        .unwrap()
        .unwrap_or_default();
    let treasury_state = state
        .get_account(&VALIDATOR_REWARD_POOL.to_string())
        .unwrap()
        .unwrap_or_default();
    let global_stake = state
        .get_account(&"__GLOBAL_TOTAL_STAKED__".to_string())
        .unwrap()
        .unwrap_or_default();

    // 🚀 NATIVE L1 AMM REZERVLERİNİ OKU
    let (native_pool_zagros, native_pool_zerenya) = state.get_pool_reserves().unwrap_or((0, 0));

    info!("===========================================================");
    info!("🏛️  VALIDATOR COMMAND CENTER - Ağın Anlık Finansal Durumu");
    info!("===========================================================");
    info!(
        "👤 Kurucu Cüzdan          : {} ZAGROS | {} ZERENYA",
        format_token_amount(founder_state.balance),
        format_token_amount(founder_state.zerenya_balance)
    );
    info!(
        "🔐 Toplam Stake           : {} ZAGROS",
        format_token_amount(founder_state.staked_balance)
    );
    info!(
        "🏊 Native L1 Havuz        : {} ZAGROS | {} ZERENYA",
        format_token_amount(native_pool_zagros),
        format_token_amount(native_pool_zerenya)
    );
    info!(
        "🏛️ Hazine (Reward Pool)   : {} ZAGROS",
        format_token_amount(treasury_state.balance)
    );
    info!(
        "🌍 Global Stake           : {} ZAGROS",
        format_token_amount(global_stake.balance)
    );
    info!("===========================================================");

    // 🛡️ Executor sürüm kontrolü (konsensüs kritik, FAIL-CLOSED): yükseltme/geri
    // sarma `acknowledged_executor_state_version` ile açıkça onaylanmadıysa node BAŞLAMAZ.
    if let Err(e) = apply_executor_version_check(
        state.as_ref(),
        should_initialize_genesis,
        config.acknowledged_executor_state_version,
    ) {
        return Err(e.into());
    }

    // 🛡️ Operatör paneli şeffaflığı (`zagros_getNodeInfo`): BU sürecin ne
    // zaman başladığını işaretler, genesis zaman damgasından farklı olarak
    // her `zagros-cli` restart'ında yeniden yazılır, "uptime" hesaplamak için.
    {
        let mut started_acc = AccountState::default();
        started_acc.balance = std::time::UNIX_EPOCH
            .elapsed()
            .map(|d| d.as_secs() as u128)
            .unwrap_or(0);
        let _ = state.set_account(&"__NODE_PROCESS_STARTED_AT__".to_string(), started_acc);
    }

    // 🚀 Mempool: ücret havuz oranına göre, yük eşiği aşınca üstel. 🔒 Hesaplayıcıyı
    // yalnız Mempool tutar, okumalar `min_required_fee` üzerinden (canlı rezervle eşitler).
    // Genesis SONRASI rezervlerle tohumlanır.
    let (gas_pool_zagros, gas_pool_zerenya) = state.get_pool_reserves().unwrap_or((0, 0));
    let gas_calculator = Arc::new(
        GasCalculator::with_target(
            Arc::new(portable_atomic::AtomicU128::new(gas_pool_zagros)),
            Arc::new(portable_atomic::AtomicU128::new(gas_pool_zerenya)),
            config.gas.gas_fee_zerenya as u128,
        )
        .with_ddos_threshold(config.mempool.ddos_threshold)
        // `[gas].enable_dynamic_gas` havuz oranına göre fiyat ölçeklemesini
        // açıp kapatır. Anti-DDoS stress çarpanı bu bayraktan bağımsız, her
        // zaman aktif kalır.
        .with_dynamic_pricing_enabled(config.gas.enable_dynamic_gas),
    );
    // Phantom config bağlandı: max_capacity / max_total_bytes artık config.mempool'dan.
    let mut mempool_builder =
        Mempool::with_config(state.clone(), gas_calculator.clone(), &config.mempool)
            // `[gas].max_gas_per_block` GERÇEK blok gas bütçesidir; yalnız
            // kendi içinde (`target ≤ max`) doğrulanıp uygulanmasaydı gerçek
            // tavan sessizce hardcoded `MAX_BLOCK_GAS_LIMIT` (100M) olurdu.
            .with_max_block_gas_limit(config.gas.max_gas_per_block as u128);
    // 🛡️ Köprü mint ücret muafiyeti (bkz. Mempool::add_transaction), Executor'daki
    // eşleniğiyle AYNI adres, tek gerçek kaynak `effective_bridge_authority`
    // (bkz. yukarıdaki doc yorumu, `bridge_signer`'dan ayrıldı, konsensüs-kritik).
    if let Some(address) = &effective_bridge_authority {
        mempool_builder = mempool_builder.with_bridge_authority(address.clone());
    }
    let shared_mempool = Arc::new(mempool_builder);
    info!("🏊 Ortak Mempool (Bekleme Odası) açıldı!");

    info!("🚦 Scheduler (Paralel İşlem Zamanlayıcı) Runtime üzerinden devrede!");

    // 🚨 `std::sync::Mutex` (tokio değil): kilit `spawn_blocking` içinde senkron
    // alınır; async mutex senkron closure'da gereksiz ve yanlış API. Tek kilitleme
    // noktası blok üreticisi görevi.
    let consensus = Arc::new(std::sync::Mutex::new(ConsensusEngine::new(runtime.clone())));
    info!("⚖️ Consensus (DPoS) iskeleti şoför koltuğuna oturdu!");

    info!("===========================================================");
    info!("✅ BÜTÜN MODÜLLER TEK BİR MERKEZE (BÖLÜNMÜŞ BEYİN DÜZELTİLDİ) BAĞLANDI!");
    info!("===========================================================");

    // 🛡️ Graceful shutdown + görev denetimi: iptal sinyali + `JoinSet`; Ctrl-C'de
    // temiz duruş, beklenmedik çıkış/panic `join_next()` ile anında fark edilir.
    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    let mut tasks: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();

    // 🌐 P2P AĞ KATMANI: `tasks: JoinSet` + `cancel_rx` deseniyle spawn edilir,
    // "sessiz görev ölümü olmaz" denetimine otomatik dahil.
    let (network_handle, network_command_rx) = zagros_network::service::channel();
    let mut bft_mode = false;
    // G14: konsensüs/P2P/RPC arasında paylaşılan süreç-içi gözlemlenebilirlik
    // sayaçları (/metrics + /health), konsensüse GİRMEZ.
    let node_metrics = std::sync::Arc::new(zagros_metrics::NodeMetrics::default());
    if config.network.enable_p2p {
        let network_identity =
            zagros_network::identity::load_or_generate(&config.network.node_key_path)?;
        info!(
            "🆔 Node PeerId: {} (diğer node'ların bootstrap_nodes'una eklemek için)",
            network_identity.public().to_peer_id()
        );
        let network_swarm =
            zagros_network::behaviour::build_swarm(network_identity, &config.network)?;
        // G5: BFT sürücüsü FAIL-CLOSED kurulur. 🚨 Anahtarsız düğümlerde (RPC/arşiv)
        // de başlar, yoksa sync/2 catch-up çalışmaz; anahtarsız sürücü öneri yapmaz, dinler.
        let consensus_keypair = match &config.network.consensus_key_path {
            Some(path) => Some(zagros_crypto::load_keyfile(path)?),
            None => None,
        };
        let dogrulayici = consensus_keypair.is_some();
        // 🛡️ Sentry mimarisi: ağ politikası + sentry duyurusu; validatör adresi
        // zincirde bu `consensus_pubkey`li hesaptır (sahte adres duyurulamaz).
        let peer_policy = {
            let announce = match (&consensus_keypair, config.network.sentry_addrs.is_empty()) {
                (Some(kp), false) => {
                    let my_pk = kp.public_key();
                    let owner = zagros_executor::validator_set::registered_validator_accounts(
                        state.as_ref(),
                    )
                    .ok()
                    .and_then(|list| {
                        list.into_iter()
                            .find(|(_, acc)| acc.consensus_pubkey == my_pk)
                            .map(|(addr, _)| addr)
                    });
                    match owner {
                        Some(validator) => Some(zagros_network::service::AnnounceConfig {
                            keypair: std::sync::Arc::new(
                                zagros_crypto::ConsensusKeypair::from_secret_bytes(
                                    &kp.secret_bytes(),
                                ),
                            ),
                            validator,
                            sentry_addrs: config.network.sentry_addrs.clone(),
                            domain: zagros_executor::params::consensus_domain(state.as_ref())?,
                        }),
                        None => {
                            tracing::warn!("⚠️ sentry_addrs ayarlı ama bu konsensüs anahtarı zincirde kayıtlı bir validatöre ait değil; duyuru yapılmayacak.");
                            None
                        }
                    }
                }
                _ => None,
            };
            zagros_network::service::PeerPolicy {
                private_peers: zagros_network::behaviour::peer_ids_of(
                    &config.network.private_peers,
                ),
                sentry_mode: config.network.sentry_mode,
                max_peers: config.network.max_peers,
                max_peers_per_ip: config.network.max_peers_per_ip,
                reserved_slots: if config.network.private_peers.is_empty() {
                    config.network.reserved_validator_slots
                } else {
                    0
                },
                announce,
            }
        };
        let checkpoint = match &config.network.trusted_checkpoint {
            Some(c) => Some(zagros_network::sync2::TrustedCheckpoint::from_config(c)?),
            None => None,
        };
        let consensus_wiring =
            match zagros_network::consensus_driver::ConsensusDriver::bootstrap_with(
                state.clone(),
                runtime.clone(),
                shared_mempool.clone(),
                consensus_keypair,
                checkpoint,
                config.network.sync_batch_size,
            ) {
                Ok((driver, wiring)) => {
                    let driver = driver.with_evidence_log(
                        Some(config.network.evidence_log_path.clone())
                            .filter(|p| !p.trim().is_empty())
                            .map(std::path::PathBuf::from),
                    );
                    // Restart-guvenli cift-imza korumasi: durum dosyasi db_path'in
                    // yaninda (`priv_validator_state`). Config semasi degismez (yeni
                    // node config'i gerektirmez); yol mevcut db_path'ten turetilir.
                    let priv_state_path = std::path::Path::new(&config.storage.db_path)
                        .parent()
                        .map(|d| d.join("priv_validator_state"))
                        .unwrap_or_else(|| std::path::PathBuf::from("priv_validator_state"));
                    let driver = driver.with_double_sign_state(Some(priv_state_path));
                    info!(
                        "⚖️ BFT modu: validator_idx={:?} N={} h={} (rol: {})",
                        driver.engine().my_idx(),
                        driver.engine().validator_set().len(),
                        driver.engine().height(),
                        if dogrulayici {
                            "dogrulayici"
                        } else {
                            "follower (yalniz senkron)"
                        }
                    );
                    let driver = driver.with_metrics(node_metrics.clone());
                    tasks.spawn(driver.run(network_handle.clone(), cancel_rx.clone()));
                    bft_mode = true;
                    Some(wiring)
                }
                // Dogrulayicida FAIL-CLOSED: anahtari var ama kurulum basarisizsa
                // sessizce eski moda dusmek konsensusten ayrisma demektir.
                Err(e) if dogrulayici => return Err(e.into()),
                // Anahtarsiz dugum: zincir BFT degilse (eski/tek-node genesis)
                // surucu kurulamaz, eski moda dusmek DOGRU davranistir.
                Err(e) => {
                    tracing::warn!("⚠️ BFT surucusu kurulamadi (anahtarsiz dugum, zincir BFT olmayabilir): {e}");
                    None
                }
            };
        tasks.spawn(zagros_network::service::run(
            network_swarm,
            config.network.network_id,
            zagros_network::peer_book::parse_bootstrap(&config.network.dial_targets()),
            shared_mempool.clone(),
            runtime.clone(),
            state.clone(),
            config.network.sync_batch_size,
            network_command_rx,
            cancel_rx.clone(),
            consensus_wiring,
            Some(node_metrics.clone()),
            peer_policy,
        ));
    } else {
        info!("🌐 P2P ağı devre dışı (network.enable_p2p=false) - node izole/tek-node modunda çalışıyor.");
        // Alıcı ucu hiç tüketilmeyecek, `network_handle.publish_*` çağrıları
        // bu yüzden sessizce no-op olur (kanal kapalı), ayrı bir kontrol
        // dallanmasına gerek kalmaz (bkz. `NetworkHandle`'ın doc yorumu).
        drop(network_command_rx);
    }

    // 🌉 RPC katmanı `zagros-network`'e bağımlı DEĞİL (bkz. `with_tx_broadcast`'ın
    // doc yorumu), bu ince köprü görevi, RPC'nin gönderdiği ham `Transaction`'ları
    // `NetworkHandle::publish_transaction`'a aktarır.
    let (tx_broadcast_tx, mut tx_broadcast_rx) =
        tokio::sync::mpsc::unbounded_channel::<zagros_types::Transaction>();
    let bridge_network_handle = network_handle.clone();
    let mut bridge_cancel = cancel_rx.clone();
    // 🔁 Yeniden yayın: bloğa girmemiş yerel işlemler gönderici+nonce sırasıyla
    // yeniden gossip'lenir (kabul yarışı adresi kilitlemesin).
    const REBROADCAST_AFTER_SECS: u64 = 4;
    const REBROADCAST_TICK_SECS: u64 = 2;
    const REBROADCAST_CAP: usize = 200;
    let rebroadcast_mempool = shared_mempool.clone();
    tasks.spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(REBROADCAST_TICK_SECS));
        loop {
            tokio::select! {
                Some(tx) = tx_broadcast_rx.recv() => {
                    bridge_network_handle.publish_transaction(tx);
                }
                _ = tick.tick() => {
                    let stale = rebroadcast_mempool
                        .stale_local_for_rebroadcast(REBROADCAST_AFTER_SECS, REBROADCAST_CAP);
                    if !stale.is_empty() {
                        tracing::info!(
                            "🔁 {} bekleyen işlem yeniden yayınlanıyor (≥{} sn'dir bloğa girmedi)",
                            stale.len(),
                            REBROADCAST_AFTER_SECS
                        );
                        for tx in stale {
                            bridge_network_handle.publish_transaction(tx);
                        }
                    }
                }
                _ = bridge_cancel.changed() => {
                    if *bridge_cancel.borrow() {
                        break;
                    }
                }
            }
        }
    });

    // 🛑 ON-DEMAND BLOK ÜRETİCİSİ (MEMPOOL İŞÇİSİ)
    let worker_mempool = shared_mempool.clone();
    let worker_consensus = consensus.clone();
    let worker_state = state.clone();
    let mut block_producer_cancel = cancel_rx.clone();
    // 📸 Otomatik snapshot ayrı zamanlayıcı değil, bu döngünün içinde: `state_root()`
    // cache'ten, `create_snapshot` diskten okur; ayrı görev flush'tan önce araya
    // girip metadata'daki kökü diskle uyumsuz bırakırdı (restore "BOZUK" der).
    let target_gas_per_block = config.gas.target_gas_per_block;
    let snapshot_interval_blocks = config.storage.snapshot_interval_blocks;
    let snapshots_root = config.storage.snapshots_root.clone();
    let max_snapshots_to_retain = config.storage.max_snapshots_to_retain;
    // 🛡️ Snapshot ayarları bir kez sentinel hesaba yazılır; RPC `state`'ten
    // okur (`__CONFIGURED_BLOCK_PRODUCER__` deseni).
    {
        let mut interval_acc = AccountState::default();
        interval_acc.balance = snapshot_interval_blocks as u128;
        let _ = state.set_account(&"__SNAPSHOT_INTERVAL_BLOCKS__".to_string(), interval_acc);
        let mut retain_acc = AccountState::default();
        retain_acc.balance = max_snapshots_to_retain as u128;
        let _ = state.set_account(&"__SNAPSHOT_MAX_RETAIN__".to_string(), retain_acc);
    }
    // 🛡️ `target_gas_per_block` ve `cache_size_mb` hiçbir nesnede tutulmadığından
    // RPC okuyabilsin diye sentinel'e yazılır.
    {
        let mut target_gas_acc = AccountState::default();
        target_gas_acc.balance = target_gas_per_block as u128;
        let _ = state.set_account(
            &"__CONFIG_TARGET_GAS_PER_BLOCK__".to_string(),
            target_gas_acc,
        );
        let mut cache_acc = AccountState::default();
        cache_acc.balance = config.storage.cache_size_mb as u128;
        let _ = state.set_account(&"__CONFIG_CACHE_SIZE_MB__".to_string(), cache_acc);
        // Sadece AÇIK/KAPALI biti, webhook URL'in kendisi (yarı-gizli, bir
        // Discord kanalına yazma yetkisi verebilir) hiçbir zaman RPC üzerinden
        // dışa açılmaz.
        let mut alerts_acc = AccountState::default();
        alerts_acc.balance = if config.alerts.webhook_url.is_some() {
            1
        } else {
            0
        };
        let _ = state.set_account(&"__CONFIG_ALERTS_ENABLED__".to_string(), alerts_acc);
        // Operatör paneli şeffaflığı: budama (K2/Historical Chain Storage)
        // ayarları da AYNI sebepten, `Runtime::PruningConfig` nesnesi RPC'ye
        // açık değil, gerçek çalışan değerleri buradan yansıtıyoruz.
        let mut pruning_enabled_acc = AccountState::default();
        pruning_enabled_acc.balance = if config.storage.enable_pruning { 1 } else { 0 };
        let _ = state.set_account(
            &"__CONFIG_ENABLE_PRUNING__".to_string(),
            pruning_enabled_acc,
        );
        let mut max_retained_acc = AccountState::default();
        max_retained_acc.balance = config.storage.max_retained_blocks as u128;
        let _ = state.set_account(
            &"__CONFIG_MAX_RETAINED_BLOCKS__".to_string(),
            max_retained_acc,
        );
        let mut pruning_interval_acc = AccountState::default();
        pruning_interval_acc.balance = config.storage.pruning_interval as u128;
        let _ = state.set_account(
            &"__CONFIG_PRUNING_INTERVAL__".to_string(),
            pruning_interval_acc,
        );
        // 🛡️ P2P statik config alanları sentinel deseniyle yansıtılır (`zagros-rpc`
        // `zagros-network`'e bağımlı olamaz); canlı PeerId/peer sayısı için ayrı kanal gerekir, yok.
        let mut enable_p2p_acc = AccountState::default();
        enable_p2p_acc.balance = if config.network.enable_p2p { 1 } else { 0 };
        let _ = state.set_account(&"__CONFIG_ENABLE_P2P__".to_string(), enable_p2p_acc);
        let mut is_proposer_acc = AccountState::default();
        is_proposer_acc.balance = if config.network.is_proposer { 1 } else { 0 };
        let _ = state.set_account(&"__CONFIG_IS_PROPOSER__".to_string(), is_proposer_acc);
        let mut network_id_acc = AccountState::default();
        network_id_acc.balance = config.network.network_id as u128;
        let _ = state.set_account(&"__CONFIG_NETWORK_ID__".to_string(), network_id_acc);
        let mut mdns_enabled_acc = AccountState::default();
        mdns_enabled_acc.balance = if config.network.mdns_enabled { 1 } else { 0 };
        let _ = state.set_account(&"__CONFIG_MDNS_ENABLED__".to_string(), mdns_enabled_acc);
        let mut sync_batch_size_acc = AccountState::default();
        sync_batch_size_acc.balance = config.network.sync_batch_size as u128;
        let _ = state.set_account(
            &"__CONFIG_SYNC_BATCH_SIZE__".to_string(),
            sync_batch_size_acc,
        );
        // `listen_addr` gizli değil (açılışta loglanır), `contract_code` ile taşınır.
        let mut listen_addr_acc = AccountState::default();
        listen_addr_acc.contract_code = config.network.listen_addr.clone().into_bytes();
        let _ = state.set_account(&"__CONFIG_LISTEN_ADDR__".to_string(), listen_addr_acc);
    }
    // 🛡️ Uyarı sistemi: `webhook_url` boşsa aşağıdaki kontroller no-op, ağ isteği
    // yok. Kenar geçişi closure'a yerel (restart'ta sıfırlanır; restart zaten fark edilir).
    let alert_webhook_url = config.alerts.webhook_url.clone();
    let alert_stall_threshold = std::time::Duration::from_secs(config.alerts.stall_threshold_secs);
    let alert_http_client = reqwest::Client::new();
    let alert_validator_address = block_producer_address.clone();
    let mut alert_was_jailed = false;
    let mut alert_was_ddos_stress = false;
    let mut alert_last_block_at = std::time::Instant::now();
    let mut alert_stall_fired = false;
    let db_path_for_disk_check = config.storage.db_path.clone();
    // İlk döngü turunda hemen bir ölçüm yapılsın diye "uzun zaman önce" ile başlatılıyor.
    let mut last_disk_check = std::time::Instant::now() - std::time::Duration::from_secs(3600);
    // 🛡️ EN KRİTİK P2P TELİ: bu görev `config.network.is_proposer` ile kapılıdır;
    // yoksa her follower kendi mempool'undan blok üretip sessiz fork yaratırdı.
    // `!enable_p2p` her zaman true: P2P kapalıysa tek node kendi bloğunu üretir.
    let block_producer_network_handle = network_handle.clone();
    // G5: BFT modunda eski tek-proposer döngüsü KULLANILMAZ (`is_proposer`
    // yok sayılır, uyarı loglanır), blok üretimi sürücüde.
    if bft_mode && config.network.is_proposer {
        tracing::warn!("⚠️ network.is_proposer=true ama BFT modu aktif: tek-proposer dongusu devre disi, bloklar BFT ile uretilir.");
    }
    if !bft_mode && (!config.network.enable_p2p || config.network.is_proposer) {
        tasks.spawn(async move {
        tracing::info!("🛸 On-Demand Blok İşçisi devrede: Mempool'u dinliyor...");
        if snapshot_interval_blocks > 0 {
            tracing::info!(
                "📸 Otomatik snapshot aktif (aralık={} blok, saklama={} adet, kök={})",
                snapshot_interval_blocks, max_snapshots_to_retain, snapshots_root
            );
        }
        loop {
            // 🚀 On-demand: mempool bildirimiyle anında uyanır; 50 ms zaman aşımı
            // yalnız kaçırılan bildirim için güvenlik ağı.
            tokio::select! {
                _ = worker_mempool.wait_for_activity(50) => {}
                _ = block_producer_cancel.changed() => {
                    if *block_producer_cancel.borrow() {
                        break;
                    }
                }
            }

            // Blok kapasitesi 10_000; ağır (EVM) işlemler en fazla %5 alır ki native
            // işlemleri aç bırakmasın (`heavy_fifo_queue`).
            let txs_to_process = worker_mempool.get_transactions_for_block(10_000, 500);

            if !txs_to_process.is_empty() {
                tracing::info!(
                    "⚙️ Mempool'da {} işlem bulundu, Motor ateşleniyor!",
                    txs_to_process.len()
                );

                let block_timestamp = std::time::UNIX_EPOCH.elapsed().unwrap().as_secs() as u128;

                // 🚨 Blok üretimi (rayon `execute_batch` + RocksDB `flush`) `spawn_blocking`
                // içinde; reaktör thread'inde koşsa RPC/WS keepalive'ı bloklardı.
                // `consensus` `std::sync::Mutex`, senkron kilitlenir.
                let consensus_for_block = worker_consensus.clone();
                let txs_for_block = txs_to_process.clone();
                let produce_result = tokio::task::spawn_blocking(move || {
                    let mut lock = consensus_for_block.lock().unwrap();
                    lock.produce_block(txs_for_block, block_timestamp)
                })
                .await
                .expect(
                    "blok üretimi thread'i panic ile sonlandı (ConsensusEngine kilidi \
                     zehirlenmiş olabilir) - denetleyici (JoinSet) bunu görüp node'u \
                     kontrollü şekilde kapatsın",
                );
                if let Err(e) = produce_result {
                    tracing::error!("🚨 Konsensüs hatası: {:?}", e);
                } else {
                    // 🛡️ Uyarı sistemi: gerçek bir blok ÜRETİLDİ, "üretim
                    // duruyor" sayacını sıfırla (bkz. döngü sonundaki stall
                    // kontrolü).
                    alert_last_block_at = std::time::Instant::now();
                    alert_stall_fired = false;

                    // 🌐 P2P: üretilen blok follower'lara gossip'lenir. Header yeniden inşa
                    // edilmez, diske yazılan GERÇEK header `block_key`'den okunur; okuma
                    // başarısızsa yalnız gossip atlanır, proposer zinciri etkilenmez.
                    let new_height = worker_state
                        .get_account(&"__GLOBAL_BLOCK_HEIGHT__".to_string())
                        .ok()
                        .flatten()
                        .map(|a| a.balance)
                        .unwrap_or(0) as u64;
                    match worker_state.get_account(&zagros_state::block_key(new_height)) {
                        Ok(Some(header_acc)) => {
                            match bincode::deserialize::<zagros_types::ArchivedBlockHeader>(
                                &header_acc.contract_code,
                            ) {
                                Ok(header) => {
                                    // 🛡️ P2P follower senkronu (bkz. `collect_proposals_for_relay`):
                                    // blok üretimi bittikten sonra okunur, önerileri arşive taşınmış
                                    // olsa da her iki hali dener.
                                    let bridge_proposals =
                                        zagros_executor::bridge::BridgeManager::collect_proposals_for_relay(
                                            worker_state.as_ref(),
                                            &txs_to_process,
                                        );
                                    block_producer_network_handle.publish_block(
                                        header,
                                        txs_to_process.clone(),
                                        bridge_proposals,
                                    )
                                }
                                Err(e) => tracing::warn!(
                                    "⚠️ Blok #{} header'ı çözülemedi, gossip atlanıyor: {}",
                                    new_height, e
                                ),
                            }
                        }
                        _ => tracing::warn!(
                            "⚠️ Blok #{} header'ı okunamadı, gossip atlanıyor",
                            new_height
                        ),
                    }
                }

                // 🔒 Blok kapanışında `sync_pools` çağrılmaz: `min_required_fee` her
                // sorguda kendisi eşitler; ikinci yol sapmaya davetiye olurdu.

                // `[gas].target_gas_per_block` yalnız gözlemlenebilirlik (sert tavan değil);
                // bloğun toplam beyan edilen gas'ı aşarsa kapasite planlaması için uyarı loglanır.
                if target_gas_per_block > 0 {
                    let declared_gas_total: u128 = txs_to_process
                        .iter()
                        .map(|tx| tx.gas_limit as u128)
                        .sum();
                    if declared_gas_total > target_gas_per_block as u128 {
                        tracing::warn!(
                            "⚠️ Blok hedef gaz kullanımını aştı: {} gas (hedef: {} gas) - \
                             bilgi amaçlı, işlem reddedilmedi.",
                            declared_gas_total,
                            target_gas_per_block
                        );
                    }
                }

                // 🛡️ Nonce boşluğu tamponu: yalnız `tx.nonce <= güncel nonce` silinir,
                // ileri nonce'lu tx bekletilir (birikim limitler + TTL ile sınırlı).
                for tx in txs_to_process {
                    let committed_nonce = worker_state.get_nonce(&tx.sender).unwrap_or(0);
                    if !tx_is_forward_nonce_gap(tx.nonce, committed_nonce) {
                        worker_mempool.remove_transaction(&tx.tx_id);
                    }
                }

                // 📸 Snapshot burada değil, `Runtime` içinden her blok yolunda
                // (yalnız bu döngüde olsaydı BFT'de alınmazdı).

                // 🛡️ Disk kullanımı yalnız blok üretildiğinde ve en çok 60 sn'de bir
                // ölçülür (her blokta tam dizin taraması gereksiz I/O).
                if last_disk_check.elapsed() >= std::time::Duration::from_secs(60) {
                    last_disk_check = std::time::Instant::now();
                    let disk_bytes = dir_size_bytes(std::path::Path::new(&db_path_for_disk_check));
                    let now_secs = std::time::UNIX_EPOCH
                        .elapsed()
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    let mut bytes_acc = AccountState::default();
                    bytes_acc.balance = disk_bytes as u128;
                    let _ =
                        worker_state.set_account(&"__STORAGE_DISK_BYTES__".to_string(), bytes_acc);
                    let mut updated_acc = AccountState::default();
                    updated_acc.balance = now_secs as u128;
                    let _ = worker_state.set_account(
                        &"__STORAGE_DISK_BYTES_UPDATED_AT__".to_string(),
                        updated_acc,
                    );

                    // 📈 Aynı 60 sn turda mempool/gas anlık görüntüsü, tek tutarlı örnek.
                    let sample_height = worker_state
                        .get_account(&"__GLOBAL_BLOCK_HEIGHT__".to_string())
                        .ok()
                        .flatten()
                        .map(|a| a.balance)
                        .unwrap_or(0);
                    let sample = zagros_types::MetricsSample {
                        timestamp: now_secs,
                        block_height: sample_height,
                        mempool_load: worker_mempool.size() as u64,
                        stress_multiplier: worker_mempool.stress_multiplier(),
                        disk_usage_bytes: disk_bytes,
                    };
                    if let Ok(sample_bytes) = bincode::serialize(&sample) {
                        let next_index = worker_state
                            .get_account(&zagros_types::METRICS_SAMPLE_NEXT_INDEX_KEY.to_string())
                            .ok()
                            .flatten()
                            .map(|a| a.balance)
                            .unwrap_or(0);
                        let mut sample_acc = AccountState::default();
                        sample_acc.contract_code = sample_bytes;
                        let _ = worker_state.set_account(
                            &zagros_types::metrics_sample_key(next_index),
                            sample_acc,
                        );
                        let mut next_index_acc = AccountState::default();
                        next_index_acc.balance = next_index + 1;
                        let _ = worker_state.set_account(
                            &zagros_types::METRICS_SAMPLE_NEXT_INDEX_KEY.to_string(),
                            next_index_acc,
                        );
                    }
                }
            }

            // 🛡️ Uyarılar döngünün HER turunda (mempool boşken de jail/DDoS görülsün);
            // `webhook_url` yoksa tamamı no-op.
            if let Some(url) = &alert_webhook_url {
                // 1) Genesis validator hapse girdi mi? (kenar geçişi, sadece
                // "yeni girdi" anında bir kez tetikler, hapiste KALDIĞI sürece
                // tekrar tekrar göndermez.)
                let is_jailed_now = worker_state
                    .get_account(&alert_validator_address)
                    .ok()
                    .flatten()
                    .map(|acc| {
                        let now = std::time::UNIX_EPOCH
                            .elapsed()
                            .map(|d| d.as_secs() as u128)
                            .unwrap_or(0);
                        acc.is_registered_validator && acc.jailed_until > now
                    })
                    .unwrap_or(false);
                if is_jailed_now && !alert_was_jailed {
                    spawn_webhook_alert(
                        alert_http_client.clone(),
                        url.clone(),
                        format!(
                            "🚨 Zagros: Genesis validator ({}) HAPSE GİRDİ (jailed).",
                            alert_validator_address
                        ),
                    );
                }
                alert_was_jailed = is_jailed_now;

                // 2) Mempool DDoS stres moduna YENİ girdi mi?
                let is_stress_now = worker_mempool.is_under_stress();
                if is_stress_now && !alert_was_ddos_stress {
                    spawn_webhook_alert(
                        alert_http_client.clone(),
                        url.clone(),
                        format!(
                            "⚠️ Zagros: Mempool Anti-DDoS stres moduna girdi (yük eşiği aşıldı, mevcut ücret çarpanı: {}x).",
                            worker_mempool.stress_multiplier()
                        ),
                    );
                }
                alert_was_ddos_stress = is_stress_now;

                // 3) Bekleyen işlem VARKEN üretim durdu mu? Mempool boşken alarm üretmez.
                if worker_mempool.size() > 0
                    && alert_last_block_at.elapsed() >= alert_stall_threshold
                    && !alert_stall_fired
                {
                    spawn_webhook_alert(
                        alert_http_client.clone(),
                        url.clone(),
                        format!(
                            "🚨 Zagros: mempool'da {} bekleyen işlem varken {} saniyedir blok üretilmiyor - node takılmış olabilir.",
                            worker_mempool.size(),
                            alert_last_block_at.elapsed().as_secs()
                        ),
                    );
                    alert_stall_fired = true;
                }
            }
        }
        tracing::info!("🛑 Blok üretici döngüsü durduruldu (graceful shutdown).");
    });
    } else {
        tracing::info!(
            "👁️ Follower modu: bu node blok ÜRETMİYOR - sadece P2P üzerinden \
             senkronize oluyor ve RPC sunuyor (network.is_proposer=false)."
        );
    }

    // 🌉 Köprü otomatik yürütücü: eşiği ve kilidi geçmiş mint önerilerini
    // periyodik imzalayıp mempool'a gönderir; imzacı anahtar yoksa başlamaz.
    if let Some((signer_key_bytes, signer_address)) = bridge_signer {
        let worker_bridge_manager = bridge_manager.clone();
        let worker_state = state.clone();
        let worker_mempool = shared_mempool.clone();
        // 🚨 Mint işlemi yalnız yerel mempool'a konursa bu düğüm üretici sırasına
        // gelene dek bloğa giremez (kümede 40 dakikaya kadar); aynı yayın kanalı
        // `eth_sendRawTransaction`'da da kullanılır.
        let kopru_yayin = tx_broadcast_tx.clone();
        let mut bridge_cancel = cancel_rx.clone();
        tasks.spawn(async move {
            tracing::info!("🌉 Köprü Otomatik Yürütücü devrede: onaylanmış önerileri tarıyor...");
            // Basit periyodik tarama yeter; 🚨 2 sn KALICI: yerel RPC taraması,
            // maliyeti yok. Hissedilen gecikme zaman kilididir.
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
            loop {
                tokio::select! {
                    _ = interval.tick() => {}
                    _ = bridge_cancel.changed() => {
                        if *bridge_cancel.borrow() {
                            break;
                        }
                    }
                }

                let now = std::time::UNIX_EPOCH.elapsed().unwrap().as_millis();
                let pending = match BridgeManager::load_pending_proposals_from_state(
                    worker_state.as_ref(),
                ) {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::error!("🚨 Köprü: bekleyen öneriler diskten okunamadı: {:?}", e);
                        continue;
                    }
                };

                // 🛡️ Mutabakat: state'in taze bekleyen listesinde olmayan (başka yoldan
                // yürütülüp arşivlenmiş) girdiler bellek içi haritadan budanır;
                // `mark_executed_in_state` bu instance'a dokunmaz.
                let still_pending_ids: Vec<zagros_types::Hash> =
                    pending.iter().map(|p| p.proposal_id).collect();
                {
                    let mut manager = worker_bridge_manager.lock().unwrap();
                    manager.prune_ids_not_in(&still_pending_ids);
                }

                if pending.is_empty() {
                    continue;
                }

                // Bu turda gönderilen işlemler henüz bloklanmadığı için
                // zincirdeki nonce'u yansıtmaz, yerel bir sayaç tutup her
                // başarılı gönderimden sonra elle artırıyoruz.
                let mut next_nonce = match worker_state.get_account(&signer_address) {
                    Ok(Some(account)) => account.nonce,
                    _ => 0,
                };
                // item 14, R7: `SecretKey` bu turluk GEÇİCİ türetilir, kalıcı
                // bir alanda tutulmuyor, bu blok bitince (bir sonraki
                // `interval.tick()`e kadar) düşer.
                let signer_secret_key = secp256k1::SecretKey::from_slice(signer_key_bytes.as_slice())
                    .expect("signer_key_bytes bozulmuş olamaz (açılışta bir kez doğrulandı)");

                for proposal in pending {
                    // 🛡️ Yalnız Mint önerileri zincire yürütülür; Burn önerileri off-chain
                    // koordinasyon verisidir, on-chain BridgeMint'e dönüşürse çift ödeme olur.
                    if proposal.tx_type != BridgeTxType::Mint {
                        continue;
                    }

                    // 🛡️ Karşılığı verilmiş yatırmanın mükerrer önerisi hiç denenmez;
                    // asıl savunma `execute_proposal`'da, burada elenmezse her turda
                    // ERROR basıp log'u doldururdu.
                    let already_processed = {
                        let manager = worker_bridge_manager.lock().unwrap();
                        manager
                            .is_source_processed(
                                &proposal.source_chain,
                                &proposal.source_tx_hash,
                                worker_state.as_ref(),
                            )
                            .unwrap_or(false)
                    };
                    if already_processed {
                        continue;
                    }

                    let can_execute = {
                        let manager = worker_bridge_manager.lock().unwrap();
                        manager
                            .can_execute(&proposal.proposal_id, now)
                            .unwrap_or(false)
                    };
                    if !can_execute {
                        continue;
                    }

                    // 🛡️ CLI yalnız istemci: yazma ve `executed` işaretleme zincirde
                    // (basımla aynı checkpoint).

                    // Mempool'daysa yeniden ekleme ama yayını tekrarla: ilk yayın mesh
                    // kurulmadan düşebilir (canlıda görüldü); gossipsub tekilleştirir.
                    if worker_mempool.contains(&proposal.proposal_id) {
                        if let Some(bekleyen) =
                            worker_mempool.get_transaction(&proposal.proposal_id)
                        {
                            let _ = kopru_yayin.send(bekleyen);
                        }
                        continue;
                    }

                    // Mint tx'ini oluştur ve mempool'a gönder, zincirin kendisi
                    // doğrulayıp finalize edecek.
                    let tx_type = if proposal.auto_swap {
                        TxType::BridgeMintAndSwap
                    } else {
                        TxType::BridgeMint
                    };
                    // 🚨 `gas_limit = 1` native standardı (`apply_fixed_gas_fee` ile aynı);
                    // executor `gas_limit × gas_price` kestiğinden 21.000 gibi bir değer
                    // kanonik ücretin binlerce katını ödetirdi.
                    let gas_limit = 1;
                    let gas_price = worker_mempool.native_min_required_fee(&tx_type).max(1);
                    // 🛡️ Kullanıcının `TokensLocked` slippage limiti payload'a kodlanır
                    // (yoksa/0 ise "sınır yok"). 🚨 Payload ÖNERİNİN KENDİSİDİR (imzalarıyla):
                    // zincir buradan doğrular, `amount_out_min` imza kapsamındadır.
                    let payload = match zagros_executor::bridge::BridgeManager::encode_proposal_payload(
                        &proposal,
                    ) {
                        Ok(p) => p,
                        Err(e) => {
                            tracing::error!(
                                "🚨 Köprü: öneri payload'a kodlanamadı (0x{}): {:?}",
                                hex::encode(proposal.proposal_id),
                                e
                            );
                            continue;
                        }
                    };
                    let mut tx = Transaction {
                        tx_id: proposal.proposal_id,
                        tx_type,
                        sender: signer_address.clone(),
                        receiver: proposal.recipient.clone(),
                        amount: proposal.amount,
                        payload,
                        signature: Vec::new(),
                        timestamp: std::time::UNIX_EPOCH.elapsed().unwrap().as_secs() as u128,
                        nonce: next_nonce,
                        gas_limit,
                        gas_price,
                        chain_id: CHAIN_ID,
                    };
                    tx.sign(&signer_secret_key);

                    let yayinlanacak = tx.clone();
                    match worker_mempool.add_transaction(tx) {
                        Ok(()) => {
                            next_nonce += 1;
                            // 🚨 İşlem AĞA da yayınlanır: hangi doğrulayıcı sırada olursa olsun
                            // bloğa koyabilir ve alıcıların konsensüs sürücüsünü uyandırır.
                            let _ = kopru_yayin.send(yayinlanacak);
                            tracing::info!(
                                "🌉 Köprü mint mempool'a gönderildi ve ağa yayıldı - finalize zincirde (executor) yapılacak: 0x{}",
                                hex::encode(proposal.proposal_id)
                            );
                        }
                        Err(e) => {
                            tracing::error!(
                                "🚨 Köprü: onaylı mint (0x{}) mempool'a gönderilemedi - {:?} \
                                 (imzalayıcı {} bakiye/gaz kontrol edin). Öneri executed \
                                 İŞARETLENMEDİ, sonraki turda tekrar denenecek.",
                                hex::encode(proposal.proposal_id),
                                e,
                                signer_address
                            );
                        }
                    }
                }
            }
            tracing::info!("🛑 Köprü otomatik yürütücü döngüsü durduruldu (graceful shutdown).");
        });
    }

    // 🌐 JSON-RPC: bind adresi, max_connections, ip_rate_limit config.rpc'ten.
    zagros_rpc::set_archive_backpressure(
        config.storage.archive_height_file.clone(),
        config.storage.archive_report_token.clone(),
    );
    let rpc_server = RpcServer::new(
        state.clone(),
        shared_mempool.clone(),
        bridge_manager.clone(),
        config.rpc.clone(),
    )
    .with_tx_broadcast(tx_broadcast_tx)
    .with_node_metrics(node_metrics.clone());
    let account_broadcaster = rpc_server.get_account_sender();

    // Event Dinleyicisi: Blok Üretildikçe Cüzdanlara Push Atar.
    // 0.5 saniyede bir mempool'da işlem yapan arkadaşlara PUSH geçer.
    let push_state = state.clone();
    let mut ws_push_cancel = cancel_rx.clone();
    tasks.spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(500)); // Hızlı iterasyon (0.5s)
        let mut last_acc: u128 = 0;

        loop {
            tokio::select! {
                _ = interval.tick() => {}
                _ = ws_push_cancel.changed() => {
                    if *ws_push_cancel.borrow() {
                        break;
                    }
                }
            }

            // Eğer kimsenin bakiyesi değişmediyse işlem yapmaz.
            let current_acc = push_state.get_accumulated_reward_per_share().unwrap_or(0);

            // Katsayı (Acc) değişmişse anında tüm Web Arayüzlerine CANLI PUSH'la
            if current_acc != last_acc {
                last_acc = current_acc;
                let message = serde_json::json!({
                    "type": "global_state_update",
                    "acc": current_acc.to_string(),
                    "timestamp": std::time::UNIX_EPOCH.elapsed().unwrap().as_secs()
                })
                .to_string();

                let _ = account_broadcaster.send(message);
            }
        }
        tracing::info!("🛑 WebSocket push döngüsü durduruldu (graceful shutdown).");
    });

    // 🧹 MEMPOOL TTL SÜPÜRÜCÜSÜ: `tx_expiry_seconds`'ı uygular (`evict_expired`);
    // 60 sn tarama aralığı, süresi dolan işlem en çok ~1 dk fazla yaşar.
    let worker_mempool_ttl = shared_mempool.clone();
    let mut ttl_cancel = cancel_rx.clone();
    let configured_tx_expiry_seconds = config.mempool.tx_expiry_seconds;
    tasks.spawn(async move {
        tracing::info!(
            "🧹 Mempool TTL süpürücüsü devrede (60s aralık, tx_expiry_seconds={}s)...",
            configured_tx_expiry_seconds
        );
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let evicted = worker_mempool_ttl.evict_expired();
                    if evicted > 0 {
                        tracing::info!(
                            "🧹 Mempool TTL: {} süresi dolmuş işlem tahliye edildi.",
                            evicted
                        );
                    }
                }
                _ = ttl_cancel.changed() => {
                    if *ttl_cancel.borrow() {
                        break;
                    }
                }
            }
        }
        tracing::info!("🛑 Mempool TTL süpürücüsü durduruldu (graceful shutdown).");
    });

    // 🚨 `RpcServer::start()` future'ı `tokio::spawn`'a verilemiyor (warp filter
    // kapanışlarıyla HRTB uyuşmazlığı, rustc sınırlaması); `select!`in kendi kolu
    // olarak kullanılır, başka kol kazanınca drop edilir.
    info!(
        "🚀 Node devrede - {} arka plan görevi + RPC sunucusu çalışıyor. (Ctrl-C / SIGTERM ile durdur.)",
        tasks.len()
    );

    // 🛡️ Görev denetimi: kapatma sinyali ile "görev beklenmedik bitti" yarışı;
    // herhangi biri tetiklenirse node kontrollü kapanır, sessiz görev ölümü olmaz.
    tokio::select! {
        _ = wait_for_shutdown_signal() => {
            info!("🛑 Kapatma sinyali alındı - görevlere graceful shutdown gönderiliyor...");
        }
        Some(result) = tasks.join_next() => {
            match result {
                Ok(()) => tracing::error!(
                    "🚨 Kritik bir arka plan görevi BEKLENMEDİK şekilde (panic olmadan) sona erdi - node kontrollü şekilde kapatılıyor."
                ),
                Err(e) if e.is_panic() => tracing::error!(
                    "🚨 Kritik bir arka plan görevi PANIC etti ({:?}) - node kontrollü şekilde kapatılıyor.", e
                ),
                Err(e) => tracing::error!(
                    "🚨 Kritik bir arka plan görevi iptal edildi ({:?}) - node kontrollü şekilde kapatılıyor.", e
                ),
            }
        }
        _ = rpc_server.start() => {
            tracing::error!(
                "🚨 RPC sunucusu BEKLENMEDİK şekilde sona erdi - node kontrollü şekilde kapatılıyor."
            );
        }
    }

    let _ = cancel_tx.send(true);

    // Kalan (arka plan) görevleri join et, ama sınırsız bekleme YOK, 5 saniyelik
    // bir üst sınır konuyor, süre dolunca süreç yine de sonlandırılır.
    let drain_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match tokio::time::timeout_at(drain_deadline, tasks.join_next()).await {
            Ok(Some(Err(e))) if e.is_panic() => {
                tracing::error!("🚨 Kapanış sırasında bir görev panic etti: {:?}", e);
            }
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(_) => {
                tracing::warn!(
                    "⏱️ 5 saniye içinde tüm görevler kapanmadı - süreç yine de sonlandırılıyor."
                );
                break;
            }
        }
    }
    info!("✅ Node temiz bir şekilde kapandı.");

    Ok(())
}

/// SIGINT (Ctrl-C) veya SIGTERM'i bekler. `zagros-relayer/src/main.rs`'teki AYNI
/// desen, container/systemd ortamlarında SIGTERM standart kapatma sinyalidir.
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

#[cfg(test)]
mod tests {
    use super::{
        apply_executor_version_check, initialize_genesis_if_needed, resolve_bridge_authority,
        tx_is_forward_nonce_gap, AccountState, FOUNDER_ADDRESS, FOUNDER_GENESIS_ZAGROS,
        GENESIS_POOL_ZAGROS, GENESIS_POOL_ZERENYA,
    };
    use zagros_state::State as _;
    use zagros_storage::Storage;

    #[test]
    fn forward_nonce_gap_is_retained_others_dropped() {
        // Gönderenin taahhüt edilmiş (bir sonraki beklenen) nonce'u = 5.
        // Uygulanan tx (nonce 4 → hesap nonce'u 5 oldu): 4 > 5? Hayır → SİL.
        assert!(!tx_is_forward_nonce_gap(4, 5));
        // Doğru nonce'ta başka nedenle düşen (nonce 5): 5 > 5? Hayır → SİL.
        assert!(!tx_is_forward_nonce_gap(5, 5));
        // Bayat/replay (nonce 3 < 5): 3 > 5? Hayır → SİL.
        assert!(!tx_is_forward_nonce_gap(3, 5));
        // İleri-nonce boşluğu (nonce 7, selef 5/6 eksik): 7 > 5? Evet → BEKLET.
        assert!(tx_is_forward_nonce_gap(7, 5));
        // Yeni hesap (nonce 0), ileri nonce 2: 2 > 0 → BEKLET.
        assert!(tx_is_forward_nonce_gap(2, 0));
        // Yeni hesap, nonce 0: 0 > 0? Hayır → SİL (şansını kullandı).
        assert!(!tx_is_forward_nonce_gap(0, 0));
    }

    // `resolve_bridge_authority`: follower'da `signer_secret_key_hex` yokken
    // `bridge_authority` sessizce yanlış (FOUNDER_ADDRESS) sabitine düşmemeli.

    #[test]
    fn resolve_bridge_authority_prefers_explicit_config_when_signer_key_absent() {
        // Follower senaryosu: signer_secret_key_hex YOK, ama authority_address
        // (açık, gizli olmayan) ayarlanmış, bunu KULLANMALI, None'a düşmemeli.
        let resolved =
            resolve_bridge_authority(Some("0x1a4b0219c74c8c78022747dd5dabe96b25d45617"), None);
        assert_eq!(
            resolved.as_deref(),
            Some("0x1a4b0219c74c8c78022747dd5dabe96b25d45617")
        );
    }

    #[test]
    fn resolve_bridge_authority_uses_derived_address_when_only_signer_key_present() {
        // Proposer senaryosu (authority_address henüz eklenmemiş eski config):
        // signer_secret_key_hex'ten türetilen adres kullanılmalı.
        let resolved = resolve_bridge_authority(None, Some("0xabc"));
        assert_eq!(resolved.as_deref(), Some("0xabc"));
    }

    #[test]
    fn resolve_bridge_authority_returns_none_when_neither_configured() {
        assert_eq!(resolve_bridge_authority(None, None), None);
    }

    #[test]
    fn resolve_bridge_authority_accepts_matching_case_insensitive_values() {
        let resolved = resolve_bridge_authority(Some("0xABC"), Some("0xabc"));
        assert_eq!(resolved.as_deref(), Some("0xABC"));
    }

    #[test]
    #[should_panic(expected = "UYUŞMUYOR")]
    fn resolve_bridge_authority_panics_on_mismatch_between_configured_and_derived() {
        resolve_bridge_authority(Some("0xaaa"), Some("0xbbb"));
    }

    // `apply_executor_version_check` gerçek RocksDB `State`'e karşı: karar
    // testleri (zagros-types) kararı, bunlar disk kablolamasını kanıtlar.

    fn test_state() -> (
        std::sync::Arc<zagros_state::manager::StateDbManager>,
        tempfile::TempDir,
    ) {
        let tmp = tempfile::tempdir().unwrap();
        let storage = std::sync::Arc::new(
            zagros_storage::rocksdb_impl::RocksDbStorage::open(tmp.path().to_str().unwrap())
                .unwrap(),
        );
        let state = std::sync::Arc::new(zagros_state::manager::StateDbManager::new(storage));
        (state, tmp)
    }

    // Genesis flush sıralaması: kanıt + regresyon.

    /// **KANIT:** genesis yazmaları `flush()` çağrılmadan `block_0` doğrudan
    /// yazılırsa "restart" kurucu bakiyesini ve AMM havuzunu sessizce kaybeder;
    /// `block_0` diskte olduğundan genesis bir daha ÇALIŞTIRILMAZ.
    #[test]
    fn pre_fix_ordering_would_have_lost_genesis_on_an_early_restart() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().to_str().unwrap();

        {
            let storage = std::sync::Arc::new(
                zagros_storage::rocksdb_impl::RocksDbStorage::open(db_path).unwrap(),
            );
            let state = zagros_state::manager::StateDbManager::new(storage.clone());

            // ÖNCEKİ (hatalı) main.rs sıralamasının BİREBİR aynısı: önce
            // hesap yazmaları (yalnızca bellek-içi cache), flush YOK, sonra
            // block_0 DOĞRUDAN storage'a.
            let mut founder_acc = AccountState::default();
            founder_acc.balance = FOUNDER_GENESIS_ZAGROS;
            zagros_state::State::set_account(&state, &FOUNDER_ADDRESS.to_string(), founder_acc)
                .unwrap();
            state
                .set_pool_reserves(GENESIS_POOL_ZAGROS, GENESIS_POOL_ZERENYA)
                .unwrap();

            let genesis_header = zagros_types::BlockHeader {
                number: 0,
                timestamp: 0,
                parent_hash: [0u8; 32],
                state_root: [0u8; 32],
                extra_data: vec![],
            };
            let genesis_bytes = bincode::serialize(&genesis_header).unwrap();
            zagros_storage::Storage::put(storage.as_ref(), b"block_0", &genesis_bytes).unwrap();
            // `state.flush()` KASITLI OLARAK ÇAĞRILMADI, "crash/restart
            // burada olur" anını simüle ediyor. `state`/`storage` bu scope
            // sonunda drop edilir (gerçek bir process sonlanması gibi).
        }

        // "Restart": AYNI fiziksel dizini yeniden aç.
        let reopened_storage = std::sync::Arc::new(
            zagros_storage::rocksdb_impl::RocksDbStorage::open(db_path).unwrap(),
        );
        let reopened_state = zagros_state::manager::StateDbManager::new(reopened_storage.clone());

        // block_0 KALICI (storage.put doğrudan yazdı), yani
        // `should_initialize_genesis` artık `false` döner, genesis BİR DAHA
        // ÇALIŞTIRILMAZ.
        assert!(
            zagros_storage::Storage::get(reopened_storage.as_ref(), b"block_0")
                .unwrap()
                .is_some(),
            "block_0 kalıcı olmalıydı (storage.put doğrudan yazdı)"
        );

        // AMA kurucu bakiyesi/AMM havuzu KAYBOLDU, hiçbir zaman flush edilmedi.
        let founder =
            zagros_state::State::get_account(&reopened_state, &FOUNDER_ADDRESS.to_string())
                .unwrap();
        assert!(
            founder.is_none() || founder.unwrap().balance == 0,
            "İSTİSMAR KANITLANDI: block_0 kalıcı olduğu halde kurucu bakiyesi kayboldu - \
             genesis bir daha ÇALIŞTIRILAMAZ, kaybedilen arz KURTARILAMAZ."
        );
        assert_eq!(
            reopened_state.get_pool_reserves().unwrap(),
            (0, 0),
            "İSTİSMAR KANITLANDI: AMM havuz rezervleri de aynı nedenle kayboldu."
        );
    }

    /// **Regresyon:** doğru sıralı genesis `block_0`dan hemen önceki restart'tan sağlam çıkar.
    #[test]
    fn genesis_survives_a_restart_immediately_after_initialization() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().to_str().unwrap();

        {
            let storage = std::sync::Arc::new(
                zagros_storage::rocksdb_impl::RocksDbStorage::open(db_path).unwrap(),
            );
            let state = zagros_state::manager::StateDbManager::new(storage.clone());
            let initialized = initialize_genesis_if_needed(
                storage.as_ref(),
                &state,
                &zagros_types::config::GenesisConfig::default(),
            )
            .unwrap();
            assert!(initialized, "taze bir dizinde genesis başlatılmalıydı");
            // `state`/`storage` burada drop edilir, "restart" simülasyonu.
        }

        let reopened_storage = std::sync::Arc::new(
            zagros_storage::rocksdb_impl::RocksDbStorage::open(db_path).unwrap(),
        );
        let reopened_state = zagros_state::manager::StateDbManager::new(reopened_storage.clone());

        assert!(
            zagros_storage::Storage::get(reopened_storage.as_ref(), b"block_0")
                .unwrap()
                .is_some(),
            "block_0 kalıcı olmalı"
        );
        let founder =
            zagros_state::State::get_account(&reopened_state, &FOUNDER_ADDRESS.to_string())
                .unwrap()
                .expect("DÜZELTME SONRASI: kurucu hesabı restart'tan SAĞLAM çıkmalı");
        assert_eq!(founder.balance, FOUNDER_GENESIS_ZAGROS);
        assert_eq!(
            reopened_state.get_pool_reserves().unwrap(),
            (GENESIS_POOL_ZAGROS, GENESIS_POOL_ZERENYA),
            "DÜZELTME SONRASI: AMM havuz rezervleri restart'tan SAĞLAM çıkmalı"
        );
    }

    /// **Sıralama testi:** `block_0` yazımını kasıtlı başarısız yapan sarmalayıcıyla
    /// flush'ın önce çalıştığı kanıtlanır (ters sırada test düşer).
    #[test]
    fn flush_is_durably_committed_before_block_0_is_written_even_if_block_0_write_then_fails() {
        struct FailBlock0Write {
            inner: std::sync::Arc<zagros_storage::rocksdb_impl::RocksDbStorage>,
        }
        impl Storage for FailBlock0Write {
            fn get(&self, key: &[u8]) -> zagros_primitives::Result<Option<Vec<u8>>> {
                self.inner.get(key)
            }
            fn put(&self, key: &[u8], value: &[u8]) -> zagros_primitives::Result<()> {
                if key == b"block_0" {
                    return Err(zagros_primitives::ZagrosError::DatabaseError(
                        "TESTTE KASITLI HATA: block_0 yazımı reddedildi".to_string(),
                    ));
                }
                self.inner.put(key, value)
            }
            fn delete(&self, key: &[u8]) -> zagros_primitives::Result<()> {
                self.inner.delete(key)
            }
            fn contains(&self, key: &[u8]) -> zagros_primitives::Result<bool> {
                self.inner.contains(key)
            }
            fn list_keys(&self) -> zagros_primitives::Result<Vec<Vec<u8>>> {
                self.inner.list_keys()
            }
        }

        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().to_str().unwrap();
        // 🚨 Tek RocksDB handle paylaşılır; iki ayrı `open()` tek yazar kilidine takılırdı.
        {
            let shared_db = std::sync::Arc::new(
                zagros_storage::rocksdb_impl::RocksDbStorage::open(db_path).unwrap(),
            );
            let failing_storage = FailBlock0Write {
                inner: shared_db.clone(),
            };
            let state = zagros_state::manager::StateDbManager::new(shared_db);

            let result = initialize_genesis_if_needed(
                &failing_storage,
                &state,
                &zagros_types::config::GenesisConfig::default(),
            );
            assert!(
                result.is_err(),
                "block_0 yazımı reddedildiği için fonksiyon Err dönmeliydi"
            );
            assert!(
                result.unwrap_err().contains("block_0"),
                "hata block_0 yazım hatasından gelmeliydi"
            );
            // 🚨 `get_account` ÖNCE cache'e bakar; yaşayan instance üzerinde kontrol
            // yanlış pozitif verirdi, asıl kanıt aşağıda taze (disk-only) instance ile.
        }

        // 🛡️ ASIL KANIT (disk-only, cache'siz TAZE bir instance): block_0
        // yazımı BAŞARISIZ oldu, ama flush() ondan ÖNCE çalıştıysa kurucu
        // bakiyesi/AMM havuzu YİNE DE DİSKTE olmalı.
        let reopened_storage = std::sync::Arc::new(
            zagros_storage::rocksdb_impl::RocksDbStorage::open(db_path).unwrap(),
        );
        let reopened_state = zagros_state::manager::StateDbManager::new(reopened_storage);

        let founder =
            zagros_state::State::get_account(&reopened_state, &FOUNDER_ADDRESS.to_string())
                .unwrap()
                .expect(
                    "SIRALAMA REGRESYONU: flush() block_0 yazımından ÖNCE çalışmıyor - \
                     block_0 başarısız olduğunda kurucu bakiyesi de diskte OLMALIYDI",
                );
        assert_eq!(founder.balance, FOUNDER_GENESIS_ZAGROS);
        assert_eq!(
            zagros_state::State::get_pool_reserves(&reopened_state).unwrap(),
            (GENESIS_POOL_ZAGROS, GENESIS_POOL_ZERENYA)
        );
    }

    /// İkinci çağrı `Ok(false)` döner, state'e dokunmaz. G13 (§16.2): replay_guard
    /// uçtan uca (export → dosya → nonce'lar final+1, bakiye korunur; bozuk dosya fail-closed).
    #[test]
    fn g13_replay_guard_export_and_genesis_apply_roundtrip() {
        use crate::replay_guard;
        // 1) "Dondurulmuş" private zincir state'i (gerçek RocksDB, tempdir)
        let frozen_dir = tempfile::tempdir().unwrap();
        {
            let storage =
                zagros_storage::rocksdb_impl::RocksDbStorage::open(frozen_dir.path()).unwrap();
            let mut a = zagros_types::AccountState::new(1_000);
            a.nonce = 5;
            storage
                .put(
                    b"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    &bincode::serialize(&a).unwrap(),
                )
                .unwrap();
            let b_acc = zagros_types::AccountState::new(2_000); // nonce 0 → listeye girmez
            storage
                .put(
                    b"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    &bincode::serialize(&b_acc).unwrap(),
                )
                .unwrap();
            storage
                .put(b"__CHAIN_PARAMS__", b"sentinel-gurultusu")
                .unwrap(); // adres-dışı anahtarlar atlanır
        }
        let entries = replay_guard::export_from_state_dir(frozen_dir.path()).unwrap();
        assert_eq!(entries.nonces.len(), 1);
        assert_eq!(
            entries.nonces[0].address,
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(entries.nonces[0].final_nonce, 5);

        // 2) Dosya yaz → taze genesis'e uygula (genesis tahsisli hesapla BİRLEŞİR)
        let file = frozen_dir.path().join("replay_guard.txt");
        std::fs::write(&file, replay_guard::to_file_format(&entries)).unwrap();
        let __tmp = tempfile::tempdir().unwrap();
        let storage2 = std::sync::Arc::new(
            zagros_storage::rocksdb_impl::RocksDbStorage::open(__tmp.path().to_str().unwrap())
                .unwrap(),
        );
        let state =
            std::sync::Arc::new(zagros_state::manager::StateDbManager::new(storage2.clone()));
        // genesis tahsisi taklidi: aynı adrese bakiye
        state
            .set_account(
                &"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                zagros_types::AccountState::new(777),
            )
            .unwrap();
        let genesis_cfg = zagros_types::config::GenesisConfig {
            replay_guard_file: Some(file.to_string_lossy().to_string()),
            ..Default::default()
        };
        let initialized =
            initialize_genesis_if_needed(storage2.as_ref(), state.as_ref(), &genesis_cfg).unwrap();
        assert!(initialized);
        let acc = state
            .get_account(&"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string())
            .unwrap()
            .unwrap();
        assert_eq!(
            acc.nonce, 6,
            "final(5)+1 — testnet'te imzalanmış hiçbir nonce ≤5 işlem geçemez"
        );
        assert_eq!(acc.balance, 777, "genesis tahsisi (bakiye) korunmalı");

        // 3) Bozuk dosya → genesis FAIL-CLOSED
        let bad = frozen_dir.path().join("bozuk.txt");
        std::fs::write(&bad, "gecersiz satir\n").unwrap();
        let __tmp3 = tempfile::tempdir().unwrap();
        let storage3 = std::sync::Arc::new(
            zagros_storage::rocksdb_impl::RocksDbStorage::open(__tmp3.path().to_str().unwrap())
                .unwrap(),
        );
        let state3 =
            std::sync::Arc::new(zagros_state::manager::StateDbManager::new(storage3.clone()));
        let bad_cfg = zagros_types::config::GenesisConfig {
            replay_guard_file: Some(bad.to_string_lossy().to_string()),
            ..Default::default()
        };
        assert!(
            initialize_genesis_if_needed(storage3.as_ref(), state3.as_ref(), &bad_cfg).is_err(),
            "eksik/bozuk replay listesi = açık replay kapısı → genesis reddetmeli"
        );
    }

    /// 🚨 Genesis kapasitesi 10; sert tavan 101 değişmedi, büyütme governance ile.
    #[test]
    fn genesis_writes_max_validators_capacity() {
        let p = zagros_types::consensus::ChainParams::genesis_defaults();
        assert_eq!(p.max_validators, 10, "genesis kapasitesi 10");
        assert!(
            p.max_validators <= zagros_types::consensus::MAX_VALIDATORS_HARD,
            "kapasite sert tavani asamaz"
        );
    }

    /// 🛡️ Sabit `GENESIS_TIMESTAMP`: iki bağımsız taze DB'de genesis birebir AYNI
    /// `block_0` baytlarını üretmeli (blok 1 parent_hash bu baytlardan türer).
    #[test]
    fn independently_initialized_genesis_produces_byte_identical_block_0() {
        let tmp_a = tempfile::tempdir().unwrap();
        let storage_a = std::sync::Arc::new(
            zagros_storage::rocksdb_impl::RocksDbStorage::open(tmp_a.path().to_str().unwrap())
                .unwrap(),
        );
        let state_a = zagros_state::manager::StateDbManager::new(storage_a.clone());
        initialize_genesis_if_needed(
            storage_a.as_ref(),
            &state_a,
            &zagros_types::config::GenesisConfig::default(),
        )
        .unwrap();

        let tmp_b = tempfile::tempdir().unwrap();
        let storage_b = std::sync::Arc::new(
            zagros_storage::rocksdb_impl::RocksDbStorage::open(tmp_b.path().to_str().unwrap())
                .unwrap(),
        );
        let state_b = zagros_state::manager::StateDbManager::new(storage_b.clone());
        initialize_genesis_if_needed(
            storage_b.as_ref(),
            &state_b,
            &zagros_types::config::GenesisConfig::default(),
        )
        .unwrap();

        let block_0_a = storage_a.get(b"block_0").unwrap().unwrap();
        let block_0_b = storage_b.get(b"block_0").unwrap().unwrap();
        assert_eq!(
            block_0_a, block_0_b,
            "iki bağımsız node'un genesis'i AYNI block_0 baytlarını üretmeli - \
             aksi halde P2P ağında blok hash zincirleri asla örtüşmez"
        );
    }

    /// Taze DB'de genesis: block_0 kökü = `state_root()`, hesaplar doğru, tüm
    /// `0x` bakiyelerin toplamı = MAX_SUPPLY, 0x...0002 için eth_getBalance simüle edilir.
    #[test]
    fn fresh_genesis_has_no_phantom_zagros_balance_and_total_supply_matches_max_supply() {
        use sha3::{Digest, Keccak256};

        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().to_str().unwrap();
        let storage = std::sync::Arc::new(
            zagros_storage::rocksdb_impl::RocksDbStorage::open(db_path).unwrap(),
        );
        let state = zagros_state::manager::StateDbManager::new(storage.clone());

        let initialized = initialize_genesis_if_needed(
            storage.as_ref(),
            &state,
            &zagros_types::config::GenesisConfig::default(),
        )
        .unwrap();
        assert!(initialized, "taze bir dizinde genesis başlatılmalıydı");

        // ---- 1) block_0 + state root (doğrudan storage/state'ten) ----
        let block_0_bytes = zagros_storage::Storage::get(storage.as_ref(), b"block_0")
            .unwrap()
            .expect("block_0 diskte olmalı");
        let genesis_header: zagros_types::BlockHeader =
            bincode::deserialize(&block_0_bytes).unwrap();
        let computed_block_hash = {
            let mut hasher = Keccak256::new();
            hasher.update(&block_0_bytes);
            hasher.finalize()
        };
        let state_root_from_state = zagros_state::State::state_root(&state).unwrap();
        assert_eq!(
            genesis_header.state_root, state_root_from_state,
            "header'daki state_root, state.state_root()'tan okunanla eşleşmeli"
        );

        // ---- 2) Founder / Havuz / 0x...0002 (doğrudan get_account) ----
        let founder = zagros_state::State::get_account(&state, &FOUNDER_ADDRESS.to_string())
            .unwrap()
            .expect("founder hesabı genesis'te oluşmalı");
        let (pool_zagros, pool_zerenya) = zagros_state::State::get_pool_reserves(&state).unwrap();
        let zerenya_token_account = zagros_state::State::get_account(
            &state,
            &"0x0000000000000000000000000000000000000002".to_string(),
        )
        .unwrap()
        .expect("0x...0002 hesabı genesis'te oluşmalı");

        assert_eq!(founder.balance, FOUNDER_GENESIS_ZAGROS);
        assert_eq!(pool_zagros, GENESIS_POOL_ZAGROS);
        assert_eq!(pool_zerenya, GENESIS_POOL_ZERENYA);
        // 🛡️ ASIL İDDİA: 0x...0002'nin ZAGROS bakiyesi SIFIR; hayalet
        // 41.999.999 ZAGROS (GENESIS_POOL_ZAGROS) yazılmamalı.
        assert_eq!(
            zerenya_token_account.balance, 0,
            "0x...0002 hesabının ZAGROS bakiyesi artık SIFIR olmalı (phantom balance kaldırıldı)"
        );
        assert_eq!(
            zerenya_token_account.zerenya_balance, GENESIS_POOL_ZERENYA,
            "0x...0002 yalnızca ZERENYA anlık görüntüsünü taşımaya devam etmeli"
        );

        // ---- 3) Explorer doğrulaması: TÜM hesapları tara, Σ(balance) ----
        let all_keys = zagros_storage::Storage::list_keys(storage.as_ref()).unwrap();
        let mut total_balance: u128 = 0;
        let mut accounts_seen = 0usize;
        for key in all_keys {
            if let Ok(key_str) = String::from_utf8(key) {
                if key_str.starts_with("0x") {
                    let bytes = zagros_storage::Storage::get(storage.as_ref(), key_str.as_bytes())
                        .unwrap()
                        .expect("listelenen 0x anahtarının değeri olmalı");
                    let account = AccountState::deserialize_with_migration(&bytes).unwrap();
                    total_balance += account.balance;
                    accounts_seen += 1;
                }
            }
        }
        assert_eq!(
            total_balance,
            zagros_types::MAX_SUPPLY,
            "TÜM hesapların .balance toplamı (Σ={}, {} hesap tarandı) MAX_SUPPLY'a ({}) eşit \
             olmalı - eşit değilse ya eksik ya fazla bir bakiye var demektir",
            total_balance,
            accounts_seen,
            zagros_types::MAX_SUPPLY
        );

        // ---- 4) eth_getBalance(0x...0002) simülasyonu (rpc/lib.rs:1599-1611
        //         ile BİREBİR aynı formül: account.balance, ölçeklemeden) ----
        let eth_get_balance_result = format!("0x{:x}", zerenya_token_account.balance);

        // ---- Rapor (cargo test, --nocapture ile görünür) ----
        println!("===== TAZE GENESİS DOĞRULAMA RAPORU =====");
        println!(
            "block_0 (bincode) uzunluğu   : {} bayt",
            block_0_bytes.len()
        );
        println!(
            "Hesaplanan block hash (keccak256 of block_0 bytes): 0x{}",
            hex::encode(computed_block_hash)
        );
        println!(
            "State Root (header + state.state_root(), eşleşti): 0x{}",
            hex::encode(state_root_from_state)
        );
        println!(
            "Founder bakiyesi              : {} ham birim ({} ZAGROS)",
            founder.balance,
            zagros_types::format_token_amount_whole(founder.balance)
        );
        println!(
            "Liquidity Pool bakiyesi        : {} ZAGROS ham birim / {} ZERENYA ham birim",
            pool_zagros, pool_zerenya
        );
        println!(
            "0x...0002 ZAGROS balance       : {} (BEKLENEN: 0)",
            zerenya_token_account.balance
        );
        println!(
            "0x...0002 ZERENYA balance          : {} ham birim",
            zerenya_token_account.zerenya_balance
        );
        println!(
            "Σ(tüm hesap .balance)          : {} ({} hesap)",
            total_balance, accounts_seen
        );
        println!(
            "MAX_SUPPLY                     : {}",
            zagros_types::MAX_SUPPLY
        );
        println!(
            "Σ == MAX_SUPPLY                : {}",
            total_balance == zagros_types::MAX_SUPPLY
        );
        println!(
            "eth_getBalance(0x...0002)      : {}",
            eth_get_balance_result
        );
        println!("===========================================");
    }

    #[test]
    fn fresh_genesis_boots_and_stamps_current_version_without_acknowledgement() {
        let (state, _tmp) = test_state();
        // `block_0` bu testte hiç yazılmadı -> `should_initialize_genesis = true`.
        apply_executor_version_check(state.as_ref(), true, None)
            .expect("taze genesis onaysız başlamalı");

        let stored = zagros_state::State::get_account(
            state.as_ref(),
            &zagros_types::EXECUTOR_STATE_VERSION_KEY.to_string(),
        )
        .unwrap()
        .expect("sürüm anahtarı yazılmış olmalı");
        assert_eq!(
            stored.balance as u32,
            zagros_types::EXECUTOR_STATE_TRANSITION_VERSION
        );
    }

    /// Bu testin ADI KRİTİK: önceki (bu PR'dan ÖNCEKİ) bir node'un ürettiği
    /// gerçek bir veritabanını simüle ediyor, sürüm anahtarı YOK ama
    /// `should_initialize_genesis = false` (yani `block_0` zaten diskteydi).
    #[test]
    fn preexisting_pre_hardening_database_refuses_to_boot_without_acknowledgement() {
        let (state, _tmp) = test_state();
        let err = apply_executor_version_check(state.as_ref(), false, None)
            .expect_err("onaysız, önceden var olan bir veritabanı BAŞLAMAMALI");
        assert!(err.contains("BAŞLAMA REDDEDİLDİ"));

        // Reddedilen bir başlatma diskteki (yok olan) sürümü DEĞİŞTİRMEMELİ.
        let stored = zagros_state::State::get_account(
            state.as_ref(),
            &zagros_types::EXECUTOR_STATE_VERSION_KEY.to_string(),
        )
        .unwrap();
        assert!(
            stored.is_none(),
            "reddedilen bir başlatma sürüm anahtarını YAZMAMALI"
        );
    }

    #[test]
    fn preexisting_pre_hardening_database_boots_with_exact_acknowledgement() {
        let (state, _tmp) = test_state();
        let current = zagros_types::EXECUTOR_STATE_TRANSITION_VERSION;
        apply_executor_version_check(state.as_ref(), false, Some(current))
            .expect("dogru onayla başlamalı");

        let stored = zagros_state::State::get_account(
            state.as_ref(),
            &zagros_types::EXECUTOR_STATE_VERSION_KEY.to_string(),
        )
        .unwrap()
        .expect("onaylı yükseltme sürüm anahtarını yazmalı");
        assert_eq!(stored.balance as u32, current);
    }

    #[test]
    fn acknowledging_the_wrong_version_number_does_not_satisfy_the_upgrade_gate() {
        // Diskte sürüm 1, operatör yanlış sayı onaylamış (`current` değil);
        // gateway atlatılmamalı.
        let (state, _tmp) = test_state();
        let mut acc = zagros_types::AccountState::default();
        acc.balance = 1;
        zagros_state::State::set_account(
            state.as_ref(),
            &zagros_types::EXECUTOR_STATE_VERSION_KEY.to_string(),
            acc,
        )
        .unwrap();

        let err = apply_executor_version_check(state.as_ref(), false, Some(1))
            .expect_err("yanlış sürüm numarası onayı BAŞLATMAMALI");
        assert!(err.contains("BAŞLAMA REDDEDİLDİ"));
    }

    #[test]
    fn matching_version_boots_silently_and_leaves_disk_untouched() {
        let (state, _tmp) = test_state();
        let current = zagros_types::EXECUTOR_STATE_TRANSITION_VERSION;
        let mut acc = zagros_types::AccountState::default();
        acc.balance = current as u128;
        zagros_state::State::set_account(
            state.as_ref(),
            &zagros_types::EXECUTOR_STATE_VERSION_KEY.to_string(),
            acc,
        )
        .unwrap();

        apply_executor_version_check(state.as_ref(), false, None)
            .expect("zaten güncel bir sürümle onaysız başlamalı");
    }

    /// R3'ün diğer yarısı: GERİ SARMA (bu ikiliden DAHA YENİ bir sürümle
    /// dokunulmuş state), hiçbir onayla geçilemez, node BAŞLAMAMALI.
    #[test]
    fn downgrade_refuses_to_boot_even_with_an_acknowledgement() {
        let (state, _tmp) = test_state();
        let future_version = zagros_types::EXECUTOR_STATE_TRANSITION_VERSION + 1;
        let mut acc = zagros_types::AccountState::default();
        acc.balance = future_version as u128;
        zagros_state::State::set_account(
            state.as_ref(),
            &zagros_types::EXECUTOR_STATE_VERSION_KEY.to_string(),
            acc,
        )
        .unwrap();

        let err = apply_executor_version_check(
            state.as_ref(),
            false,
            Some(zagros_types::EXECUTOR_STATE_TRANSITION_VERSION),
        )
        .expect_err("geri sarma hiçbir onayla BAŞLAMAMALI");
        assert!(err.contains("GERİ SARMA"));

        // Diskteki (daha yüksek) sürüm AŞAĞI ÇEKİLMEMELİ, gerçeği gizlemez.
        let stored = zagros_state::State::get_account(
            state.as_ref(),
            &zagros_types::EXECUTOR_STATE_VERSION_KEY.to_string(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(stored.balance as u32, future_version);
    }
}
