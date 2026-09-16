// Zagros Network, Configuration Management
// Tüm konfigürasyon yönetimi

use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::path::Path;

/// Main Zagros configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ZagrosConfig {
    /// Network configuration
    pub network: NetworkConfig,

    /// Consensus configuration
    pub consensus: ConsensusConfig,

    /// Storage configuration
    pub storage: StorageConfig,

    /// RPC configuration
    pub rpc: RpcConfig,

    /// Gas configuration
    pub gas: GasConfig,

    /// Mempool configuration
    pub mempool: MempoolConfig,

    /// Bridge multi-sig configuration
    #[serde(default)]
    pub bridge: BridgeConfig,

    /// Governance (proposal/vote) configuration
    #[serde(default)]
    pub governance: GovernanceConfig,

    /// Operatör uyarı (alert) webhook yapılandırması, validator hapis
    /// yerse, DDoS stres modu tetiklenirse veya blok üretimi (talep varken)
    /// durursa Discord/Slack-uyumlu bir webhook'a otomatik POST atılır.
    #[serde(default)]
    pub alerts: AlertsConfig,

    /// 🛡️ Konsensüs kritik executor sürüm yükseltmesinde node'un başlaması
    /// için operatörün BİLEREK yazacağı hedef sürüm (`EXECUTOR_STATE_TRANSITION_VERSION`).
    /// Boolean değil sayı: bir kez `true` yapılıp unutulan bayrak gelecek her
    /// sıçramayı sessizce onaylardı. `None` ya da uyuşmayan değer + gereken
    /// yükseltme = FAIL-CLOSED ret; geri sarmada bu alan hiçbir şeyi onaylayamaz.
    #[serde(default)]
    pub acknowledged_executor_state_version: Option<u32>,

    /// G8 (§16): BFT genesis (multisig + ilk küme). `validators` boşsa eski
    /// davranış birebir; doluysa FAIL-CLOSED kurulur.
    #[serde(default)]
    pub genesis: GenesisConfig,
}

/// `[genesis]`, yalnızca genesis ANINDA (block_0 ilk kez yazılırken) okunur;
/// sonraki başlatmalarda YOK SAYILIR (genesis zaten kalıcı state'te).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GenesisConfig {
    /// Faz A (§2.1) 3-of-5 admin multisig. `None` = validator listesi boşsa
    /// zararsız; validator listesi DOLUYSA zorunlu (yoksa genesis fail-closed
    /// reddeder, BFT kümesi admin onayı olmadan anlamsız).
    #[serde(default)]
    pub admin_multisig: Option<GenesisAdminMultisigConfig>,
    /// Genesis validator kümesi (§2, INV-L1 istisnası: doğrudan Active). Operatör
    /// bu adresleri epoch 1 sınırından ÖNCE gerçek `staked_balance` ile fonlamalı,
    /// yoksa ilk epoch'ta Probation'a düşerler.
    #[serde(default)]
    pub validators: Vec<GenesisValidatorConfig>,
    /// G13 (§16.2 replay_guard): dondurulan zincirden `replay_guard_export` ile
    /// üretilen "adres nonce" dosyası; genesis'te nonce'lar `final+1`'den başlar,
    /// test zincirinde imzalanmış işlem oynatılamaz (chain_id aynı). `None` = koruma yok.
    #[serde(default)]
    pub replay_guard_file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisAdminMultisigConfig {
    /// 3-of-5 (ya da operatörün seçtiği N) imzacı Zagros adresi.
    pub signers: Vec<String>,
    pub threshold: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisValidatorConfig {
    pub address: String,
    /// 32 baytlık Ed25519 konsensüs açık anahtarı, hex (`0x` önekli olabilir).
    pub consensus_pubkey_hex: String,
    /// §2.2 çeşitlilik beyanı, provider/region tavanları buradan sayılır.
    pub provider: String,
    pub region: String,
    pub asn: u32,
    /// 32 baytlık operatör kimliği, hex (aynı operatörün birden validator'ı
    /// olamaz, `max_per_operator=1`).
    pub operator_id_hex: String,
}

impl ZagrosConfig {
    /// Load configuration from TOML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let content = fs::read_to_string(path).map_err(|e| ConfigError::IoError(e.to_string()))?;

        let config: ZagrosConfig =
            toml::from_str(&content).map_err(|e| ConfigError::ParseError(e.to_string()))?;

        config.validate()?;

        Ok(config)
    }

    /// Save configuration to TOML file
    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), ConfigError> {
        let content =
            toml::to_string_pretty(self).map_err(|e| ConfigError::SerializeError(e.to_string()))?;

        fs::write(path, content).map_err(|e| ConfigError::IoError(e.to_string()))?;

        Ok(())
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.network.validate()?;
        self.consensus.validate()?;
        self.storage.validate()?;
        self.rpc.validate()?;
        self.gas.validate()?;
        self.mempool.validate()?;
        self.bridge.validate()?;
        self.governance.validate()?;
        self.alerts.validate()?;

        Ok(())
    }

    /// Create default configuration file
    pub fn create_default_config<P: AsRef<Path>>(path: P) -> Result<(), ConfigError> {
        let config = Self::default();
        config.to_file(path)
    }
}

/// Ağ yapılandırması; alanlar `zagros-network` libp2p kimliği/davranışına bağlıdır.
/// `network.trusted_checkpoint`, hex alanlar `0x` önekli ya da öneksiz 32 bayt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedCheckpointConfig {
    pub height: u64,
    pub block_hash: String,
    pub validator_set_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// P2P listen address
    pub listen_addr: String,

    /// Bootstrap nodes
    pub bootstrap_nodes: Vec<String>,

    /// Maximum number of peers
    pub max_peers: usize,

    /// Enable P2P networking
    pub enable_p2p: bool,

    /// Network ID
    pub network_id: u64,

    /// 🛡️ Ağda TAM OLARAK BİR node `true`: on-demand üretici döngüsünü çalıştırıp
    /// gossip'ler, diğerleri `false` (senkronize eder, önermez). `block_producer_address`
    /// yalnız ödül alıcısıdır, kapı değildir; iki node önerirse sessiz fork oluşur.
    #[serde(default)]
    pub is_proposer: bool,

    /// G5: Ed25519 konsensüs anahtar dosyası (`save_keyfile` biçimi). Ayarlıysa
    /// BFT modu (`BftEngine` + konsensüs topic'i), eski `is_proposer` döngüsü
    /// kullanılmaz. Hesap/admin/köprü anahtarlarından AYRIDIR (§15).
    #[serde(default)]
    pub consensus_key_path: Option<String>,

    /// 🚨 Equivocation kanıtlarının yazıldığı YEREL dosya; satır hazır
    /// `ReportMalicious` payload'ı taşır (`validator evidence-report` okur).
    /// Zincire otomatik yazılmaz (determinizm); boşsa yalnız log'a düşer.
    #[serde(default = "default_evidence_log_path")]
    pub evidence_log_path: String,

    /// G6 (§9): güvenilen kontrol noktası; catch-up'ta hash/validator_set_hash
    /// eşleşmezse node durur. `None` = genesis'ten tam QC zinciri.
    #[serde(default)]
    pub trusted_checkpoint: Option<TrustedCheckpointConfig>,

    /// Node'un kalıcı ed25519 libp2p kimliği (protobuf); yoksa ilk açılışta
    /// üretilir (`0600`). Köprü yetkili anahtarından AYRI, yalnız kararlı `PeerId` için.
    #[serde(default = "default_node_key_path")]
    pub node_key_path: String,

    /// mDNS yerel-alt ağ keşfi. Localhost/LAN testi için kullanışlı,
    /// bağımsız sunucular arası (internet üzerinden) İŞE YARAMAZ (multicast
    /// yönlenmez), gerçek çoklu-sunucu dağıtımda `false` yapılması önerilir.
    #[serde(default = "default_mdns_enabled")]
    pub mdns_enabled: bool,

    /// Bir `SyncResponse::BlockRange` yanıtında dönülecek azami blok sayısı.
    #[serde(default = "default_sync_batch_size")]
    pub sync_batch_size: u64,

    // ── 🛡️ P2P koruma / sentry mimarisi (konsensüs dışı, kapı gerekmez):
    // validatör kapalı, açık yüz sentry; adresleri imzalayıp duyurur.
    /// Bu düğüm bir SENTRY mi (herkese açık, validatörlerin duyurduğu
    /// sentry'lere bağlantı kotası ayırır)? Konsensüs anahtarı OLMAYAN, dış
    /// dünyaya açık düğümler için `true`. Validatörde `false`.
    #[serde(default)]
    pub sentry_mode: bool,

    /// Özel eş listesi (multiaddr, `/p2p/<PeerId>` ZORUNLU). Doluysa düğüm
    /// YALNIZ bu eşlerle konuşur (allow-list), dinleme adresini ilan etmez,
    /// yabancı sentry aramaz. Validatör için: kendi sentry'leri. Boşsa açık düğüm.
    #[serde(default)]
    pub private_peers: Vec<String>,

    /// Bu düğümün dış dünyaya duyuracağı kendi adresi (multiaddr, `/p2p/`
    /// OLMADAN; örn. `/ip4/1.2.3.4/tcp/30303`). NAT/bulut arkasındaki sentry
    /// için gerekir: libp2p `add_external_address` ile identify'da ilan edilir.
    #[serde(default)]
    pub external_addr: Option<String>,

    /// Validatörün sentry'lerinin halka açık adresleri; konsensüs anahtarı varsa
    /// `/zagros/{id}/peers/1` topic'inde imzalı duyurulur, açık düğümler
    /// doğrulayıp bu adreslere bağlantı kotası ayırır.
    #[serde(default)]
    pub sentry_addrs: Vec<String>,

    /// Aynı IP'den aynı anda kabul edilecek azami bağlantı (duyurulmuş
    /// sentry'ler ve `private_peers` bu kotadan MUAF). Bağlantı seli/Sybil
    /// koruması; libp2p'nin peer başına sınırının IP boyutu.
    #[serde(default = "default_max_peers_per_ip")]
    pub max_peers_per_ip: u32,

    /// Duyurulmuş validatör sentry'leri için toplam bağlantı tavanının
    /// ÜSTÜNE ayrılan slot sayısı (yalnız sentry_mode/açık düğümlerde anlamlı).
    /// Açık ağ dolsa bile kümedeki validatörlerin trafiği her zaman yer bulur.
    #[serde(default = "default_reserved_validator_slots")]
    pub reserved_validator_slots: u32,
}

fn default_max_peers_per_ip() -> u32 {
    4
}

fn default_reserved_validator_slots() -> u32 {
    32
}

fn default_evidence_log_path() -> String {
    "zagros-evidence.jsonl".to_string()
}

fn default_node_key_path() -> String {
    "./zagros-data/network/node_key".to_string()
}

fn default_mdns_enabled() -> bool {
    true
}

fn default_sync_batch_size() -> u64 {
    500
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_addr: "/ip4/0.0.0.0/tcp/30303".to_string(),
            bootstrap_nodes: Vec::new(),
            max_peers: 50,
            // 🚨 `is_proposer` varsayılanı `false`: `enable_p2p: true` ile birlikte
            // olsaydı `Default` kullanan her yeni node sessizce hiç blok üretmezdi.
            // Güvenli varsayılan: P2P kapalı, tek node modu.
            enable_p2p: false,
            network_id: crate::CHAIN_ID,
            is_proposer: false,
            consensus_key_path: None,
            trusted_checkpoint: None,
            node_key_path: default_node_key_path(),
            evidence_log_path: default_evidence_log_path(),
            mdns_enabled: default_mdns_enabled(),
            sync_batch_size: default_sync_batch_size(),
            sentry_mode: false,
            private_peers: Vec::new(),
            external_addr: None,
            sentry_addrs: Vec::new(),
            max_peers_per_ip: default_max_peers_per_ip(),
            reserved_validator_slots: default_reserved_validator_slots(),
        }
    }
}

impl NetworkConfig {
    /// 🛡️ Aranacak adresler = `bootstrap_nodes` ∪ `private_peers` (sıra korunur).
    /// Yalnız bootstrap aransaydı iki validatör birbirini hiç aramaz, oylar bir
    /// hop uzun giderdi; `private_peers` zaten konuşulması gereken eşlerdir.
    pub fn dial_targets(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for a in self.bootstrap_nodes.iter().chain(self.private_peers.iter()) {
            if !out.iter().any(|x| x == a) {
                out.push(a.clone());
            }
        }
        out
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.max_peers == 0 {
            return Err(ConfigError::ValidationError(
                "max_peers must be > 0".to_string(),
            ));
        }
        if self.max_peers_per_ip == 0 {
            return Err(ConfigError::ValidationError(
                "max_peers_per_ip must be > 0".to_string(),
            ));
        }
        // private_peers / sentry_addrs: her giriş `/p2p/<PeerId>` taşımalı,
        // yoksa allow-list kurulamaz ve duyuru işe yaramaz. Basit sözdizimi
        // kontrolü (tam multiaddr ayrıştırması zagros-network'te yapılır).
        for (name, list) in [
            ("private_peers", &self.private_peers),
            ("sentry_addrs", &self.sentry_addrs),
        ] {
            for a in list {
                if !a.starts_with('/') || !a.contains("/p2p/") {
                    return Err(ConfigError::ValidationError(format!(
                        "{name}: '{a}' gecersiz - '/ip4/.../tcp/PORT/p2p/<PeerId>' bicimi bekleniyor"
                    )));
                }
            }
        }
        if let Some(ext) = &self.external_addr {
            if !ext.starts_with('/') || ext.contains("/p2p/") {
                return Err(ConfigError::ValidationError(
                    "external_addr: '/ip4/.../tcp/PORT' bicimi bekleniyor (/p2p/ OLMADAN)"
                        .to_string(),
                ));
            }
        }
        if self.sentry_mode && !self.private_peers.is_empty() {
            return Err(ConfigError::ValidationError(
                "sentry_mode=true ile private_peers birlikte kullanilamaz (sentry herkese aciktir)"
                    .to_string(),
            ));
        }
        if self.sentry_mode && self.consensus_key_path.is_some() {
            return Err(ConfigError::ValidationError(
                "sentry_mode=true bir dugum konsensus anahtari TASIMAMALI (validator ayri dugumde calisir)".to_string(),
            ));
        }
        Ok(())
    }
}

/// Konsensüs yapılandırması. Alanların çoğu ETKİSİZ (blok üretimi talep
/// üzerine, epoch/min-stake kapısı zincir üstü ChainParams'ta); sahte wiring
/// yazmamak için rezerve. 🚨 Çoklu validator parçaları (rotation, proposer
/// election, liveness, fork choice, equivocation çapraz doğrulama, komisyon)
/// BİRLİKTE açılmalı; yarım geçiş hiç açmamaktan tehlikelidir.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConsensusConfig {
    // Node yerel konsensüs parametresi YOK: tek kaynak zincir üstü ChainParams;
    // eski config anahtarlarını serde yok sayar.
    /// 🏛️ %20 validator ödül payının adresi (`Executor::block_producer_address`).
    /// Boş = pay devre dışı, tüm ödül stakerlara. BFT'de gerçek üretici konsensüs
    /// kaydından çözülür (RPC `real_block_producer`); bu alan yapılandırılmış varsayılan.
    #[serde(default)]
    pub block_producer_address: String,
}

impl ConsensusConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        Ok(())
    }
}

/// Storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Database path
    pub db_path: String,

    /// Cache size in MB
    pub cache_size_mb: usize,

    /// Arşiv (`block_<N>`, `Receipt_`, `tx_body_`) budamasını açar. `false` =
    /// arşiv sonsuza dek saklanır (tam node); `true` = `max_retained_blocks`'tan
    /// eski geçmiş sorgulanamaz. Chain state (0x hesaplar) hiçbir zaman etkilenmez.
    pub enable_pruning: bool,

    /// Pruning interval in blocks (kaç blokta bir budama tetiklenir)
    pub pruning_interval: u64,

    /// `enable_pruning=true` iken bu derinlikten eski arşiv kayıtları budanır;
    /// chain state etkilenmez. serde default: eski config.toml bozulmaz.
    #[serde(default = "default_max_retained_blocks")]
    pub max_retained_blocks: u64,

    /// K2: Tek bir budama çağrısında silinecek maksimum dekont sayısı,
    /// RocksDB'yi uzun süre meşgul etmemek için batch limiti.
    #[serde(default = "default_prune_batch_limit")]
    pub prune_batch_limit: usize,

    /// Budama backpressure: ayarlıysa düğüm ZagrosRadar arşiv yüksekliğinin
    /// üstünü budamaz. None = kapalı. Yalnız arşiv kaynak düğümde, konsensüs dışı.
    #[serde(default)]
    pub archive_height_file: Option<String>,

    /// zagros_reportArchiveHeight icin paylasilan sir. Yanlis token'li raporlar
    /// reddedilir (yetkisiz budama-manipulasyonu engellenir). None VEYA
    /// archive_height_file None ise metod tamamen kapalidir.
    #[serde(default)]
    pub archive_report_token: Option<String>,

    /// 🛡️ FAIL-CLOSED: `enable_pruning = true` ama `archive_height_file` yoksa
    /// node başlamaz; bu bayrak reddi kaldırır. Dosya yokken budama backpressure'ı
    /// atlanır ve arşivci (ZagrosRadar) almadan geçmiş silinir, kayıp geri gelmez.
    /// Arşivcisiz düğüm için budama meşru bir seçimdir; bayrak o bilinçli seçimi
    /// kaydeder. Boolean yeterli: risk dağıtımın statik özelliğidir, sürüm başına yenilenmez.
    #[serde(default)]
    pub acknowledged_pruning_without_archive: bool,

    // RocksDB üretim ayarları: operatör kontrolünde, otomatik donanım algılama
    // YOK; hepsi `#[serde(default)]`, eski config.toml bozulmaz.
    /// MemTable (yazma tamponu) boyutu (MB). Varsayılan 64.
    #[serde(default = "default_write_buffer_size_mb")]
    pub write_buffer_size_mb: usize,

    /// Bellekte tutulan maksimum memtable sayısı. Varsayılan 3.
    #[serde(default = "default_max_write_buffer_number")]
    pub max_write_buffer_number: i32,

    /// Level-0 hedef SST dosya boyutu (MB), üst seviyeler bunun katları
    /// olacak şekilde ölçeklenir. Varsayılan 64.
    #[serde(default = "default_target_file_size_base_mb")]
    pub target_file_size_base_mb: u64,

    /// Aynı anda açık tutulacak maksimum dosya tanıtıcısı. `-1` = RocksDB'nin
    /// kendi varsayılanı (fiilen sınırsız, OS limitine tabi).
    #[serde(default = "default_max_open_files")]
    pub max_open_files: i32,

    /// Bloom filtresi anahtar başına bit sayısı, nokta okumalarını (`get`)
    /// hızlandırır. Varsayılan 10.0 (RocksDB'nin kendi önerdiği tipik değer).
    #[serde(default = "default_bloom_filter_bits_per_key")]
    pub bloom_filter_bits_per_key: f64,

    /// RocksDB dahili istatistiklerini topla (`rocksdb.stats`). Varsayılan
    /// `false`, toplamanın kendi (küçük) CPU maliyeti var, operatör açıkça
    /// isterse (ör. gözlemlenebilirlik için) açar.
    #[serde(default = "default_enable_statistics")]
    pub enable_statistics: bool,

    /// Arka-plan flush/compaction iş parçacığı sayısı. Varsayılan 4.
    #[serde(default = "default_max_background_jobs")]
    pub max_background_jobs: i32,

    /// item 8: snapshot'ların (RocksDB checkpoint + metadata.json) yazılacağı
    /// kök dizin.
    #[serde(default = "default_snapshots_root")]
    pub snapshots_root: String,

    /// Otomatik snapshot aralığı (blok). `0` = kapalı (yalnız elle
    /// `zagros-cli snapshot create`). Aşan her yükseklikte snapshot alınır,
    /// `max_snapshots_to_retain`'i aşan en eskiler silinir.
    #[serde(default = "default_snapshot_interval_blocks")]
    pub snapshot_interval_blocks: u64,

    /// Saklanacak azami snapshot sayısı; fazlası en eskiden silinir. `0` = sınırsız (önerilmez).
    #[serde(default = "default_max_snapshots_to_retain")]
    pub max_snapshots_to_retain: usize,

    /// 🚨 Bellek içi hesap `cache`'inin üst sınırı (dokunulan HER anahtar,
    /// tarihsel kayıtlar dahil); aşılınca dirty olmayan girdiler tahliye edilir.
    /// `cache_size_mb` (RocksDB blok cache'i) ile karıştırılmamalı.
    #[serde(default = "default_max_account_cache_entries")]
    pub max_account_cache_entries: usize,
}

fn default_max_retained_blocks() -> u64 {
    100_000
}

/// 🚨 Ölçüme dayalı: işlem başına ~10,4 µs, blok başına 1.000 işlem ~10 ms.
/// Silme hızı yaratma hızını (en dolu blok 602) aşmalı; sık ve küçük partiler.
fn default_prune_batch_limit() -> usize {
    1_000
}

fn default_write_buffer_size_mb() -> usize {
    64
}

fn default_max_write_buffer_number() -> i32 {
    3
}

fn default_target_file_size_base_mb() -> u64 {
    64
}

fn default_max_open_files() -> i32 {
    -1
}

fn default_bloom_filter_bits_per_key() -> f64 {
    10.0
}

fn default_enable_statistics() -> bool {
    false
}

fn default_max_background_jobs() -> i32 {
    4
}

fn default_snapshots_root() -> String {
    "./zagros-data/snapshots".to_string()
}

/// Varsayılan olarak KAPALI (`0`), eski `config.toml` dosyaları bu alanı
/// içermeden parse edilmeye devam eder ve davranış DEĞİŞMEZ (operatör açıkça
/// pozitif bir değer yazmadan otomatik snapshot başlamaz).
fn default_snapshot_interval_blocks() -> u64 {
    0
}

fn default_max_snapshots_to_retain() -> usize {
    3
}

/// `zagros-types` `zagros-state`'ten önce derlendiğinden `DEFAULT_MAX_CACHE_ENTRIES`
/// import edilemez; aynı değer (2_000_000) bağımsız tutulur. Çalışma zamanı
/// her zaman bu config değerini okur, sürüklenme yalnız varsayılan senaryoyu etkiler.
fn default_max_account_cache_entries() -> usize {
    2_000_000
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            // Önceden CLI'da hardcoded olan yol, wiring'in davranışı DEĞİŞTİRMEMESİ
            // için varsayılan bununla eşleşir (./zagros-data/state).
            db_path: "./zagros-data/state".to_string(),
            cache_size_mb: 1024, // 1GB
            enable_pruning: false,
            // Ölçüme dayalı (bkz. `default_prune_batch_limit` doc yorumu):
            // her blok küçük bir ısırık. Seyrek+büyük partiler hem kuyruğa
            // yetişemiyor hem bloğu tökezletiyordu.
            pruning_interval: 1,
            max_retained_blocks: 100_000,
            prune_batch_limit: default_prune_batch_limit(),
            archive_height_file: None,
            archive_report_token: None,
            acknowledged_pruning_without_archive: false,
            write_buffer_size_mb: default_write_buffer_size_mb(),
            max_write_buffer_number: default_max_write_buffer_number(),
            target_file_size_base_mb: default_target_file_size_base_mb(),
            max_open_files: default_max_open_files(),
            bloom_filter_bits_per_key: default_bloom_filter_bits_per_key(),
            enable_statistics: default_enable_statistics(),
            max_background_jobs: default_max_background_jobs(),
            snapshots_root: default_snapshots_root(),
            snapshot_interval_blocks: default_snapshot_interval_blocks(),
            max_snapshots_to_retain: default_max_snapshots_to_retain(),
            max_account_cache_entries: default_max_account_cache_entries(),
        }
    }
}

impl StorageConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.cache_size_mb == 0 {
            return Err(ConfigError::ValidationError(
                "cache_size_mb must be > 0".to_string(),
            ));
        }
        if self.max_account_cache_entries == 0 {
            return Err(ConfigError::ValidationError(
                "max_account_cache_entries must be > 0".to_string(),
            ));
        }

        // 🛡️ Budama açıkken sessizce çalışmayan yapılandırmalar fail-closed
        // reddedilir: operatör budamayı çalışıyor sanır, `pruning_total_deleted: 0`
        // "budanacak bir şey yok" gibi okunur, disk sınırsız büyür.
        if self.enable_pruning {
            if self.pruning_interval == 0 {
                return Err(ConfigError::ValidationError(
                    "enable_pruning = true iken pruning_interval 0 OLAMAZ: \
                     `Runtime::maybe_prune` 0'da hemen döner, yani budama \
                     sessizce hiç çalışmaz. Pozitif bir değer yazın (öneri: 1)."
                        .to_string(),
                ));
            }
            if self.prune_batch_limit == 0 {
                return Err(ConfigError::ValidationError(
                    "enable_pruning = true iken prune_batch_limit 0 OLAMAZ: \
                     `prune_historical_data` 0'da hemen döner, yani budama \
                     sessizce hiç çalışmaz. Pozitif bir değer yazın (öneri: 1000)."
                        .to_string(),
                ));
            }
            if self.archive_height_file.is_none() && !self.acknowledged_pruning_without_archive {
                return Err(ConfigError::ValidationError(
                    "enable_pruning = true ama archive_height_file AYARLANMAMIŞ. \
                     Bu durumda budama backpressure'ı tamamen atlanır ve düğüm, \
                     harici arşivcinin (ZagrosRadar) veriyi alıp almadığına \
                     BAKMADAN geçmişi siler - silinen dekontlar GERİ GELMEZ.\n\
                     \n\
                     Ya arşiv kilidini bağlayın:\n\
                     \tarchive_height_file = \"./zagros-data/archive_height\"\n\
                     ya da arşivcisiz budamayı BİLEREK kabul ettiğinizi yazın:\n\
                     \tacknowledged_pruning_without_archive = true"
                        .to_string(),
                ));
            }
        }

        Ok(())
    }
}

/// RPC configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcConfig {
    /// HTTP RPC address
    pub http_addr: String,

    /// WebSocket RPC address
    pub ws_addr: String,

    /// Maximum overall API connections allowed.
    pub max_connections: usize,

    /// RPC Ratelimit (burst limit limit per IP per second)
    pub ip_rate_limit: usize,

    /// Flood limitinden muaf IP-ler (ic servisler: indexer/takipci).
    #[serde(default)]
    pub rate_limit_whitelist: Vec<String>,

    /// Enable HTTP RPC
    pub enable_http: bool,

    /// Enable WebSocket RPC
    pub enable_ws: bool,

    /// CORS allowed origins
    pub cors_origins: Vec<String>,

    // RPC zaman aşımı + WS boşta koruması (TCP Slowloris ters proxy'ye bırakıldı).
    /// Salt okunur/statik RPC metodları için üst zaman sınırı.
    #[serde(default = "default_light_method_timeout_secs")]
    pub light_method_timeout_secs: u64,

    /// State/RocksDB okuyan ama EVM çalıştırmayan RPC metodları (ör.
    /// `eth_getBalance`, `eth_getBlockByNumber`, `eth_sendRawTransaction`,
    /// `zagros_get*`) için üst zaman sınırı.
    #[serde(default = "default_default_method_timeout_secs")]
    pub default_method_timeout_secs: u64,

    /// `eth_call`/`eth_estimateGas`, gerçek EVM yürütmesi çalıştıran, bu
    /// yüzden ayrı ve daha cömert bir üst sınıra ihtiyaç duyan tek iki metod.
    #[serde(default = "default_evm_execution_timeout_secs")]
    pub evm_execution_timeout_secs: u64,

    /// Toplu (JSON-RPC batch) isteklerde, tek tek metod zaman sınırlarının
    /// TOPLAMI bu tavanı aşamaz.
    #[serde(default = "default_max_batch_timeout_secs")]
    pub max_batch_timeout_secs: u64,

    /// 🛡️ Batch'teki azami alt istek: 2 MiB'a ~35.000 çağrı sığar ve `timeout`
    /// bloklayan işi durduramaz (amplifikasyon). Varsayılan 100.
    #[serde(default = "default_max_batch_requests")]
    pub max_batch_requests: usize,

    /// Sunucunun her açık WS bağlantısına PING gönderme aralığı (saniye).
    #[serde(default = "default_ws_ping_interval_secs")]
    pub ws_ping_interval_secs: u64,

    /// Bu süre hiç mesaj gelmezse WS bağlantısı boşta sayılıp kapatılır;
    /// `ws_ping_interval_secs`in birkaç katı olmalı.
    #[serde(default = "default_ws_pong_timeout_secs")]
    pub ws_pong_timeout_secs: u64,

    // `eth_call`/`eth_estimateGas` sınırsız EVM hesaplaması sunmasın: tavanlar
    // `Transaction::validate()`'in gerçek işlemlere uyguladığı 10_000_000 ile
    // AYNI, hiçbir meşru simülasyon gönderilemeyecek işlemi simüle etmez.
    /// `eth_call` üst gas sınırı; beyan edilen `gas` bu tavana kadar saygı görür,
    /// üstü sessizce kırpılır (geth davranışı).
    #[serde(default = "default_eth_call_max_gas")]
    pub eth_call_max_gas: u64,

    /// `eth_estimateGas` için üst gas sınırı, aynı gerekçe.
    #[serde(default = "default_eth_estimate_gas_max_gas")]
    pub eth_estimate_gas_max_gas: u64,

    /// `eth_call`/`eth_estimateGas` için ortak eş zamanlı simülasyon bütçesi
    /// (aynı `run_isolated_eth_call` maliyeti). `IN_FLIGHT_HTTP_REQUESTS`'ten
    /// (2048) ayrı ve sıkı; yalnız CPU ağır EVM simülasyonlarını sınırlar.
    #[serde(default = "default_max_parallel_evm_simulations")]
    pub max_parallel_evm_simulations: usize,
}

fn default_eth_call_max_gas() -> u64 {
    10_000_000
}

fn default_eth_estimate_gas_max_gas() -> u64 {
    10_000_000
}

fn default_max_parallel_evm_simulations() -> usize {
    32
}

fn default_light_method_timeout_secs() -> u64 {
    3
}

fn default_default_method_timeout_secs() -> u64 {
    6
}

fn default_evm_execution_timeout_secs() -> u64 {
    10
}

fn default_max_batch_timeout_secs() -> u64 {
    30
}

fn default_max_batch_requests() -> usize {
    100
}

fn default_ws_ping_interval_secs() -> u64 {
    30
}

fn default_ws_pong_timeout_secs() -> u64 {
    90
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            http_addr: "0.0.0.0:8545".to_string(),
            ws_addr: "0.0.0.0:8546".to_string(),
            max_connections: 50_000, // 🔥 High-performance global WS/HTTP connection limit
            ip_rate_limit: 100,      // 🛡️ 100 requests per IP per second
            rate_limit_whitelist: Vec::new(),
            enable_http: true,
            enable_ws: true,
            cors_origins: vec!["*".to_string()],
            light_method_timeout_secs: default_light_method_timeout_secs(),
            default_method_timeout_secs: default_default_method_timeout_secs(),
            evm_execution_timeout_secs: default_evm_execution_timeout_secs(),
            max_batch_timeout_secs: default_max_batch_timeout_secs(),
            max_batch_requests: default_max_batch_requests(),
            ws_ping_interval_secs: default_ws_ping_interval_secs(),
            ws_pong_timeout_secs: default_ws_pong_timeout_secs(),
            eth_call_max_gas: default_eth_call_max_gas(),
            eth_estimate_gas_max_gas: default_eth_estimate_gas_max_gas(),
            max_parallel_evm_simulations: default_max_parallel_evm_simulations(),
        }
    }
}

impl RpcConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.max_connections == 0 {
            return Err(ConfigError::ValidationError(
                "max_connections must be > 0".to_string(),
            ));
        }
        // 🛡️ 0 = her toplu istek reddedilir; cüzdanlar batch kullandığı için bu
        // sessiz bir kırılma olurdu (bkz. `max_batch_requests` doc yorumu).
        if self.max_batch_requests == 0 {
            return Err(ConfigError::ValidationError(
                "max_batch_requests 0 OLAMAZ: her toplu istek reddedilirdi. \
                 Pozitif bir deger yazin (oneri: 100)."
                    .to_string(),
            ));
        }
        if self.light_method_timeout_secs == 0
            || self.default_method_timeout_secs == 0
            || self.evm_execution_timeout_secs == 0
            || self.max_batch_timeout_secs == 0
        {
            return Err(ConfigError::ValidationError(
                "rpc timeout fields (light/default/evm_execution/max_batch) must be > 0"
                    .to_string(),
            ));
        }
        if self.ws_ping_interval_secs == 0 {
            return Err(ConfigError::ValidationError(
                "ws_ping_interval_secs must be > 0".to_string(),
            ));
        }
        if self.ws_pong_timeout_secs <= self.ws_ping_interval_secs {
            return Err(ConfigError::ValidationError(
                "ws_pong_timeout_secs must be greater than ws_ping_interval_secs (needs room for at least one missed ping before closing)"
                    .to_string(),
            ));
        }
        if self.eth_call_max_gas == 0 || self.eth_estimate_gas_max_gas == 0 {
            return Err(ConfigError::ValidationError(
                "eth_call_max_gas/eth_estimate_gas_max_gas must be > 0".to_string(),
            ));
        }
        if self.max_parallel_evm_simulations == 0 {
            return Err(ConfigError::ValidationError(
                "max_parallel_evm_simulations must be > 0".to_string(),
            ));
        }

        Ok(())
    }
}

/// Gas configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasConfig {
    /// Target gas fee in ZERENYA (18-decimal ham birim), stored as u64 for TOML compatibility
    pub gas_fee_zerenya: u64,

    /// Maximum gas per block
    pub max_gas_per_block: u64,

    /// Target gas per block
    pub target_gas_per_block: u64,

    /// `true` = taban ücret havuz oranına göre ölçeklenir; `false` = sabit
    /// `gas_fee_zerenya`. 🛡️ Anti-DDoS üstel stres kalkanını ETKİLEMEZ, o hep aktif.
    #[serde(default = "default_enable_dynamic_gas")]
    pub enable_dynamic_gas: bool,
}

fn default_enable_dynamic_gas() -> bool {
    true
}

impl Default for GasConfig {
    fn default() -> Self {
        Self {
            gas_fee_zerenya: crate::GAS_FEE_ZERENYA as u64,
            // `evm_load_test` benchmark'ıyla ölçüldü (bkz. config.example.toml'daki
            // [gas] açıklaması): 35M'de tamamen dolu bir EVM bloğu ~107ms'de kalır
            // (200ms hedefin ~%54'ü), 100M eski varsayımıyla bu %153'e (306ms) çıkardı.
            max_gas_per_block: 35_000_000,
            target_gas_per_block: 25_000_000,
            enable_dynamic_gas: default_enable_dynamic_gas(),
        }
    }
}

impl GasConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.max_gas_per_block == 0 {
            return Err(ConfigError::ValidationError(
                "max_gas_per_block must be > 0".to_string(),
            ));
        }

        if self.target_gas_per_block > self.max_gas_per_block {
            return Err(ConfigError::ValidationError(
                "target_gas_per_block must be <= max_gas_per_block".to_string(),
            ));
        }

        Ok(())
    }
}

/// Mempool configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolConfig {
    /// Maximum mempool capacity
    pub max_capacity: usize,

    /// DDoS threshold
    pub ddos_threshold: usize,

    /// Toplam mempool bellek bütçesi (bayt), adet sınırından bağımsız. serde default: eski config bozulmaz.
    #[serde(default = "default_max_total_bytes")]
    pub max_total_bytes: usize,

    /// Transaction expiry time in seconds
    pub tx_expiry_seconds: u64,
}

fn default_max_total_bytes() -> usize {
    crate::MAX_MEMPOOL_TOTAL_BYTES
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            max_capacity: crate::MAX_MEMPOOL_CAPACITY,
            ddos_threshold: crate::DDOS_THRESHOLD,
            max_total_bytes: crate::MAX_MEMPOOL_TOTAL_BYTES,
            tx_expiry_seconds: 3600, // 1 hour
        }
    }
}

impl MempoolConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.max_capacity == 0 {
            return Err(ConfigError::ValidationError(
                "max_capacity must be > 0".to_string(),
            ));
        }

        if self.ddos_threshold > self.max_capacity {
            return Err(ConfigError::ValidationError(
                "ddos_threshold must be <= max_capacity".to_string(),
            ));
        }

        Ok(())
    }
}

/// Tek bir köprü çoklu-imza yetkilisi (relayer/authority), Ed25519 açık
/// anahtarıyla tanımlanır.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeAuthorityConfig {
    /// Yetkilinin Zagros adresi (public_key_hex'ten türetilir, bilgi
    /// amaçlı burada da tutulur, doğrulama sırasında yeniden türetilip
    /// karşılaştırılır).
    pub address: String,

    /// 32 baytlık Ed25519 açık anahtarı, hex (0x önekli olabilir).
    pub public_key_hex: String,

    /// Devre dışı bırakılmış yetkililer imza veremez ama proposal geçmişinde
    /// görünür kalır.
    #[serde(default = "default_true")]
    pub is_active: bool,
}

fn default_true() -> bool {
    true
}

/// Köprü çoklu-imza (multi-sig) yapılandırması.
#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BridgeConfig {
    /// Çoklu imza yetkilileri. Boşsa ve `allow_insecure_default_authorities`
    /// açık değilse node başlamaz: kaynak koddaki bilinen test anahtarlarına
    /// düşmek köprünün sahte imzayla boşaltılması demektir.
    pub authorities: Vec<BridgeAuthorityConfig>,

    /// 🚨 YALNIZ YEREL GELİŞTİRME: `true` ve `authorities` boşsa node bilinen
    /// sabit test anahtarlarıyla açılır; gerçek parayla ASLA. Varsayılan `false`.
    #[serde(default)]
    pub allow_insecure_default_authorities: bool,

    /// Bir önerinin yürütülebilmesi için gereken imza sayısı (m-of-n eşiği).
    pub required_signatures: usize,

    /// Onaylı mint önerilerini imzalayıp gönderecek node içi anahtar (hex);
    /// boşsa otomatik yürütme kapalı (RPC'ler çalışır).
    pub signer_secret_key_hex: Option<String>,

    /// 🔐 TERCİH EDİLEN YOL: anahtar 0600 izinli ayrı dosyadan (tek satır hex),
    /// config yedeklenirken sızmasın. `signer_secret_key_hex` ile birlikte
    /// verilirse ya da izinler açıksa node durur. Çözümleme `main.rs`'te.
    #[serde(default)]
    pub signer_key_path: Option<String>,

    /// 🛡️ KONSENSÜS KRİTİK, gizli DEĞİL: imzacının AÇIK adresi. Mint ücret
    /// muafiyeti (`is_exempt_bridge_mint`) buna göre kontrol edilir. Gizli anahtar
    /// yalnız imzalayan node'da olur; bu adres HER node'da AYNI olmalı, yoksa
    /// follower muaf mint'i ücretli sanıp reddeder ve state_root'ta ayrışır.
    /// Boşsa `BRIDGE_AUTHORITY_ADDRESS` sabitine düşülür (`effective_bridge_authority`).
    #[serde(default)]
    pub authority_address: Option<String>,

    /// ⏳ Köprü önerilerinin zaman kilidi (saniye). 🚨 ÜRETİMDE 24 SAAT: sahte
    /// çekimin fark edilip `pause()` ile durdurulma penceresi. Relayer'larla aynı olmalı.
    #[serde(default = "default_bridge_timelock_secs")]
    pub timelock_secs: u64,

    /// 🛡️ Zincir seviyesi GLOBAL günlük mint tavanı (24 saat kayan pencere,
    /// tek sayaç); varsayılan 2.500 ZERENYA/gün, otomatik ölçeklenmez.
    #[serde(default = "default_bridge_daily_mint_limit")]
    pub daily_mint_limit: u128,

    /// 🎟️ Claim fişi doğrulaması için Ethereum tarafı bilgileri: fiş saklanmadan
    /// önce EIP-712 dijesti yeniden hesaplanır, imzalayan `relayer_eth_addresses`
    /// kümesinde mi bakılır. Boşsa fiş kabulü KAPALI (fail-closed).
    #[serde(default)]
    pub ethereum: BridgeEthereumConfig,
}

/// `Debug` elle yazılır: `{:?}` çağrısı `signer_secret_key_hex`'i düz metin
/// loglamasın. Diğer alanlar gizli değil, hata ayıklama için görünür.
impl fmt::Debug for BridgeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BridgeConfig")
            .field("authorities", &self.authorities)
            .field(
                "allow_insecure_default_authorities",
                &self.allow_insecure_default_authorities,
            )
            .field("required_signatures", &self.required_signatures)
            .field(
                "signer_secret_key_hex",
                &self.signer_secret_key_hex.as_ref().map(|_| "<redacted>"),
            )
            .field("signer_key_path", &self.signer_key_path)
            .field("authority_address", &self.authority_address)
            .field("timelock_secs", &self.timelock_secs)
            .field("daily_mint_limit", &self.daily_mint_limit)
            .field("ethereum", &self.ethereum)
            .finish()
    }
}

fn default_bridge_timelock_secs() -> u64 {
    24 * 60 * 60
}

fn default_bridge_daily_mint_limit() -> u128 {
    2_500 * crate::TOKEN_DECIMAL
}

fn default_unlock_token_decimals() -> u32 {
    18 // PAXG
}

/// Claim fişlerinin doğrulanabilmesi için gereken Ethereum tarafı yapılandırması.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BridgeEthereumConfig {
    /// Ethereum zincir kimliği (mainnet = 1). EIP-712 domain'ine girer.
    #[serde(default)]
    pub chain_id: u64,

    /// Deploy edilmiş `ZagrosBridgeGateway` adresi. EIP-712 domain'ine girer,
    /// bu yüzden yanlışsa üretilen/doğrulanan tüm fişler zincirde reddedilir.
    #[serde(default)]
    pub gateway_contract_address: String,

    /// Kasadan çekilecek ERC20'nin adresi (PAXG, Pax Gold). Dijeste girer.
    #[serde(default)]
    pub unlock_token_address: String,

    /// Hedef ERC20 ondalığı (PAXG = 18); dijeste ölçeklenmiş tutar girer.
    /// Relayer'la aynı olmalı, yoksa hiçbir fiş doğrulanmaz.
    #[serde(default = "default_unlock_token_decimals")]
    pub unlock_token_decimals: u32,

    /// Habercilerin Ethereum adresleri, kontrattaki `isRelayer` kümesiyle aynı
    /// olmalı. Fişin imzalayanı bu kümede değilse fiş reddedilir.
    #[serde(default)]
    pub relayer_eth_addresses: Vec<String>,
}

impl BridgeEthereumConfig {
    /// Fiş kabulü açık mı (tüm alanlar anlamlı dolu). 🚨 SIFIR ADRES REDDEDİLİR:
    /// gateway deploy edilmeden kanal "açık" görünür, haberciler yanlış domain'e
    /// imza üretir, kullanıcı `claimTokens`ta gas yakardı.
    pub fn is_claim_voucher_enabled(&self) -> bool {
        const ZERO: [u8; 20] = [0u8; 20];
        let gateway = crate::eip712::parse_eth_address(&self.gateway_contract_address);
        let token = crate::eip712::parse_eth_address(&self.unlock_token_address);

        self.chain_id != 0
            && matches!(gateway, Some(address) if address != ZERO)
            && matches!(token, Some(address) if address != ZERO)
            && !self.relayer_eth_addresses.is_empty()
    }
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            authorities: Vec::new(),
            allow_insecure_default_authorities: false,
            required_signatures: 2,
            signer_secret_key_hex: None,
            signer_key_path: None,
            authority_address: None,
            timelock_secs: default_bridge_timelock_secs(),
            daily_mint_limit: default_bridge_daily_mint_limit(),
            ethereum: BridgeEthereumConfig::default(),
        }
    }
}

impl BridgeConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.authorities.is_empty() {
            if self.allow_insecure_default_authorities {
                // Açıkça (ve bilerek) yerel geliştirme için opt-in yapıldı,
                // dev-default (BridgeManager::default_bridge_manager) kullanılacak.
                return Ok(());
            }
            return Err(ConfigError::ValidationError(
                "bridge.authorities boş - node güvenlik nedeniyle BAŞLAMIYOR. Ya \
                 [[bridge.authorities]] listesini gerçek haberci anahtarlarıyla doldurun, \
                 ya da SADECE yerel geliştirme için bridge.allow_insecure_default_authorities \
                 = true yapıp kaynak kodda duran, herkesçe bilinen sabit test anahtarlarını \
                 KABUL ettiğinizi açıkça belirtin (gerçek parayla ASLA kullanmayın)."
                    .to_string(),
            ));
        }

        if self.required_signatures < 2 {
            return Err(ConfigError::ValidationError(
                "bridge.required_signatures must be at least 2 when authorities are configured"
                    .to_string(),
            ));
        }

        if self.required_signatures > self.authorities.len() {
            return Err(ConfigError::ValidationError(
                "bridge.required_signatures cannot exceed the number of configured authorities"
                    .to_string(),
            ));
        }

        for authority in &self.authorities {
            let hex_str = authority
                .public_key_hex
                .strip_prefix("0x")
                .unwrap_or(&authority.public_key_hex);
            let decoded = hex::decode(hex_str).map_err(|_| {
                ConfigError::ValidationError(format!(
                    "bridge authority {} has a non-hex public_key_hex",
                    authority.address
                ))
            })?;
            if decoded.len() != 32 {
                return Err(ConfigError::ValidationError(format!(
                    "bridge authority {} has an invalid public_key_hex (must be 32 bytes, got {})",
                    authority.address,
                    decoded.len()
                )));
            }
        }

        Ok(())
    }
}

/// Governance yapılandırması; spam koruması dörtlüsü (ücret, kilit, aktif tavan,
/// süre pencereleri) birlikte kullanılmalı.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GovernanceConfig {
    /// `SubmitProposal` ile yakılan (kimseye kredilenmeyen) düz ücret (ZAGROS,
    /// 18 ondalık). Varsayılan 1000 ZAGROS.
    pub proposal_fee: u128,

    /// Öneri sunabilmek için gereken minimum `staked_balance` (ZAGROS, 18
    /// ondalık), asıl spam filtresi bu. Varsayılan 10.000 ZAGROS.
    pub min_stake_to_submit: u128,

    /// Aynı anda "aktif" (arşivlenmemiş) sayılan öneri sayısının global tavanı.
    /// Varsayılan 50.
    pub max_active_proposals: usize,

    /// Bir önerinin oylamaya açık kaldığı süre (saniye). Bu pencere kapandığında
    /// oy dağılımına göre Succeeded/Rejected/Expired'a geçer. Varsayılan 7 gün.
    pub voting_period_secs: u64,

    /// Önerinin Archived'e geçip aktif sayaçtan düştüğü süre; `voting_period_secs`ten
    /// büyük olmalı. Varsayılan 30 gün.
    pub proposal_expiry_secs: u64,
}

fn default_proposal_fee() -> u128 {
    1000 * crate::TOKEN_DECIMAL
}

fn default_min_stake_to_submit() -> u128 {
    10_000 * crate::TOKEN_DECIMAL
}

fn default_max_active_proposals() -> usize {
    50
}

fn default_voting_period_secs() -> u64 {
    7 * 24 * 60 * 60
}

fn default_proposal_expiry_secs() -> u64 {
    30 * 24 * 60 * 60
}

impl Default for GovernanceConfig {
    fn default() -> Self {
        Self {
            proposal_fee: default_proposal_fee(),
            min_stake_to_submit: default_min_stake_to_submit(),
            max_active_proposals: default_max_active_proposals(),
            voting_period_secs: default_voting_period_secs(),
            proposal_expiry_secs: default_proposal_expiry_secs(),
        }
    }
}

impl GovernanceConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.voting_period_secs == 0 {
            return Err(ConfigError::ValidationError(
                "governance.voting_period_secs must be > 0".to_string(),
            ));
        }
        if self.max_active_proposals == 0 {
            return Err(ConfigError::ValidationError(
                "governance.max_active_proposals must be > 0".to_string(),
            ));
        }
        if self.proposal_expiry_secs <= self.voting_period_secs {
            return Err(ConfigError::ValidationError(
                "governance.proposal_expiry_secs must be greater than voting_period_secs \
                 (a proposal cannot expire/archive before its own voting window closes)"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

/// Operatör uyarı webhook'u. `webhook_url` boşsa hiçbir istek atılmaz. Üç
/// olay TEK SEFERLİK (kenar geçişi) POST tetikler: genesis validator hapis,
/// mempool DDoS stres modu, bekleyen işlem varken `stall_threshold_secs`ten
/// uzun üretim durması (boş mempool alarm değildir). Gövde Discord + Slack
/// uyumlu; Telegram için aracı proxy gerekir.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AlertsConfig {
    /// `None`/boş (varsayılan) = uyarı sistemi tamamen kapalı, hiçbir ağ
    /// isteği atılmaz.
    pub webhook_url: Option<String>,

    /// Mempool'da bekleyen işlem varken blok üretiminin bu kadar saniye
    /// durması "muhtemelen bozuk" sayılır. Varsayılan 300 (5 dakika).
    pub stall_threshold_secs: u64,
}

fn default_alert_stall_threshold_secs() -> u64 {
    300
}

impl Default for AlertsConfig {
    fn default() -> Self {
        Self {
            webhook_url: None,
            stall_threshold_secs: default_alert_stall_threshold_secs(),
        }
    }
}

impl AlertsConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if let Some(url) = &self.webhook_url {
            if !url.starts_with("http://") && !url.starts_with("https://") {
                return Err(ConfigError::ValidationError(
                    "alerts.webhook_url must start with http:// or https://".to_string(),
                ));
            }
        }
        if self.stall_threshold_secs == 0 {
            return Err(ConfigError::ValidationError(
                "alerts.stall_threshold_secs must be > 0".to_string(),
            ));
        }
        Ok(())
    }
}

/// Configuration errors
#[derive(Debug, Clone)]
pub enum ConfigError {
    IoError(String),
    ParseError(String),
    SerializeError(String),
    ValidationError(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::IoError(msg) => write!(f, "IO error: {}", msg),
            ConfigError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            ConfigError::SerializeError(msg) => write!(f, "Serialize error: {}", msg),
            ConfigError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// 🛡️ `[bridge]` bölümü olmayan config GEÇERLİ SAYILMAMALI: `authorities`
    /// boş ve `allow_insecure_default_authorities` varsayılan `false`.
    #[test]
    fn test_default_config_is_rejected_because_bridge_authorities_are_empty() {
        let config = ZagrosConfig::default();
        assert!(config.validate().is_err());
    }

    /// Opt-in dev config'in geri kalanı geçerli sayılmalı.
    #[test]
    fn default_config_validates_once_dev_bridge_fallback_is_explicitly_opted_into() {
        let mut config = ZagrosConfig::default();
        config.bridge.allow_insecure_default_authorities = true;
        assert!(config.validate().is_ok());
    }

    /// `Debug` `signer_secret_key_hex`i redakte etmeli, diğer alanlar görünür kalmalı.
    #[test]
    fn bridge_config_debug_output_redacts_signer_secret_key_but_shows_other_fields() {
        let config = BridgeConfig {
            signer_secret_key_hex: Some("deadbeef".repeat(8)),
            signer_key_path: None,
            required_signatures: 2,
            ..Default::default()
        };

        let debug_output = format!("{:?}", config);

        assert!(
            !debug_output.contains("deadbeef"),
            "Debug çıktısı özel anahtarı SIZDIRMAMALI: {}",
            debug_output
        );
        assert!(debug_output.contains("<redacted>"));
        assert!(
            debug_output.contains("required_signatures"),
            "gizli OLMAYAN alanlar Debug çıktısında görünür kalmalı: {}",
            debug_output
        );
    }

    /// Anahtar hiç ayarlanmamışsa (`None`) redaksiyon `None` olarak
    /// görünmeli, `<redacted>` metniyle yanıltıcı biçimde karıştırılmamalı.
    #[test]
    fn bridge_config_debug_output_shows_none_when_signer_key_is_unset() {
        let config = BridgeConfig {
            signer_secret_key_hex: None,
            signer_key_path: None,
            authority_address: None,
            ..Default::default()
        };
        let debug_output = format!("{:?}", config);
        assert!(debug_output.contains("None"));
        assert!(!debug_output.contains("<redacted>"));
    }

    /// Regresyon: `config.example.toml` geçerli TOML olmalı ve `[governance]`
    /// belgelenen varsayılanları üretmeli. `validate()` çağrılmaz: dosya
    /// yetkilileri yorumda bırakılmış bir ŞABLONDUR.
    #[test]
    fn the_repo_example_config_file_governance_section_parses_to_documented_defaults() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../config.example.toml");
        let content = std::fs::read_to_string(path).expect("config.example.toml okunabilmeli");
        let config: ZagrosConfig =
            toml::from_str(&content).expect("config.example.toml gecerli TOML olmali");
        assert_eq!(config.governance.proposal_fee, 1000 * crate::TOKEN_DECIMAL);
        assert_eq!(
            config.governance.min_stake_to_submit,
            10_000 * crate::TOKEN_DECIMAL
        );
        assert_eq!(config.governance.max_active_proposals, 50);
        assert_eq!(config.governance.voting_period_secs, 604_800);
        assert_eq!(config.governance.proposal_expiry_secs, 2_592_000);
    }

    /// 🛡️ Şablonun `[storage]` bölümü budamayı sessizce çalışmaz bırakmamalı:
    /// (a) kendi `validate()`'inden geçer, (b) silme hızı en dolu bloğu (602)
    /// aşar, (c) mainnet için budama açık. Tam `validate()` çağrılmaz (şablon).
    #[test]
    fn the_repo_example_config_storage_section_is_a_working_pruning_setup() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../config.example.toml");
        let content = std::fs::read_to_string(path).expect("config.example.toml okunabilmeli");
        let config: ZagrosConfig =
            toml::from_str(&content).expect("config.example.toml gecerli TOML olmali");

        config
            .storage
            .validate()
            .expect("sablonun [storage] bolumu KENDI dogrulamasindan gecmeli");

        assert!(
            config.storage.enable_pruning,
            "mainnet sablonunda budama ACIK gelmeli (kapaliyken RocksDB sinirsiz buyur)"
        );
        assert!(
            config.storage.archive_height_file.is_some(),
            "sablon arsiv kilidini BAGLI vermeli - aksi halde arsivci coktugunde \
             silinen gecmis GERI GELMEZ"
        );

        let per_block =
            config.storage.prune_batch_limit as f64 / config.storage.pruning_interval as f64;
        assert!(
            per_block > 602.0,
            "sablonun silme hizi blok basina {per_block:.1} islem - olculen en dolu \
             blok 602 islem tasiyor, yani budama ASLA yetisemez ve disk sinirsiz buyur"
        );
    }

    #[test]
    fn test_config_serialization() {
        let config = ZagrosConfig::default();
        let toml_str = toml::to_string(&config).unwrap();
        let parsed: ZagrosConfig = toml::from_str(&toml_str).unwrap();

        assert_eq!(config.network.max_peers, parsed.network.max_peers);
    }

    /// `[governance]` bölümü hiç OLMAYAN eski bir config.toml (bu PR'dan önce
    /// yazılmış) hâlâ parse edilebilmeli, `GovernanceConfig::default()`'a
    /// sessizce düşmeli, hataya değil (geriye dönük uyumluluk).
    #[test]
    fn governance_config_defaults_preserve_existing_toml_files_without_governance_section() {
        let mut config = ZagrosConfig::default();
        config.bridge.allow_insecure_default_authorities = true;
        let full_toml = toml::to_string(&config).unwrap();

        // Eski config'i taklit için `[governance]` metinsel çıkarılır;
        // `Default`'ın TOML çıktısı bölümü zaten içerir.
        let mut toml_without_governance = String::new();
        let mut skipping = false;
        for line in full_toml.lines() {
            if line.trim_start().starts_with('[') {
                skipping = line.trim() == "[governance]";
            }
            if !skipping {
                toml_without_governance.push_str(line);
                toml_without_governance.push('\n');
            }
        }
        assert!(!toml_without_governance.contains("[governance]"));

        let parsed: ZagrosConfig = toml::from_str(&toml_without_governance)
            .expect("eski (governance bölümsüz) config.toml hâlâ parse edilebilmeli");
        assert_eq!(parsed.governance.proposal_fee, 1000 * crate::TOKEN_DECIMAL);
        assert_eq!(
            parsed.governance.min_stake_to_submit,
            10_000 * crate::TOKEN_DECIMAL
        );
        assert_eq!(parsed.governance.max_active_proposals, 50);
        assert_eq!(parsed.governance.voting_period_secs, 7 * 24 * 60 * 60);
        assert_eq!(parsed.governance.proposal_expiry_secs, 30 * 24 * 60 * 60);
        assert!(parsed.validate().is_ok());
    }

    #[test]
    fn governance_config_rejects_expiry_not_greater_than_voting_period() {
        let mut config = GovernanceConfig::default();
        config.proposal_expiry_secs = config.voting_period_secs;
        assert!(config.validate().is_err());
    }

    /// items 6+7: yeni RocksDB tuning alanlarını İÇERMEYEN eski bir `[storage]`
    /// bölümü hâlâ parse edilebilmeli, her yeni alan kendi varsayılanına düşer.
    #[test]
    fn storage_config_new_tuning_fields_have_sane_defaults_and_parse_from_partial_toml() {
        let partial_toml = r#"
            db_path = "./zagros-data/state"
            cache_size_mb = 1024
            enable_pruning = false
            pruning_interval = 10000
        "#;
        let parsed: StorageConfig = toml::from_str(partial_toml)
            .expect("eski (tuning alanları içermeyen) [storage] hâlâ parse edilebilmeli");
        assert_eq!(parsed.write_buffer_size_mb, 64);
        assert_eq!(parsed.max_write_buffer_number, 3);
        assert_eq!(parsed.target_file_size_base_mb, 64);
        assert_eq!(parsed.max_open_files, -1);
        assert_eq!(parsed.bloom_filter_bits_per_key, 10.0);
        assert!(!parsed.enable_statistics);
        assert_eq!(parsed.max_background_jobs, 4);
        assert_eq!(parsed.snapshots_root, "./zagros-data/snapshots");
        assert_eq!(parsed.max_account_cache_entries, 2_000_000);
    }

    /// Eski (timeout alanları olmayan) [rpc] bölümü bozulmadan parse edilmeli.
    #[test]
    fn rpc_config_new_timeout_fields_have_sane_defaults_and_parse_from_partial_toml() {
        let partial_toml = r#"
            http_addr = "0.0.0.0:8545"
            ws_addr = "0.0.0.0:8546"
            max_connections = 50000
            ip_rate_limit = 100
            enable_http = true
            enable_ws = true
            cors_origins = ["*"]
        "#;
        let parsed: RpcConfig = toml::from_str(partial_toml)
            .expect("eski (timeout alanları içermeyen) [rpc] hâlâ parse edilebilmeli");
        assert_eq!(parsed.light_method_timeout_secs, 3);
        assert_eq!(parsed.default_method_timeout_secs, 6);
        assert_eq!(parsed.evm_execution_timeout_secs, 10);
        assert_eq!(parsed.max_batch_timeout_secs, 30);
        assert_eq!(parsed.ws_ping_interval_secs, 30);
        assert_eq!(parsed.ws_pong_timeout_secs, 90);
    }

    #[test]
    fn rpc_config_rejects_zero_valued_timeout_fields() {
        let config = RpcConfig {
            evm_execution_timeout_secs: 0,
            ..RpcConfig::default()
        };
        assert!(config.validate().is_err());

        let config = RpcConfig {
            max_batch_timeout_secs: 0,
            ..RpcConfig::default()
        };
        assert!(config.validate().is_err());
    }

    /// `ws_pong_timeout_secs` > `ws_ping_interval_secs` olmalı (yanlış pozitif kapama olmasın).
    #[test]
    fn rpc_config_rejects_pong_timeout_not_greater_than_ping_interval() {
        let mut config = RpcConfig {
            ws_ping_interval_secs: 30,
            ws_pong_timeout_secs: 30,
            ..RpcConfig::default()
        };
        assert!(config.validate().is_err());

        config.ws_pong_timeout_secs = 29;
        assert!(config.validate().is_err());

        config.ws_pong_timeout_secs = 31;
        assert!(config.validate().is_ok());
    }

    /// YÜKSEK #7: eski (bu turdan önceki) bir [rpc] bölümü, yeni EVM
    /// simülasyon alanlarının `#[serde(default)]`'ları sayesinde bozulmadan
    /// parse edilmeye devam etmeli.
    #[test]
    fn rpc_config_new_evm_simulation_fields_have_sane_defaults_and_parse_from_partial_toml() {
        let partial_toml = r#"
            http_addr = "0.0.0.0:8545"
            ws_addr = "0.0.0.0:8546"
            max_connections = 50000
            ip_rate_limit = 100
            enable_http = true
            enable_ws = true
            cors_origins = ["*"]
        "#;
        let parsed: RpcConfig = toml::from_str(partial_toml)
            .expect("eski (EVM simülasyon alanları içermeyen) [rpc] hâlâ parse edilebilmeli");
        assert_eq!(parsed.eth_call_max_gas, 10_000_000);
        assert_eq!(parsed.eth_estimate_gas_max_gas, 10_000_000);
        assert_eq!(parsed.max_parallel_evm_simulations, 32);
    }

    /// Varsayılan (10M) `Transaction::validate()` tavanıyla aynı olmalı: hiçbir
    /// meşru simülasyon gönderilemeyecek işlemi simüle etmez (dApp uyumu bozulmaz).
    #[test]
    fn rpc_config_default_eth_call_and_estimate_gas_limits_match_the_real_transaction_gas_ceiling()
    {
        let config = RpcConfig::default();
        assert_eq!(config.eth_call_max_gas, 10_000_000);
        assert_eq!(config.eth_estimate_gas_max_gas, 10_000_000);
    }

    #[test]
    fn rpc_config_rejects_zero_valued_evm_simulation_fields() {
        let config = RpcConfig {
            eth_call_max_gas: 0,
            ..RpcConfig::default()
        };
        assert!(config.validate().is_err());

        let config = RpcConfig {
            eth_estimate_gas_max_gas: 0,
            ..RpcConfig::default()
        };
        assert!(config.validate().is_err());

        let config = RpcConfig {
            max_parallel_evm_simulations: 0,
            ..RpcConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validation() {
        let mut config = ZagrosConfig::default();
        config.network.max_peers = 0;

        assert!(config.validate().is_err());
    }

    /// Boş `authorities` + varsayılan (`false`) `allow_insecure_default_authorities`
    /// artık node'un başlamasını REDDETMELİ, bu, dev-key tuzağının kapatılmasının
    /// asıl kanıtı.
    #[test]
    fn empty_bridge_authorities_without_explicit_opt_in_is_rejected() {
        let config = ZagrosConfig::default();
        assert!(config.bridge.authorities.is_empty());
        assert!(!config.bridge.allow_insecure_default_authorities);
        assert!(config.bridge.validate().is_err());
    }

    /// Boş `authorities` + AÇIKÇA `allow_insecure_default_authorities = true`
    /// hâlâ geçerli sayılmalı, bilinçli, dokümante edilmiş bir dev-only opt-in.
    #[test]
    fn empty_bridge_authorities_with_explicit_opt_in_is_valid() {
        let config = BridgeConfig {
            allow_insecure_default_authorities: true,
            ..Default::default()
        };
        assert!(config.authorities.is_empty());
        assert!(config.validate().is_ok());
    }

    fn sample_authority(address: &str, public_key_hex: &str) -> BridgeAuthorityConfig {
        BridgeAuthorityConfig {
            address: address.to_string(),
            public_key_hex: public_key_hex.to_string(),
            is_active: true,
        }
    }

    #[test]
    fn rejects_required_signatures_below_two() {
        let config = BridgeConfig {
            authorities: vec![
                sample_authority("0xaaa", &"11".repeat(32)),
                sample_authority("0xbbb", &"22".repeat(32)),
            ],
            required_signatures: 1,
            signer_secret_key_hex: None,
            signer_key_path: None,
            authority_address: None,
            timelock_secs: default_bridge_timelock_secs(),
            daily_mint_limit: default_bridge_daily_mint_limit(),
            ethereum: BridgeEthereumConfig::default(),
            allow_insecure_default_authorities: false,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_required_signatures_above_authority_count() {
        let config = BridgeConfig {
            authorities: vec![sample_authority("0xaaa", &"11".repeat(32))],
            required_signatures: 2,
            signer_secret_key_hex: None,
            signer_key_path: None,
            authority_address: None,
            timelock_secs: default_bridge_timelock_secs(),
            daily_mint_limit: default_bridge_daily_mint_limit(),
            ethereum: BridgeEthereumConfig::default(),
            allow_insecure_default_authorities: false,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_malformed_public_key_hex() {
        let config = BridgeConfig {
            authorities: vec![
                sample_authority("0xaaa", "not-hex"),
                sample_authority("0xbbb", &"22".repeat(32)),
            ],
            required_signatures: 2,
            signer_secret_key_hex: None,
            signer_key_path: None,
            authority_address: None,
            timelock_secs: default_bridge_timelock_secs(),
            daily_mint_limit: default_bridge_daily_mint_limit(),
            ethereum: BridgeEthereumConfig::default(),
            allow_insecure_default_authorities: false,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn accepts_well_formed_authority_list() {
        let config = BridgeConfig {
            authorities: vec![
                sample_authority("0xaaa", &"11".repeat(32)),
                sample_authority("0xbbb", &format!("0x{}", "22".repeat(32))),
                sample_authority("0xccc", &"33".repeat(32)),
            ],
            required_signatures: 2,
            signer_secret_key_hex: None,
            signer_key_path: None,
            authority_address: None,
            timelock_secs: default_bridge_timelock_secs(),
            daily_mint_limit: default_bridge_daily_mint_limit(),
            ethereum: BridgeEthereumConfig::default(),
            allow_insecure_default_authorities: false,
        };
        assert!(config.validate().is_ok());
    }

    // BUDAMA YAPILANDIRMASI, "sessizce çalışmayan" tuzaklarına karşı fail-closed

    fn pruning_storage(enable: bool) -> StorageConfig {
        StorageConfig {
            enable_pruning: enable,
            ..StorageConfig::default()
        }
    }

    /// 🛡️ Budama açık ama arşiv kilidi yok: geçmiş arşivci almadan silinir, geri gelmez.
    #[test]
    fn pruning_without_an_archive_lock_is_refused_unless_explicitly_acknowledged() {
        let config = pruning_storage(true);
        assert!(config.archive_height_file.is_none(), "test ön koşulu");
        let err = config
            .validate()
            .expect_err("arşiv kilidi olmadan budama SESSİZCE kabul edilmemeli");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("archive_height_file"),
            "hata mesajı operatöre hangi alanı bağlayacağını söylemeli: {msg}"
        );

        // (a) Arşiv kilidini bağlamak reddi kaldırır.
        let mut with_lock = pruning_storage(true);
        with_lock.archive_height_file = Some("./zagros-data/archive_height".to_string());
        assert!(with_lock.validate().is_ok());

        // (b) Arşivcisiz budamayı BİLEREK kabul etmek de kaldırır.
        let mut acknowledged = pruning_storage(true);
        acknowledged.acknowledged_pruning_without_archive = true;
        assert!(acknowledged.validate().is_ok());
    }

    /// Budama KAPALIYKEN arşiv kilidi aranmaz, kilit yalnızca fiilen silme
    /// yapan düğümler için anlamlı.
    #[test]
    fn the_archive_lock_is_only_required_when_pruning_is_actually_enabled() {
        assert!(pruning_storage(false).validate().is_ok());
    }

    /// `pruning_interval = 0` ya da `prune_batch_limit = 0` budamayı sessizce kapatır.
    #[test]
    fn zero_valued_pruning_knobs_are_refused_instead_of_silently_disabling_pruning() {
        for (interval, batch, needle) in [
            (0u64, 1_000usize, "pruning_interval"),
            (1u64, 0usize, "prune_batch_limit"),
        ] {
            let mut config = pruning_storage(true);
            config.acknowledged_pruning_without_archive = true; // bu testin konusu değil
            config.pruning_interval = interval;
            config.prune_batch_limit = batch;
            let err = config.validate().expect_err(
                "0 değerli budama ayarı sessizce kabul edilmemeli (budama hiç çalışmaz)",
            );
            assert!(
                format!("{err:?}").contains(needle),
                "hata hangi alanın sıfır olduğunu söylemeli ({needle})"
            );
        }
    }

    /// 🚨 Silme hızı yaratma hızını aşmalı; varsayılanlar en dolu bloğu (602) rahatça aşmalı.
    #[test]
    fn default_pruning_throughput_outpaces_the_fullest_possible_block() {
        let config = StorageConfig::default();
        let per_block = config.prune_batch_limit as f64 / config.pruning_interval as f64;
        assert!(
            per_block > 602.0,
            "varsayılan silme hızı blok başına {per_block:.1} işlem - ölçülen en \
             dolu blok 602 işlem taşıyor, yani budama ASLA yetişemez"
        );
    }
}

#[cfg(test)]
mod sentry_config_tests {
    use super::*;

    fn base() -> NetworkConfig {
        NetworkConfig::default()
    }

    #[test]
    fn private_peers_and_sentry_addrs_require_p2p_component() {
        let mut n = base();
        n.private_peers = vec!["/ip4/1.2.3.4/tcp/30303".into()];
        assert!(n.validate().is_err());
        n.private_peers = vec![
            "/ip4/1.2.3.4/tcp/30303/p2p/12D3KooWQuPAZdnhENsAQ8GjRUAVR4hVmEpB8onx6GKiF2XYdCmY"
                .into(),
        ];
        assert!(n.validate().is_ok());
        n.sentry_addrs = vec!["bozuk".into()];
        assert!(n.validate().is_err());
    }

    #[test]
    fn sentry_mode_excludes_private_peers_and_consensus_key() {
        let mut n = base();
        n.sentry_mode = true;
        assert!(n.validate().is_ok());
        n.private_peers = vec![
            "/ip4/1.2.3.4/tcp/30303/p2p/12D3KooWQuPAZdnhENsAQ8GjRUAVR4hVmEpB8onx6GKiF2XYdCmY"
                .into(),
        ];
        assert!(n.validate().is_err());
        n.private_peers.clear();
        n.consensus_key_path = Some("k".into());
        assert!(n.validate().is_err());
    }

    #[test]
    fn external_addr_must_not_carry_p2p_and_ip_quota_must_be_positive() {
        let mut n = base();
        n.external_addr = Some(
            "/ip4/1.2.3.4/tcp/30303/p2p/12D3KooWQuPAZdnhENsAQ8GjRUAVR4hVmEpB8onx6GKiF2XYdCmY"
                .into(),
        );
        assert!(n.validate().is_err());
        n.external_addr = Some("/ip4/1.2.3.4/tcp/30303".into());
        assert!(n.validate().is_ok());
        n.max_peers_per_ip = 0;
        assert!(n.validate().is_err());
    }

    #[test]
    fn dial_targets_is_bootstrap_union_private_peers_without_duplicates() {
        let mut n = base();
        n.bootstrap_nodes = vec![
            "/ip4/1.1.1.1/tcp/30303/p2p/12D3KooWQuPAZdnhENsAQ8GjRUAVR4hVmEpB8onx6GKiF2XYdCmY"
                .into(),
        ];
        n.private_peers = vec![
            "/ip4/1.1.1.1/tcp/30303/p2p/12D3KooWQuPAZdnhENsAQ8GjRUAVR4hVmEpB8onx6GKiF2XYdCmY"
                .into(),
            "/ip4/2.2.2.2/tcp/30303/p2p/12D3KooWDegXffUJNkvguA8Fi2b5T9yj8KWMByF8X1QM4cvNXQgF"
                .into(),
        ];
        let d = n.dial_targets();
        assert_eq!(d.len(), 2);
        assert!(d[1].starts_with("/ip4/2.2.2.2/"));
    }

    /// Eski config dosyaları (yeni alanlar yok) aynen yüklenmeli: hepsi serde(default).
    #[test]
    fn legacy_network_config_without_new_fields_deserializes_with_defaults() {
        let toml_str = "listen_addr = \"/ip4/0.0.0.0/tcp/30303\"\nbootstrap_nodes = []\nmax_peers = 50\nenable_p2p = true\nnetwork_id = 21072026\nis_proposer = false\n";
        let n: NetworkConfig = toml::from_str(toml_str).expect("eski config yuklenmeli");
        assert!(!n.sentry_mode);
        assert!(n.private_peers.is_empty());
        assert_eq!(n.max_peers_per_ip, 4);
        assert_eq!(n.reserved_validator_slots, 32);
    }
}
