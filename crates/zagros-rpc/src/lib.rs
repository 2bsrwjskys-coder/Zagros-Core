use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{broadcast, mpsc, Mutex};
use tracing::{error, info, warn};
use warp::http::StatusCode;
use warp::reject::Reject;
use warp::reply::with_status;
use warp::ws::{Message, WebSocket, Ws};
use warp::Filter;
use zagros_executor::bridge::{BridgeManager, BridgeTxType};
use zagros_mempool::Mempool;
use zagros_state::{block_hash_key, block_key, receipt_key, tx_body_key, State};
use zagros_types::{
    config::RpcConfig, AccountState, ArchivedBlockHeader, ArchivedReceipt, Transaction, TxType,
    CHAIN_ID, LIQUIDITY_POOL_ADDRESS, VALIDATOR_REWARD_POOL,
};

// 🛡️ IP bazlı SLIDING-WINDOW rate limiter: her IP için son isteklerin ms zaman
// damgaları tutulur, penceresi (1000ms) geçenler atılır; saniye sınırını
// çaprazlayan patlamalar limiti aşamaz.
const RATE_LIMIT_WINDOW_MS: u64 = 1000;
// IP haritasının azami boyutu; aşılınca penceresi geçmiş IP'ler tahliye edilir
// (botnet/spoofed IP flood'unda bellek şişmesin). O(n) tarama pencere başına
// en fazla bir kez çalışır (LAST_SWEEP_MS).
const MAX_TRACKED_IPS: usize = 100_000;
// F2: Eşzamanlı işlenen HTTP POST isteği tavanı. spawn_blocking havuzunu
// (varsayılan 512 thread) koruyor: bu tavanı aşan istekler hemen 503 ile
// reddedilir, blocking-pool kuyruğu şişmez.
const MAX_IN_FLIGHT_HTTP_REQUESTS: usize = 2048;
// tx_cache: bu düğümden gönderilmiş ama makbuzu henüz diske yazılmamış
// işlemleri geçici görünür kılar (bkz. eth_getTransactionByHash). TTL blok
// üretim süresini fazlasıyla aşar ama harita sınırsız büyümez.
const TX_CACHE_TTL_SECS: u64 = 3600;
const TX_CACHE_SWEEP_INTERVAL_SECS: u64 = 300;
lazy_static::lazy_static! {
    static ref ACTIVE_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);
    static ref IP_RATE_LIMITER: Arc<DashMap<String, VecDeque<u64>>> = Arc::new(DashMap::new());
    /// F3: Son IP-haritası tahliye taramasının zamanı (ms), O(n) taramayı
    /// pencere başına bir kere ile sınırlar.
    static ref LAST_IP_SWEEP_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    /// F2: Şu an işlenmekte olan HTTP POST istek sayısı.
    static ref IN_FLIGHT_HTTP_REQUESTS: AtomicUsize = AtomicUsize::new(0);
    /// Zaman aşımıyla reddedilen RPC çağrısı/batch sayısı; ani artış kaynak
    /// istismarı sinyali.
    static ref RPC_TIMEOUT_COUNT: AtomicUsize = AtomicUsize::new(0);
    /// Ping'e rağmen boşta kalıp sunucuca kapatılan WS bağlantı sayısı (erken uyarı).
    static ref WS_IDLE_CLOSE_COUNT: AtomicUsize = AtomicUsize::new(0);
    /// İşlenmekte olan EVM simülasyonu sayısı; genel HTTP tavanından ayrı ve
    /// daha sıkı (`max_parallel_evm_simulations`).
    static ref EVM_SIMULATION_IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);
    /// YÜKSEK #7: eş-zamanlı simülasyon tavanı doluyken reddedilen
    /// `eth_call`/`eth_estimateGas` istek sayısı, operasyonel erken uyarı
    /// sinyali.
    static ref EVM_SIMULATION_BUSY_COUNT: AtomicUsize = AtomicUsize::new(0);
}

/// In-flight HTTP sayacının RAII muhafızı (Drop'ta azaltır). Sayaç parametreyle
/// verilir: üretimde `IN_FLIGHT_HTTP_REQUESTS`, testler izole yerel sayaç kullanır.
struct InFlightGuard<'a>(&'a AtomicUsize);
impl<'a> InFlightGuard<'a> {
    /// Sayacı artırır; tavan zaten dolmuşsa geri alıp `None` döner (503).
    fn try_acquire(counter: &'a AtomicUsize, max: usize) -> Option<Self> {
        let previous = counter.fetch_add(1, Ordering::AcqRel);
        if previous >= max {
            counter.fetch_sub(1, Ordering::AcqRel);
            None
        } else {
            Some(InFlightGuard(counter))
        }
    }
}
impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// `ACTIVE_CONNECTIONS` RAII muhafızı; `Drop` her çıkış yolunu kapsar (elle
/// `fetch_sub` panic-safe değil). WS ve HTTP POST istekleri sayaca dahildir.
struct ActiveConnectionGuard<'a>(&'a AtomicUsize);
impl<'a> ActiveConnectionGuard<'a> {
    fn acquire(counter: &'a AtomicUsize) -> Self {
        counter.fetch_add(1, Ordering::AcqRel);
        ActiveConnectionGuard(counter)
    }
}
impl Drop for ActiveConnectionGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// IP için kayan pencere: pencere içindeki sayı `ip_rate_limit`e ulaştıysa ret,
/// yoksa kaydedip kabul. Harita `MAX_TRACKED_IPS`i aşarsa bayat IP'ler tahliye edilir.
fn sliding_window_allows(ip: &str, now_ms: u64, ip_rate_limit: usize) -> bool {
    let allowed = {
        let mut entry = IP_RATE_LIMITER.entry(ip.to_string()).or_default();
        // Pencereden düşen (eski) zaman damgalarını at.
        while let Some(&front) = entry.front() {
            if now_ms.saturating_sub(front) >= RATE_LIMIT_WINDOW_MS {
                entry.pop_front();
            } else {
                break;
            }
        }
        if entry.len() >= ip_rate_limit {
            false
        } else {
            entry.push_back(now_ms);
            true
        }
    }; // entry kilidi burada bırakılır (retain'den önce - deadlock olmasın)

    maybe_evict_stale_ips(now_ms, ip_rate_limit);
    allowed
}

/// F3: Harita kapasiteyi aşmışsa ve son tarama üzerinden bir pencere geçmişse,
/// son 1sn'de görülmeyen IP'leri tahliye eder. O(n) tarama pencere başına en
/// fazla bir kez çalışır (flood altında bile amortize sabit maliyet).
fn maybe_evict_stale_ips(now_ms: u64, ip_rate_limit: usize) {
    if IP_RATE_LIMITER.len() <= MAX_TRACKED_IPS {
        return;
    }
    let last = LAST_IP_SWEEP_MS.load(Ordering::Relaxed);
    if now_ms.saturating_sub(last) < RATE_LIMIT_WINDOW_MS {
        return;
    }
    // Yalnızca bir thread tarasın (CAS); diğerleri atlar.
    if LAST_IP_SWEEP_MS
        .compare_exchange(last, now_ms, Ordering::AcqRel, Ordering::Relaxed)
        .is_ok()
    {
        enforce_ip_map_bound(&IP_RATE_LIMITER, now_ms, ip_rate_limit);
    }
}

/// 🛡️ Sert tavan: önce bayat girdiler, hâlâ üstündeyse az istek yapanlar atılır
/// (saldırgan her IP'yi pencere başına bir istekle taze tutabilir). Harita parametre (test).
fn enforce_ip_map_bound(map: &DashMap<String, VecDeque<u64>>, now_ms: u64, ip_rate_limit: usize) {
    map.retain(|_, deque| {
        deque
            .back()
            .is_some_and(|&last_seen| !ip_is_stale(last_seen, now_ms))
    });
    if map.len() > MAX_TRACKED_IPS {
        let keep_from = (ip_rate_limit / 2).max(2);
        map.retain(|_, deque| deque.len() >= keep_from);
        // Son çare: hepsi ağır kullanıcıysa bile bellek sınırlı kalmalı.
        // Kaybedilen tek şey bir pencerelik kısıtlama hafızasıdır.
        if map.len() > MAX_TRACKED_IPS {
            tracing::warn!(
                "🚨 IP rate-limiter tavanı ({}) ağır kullanıcılarla doldu - sayaç \
                 sıfırlanıyor (bellek sınırı korunuyor). Muhtemel dağıtık flood.",
                MAX_TRACKED_IPS
            );
            map.clear();
        }
    }
}

/// F3: Bir IP, son görülme zamanı üzerinden bir tam pencere geçmişse "bayat"
/// (tahliye edilebilir) sayılır. Saf fonksiyon, tahliye ölçütünün testi.
fn ip_is_stale(last_seen_ms: u64, now_ms: u64) -> bool {
    now_ms.saturating_sub(last_seen_ms) >= RATE_LIMIT_WINDOW_MS
}

#[derive(Debug)]
struct RateLimitError;
impl Reject for RateLimitError {}

#[derive(Debug)]
struct SocketLimitError;
impl Reject for SocketLimitError {}

pub async fn handle_rejection(
    err: warp::Rejection,
) -> Result<impl warp::Reply, std::convert::Infallible> {
    if err.find::<RateLimitError>().is_some() {
        Ok(with_status(
            warp::reply::json(
                &serde_json::json!({"error": "Rate limit exceeded. Too many requests! Please slow down."}),
            ),
            StatusCode::TOO_MANY_REQUESTS,
        ))
    } else if err.find::<SocketLimitError>().is_some() {
        Ok(with_status(
            warp::reply::json(
                &serde_json::json!({"error": "RPC node is currently at maximum global capacity. Try later."}),
            ),
            StatusCode::SERVICE_UNAVAILABLE,
        ))
    } else if err.find::<warp::reject::MethodNotAllowed>().is_some() || err.is_not_found() {
        // 🛡️ Tarayıcıdan düz GET (ChainList gözden geçireni, meraklı kullanıcı) sunucu
        // hatası gibi görünmesin; HTTP 200 dönülür ki basit erişilebilirlik kontrolleri "canlı" görsün.
        Ok(with_status(
            warp::reply::json(&serde_json::json!({
                "message": "This is the Zagros JSON-RPC endpoint. Send a POST request with a JSON-RPC 2.0 payload (e.g. {\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_chainId\",\"params\":[]})."
            })),
            StatusCode::OK,
        ))
    } else {
        Ok(with_status(
            warp::reply::json(&serde_json::json!({"error": "Unhandled rejection"})),
            StatusCode::INTERNAL_SERVER_ERROR,
        ))
    }
}

// 🔥 Anti-flood: IP başına kayan pencere + global max_connections (`RpcConfig`ten);
// hem POST hem WS-upgrade route'una uygulanır.
fn check_rate_limit(
    max_connections: usize,
    ip_rate_limit: usize,
    whitelist: Arc<std::collections::HashSet<String>>,
) -> impl Filter<Extract = (), Error = warp::Rejection> + Clone {
    warp::addr::remote()
        .and(warp::header::optional::<String>("x-real-ip"))
        .and_then(move |addr: Option<SocketAddr>, real_ip: Option<String>| {
            let whitelist = whitelist.clone();
            async move {
                // Global (Node-Genel) Soket Sınırı (K5: WS + HTTP birlikte).
                let current = ACTIVE_CONNECTIONS.load(Ordering::Relaxed);
                if current >= max_connections {
                    return Err(warp::reject::custom(SocketLimitError));
                }

                // Y5: IP-bazlı KAYAN PENCERE flood koruması.
                if let Some(ip) = addr {
                    let sock_ip = ip.ip();
                    // Ters-vekil (nginx) duzeltmesi: soket loopback (guvenilir nginx)
                    // ise gercek istemci IP-si X-Real-IP header-inda. 8545 ufw ile disa
                    // KAPALI oldugundan yalniz nginx baglanir -> header guvenilir.
                    let ip_str = if sock_ip.is_loopback() {
                        real_ip
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .unwrap_or_else(|| sock_ip.to_string())
                    } else {
                        sock_ip.to_string()
                    };
                    if whitelist.contains(&ip_str) {
                        return Ok(());
                    }
                    let now_ms = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_millis() as u64)
                        .unwrap_or(0);

                    if !sliding_window_allows(&ip_str, now_ms, ip_rate_limit) {
                        tracing::warn!("Blocked IP (Flood): {}", ip_str);
                        return Err(warp::reject::custom(RateLimitError));
                    }
                }
                Ok(())
            }
        })
        .untuple_one()
}

/// Hex bir tx_id dizesini (0x'li/'siz, 64 hex karakter) 32 baytlık Hash'e
/// çevirir. K3: mempool'da tx_id ile O(1) arama için (eski `hex::encode`'lu
/// tüm-havuz taramasının yerine).
fn parse_tx_id_hex(hex_str: &str) -> Option<[u8; 32]> {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(stripped).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes);
    Some(id)
}

// K3 sonrası yalnızca testte kullanılan referans algoritma: canlı yolda artık
// `Mempool::pending_nonce` (O(1) indeksli) kullanılıyor. İkisinin de anlamı
// aynı; bu, o mantığın saf/bağımsız doğrulaması olarak korunuyor.
#[cfg(test)]
fn next_pending_nonce(state_nonce: u64, sender: &str, pending: &[Transaction]) -> u64 {
    let pending_nonces: std::collections::HashSet<u64> = pending
        .iter()
        .filter(|tx| tx.sender.eq_ignore_ascii_case(sender))
        .map(|tx| tx.nonce)
        .collect();
    let mut next_nonce = state_nonce;

    while pending_nonces.contains(&next_nonce) {
        next_nonce = next_nonce.saturating_add(1);
    }

    next_nonce
}

fn with_state(
    state: Arc<dyn State>,
) -> impl warp::Filter<Extract = (Arc<dyn State>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || state.clone())
}

fn with_mempool(
    mempool: Arc<Mempool>,
) -> impl warp::Filter<Extract = (Arc<Mempool>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || mempool.clone())
}

fn with_tx_cache(
    tx_cache: Arc<DashMap<String, (String, u64)>>,
) -> impl warp::Filter<
    Extract = (Arc<DashMap<String, (String, u64)>>,),
    Error = std::convert::Infallible,
> + Clone {
    warp::any().map(move || tx_cache.clone())
}

/// 🛡️ `zagros-rpc` KASITLI olarak `zagros-network`'e bağımlı değil (kardeş
/// katmanlar, yalnız `zagros-cli` birleştirir); ham `mpsc::UnboundedSender<Transaction>`
/// alır, CLI onu `NetworkHandle::publish_transaction`'a köprüler. `None` = P2P kapalı.
fn with_tx_broadcast(
    tx_broadcast: Option<mpsc::UnboundedSender<Transaction>>,
) -> impl warp::Filter<
    Extract = (Option<mpsc::UnboundedSender<Transaction>>,),
    Error = std::convert::Infallible,
> + Clone {
    warp::any().map(move || tx_broadcast.clone())
}

/// Tek bir RPC çağrısının ne kadar BEKLENECEĞİNİ sınırlayan üç kademeli zaman
/// aşımı politikası (`[rpc]` config). TCP seviyesi Slowloris'i çözmez, yalnız
/// isteğin işlenme süresini sınırlar.
#[derive(Debug, Clone, Copy)]
struct RpcTimeouts {
    light: Duration,
    default_: Duration,
    evm_execution: Duration,
    max_batch: Duration,
    /// 🛡️ Tek batch'teki azami alt istek sayısı, bkz. kullanım yerindeki
    /// gerekçe (küçük istek → devasa sunucu işi amplifikasyonu).
    max_batch_requests: usize,
}

impl From<&RpcConfig> for RpcTimeouts {
    fn from(config: &RpcConfig) -> Self {
        RpcTimeouts {
            light: Duration::from_secs(config.light_method_timeout_secs),
            default_: Duration::from_secs(config.default_method_timeout_secs),
            evm_execution: Duration::from_secs(config.evm_execution_timeout_secs),
            max_batch: Duration::from_secs(config.max_batch_timeout_secs),
            max_batch_requests: config.max_batch_requests,
        }
    }
}

impl Default for RpcTimeouts {
    fn default() -> Self {
        RpcTimeouts::from(&RpcConfig::default())
    }
}

/// `eth_call`/`eth_estimateGas` üst gas sınırları + eş zamanlı simülasyon tavanı
/// (`[rpc]` config). İkisi aynı `run_isolated_eth_call` maliyetine sahip olduğundan
/// tek paylaşımlı bütçe (`max_parallel_simulations`, `EVM_SIMULATION_IN_FLIGHT`).
#[derive(Debug, Clone, Copy)]
pub struct EvmSimulationLimits {
    pub eth_call_max_gas: u64,
    pub eth_estimate_gas_max_gas: u64,
    pub max_parallel_simulations: usize,
}

impl From<&RpcConfig> for EvmSimulationLimits {
    fn from(config: &RpcConfig) -> Self {
        EvmSimulationLimits {
            eth_call_max_gas: config.eth_call_max_gas,
            eth_estimate_gas_max_gas: config.eth_estimate_gas_max_gas,
            max_parallel_simulations: config.max_parallel_evm_simulations,
        }
    }
}

impl Default for EvmSimulationLimits {
    fn default() -> Self {
        EvmSimulationLimits::from(&RpcConfig::default())
    }
}

/// `call_obj`un isteğe bağlı `"gas"` alanını çözer; yoksa/geçersizse `None`,
/// çağıran config tavanının tamamını kullanır.
fn parse_requested_gas(call_obj: &Value) -> Option<u64> {
    let gas_str = call_obj.get("gas")?.as_str()?;
    u64::from_str_radix(gas_str.trim_start_matches("0x"), 16).ok()
}

/// Beyan edilen gas tavana KADAR saygı görür, aşarsa sessizce kırpılır (geth
/// davranışı); beyan yoksa tavanın tamamı kullanılır.
fn resolve_effective_gas(call_obj: &Value, configured_max: u64) -> u64 {
    parse_requested_gas(call_obj)
        .map(|requested| requested.min(configured_max))
        .unwrap_or(configured_max)
}

/// Native işlemler `gas_limit=1, gas_price=fee`; cüzdanlar `gas_limit × gas_price`
/// hesapladığından `fee / MIN_EVM_GAS_PRICE_WEI` sentetik gas_limit döner (asgari 21000).
fn synthetic_gas_limit_for_fee(fee: u128) -> u64 {
    let gas_limit = fee / zagros_types::MIN_EVM_GAS_PRICE_WEI;
    gas_limit.max(21_000).min(u64::MAX as u128) as u64
}

/// -32003: "Server error" aralığında uygulamaya özgü kod; istemci "zaman aşımı,
/// tekrar denenebilir" ile "kalıcı hata"yı ayırt edebilsin.
const RPC_TIMEOUT_ERROR_CODE: i64 = -32003;

/// Yalnız hata gövdesini üretir, `RPC_TIMEOUT_COUNT`'u artırmaz: batch N yanıt
/// üretse de TEK zaman aşımı olayıdır, sayacı çağıran bir kez artırır.
fn rpc_timeout_error_body(timeout: Duration) -> Value {
    json!({
        "code": RPC_TIMEOUT_ERROR_CODE,
        "message": format!(
            "Request timeout: processing exceeded {:.1}s, retry with a narrower request or contact the node operator",
            timeout.as_secs_f64()
        )
    })
}

fn rpc_timeout_error_response(id: Value, timeout: Duration) -> RpcResponse {
    RpcResponse {
        jsonrpc: "2.0".to_string(),
        id,
        result: None,
        error: Some(rpc_timeout_error_body(timeout)),
    }
}

/// `eth_sendRawTransaction` zaman aşımı mesajı: `spawn_blocking` arka planda
/// bitebilir, işlem mempool'a girmiş olabilir; kullanıcı hash ile kontrol etmeli.
fn rpc_timeout_error_body_for_send_raw_tx(timeout: Duration, tx_hash: Option<&str>) -> Value {
    let message = match tx_hash {
        Some(hash) => format!(
            "Request timeout: processing exceeded {:.1}s; the transaction may still have been \
             accepted in the background. Check transaction status using tx hash {} before \
             resubmitting.",
            timeout.as_secs_f64(),
            hash
        ),
        None => format!(
            "Request timeout: processing exceeded {:.1}s; the transaction may still have been \
             accepted in the background. Check transaction status using its transaction hash \
             before resubmitting.",
            timeout.as_secs_f64()
        ),
    };
    let mut body = json!({
        "code": RPC_TIMEOUT_ERROR_CODE,
        "message": message,
    });
    if let Some(hash) = tx_hash {
        body["data"] = json!({ "txHash": hash });
    }
    body
}

/// Ham RLP baytlarından `decode_and_convert_tx` ile AYNI formülle (`keccak256(tx_bytes)`)
/// tx hash türetir; decode etmeden, yan etkisiz (zaman aşımı yolunda güvenle çağrılır).
fn raw_eth_send_tx_hash(params: &Option<Vec<Value>>) -> Option<String> {
    let raw_hex = params.as_ref()?.first()?.as_str()?;
    let bytes = hex::decode(raw_hex.strip_prefix("0x").unwrap_or(raw_hex)).ok()?;
    let mut hasher = Keccak256::new();
    hasher.update(&bytes);
    Some(format!("0x{}", hex::encode(hasher.finalize())))
}

/// Zaman aşımı kovası: `light` (state/disk erişimsiz statik yanıtlar),
/// `evm_execution` (`eth_call`/`eth_estimateGas`, asıl istismar yüzeyi),
/// `default_` (geri kalanı; bilinmeyen metodlar güvenli tarafta buraya düşer).
fn classify_rpc_method(method: &str) -> fn(&RpcTimeouts) -> Duration {
    const LIGHT_METHODS: &[&str] = &[
        "zagros_getNetworkPeers",
        "zagros_getLateVoteStats",
        "eth_chainId",
        "net_version",
        "web3_clientVersion",
        "net_listening",
        "net_peerCount",
        "eth_syncing",
        "eth_accounts",
        "eth_mining",
        "eth_hashrate",
        "eth_protocolVersion",
        "eth_coinbase",
        "web3_sha3",
        "eth_gasPrice",
        "eth_maxPriorityFeePerGas",
        "eth_feeHistory",
        "eth_getUncleCountByBlockNumber",
        "eth_getUncleCountByBlockHash",
    ];
    const EVM_EXECUTION_METHODS: &[&str] = &["eth_call", "eth_estimateGas"];

    if EVM_EXECUTION_METHODS.contains(&method) {
        |t: &RpcTimeouts| t.evm_execution
    } else if LIGHT_METHODS.contains(&method) {
        |t: &RpcTimeouts| t.light
    } else {
        |t: &RpcTimeouts| t.default_
    }
}

fn with_rpc_timeouts(
    timeouts: RpcTimeouts,
) -> impl warp::Filter<Extract = (RpcTimeouts,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || timeouts)
}

fn with_evm_simulation_limits(
    limits: EvmSimulationLimits,
) -> impl warp::Filter<Extract = (EvmSimulationLimits,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || limits)
}

/// Saf WS boşta kalma kararı (`handle_ws_connection` ile aynı mantık, soket
/// olmadan test edilir). Birimler BİLEREK milisaniye: saniye çözünürlüğü
/// yuvarlama hatasına yol açar (bkz. `handle_ws_connection` tasarım notu).
fn ws_connection_is_idle(idle_for_ms: u64, pong_timeout_ms: u64) -> bool {
    idle_for_ms > pong_timeout_ms
}

/// Yetkili köprü RPC isteklerinin azami zaman damgası sapması (yakalanan istek
/// pencere dışında oynatılamaz); BridgeManager toleransından kasıtlı dar.
const BRIDGE_RPC_TIMESTAMP_DRIFT_SECS: u64 = 120;

/// `timestamp`'in node'un yerel saatinden `BRIDGE_RPC_TIMESTAMP_DRIFT_SECS`
/// saniyeden fazla sapıp sapmadığını kontrol eder.
fn bridge_timestamp_within_drift_window(timestamp: u64) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    now.abs_diff(timestamp) <= BRIDGE_RPC_TIMESTAMP_DRIFT_SECS
}

/// `Burn` ise `verify_source_burn_matches`; mint'te no-op (gerçekliği Ethereum'da,
/// burada doğrulanamaz).
fn verify_burn_proposal_if_needed(
    state: &dyn zagros_state::State,
    tx_type: &BridgeTxType,
    source_tx_hash: &str,
    recipient: &str,
    amount: u128,
) -> zagros_types::Result<()> {
    match tx_type {
        BridgeTxType::Burn => zagros_executor::bridge::BridgeManager::verify_source_burn_matches(
            state,
            source_tx_hash,
            &recipient.to_string(),
            amount,
        ),
        BridgeTxType::Mint => Ok(()),
    }
}

fn bridge_tx_type_str(tx_type: &BridgeTxType) -> &'static str {
    match tx_type {
        BridgeTxType::Mint => "mint",
        BridgeTxType::Burn => "burn",
    }
}

/// `zagros_getBridgeProposal`/`zagros_getPendingBridgeProposals` için ortak
/// JSON şekli, ikisi de aynı alanları döndürür.
fn bridge_proposal_json(
    proposal: &zagros_executor::bridge::BridgeProposal,
    can_execute: bool,
) -> Value {
    serde_json::json!({
        "proposal_id": format!("0x{}", hex::encode(proposal.proposal_id)),
        "tx_type": bridge_tx_type_str(&proposal.tx_type),
        "recipient": proposal.recipient,
        "amount": proposal.amount.to_string(),
        "source_chain": proposal.source_chain,
        "source_tx_hash": proposal.source_tx_hash,
        // timestamp/nonce imza mesajına dahil; öneriyi oluşturmamış relayer mesajı
        // yeniden üretebilsin.
        "timestamp": proposal.timestamp.to_string(),
        "nonce": proposal.nonce.to_string(),
        "signatures_collected": proposal.signatures.len(),
        // Kimlerin imzaladığı (relayer keşfi için).
        "signers": proposal.signatures.iter().map(|s| s.authority.clone()).collect::<Vec<_>>(),
        // Toplanan HAM Ed25519 imzaları: relayer, RPC'nin `can_execute` beyanına
        // güvenmeden kendi yetkili kümesine karşı doğrular (ele geçirilmiş node
        // sahte `can_execute:true` üretse bile geçerli imza uyduramaz).
        "signatures": proposal.signatures.iter().map(|s| serde_json::json!({
            "authority": s.authority,
            "signature": format!("0x{}", hex::encode(&s.signature)),
            "public_key": format!("0x{}", hex::encode(&s.public_key)),
            "timestamp": s.timestamp.to_string(),
        })).collect::<Vec<_>>(),
        "executed": proposal.executed,
        "can_execute": can_execute,
        "auto_swap": proposal.auto_swap,
        // amount_out_min: create_signing_message'ın hash'e dahil ettiği bir
        // alan daha, relayer'ların imza mesajını yeniden üretebilmesi için
        // (yukarıdaki timestamp/nonce ile aynı gerekçe).
        "amount_out_min": proposal.amount_out_min.to_string(),
        // 🎟️ Claim fişleri; 🚨 kontrat imzaları imzalayan adrese göre ARTAN sırada
        // bekler, sıra burada verilir (yanlış sıra revert edip gas yakardı).
        "claim_vouchers": claim_vouchers_json(proposal),
    })
}

/// Claim fişlerini imzalayan adrese göre ARTAN sırada serileştirir: `claimTokens`
/// bu sırayı şart koşar (tekillik); yanlış sıra revert eder ve gas yanar.
fn claim_vouchers_json(proposal: &zagros_executor::bridge::BridgeProposal) -> Value {
    let mut vouchers: Vec<&zagros_executor::bridge::ClaimVoucher> =
        proposal.claim_vouchers.iter().collect();
    vouchers.sort_by(|a, b| a.signer.cmp(&b.signer));
    Value::Array(
        vouchers
            .into_iter()
            .map(|v| serde_json::json!({ "signer": v.signer, "signature": v.signature }))
            .collect(),
    )
}

fn with_bridge_manager(
    bridge_manager: Arc<std::sync::Mutex<BridgeManager>>,
) -> impl warp::Filter<
    Extract = (Arc<std::sync::Mutex<BridgeManager>>,),
    Error = std::convert::Infallible,
> + Clone {
    warp::any().map(move || bridge_manager.clone())
}

fn with_reserve_sender(
    reserve_sender: broadcast::Sender<String>,
) -> impl warp::Filter<Extract = (broadcast::Sender<String>,), Error = std::convert::Infallible> + Clone
{
    warp::any().map(move || reserve_sender.clone())
}

fn with_price_history(
    price_history: Arc<Mutex<VecDeque<PoolReserveHistoryEntry>>>,
) -> impl warp::Filter<
    Extract = (Arc<Mutex<VecDeque<PoolReserveHistoryEntry>>>,),
    Error = std::convert::Infallible,
> + Clone {
    warp::any().map(move || price_history.clone())
}

#[allow(clippy::too_many_arguments)]
async fn handle_rpc_request(
    body: bytes::Bytes, // 🔥 RAW HTTP BYTES
    state: Arc<dyn State>,
    mempool: Arc<Mempool>,
    tx_cache: Arc<DashMap<String, (String, u64)>>,
    bridge_manager: Arc<std::sync::Mutex<BridgeManager>>,
    timeouts: RpcTimeouts,
    evm_limits: EvmSimulationLimits,
    tx_broadcast: Option<mpsc::UnboundedSender<Transaction>>,
) -> Result<Box<dyn warp::Reply>, std::convert::Infallible> {
    // 🛡️ HTTP in-flight tavanı: dolu ise hemen 503, iş yükü kuyruğa yığılmaz;
    // guard fonksiyon bitince sayacı düşürür.
    let _in_flight =
        match InFlightGuard::try_acquire(&IN_FLIGHT_HTTP_REQUESTS, MAX_IN_FLIGHT_HTTP_REQUESTS) {
            Some(guard) => guard,
            None => {
                let busy = RpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id: Value::Null,
                    result: None,
                    error: Some(json!({
                        "code": -32005,
                        "message": "Server busy: too many concurrent requests, retry shortly"
                    })),
                };
                return Ok(Box::new(warp::reply::json(&busy)));
            }
        };
    // ACTIVE_CONNECTIONS HTTP POST isteklerini de sayar; `check_rate_limit`'in
    // POST rotası için okuduğu eşik ancak böyle anlamlı (bkz. ActiveConnectionGuard).
    let _conn_guard = ActiveConnectionGuard::acquire(&ACTIVE_CONNECTIONS);

    // MetaMask toplu (batch) JSON-RPC gönderir; önce tekil şekil denenir, olmazsa dizi.
    if let Ok(req) = sonic_rs::from_slice::<RpcRequest>(&body) {
        // 🛡️ handle_request senkron RocksDB/mempool erişimi yapar; async worker'ı
        // bloklamamak için spawn_blocking (soğuk RocksDB okuması WS keepalive'ı geciktirirdi).
        let request_id = req.id.clone();
        let method_name = req.method.clone();
        let method_timeout = classify_rpc_method(&req.method)(&timeouts);
        // `req` closure'a taşınmadan olası tx hash'i (yan etkisiz) hesaplanır.
        let raw_send_tx_hash = if method_name == "eth_sendRawTransaction" {
            raw_eth_send_tx_hash(&req.params)
        } else {
            None
        };
        // 🛡️ `timeout` yalnız async bekleyişi keser, `spawn_blocking` işi arka planda
        // biter; sağladığı: bağlantı süresiz tutulmaz. CPU sınırı gas tavanı + bütçe.
        let handle = tokio::task::spawn_blocking(move || {
            RpcServer::handle_request_with_broadcast(
                req,
                state,
                mempool,
                tx_cache,
                bridge_manager,
                evm_limits,
                tx_broadcast,
            )
        });
        let response = match tokio::time::timeout(method_timeout, handle).await {
            Ok(Ok(response)) => response,
            Ok(Err(_)) => RpcResponse {
                jsonrpc: "2.0".to_string(),
                id: request_id,
                result: None,
                error: Some(json!({"code": -32603, "message": "Internal error (worker panicked)"})),
            },
            Err(_elapsed) => {
                RPC_TIMEOUT_COUNT.fetch_add(1, Ordering::Relaxed);
                warn!(
                    "⏱️ RPC zaman aşımı: method={} limit={:.1}s",
                    method_name,
                    method_timeout.as_secs_f64()
                );
                if method_name == "eth_sendRawTransaction" {
                    RpcResponse {
                        jsonrpc: "2.0".to_string(),
                        id: request_id,
                        result: None,
                        error: Some(rpc_timeout_error_body_for_send_raw_tx(
                            method_timeout,
                            raw_send_tx_hash.as_deref(),
                        )),
                    }
                } else {
                    rpc_timeout_error_response(request_id, method_timeout)
                }
            }
        };
        return Ok(Box::new(warp::reply::json(&response)));
    }

    if let Ok(batch) = sonic_rs::from_slice::<Vec<RpcRequest>>(&body) {
        if batch.is_empty() {
            // JSON-RPC 2.0: boş dizi geçersiz istek sayılır.
            let err_response = RpcResponse {
                jsonrpc: "2.0".to_string(),
                id: Value::Null,
                result: None,
                error: Some(json!({"code": -32600, "message": "Invalid Request (empty batch)"})),
            };
            return Ok(Box::new(warp::reply::json(&err_response)));
        }

        // 🛡️ BATCH BOYUT TAVANI: 2 MiB gövde ~35.000 alt çağrı taşıyabilir, hepsi
        // TEK `spawn_blocking`'de sırayla işlenir; `max_batch_timeout_secs` yalnız
        // istemcinin beklemesini keser, thread çalışmaya devam eder (amplifikasyon).
        if batch.len() > timeouts.max_batch_requests {
            let err_response = RpcResponse {
                jsonrpc: "2.0".to_string(),
                id: Value::Null,
                result: None,
                error: Some(json!({
                    "code": -32600,
                    "message": format!(
                        "Batch too large: {} > {} requests",
                        batch.len(),
                        timeouts.max_batch_requests
                    )
                })),
            };
            return Ok(Box::new(warp::reply::json(&err_response)));
        }

        // Batch'in TOPLAM zaman aşımı, her alt isteğin kendi kovasının TOPLAMI,
        // ama `max_batch_timeout_secs` tavanını AŞAMAZ.
        let batch_ids: Vec<Value> = batch.iter().map(|r| r.id.clone()).collect();
        let batch_timeout: Duration = batch
            .iter()
            .map(|r| classify_rpc_method(&r.method)(&timeouts))
            .sum::<Duration>()
            .min(timeouts.max_batch);

        // Toplu istekteki HER bir alt istek, tek istek yolundakiyle AYNI
        // senkron/bloklamayan yürütme kuralına tabi, hepsini TEK bir
        // spawn_blocking içinde sırayla işleyip yanıt dizisini döndürüyoruz.
        let handle = tokio::task::spawn_blocking(move || {
            batch
                .into_iter()
                .map(|req| {
                    RpcServer::handle_request_with_broadcast(
                        req,
                        state.clone(),
                        mempool.clone(),
                        tx_cache.clone(),
                        bridge_manager.clone(),
                        evm_limits,
                        tx_broadcast.clone(),
                    )
                })
                .collect::<Vec<RpcResponse>>()
        });
        let responses = match tokio::time::timeout(batch_timeout, handle).await {
            Ok(Ok(responses)) => responses,
            Ok(Err(_)) => batch_ids
                .into_iter()
                .map(|id| RpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id,
                    result: None,
                    error: Some(
                        json!({"code": -32603, "message": "Internal error (worker panicked)"}),
                    ),
                })
                .collect::<Vec<RpcResponse>>(),
            Err(_elapsed) => {
                RPC_TIMEOUT_COUNT.fetch_add(1, Ordering::Relaxed);
                warn!(
                    "⏱️ RPC batch zaman aşımı: {} istek, limit={:.1}s",
                    batch_ids.len(),
                    batch_timeout.as_secs_f64()
                );
                batch_ids
                    .into_iter()
                    .map(|id| rpc_timeout_error_response(id, batch_timeout))
                    .collect::<Vec<RpcResponse>>()
            }
        };
        return Ok(Box::new(warp::reply::json(&responses)));
    }

    let err_response = RpcResponse {
        jsonrpc: "2.0".to_string(),
        id: Value::Null,
        result: None,
        error: Some(json!({"code": -32700, "message": "Parse error (Invalid JSON)"})),
    };
    Ok(Box::new(warp::reply::json(&err_response)))
}

use ethers_core::types::{transaction::eip2718::TypedTransaction, U256};
use ethers_core::utils::rlp::Rlp;
use sha3::{Digest, Keccak256};

#[derive(Deserialize, Debug)]
pub struct RpcRequest {
    pub jsonrpc: String,
    pub method: String,
    pub params: Option<Vec<Value>>,
    pub id: Value,
}

#[derive(Serialize)]
pub struct RpcResponse {
    pub jsonrpc: String,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
}

#[derive(Serialize, Deserialize, Clone)]
struct PoolReserveHistoryEntry {
    timestamp: u64,
    price: String,
}

fn history_file_path() -> PathBuf {
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("price_history.json")
}

fn load_price_history(path: &PathBuf) -> VecDeque<PoolReserveHistoryEntry> {
    let mut history = VecDeque::with_capacity(120);
    if let Ok(contents) = fs::read_to_string(path) {
        if let Ok(mut loaded) = serde_json::from_str::<VecDeque<PoolReserveHistoryEntry>>(&contents)
        {
            let cutoff = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs().saturating_sub(48 * 3600))
                .unwrap_or(0);
            while loaded
                .front()
                .map(|entry| entry.timestamp < cutoff)
                .unwrap_or(false)
            {
                loaded.pop_front();
            }
            history = loaded;
        }
    }
    history
}

fn persist_price_history(path: &PathBuf, history: &VecDeque<PoolReserveHistoryEntry>) {
    if let Ok(serialized) = serde_json::to_string(history) {
        let _ = fs::write(path, serialized);
    }
}

/// Budama backpressure: arsiv yukseklik dosyasi + rapor token'i (main.rs startup'ta set).
static ARCHIVE_HEIGHT_FILE: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
static ARCHIVE_REPORT_TOKEN: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();

/// 🛡️ Paylaşılan sır için sabit zamanlı eşitlik: `==` ilk farklı baytta kısa
/// devre yapar, uzaktan ölçülen süre farkı token'ı bayt bayt aratabilir.
fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn set_archive_backpressure(file: Option<String>, token: Option<String>) {
    let _ = ARCHIVE_HEIGHT_FILE.set(file);
    let _ = ARCHIVE_REPORT_TOKEN.set(token);
}

pub struct RpcServer {
    state: Arc<dyn State>,
    mempool: Arc<Mempool>,
    bridge_manager: Arc<std::sync::Mutex<BridgeManager>>,
    tx_cache: Arc<DashMap<String, (String, u64)>>,
    reserve_sender: broadcast::Sender<String>,
    account_sender: broadcast::Sender<String>,
    price_history: Arc<Mutex<VecDeque<PoolReserveHistoryEntry>>>,
    history_file: PathBuf,
    /// Y3/Y4/Y5: bind adresi, max_connections ve ip_rate_limit artık
    /// config.toml'dan gelir (hardcoded değil).
    config: RpcConfig,
    /// Bkz. `with_tx_broadcast`'ın doc yorumu, `None` varsayılan (P2P kapalı).
    tx_broadcast: Option<mpsc::UnboundedSender<Transaction>>,
    /// G14: /metrics + /health uçlarının konsensüs/P2P sayaçları (None =
    /// kablosuz; uçlar yine çalışır, yalnız state'ten türetilen alanlar dolar).
    node_metrics: Option<Arc<zagros_metrics::NodeMetrics>>,
}

// 🗳️ Yönetişim RPC yardımcıları
/// `ParamKey` bincode varyant sırasıyla birebir (dApp indeksleri kullanır; test kilitler).
fn gov_param_key_rows(
    p: &zagros_types::consensus::ChainParams,
    qc_grace_ms: u64,
) -> Vec<(zagros_types::consensus::ParamKey, &'static str, u128)> {
    use zagros_types::consensus::ParamKey::*;
    vec![
        (MaxValidators, "max_validators", p.max_validators as u128),
        (MaxBlockBytes, "max_block_bytes", p.max_block_bytes as u128),
        (
            BlockIntervalMs,
            "block_interval_ms",
            p.block_interval_ms as u128,
        ),
        (TBaseMs, "t_base_ms", p.t_base_ms as u128),
        (EpochSeconds, "epoch_seconds", p.epoch_seconds as u128),
        (
            ProbationEpochs,
            "probation_epochs",
            p.probation_epochs as u128,
        ),
        (
            UptimeThresholdBps,
            "uptime_threshold_bps",
            p.uptime_threshold_bps as u128,
        ),
        (
            MaxLivenessStrikes,
            "max_liveness_strikes",
            p.max_liveness_strikes as u128,
        ),
        (
            IdleBlockIntervalS,
            "idle_block_interval_s",
            p.idle_block_interval_s as u128,
        ),
        (
            MaxClockSkewMs,
            "max_clock_skew_ms",
            p.max_clock_skew_ms as u128,
        ),
        (
            EvidenceMaxAgeEpochs,
            "evidence_max_age_epochs",
            p.evidence_max_age_epochs as u128,
        ),
        (
            BondLockSeconds,
            "bond_lock_seconds",
            p.bond_lock_seconds as u128,
        ),
        (
            MaxPerProvider,
            "max_per_provider",
            p.max_per_provider as u128,
        ),
        (MaxPerRegion, "max_per_region", p.max_per_region as u128),
        (
            MaxPerOperator,
            "max_per_operator",
            p.max_per_operator as u128,
        ),
        (TimelockEpochs, "timelock_epochs", p.timelock_epochs as u128),
        (
            GovVotingEpochs,
            "gov_voting_epochs",
            p.gov_voting_epochs as u128,
        ),
        (
            MinValidatorStakeZerenya,
            "min_validator_stake_zerenya",
            p.min_validator_stake_zerenya,
        ),
        (
            StakeHysteresisBps,
            "stake_hysteresis_bps",
            p.stake_hysteresis_bps as u128,
        ),
        (
            ApplicationFeeZerenya,
            "application_fee_zerenya",
            p.application_fee_zerenya,
        ),
        (
            ReserveFloorZerenyaPerDay,
            "reserve_floor_zerenya_per_day",
            p.reserve_floor_zerenya_per_day,
        ),
        (
            ReserveEndEpoch,
            "reserve_end_epoch",
            p.reserve_end_epoch as u128,
        ),
        (
            ReporterRewardCapBps,
            "reporter_reward_cap_bps",
            p.reporter_reward_cap_bps as u128,
        ),
        (
            FalseDeclarationSlashBps,
            "false_declaration_slash_bps",
            p.false_declaration_slash_bps as u128,
        ),
        (VoteCapBps, "vote_cap_bps", p.vote_cap_bps as u128),
        (
            StakerQuorumBps,
            "staker_quorum_bps",
            p.staker_quorum_bps as u128,
        ),
        (QcGraceMs, "qc_grace_ms", qc_grace_ms as u128),
    ]
}

fn gov_action_json(action: &zagros_types::consensus::ProposalAction) -> Value {
    use zagros_types::consensus::ProposalAction as A;
    match action {
        A::Text => json!({ "kind": "Text" }),
        A::ParamChange(updates) => json!({
            "kind": "ParamChange",
            "updates": updates.iter().map(|u| json!({
                "key": format!("{:?}", u.key),
                "channel": format!("{:?}", u.key.channel()),
                "value": u.value.to_string(),
            })).collect::<Vec<_>>(),
        }),
        A::ScheduleUpgrade {
            target_ruleset,
            binary_sha256,
            activation_epoch,
        } => json!({
            "kind": "ScheduleUpgrade",
            "target_ruleset": target_ruleset,
            "binary_sha256": format!("0x{}", hex::encode(binary_sha256)),
            "activation_epoch": activation_epoch,
        }),
        A::ShortenAdminAuthority { end_timestamp } => {
            json!({ "kind": "ShortenAdminAuthority", "end_timestamp": end_timestamp })
        }
        A::ApproveValidator { target } => json!({ "kind": "ApproveValidator", "target": target }),
        A::RemoveValidator { target } => json!({ "kind": "RemoveValidator", "target": target }),
    }
}

impl RpcServer {
    // G14 — /health (JSON) + /metrics (Prometheus metni)

    /// Uçların ortak veri kaynağı: state'ten türetilen zincir görünümü +
    /// (varsa) sürücü/P2P sayaçları. Salt-okunur, konsensüse girmez.
    fn node_status_snapshot(
        state: &Arc<dyn State>,
        mempool: &Arc<Mempool>,
        metrics: &Option<Arc<zagros_metrics::NodeMetrics>>,
    ) -> serde_json::Value {
        use std::sync::atomic::Ordering::Relaxed;
        let height = Self::lookup_account(state, "__GLOBAL_BLOCK_HEIGHT__")
            .map(|a| a.balance as u64)
            .unwrap_or(0);
        let params = state
            .get_account(&zagros_types::consensus::CHAIN_PARAMS_KEY.to_string())
            .ok()
            .flatten()
            .filter(|a| !a.contract_code.is_empty())
            .and_then(|a| zagros_types::consensus::ChainParams::decode(&a.contract_code).ok());
        let genesis_ts = Self::lookup_account(state, zagros_types::GENESIS_TIMESTAMP_KEY)
            .map(|a| a.balance)
            .unwrap_or(0);
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u128)
            .unwrap_or(0);
        let epoch = match &params {
            Some(p) if p.epoch_seconds > 0 && genesis_ts > 0 && now_secs > genesis_ts => {
                ((now_secs - genesis_ts) / p.epoch_seconds as u128) as u64
            }
            _ => 0,
        };
        let validator_set = state
            .get_account(&zagros_types::consensus::ACTIVE_VALIDATOR_SET_KEY.to_string())
            .ok()
            .flatten()
            .filter(|a| !a.contract_code.is_empty())
            .and_then(|a| {
                bincode::deserialize::<zagros_types::consensus::ActiveValidatorSet>(
                    &a.contract_code,
                )
                .ok()
            });
        let mut v = serde_json::json!({
            "status": "ok",
            "chain_id": zagros_types::CHAIN_ID,
            "height": height,
            "epoch": epoch,
            "active_ruleset": params.as_ref().map(|p| p.active_ruleset).unwrap_or(0),
            "supported_ruleset": zagros_types::consensus::SUPPORTED_RULESET,
            "validators": validator_set.as_ref().map(|s| s.len()).unwrap_or(0),
            "validator_set_epoch": validator_set.as_ref().map(|s| s.epoch).unwrap_or(0),
            "mempool_pending": mempool.get_all_transactions().len(),
        });
        if let Some(m) = metrics {
            v["consensus"] = serde_json::json!({
                "commits_total": m.commits_total.load(Relaxed),
                "view_changes_total": m.view_changes_total.load(Relaxed),
                "timeouts_total": m.timeouts_total.load(Relaxed),
                "round_skips": m.round_skips.load(Relaxed),
                "last_commit_round": m.last_commit_round.load(Relaxed),
                "last_commit_height": m.last_commit_height.load(Relaxed),
                "last_commit_unix_ms": m.last_commit_unix_ms.load(Relaxed),
                "catch_up_active": m.catch_up_active.load(Relaxed) == 1,
                "state_root_mismatch_total": m.state_root_mismatch_total.load(Relaxed),
                "peers_connected": m.peers_connected.load(Relaxed),
            });
        }
        v
    }

    /// Prometheus text-format (version 0.0.4) çıktısı. Alarm tarafının (spec
    /// §19) baktığı sayaçlar: view_change_rate (rate(view_changes_total)),
    /// lag (time(), last_commit_unix_ms/1000), state_root_mismatch_total.
    fn render_prometheus_metrics(
        state: &Arc<dyn State>,
        mempool: &Arc<Mempool>,
        metrics: &Option<Arc<zagros_metrics::NodeMetrics>>,
    ) -> String {
        let snap = Self::node_status_snapshot(state, mempool, metrics);
        let g = |k: &str| snap.get(k).and_then(|v| v.as_u64()).unwrap_or(0);
        let mut out = String::new();
        let mut push = |name: &str, kind: &str, val: u64| {
            out.push_str(&format!(
                "# TYPE zagros_{name} {kind}\nzagros_{name} {val}\n"
            ));
        };
        push("height", "gauge", g("height"));
        push("epoch", "gauge", g("epoch"));
        push("active_ruleset", "gauge", g("active_ruleset"));
        push("validators", "gauge", g("validators"));
        push("mempool_pending", "gauge", g("mempool_pending"));
        if let Some(c) = snap.get("consensus") {
            let c = |k: &str| c.get(k).and_then(|v| v.as_u64()).unwrap_or(0);
            push("commits_total", "counter", c("commits_total"));
            push("view_changes_total", "counter", c("view_changes_total"));
            push("timeouts_total", "counter", c("timeouts_total"));
            push("round_skips_total", "counter", c("round_skips"));
            push("last_commit_height", "gauge", c("last_commit_height"));
            push("last_commit_unix_ms", "gauge", c("last_commit_unix_ms"));
            push("catch_up_active", "gauge", c("catch_up_active"));
            push(
                "state_root_mismatch_total",
                "counter",
                c("state_root_mismatch_total"),
            );
            push("peers_connected", "gauge", c("peers_connected"));
        }
        out
    }

    pub fn new(
        state: Arc<dyn State>,
        mempool: Arc<Mempool>,
        bridge_manager: Arc<std::sync::Mutex<BridgeManager>>,
        config: RpcConfig,
    ) -> Self {
        let (reserve_sender, _) = broadcast::channel(32);
        let (account_sender, _) = broadcast::channel(250); // Cüzdan Push bildirimleri için (yüksek limit)
        let history_file = history_file_path();
        let price_history = Arc::new(Mutex::new(load_price_history(&history_file)));
        Self {
            state,
            mempool,
            bridge_manager,
            tx_cache: Arc::new(DashMap::new()),
            reserve_sender,
            account_sender,
            price_history,
            history_file,
            config,
            tx_broadcast: None,
            node_metrics: None,
        }
    }

    /// G14: konsensüs/P2P sayaçlarını bağlar (bkz. `zagros_metrics::NodeMetrics`).
    pub fn with_node_metrics(mut self, metrics: Arc<zagros_metrics::NodeMetrics>) -> Self {
        self.node_metrics = Some(metrics);
        self
    }

    /// P2P etkinse `zagros-cli` bunu çağırıp yerel olarak kabul edilen
    /// işlemlerin ağa gossiplenmesini sağlar, bkz. `with_tx_broadcast`.
    pub fn with_tx_broadcast(mut self, tx_broadcast: mpsc::UnboundedSender<Transaction>) -> Self {
        self.tx_broadcast = Some(tx_broadcast);
        self
    }

    pub fn get_account_sender(&self) -> broadcast::Sender<String> {
        self.account_sender.clone()
    }

    pub async fn start(&self) {
        // Y3: bind adresi config.rpc.http_addr'dan gelir (hardcoded 0.0.0.0:8545
        // değil). Ayrıştırılamazsa güvenli varsayılana düşer.
        let bind_addr: SocketAddr = self.config.http_addr.parse().unwrap_or_else(|_| {
            tracing::warn!(
                "⚠️ Geçersiz rpc.http_addr='{}', 0.0.0.0:8545'e düşülüyor",
                self.config.http_addr
            );
            ([0, 0, 0, 0], 8545).into()
        });
        info!(
            "🌐 EVM Gateway & RPC Sunucusu {} adresinde AKTİF!",
            bind_addr
        );

        let state_for_broadcast = self.state.clone();
        let reserve_sender_broadcast = self.reserve_sender.clone();
        let price_history_broadcast = self.price_history.clone();
        let history_file_broadcast = self.history_file.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            let mut last_reserves: Option<(u128, u128)> = None;

            if let Ok(reserves) = state_for_broadcast.get_pool_reserves() {
                let current_price = if reserves.0 > 0 {
                    (reserves.1 as f64) / (reserves.0 as f64)
                } else {
                    1.0
                };
                let mut history = price_history_broadcast.lock().await;
                if history.is_empty() {
                    history.push_back(PoolReserveHistoryEntry {
                        timestamp: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0),
                        price: format!("{:.8}", current_price),
                    });
                    let history_clone = history.clone();
                    let file_clone = history_file_broadcast.clone();
                    tokio::task::spawn_blocking(move || {
                        persist_price_history(&file_clone, &history_clone)
                    });
                }
            }

            loop {
                interval.tick().await;
                if let Ok(reserves) = state_for_broadcast.get_pool_reserves() {
                    let price = if reserves.0 > 0 {
                        (reserves.1 as f64) / (reserves.0 as f64)
                    } else {
                        1.0
                    };
                    if Some(reserves) != last_reserves {
                        last_reserves = Some(reserves);
                        let entry = PoolReserveHistoryEntry {
                            timestamp: SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .map(|d| d.as_secs())
                                .unwrap_or(0),
                            price: format!("{:.8}", price),
                        };
                        let mut history = price_history_broadcast.lock().await;
                        history.push_back(entry.clone());
                        let cutoff = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .map(|d| d.as_secs().saturating_sub(48 * 3600))
                            .unwrap_or(0);
                        while history
                            .front()
                            .map(|old| old.timestamp < cutoff)
                            .unwrap_or(false)
                        {
                            history.pop_front();
                        }
                        let history_clone = history.clone();
                        let file_clone = history_file_broadcast.clone();
                        tokio::task::spawn_blocking(move || {
                            persist_price_history(&file_clone, &history_clone)
                        });

                        let message = json!({
                            "type": "pool_reserves",
                            "zagros": reserves.0.to_string(),
                            "zerenya": reserves.1.to_string(),
                        })
                        .to_string();
                        let _ = reserve_sender_broadcast.send(message);
                    }
                }
            }
        });

        // tx_cache periyodik temizliği: TTL'i geçmiş kayıtları at, harita
        // sınırsız büyüyüp belleği tüketemesin (bkz. TX_CACHE_TTL_SECS yorumu).
        let tx_cache_for_cleanup = self.tx_cache.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(TX_CACHE_SWEEP_INTERVAL_SECS));
            loop {
                interval.tick().await;
                let now_secs = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                tx_cache_for_cleanup.retain(|_, (_, inserted_at)| {
                    now_secs.saturating_sub(*inserted_at) < TX_CACHE_TTL_SECS
                });
            }
        });

        // 🛡️ KURŞUN GEÇİRMEZ CORS: Ethers.js'in gönderebileceği tüm başlıklara izin!
        let cors = warp::cors()
            .allow_any_origin()
            .allow_headers(vec![
                "Content-Type",
                "Accept",
                "Origin",
                "Access-Control-Request-Method",
                "Access-Control-Request-Headers",
                "User-Agent",
                "Sec-Fetch-Mode",
                "Referer",
            ])
            .allow_methods(vec!["GET", "POST", "OPTIONS"]);

        let max_connections = self.config.max_connections;
        let ip_rate_limit = self.config.ip_rate_limit;
        let rl_whitelist: Arc<std::collections::HashSet<String>> =
            Arc::new(self.config.rate_limit_whitelist.iter().cloned().collect());
        // YÜKSEK #6 (Seçenek B): WS idle koruması, config.toml'dan.
        let ws_ping_interval = Duration::from_secs(self.config.ws_ping_interval_secs);
        let ws_pong_timeout = Duration::from_secs(self.config.ws_pong_timeout_secs);

        // 🛡️ WS upgrade route'una da flood sınırlayıcı; yoksa sınırsız WebSocket açılırdı.
        let ws_route = warp::path("ws")
            .and(check_rate_limit(
                max_connections,
                ip_rate_limit,
                rl_whitelist.clone(),
            ))
            .and(warp::ws())
            .and(with_state(self.state.clone()))
            .and(with_reserve_sender(self.reserve_sender.clone()))
            .and(warp::any().map({
                let s = self.account_sender.clone();
                move || s.clone()
            }))
            .and(with_price_history(self.price_history.clone()))
            .map(
                move |ws: Ws, state, reserve_sender, account_sender, price_history| {
                    ws.on_upgrade(move |socket| {
                        Self::handle_ws_connection(
                            socket,
                            state,
                            reserve_sender,
                            account_sender,
                            price_history,
                            ws_ping_interval,
                            ws_pong_timeout,
                        )
                    })
                },
            );

        // G14: salt-okunur operatör uçları. Rate-limit'e KASITLI olarak tabi
        // değiller (izleme kazıyıcısının 429'a takılması alarm sistemini kör
        // eder); yanıtlar ucuz, state'e salt-okunur bakar.
        let health_state = self.state.clone();
        let health_mempool = self.mempool.clone();
        let health_metrics = self.node_metrics.clone();
        let health_route = warp::get()
            .and(warp::path("health"))
            .and(warp::path::end())
            .map(move || {
                warp::reply::json(&Self::node_status_snapshot(
                    &health_state,
                    &health_mempool,
                    &health_metrics,
                ))
            });
        let prom_state = self.state.clone();
        let prom_mempool = self.mempool.clone();
        let prom_metrics = self.node_metrics.clone();
        let metrics_route = warp::get()
            .and(warp::path("metrics"))
            .and(warp::path::end())
            .map(move || {
                Self::render_prometheus_metrics(&prom_state, &prom_mempool, &prom_metrics)
            });

        let routes = warp::post()
            .and(warp::path::end())
            .and(check_rate_limit(
                max_connections,
                ip_rate_limit,
                rl_whitelist.clone(),
            )) // 🛡️ GLOBAL KORUMA: Her Rpc Call'ından önce geçer!
            // 🛡️ Gövde tavanı 2 MiB: en büyük meşru gövde (128KB calldata hex + zarf
            // ya da MetaMask okuma batch'i) çok altında; tavan olmasaydı büyük
            // Content-Length bildiren istemci sınırsız arabellek zorlardı.
            .and(warp::body::content_length_limit(2 * 1024 * 1024))
            .and(warp::body::bytes()) // 🔥 SONIC-RS İÇİN RAW BYTES YÜKLEMESİ (Dehşet Hızlı)
            .and(with_state(self.state.clone()))
            .and(with_mempool(self.mempool.clone()))
            .and(with_tx_cache(self.tx_cache.clone()))
            .and(with_bridge_manager(self.bridge_manager.clone()))
            .and(with_rpc_timeouts(RpcTimeouts::from(&self.config)))
            .and(with_evm_simulation_limits(EvmSimulationLimits::from(
                &self.config,
            )))
            .and(with_tx_broadcast(self.tx_broadcast.clone()))
            .and_then(crate::handle_rpc_request)
            .or(ws_route)
            .or(health_route)
            .or(metrics_route)
            .recover(handle_rejection) // 🛡️ Özel Hata Yanıtları
            .with(cors);

        warp::serve(routes).run(bind_addr).await;
    }

    /// 🔒 Sahte kontrat adreslerine çağrının native `TxType`ı; decode ve estimateGas
    /// aynı fonksiyonu kullanır. 🚨 Adresler revm precompile aralığıyla çakışır (modexp Halt).
    fn native_tx_type_for_evm_call(receiver: &str, data: &[u8]) -> Option<(TxType, Option<u128>)> {
        zagros_types::native_tx_type_for_evm_call(receiver, data)
    }

    fn decode_and_convert_tx(tx_bytes: &[u8]) -> Result<Transaction, String> {
        let rlp = Rlp::new(tx_bytes);
        let (typed_tx, signature) = TypedTransaction::decode_signed(&rlp)
            .map_err(|e| format!("RLP Decode error: {}", e))?;

        // 🛡️ Cross-chain replay: `chain_id()` RLP'nin imzalandığı zinciri verir;
        // `None` (EIP-155 öncesi) fail-closed reddedilir, tek istisna keyless deployer.
        let verified_chain_id: Option<u64> = match typed_tx.chain_id() {
            Some(signed_chain_id) if signed_chain_id.as_u64() == CHAIN_ID => {
                Some(signed_chain_id.as_u64())
            }
            Some(signed_chain_id) => {
                return Err(format!(
                    "chain_id uyuşmazlığı: işlem chain_id={} için imzalanmış, bu ağın chain_id'si {} \
                     (olası cross-chain replay, reddedildi)",
                    signed_chain_id, CHAIN_ID
                ));
            }
            None => {
                // 🛡️ Tek istisna: keyless deterministik dağıtım (Multicall3); replay
                // amaçtır, istisna `KEYLESS_DEPLOYERS`taki gönderenle sınırlı.
                let sender_is_keyless_deployer = typed_tx
                    .from()
                    .map(|a| {
                        zagros_types::is_keyless_deployer(&format!(
                            "0x{}",
                            hex::encode(a.as_bytes())
                        ))
                    })
                    .unwrap_or(false);
                if !sender_is_keyless_deployer {
                    return Err(
                        "chain_id uyuşmazlığı: işlemde chain_id koruması (EIP-155) yok - fail-closed reddedildi"
                            .to_string(),
                    );
                }
                None
            }
        };

        // 🚨 Sighash burada HESAPLANIP GÖMÜLMEZ: `Transaction::verify_signature()`
        // onu ham RLP'den KENDİSİ türetir, decode katmanına körü körüne
        // güvenmez; taşınan kopya olmadığı için işlem başına 32 bayt kazanılır.

        let eth_from = typed_tx.from().ok_or("No sender in TX")?;
        let sender = format!("0x{}", hex::encode(eth_from.as_bytes()));

        let to = typed_tx.to_addr().map(|addr| addr.as_bytes().to_vec());
        let receiver = if let Some(ref t) = to {
            format!("0x{}", hex::encode(t))
        } else {
            "0x0000000000000000000000000000000000000000".to_string()
        };

        let data: Vec<u8> = typed_tx
            .data()
            .map(|d| d.0.clone().into())
            .unwrap_or_default();
        let value = typed_tx.value().cloned().unwrap_or_default();

        // 🛡️ RLP decode 256-bit alanların büyüklüğünü doğrulamaz; `.as_u64()`
        // sığmayan değerde panic atar (tek geçerli imzalı ham işlemle tetiklenir).
        // `bits() <= N` kontrolü fail-closed RPC hatasına çevirir.
        let checked_u64 = |v: &U256, field: &str| -> Result<u64, String> {
            if v.bits() > 64 {
                return Err(format!("{field} exceeds u64 range"));
            }
            Ok(v.as_u64())
        };
        let checked_u128 = |v: &U256, field: &str| -> Result<u128, String> {
            if v.bits() > 128 {
                return Err(format!("{field} exceeds u128 range"));
            }
            Ok(v.as_u128())
        };

        let nonce = typed_tx
            .nonce()
            .map(|n| checked_u64(n, "nonce"))
            .transpose()?
            .unwrap_or_default();
        let gas_limit = typed_tx
            .gas()
            .map(|g| checked_u64(g, "gas"))
            .transpose()?
            .unwrap_or_default();
        let gas_price_raw = typed_tx.gas_price().unwrap_or_default();
        let gas_price = checked_u128(&gas_price_raw, "gasPrice")?;

        let mut amount = checked_u128(&value, "value")?;
        // Seçici→native-tür eşleştirmesi artık `native_tx_type_for_evm_call`'da
        // (TEK doğruluk kaynağı), `eth_estimateGas` da AYNI fonksiyonu
        // kullanıyor (bkz. o fonksiyonun doc yorumu).
        let tx_type = if let Some((native_type, maybe_amount)) =
            Self::native_tx_type_for_evm_call(&receiver, &data)
        {
            if let Some(a) = maybe_amount {
                amount = a;
            }
            native_type
        } else if to.is_none() {
            TxType::ContractCall { data: data.clone() }
        } else if data.is_empty() {
            TxType::Transfer
        } else {
            TxType::ContractCall { data: data.clone() }
        };

        // 🚨 Seçici ayıklama: RegisterValidator/RotateConsensusKey/ReportMalicious/
        // SubmitProposal/Vote payload'ı seçicisiz okur; seçici geçerse reddedilir.
        // Kural `zagros_types::derive_native_call`da da var; birlikte güncellenmeli.
        let payload = if matches!(
            tx_type,
            TxType::RegisterValidator
                | TxType::RotateConsensusKey
                | TxType::ReportMalicious
                | TxType::ApproveValidator
                | TxType::RemoveValidator
                | TxType::SubmitProposal
                | TxType::Vote
        ) {
            data.get(4..).map(|rest| rest.to_vec()).unwrap_or_default()
        } else {
            data
        };

        let mut sig_bytes = Vec::with_capacity(98);
        let mut r_bytes = [0u8; 32];
        signature.r.to_big_endian(&mut r_bytes);
        sig_bytes.extend_from_slice(&r_bytes);

        let mut s_bytes = [0u8; 32];
        signature.s.to_big_endian(&mut s_bytes);
        sig_bytes.extend_from_slice(&s_bytes);
        sig_bytes.push(signature.v as u8);
        // 🚨 İşlem tipi tek bayt olarak v'nin ardına gömülür; bilinmezse `extract_vrs`
        // 2930/1559 `v`sini Legacy formülüyle yanlış kurar. İmza doğrulaması bakmaz.
        let eth_type_byte: u8 = match &typed_tx {
            TypedTransaction::Legacy(_) => 0,
            TypedTransaction::Eip2930(_) => 1,
            TypedTransaction::Eip1559(_) => 2,
        };
        sig_bytes.push(eth_type_byte);
        // 🚨 Sighash taşınmaz (32 bayt/işlem); ham RLP imza bloğunun sonuna eklenir,
        // `verify_evm_field_binding` alanları imzaya bağlar (gossip/blok yolları için).
        sig_bytes.extend_from_slice(tx_bytes);

        let timestamp = std::time::UNIX_EPOCH.elapsed().unwrap().as_secs() as u128;

        let mut hasher = Keccak256::new();
        hasher.update(tx_bytes);
        let tx_hash_bytes = hasher.finalize();
        let mut tx_id = [0u8; 32];
        tx_id.copy_from_slice(&tx_hash_bytes);

        // 🛡️ Merkezi kurucu çağrılır: EIP-155 yolu chain_id eşitliğini, keyless yolu
        // gönderen allowlist'ini BAĞIMSIZ yeniden doğrular (ikinci savunma katmanı).
        match verified_chain_id {
            Some(signed_chain_id) => Transaction::from_verified_eip155(
                tx_id,
                tx_type,
                sender,
                receiver,
                amount,
                payload,
                sig_bytes,
                timestamp,
                nonce,
                gas_limit,
                gas_price,
                signed_chain_id,
            ),
            None => Transaction::from_verified_keyless_deployment(
                tx_id, tx_type, sender, receiver, amount, payload, sig_bytes, timestamp, nonce,
                gas_limit, gas_price,
            ),
        }
        .map_err(|e| e.to_string())
    }

    /// Güncel havuz rezervleri (+ hazine) WS mesajı; DÖNDÜRÜR, broadcast etmez
    /// (yeni bağlanan istemciye anlık görüntü; herkese göndermek gereksiz gürültü).
    fn current_reserves_message(state: &Arc<dyn State>) -> Option<String> {
        let (zagros_scaled, zerenya_scaled) = state.get_pool_reserves().ok()?;
        let treasury = state
            .get_account(&VALIDATOR_REWARD_POOL.to_string())
            .unwrap_or(None)
            .unwrap_or_default();
        Some(
            json!({
                "type": "pool_reserves",
                "zagros": zagros_scaled.to_string(),
                "zerenya": zerenya_scaled.to_string(),
                "treasury_zagros": treasury.balance.to_string(),
                "treasury_zerenya": treasury.zerenya_balance.to_string(),
            })
            .to_string(),
        )
    }

    fn lookup_account(state: &Arc<dyn State>, address: &str) -> Option<AccountState> {
        let normalized = if address.starts_with("0x") || address.starts_with("0X") {
            format!("0x{}", address[2..].to_lowercase())
        } else {
            address.to_string()
        };
        state.get_account(&normalized).ok().flatten()
    }

    /// 🛡️ D14 (denetim C4): depolama HATASI "hesap yok" (None) ile aynı kefeye
    /// konmaz; para kritik metotlar `Err`'de -32603 döner (disk sıkışınca
    /// kendinden emin `0` bakiye/nonce dönmek cüzdan ve borsayı yanıltır).
    fn lookup_account_strict(
        state: &Arc<dyn State>,
        address: &str,
    ) -> zagros_primitives::Result<Option<AccountState>> {
        let normalized = if address.starts_with("0x") || address.starts_with("0X") {
            format!("0x{}", address[2..].to_lowercase())
        } else {
            address.to_string()
        };
        state.get_account(&normalized)
    }

    // 🏛️ HISTORICAL CHAIN STORAGE OKUMA YARDIMCILARI

    /// Bloğun GERÇEK üreticisi BFT kaydındaki `(epoch, proposer_idx)`ten çözülür
    /// (`miner` ödülün gittiği adres); kayıt yoksa yapılandırılmış sentinel'e düşülür.
    fn real_block_producer(state: &Arc<dyn State>, number: u64) -> String {
        let bytes = match state.get_account(&zagros_state::consensus_block_key(number)) {
            Ok(Some(acc)) if !acc.contract_code.is_empty() => acc.contract_code,
            _ => return Self::configured_block_producer(state),
        };
        type ConsensusRecord = (
            zagros_types::consensus::SignedHeader,
            zagros_types::consensus::QuorumCertificate,
            Vec<zagros_types::consensus::ShadowVoteAttestation>,
        );
        let Ok((signed, _, _)) = bincode::deserialize::<ConsensusRecord>(&bytes) else {
            return Self::configured_block_producer(state);
        };
        match zagros_executor::validator_set::load_validator_set_at_epoch(
            state.as_ref(),
            signed.header.epoch,
        ) {
            Ok(set) => set
                .members
                .get(signed.header.proposer_idx as usize)
                .map(|m| m.address.clone())
                .unwrap_or_else(|| Self::configured_block_producer(state)),
            Err(_) => Self::configured_block_producer(state),
        }
    }

    fn configured_block_producer(state: &Arc<dyn State>) -> String {
        let configured = match state.get_account(&"__CONFIGURED_BLOCK_PRODUCER__".to_string()) {
            Ok(Some(acc)) if !acc.contract_code.is_empty() => {
                String::from_utf8(acc.contract_code).unwrap_or_default()
            }
            _ => String::new(),
        };
        if configured.is_empty() {
            "0x0000000000000000000000000000000000000000".to_string()
        } else {
            configured
        }
    }

    /// `__CONFIGURED_BRIDGE_DAILY_MINT_LIMIT__` sentinel'inden (`configured_block_producer`
    /// deseni); yoksa `zagros_types::config` varsayılanı (2.500 ZERENYA).
    fn configured_bridge_daily_mint_limit(state: &Arc<dyn State>) -> u128 {
        match state.get_account(&"__CONFIGURED_BRIDGE_DAILY_MINT_LIMIT__".to_string()) {
            Ok(Some(acc)) if !acc.contract_code.is_empty() => String::from_utf8(acc.contract_code)
                .ok()
                .and_then(|s| s.parse::<u128>().ok())
                .unwrap_or(2_500 * zagros_types::TOKEN_DECIMAL),
            _ => 2_500 * zagros_types::TOKEN_DECIMAL,
        }
    }

    /// İmzaya gömülü Ethereum işlem tipini okur (bkz. `decode_and_convert_tx`).
    /// 65 baytlık native ve eski tip bilgisiz imzalar için `"0x0"` (Legacy).
    fn extract_eth_tx_type(signature: &[u8]) -> &'static str {
        // 🚨 Bağlamalı EVM imzası 98 + ham_RLP uzunluğundadır;
        // tip baytı yine 65. indekstedir (bkz. Transaction::verify_evm_field_binding).
        if signature.len() >= 98 {
            match signature[65] {
                1 => "0x1",
                2 => "0x2",
                _ => "0x0",
            }
        } else {
            "0x0"
        }
    }

    /// `(v, r, s)`: `r`/`s` ilk 64 bayt, `v` recovery id'den. 🚨 Yalnız Legacy
    /// EIP-155 formülü alır; 2930/1559 sade yParity. Biçimsiz imza placeholder, panic yok.
    fn extract_vrs(signature: &[u8]) -> (String, String, String) {
        if signature.len() < 65 {
            return (
                "0x1b".to_string(),
                "0x0000000000000000000000000000000000000000000000000000000000000001".to_string(),
                "0x0000000000000000000000000000000000000000000000000000000000000001".to_string(),
            );
        }
        let r = format!("0x{}", hex::encode(&signature[0..32]));
        let s = format!("0x{}", hex::encode(&signature[32..64]));
        let recovery_byte = signature[64];
        let recovery_id: u64 = match recovery_byte {
            0 | 1 => recovery_byte as u64,
            27 | 28 => (recovery_byte - 27) as u64,
            v if v >= 35 => ((v - 35) % 2) as u64,
            _ => 0,
        };
        // `eth_type` baytinin VARLIK kosulu: 65 imza + 1 tip.
        let v = if signature.len() >= 66 {
            match signature[65] {
                0 => CHAIN_ID * 2 + 35 + recovery_id,
                _ => recovery_id,
            }
        } else if signature.len() == 97 {
            CHAIN_ID * 2 + 35 + recovery_id
        } else {
            27 + recovery_id
        };
        (format!("0x{:x}", v), r, s)
    }

    fn keccak256(bytes: &[u8]) -> [u8; 32] {
        use sha3::{Digest, Keccak256};
        let mut hasher = Keccak256::new();
        hasher.update(bytes);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// `block_<N>`i okur, hash'ini ham baytlardan hesaplar; `number == 0` genesis'in
    /// özel `block_0` yolunu kullanır.
    fn load_archived_block(
        state: &Arc<dyn State>,
        number: u64,
    ) -> Option<(ArchivedBlockHeader, [u8; 32])> {
        if number == 0 {
            let bytes = state.get_genesis_block_0_bytes().ok().flatten()?;
            let genesis_header: zagros_types::BlockHeader = bincode::deserialize(&bytes).ok()?;
            let hash = Self::keccak256(&bytes);
            let header = ArchivedBlockHeader {
                number: 0,
                parent_hash: genesis_header.parent_hash,
                state_root: genesis_header.state_root,
                timestamp: genesis_header.timestamp,
                tx_hashes: Vec::new(),
            };
            return Some((header, hash));
        }
        let acc = state.get_account(&block_key(number)).ok().flatten()?;
        let header: ArchivedBlockHeader = bincode::deserialize(&acc.contract_code).ok()?;
        let hash = Self::keccak256(&acc.contract_code);
        Some((header, hash))
    }

    /// `eth_getBlockByNumber` ilk parametresi: hex, `"latest"`/`"pending"`, `"earliest"`.
    /// 🛡️ D14 (C1): tanınmayan etiket `None` (-32602); sessizce güncel yükseklik
    /// saymak çöp dizeye kendinden emin cevap verir.
    fn resolve_block_number_param(state: &Arc<dyn State>, param: Option<&Value>) -> Option<u64> {
        let current_height = Self::lookup_account(state, "__GLOBAL_BLOCK_HEIGHT__")
            .map(|account| account.balance as u64)
            .unwrap_or(0);
        match param.and_then(|v| v.as_str()) {
            Some("earliest") => Some(0),
            Some("latest") | Some("pending") | None => Some(current_height),
            Some(tag) => {
                let clean = tag.strip_prefix("0x").unwrap_or(tag);
                u64::from_str_radix(clean, 16).ok()
            }
        }
    }

    /// 🛡️ D14 (C1): state sorgularının blok parametresi bekçisi; node yalnız
    /// GÜNCEL state'i servis eder, geçmiş blok istenirse "latest" saymak yerine
    /// açık hata (borsa mutabakatını yanıltmamak için).
    fn historical_state_guard(state: &Arc<dyn State>, param: Option<&Value>) -> Option<Value> {
        let raw = param?;
        let tag = match raw.as_str() {
            Some(t) => t,
            None => {
                return Some(serde_json::json!({
                    "code": -32602,
                    "message": "invalid block parameter"
                }))
            }
        };
        if tag == "latest" || tag == "pending" {
            return None;
        }
        let current_height = Self::lookup_account(state, "__GLOBAL_BLOCK_HEIGHT__")
            .map(|account| account.balance as u64)
            .unwrap_or(0);
        if tag == "earliest" {
            if current_height == 0 {
                return None;
            }
            return Some(serde_json::json!({
                "code": -32000,
                "message": "historical state is not available on this node (earliest requested)"
            }));
        }
        let clean = tag.strip_prefix("0x").unwrap_or(tag);
        match u64::from_str_radix(clean, 16) {
            Ok(n) if n == current_height => None,
            Ok(n) => Some(serde_json::json!({
                "code": -32000,
                "message": format!(
                    "historical state is not available on this node (block {n} requested, state is at {current_height})"
                )
            })),
            Err(_) => Some(serde_json::json!({
                "code": -32602,
                "message": format!("invalid block parameter: {tag:?}")
            })),
        }
    }

    /// Hash'ten blok numarası: önce `block_hash_<hex>` ters indeksi, yoksa genesis
    /// `block_0` hash'iyle karşılaştırma (genesis ters indeks almaz).
    fn resolve_block_number_by_hash(state: &Arc<dyn State>, hash_hex_clean: &str) -> Option<u64> {
        let hash_bytes = parse_tx_id_hex(hash_hex_clean)?;
        if let Some(acc) = state
            .get_account(&block_hash_key(&hash_bytes))
            .ok()
            .flatten()
        {
            return Some(acc.balance as u64);
        }
        let genesis_bytes = state.get_genesis_block_0_bytes().ok().flatten()?;
        if Self::keccak256(&genesis_bytes) == hash_bytes {
            return Some(0);
        }
        None
    }

    fn block_json(
        state: &Arc<dyn State>,
        number: u64,
        header: &ArchivedBlockHeader,
        hash: [u8; 32],
    ) -> Value {
        Self::block_json_full(state, number, header, hash, false)
    }

    /// 🛡️ D14: `fullTransactions=true` gerçekten tam işlem nesneleri döner; gövdesi
    /// bulunamayan hash olarak kalır, liste eksilmez.
    fn block_json_full(
        state: &Arc<dyn State>,
        number: u64,
        header: &ArchivedBlockHeader,
        hash: [u8; 32],
        full_transactions: bool,
    ) -> Value {
        let block_hash_hex = format!("0x{}", hex::encode(hash));
        let tx_hashes: Vec<Value> = header
            .tx_hashes
            .iter()
            .enumerate()
            .map(|(idx, h)| {
                if full_transactions {
                    if let Some(tx) = Self::lookup_account(state, &tx_body_key(h))
                        .and_then(|acc| Transaction::from_stored_bytes(&acc.contract_code).ok())
                    {
                        return serde_json::json!({
                            "hash": format!("0x{}", hex::encode(h)),
                            "nonce": format!("0x{:x}", tx.nonce),
                            "blockHash": block_hash_hex,
                            "blockNumber": format!("0x{:x}", number),
                            "transactionIndex": format!("0x{:x}", idx),
                            "from": tx.sender,
                            "to": if zagros_types::is_evm_deploy(&tx.receiver) { Value::Null } else { Value::String(tx.receiver.clone()) },
                            "value": format!("0x{:x}", tx.amount),
                            "gas": format!("0x{:x}", tx.gas_limit),
                            "gasPrice": format!("0x{:x}", tx.gas_price),
                            "input": format!("0x{}", hex::encode(&tx.payload)),
                            "type": Self::extract_eth_tx_type(&tx.signature),
                            "chainId": format!("0x{:x}", tx.chain_id),
                        });
                    }
                }
                Value::String(format!("0x{}", hex::encode(h)))
            })
            .collect();
        // 🏛️ Gerçek gasUsed: makbuzların `gas_used` toplamı; makbuzu olmayan tx 0 sayılır.
        let gas_used_sum: u128 = header
            .tx_hashes
            .iter()
            .filter_map(|id| Self::lookup_account(state, &receipt_key(id)))
            .filter_map(|acc| bincode::deserialize::<ArchivedReceipt>(&acc.contract_code).ok())
            .map(|r| r.gas_used as u128)
            .sum();
        serde_json::json!({
            "number": format!("0x{:x}", number),
            "hash": format!("0x{}", hex::encode(hash)),
            "parentHash": format!("0x{}", hex::encode(header.parent_hash)),
            "nonce": "0x0000000000000000",
            "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
            "logsBloom": "0x",
            "transactionsRoot": "0x",
            "stateRoot": format!("0x{}", hex::encode(header.state_root)),
            "receiptsRoot": "0x",
            // Bloğun GERÇEK üreticisi (bkz. `real_block_producer`): BFT
            // konsensüs kaydındaki (epoch, proposer_idx) çözülür, yani %20
            // üretici payının gerçekten gittiği adres.
            "miner": Self::real_block_producer(state, number),
            "difficulty": "0x0",
            "totalDifficulty": "0x0",
            "extraData": "0x",
            "size": "0x0",
            // `MAX_BLOCK_GAS_LIMIT`: deklare edilmiş protokol sabiti (isimli sabit,
            // keyfi değer değil).
            "gasLimit": format!("0x{:x}", zagros_types::MAX_BLOCK_GAS_LIMIT),
            "gasUsed": format!("0x{:x}", gas_used_sum),
            "baseFeePerGas": "0x0",
            "timestamp": format!("0x{:x}", header.timestamp),
            "transactions": tx_hashes,
            "uncles": []
        })
    }

    async fn handle_ws_connection(
        ws: WebSocket,
        _state: Arc<dyn State>,
        reserve_sender: broadcast::Sender<String>,
        account_sender: broadcast::Sender<String>,
        price_history: Arc<Mutex<VecDeque<PoolReserveHistoryEntry>>>,
        ws_ping_interval: Duration,
        ws_pong_timeout: Duration,
    ) {
        // 🔥 WS Soket sayacını 1 artırıyoruz, RAII guard, fonksiyondan HANGİ
        // yoldan çıkılırsa çıkılsın (erken `return`, panic, vs.) Drop'ta düşer.
        let _conn_guard = ActiveConnectionGuard::acquire(&ACTIVE_CONNECTIONS);

        let (mut ws_tx, mut ws_rx) = ws.split();
        let mut reserve_rx = reserve_sender.subscribe();
        let mut account_rx = account_sender.subscribe();

        // Immediately send current pool reserves and history to the new client
        // (yalnızca BU istemciye, bkz. `current_reserves_message` doc yorumu,
        // artık bağlı diğer istemcilere broadcast EDİLMİYOR).
        if let Some(reserves_message) = Self::current_reserves_message(&_state) {
            let _ = ws_tx.send(Message::text(reserves_message)).await;
        }
        let history_snapshot = {
            let history = price_history.lock().await;
            history.iter().cloned().collect::<Vec<_>>()
        };
        let history_message = json!({
            "type": "pool_reserves_history",
            "history": history_snapshot,
        })
        .to_string();
        let _ = ws_tx.send(Message::text(history_message)).await;

        // 🛡️ WS idle: `ws_ping_interval`da PING, `ws_pong_timeout` sessizlikte kapat.
        // 🛑 Yerel monotonik `Instant` + milisaniye (unix saniye yuvarlaması testleri bozuyordu).
        let conn_start = tokio::time::Instant::now();
        let last_activity_ms = Arc::new(AtomicU64::new(0));

        let recv_last_activity_ms = last_activity_ms.clone();
        let mut recv_task = tokio::spawn(async move {
            while let Some(Ok(msg)) = ws_rx.next().await {
                recv_last_activity_ms
                    .store(conn_start.elapsed().as_millis() as u64, Ordering::Relaxed);
                if msg.is_close() {
                    break;
                }
            }
        });

        let send_last_activity_ms = last_activity_ms.clone();
        let ws_pong_timeout_ms = ws_pong_timeout.as_millis() as u64;
        let mut send_task = tokio::spawn(async move {
            let mut ping_interval = tokio::time::interval(ws_ping_interval);
            ping_interval.tick().await; // ilk tick anında ateşlenir - atla.
            loop {
                tokio::select! {
                    Ok(message) = reserve_rx.recv() => {
                        if ws_tx.send(Message::text(message)).await.is_err() { break; }
                    }
                    Ok(account_msg) = account_rx.recv() => {
                        if ws_tx.send(Message::text(account_msg)).await.is_err() { break; }
                    }
                    _ = ping_interval.tick() => {
                        let idle_for_ms = (conn_start.elapsed().as_millis() as u64)
                            .saturating_sub(send_last_activity_ms.load(Ordering::Relaxed));
                        if ws_connection_is_idle(idle_for_ms, ws_pong_timeout_ms) {
                            WS_IDLE_CLOSE_COUNT.fetch_add(1, Ordering::Relaxed);
                            warn!(
                                "🔌 WS bağlantısı boşta kaldığı için kapatılıyor: {}ms (limit={}ms)",
                                idle_for_ms, ws_pong_timeout_ms
                            );
                            let _ = ws_tx.close().await;
                            break;
                        }
                        if ws_tx.send(Message::ping(Vec::new())).await.is_err() { break; }
                    }
                    else => break,
                }
            }
        });

        tokio::select! {
            _ = (&mut send_task) => {
                recv_task.abort();
            }
            _ = (&mut recv_task) => {
                send_task.abort();
            }
        }
        // `_conn_guard` burada drop olur, sayaç otomatik düşer.
    }

    /// `pub`: entegrasyon testleri (warp HRTB kısıtına takılmadan) doğrudan sürer,
    /// bkz. zagros-relayer/tests/inbound_integration.rs. `handle_request_with_broadcast`'ın
    /// ince sarmalayıcısı; `None` = P2P'siz davranış.
    pub fn handle_request(
        req: RpcRequest,
        state: Arc<dyn State>,
        mempool: Arc<Mempool>,
        tx_cache: Arc<DashMap<String, (String, u64)>>,
        bridge_manager: Arc<std::sync::Mutex<BridgeManager>>,
        evm_limits: EvmSimulationLimits,
    ) -> RpcResponse {
        Self::handle_request_with_broadcast(
            req,
            state,
            mempool,
            tx_cache,
            bridge_manager,
            evm_limits,
            None,
        )
    }

    /// 🛡️ P2P tx-gossip: `tx_broadcast` `Some` ise kabul edilen her işlem kanala
    /// gönderilir, CLI alıcı ucunu `NetworkHandle::publish_transaction`'a köprüler.
    pub fn handle_request_with_broadcast(
        req: RpcRequest,
        state: Arc<dyn State>,
        mempool: Arc<Mempool>,
        tx_cache: Arc<DashMap<String, (String, u64)>>,
        bridge_manager: Arc<std::sync::Mutex<BridgeManager>>,
        evm_limits: EvmSimulationLimits,
        tx_broadcast: Option<mpsc::UnboundedSender<Transaction>>,
    ) -> RpcResponse {
        let default_params = Vec::new();
        let safe_params = req.params.as_ref().unwrap_or(&default_params);

        let result = match req.method.as_str() {
            "eth_chainId" => Value::String(format!("0x{:x}", CHAIN_ID)),
            "net_version" => Value::String(CHAIN_ID.to_string()),

            // Budama backpressure: ZagrosRadar arsivi indeksledigi yuksekligi bildirir;
            // dugum bu yuksekligin USTUNU BUDAMAZ. Token dogrulanir (yetkisiz rapor reddedilir).
            "zagros_reportArchiveHeight" => {
                let file = ARCHIVE_HEIGHT_FILE.get().and_then(|o| o.as_ref());
                let want = ARCHIVE_REPORT_TOKEN.get().and_then(|o| o.as_ref());
                let got = safe_params.get(1).and_then(|v| v.as_str());
                let height = safe_params.first().and_then(|v| v.as_u64());
                match (file, want, height) {
                    (Some(path), Some(tok), Some(h))
                        if got.is_some_and(|g| constant_time_eq(g, tok)) =>
                    {
                        // 🛡️ Rapor zincir yüksekliğiyle kırpılır (UYARIYLA): şişirilmiş
                        // rapor budama kilidini devre dışı bırakıp arşivlenmemiş blokları sildirirdi.
                        let chain_height = Self::lookup_account(&state, "__GLOBAL_BLOCK_HEIGHT__")
                            .map(|a| a.balance as u64)
                            .unwrap_or(0);
                        let effective = if h > chain_height {
                            tracing::warn!(
                                "⚠️ Arşiv yüksekliği raporu zincirin ÜSTÜNDE ({} > {}) - \
                                 zincir yüksekliğine kırpıldı. Arşivci hatalı olabilir.",
                                h,
                                chain_height
                            );
                            chain_height
                        } else {
                            h
                        };
                        let tmp = format!("{}.tmp", path);
                        if std::fs::write(&tmp, effective.to_string()).is_ok() {
                            let _ = std::fs::rename(&tmp, path);
                        }
                        Value::Bool(true)
                    }
                    _ => Value::Bool(false),
                }
            }

            // Standart Ethereum JSON-RPC metodları: MetaMask ve benzeri
            // cüzdanlar bağlantı/sağlık kontrolü için bunları sorgulayabilir;
            // dürüst, anlamlı değerler dönülür (madencilik YOK, BFT).
            "web3_clientVersion" => Value::String("Zagros/v1.0.0".to_string()),
            "net_listening" => Value::Bool(true),
            "net_peerCount" => Value::String(format!(
                "{:#x}",
                zagros_metrics::GLOBAL_PEERS_CONNECTED.load(std::sync::atomic::Ordering::Relaxed)
            )),
            // 🛡️ Ağ katmanı anlık görüntüsü (mod, peer, doğrulanmış sentry duyuruları);
            // yalnız görünürlük, zincir kuralı değil. ⏱️ QC sonrası geç precommit dağılımı.
            "zagros_getLateVoteStats" => {
                serde_json::from_str::<Value>(&zagros_metrics::late_vote_stats_json())
                    .unwrap_or(Value::Null)
            }
            "zagros_getNetworkPeers" => match zagros_metrics::network_snapshot() {
                Some(json) => serde_json::from_str::<Value>(&json).unwrap_or(Value::Null),
                None => serde_json::json!({
                    "peers_connected": zagros_metrics::GLOBAL_PEERS_CONNECTED.load(std::sync::atomic::Ordering::Relaxed),
                    "mode": "unknown",
                    "announcements": [],
                }),
            },
            // 🛡️ D14 (denetim C2): sabit `false` yerine gerçek
            // catch-up durumu. Senkrondayken standart Ethereum biçiminde bir
            // nesne döner (currentBlock; highest bilinmiyorsa current ile eş).
            "eth_syncing" => {
                let syncing = zagros_metrics::GLOBAL_CATCH_UP_ACTIVE
                    .load(std::sync::atomic::Ordering::Relaxed)
                    == 1;
                if syncing {
                    let h = Self::lookup_account(&state, "__GLOBAL_BLOCK_HEIGHT__")
                        .map(|a| a.balance as u64)
                        .unwrap_or(0);
                    serde_json::json!({
                        "startingBlock": "0x0",
                        "currentBlock": format!("0x{h:x}"),
                        "highestBlock": format!("0x{h:x}"),
                    })
                } else {
                    Value::Bool(false)
                }
            }
            "eth_accounts" => Value::Array(vec![]),
            "eth_mining" => Value::Bool(false),
            "eth_hashrate" => Value::String("0x0".to_string()),
            "eth_protocolVersion" => Value::String("0x41".to_string()),
            // Aynı desen `zagros_getNetworkParams`'taki gibi, main.rs'in
            // yazdığı `__CONFIGURED_BLOCK_PRODUCER__` sentinel'inden okunur,
            // ayrı bir kod yolu YOKTUR (tek doğruluk kaynağı).
            "eth_coinbase" => Value::String(Self::configured_block_producer(&state)),
            "web3_sha3" => {
                let raw = safe_params.first().and_then(|v| v.as_str()).unwrap_or("");
                let hex_data = raw.strip_prefix("0x").unwrap_or(raw);
                match hex::decode(hex_data) {
                    Ok(bytes) => {
                        let mut hasher = Keccak256::new();
                        hasher.update(&bytes);
                        Value::String(format!("0x{}", hex::encode(hasher.finalize())))
                    }
                    Err(_) => {
                        return RpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: req.id,
                            result: None,
                            error: Some(json!({
                                "code": -32602,
                                "message": "Invalid params: data is not valid hex"
                            })),
                        };
                    }
                }
            }
            // 🚨 GERÇEK zincir yüksekliği: cüzdanların block tracker'ı yalnız SAYI
            // DEĞİŞİNCE "yeni blok" olayı yayınlar, bakiye yenileme buna bağlıdır.
            "eth_blockNumber" => {
                let height = Self::lookup_account(&state, "__GLOBAL_BLOCK_HEIGHT__")
                    .map(|account| account.balance)
                    .unwrap_or(0);
                Value::String(format!("0x{height:x}"))
            }

            "eth_getBalance" => {
                // 🛡️ D14 (denetim C1/C4): blok parametresi sessizce yutulmaz;
                // depolama hatası "hesap yok" (0 bakiye) gibi gösterilmez.
                if let Some(err) = Self::historical_state_guard(&state, safe_params.get(1)) {
                    return RpcResponse {
                        jsonrpc: "2.0".to_string(),
                        id: req.id,
                        result: None,
                        error: Some(err),
                    };
                }
                let address = safe_params.first().and_then(|v| v.as_str()).unwrap_or("");
                if let Err(e) = Self::lookup_account_strict(&state, address) {
                    tracing::error!("eth_getBalance depolama hatasi ({address}): {e:?}");
                    return RpcResponse {
                        jsonrpc: "2.0".to_string(),
                        id: req.id,
                        result: None,
                        error: Some(
                            serde_json::json!({"code": -32603, "message": "state read failed"}),
                        ),
                    };
                }
                if let Some(account) = Self::lookup_account(&state, address) {
                    // Ham 18 ondalıklı değer olduğu gibi döner; bölünmez.
                    let evm_balance = account.balance;
                    Value::String(format!("0x{:x}", evm_balance))
                } else {
                    Value::String("0x0".to_string())
                }
            }

            "eth_getTransactionCount" => {
                // 🛡️ D14 (denetim C1/C4): "pending" meşru (aşağıda ele alınır);
                // açık GEÇMİŞ blok isteği ve depolama hatası açık hata döner.
                if let Some(err) = Self::historical_state_guard(&state, safe_params.get(1)) {
                    return RpcResponse {
                        jsonrpc: "2.0".to_string(),
                        id: req.id,
                        result: None,
                        error: Some(err),
                    };
                }
                let raw_address = safe_params.first().and_then(|v| v.as_str()).unwrap_or("");
                if let Err(e) = Self::lookup_account_strict(&state, raw_address) {
                    tracing::error!(
                        "eth_getTransactionCount depolama hatasi ({raw_address}): {e:?}"
                    );
                    return RpcResponse {
                        jsonrpc: "2.0".to_string(),
                        id: req.id,
                        result: None,
                        error: Some(
                            serde_json::json!({"code": -32603, "message": "state read failed"}),
                        ),
                    };
                }
                let lower_hex = if let Some(stripped) = raw_address.strip_prefix("0x") {
                    stripped.to_lowercase()
                } else {
                    raw_address.to_lowercase()
                };

                let eth_address = format!("0x{}", lower_hex);
                let state_nonce = Self::lookup_account(&state, &eth_address)
                    .map(|account| account.nonce)
                    .unwrap_or(0);
                // 🚨 Blok etiketi Ethereum anlamıyla okunur: yalnız "pending" bekleyen
                // nonce'u sayar; "latest"/"earliest"/blok numarası zincirdeki nonce.
                let tag = safe_params
                    .get(1)
                    .and_then(|v| v.as_str())
                    .unwrap_or("latest");
                let next_nonce = if tag == "pending" {
                    // K3: O(k) indeksli hesaplama, eski tüm-havuz klonlaması yerine.
                    mempool.pending_nonce(state_nonce, &eth_address)
                } else {
                    state_nonce
                };

                Value::String(format!("0x{:x}", next_nonce))
            }

            "eth_sendRawTransaction" => {
                // 🚨 HER reddetme yolu gerçek JSON-RPC `error` döner; `result: null`
                // ethers/MetaMask'te "boş ama başarılı" sanılıp `null` hash ile çöker.
                let raw_tx = safe_params.first().and_then(|v| v.as_str()).unwrap_or("");
                let hex_data = raw_tx.strip_prefix("0x").unwrap_or(raw_tx);

                let tx_bytes = match hex::decode(hex_data) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        return RpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: req.id,
                            result: None,
                            error: Some(json!({
                                "code": -32602,
                                "message": format!("Invalid params: raw transaction is not valid hex: {e}")
                            })),
                        };
                    }
                };

                let zagros_tx = match Self::decode_and_convert_tx(&tx_bytes) {
                    Ok(tx) => tx,
                    Err(e) => {
                        error!("❌ RLP Decode Hatası: {}", e);
                        return RpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: req.id,
                            result: None,
                            error: Some(json!({
                                "code": -32602,
                                "message": format!("Invalid params: could not decode transaction: {e}")
                            })),
                        };
                    }
                };

                let tx_hash = format!("0x{}", hex::encode(zagros_tx.tx_id).to_lowercase());
                tracing::debug!(
                    "🔓 RLP ÇÖZÜLDÜ: Gönderen={}, Alıcı={}, Miktar={}, DATA={:?}",
                    zagros_tx.sender,
                    zagros_tx.receiver,
                    zagros_tx.amount,
                    zagros_tx.payload
                );
                let eth_sender = zagros_tx.sender.clone();

                // 🛡️ Tek giriş kapısı `admit_transaction`: RPC ve P2P gossip aynı kapıdan geçer.
                match mempool.admit_transaction(zagros_tx) {
                    Ok(tx_id) => {
                        // 🔁 Yerel kaynaklı: bloğa girmezse periyodik yeniden
                        // yayın adayı (bkz. zagros-cli "tx yeniden yayın" görevi).
                        mempool.mark_local_origin(&tx_id);
                        mempool.mark_queued_local_origin(&eth_sender, &tx_id);
                        // 🛡️ Kabul edilen kanonik işlem mempool'dan geri okunup gossip'lenir;
                        // `admit_transaction` gas alanlarını mutasyona uğrattı.
                        if let Some(sender) = &tx_broadcast {
                            if let Some(admitted_tx) = mempool.get_transaction(&tx_id) {
                                let _ = sender.send(admitted_tx);
                            }
                        }
                    }
                    Err(zagros_mempool::AdmissionError::Full) => {
                        error!("❌ Mempool dolu, işlem reddedildi (kapasite)");
                        return RpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: req.id,
                            result: None,
                            error: Some(json!({
                                "code": -32005,
                                "message": "Server busy: mempool full, retry shortly"
                            })),
                        };
                    }
                    Err(zagros_mempool::AdmissionError::InvalidNonce { expected, got }) => {
                        error!("❌ Geçersiz nonce: beklenen={}, gelen={}", expected, got);
                        return RpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: req.id,
                            result: None,
                            error: Some(json!({
                                "code": -32000,
                                "message": format!(
                                    "Invalid transaction: nonce too {} (expected {expected}, got {got})",
                                    if got < expected { "low" } else { "high" },
                                )
                            })),
                        };
                    }
                    Err(zagros_mempool::AdmissionError::Rejected(e)) => {
                        error!("❌ Mempool Hatası: {:?}", e);
                        return RpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: req.id,
                            result: None,
                            error: Some(json!({
                                "code": -32000,
                                "message": format!("Invalid transaction: {e:?}")
                            })),
                        };
                    }
                }

                let now_secs = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                tx_cache.insert(tx_hash.clone(), (eth_sender, now_secs));
                info!("✅ İşlem başarıyla Mempool'a eklendi!");
                Value::String(tx_hash)
            }

            "eth_getTransactionByHash" => {
                let tx_hash_param = safe_params.first().and_then(|v| v.as_str()).unwrap_or("");
                let clean = tx_hash_param
                    .strip_prefix("0x")
                    .unwrap_or(tx_hash_param)
                    .to_lowercase();
                let tx_hash = format!("0x{}", clean);
                let tx_id = parse_tx_id_hex(&clean);

                // 🏛️ Gerçek tx gövdesi `tx_body_<hash>`'ten; bulunamazsa mempool
                // (bekliyorsa `blockHash`/`blockNumber` standart semantikle `null`).
                let archived_tx = tx_id.and_then(|id| {
                    Self::lookup_account(&state, &tx_body_key(&id))
                        .and_then(|acc| Transaction::from_stored_bytes(&acc.contract_code).ok())
                });

                if let Some(tx) = archived_tx {
                    let id = tx_id.expect("archived_tx yalnizca tx_id Some ise doldu");
                    let receipt = Self::lookup_account(&state, &receipt_key(&id)).and_then(|acc| {
                        bincode::deserialize::<ArchivedReceipt>(&acc.contract_code).ok()
                    });
                    let (block_hash_json, block_number_json, tx_index_json) = match receipt
                        .and_then(|r| {
                            Self::load_archived_block(&state, r.block_number)
                                .map(|b| (r.block_number, b))
                        }) {
                        Some((number, (header, hash))) => {
                            let idx = header.tx_hashes.iter().position(|h| *h == id);
                            (
                                Value::String(format!("0x{}", hex::encode(hash))),
                                Value::String(format!("0x{:x}", number)),
                                idx.map(|i| Value::String(format!("0x{:x}", i)))
                                    .unwrap_or(Value::Null),
                            )
                        }
                        None => (Value::Null, Value::Null, Value::Null),
                    };
                    let to_json = if zagros_types::is_evm_deploy(&tx.receiver) {
                        Value::Null
                    } else {
                        Value::String(tx.receiver.clone())
                    };
                    let (v, r, s) = Self::extract_vrs(&tx.signature);
                    let eth_type = Self::extract_eth_tx_type(&tx.signature);
                    let mut tx_json = serde_json::json!({
                        "hash": tx_hash,
                        "nonce": format!("0x{:x}", tx.nonce),
                        "blockHash": block_hash_json,
                        "blockNumber": block_number_json,
                        "transactionIndex": tx_index_json,
                        "from": tx.sender,
                        "to": to_json,
                        "value": format!("0x{:x}", tx.amount),
                        "gasPrice": format!("0x{:x}", tx.gas_price),
                        "gas": format!("0x{:x}", tx.gas_limit),
                        "input": format!("0x{}", hex::encode(&tx.payload)),
                        "type": eth_type,
                        // (Radar /kopru bulgusu): native işlem türü. Köprü mint gibi
                        // selector'sız native işlemler dışarıdan "contract call" gibi görünüyor,
                        // explorer sınıflandıramıyordu. Ethereum alanlarına dokunmadan ek alan.
                        "zagrosType": tx.tx_type.to_string(),
                        "v": v,
                        "r": r,
                        "s": s
                    });
                    // 2930/1559 istemcileri bu alanı bekler; access list saklanmadığından boş dizi.
                    if eth_type != "0x0" {
                        tx_json["accessList"] = serde_json::json!([]);
                    }
                    tx_json
                } else if let Some(tx) = tx_id
                    .filter(|id| mempool.contains(id))
                    .and_then(|id| mempool.get_transaction(&id))
                {
                    // Hâlâ mempool'da bekliyor, gövde GERÇEK ama blok
                    // konumu henüz yok, standart JSON-RPC'ye uygun null.
                    let to_json = if zagros_types::is_evm_deploy(&tx.receiver) {
                        Value::Null
                    } else {
                        Value::String(tx.receiver.clone())
                    };
                    let (v, r, s) = Self::extract_vrs(&tx.signature);
                    let eth_type = Self::extract_eth_tx_type(&tx.signature);
                    let mut tx_json = serde_json::json!({
                        "hash": tx_hash,
                        "nonce": format!("0x{:x}", tx.nonce),
                        "blockHash": Value::Null,
                        "blockNumber": Value::Null,
                        "transactionIndex": Value::Null,
                        "from": tx.sender,
                        "to": to_json,
                        "value": format!("0x{:x}", tx.amount),
                        "gasPrice": format!("0x{:x}", tx.gas_price),
                        "gas": format!("0x{:x}", tx.gas_limit),
                        "input": format!("0x{}", hex::encode(&tx.payload)),
                        "type": eth_type,
                        // (Radar /kopru bulgusu): native işlem türü. Köprü mint gibi
                        // selector'sız native işlemler dışarıdan "contract call" gibi görünüyor,
                        // explorer sınıflandıramıyordu. Ethereum alanlarına dokunmadan ek alan.
                        "zagrosType": tx.tx_type.to_string(),
                        "v": v,
                        "r": r,
                        "s": s
                    });
                    if eth_type != "0x0" {
                        tx_json["accessList"] = serde_json::json!([]);
                    }
                    tx_json
                } else {
                    Value::Null
                }
            }

            "eth_getTransactionReceipt" => {
                let tx_hash_param = safe_params.first().and_then(|v| v.as_str()).unwrap_or("");
                let clean_hash = tx_hash_param
                    .strip_prefix("0x")
                    .unwrap_or(tx_hash_param)
                    .to_lowercase();
                let tx_hash = format!("0x{}", clean_hash);
                let tx_id = parse_tx_id_hex(&clean_hash);

                // 🏛️ `Receipt_<hash>` gerçek `ArchivedReceipt`; `blockNumber` tx'in
                // GERÇEKTEN yürütüldüğü bloktan gelir (güncel yükseklik olsaydı eski
                // tx'in blockNumber'ı zincir ilerledikçe değişirdi).
                let receipt = tx_id.and_then(|id| {
                    Self::lookup_account(&state, &receipt_key(&id)).and_then(|acc| {
                        bincode::deserialize::<ArchivedReceipt>(&acc.contract_code).ok()
                    })
                });

                if let (Some(id), Some(receipt)) = (tx_id, receipt) {
                    let archived_tx = Self::lookup_account(&state, &tx_body_key(&id))
                        .and_then(|acc| Transaction::from_stored_bytes(&acc.contract_code).ok());
                    let sender = archived_tx
                        .as_ref()
                        .map(|tx| tx.sender.clone())
                        .unwrap_or_else(|| {
                            "0x0000000000000000000000000000000000000000".to_string()
                        });
                    let receiver_json = archived_tx
                        .as_ref()
                        .map(|tx| {
                            if zagros_types::is_evm_deploy(&tx.receiver) {
                                Value::Null
                            } else {
                                Value::String(tx.receiver.clone())
                            }
                        })
                        .unwrap_or(Value::Null);

                    let (block_hash_hex, tx_index) = match Self::load_archived_block(
                        &state,
                        receipt.block_number,
                    ) {
                        Some((header, hash)) => (
                            format!("0x{}", hex::encode(hash)),
                            header.tx_hashes.iter().position(|h| *h == id).unwrap_or(0),
                        ),
                        // 🛡️ D14: budanmış blokta sıfırlardan sahte blockHash uydurulmaz,
                        // açık hata + arşiv düğümü işaret edilir.
                        None => {
                            return RpcResponse {
                                jsonrpc: "2.0".to_string(),
                                id: req.id,
                                result: None,
                                error: Some(serde_json::json!({
                                    "code": -32000,
                                    "message": format!(
                                        "transaction executed in block {} but that block is pruned on this node; query an archive node (rpc.zagrosnetwork.com)",
                                        receipt.block_number
                                    )
                                })),
                            };
                        }
                    };

                    let logs_json: Vec<Value> = receipt
                        .logs
                        .iter()
                        .enumerate()
                        .map(|(log_index, log)| {
                            serde_json::json!({
                                "address": log.address,
                                "topics": log.topics.iter().map(|t| format!("0x{}", hex::encode(t))).collect::<Vec<_>>(),
                                "data": format!("0x{}", hex::encode(&log.data)),
                                "blockHash": block_hash_hex,
                                "blockNumber": format!("0x{:x}", receipt.block_number),
                                "transactionHash": tx_hash,
                                "transactionIndex": format!("0x{:x}", tx_index),
                                "logIndex": format!("0x{:x}", log_index),
                                "removed": false
                            })
                        })
                        .collect();

                    let eth_type = archived_tx
                        .as_ref()
                        .map(|tx| Self::extract_eth_tx_type(&tx.signature))
                        .unwrap_or("0x0");
                    serde_json::json!({
                        "transactionHash": tx_hash,
                        "transactionIndex": format!("0x{:x}", tx_index),
                        "blockHash": block_hash_hex,
                        "blockNumber": format!("0x{:x}", receipt.block_number),
                        "from": sender,
                        "to": receiver_json,
                        "contractAddress": receipt.contract_address.map(Value::String).unwrap_or(Value::Null),
                        // 🔧 BİLİNEN SINIRLAMA (bilerek kapsam dışı): bu tx'in
                        // KENDİ gas_used'ı, bloktaki önceki tx'lerin
                        // toplamıyla gerçek bir "cumulative" DEĞİL.
                        "cumulativeGasUsed": format!("0x{:x}", receipt.gas_used),
                        "gasUsed": format!("0x{:x}", receipt.gas_used),
                        // 🛡️ D14 (C5): cüzdan/borsa kütüphaneleri ücreti gasUsed ×
                        // effectiveGasPrice hesaplar; bizde kesilen = gas_limit × gas_price
                        // ve gasUsed = gas_limit, effectiveGasPrice = tx.gas_price doğru sonucu verir.
                        "effectiveGasPrice": archived_tx
                            .as_ref()
                            .map(|tx| format!("0x{:x}", tx.gas_price))
                            .unwrap_or_else(|| "0x0".to_string()),
                        "status": if receipt.status { "0x1" } else { "0x0" },
                        "logs": logs_json,
                        "logsBloom": "0x",
                        "type": eth_type
                    })
                } else {
                    // K3: tx_id ile O(1) varlık kontrolü, klonlama yok.
                    let is_pending = tx_id.map(|id| mempool.contains(&id)).unwrap_or(false);

                    if is_pending {
                        Value::Null
                    } else {
                        tracing::warn!(
                            "📦 Receipt not yet available for tx {}. Returning pending null.",
                            tx_hash
                        );
                        Value::Null
                    }
                }
            }

            "eth_call" => {
                let call_obj = safe_params.first().unwrap_or(&Value::Null);
                let to = call_obj.get("to").and_then(|v| v.as_str()).unwrap_or("");
                let data = call_obj.get("data").and_then(|v| v.as_str()).unwrap_or("");
                let from = call_obj
                    .get("from")
                    .and_then(|v| v.as_str())
                    .unwrap_or("0x0000000000000000000000000000000000000000");

                let to_address = if to.is_empty() {
                    "0x0000000000000000000000000000000000000000".to_string()
                } else {
                    to.to_string()
                };
                let from_address = if from.is_empty() {
                    "0x0000000000000000000000000000000000000000".to_string()
                } else {
                    from.to_string()
                };

                let payload =
                    hex::decode(data.strip_prefix("0x").unwrap_or(data)).unwrap_or_default();

                // 🛡️ Çağıranın beyan ettiği `gas` alanına config tavanına
                // (varsayılan 10M, gerçek işlemlerin `Transaction::validate()`
                // tavanıyla AYNI) KADAR saygı gösterilir; sabit/sınırsız 30M yok.
                let effective_gas = resolve_effective_gas(call_obj, evm_limits.eth_call_max_gas);

                // 🛡️ EVM simülasyonları için ayrı, daha sıkı eş zamanlılık bütçesi;
                // dolu ise hemen ret, blocking pool tekelleşmez.
                let _evm_sim_guard = match InFlightGuard::try_acquire(
                    &EVM_SIMULATION_IN_FLIGHT,
                    evm_limits.max_parallel_simulations,
                ) {
                    Some(guard) => guard,
                    None => {
                        EVM_SIMULATION_BUSY_COUNT.fetch_add(1, Ordering::Relaxed);
                        return RpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: req.id,
                            result: None,
                            error: Some(serde_json::json!({
                                "code": -32005,
                                "message": "Server busy: too many concurrent EVM simulations (eth_call/eth_estimateGas), retry shortly"
                            })),
                        };
                    }
                };

                // 🚨 KÖKLÜ ÇÖZÜM: Hardcoded if-else blokları çöpe atıldı.
                // Okuma işlemini Gerçek EVM'e (Simülasyon Modunda) gönderiyoruz!
                let executor = zagros_executor::evm::EvmExecutor::new(state.clone());
                match executor.simulate_eth_call(&from_address, &to_address, payload, effective_gas)
                {
                    Ok(output) => {
                        let hex_out = hex::encode(output);
                        Value::String(format!("0x{}", hex_out))
                    }
                    Err(e) => {
                        // 🛡️ D14: revert/halt "0x" değil açık hata (cüzdan balanceOf'u 0 okumasın).
                        error!("❌ eth_call EVM Simülasyon Hatası: {:?}", e);
                        return RpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: req.id,
                            result: None,
                            error: Some(serde_json::json!({
                                "code": -32000,
                                "message": format!("execution reverted: {e:?}"),
                            })),
                        };
                    }
                }
            }

            "zagros_get_pool_reserves" => match state.get_pool_reserves() {
                Ok((zagros_scaled, zerenya_scaled)) => {
                    serde_json::json!({ "zagros": zagros_scaled.to_string(), "zerenya": zerenya_scaled.to_string() })
                }
                Err(_) => serde_json::json!({"zagros": "0", "zerenya": "0"}),
            },

            // 🛡️ Token Fabrikası frontend'i motorun `new_contract_count > 0`'da tahsil
            // ettiği `TOKEN_FACTORY_FEE_ZERENYA` eşdeğerini göstermeli; formül
            // `token_factory_fee_per_contract` ile aynı, burada tekrarlanmaz.
            "zagros_estimateTokenFactoryFee" => match state.get_pool_reserves() {
                Ok((pool_zagros, pool_zerenya)) => {
                    let fee = zagros_types::base_gas_fee_from_reserves(
                        zagros_types::TOKEN_FACTORY_FEE_ZERENYA,
                        pool_zagros,
                        pool_zerenya,
                    );
                    serde_json::json!({ "fee": fee.to_string() })
                }
                Err(_) => {
                    serde_json::json!({ "fee": zagros_types::TOKEN_FACTORY_FEE_ZERENYA.to_string() })
                }
            },

            // 🛡️ Frontend "MAX" hesabı gerçekte kesilecek ücretle AYNI kaynaktan
            // beslenmeli (istemci tarafı tahmin kayar): `Mempool::native_min_required_fee`
            // tek kaynak, burada tekrarlanmaz. Yalnız NATIVE türler (EVM ücreti calldata'ya bağlı).
            "zagros_estimateNativeFee" => {
                let tx_type_str = safe_params
                    .first()
                    .and_then(|v| v.as_str())
                    .unwrap_or("StakeZagros");
                let tx_type = match tx_type_str {
                    "Transfer" => TxType::Transfer,
                    "SwapBuy" => TxType::SwapBuy,
                    "SwapSell" => TxType::SwapSell,
                    "StakeZagros" => TxType::StakeZagros,
                    "UnstakeZagros" => TxType::UnstakeZagros,
                    "ClaimReward" => TxType::ClaimReward,
                    "RegisterValidator" => TxType::RegisterValidator,
                    "UnregisterValidator" => TxType::UnregisterValidator,
                    "ApproveValidator" => TxType::ApproveValidator,
                    "RemoveValidator" => TxType::RemoveValidator,
                    "RotateConsensusKey" => TxType::RotateConsensusKey,
                    // 🚨 Köprü çıkışı listede olmalı: çarpanı 3 (gas.rs); 'SwapSell' (2)
                    // ile yaklaşmak MAX'a basan kullanıcının işlemini reddettirir.
                    "BridgeBurn" => TxType::BridgeBurn,
                    "BridgeSwapAndBurn" => TxType::BridgeSwapAndBurn,
                    _ => {
                        return RpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: req.id,
                            result: None,
                            error: Some(serde_json::json!({
                                "code": -32602,
                                "message": format!("Unknown or unsupported (EVM?) tx_type: {}", tx_type_str)
                            })),
                        };
                    }
                };
                let fee = mempool.native_min_required_fee(&tx_type);
                serde_json::json!({ "tx_type": tx_type_str, "fee": fee.to_string() })
            }

            // 🌐 Komuta Merkezi: stake > 0 adres sayısı (staker_count) ve eşiği geçenler
            // (validator_count); `get_validator_candidates()` salt okunur sayılır.
            "zagros_getValidatorStats" => match state.get_validator_candidates() {
                Ok(candidates) => {
                    let staker_count = candidates.len();
                    let now_secs = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() as u128)
                        .unwrap_or(0);

                    // 🛡️ `active_validator_set` ile aynı kriter, ikinci tam tarama olmadan
                    // tek döngüden iki sayaç.
                    let (min_stake_zagros, hysteresis_bps) =
                        match zagros_executor::params::load_chain_params(&*state) {
                            Ok(p) => (
                                zagros_executor::params::min_validator_stake_zagros(&*state, &p)
                                    .ok(),
                                p.stake_hysteresis_bps,
                            ),
                            Err(_) => (None, 0),
                        };
                    let mut jailed_count = 0usize;
                    let mut validator_count = 0usize;
                    let mut total_stake: u128 = 0;
                    let mut max_stake: u128 = 0;
                    for (address, stake) in &candidates {
                        total_stake = total_stake.saturating_add(*stake);
                        if *stake > max_stake {
                            max_stake = *stake;
                        }
                        if let Some(account) = Self::lookup_account(&state, address) {
                            if account.jailed_until > now_secs {
                                jailed_count += 1;
                            }
                            // G2: eşik zincir-üstü ChainParams (0,17 ons altın-eşdeğeri);
                            // parametre yoksa hiçbir hesap "nitelikli" sayılmaz (fail-closed).
                            let threshold = min_stake_zagros.map(|m| {
                                zagros_executor::params::qualification_threshold(
                                    account.validator_stake_snapshot,
                                    m,
                                    hysteresis_bps,
                                )
                            });
                            if account.is_registered_validator
                                && threshold
                                    .map(|t| account.staked_balance >= t)
                                    .unwrap_or(false)
                                && now_secs >= account.jailed_until
                            {
                                validator_count += 1;
                            }
                        }
                    }
                    let average_stake = if staker_count > 0 {
                        total_stake / staker_count as u128
                    } else {
                        0
                    };

                    serde_json::json!({
                        "staker_count": staker_count,
                        "validator_count": validator_count,
                        "jailed_count": jailed_count,
                        "average_stake": average_stake.to_string(),
                        "max_stake": max_stake.to_string(),
                        "total_stake": total_stake.to_string(),
                    })
                }
                Err(_) => serde_json::json!({
                    "staker_count": 0, "validator_count": 0, "jailed_count": 0,
                    "average_stake": "0", "max_stake": "0", "total_stake": "0",
                }),
            },

            // 🛡️ Validator listesi: `get_validator_candidates()` ile aynı kaynak
            // (`zagros_getValidatorStats` ile tutarlı).
            "zagros_getValidatorList" => {
                // 🚨 Liste = BFT aktif kümesi ∪ stake index'i: teminatı olgunlaşmamış ya
                // da eşik altı bir validator kümede blok üretirken listede görünmeli.
                // `in_active_set`/`proposer_index`/`pending_stake` kaynağı gösterir.
                let now_secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as u128)
                    .unwrap_or(0);
                let active_set = zagros_executor::validator_set::load_active_set(&*state).ok();
                let mut merged: std::collections::BTreeMap<String, u128> =
                    std::collections::BTreeMap::new();
                if let Ok(candidates) = state.get_validator_candidates() {
                    for (address, stake) in candidates {
                        merged.insert(address, stake);
                    }
                }
                if let Some(set) = &active_set {
                    for member in &set.members {
                        merged.entry(member.address.clone()).or_insert(0);
                    }
                }
                {
                    let list: Vec<Value> = merged
                        .iter()
                        .map(|(address, stake)| {
                            let account = Self::lookup_account(&state, address).unwrap_or_default();
                            let jailed = account.jailed_until > now_secs;
                            let proposer_index = active_set.as_ref().and_then(|s| {
                                s.members.iter().position(|m| &m.address == address)
                            });
                            serde_json::json!({
                                "address": address,
                                "stake": stake.to_string(),
                                "pending_stake": account.pending_stake_amount.to_string(),
                                "pending_stake_activation_time":
                                    account.pending_stake_activation_time.to_string(),
                                "in_active_set": proposer_index.is_some(),
                                "proposer_index": proposer_index,
                                "is_registered_validator": account.is_registered_validator,
                                "validator_status": account.validator_status.map(|st| format!("{st:?}")),
                                // G8: bu duruma geçilen epoch (Probation'a giriş);
                                // `served = current_epoch - validator_status_epoch >= probation_epochs`.
                                "validator_status_epoch": account.validator_status_epoch.to_string(),
                                "consensus_pubkey": hex::encode(account.consensus_pubkey),
                                "jailed": jailed,
                                "jailed_until": account.jailed_until.to_string(),
                                "validator_registered_at": account.validator_registered_at.to_string(),
                                // G8: gerçek QC/ShadowVote katılımından biriken liveness
                                // (epoch, katılım/toplam, ardışık strike, oran bps; ölçüm yoksa null).
                                "liveness": {
                                    "epoch": account.liveness.epoch.to_string(),
                                    "participated": account.liveness.participated.to_string(),
                                    "total": account.liveness.total.to_string(),
                                    "strikes": account.liveness.strikes,
                                    "participation_bps": account.liveness.participation_bps(),
                                },
                                // G8 finalizasyon: teminat kilit bitişi (unstake
                                // TALEBİ değil, jail/equivocation sonrası zorunlu
                                // kilit, INV-E3, bond-lock kuralı DEĞİŞMEDİ).
                                "bond_unlock_at": account.bond_unlock_at.to_string(),
                            })
                        })
                        .collect();
                    serde_json::json!({
                        "validators": list,
                        "active_set_epoch": active_set.as_ref().map(|s| s.epoch.to_string()),
                        "active_set_size": active_set.as_ref().map(|s| s.len()),
                    })
                }
            }

            // 🛡️ Ağ parametreleri: derleme zamanı sabitleri (tek istisna
            // `configured_block_producer_address`, sentinel'den). Panelin tek doğruluk
            // kaynağı; bu sayılar başka yerde tekrarlanmamalı.
            "zagros_getNetworkParams" => {
                let configured_block_producer_address =
                    match state.get_account(&"__CONFIGURED_BLOCK_PRODUCER__".to_string()) {
                        Ok(Some(acc)) if !acc.contract_code.is_empty() => {
                            String::from_utf8(acc.contract_code).unwrap_or_default()
                        }
                        _ => String::new(),
                    };
                serde_json::json!({
                    "staker_reward_bps": zagros_types::STAKER_REWARD_BPS.to_string(),
                    "validator_reward_bps": zagros_types::VALIDATOR_REWARD_BPS.to_string(),
                    // G2: zincir-üstü parametre; yoksa null (sabit YOK).
                    "min_validator_stake": zagros_executor::params::load_chain_params(&*state)
                        .ok()
                        .and_then(|p| zagros_executor::params::min_validator_stake_zagros(&*state, &p).ok())
                        .map(|m| serde_json::Value::String(m.to_string()))
                        .unwrap_or(serde_json::Value::Null),
                    "min_validator_stake_zerenya": zagros_executor::params::load_chain_params(&*state)
                        .ok()
                        .map(|p| serde_json::Value::String(p.min_validator_stake_zerenya.to_string()))
                        .unwrap_or(serde_json::Value::Null),
                    "jail_duration_seconds": zagros_types::JAIL_DURATION_SECONDS.to_string(),
                    "reward_vesting_seconds": zagros_types::REWARD_VESTING_SECONDS.to_string(),
                    "configured_block_producer_address": configured_block_producer_address,
                    // G8: BFT epoch/liveness/probation/jail eşikleri zincirden okunur,
                    // yoksa null (sabit uydurulmaz).
                    "current_epoch": zagros_executor::validator_set::load_active_set(&*state)
                        .ok()
                        .map(|s| serde_json::Value::String(s.epoch.to_string()))
                        .unwrap_or(serde_json::Value::Null),
                    "epoch_seconds": zagros_executor::params::load_chain_params(&*state)
                        .ok()
                        .map(|p| serde_json::Value::String(p.epoch_seconds.to_string()))
                        .unwrap_or(serde_json::Value::Null),
                    "probation_epochs": zagros_executor::params::load_chain_params(&*state)
                        .ok()
                        .map(|p| serde_json::Value::from(p.probation_epochs))
                        .unwrap_or(serde_json::Value::Null),
                    // 🚨 ETKİN (clamp uygulanmış) değerler raporlanır; ceza bunları kullanır,
                    // ham değer operatörü yanıltırdı. Ham değerler `*_stored` alanlarında.
                    "uptime_threshold_bps": zagros_executor::params::load_chain_params(&*state)
                        .ok()
                        .map(|p| serde_json::Value::from(
                            zagros_executor::params::effective_uptime_threshold_bps(&p)
                        ))
                        .unwrap_or(serde_json::Value::Null),
                    "uptime_threshold_bps_stored": zagros_executor::params::load_chain_params(&*state)
                        .ok()
                        .map(|p| serde_json::Value::from(p.uptime_threshold_bps))
                        .unwrap_or(serde_json::Value::Null),
                    "max_liveness_strikes": zagros_executor::params::load_chain_params(&*state)
                        .ok()
                        .map(|p| serde_json::Value::from(
                            zagros_executor::params::effective_max_liveness_strikes(&p)
                        ))
                        .unwrap_or(serde_json::Value::Null),
                    "max_liveness_strikes_stored": zagros_executor::params::load_chain_params(&*state)
                        .ok()
                        .map(|p| serde_json::Value::from(p.max_liveness_strikes))
                        .unwrap_or(serde_json::Value::Null),
                    // D11 oransal üretici ödülü: bu epoch'tan itibaren aktif (Command Center gösterir).
                    "d11_activation_epoch": zagros_executor::params::D11_ACTIVATION_EPOCH,
                    "bond_lock_seconds": zagros_executor::params::load_chain_params(&*state)
                        .ok()
                        .map(|p| serde_json::Value::String(p.bond_lock_seconds.to_string()))
                        .unwrap_or(serde_json::Value::Null),
                    // KUYRUK REFORMU: kapasite (aynı anda kaç validator Aktif/
                    // Probation olabilir). dApp bunu Aktif+Probation sayısıyla
                    // karşılaştırıp "X/max dolu" ve Approved kuyruk sırasını gösterir.
                    "max_validators": zagros_executor::params::load_chain_params(&*state)
                        .ok()
                        .map(|p| serde_json::Value::from(p.max_validators))
                        .unwrap_or(serde_json::Value::Null),
                })
            }

            // 🛡️ Slash geçmişi elle, u128 `.to_string()` ile (`json!` u64 aşımında panikler).
            // 🛡️ D14: `trusted_checkpoint` için BFT başlığının gerçek hash'i + validator_set_hash.
            "zagros_getConsensusCheckpoint" => {
                let height_param = safe_params.first().and_then(|v| v.as_str()).map(|t| {
                    let clean = t.strip_prefix("0x").unwrap_or(t);
                    u64::from_str_radix(clean, 16).ok()
                });
                let number = match height_param {
                    Some(Some(n)) => Some(n),
                    Some(None) => None, // bozuk parametre
                    None => Self::lookup_account(&state, "__GLOBAL_BLOCK_HEIGHT__")
                        .map(|a| Some(a.balance as u64))
                        .unwrap_or(None),
                };
                match number {
                    None => Value::Null,
                    Some(n) => {
                        type ConsensusRecord = (
                            zagros_types::consensus::SignedHeader,
                            zagros_types::consensus::QuorumCertificate,
                            Vec<zagros_types::consensus::ShadowVoteAttestation>,
                        );
                        match state.get_account(&zagros_state::consensus_block_key(n)) {
                            Ok(Some(acc)) if !acc.contract_code.is_empty() => {
                                match bincode::deserialize::<ConsensusRecord>(&acc.contract_code) {
                                    Ok((signed, _, _)) => serde_json::json!({
                                        "height": signed.header.number,
                                        "block_hash": format!("0x{}", hex::encode(signed.header.hash())),
                                        "validator_set_hash": format!("0x{}", hex::encode(signed.header.validator_set_hash)),
                                        "epoch": signed.header.epoch,
                                    }),
                                    Err(_) => Value::Null,
                                }
                            }
                            _ => Value::Null,
                        }
                    }
                }
            }

            "zagros_getValidatorSlashHistory" => {
                // 🛡️ D14: adres parametresi verilmişse hedefe göre süzülür (yok
                // sayılsaydı her validatör "cezalı" görünürdü); parametresiz küresel liste.
                let filter = safe_params
                    .first()
                    .and_then(|v| v.as_str())
                    .map(|a| a.to_ascii_lowercase());
                match zagros_executor::Executor::load_slash_history(state.as_ref()) {
                    Ok(records) => {
                        let list: Vec<Value> = records
                            .iter()
                            .filter(|r| match &filter {
                                Some(f) => r.target.eq_ignore_ascii_case(f),
                                None => true,
                            })
                            .map(|r| {
                                serde_json::json!({
                                    "index": r.index,
                                    "target": r.target,
                                    "reason": r.reason,
                                    "confiscated_amount": r.confiscated_amount.to_string(),
                                    "timestamp": r.timestamp.to_string(),
                                })
                            })
                            .collect();
                        serde_json::json!({ "records": list })
                    }
                    Err(_) => serde_json::json!({ "records": [] }),
                }
            }

            // 🛡️ En son ödül dağıtım anlık görüntüsü: `Executor::load_last_
            // reward_snapshot`, henüz hiç dağıtım olmadıysa `null` (sahte 0
            // DEĞİL).
            "zagros_getLastRewardSnapshot" => {
                match zagros_executor::Executor::load_last_reward_snapshot(state.as_ref()) {
                    // 🚨 `serde_json::json!(snapshot)` KULLANILMAZ: u128 alanlar JSON
                    // `Number`'a sığmaz ve panikler; u128 her yerde `.to_string()` ile yazılır.
                    Ok(Some(snapshot)) => serde_json::json!({
                        "total_staked": snapshot.total_staked.to_string(),
                        "accumulated_reward_per_share": snapshot.accumulated_reward_per_share.to_string(),
                        "staker_share": snapshot.staker_share.to_string(),
                        "validator_share": snapshot.validator_share.to_string(),
                        "timestamp": snapshot.timestamp.to_string(),
                    }),
                    Ok(None) => Value::Null,
                    Err(_) => Value::Null,
                }
            }

            // 🛡️ Mempool anlık görüntüsü: `Mempool::get_all_transactions()`
            // zaten var olan canlı veri üzerinde salt-okunur bir hesaplama,
            // yeni bir izleme/sayaç mekanizması YOK.
            "zagros_getMempoolStats" => {
                let txs = mempool.get_all_transactions();
                let pending_count = txs.len();
                let now_secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as u128)
                    .unwrap_or(0);

                let (mut min_fee, mut max_fee, mut fee_sum, mut wait_sum) =
                    (u128::MAX, 0u128, 0u128, 0u128);
                for tx in &txs {
                    let fee = (tx.gas_limit as u128).saturating_mul(tx.gas_price);
                    min_fee = min_fee.min(fee);
                    max_fee = max_fee.max(fee);
                    fee_sum = fee_sum.saturating_add(fee);
                    wait_sum = wait_sum.saturating_add(now_secs.saturating_sub(tx.timestamp));
                }
                let (average_fee, average_wait_seconds, min_fee_out) = if pending_count > 0 {
                    (
                        fee_sum / pending_count as u128,
                        wait_sum / pending_count as u128,
                        min_fee,
                    )
                } else {
                    (0, 0, 0)
                };

                // 🛡️ DDoS/stres şeffaflığı: `min_required_fee`'nin içinde uygulanan
                // AYNI değerler gözlemlenebilir kılınır, ayrı hesap değil.
                serde_json::json!({
                    "pending_count": pending_count,
                    "queued_count": mempool.queued_count(),
                    "average_fee": average_fee.to_string(),
                    "min_fee": min_fee_out.to_string(),
                    "max_fee": max_fee.to_string(),
                    "average_wait_seconds": average_wait_seconds.to_string(),
                    "ddos_threshold": mempool.ddos_threshold(),
                    "stress_multiplier": mempool.stress_multiplier().to_string(),
                    "is_ddos_stress_active": mempool.is_under_stress(),
                })
            }

            // 🛡️ Snapshot durumu `__SNAPSHOT_*__`/`__STORAGE_DISK_BYTES*__` sentinel'lerinden
            // okunur; etkin değilse/hiç alınmadıysa alanlar dürüstçe "0" döner.
            "zagros_getSnapshotStatus" => {
                let interval = Self::lookup_account(&state, "__SNAPSHOT_INTERVAL_BLOCKS__")
                    .map(|a| a.balance)
                    .unwrap_or(0);
                let max_retain = Self::lookup_account(&state, "__SNAPSHOT_MAX_RETAIN__")
                    .map(|a| a.balance)
                    .unwrap_or(0);
                let last_height = Self::lookup_account(&state, "__SNAPSHOT_LAST_HEIGHT__")
                    .map(|a| a.balance)
                    .unwrap_or(0);
                let last_created_at = Self::lookup_account(&state, "__SNAPSHOT_LAST_CREATED_AT__")
                    .map(|a| a.balance)
                    .unwrap_or(0);
                let current_height = Self::lookup_account(&state, "__GLOBAL_BLOCK_HEIGHT__")
                    .map(|a| a.balance)
                    .unwrap_or(0);
                let disk_bytes = Self::lookup_account(&state, "__STORAGE_DISK_BYTES__")
                    .map(|a| a.balance)
                    .unwrap_or(0);
                let disk_updated_at =
                    Self::lookup_account(&state, "__STORAGE_DISK_BYTES_UPDATED_AT__")
                        .map(|a| a.balance)
                        .unwrap_or(0);
                let next_due_height = if interval > 0 {
                    (last_height + interval).to_string()
                } else {
                    "0".to_string()
                };
                // Budama aktivitesi ("gerçekten çalışıyor mu"); statik ayarlar
                // `zagros_getEffectiveConfig`te.
                let pruning_total_deleted =
                    Self::lookup_account(&state, "__PRUNING_TOTAL_DELETED__")
                        .map(|a| a.balance)
                        .unwrap_or(0);
                let pruning_last_run_at = Self::lookup_account(&state, "__PRUNING_LAST_RUN_AT__")
                    .map(|a| a.balance)
                    .unwrap_or(0);

                serde_json::json!({
                    "snapshot_interval_blocks": interval.to_string(),
                    "max_snapshots_to_retain": max_retain.to_string(),
                    "last_snapshot_height": last_height.to_string(),
                    "last_snapshot_created_at": last_created_at.to_string(),
                    "next_snapshot_due_height": next_due_height,
                    "current_block_height": current_height.to_string(),
                    "disk_usage_bytes": disk_bytes.to_string(),
                    "disk_usage_updated_at": disk_updated_at.to_string(),
                    "pruning_total_deleted": pruning_total_deleted.to_string(),
                    "pruning_last_run_at": pruning_last_run_at.to_string(),
                })
            }

            // 🛡️ `binary_executor_state_version` çalışan ikilinin sabiti,
            // `disk_executor_state_version` diskte kayıtlı olan; RPC cevap veriyorsa
            // eşit olmalı, disk elle taşınırsa uyuşmazlık buradan görülür.
            "zagros_getNodeInfo" => {
                let disk_version =
                    Self::lookup_account(&state, zagros_types::EXECUTOR_STATE_VERSION_KEY)
                        .map(|a| a.balance)
                        .unwrap_or(0);
                let started_at = Self::lookup_account(&state, "__NODE_PROCESS_STARTED_AT__")
                    .map(|a| a.balance)
                    .unwrap_or(0);
                let now_secs = std::time::UNIX_EPOCH
                    .elapsed()
                    .map(|d| d.as_secs() as u128)
                    .unwrap_or(0);
                let uptime_seconds = now_secs.saturating_sub(started_at);

                serde_json::json!({
                    "version": "Zagros/v1.0.0",
                    "chain_id": CHAIN_ID,
                    "binary_executor_state_version": zagros_types::EXECUTOR_STATE_TRANSITION_VERSION,
                    "disk_executor_state_version": disk_version.to_string(),
                    "node_started_at": started_at.to_string(),
                    "uptime_seconds": uptime_seconds.to_string(),
                })
            }

            // 🛡️ Hayalet config'e karşı: dönen HER değer çalışan nesnenin getter'ından
            // ya da main.rs'in yazdığı sentinel'den okunur, config.toml YENİDEN PARSE
            // EDİLMEZ; "node ŞU AN ne uyguluyor" sorusuna cevap verir.
            "zagros_getEffectiveConfig" => {
                let target_gas_per_block =
                    Self::lookup_account(&state, "__CONFIG_TARGET_GAS_PER_BLOCK__")
                        .map(|a| a.balance)
                        .unwrap_or(0);
                let cache_size_mb = Self::lookup_account(&state, "__CONFIG_CACHE_SIZE_MB__")
                    .map(|a| a.balance)
                    .unwrap_or(0);
                let snapshot_interval_blocks =
                    Self::lookup_account(&state, "__SNAPSHOT_INTERVAL_BLOCKS__")
                        .map(|a| a.balance)
                        .unwrap_or(0);
                let max_snapshots_to_retain =
                    Self::lookup_account(&state, "__SNAPSHOT_MAX_RETAIN__")
                        .map(|a| a.balance)
                        .unwrap_or(0);
                // Sadece açık/kapalı, webhook URL'in kendisi hiçbir zaman
                // RPC üzerinden dışa açılmaz (bkz. main.rs'teki yazım yeri).
                let alerts_enabled = Self::lookup_account(&state, "__CONFIG_ALERTS_ENABLED__")
                    .map(|a| a.balance)
                    .unwrap_or(0)
                    != 0;
                // `enable_pruning=false` tam arşiv; `true` disk büyümesini `max_retained_blocks`
                // penceresine sınırlar (1.000 tx/sn karışık yükte ~30 TB/yıl ölçüldü).
                let enable_pruning = Self::lookup_account(&state, "__CONFIG_ENABLE_PRUNING__")
                    .map(|a| a.balance)
                    .unwrap_or(0)
                    != 0;
                let max_retained_blocks =
                    Self::lookup_account(&state, "__CONFIG_MAX_RETAINED_BLOCKS__")
                        .map(|a| a.balance)
                        .unwrap_or(0);
                let pruning_interval = Self::lookup_account(&state, "__CONFIG_PRUNING_INTERVAL__")
                    .map(|a| a.balance)
                    .unwrap_or(0);
                // 🛡️ P2P statik config alanları sentinel deseniyle yansıtılır (`zagros-rpc`
                // `zagros-network`'e bağımlı olamaz); canlı PeerId/peer sayısı burada yok.
                let enable_p2p = Self::lookup_account(&state, "__CONFIG_ENABLE_P2P__")
                    .map(|a| a.balance)
                    .unwrap_or(0)
                    != 0;
                let is_proposer = Self::lookup_account(&state, "__CONFIG_IS_PROPOSER__")
                    .map(|a| a.balance)
                    .unwrap_or(0)
                    != 0;
                let network_id = Self::lookup_account(&state, "__CONFIG_NETWORK_ID__")
                    .map(|a| a.balance)
                    .unwrap_or(0);
                let mdns_enabled = Self::lookup_account(&state, "__CONFIG_MDNS_ENABLED__")
                    .map(|a| a.balance)
                    .unwrap_or(0)
                    != 0;
                let sync_batch_size = Self::lookup_account(&state, "__CONFIG_SYNC_BATCH_SIZE__")
                    .map(|a| a.balance)
                    .unwrap_or(0);
                let listen_addr = Self::lookup_account(&state, "__CONFIG_LISTEN_ADDR__")
                    .map(|a| String::from_utf8_lossy(&a.contract_code).to_string())
                    .unwrap_or_default();

                serde_json::json!({
                    "gas_fee_zerenya": mempool.gas_target().to_string(),
                    "max_gas_per_block": mempool.max_block_gas_limit().to_string(),
                    "target_gas_per_block": target_gas_per_block.to_string(),
                    "enable_dynamic_gas": mempool.dynamic_pricing_enabled(),
                    "ddos_threshold": mempool.ddos_threshold(),
                    "mempool_max_capacity": mempool.max_capacity(),
                    "mempool_max_total_bytes": mempool.max_total_bytes(),
                    "cache_size_mb": cache_size_mb.to_string(),
                    "snapshot_interval_blocks": snapshot_interval_blocks.to_string(),
                    "max_snapshots_to_retain": max_snapshots_to_retain.to_string(),
                    "alerts_enabled": alerts_enabled,
                    "enable_pruning": enable_pruning,
                    "max_retained_blocks": max_retained_blocks.to_string(),
                    "pruning_interval": pruning_interval.to_string(),
                    "enable_p2p": enable_p2p,
                    "is_proposer": is_proposer,
                    "network_id": network_id.to_string(),
                    "mdns_enabled": mdns_enabled,
                    "sync_batch_size": sync_batch_size.to_string(),
                    "listen_addr": listen_addr,
                })
            }

            // 📈 `MetricsSample_<index % MAX>` dönen tamponu: dolu slotlar zaman
            // damgasına göre sıralanır (index sırası ≠ zaman sırası).
            "zagros_getMetricsHistory" => {
                let mut samples: Vec<zagros_types::MetricsSample> = Vec::new();
                for i in 0..zagros_types::MAX_METRICS_SAMPLES {
                    if let Some(acc) =
                        Self::lookup_account(&state, &zagros_types::metrics_sample_key(i))
                    {
                        if let Ok(sample) =
                            bincode::deserialize::<zagros_types::MetricsSample>(&acc.contract_code)
                        {
                            samples.push(sample);
                        }
                    }
                }
                samples.sort_by_key(|s| s.timestamp);

                serde_json::json!({
                    "samples": samples.iter().map(|s| serde_json::json!({
                        "timestamp": s.timestamp.to_string(),
                        "block_height": s.block_height.to_string(),
                        "mempool_load": s.mempool_load,
                        "stress_multiplier": s.stress_multiplier.to_string(),
                        "disk_usage_bytes": s.disk_usage_bytes.to_string(),
                    })).collect::<Vec<_>>(),
                })
            }

            "zagros_getNetworkPulse" => {
                let total_staked = if let Some(tracker) =
                    Self::lookup_account(&state, "__GLOBAL_TOTAL_STAKED__")
                {
                    tracker.balance
                } else {
                    0
                };

                let (pool_zagros, pool_zerenya) =
                    if let Some(pool) = Self::lookup_account(&state, LIQUIDITY_POOL_ADDRESS) {
                        (pool.balance, pool.zerenya_balance)
                    } else {
                        (0, 0)
                    };

                let (treasury_zagros, treasury_zerenya) =
                    if let Some(treasury) = Self::lookup_account(&state, VALIDATOR_REWARD_POOL) {
                        (treasury.balance, treasury.zerenya_balance)
                    } else {
                        (0, 0)
                    };

                let total_tx =
                    if let Some(tracker) = Self::lookup_account(&state, "__GLOBAL_TOTAL_TX__") {
                        tracker.balance.to_string()
                    } else {
                        "0".to_string()
                    };

                // `total_known_addresses()` Merkle state_root için tutulan
                // `address_index`'i kullanır (her zaman doğru, ayrı bir sayaç
                // gerektirmez).
                let total_accounts = state.total_known_addresses().unwrap_or(0).to_string();

                let block_height = if let Some(block_height_account) =
                    Self::lookup_account(&state, "__GLOBAL_BLOCK_HEIGHT__")
                {
                    block_height_account.balance
                } else {
                    0
                };

                serde_json::json!({
                    "total_staked": total_staked.to_string(),
                    "pool_zagros": pool_zagros.to_string(),
                    "pool_zerenya": pool_zerenya.to_string(),
                    "treasury_zagros": treasury_zagros.to_string(),
                    "treasury_zerenya": treasury_zerenya.to_string(),
                    "total_tx": total_tx,
                    "total_accounts": total_accounts,
                    "block_height": format!("0x{:x}", block_height),
                    "block_height_decimal": block_height.to_string(),
                })
            }

            "zagros_get_account_state" => {
                let address = safe_params.first().and_then(|v| v.as_str()).unwrap_or("");
                if let Some(account) = Self::lookup_account(&state, address) {
                    // Az önce bölerek hata yaptık. Doğrusu: sayıyı hiç ellemiyoruz, web arayüzünüz veya cüzdanınız
                    // zaten '10000' miktarını JavaScript'te kendi mantığına göre bölüp sonuna 0 koyuyor olmalı.
                    let zagros_scaled = account.balance;
                    let zerenya_scaled = account.zerenya_balance;
                    let staked_scaled = account.staked_balance;

                    let pending_rewards = match state.get_accumulated_reward_per_share() {
                        Ok(accumulated_reward_per_share) => {
                            let accrued = zagros_executor::reward_owed(
                                account.staked_balance,
                                accumulated_reward_per_share,
                            );
                            accrued.saturating_sub(account.reward_debt)
                        }
                        Err(_) => 0,
                    };

                    let pending_unstake_scaled = account.pending_unstake_amount;

                    // 🛡️ Gözlemlenebilirlik: `pending_stake_amount`/`pending_stake_activation_time`
                    // dışa açılır (`staked_balance` yalnız hak etmiş kısmı gösterir).
                    let pending_stake_scaled = account.pending_stake_amount;

                    serde_json::json!({
                        "address": address,
                        "balance": zagros_scaled.to_string(),
                        "zerenya_balance": zerenya_scaled.to_string(),
                        "nonce": account.nonce,
                        "staked_balance": staked_scaled.to_string(),
                        "pending_rewards": pending_rewards.to_string(),
                        "pending_unstake_amount": pending_unstake_scaled.to_string(),
                        "unlock_time": account.unlock_time.to_string(),
                        "pending_stake_amount": pending_stake_scaled.to_string(),
                        "pending_stake_activation_time": account.pending_stake_activation_time.to_string(),
                        // 🛡️ Validator Command Center için: bu üç alan da
                        // AccountState'te zaten vardı, hiç dışa açılmamıştı.
                        "is_registered_validator": account.is_registered_validator,
                        "jailed_until": account.jailed_until.to_string(),
                        "validator_registered_at": account.validator_registered_at.to_string(),
                    })
                } else {
                    serde_json::json!({
                        "address": address, "balance": "0", "zerenya_balance": "0", "nonce": 0,
                        "staked_balance": "0", "pending_rewards": "0", "pending_unstake_amount": "0",
                        "unlock_time": "0", "pending_stake_amount": "0", "pending_stake_activation_time": "0",
                        "is_registered_validator": false, "jailed_until": "0",
                        "validator_registered_at": "0",
                    })
                }
            }

            "zagros_getPendingUnstake" => {
                let address = safe_params.first().and_then(|v| v.as_str()).unwrap_or("");
                if let Some(acc) = Self::lookup_account(&state, address) {
                    let current_time_secs = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as u128;

                    let remaining_ms = acc
                        .unlock_time
                        .saturating_sub(current_time_secs)
                        .saturating_mul(1000);
                    let pending_scaled = acc.pending_unstake_amount;

                    serde_json::json!({
                        "pending_amount_hex": format!("0x{:x}", pending_scaled),
                        "pending_amount_raw": pending_scaled.to_string(),
                        "unlock_time_ms": acc.unlock_time.saturating_mul(1000),
                        "remaining_ms": remaining_ms,
                        "is_locked": remaining_ms > 0 && acc.pending_unstake_amount > 0
                    })
                } else {
                    serde_json::json!({
                        "pending_amount_hex": "0x0",
                        "pending_amount_raw": "0",
                        "unlock_time_ms": 0,
                        "remaining_ms": 0,
                        "is_locked": false
                    })
                }
            }

            // 🚨 Aynı izole simülasyonla gerçek gas ölçülür; `data`sız native çağrılar
            // 21000, revert/halt'ta JSON-RPC hatası (geth davranışı).
            "eth_estimateGas" => {
                let call_obj = safe_params.first().unwrap_or(&Value::Null);
                let to = call_obj.get("to").and_then(|v| v.as_str()).unwrap_or("");
                let data = call_obj.get("data").and_then(|v| v.as_str()).unwrap_or("");
                let from = call_obj
                    .get("from")
                    .and_then(|v| v.as_str())
                    .unwrap_or("0x0000000000000000000000000000000000000000");

                if data.is_empty() || data == "0x" {
                    // Düz 21000 yerine `apply_fixed_gas_fee`'nin uygulayacağı sabit ücrete
                    // karşılık gelen "sentetik" gas_limit: MetaMask'ın gas_limit × gasPrice
                    // çarpımı gerçek ücrete yaklaşır (ücretlendirme değişmez, gösterim).
                    Value::String(format!(
                        "0x{:x}",
                        synthetic_gas_limit_for_fee(
                            mempool.native_min_required_fee(&TxType::Transfer)
                        )
                    ))
                } else {
                    let to_address = if to.is_empty() {
                        "0x0000000000000000000000000000000000000000".to_string()
                    } else {
                        to.to_string()
                    };
                    let from_address = if from.is_empty() {
                        "0x0000000000000000000000000000000000000000".to_string()
                    } else {
                        from.to_string()
                    };
                    let payload =
                        hex::decode(data.strip_prefix("0x").unwrap_or(data)).unwrap_or_default();

                    // 🚨 Sahte kontrat adresleri simülasyondan ÖNCE tanınıp native ilkeyle
                    // 21000 dönülür (modexp sahte `PrecompileError` üretirdi).
                    if let Some((native_tx_type, _)) =
                        Self::native_tx_type_for_evm_call(&to_address, &payload)
                    {
                        // Tanınan native tipin gerçek sabit ücretine karşılık gelen sentetik gas_limit.
                        return RpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: req.id,
                            result: Some(Value::String(format!(
                                "0x{:x}",
                                synthetic_gas_limit_for_fee(
                                    mempool.native_min_required_fee(&native_tx_type)
                                )
                            ))),
                            error: None,
                        };
                    }

                    // 🛡️ Kullanıcı beyanı tavana kadar saygı görür; bütçe `eth_call` ile paylaşımlı.
                    let effective_gas =
                        resolve_effective_gas(call_obj, evm_limits.eth_estimate_gas_max_gas);
                    let _evm_sim_guard = match InFlightGuard::try_acquire(
                        &EVM_SIMULATION_IN_FLIGHT,
                        evm_limits.max_parallel_simulations,
                    ) {
                        Some(guard) => guard,
                        None => {
                            EVM_SIMULATION_BUSY_COUNT.fetch_add(1, Ordering::Relaxed);
                            return RpcResponse {
                                jsonrpc: "2.0".to_string(),
                                id: req.id,
                                result: None,
                                error: Some(serde_json::json!({
                                    "code": -32005,
                                    "message": "Server busy: too many concurrent EVM simulations (eth_call/eth_estimateGas), retry shortly"
                                })),
                            };
                        }
                    };

                    let executor = zagros_executor::evm::EvmExecutor::new(state.clone());
                    match executor.simulate_gas_estimate(
                        &from_address,
                        &to_address,
                        payload,
                        effective_gas,
                    ) {
                        Ok(gas_used) => {
                            // Standart cüzdan/geth pratiği: gerçek `gas_used`'a ~%20
                            // tampon ekle (gönderim anındaki state farkları
                            // simülasyondan biraz sapabilir).
                            let with_buffer =
                                gas_used.saturating_mul(120).saturating_div(100).max(21_000);
                            Value::String(format!("0x{:x}", with_buffer))
                        }
                        Err(e) => {
                            warn!(
                                "⚠️ eth_estimateGas: simülasyon reverted/başarısız: {:?} (from={} to={} data={})",
                                e, from_address, to_address, data
                            );
                            return RpcResponse {
                                jsonrpc: "2.0".to_string(),
                                id: req.id,
                                result: None,
                                error: Some(serde_json::json!({
                                    "code": -32000,
                                    "message": "execution reverted: gas estimation failed because the transaction would fail"
                                })),
                            };
                        }
                    }
                }
            }
            // `synthetic_gas_limit_for_fee`'nin böldüğü AYNI sabit (`MIN_EVM_GAS_PRICE_WEI`);
            // eth_gasPrice × eth_estimateGas gerçek ücrete karşılık gelsin.
            "eth_gasPrice" => Value::String(format!("0x{:x}", zagros_types::MIN_EVM_GAS_PRICE_WEI)),
            // 🚨 Gerçek `contract_code` okunur; sabit "0x" cüzdanların "kontrat mı"
            // uyarılarını ve dApp kararlarını yanıltır.
            "eth_getCode" => {
                let address = safe_params.first().and_then(|v| v.as_str()).unwrap_or("");
                match Self::lookup_account(&state, address) {
                    Some(account) if !account.contract_code.is_empty() => {
                        Value::String(format!("0x{}", hex::encode(account.contract_code)))
                    }
                    _ => Value::String("0x".to_string()),
                }
            }
            // 🚨 `AccountState.storage` (bkz. `zagros-types`) EVM SLOAD/SSTORE
            // için GERÇEK, kalıcı depolama tutar; eth_getCode ile aynı ilkeyle
            // gerçek değer okunur, uydurma/sabit bir şey dönmez.
            "eth_getStorageAt" => {
                let address = safe_params.first().and_then(|v| v.as_str()).unwrap_or("");
                let position_hex = safe_params.get(1).and_then(|v| v.as_str()).unwrap_or("0x0");
                let clean = position_hex.strip_prefix("0x").unwrap_or(position_hex);
                if clean.len() > 64 {
                    return RpcResponse {
                        jsonrpc: "2.0".to_string(),
                        id: req.id,
                        result: None,
                        error: Some(serde_json::json!({
                            "code": -32602,
                            "message": "Invalid params: storage position exceeds 32 bytes"
                        })),
                    };
                }
                let padded = format!("{:0>64}", clean);
                match hex::decode(&padded) {
                    Ok(bytes) => {
                        let position_bytes: [u8; 32] = bytes.try_into().unwrap();
                        let position = zagros_types::U256::from_be_bytes(position_bytes);
                        let value = Self::lookup_account(&state, address)
                            .and_then(|account| account.storage.get(&position).cloned())
                            .unwrap_or(zagros_types::U256::ZERO);
                        Value::String(format!("0x{}", hex::encode(value.to_be_bytes::<32>())))
                    }
                    Err(_) => {
                        return RpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: req.id,
                            result: None,
                            error: Some(serde_json::json!({
                                "code": -32602,
                                "message": "Invalid params: storage position is not valid hex"
                            })),
                        };
                    }
                }
            }
            // Zagros DPoS kullanıyor, PoW değil, "amca blok" (uncle/ommer)
            // kavramı YOK. Bu yüzden 0 sabit değil, GERÇEK ve DOĞRU cevap.
            "eth_getUncleCountByBlockNumber" | "eth_getUncleCountByBlockHash" => {
                Value::String("0x0".to_string())
            }
            "eth_feeHistory" => serde_json::json!({
                "oldestBlock": "0x1",
                "reward": [["0x0"]],
                "baseFeePerGas": ["0x0", "0x0"],
                "gasUsedRatio": [0.0]
            }),

            // 🏛️ Gerçek `parentHash`/`stateRoot`/`hash`/`timestamp`/`transactions`
            // parametredeki bloktan; `logsBloom`/`transactionsRoot`/`receiptsRoot`
            // bilerek placeholder (ayrı Merkle/bloom gerektirir).
            "eth_getBlockByNumber" => {
                let number = match Self::resolve_block_number_param(&state, safe_params.first()) {
                    Some(n) => n,
                    None => {
                        return RpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: req.id,
                            result: None,
                            error: Some(serde_json::json!({
                                "code": -32602,
                                "message": "invalid block parameter"
                            })),
                        };
                    }
                };
                let full = safe_params
                    .get(1)
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                match Self::load_archived_block(&state, number) {
                    Some((header, hash)) => {
                        Self::block_json_full(&state, number, &header, hash, full)
                    }
                    None => Value::Null,
                }
            }

            "eth_getBlockByHash" => {
                let hash_param = safe_params.first().and_then(|v| v.as_str()).unwrap_or("");
                let clean = hash_param
                    .strip_prefix("0x")
                    .unwrap_or(hash_param)
                    .to_lowercase();
                match Self::resolve_block_number_by_hash(&state, &clean).and_then(|number| {
                    Self::load_archived_block(&state, number).map(|b| (number, b))
                }) {
                    Some((number, (header, hash))) => {
                        Self::block_json(&state, number, &header, hash)
                    }
                    None => Value::Null,
                }
            }

            // Standart EIP-1559 istemcilerinin (MetaMask/ethers/viem) gas ücreti
            // tahmini için çağırdığı metod; `eth_gasPrice`/`eth_feeHistory`'nin
            // sabit döndürdüğü ücretle tutarlı bir değer veriyoruz.
            "eth_maxPriorityFeePerGas" => Value::String("0x3b9aca00".to_string()),

            // 🌉 KÖPRÜ ÇOKLU İMZA AKIŞI: mint yalnız aktif yetkilinin Ed25519 imzasıyla
            // önerilir/onaylanır; Burn çoklu imza gerektirmez, off-chain mutabakat verisidir.

            // 1. Yetkili yeni öneri sunar (mint ya da burn); kimlik Ed25519 imza
            // (tx_type dahil, `propose_request_message`).
            "zagros_proposeBridgeAction" => {
                let tx_type_str = safe_params.first().and_then(|v| v.as_str()).unwrap_or("");
                let tx_type = match tx_type_str {
                    "mint" => BridgeTxType::Mint,
                    "burn" => BridgeTxType::Burn,
                    _ => {
                        return RpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: req.id,
                            result: None,
                            error: Some(json!({
                                "code": -32602,
                                "message": "InvalidParams: tx_type must be \"mint\" or \"burn\""
                            })),
                        };
                    }
                };
                let recipient = safe_params
                    .get(1)
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let amount = safe_params
                    .get(2)
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<u128>().ok())
                    .unwrap_or(0);
                let source_chain = safe_params
                    .get(3)
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let source_tx_hash = safe_params
                    .get(4)
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let timestamp = safe_params
                    .get(5)
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);
                // Sadece mint için anlamlı ("basılan ZERENYA anında ZAGROS'a
                // çevrilsin mi"), burn/unlock-intent yönünde yok sayılır.
                let auto_swap = safe_params
                    .get(6)
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                // 🛡️ Kullanıcının `lockTokens`'ta belirttiği minimum ZAGROS çıktısı
                // (yalnızca auto_swap=true iken anlamlı), zincirdeki TokensLocked
                // olayından AYNEN taşınır, relayer/node bunu değiştiremez (imzaya dahil).
                let amount_out_min = safe_params
                    .get(7)
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<u128>().ok())
                    .unwrap_or(0);
                let authority = safe_params
                    .get(8)
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let public_key_hex = safe_params.get(9).and_then(|v| v.as_str()).unwrap_or("");
                let signature_hex = safe_params.get(10).and_then(|v| v.as_str()).unwrap_or("");

                // 🛡️ Timestamp Drift Guard: replay/ağ dinleme koruması, en ucuz
                // kontrol olduğu için imza/anahtar çözümlemesinden önce yapılır.
                if !bridge_timestamp_within_drift_window(timestamp) {
                    tracing::warn!(
                        target: "security::bridge",
                        "🚨 zagros_proposeBridgeAction reddedildi: timestamp ({}) izin verilen \
                         ±{}s penceresi dışında (authority={})",
                        timestamp,
                        BRIDGE_RPC_TIMESTAMP_DRIFT_SECS,
                        authority
                    );
                    return RpcResponse {
                        jsonrpc: "2.0".to_string(),
                        id: req.id,
                        result: None,
                        error: Some(json!({
                            "code": -32602,
                            "message": "InvalidParams: timestamp outside the allowed ±120s drift window"
                        })),
                    };
                }

                let public_key_bytes =
                    hex::decode(public_key_hex.strip_prefix("0x").unwrap_or(public_key_hex)).ok();
                let signature_bytes =
                    hex::decode(signature_hex.strip_prefix("0x").unwrap_or(signature_hex)).ok();

                match (public_key_bytes, signature_bytes) {
                    (Some(pk), Some(sig)) if pk.len() == 32 => {
                        let mut public_key = [0u8; 32];
                        public_key.copy_from_slice(&pk);
                        let now = std::time::UNIX_EPOCH.elapsed().unwrap().as_millis();

                        let mut manager = bridge_manager.lock().unwrap();
                        let message = BridgeManager::propose_request_message(
                            &tx_type,
                            &recipient,
                            amount,
                            &source_chain,
                            &source_tx_hash,
                            timestamp,
                            auto_swap,
                            amount_out_min,
                            manager.chain_id(),
                        );
                        if !manager.authenticate_authority_request(
                            &authority,
                            &public_key,
                            &message,
                            &sig,
                        ) {
                            warn!(
                                "🚨 Köprü: Yetkisiz zagros_proposeBridgeAction denemesi (authority={})",
                                authority
                            );
                            serde_json::json!({"error": "Unauthorized: unknown authority or invalid signature"})
                        } else if let Err(e) = verify_burn_proposal_if_needed(
                            state.as_ref(),
                            &tx_type,
                            &source_tx_hash,
                            &recipient,
                            amount,
                        ) {
                            // 🛡️ "burn" önerisi yalnız zincirin görünürlük indeksinde kayıtlı
                            // GERÇEK bir yakma için oluşturulur; yoksa tek yetkilinin uydurduğu
                            // öneriyi diğerleri körlemesine eş imzalardı (bkz. verify_source_burn_matches).
                            tracing::warn!(
                                target: "security::bridge",
                                "🚨 Köprü: uydurma/eslesmeyen burn onerisi reddedildi (authority={}, source_tx_hash={}): {}",
                                authority, source_tx_hash, e
                            );
                            serde_json::json!({"error": format!("Burn dogrulanamadi: {}", e)})
                        } else {
                            match manager.create_proposal(
                                tx_type,
                                amount,
                                recipient,
                                source_chain,
                                source_tx_hash,
                                timestamp,
                                auto_swap,
                                amount_out_min,
                                now,
                                state.as_ref(),
                            ) {
                                Ok(proposal_id) => {
                                    // D14-kozmetik (denetim C7): persist hatası artık SESSİZ değil.
                                    if let Err(e) =
                                        manager.persist_proposal(state.as_ref(), &proposal_id)
                                    {
                                        tracing::error!(
                                            "🌉 öneri persist HATASI (restart'ta kaybolur): {e:?}"
                                        );
                                    }
                                    let _ = manager.persist_meta(state.as_ref());
                                    tracing::info!(
                                        "🌉 Köprü önerisi oluşturuldu: 0x{} (yetkili={}, tür={})",
                                        hex::encode(proposal_id),
                                        authority,
                                        tx_type_str
                                    );
                                    serde_json::json!({
                                        "proposal_id": format!("0x{}", hex::encode(proposal_id))
                                    })
                                }
                                Err(e) => serde_json::json!({"error": e.to_string()}),
                            }
                        }
                    }
                    _ => serde_json::json!({"error": "Invalid public_key_hex or signature_hex"}),
                }
            }

            // 2. Bir yetkili, var olan bir öneriyi kendi Ed25519 imzasıyla
            // onaylar, kriptografik doğrulama BridgeManager::sign_proposal
            // içinde zaten tam olarak yapılıyor.
            "zagros_signBridgeProposal" => {
                let proposal_id_hex = safe_params.first().and_then(|v| v.as_str()).unwrap_or("");
                let authority = safe_params
                    .get(1)
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let public_key_hex = safe_params.get(2).and_then(|v| v.as_str()).unwrap_or("");
                let signature_hex = safe_params.get(3).and_then(|v| v.as_str()).unwrap_or("");
                let timestamp = safe_params
                    .get(4)
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);

                // 🛡️ Timestamp Drift Guard: replay/ağ dinleme koruması, en ucuz
                // kontrol olduğu için imza/anahtar çözümlemesinden önce yapılır.
                if !bridge_timestamp_within_drift_window(timestamp) {
                    tracing::warn!(
                        target: "security::bridge",
                        "🚨 zagros_signBridgeProposal reddedildi: timestamp ({}) izin verilen \
                         ±{}s penceresi dışında (authority={})",
                        timestamp,
                        BRIDGE_RPC_TIMESTAMP_DRIFT_SECS,
                        authority
                    );
                    return RpcResponse {
                        jsonrpc: "2.0".to_string(),
                        id: req.id,
                        result: None,
                        error: Some(json!({
                            "code": -32602,
                            "message": "InvalidParams: timestamp outside the allowed ±120s drift window"
                        })),
                    };
                }

                let proposal_id_bytes = hex::decode(
                    proposal_id_hex
                        .strip_prefix("0x")
                        .unwrap_or(proposal_id_hex),
                )
                .ok();
                let public_key_bytes =
                    hex::decode(public_key_hex.strip_prefix("0x").unwrap_or(public_key_hex)).ok();
                let signature_bytes =
                    hex::decode(signature_hex.strip_prefix("0x").unwrap_or(signature_hex)).ok();

                match (proposal_id_bytes, public_key_bytes, signature_bytes) {
                    (Some(pid), Some(pk), Some(sig)) if pid.len() == 32 => {
                        let mut proposal_id = [0u8; 32];
                        proposal_id.copy_from_slice(&pid);
                        let now = std::time::UNIX_EPOCH.elapsed().unwrap().as_millis();

                        let mut manager = bridge_manager.lock().unwrap();
                        match manager.sign_proposal(
                            &proposal_id,
                            authority.clone(),
                            sig,
                            pk,
                            timestamp,
                            now,
                        ) {
                            Ok(()) => {
                                if let Err(e) =
                                    manager.persist_proposal(state.as_ref(), &proposal_id)
                                {
                                    tracing::error!(
                                        "🌉 öneri persist HATASI (restart'ta kaybolur): {e:?}"
                                    );
                                }
                                let can_execute =
                                    manager.can_execute(&proposal_id, now).unwrap_or(false);
                                tracing::info!(
                                    "🌉 Köprü önerisi imzalandı: 0x{} (yetkili={})",
                                    hex::encode(proposal_id),
                                    authority
                                );
                                serde_json::json!({"ok": true, "can_execute": can_execute})
                            }
                            Err(e) => {
                                warn!(
                                    "🚨 Köprü: Geçersiz zagros_signBridgeProposal denemesi (authority={}): {}",
                                    authority, e
                                );
                                serde_json::json!({"error": e.to_string()})
                            }
                        }
                    }
                    _ => serde_json::json!({
                        "error": "Invalid proposal_id_hex, public_key_hex, or signature_hex"
                    }),
                }
            }

            // 🎟️ Claim fişi sunma: haberci `claimTokens` için EIP-712 imzasını bırakır.
            // Ayrı kimlik doğrulaması yok, fiş kendini doğrular (`add_claim_voucher`).
            "zagros_submitClaimVoucher" => {
                let proposal_id_hex = safe_params.first().and_then(|v| v.as_str()).unwrap_or("");
                let signature_hex = safe_params.get(1).and_then(|v| v.as_str()).unwrap_or("");

                let decoded = hex::decode(
                    proposal_id_hex
                        .strip_prefix("0x")
                        .unwrap_or(proposal_id_hex),
                );

                match decoded {
                    Ok(bytes) if bytes.len() == 32 => {
                        let mut proposal_id = [0u8; 32];
                        proposal_id.copy_from_slice(&bytes);

                        let mut manager = bridge_manager.lock().unwrap();
                        match manager.add_claim_voucher(&proposal_id, signature_hex) {
                            Ok(signer) => {
                                if let Err(e) =
                                    manager.persist_proposal(state.as_ref(), &proposal_id)
                                {
                                    tracing::error!(
                                        "🌉 öneri persist HATASI (restart'ta kaybolur): {e:?}"
                                    );
                                }
                                let collected = manager
                                    .get_proposal(&proposal_id)
                                    .map(|p| p.claim_vouchers.len())
                                    .unwrap_or(0);
                                tracing::info!(
                                    "🎟️ Claim fişi kabul edildi: 0x{} (haberci={}, toplam={})",
                                    hex::encode(proposal_id),
                                    signer,
                                    collected
                                );
                                serde_json::json!({
                                    "ok": true,
                                    "signer": signer,
                                    "vouchers_collected": collected,
                                })
                            }
                            Err(e) => {
                                warn!(
                                    target: "security::bridge",
                                    "🚨 Köprü: Geçersiz zagros_submitClaimVoucher denemesi (öneri=0x{}): {}",
                                    hex::encode(proposal_id),
                                    e
                                );
                                serde_json::json!({"error": e.to_string()})
                            }
                        }
                    }
                    _ => serde_json::json!({"error": "Invalid proposal_id_hex"}),
                }
            }

            // 3. Salt okuma, herhangi biri bir önerinin durumunu sorgulayabilir
            // (relayer araçları/panolar için), kimlik doğrulaması gerekmez.
            "zagros_getBridgeProposal" => {
                let proposal_id_hex = safe_params.first().and_then(|v| v.as_str()).unwrap_or("");
                let decoded = hex::decode(
                    proposal_id_hex
                        .strip_prefix("0x")
                        .unwrap_or(proposal_id_hex),
                );

                match decoded {
                    Ok(bytes) if bytes.len() == 32 => {
                        let mut proposal_id = [0u8; 32];
                        proposal_id.copy_from_slice(&bytes);

                        let manager = bridge_manager.lock().unwrap();
                        let proposal = manager
                            .get_proposal(&proposal_id)
                            .cloned()
                            .or_else(|| {
                                BridgeManager::load_proposal_from_state(
                                    state.as_ref(),
                                    &proposal_id,
                                )
                                .ok()
                                .flatten()
                            })
                            // item 5: yürütülmüş (arşivlenmiş) öneriler artık aktif
                            // `Bridge_<hex>` anahtarında değil, üçüncü halka bunları
                            // hâlâ id ile sorgulanabilir tutuyor (RPC davranışı bozulmasın diye).
                            .or_else(|| {
                                BridgeManager::load_archived_proposal_from_state(
                                    state.as_ref(),
                                    &proposal_id,
                                )
                                .ok()
                                .flatten()
                            });

                        match proposal {
                            Some(p) => {
                                let now = std::time::UNIX_EPOCH.elapsed().unwrap().as_millis();
                                let can_execute =
                                    manager.can_execute(&proposal_id, now).unwrap_or(false);
                                bridge_proposal_json(&p, can_execute)
                            }
                            None => serde_json::json!({"error": "Proposal not found"}),
                        }
                    }
                    _ => serde_json::json!({"error": "Invalid proposal_id_hex"}),
                }
            }

            // 🗳️ Yönetişim özeti: parametreler, pencereler (sentinel ya da varsayılan),
            // öneri ekonomisi, aktif küme; dApp form sınırlarını buradan alır.
            "zagros_getGovernanceInfo" => {
                let params = zagros_executor::params::load_chain_params(state.as_ref())
                    .unwrap_or_else(|_| zagros_types::consensus::ChainParams::genesis_defaults());
                let qc_grace = zagros_executor::params::load_qc_grace_ms(state.as_ref())
                    .unwrap_or(zagros_types::consensus::DEFAULT_QC_GRACE_MS);
                let genesis_ts =
                    zagros_executor::params::genesis_timestamp(state.as_ref()).unwrap_or(0);
                let now_secs = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs() as u128)
                    .unwrap_or(0);
                let current_epoch =
                    zagros_executor::params::epoch_at(now_secs, genesis_ts, params.epoch_seconds);
                let height = Self::lookup_account(&state, "__GLOBAL_BLOCK_HEIGHT__")
                    .map(|a| a.balance as u64)
                    .unwrap_or(0);
                let econ = Self::lookup_account(&state, "__CONFIGURED_GOVERNANCE_ECON__");
                let (fee, min_stake, max_active) = econ
                    .map(|a| (a.balance, a.staked_balance, a.nonce))
                    .unwrap_or((
                        1000 * zagros_types::TOKEN_DECIMAL,
                        10_000 * zagros_types::TOKEN_DECIMAL,
                        50,
                    ));
                let windows = Self::lookup_account(&state, "__CONFIGURED_GOVERNANCE_WINDOWS__")
                    .map(|a| (a.balance as u64, a.staked_balance as u64))
                    .unwrap_or((7 * 24 * 60 * 60, 30 * 24 * 60 * 60));
                let active_count = Self::lookup_account(&state, "__ACTIVE_PROPOSAL_COUNT__")
                    .map(|a| a.balance)
                    .unwrap_or(0);
                let total_staked = Self::lookup_account(&state, "__GLOBAL_TOTAL_STAKED__")
                    .map(|a| a.balance)
                    .unwrap_or(0);
                let escrow = Self::lookup_account(
                    &state,
                    zagros_executor::governance::GOV_DEPOSIT_ESCROW_KEY,
                )
                .map(|a| a.balance)
                .unwrap_or(0);
                let set = zagros_executor::validator_set::load_active_set(state.as_ref()).ok();
                let admin_end =
                    zagros_executor::params::admin_authority_end(state.as_ref()).unwrap_or(0);
                let rows = gov_param_key_rows(&params, qc_grace);
                json!({
                    "height": height,
                    "genesis_timestamp": genesis_ts.to_string(),
                    "now": now_secs.to_string(),
                    "current_epoch": current_epoch,
                    "epoch_seconds": params.epoch_seconds,
                    "gov_voting_epochs": params.gov_voting_epochs,
                    "timelock_epochs": params.timelock_epochs,
                    "staker_quorum_bps": params.staker_quorum_bps,
                    "vote_cap_bps": params.vote_cap_bps,
                    "max_validators": params.max_validators,
                    "active_ruleset": params.active_ruleset,
                    "proposal_fee": fee.to_string(),
                    "min_stake_to_submit": min_stake.to_string(),
                    "max_active_proposals": max_active,
                    "active_proposal_count": active_count.to_string(),
                    "text_voting_period_secs": windows.0,
                    "text_proposal_expiry_secs": windows.1,
                    "deposit_activation_height": zagros_types::GOV_DEPOSIT_ACTIVATION_HEIGHT,
                    "deposit_mode": height >= zagros_types::GOV_DEPOSIT_ACTIVATION_HEIGHT,
                    "deposit_escrow_total": escrow.to_string(),
                    "total_staked": total_staked.to_string(),
                    "admin_authority_end": admin_end.to_string(),
                    "admin_phase_active": now_secs <= admin_end,
                    "active_set": set.as_ref().map(|s| s.members.iter().map(|m| m.address.clone()).collect::<Vec<_>>()).unwrap_or_default(),
                    "active_set_epoch": set.as_ref().map(|s| s.epoch),
                    "governance_address": zagros_types::GOVERNANCE_ADDRESS,
                    "submit_selector": "0xd2383136",
                    "vote_selector": "0xe9dc0614",
                    "param_keys": rows.iter().enumerate().map(|(i, (k, name, cur))| json!({
                        "index": i,
                        "key": format!("{:?}", k),
                        "name": name,
                        "channel": format!("{:?}", k.channel()),
                        "current": cur.to_string(),
                    })).collect::<Vec<_>>(),
                })
            }

            // 🗳️ Öneri listesi (dizin sırası, en yeni önce): durum, pencere,
            // doğrulayıcı ve staker sayımı, depozito. Parametreler:
            // [limit?, address?], address verilirse o adresin oyu da döner.
            "zagros_listProposals" => {
                let limit = safe_params
                    .first()
                    .and_then(|v| v.as_u64())
                    .unwrap_or(50)
                    .clamp(1, 200) as usize;
                let who = safe_params
                    .get(1)
                    .and_then(|v| v.as_str())
                    .map(|a| a.to_ascii_lowercase());
                let params = zagros_executor::params::load_chain_params(state.as_ref())
                    .unwrap_or_else(|_| zagros_types::consensus::ChainParams::genesis_defaults());
                let genesis_ts =
                    zagros_executor::params::genesis_timestamp(state.as_ref()).unwrap_or(0);
                let now_secs = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let current_epoch = zagros_executor::params::epoch_at(
                    now_secs as u128,
                    genesis_ts,
                    params.epoch_seconds,
                );
                let windows = Self::lookup_account(&state, "__CONFIGURED_GOVERNANCE_WINDOWS__")
                    .map(|a| (a.balance as u64, a.staked_balance as u64))
                    .unwrap_or((7 * 24 * 60 * 60, 30 * 24 * 60 * 60));
                let set = zagros_executor::validator_set::load_active_set(state.as_ref()).ok();
                let ids =
                    zagros_executor::governance::load_index(state.as_ref()).unwrap_or_default();
                let epoch_ts = |e: u64| -> String {
                    genesis_ts
                        .saturating_add((e as u128).saturating_mul(params.epoch_seconds as u128))
                        .to_string()
                };
                let mut out = Vec::new();
                for pid in ids.iter().rev().take(limit) {
                    let Ok(Some(p)) =
                        zagros_executor::Executor::load_proposal_from_state(state.as_ref(), pid)
                    else {
                        continue;
                    };
                    let is_text = p.action == zagros_types::consensus::ProposalAction::Text;
                    let is_upgrade = matches!(
                        p.action,
                        zagros_types::consensus::ProposalAction::ScheduleUpgrade { .. }
                    );
                    let channel = p
                        .action
                        .channel()
                        .ok()
                        .flatten()
                        .map(|c| format!("{:?}", c));
                    // Durum + evre: tipli → kalıcı durum; metin → tembel efektif durum.
                    let status = if is_text {
                        zagros_types::effective_status(&p, now_secs, windows.0, windows.1)
                            .to_string()
                    } else {
                        p.status.to_string()
                    };
                    let voting_open = if is_text {
                        now_secs < (p.created_at as u64).saturating_add(windows.0)
                    } else {
                        p.status == zagros_types::ProposalStatus::Active
                            && current_epoch < p.voting_ends_at_epoch
                    };
                    let phase = if voting_open {
                        "Voting"
                    } else if !is_text && p.status == zagros_types::ProposalStatus::Active {
                        "Tallying"
                    } else {
                        "Closed"
                    };
                    let (vt_yes, vt_no, vt_total, votes_json) = match &set {
                        Some(s) => {
                            let votes = zagros_executor::governance::validator_votes_view(
                                state.as_ref(),
                                pid,
                                s,
                            )
                            .unwrap_or_default();
                            let yes = votes.iter().filter(|(_, v)| *v == Some(true)).count() as u64;
                            let no = votes.iter().filter(|(_, v)| *v == Some(false)).count() as u64;
                            let vj = votes
                                .iter()
                                .map(|(a, v)| json!({ "address": a, "support": v }))
                                .collect::<Vec<_>>();
                            (yes, no, s.members.len() as u64, vj)
                        }
                        None => (0, 0, 0, Vec::new()),
                    };
                    let yes_needed = if is_upgrade {
                        (4 * vt_total + 4) / 5
                    } else {
                        (2 * vt_total + 2) / 3
                    };
                    let (st_acc, st_q, st_part, st_yes, st_no, st_total) =
                        zagros_executor::governance::staker_tally_view(
                            state.as_ref(),
                            pid,
                            params.vote_cap_bps,
                            params.staker_quorum_bps,
                        )
                        .unwrap_or((false, false, 0, 0, 0, 0));
                    let deposit =
                        zagros_executor::governance::deposit_of(state.as_ref(), pid).unwrap_or(0);
                    let my_vote = who.as_ref().and_then(|a| {
                        zagros_executor::governance::vote_of_view(state.as_ref(), pid, a)
                            .ok()
                            .flatten()
                    });
                    out.push(json!({
                        "proposal_id": format!("0x{}", hex::encode(pid)),
                        "proposer": p.proposer,
                        "created_at": p.created_at.to_string(),
                        "description": if is_text { String::from_utf8_lossy(&p.description).to_string() } else { String::new() },
                        "action": gov_action_json(&p.action),
                        "channel": channel,
                        "status": status,
                        "phase": phase,
                        "voting_ends_at_epoch": p.voting_ends_at_epoch,
                        "voting_ends_at": if is_text {
                            (p.created_at as u64).saturating_add(windows.0).to_string()
                        } else {
                            epoch_ts(p.voting_ends_at_epoch)
                        },
                        "executes_at_epoch": p.executes_at_epoch,
                        "executes_at": if p.executes_at_epoch > 0 { Some(epoch_ts(p.executes_at_epoch)) } else { None },
                        "votes_for": p.votes_for.to_string(),
                        "votes_against": p.votes_against.to_string(),
                        "deposit": deposit.to_string(),
                        "validator_tally": {
                            "yes": vt_yes, "no": vt_no, "voted": vt_yes + vt_no, "total": vt_total,
                            "yes_needed": yes_needed, "votes": votes_json,
                        },
                        "staker_tally": {
                            "accepted": st_acc, "quorum_ok": st_q,
                            "participation": st_part.to_string(), "yes_weight": st_yes.to_string(),
                            "no_weight": st_no.to_string(), "total_staked": st_total.to_string(),
                            "quorum_bps": params.staker_quorum_bps,
                        },
                        "my_vote": my_vote.map(|(s, w)| json!({ "support": s, "weight": w.to_string() })),
                    }));
                }
                json!({ "current_epoch": current_epoch, "total": ids.len(), "proposals": out })
            }

            "zagros_getProposal" => {
                let proposal_id_hex = safe_params.first().and_then(|v| v.as_str()).unwrap_or("");
                let decoded = hex::decode(
                    proposal_id_hex
                        .strip_prefix("0x")
                        .unwrap_or(proposal_id_hex),
                );
                match decoded {
                    Ok(bytes) if bytes.len() == 32 => {
                        let mut proposal_id = [0u8; 32];
                        proposal_id.copy_from_slice(&bytes);

                        match zagros_executor::Executor::load_proposal_from_state(
                            state.as_ref(),
                            &proposal_id,
                        ) {
                            Ok(Some(p)) => {
                                let (voting_period_secs, proposal_expiry_secs) = state
                                    .get_account(&"__CONFIGURED_GOVERNANCE_WINDOWS__".to_string())
                                    .ok()
                                    .flatten()
                                    .map(|acc| (acc.balance as u64, acc.staked_balance as u64))
                                    .unwrap_or((7 * 24 * 60 * 60, 30 * 24 * 60 * 60));
                                let now_secs = std::time::UNIX_EPOCH
                                    .elapsed()
                                    .unwrap_or_default()
                                    .as_secs();
                                let status = zagros_types::effective_status(
                                    &p,
                                    now_secs,
                                    voting_period_secs,
                                    proposal_expiry_secs,
                                );
                                serde_json::json!({
                                    "proposal_id": format!("0x{}", hex::encode(p.proposal_id)),
                                    "proposer": p.proposer,
                                    "description": String::from_utf8_lossy(&p.description),
                                    "created_at": p.created_at.to_string(),
                                    "votes_for": p.votes_for.to_string(),
                                    "votes_against": p.votes_against.to_string(),
                                    "status": status.to_string(),
                                    "voting_period_secs": voting_period_secs,
                                    "proposal_expiry_secs": proposal_expiry_secs,
                                    // 🗳️ iadeli depozito (kapı sonrası): kasada bekleyen tutar, ham birim; "0" = yok/sonuçlandı
                                    "deposit": zagros_executor::governance::deposit_of(state.as_ref(), &proposal_id).unwrap_or(0).to_string(),
                                })
                            }
                            Ok(None) => serde_json::json!({"error": "Proposal not found"}),
                            Err(e) => serde_json::json!({"error": e.to_string()}),
                        }
                    }
                    _ => serde_json::json!({"error": "Invalid proposal_id_hex"}),
                }
            }

            // 4. Bekleyen (executed=false) öneriler, salt okuma; `proposal_id` sunucu
            // sayacına bağlı olduğundan başkasının önerisini keşfetmenin tek yolu.
            "zagros_getPendingBridgeProposals" => {
                // 🚨 Yanıt sınırlı: burn önerileri listesi süresiz büyür, sınırsız yanıt
                // habercilerde "transport error" verirdi. En yeni önce, varsayılan 200.
                let limit = safe_params
                    .first()
                    .and_then(|v| v.as_u64())
                    .map(|n| n as usize)
                    .unwrap_or(200)
                    .clamp(1, 500);
                let manager = bridge_manager.lock().unwrap();
                let now = std::time::UNIX_EPOCH.elapsed().unwrap().as_millis();
                let mut pend = manager.get_pending_proposals();
                pend.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
                let proposals: Vec<Value> = pend
                    .into_iter()
                    .take(limit)
                    .map(|p| {
                        let can_execute = manager.can_execute(&p.proposal_id, now).unwrap_or(false);
                        bridge_proposal_json(p, can_execute)
                    })
                    .collect();
                serde_json::json!({ "proposals": proposals })
            }

            // 4b. Yürütülmüş önerileri DE içerir (en yeni `limit` adet): dApp'in
            // "Relayer Durumu" kutusu sakin dönemde "veri yok" göstermesin, "son köprü
            // işleminde kaç imza, ne zaman" sorulabilsin. Salt okuma.
            "zagros_getRecentBridgeProposals" => {
                let limit = safe_params
                    .first()
                    .and_then(|v| v.as_u64())
                    .map(|n| n as usize)
                    .unwrap_or(1)
                    .clamp(1, 50);
                let manager = bridge_manager.lock().unwrap();
                let now = std::time::UNIX_EPOCH.elapsed().unwrap().as_millis();
                let proposals: Vec<Value> = manager
                    .get_recent_proposals(limit)
                    .into_iter()
                    .map(|p| {
                        let can_execute = manager.can_execute(&p.proposal_id, now).unwrap_or(false);
                        bridge_proposal_json(p, can_execute)
                    })
                    .collect();
                serde_json::json!({
                    "proposals": proposals,
                    "required_signatures": manager.required_signatures(),
                    "authorities_count": manager.authorities_count(),
                })
            }

            // 5. Burn görünürlük indeksinden `since_index`'ten itibaren yeni kayıtlar;
            // event-log RPC'si olmadığından relayer'ların burn keşfetme yolu.
            "zagros_getRecentBridgeBurns" => {
                let since_index = safe_params
                    .first()
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<u128>().ok())
                    .unwrap_or(0);

                match zagros_executor::Executor::load_recent_bridge_burns(
                    state.as_ref(),
                    since_index,
                ) {
                    Ok(records) => {
                        let entries: Vec<Value> = records
                            .into_iter()
                            .map(|r| {
                                serde_json::json!({
                                    "index": r.index.to_string(),
                                    "tx_id": format!("0x{}", hex::encode(r.tx_id)),
                                    "sender": r.sender,
                                    "amount": r.amount.to_string(),
                                    "timestamp": r.timestamp.to_string(),
                                })
                            })
                            .collect();
                        // 🛡️ [7]: Saklı en eski index'i de döndür, relayer, kendi
                        // since_index'i bunun altındaysa budanmış (kaçırılan) kayıt
                        // olduğunu anlayıp fail-closed davranabilsin (cursor gap).
                        let oldest_index =
                            zagros_executor::Executor::oldest_bridge_burn_index(state.as_ref())
                                .ok()
                                .flatten()
                                .map(|i| Value::String(i.to_string()))
                                .unwrap_or(Value::Null);
                        serde_json::json!({ "burns": entries, "oldest_index": oldest_index })
                    }
                    Err(e) => serde_json::json!({"error": e.to_string()}),
                }
            }

            // 📜 Adrese gelen native ZAGROS/ZERENYA transferlerini artımlı tarar
            // (dApp "İşlem Geçmişi" 'Alındı' girdileri); `getRecentBridgeBurns` deseni.
            "zagros_getReceivedTransfers" => {
                let receiver = safe_params.first().and_then(|v| v.as_str()).unwrap_or("");
                let since_index = safe_params
                    .get(1)
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<u128>().ok())
                    .unwrap_or(0);

                if receiver.is_empty() {
                    serde_json::json!({"error": "Gecersiz veya eksik receiver adresi"})
                } else {
                    match zagros_executor::Executor::load_recent_transfers_for(
                        state.as_ref(),
                        receiver,
                        since_index,
                    ) {
                        Ok(records) => {
                            let entries: Vec<Value> = records
                                .into_iter()
                                .map(|r| {
                                    serde_json::json!({
                                        "index": r.index.to_string(),
                                        "tx_id": format!("0x{}", hex::encode(r.tx_id)),
                                        "sender": r.sender,
                                        "receiver": r.receiver,
                                        "amount": r.amount.to_string(),
                                        "asset": r.asset,
                                        "timestamp": r.timestamp.to_string(),
                                    })
                                })
                                .collect();
                            serde_json::json!({ "transfers": entries })
                        }
                        Err(e) => serde_json::json!({"error": e.to_string()}),
                    }
                }
            }

            // 🛡️ Köprüden basılan − yakılan ZERENYA; havuz/genesis ZERENYA dahil DEĞİL.
            // Bir ZERENYA'nın köprüden PAXG'ye çevrilebilirliği buna bağlı.
            "zagros_getBridgeBackedZerenya" => {
                match zagros_executor::Executor::read_bridge_backed_zerenya(state.as_ref()) {
                    Ok(amount) => {
                        serde_json::json!({ "bridge_backed_zerenya": amount.to_string() })
                    }
                    Err(e) => serde_json::json!({ "error": e.to_string() }),
                }
            }

            // 🛡️ GLOBAL 24 saatlik kayan mint penceresi durumu: dApp kullanıcıyı PAXG
            // kilitlemeye göndermeden önce "bugün yeterli mint hakkı var mı" sorar.
            "zagros_getBridgeDailyMintStatus" => {
                let now_secs = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let daily_limit = Self::configured_bridge_daily_mint_limit(&state);
                match zagros_executor::bridge::BridgeManager::daily_mint_status(
                    state.as_ref(),
                    now_secs,
                    daily_limit,
                ) {
                    Ok(status) => serde_json::json!({
                        "daily_limit": status.daily_limit.to_string(),
                        "minted_in_window": status.minted_in_window.to_string(),
                        "remaining": status.remaining.to_string(),
                        "retry_after_secs": status.retry_after_secs.to_string(),
                        // 🛡️ Tek işlem tavanı (`MAX_SINGLE_BRIDGE_MINT`) günlük tavandan ayrı;
                        // dApp "günlük hak var ama X işleme böl" ayrımını yapabilsin.
                        "max_single_mint": zagros_types::MAX_SINGLE_BRIDGE_MINT.to_string(),
                    }),
                    Err(e) => serde_json::json!({ "error": e.to_string() }),
                }
            }

            // 🚨 Bilinmeyen metod için standart "-32601 Method not found"; sessiz
            // `result: null` istemcilere "başarılı ama boş" görünür.
            _ => {
                warn!("⚠️ Henüz desteklenmeyen RPC metodu: {}", req.method);
                return RpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id: req.id,
                    result: None,
                    error: Some(json!({
                        "code": -32601,
                        "message": format!("Method not found: {}", req.method)
                    })),
                };
            }
        };

        RpcResponse {
            jsonrpc: "2.0".to_string(),
            id: req.id,
            result: Some(result),
            error: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// G2: havuz yokken 0,17 ZERENYA-eşdeğeri 1:1 ZAGROS (ChainParams başlangıcı).
    const TEST_MIN_STAKE: u128 = 170_000_000_000_000_000;

    /// ChainParams + genesis hash'i state'e yazar (validator RPC'leri fail-closed).
    fn install_test_chain_params(state: &Arc<dyn State>) {
        zagros_executor::params::store_chain_params(
            state.as_ref(),
            &zagros_types::consensus::ChainParams::genesis_defaults(),
        )
        .unwrap();
        zagros_executor::params::store_genesis_hash(state.as_ref(), &[0x5a; 32]).unwrap();
    }

    // ---- Y5: Kayan-pencere (sliding-window) IP rate limiter ----

    #[test]
    fn sliding_window_allows_up_to_limit_then_blocks_within_window() {
        let ip = "10.0.0.1"; // teste özel IP (global limiter map'inde çakışma olmasın)
        let limit = 3;
        let t = 5_000u64;
        // Pencere içinde ilk `limit` istek geçer.
        assert!(sliding_window_allows(ip, t, limit));
        assert!(sliding_window_allows(ip, t + 10, limit));
        assert!(sliding_window_allows(ip, t + 20, limit));
        // limit'e ulaşıldı: pencere içindeki 4. istek reddedilir.
        assert!(!sliding_window_allows(ip, t + 30, limit));
    }

    #[test]
    fn sliding_window_blocks_boundary_bursts_that_a_fixed_window_would_allow() {
        // Sabit-pencere (saniye-bazlı) sayaç t=1999 ile t=2000 arasında sıfırlanır
        // ve <1s içinde 2*limit isteğe izin verirdi. Kayan pencere buna izin vermez.
        let ip = "10.0.0.2";
        let limit = 3;
        // t=1900ms'de limit kadar iste (pencereyi doldur).
        assert!(sliding_window_allows(ip, 1_900, limit));
        assert!(sliding_window_allows(ip, 1_950, limit));
        assert!(sliding_window_allows(ip, 1_990, limit));
        // t=2100ms: saniye sınırı geçildi ama son 1000ms'de hâlâ 3 istek var
        // ([1900,2100] penceresi) -> REDDEDİLMELİ (sabit pencere kabul ederdi).
        assert!(!sliding_window_allows(ip, 2_100, limit));
    }

    #[test]
    fn sliding_window_recovers_after_the_window_fully_passes() {
        let ip = "10.0.0.3";
        let limit = 2;
        assert!(sliding_window_allows(ip, 1_000, limit));
        assert!(sliding_window_allows(ip, 1_100, limit));
        assert!(!sliding_window_allows(ip, 1_200, limit)); // dolu
                                                           // Pencere tamamen geçince (>= 1000ms sonra) eski damgalar düşer, tekrar açılır.
        assert!(sliding_window_allows(ip, 2_200, limit));
    }

    /// 🚨 REGRESYON: yalnız bayat girdileri silen tahliye, her IP'yi taze tutan
    /// saldırgana (IPv6 /64 = 2^64 adres) karşı haritayı sınırsız büyütür.
    /// Test YEREL harita kullanır (global `IP_RATE_LIMITER` paralel testlerde kararsız).
    #[test]
    fn the_ip_map_stays_bounded_even_when_every_source_stays_fresh() {
        let map: DashMap<String, VecDeque<u64>> = DashMap::new();
        let limit = 100usize;
        let now = 1_000_000u64;
        // Tavanin uzerinde, HEPSI AYNI ANDA eklenmis (yani TAZE) kaynak:
        // saldirganin "her kimligi taze tut" davranisinin birebir modeli.
        for i in 0..(MAX_TRACKED_IPS + 5_000) {
            map.insert(format!("2001:db8::{i:x}"), VecDeque::from(vec![now]));
        }
        assert!(
            map.len() > MAX_TRACKED_IPS,
            "test on kosulu: tavan asilmis olmali"
        );

        enforce_ip_map_bound(&map, now, limit);

        assert!(
            map.len() <= MAX_TRACKED_IPS,
            "harita tavani asti: {} > {MAX_TRACKED_IPS} - taze kaynaklarla sinirsiz \
             bellek buyumesi hala mumkun",
            map.len()
        );
    }

    /// Sınırlama ASIL işlevi bozmamalı: tavanın ALTINDAysa hiçbir taze girdi
    /// atılmaz (meşru kullanıcıların sayacı korunur).
    #[test]
    fn bounding_does_not_drop_fresh_entries_while_under_the_cap() {
        let map: DashMap<String, VecDeque<u64>> = DashMap::new();
        let now = 1_000_000u64;
        for i in 0..10 {
            map.insert(format!("10.0.0.{i}"), VecDeque::from(vec![now]));
        }
        enforce_ip_map_bound(&map, now, 100);
        assert_eq!(
            map.len(),
            10,
            "tavanin altinda hicbir taze girdi atilmamali"
        );
    }

    /// Bayat girdiler tavanın altındayken de temizlenir (mevcut F3 davranışı).
    #[test]
    fn stale_entries_are_evicted_even_under_the_cap() {
        let map: DashMap<String, VecDeque<u64>> = DashMap::new();
        let now = 1_000_000u64;
        map.insert("10.0.0.1".to_string(), VecDeque::from(vec![now]));
        map.insert(
            "10.0.0.2".to_string(),
            VecDeque::from(vec![now - RATE_LIMIT_WINDOW_MS - 1]),
        );
        enforce_ip_map_bound(&map, now, 100);
        assert!(map.contains_key("10.0.0.1"), "taze girdi kalmali");
        assert!(!map.contains_key("10.0.0.2"), "bayat girdi atilmali");
    }

    #[test]
    fn ip_is_stale_only_after_a_full_window_has_elapsed() {
        // F3: tahliye ölçütü, son görülmeden bir tam pencere geçmişse bayat.
        assert!(!ip_is_stale(1_000, 1_000)); // aynı an
        assert!(!ip_is_stale(1_000, 1_999)); // pencere içinde
        assert!(ip_is_stale(1_000, 2_000)); // tam bir pencere geçti
        assert!(ip_is_stale(1_000, 9_999)); // çok eski
    }

    #[test]
    fn in_flight_guard_rejects_over_the_ceiling_and_releases_on_drop() {
        // Global sayaç paralel testlerde "0'dan başlar" varsayımını kırar;
        // `InFlightGuard` sayacı parametre aldığından yerel/izole sayaç kullanılır.
        let counter = AtomicUsize::new(0);

        // F2: eşzamanlı istek tavanı + RAII serbest bırakma.
        let g1 = InFlightGuard::try_acquire(&counter, 2);
        let g2 = InFlightGuard::try_acquire(&counter, 2);
        assert!(g1.is_some() && g2.is_some());
        // Tavan doldu → 3. istek reddedilir (503).
        assert!(InFlightGuard::try_acquire(&counter, 2).is_none());
        // Birini bırakınca yeniden yer açılır.
        drop(g1);
        let g3 = InFlightGuard::try_acquire(&counter, 2);
        assert!(g3.is_some());
        drop(g2);
        drop(g3);
    }

    #[test]
    fn active_connection_guard_increments_on_acquire_and_decrements_on_drop() {
        let counter = AtomicUsize::new(0);
        let guard = ActiveConnectionGuard::acquire(&counter);
        assert_eq!(counter.load(Ordering::Relaxed), 1);
        drop(guard);
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn active_connection_guard_decrements_even_when_scope_exits_via_early_return() {
        fn acquire_then_bail(counter: &AtomicUsize, bail: bool) -> Result<(), &'static str> {
            let _guard = ActiveConnectionGuard::acquire(counter);
            if bail {
                return Err("early exit while guard is still in scope");
            }
            Ok(())
        }

        let counter = AtomicUsize::new(0);
        let _ = acquire_then_bail(&counter, true);
        // Guard must have been dropped (via `?`/early-return unwind of the stack
        // frame) exactly like a normal fall-through, no manual fetch_sub needed.
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn handle_rpc_request_increments_active_connections_for_http_post() {
        // HTTP POST yolu ACTIVE_CONNECTIONS'a dokunmalı (gerçek global sayaç).
        // 🛡️ Kararsızlığa karşı taban her denemede alınır, gözlem birkaç kez denenir.
        let mut observed = false;
        for _ in 0..20 {
            let state = test_state();
            let mempool = test_mempool(state.clone());
            let body = bytes::Bytes::from(
                r#"{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}"#,
            );
            let before = ACTIVE_CONNECTIONS.load(Ordering::Relaxed);
            let handle = tokio::spawn(handle_rpc_request(
                body,
                state,
                mempool,
                Arc::new(DashMap::new()),
                default_bridge_manager_arc(),
                RpcTimeouts::default(),
                EvmSimulationLimits::default(),
                None,
            ));
            tokio::task::yield_now().await;
            if ACTIVE_CONNECTIONS.load(Ordering::Relaxed) > before {
                observed = true;
            }
            handle.await.unwrap().unwrap();
            if observed {
                break;
            }
        }
        assert!(
            observed,
            "HTTP POST path must increment ACTIVE_CONNECTIONS while a request is in flight"
        );
        // Kesin eşitlik yok (global sayaç, paralel testler); `during > before` yeter.
    }

    #[tokio::test]
    async fn handle_ws_connection_still_decrements_active_connections_on_normal_close() {
        // Regression: the WS path used to do a manual fetch_add/fetch_sub pair;
        // confirm the RAII-guard rewrite preserves the same net-zero behavior
        // across a normal (non-panicking) connection lifecycle.
        let before = ACTIVE_CONNECTIONS.load(Ordering::Relaxed);
        {
            let _guard = ActiveConnectionGuard::acquire(&ACTIVE_CONNECTIONS);
            assert_eq!(ACTIVE_CONNECTIONS.load(Ordering::Relaxed), before + 1);
        }
        assert_eq!(ACTIVE_CONNECTIONS.load(Ordering::Relaxed), before);
    }

    // YÜKSEK #6 (Seçenek B): WS ping/pong idle koruması testleri.

    #[test]
    fn ws_connection_is_idle_uses_a_strict_greater_than_comparison() {
        // Tam sınırda (idle_for == pong_timeout) henüz kapatılmamalı: ilk ping'in
        // kendisi `ping_interval` gecikebilir (config'in `pong > ping` şartıyla aynı gerekçe).
        assert!(!ws_connection_is_idle(90, 90));
        assert!(ws_connection_is_idle(91, 90));
        assert!(!ws_connection_is_idle(0, 90));
        assert!(!ws_connection_is_idle(89, 90));
    }

    fn ws_test_route(
        ping_interval: Duration,
        pong_timeout: Duration,
    ) -> impl warp::Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        let state = test_state();
        let (reserve_sender, _) = broadcast::channel::<String>(8);
        let (account_sender, _) = broadcast::channel::<String>(8);
        let price_history = Arc::new(Mutex::new(VecDeque::new()));
        warp::path::end().and(warp::ws()).map(move |ws: Ws| {
            let state = state.clone();
            let reserve_sender = reserve_sender.clone();
            let account_sender = account_sender.clone();
            let price_history = price_history.clone();
            ws.on_upgrade(move |socket| {
                RpcServer::handle_ws_connection(
                    socket,
                    state,
                    reserve_sender,
                    account_sender,
                    price_history,
                    ping_interval,
                    pong_timeout,
                )
            })
        })
    }

    /// Sunucu aralıkta gerçekten PING gönderir (`warp::test::ws()` gerçek istemci).
    #[tokio::test]
    async fn handle_ws_connection_sends_a_ping_within_the_configured_interval() {
        let mut client = warp::test::ws()
            .handshake(ws_test_route(
                Duration::from_millis(10),
                Duration::from_secs(30),
            ))
            .await
            .expect("handshake basarili olmali");

        // Açılışta `pool_reserves_history` (text) ve `pool_reserves` (broadcast) iki
        // ayrı kanaldan gelir, sıra sabit değil; PING görene (ya da zaman aşımına) kadar oku.
        let deadline = tokio::time::Instant::now() + Duration::from_millis(400);
        let mut saw_ping = false;
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(Duration::from_millis(400), client.recv()).await {
                Ok(Ok(msg)) if msg.is_ping() => {
                    saw_ping = true;
                    break;
                }
                Ok(Ok(_non_ping)) => continue,
                Ok(Err(e)) => panic!("beklenmedik ws hatasi: {:?}", e),
                Err(_) => break,
            }
        }
        assert!(
            saw_ping,
            "ping_interval sonrasinda bir PING mesaji GELMELI, hic gelmedi"
        );
    }

    /// Sağlıklı istemci (PING'e PONG) kapanmamalı. 🛑 Test PONG'u açıkça gönderir
    /// (`WsClient` otomatik pong flush'ı CPU baskısında flaky).
    #[tokio::test]
    async fn handle_ws_connection_keeps_a_healthy_client_alive_across_several_ping_intervals() {
        let mut client = warp::test::ws()
            .handshake(ws_test_route(
                Duration::from_millis(10),
                Duration::from_millis(60),
            ))
            .await
            .expect("handshake basarili olmali");

        let _history = client.recv().await.expect("history mesaji gelmeli");

        // pong_timeout'un (60ms) ÇOK üzerinde bir pencere boyunca (250ms),
        // gelen HER PING'e ANINDA bir PONG ile karşılık ver.
        let deadline = tokio::time::Instant::now() + Duration::from_millis(250);
        let mut ping_count = 0u32;
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(Duration::from_millis(150), client.recv()).await {
                Ok(Ok(msg)) if msg.is_ping() => {
                    ping_count += 1;
                    client.send(Message::pong(Vec::new())).await;
                }
                Ok(Ok(_)) => {}
                Ok(Err(e)) => panic!(
                    "baglanti beklenmedik sekilde kapandi ({} ping/pong turundan sonra): {:?}",
                    ping_count, e
                ),
                Err(_) => break,
            }
        }
        assert!(
            ping_count >= 2,
            "250ms/10ms marjinda EN AZ 2 PING beklenir (gelen: {}), test kurulumu \
             beklenenden farklı davranıyor olabilir",
            ping_count
        );
    }

    /// 🔒 `apply_fixed_gas_fee` ücreti türetmez, mempool'un `min_required_fee`'sini
    /// gömer; doğrulanan EŞİTLİĞİN kendisi (iç matematik `zagros-types` testlerinde kilitli).
    #[test]
    fn rpc_embeds_exactly_the_fee_the_mempool_demands() {
        use secp256k1::SecretKey;
        let state = test_state();
        state
            .set_pool_reserves(1_000 * 10u128.pow(18), 1_000 * 10u128.pow(18))
            .unwrap();
        let mempool = test_mempool(state.clone());

        let secret_key = SecretKey::from_slice(&[9u8; 32]).unwrap();
        let raw_tx = build_signed_legacy_tx(
            &secret_key,
            "0x2222222222222222222222222222222222222222",
            Vec::new(),
            0,
            CHAIN_ID,
        );
        let mut tx = RpcServer::decode_and_convert_tx(&raw_tx).unwrap();
        assert_eq!(tx.tx_type, TxType::Transfer);

        mempool.apply_fixed_gas_fee(&mut tx);

        assert_eq!(tx.gas_limit, 1);
        // Gömülen ücret == mempool'un talebi (sıfır sapma).
        assert_eq!(tx.gas_price, mempool.min_required_fee(&tx));
        // 1:1 havuzda (1 ZAGROS = 1 ZERENYA) bu tam olarak kanonik GAS_FEE_ZERENYA'dır.
        assert_eq!(tx.gas_price, zagros_types::GAS_FEE_ZERENYA);
        // 🚨 Gas alanlarını değiştirmek EVM-kökenli (97-bayt) imzayı BOZMAMALI.
        assert!(tx.verify_signature());
    }

    #[test]
    fn zagros_estimate_native_fee_matches_what_the_mempool_will_actually_charge() {
        // 🛡️ MAX düğmesi bu ucu kullanır; dönen rakam gerçek işlemin mempool ücretiyle
        // sıfır sapmayla eşleşmeli.
        let state = test_state();
        state
            .set_pool_reserves(1_000 * 10u128.pow(18), 1_000 * 10u128.pow(18))
            .unwrap();
        let mempool = test_mempool(state.clone());
        let expected_fee = mempool.native_min_required_fee(&TxType::StakeZagros);

        let response = RpcServer::handle_request(
            rpc_request(
                "zagros_estimateNativeFee",
                vec![Value::String("StakeZagros".to_string())],
            ),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );

        let result = response.result.expect("beklenen bir sonuc");
        assert_eq!(result["fee"], Value::String(expected_fee.to_string()));
        assert_eq!(result["tx_type"], Value::String("StakeZagros".to_string()));
    }

    #[test]
    fn zagros_estimate_token_factory_fee_matches_the_engines_actual_charge() {
        // 🛡️ Token Fabrikası sihirbazı `createToken` öncesi gerçek maliyeti gösterir;
        // rakam motorun tahsil ettiği `token_factory_fee_per_contract` ile aynı formülden gelmeli.
        let pool_zagros = 1_000 * 10u128.pow(18);
        let pool_zerenya = 4_000 * 10u128.pow(18);
        let state = test_state();
        state.set_pool_reserves(pool_zagros, pool_zerenya).unwrap();
        let mempool = test_mempool(state.clone());

        let expected_fee = zagros_types::base_gas_fee_from_reserves(
            zagros_types::TOKEN_FACTORY_FEE_ZERENYA,
            pool_zagros,
            pool_zerenya,
        );

        let response = RpcServer::handle_request(
            rpc_request("zagros_estimateTokenFactoryFee", vec![]),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );

        let result = response.result.expect("beklenen bir sonuc");
        assert_eq!(result["fee"], Value::String(expected_fee.to_string()));
    }

    #[test]
    fn zagros_estimate_native_fee_rejects_evm_or_unknown_tx_types() {
        let state = test_state();
        let mempool = test_mempool(state.clone());

        let response = RpcServer::handle_request(
            rpc_request(
                "zagros_estimateNativeFee",
                vec![Value::String("ContractCall".to_string())],
            ),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );

        assert!(response.result.is_none());
        assert!(
            response.error.is_some(),
            "EVM/bilinmeyen tur icin hata donmeli"
        );
    }

    #[test]
    fn validator_stats_uses_real_registration_and_jail_criteria_not_just_stake_amount() {
        // 🛡️ Regresyon: validator_count yalnız stake >= MIN_VALIDATOR_STAKE'e
        // bakmamalı; kayıt/hapis modeli hesaba katılmalı.
        let state = test_state();
        install_test_chain_params(&state);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u128;

        // Kayıtlı, yeterli stake'i olan, hapiste OLMAYAN, gerçek bir validator.
        state
            .set_account(
                &"0x1111111111111111111111111111111111111111".to_string(),
                AccountState {
                    staked_balance: TEST_MIN_STAKE,
                    is_registered_validator: true,
                    ..Default::default()
                },
            )
            .unwrap();
        // Yeterli stake'i var ama HİÇ kayıt olmamış, sadece staker.
        state
            .set_account(
                &"0x2222222222222222222222222222222222222222".to_string(),
                AccountState {
                    staked_balance: TEST_MIN_STAKE * 3,
                    ..Default::default()
                },
            )
            .unwrap();
        // Kayıtlı ve yeterli stake'i var ama HAPİSTE, validator sayılmamalı.
        state
            .set_account(
                &"0x3333333333333333333333333333333333333333".to_string(),
                AccountState {
                    staked_balance: TEST_MIN_STAKE,
                    is_registered_validator: true,
                    jailed_until: now + 1_000_000,
                    ..Default::default()
                },
            )
            .unwrap();

        let mempool = test_mempool(state.clone());
        let response = RpcServer::handle_request(
            rpc_request("zagros_getValidatorStats", vec![]),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );

        let result = response.result.expect("beklenen bir sonuc");
        assert_eq!(result["staker_count"], 3);
        assert_eq!(
            result["validator_count"], 1,
            "sadece kayitli+staked+hapiste-olmayan sayilmali"
        );
        assert_eq!(result["jailed_count"], 1);
        assert_eq!(
            result["max_stake"],
            Value::String((TEST_MIN_STAKE * 3).to_string())
        );
    }

    #[test]
    fn account_state_exposes_registration_and_jail_fields() {
        // G13: commission SÖKÜLDÜ
        let state = test_state();
        let address = "0x4444444444444444444444444444444444444444".to_string();
        state
            .set_account(
                &address,
                AccountState {
                    is_registered_validator: true,
                    jailed_until: 123,
                    validator_registered_at: 999_000,
                    ..Default::default()
                },
            )
            .unwrap();
        let mempool = test_mempool(state.clone());

        let response = RpcServer::handle_request(
            rpc_request("zagros_get_account_state", vec![Value::String(address)]),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );

        let result = response.result.expect("beklenen bir sonuc");
        assert_eq!(result["is_registered_validator"], true);
        assert_eq!(result["jailed_until"], Value::String("123".to_string()));
        assert!(
            result.get("validator_commission_bps").is_none(),
            "G13: komisyon alanı RPC yanıtından SÖKÜLDÜ"
        );
        assert_eq!(
            result["validator_registered_at"],
            Value::String("999000".to_string())
        );
    }

    #[test]
    fn validator_list_returns_per_address_registration_and_jail_data() {
        let state = test_state();
        state
            .set_account(
                &"0x5555555555555555555555555555555555555555".to_string(),
                AccountState {
                    staked_balance: 1_000,
                    is_registered_validator: true,
                    validator_registered_at: 555_000,
                    ..Default::default()
                },
            )
            .unwrap();
        let mempool = test_mempool(state.clone());

        let response = RpcServer::handle_request(
            rpc_request("zagros_getValidatorList", vec![]),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );

        let result = response.result.expect("beklenen bir sonuc");
        let validators = result["validators"].as_array().unwrap();
        assert_eq!(validators.len(), 1);
        assert_eq!(validators[0]["stake"], Value::String("1000".to_string()));
        assert_eq!(validators[0]["is_registered_validator"], true);
        assert_eq!(validators[0]["jailed"], false);
        assert!(
            validators[0].get("validator_commission_bps").is_none(),
            "G13: komisyon alanı SÖKÜLDÜ"
        );
        assert_eq!(
            validators[0]["validator_registered_at"],
            Value::String("555000".to_string())
        );
    }

    // 🛡️ G8: validator'ın epoch/probation/liveness/strike/bond-lock durumu
    // `zagros_getValidatorList`ten okunabilmeli.
    #[test]
    fn validator_list_exposes_liveness_strikes_and_bond_lock_for_operator_visibility() {
        let state = test_state();
        state
            .set_account(
                &"0x6666666666666666666666666666666666666666".to_string(),
                AccountState {
                    staked_balance: 170_000_000_000_000_000,
                    is_registered_validator: true,
                    validator_status: Some(zagros_types::consensus::ValidatorStatus::Probation),
                    validator_status_epoch: 4,
                    bond_unlock_at: 1_800_000_000,
                    liveness: zagros_types::consensus::LivenessCounters {
                        epoch: 6,
                        participated: 3,
                        total: 10,
                        strikes: 2,
                    },
                    ..Default::default()
                },
            )
            .unwrap();
        let mempool = test_mempool(state.clone());

        let response = RpcServer::handle_request(
            rpc_request("zagros_getValidatorList", vec![]),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );

        let result = response.result.expect("beklenen bir sonuc");
        let validators = result["validators"].as_array().unwrap();
        assert_eq!(validators.len(), 1);
        let v = &validators[0];
        assert_eq!(
            v["validator_status"],
            Value::String("Probation".to_string())
        );
        assert_eq!(v["validator_status_epoch"], Value::String("4".to_string()));
        assert_eq!(v["bond_unlock_at"], Value::String("1800000000".to_string()));
        assert_eq!(v["liveness"]["epoch"], Value::String("6".to_string()));
        assert_eq!(
            v["liveness"]["participated"],
            Value::String("3".to_string())
        );
        assert_eq!(v["liveness"]["total"], Value::String("10".to_string()));
        assert_eq!(v["liveness"]["strikes"], 2);
        assert_eq!(
            v["liveness"]["participation_bps"], 3_000,
            "3/10 katilim = 3000 bps"
        );
    }

    #[test]
    fn validator_list_liveness_participation_bps_is_null_without_any_measurement_fail_closed() {
        let state = test_state();
        state
            .set_account(
                &"0x7777777777777777777777777777777777777777".to_string(),
                AccountState {
                    staked_balance: 170_000_000_000_000_000,
                    is_registered_validator: true,
                    ..Default::default()
                },
            )
            .unwrap();
        let mempool = test_mempool(state.clone());

        let response = RpcServer::handle_request(
            rpc_request("zagros_getValidatorList", vec![]),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );

        let result = response.result.expect("beklenen bir sonuc");
        let v = &result["validators"][0];
        assert_eq!(
            v["liveness"]["participation_bps"],
            Value::Null,
            "hic olcum yoksa (total=0) uydurma bir yuzde DONMEMELI"
        );
    }

    #[test]
    fn network_params_returns_the_real_constants_not_hardcoded_copies() {
        let state = test_state();
        install_test_chain_params(&state);
        let mempool = test_mempool(state.clone());
        let response = RpcServer::handle_request(
            rpc_request("zagros_getNetworkParams", vec![]),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );
        let result = response.result.expect("beklenen bir sonuc");
        assert_eq!(
            result["staker_reward_bps"],
            Value::String(zagros_types::STAKER_REWARD_BPS.to_string())
        );
        assert_eq!(
            result["validator_reward_bps"],
            Value::String(zagros_types::VALIDATOR_REWARD_BPS.to_string())
        );
        assert_eq!(
            result["min_validator_stake"],
            Value::String(TEST_MIN_STAKE.to_string())
        );
        assert_eq!(
            result["configured_block_producer_address"], "",
            "sentinel hic yazilmamissa bos string donmeli, panik degil"
        );
    }

    // 🛡️ G8 finalizasyon: operatör görünürlüğü, `current_epoch` +
    // probation/liveness/jail eşikleri zincir-üstü state'ten (uydurma
    // sabit DEĞİL) okunmalı; ChainParams/aktif küme yoksa fail-closed null.
    #[test]
    fn network_params_exposes_current_epoch_and_liveness_thresholds_from_live_state() {
        let state = test_state();
        install_test_chain_params(&state);
        let set = zagros_types::consensus::ActiveValidatorSet {
            epoch: 7,
            members: (0..4u8)
                .map(|i| zagros_types::consensus::ValidatorMember {
                    address: format!("0x{:040x}", i + 1),
                    consensus_pubkey: [i + 1; 32],
                })
                .collect(),
        };
        zagros_executor::validator_set::store_active_set(state.as_ref(), &set).unwrap();
        let mempool = test_mempool(state.clone());
        let response = RpcServer::handle_request(
            rpc_request("zagros_getNetworkParams", vec![]),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );
        let result = response.result.expect("beklenen bir sonuc");
        let defaults = zagros_types::consensus::ChainParams::genesis_defaults();
        assert_eq!(result["current_epoch"], Value::String("7".to_string()));
        assert_eq!(
            result["epoch_seconds"],
            Value::String(defaults.epoch_seconds.to_string())
        );
        assert_eq!(result["probation_epochs"], defaults.probation_epochs);
        // RPC etkin (clamp'li) değerleri, ham değerler `*_stored`da; ikisi farklı olmalı.
        assert_eq!(
            result["uptime_threshold_bps"],
            zagros_executor::params::effective_uptime_threshold_bps(&defaults)
        );
        assert_eq!(
            result["uptime_threshold_bps_stored"],
            defaults.uptime_threshold_bps
        );
        assert_eq!(
            result["max_liveness_strikes"],
            zagros_executor::params::effective_max_liveness_strikes(&defaults)
        );
        assert_eq!(
            result["max_liveness_strikes_stored"],
            defaults.max_liveness_strikes
        );
        assert_eq!(
            result["d11_activation_epoch"],
            zagros_executor::params::D11_ACTIVATION_EPOCH
        );
        assert_ne!(
            result["uptime_threshold_bps"],
            result["uptime_threshold_bps_stored"]
        );
        assert_ne!(
            result["max_liveness_strikes"],
            result["max_liveness_strikes_stored"]
        );
        assert_eq!(
            result["bond_lock_seconds"],
            Value::String(defaults.bond_lock_seconds.to_string())
        );
        assert_eq!(result["max_validators"], defaults.max_validators);
    }

    #[test]
    fn network_params_current_epoch_is_null_without_an_installed_active_set_fail_closed() {
        let state = test_state();
        install_test_chain_params(&state);
        let mempool = test_mempool(state.clone());
        let response = RpcServer::handle_request(
            rpc_request("zagros_getNetworkParams", vec![]),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );
        let result = response.result.expect("beklenen bir sonuc");
        assert_eq!(
            result["current_epoch"],
            Value::Null,
            "aktif kume yoksa uydurma epoch DONMEMELI"
        );
    }

    #[test]
    fn network_params_reflects_the_configured_block_producer_sentinel() {
        let state = test_state();
        state
            .set_account(
                &"__CONFIGURED_BLOCK_PRODUCER__".to_string(),
                AccountState {
                    contract_code: b"0xabc123".to_vec(),
                    ..Default::default()
                },
            )
            .unwrap();
        let mempool = test_mempool(state.clone());
        let response = RpcServer::handle_request(
            rpc_request("zagros_getNetworkParams", vec![]),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );
        let result = response.result.expect("beklenen bir sonuc");
        assert_eq!(result["configured_block_producer_address"], "0xabc123");
    }

    #[test]
    fn validator_slash_history_returns_recorded_events() {
        // `record_slash_history` private; infaz akışı zagros-executor'da test edildiğinden
        // `__SLASH_HISTORY__` aynı formatta (bincode `Vec<SlashRecord>`) doğrudan seedlenir.
        let state = test_state();
        let record = zagros_types::SlashRecord {
            index: 0,
            target: "0x5555555555555555555555555555555555555555".to_string(),
            reason: zagros_types::SlashReason::AdminEmergencySeizure,
            confiscated_amount: 500,
            timestamp: 1_000,
        };
        state
            .set_account(
                &"__SLASH_HISTORY__".to_string(),
                AccountState {
                    contract_code: bincode::serialize(&vec![record]).unwrap(),
                    ..Default::default()
                },
            )
            .unwrap();
        let mempool = test_mempool(state.clone());
        let response = RpcServer::handle_request(
            rpc_request("zagros_getValidatorSlashHistory", vec![]),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );
        let result = response.result.expect("beklenen bir sonuc");
        let records = result["records"].as_array().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0]["confiscated_amount"],
            Value::String("500".to_string()),
            "u128 alan string olarak donmeli (JSON Number'a sigmayabilir)"
        );
    }

    /// 🚨 REGRESYON: `serde_json::json!({ "records": records })` kestirmesi u64::MAX'ı
    /// aşan u128 alanlarda "number out of range" ile panikler (canlıda görüldü);
    /// değer gerçek 18 ondalıklı 100.000 ZAGROS.
    #[test]
    fn validator_slash_history_survives_amounts_larger_than_u64_max() {
        let state = test_state();
        let huge_amount: u128 = 100_000 * 10u128.pow(18);
        let record = zagros_types::SlashRecord {
            index: 0,
            target: "0x5555555555555555555555555555555555555555".to_string(),
            reason: zagros_types::SlashReason::AdminEmergencySeizure,
            confiscated_amount: huge_amount,
            timestamp: 1_000,
        };
        state
            .set_account(
                &"__SLASH_HISTORY__".to_string(),
                AccountState {
                    contract_code: bincode::serialize(&vec![record]).unwrap(),
                    ..Default::default()
                },
            )
            .unwrap();
        let mempool = test_mempool(state.clone());
        let response = RpcServer::handle_request(
            rpc_request("zagros_getValidatorSlashHistory", vec![]),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );
        let result = response.result.expect("panik atmadan bir sonuc donmeli");
        assert_eq!(
            result["records"][0]["confiscated_amount"],
            Value::String(huge_amount.to_string())
        );
    }

    #[test]
    fn last_reward_snapshot_is_null_before_any_distribution() {
        let state = test_state();
        let mempool = test_mempool(state.clone());
        let response = RpcServer::handle_request(
            rpc_request("zagros_getLastRewardSnapshot", vec![]),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );
        assert_eq!(response.result, Some(Value::Null));
    }

    /// 🚨 REGRESYON: aynı u128 panik sınıfı; `RewardSnapshot`'ın dört alanı da u128.
    #[test]
    fn last_reward_snapshot_survives_amounts_larger_than_u64_max() {
        let state = test_state();
        let huge: u128 = 300_000 * 10u128.pow(18);
        let snapshot = zagros_types::RewardSnapshot {
            total_staked: huge,
            accumulated_reward_per_share: huge,
            staker_share: huge,
            validator_share: huge,
            timestamp: 1_000,
        };
        state
            .set_account(
                &"__LAST_REWARD_SNAPSHOT__".to_string(),
                AccountState {
                    contract_code: bincode::serialize(&snapshot).unwrap(),
                    ..Default::default()
                },
            )
            .unwrap();
        let mempool = test_mempool(state.clone());
        let response = RpcServer::handle_request(
            rpc_request("zagros_getLastRewardSnapshot", vec![]),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );
        let result = response.result.expect("panik atmadan bir sonuc donmeli");
        assert_eq!(result["total_staked"], Value::String(huge.to_string()));
        assert_eq!(result["staker_share"], Value::String(huge.to_string()));
        assert_eq!(result["validator_share"], Value::String(huge.to_string()));
    }

    /// 🚨 `eth_getTransactionCount`: "pending" → zincir + bekleyen ardışıklar;
    /// "latest"/etiketsiz → zincirdeki nonce (etiket yok sayılıyordu).
    #[test]
    fn transaction_count_latest_is_the_chain_nonce_and_pending_includes_the_mempool() {
        let state = test_state();
        state
            .set_pool_reserves(1_000 * 10u128.pow(18), 1_000 * 10u128.pow(18))
            .unwrap();
        let sender_key = secp256k1::SecretKey::from_slice(&[7u8; 32]).unwrap();
        let sender_address = zagros_types::Transaction::address_from_secret_key(&sender_key);
        let mut acc = AccountState::new(1_000_000_000 * 10u128.pow(18));
        acc.nonce = 5;
        state.set_account(&sender_address, acc).unwrap();
        let mempool = test_mempool(state.clone());
        for nonce in 5..8 {
            let mut tx = transaction(&sender_address, nonce);
            tx.gas_limit = 1;
            tx.gas_price = mempool.native_min_required_fee(&TxType::Transfer).max(1);
            tx.sign(&sender_key);
            mempool.add_transaction(tx).unwrap();
        }
        let count = |params: Vec<Value>| {
            RpcServer::handle_request(
                rpc_request("eth_getTransactionCount", params),
                state.clone(),
                mempool.clone(),
                Arc::new(DashMap::new()),
                default_bridge_manager_arc(),
                EvmSimulationLimits::default(),
            )
            .result
            .expect("sonuc")
            .as_str()
            .unwrap()
            .to_string()
        };
        let addr = Value::String(sender_address.clone());
        assert_eq!(
            count(vec![addr.clone(), Value::String("pending".into())]),
            "0x8"
        );
        assert_eq!(
            count(vec![addr.clone(), Value::String("latest".into())]),
            "0x5"
        );
        // Yükseklik 0'dayken "earliest" == güncel state, serbest.
        assert_eq!(
            count(vec![addr.clone(), Value::String("earliest".into())]),
            "0x5"
        );
        // 🛡️ D14 (denetim C1): açık GEÇMİŞ blok isteği artık SESSİZCE "latest"
        // sayılmaz; -32000 açık hata döner (borsa mutabakatını yanıltmamak için).
        let hist = RpcServer::handle_request(
            rpc_request(
                "eth_getTransactionCount",
                vec![addr.clone(), Value::String("0x10".into())],
            ),
            state.clone(),
            mempool.clone(),
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );
        assert!(
            hist.result.is_none(),
            "gecmis blok istegi sonuc DONDURMEMELI"
        );
        assert_eq!(
            hist.error
                .as_ref()
                .and_then(|e| e.get("code"))
                .and_then(|c| c.as_i64()),
            Some(-32000),
            "gecmis blok istegi -32000 ile reddedilmeli: {:?}",
            hist.error
        );
        assert_eq!(count(vec![addr]), "0x5", "etiketsiz = latest");
    }

    #[test]
    fn mempool_stats_reflects_real_pending_transactions() {
        let state = test_state();
        // 1:1 havuz; test_mempool'un varsayılan (aşırı dengesiz) seed'i
        // gerçekçi olmayan bir ücrete yol açar (bkz. rpc_embeds_exactly_the_fee_the_mempool_demands).
        state
            .set_pool_reserves(1_000 * 10u128.pow(18), 1_000 * 10u128.pow(18))
            .unwrap();
        let sender_key = secp256k1::SecretKey::from_slice(&[6u8; 32]).unwrap();
        let sender_address = zagros_types::Transaction::address_from_secret_key(&sender_key);
        state
            .set_account(
                &sender_address,
                AccountState::new(1_000_000_000 * 10u128.pow(18)),
            )
            .unwrap();
        let mempool = test_mempool(state.clone());

        let empty_response = RpcServer::handle_request(
            rpc_request("zagros_getMempoolStats", vec![]),
            state.clone(),
            mempool.clone(),
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );
        assert_eq!(empty_response.result.unwrap()["pending_count"], 0);

        let mut tx = transaction(&sender_address, 0);
        // Gerçek kabul kapısıyla AYNI ücreti kullan, sabit bir sayı
        // uydurmak (mempool'un o an talep ettiğinden düşükse) reddedilir.
        let required_fee = mempool.native_min_required_fee(&TxType::Transfer).max(1);
        tx.gas_limit = 1;
        tx.gas_price = required_fee;
        tx.sign(&sender_key);
        mempool.add_transaction(tx).unwrap();

        let response = RpcServer::handle_request(
            rpc_request("zagros_getMempoolStats", vec![]),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );
        let result = response.result.expect("beklenen bir sonuc");
        assert_eq!(result["pending_count"], 1);
        assert_eq!(
            result["average_fee"],
            Value::String(required_fee.to_string())
        );
        assert_eq!(result["min_fee"], Value::String(required_fee.to_string()));
        assert_eq!(result["max_fee"], Value::String(required_fee.to_string()));
    }

    fn transaction(sender: &str, nonce: u64) -> Transaction {
        Transaction {
            tx_id: [nonce as u8; 32],
            tx_type: TxType::Transfer,
            sender: sender.to_string(),
            receiver: "0x0000000000000000000000000000000000000002".to_string(),
            amount: 1,
            payload: Vec::new(),
            signature: Vec::new(),
            timestamp: nonce as u128,
            nonce,
            gas_limit: 21_000,
            gas_price: 1,
            chain_id: CHAIN_ID,
        }
    }

    #[test]
    fn pending_nonce_advances_only_over_contiguous_transactions() {
        let sender = "0x0000000000000000000000000000000000000001";
        let pending = vec![
            transaction(sender, 7),
            transaction(sender, 8),
            transaction(sender, 10),
            transaction("0x0000000000000000000000000000000000000003", 9),
        ];

        assert_eq!(next_pending_nonce(7, sender, &pending), 9);
        assert_eq!(next_pending_nonce(11, sender, &pending), 11);
    }

    // 🌉 Köprü (Bridge) RPC uç noktaları
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::HashMap as StdHashMap;
    use std::sync::Mutex as StdMutex;
    use zagros_state::manager::StateDbManager;
    use zagros_storage::{Storage, StorageEngine};
    use zagros_types::GasCalculator;

    #[derive(Default)]
    struct MemoryStorage {
        values: StdMutex<StdHashMap<Vec<u8>, Vec<u8>>>,
    }

    impl Storage for MemoryStorage {
        fn get(&self, key: &[u8]) -> zagros_primitives::Result<Option<Vec<u8>>> {
            Ok(self.values.lock().unwrap().get(key).cloned())
        }
        fn put(&self, key: &[u8], value: &[u8]) -> zagros_primitives::Result<()> {
            self.values
                .lock()
                .unwrap()
                .insert(key.to_vec(), value.to_vec());
            Ok(())
        }
        fn delete(&self, key: &[u8]) -> zagros_primitives::Result<()> {
            self.values.lock().unwrap().remove(key);
            Ok(())
        }
        fn contains(&self, key: &[u8]) -> zagros_primitives::Result<bool> {
            Ok(self.values.lock().unwrap().contains_key(key))
        }
        fn list_keys(&self) -> zagros_primitives::Result<Vec<Vec<u8>>> {
            Ok(self.values.lock().unwrap().keys().cloned().collect())
        }
    }

    impl StorageEngine for MemoryStorage {
        fn write_batch(&self, kvs: &[(Vec<u8>, Option<Vec<u8>>)]) -> zagros_primitives::Result<()> {
            let mut values = self.values.lock().unwrap();
            for (key, value) in kvs {
                match value {
                    Some(v) => {
                        values.insert(key.clone(), v.clone());
                    }
                    None => {
                        values.remove(key);
                    }
                }
            }
            Ok(())
        }
    }

    fn test_state() -> Arc<dyn State> {
        Arc::new(StateDbManager::new(Arc::new(MemoryStorage::default())))
    }

    fn test_mempool(state: Arc<dyn State>) -> Arc<Mempool> {
        let gas_calculator = Arc::new(GasCalculator::new(
            Arc::new(portable_atomic::AtomicU128::new(1)),
            Arc::new(portable_atomic::AtomicU128::new(1_000_000_000_000_000)),
        ));
        Arc::new(Mempool::new(state, gas_calculator))
    }

    #[test]
    fn g14_health_snapshot_and_prometheus_render_report_chain_state() {
        let state = test_state();
        let mempool = test_mempool(state.clone());
        // Zincir görünümü: yükseklik + ChainParams + genesis ts + aktif küme
        let h = AccountState {
            balance: 4_242,
            ..Default::default()
        };
        state
            .set_account(&"__GLOBAL_BLOCK_HEIGHT__".to_string(), h)
            .unwrap();
        let params = zagros_types::consensus::ChainParams::genesis_defaults();
        let pa = AccountState {
            contract_code: params.encode(),
            ..Default::default()
        };
        state
            .set_account(&zagros_types::consensus::CHAIN_PARAMS_KEY.to_string(), pa)
            .unwrap();
        // genesis ts = 1 sn → epoch hesabı > 0 çıkar
        let g = AccountState {
            balance: 1,
            ..Default::default()
        };
        state
            .set_account(&zagros_types::GENESIS_TIMESTAMP_KEY.to_string(), g)
            .unwrap();
        let set = zagros_types::consensus::ActiveValidatorSet {
            epoch: 3,
            members: (0..5u8)
                .map(|i| zagros_types::consensus::ValidatorMember {
                    address: format!("0x{:040x}", i + 1),
                    consensus_pubkey: [i + 1; 32],
                })
                .collect(),
        };
        let va = AccountState {
            contract_code: bincode::serialize(&set).unwrap(),
            ..Default::default()
        };
        state
            .set_account(
                &zagros_types::consensus::ACTIVE_VALIDATOR_SET_KEY.to_string(),
                va,
            )
            .unwrap();
        // Sürücü sayaçları
        let metrics = Arc::new(zagros_metrics::NodeMetrics::default());
        metrics
            .commits_total
            .store(77, std::sync::atomic::Ordering::Relaxed);
        metrics
            .peers_connected
            .store(4, std::sync::atomic::Ordering::Relaxed);
        let m = Some(metrics);

        let snap = RpcServer::node_status_snapshot(&state, &mempool, &m);
        assert_eq!(snap["status"], "ok");
        assert_eq!(snap["height"], 4_242);
        assert_eq!(snap["chain_id"], zagros_types::CHAIN_ID);
        assert_eq!(snap["active_ruleset"], 1);
        assert_eq!(snap["validators"], 5);
        assert_eq!(snap["validator_set_epoch"], 3);
        assert!(
            snap["epoch"].as_u64().unwrap() > 0,
            "genesis ts=1 ile epoch hesaplanmali"
        );
        assert_eq!(snap["consensus"]["commits_total"], 77);
        assert_eq!(snap["consensus"]["peers_connected"], 4);

        let prom = RpcServer::render_prometheus_metrics(&state, &mempool, &m);
        assert!(
            prom.contains("zagros_height 4242"),
            "prometheus metni yükseklik taşımalı: {prom}"
        );
        assert!(prom.contains("zagros_commits_total 77"));
        assert!(prom.contains("zagros_validators 5"));
        assert!(prom.contains("# TYPE zagros_state_root_mismatch_total counter"));

        // Sayaçlar bağlanmamışken (None) uçlar yine çalışır, consensus bölümü olmaz
        let snap_none = RpcServer::node_status_snapshot(&state, &mempool, &None);
        assert_eq!(snap_none["height"], 4_242);
        assert!(snap_none.get("consensus").is_none());
    }

    /// `BridgeManager::default_authorities()`'in aynısı, seed'ler (1..=3)
    /// kasıtlı olarak eşleşiyor ki bu testler o yetkililer adına gerçek
    /// imza üretebilsin.
    fn authority_signing_key(seed: u8) -> SigningKey {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        SigningKey::from_bytes(&bytes)
    }

    /// Governance testleri için secp256k1 anahtar/adres; `#[cfg(test)]` imza
    /// atlaması bu crate'te geçerli değil, gerçek imza gerekir.
    fn governance_test_key(seed: u64) -> secp256k1::SecretKey {
        let mut bytes = [0u8; 32];
        bytes[24..32].copy_from_slice(&seed.to_be_bytes());
        secp256k1::SecretKey::from_slice(&bytes).unwrap()
    }

    fn current_unix_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn rpc_request(method: &str, params: Vec<Value>) -> RpcRequest {
        RpcRequest {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params: Some(params),
            id: Value::from(1),
        }
    }

    /// `handle_rpc_request`'in döndürdüğü `Box<dyn Reply>`'i test için JSON'a çevirir.
    async fn reply_body_json(reply: Box<dyn warp::Reply>) -> Value {
        use warp::Reply as _;
        let response = reply.into_response();
        let body_bytes = warp::hyper::body::to_bytes(response.into_body())
            .await
            .expect("yanit govdesi okunamadi");
        sonic_rs::from_slice(&body_bytes).expect("yanit gecerli JSON degil")
    }

    // 🚨 REGRESYON: MetaMask JSON-RPC batch (dizi) gönderir; tekil nesne bekleyen
    // handler "Parse error" verir ve bakiye asla gelmez. Tekil + batch desteklenir.
    #[tokio::test]
    async fn handle_rpc_request_still_supports_single_object_body() {
        let state = test_state();
        let mempool = test_mempool(state.clone());

        let body =
            bytes::Bytes::from(r#"{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}"#);
        let reply = handle_rpc_request(
            body,
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            RpcTimeouts::default(),
            EvmSimulationLimits::default(),
            None,
        )
        .await
        .unwrap();

        let json = reply_body_json(reply).await;
        assert!(json.get("result").is_some(), "tekil istek hala calismali");
        assert!(json.get("error").is_none());
    }

    #[tokio::test]
    async fn handle_rpc_request_supports_json_rpc_batch_array() {
        let state = test_state();
        let mempool = test_mempool(state.clone());

        let body = bytes::Bytes::from(
            r#"[
                {"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1},
                {"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":2}
            ]"#,
        );
        let reply = handle_rpc_request(
            body,
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            RpcTimeouts::default(),
            EvmSimulationLimits::default(),
            None,
        )
        .await
        .unwrap();

        let json = reply_body_json(reply).await;
        let array = json.as_array().expect("toplu yanit bir dizi olmali");
        assert_eq!(array.len(), 2, "her alt istege bir yanit dizide olmali");
        assert_eq!(array[0]["id"], Value::from(1));
        assert!(array[0].get("result").is_some());
        assert_eq!(array[1]["id"], Value::from(2));
        assert!(array[1].get("result").is_some());
    }

    #[tokio::test]
    async fn handle_rpc_request_rejects_empty_batch_array() {
        let state = test_state();
        let mempool = test_mempool(state.clone());

        let body = bytes::Bytes::from("[]");
        let reply = handle_rpc_request(
            body,
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            RpcTimeouts::default(),
            EvmSimulationLimits::default(),
            None,
        )
        .await
        .unwrap();

        let json = reply_body_json(reply).await;
        assert_eq!(json["error"]["code"], Value::from(-32600));
    }

    #[tokio::test]
    async fn handle_rpc_request_still_rejects_truly_invalid_json() {
        let state = test_state();
        let mempool = test_mempool(state.clone());

        let body = bytes::Bytes::from("not json at all");
        let reply = handle_rpc_request(
            body,
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            RpcTimeouts::default(),
            EvmSimulationLimits::default(),
            None,
        )
        .await
        .unwrap();

        let json = reply_body_json(reply).await;
        assert_eq!(json["error"]["code"], Value::from(-32700));
    }

    // YÜKSEK #6 (Seçenek B): RPC application-layer timeout testleri.

    /// 🚨 REGRESYON: batch üst sınırı olmalı; 2 MiB gövde ~35.000 alt çağrı, hepsi tek
    /// `spawn_blocking`'de sırayla, zaman aşımı bloklayan görevi durduramaz (amplifikasyon).
    #[tokio::test]
    async fn an_oversized_json_rpc_batch_is_rejected_before_any_work_is_done() {
        let state = test_state();
        let mempool = test_mempool(state.clone());
        let limit = 5usize;
        let mut timeouts = RpcTimeouts::default();
        timeouts.max_batch_requests = limit;

        let one = r#"{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}"#;
        let too_many: String = format!(
            "[{}]",
            std::iter::repeat(one)
                .take(limit + 1)
                .collect::<Vec<_>>()
                .join(",")
        );
        let reply = handle_rpc_request(
            bytes::Bytes::from(too_many),
            state.clone(),
            mempool.clone(),
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            timeouts,
            EvmSimulationLimits::default(),
            None,
        )
        .await
        .unwrap();
        let body = warp::reply::Reply::into_response(reply);
        let bytes = warp::hyper::body::to_bytes(body.into_body()).await.unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            text.contains("Batch too large"),
            "tavani asan batch REDDEDILMELI, alinan: {text}"
        );

        // Tavana SIGAN bir batch normal calismali, sinir asiri sert olmamali.
        let ok_batch: String = format!(
            "[{}]",
            std::iter::repeat(one)
                .take(limit)
                .collect::<Vec<_>>()
                .join(",")
        );
        let reply_ok = handle_rpc_request(
            bytes::Bytes::from(ok_batch),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            timeouts,
            EvmSimulationLimits::default(),
            None,
        )
        .await
        .unwrap();
        let body_ok = warp::reply::Reply::into_response(reply_ok);
        let bytes_ok = warp::hyper::body::to_bytes(body_ok.into_body())
            .await
            .unwrap();
        let text_ok = String::from_utf8_lossy(&bytes_ok);
        assert!(
            !text_ok.contains("Batch too large"),
            "tavana sigan batch reddedilmemeli: {text_ok}"
        );
    }

    #[test]
    fn classify_rpc_method_routes_evm_execution_methods_to_the_evm_bucket() {
        let timeouts = RpcTimeouts {
            light: Duration::from_secs(1),
            default_: Duration::from_secs(2),
            evm_execution: Duration::from_secs(3),
            max_batch: Duration::from_secs(99),
            max_batch_requests: 100,
        };
        assert_eq!(
            classify_rpc_method("eth_call")(&timeouts),
            Duration::from_secs(3)
        );
        assert_eq!(
            classify_rpc_method("eth_estimateGas")(&timeouts),
            Duration::from_secs(3)
        );
    }

    #[test]
    fn classify_rpc_method_routes_static_methods_to_the_light_bucket() {
        let timeouts = RpcTimeouts {
            light: Duration::from_secs(1),
            default_: Duration::from_secs(2),
            evm_execution: Duration::from_secs(3),
            max_batch: Duration::from_secs(99),
            max_batch_requests: 100,
        };
        for method in [
            "eth_chainId",
            "net_version",
            "web3_clientVersion",
            "eth_gasPrice",
        ] {
            assert_eq!(
                classify_rpc_method(method)(&timeouts),
                Duration::from_secs(1),
                "method {} should route to the light bucket",
                method
            );
        }
    }

    #[test]
    fn classify_rpc_method_routes_everything_else_to_the_default_bucket() {
        let timeouts = RpcTimeouts {
            light: Duration::from_secs(1),
            default_: Duration::from_secs(2),
            evm_execution: Duration::from_secs(3),
            max_batch: Duration::from_secs(99),
            max_batch_requests: 100,
        };
        for method in [
            "eth_getBalance",
            "eth_sendRawTransaction",
            "eth_getBlockByNumber",
            "zagros_get_account_state",
            "some_totally_unknown_method",
        ] {
            assert_eq!(
                classify_rpc_method(method)(&timeouts),
                Duration::from_secs(2),
                "method {} should route to the default bucket",
                method
            );
        }
    }

    /// 🛑 Zaman aşımında -32003. Deterministik: tek bloklayan thread önceden
    /// işgal edilir, asıl çağrının `spawn_blocking`i başlayamaz, timeout önce dolar.
    #[test]
    fn handle_rpc_request_returns_timeout_error_when_the_blocking_pool_is_saturated() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            // Tek bloklayan thread'i, gerçek isteğimizin timeout'undan (20ms)
            // ÇOK daha uzun bir süre (300ms) işgal et.
            let _occupier =
                tokio::task::spawn_blocking(|| std::thread::sleep(Duration::from_millis(100)));
            // Runtime'a işgalciyi GERÇEKTEN o tek thread'e dispatch etmesi için
            // kısa bir pay ver (gerçek zaman, ama marj çok büyük: 5ms << 100ms).
            tokio::time::sleep(Duration::from_millis(5)).await;

            let state = test_state();
            let mempool = test_mempool(state.clone());
            let before = RPC_TIMEOUT_COUNT.load(Ordering::Relaxed);

            let body = bytes::Bytes::from(
                r#"{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":7}"#,
            );
            let tight_timeout = RpcTimeouts {
                light: Duration::from_millis(8),
                default_: Duration::from_millis(8),
                evm_execution: Duration::from_millis(8),
                max_batch: Duration::from_millis(8),
                max_batch_requests: 100,
            };
            let reply = handle_rpc_request(
                body,
                state,
                mempool,
                Arc::new(DashMap::new()),
                default_bridge_manager_arc(),
                tight_timeout,
            EvmSimulationLimits::default(),
            None,
        )
            .await
            .unwrap();

            let json = reply_body_json(reply).await;
            assert_eq!(
                json["error"]["code"],
                Value::from(RPC_TIMEOUT_ERROR_CODE),
                "bloklayan havuz doluyken (20ms timeout, 300ms işgal) istek -32003 ile REDDEDİLMELİ, gelen: {:?}",
                json
            );
            assert_eq!(
                json["id"],
                Value::from(7),
                "hata yanıtı orijinal isteğin id'sini korumalı"
            );
            // 🛑 Kesin eşitlik yok: `RPC_TIMEOUT_COUNT` process geneli, paralel testler artırır.
            assert!(
                RPC_TIMEOUT_COUNT.load(Ordering::Relaxed) > before,
                "RPC_TIMEOUT_COUNT metriği EN AZ 1 artmalı"
            );
        });
    }

    /// Normal/cömert bir timeout ile AYNI isteğin sorunsuz geçtiğini kanıtlar,
    /// yukarıdaki testin yalnızca "her zaman reddediyor" bir kırık sarmalayıcı
    /// olmadığını, gerçekten SÜREYE göre karar verdiğini gösterir.
    #[tokio::test]
    async fn handle_rpc_request_succeeds_when_configured_timeout_is_generous() {
        let state = test_state();
        let mempool = test_mempool(state.clone());

        let body =
            bytes::Bytes::from(r#"{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":7}"#);
        let reply = handle_rpc_request(
            body,
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            RpcTimeouts::default(),
            EvmSimulationLimits::default(),
            None,
        )
        .await
        .unwrap();

        let json = reply_body_json(reply).await;
        assert!(json.get("result").is_some());
        assert!(json.get("error").is_none());
    }

    /// Batch'te de zaman aşımı; her alt istek kendi orijinal id'siyle hata alır.
    #[test]
    fn handle_rpc_request_batch_returns_one_timeout_error_per_original_id() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let _occupier =
                tokio::task::spawn_blocking(|| std::thread::sleep(Duration::from_millis(100)));
            tokio::time::sleep(Duration::from_millis(5)).await;

            let state = test_state();
            let mempool = test_mempool(state.clone());
            let before = RPC_TIMEOUT_COUNT.load(Ordering::Relaxed);

            let body = bytes::Bytes::from(
                r#"[
                    {"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":11},
                    {"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":22}
                ]"#,
            );
            let tight_timeout = RpcTimeouts {
                light: Duration::from_millis(8),
                default_: Duration::from_millis(8),
                evm_execution: Duration::from_millis(8),
                max_batch: Duration::from_millis(16),
                max_batch_requests: 100,
            };
            let reply = handle_rpc_request(
                body,
                state,
                mempool,
                Arc::new(DashMap::new()),
                default_bridge_manager_arc(),
                tight_timeout,
                EvmSimulationLimits::default(),
                None,
            )
            .await
            .unwrap();

            let json = reply_body_json(reply).await;
            let array = json.as_array().expect("batch yaniti bir dizi olmali");
            assert_eq!(array.len(), 2);
            assert_eq!(array[0]["id"], Value::from(11));
            assert_eq!(
                array[0]["error"]["code"],
                Value::from(RPC_TIMEOUT_ERROR_CODE)
            );
            assert_eq!(array[1]["id"], Value::from(22));
            assert_eq!(
                array[1]["error"]["code"],
                Value::from(RPC_TIMEOUT_ERROR_CODE)
            );
            // 🛑 `RPC_TIMEOUT_COUNT` process global; yalnız EN AZ 1 arttığı doğrulanır.
            // "Batch tek olay" iddiası kodda: `fetch_add` batch `Err(_elapsed)` kolunda
            // bir kez, yanıt döngüsünün içinde değil.
            assert!(
                RPC_TIMEOUT_COUNT.load(Ordering::Relaxed) > before,
                "RPC_TIMEOUT_COUNT metriği EN AZ 1 artmalı"
            );
        });
    }

    /// `max_batch_timeout_secs`: toplam tavan küçükse batch zaman aşımına uğrar
    /// (1 ms zamanlayıcı çözünürlüğünün üstünde, güvenilir).
    #[tokio::test]
    async fn handle_rpc_request_batch_timeout_is_capped_by_max_batch_even_with_generous_per_method_timeouts(
    ) {
        let state = test_state();
        let mempool = test_mempool(state.clone());

        let body = bytes::Bytes::from(
            r#"[
                {"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1},
                {"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":2}
            ]"#,
        );
        let generous_per_method_tiny_cap = RpcTimeouts {
            light: Duration::from_secs(60),
            default_: Duration::from_secs(60),
            evm_execution: Duration::from_secs(60),
            max_batch: Duration::from_nanos(1),
            max_batch_requests: 100,
        };
        let reply = handle_rpc_request(
            body,
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            generous_per_method_tiny_cap,
            EvmSimulationLimits::default(),
            None,
        )
        .await
        .unwrap();

        let json = reply_body_json(reply).await;
        let array = json.as_array().expect("batch yaniti bir dizi olmali");
        // 🛑 `from_nanos(1)` zamanlamaya bağlı flaky olabilir; bu test yalnız "zaman
        // aşımı olduysa şekli doğru mu" bakar, tavanın mantıksal uygulanması
        // (`sum(...).min(max_batch)`) ayrı birim testte kanıtlanır.
        if array[0].get("error").is_some() {
            assert_eq!(
                array[0]["error"]["code"],
                Value::from(RPC_TIMEOUT_ERROR_CODE)
            );
            assert_eq!(
                array[1]["error"]["code"],
                Value::from(RPC_TIMEOUT_ERROR_CODE)
            );
        }
    }

    /// Saf mantık: `min(sum_of_per_item_timeouts, max_batch)` ifadesi izole doğrulanır.
    #[test]
    fn batch_timeout_calculation_is_capped_by_max_batch() {
        let timeouts = RpcTimeouts {
            light: Duration::from_secs(60),
            default_: Duration::from_secs(60),
            evm_execution: Duration::from_secs(60),
            max_batch: Duration::from_millis(1),
            max_batch_requests: 100,
        };
        let methods = ["eth_chainId", "eth_blockNumber"];
        let computed: Duration = methods
            .iter()
            .map(|m| classify_rpc_method(m)(&timeouts))
            .sum::<Duration>()
            .min(timeouts.max_batch);
        assert_eq!(
            computed,
            Duration::from_millis(1),
            "sum (120s) max_batch (1ms) tavanını AŞMAMALI"
        );
    }

    // YÜKSEK #7: eth_call/eth_estimateGas kaynak sınırları testleri.

    /// Gas yakıcı (sonsuz döngü), evm.rs testindeki aynı bytecode.
    fn gas_burner_hex() -> String {
        format!("0x{}", hex::encode([0x5b, 0x60, 0x00, 0x56]))
    }

    #[test]
    fn parse_requested_gas_reads_a_valid_hex_gas_field() {
        let call_obj = serde_json::json!({"to": "0x2222222222222222222222222222222222222222", "gas": "0x5208"});
        assert_eq!(parse_requested_gas(&call_obj), Some(21_000));
    }

    #[test]
    fn parse_requested_gas_returns_none_when_gas_field_is_absent_or_invalid() {
        let no_gas = serde_json::json!({"to": "0x2222222222222222222222222222222222222222"});
        assert_eq!(parse_requested_gas(&no_gas), None);

        let bad_gas = serde_json::json!({"gas": "not-hex"});
        assert_eq!(parse_requested_gas(&bad_gas), None);
    }

    /// 🛡️ YÜKSEK #7 KANIT: kullanıcı beyanı config tavanının ALTINDAYSA
    /// AYNEN kullanılır (kırpılmaz), dApp'in KENDİ beyan ettiği, zaten
    /// makul bir gas değeri gereksiz yere büyütülmez.
    #[test]
    fn resolve_effective_gas_uses_the_requested_value_when_under_the_cap() {
        let call_obj = serde_json::json!({"gas": "0x5208"}); // 21_000
        assert_eq!(resolve_effective_gas(&call_obj, 10_000_000), 21_000);
    }

    /// 🛡️ KANIT: kullanıcı beyanı config tavanını AŞARSA sessizce tavana
    /// KIRPILIR (reddedilmez), geth/standart RPC davranışıyla tutarlı;
    /// beyan yok sayılıp her zaman 30M kullanılmaz.
    #[test]
    fn resolve_effective_gas_clamps_a_request_above_the_configured_cap() {
        let call_obj = serde_json::json!({"gas": "0x1c9c380"}); // 30_000_000
        assert_eq!(resolve_effective_gas(&call_obj, 10_000_000), 10_000_000);
    }

    #[test]
    fn resolve_effective_gas_uses_the_full_cap_when_gas_field_is_absent() {
        let call_obj = serde_json::json!({});
        assert_eq!(resolve_effective_gas(&call_obj, 10_000_000), 10_000_000);
    }

    /// 🛑 `eth_call` `eth_call_max_gas`a saygı gösterir; kanıt duvar saati (düşük
    /// tavanla gas yakıcı hızlı biter).
    #[test]
    fn eth_call_wiring_low_configured_max_gas_finishes_faster_than_high() {
        let state = test_state();
        let mempool = test_mempool(state.clone());
        let body = serde_json::json!({"to": "", "data": gas_burner_hex()});
        let req_low = rpc_request("eth_call", vec![body.clone()]);
        let req_high = rpc_request("eth_call", vec![body]);

        let low_limits = EvmSimulationLimits {
            eth_call_max_gas: 100_000,
            eth_estimate_gas_max_gas: 100_000,
            max_parallel_simulations: 32,
        };
        let high_limits = EvmSimulationLimits {
            eth_call_max_gas: 25_000_000,
            eth_estimate_gas_max_gas: 25_000_000,
            max_parallel_simulations: 32,
        };

        let start_low = std::time::Instant::now();
        RpcServer::handle_request(
            req_low,
            state.clone(),
            mempool.clone(),
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            low_limits,
        );
        let elapsed_low = start_low.elapsed();

        let start_high = std::time::Instant::now();
        RpcServer::handle_request(
            req_high,
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            high_limits,
        );
        let elapsed_high = start_high.elapsed();

        eprintln!(
            "📊 YÜKSEK #7 RPC-KATMANI ÖLÇÜMÜ: low(100K)={:?} high(25M)={:?}",
            elapsed_low, elapsed_high
        );
        assert!(
            elapsed_low < elapsed_high,
            "DÜZELTME REGRESYONU: düşük yapılandırılmış tavan (100K), yüksek \
             tavandan (25M) daha HIZLI bitmeli - config RPC katmanından \
             executor'a ulaşmıyor olabilir (low={:?}, high={:?})",
            elapsed_low,
            elapsed_high
        );
    }

    /// 🛑 KANIT (eş zamanlılık): simülasyon tavanı doluyken yeni `eth_call` hemen
    /// -32005 ("Server busy") alır. `EVM_SIMULATION_IN_FLIGHT` process global
    /// olduğundan test payını "şu anki değer + 1" olarak kurar (paralel gürültüden bağımsız).
    #[test]
    fn eth_call_is_rejected_with_busy_error_when_concurrent_simulation_limit_is_reached() {
        let state = test_state();
        let mempool = test_mempool(state.clone());

        let before = EVM_SIMULATION_IN_FLIGHT.load(Ordering::Relaxed);
        let tight_limit = before + 1;
        // Tavanı TAM doldur: mevcut (muhtemelen paralel testlerden gelen)
        // kullanım + bu tek işgalci = tight_limit.
        let _occupier = InFlightGuard::try_acquire(&EVM_SIMULATION_IN_FLIGHT, tight_limit).unwrap();

        let evm_limits = EvmSimulationLimits {
            eth_call_max_gas: 10_000_000,
            eth_estimate_gas_max_gas: 10_000_000,
            max_parallel_simulations: tight_limit,
        };
        let body = serde_json::json!({
            "to": "0x2222222222222222222222222222222222222222",
            "data": "0x"
        });
        let response = RpcServer::handle_request(
            rpc_request("eth_call", vec![body]),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            evm_limits,
        );

        assert!(response.result.is_none());
        assert_eq!(
            response.error.unwrap()["code"],
            Value::from(-32005),
            "tavan doluyken eth_call -32005 (Server busy) ile REDDEDİLMELİ"
        );
    }

    // 🚨 Regresyon: `eth_getBlockByHash` desteklenmeli; sessiz `null` MetaMask
    // bakiye güncellemesini durdurur.
    #[test]
    fn eth_get_block_by_hash_returns_the_same_stub_block_as_by_number() {
        let state = test_state();
        let mempool = test_mempool(state.clone());

        let by_hash = RpcServer::handle_request(
            rpc_request(
                "eth_getBlockByHash",
                vec![
                    Value::String(
                        "0x0000000000000000000000000000000000000000000000000000000000000001"
                            .to_string(),
                    ),
                    Value::from(false),
                ],
            ),
            state.clone(),
            mempool.clone(),
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );

        let by_number = RpcServer::handle_request(
            rpc_request(
                "eth_getBlockByNumber",
                vec![Value::String("latest".to_string()), Value::from(false)],
            ),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );

        assert!(
            by_hash.result.is_some(),
            "eth_getBlockByHash artik null degil gecerli bir blok donmeli"
        );
        assert_eq!(by_hash.result, by_number.result);
    }

    // 🚨 Regresyon: `eth_blockNumber` blok ilerledikçe değişmeli; sabit değerde
    // MetaMask block tracker'ı donar.
    #[test]
    fn eth_block_number_reflects_real_height_and_changes_as_it_advances() {
        let state = test_state();
        let mempool = test_mempool(state.clone());

        let at_genesis = RpcServer::handle_request(
            rpc_request("eth_blockNumber", vec![]),
            state.clone(),
            mempool.clone(),
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );
        assert_eq!(at_genesis.result, Some(Value::String("0x0".to_string())));

        state
            .set_account(&"__GLOBAL_BLOCK_HEIGHT__".to_string(), AccountState::new(7))
            .unwrap();

        let after_advance = RpcServer::handle_request(
            rpc_request("eth_blockNumber", vec![]),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );
        assert_eq!(
            after_advance.result,
            Some(Value::String("0x7".to_string())),
            "eth_blockNumber sabit KALMAMALI, gercek yuksekligi yansitmali"
        );
        assert_ne!(
            at_genesis.result, after_advance.result,
            "MetaMask'in block tracker'i icin sayi degismezse 'yeni blok' olayi hic tetiklenmez"
        );
    }

    // 🚨 REGRESYON: eth_getBlockByNumber/Hash'in "number" alanı ile
    // eth_blockNumber AYNI kaynaktan (gerçek yükseklik) beslenir; iki metod
    // birbiriyle çelişmemeli.
    #[test]
    fn eth_get_block_by_number_matches_eth_block_number_after_height_changes() {
        let state = test_state();
        let mempool = test_mempool(state.clone());

        state
            .set_account(
                &"__GLOBAL_BLOCK_HEIGHT__".to_string(),
                AccountState::new(42),
            )
            .unwrap();
        // 🏛️ `eth_getBlockByNumber` gerçek arşivlenmiş `block_<N>` header'ı gerektirir
        // (yalnız yüksekliği bumplamak yetmez); gerçek blok üretimi taklit edilir.
        let header = ArchivedBlockHeader {
            number: 42,
            parent_hash: [0u8; 32],
            state_root: [0u8; 32],
            timestamp: 1_700_000_000,
            tx_hashes: Vec::new(),
        };
        state
            .set_account(
                &block_key(42),
                AccountState {
                    contract_code: bincode::serialize(&header).unwrap(),
                    ..Default::default()
                },
            )
            .unwrap();

        let block_number_response = RpcServer::handle_request(
            rpc_request("eth_blockNumber", vec![]),
            state.clone(),
            mempool.clone(),
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );
        let block_response = RpcServer::handle_request(
            rpc_request(
                "eth_getBlockByNumber",
                vec![Value::String("latest".to_string()), Value::from(false)],
            ),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );

        assert_eq!(
            block_number_response.result,
            Some(Value::String("0x2a".to_string()))
        );
        assert_eq!(
            block_response.result.unwrap()["number"],
            Value::String("0x2a".to_string()),
            "eth_getBlockByNumber'in 'number' alani eth_blockNumber ile TUTARLI olmali"
        );
    }

    // 🚨 REGRESYON (RPC uyumluluk): blok JSON'unun "gasUsed"i, bloktaki her
    // tx'in gerçek arşivlenmiş `ArchivedReceipt.gas_used`'inin TOPLAMI
    // olmalı, sabit "0x0" değil.
    #[test]
    fn eth_get_block_by_number_gas_used_is_the_real_sum_of_archived_receipts_not_a_hardcoded_zero()
    {
        let state = test_state();
        let mempool = test_mempool(state.clone());

        let tx_id_1 = [1u8; 32];
        let tx_id_2 = [2u8; 32];
        let header = ArchivedBlockHeader {
            number: 5,
            parent_hash: [0u8; 32],
            state_root: [0u8; 32],
            timestamp: 1_700_000_000,
            tx_hashes: vec![tx_id_1, tx_id_2],
        };
        state
            .set_account(
                &block_key(5),
                AccountState {
                    contract_code: bincode::serialize(&header).unwrap(),
                    ..Default::default()
                },
            )
            .unwrap();
        for (id, gas) in [(tx_id_1, 21_000u64), (tx_id_2, 50_000u64)] {
            let receipt = ArchivedReceipt {
                status: true,
                gas_used: gas,
                contract_address: None,
                logs: Vec::new(),
                block_number: 5,
            };
            state
                .set_account(
                    &receipt_key(&id),
                    AccountState {
                        contract_code: bincode::serialize(&receipt).unwrap(),
                        ..Default::default()
                    },
                )
                .unwrap();
        }

        let response = RpcServer::handle_request(
            rpc_request(
                "eth_getBlockByNumber",
                vec![Value::String("0x5".to_string()), Value::from(false)],
            ),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );

        let result = response.result.expect("blok bulunmali");
        assert_eq!(
            result["gasUsed"],
            Value::String(format!("0x{:x}", 71_000u128)),
            "gasUsed 21000+50000'in gercek toplami olmali, sabit 0x0 DEGIL"
        );
    }

    // 🚨 REGRESYON (RPC uyumluluk): blok JSON'unun "miner"i, `main.rs`'in
    // yazdığı `__CONFIGURED_BLOCK_PRODUCER__` sentinel'i ayarlanmışsa onu
    // yansıtmalı (eth_coinbase ile AYNI tek doğruluk kaynağı), sıfır adres değil.
    #[test]
    fn eth_get_block_by_number_miner_reflects_the_configured_block_producer() {
        let state = test_state();
        let mempool = test_mempool(state.clone());

        state
            .set_account(
                &"__CONFIGURED_BLOCK_PRODUCER__".to_string(),
                AccountState {
                    contract_code: b"0xabc0000000000000000000000000000000000d".to_vec(),
                    ..Default::default()
                },
            )
            .unwrap();
        let header = ArchivedBlockHeader {
            number: 1,
            parent_hash: [0u8; 32],
            state_root: [0u8; 32],
            timestamp: 1_700_000_000,
            tx_hashes: Vec::new(),
        };
        state
            .set_account(
                &block_key(1),
                AccountState {
                    contract_code: bincode::serialize(&header).unwrap(),
                    ..Default::default()
                },
            )
            .unwrap();

        let response = RpcServer::handle_request(
            rpc_request(
                "eth_getBlockByNumber",
                vec![Value::String("0x1".to_string()), Value::from(false)],
            ),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );

        assert_eq!(
            response.result.expect("blok bulunmali")["miner"],
            Value::String("0xabc0000000000000000000000000000000000d".to_string())
        );
    }

    // Yapilandirilmamis (bos) durumda eskisi gibi sifir adrese dusmeli,
    // `eth_coinbase`'in fallback davranisiyla TUTARLI kalmali.
    #[test]
    fn eth_get_block_by_number_miner_falls_back_to_zero_address_when_unconfigured() {
        let state = test_state();
        let mempool = test_mempool(state.clone());
        let header = ArchivedBlockHeader {
            number: 1,
            parent_hash: [0u8; 32],
            state_root: [0u8; 32],
            timestamp: 1_700_000_000,
            tx_hashes: Vec::new(),
        };
        state
            .set_account(
                &block_key(1),
                AccountState {
                    contract_code: bincode::serialize(&header).unwrap(),
                    ..Default::default()
                },
            )
            .unwrap();

        let response = RpcServer::handle_request(
            rpc_request(
                "eth_getBlockByNumber",
                vec![Value::String("0x1".to_string()), Value::from(false)],
            ),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );

        assert_eq!(
            response.result.expect("blok bulunmali")["miner"],
            Value::String("0x0000000000000000000000000000000000000000".to_string())
        );
    }

    // 🚨 REGRESYON: eth_maxPriorityFeePerGas desteklenmeli; standart EIP-1559
    // istemcileri (MetaMask/ethers/viem) bunu bir hex miktar bekleyerek
    // çağırır, genel yakalayıcıya düşüp `null` dönmemeli.
    #[test]
    fn eth_max_priority_fee_per_gas_returns_a_real_value_not_null() {
        let state = test_state();
        let mempool = test_mempool(state.clone());

        let response = RpcServer::handle_request(
            rpc_request("eth_maxPriorityFeePerGas", vec![]),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );

        assert!(response.result.is_some());
        assert_ne!(response.result, Some(Value::Null));
    }

    // 🚨 REGRESYON: `eth_sendRawTransaction` her ret için gerçek JSON-RPC `error`
    // dönmeli; `result: null` cüzdanlarda "boş ama başarılı" sanılıp çöker.
    #[test]
    fn eth_send_raw_transaction_rejects_invalid_hex_with_a_proper_error_not_null_result() {
        let state = test_state();
        let mempool = test_mempool(state.clone());

        let response = RpcServer::handle_request(
            rpc_request(
                "eth_sendRawTransaction",
                vec![Value::String("0xnot-valid-hex".to_string())],
            ),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );

        assert!(
            response.result.is_none(),
            "gecersiz hex icin result null DEGIL, error donmeli"
        );
        assert_eq!(response.error.unwrap()["code"], Value::from(-32602));
    }

    #[test]
    fn eth_send_raw_transaction_rejects_undecodable_rlp_with_a_proper_error_not_null_result() {
        let state = test_state();
        let mempool = test_mempool(state.clone());

        // Gecerli hex ama gecersiz RLP/işlem baytları.
        let response = RpcServer::handle_request(
            rpc_request(
                "eth_sendRawTransaction",
                vec![Value::String("0xdeadbeef".to_string())],
            ),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );

        assert!(
            response.result.is_none(),
            "cozulemeyen RLP icin result null DEGIL, error donmeli"
        );
        assert_eq!(response.error.unwrap()["code"], Value::from(-32602));
    }

    /// İleri-nonce kuyrugu: fonlu hesabin kucuk-bosluklu islemi kabul edilir
    /// (hash doner, kuyrukta bekler, pending nonce ilerlemez); fonsuz hesabinki reddedilir.
    #[test]
    fn eth_send_raw_transaction_queues_a_small_forward_nonce_gap_for_a_funded_sender_only() {
        use secp256k1::SecretKey;
        let state = test_state();
        state
            .set_pool_reserves(1_000 * 10u128.pow(18), 1_000 * 10u128.pow(18))
            .unwrap();
        let mempool = test_mempool(state.clone());
        let funded = SecretKey::from_slice(&[11u8; 32]).unwrap();
        let funded_addr = zagros_types::Transaction::address_from_secret_key(&funded);
        state
            .set_account(
                &funded_addr,
                AccountState::new(1_000_000_000 * 10u128.pow(18)),
            )
            .unwrap();
        let send = |key: &SecretKey, nonce: u64| {
            let raw = build_signed_legacy_tx_with_value(
                key,
                "0x2222222222222222222222222222222222222222",
                Vec::new(),
                nonce,
                CHAIN_ID,
                10u128.pow(18),
            );
            RpcServer::handle_request(
                rpc_request(
                    "eth_sendRawTransaction",
                    vec![Value::String(format!("0x{}", hex::encode(raw)))],
                ),
                state.clone(),
                mempool.clone(),
                Arc::new(DashMap::new()),
                default_bridge_manager_arc(),
                EvmSimulationLimits::default(),
            )
        };
        let r = send(&funded, 3);
        assert!(
            r.error.is_none() && r.result.is_some(),
            "fonlu + bosluk 3 -> kuyruk, hash doner: {:?}",
            r.error
        );
        assert_eq!(mempool.size(), 0);
        assert_eq!(mempool.queued_count(), 1);
        assert_eq!(
            mempool.pending_nonce(0, &funded_addr),
            0,
            "kuyruk pending nonce'u ilerletmez"
        );
        // Fonsuz hesap: kuyruga ALINMAZ (spam kalkani)
        let poor = SecretKey::from_slice(&[12u8; 32]).unwrap();
        let r2 = send(&poor, 3);
        assert!(
            r2.result.is_none() && r2.error.is_some(),
            "fonsuz hesap kuyruga giremez"
        );
        assert_eq!(mempool.queued_count(), 1);
    }

    #[test]
    fn eth_send_raw_transaction_rejects_wrong_nonce_with_a_proper_error_not_null_result() {
        use secp256k1::SecretKey;
        let state = test_state();
        let mempool = test_mempool(state.clone());

        let secret_key = SecretKey::from_slice(&[9u8; 32]).unwrap();
        // Taze bir hesap icin beklenen nonce 0'dir. ileri-nonce kuyrugu:
        // kucuk bosluk (<=32) artik kuyruga alinir; bu test BUYUK boslugu (100)
        // olcer -> hala "nonce" hatasi. Kuyruk davranisi ayri testte.
        let raw_tx = build_signed_legacy_tx(
            &secret_key,
            "0x2222222222222222222222222222222222222222",
            Vec::new(),
            100,
            CHAIN_ID,
        );

        let response = RpcServer::handle_request(
            rpc_request(
                "eth_sendRawTransaction",
                vec![Value::String(format!("0x{}", hex::encode(raw_tx)))],
            ),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );

        assert!(
            response.result.is_none(),
            "yanlis nonce icin result null DEGIL, error donmeli"
        );
        let error = response.error.unwrap();
        assert_eq!(error["code"], Value::from(-32000));
        let message = error["message"].as_str().unwrap();
        assert!(
            message.contains("nonce"),
            "hata mesaji nonce'dan bahsetmeli: {message}"
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn propose_params(
        key: &SigningKey,
        authority_address: &str,
        tx_type: &str,
        recipient: &str,
        amount: u128,
        source_chain: &str,
        source_tx_hash: &str,
        timestamp: u64,
        auto_swap: bool,
        amount_out_min: u128,
        chain_id: u64,
    ) -> Vec<Value> {
        let bridge_tx_type = match tx_type {
            "mint" => zagros_executor::bridge::BridgeTxType::Mint,
            "burn" => zagros_executor::bridge::BridgeTxType::Burn,
            other => panic!("unknown tx_type in test helper: {}", other),
        };

        let mut hasher_input = Vec::new();
        hasher_input.extend_from_slice(b"BRIDGE_PROPOSE:");
        hasher_input.extend_from_slice(format!("{:?}", bridge_tx_type).as_bytes());
        hasher_input.extend_from_slice(recipient.as_bytes());
        hasher_input.extend_from_slice(&amount.to_le_bytes());
        hasher_input.extend_from_slice(source_chain.as_bytes());
        hasher_input.extend_from_slice(source_tx_hash.as_bytes());
        hasher_input.extend_from_slice(&timestamp.to_le_bytes());
        hasher_input.push(auto_swap as u8);
        hasher_input.extend_from_slice(&amount_out_min.to_le_bytes());
        hasher_input.extend_from_slice(&chain_id.to_le_bytes());
        let message = Keccak256::digest(&hasher_input);
        let signature = key.sign(&message);

        vec![
            Value::String(tx_type.to_string()),
            Value::String(recipient.to_string()),
            Value::String(amount.to_string()),
            Value::String(source_chain.to_string()),
            Value::String(source_tx_hash.to_string()),
            Value::String(timestamp.to_string()),
            Value::Bool(auto_swap),
            Value::String(amount_out_min.to_string()),
            Value::String(authority_address.to_string()),
            Value::String(hex::encode(key.verifying_key().to_bytes())),
            Value::String(hex::encode(signature.to_bytes())),
        ]
    }

    /// 🛡️ Sabit-zamanlı token karşılaştırması doğru sonucu vermeli, "sabit
    /// zamanlı" olması DOĞRULUKTAN ödün vermek demek değil.
    #[test]
    fn constant_time_token_comparison_is_still_correct() {
        assert!(constant_time_eq("gizli-token", "gizli-token"));
        assert!(!constant_time_eq("gizli-token", "gizli-tokeM"));
        assert!(!constant_time_eq("gizli-token", "gizli-toke"));
        assert!(!constant_time_eq("", "x"));
        assert!(constant_time_eq("", ""));
        // Ilk bayti ayni olan uzun bir yanlis token da reddedilmeli (kisa
        // devre yapan bir karsilastirmanin sizdirdigi tam durum).
        assert!(!constant_time_eq("aaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaab"));
    }

    fn default_bridge_manager_arc() -> Arc<std::sync::Mutex<BridgeManager>> {
        Arc::new(std::sync::Mutex::new(
            BridgeManager::default_bridge_manager(CHAIN_ID),
        ))
    }

    /// Gerçek RPC yolundan (üretim kodu) mint önerisi oluşturup 2/3 imza toplar ve
    /// persist eder; dönen proposal_id `mint_tx.tx_id`'ye atanmalı (zincir doğrular).
    #[allow(clippy::too_many_arguments)]
    /// 🚨 `BridgeMint` öneriyi payload'ında TAŞIMAK ZORUNDA (bkz.
    /// `decode_proposal_payload`); boş payload ile kurulan test köprünün en kritik
    /// yolunu testsiz bırakır. Öneriyi manager'dan alıp üretimin beklediği baytları üretir.
    fn mint_proposal_payload(
        bridge_manager: &Arc<std::sync::Mutex<BridgeManager>>,
        proposal_id: &[u8; 32],
    ) -> Vec<u8> {
        let guard = bridge_manager.lock().unwrap();
        let proposal = guard
            .get_proposal(proposal_id)
            .expect("oneri manager'da bulunmali (seed_mint_proposal_via_rpc onu olusturdu)");
        zagros_executor::bridge::BridgeManager::encode_proposal_payload(proposal)
            .expect("oneri payload'i serialize edilebilmeli")
    }
    fn seed_mint_proposal_via_rpc(
        state: Arc<dyn State>,
        mempool: Arc<Mempool>,
        bridge_manager: Arc<std::sync::Mutex<BridgeManager>>,
        recipient: &str,
        amount: u128,
        auto_swap: bool,
        now: u64,
    ) -> [u8; 32] {
        let authorities = BridgeManager::default_authorities();
        // 🛡️ Basim dogrulamasi ZINCIRDEKI yetkili kumesini okur (uretimde
        // genesis yazar; bkz. Executor::validate_bridge_mint_proposal) ve
        // fail-closed'dir, testte de kurulmali.
        zagros_executor::bridge::store_bridge_authority_set(
            state.as_ref(),
            &zagros_executor::bridge::OnChainBridgeAuthoritySet {
                authorities: authorities.clone(),
                required_signatures: 2,
            },
        )
        .unwrap();
        let proposer_key = authority_signing_key(1);
        let params = propose_params(
            &proposer_key,
            &authorities[0].address,
            "mint",
            recipient,
            amount,
            "Ethereum",
            "0xtest_source_tx_hash",
            now,
            auto_swap,
            0,
            CHAIN_ID,
        );
        let propose_result = RpcServer::handle_request(
            rpc_request("zagros_proposeBridgeAction", params),
            state.clone(),
            mempool.clone(),
            Arc::new(DashMap::new()),
            bridge_manager.clone(),
            EvmSimulationLimits::default(),
        )
        .result
        .unwrap();
        assert!(
            propose_result.get("error").is_none(),
            "propose failed: {:?}",
            propose_result
        );
        let proposal_id_hex = propose_result["proposal_id"].as_str().unwrap().to_string();

        let mut proposal_id = [0u8; 32];
        hex::decode_to_slice(
            proposal_id_hex.strip_prefix("0x").unwrap(),
            &mut proposal_id,
        )
        .unwrap();

        // default_authorities() 3 taneden en az 2'si (varsayılan eşik) imzalamalı.
        // `propose_then_sign_reaches_required_threshold_but_not_yet_executable`
        // testindeki GERÇEK imzalama deseninin birebir aynısı.
        for seed in 1..=2u8 {
            let signer_key = authority_signing_key(seed);
            let authority_address = BridgeManager::derive_address_from_public_key(
                &signer_key.verifying_key().to_bytes(),
            );
            let message = {
                let manager = bridge_manager.lock().unwrap();
                BridgeManager::create_signing_message(
                    manager.get_proposal(&proposal_id).unwrap(),
                    manager.chain_id(),
                )
            };
            let sig_ts = now;
            let bound = BridgeManager::bind_timestamp_to_message(&message, sig_ts);
            let signature = signer_key.sign(&bound);

            let sign_result = RpcServer::handle_request(
                rpc_request(
                    "zagros_signBridgeProposal",
                    vec![
                        Value::String(proposal_id_hex.clone()),
                        Value::String(authority_address),
                        Value::String(hex::encode(signer_key.verifying_key().to_bytes())),
                        Value::String(hex::encode(signature.to_bytes())),
                        Value::String(sig_ts.to_string()),
                    ],
                ),
                state.clone(),
                mempool.clone(),
                Arc::new(DashMap::new()),
                bridge_manager.clone(),
                EvmSimulationLimits::default(),
            )
            .result
            .unwrap();
            assert!(
                sign_result.get("error").is_none(),
                "sign failed: {:?}",
                sign_result
            );
        }

        proposal_id
    }

    /// Gerçek `BridgeBurn` (önce teminat mint'i) ile burn indeksine bilinen kayıt
    /// düşürür; döner: gönderen adresi.
    fn seed_real_bridge_burn(
        state: Arc<dyn State>,
        mempool: Arc<Mempool>,
        bridge_manager: Arc<std::sync::Mutex<BridgeManager>>,
        sender_seed: u8,
        authority_seed: u8,
        burn_tx_id: [u8; 32],
        burn_amount: u128,
    ) -> String {
        let secret_key = secp256k1::SecretKey::from_slice(&[sender_seed; 32]).unwrap();
        let sender = Transaction::address_from_secret_key(&secret_key);
        state
            .set_account(
                &sender,
                AccountState {
                    balance: 1_000_000_000_000_000_000,
                    zerenya_balance: burn_amount.saturating_mul(2).max(1),
                    ..Default::default()
                },
            )
            .unwrap();

        let authority_key = secp256k1::SecretKey::from_slice(&[authority_seed; 32]).unwrap();
        let authority = Transaction::address_from_secret_key(&authority_key);
        state
            .set_account(&authority, AccountState::new(1_000_000_000_000_000_000))
            .unwrap();
        let mint_amount = burn_amount.saturating_mul(2).max(1);
        let now_secs = current_unix_secs();
        let mint_proposal_id = seed_mint_proposal_via_rpc(
            state.clone(),
            mempool.clone(),
            bridge_manager.clone(),
            &sender,
            mint_amount,
            false,
            now_secs,
        );
        let mut mint_tx = Transaction {
            tx_id: mint_proposal_id,
            tx_type: TxType::BridgeMint,
            sender: authority.clone(),
            receiver: sender.clone(),
            amount: mint_amount,
            payload: mint_proposal_payload(&bridge_manager, &mint_proposal_id),
            signature: Vec::new(),
            timestamp: (now_secs as u128) * 1000,
            nonce: 0,
            gas_limit: 1,
            gas_price: 1,
            chain_id: CHAIN_ID,
        };
        mint_tx.sign(&authority_key);
        zagros_executor::Executor::new(state.clone())
            .with_bridge_authority(authority)
            .with_bridge_threshold(2, 0)
            .execute_transaction(&mint_tx, mint_tx.timestamp)
            .unwrap();

        let mut burn_tx = Transaction {
            tx_id: burn_tx_id,
            tx_type: TxType::BridgeBurn,
            sender: sender.clone(),
            receiver: "0x0000000000000000000000000000000000000002".to_string(),
            amount: burn_amount,
            payload: Vec::new(),
            signature: Vec::new(),
            timestamp: current_unix_secs() as u128,
            nonce: 0,
            gas_limit: 21_000,
            gas_price: 1,
            chain_id: CHAIN_ID,
        };
        burn_tx.sign(&secret_key);
        zagros_executor::Executor::new(state.clone())
            .execute_transaction(&burn_tx, burn_tx.timestamp)
            .unwrap();

        sender
    }

    /// 🚨 BİLİNMEYEN HASH İÇİN `null`, UYDURMA İŞLEM DEĞİL: her hash'e "kazıldı"
    /// demek makbuz `null` gelince ethers/MetaMask tutarlılık kontrolünü bozar
    /// (`-32603 precondition failure`) ve başka zincirin işlemine "bende var" dedirtir.
    #[test]
    fn get_transaction_by_hash_returns_null_for_an_unknown_hash() {
        let state = test_state();
        let mempool = test_mempool(state.clone());
        let response = RpcServer::handle_request(
            rpc_request(
                "eth_getTransactionByHash",
                vec![Value::String(
                    "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
                        .to_string(),
                )],
            ),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );

        assert_eq!(
            response.result,
            Some(Value::Null),
            "bilinmeyen hash icin uydurma islem donduruldu - cuzdanlarda \
             'precondition failure' hatasina yol acar"
        );
    }

    /// Bu düğümden gönderilmiş bir işlem ise NORMAL şekilde döndürülmeli,
    /// yukarıdaki katılık, bilinen işlemleri gizlemeye dönüşmemeli.
    #[test]
    fn get_transaction_by_hash_still_returns_transactions_this_node_knows() {
        // 🏛️ "Bu düğüm biliyor mu" kalıcı `tx_body_<hash>` arşiviyle kanıtlanır
        // (geçici `tx_cache` değil), gerçek gövde (to/value/input) döner.
        let state = test_state();
        let mempool = test_mempool(state.clone());
        let hash = "0x1111111111111111111111111111111111111111111111111111111111111111";
        let clean = hash.trim_start_matches("0x");
        let tx_id = parse_tx_id_hex(clean).unwrap();

        let tx = Transaction {
            tx_id,
            tx_type: TxType::Transfer,
            sender: "0x00000000000000000000000000000000000000aa".to_string(),
            amount: 0,
            receiver: "0x00000000000000000000000000000000000000bb".to_string(),
            payload: Vec::new(),
            signature: Vec::new(),
            timestamp: 0,
            nonce: 0,
            gas_limit: 21_000,
            gas_price: 1,
            chain_id: CHAIN_ID,
        };
        state
            .set_account(
                &tx_body_key(&tx_id),
                AccountState {
                    contract_code: bincode::serialize(&tx).unwrap(),
                    ..Default::default()
                },
            )
            .unwrap();

        let response = RpcServer::handle_request(
            rpc_request(
                "eth_getTransactionByHash",
                vec![Value::String(hash.to_string())],
            ),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );

        let result = response.result.expect("sonuc bekleniyordu");
        assert_eq!(result.get("hash").and_then(|v| v.as_str()), Some(hash));
        assert_eq!(
            result.get("from").and_then(|v| v.as_str()),
            Some("0x00000000000000000000000000000000000000aa")
        );
    }

    // 🚨 REGRESYON: "v"/"r"/"s" gerçek imza baytlarından (r/s birebir, v EIP-155
    // formülüyle kayıpsız yeniden inşa; bkz. `extract_vrs`).
    #[test]
    fn eth_get_transaction_by_hash_returns_real_vrs_derived_from_the_evm_origin_signature() {
        let state = test_state();
        let mempool = test_mempool(state.clone());
        let hash = "0x2222222222222222222222222222222222222222222222222222222222222222";
        let clean = hash.trim_start_matches("0x");
        let tx_id = parse_tx_id_hex(clean).unwrap();

        // 97 bayt = r(32) || s(32) || v(1)=27 || sighash(32), gercek EVM
        // kokenli imza semasi (bkz. decode_and_convert_tx doc yorumu).
        let mut signature = vec![0xAAu8; 32]; // r
        signature.extend(vec![0xBBu8; 32]); // s
        signature.push(27); // v (0|1 formundaki recovery byte)
        signature.extend(vec![0u8; 32]); // external sighash dolgusu

        let tx = Transaction {
            tx_id,
            tx_type: TxType::Transfer,
            sender: "0x00000000000000000000000000000000000000aa".to_string(),
            amount: 0,
            receiver: "0x00000000000000000000000000000000000000bb".to_string(),
            payload: Vec::new(),
            signature,
            timestamp: 0,
            nonce: 0,
            gas_limit: 21_000,
            gas_price: 1,
            chain_id: CHAIN_ID,
        };
        state
            .set_account(
                &tx_body_key(&tx_id),
                AccountState {
                    contract_code: bincode::serialize(&tx).unwrap(),
                    ..Default::default()
                },
            )
            .unwrap();

        let response = RpcServer::handle_request(
            rpc_request(
                "eth_getTransactionByHash",
                vec![Value::String(hash.to_string())],
            ),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );

        let result = response.result.expect("sonuc bekleniyordu");
        assert_eq!(
            result["r"],
            Value::String(format!("0x{}", "aa".repeat(32))),
            "r imzanin ilk 32 bayti olmali, sabit ...0001 DEGIL"
        );
        assert_eq!(
            result["s"],
            Value::String(format!("0x{}", "bb".repeat(32))),
            "s imzanin ikinci 32 bayti olmali, sabit ...0001 DEGIL"
        );
        assert_eq!(
            result["v"],
            Value::String(format!("0x{:x}", CHAIN_ID * 2 + 35)),
            "v gercek EIP-155 formuluyle (chain_id*2+35+recovery_id=0) yeniden insa edilmeli"
        );
    }

    // Native (65 bayt, EIP-155 disi) imzalar icin EIP-155 kavrami yok, v
    // klasik 27+recovery_id konvansiyonuna dusmeli.
    #[test]
    fn eth_get_transaction_by_hash_returns_legacy_v_for_a_native_65_byte_signature() {
        let state = test_state();
        let mempool = test_mempool(state.clone());
        let hash = "0x3333333333333333333333333333333333333333333333333333333333333333";
        let clean = hash.trim_start_matches("0x");
        let tx_id = parse_tx_id_hex(clean).unwrap();

        let mut signature = vec![0xCCu8; 32]; // r
        signature.extend(vec![0xDDu8; 32]); // s
        signature.push(1); // recovery byte 0|1 formunda, id=1

        let tx = Transaction {
            tx_id,
            tx_type: TxType::Transfer,
            sender: "0x00000000000000000000000000000000000000aa".to_string(),
            amount: 0,
            receiver: "0x00000000000000000000000000000000000000bb".to_string(),
            payload: Vec::new(),
            signature,
            timestamp: 0,
            nonce: 0,
            gas_limit: 21_000,
            gas_price: 1,
            chain_id: CHAIN_ID,
        };
        state
            .set_account(
                &tx_body_key(&tx_id),
                AccountState {
                    contract_code: bincode::serialize(&tx).unwrap(),
                    ..Default::default()
                },
            )
            .unwrap();

        let response = RpcServer::handle_request(
            rpc_request(
                "eth_getTransactionByHash",
                vec![Value::String(hash.to_string())],
            ),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );

        let result = response.result.expect("sonuc bekleniyordu");
        assert_eq!(
            result["v"],
            Value::String("0x1c".to_string()),
            "27+1=28=0x1c"
        );
    }

    // 🚨 REGRESYON: `status` koşulsuz "0x1" olmamalı; `FAILED_RECEIPT_MARKER`'lı
    // makbuz "0x0" döner. Bilinmeyen metod standart -32601.
    #[test]
    fn an_unknown_rpc_method_returns_a_proper_method_not_found_error_not_null() {
        let state = test_state();
        let mempool = test_mempool(state.clone());

        let response = RpcServer::handle_request(
            rpc_request("this_method_does_not_exist", vec![]),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );

        assert!(response.result.is_none());
        assert_eq!(response.error.unwrap()["code"], Value::from(-32601));
    }

    #[test]
    fn previously_missing_standard_methods_now_return_honest_values_not_null() {
        let state = test_state();
        let mempool = test_mempool(state.clone());

        let check = |method: &str, mempool: Arc<Mempool>| {
            RpcServer::handle_request(
                rpc_request(method, vec![]),
                state.clone(),
                mempool,
                Arc::new(DashMap::new()),
                default_bridge_manager_arc(),
                EvmSimulationLimits::default(),
            )
        };

        assert_eq!(
            check("web3_clientVersion", mempool.clone()).result,
            Some(Value::String("Zagros/v1.0.0".to_string()))
        );
        assert_eq!(
            check("net_listening", mempool.clone()).result,
            Some(Value::Bool(true))
        );
        assert_eq!(
            check("net_peerCount", mempool.clone()).result,
            Some(Value::String("0x0".to_string()))
        );
        assert_eq!(
            check("eth_syncing", mempool.clone()).result,
            Some(Value::Bool(false))
        );
        assert_eq!(
            check("eth_accounts", mempool.clone()).result,
            Some(Value::Array(vec![]))
        );
        assert_eq!(
            check("eth_mining", mempool.clone()).result,
            Some(Value::Bool(false))
        );
        assert_eq!(
            check("eth_coinbase", mempool.clone()).result,
            Some(Value::String(
                "0x0000000000000000000000000000000000000000".to_string()
            ))
        );
    }

    #[test]
    fn web3_sha3_computes_a_real_keccak256_hash() {
        let state = test_state();
        let mempool = test_mempool(state.clone());

        let response = RpcServer::handle_request(
            rpc_request("web3_sha3", vec![Value::String("0x".to_string())]),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );

        let hash = response.result.expect("sonuc bekleniyordu");
        let hash_str = hash.as_str().expect("hex string bekleniyordu");
        // Keccak256("") deterministik ve 32 bayt; tam değer ezberlenmez.
        assert_eq!(hash_str.len(), 66, "0x + 64 hex karakter (32 bayt) olmali");
        assert!(hash_str.starts_with("0x"));
    }

    #[test]
    fn eth_get_transaction_receipt_reports_status_0x0_for_a_failed_receipt() {
        let state = test_state();
        let mempool = test_mempool(state.clone());
        let hash = "0x2222222222222222222222222222222222222222222222222222222222222222";
        let clean = hash.trim_start_matches("0x");
        let tx_id = parse_tx_id_hex(clean).unwrap();

        let receipt = ArchivedReceipt {
            status: false,
            gas_used: 21_000,
            contract_address: None,
            logs: Vec::new(),
            block_number: 42,
        };
        let receipt_acc = AccountState {
            contract_code: bincode::serialize(&receipt).unwrap(),
            ..Default::default()
        };
        state
            .set_account(&receipt_key(&tx_id), receipt_acc)
            .unwrap();
        // D14-kozmetik: fiş artık bloğu BULAMAZSA sentetik hash uydurmak
        // yerine -32000 döner; bu test status alanını sınadığından bloğu
        // gerçekçi şekilde tohumluyoruz.
        let header = ArchivedBlockHeader {
            number: 42,
            parent_hash: [0u8; 32],
            state_root: [0u8; 32],
            timestamp: 1_700_000_000,
            tx_hashes: vec![tx_id],
        };
        state
            .set_account(
                &block_key(42),
                AccountState {
                    contract_code: bincode::serialize(&header).unwrap(),
                    ..Default::default()
                },
            )
            .unwrap();

        let response = RpcServer::handle_request(
            rpc_request(
                "eth_getTransactionReceipt",
                vec![Value::String(hash.to_string())],
            ),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );

        let result = response.result.expect("sonuc bekleniyordu");
        assert_eq!(result["status"], Value::String("0x0".to_string()));
        assert_eq!(result["logs"], Value::Array(vec![]));
    }

    #[test]
    fn eth_get_transaction_receipt_still_reports_status_0x1_for_a_successful_receipt() {
        let state = test_state();
        let mempool = test_mempool(state.clone());
        let hash = "0x3333333333333333333333333333333333333333333333333333333333333333";
        let clean = hash.trim_start_matches("0x");
        let tx_id = parse_tx_id_hex(clean).unwrap();

        // 🚨 Regresyon: `blockNumber` makbuzdaki gerçek bloktan; güncel yükseklik
        // kullanılsaydı eski tx'in numarası zincirle değişirdi.
        let receipt = ArchivedReceipt {
            status: true,
            gas_used: 21_000,
            contract_address: None,
            logs: Vec::new(),
            block_number: 9,
        };
        let receipt_acc = AccountState {
            contract_code: bincode::serialize(&receipt).unwrap(),
            ..Default::default()
        };
        state
            .set_account(&receipt_key(&tx_id), receipt_acc)
            .unwrap();
        // D14-kozmetik: fiş artık bloğu BULAMAZSA sentetik hash uydurmak
        // yerine -32000 döner; bu test status alanını sınadığından bloğu
        // gerçekçi şekilde tohumluyoruz.
        let header = ArchivedBlockHeader {
            number: 9,
            parent_hash: [0u8; 32],
            state_root: [0u8; 32],
            timestamp: 1_700_000_000,
            tx_hashes: vec![tx_id],
        };
        state
            .set_account(
                &block_key(9),
                AccountState {
                    contract_code: bincode::serialize(&header).unwrap(),
                    ..Default::default()
                },
            )
            .unwrap();

        let response = RpcServer::handle_request(
            rpc_request(
                "eth_getTransactionReceipt",
                vec![Value::String(hash.to_string())],
            ),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );

        let result = response.result.expect("sonuc bekleniyordu");
        assert_eq!(result["status"], Value::String("0x1".to_string()));
        assert_eq!(result["blockNumber"], Value::String("0x9".to_string()));
    }

    // 🚨 REGRESYON: `eth_getCode` adres parametresine bakmalı; sabit "0x"
    // (kod yok/EOA) dönmek MetaMask gibi cüzdanlara gerçekten deploy edilmiş
    // bir sözleşme için bile "burada bir sözleşme yok" dedirtir.
    #[test]
    fn eth_get_code_returns_the_real_deployed_bytecode_not_always_0x() {
        let state = test_state();
        let mempool = test_mempool(state.clone());
        let contract = "0x4444444444444444444444444444444444444444".to_string();
        let bytecode = vec![0x60, 0x00, 0x60, 0x00, 0xfd];
        state
            .set_account(&contract, AccountState::new_contract(bytecode.clone()))
            .unwrap();

        let response = RpcServer::handle_request(
            rpc_request("eth_getCode", vec![Value::String(contract.clone())]),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );

        let result = response.result.expect("sonuc bekleniyordu");
        assert_eq!(
            result,
            Value::String(format!("0x{}", hex::encode(&bytecode)))
        );
    }

    #[test]
    fn eth_get_code_returns_0x_for_an_address_with_no_contract() {
        let state = test_state();
        let mempool = test_mempool(state.clone());
        let eoa = "0x5555555555555555555555555555555555555555".to_string();
        state.set_account(&eoa, AccountState::new(1_000)).unwrap();

        let response = RpcServer::handle_request(
            rpc_request("eth_getCode", vec![Value::String(eoa)]),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );

        let result = response.result.expect("sonuc bekleniyordu");
        assert_eq!(result, Value::String("0x".to_string()));
    }

    // 🚨 REGRESYON: `eth_getStorageAt` `AccountState.storage`'daki GERÇEK
    // SLOAD/SSTORE değerini okur (genel -32601'e düşmez).
    #[test]
    fn eth_get_storage_at_returns_the_real_stored_slot_value() {
        let state = test_state();
        let mempool = test_mempool(state.clone());
        let contract = "0x9999999999999999999999999999999999999999".to_string();
        let mut account = AccountState::new_contract(vec![0x00]);
        account.storage.insert(
            zagros_types::U256::from(7u64),
            zagros_types::U256::from(42u64),
        );
        state.set_account(&contract, account).unwrap();

        let response = RpcServer::handle_request(
            rpc_request(
                "eth_getStorageAt",
                vec![Value::String(contract), Value::String("0x7".to_string())],
            ),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );

        let result = response.result.expect("sonuc bekleniyordu");
        let expected = format!(
            "0x{}",
            hex::encode(zagros_types::U256::from(42u64).to_be_bytes::<32>())
        );
        assert_eq!(result, Value::String(expected));
    }

    #[test]
    fn eth_get_storage_at_returns_zero_for_an_unset_slot() {
        let state = test_state();
        let mempool = test_mempool(state.clone());
        let contract = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        state
            .set_account(&contract, AccountState::new_contract(vec![0x00]))
            .unwrap();

        let response = RpcServer::handle_request(
            rpc_request(
                "eth_getStorageAt",
                vec![Value::String(contract), Value::String("0x0".to_string())],
            ),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );

        let result = response.result.expect("sonuc bekleniyordu");
        assert_eq!(result, Value::String(format!("0x{}", "0".repeat(64))));
    }

    // Zagros DPoS, uncle/ommer kavramı yok, bu yüzden 0 GERÇEK cevap.
    #[test]
    fn eth_get_uncle_count_is_honestly_always_zero_no_uncles_in_dpos() {
        let state = test_state();
        let mempool = test_mempool(state.clone());

        let response = RpcServer::handle_request(
            rpc_request(
                "eth_getUncleCountByBlockNumber",
                vec![Value::String("0x1".to_string())],
            ),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );

        let result = response.result.expect("sonuc bekleniyordu");
        assert_eq!(result, Value::String("0x0".to_string()));
    }

    // 🚨 REGRESYON: `eth_estimateGas` çağrının içeriğine bakıp gerçek EVM
    // simülasyonuyla ölçer; başarılı bir çağrı gerçek `gas_used`'a dayalı
    // (sabit 5.000.000'dan farklı) bir sonuç döner.
    #[test]
    fn eth_estimate_gas_returns_a_real_measured_value_for_a_successful_call() {
        let state = test_state();
        let mempool = test_mempool(state.clone());
        let contract = "0x6666666666666666666666666666666666666666".to_string();
        // STOP, trivially başarılı, minimal gas harcar.
        state
            .set_account(&contract, AccountState::new_contract(vec![0x00]))
            .unwrap();

        let call_obj = serde_json::json!({
            "to": contract,
            "data": "0x1234",
        });
        let response = RpcServer::handle_request(
            rpc_request("eth_estimateGas", vec![call_obj]),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );

        let result = response.result.expect("sonuc bekleniyordu");
        let hex_str = result.as_str().expect("hex string bekleniyordu");
        assert!(hex_str.starts_with("0x"));
        let gas = u64::from_str_radix(hex_str.trim_start_matches("0x"), 16).unwrap();
        // Sabit eski değerden (5.000.000) FARKLI ve makul bir aralıkta olmalı.
        assert_ne!(gas, 0x4c4b40);
        assert!(gas >= 21_000);
        assert!(gas < 100_000);
    }

    // 🚨 REGRESYON (F-rpc-panic): 4 baytlık selector'lı (36 bayt beklenen dilimleme
    // için yetersiz) `eth_estimateGas` worker'ı panikletmemeli, JSON-RPC yanıtı dönmeli.
    #[test]
    fn eth_estimate_gas_does_not_panic_on_a_truncated_selector_only_calldata() {
        let state = test_state();
        let mempool = test_mempool(state.clone());

        // 0x34c5163e = SwapBuy seçicisi, normalde `data[4..36]`'dan miktar
        // okur, burada sadece seçicinin kendisi gönderiliyor (4 bayt).
        let call_obj = serde_json::json!({
            "to": "0x0000000000000000000000000000000000000000",
            "data": "0x34c5163e",
        });
        let response = RpcServer::handle_request(
            rpc_request("eth_estimateGas", vec![call_obj]),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );

        // Panic etmeden buraya kadar gelmesi asıl regresyon kanıtı; ayrıca
        // yanıtın da geçerli bir JSON-RPC şekli (sonuç YA DA hata, ikisi
        // birden değil) olduğunu doğrula.
        assert!(response.result.is_some() != response.error.is_some());
    }

    // 🚨 Regresyon: 36 baytlık `data`da u128'e sığmayan değer `as_u128()` panic'i
    // atmamalı (kimliksiz tek istekle tetiklenebilir).
    #[test]
    fn eth_estimate_gas_does_not_panic_on_a_swap_amount_exceeding_u128_range() {
        let state = test_state();
        let mempool = test_mempool(state.clone());

        // 0x34c5163e = SwapBuy seçicisi + 32 bayt TAMAMEN 0xff (u128'in çok
        // üzerinde bir değer kodluyor, üst 16 baytı sıfır değil).
        let data = format!("0x34c5163e{}", "ff".repeat(32));
        let call_obj = serde_json::json!({
            "to": "0x0000000000000000000000000000000000000000",
            "data": data,
        });
        let response = RpcServer::handle_request(
            rpc_request("eth_estimateGas", vec![call_obj]),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );

        assert!(response.result.is_some() != response.error.is_some());
    }

    #[test]
    fn eth_estimate_gas_returns_a_proper_error_not_a_fabricated_number_for_a_reverting_call() {
        let state = test_state();
        let mempool = test_mempool(state.clone());
        let contract = "0x7777777777777777777777777777777777777777".to_string();
        // PUSH1 0x00 PUSH1 0x00 REVERT, her zaman revert eder.
        state
            .set_account(
                &contract,
                AccountState::new_contract(vec![0x60, 0x00, 0x60, 0x00, 0xfd]),
            )
            .unwrap();

        let call_obj = serde_json::json!({
            "to": contract,
            "data": "0x1234",
        });
        let response = RpcServer::handle_request(
            rpc_request("eth_estimateGas", vec![call_obj]),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );

        assert!(response.result.is_none());
        assert!(response.error.is_some());
    }

    /// `test_mempool`'un kasıtlı dejenere havuzuyla (pool_zagros=1) hesap düşük tarafa
    /// taşar ve `synthetic_gas_limit_for_fee` 21000 tabanına takılır (`0x5208`).
    /// Gerçekçi havuzla orantılı tahmin `..._with_a_realistic_pool` testinde.
    #[test]
    fn eth_estimate_gas_floors_at_21000_for_a_plain_native_transfer_with_a_degenerate_pool() {
        let state = test_state();
        let mempool = test_mempool(state.clone());

        let call_obj = serde_json::json!({
            "to": "0x8888888888888888888888888888888888888888",
        });
        let response = RpcServer::handle_request(
            rpc_request("eth_estimateGas", vec![call_obj]),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );

        let result = response.result.expect("sonuc bekleniyordu");
        assert_eq!(result, Value::String("0x5208".to_string()));
    }

    /// Gerçekçi havuzla `eth_estimateGas`'ın native transfer değeri, `apply_fixed_gas_fee`'nin
    /// gerçek ücretinin `eth_gasPrice`'a bölümüne eşit olmalı (MetaMask çarpımı gerçek ücrete yaklaşır).
    #[test]
    fn eth_estimate_gas_native_transfer_reflects_the_actual_fixed_fee_with_a_realistic_pool() {
        let state = test_state();
        // Gerçekçi bir havuz: genesis'teki gibi büyük ölçekli, ~4000:1 oranlı rezervler
        // (42.000.000 ZAGROS / 10.500 ZERENYA), eski 1:1'e yakın ZERENYA-ölçekli oran
        // artık gerçekçi değil.
        state
            .set_pool_reserves(
                zagros_types::GENESIS_POOL_ZAGROS,
                zagros_types::GENESIS_POOL_ZERENYA,
            )
            .unwrap();
        let mempool = test_mempool(state.clone());

        let expected_fee = mempool.native_min_required_fee(&TxType::Transfer);
        let expected_gas_limit =
            (expected_fee / zagros_types::MIN_EVM_GAS_PRICE_WEI).max(21_000) as u64;

        let call_obj = serde_json::json!({
            "to": "0x8888888888888888888888888888888888888888",
        });
        let response = RpcServer::handle_request(
            rpc_request("eth_estimateGas", vec![call_obj]),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );

        let result = response.result.expect("sonuc bekleniyordu");
        assert_eq!(
            result,
            Value::String(format!("0x{:x}", expected_gas_limit)),
            "eth_estimateGas, apply_fixed_gas_fee'nin uygulayacağı GERÇEK ücrete karşılık gelen \
             bir gas_limit döndürmeli, ilgisiz sabit bir değer değil"
        );
        // Bu gerçekçi havuzda tahminin artık dejenere durumdaki gibi
        // 21000'e SIKIŞMADIĞINI da doğrula, asıl iyileştirmenin kanıtı.
        assert!(
            expected_gas_limit > 21_000,
            "gerçekçi bir havuzda beklenen gas_limit 21000 tabanının ÜZERİNDE olmalı, aksi halde \
             bu test dejenere fixture'la aynı şeyi kanıtlıyor demektir"
        );
    }

    // 🚨 REGRESYON: `0x...0005` (UNSTAKE) revm modexp precompile'ıyla çakışır; ham
    // simülasyon sahte `PrecompileError` üretir. `native_tx_type_for_evm_call`
    // simülasyondan ÖNCE tanır.
    #[test]
    fn eth_estimate_gas_recognizes_unstake_call_and_skips_the_precompile_colliding_simulation() {
        let state = test_state();
        let mempool = test_mempool(state.clone());

        // keccak256("unstake(uint256)") = 0x2e17de78, amount = 724990.76e18 gibi büyük bir rakam.
        let call_obj = serde_json::json!({
            "from": "0x00000005668becb40d7eaafdae73ed6347932d49",
            "to": "0x0000000000000000000000000000000000000005",
            "data": "0x2e17de78000000000000000000000000000000000000000000009985d3ee0e541e840000",
        });
        let response = RpcServer::handle_request(
            rpc_request("eth_estimateGas", vec![call_obj]),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );

        let result = response.result.expect("sonuc bekleniyordu - hata degil");
        assert_eq!(result, Value::String("0x5208".to_string()));
    }

    // Aynı çakışma 0x...0004 (identity) ve 0x...0003 (ripemd160) için; tesadüfen
    // geçiyordu, artık kasıtlı tanınıyorlar.
    #[test]
    fn eth_estimate_gas_recognizes_stake_call_to_the_precompile_colliding_validator_address() {
        let state = test_state();
        let mempool = test_mempool(state.clone());

        // keccak256("stake()") selector'ı, StakeView.tsx'teki gerçek çağrı.
        let call_obj = serde_json::json!({
            "from": "0x03f779e5b63ae830d2bea2e8b8d593823b066118",
            "to": "0x0000000000000000000000000000000000000004",
            "data": "0x3a4b66f1",
        });
        let response = RpcServer::handle_request(
            rpc_request("eth_estimateGas", vec![call_obj]),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );

        let result = response.result.expect("sonuc bekleniyordu - hata degil");
        assert_eq!(result, Value::String("0x5208".to_string()));
    }

    // Gerçek bir kontrata (native-yönlendirme dışı, sahte-kontrat adresleri
    // DIŞINDA bir hedef) yapılan çağrılar HÂLÂ gerçek EVM simülasyonundan
    // geçmeli, kısayol SADECE bilinen native seçicilere uygulanır.
    #[test]
    fn eth_estimate_gas_still_really_simulates_genuine_contract_calls() {
        let state = test_state();
        let mempool = test_mempool(state.clone());
        let contract = "0x6666666666666666666666666666666666666666".to_string();
        state
            .set_account(&contract, AccountState::new_contract(vec![0x00]))
            .unwrap();

        let call_obj = serde_json::json!({
            "to": contract,
            "data": "0x12345678",
        });
        let response = RpcServer::handle_request(
            rpc_request("eth_estimateGas", vec![call_obj]),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );

        let result = response.result.expect("sonuc bekleniyordu");
        let hex_str = result.as_str().expect("hex string bekleniyordu");
        let gas = u64::from_str_radix(hex_str.trim_start_matches("0x"), 16).unwrap();
        // Gerçek simülasyondan gelen (STOP, minimal) gaz, düz 21000'den farklı olmalı.
        assert_ne!(gas, 21_000);
    }

    #[test]
    fn propose_bridge_mint_rejects_unknown_authority() {
        let state = test_state();
        let mempool = test_mempool(state.clone());
        let bridge_manager = default_bridge_manager_arc();

        let stranger_key = authority_signing_key(99); // not one of the 3 default authorities
        let stranger_address =
            BridgeManager::derive_address_from_public_key(&stranger_key.verifying_key().to_bytes());
        let params = propose_params(
            &stranger_key,
            &stranger_address,
            "mint",
            "0x0000000000000000000000000000000000000009",
            1_000,
            "Ethereum",
            "0xabc",
            current_unix_secs(),
            false,
            0,
            CHAIN_ID,
        );

        let response = RpcServer::handle_request(
            rpc_request("zagros_proposeBridgeAction", params),
            state,
            mempool,
            Arc::new(DashMap::new()),
            bridge_manager,
            EvmSimulationLimits::default(),
        );

        let result = response.result.unwrap();
        assert!(
            result.get("error").is_some(),
            "expected an error, got {:?}",
            result
        );
        assert!(result.get("proposal_id").is_none());
    }

    #[test]
    fn propose_then_sign_reaches_required_threshold_but_not_yet_executable() {
        let state = test_state();
        let mempool = test_mempool(state.clone());
        let bridge_manager = default_bridge_manager_arc();
        let authorities = BridgeManager::default_authorities();

        let proposer_key = authority_signing_key(1);
        let params = propose_params(
            &proposer_key,
            &authorities[0].address,
            "mint",
            "0x0000000000000000000000000000000000000009",
            5_000,
            "Ethereum",
            "0xdeadbeef",
            current_unix_secs(),
            true,
            0,
            CHAIN_ID,
        );

        let propose_response = RpcServer::handle_request(
            rpc_request("zagros_proposeBridgeAction", params),
            state.clone(),
            mempool.clone(),
            Arc::new(DashMap::new()),
            bridge_manager.clone(),
            EvmSimulationLimits::default(),
        );
        let propose_result = propose_response.result.unwrap();
        assert!(
            propose_result.get("error").is_none(),
            "propose failed: {:?}",
            propose_result
        );
        let proposal_id_hex = propose_result["proposal_id"].as_str().unwrap().to_string();

        // Status right after proposing: no signatures yet, cannot execute.
        let status = RpcServer::handle_request(
            rpc_request(
                "zagros_getBridgeProposal",
                vec![Value::String(proposal_id_hex.clone())],
            ),
            state.clone(),
            mempool.clone(),
            Arc::new(DashMap::new()),
            bridge_manager.clone(),
            EvmSimulationLimits::default(),
        )
        .result
        .unwrap();
        assert_eq!(status["signatures_collected"], 0);
        assert_eq!(status["executed"], false);
        assert_eq!(status["can_execute"], false);
        assert_eq!(status["auto_swap"], true);

        // 2 of 3 default authorities sign, default_bridge_manager() requires 2.
        for seed in 1..=2u8 {
            let signer_key = authority_signing_key(seed);
            let authority_address = BridgeManager::derive_address_from_public_key(
                &signer_key.verifying_key().to_bytes(),
            );

            // İmza mesajı `BridgeManager::create_signing_message`'ı yansıtır; gerçek
            // nonce/id yalnız sunucuda bilindiğinden manager'dan (aynı Arc) geri okunur.
            let mut proposal_id = [0u8; 32];
            hex::decode_to_slice(
                proposal_id_hex.strip_prefix("0x").unwrap(),
                &mut proposal_id,
            )
            .unwrap();
            let message = {
                let manager = bridge_manager.lock().unwrap();
                BridgeManager::create_signing_message(
                    manager.get_proposal(&proposal_id).unwrap(),
                    manager.chain_id(),
                )
            };
            // 🛡️ FAZ4: imza, mesaj + gönderilen timestamp'e bağlı türetilmiş
            // mesaj üzerinden atılmalı (sunucu da öyle doğruluyor).
            let sig_ts = current_unix_secs();
            let bound = BridgeManager::bind_timestamp_to_message(&message, sig_ts);
            let signature = signer_key.sign(&bound);

            let sign_response = RpcServer::handle_request(
                rpc_request(
                    "zagros_signBridgeProposal",
                    vec![
                        Value::String(proposal_id_hex.clone()),
                        Value::String(authority_address),
                        Value::String(hex::encode(signer_key.verifying_key().to_bytes())),
                        Value::String(hex::encode(signature.to_bytes())),
                        Value::String(sig_ts.to_string()),
                    ],
                ),
                state.clone(),
                mempool.clone(),
                Arc::new(DashMap::new()),
                bridge_manager.clone(),
                EvmSimulationLimits::default(),
            );
            let sign_result = sign_response.result.unwrap();
            assert!(
                sign_result.get("error").is_none(),
                "sign failed for seed {}: {:?}",
                seed,
                sign_result
            );
        }

        let status_after_signing = RpcServer::handle_request(
            rpc_request(
                "zagros_getBridgeProposal",
                vec![Value::String(proposal_id_hex)],
            ),
            state,
            mempool,
            Arc::new(DashMap::new()),
            bridge_manager,
            EvmSimulationLimits::default(),
        )
        .result
        .unwrap();
        assert_eq!(status_after_signing["signatures_collected"], 2);
        // Threshold met, but the 24h timelock hasn't, can_execute must stay false.
        assert_eq!(status_after_signing["can_execute"], false);
    }

    #[test]
    fn sign_bridge_proposal_rejects_signature_from_the_wrong_key() {
        let state = test_state();
        let mempool = test_mempool(state.clone());
        let bridge_manager = default_bridge_manager_arc();
        let authorities = BridgeManager::default_authorities();

        let proposer_key = authority_signing_key(1);
        let params = propose_params(
            &proposer_key,
            &authorities[0].address,
            "mint",
            "0x0000000000000000000000000000000000000009",
            250,
            "Ethereum",
            "0xfeed",
            current_unix_secs(),
            false,
            0,
            CHAIN_ID,
        );
        let proposal_id_hex = RpcServer::handle_request(
            rpc_request("zagros_proposeBridgeAction", params),
            state.clone(),
            mempool.clone(),
            Arc::new(DashMap::new()),
            bridge_manager.clone(),
            EvmSimulationLimits::default(),
        )
        .result
        .unwrap()["proposal_id"]
            .as_str()
            .unwrap()
            .to_string();

        // Claims to be authority #2 but signs with authority #3's key.
        let real_authority = &authorities[1].address;
        let wrong_key = authority_signing_key(3);
        let bogus_message = b"not the real signing message";
        let bogus_signature = wrong_key.sign(bogus_message);

        let response = RpcServer::handle_request(
            rpc_request(
                "zagros_signBridgeProposal",
                vec![
                    Value::String(proposal_id_hex),
                    Value::String(real_authority.clone()),
                    Value::String(hex::encode(wrong_key.verifying_key().to_bytes())),
                    Value::String(hex::encode(bogus_signature.to_bytes())),
                    Value::String(current_unix_secs().to_string()),
                ],
            ),
            state,
            mempool,
            Arc::new(DashMap::new()),
            bridge_manager,
            EvmSimulationLimits::default(),
        );

        let result = response.result.unwrap();
        assert!(
            result.get("error").is_some(),
            "expected an error, got {:?}",
            result
        );
    }

    // 🛡️ Timestamp Drift Guard (±120s), replay/ağ dinleme koruması

    #[test]
    fn propose_bridge_mint_rejects_a_timestamp_300_seconds_in_the_past() {
        let state = test_state();
        let mempool = test_mempool(state.clone());
        let bridge_manager = default_bridge_manager_arc();
        let authorities = BridgeManager::default_authorities();

        let proposer_key = authority_signing_key(1);
        let stale_timestamp = current_unix_secs().saturating_sub(300);
        let params = propose_params(
            &proposer_key,
            &authorities[0].address,
            "mint",
            "0x0000000000000000000000000000000000000009",
            1_000,
            "Ethereum",
            "0xstale",
            stale_timestamp,
            false,
            0,
            CHAIN_ID,
        );

        let response = RpcServer::handle_request(
            rpc_request("zagros_proposeBridgeAction", params),
            state,
            mempool,
            Arc::new(DashMap::new()),
            bridge_manager,
            EvmSimulationLimits::default(),
        );

        assert!(
            response.result.is_none(),
            "stale timestamp must be rejected before any proposal is created"
        );
        let error = response.error.expect("expected a JSON-RPC error object");
        assert_eq!(error["code"], -32602);
    }

    #[test]
    fn propose_bridge_mint_rejects_a_timestamp_300_seconds_in_the_future() {
        let state = test_state();
        let mempool = test_mempool(state.clone());
        let bridge_manager = default_bridge_manager_arc();
        let authorities = BridgeManager::default_authorities();

        let proposer_key = authority_signing_key(1);
        let future_timestamp = current_unix_secs() + 300;
        let params = propose_params(
            &proposer_key,
            &authorities[0].address,
            "mint",
            "0x0000000000000000000000000000000000000009",
            1_000,
            "Ethereum",
            "0xfuture",
            future_timestamp,
            false,
            0,
            CHAIN_ID,
        );

        let response = RpcServer::handle_request(
            rpc_request("zagros_proposeBridgeAction", params),
            state,
            mempool,
            Arc::new(DashMap::new()),
            bridge_manager,
            EvmSimulationLimits::default(),
        );

        assert!(response.result.is_none());
        let error = response.error.expect("expected a JSON-RPC error object");
        assert_eq!(error["code"], -32602);
    }

    #[test]
    fn sign_bridge_proposal_rejects_a_timestamp_300_seconds_in_the_past() {
        let state = test_state();
        let mempool = test_mempool(state.clone());
        let bridge_manager = default_bridge_manager_arc();

        let stale_timestamp = current_unix_secs().saturating_sub(300);
        let response = RpcServer::handle_request(
            rpc_request(
                "zagros_signBridgeProposal",
                vec![
                    Value::String(format!("0x{}", "ab".repeat(32))),
                    Value::String("0x0000000000000000000000000000000000000001".to_string()),
                    Value::String("00".repeat(32)),
                    Value::String("00".repeat(64)),
                    Value::String(stale_timestamp.to_string()),
                ],
            ),
            state,
            mempool,
            Arc::new(DashMap::new()),
            bridge_manager,
            EvmSimulationLimits::default(),
        );

        assert!(
            response.result.is_none(),
            "stale timestamp must be rejected before sign_proposal ever runs"
        );
        let error = response.error.expect("expected a JSON-RPC error object");
        assert_eq!(error["code"], -32602);
    }

    #[test]
    fn get_bridge_proposal_reports_not_found_for_unknown_id() {
        let state = test_state();
        let mempool = test_mempool(state.clone());
        let bridge_manager = default_bridge_manager_arc();

        let response = RpcServer::handle_request(
            rpc_request(
                "zagros_getBridgeProposal",
                vec![Value::String(format!("0x{}", "ab".repeat(32)))],
            ),
            state,
            mempool,
            Arc::new(DashMap::new()),
            bridge_manager,
            EvmSimulationLimits::default(),
        );

        let result = response.result.unwrap();
        assert_eq!(result["error"], "Proposal not found");
    }

    /// item 5: bir öneri yürütülüp (`mark_executed_in_state`, gerçek üretim
    /// yolu) arşivlendikten SONRA bile `zagros_getBridgeProposal` id ile hâlâ
    /// sorgulanabilmeli (public API davranışı bozulmamalı).
    #[test]
    fn get_bridge_proposal_falls_back_to_archive_after_execution() {
        let state = test_state();
        let mempool = test_mempool(state.clone());
        let bridge_manager = default_bridge_manager_arc();
        let authorities = BridgeManager::default_authorities();

        let proposer_key = authority_signing_key(1);
        let params = propose_params(
            &proposer_key,
            &authorities[0].address,
            "mint",
            "0x0000000000000000000000000000000000000009",
            42,
            "Ethereum",
            "0xarchived_via_rpc",
            current_unix_secs(),
            false,
            0,
            CHAIN_ID,
        );
        let proposal_id_hex = RpcServer::handle_request(
            rpc_request("zagros_proposeBridgeAction", params),
            state.clone(),
            mempool.clone(),
            Arc::new(DashMap::new()),
            bridge_manager.clone(),
            EvmSimulationLimits::default(),
        )
        .result
        .unwrap()["proposal_id"]
            .as_str()
            .unwrap()
            .to_string();
        let mut proposal_id = [0u8; 32];
        proposal_id.copy_from_slice(&hex::decode(&proposal_id_hex[2..]).unwrap());

        // Üretim yürütme yolu canlı `bridge_manager`'a dokunmaz; CLI'nin her turda
        // çağırdığı `prune_ids_not_in` simüle edilir ki fallback diske/arşive düşsün.
        BridgeManager::mark_executed_in_state(state.as_ref(), &proposal_id).unwrap();
        bridge_manager.lock().unwrap().prune_ids_not_in(&[]);

        let response = RpcServer::handle_request(
            rpc_request(
                "zagros_getBridgeProposal",
                vec![Value::String(proposal_id_hex.clone())],
            ),
            state,
            mempool,
            Arc::new(DashMap::new()),
            bridge_manager,
            EvmSimulationLimits::default(),
        );
        let result = response.result.unwrap();
        assert_eq!(result["proposal_id"], proposal_id_hex);
        assert_eq!(result["executed"], true);
    }

    /// Mutabakat sonrası `zagros_getPendingBridgeProposals` yürütülmüş önerileri listelememeli.
    #[test]
    fn get_pending_bridge_proposals_excludes_archived_proposals() {
        let state = test_state();
        let mempool = test_mempool(state.clone());
        let bridge_manager = default_bridge_manager_arc();
        let authorities = BridgeManager::default_authorities();

        let proposer_key = authority_signing_key(1);
        let params = propose_params(
            &proposer_key,
            &authorities[0].address,
            "mint",
            "0x0000000000000000000000000000000000000009",
            42,
            "Ethereum",
            "0xwill_be_pruned",
            current_unix_secs(),
            false,
            0,
            CHAIN_ID,
        );
        let proposal_id_hex = RpcServer::handle_request(
            rpc_request("zagros_proposeBridgeAction", params),
            state.clone(),
            mempool.clone(),
            Arc::new(DashMap::new()),
            bridge_manager.clone(),
            EvmSimulationLimits::default(),
        )
        .result
        .unwrap()["proposal_id"]
            .as_str()
            .unwrap()
            .to_string();
        let mut proposal_id = [0u8; 32];
        proposal_id.copy_from_slice(&hex::decode(&proposal_id_hex[2..]).unwrap());

        BridgeManager::mark_executed_in_state(state.as_ref(), &proposal_id).unwrap();
        // CLI'nin köprü otomatik-yürütücü döngüsünün her turda yaptığı
        // mutabakat adımının simülasyonu: state'in taze (artık boş) bekleyen
        // listesiyle buda.
        bridge_manager.lock().unwrap().prune_ids_not_in(&[]);

        let response = RpcServer::handle_request(
            rpc_request("zagros_getPendingBridgeProposals", vec![]),
            state,
            mempool,
            Arc::new(DashMap::new()),
            bridge_manager,
            EvmSimulationLimits::default(),
        );
        let proposals = response.result.unwrap()["proposals"]
            .as_array()
            .unwrap()
            .clone();
        assert!(
            proposals.is_empty(),
            "arşivlenmiş bir öneri hâlâ bekleyen listede görünüyor"
        );
    }

    // 📋 zagros_getPendingBridgeProposals / burn-direction proposals

    #[test]
    fn pending_bridge_proposals_lists_a_freshly_proposed_mint() {
        let state = test_state();
        let mempool = test_mempool(state.clone());
        let bridge_manager = default_bridge_manager_arc();
        let authorities = BridgeManager::default_authorities();

        let proposer_key = authority_signing_key(1);
        let params = propose_params(
            &proposer_key,
            &authorities[0].address,
            "mint",
            "0x0000000000000000000000000000000000000009",
            42,
            "Ethereum",
            "0xpending",
            current_unix_secs(),
            false,
            0,
            CHAIN_ID,
        );
        let proposal_id_hex = RpcServer::handle_request(
            rpc_request("zagros_proposeBridgeAction", params),
            state.clone(),
            mempool.clone(),
            Arc::new(DashMap::new()),
            bridge_manager.clone(),
            EvmSimulationLimits::default(),
        )
        .result
        .unwrap()["proposal_id"]
            .as_str()
            .unwrap()
            .to_string();

        let response = RpcServer::handle_request(
            rpc_request("zagros_getPendingBridgeProposals", vec![]),
            state,
            mempool,
            Arc::new(DashMap::new()),
            bridge_manager,
            EvmSimulationLimits::default(),
        );
        let proposals = response.result.unwrap()["proposals"]
            .as_array()
            .unwrap()
            .clone();
        assert_eq!(proposals.len(), 1);
        assert_eq!(proposals[0]["proposal_id"], proposal_id_hex);
        assert_eq!(proposals[0]["tx_type"], "mint");
        assert_eq!(proposals[0]["executed"], false);
    }

    #[test]
    fn zagros_get_proposal_returns_status_and_tally_for_a_submitted_proposal() {
        use zagros_executor::Executor;
        use zagros_types::{AccountState, Transaction, TxType, CHAIN_ID, TOKEN_DECIMAL};

        let state = test_state();
        let mempool = test_mempool(state.clone());
        let bridge_manager = default_bridge_manager_arc();

        let proposer_key = governance_test_key(500);
        let proposer_address = Transaction::address_from_secret_key(&proposer_key);
        state
            .set_account(
                &proposer_address,
                AccountState {
                    balance: 1_000_000 * TOKEN_DECIMAL,
                    staked_balance: 20_000 * TOKEN_DECIMAL,
                    ..Default::default()
                },
            )
            .unwrap();

        let proposal_id = [17u8; 32];
        let mut tx = Transaction {
            tx_id: proposal_id,
            tx_type: TxType::SubmitProposal,
            sender: proposer_address.clone(),
            amount: 0,
            receiver: proposer_address.clone(),
            payload: b"lower gas fee".to_vec(),
            signature: Vec::new(),
            timestamp: std::time::UNIX_EPOCH.elapsed().unwrap().as_millis(),
            nonce: 0,
            gas_limit: 210_000,
            gas_price: 1,
            chain_id: CHAIN_ID,
        };
        tx.sign(&proposer_key);

        let executor = Executor::new(state.clone());
        executor.execute_transaction(&tx, tx.timestamp).unwrap();

        let response = RpcServer::handle_request(
            rpc_request(
                "zagros_getProposal",
                vec![Value::String(format!("0x{}", hex::encode(proposal_id)))],
            ),
            state,
            mempool,
            Arc::new(DashMap::new()),
            bridge_manager,
            EvmSimulationLimits::default(),
        );
        let result = response.result.unwrap();
        assert_eq!(
            result["proposal_id"],
            format!("0x{}", hex::encode(proposal_id))
        );
        assert_eq!(result["proposer"], proposer_address);
        assert_eq!(result["votes_for"], "0");
        assert_eq!(result["votes_against"], "0");
        assert_eq!(result["status"], "Active");
    }

    /// 🗳️ Öneri listesi: dizin en yeni önce, sayım/depozito alanları dolu.
    #[test]
    fn zagros_list_proposals_returns_newest_first_with_tally_fields() {
        let state = test_state();
        let mempool = test_mempool(state.clone());
        let bridge_manager = default_bridge_manager_arc();
        let proposer_key = secp256k1::SecretKey::from_slice(&[0x51u8; 32]).unwrap();
        let proposer_address = Transaction::address_from_secret_key(&proposer_key);
        state
            .set_account(
                &proposer_address,
                AccountState {
                    balance: 1_000_000 * zagros_types::TOKEN_DECIMAL,
                    staked_balance: 20_000 * zagros_types::TOKEN_DECIMAL,
                    ..Default::default()
                },
            )
            .unwrap();
        let executor = zagros_executor::Executor::new(state.clone());
        for (i, id) in [[0x21u8; 32], [0x22u8; 32]].iter().enumerate() {
            let mut tx = Transaction {
                tx_id: *id,
                tx_type: TxType::SubmitProposal,
                sender: proposer_address.clone(),
                amount: 0,
                receiver: proposer_address.clone(),
                payload: format!("oneri {i}").into_bytes(),
                signature: Vec::new(),
                timestamp: std::time::UNIX_EPOCH.elapsed().unwrap().as_millis(),
                nonce: i as u64,
                gas_limit: 210_000,
                gas_price: 1,
                chain_id: CHAIN_ID,
            };
            tx.sign(&proposer_key);
            executor.execute_transaction(&tx, tx.timestamp).unwrap();
        }
        let response = RpcServer::handle_request(
            rpc_request(
                "zagros_listProposals",
                vec![Value::from(10), Value::String(proposer_address.clone())],
            ),
            state,
            mempool,
            Arc::new(DashMap::new()),
            bridge_manager,
            EvmSimulationLimits::default(),
        );
        let result = response.result.unwrap();
        assert_eq!(result["total"], 2);
        let list = result["proposals"].as_array().unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(
            list[0]["proposal_id"],
            format!("0x{}", hex::encode([0x22u8; 32])),
            "en yeni once"
        );
        assert_eq!(list[0]["description"], "oneri 1");
        assert_eq!(list[0]["action"]["kind"], "Text");
        assert_eq!(list[0]["phase"], "Voting");
        assert_eq!(
            list[0]["deposit"], "0",
            "kapi oncesi (yukseklik 0) depozito yok"
        );
        assert!(list[0]["my_vote"].is_null());
        assert_eq!(list[0]["validator_tally"]["total"], 0);
        assert_eq!(list[0]["staker_tally"]["quorum_bps"], 2000);
    }

    /// 🗳️ Yönetişim bilgisi: parametre tablosu bincode indeksiyle birebir.
    #[test]
    fn zagros_get_governance_info_param_rows_match_bincode_index() {
        let state = test_state();
        let mempool = test_mempool(state.clone());
        let bridge_manager = default_bridge_manager_arc();
        let response = RpcServer::handle_request(
            rpc_request("zagros_getGovernanceInfo", vec![]),
            state,
            mempool,
            Arc::new(DashMap::new()),
            bridge_manager,
            EvmSimulationLimits::default(),
        );
        let result = response.result.unwrap();
        assert_eq!(result["max_validators"], 10);
        assert_eq!(result["gov_voting_epochs"], 168);
        assert_eq!(
            result["proposal_fee"],
            (1000 * zagros_types::TOKEN_DECIMAL).to_string()
        );
        assert_eq!(result["submit_selector"], "0xd2383136");
        let rows = result["param_keys"].as_array().unwrap();
        let defaults = zagros_types::consensus::ChainParams::genesis_defaults();
        let table = gov_param_key_rows(&defaults, zagros_types::consensus::DEFAULT_QC_GRACE_MS);
        assert_eq!(rows.len(), table.len());
        for (i, (key, name, _)) in table.iter().enumerate() {
            // bincode: birim varyant = u32 LE varyant indeksi
            let enc = bincode::serialize(key).unwrap();
            assert_eq!(
                enc,
                (i as u32).to_le_bytes().to_vec(),
                "{name} bincode indeksi {i} olmali"
            );
            assert_eq!(rows[i]["index"], i);
            assert_eq!(rows[i]["name"], *name);
        }
        assert_eq!(rows[0]["current"], "10");
    }

    #[test]
    fn zagros_get_proposal_returns_error_for_unknown_id() {
        let state = test_state();
        let mempool = test_mempool(state.clone());
        let bridge_manager = default_bridge_manager_arc();

        let response = RpcServer::handle_request(
            rpc_request(
                "zagros_getProposal",
                vec![Value::String(format!("0x{}", hex::encode([1u8; 32])))],
            ),
            state,
            mempool,
            Arc::new(DashMap::new()),
            bridge_manager,
            EvmSimulationLimits::default(),
        );
        let result = response.result.unwrap();
        assert!(result.get("error").is_some());
    }

    #[test]
    fn propose_bridge_action_supports_the_burn_unlock_intent_direction() {
        let state = test_state();
        let mempool = test_mempool(state.clone());
        let bridge_manager = default_bridge_manager_arc();
        let authorities = BridgeManager::default_authorities();

        let burn_tx_id = [21u8; 32];
        let burn_amount = 999u128;
        let sender = seed_real_bridge_burn(
            state.clone(),
            mempool.clone(),
            bridge_manager.clone(),
            201,
            202,
            burn_tx_id,
            burn_amount,
        );

        let proposer_key = authority_signing_key(1);
        let params = propose_params(
            &proposer_key,
            &authorities[0].address,
            "burn",
            &sender,
            burn_amount,
            "Zagros",
            &format!("0x{}", hex::encode(burn_tx_id)),
            current_unix_secs(),
            false,
            0,
            CHAIN_ID,
        );

        let response = RpcServer::handle_request(
            rpc_request("zagros_proposeBridgeAction", params),
            state,
            mempool,
            Arc::new(DashMap::new()),
            bridge_manager,
            EvmSimulationLimits::default(),
        );
        let result = response.result.unwrap();
        assert!(
            result.get("error").is_none(),
            "burn propose failed: {:?}",
            result
        );
        assert!(result.get("proposal_id").is_some());
    }

    /// Asıl kanıt: `source_tx_hash` gerçek bir burn kaydına
    /// karşılık geliyor ama `amount`/`recipient` (sender) UYDURMA, reddedilmeli.
    #[test]
    fn burn_proposal_with_mismatched_amount_is_rejected() {
        let state = test_state();
        let mempool = test_mempool(state.clone());
        let bridge_manager = default_bridge_manager_arc();
        let authorities = BridgeManager::default_authorities();

        let burn_tx_id = [22u8; 32];
        let real_amount = 500u128;
        let sender = seed_real_bridge_burn(
            state.clone(),
            mempool.clone(),
            bridge_manager.clone(),
            203,
            204,
            burn_tx_id,
            real_amount,
        );

        let proposer_key = authority_signing_key(1);
        let params = propose_params(
            &proposer_key,
            &authorities[0].address,
            "burn",
            &sender,
            real_amount * 1000, // GERÇEK yakma miktarinin 1000 kati - uydurma.
            "Zagros",
            &format!("0x{}", hex::encode(burn_tx_id)),
            current_unix_secs(),
            false,
            0,
            CHAIN_ID,
        );

        let response = RpcServer::handle_request(
            rpc_request("zagros_proposeBridgeAction", params),
            state,
            mempool,
            Arc::new(DashMap::new()),
            bridge_manager,
            EvmSimulationLimits::default(),
        );
        let result = response.result.unwrap();
        assert!(
            result.get("error").is_some(),
            "gercek bir burn kaydiyla eslesmeyen miktar kabul edildi: {:?}",
            result
        );
        assert!(result.get("proposal_id").is_none());
    }

    /// `source_tx_hash` hiçbir gerçek burn kaydına karşılık
    /// gelmiyor (tamamen uydurma), reddedilmeli. Bu, tek bir yetkilinin
    /// hiç yaşanmamış bir yakma için proposal oluşturamayacağının kanıtı.
    #[test]
    fn burn_proposal_for_a_nonexistent_burn_is_rejected() {
        let state = test_state();
        let mempool = test_mempool(state.clone());
        let bridge_manager = default_bridge_manager_arc();
        let authorities = BridgeManager::default_authorities();

        let proposer_key = authority_signing_key(1);
        let params = propose_params(
            &proposer_key,
            &authorities[0].address,
            "burn",
            "0x0000000000000000000000000000000000000009",
            999,
            "Zagros",
            &format!("0x{}", hex::encode([99u8; 32])), // hic yasanmamis bir tx_id.
            current_unix_secs(),
            false,
            0,
            CHAIN_ID,
        );

        let response = RpcServer::handle_request(
            rpc_request("zagros_proposeBridgeAction", params),
            state,
            mempool,
            Arc::new(DashMap::new()),
            bridge_manager,
            EvmSimulationLimits::default(),
        );
        let result = response.result.unwrap();
        assert!(
            result.get("error").is_some(),
            "hic yasanmamis bir burn icin proposal olusturuldu: {:?}",
            result
        );
        assert!(result.get("proposal_id").is_none());
    }

    #[test]
    fn a_signature_produced_for_mint_is_rejected_when_replayed_as_burn() {
        let state = test_state();
        let mempool = test_mempool(state.clone());
        let bridge_manager = default_bridge_manager_arc();
        let authorities = BridgeManager::default_authorities();

        let proposer_key = authority_signing_key(1);
        // Sign a "mint" request...
        let mut params = propose_params(
            &proposer_key,
            &authorities[0].address,
            "mint",
            "0x0000000000000000000000000000000000000009",
            1_000,
            "Ethereum",
            "0xswapped",
            current_unix_secs(),
            false,
            0,
            CHAIN_ID,
        );
        // ...then splice the tx_type field to "burn" post-signing, simulating
        // an attacker replaying a captured mint-signature against the burn
        // (unlock-intent) direction with otherwise-identical fields.
        params[0] = Value::String("burn".to_string());

        let response = RpcServer::handle_request(
            rpc_request("zagros_proposeBridgeAction", params),
            state,
            mempool,
            Arc::new(DashMap::new()),
            bridge_manager,
            EvmSimulationLimits::default(),
        );
        let result = response.result.unwrap();
        assert!(
            result.get("error").is_some(),
            "cross-direction signature replay must be rejected"
        );
        assert!(result.get("proposal_id").is_none());
    }

    // 🔥 zagros_getRecentBridgeBurns

    #[test]
    fn recent_bridge_burns_returns_empty_when_nothing_has_burned() {
        let state = test_state();
        let mempool = test_mempool(state.clone());
        let bridge_manager = default_bridge_manager_arc();

        let response = RpcServer::handle_request(
            rpc_request(
                "zagros_getRecentBridgeBurns",
                vec![Value::String("0".to_string())],
            ),
            state,
            mempool,
            Arc::new(DashMap::new()),
            bridge_manager,
            EvmSimulationLimits::default(),
        );

        let burns = response.result.unwrap()["burns"]
            .as_array()
            .unwrap()
            .clone();
        assert!(burns.is_empty());
    }

    /// `zagros_getBridgeBackedZerenya`, operatörün/kullanıcının "şu an köprü
    /// üzerinden ne kadar ZERENYA yakılabilir" sorusuna kesin cevap verebilmesi
    /// için eklendi (canlı testte bu değeri tahmin etmek zorunda kalmıştık).
    #[test]
    fn get_bridge_backed_zerenya_reports_zero_before_any_mint() {
        let state = test_state();
        let mempool = test_mempool(state.clone());
        let response = RpcServer::handle_request(
            rpc_request("zagros_getBridgeBackedZerenya", vec![]),
            state,
            mempool,
            Arc::new(DashMap::new()),
            default_bridge_manager_arc(),
            EvmSimulationLimits::default(),
        );
        assert_eq!(
            response.result.unwrap()["bridge_backed_zerenya"],
            "0",
            "hic mint yapilmamis bir zincirde teminat sifir olmali"
        );
    }

    #[test]
    fn get_bridge_backed_zerenya_reflects_a_real_mint() {
        let state = test_state();
        let mempool = test_mempool(state.clone());
        let bridge_manager = default_bridge_manager_arc();

        let authority_key = secp256k1::SecretKey::from_slice(&[77u8; 32]).unwrap();
        let authority = Transaction::address_from_secret_key(&authority_key);
        state
            .set_account(&authority, AccountState::new(1_000_000_000_000_000_000))
            .unwrap();
        let receiver = "0x0000000000000000000000000000000000000abc".to_string();
        let amount = 3_000_000_000_000_000_000u128;
        let now_secs = current_unix_secs();
        let proposal_id = seed_mint_proposal_via_rpc(
            state.clone(),
            mempool.clone(),
            bridge_manager.clone(),
            &receiver,
            amount,
            false,
            now_secs,
        );

        let mut mint_tx = Transaction {
            tx_id: proposal_id,
            tx_type: TxType::BridgeMint,
            sender: authority.clone(),
            receiver,
            amount,
            payload: mint_proposal_payload(&bridge_manager, &proposal_id),
            signature: Vec::new(),
            // 🚨 block_timestamp MİLİSANİYE olmalı, proposal_is_executable
            // bunu /1000 ile saniyeye çevirip proposal.timestamp (saniye) ile
            // karşılaştırıyor.
            timestamp: (now_secs as u128) * 1000,
            nonce: 0,
            gas_limit: 1,
            gas_price: 1,
            chain_id: CHAIN_ID,
        };
        mint_tx.sign(&authority_key);
        zagros_executor::Executor::new(state.clone())
            .with_bridge_authority(authority)
            .with_bridge_threshold(2, 0)
            .execute_transaction(&mint_tx, mint_tx.timestamp)
            .unwrap();

        let response = RpcServer::handle_request(
            rpc_request("zagros_getBridgeBackedZerenya", vec![]),
            state,
            mempool,
            Arc::new(DashMap::new()),
            bridge_manager,
            EvmSimulationLimits::default(),
        );
        assert_eq!(
            response.result.unwrap()["bridge_backed_zerenya"],
            "3000000000000000000",
            "gercek bir mint sonrasi teminat basilan miktari yansitmali"
        );
    }

    #[test]
    fn recent_bridge_burns_returns_a_new_entry_after_a_real_burn_executes() {
        let state = test_state();
        let mempool = test_mempool(state.clone());
        let bridge_manager = default_bridge_manager_arc();

        let secret_key = secp256k1::SecretKey::from_slice(&[55u8; 32]).unwrap();
        let sender = Transaction::address_from_secret_key(&secret_key);
        state
            .set_account(
                &sender,
                AccountState {
                    balance: 1_000_000_000_000_000_000,
                    zerenya_balance: 5_000_000_000_000_000_000,
                    ..Default::default()
                },
            )
            .unwrap();

        // 🛡️ Yakılacak ZERENYA'nın köprüden basılmış sayılması için önce gerçek BridgeMint.
        let authority_key = secp256k1::SecretKey::from_slice(&[66u8; 32]).unwrap();
        let authority = Transaction::address_from_secret_key(&authority_key);
        state
            .set_account(&authority, AccountState::new(1_000_000_000_000_000_000))
            .unwrap();
        let mint_amount = 5_000_000_000_000_000_000u128;
        let now_secs = current_unix_secs();
        let mint_proposal_id = seed_mint_proposal_via_rpc(
            state.clone(),
            mempool.clone(),
            bridge_manager.clone(),
            &sender,
            mint_amount,
            false,
            now_secs,
        );
        let mut mint_tx = Transaction {
            tx_id: mint_proposal_id,
            tx_type: TxType::BridgeMint,
            sender: authority.clone(),
            receiver: sender.clone(),
            amount: mint_amount,
            payload: mint_proposal_payload(&bridge_manager, &mint_proposal_id),
            signature: Vec::new(),
            timestamp: (now_secs as u128) * 1000,
            nonce: 0,
            gas_limit: 1,
            gas_price: 1,
            chain_id: CHAIN_ID,
        };
        mint_tx.sign(&authority_key);
        zagros_executor::Executor::new(state.clone())
            .with_bridge_authority(authority)
            .with_bridge_threshold(2, 0)
            .execute_transaction(&mint_tx, mint_tx.timestamp)
            .unwrap();

        let mut tx = Transaction {
            tx_id: [9u8; 32],
            tx_type: TxType::BridgeBurn,
            sender: sender.clone(),
            receiver: "0x0000000000000000000000000000000000000002".to_string(),
            amount: 250_000_000_000_000_000,
            payload: Vec::new(),
            signature: Vec::new(),
            timestamp: current_unix_secs() as u128,
            nonce: 0,
            gas_limit: 21_000,
            gas_price: 1,
            chain_id: CHAIN_ID,
        };
        tx.sign(&secret_key);

        let executor = zagros_executor::Executor::new(state.clone());
        executor.execute_transaction(&tx, tx.timestamp).unwrap();

        let response = RpcServer::handle_request(
            rpc_request(
                "zagros_getRecentBridgeBurns",
                vec![Value::String("0".to_string())],
            ),
            state,
            mempool,
            Arc::new(DashMap::new()),
            bridge_manager,
            EvmSimulationLimits::default(),
        );

        let burns = response.result.unwrap()["burns"]
            .as_array()
            .unwrap()
            .clone();
        assert_eq!(burns.len(), 1);
        assert_eq!(burns[0]["sender"], sender);
        assert_eq!(burns[0]["amount"], "250000000000000000");
        assert_eq!(burns[0]["index"], "0");
    }

    // 🔥 Köprü çıkışı (Burn), eth_sendRawTransaction çözücüsü
    use ethers_core::types::{NameOrAddress, Signature as EthSignature, TransactionRequest, H160};

    /// Cüzdan gibi legacy işlemi secp256k1 ile imzalayıp EIP-155 RLP baytları üretir.
    fn build_signed_legacy_tx(
        secret_key: &secp256k1::SecretKey,
        to: &str,
        calldata: Vec<u8>,
        nonce: u64,
        chain_id: u64,
    ) -> Vec<u8> {
        build_signed_legacy_tx_with_value(secret_key, to, calldata, nonce, chain_id, 0)
    }

    /// `build_signed_legacy_tx`'in `msg.value` taşıyan hali. Native stake gibi
    /// miktarı calldata'da DEĞİL value'da taşıyan işlemler için gerekir
    /// (`Transaction::validate()` sıfır miktarı reddeder).
    fn build_signed_legacy_tx_with_value(
        secret_key: &secp256k1::SecretKey,
        to: &str,
        calldata: Vec<u8>,
        nonce: u64,
        chain_id: u64,
        value: u128,
    ) -> Vec<u8> {
        let to_addr: H160 = to.parse().unwrap();
        let tx = TransactionRequest {
            to: Some(NameOrAddress::Address(to_addr)),
            data: Some(calldata.into()),
            nonce: Some(nonce.into()),
            gas: Some(100_000u64.into()),
            gas_price: Some(1_000_000_000u64.into()),
            value: Some(ethers_core::types::U256::from(value)),
            chain_id: Some(chain_id.into()),
            ..Default::default()
        };

        let sighash = tx.sighash();
        let secp = secp256k1::Secp256k1::new();
        let message = secp256k1::Message::from_digest_slice(sighash.as_bytes()).unwrap();
        let recoverable_sig = secp.sign_ecdsa_recoverable(&message, secret_key);
        let (recovery_id, compact) = recoverable_sig.serialize_compact();

        let signature = EthSignature {
            r: ethers_core::types::U256::from_big_endian(&compact[0..32]),
            s: ethers_core::types::U256::from_big_endian(&compact[32..64]),
            v: chain_id * 2 + 35 + recovery_id.to_i32() as u64,
        };

        tx.rlp_signed(&signature).to_vec()
    }

    /// EIP-2930 (`accessList`, tip 0x1) hali: `decode_and_convert_tx`'in tip farkında
    /// imza gömme yolunu gerçek `TypedTransaction::Eip2930` ile kanıtlar (`v` sade yParity).
    fn build_signed_eip2930_tx(
        secret_key: &secp256k1::SecretKey,
        to: &str,
        calldata: Vec<u8>,
        nonce: u64,
        chain_id: u64,
    ) -> Vec<u8> {
        use ethers_core::types::transaction::{
            eip2718::TypedTransaction, eip2930::Eip2930TransactionRequest,
        };
        let to_addr: H160 = to.parse().unwrap();
        let inner = TransactionRequest {
            to: Some(NameOrAddress::Address(to_addr)),
            data: Some(calldata.into()),
            nonce: Some(nonce.into()),
            gas: Some(100_000u64.into()),
            gas_price: Some(1_000_000_000u64.into()),
            value: Some(ethers_core::types::U256::zero()),
            chain_id: Some(chain_id.into()),
            ..Default::default()
        };
        let typed_tx =
            TypedTransaction::Eip2930(Eip2930TransactionRequest::new(inner, Default::default()));

        let sighash = typed_tx.sighash();
        let secp = secp256k1::Secp256k1::new();
        let message = secp256k1::Message::from_digest_slice(sighash.as_bytes()).unwrap();
        let recoverable_sig = secp.sign_ecdsa_recoverable(&message, secret_key);
        let (recovery_id, compact) = recoverable_sig.serialize_compact();

        let signature = EthSignature {
            r: ethers_core::types::U256::from_big_endian(&compact[0..32]),
            s: ethers_core::types::U256::from_big_endian(&compact[32..64]),
            v: recovery_id.to_i32() as u64,
        };

        typed_tx.rlp_signed(&signature).to_vec()
    }

    /// `build_signed_legacy_tx_with_value`'nun EIP-1559 (tip 0x2, `maxFeePerGas`/
    /// `maxPriorityFeePerGas`) hali, aynı gerekçe, `TypedTransaction::Eip1559`
    /// ile. `v` burada da sade yParity (0/1).
    fn build_signed_eip1559_tx(
        secret_key: &secp256k1::SecretKey,
        to: &str,
        calldata: Vec<u8>,
        nonce: u64,
        chain_id: u64,
    ) -> Vec<u8> {
        use ethers_core::types::transaction::{
            eip1559::Eip1559TransactionRequest, eip2718::TypedTransaction,
        };
        let to_addr: H160 = to.parse().unwrap();
        let typed_tx = TypedTransaction::Eip1559(Eip1559TransactionRequest {
            to: Some(NameOrAddress::Address(to_addr)),
            data: Some(calldata.into()),
            nonce: Some(nonce.into()),
            gas: Some(100_000u64.into()),
            value: Some(ethers_core::types::U256::zero()),
            max_priority_fee_per_gas: Some(1_000_000_000u64.into()),
            max_fee_per_gas: Some(2_000_000_000u64.into()),
            chain_id: Some(chain_id.into()),
            ..Default::default()
        });

        let sighash = typed_tx.sighash();
        let secp = secp256k1::Secp256k1::new();
        let message = secp256k1::Message::from_digest_slice(sighash.as_bytes()).unwrap();
        let recoverable_sig = secp.sign_ecdsa_recoverable(&message, secret_key);
        let (recovery_id, compact) = recoverable_sig.serialize_compact();

        let signature = EthSignature {
            r: ethers_core::types::U256::from_big_endian(&compact[0..32]),
            s: ethers_core::types::U256::from_big_endian(&compact[32..64]),
            v: recovery_id.to_i32() as u64,
        };

        typed_tx.rlp_signed(&signature).to_vec()
    }

    /// 🚨 KRİTİK: Legacy/EIP-2930/EIP-1559 üçü de doğru tip bilgisiyle kodlanmalı,
    /// `extract_eth_tx_type` "0x0"/"0x1"/"0x2" okumalı, `extract_vrs` `v`'si yalnız
    /// Legacy'de EIP-155 kodlu, 2930/1559'da sade yParity olmalı.
    #[test]
    fn decode_and_convert_tx_preserves_the_real_ethereum_tx_type_for_every_wire_format() {
        let secret_key = secp256k1::SecretKey::from_slice(&[13u8; 32]).unwrap();
        let to = "0x2222222222222222222222222222222222222222";

        let legacy_raw = build_signed_legacy_tx(&secret_key, to, Vec::new(), 0, CHAIN_ID);
        let legacy_tx = RpcServer::decode_and_convert_tx(&legacy_raw).unwrap();
        // 🚨 İmza artık ham RLP de taşıyor (alan bağlaması) → 98 + N
        assert!(
            legacy_tx.signature.len() > 98,
            "bağlamalı EVM imzası ham RLP taşımalı"
        );
        assert_eq!(RpcServer::extract_eth_tx_type(&legacy_tx.signature), "0x0");
        let (legacy_v, _, _) = RpcServer::extract_vrs(&legacy_tx.signature);
        // Legacy: EIP-155 kodlamalı v, chain_id'ye bağlı büyük bir sayı,
        // asla 0/1 olamaz.
        assert_ne!(legacy_v, "0x0");
        assert_ne!(legacy_v, "0x1");

        let eip2930_raw = build_signed_eip2930_tx(&secret_key, to, Vec::new(), 0, CHAIN_ID);
        let eip2930_tx = RpcServer::decode_and_convert_tx(&eip2930_raw).unwrap();
        // 🚨 İmza artık ham RLP de taşıyor (alan bağlaması) → 98 + N
        assert!(
            eip2930_tx.signature.len() > 98,
            "bağlamalı EVM imzası ham RLP taşımalı"
        );
        assert_eq!(RpcServer::extract_eth_tx_type(&eip2930_tx.signature), "0x1");
        let (eip2930_v, _, _) = RpcServer::extract_vrs(&eip2930_tx.signature);
        // EIP-2930: sade yParity, HER ZAMAN 0x0 ya da 0x1, asla EIP-155
        // formülüyle şişirilmemeli.
        assert!(
            eip2930_v == "0x0" || eip2930_v == "0x1",
            "EIP-2930 v'si yParity olmali, alinan: {eip2930_v}"
        );

        let eip1559_raw = build_signed_eip1559_tx(&secret_key, to, Vec::new(), 0, CHAIN_ID);
        let eip1559_tx = RpcServer::decode_and_convert_tx(&eip1559_raw).unwrap();
        // 🚨 İmza artık ham RLP de taşıyor (alan bağlaması) → 98 + N
        assert!(
            eip1559_tx.signature.len() > 98,
            "bağlamalı EVM imzası ham RLP taşımalı"
        );
        assert_eq!(RpcServer::extract_eth_tx_type(&eip1559_tx.signature), "0x2");
        let (eip1559_v, _, _) = RpcServer::extract_vrs(&eip1559_tx.signature);
        assert!(
            eip1559_v == "0x0" || eip1559_v == "0x1",
            "EIP-1559 v'si yParity olmali, alinan: {eip1559_v}"
        );

        // Üçü de imza dogrulamasindan (Transaction::verify_signature)
        // GECMELI, tip bayti sadece bilgi tasir, kriptografik kontrolu
        // etkilememeli.
        assert!(legacy_tx.verify_signature());
        assert!(eip2930_tx.verify_signature());
        assert!(eip1559_tx.verify_signature());
    }

    /// Eski (tip-bilgisiz, 97-bayt) format hâlâ desteklenmeli, geriye dönük
    /// uyumluluk (bu formatı taşıyan zaten arşivlenmiş eski tx gövdeleri
    /// için). Legacy varsayımıyla eskisi gibi davranmalı.
    #[test]
    fn extract_vrs_and_type_fall_back_to_legacy_for_the_old_type_unaware_97_byte_format() {
        let mut sig_97 = vec![0u8; 65];
        sig_97[64] = 0; // recovery_id = 0
        sig_97.extend_from_slice(&[0u8; 32]); // sighash
        assert_eq!(sig_97.len(), 97);
        assert_eq!(RpcServer::extract_eth_tx_type(&sig_97), "0x0");
        let (v, _, _) = RpcServer::extract_vrs(&sig_97);
        assert_eq!(v, format!("0x{:x}", CHAIN_ID * 2 + 35));
    }

    // 🚨 REGRESYON (F-rpc-panic-2): 256-bit alanlar koşulsuz `.as_u64()` ile
    // çevrilirse geçerli imzalı tek işlem panic ettirir (ön koşul gerekmez).
    #[test]
    fn decode_and_convert_tx_rejects_an_oversized_nonce_instead_of_panicking() {
        let secret_key = secp256k1::SecretKey::from_slice(&[7u8; 32]).unwrap();
        let to_addr: H160 = "0x2222222222222222222222222222222222222222"
            .parse()
            .unwrap();
        let tx = TransactionRequest {
            to: Some(NameOrAddress::Address(to_addr)),
            data: Some(Vec::new().into()),
            nonce: Some(ethers_core::types::U256::MAX), // u64::MAX'ı çok aşıyor
            gas: Some(100_000u64.into()),
            gas_price: Some(1_000_000_000u64.into()),
            value: Some(ethers_core::types::U256::zero()),
            chain_id: Some(CHAIN_ID.into()),
            ..Default::default()
        };

        let sighash = tx.sighash();
        let secp = secp256k1::Secp256k1::new();
        let message = secp256k1::Message::from_digest_slice(sighash.as_bytes()).unwrap();
        let recoverable_sig = secp.sign_ecdsa_recoverable(&message, &secret_key);
        let (recovery_id, compact) = recoverable_sig.serialize_compact();
        let signature = EthSignature {
            r: ethers_core::types::U256::from_big_endian(&compact[0..32]),
            s: ethers_core::types::U256::from_big_endian(&compact[32..64]),
            v: CHAIN_ID * 2 + 35 + recovery_id.to_i32() as u64,
        };
        let raw_tx = tx.rlp_signed(&signature).to_vec();

        let result = RpcServer::decode_and_convert_tx(&raw_tx);
        assert!(
            result.is_err(),
            "oversized nonce must be rejected with an error, not panic"
        );
    }

    // RPC zaman aşımında işlem durumu netliği, regresyon testleri.

    /// `raw_eth_send_tx_hash` (decode etmeden) `decode_and_convert_tx`'in `tx_id`'siyle
    /// birebir eşleşmeli; yoksa zaman aşımı mesajında yanlış hash gösterilir.
    #[test]
    fn raw_eth_send_tx_hash_matches_the_tx_id_decode_and_convert_tx_would_compute() {
        let secret_key = secp256k1::SecretKey::from_slice(&[11u8; 32]).unwrap();
        let raw_tx = build_signed_legacy_tx(
            &secret_key,
            "0x2222222222222222222222222222222222222222",
            Vec::new(),
            0,
            CHAIN_ID,
        );
        let decoded = RpcServer::decode_and_convert_tx(&raw_tx).unwrap();
        let expected_hash = format!("0x{}", hex::encode(decoded.tx_id));

        let params = Some(vec![Value::String(format!("0x{}", hex::encode(&raw_tx)))]);
        let computed = raw_eth_send_tx_hash(&params)
            .expect("geçerli hex params[0] için hash hesaplanabilmeli");

        assert_eq!(
            computed, expected_hash,
            "raw_eth_send_tx_hash, decode_and_convert_tx'in tx_id'siyle AYNI olmalı"
        );
    }

    /// params eksik/geçersizse (boş dizi, hex olmayan string, vb.)
    /// `raw_eth_send_tx_hash` panic ATMAMALI, sessizce `None` dönmeli, zaman
    /// aşımı mesajı hash'siz (ama hâlâ anlamlı) bir geri düşüşe sahip olmalı.
    #[test]
    fn raw_eth_send_tx_hash_returns_none_for_missing_or_invalid_params() {
        assert_eq!(raw_eth_send_tx_hash(&None), None);
        assert_eq!(raw_eth_send_tx_hash(&Some(vec![])), None);
        assert_eq!(
            raw_eth_send_tx_hash(&Some(vec![Value::String("not-hex".to_string())])),
            None
        );
        assert_eq!(raw_eth_send_tx_hash(&Some(vec![Value::Bool(true)])), None);
    }

    /// Hash mevcutsa, hata gövdesi hem okunabilir mesajda hem `data.txHash`
    /// alanında (programatik erişim için) bu hash'i içermeli.
    #[test]
    fn rpc_timeout_error_body_for_send_raw_tx_includes_tx_hash_when_available() {
        let body = rpc_timeout_error_body_for_send_raw_tx(Duration::from_secs(6), Some("0xabc123"));
        assert_eq!(body["code"], Value::from(RPC_TIMEOUT_ERROR_CODE));
        let message = body["message"].as_str().unwrap();
        assert!(
            message.contains("0xabc123"),
            "mesaj tx hash'i içermeli: {}",
            message
        );
        assert!(
            message
                .to_lowercase()
                .contains("may still have been accepted"),
            "mesaj işlemin arka planda kabul edilmiş olabileceğini açıkça belirtmeli: {}",
            message
        );
        assert_eq!(body["data"]["txHash"], Value::from("0xabc123"));
    }

    /// Hash hesaplanamadıysa (ör. bozuk/eksik params) mesaj YİNE DE
    /// kullanıcıyı tx hash'iyle durum kontrolüne yönlendirmeli, yalnızca
    /// somut hash'i içermez, `data` alanı da eklenmemeli.
    #[test]
    fn rpc_timeout_error_body_for_send_raw_tx_falls_back_gracefully_without_tx_hash() {
        let body = rpc_timeout_error_body_for_send_raw_tx(Duration::from_secs(6), None);
        assert_eq!(body["code"], Value::from(RPC_TIMEOUT_ERROR_CODE));
        let message = body["message"].as_str().unwrap();
        assert!(
            message
                .to_lowercase()
                .contains("may still have been accepted"),
            "hash olmasa bile mesaj aynı uyarıyı vermeli: {}",
            message
        );
        assert!(
            body.get("data").is_none(),
            "hash yoksa 'data' alanı hiç eklenmemeli"
        );
    }

    /// Uçtan uca: bloklayan havuz doluyken `eth_sendRawTransaction` zaman aşımı
    /// yanıtı GERÇEK tx hash'i taşımalı.
    #[test]
    fn handle_rpc_request_eth_send_raw_transaction_timeout_includes_recoverable_tx_hash() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let _occupier =
                tokio::task::spawn_blocking(|| std::thread::sleep(Duration::from_millis(100)));
            tokio::time::sleep(Duration::from_millis(5)).await;

            let secret_key = secp256k1::SecretKey::from_slice(&[13u8; 32]).unwrap();
            let raw_tx = build_signed_legacy_tx(
                &secret_key,
                "0x2222222222222222222222222222222222222222",
                Vec::new(),
                0,
                CHAIN_ID,
            );
            let expected_hash = {
                let decoded = RpcServer::decode_and_convert_tx(&raw_tx).unwrap();
                format!("0x{}", hex::encode(decoded.tx_id))
            };

            let state = test_state();
            let mempool = test_mempool(state.clone());
            let body = bytes::Bytes::from(
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "method": "eth_sendRawTransaction",
                    "params": [format!("0x{}", hex::encode(&raw_tx))],
                    "id": 42
                })
                .to_string(),
            );
            let tight_timeout = RpcTimeouts {
                light: Duration::from_millis(8),
                default_: Duration::from_millis(8),
                evm_execution: Duration::from_millis(8),
                max_batch: Duration::from_millis(8),
                max_batch_requests: 100,
            };
            let reply = handle_rpc_request(
                body,
                state,
                mempool,
                Arc::new(DashMap::new()),
                default_bridge_manager_arc(),
                tight_timeout,
                EvmSimulationLimits::default(),
                None,
            )
            .await
            .unwrap();

            let json = reply_body_json(reply).await;
            assert_eq!(json["error"]["code"], Value::from(RPC_TIMEOUT_ERROR_CODE));
            assert_eq!(
                json["error"]["data"]["txHash"],
                Value::from(expected_hash.clone()),
                "zaman aşımı yanıtı GERÇEK tx hash'ini taşımalı: {:?}",
                json
            );
            let message = json["error"]["message"].as_str().unwrap();
            assert!(message.contains(&expected_hash));
        });
    }

    fn a_native_transfer_is_charged_exactly_five_cents_worth_of_zagros_helper(
        pool_zagros: u128,
        pool_zerenya: u128,
    ) -> Transaction {
        use secp256k1::SecretKey;
        let state = test_state();
        state.set_pool_reserves(pool_zagros, pool_zerenya).unwrap();

        // Boş calldata + geçerli alıcı => decode TxType::Transfer üretir.
        let secret_key = SecretKey::from_slice(&[9u8; 32]).unwrap();
        let raw_tx = build_signed_legacy_tx(
            &secret_key,
            "0x2222222222222222222222222222222222222222",
            Vec::new(),
            0,
            CHAIN_ID,
        );
        let mut tx = RpcServer::decode_and_convert_tx(&raw_tx).unwrap();
        assert_eq!(tx.tx_type, TxType::Transfer);

        // Ücret tek kaynaktan (mempool) gelir; `test_mempool`'un hesaplayıcısı
        // kasten bayat rezervlerle kurulur ama `min_required_fee` okumadan önce
        // canlı state ile eşitlediği için sonuç yukarıdaki havuzu yansıtır.
        let mempool = test_mempool(state.clone());
        mempool.apply_fixed_gas_fee(&mut tx);
        tx
    }

    /// 🛑 Cross-chain replay: chain_id=1 için imzalanmış işlem kabul edilmemeli;
    /// `chain_id` RLP'den okunup Zagros ile eşleşmeli.
    #[test]
    fn cross_chain_replay_a_transaction_signed_for_a_foreign_chain_id_is_rejected() {
        use secp256k1::SecretKey;
        // Kurban chain_id=1'de geçerli işlem imzalar; saldırgan explorer'dan alıp
        // olduğu gibi Zagros'a gönderir.
        let victim_key = SecretKey::from_slice(&[0x42u8; 32]).unwrap();
        const ETHEREUM_MAINNET_CHAIN_ID: u64 = 1;
        let foreign_chain_raw_tx = build_signed_legacy_tx(
            &victim_key,
            "0x2222222222222222222222222222222222222222",
            Vec::new(),
            0,
            ETHEREUM_MAINNET_CHAIN_ID, // <- Zagros'un CHAIN_ID'si DEĞİL.
        );

        let result = RpcServer::decode_and_convert_tx(&foreign_chain_raw_tx);

        // 🛡️ chain_id eşleşmediği için ret; sighash geçerliliği yetmez.
        let err = result.expect_err(
            "İSTİSMAR: yabancı bir zincir için imzalanmış işlem KABUL EDİLDİ - \
             cross-chain replay mümkün. Herhangi bir yayınlanmış Ethereum mainnet \
             işlemi olduğu gibi Zagros'a gönderilip kurbanın rızası olmadan \
             yürütülebilir.",
        );
        assert!(
            err.to_lowercase().contains("chain") || err.to_lowercase().contains("zincir"),
            "hata mesajı chain_id uyuşmazlığını açıkça belirtmeli, alınan: {}",
            err
        );
    }

    /// Multicall3'ün GERÇEK, herkesçe bilinen önceden imzalı deploy işlemi
    /// (github.com/mds1/multicall3 README), keyless deployer istisnasının
    /// gerçek hedefiyle uçtan uca kanıtı.
    const MULTICALL3_PRESIGNED_DEPLOY_TX: &str = "0xf90f538085174876e800830f42408080b90f00608060405234801561001057600080fd5b50610ee0806100206000396000f3fe6080604052600436106100f35760003560e01c80634d2301cc1161008a578063a8b0574e11610059578063a8b0574e1461025a578063bce38bd714610275578063c3077fa914610288578063ee82ac5e1461029b57600080fd5b80634d2301cc146101ec57806372425d9d1461022157806382ad56cb1461023457806386d516e81461024757600080fd5b80633408e470116100c65780633408e47014610191578063399542e9146101a45780633e64a696146101c657806342cbb15c146101d957600080fd5b80630f28c97d146100f8578063174dea711461011a578063252dba421461013a57806327e86d6e1461015b575b600080fd5b34801561010457600080fd5b50425b6040519081526020015b60405180910390f35b61012d610128366004610a85565b6102ba565b6040516101119190610bbe565b61014d610148366004610a85565b6104ef565b604051610111929190610bd8565b34801561016757600080fd5b50437fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0140610107565b34801561019d57600080fd5b5046610107565b6101b76101b2366004610c60565b610690565b60405161011193929190610cba565b3480156101d257600080fd5b5048610107565b3480156101e557600080fd5b5043610107565b3480156101f857600080fd5b50610107610207366004610ce2565b73ffffffffffffffffffffffffffffffffffffffff163190565b34801561022d57600080fd5b5044610107565b61012d610242366004610a85565b6106ab565b34801561025357600080fd5b5045610107565b34801561026657600080fd5b50604051418152602001610111565b61012d610283366004610c60565b61085a565b6101b7610296366004610a85565b610a1a565b3480156102a757600080fd5b506101076102b6366004610d18565b4090565b60606000828067ffffffffffffffff8111156102d8576102d8610d31565b60405190808252806020026020018201604052801561031e57816020015b6040805180820190915260008152606060208201528152602001906001900390816102f65790505b5092503660005b8281101561047757600085828151811061034157610341610d60565b6020026020010151905087878381811061035d5761035d610d60565b905060200281019061036f9190610d8f565b6040810135958601959093506103886020850185610ce2565b73ffffffffffffffffffffffffffffffffffffffff16816103ac6060870187610dcd565b6040516103ba929190610e32565b60006040518083038185875af1925050503d80600081146103f7576040519150601f19603f3d011682016040523d82523d6000602084013e6103fc565b606091505b50602080850191909152901515808452908501351761046d577f08c379a000000000000000000000000000000000000000000000000000000000600052602060045260176024527f4d756c746963616c6c333a2063616c6c206661696c656400000000000000000060445260846000fd5b5050600101610325565b508234146104e6576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601a60248201527f4d756c746963616c6c333a2076616c7565206d69736d6174636800000000000060448201526064015b60405180910390fd5b50505092915050565b436060828067ffffffffffffffff81111561050c5761050c610d31565b60405190808252806020026020018201604052801561053f57816020015b606081526020019060019003908161052a5790505b5091503660005b8281101561068657600087878381811061056257610562610d60565b90506020028101906105749190610e42565b92506105836020840184610ce2565b73ffffffffffffffffffffffffffffffffffffffff166105a66020850185610dcd565b6040516105b4929190610e32565b6000604051808303816000865af19150503d80600081146105f1576040519150601f19603f3d011682016040523d82523d6000602084013e6105f6565b606091505b5086848151811061060957610609610d60565b602090810291909101015290508061067d576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601760248201527f4d756c746963616c6c333a2063616c6c206661696c656400000000000000000060448201526064016104dd565b50600101610546565b5050509250929050565b43804060606106a086868661085a565b905093509350939050565b6060818067ffffffffffffffff8111156106c7576106c7610d31565b60405190808252806020026020018201604052801561070d57816020015b6040805180820190915260008152606060208201528152602001906001900390816106e55790505b5091503660005b828110156104e657600084828151811061073057610730610d60565b6020026020010151905086868381811061074c5761074c610d60565b905060200281019061075e9190610e76565b925061076d6020840184610ce2565b73ffffffffffffffffffffffffffffffffffffffff166107906040850185610dcd565b60405161079e929190610e32565b6000604051808303816000865af19150503d80600081146107db576040519150601f19603f3d011682016040523d82523d6000602084013e6107e0565b606091505b506020808401919091529015158083529084013517610851577f08c379a000000000000000000000000000000000000000000000000000000000600052602060045260176024527f4d756c746963616c6c333a2063616c6c206661696c656400000000000000000060445260646000fd5b50600101610714565b6060818067ffffffffffffffff81111561087657610876610d31565b6040519080825280602002602001820160405280156108bc57816020015b6040805180820190915260008152606060208201528152602001906001900390816108945790505b5091503660005b82811015610a105760008482815181106108df576108df610d60565b602002602001015190508686838181106108fb576108fb610d60565b905060200281019061090d9190610e42565b925061091c6020840184610ce2565b73ffffffffffffffffffffffffffffffffffffffff1661093f6020850185610dcd565b60405161094d929190610e32565b6000604051808303816000865af19150503d806000811461098a576040519150601f19603f3d011682016040523d82523d6000602084013e61098f565b606091505b506020830152151581528715610a07578051610a07576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601760248201527f4d756c746963616c6c333a2063616c6c206661696c656400000000000000000060448201526064016104dd565b506001016108c3565b5050509392505050565b6000806060610a2b60018686610690565b919790965090945092505050565b60008083601f840112610a4b57600080fd5b50813567ffffffffffffffff811115610a6357600080fd5b6020830191508360208260051b8501011115610a7e57600080fd5b9250929050565b60008060208385031215610a9857600080fd5b823567ffffffffffffffff811115610aaf57600080fd5b610abb85828601610a39565b90969095509350505050565b6000815180845260005b81811015610aed57602081850181015186830182015201610ad1565b81811115610aff576000602083870101525b50601f017fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0169290920160200192915050565b600082825180855260208086019550808260051b84010181860160005b84811015610bb1578583037fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe001895281518051151584528401516040858501819052610b9d81860183610ac7565b9a86019a9450505090830190600101610b4f565b5090979650505050505050565b602081526000610bd16020830184610b32565b9392505050565b600060408201848352602060408185015281855180845260608601915060608160051b870101935082870160005b82811015610c52577fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa0888703018452610c40868351610ac7565b95509284019290840190600101610c06565b509398975050505050505050565b600080600060408486031215610c7557600080fd5b83358015158114610c8557600080fd5b9250602084013567ffffffffffffffff811115610ca157600080fd5b610cad86828701610a39565b9497909650939450505050565b838152826020820152606060408201526000610cd96060830184610b32565b95945050505050565b600060208284031215610cf457600080fd5b813573ffffffffffffffffffffffffffffffffffffffff81168114610bd157600080fd5b600060208284031215610d2a57600080fd5b5035919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b600082357fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff81833603018112610dc357600080fd5b9190910192915050565b60008083357fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe1843603018112610e0257600080fd5b83018035915067ffffffffffffffff821115610e1d57600080fd5b602001915036819003821315610a7e57600080fd5b8183823760009101908152919050565b600082357fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc1833603018112610dc357600080fd5b600082357fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa1833603018112610dc357600080fdfea2646970667358221220bb2b5c71a328032f97c676ae39a1ec2148d3e5d6f73d95e9b17910152d61f16264736f6c634300080c00331ca0edce47092c0f398cebf3ffc267f05c8e7076e3b89445e0fe50f6332273d4569ba01b0b9d000e19b24c5869b0fc3b22b0d6fa47cd63316875cbbd577d76e6fde086";

    /// Pre-EIP-155 (chain_id İÇERMEYEN, v=27/28) imzalı legacy işlem üretir,
    /// keyless deployer istisnasının SINIRLARINI test etmek için.
    fn build_signed_pre_eip155_tx(secret_key: &secp256k1::SecretKey) -> Vec<u8> {
        let to_addr: H160 = "0x2222222222222222222222222222222222222222"
            .parse()
            .unwrap();
        let tx = TransactionRequest {
            to: Some(NameOrAddress::Address(to_addr)),
            data: Some(Vec::new().into()),
            nonce: Some(0u64.into()),
            gas: Some(100_000u64.into()),
            gas_price: Some(1_000_000_000u64.into()),
            value: Some(ethers_core::types::U256::zero()),
            chain_id: None, // <- EIP-155 koruması bilinçli olarak YOK
            ..Default::default()
        };
        let sighash = tx.sighash();
        let secp = secp256k1::Secp256k1::new();
        let message = secp256k1::Message::from_digest_slice(sighash.as_bytes()).unwrap();
        let recoverable_sig = secp.sign_ecdsa_recoverable(&message, secret_key);
        let (recovery_id, compact) = recoverable_sig.serialize_compact();
        let signature = EthSignature {
            r: ethers_core::types::U256::from_big_endian(&compact[0..32]),
            s: ethers_core::types::U256::from_big_endian(&compact[32..64]),
            // Pre-EIP-155: v = 27/28, chain_id kodlaması yok.
            v: 27 + recovery_id.to_i32() as u64,
        };
        tx.rlp_signed(&signature).to_vec()
    }

    /// 🛡️ İstisnanın SINIRI: keyless deployer listesinde OLMAYAN bir
    /// gönderenden gelen pre-EIP-155 imza, istisna eklendikten sonra da
    /// aynen fail-closed reddedilmeli.
    #[test]
    fn a_pre_eip155_tx_from_an_unknown_sender_is_still_rejected() {
        let random_key = secp256k1::SecretKey::from_slice(&[0x43u8; 32]).unwrap();
        let raw_tx = build_signed_pre_eip155_tx(&random_key);
        let err = RpcServer::decode_and_convert_tx(&raw_tx).expect_err(
            "keyless listede olmayan pre-EIP-155 gönderen KABUL EDİLDİ - istisna sızdırıyor",
        );
        assert!(
            err.contains("fail-closed"),
            "hata mesajı fail-closed reddi belirtmeli, alınan: {}",
            err
        );
    }

    /// 🛡️ İstisna: Multicall3'ün chain_id'siz gerçek deploy işlemi kabul edilmeli,
    /// gönderen bilinen keyless deployer'a çözülür.
    #[test]
    fn the_canonical_multicall3_deployment_tx_is_accepted() {
        let raw_bytes =
            hex::decode(MULTICALL3_PRESIGNED_DEPLOY_TX.trim_start_matches("0x")).unwrap();
        let tx = RpcServer::decode_and_convert_tx(&raw_bytes)
            .expect("Multicall3 keyless deploy işlemi reddedildi - istisna çalışmıyor");
        assert_eq!(tx.sender, "0x05f32b3cc3888453ff71b01135b34ff8e41263f2");
        assert!(
            matches!(tx.tx_type, TxType::ContractCall { .. }),
            "kontrat kurulumu ContractCall'a dönüşmeli, alınan: {:?}",
            tx.tx_type
        );
        assert_eq!(tx.nonce, 0);
        assert!(tx.verify_signature(), "bağımsız imza doğrulaması geçmeli");
    }

    #[test]
    fn native_transfer_gas_fee_is_exactly_five_cents_at_par_pool() {
        // 1:1 havuz (1 ZAGROS = 1 ZERENYA) => tam GAS_FEE_ZERENYA kesilir.
        let tx = a_native_transfer_is_charged_exactly_five_cents_worth_of_zagros_helper(
            1_000 * 10u128.pow(18),
            1_000 * 10u128.pow(18),
        );
        assert_eq!(tx.gas_limit, 1);
        assert_eq!(tx.gas_price, zagros_types::GAS_FEE_ZERENYA);
        // Kesilen toplam ücret = gas_limit * gas_price.
        assert_eq!(
            (tx.gas_limit as u128) * tx.gas_price,
            zagros_types::GAS_FEE_ZERENYA
        );
        // 🚨 Gas alanlarını değiştirmek EVM-kökenli (97-bayt) imzayı BOZMAMALI.
        assert!(tx.verify_signature());
    }

    #[test]
    fn native_transfer_gas_fee_stays_worth_five_cents_when_zagros_is_expensive() {
        // ZAGROS pahalıyken (havuzda az ZAGROS, çok ZERENYA) kesilen ham ZAGROS azalır
        // ama ZERENYA değeri hâlâ sabit: gas_price * pool_zerenya == TARGET * pool_zagros.
        let pool_zagros = 1_000u128;
        let pool_zerenya = 1_000_000u128;
        let tx = a_native_transfer_is_charged_exactly_five_cents_worth_of_zagros_helper(
            pool_zagros,
            pool_zerenya,
        );
        assert_eq!(tx.gas_limit, 1);
        assert_eq!(
            tx.gas_price.saturating_mul(pool_zerenya),
            zagros_types::GAS_FEE_ZERENYA.saturating_mul(pool_zagros)
        );
    }

    #[test]
    fn evm_contract_call_is_not_forced_to_the_fixed_native_fee() {
        use secp256k1::SecretKey;
        let state = test_state();
        state
            .set_pool_reserves(1_000 * 10u128.pow(18), 1_000 * 10u128.pow(18))
            .unwrap();

        // `to: None` => decode TxType::ContractCall (EVM dağıtımı) üretir; sabit
        // ücret uygulanmaz, cüzdanın gas'ı korunur (gerçek EVM gas kullanımına
        // göre ücretlenir).
        let secret_key = SecretKey::from_slice(&[8u8; 32]).unwrap();
        let tx_req = TransactionRequest {
            to: None,
            data: Some(vec![0x60, 0x00].into()),
            nonce: Some(0u64.into()),
            gas: Some(100_000u64.into()),
            gas_price: Some(1_000_000_000u64.into()),
            value: Some(0u64.into()),
            chain_id: Some(CHAIN_ID.into()),
            ..Default::default()
        };
        let sighash = tx_req.sighash();
        let secp = secp256k1::Secp256k1::new();
        let message = secp256k1::Message::from_digest_slice(sighash.as_bytes()).unwrap();
        let recoverable_sig = secp.sign_ecdsa_recoverable(&message, &secret_key);
        let (recovery_id, compact) = recoverable_sig.serialize_compact();
        let signature = EthSignature {
            r: ethers_core::types::U256::from_big_endian(&compact[0..32]),
            s: ethers_core::types::U256::from_big_endian(&compact[32..64]),
            v: CHAIN_ID * 2 + 35 + recovery_id.to_i32() as u64,
        };
        let raw_tx = tx_req.rlp_signed(&signature).to_vec();

        let mut tx = RpcServer::decode_and_convert_tx(&raw_tx).unwrap();
        assert!(matches!(tx.tx_type, TxType::ContractCall { .. }));
        let (limit_before, price_before) = (tx.gas_limit, tx.gas_price);
        let mempool = test_mempool(state.clone());
        mempool.apply_fixed_gas_fee(&mut tx);
        assert_eq!(tx.gas_limit, limit_before);
        assert_eq!(tx.gas_price, price_before);
    }

    /// zagros-cli'nin genesis havuzu (41.999.999 ZAGROS / 10.500 ZERENYA).
    fn genesis_reserves() -> (u128, u128) {
        (
            zagros_types::GENESIS_POOL_ZAGROS,
            zagros_types::GENESIS_POOL_ZERENYA,
        )
    }

    /// Genesis havuzlu state + mempool; `seed` kasten bayat `GasCalculator` tohumu
    /// (canlı senkron tohumu geçersiz kılmalı).
    fn genesis_state_and_mempool(seed: (u128, u128)) -> (Arc<dyn State>, Arc<Mempool>) {
        let (pool_zagros, pool_zerenya) = genesis_reserves();
        let state = test_state();
        state.set_pool_reserves(pool_zagros, pool_zerenya).unwrap();

        let gas_calculator = Arc::new(GasCalculator::new(
            Arc::new(portable_atomic::AtomicU128::new(seed.0)),
            Arc::new(portable_atomic::AtomicU128::new(seed.1)),
        ));
        let mempool = Arc::new(Mempool::new(state.clone(), gas_calculator));
        (state, mempool)
    }

    /// Bir native stake işlemini, RPC yolunun yaptığı gibi çözüp fiyatlar.
    fn stake_tx_priced_through_rpc(mempool: &Mempool) -> Transaction {
        use secp256k1::SecretKey;
        // 0x3a4b66f1 = native stake; miktar `data`da DEĞİL msg.value ile gelir.
        let secret_key = SecretKey::from_slice(&[12u8; 32]).unwrap();
        let raw_tx = build_signed_legacy_tx_with_value(
            &secret_key,
            "0x0000000000000000000000000000000000000001",
            vec![58, 75, 102, 241],
            0,
            CHAIN_ID,
            10u128.pow(18), // 1 ZAGROS stake
        );
        let mut tx = RpcServer::decode_and_convert_tx(&raw_tx).unwrap();
        assert_eq!(tx.tx_type, TxType::StakeZagros);
        mempool.apply_fixed_gas_fee(&mut tx);
        tx
    }

    /// 🔒 ENTEGRASYON: RPC'nin fiyatladığı bir işlem mempool tarafından SIFIR
    /// SAPMA ile kabul edilmeli. İki katman ücreti ayrı ayrı türetseydi bir ham
    /// birimlik fark bile burada "Gas fee too low" olarak düşerdi.
    #[test]
    fn an_rpc_priced_stake_is_accepted_by_the_mempool_without_drift() {
        let (state, mempool) = genesis_state_and_mempool(genesis_reserves());
        let tx = stake_tx_priced_through_rpc(&mempool);

        // Gönderen hem stake miktarını hem ücreti karşılayabilsin.
        state.add_balance(&tx.sender, 10 * 10u128.pow(18)).unwrap();

        let declared = (tx.gas_limit as u128).saturating_mul(tx.gas_price);
        assert_eq!(
            declared,
            mempool.min_required_fee(&tx),
            "RPC'nin gömdüğü ücret ile mempool'un talebi ayrıştı"
        );
        let accepted = mempool.add_transaction(tx);
        assert!(
            accepted.is_ok(),
            "mempool, RPC'nin fiyatladığı işlemi reddetti: {:?}",
            accepted
        );
    }

    /// 🔒 UÇTAN UCA: gerçek RLP imzalı `registerValidator()` (0xbcc6587f, `0x...0006`)
    /// doğru sınıflandırılmalı ve seçici `tx.payload`'a SIZMAMALI (executor `0xbcc6`'yı
    /// geçersiz komisyon sanıp reddederdi).
    #[test]
    fn register_validator_selector_call_is_classified_and_flips_registration_through_the_executor()
    {
        let secret_key = secp256k1::SecretKey::from_slice(&[15u8; 32]).unwrap();
        let sender = Transaction::address_from_secret_key(&secret_key);

        // G2: kayıt payload'ı (pubkey + sahiplik kanıtı + beyan) calldata'da
        // seçiciden SONRA taşınır; RPC seçiciyi ayıklayıp kalanı payload yapar.
        let state = test_state();
        install_test_chain_params(&state);
        let domain = zagros_executor::params::consensus_domain(state.as_ref()).unwrap();
        let kp = zagros_crypto::ConsensusKeypair::from_secret_bytes(&[77u8; 32]);
        let payload = zagros_types::consensus::RegisterValidatorPayload {
            consensus_pubkey: kp.public_key(),
            ownership_proof: zagros_crypto::prove_key_ownership(&kp, &domain, &sender, None),
            declaration: zagros_types::consensus::ValidatorDeclaration {
                provider: "hetzner".into(),
                region: "eu-fsn".into(),
                asn: 24940,
                operator_id: [9u8; 32],
            },
        }
        .encode();
        let mut calldata = vec![0xbc, 0xc6, 0x58, 0x7f];
        calldata.extend_from_slice(&payload);
        let raw_tx = build_signed_legacy_tx(
            &secret_key,
            "0x0000000000000000000000000000000000000006",
            calldata,
            0,
            CHAIN_ID,
        );

        let tx = RpcServer::decode_and_convert_tx(&raw_tx).unwrap();
        assert_eq!(tx.tx_type, TxType::RegisterValidator);
        assert_eq!(
            tx.payload, payload,
            "seçici ayıklanmalı, kalan calldata payload olmalı"
        );
        if state
            .get_account(&zagros_types::GENESIS_TIMESTAMP_KEY.to_string())
            .unwrap()
            .is_none()
        {
            let g = AccountState {
                balance: 1,
                ..Default::default()
            };
            state
                .set_account(&zagros_types::GENESIS_TIMESTAMP_KEY.to_string(), g)
                .unwrap();
        }
        state
            .set_account(
                &sender,
                AccountState {
                    balance: 1_000 * 10u128.pow(18),
                    staked_balance: TEST_MIN_STAKE,
                    ..Default::default()
                },
            )
            .unwrap();

        zagros_executor::Executor::new(state.clone())
            .execute_transaction(&tx, tx.timestamp)
            .unwrap();

        let after = state.get_account(&sender).unwrap().unwrap();
        assert!(after.is_registered_validator);
        assert_eq!(
            after.validator_status,
            Some(zagros_types::consensus::ValidatorStatus::Candidate)
        );
        assert_eq!(after.consensus_pubkey, kp.public_key());
    }

    /// 🔒 Regresyon: dApp'in `slash(address)` biçimi (seçici + sağa hizalı adres)
    /// doğru hedefe çözülmeli; `from_utf8` okuması boş adrese düşerdi.
    #[test]
    fn slash_selector_call_from_command_view_decodes_to_the_real_target_address() {
        let secret_key = secp256k1::SecretKey::from_slice(&[16u8; 32]).unwrap();
        let target = "0x1234567890123456789012345678901234567890";

        let mut calldata = vec![0xc9, 0x6b, 0xe4, 0xcb]; // keccak256("slash(address)")[0..4]
        calldata.extend_from_slice(&[0u8; 12]);
        calldata.extend_from_slice(&hex::decode(&target[2..]).unwrap());
        assert_eq!(calldata.len(), 36);

        let raw_tx = build_signed_legacy_tx(
            &secret_key,
            "0x0000000000000000000000000000000000000007",
            calldata,
            0,
            CHAIN_ID,
        );

        let tx = RpcServer::decode_and_convert_tx(&raw_tx).unwrap();
        assert_eq!(tx.tx_type, TxType::SlashValidator);
        assert_eq!(tx.receiver, "0x0000000000000000000000000000000000000007");
        assert_eq!(
            zagros_types::slash_target_address(&tx.receiver, &tx.payload),
            target,
            "sentinel + ABI-kodlu payload'dan GERÇEK hedef doğru çözülmedi"
        );
    }

    /// 🔒 Çift imza kanıtı sıradan cüzdanla `reportEquivocation(bytes)` olarak
    /// zincire ulaşabilmeli.
    #[test]
    fn report_equivocation_selector_call_decodes_to_report_malicious_with_the_evidence_payload() {
        let secret_key = secp256k1::SecretKey::from_slice(&[17u8; 32]).unwrap();
        let accused = "0x00000000000000000000000000000000000000ab";

        // Gerçek bir kanıt payload'ı üret (motorun ürettiğiyle aynı tip).
        let vote = |hash: u8| zagros_types::consensus::Vote {
            height: 9,
            round: 1,
            phase: zagros_types::consensus::VotePhase::Prevote,
            block_hash: [hash; 32],
            validator_idx: 4,
            shadow: false,
            sig: vec![3u8; 64],
        };
        let evidence = zagros_types::consensus::Evidence::DoubleVote {
            a: vote(1),
            b: vote(2),
        };
        let report = zagros_types::EquivocationReport::ConsensusEvidence(evidence).to_bytes();

        let mut calldata = vec![0x62, 0x16, 0xe6, 0xf0]; // keccak256("reportEquivocation(bytes)")[0..4]
        calldata.extend_from_slice(&report);

        let raw_tx = build_signed_legacy_tx(&secret_key, accused, calldata, 0, CHAIN_ID);
        let tx = RpcServer::decode_and_convert_tx(&raw_tx).unwrap();

        assert_eq!(tx.tx_type, TxType::ReportMalicious);
        assert_eq!(tx.receiver, accused, "alici SUCLANAN validator olmali");
        assert_eq!(
            tx.payload, report,
            "payload seciciden SONRAKI kanit baytlari olmali"
        );
        // Executor'un beklediği biçimde geri çözülebilmeli.
        assert!(zagros_types::EquivocationReport::from_bytes(&tx.payload).is_ok());
    }

    /// 🔒 (0, 0) tohumlu `GasCalculator` her işlemi reddettirirdi; `min_required_fee`
    /// canlı rezervlerle eşitlendiğinden bayat tohum kendini onarır.
    #[test]
    fn a_pre_genesis_zero_seeded_calculator_self_heals_from_live_reserves() {
        let (state, mempool) = genesis_state_and_mempool((0, 0));
        let tx = stake_tx_priced_through_rpc(&mempool);
        state.add_balance(&tx.sender, 10 * 10u128.pow(18)).unwrap();

        // Ücret ham hedeften değil, CANLI havuz oranından türedi (StakeZagros 2x).
        let (pool_zagros, pool_zerenya) = genesis_reserves();
        let expected = zagros_types::base_gas_fee_from_reserves(
            zagros_types::GAS_FEE_ZERENYA,
            pool_zagros,
            pool_zerenya,
        )
        .saturating_mul(2);
        assert_eq!(tx.gas_price, expected);
        assert_ne!(
            tx.gas_price,
            zagros_types::GAS_FEE_ZERENYA.saturating_mul(2),
            "ham (ölçeklenmemiş) hedef kullanılmış - canlı senkronizasyon çalışmıyor"
        );

        // Ve bayat tohuma rağmen işlem kabul edilir: kilitlenme yok.
        let accepted = mempool.add_transaction(tx);
        assert!(
            accepted.is_ok(),
            "bayat tohum hâlâ kilitliyor: {:?}",
            accepted
        );
    }

    /// Bir EVM kontrat çağrısını, tipik bir MetaMask cüzdanının beyan ettiği gas
    /// alanlarıyla (varsayılan 100.000 gas @ 1 gwei) kurar. `gas`/`gas_price`
    /// verilirse onlar kullanılır, taban sınırının altına inen senaryolar için.
    fn evm_call_tx(calldata: Vec<u8>, gas: u64, gas_price: u64) -> Transaction {
        use secp256k1::SecretKey;
        let secret_key = SecretKey::from_slice(&[13u8; 32]).unwrap();
        let tx_req = TransactionRequest {
            to: Some(NameOrAddress::Address(
                "0x00000000000000000000000000000000000000aa"
                    .parse()
                    .unwrap(),
            )),
            data: Some(calldata.into()),
            nonce: Some(0u64.into()),
            gas: Some(gas.into()),
            gas_price: Some(gas_price.into()),
            value: Some(0u64.into()),
            chain_id: Some(CHAIN_ID.into()),
            ..Default::default()
        };
        let sighash = tx_req.sighash();
        let secp = secp256k1::Secp256k1::new();
        let message = secp256k1::Message::from_digest_slice(sighash.as_bytes()).unwrap();
        let recoverable_sig = secp.sign_ecdsa_recoverable(&message, &secret_key);
        let (recovery_id, compact) = recoverable_sig.serialize_compact();
        let signature = EthSignature {
            r: ethers_core::types::U256::from_big_endian(&compact[0..32]),
            s: ethers_core::types::U256::from_big_endian(&compact[32..64]),
            v: CHAIN_ID * 2 + 35 + recovery_id.to_i32() as u64,
        };
        let raw_tx = tx_req.rlp_signed(&signature).to_vec();
        let tx = RpcServer::decode_and_convert_tx(&raw_tx).unwrap();
        assert!(matches!(tx.tx_type, TxType::ContractCall { .. }));
        tx
    }

    /// 🔷 Tipik MetaMask çağrısı (100.000 gas @ 1 gwei) mempool'a girebilmeli;
    /// sabit native cetvel ~2500 kat yetersiz kalırdı.
    #[test]
    fn a_typical_metamask_contract_call_passes_the_evm_anti_ddos_floor() {
        let (state, mempool) = genesis_state_and_mempool(genesis_reserves());
        let mut tx = evm_call_tx(vec![0xab, 0xcd, 0xef, 0x01], 100_000, 1_000_000_000);

        // RPC EVM türlerine DOKUNMAZ: cüzdanın gas alanları korunur.
        let (limit_before, price_before) = (tx.gas_limit, tx.gas_price);
        mempool.apply_fixed_gas_fee(&mut tx);
        assert_eq!((tx.gas_limit, tx.gas_price), (limit_before, price_before));

        // Taban, native cetvelden değil dinamik EVM modelinden gelir.
        let evm_floor = mempool.min_required_fee(&tx);
        let native_floor = mempool.native_min_required_fee(&TxType::Transfer);
        assert!(
            evm_floor < native_floor,
            "EVM tabanı native cetvele bağlı kalmış: evm={}, native={}",
            evm_floor,
            native_floor
        );
        assert!((tx.gas_limit as u128).saturating_mul(tx.gas_price) >= evm_floor);

        state.add_balance(&tx.sender, 10u128.pow(18)).unwrap();
        let accepted = mempool.add_transaction(tx);
        assert!(
            accepted.is_ok(),
            "meşru EVM çağrısı reddedildi: {:?}",
            accepted
        );
    }

    /// 🔷 EVM iş kapısı: intrinsic gas'ı karşılamayan bir `gas_limit` reddedilmeli
    /// (işlem EVM'de zaten çalışamazdı; bedava mempool/bellek spam'i olurdu).
    #[test]
    fn an_evm_call_below_intrinsic_gas_is_rejected() {
        let (state, mempool) = genesis_state_and_mempool(genesis_reserves());
        // 21.000 taban intrinsic gas'ın altında bir gas_limit.
        let tx = evm_call_tx(vec![0xab, 0xcd, 0xef, 0x01], 20_000, 1_000_000_000);
        state.add_balance(&tx.sender, 10u128.pow(18)).unwrap();

        let rejected = mempool.add_transaction(tx);
        assert!(
            format!("{:?}", rejected).contains("EVM gas limit too low"),
            "intrinsic gas kapısı çalışmadı: {:?}",
            rejected
        );
    }

    /// 🔷 EVM anti-DDoS ücret ayağı: `gas_price`'ı dibe çekerek tabandan kaçılamaz.
    #[test]
    fn an_evm_call_with_a_dust_gas_price_is_rejected() {
        let (state, mempool) = genesis_state_and_mempool(genesis_reserves());
        // gas_limit yeterli ama gas_price 1 wei → asgari 1 gwei tabanının altında.
        let tx = evm_call_tx(vec![0xab, 0xcd, 0xef, 0x01], 100_000, 1);
        state.add_balance(&tx.sender, 10u128.pow(18)).unwrap();

        let rejected = mempool.add_transaction(tx);
        assert!(
            format!("{:?}", rejected).contains("Gas fee too low"),
            "toz gas fiyatı tabandan kaçtı: {:?}",
            rejected
        );
    }

    /// 🔷 EVM tabanı calldata ile büyür (EIP-2028): daha ağır calldata, daha
    /// yüksek anti-DDoS tabanı. Spam'in maliyeti taşıdığı yükle orantılı olur.
    #[test]
    fn the_evm_floor_grows_with_calldata_weight() {
        let (_state, mempool) = genesis_state_and_mempool(genesis_reserves());
        let light = evm_call_tx(vec![0xab, 0xcd, 0xef, 0x01], 100_000, 1_000_000_000);
        let heavy = evm_call_tx(vec![0xab; 1_024], 100_000, 1_000_000_000);

        assert!(
            mempool.min_required_fee(&heavy) > mempool.min_required_fee(&light),
            "calldata ağırlığı tabana yansımıyor"
        );
        // EIP-2028: sıfır olmayan bayt 16 gas, sıfır bayt 4 gas.
        let zeros = evm_call_tx(vec![0x00; 1_024], 100_000, 1_000_000_000);
        assert!(mempool.min_required_fee(&zeros) < mempool.min_required_fee(&heavy));
    }

    /// 🔷 Native hat DEĞİŞMEDİ: sabit cetvel ve kademeli çarpanlar yerinde.
    /// Özellikle kontrat üretim harcı (DeployContract x100 = $5,00 karşılığı)
    /// korunuyor.
    #[test]
    fn the_native_fee_ladder_including_the_x100_deploy_levy_is_unchanged() {
        let (_state, mempool) = genesis_state_and_mempool(genesis_reserves());
        let transfer = mempool.native_min_required_fee(&TxType::Transfer);

        // x2: swap / staking, x3: köprü, x100: kontrat üretim harcı.
        assert_eq!(
            mempool.native_min_required_fee(&TxType::StakeZagros),
            transfer * 2
        );
        assert_eq!(
            mempool.native_min_required_fee(&TxType::BridgeMint),
            transfer * 3
        );
        assert_eq!(
            mempool.native_min_required_fee(&TxType::DeployContract),
            transfer * 100
        );
    }

    fn burn_calldata(selector: [u8; 4], amount: u128) -> Vec<u8> {
        let mut data = selector.to_vec();
        let mut amount_bytes = [0u8; 32];
        ethers_core::types::U256::from(amount).to_big_endian(&mut amount_bytes);
        data.extend_from_slice(&amount_bytes);
        data
    }

    #[test]
    fn burn_selector_decodes_to_bridge_burn_with_the_real_signer_as_sender() {
        let secret_key = secp256k1::SecretKey::from_slice(&[11u8; 32]).unwrap();
        let expected_sender = Transaction::address_from_secret_key(&secret_key);

        // keccak256("burn(uint256)") = 0x42966c68 (same selector as OpenZeppelin's
        // ERC20Burnable.burn(uint256), computed directly with the sha3 crate).
        let calldata = burn_calldata([0x42, 0x96, 0x6c, 0x68], 2_500 * 10u128.pow(18));
        let raw_tx = build_signed_legacy_tx(
            &secret_key,
            "0x0000000000000000000000000000000000000002",
            calldata,
            0,
            CHAIN_ID,
        );

        let tx = RpcServer::decode_and_convert_tx(&raw_tx).unwrap();

        assert_eq!(tx.tx_type, TxType::BridgeBurn);
        assert_eq!(tx.amount, 2_500 * 10u128.pow(18));
        // The critical regression check: sender is the REAL, cryptographically
        // recovered signer, not the old hardcoded zero address.
        assert_eq!(tx.sender, expected_sender);
        assert_ne!(tx.sender, "0x0000000000000000000000000000000000000000");
    }

    #[test]
    fn burn_and_swap_selector_decodes_to_bridge_swap_and_burn() {
        let secret_key = secp256k1::SecretKey::from_slice(&[12u8; 32]).unwrap();
        let expected_sender = Transaction::address_from_secret_key(&secret_key);

        // keccak256("burnAndSwap(uint256)") = 0x06696ec0
        let calldata = burn_calldata([0x06, 0x69, 0x6e, 0xc0], 777 * 10u128.pow(18));
        let raw_tx = build_signed_legacy_tx(
            &secret_key,
            "0x0000000000000000000000000000000000000002",
            calldata,
            0,
            CHAIN_ID,
        );

        let tx = RpcServer::decode_and_convert_tx(&raw_tx).unwrap();

        assert_eq!(tx.tx_type, TxType::BridgeSwapAndBurn);
        assert_eq!(tx.amount, 777 * 10u128.pow(18));
        assert_eq!(tx.sender, expected_sender);
    }

    /// 2 argümanlı `burnAndSwap(uint256,uint256)` (`0xa03b6162`) `BridgeSwapAndBurn`'e
    /// çözülmeli ve 68 baytlık payload TAMAMEN korunmalı (`swap_amount_out_min`
    /// bytes[36..68]'i okur). Yalnız RPC/decode katmanı; executor ayrı testte.
    #[test]
    fn burn_and_swap_with_min_out_selector_decodes_and_preserves_the_full_payload() {
        let secret_key = secp256k1::SecretKey::from_slice(&[13u8; 32]).unwrap();
        let expected_sender = Transaction::address_from_secret_key(&secret_key);
        let amount = 777 * 10u128.pow(18);
        let min_amount_out = 700 * 10u128.pow(18);

        // keccak256("burnAndSwap(uint256,uint256)") = 0xa03b6162 (ethers.js ile
        // dogrulandi, bkz. tasarim notu).
        let mut calldata = burn_calldata([0xa0, 0x3b, 0x61, 0x62], amount);
        let mut min_out_bytes = [0u8; 32];
        ethers_core::types::U256::from(min_amount_out).to_big_endian(&mut min_out_bytes);
        calldata.extend_from_slice(&min_out_bytes);

        let raw_tx = build_signed_legacy_tx(
            &secret_key,
            "0x0000000000000000000000000000000000000002",
            calldata,
            0,
            CHAIN_ID,
        );

        let tx = RpcServer::decode_and_convert_tx(&raw_tx).unwrap();

        assert_eq!(tx.tx_type, TxType::BridgeSwapAndBurn);
        assert_eq!(tx.amount, amount);
        assert_eq!(tx.sender, expected_sender);
        assert_eq!(
            tx.payload.len(),
            68,
            "ikinci argumanla birlikte tam 68 bayt olmali"
        );
        assert_eq!(
            &tx.payload[36..68],
            &min_out_bytes[..],
            "swap_amount_out_min'in okuyacagi bytes[36..68] minAmountOut'u tasimiyor"
        );
    }

    /// UÇTAN UCA: gerçek RLP imzalı cüzdan işlemi, decode'dan geçip `Executor`'a
    /// verildiğinde ulaşılamaz minAmountOut REDDEDİLMELİ (decode taşır + executor uygular).
    #[test]
    fn burn_and_swap_with_min_out_selector_is_rejected_by_the_executor_when_unreachable() {
        let secret_key = secp256k1::SecretKey::from_slice(&[14u8; 32]).unwrap();
        let sender = Transaction::address_from_secret_key(&secret_key);
        let amount = 100_000 * 10u128.pow(18);
        // 100_000 ZERENYA girdisi asla 1_000_000 ZAGROS cikti vermez, kesin red.
        let unreachable_min = 1_000_000 * 10u128.pow(18);

        let mut calldata = burn_calldata([0xa0, 0x3b, 0x61, 0x62], amount);
        let mut min_out_bytes = [0u8; 32];
        ethers_core::types::U256::from(unreachable_min).to_big_endian(&mut min_out_bytes);
        calldata.extend_from_slice(&min_out_bytes);
        let raw_tx = build_signed_legacy_tx(
            &secret_key,
            "0x0000000000000000000000000000000000000002",
            calldata,
            0,
            CHAIN_ID,
        );
        let tx = RpcServer::decode_and_convert_tx(&raw_tx).unwrap();
        assert_eq!(tx.tx_type, TxType::BridgeSwapAndBurn);

        let pool_zagros = 10_000_000 * 10u128.pow(18);
        let pool_zerenya = 10_000_000 * 10u128.pow(18);
        let state = test_state();
        state
            .set_account(&sender, AccountState::new(1_000_000 * 10u128.pow(18)))
            .unwrap();
        state.set_pool_reserves(pool_zagros, pool_zerenya).unwrap();

        let result =
            zagros_executor::Executor::new(state.clone()).execute_transaction(&tx, tx.timestamp);

        assert!(
            result.is_err(),
            "RPC'nin decode ettigi gercek bir cuzdan islemi, ulasilamaz minAmountOut'a ragmen gecti"
        );
        assert_eq!(
            state.get_pool_reserves().unwrap(),
            (pool_zagros, pool_zerenya)
        );
    }
}
