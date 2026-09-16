use tracing_subscriber::{fmt, EnvFilter};

// GÖZLEMLENEBİLİRLİK (OBSERVABILITY) MOTORU
/// Tüm ağın loglama ve metrik altyapısını başlatır.
/// Kör uçuşu engeller, şantiyede her şeyi görünür kılar.
pub fn init_telemetry() {
    // Varsayılan olarak "info" seviyesindeki logları göster.
    // RUST_LOG=debug çevre değişkeniyle detaylı röntgene geçilebilir.
    let verbose_debug_requested = std::env::var("RUST_LOG").is_ok();
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    // Thread id/adı + dosya/satır numarası yalnız kasıtlı bir hata ayıklama
    // oturumunda (RUST_LOG açıkça ayarlandığında) eklenir; varsayılan "info"
    // modunda her satırı 2-3 kat uzatıp başlangıç logunu "Matrix ekranı"na
    // çevirirdi, varsayılan çıktı sade kalır.
    fmt()
        .with_env_filter(filter)
        .with_target(false) // Log kalabalığını azaltır
        .with_thread_ids(verbose_debug_requested)
        .with_thread_names(verbose_debug_requested)
        .with_file(verbose_debug_requested)
        .with_line_number(verbose_debug_requested)
        .init();

    tracing::info!("👁️ Zagros Telemetri ve Gözlemlenebilirlik (Observability) sistemi aktif!");
}

// G14 — NODE METRİKLERİ (/metrics + /health veri kaynağı)
use std::sync::atomic::{AtomicU64, Ordering};

/// Süreç-içi sayaçlar: konsensüs sürücüsü ve P2P servisi yazar, RPC'nin
/// `/metrics` (Prometheus metni) ve `/health` (JSON) uçları okur. Hepsi
/// `Relaxed` atomik, gözlemlenebilirlik verisi, konsensüse GİRMEZ (state'e
/// yazılmaz, deterministik olması gerekmez).
#[derive(Debug, Default)]
pub struct NodeMetrics {
    // Konsensüs (BftEngine::stats() aynası + commit bağlamı)
    pub view_changes_total: AtomicU64,
    pub timeouts_total: AtomicU64,
    pub round_skips: AtomicU64,
    pub commits_total: AtomicU64,
    pub last_commit_round: AtomicU64,
    pub last_commit_height: AtomicU64,
    /// Son commit'in duvar-saati zamanı (unix ms). Alarm tarafı "lag"i
    /// bundan türetir (spec §19: lag alarmı) — 0 = henüz commit yok.
    pub last_commit_unix_ms: AtomicU64,
    // Ağ
    pub peers_connected: AtomicU64,
    // Catch-up / güvenlik
    pub catch_up_active: AtomicU64,
    /// Simulate/commit kök uyuşmazlığı sayısı (spec §19 state_root_mismatch
    /// alarmı, normalde HEP 0; artışı "acil yükseltme" sinyalidir).
    pub state_root_mismatch_total: AtomicU64,
}

/// 🛡️ `net_peerCount` için süreç çapında gerçek sayı; `handle_rpc_request`
/// `NodeMetrics` almaz. `publish_peer_count` burayı da günceller, iki temsil sapmaz.
pub static GLOBAL_PEERS_CONNECTED: AtomicU64 = AtomicU64::new(0);

/// 🛡️ D14 RPC dürüstlüğü (denetim C2): `eth_syncing` sabit `false`
/// dönmemeli; node 10.000 blok geride olsa da "senkronum" demek borsa yatırma
/// taramasını bayat zincire göre açar. AYNI desen: `ConsensusDriver` catch-up
/// durumunu buraya yazar, RPC okur.
pub static GLOBAL_CATCH_UP_ACTIVE: AtomicU64 = AtomicU64::new(0);

/// 🛡️ Ağ katmanının RPC'ye (`zagros_getNetworkPeers`) sunduğu JSON
/// anlık görüntü (peer sayısı, mod, doğrulanmış sentry duyuruları). Aynı
/// gerekçe: RPC `zagros-network`'e bağımlı değil; servis döngüsü yazar,
/// RPC okur. Yalnız görünürlük, konsensüs-dışı.
static GLOBAL_NETWORK_SNAPSHOT: std::sync::RwLock<Option<String>> = std::sync::RwLock::new(None);

pub fn set_network_snapshot(json: String) {
    if let Ok(mut g) = GLOBAL_NETWORK_SNAPSHOT.write() {
        *g = Some(json);
    }
}

pub fn network_snapshot() -> Option<String> {
    GLOBAL_NETWORK_SNAPSHOT.read().ok().and_then(|g| g.clone())
}

/// ⏱️ Ölçüm: QC kapandıktan sonra gelen (QC'ye giremeyen) precommit gecikme
/// dağılımı, grace_ms'i veriyle seçmek için (son 4096 örnek). RPC `zagros_getLateVoteStats`.
#[derive(Default)]
struct LateVoteBook {
    /// idx → (adres, QC'ye girdi sayısı, geç geldi sayısı, gecikmeler)
    per: std::collections::BTreeMap<u16, (String, u64, u64, std::collections::VecDeque<u64>)>,
    qc_formed: u64,
    since_ms: u64,
    /// ⏱️ QC kapanış sebebi sayaçları: immediate / full / grace_expired / clamped
    close: [u64; 4],
    grace_ms: u64,
}
static LATE_VOTES: std::sync::RwLock<Option<LateVoteBook>> = std::sync::RwLock::new(None);
const LATE_SAMPLES_CAP: usize = 4096;

/// Her commit'te: QC'yi kuran node, kümedeki adresleri ve QC imzacılarını bildirir.
pub fn record_qc_formed(members: &[String], signers: &[u16], now_ms: u64) {
    if let Ok(mut g) = LATE_VOTES.write() {
        let b = g.get_or_insert_with(LateVoteBook::default);
        if b.since_ms == 0 {
            b.since_ms = now_ms;
        }
        b.qc_formed += 1;
        for (i, addr) in members.iter().enumerate() {
            let e = b
                .per
                .entry(i as u16)
                .or_insert_with(|| (addr.clone(), 0, 0, Default::default()));
            e.0 = addr.clone();
            if signers.contains(&(i as u16)) {
                e.1 += 1;
            }
        }
    }
}

/// QC kapanış sebebi (bkz. engine `QcClose`) + yürürlükteki grace.
pub fn record_qc_close(reason: &str, grace_ms: u64) {
    if let Ok(mut g) = LATE_VOTES.write() {
        let b = g.get_or_insert_with(LateVoteBook::default);
        let i = match reason {
            "immediate" => 0,
            "full" => 1,
            "grace_expired" => 2,
            _ => 3,
        };
        b.close[i] += 1;
        b.grace_ms = grace_ms;
    }
}

/// QC kapandıktan `delta_ms` sonra gelen (QC dışı kalmış) precommit.
pub fn record_late_precommit(validator_idx: u16, delta_ms: u64) {
    if let Ok(mut g) = LATE_VOTES.write() {
        let b = g.get_or_insert_with(LateVoteBook::default);
        let e = b
            .per
            .entry(validator_idx)
            .or_insert_with(|| (String::new(), 0, 0, Default::default()));
        e.2 += 1;
        if e.3.len() >= LATE_SAMPLES_CAP {
            e.3.pop_front();
        }
        e.3.push_back(delta_ms);
    }
}

fn pct(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let k = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[k.min(sorted.len() - 1)]
}

/// JSON (elle; serde bağımlılığı eklememek için).
pub fn late_vote_stats_json() -> String {
    let g = match LATE_VOTES.read() {
        Ok(g) => g,
        Err(_) => return "{}".into(),
    };
    let Some(b) = g.as_ref() else {
        return r#"{"qc_formed":0,"validators":[]}"#.into();
    };
    let mut vals = Vec::new();
    for (idx, (addr, in_qc, late, samples)) in &b.per {
        let mut s: Vec<u64> = samples.iter().copied().collect();
        s.sort_unstable();
        vals.push(format!(
            r#"{{"idx":{idx},"address":"{addr}","in_qc":{in_qc},"late":{late},"qc_rate":{rate:.4},"late_ms":{{"n":{n},"p50":{p50},"p90":{p90},"p95":{p95},"p99":{p99},"max":{max}}}}}"#,
            rate = if b.qc_formed > 0 { *in_qc as f64 / b.qc_formed as f64 } else { 0.0 },
            n = s.len(), p50 = pct(&s, 0.50), p90 = pct(&s, 0.90), p95 = pct(&s, 0.95), p99 = pct(&s, 0.99),
            max = s.last().copied().unwrap_or(0)
        ));
    }
    format!(
        r#"{{"qc_formed":{},"since_ms":{},"grace_ms":{},"qc_close":{{"immediate":{},"full":{},"grace_expired":{},"clamped":{}}},"validators":[{}]}}"#,
        b.qc_formed,
        b.since_ms,
        b.grace_ms,
        b.close[0],
        b.close[1],
        b.close[2],
        b.close[3],
        vals.join(",")
    )
}

impl NodeMetrics {
    pub fn set(&self, field: &AtomicU64, value: u64) {
        field.store(value, Ordering::Relaxed);
    }
    pub fn get(field: &AtomicU64) -> u64 {
        field.load(Ordering::Relaxed)
    }
    pub fn incr(field: &AtomicU64) {
        field.fetch_add(1, Ordering::Relaxed);
    }
}
