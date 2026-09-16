//! Zincir üstü konsensüs parametreleri ve genesis sentinel kayıtları (G2):
//! `ChainParams`, `genesis_hash`, admin multisig sentinel hesaplarda (bincode).
//! Okuma FAIL-CLOSED: kayıt yoksa/bozuksa `Err`, varsayılana düşülmez.

use zagros_primitives::{Result, ZagrosError};
use zagros_state::State;
use zagros_types::consensus::{
    AdminMultisig, ChainParams, ConsensusDomain, ScheduledUpgrade, ACTIVE_VALIDATOR_SET_KEY,
    ADMIN_MULTISIG_KEY, CHAIN_PARAMS_KEY, GENESIS_HASH_KEY, SCHEDULED_UPGRADE_KEY,
};
use zagros_types::{
    base_gas_fee_from_reserves, AccountState, Hash, CHAIN_ID, GENESIS_TIMESTAMP_KEY,
};

fn read_sentinel(state: &dyn State, key: &str) -> Result<Vec<u8>> {
    match state.get_account(&key.to_string())? {
        Some(acc) if !acc.contract_code.is_empty() => Ok(acc.contract_code),
        _ => Err(ZagrosError::ConfigError(format!(
            "{key} state'te yok (genesis yazilmamis?)"
        ))),
    }
}

fn write_sentinel(state: &dyn State, key: &str, bytes: Vec<u8>) -> Result<()> {
    let mut acc = AccountState::default();
    acc.contract_code = bytes;
    state.set_account(&key.to_string(), acc)
}

pub fn load_chain_params(state: &dyn State) -> Result<ChainParams> {
    let params = ChainParams::decode(&read_sentinel(state, CHAIN_PARAMS_KEY)?)?;
    // 🚨 §23: işlem tel formatı zincirdeki kural setine BAĞLI (bkz.
    // `zagros_types::set_tx_wire_ruleset`). Her okumada senkronlamak, hem
    // açılışta hem epoch sınırındaki aktivasyondan sonra bayrağın kendiliğinden
    // doğru değere gelmesini sağlar, ayrı bir "unutulabilir" çağrı yok.
    zagros_types::set_tx_wire_ruleset(params.active_ruleset);
    Ok(params)
}

/// Yazmadan önce doğrular (INV-G3): geçersiz parametre state'e giremez.
/// ⏱️ QC kapanış toleransı: sentinel yoksa varsayılan (200 ms). Bozuk sentinel
/// → hata (fail-closed; sessizce varsayılana düşmez).
pub fn load_qc_grace_ms(state: &dyn State) -> Result<u64> {
    match state.get_account(&zagros_types::consensus::QC_GRACE_MS_KEY.to_string())? {
        Some(acc) if !acc.contract_code.is_empty() => {
            zagros_types::consensus::decode_qc_grace(&acc.contract_code)
        }
        _ => Ok(zagros_types::consensus::DEFAULT_QC_GRACE_MS),
    }
}

pub fn store_qc_grace_ms(state: &dyn State, ms: u64) -> Result<()> {
    write_sentinel(
        state,
        zagros_types::consensus::QC_GRACE_MS_KEY,
        zagros_types::consensus::encode_qc_grace(ms),
    )
}

pub fn store_chain_params(state: &dyn State, params: &ChainParams) -> Result<()> {
    params.validate()?;
    write_sentinel(state, CHAIN_PARAMS_KEY, params.encode())
}

pub fn load_genesis_hash(state: &dyn State) -> Result<Hash> {
    let bytes = read_sentinel(state, GENESIS_HASH_KEY)?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| ZagrosError::ConfigError("genesis_hash 32 bayt degil".into()))?;
    if arr == [0u8; 32] {
        return Err(ZagrosError::ConfigError("genesis_hash sifir olamaz".into()));
    }
    Ok(arr)
}

pub fn store_genesis_hash(state: &dyn State, hash: &Hash) -> Result<()> {
    if *hash == [0u8; 32] {
        return Err(ZagrosError::ConfigError("genesis_hash sifir olamaz".into()));
    }
    write_sentinel(state, GENESIS_HASH_KEY, hash.to_vec())
}

/// Konsensüs imza bağlamı: `chain_id` + `genesis_hash` (§6).
pub fn consensus_domain(state: &dyn State) -> Result<ConsensusDomain> {
    Ok(ConsensusDomain::new(CHAIN_ID, load_genesis_hash(state)?))
}

/// 🛡️ Kurucu admin yetkisinin efektif bitişi: sabit süre ile governance erken
/// bitişinin küçüğü. Tek kaynak, yetkiyi kontrol eden her yol bunu çağırmalı.
pub fn admin_authority_end(state: &dyn State) -> Result<u128> {
    let genesis_ts = genesis_timestamp(state)?;
    let sabit_bitis = genesis_ts.saturating_add(zagros_types::ADMIN_AUTHORITY_PERIOD_SECONDS);
    match state.get_account(&zagros_types::ADMIN_AUTHORITY_END_KEY.to_string())? {
        Some(acc) if acc.balance > 0 => Ok(sabit_bitis.min(acc.balance)),
        _ => Ok(sabit_bitis),
    }
}

/// Governance ile yetkiyi erkene çeker. UZATMA REDDEDİLİR.
pub fn shorten_admin_authority(state: &dyn State, end_timestamp: u128) -> Result<()> {
    let mevcut = admin_authority_end(state)?;
    if end_timestamp >= mevcut {
        return Err(ZagrosError::Other(format!(
            "admin yetkisi yalnizca KISALTILABILIR: {end_timestamp} >= mevcut bitis {mevcut}"
        )));
    }
    let acc = AccountState {
        balance: end_timestamp,
        ..Default::default()
    };
    state.set_account(&zagros_types::ADMIN_AUTHORITY_END_KEY.to_string(), acc)
}

pub fn load_admin_multisig(state: &dyn State) -> Result<AdminMultisig> {
    AdminMultisig::decode(&read_sentinel(state, ADMIN_MULTISIG_KEY)?)
}

pub fn store_admin_multisig(state: &dyn State, m: &AdminMultisig) -> Result<()> {
    m.validate()?;
    write_sentinel(state, ADMIN_MULTISIG_KEY, m.encode())
}

pub fn load_active_validator_set_bytes(state: &dyn State) -> Result<Vec<u8>> {
    read_sentinel(state, ACTIVE_VALIDATOR_SET_KEY)
}

pub fn store_active_validator_set_bytes(state: &dyn State, bytes: Vec<u8>) -> Result<()> {
    write_sentinel(state, ACTIVE_VALIDATOR_SET_KEY, bytes)
}

/// Genesis zaman damgası (saniye). Mevcut `GENESIS_TIMESTAMP_KEY` kaydı
/// (`balance` alanında). Yoksa `Err`.
pub fn genesis_timestamp(state: &dyn State) -> Result<u128> {
    match state.get_account(&GENESIS_TIMESTAMP_KEY.to_string())? {
        Some(acc) if acc.balance > 0 => Ok(acc.balance),
        _ => Err(ZagrosError::ConfigError("genesis zaman damgasi yok".into())),
    }
}

/// Epoch numarası = ⌊(block_ts − genesis_ts) / epoch_seconds⌋ (§3, epoch = zaman).
pub fn epoch_at(block_timestamp_secs: u128, genesis_ts: u128, epoch_seconds: u64) -> u64 {
    if epoch_seconds == 0 || block_timestamp_secs < genesis_ts {
        return 0;
    }
    ((block_timestamp_secs - genesis_ts) / epoch_seconds as u128) as u64
}

/// Altın-eşdeğeri (ZERENYA ham) tutarı anlık havuz oranıyla ZAGROS'a çevirir —
/// gas ücretiyle AYNI formül (`base_gas_fee_from_reserves`). Havuz ZERENYA
/// rezervi 0 ise mevcut gas davranışı gibi 1:1 (yalnız genesis öncesi/test).
pub fn zerenya_to_zagros(state: &dyn State, zerenya_amount: u128) -> Result<u128> {
    let (pool_zagros, pool_zerenya) = state.get_pool_reserves()?;
    Ok(base_gas_fee_from_reserves(
        zerenya_amount,
        pool_zagros,
        pool_zerenya,
    ))
}

/// Validator teminatı (ZAGROS ham) = `min_validator_stake_zerenya` × havuz oranı (§13.3).
pub fn min_validator_stake_zagros(state: &dyn State, params: &ChainParams) -> Result<u128> {
    zerenya_to_zagros(state, params.min_validator_stake_zerenya)
}

/// Başvuru ücreti (ZAGROS ham) = `application_fee_zerenya` × havuz oranı (§13.7).
pub fn application_fee_zagros(state: &dyn State, params: &ChainParams) -> Result<u128> {
    zerenya_to_zagros(state, params.application_fee_zerenya)
}

/// Niteliklilik eşiği: snapshot × (1 − histerezis) (§13.3). Snapshot 0 ise
/// (G2 öncesi kayıt) güncel eşik kullanılır.
pub fn qualification_threshold(snapshot: u128, current_min: u128, hysteresis_bps: u16) -> u128 {
    let base = if snapshot == 0 { current_min } else { snapshot };
    base.saturating_mul(10_000u128.saturating_sub(hysteresis_bps as u128)) / 10_000
}

// Canlılık eşiği tavanı. 🚨 QC yeter sayıda kapandığından blok başına
// katılım payı `quorum/N` ile sınırlı (N=4 → ortalama %75); herkesin %90'ı
// geçmesi matematiksel olarak imkânsız, strike'lar sırayla herkese dağılıyordu
// (epoch 45 canlı ölçüm). Eşik yapısal tavanın altında tutulur (Cosmos %5,
// Celestia %25 → %21). Clamp saf okuma yolu kuralı: state migration gibi
// aktivasyon riski yok; governance state'e yazınca no-op olur.

/// Canlılık eşiği ÜST SINIRI (bps). State'te daha yükseği yazılı olsa bile
/// ceza değerlendirmesinde bu değer aşılmaz.
pub const LIVENESS_THRESHOLD_CAP_BPS: u16 = 2_100; // %21

/// Ceza için gereken ARDIŞIK kötü epoch sayısının ALT SINIRI. State'te daha
/// azı yazılı olsa bile bu kadar ardışık kötü epoch beklenir (2sa × 12 = 24 saat).
pub const LIVENESS_MAX_STRIKES_FLOOR: u32 = 12;

/// Etkin canlılık eşiği. 🚨 Tarih oynatma determinizmi: epoch < 48 → eski
/// kurallar (ham %90/3, jail); epoch ≥ 48 → v2 (clamp + Probation + circuit
/// breaker). Kapısız dağıtım taze node'da blok 10'da farklı state_root vermişti.
/// Bu sabit bir daha DEĞİŞTİRİLEMEZ (zincir tarihi).
pub const LIVENESS_V2_ACTIVATION_EPOCH: u64 = 48;

/// 🔓 Tek seferlik erken tahliye: eski canlılık kuralının hapsettiği, teminatı
/// duran validatörler bu epoch'ta Jailed → Probation olur; çift imza hapsi
/// kapsam dışı. Yalnız `epoch == 57`de çalışır. Zincir tarihi, DEĞİŞTİRİLEMEZ.
pub const LIVENESS_JAIL_AMNESTY_EPOCH: u64 = 57;

pub fn liveness_v2_active(epoch: u64) -> bool {
    epoch >= LIVENESS_V2_ACTIVATION_EPOCH
}

pub fn effective_uptime_threshold_bps(params: &ChainParams) -> u16 {
    params.uptime_threshold_bps.min(LIVENESS_THRESHOLD_CAP_BPS)
}

/// Epoch'a göre etkin eşik: v2 öncesi ham (zincirdeki) değer.
pub fn effective_uptime_threshold_bps_at(params: &ChainParams, epoch: u64) -> u16 {
    if liveness_v2_active(epoch) {
        effective_uptime_threshold_bps(params)
    } else {
        params.uptime_threshold_bps
    }
}

/// Epoch'a göre etkin strike tabanı: v2 öncesi ham değer.
pub fn effective_max_liveness_strikes_at(params: &ChainParams, epoch: u64) -> u32 {
    if liveness_v2_active(epoch) {
        effective_max_liveness_strikes(params)
    } else {
        params.max_liveness_strikes
    }
}

/// Ceza değerlendirmesinde kullanılacak ETKİN ardışık-strike sayısı.
pub fn effective_max_liveness_strikes(params: &ChainParams) -> u32 {
    params.max_liveness_strikes.max(LIVENESS_MAX_STRIKES_FLOOR)
}

/// 🔴 D11, oransal üretici ödülü: %20 üretici payı epoch katılım oranına göre
/// ölçeklenir, kırpılan kısım staker havuzuna gider (yakılmaz). Faktör
/// `min(1, katılım / tavan)` (tavan `quorum/N`, gecikme değil kapalılık cezalanır).
/// Aktivasyon `D11_ACTIVATION_EPOCH`tan itibaren tüm node'larda aynı epoch'ta
/// (state geçişini değiştirir, karışık dönem çatal olurdu). Fail-open: küme yok /
/// üretici kümede değil / ölçüm yok → faktör 1.
pub const D11_ACTIVATION_EPOCH: u64 = 56;

/// 🚨 EVM blok ortamı: `BlockEnv::default()` ile her kontrat `block.timestamp = 1`
/// görüyordu (LP kilitleri anında "dolmuş", Router `deadline` boş). Gerçek zaman
/// + yükseklik EVM sonuçlarını değiştirdiğinden bu epoch'tan itibaren tüm
/// node'larda aynı anda; öncesi eski davranış. DEĞİŞTİRİLEMEZ.
pub const EVM_BLOCK_ENV_ACTIVATION_EPOCH: u64 = 60;

/// Kapı: aktif kümenin epoch'u ≥ aktivasyon. Küme okunamazsa (genesis öncesi
/// test state'i vb.) eski davranış (kapalı), deterministik, fail-closed.
pub fn evm_block_env_active(state: &dyn State) -> bool {
    match crate::validator_set::load_active_set(state) {
        Ok(set) => set.epoch >= EVM_BLOCK_ENV_ACTIVATION_EPOCH,
        Err(_) => false,
    }
}

pub fn producer_reward_factor_bps(state: &dyn State, producer: &str) -> u16 {
    let set = match crate::validator_set::load_active_set(state) {
        Ok(s) => s,
        Err(_) => return 10_000,
    };
    if set.epoch < D11_ACTIVATION_EPOCH {
        return 10_000;
    }
    let n = set.len();
    if n == 0
        || !set
            .members
            .iter()
            .any(|m| m.address.eq_ignore_ascii_case(producer))
    {
        return 10_000;
    }
    let acc = match state.get_account(&producer.to_string()) {
        Ok(Some(a)) => a,
        _ => return 10_000,
    };
    if acc.liveness.epoch != set.epoch {
        return 10_000;
    }
    let Some(participation_bps) = acc.liveness.participation_bps() else {
        return 10_000;
    };
    let quorum = zagros_types::consensus::quorum_of(n).unwrap_or(n) as u128;
    let ceiling_bps = (quorum * 10_000 / n as u128).max(1);
    ((participation_bps as u128 * 10_000) / ceiling_bps).min(10_000) as u16
}

// §23 (G10), Kesintisiz Yükseltme makinesi

/// Bir validator'ün "desteklediğim en yüksek kural seti" BEYANININ saklandığı
/// anahtar. Beyan, validator'ün ürettiği her bloğun başlığından (`max_ruleset`)
/// commit sırasında deterministik olarak yazılır, gossip'e bağımlılık yok.
pub fn ruleset_decl_key(address: &str) -> String {
    format!("__RULESET_DECL_{}__", address.to_ascii_lowercase())
}

pub fn record_ruleset_declaration(
    state: &dyn State,
    address: &str,
    max_ruleset: u32,
) -> Result<()> {
    let key = ruleset_decl_key(address);
    let mut acc = state.get_account(&key)?.unwrap_or_default();
    acc.balance = max_ruleset as u128;
    state.set_account(&key, acc)
}

pub fn ruleset_declaration(state: &dyn State, address: &str) -> u32 {
    state
        .get_account(&ruleset_decl_key(address))
        .ok()
        .flatten()
        .map(|a| a.balance as u32)
        .unwrap_or(0)
}

/// Planlanmış yükseltmeyi yazar. Kaydı ÜRETEN yol G12 governance'ıdır (%80 oy);
/// bu fonksiyon o yolun (ve testlerin) tek giriş kapısı. Hedef, yürürlükteki
/// setten büyük olmak zorunda (geri gitmek yasak, mevcut sürüm-kilidi felsefesi).
pub fn store_scheduled_upgrade(state: &dyn State, up: &ScheduledUpgrade) -> Result<()> {
    let params = load_chain_params(state)?;
    if up.target_ruleset <= params.active_ruleset {
        return Err(ZagrosError::ConfigError(format!(
            "hedef ruleset {} yururlukteki {}'den buyuk olmali",
            up.target_ruleset, params.active_ruleset
        )));
    }
    let bytes = bincode::serialize(up)
        .map_err(|e| ZagrosError::ConfigError(format!("ScheduledUpgrade serialize: {e}")))?;
    write_sentinel(state, SCHEDULED_UPGRADE_KEY, bytes)
}

/// Kayıt yoksa `None` (sentinel hiç yazılmamış olabilir, hata değil).
pub fn load_scheduled_upgrade(state: &dyn State) -> Result<Option<ScheduledUpgrade>> {
    match state.get_account(&SCHEDULED_UPGRADE_KEY.to_string())? {
        Some(acc) if !acc.contract_code.is_empty() => Ok(Some(
            bincode::deserialize(&acc.contract_code)
                .map_err(|e| ZagrosError::ConfigError(format!("ScheduledUpgrade decode: {e}")))?,
        )),
        _ => Ok(None),
    }
}

pub fn clear_scheduled_upgrade(state: &dyn State) -> Result<()> {
    // contract_code boş = kayıt yok (load None döner); ayrı silme API'si yok.
    write_sentinel(state, SCHEDULED_UPGRADE_KEY, Vec::new())
}

/// Epoch sınırında: `activation_epoch`a ulaşıldıysa aktif kümenin ≥%80'i
/// beyan etmişse `active_ruleset` atomik hedefe çekilir (INV-U1/U2), yetersizse
/// kayıt iptal (FM-U1). Her iki dalda kayıt temizlenir. Döner: aktive edilen hedef.
pub fn maybe_activate_scheduled_upgrade(
    state: &dyn State,
    current_epoch: u64,
    set: &zagros_types::consensus::ActiveValidatorSet,
) -> Result<Option<u32>> {
    let Some(up) = load_scheduled_upgrade(state)? else {
        return Ok(None);
    };
    if current_epoch < up.activation_epoch {
        return Ok(None);
    }
    clear_scheduled_upgrade(state)?;
    let n = set.members.len() as u64;
    let ready = set
        .members
        .iter()
        .filter(|m| ruleset_declaration(state, &m.address) >= up.target_ruleset)
        .count() as u64;
    // ≥%80: ready/n ≥ 4/5  ⇔  5×ready ≥ 4×n (tam sayı, yuvarlama hilesiz)
    if n == 0 || 5 * ready < 4 * n {
        tracing::warn!(
            "🔄 Yükseltme İPTAL (FM-U1): epoch {} — hazırlık {}/{} (<%80), ruleset {} aktive EDİLMEDİ; zincir {} ile sürüyor",
            current_epoch, ready, n, up.target_ruleset,
            load_chain_params(state)?.active_ruleset
        );
        return Ok(None);
    }
    let mut params = load_chain_params(state)?;
    params.active_ruleset = up.target_ruleset;
    store_chain_params(state, &params)?;
    // Aktivasyon ANINDA bayrağı çevir: bu bloktan sonra yazılan her işlem
    // yeni formatta olacak ve TÜM node'lar aynı yükseklikte çevirdiği için
    // kodlama farkı oluşmaz.
    zagros_types::set_tx_wire_ruleset(up.target_ruleset);
    tracing::info!(
        "🔄✅ KESİNTİSİZ YÜKSELTME: epoch {} sınırında active_ruleset → {} (hazırlık {}/{})",
        current_epoch,
        up.target_ruleset,
        ready,
        n
    );
    Ok(Some(up.target_ruleset))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_math() {
        assert_eq!(epoch_at(1_000, 1_000, 3_600), 0);
        assert_eq!(epoch_at(4_599, 1_000, 3_600), 0);
        assert_eq!(epoch_at(4_600, 1_000, 3_600), 1);
        assert_eq!(epoch_at(1_000 + 10 * 3_600, 1_000, 3_600), 10);
        assert_eq!(epoch_at(500, 1_000, 3_600), 0, "genesis oncesi");
        assert_eq!(
            epoch_at(5_000, 1_000, 0),
            0,
            "bozuk param sifira duser, panic yok"
        );
    }

    #[test]
    fn hysteresis_threshold() {
        assert_eq!(qualification_threshold(1_000, 2_000, 2_000), 800);
        assert_eq!(
            qualification_threshold(0, 2_000, 2_000),
            1_600,
            "snapshot yoksa guncel esik"
        );
        assert_eq!(qualification_threshold(1_000, 2_000, 0), 1_000);
        assert_eq!(qualification_threshold(1_000, 2_000, 10_000), 0);
    }
}
