//! Validator kümesi, epoch geçişi ve lifecycle (G2, §2, §3).
//! Durumlar: Candidate → Approved → Probation → Active → Jailed | Exiting |
//! Removed. Küme yalnız EPOCH SINIRINDA değişir (INV-S2), state'ten deterministik türer.
//! Faz A (genesis + `admin_period`): onay/çıkarma 3-of-5 admin multisig; Faz B:
//! validator oylaması (≥2/3). İki kapı asla aynı anda açık değildir.
//! Tüm kontroller fail-closed: ChainParams/genesis_hash/multisig yoksa ret.

use std::collections::HashMap;

use zagros_primitives::{Result, ZagrosError};
use zagros_state::State;
use zagros_types::consensus::{
    active_validator_set_epoch_key, admin_action_digest, ActiveValidatorSet, AdminAction,
    AdminActionPayload, ChainParams, ConsensusDomain, LivenessCounters, QuorumCertificate,
    ValidatorMember, ValidatorStatus, Vote, MAX_VALIDATORS_HARD,
};
use zagros_types::{recover_signer_address, AccountState, Address};

use crate::params;

/// `is_registered_validator` (geriye uyum) ↔ `validator_status` senkronu.
pub fn sync_registered_flag(account: &mut AccountState) {
    account.is_registered_validator = matches!(
        account.validator_status,
        Some(ValidatorStatus::Candidate)
            | Some(ValidatorStatus::Approved)
            | Some(ValidatorStatus::Probation)
            | Some(ValidatorStatus::Active)
    );
}

pub fn load_active_set(state: &dyn State) -> Result<ActiveValidatorSet> {
    let bytes = params::load_active_validator_set_bytes(state)?;
    let set: ActiveValidatorSet = bincode::deserialize(&bytes)
        .map_err(|e| ZagrosError::ConfigError(format!("ActiveValidatorSet cozulemedi: {e}")))?;
    set.validate()?;
    Ok(set)
}

pub fn store_active_set(state: &dyn State, set: &ActiveValidatorSet) -> Result<()> {
    set.validate()?;
    let bytes = bincode::serialize(set)
        .map_err(|e| ZagrosError::Other(format!("ActiveValidatorSet: {e}")))?;
    params::store_active_validator_set_bytes(state, bytes)
}

/// G7 (§11 INV-E3): epoch'a özel KALICI küme anlık görüntüsü; `store_active_set`in
/// aksine sonraki geçişlerde silinmez. Budama yapılmaz (pencere dışı kanıt
/// zaten yaş kontrolüyle reddedilir).
pub fn store_active_set_epoch_snapshot(state: &dyn State, set: &ActiveValidatorSet) -> Result<()> {
    set.validate()?;
    let bytes = bincode::serialize(set)
        .map_err(|e| ZagrosError::Other(format!("ActiveValidatorSet snapshot: {e}")))?;
    let acc = AccountState {
        contract_code: bytes,
        ..Default::default()
    };
    state.set_account(&active_validator_set_epoch_key(set.epoch), acc)
}

/// `epoch`'un kalıcı anlık görüntüsünü okur. Yoksa `Err` (fail-closed —
/// pencere dışı ya da hiç yazılmamış epoch, evidence doğrulaması reddeder).
pub fn load_validator_set_at_epoch(state: &dyn State, epoch: u64) -> Result<ActiveValidatorSet> {
    let key = active_validator_set_epoch_key(epoch);
    match state.get_account(&key)? {
        Some(acc) if !acc.contract_code.is_empty() => {
            let set: ActiveValidatorSet =
                bincode::deserialize(&acc.contract_code).map_err(|e| {
                    ZagrosError::ConfigError(format!(
                        "epoch {epoch} kume anlik goruntusu cozulemedi: {e}"
                    ))
                })?;
            set.validate()?;
            Ok(set)
        }
        _ => Err(ZagrosError::ConfigError(format!(
            "epoch {epoch} icin kume anlik goruntusu yok"
        ))),
    }
}

/// G7: QC imzacılarını epoch kümesinin tüm üyeleri için liveness'a işler
/// (deterministik, state_root hesabı içinde); görüntü yoksa sessizce atlanır.
pub fn record_qc_liveness(state: &dyn State, qc: &QuorumCertificate) -> Result<()> {
    let set = match load_validator_set_at_epoch(state, qc.epoch) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                "⚠️ liveness: epoch {} anlik goruntusu yok, atlaniyor: {}",
                qc.epoch,
                e
            );
            return Ok(());
        }
    };
    let signers = qc.signer_indices();
    for (idx, member) in set.members.iter().enumerate() {
        let mut acc = state.get_account(&member.address)?.unwrap_or_default();
        if acc.liveness.epoch != qc.epoch {
            acc.liveness = LivenessCounters {
                epoch: qc.epoch,
                participated: 0,
                total: 0,
                strikes: acc.liveness.strikes,
            };
        }
        acc.liveness.total = acc.liveness.total.saturating_add(1);
        if signers.contains(&(idx as u16)) {
            acc.liveness.participated = acc.liveness.participated.saturating_add(1);
        }
        state.set_account(&member.address, acc)?;
    }
    Ok(())
}

/// G7: Probation validator'ının doğrulanmış ShadowVote'unu liveness sayacına
/// işler. Kriptografik doğrulama YAPMAZ, çağıran `verify_shadow_vote` ile önce
/// doğrulamalı (deterministik state geçişi saf kalsın).
pub fn record_shadow_vote_liveness(state: &dyn State, address: &Address, epoch: u64) -> Result<()> {
    let key = canonical(address)?;
    let mut acc = state
        .get_account(&key)?
        .ok_or_else(|| ZagrosError::Other("shadow oy: hesap yok".into()))?;
    if acc.liveness.epoch != epoch {
        acc.liveness = LivenessCounters {
            epoch,
            participated: 0,
            total: 0,
            strikes: acc.liveness.strikes,
        };
    }
    acc.liveness.total = acc.liveness.total.saturating_add(1);
    acc.liveness.participated = acc.liveness.participated.saturating_add(1);
    state.set_account(&key, acc)
}

/// G7: doğrula + kaydet, fail-closed (imza geçersizse state'e dokunmaz).
/// `address` oyu imzalayan pubkey'in KAYITLI sahibi olmalı.
pub fn verify_and_record_shadow_vote(
    state: &dyn State,
    domain: &ConsensusDomain,
    epoch: u64,
    address: &Address,
    vote: &Vote,
    block_number: u64,
) -> Result<()> {
    let key = canonical(address)?;
    let acc = state
        .get_account(&key)?
        .ok_or_else(|| ZagrosError::Other("shadow oy: hesap yok".into()))?;
    zagros_crypto::verify_shadow_vote(vote, domain, epoch, &acc.consensus_pubkey)?;
    // Replay koruması: aynı (adres, height, round) ikinci kez sayılmaz; geçersiz
    // imza buraya ulaşmaz (fail-closed).
    let replay_key = shadow_vote_replay_hash(&key, vote.height, vote.round);
    if is_shadow_vote_used(state, vote.height, &replay_key)? {
        return Err(ZagrosError::Other(
            "shadow oy: bu (validator, yukseklik, tur) icin zaten kaydedildi".into(),
        ));
    }
    mark_shadow_vote_used(state, vote.height, replay_key, block_number)?;
    record_shadow_vote_liveness(state, &key, epoch)
}

fn shadow_vote_replay_hash(address: &Address, height: u64, round: u32) -> zagros_primitives::Hash {
    let mut buf = Vec::with_capacity(address.len() + 12);
    buf.extend_from_slice(address.as_bytes());
    buf.extend_from_slice(&height.to_le_bytes());
    buf.extend_from_slice(&round.to_le_bytes());
    zagros_types::consensus::keccak256(&buf)
}

fn used_shadow_votes_key() -> Address {
    "__USED_SHADOW_VOTES__".to_string()
}

/// 🚨 Budanabilir tekrar defteri `(height, hash)`: yükseklik önde, `split_off` ile
/// pencere dışı tek hamlede atılır; üst sınır 128 blok × 256 oy.
type ShadowVoteReplayKey = (u64, zagros_primitives::Hash);

fn load_used_shadow_votes(
    state: &dyn State,
) -> Result<std::collections::BTreeSet<ShadowVoteReplayKey>> {
    match state.get_account(&used_shadow_votes_key())? {
        Some(acc) if !acc.contract_code.is_empty() => bincode::deserialize(&acc.contract_code)
            .map_err(|e| ZagrosError::Other(format!("Corrupt used-shadow-vote set: {e}"))),
        _ => Ok(std::collections::BTreeSet::new()),
    }
}

fn is_shadow_vote_used(
    state: &dyn State,
    height: u64,
    h: &zagros_primitives::Hash,
) -> Result<bool> {
    Ok(load_used_shadow_votes(state)?.contains(&(height, *h)))
}

/// G8: bloğa gömülü `ShadowVoteAttestation` listesini deterministik işler
/// (`record_qc_liveness` ile aynı konumda). Geçersiz giriş yalnız ATLANIR,
/// bloğu düşürmez (kötü proposer çöple dürüst validatörleri durduramaz);
/// karar state'ten türediğinden her node aynı sonucu verir.
/// Blok başına azami gölge oy (§11). 🚨 Sınırsız liste liveness sayacını
/// şişirir ve O(n²) (de)serialize + sınırsız state büyümesi yaratırdı.
pub const MAX_SHADOW_VOTES_PER_BLOCK: usize = 256;

/// Bir gölge oyun referans verebileceği en eski yükseklik (blok cinsinden).
pub const SHADOW_VOTE_MAX_AGE_BLOCKS: u64 = 128;

/// 🚨 GÜVENLİK: gölge oy yüksekliği gerçek zincire bağlanır ve sayı sınırlıdır.
/// Bağlanmasaydı validator uydurma (height, round) çiftlerini kendi bloğuna
/// gömüp katılımını istediği kadar şişirir, cezadan kaçar, iş yapmadan terfi ederdi.
/// KURAL: oy yalnız commit edilmiş yakın geçmişe (`block_number - MAX_AGE ..<
/// block_number`) referans verebilir; blok başına en fazla MAX_SHADOW_VOTES_PER_BLOCK.
pub fn apply_shadow_vote_attestations(
    state: &dyn State,
    domain: &ConsensusDomain,
    epoch: u64,
    block_number: u64,
    attestations: &[zagros_types::consensus::ShadowVoteAttestation],
) {
    for a in attestations.iter().take(MAX_SHADOW_VOTES_PER_BLOCK) {
        if a.vote.height >= block_number
            || block_number.saturating_sub(a.vote.height) > SHADOW_VOTE_MAX_AGE_BLOCKS
        {
            tracing::debug!(
                "shadow oy atlandi ({}): yukseklik {} penceredisi (blok {})",
                a.address,
                a.vote.height,
                block_number
            );
            continue;
        }
        if let Err(e) =
            verify_and_record_shadow_vote(state, domain, epoch, &a.address, &a.vote, block_number)
        {
            tracing::debug!("shadow oy atlandi ({}): {e:?}", a.address);
        }
    }
}

fn mark_shadow_vote_used(
    state: &dyn State,
    height: u64,
    h: zagros_primitives::Hash,
    block_number: u64,
) -> Result<()> {
    let key = used_shadow_votes_key();
    let mut used = load_used_shadow_votes(state)?;
    // 🚨 Önce buda, sonra ekle; tersi pencere dışı oyu eklendiği çağrıda silip korumayı kaybederdi.
    let floor = block_number.saturating_sub(SHADOW_VOTE_MAX_AGE_BLOCKS);
    used = used.split_off(&(floor, [0u8; 32]));
    used.insert((height, h));
    let bytes = bincode::serialize(&used)
        .map_err(|e| ZagrosError::Other(format!("used-shadow-vote set serialize: {e}")))?;
    let acc = AccountState {
        contract_code: bytes,
        ..Default::default()
    };
    state.set_account(&key, acc)
}

/// Genesis kümesini kurar: verilen hesaplar doğrudan `Active` olur (genesis
/// istisnası, INV-L1), kümenin `epoch = 0`. Çeşitlilik tavanları ve N≥4
/// burada da uygulanır (genesis dosyası hatalıysa fail-closed).
pub fn install_genesis_validator_set(
    state: &dyn State,
    params: &ChainParams,
    validators: &[(
        Address,
        [u8; 32],
        zagros_types::consensus::ValidatorDeclaration,
    )],
) -> Result<ActiveValidatorSet> {
    if validators.len() > params.max_validators as usize {
        return Err(ZagrosError::ConfigError(
            "genesis validator sayisi max_validators'i asiyor".into(),
        ));
    }
    let mut members = Vec::with_capacity(validators.len());
    let mut counts = DiversityCounts::default();
    for (address, pubkey, decl) in validators {
        counts.check_and_add(params, decl)?;
        let key = canonical(address)?;
        let mut acc = state.get_account(&key)?.unwrap_or_default();
        acc.validator_status = Some(ValidatorStatus::Active);
        acc.consensus_pubkey = *pubkey;
        acc.validator_declaration = decl.clone();
        acc.validator_status_epoch = 0;
        acc.validator_registered_at = 0;
        sync_registered_flag(&mut acc);
        state.set_account(&key, acc)?;
        members.push(ValidatorMember {
            address: key,
            consensus_pubkey: *pubkey,
        });
    }
    let set = ActiveValidatorSet { epoch: 0, members };
    store_active_set(state, &set)?;
    store_active_set_epoch_snapshot(state, &set)?; // G7: epoch 0 evidence penceresi icin
    Ok(set)
}

/// Beyan tavanları sayacı (§2.2). Kayıtlı (Candidate dahil DEĞİL, yalnız
/// Approved/Probation/Active) validator'lar sayılır; tavan aşımı = ret.
#[derive(Default)]
pub struct DiversityCounts {
    provider: HashMap<String, u16>,
    region: HashMap<String, u16>,
    operator: HashMap<[u8; 32], u16>,
}

impl DiversityCounts {
    pub fn from_accounts<'a>(accounts: impl Iterator<Item = &'a AccountState>) -> Self {
        let mut c = Self::default();
        for a in accounts {
            if matches!(
                a.validator_status,
                Some(ValidatorStatus::Approved)
                    | Some(ValidatorStatus::Probation)
                    | Some(ValidatorStatus::Active)
            ) {
                c.add(&a.validator_declaration);
            }
        }
        c
    }
    fn add(&mut self, d: &zagros_types::consensus::ValidatorDeclaration) {
        *self
            .provider
            .entry(d.provider.to_ascii_lowercase())
            .or_default() += 1;
        *self
            .region
            .entry(d.region.to_ascii_lowercase())
            .or_default() += 1;
        *self.operator.entry(d.operator_id).or_default() += 1;
    }
    /// Tavanı aşacaksa `Err`, aksi halde sayar.
    pub fn check_and_add(
        &mut self,
        p: &ChainParams,
        d: &zagros_types::consensus::ValidatorDeclaration,
    ) -> Result<()> {
        let prov = self
            .provider
            .get(&d.provider.to_ascii_lowercase())
            .copied()
            .unwrap_or(0);
        if prov >= p.max_per_provider {
            return Err(ZagrosError::Other(format!(
                "cesitlilik: provider '{}' tavani ({}) dolu",
                d.provider, p.max_per_provider
            )));
        }
        let reg = self
            .region
            .get(&d.region.to_ascii_lowercase())
            .copied()
            .unwrap_or(0);
        if reg >= p.max_per_region {
            return Err(ZagrosError::Other(format!(
                "cesitlilik: region '{}' tavani ({}) dolu",
                d.region, p.max_per_region
            )));
        }
        let op = self.operator.get(&d.operator_id).copied().unwrap_or(0);
        if op >= p.max_per_operator {
            return Err(ZagrosError::Other(format!(
                "cesitlilik: operator tavani ({}) dolu",
                p.max_per_operator
            )));
        }
        self.add(d);
        Ok(())
    }
}

fn canonical(address: &str) -> Result<Address> {
    if !zagros_types::Transaction::validate_address(address) {
        return Err(ZagrosError::InvalidAddress);
    }
    Ok(address.to_ascii_lowercase())
}

/// Kümedeki (Approved/Probation/Active) tüm hesapları döner, tavan ve
/// kapasite hesapları için. Kaynak: mevcut `get_validator_candidates`
/// (stake'i > 0 olan hesaplar) + küme üyeleri (stake'i düşmüş olabilir).
pub fn registered_validator_accounts(state: &dyn State) -> Result<Vec<(Address, AccountState)>> {
    let mut seen = std::collections::BTreeMap::new();
    for (addr, _) in state.get_validator_candidates()? {
        let key = addr.to_ascii_lowercase();
        if let Some(acc) = state.get_account(&key)? {
            if acc.validator_status.is_some() {
                seen.insert(key, acc);
            }
        }
    }
    if let Ok(set) = load_active_set(state) {
        for m in set.members {
            if !seen.contains_key(&m.address) {
                if let Some(acc) = state.get_account(&m.address)? {
                    seen.insert(m.address.clone(), acc);
                }
            }
        }
    }
    Ok(seen.into_iter().collect())
}

// §15 (G14), Konsensüs anahtarı rotasyonu

/// Bekleyen rotasyon sentinel anahtarı (`contract_code` = bincode).
pub fn pending_keyrot_key(address: &str) -> String {
    format!("__KEYROT_{}__", address.to_ascii_lowercase())
}

pub fn load_pending_key_rotation(
    state: &dyn State,
    address: &str,
) -> Result<Option<zagros_types::consensus::PendingKeyRotation>> {
    match state.get_account(&pending_keyrot_key(address))? {
        Some(acc) if !acc.contract_code.is_empty() => Ok(Some(
            zagros_types::consensus::PendingKeyRotation::decode(&acc.contract_code)?,
        )),
        _ => Ok(None),
    }
}

pub fn store_pending_key_rotation(
    state: &dyn State,
    address: &str,
    rot: &zagros_types::consensus::PendingKeyRotation,
) -> Result<()> {
    let key = pending_keyrot_key(address);
    let mut acc = state.get_account(&key)?.unwrap_or_default();
    acc.contract_code = rot.encode();
    state.set_account(&key, acc)
}

fn clear_pending_key_rotation(state: &dyn State, address: &str) -> Result<()> {
    let key = pending_keyrot_key(address);
    let mut acc = state.get_account(&key)?.unwrap_or_default();
    acc.contract_code = Vec::new();
    state.set_account(&key, acc)
}

/// Epoch geçişinin en başında: talepten sonraki ilk geçişte `consensus_pubkey`
/// işlenir (INV-K1: epoch içinde anahtar değişmez). Dönen (adres, yeni_pubkey)
/// listesi "kept-set" fallback'ini hesapla tutarlı tutar.
fn apply_pending_key_rotations(
    state: &dyn State,
    accounts: &mut [(Address, AccountState)],
    current_epoch: u64,
) -> Result<Vec<(Address, [u8; 32])>> {
    let mut rotated = Vec::new();
    for (addr, acc) in accounts.iter_mut() {
        let Some(rot) = load_pending_key_rotation(state, addr)? else {
            continue;
        };
        if rot.requested_epoch >= current_epoch {
            continue; // aynı epoch içinde verilmiş talep → bir sonraki geçişte
        }
        acc.consensus_pubkey = rot.new_pubkey;
        state.set_account(addr, acc.clone())?;
        clear_pending_key_rotation(state, addr)?;
        tracing::info!(
            "🔑 Epoch {}: {} konsensüs anahtarı rotasyonu etkin (yeni 0x{})",
            current_epoch,
            addr,
            hex::encode(&rot.new_pubkey[..8])
        );
        rotated.push((addr.clone(), rot.new_pubkey));
    }
    Ok(rotated)
}

/// `personal_sign` uyumu: admin multisig imzaları EIP-191 önekiyle kurtarılır
/// (yalnız admin yolu). `pub(crate)`: testler kopyalamaz, bunu çağırır.
pub(crate) fn eip191_admin_digest(digest: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(28 + 32);
    buf.extend_from_slice(b"\x19Ethereum Signed Message:\n32");
    buf.extend_from_slice(digest);
    zagros_types::consensus::keccak256(&buf)
}

/// Faz A admin multisig doğrulaması: digest `admin_action_digest(domain, action,
/// target, epoch)`; her imza secp256k1 recover → imzacı multisig üyesi ve FARKLI
/// olmalı; sayı ≥ threshold. `payload.epoch` güncel epoch olmalı (replay).
pub fn verify_admin_action(
    state: &dyn State,
    payload: &AdminActionPayload,
    current_epoch: u64,
) -> Result<()> {
    if payload.epoch != current_epoch {
        return Err(ZagrosError::Other(format!(
            "admin aksiyonu epoch {} icin imzalanmis, guncel epoch {}",
            payload.epoch, current_epoch
        )));
    }
    let multisig = params::load_admin_multisig(state)?;
    let domain = params::consensus_domain(state)?;
    let digest = admin_action_digest(&domain, payload.action, &payload.target, payload.epoch);
    // Cüzdan personal_sign EIP-191 önekiyle imzalar; kurtarmadan önce aynı öneği uygula.
    let signing_digest = eip191_admin_digest(&digest);
    let mut signers: Vec<Address> = Vec::new();
    for sig in &payload.signatures {
        let Some(signer) = recover_signer_address(&signing_digest, sig) else {
            return Err(ZagrosError::InvalidSignature);
        };
        let signer = signer.to_ascii_lowercase();
        if !multisig.is_signer(&signer) {
            return Err(ZagrosError::Other(
                "admin aksiyonu: imzaci multisig uyesi degil".into(),
            ));
        }
        if signers.contains(&signer) {
            return Err(ZagrosError::Other(
                "admin aksiyonu: tekrar eden imzaci".into(),
            ));
        }
        signers.push(signer);
    }
    if signers.len() < multisig.threshold as usize {
        return Err(ZagrosError::Other(format!(
            "admin aksiyonu: {} imza < esik {}",
            signers.len(),
            multisig.threshold
        )));
    }
    Ok(())
}

/// Olgunlaşmış bekleyen teminatı `staked_balance`a taşır (`settle_pending_stake`
/// ile aynı muhasebe). 🚨 Neden burada: `settle_pending_stake` yalnız hesabın
/// kendi işleminde çağrılır; stake edip pasif kalan validator teminatını hiç
/// geçiremez, üretici payını kaybeder ve epoch sınırında Probation'a düşerdi.
/// Epoch sınırı deterministik süpürme noktası, küme değerlendirmesinden ÖNCE işlenir.
fn settle_matured_stake(state: &dyn State, acc: &mut AccountState, now_secs: u128) -> Result<bool> {
    if acc.pending_stake_amount == 0 || now_secs < acc.pending_stake_activation_time {
        return Ok(false);
    }
    let acc_per_share = state.get_accumulated_reward_per_share()?;
    let settling = acc.pending_stake_amount;
    acc.reward_debt = acc
        .reward_debt
        .saturating_add(crate::reward_owed(settling, acc_per_share));
    acc.staked_balance = acc.staked_balance.saturating_add(settling);
    acc.pending_stake_amount = 0;
    acc.pending_stake_activation_time = 0;

    let tracker_key = "__GLOBAL_TOTAL_STAKED__".to_string();
    let mut tracker = state.get_account(&tracker_key)?.unwrap_or_default();
    tracker.balance = tracker.balance.saturating_add(settling);
    state.set_account(&tracker_key, tracker)?;
    Ok(true)
}

/// Epoch geçişi (§3): Exiting→Removed, Jailed→Candidate, Probation→Active
/// (ölçüm yoksa geçmez), Approved→Probation; eşik altı Active→Probation.
pub fn advance_epoch_if_due(
    state: &dyn State,
    block_timestamp_secs: u128,
) -> Result<ActiveValidatorSet> {
    let params = params::load_chain_params(state)?;
    let genesis_ts = params::genesis_timestamp(state)?;
    let current_epoch = params::epoch_at(block_timestamp_secs, genesis_ts, params.epoch_seconds);
    let set = load_active_set(state)?;
    if current_epoch <= set.epoch {
        return Ok(set);
    }
    let min_stake = params::min_validator_stake_zagros(state, &params)?;
    let mut accounts = registered_validator_accounts(state)?;

    // 🚨 EKONOMİK: olgunlaşmış teminatlar küme değerlendirmesinden ÖNCE
    // işlenir. Ayrıntı için bkz. `settle_matured_stake` doc yorumu.
    for (addr, acc) in accounts.iter_mut() {
        if settle_matured_stake(state, acc, block_timestamp_secs)? {
            state.set_account(addr, acc.clone())?;
        }
    }

    // 0) §15 (G14): bekleyen anahtar rotasyonları, küme yeniden kurulmadan
    // ÖNCE hesaba işlenir ki adım 4'teki üye listesi yeni anahtarı görsün.
    let rotated = apply_pending_key_rotations(state, &mut accounts, current_epoch)?;

    // 1) Durum geçişleri. 🚨 İki aşama: canlılık cezası circuit breaker'a bağlı,
    // 1a yalnız strike sayar ve aday indekslerini toplar, ceza 1b'de topluca
    // uygulanır. `accounts` adrese göre sıralı (deterministik).
    // 🔓 0) Tek seferlik erken tahliye (`LIVENESS_JAIL_AMNESTY_EPOCH`): eski
    // kuralın hapsettiği validatörler bu sınırda Probation'a döner, adım 1'den önce.
    if current_epoch == params::LIVENESS_JAIL_AMNESTY_EPOCH {
        for (addr, acc) in accounts.iter_mut() {
            if acc.validator_status == Some(ValidatorStatus::Jailed) && acc.staked_balance > 0 {
                acc.validator_status = Some(ValidatorStatus::Probation);
                acc.validator_status_epoch = current_epoch;
                acc.jailed_until = 0;
                acc.liveness = Default::default();
                sync_registered_flag(acc);
                state.set_account(addr, acc.clone())?;
                tracing::warn!(
                    "🔓 Erken tahliye (epoch {}): {} Jailed → Probation (eski canlılık kuralı hapsi; teminat duruyor)",
                    current_epoch, addr
                );
            }
        }
    }

    // 🚨 Tarih oynatma determinizmi: eski epoch'larda (< 48) ham eşik/strike + jail.
    let liveness_v2 = params::liveness_v2_active(current_epoch);
    let uptime_threshold_bps = params::effective_uptime_threshold_bps_at(&params, current_epoch);
    let max_liveness_strikes = params::effective_max_liveness_strikes_at(&params, current_epoch);
    let mut pending_liveness_demotions: Vec<usize> = Vec::new();

    for (idx, (addr, acc)) in accounts.iter_mut().enumerate() {
        let mut changed = false;
        match acc.validator_status {
            Some(ValidatorStatus::Exiting) => {
                acc.validator_status = Some(ValidatorStatus::Removed);
                changed = true;
            }
            Some(ValidatorStatus::Jailed) => {
                if block_timestamp_secs >= acc.jailed_until {
                    acc.validator_status = Some(ValidatorStatus::Candidate);
                    changed = true;
                }
            }
            Some(ValidatorStatus::Active) => {
                // G7 (§11): yalnız biten epoch'un (`set.epoch`) ölçümü değerlendirilir;
                // eski epoch ölçümü tekrar cezalandırmaz. Eşik altı → strike, eşik
                // üstü → strike sıfırlanır, ölçüm yoksa fail-closed (ne ceza ne aklama).
                if acc.liveness.epoch == set.epoch {
                    if let Some(bps) = acc.liveness.participation_bps() {
                        if bps < uptime_threshold_bps {
                            acc.liveness.strikes = acc.liveness.strikes.saturating_add(1);
                        } else {
                            acc.liveness.strikes = 0;
                        }
                        changed = true;
                    }
                }
                if acc.liveness.strikes >= max_liveness_strikes && !liveness_v2 {
                    // ESKİ KURAL (epoch < 48, yalnız tarih oynatma): jail + bond kilidi.
                    acc.validator_status = Some(ValidatorStatus::Jailed);
                    acc.jailed_until =
                        block_timestamp_secs.saturating_add(zagros_types::JAIL_DURATION_SECONDS);
                    acc.bond_unlock_at = acc
                        .bond_unlock_at
                        .max(block_timestamp_secs.saturating_add(params.bond_lock_seconds as u128));
                    acc.liveness.strikes = 0;
                    changed = true;
                } else if acc.liveness.strikes >= max_liveness_strikes {
                    // 🚨 Yavaşlık cezası jail değil (ölçüm `quorum/N` tavanlı, N=4'te
                    // tek jail toleransı sıfırlar); 1b'de topluca uygulanır.
                    pending_liveness_demotions.push(idx);
                } else {
                    let threshold = params::qualification_threshold(
                        acc.validator_stake_snapshot,
                        min_stake,
                        params.stake_hysteresis_bps,
                    );
                    if acc.staked_balance < threshold {
                        acc.validator_status = Some(ValidatorStatus::Probation);
                        changed = true;
                    }
                }
            }
            _ => {}
        }
        if changed {
            acc.validator_status_epoch = current_epoch;
            sync_registered_flag(acc);
            state.set_account(addr, acc.clone())?;
        }
    }

    // 1b) Canlılık cezası = Probation. 🛡️ Circuit breaker: Active sayısı
    // `MIN_VALIDATORS`ın altına düşecekse hiçbiri uygulanmaz (hepsi ya hiçbiri).
    if !pending_liveness_demotions.is_empty() {
        let active_now = accounts
            .iter()
            .filter(|(_, a)| a.validator_status == Some(ValidatorStatus::Active))
            .count();
        let remaining = active_now.saturating_sub(pending_liveness_demotions.len());
        let floor = zagros_types::consensus::MIN_VALIDATORS as usize;
        if remaining >= floor {
            for &idx in &pending_liveness_demotions {
                let (addr, acc) = &mut accounts[idx];
                acc.validator_status = Some(ValidatorStatus::Probation);
                acc.validator_status_epoch = current_epoch;
                // Sayaçlar sıfırlanır: yeniden değerlendirme temiz pencereyle başlar.
                acc.liveness.strikes = 0;
                acc.liveness.participated = 0;
                acc.liveness.total = 0;
                sync_registered_flag(acc);
                state.set_account(addr, acc.clone())?;
                tracing::warn!(
                    "⚠️ Canlılık cezası (epoch {}): {} → Probation (jail DEĞİL, kendiliğinden iyileşir)",
                    current_epoch,
                    addr
                );
            }
        } else {
            tracing::error!(
                "🛡️ Canlılık cezası ERTELENDİ (epoch {}): {} aday düşürülse Active {} → {} olurdu, taban {}. Küme güvenliği cezadan önce gelir.",
                current_epoch,
                pending_liveness_demotions.len(),
                active_now,
                remaining,
                floor
            );
        }
    }

    // 2) Probation → Active (probation_epochs geçti + katılım ölçülmüş ve ≥ eşik)
    for (addr, acc) in accounts.iter_mut() {
        if acc.validator_status != Some(ValidatorStatus::Probation) {
            continue;
        }
        let served = current_epoch.saturating_sub(acc.validator_status_epoch);
        if served < params.probation_epochs as u64 {
            continue;
        }
        let passed = acc
            .liveness
            .participation_bps()
            .map(|bps| bps >= uptime_threshold_bps)
            .unwrap_or(false); // ölçüm yok → geçmez (fail-closed)
        let threshold = params::qualification_threshold(
            acc.validator_stake_snapshot,
            min_stake,
            params.stake_hysteresis_bps,
        );
        if passed && acc.staked_balance >= threshold && acc.consensus_pubkey != [0u8; 32] {
            acc.validator_status = Some(ValidatorStatus::Active);
            acc.validator_status_epoch = current_epoch;
            sync_registered_flag(acc);
            state.set_account(addr, acc.clone())?;
        }
    }

    // 3) Approved → Probation (kapasite): terfi FIFO, `validator_registered_at`e
    // göre; adres yalnız ikincil ayraç (adres sırası sonradan geleni öne geçirirdi).
    let occupancy = |accs: &Vec<(Address, AccountState)>| {
        accs.iter()
            .filter(|(_, a)| {
                matches!(
                    a.validator_status,
                    Some(ValidatorStatus::Active) | Some(ValidatorStatus::Probation)
                )
            })
            .count() as u16
    };
    let used = occupancy(&accounts);
    let free_slots = (params.max_validators as usize).saturating_sub(used as usize);
    let mut approved_order: Vec<usize> = accounts
        .iter()
        .enumerate()
        .filter(|(_, (_, a))| a.validator_status == Some(ValidatorStatus::Approved))
        .map(|(i, _)| i)
        .collect();
    approved_order.sort_by(|&i, &j| {
        let (ai_addr, ai) = &accounts[i];
        let (aj_addr, aj) = &accounts[j];
        ai.validator_registered_at
            .cmp(&aj.validator_registered_at)
            .then_with(|| ai_addr.cmp(aj_addr))
    });
    // FIFO sırayla yalnız boş slot kadarını terfi ettir (take).
    for i in approved_order.into_iter().take(free_slots) {
        let (addr, acc) = &mut accounts[i];
        acc.validator_status = Some(ValidatorStatus::Probation);
        acc.validator_status_epoch = current_epoch;
        acc.liveness = Default::default();
        sync_registered_flag(acc);
        state.set_account(addr, acc.clone())?;
    }

    // 4) Yeni küme = Active olanlar (kayıt sırası)
    let mut actives: Vec<(Address, AccountState)> = accounts
        .into_iter()
        .filter(|(_, a)| a.validator_status == Some(ValidatorStatus::Active))
        .collect();
    // 🛡️ KONSENSÜS KRİTİK SIRALAMA: sıra proposer rotasyonunu ((h + r) % N)
    // belirler. Adres üçüncül ayraç olarak AÇIKÇA yazılır; kaynak BTreeMap'ten
    // HashMap'e dönse örtük sıra sessizce çatallanırdı.
    actives.sort_by(|(a_addr, a), (b_addr, b)| {
        a.validator_registered_at
            .cmp(&b.validator_registered_at)
            .then_with(|| a.validator_status_epoch.cmp(&b.validator_status_epoch))
            .then_with(|| a_addr.cmp(b_addr))
    });
    let members: Vec<ValidatorMember> = actives
        .iter()
        .map(|(addr, a)| ValidatorMember {
            address: addr.clone(),
            consensus_pubkey: a.consensus_pubkey,
        })
        .collect();
    let new_set = ActiveValidatorSet {
        epoch: current_epoch,
        members,
    };
    if new_set.len() < zagros_types::consensus::MIN_VALIDATORS
        || new_set.len() > MAX_VALIDATORS_HARD
    {
        // INV-S1: BFT için yetersiz küme, eski küme korunur (epoch ilerler ama
        // üyelik değişmez), açık hata loglanır. Sessiz küçülme YOK.
        tracing::error!(
            "🚨 Epoch {}: yeni kume boyutu {} BFT siniri disinda; eski kume ({} uye) korunuyor",
            current_epoch,
            new_set.len(),
            set.len()
        );
        // G14: rotasyon hesaba işlendiyse korunan kümenin üyeleri de yeni
        // anahtarı taşımalı, aksi halde küme eski, hesap yeni anahtarla kalır.
        let kept_members = set
            .members
            .iter()
            .map(|m| {
                let pk = rotated
                    .iter()
                    .find(|(a, _)| a == &m.address)
                    .map(|(_, pk)| *pk)
                    .unwrap_or(m.consensus_pubkey);
                ValidatorMember {
                    address: m.address.clone(),
                    consensus_pubkey: pk,
                }
            })
            .collect();
        let kept = ActiveValidatorSet {
            epoch: current_epoch,
            members: kept_members,
        };
        store_active_set(state, &kept)?;
        store_active_set_epoch_snapshot(state, &kept)?;
        crate::governance::process_at_epoch(state, current_epoch, &kept)?;
        params::maybe_activate_scheduled_upgrade(state, current_epoch, &kept)?;
        return Ok(kept);
    }
    store_active_set(state, &new_set)?;
    store_active_set_epoch_snapshot(state, &new_set)?;
    // §23 (G10): planlanmış yükseltme varsa TAM BURADA, küme kesinleştikten
    // sonra, aynı deterministik blok yürütmesinin içinde, değerlendirilir.
    crate::governance::process_at_epoch(state, current_epoch, &new_set)?;
    params::maybe_activate_scheduled_upgrade(state, current_epoch, &new_set)?;
    tracing::info!(
        "🏛️ Epoch {} kumesi: {} validator, hash 0x{}",
        current_epoch,
        new_set.len(),
        hex::encode(&new_set.hash()[..8])
    );
    Ok(new_set)
}

/// `ApproveValidator` (Faz A): Candidate → Approved. Çeşitlilik tavanı ve
/// teminat kontrolü burada; kümeye giriş epoch sınırında (§2).
pub fn apply_admin_approve(state: &dyn State, target: &str, current_epoch: u64) -> Result<()> {
    let key = canonical(target)?;
    let params = params::load_chain_params(state)?;
    let mut acc = state
        .get_account(&key)?
        .ok_or_else(|| ZagrosError::Other("onay: hedef hesap yok".into()))?;
    if acc.validator_status != Some(ValidatorStatus::Candidate) {
        return Err(ZagrosError::Other(format!(
            "onay: hedef Candidate degil ({:?})",
            acc.validator_status
        )));
    }
    if acc.consensus_pubkey == [0u8; 32] {
        return Err(ZagrosError::Other("onay: konsensus anahtari yok".into()));
    }
    let min_stake = params::min_validator_stake_zagros(state, &params)?;
    if acc.staked_balance
        < params::qualification_threshold(
            acc.validator_stake_snapshot,
            min_stake,
            params.stake_hysteresis_bps,
        )
    {
        return Err(ZagrosError::StakingError(
            "onay: teminat esigin altinda".into(),
        ));
    }
    let others = registered_validator_accounts(state)?;
    let mut counts = DiversityCounts::from_accounts(
        others.iter().filter(|(a, _)| *a != key).map(|(_, acc)| acc),
    );
    counts.check_and_add(&params, &acc.validator_declaration)?;
    acc.validator_status = Some(ValidatorStatus::Approved);
    acc.validator_status_epoch = current_epoch;
    sync_registered_flag(&mut acc);
    state.set_account(&key, acc)
}

/// `RemoveValidator` (Faz A): herhangi bir kayıtlı durumdan → Removed; teminat
/// `bond_lock_seconds` boyunca kilitli (slash edilebilir). Küme epoch sınırında
/// güncellenir (INV-S2), bu çağrı kümeyi doğrudan değiştirmez.
pub fn apply_admin_remove(
    state: &dyn State,
    target: &str,
    now_secs: u128,
    current_epoch: u64,
) -> Result<()> {
    let key = canonical(target)?;
    let params = params::load_chain_params(state)?;
    let mut acc = state
        .get_account(&key)?
        .ok_or_else(|| ZagrosError::Other("cikarma: hedef hesap yok".into()))?;
    match acc.validator_status {
        None | Some(ValidatorStatus::Removed) => {
            return Err(ZagrosError::Other(
                "cikarma: hedef kayitli validator degil".into(),
            ))
        }
        _ => {}
    }
    acc.validator_status = Some(ValidatorStatus::Removed);
    acc.validator_status_epoch = current_epoch;
    acc.bond_unlock_at = now_secs.saturating_add(params.bond_lock_seconds as u128);
    sync_registered_flag(&mut acc);
    state.set_account(&key, acc)
}

/// Faz A mı? Bitiş anı `params::admin_authority_end` tek kaynağından (sabit
/// süre ile governance erken bitişinin küçüğü); `is_admin_authority_active` de bunu çağırır.
pub fn admin_phase_active(state: &dyn State, now_secs: u128) -> Result<bool> {
    Ok(now_secs <= params::admin_authority_end(state)?)
}

/// `ApproveValidator`/`RemoveValidator` işlemi: Faz A → multisig; Faz B → P1-5
/// (açık hata). Gönderen herhangi bir hesap olabilir (imzalar payload'da).
pub fn apply_admin_action_tx(
    state: &dyn State,
    action: AdminAction,
    payload_bytes: &[u8],
    now_secs: u128,
) -> Result<Address> {
    let payload = AdminActionPayload::decode(payload_bytes)?;
    // G12: VetoProposal ayrı bir TxType almaz, ApproveValidator rotasından
    // taşınır (imzalar aksiyonu DIGEST'te bağlar: Approve imzası Veto'ya,
    // Veto imzası Approve'a dönüştürülemez; tür-karışıklığı saldırısı yok).
    let action_ok = payload.action == action
        || (action == AdminAction::Approve && payload.action == AdminAction::VetoProposal);
    if !action_ok {
        return Err(ZagrosError::Other(
            "payload aksiyonu tx turuyle uyusmuyor".into(),
        ));
    }
    let action = payload.action;
    let params = params::load_chain_params(state)?;
    let genesis_ts = params::genesis_timestamp(state)?;
    let current_epoch = params::epoch_at(now_secs, genesis_ts, params.epoch_seconds);
    if !admin_phase_active(state, now_secs)? {
        return Err(ZagrosError::Other(
            "Faz A sona erdi: kume uyeligi artik VALIDATOR OYLAMASINDA. \
             SubmitProposal ile ApproveValidator/RemoveValidator onerisi acin \
             (GovChannel::Consensus, aktif validatorler esit oy, >=2/3)."
                .into(),
        ));
    }
    verify_admin_action(state, &payload, current_epoch)?;
    match action {
        AdminAction::Approve => apply_admin_approve(state, &payload.target, current_epoch)?,
        AdminAction::Remove => apply_admin_remove(state, &payload.target, now_secs, current_epoch)?,
        AdminAction::VetoProposal => crate::governance::apply_veto(state, &payload.target)?,
    }
    Ok(payload.target.to_ascii_lowercase())
}
