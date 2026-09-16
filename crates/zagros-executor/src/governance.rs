//! G12: Governance iki kanal (§14), epoch sınırında deterministik boru hattı:
//! SubmitProposal → Active → pencere biter → SAYIM (Consensus: aktif kümenin
//! ≥2/3, ScheduleUpgrade ≥%80; Economic: validator ≥2/3 VE staker çift quorum)
//! → Queued (timelock) → yürütme (ParamChange / ScheduleUpgrade) ya da Rejected/Vetoed.
//! Faz A vetosu: AdminAction::VetoProposal (3-of-5), yalnız consensus kanalı.
use zagros_primitives::{Result, ZagrosError};
use zagros_state::State;
use zagros_types::consensus::{ActiveValidatorSet, GovChannel, ProposalAction};
use zagros_types::{AccountState, Address, Hash, Proposal, ProposalStatus, VALIDATOR_REWARD_POOL};

use crate::params;

/// Tipli (yürütülebilir) önerilerin kimlik listesi, epoch işleyicisi yalnız
/// bunları tarar; legacy Text önerileri ESKİ davranışıyla (effective_status)
/// yaşar, bu listeye hiç girmez.
pub const GOV_ACTIVE_LIST_KEY: &str = "__GOV_TYPED_ACTIVE__";

fn vote_key(pid: &Hash, addr: &str) -> String {
    format!("GovVote_{}_{}", hex::encode(pid), addr.to_ascii_lowercase())
}
fn voter_count_key(pid: &Hash) -> String {
    format!("GovVoterCount_{}", hex::encode(pid))
}
fn voter_index_key(pid: &Hash, n: u128) -> String {
    format!("GovVoter_{}_{}", hex::encode(pid), n)
}

pub fn load_typed_active(state: &dyn State) -> Result<Vec<Hash>> {
    match state.get_account(&GOV_ACTIVE_LIST_KEY.to_string())? {
        Some(acc) if !acc.contract_code.is_empty() => bincode::deserialize(&acc.contract_code)
            .map_err(|e| ZagrosError::Other(format!("gov aktif liste decode: {e}"))),
        _ => Ok(Vec::new()),
    }
}

fn store_typed_active(state: &dyn State, list: &[Hash]) -> Result<()> {
    let mut acc = AccountState::default();
    acc.contract_code = bincode::serialize(list)
        .map_err(|e| ZagrosError::Other(format!("gov aktif liste encode: {e}")))?;
    state.set_account(&GOV_ACTIVE_LIST_KEY.to_string(), acc)
}

pub fn register_typed_active(state: &dyn State, pid: Hash) -> Result<()> {
    let mut list = load_typed_active(state)?;
    if !list.contains(&pid) {
        list.push(pid);
        store_typed_active(state, &list)?;
    }
    Ok(())
}

fn remove_typed_active(state: &dyn State, pid: &Hash) -> Result<()> {
    let mut list = load_typed_active(state)?;
    list.retain(|p| p != pid);
    store_typed_active(state, &list)
}

/// Oy kişi-bazında saklanır (çerçeve #2): ağırlık = OY ANINDAKİ stake
/// (deterministik snapshot), destek `nonce` alanında (1=evet).
pub fn record_vote(
    state: &dyn State,
    pid: &Hash,
    addr: &str,
    support: bool,
    weight: u128,
) -> Result<()> {
    let mut acc = AccountState::default();
    acc.balance = weight;
    acc.nonce = if support { 1 } else { 0 };
    state.set_account(&vote_key(pid, addr), acc)?;
    let ck = voter_count_key(pid);
    let mut c = state.get_account(&ck)?.unwrap_or_default();
    let n = c.balance;
    c.balance = n.saturating_add(1);
    state.set_account(&ck, c)?;
    let mut idx = AccountState::default();
    idx.contract_code = addr.to_ascii_lowercase().into_bytes();
    state.set_account(&voter_index_key(pid, n), idx)
}

fn vote_of(state: &dyn State, pid: &Hash, addr: &str) -> Result<Option<(bool, u128)>> {
    Ok(state
        .get_account(&vote_key(pid, addr))?
        .map(|a| (a.nonce == 1, a.balance)))
}

fn voters(state: &dyn State, pid: &Hash) -> Result<Vec<Address>> {
    let n = state
        .get_account(&voter_count_key(pid))?
        .map(|a| a.balance)
        .unwrap_or(0);
    let mut out = Vec::with_capacity(n.min(10_000) as usize);
    for i in 0..n {
        if let Some(acc) = state.get_account(&voter_index_key(pid, i))? {
            out.push(String::from_utf8_lossy(&acc.contract_code).to_string());
        }
    }
    Ok(out)
}

// 🗳️ İadeli depozito (`GOV_DEPOSIT_ACTIVATION_HEIGHT` sonrası): bedel kasada
// tutulur, yeter sayıda iade, yoksa/vetoda Hevsel'e. Kayıt ayrı `GovDeposit_<pid>`
// anahtarında, Proposal gövdesi değişmez; kapı öncesi önerilerde `settle_deposit` 0 döner.
pub const GOV_DEPOSIT_ESCROW_KEY: &str = "__GOV_DEPOSIT_ESCROW__";

fn deposit_key(pid: &Hash) -> String {
    format!("GovDeposit_{}", hex::encode(pid))
}

/// Bedeli öneri adına kasaya koyar (gönderenin bakiyesi çağıranda düşülmüştür).
pub fn escrow_deposit(state: &dyn State, pid: &Hash, amount: u128) -> Result<()> {
    if amount == 0 {
        return Ok(());
    }
    let key = deposit_key(pid);
    let mut d = state.get_account(&key)?.unwrap_or_default();
    d.balance = d.balance.saturating_add(amount);
    state.set_account(&key, d)?;
    state.add_balance(&GOV_DEPOSIT_ESCROW_KEY.to_string(), amount)
}

/// Öneri adına kasada bekleyen depozito (0 = yok ya da çoktan sonuçlandı).
pub fn deposit_of(state: &dyn State, pid: &Hash) -> Result<u128> {
    Ok(state
        .get_account(&deposit_key(pid))?
        .map(|a| a.balance)
        .unwrap_or(0))
}

/// Depozito Hevsel'e: `distribute_staking_reward` staker koluyla aynı muhasebe;
/// epoch sınırında üretici bağlamı yok, tamamı stake edenlere. Kimse stake etmemişse havuzda bekler.
fn forfeit_to_hevsel(state: &dyn State, amount: u128) -> Result<()> {
    if amount == 0 {
        return Ok(());
    }
    let total_staked = state
        .get_account(&"__GLOBAL_TOTAL_STAKED__".to_string())?
        .map(|a| a.balance)
        .unwrap_or(0);
    state.add_balance(&VALIDATOR_REWARD_POOL.to_string(), amount)?;
    if total_staked > 0 {
        let acc = state.get_accumulated_reward_per_share()?;
        let added = amount
            .saturating_mul(1_000_000_000_000)
            .checked_div(total_staked)
            .unwrap_or(0);
        state.set_accumulated_reward_per_share(acc.saturating_add(added))?;
    }
    Ok(())
}

/// Depozitoyu sonuçlandırır: `refund` ise önericiye, değilse Hevsel'e.
/// Döndürdüğü tutar 0 ise yapılacak bir şey yoktu (kapı öncesi öneri ya da
/// çoktan sonuçlanmış). İdempotent: ikinci çağrı no-op.
pub fn settle_deposit(state: &dyn State, proposal: &Proposal, refund: bool) -> Result<u128> {
    let amount = deposit_of(state, &proposal.proposal_id)?;
    if amount == 0 {
        return Ok(0);
    }
    let key = deposit_key(&proposal.proposal_id);
    let mut d = state.get_account(&key)?.unwrap_or_default();
    d.balance = 0;
    state.set_account(&key, d)?;
    let ek = GOV_DEPOSIT_ESCROW_KEY.to_string();
    let mut e = state.get_account(&ek)?.unwrap_or_default();
    e.balance = e.balance.saturating_sub(amount);
    state.set_account(&ek, e)?;
    if refund {
        state.add_balance(&proposal.proposer, amount)?;
        tracing::info!(
            "🗳️💰 Depozito İADE: 0x{} → {} ({} ham)",
            hex::encode(&proposal.proposal_id[..6]),
            proposal.proposer,
            amount
        );
    } else {
        forfeit_to_hevsel(state, amount)?;
        tracing::info!(
            "🗳️🏛️ Depozito HEVSEL'E (yeter sayı yok / veto): 0x{} ({} ham)",
            hex::encode(&proposal.proposal_id[..6]),
            amount
        );
    }
    Ok(amount)
}

// 📇 Öneri dizini (RPC listeleme için; state_root DIŞI, salt gözlemlenebilirlik)
pub const GOV_PROPOSAL_INDEX_KEY: &str = "__GOV_PROPOSAL_INDEX__";

/// Sunulan HER öneri (tipli + metin) sırayla dizine yazılır; terminal duruma
/// geçince silinmez (geçmiş görünür kalsın). `0x` dışı anahtar olduğundan
/// köke girmez; eski ikili çalıştıran bir düğüm yalnız listeyi eksik görür.
pub fn register_index(state: &dyn State, pid: Hash) -> Result<()> {
    let mut list = load_index(state)?;
    if !list.contains(&pid) {
        list.push(pid);
        let mut acc = AccountState::default();
        acc.contract_code = bincode::serialize(&list)
            .map_err(|e| ZagrosError::Other(format!("gov dizin encode: {e}")))?;
        state.set_account(&GOV_PROPOSAL_INDEX_KEY.to_string(), acc)?;
    }
    Ok(())
}

pub fn load_index(state: &dyn State) -> Result<Vec<Hash>> {
    match state.get_account(&GOV_PROPOSAL_INDEX_KEY.to_string())? {
        Some(acc) if !acc.contract_code.is_empty() => bincode::deserialize(&acc.contract_code)
            .map_err(|e| ZagrosError::Other(format!("gov dizin decode: {e}"))),
        _ => Ok(Vec::new()),
    }
}

/// Salt-okuma: bir adresin kayıtlı oyu (destek, ağırlık).
pub fn vote_of_view(state: &dyn State, pid: &Hash, addr: &str) -> Result<Option<(bool, u128)>> {
    vote_of(state, pid, addr)
}

/// Salt-okuma: aktif küme üyelerinin oyları (adres, Some(destek) | None = oy yok).
pub fn validator_votes_view(
    state: &dyn State,
    pid: &Hash,
    set: &ActiveValidatorSet,
) -> Result<Vec<(Address, Option<bool>)>> {
    let mut out = Vec::with_capacity(set.members.len());
    for m in &set.members {
        out.push((
            m.address.clone(),
            vote_of(state, pid, &m.address)?.map(|(s, _)| s),
        ));
    }
    Ok(out)
}

/// Salt-okuma staker sayımı: (kabul, yeter sayı, katılım, evet, hayır, toplam kilitli).
pub fn staker_tally_view(
    state: &dyn State,
    pid: &Hash,
    vote_cap_bps: u16,
    staker_quorum_bps: u16,
) -> Result<(bool, bool, u128, u128, u128, u128)> {
    let total_staked = state
        .get_account(&"__GLOBAL_TOTAL_STAKED__".to_string())?
        .map(|a| a.balance)
        .unwrap_or(0);
    let (a, q, p, y, n) = staker_tally(state, pid, vote_cap_bps, staker_quorum_bps)?;
    Ok((a, q, p, y, n, total_staked))
}

/// Aktif kümenin eşit-oy sayımı: (evet, oy kullanan, toplam üye).
fn validator_tally(
    state: &dyn State,
    pid: &Hash,
    set: &ActiveValidatorSet,
) -> Result<(u64, u64, u64)> {
    let mut yes = 0u64;
    let mut voted = 0u64;
    for m in &set.members {
        if let Some((support, _)) = vote_of(state, pid, &m.address)? {
            voted += 1;
            if support {
                yes += 1;
            }
        }
    }
    Ok((yes, voted, set.members.len() as u64))
}

/// Staker çift-quorum sayımı (economic): (kabul mü, yeter sayı var mı, katılım, evet_ağırlık, hayır_ağırlık).
fn staker_tally(
    state: &dyn State,
    pid: &Hash,
    vote_cap_bps: u16,
    staker_quorum_bps: u16,
) -> Result<(bool, bool, u128, u128, u128)> {
    let total_staked = state
        .get_account(&"__GLOBAL_TOTAL_STAKED__".to_string())?
        .map(|a| a.balance)
        .unwrap_or(0);
    if total_staked == 0 {
        return Ok((false, false, 0, 0, 0));
    }
    // Mikro-karar (a): adres tavanı = TOPLAM kilitli stake'in vote_cap_bps'i.
    let cap = total_staked.saturating_mul(vote_cap_bps as u128) / 10_000;
    let (mut yes_w, mut no_w) = (0u128, 0u128);
    for addr in voters(state, pid)? {
        if let Some((support, w)) = vote_of(state, pid, &addr)? {
            // 🛡️ Ağırlık oy anında saklanır; yalnız o kullanılsaydı "oy ver → unstake"
            // yapan artık sahip olmadığı sermayeyle katılırdı. Ağırlık GÜNCEL
            // `staked_balance` ile sınırlanır: yalnız azaltır, asla artırmaz.
            let live_staked = state
                .get_account(&addr)?
                .map(|a| a.staked_balance)
                .unwrap_or(0);
            let w = w.min(live_staked).min(cap);
            if support {
                yes_w = yes_w.saturating_add(w)
            } else {
                no_w = no_w.saturating_add(w)
            }
        }
    }
    let participation = yes_w.saturating_add(no_w);
    let quorum_ok = participation.saturating_mul(10_000)
        >= total_staked.saturating_mul(staker_quorum_bps as u128);
    Ok((
        quorum_ok && yes_w > no_w,
        quorum_ok,
        participation,
        yes_w,
        no_w,
    ))
}

fn proposal_state_key(pid: &Hash) -> String {
    format!("Proposal_{}", hex::encode(pid))
}

/// State-yalnız öneri okuma (epoch yolu `&dyn State` ile çalışır; Executor
/// kurulamaz). Tipli listede yalnız V3 kayıtlar beklenir; legacy(V1) tespit
/// edilirse tutarsızlıktır, None döner, çağıran listeden düşürür.
fn load_proposal_state(state: &dyn State, pid: &Hash) -> Result<Option<Proposal>> {
    match state.get_account(&proposal_state_key(pid))? {
        Some(acc) if !acc.contract_code.is_empty() => {
            match Proposal::deserialize_detecting_legacy(&acc.contract_code) {
                Ok((p, _legacy)) => Ok(Some(p)),
                Err(e) => Err(ZagrosError::Other(format!("gov oneri decode: {e}"))),
            }
        }
        _ => Ok(None),
    }
}

fn save_proposal_state(state: &dyn State, proposal: &Proposal) -> Result<()> {
    let bytes = bincode::serialize(proposal)
        .map_err(|e| ZagrosError::Other(format!("gov oneri encode: {e}")))?;
    let mut acc = state
        .get_account(&proposal_state_key(&proposal.proposal_id))?
        .unwrap_or_default();
    acc.contract_code = bytes;
    state.set_account(&proposal_state_key(&proposal.proposal_id), acc)
}

const ACTIVE_PROPOSAL_COUNT_KEY: &str = "__ACTIVE_PROPOSAL_COUNT__";

fn decrement_active_count(state: &dyn State) -> Result<()> {
    let key = ACTIVE_PROPOSAL_COUNT_KEY.to_string();
    let mut acc = state.get_account(&key)?.unwrap_or_default();
    acc.balance = acc.balance.saturating_sub(1);
    state.set_account(&key, acc)
}

fn terminalize(state: &dyn State, proposal: &mut Proposal, status: ProposalStatus) -> Result<()> {
    proposal.status = status;
    save_proposal_state(state, proposal)?;
    remove_typed_active(state, &proposal.proposal_id)?;
    decrement_active_count(state)
}

/// Epoch sınırı işleyicisi (mikro-karar (b)): sayım + kuyruk + yürütme.
/// `advance_epoch_if_due` içinden, YENİ küme kesinleştikten sonra ve G10
/// aktivasyonundan ÖNCE çağrılır (aynı deterministik blok yürütmesinde).
pub fn process_at_epoch(
    state: &dyn State,
    current_epoch: u64,
    set: &ActiveValidatorSet,
) -> Result<()> {
    let list = load_typed_active(state)?;
    if list.is_empty() {
        return Ok(());
    }
    let params = params::load_chain_params(state)?;
    for pid in list {
        let Some(mut proposal) = load_proposal_state(state, &pid)? else {
            remove_typed_active(state, &pid)?;
            continue;
        };
        match proposal.status {
            ProposalStatus::Active if current_epoch >= proposal.voting_ends_at_epoch => {
                let (yes, voted, n) = validator_tally(state, &pid, set)?;
                if proposal.action == ProposalAction::Text {
                    // Kapı sonrası metin (sinyal) önerisi: listeye YALNIZ depozito
                    // sayımı için girer. Durumu eskisi gibi tembel (`effective_
                    // status`) hesaplanır, aktif sayaç da eskisi gibi kalır,
                    // burada yalnız yeter sayıya bakılıp depozito sonuçlandırılır.
                    let (_, quorum_ok, part, _, _) =
                        staker_tally(state, &pid, params.vote_cap_bps, params.staker_quorum_bps)?;
                    let amount = settle_deposit(state, &proposal, quorum_ok)?;
                    tracing::info!(
                        "🗳️📝 Metin öneri depozito sayımı 0x{}: katılım={} yeter sayı={} → {} ({} ham)",
                        hex::encode(&pid[..6]), part, quorum_ok, if quorum_ok { "iade" } else { "Hevsel" }, amount
                    );
                    remove_typed_active(state, &pid)?;
                    continue;
                }
                let channel = proposal.action.channel()?.ok_or_else(|| {
                    ZagrosError::Other("tipli listede Text oneri (tutarsizlik)".into())
                })?;
                let is_upgrade = matches!(proposal.action, ProposalAction::ScheduleUpgrade { .. });
                // Consensus eşiği: 3·yes ≥ 2·N; ScheduleUpgrade: 5·yes ≥ 4·N (%80).
                let validators_ok = if is_upgrade {
                    5 * yes >= 4 * n
                } else {
                    3 * yes >= 2 * n
                };
                // Depozito yeter sayısı (her iki kanalda staker_quorum_bps, %20):
                // consensus kanalında oy kullanan doğrulayıcı oranı, economic
                // kanalında staker katılım ağırlığı.
                let (accepted, quorum_reached) = match channel {
                    GovChannel::Consensus => (
                        validators_ok,
                        n > 0
                            && (voted as u128).saturating_mul(10_000)
                                >= (n as u128).saturating_mul(params.staker_quorum_bps as u128),
                    ),
                    GovChannel::Economic => {
                        let (stakers_ok, quorum_ok, part, yw, nw) = staker_tally(
                            state,
                            &pid,
                            params.vote_cap_bps,
                            params.staker_quorum_bps,
                        )?;
                        tracing::info!(
                            "🗳️ Economic sayım 0x{}: validator {}/{}, staker katılım={} evet={} hayır={} → {}",
                            hex::encode(&pid[..6]), yes, n, part, yw, nw, stakers_ok && validators_ok
                        );
                        (validators_ok && stakers_ok, quorum_ok)
                    }
                };
                if accepted {
                    proposal.status = ProposalStatus::Queued;
                    proposal.executes_at_epoch =
                        current_epoch.saturating_add(params.timelock_epochs as u64);
                    save_proposal_state(state, &proposal)?;
                    // Kabul = yeter sayı sağlandı: depozito hemen iade (yürütme
                    // sonucunu beklemez; timelock'ta başarısız yürütme önericinin
                    // kusuru değildir).
                    settle_deposit(state, &proposal, true)?;
                    tracing::info!(
                        "🗳️✅ Öneri KABUL (kanal {:?}, {}/{}): 0x{} → epoch {}'te yürütülecek",
                        channel,
                        yes,
                        n,
                        hex::encode(&pid[..6]),
                        proposal.executes_at_epoch
                    );
                } else {
                    tracing::info!(
                        "🗳️❌ Öneri RED ({}/{}, yeter sayı: {}): 0x{}",
                        yes,
                        n,
                        quorum_reached,
                        hex::encode(&pid[..6])
                    );
                    settle_deposit(state, &proposal, quorum_reached)?;
                    terminalize(state, &mut proposal, ProposalStatus::Rejected)?;
                }
            }
            ProposalStatus::Queued if current_epoch >= proposal.executes_at_epoch => {
                let outcome = execute(state, current_epoch, &proposal);
                match outcome {
                    Ok(()) => {
                        tracing::info!("🗳️⚙️ Öneri YÜRÜTÜLDÜ: 0x{}", hex::encode(&pid[..6]));
                        terminalize(state, &mut proposal, ProposalStatus::Executed)?;
                    }
                    Err(e) => {
                        // Fail-closed: yürütme anında sınırlar tutmuyorsa (örn.
                        // bu arada başka bir yama parametreyi değiştirdi) öneri
                        // sessizce yarım uygulanmaz — Rejected + açık log.
                        tracing::warn!(
                            "🗳️🛑 Öneri yürütülemedi (Rejected): 0x{} — {e:?}",
                            hex::encode(&pid[..6])
                        );
                        terminalize(state, &mut proposal, ProposalStatus::Rejected)?;
                    }
                }
            }
            ProposalStatus::Vetoed | ProposalStatus::Rejected | ProposalStatus::Executed => {
                remove_typed_active(state, &pid)?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn execute(state: &dyn State, current_epoch: u64, proposal: &Proposal) -> Result<()> {
    match &proposal.action {
        ProposalAction::Text => Err(ZagrosError::Other("Text oneri yurutulemez".into())),
        ProposalAction::ParamChange(updates) => {
            let base = params::load_chain_params(state)?;
            let grace = params::load_qc_grace_ms(state)?;
            let (next, next_grace) =
                zagros_types::consensus::apply_param_updates_with_grace(&base, grace, updates)?;
            params::store_chain_params(state, &next)?;
            if next_grace != grace {
                params::store_qc_grace_ms(state, next_grace)?;
            }
            Ok(())
        }
        ProposalAction::ScheduleUpgrade {
            target_ruleset,
            binary_sha256,
            activation_epoch,
        } => {
            if *activation_epoch <= current_epoch {
                return Err(ZagrosError::Other(format!(
                    "activation_epoch {activation_epoch} gecmiste (şu an {current_epoch})"
                )));
            }
            params::store_scheduled_upgrade(
                state,
                &zagros_types::consensus::ScheduledUpgrade {
                    target_ruleset: *target_ruleset,
                    binary_sha256: *binary_sha256,
                    activation_epoch: *activation_epoch,
                },
            )
        }
        ProposalAction::ShortenAdminAuthority { end_timestamp } => {
            // Yalnızca kısaltır; uzatma girişimi `shorten_admin_authority`
            // içinde reddedilir (tek doğruluk kaynağı orada).
            params::shorten_admin_authority(state, *end_timestamp as u128)
        }
        // 🗳️ Faz B: Faz A'nın admin yolundaki AYNI fonksiyonlar çağrılır, yalnız
        // karar veren değişir. 🚨 Kontroller burada tekrarlanmaz ("birinde var, ötekinde yok" hatası).
        ProposalAction::ApproveValidator { target } => {
            crate::validator_set::apply_admin_approve(state, target, current_epoch)
        }
        ProposalAction::RemoveValidator { target } => {
            // `now_secs`: bond kilidi bu ana göre kurulur. Epoch başlangıcı
            // yeterince doğru bir zaman kaynağıdır ve DETERMİNİSTİKTİR —
            // gerçek duvar saati düğümden düğüme değişir, state_root ayrışırdı.
            let genesis_ts = params::genesis_timestamp(state)?;
            let p = params::load_chain_params(state)?;
            let now_secs = genesis_ts
                .saturating_add((current_epoch as u128).saturating_mul(p.epoch_seconds as u128));
            crate::validator_set::apply_admin_remove(state, target, now_secs, current_epoch)
        }
    }
}

/// Faz A 3-of-5 vetosu (imza doğrulaması çağıranda, validator_set admin yolu).
/// Yalnız CONSENSUS kanalı + Active/Queued tipli öneriler vetolanabilir.
pub fn apply_veto(state: &dyn State, target: &str) -> Result<()> {
    let hex_part = target.strip_prefix("0x").unwrap_or(target);
    let bytes = hex::decode(hex_part)
        .map_err(|e| ZagrosError::Other(format!("veto hedefi hex degil: {e}")))?;
    let pid: Hash = bytes
        .try_into()
        .map_err(|_| ZagrosError::Other("veto hedefi 32 bayt olmali".into()))?;
    let mut proposal = load_proposal_state(state, &pid)?
        .ok_or_else(|| ZagrosError::Other("veto: oneri yok".into()))?;
    let channel = proposal
        .action
        .channel()?
        .ok_or_else(|| ZagrosError::Other("veto: Text oneriye veto yok (legacy)".into()))?;
    if channel != GovChannel::Consensus {
        return Err(ZagrosError::Other(
            "veto yalniz consensus kanalinda (economic staker iradesine birakilir)".into(),
        ));
    }
    if !matches!(
        proposal.status,
        ProposalStatus::Active | ProposalStatus::Queued
    ) {
        return Err(ZagrosError::Other(format!(
            "veto: durum uygun degil ({})",
            proposal.status
        )));
    }
    // Veto = spam/zarar kararı: depozito (varsa) Hevsel'e (Cosmos'taki
    // "NoWithVeto → depozito yakılır" karşılığı; burada yakılmaz, dağıtılır).
    settle_deposit(state, &proposal, false)?;
    terminalize(state, &mut proposal, ProposalStatus::Vetoed)?;
    tracing::warn!(
        "🗳️🛡️ Öneri VETOLANDI (Faz A 3-of-5): 0x{}",
        hex::encode(&pid[..6])
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use zagros_types::AccountState;

    #[derive(Default)]
    struct MemoryStorage {
        values: std::sync::Mutex<std::collections::HashMap<Vec<u8>, Vec<u8>>>,
    }

    impl zagros_storage::Storage for MemoryStorage {
        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
            Ok(self.values.lock().unwrap().get(key).cloned())
        }
        fn put(&self, key: &[u8], value: &[u8]) -> Result<()> {
            self.values
                .lock()
                .unwrap()
                .insert(key.to_vec(), value.to_vec());
            Ok(())
        }
        fn delete(&self, key: &[u8]) -> Result<()> {
            self.values.lock().unwrap().remove(key);
            Ok(())
        }
        fn contains(&self, key: &[u8]) -> Result<bool> {
            Ok(self.values.lock().unwrap().contains_key(key))
        }
        fn list_keys(&self) -> Result<Vec<Vec<u8>>> {
            Ok(self.values.lock().unwrap().keys().cloned().collect())
        }
    }

    impl zagros_storage::StorageEngine for MemoryStorage {
        fn write_batch(&self, kvs: &[(Vec<u8>, Option<Vec<u8>>)]) -> Result<()> {
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
        Arc::new(zagros_state::manager::StateDbManager::new(Arc::new(
            MemoryStorage::default(),
        )))
    }

    fn seed_staker(state: &Arc<dyn State>, addr: &str, staked: u128) {
        let mut acc = AccountState::default();
        acc.staked_balance = staked;
        state.set_account(&addr.to_string(), acc).unwrap();
    }

    fn set_total_staked(state: &Arc<dyn State>, total: u128) {
        let mut acc = AccountState::default();
        acc.balance = total;
        state
            .set_account(&"__GLOBAL_TOTAL_STAKED__".to_string(), acc)
            .unwrap();
    }

    /// 🚨 Regresyon: "oy ver → hemen unstake" ile artık sahip olunmayan sermaye
    /// tam ağırlıkla sayılmamalı.
    #[test]
    fn vote_weight_shrinks_when_the_voter_withdraws_their_stake_after_voting() {
        let state = test_state();
        let pid: Hash = [9u8; 32];
        let yes_voter = "0x00000000000000000000000000000000000000a1";
        let no_voter = "0x00000000000000000000000000000000000000a2";

        set_total_staked(&state, 1_000);
        seed_staker(&state, yes_voter, 600);
        seed_staker(&state, no_voter, 300);

        // Ikisi de o anki teminatlariyla oy verir: evet 600, hayir 300.
        record_vote(state.as_ref(), &pid, yes_voter, true, 600).unwrap();
        record_vote(state.as_ref(), &pid, no_voter, false, 300).unwrap();

        // Tavan yok (%100), quorum dusuk -> saf agirlik karsilastirmasi.
        let (accepted, _quorum, _participation, yes_w, no_w) =
            staker_tally(state.as_ref(), &pid, 10_000, 1).unwrap();
        assert_eq!(yes_w, 600);
        assert_eq!(no_w, 300);
        assert!(accepted, "teminatlar dururken evet kazanmali");

        // "evet" oy veren teminatinin nerdeyse tamamini CEKIYOR.
        seed_staker(&state, yes_voter, 50);

        let (accepted_after, _q, _p, yes_after, no_after) =
            staker_tally(state.as_ref(), &pid, 10_000, 1).unwrap();
        assert_eq!(
            yes_after, 50,
            "cekilen teminat kadar oy agirligi DUSMELI (saklanan 600 degil)"
        );
        assert_eq!(no_after, 300, "teminatini koruyanin agirligi DEGISMEMELI");
        assert!(
            !accepted_after,
            "artik riske atilmis sermaye kalmadigina gore sonuc degismeli"
        );
    }

    /// Ağırlık sınırı TEK YÖNLÜ olmalı: oy verdikten SONRA stake eklemek
    /// ağırlığı BÜYÜTEMEZ (saklanan değer tavan olarak kalır), aksi halde
    /// düşük ağırlıkla oy verip sonuç belli olurken ağırlık yığmak mümkün olurdu.
    #[test]
    fn adding_stake_after_voting_cannot_inflate_the_recorded_weight() {
        let state = test_state();
        let pid: Hash = [8u8; 32];
        let voter = "0x00000000000000000000000000000000000000b1";
        set_total_staked(&state, 1_000);
        seed_staker(&state, voter, 100);
        record_vote(state.as_ref(), &pid, voter, true, 100).unwrap();

        // Oydan SONRA teminati 10 katina cikar.
        seed_staker(&state, voter, 1_000);
        let (_a, _q, _p, yes_w, _n) = staker_tally(state.as_ref(), &pid, 10_000, 1).unwrap();
        assert_eq!(yes_w, 100, "oy sonrasi stake ekleyerek agirlik BUYUTULEMEZ");
    }

    /// Adres tavanı (`vote_cap_bps`) hâlâ uygulanmalı, canlı teminat sınırı
    /// onun YERİNE değil, ONUNLA BİRLİKTE çalışır.
    #[test]
    fn the_per_address_cap_still_applies_on_top_of_the_live_stake_limit() {
        let state = test_state();
        let pid: Hash = [7u8; 32];
        let whale = "0x00000000000000000000000000000000000000c1";
        set_total_staked(&state, 1_000);
        seed_staker(&state, whale, 900);
        record_vote(state.as_ref(), &pid, whale, true, 900).unwrap();

        // Tavan %10 = 100.
        let (_a, _q, _p, yes_w, _n) = staker_tally(state.as_ref(), &pid, 1_000, 1).unwrap();
        assert_eq!(yes_w, 100, "adres tavani uygulanmali");
    }
}
