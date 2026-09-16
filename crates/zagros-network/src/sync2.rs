//! G6, `/zagros/sync/2` QC'li catch-up (§9). Sunucu: konsensüs kaydı (header v2
//! + QC), tx gövdeleri, köprü önerileri; `GetStatus` → tip/epoch/küme hash'i.
//! İstemci (`validate_block`): saf doğrulama, hiçbir alan güvenilir sayılmaz
//! (ardışıklık, başlık, rotasyon, imza, `last_qc`, bloğun QC'si, gövde, checkpoint).
//! Yeniden yürütme kök eşitliği `Runtime::commit_block`ta. [INV-Y1] QC'siz commit yolu YOKTUR.

use std::sync::Arc;

use zagros_crypto::{verify_qc, verify_signed_header};
use zagros_executor::bridge::BridgeManager;
use zagros_executor::{params, validator_set};
use zagros_primitives::{Hash, Result, ZagrosError};
use zagros_state::State;
use zagros_types::consensus::{
    block_body_bytes, ActiveValidatorSet, BlockHeaderV2, ChainParams, ConsensusDomain,
    QuorumCertificate, ShadowVoteAttestation, SignedHeader, CONSENSUS_TIP_KEY,
};
use zagros_types::Transaction;

use crate::messages::{Sync2Block, Sync2Request, Sync2Response, Sync2Status};

/// Tek yanıtta taşınacak azami blok (istemci de bu tavanı uygular).
pub const MAX_BLOCKS_PER_RESPONSE: u64 = 512;

/// Spec §9 weak-subjectivity kontrol noktası (çözümlenmiş).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedCheckpoint {
    pub height: u64,
    pub block_hash: Hash,
    pub validator_set_hash: Hash,
}

impl TrustedCheckpoint {
    pub fn from_config(c: &zagros_types::config::TrustedCheckpointConfig) -> Result<Self> {
        fn hex32(s: &str) -> Result<Hash> {
            let s = s.trim().trim_start_matches("0x");
            let bytes = hex::decode(s)
                .map_err(|e| ZagrosError::ConfigError(format!("checkpoint hex: {e}")))?;
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| ZagrosError::ConfigError("checkpoint hash 32 bayt olmali".into()))
        }
        if c.height == 0 {
            return Err(ZagrosError::ConfigError(
                "trusted_checkpoint.height > 0 olmali".into(),
            ));
        }
        Ok(Self {
            height: c.height,
            block_hash: hex32(&c.block_hash)?,
            validator_set_hash: hex32(&c.validator_set_hash)?,
        })
    }
}

// DİSK KAYITLARI

pub type ConsensusRecord = (SignedHeader, QuorumCertificate, Vec<ShadowVoteAttestation>);

pub fn load_consensus_record(state: &dyn State, height: u64) -> Result<Option<ConsensusRecord>> {
    match state.get_account(&zagros_state::consensus_block_key(height))? {
        Some(acc) if !acc.contract_code.is_empty() => bincode::deserialize(&acc.contract_code)
            .map(Some)
            .map_err(|e| {
                ZagrosError::ConfigError(format!("consensus_block_{height} cozulemedi: {e}"))
            }),
        _ => Ok(None),
    }
}

pub fn load_consensus_tip(state: &dyn State) -> Result<Option<ConsensusRecord>> {
    match state.get_account(&CONSENSUS_TIP_KEY.to_string())? {
        Some(acc) if !acc.contract_code.is_empty() => bincode::deserialize(&acc.contract_code)
            .map(Some)
            .map_err(|e| ZagrosError::ConfigError(format!("__CONSENSUS_TIP__ cozulemedi: {e}"))),
        _ => Ok(None),
    }
}

/// Tip sentinel'i + per-height kayıt (ikisi de aynı flush batch'ine girer).
/// `shadow_votes`: bu bloğa gömülü ShadowVote'lar da kayda dahil, G6
/// catch-up (`sync/2`) bloğu yeniden yürütürken AYNI girdiyi (dolayısıyla
/// AYNI `state_root`'u) üretebilsin diye (bkz. `sync2::read_block`).
pub fn store_consensus_records(
    state: &dyn State,
    signed: &SignedHeader,
    qc: &QuorumCertificate,
    shadow_votes: &[ShadowVoteAttestation],
) -> Result<()> {
    let bytes = bincode::serialize(&(signed, qc, shadow_votes))
        .map_err(|e| ZagrosError::Other(format!("consensus record serialize: {e}")))?;
    let tip = zagros_types::AccountState {
        contract_code: bytes.clone(),
        ..Default::default()
    };
    state.set_account(&CONSENSUS_TIP_KEY.to_string(), tip)?;
    let rec = zagros_types::AccountState {
        contract_code: bytes,
        ..Default::default()
    };
    state.set_account(
        &zagros_state::consensus_block_key(signed.header.number),
        rec,
    )
}

// SUNUCU

pub fn build_response(
    state: &Arc<dyn State>,
    request: Sync2Request,
    max_blocks: u64,
) -> Sync2Response {
    match request {
        Sync2Request::GetStatus => {
            let set = match validator_set::load_active_set(state.as_ref()) {
                Ok(s) => s,
                Err(_) => return Sync2Response::NotAvailable,
            };
            let (tip_height, tip_hash) = match load_consensus_tip(state.as_ref()) {
                Ok(Some((sh, _, _))) => (sh.header.number, sh.header.hash()),
                _ => (0, [0u8; 32]),
            };
            Sync2Response::Status(Sync2Status {
                tip_height,
                tip_hash,
                epoch: set.epoch,
                validator_set_hash: set.hash(),
            })
        }
        Sync2Request::GetBlockRange { from, to } => {
            if from == 0 || to < from {
                return Sync2Response::NotAvailable;
            }
            let cap = max_blocks.clamp(1, MAX_BLOCKS_PER_RESPONSE);
            let clamped_to = to.min(from.saturating_add(cap - 1));
            let mut blocks = Vec::new();
            for height in from..=clamped_to {
                match read_block_tolerant(state, height) {
                    Some(b) => blocks.push(b),
                    None => break, // boşluklu dizi dönülmez
                }
            }
            if blocks.is_empty() {
                Sync2Response::NotAvailable
            } else if blocks.iter().all(|b| b.missing.is_empty()) {
                Sync2Response::Blocks(blocks.into_iter().map(|b| b.block).collect())
            } else {
                Sync2Response::BlocksV2(blocks)
            }
        }
    }
}

/// 🚨 (ana ağ, blok 2878): yürütmede düşen işlemlerin gövdesi
/// arşivlenmediği (F düzeltmesi öncesi) bloklar `None` dönüyor, o bloğu kaçıran
/// node sonsuza dek takılıyordu. Artık gövdesi olmayan işlemler `missing`
/// listesiyle (sıra, id) bildirilir; alıcı doğruluğu state_root ile kanıtlar.
pub fn read_block_tolerant(
    state: &Arc<dyn State>,
    height: u64,
) -> Option<crate::messages::Sync2BlockV2> {
    let (signed, qc, shadow_votes) = load_consensus_record(state.as_ref(), height)
        .ok()
        .flatten()?;
    // Gövde: `ArchivedBlockHeader.tx_hashes` sırası = yürütme sırası.
    let archived_acc = state
        .get_account(&zagros_state::block_key(height))
        .ok()
        .flatten()?;
    let archived: zagros_types::ArchivedBlockHeader =
        bincode::deserialize(&archived_acc.contract_code).ok()?;
    let mut transactions = Vec::with_capacity(archived.tx_hashes.len());
    let mut missing = Vec::new();
    for (i, tx_id) in archived.tx_hashes.iter().enumerate() {
        let body = state
            .get_account(&zagros_state::tx_body_key(tx_id))
            .ok()
            .flatten()
            .filter(|a| !a.contract_code.is_empty())
            .and_then(|a| Transaction::from_stored_bytes(&a.contract_code).ok());
        match body {
            Some(tx) => transactions.push(tx),
            None => missing.push((i as u32, *tx_id)),
        }
    }
    let bridge_proposals =
        BridgeManager::collect_proposals_for_relay(state.as_ref(), &transactions);
    Some(crate::messages::Sync2BlockV2 {
        block: Sync2Block {
            signed,
            qc,
            transactions,
            bridge_proposals,
            shadow_votes,
        },
        missing,
    })
}

/// Mevcut gövdelerin id'leri ile eksik (sıra, id) listesini header sırasına göre
/// birleştirir. Sıra çakışırsa/dışarı taşarsa `None` (bozuk yanıt).
pub fn merged_tx_ids(present: &[Transaction], missing: &[(u32, Hash)]) -> Option<Vec<Hash>> {
    let total = present.len() + missing.len();
    let mut out: Vec<Option<Hash>> = vec![None; total];
    for (i, id) in missing {
        let slot = out.get_mut(*i as usize)?;
        if slot.is_some() {
            return None;
        }
        *slot = Some(*id);
    }
    let mut it = present.iter();
    for slot in out.iter_mut() {
        if slot.is_none() {
            *slot = Some(it.next()?.tx_id);
        }
    }
    if it.next().is_some() {
        return None;
    }
    out.into_iter().collect()
}

// İSTEMCİ DOĞRULAMASI (saf)

pub struct SyncContext<'a> {
    pub domain: &'a ConsensusDomain,
    pub params: &'a ChainParams,
    /// Bu yükseklikte geçerli küme (bloğun QC'si buna karşı).
    pub set: &'a ActiveValidatorSet,
    /// Tip'in kümesi (`last_qc` buna karşı).
    pub tip_set: &'a ActiveValidatorSet,
    pub tip_height: u64,
    pub tip_hash: Hash,
    /// Tip'in zaman damgası, §7 monotonluk kontrolü için (bkz.
    /// `validate_block`'taki zaman damgası bloğu).
    pub tip_timestamp_ms: u64,
    /// Doğrulayan node'un ŞU ANKİ duvar saati (ms). Fonksiyonun saf kalması
    /// için saat çağırandan gelir, `validate_block` kendi başına saat okumaz.
    pub now_ms: u64,
    pub checkpoint: Option<&'a TrustedCheckpoint>,
}

pub fn validate_block(ctx: &SyncContext<'_>, block: &Sync2Block) -> Result<()> {
    validate_block_with_missing(ctx, block, &[])
}

/// `validate_block` + gövdesi eksik işlemler (bkz. `Sync2BlockV2`): tx_count ve
/// tx_root birleşik id listesinden; `body_bytes` eksikler bilinmediği için
/// yalnız tavanla sınırlanır (kesin eşitlik yalnız eksiksiz blokta).
pub fn validate_block_with_missing(
    ctx: &SyncContext<'_>,
    block: &Sync2Block,
    missing: &[(u32, Hash)],
) -> Result<()> {
    let h = &block.signed.header;
    let err = |m: String| Err(ZagrosError::Other(format!("sync2 blok #{}: {m}", h.number)));
    h.validate_structure(ctx.params)?;
    if h.number != ctx.tip_height + 1 {
        return err(format!("ardisik degil (tip {})", ctx.tip_height));
    }
    if h.parent_hash != ctx.tip_hash {
        return err("parent_hash tip ile uyusmuyor (missing parent / fork)".into());
    }
    // 🛡️ §7 zaman damgası kuralı canlı BFT yoluyla AYNI: yalnız bir yolda
    // uygulansaydı senkronize olan node canlı ağın reddedeceği başlığı kabul
    // ederdi; epoch, ödül olgunlaşması, jail ve köprü kilidi bu alandan türer.
    if h.timestamp_ms <= ctx.tip_timestamp_ms {
        return err(format!(
            "zaman damgasi monoton degil ({} <= ebeveyn {})",
            h.timestamp_ms, ctx.tip_timestamp_ms
        ));
    }
    if h.timestamp_ms > ctx.now_ms.saturating_add(ctx.params.max_clock_skew_ms) {
        return err(format!(
            "zaman damgasi gelecekte ({} > simdi {} + skew {})",
            h.timestamp_ms, ctx.now_ms, ctx.params.max_clock_skew_ms
        ));
    }
    let n = ctx.set.len() as u64;
    if n == 0 {
        return err("aktif kume bos".into());
    }
    if h.proposer_idx as u64 != (h.number + h.round as u64) % n {
        return err("proposer_idx rotasyonla uyusmuyor".into());
    }
    verify_signed_header(&block.signed, ctx.domain, ctx.set)?;
    match (&h.last_qc, ctx.tip_height) {
        (None, 0) => {}
        (Some(qc), _) => {
            if qc.height != ctx.tip_height || qc.block_hash != ctx.tip_hash {
                return err("last_qc tip ile uyusmuyor".into());
            }
            verify_qc(qc, ctx.domain, ctx.tip_set)?;
        }
        (None, _) => return err("genesis disinda last_qc zorunlu".into()),
    }
    // Bloğun KENDİ QC'si: zorunlu, bu kümeye karşı, hash = header.hash()
    let qc = &block.qc;
    if qc.height != h.number {
        return err(format!("QC yuksekligi {} != {}", qc.height, h.number));
    }
    if qc.block_hash != h.hash() {
        return err("QC.block_hash != header.hash()".into());
    }
    if qc.epoch != h.epoch || h.validator_set_hash != ctx.set.hash() {
        return err("QC/baslik epoch ya da kume hash'i uyusmuyor".into());
    }
    verify_qc(qc, ctx.domain, ctx.set)?;
    // Gövde
    if h.tx_count as usize != block.transactions.len() + missing.len() {
        return err("tx_count govdeyle uyusmuyor".into());
    }
    let Some(ids) = merged_tx_ids(&block.transactions, missing) else {
        return err("eksik islem listesi bozuk (sira cakisiyor/tasiyor)".into());
    };
    if h.tx_root != BlockHeaderV2::compute_tx_root(&ids) {
        return err("tx_root govdeyle uyusmuyor".into());
    }
    let bytes = block_body_bytes(&block.transactions);
    if missing.is_empty() {
        if bytes != h.body_bytes as u64 || bytes > ctx.params.max_block_bytes {
            return err(format!(
                "body_bytes {} / gercek {} / tavan {}",
                h.body_bytes, bytes, ctx.params.max_block_bytes
            ));
        }
    } else if bytes > h.body_bytes as u64 || h.body_bytes as u64 > ctx.params.max_block_bytes {
        return err(format!(
            "body_bytes {} / mevcut govde {} / tavan {} (eksik govdeli blok)",
            h.body_bytes, bytes, ctx.params.max_block_bytes
        ));
    }
    if block
        .transactions
        .iter()
        .any(|t| t.chain_id != zagros_types::CHAIN_ID)
    {
        return err("yabanci chain_id'li tx".into());
    }
    if let Some(cp) = ctx.checkpoint {
        if cp.height == h.number
            && (cp.block_hash != h.hash() || cp.validator_set_hash != h.validator_set_hash)
        {
            return Err(ZagrosError::Other(format!(
                "sync2 blok #{}: GUVENILIR CHECKPOINT UYUSMAZLIGI (long-range / sahte zincir) — node durmali",
                h.number
            )));
        }
    }
    Ok(())
}

/// Bir yanıttaki blok listesinin sınır kontrolü (sayı, ilk yükseklik).
pub fn validate_batch_shape(
    blocks: &[Sync2Block],
    expected_first: u64,
    max_blocks: u64,
) -> Result<()> {
    if blocks.is_empty() {
        return Err(ZagrosError::Other("sync2: bos blok listesi".into()));
    }
    if blocks.len() as u64 > max_blocks.clamp(1, MAX_BLOCKS_PER_RESPONSE) {
        return Err(ZagrosError::Other(format!(
            "sync2: {} blok > tavan",
            blocks.len()
        )));
    }
    if blocks[0].signed.header.number != expected_first {
        return Err(ZagrosError::Other(format!(
            "sync2: ilk blok {} != beklenen {}",
            blocks[0].signed.header.number, expected_first
        )));
    }
    Ok(())
}

/// Sürücü için: state'ten (domain, params, set) yükler.
pub fn load_chain_context(
    state: &dyn State,
) -> Result<(ConsensusDomain, ChainParams, ActiveValidatorSet)> {
    Ok((
        params::consensus_domain(state)?,
        params::load_chain_params(state)?,
        validator_set::load_active_set(state)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::Sync2Block;
    use zagros_consensus::engine::{
        BftEngine, BlockVerifier, ChainTip, Message, NodeIdentity, Output,
    };
    use zagros_crypto::{build_qc, sign_vote, ConsensusKeypair};
    use zagros_executor::bridge::BridgeProposal;
    use zagros_types::consensus::{ValidatorMember, Vote, VotePhase};
    use zagros_types::CHAIN_ID;

    struct FakeVerifier;
    impl BlockVerifier for FakeVerifier {
        fn simulate(
            &self,
            h: &BlockHeaderV2,
            _t: &[Transaction],
            _b: &[BridgeProposal],
            _sv: &[ShadowVoteAttestation],
        ) -> Result<Hash> {
            Ok(h.parent_hash)
        }
    }
    fn kps() -> Vec<ConsensusKeypair> {
        (0..4u8)
            .map(|i| ConsensusKeypair::from_secret_bytes(&[i + 1; 32]))
            .collect()
    }
    fn set(kps: &[ConsensusKeypair]) -> ActiveValidatorSet {
        ActiveValidatorSet {
            epoch: 0,
            members: kps
                .iter()
                .enumerate()
                .map(|(i, k)| ValidatorMember {
                    address: format!("0x{:040x}", i + 1),
                    consensus_pubkey: k.public_key(),
                })
                .collect(),
        }
    }
    fn domain() -> ConsensusDomain {
        ConsensusDomain::new(CHAIN_ID, [7u8; 32])
    }
    /// Gerçek motorla h=1 önerisi + Q precommit'ten QC → geçerli Sync2Block.
    fn genuine_block(kps: &[ConsensusKeypair]) -> (Sync2Block, ChainTip) {
        let s = set(kps);
        let tip = ChainTip {
            height: 0,
            hash: [9; 32],
            qc: None,
            timestamp_ms: 0,
        };
        let mut e = BftEngine::new(
            domain(),
            ChainParams::genesis_defaults(),
            s.clone(),
            Some(NodeIdentity {
                idx: 1,
                keypair: ConsensusKeypair::from_secret_bytes(&kps[1].secret_bytes()),
            }),
            tip.clone(),
            None,
        )
        .unwrap();
        e.start(1_000, &FakeVerifier);
        let outs = e
            .propose(1_500, vec![], vec![], vec![], &FakeVerifier)
            .unwrap();
        let p = outs
            .iter()
            .find_map(|o| match o {
                Output::Broadcast(Message::Proposal(p)) => Some((**p).clone()),
                _ => None,
            })
            .unwrap();
        let hash = p.block_hash();
        let votes: Vec<Vote> = (0..3)
            .map(|i| {
                let mut v = Vote {
                    height: 1,
                    round: 0,
                    phase: VotePhase::Precommit,
                    block_hash: hash,
                    validator_idx: i as u16,
                    shadow: false,
                    sig: vec![],
                };
                sign_vote(&kps[i], &domain(), 0, &mut v);
                v
            })
            .collect();
        let qc = build_qc(&votes, &domain(), &s, 1, 0, hash).unwrap();
        (
            Sync2Block {
                signed: p.signed,
                qc,
                transactions: vec![],
                bridge_proposals: vec![],
                shadow_votes: vec![],
            },
            tip,
        )
    }
    fn ctx<'a>(
        s: &'a ActiveValidatorSet,
        tip: &'a ChainTip,
        d: &'a ConsensusDomain,
        p: &'a ChainParams,
        cp: Option<&'a TrustedCheckpoint>,
    ) -> SyncContext<'a> {
        SyncContext {
            domain: d,
            params: p,
            set: s,
            tip_set: s,
            tip_height: tip.height,
            tip_hash: tip.hash,
            tip_timestamp_ms: tip.timestamp_ms,
            // Testlerde saat "cok ileride" kabul edilir: amac zaman damgasi
            // kontrolunu degil, diger kurallari olcmek (zaman damgasinin
            // KENDI testleri ayrica var).
            now_ms: u64::MAX / 2,
            checkpoint: cp,
        }
    }

    fn tx_for_test(seed: u8) -> Transaction {
        let key = secp256k1::SecretKey::from_slice(&[seed; 32]).unwrap();
        let mut tx = Transaction {
            tx_id: [seed; 32],
            tx_type: zagros_types::TxType::Transfer,
            sender: Transaction::address_from_secret_key(&key),
            receiver: "0x2222222222222222222222222222222222222222".to_string(),
            amount: 1,
            payload: Vec::new(),
            signature: Vec::new(),
            timestamp: 1,
            nonce: 0,
            gas_limit: 1,
            gas_price: 1,
            chain_id: CHAIN_ID,
        };
        tx.sign(&key);
        tx
    }

    /// İki işlemli gerçek blok (QC'li), eksik-gövde testleri için.
    fn genuine_block_with_txs(
        kps: &[ConsensusKeypair],
        txs: Vec<Transaction>,
    ) -> (Sync2Block, ChainTip) {
        let s = set(kps);
        let tip = ChainTip {
            height: 0,
            hash: [9; 32],
            qc: None,
            timestamp_ms: 0,
        };
        let mut e = BftEngine::new(
            domain(),
            ChainParams::genesis_defaults(),
            s.clone(),
            Some(NodeIdentity {
                idx: 1,
                keypair: ConsensusKeypair::from_secret_bytes(&kps[1].secret_bytes()),
            }),
            tip.clone(),
            None,
        )
        .unwrap();
        e.start(1_000, &FakeVerifier);
        let outs = e
            .propose(1_500, txs.clone(), vec![], vec![], &FakeVerifier)
            .unwrap();
        let p = outs
            .iter()
            .find_map(|o| match o {
                Output::Broadcast(Message::Proposal(p)) => Some((**p).clone()),
                _ => None,
            })
            .unwrap();
        let hash = p.block_hash();
        let votes: Vec<Vote> = (0..3)
            .map(|i| {
                let mut v = Vote {
                    height: 1,
                    round: 0,
                    phase: VotePhase::Precommit,
                    block_hash: hash,
                    validator_idx: i as u16,
                    shadow: false,
                    sig: vec![],
                };
                sign_vote(&kps[i], &domain(), 0, &mut v);
                v
            })
            .collect();
        let qc = build_qc(&votes, &domain(), &s, 1, 0, hash).unwrap();
        (
            Sync2Block {
                signed: p.signed,
                qc,
                transactions: txs,
                bridge_proposals: vec![],
                shadow_votes: vec![],
            },
            tip,
        )
    }

    /// 🚨 (blok 2878): gövdesi eksik işlemli blok, birleşik id listesiyle
    /// tx_root/tx_count doğrulanır, body_bytes yalnız tavanla sınırlanır; eksik id/sıra
    /// oynanırsa reddedilir; eksiksiz blokta kesin body_bytes eşitliği korunur.
    #[test]
    fn a_block_with_missing_tx_bodies_validates_via_merged_ids_and_rejects_tampering() {
        let k = kps();
        let s = set(&k);
        let d = domain();
        let p = ChainParams::genesis_defaults();
        let (t0, t1, t2) = (tx_for_test(11), tx_for_test(12), tx_for_test(13));
        let (full, tip) = genuine_block_with_txs(&k, vec![t0.clone(), t1.clone(), t2.clone()]);
        let c = ctx(&s, &tip, &d, &p, None);
        assert!(validate_block(&c, &full).is_ok(), "eksiksiz blok");

        // Ortadaki gövde yok → present [t0, t2], missing [(1, t1.id)]
        let mut partial = full.clone();
        partial.transactions = vec![t0.clone(), t2.clone()];
        let missing = vec![(1u32, t1.tx_id)];
        assert!(
            validate_block_with_missing(&c, &partial, &missing).is_ok(),
            "eksik gövdeli blok birleşik id ile geçmeli"
        );
        assert_eq!(
            merged_tx_ids(&partial.transactions, &missing).unwrap(),
            vec![t0.tx_id, t1.tx_id, t2.tx_id]
        );

        // Eski (eksiksiz) doğrulama aynı gövdeyi reddeder (tx_count uyuşmaz)
        assert!(validate_block(&c, &partial).is_err());
        // Yanlış id → tx_root uyuşmaz
        assert!(validate_block_with_missing(&c, &partial, &[(1u32, [0xEE; 32])]).is_err());
        // Yanlış sıra → tx_root uyuşmaz
        assert!(validate_block_with_missing(&c, &partial, &[(0u32, t1.tx_id)]).is_err());
        // Sıra çakışması/taşma → bozuk liste
        assert!(merged_tx_ids(&partial.transactions, &[(5u32, t1.tx_id)]).is_none());
        // Eksik listesiyle FAZLA gövde (tx_count'u aşan) → ret
        let mut too_many = full.clone();
        too_many.transactions = vec![t0.clone(), t1.clone(), t2.clone()];
        assert!(validate_block_with_missing(&c, &too_many, &missing).is_err());
    }

    #[test]
    fn genuine_block_validates_and_each_tampering_is_rejected() {
        let k = kps();
        let s = set(&k);
        let d = domain();
        let p = ChainParams::genesis_defaults();
        let (block, tip) = genuine_block(&k);
        validate_block(&ctx(&s, &tip, &d, &p, None), &block).unwrap();

        // Sahte QC: imzalar başka anahtarla
        let mut bad = block.clone();
        let forged = ConsensusKeypair::from_secret_bytes(&[77; 32]);
        let mut v = Vote {
            height: 1,
            round: 0,
            phase: VotePhase::Precommit,
            block_hash: block.signed.header.hash(),
            validator_idx: 0,
            shadow: false,
            sig: vec![],
        };
        sign_vote(&forged, &d, 0, &mut v);
        bad.qc.sigs[0] = v.sig;
        assert!(
            validate_block(&ctx(&s, &tip, &d, &p, None), &bad).is_err(),
            "sahte QC imzasi"
        );
        // QC quorum altı (2 imza)
        let mut bad = block.clone();
        bad.qc.sigs.pop();
        bad.qc.signers = vec![0b0000_0011];
        assert!(
            validate_block(&ctx(&s, &tip, &d, &p, None), &bad).is_err(),
            "quorum alti QC"
        );
        // QC başka bloğa ait
        let mut bad = block.clone();
        bad.qc.block_hash = [3; 32];
        assert!(validate_block(&ctx(&s, &tip, &d, &p, None), &bad).is_err());
        // Ardışık değil / parent yanlış
        let tip2 = ChainTip {
            height: 1,
            hash: [1; 32],
            qc: None,
            timestamp_ms: 0,
        };
        assert!(
            validate_block(&ctx(&s, &tip2, &d, &p, None), &block).is_err(),
            "missing parent"
        );
        let tip3 = ChainTip {
            height: 0,
            hash: [8; 32],
            qc: None,
            timestamp_ms: 0,
        };
        assert!(
            validate_block(&ctx(&s, &tip3, &d, &p, None), &block).is_err(),
            "parent hash"
        );
        // Gövde: tx eklenmiş (tx_count/tx_root uyuşmaz)
        let mut bad = block.clone();
        bad.transactions.push(Transaction {
            tx_id: [5; 32],
            tx_type: zagros_types::TxType::Transfer,
            sender: "0x1".into(),
            receiver: "0x2".into(),
            amount: 1,
            payload: vec![],
            signature: vec![],
            timestamp: 1,
            nonce: 0,
            gas_limit: 1,
            gas_price: 1,
            chain_id: CHAIN_ID,
        });
        assert!(
            validate_block(&ctx(&s, &tip, &d, &p, None), &bad).is_err(),
            "govde uyusmazligi"
        );
        // Başlık imzası bozuk
        let mut bad = block.clone();
        bad.signed.sig[0] ^= 1;
        assert!(
            validate_block(&ctx(&s, &tip, &d, &p, None), &bad).is_err(),
            "baslik imzasi"
        );
        // Yanlış domain (başka genesis)
        let d2 = ConsensusDomain::new(CHAIN_ID, [8; 32]);
        assert!(
            validate_block(&ctx(&s, &tip, &d2, &p, None), &block).is_err(),
            "domain ayrimi"
        );
        // Checkpoint uyuşmazlığı
        let cp = TrustedCheckpoint {
            height: 1,
            block_hash: [0xCC; 32],
            validator_set_hash: s.hash(),
        };
        let e = validate_block(&ctx(&s, &tip, &d, &p, Some(&cp)), &block).unwrap_err();
        assert!(format!("{e:?}").contains("CHECKPOINT"));
        let cp_ok = TrustedCheckpoint {
            height: 1,
            block_hash: block.signed.header.hash(),
            validator_set_hash: s.hash(),
        };
        validate_block(&ctx(&s, &tip, &d, &p, Some(&cp_ok)), &block).unwrap();
    }

    #[test]
    fn batch_shape_is_bounded_and_contiguous() {
        let k = kps();
        let (block, _) = genuine_block(&k);
        assert!(validate_batch_shape(&[], 1, 10).is_err());
        assert!(
            validate_batch_shape(std::slice::from_ref(&block), 2, 10).is_err(),
            "ilk blok beklenen degil"
        );
        validate_batch_shape(std::slice::from_ref(&block), 1, 10).unwrap();
        let many: Vec<_> = (0..3).map(|_| block.clone()).collect();
        assert!(validate_batch_shape(&many, 1, 2).is_err(), "tavan asimi");
    }

    #[test]
    fn checkpoint_config_parsing_is_strict() {
        use zagros_types::config::TrustedCheckpointConfig;
        let ok = TrustedCheckpointConfig {
            height: 5,
            block_hash: format!("0x{}", "ab".repeat(32)),
            validator_set_hash: "cd".repeat(32),
        };
        assert!(TrustedCheckpoint::from_config(&ok).is_ok());
        let bad = TrustedCheckpointConfig {
            height: 0,
            ..ok.clone()
        };
        assert!(TrustedCheckpoint::from_config(&bad).is_err());
        let bad = TrustedCheckpointConfig {
            block_hash: "zz".into(),
            ..ok.clone()
        };
        assert!(TrustedCheckpoint::from_config(&bad).is_err());
        let bad = TrustedCheckpointConfig {
            block_hash: "ab".repeat(31),
            ..ok
        };
        assert!(TrustedCheckpoint::from_config(&bad).is_err());
    }

    /// 🚨 Regresyon: §7 zaman damgası kuralı sync2'de de uygulanmalı; aynı başlık
    /// hangi yoldan geldiğine göre farklı kurala tabi olmamalı.
    #[test]
    fn sync_rejects_a_header_whose_timestamp_is_not_after_its_parent() {
        let k = kps();
        let (mut block, tip) = genuine_block(&k);
        let s = set(&k);
        let d = domain();
        let p = ChainParams::genesis_defaults();
        // Ebeveynle AYNI zaman damgasi -> monoton DEGIL.
        block.signed.header.timestamp_ms = tip.timestamp_ms;
        let c = ctx(&s, &tip, &d, &p, None);
        let err =
            validate_block(&c, &block).expect_err("monoton olmayan zaman damgasi reddedilmeli");
        assert!(
            format!("{err:?}").contains("monoton"),
            "red gerekcesi monotonluk olmali: {err:?}"
        );
    }

    #[test]
    fn sync_rejects_a_header_dated_beyond_the_allowed_clock_skew() {
        let k = kps();
        let (mut block, tip) = genuine_block(&k);
        let s = set(&k);
        let d = domain();
        let p = ChainParams::genesis_defaults();
        let now = 20_000u64;
        block.signed.header.timestamp_ms = now + p.max_clock_skew_ms + 60_000;
        let mut c = ctx(&s, &tip, &d, &p, None);
        c.now_ms = now;
        let err = validate_block(&c, &block).expect_err("gelecekteki zaman damgasi reddedilmeli");
        assert!(
            format!("{err:?}").contains("gelecekte"),
            "red gerekcesi gelecek-damgasi olmali: {err:?}"
        );
    }

    /// Kurallara UYAN bir zaman damgası kabul edilmeli, kontrol fazla sıkı
    /// olup meşru senkronizasyonu KIRMAMALI.
    #[test]
    fn sync_accepts_a_header_with_a_normal_forward_timestamp() {
        let k = kps();
        let (block, tip) = genuine_block(&k);
        let s = set(&k);
        let d = domain();
        let p = ChainParams::genesis_defaults();
        assert!(
            block.signed.header.timestamp_ms > tip.timestamp_ms,
            "test on kosulu: gercek blok ileri damgali olmali"
        );
        let mut c = ctx(&s, &tip, &d, &p, None);
        c.now_ms = block.signed.header.timestamp_ms + 1_000;
        validate_block(&c, &block).expect("normal ileri zaman damgasi kabul edilmeli");
    }
}
