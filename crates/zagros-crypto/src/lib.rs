//! Konsensüs kriptografisi (§6, §15): Ed25519 konsensüs anahtarı (hesap ve
//! P2P/köprü anahtarlarından ayrı), domain-separated 32 bayt digest imzası,
//! fail-closed doğrulama, 0600 izinli JSON anahtar dosyası (gevşek izin yüklenmez).

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use zagros_primitives::{Result, ZagrosError};
use zagros_types::consensus::{
    ActiveValidatorSet, BlockHeaderV2, ConsensusDomain, Evidence, Heartbeat, QuorumCertificate,
    SignedHeader, Vote, DOMAIN_KEYOWN, DOMAIN_KEYROT,
};
use zagros_types::Hash;

pub const SIGNATURE_LEN: usize = 64;
pub const PUBKEY_LEN: usize = 32;

// ANAHTAR

/// Ed25519 konsensüs anahtar çifti.
pub struct ConsensusKeypair {
    signing: SigningKey,
}

impl ConsensusKeypair {
    pub fn generate() -> Self {
        let mut rng = rand::rngs::OsRng;
        Self {
            signing: SigningKey::generate(&mut rng),
        }
    }

    pub fn from_secret_bytes(secret: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(secret),
        }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    pub fn secret_bytes(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    /// 32 baytlık domain-separated digest'i imzalar (64 bayt).
    pub fn sign_digest(&self, digest: &Hash) -> Vec<u8> {
        self.signing.sign(digest).to_bytes().to_vec()
    }
}

/// Ed25519 doğrulama. Yanlış uzunlukta pubkey/imza → `Err` (fail-closed).
pub fn verify_digest(pubkey: &[u8; 32], digest: &Hash, sig: &[u8]) -> Result<()> {
    let vk = VerifyingKey::from_bytes(pubkey).map_err(|e| {
        ZagrosError::InvalidSignature.with_context(format!("gecersiz Ed25519 pubkey: {e}"))
    })?;
    let sig_bytes: [u8; SIGNATURE_LEN] = sig.try_into().map_err(|_| {
        ZagrosError::InvalidSignature
            .with_context(format!("imza uzunlugu {} != {SIGNATURE_LEN}", sig.len()))
    })?;
    let signature = Signature::from_bytes(&sig_bytes);
    vk.verify(digest, &signature)
        .map_err(|_| ZagrosError::InvalidSignature)
}

/// `ZagrosError`'a bağlam eklemek için küçük yardımcı (InvalidSignature → Other).
trait WithContext {
    fn with_context(self, ctx: String) -> ZagrosError;
}
impl WithContext for ZagrosError {
    fn with_context(self, ctx: String) -> ZagrosError {
        ZagrosError::Other(format!("{self:?}: {ctx}"))
    }
}

// OY / BAŞLIK / HEARTBEAT

pub fn sign_vote(kp: &ConsensusKeypair, domain: &ConsensusDomain, epoch: u64, vote: &mut Vote) {
    let digest = vote.signing_digest(domain, epoch);
    vote.sig = kp.sign_digest(&digest);
}

/// Oy imzasını, oyun `validator_idx`'ine karşılık gelen epoch pubkey'iyle
/// doğrular. Kümede olmayan indeks → `Err`.
pub fn verify_vote(vote: &Vote, domain: &ConsensusDomain, set: &ActiveValidatorSet) -> Result<()> {
    let pk = set.pubkey_of(vote.validator_idx).ok_or_else(|| {
        ZagrosError::Other(format!(
            "oy: validator_idx {} kumede yok",
            vote.validator_idx
        ))
    })?;
    verify_digest(pk, &vote.signing_digest(domain, set.epoch), &vote.sig)
}

/// G7: Probation validator'ın ShadowVote'unu doğrudan `consensus_pubkey` ile
/// doğrular (küme üyeliği aranmaz); pubkey'in o adresin kayıtlı anahtarı olduğunu
/// çağıran doğrular. [INV-L4] QC/quorum onayı üretmez, yalnız liveness kanıtı.
pub fn verify_shadow_vote(
    vote: &Vote,
    domain: &ConsensusDomain,
    epoch: u64,
    pubkey: &[u8; 32],
) -> Result<()> {
    if !vote.shadow {
        return Err(ZagrosError::Other(
            "shadow=false oy shadow dogrulamasindan gecemez".into(),
        ));
    }
    if *pubkey == [0u8; 32] {
        return Err(ZagrosError::Other("shadow oy: sifir pubkey".into()));
    }
    verify_digest(pubkey, &vote.signing_digest(domain, epoch), &vote.sig)
}

pub fn sign_header(
    kp: &ConsensusKeypair,
    domain: &ConsensusDomain,
    header: BlockHeaderV2,
) -> SignedHeader {
    let digest = header.signing_digest(domain);
    SignedHeader {
        sig: kp.sign_digest(&digest),
        header,
    }
}

/// Başlık imzasını `proposer_idx`'in pubkey'iyle doğrular; epoch ve küme
/// hash'i başlıkla uyuşmalıdır.
pub fn verify_signed_header(
    sh: &SignedHeader,
    domain: &ConsensusDomain,
    set: &ActiveValidatorSet,
) -> Result<()> {
    if sh.header.epoch != set.epoch {
        return Err(ZagrosError::Other(format!(
            "baslik epoch {} != kume epoch {}",
            sh.header.epoch, set.epoch
        )));
    }
    if sh.header.validator_set_hash != set.hash() {
        return Err(ZagrosError::Other(
            "baslik validator_set_hash kume ile uyusmuyor".into(),
        ));
    }
    let pk = set.pubkey_of(sh.header.proposer_idx).ok_or_else(|| {
        ZagrosError::Other(format!(
            "baslik: proposer_idx {} kumede yok",
            sh.header.proposer_idx
        ))
    })?;
    verify_digest(pk, &sh.header.signing_digest(domain), &sh.sig)
}

pub fn sign_heartbeat(
    kp: &ConsensusKeypair,
    domain: &ConsensusDomain,
    epoch: u64,
    hb: &mut Heartbeat,
) {
    let digest = hb.signing_digest(domain, epoch);
    hb.sig = kp.sign_digest(&digest);
}

pub fn verify_heartbeat(
    hb: &Heartbeat,
    domain: &ConsensusDomain,
    set: &ActiveValidatorSet,
) -> Result<()> {
    let pk = set.pubkey_of(hb.validator_idx).ok_or_else(|| {
        ZagrosError::Other(format!(
            "heartbeat: validator_idx {} kumede yok",
            hb.validator_idx
        ))
    })?;
    verify_digest(pk, &hb.signing_digest(domain, set.epoch), &hb.sig)
}

// QC

/// QC'yi yapısal + kriptografik olarak doğrular (INV-Q1): yapısal kurallar
/// (`QuorumCertificate::validate_structure`) + her imza, set bit sırasındaki
/// validator'ın pubkey'iyle PRECOMMIT(block_hash) digest'i üzerinde geçerli.
/// Gölge oy digest'i farklı domain'de olduğundan bir QC'ye GİREMEZ (INV-L4).
pub fn verify_qc(
    qc: &QuorumCertificate,
    domain: &ConsensusDomain,
    set: &ActiveValidatorSet,
) -> Result<()> {
    qc.validate_structure(set)?;
    let digest = zagros_types::consensus::signing_digest(
        zagros_types::consensus::DOMAIN_VOTE,
        domain,
        qc.epoch,
        qc.height,
        qc.round,
        zagros_types::consensus::VotePhase::Precommit.as_u8(),
        &qc.block_hash,
    );
    for (i, idx) in qc.signer_indices().iter().enumerate() {
        let pk = set
            .pubkey_of(*idx)
            .ok_or_else(|| ZagrosError::Other(format!("QC: imzaci {idx} kumede yok")))?;
        verify_digest(pk, &digest, &qc.sigs[i])
            .map_err(|_| ZagrosError::Other(format!("QC: validator {idx} imzasi gecersiz")))?;
    }
    Ok(())
}

/// PRECOMMIT oylarından QC kurar. Gölge oylar, nil oylar, farklı (h, r, hash)
/// oyları ve tekrar eden validator'lar reddedilir; sonuç `verify_qc`'den geçer.
pub fn build_qc(
    votes: &[Vote],
    domain: &ConsensusDomain,
    set: &ActiveValidatorSet,
    height: u64,
    round: u32,
    block_hash: Hash,
) -> Result<QuorumCertificate> {
    let n = set.len();
    let mut signers = vec![0u8; QuorumCertificate::bitset_len_for(n)];
    let mut picked: Vec<(u16, Vec<u8>)> = Vec::new();
    for v in votes {
        if v.shadow
            || v.is_nil()
            || v.height != height
            || v.round != round
            || v.block_hash != block_hash
        {
            continue;
        }
        if v.phase != zagros_types::consensus::VotePhase::Precommit {
            continue;
        }
        if v.validator_idx >= n || picked.iter().any(|(i, _)| *i == v.validator_idx) {
            continue;
        }
        verify_vote(v, domain, set)?;
        picked.push((v.validator_idx, v.sig.clone()));
    }
    picked.sort_by_key(|(i, _)| *i);
    for (i, _) in &picked {
        QuorumCertificate::set_signer(&mut signers, *i);
    }
    let qc = QuorumCertificate {
        height,
        round,
        block_hash,
        epoch: set.epoch,
        validator_set_hash: set.hash(),
        signers,
        sigs: picked.into_iter().map(|(_, s)| s).collect(),
    };
    verify_qc(&qc, domain, set)?;
    Ok(qc)
}

// EVIDENCE

/// Equivocation kanıtını yapısal + kriptografik olarak doğrular (INV-E1).
/// `set`, kanıtın epoch'undaki küme olmalıdır (eski epoch pubkey kaydı —
/// `evidence_max_age_epochs`, çağıranın sorumluluğu).
pub fn verify_evidence(
    ev: &Evidence,
    domain: &ConsensusDomain,
    set: &ActiveValidatorSet,
) -> Result<()> {
    ev.validate_structure()?;
    match ev {
        Evidence::DoubleVote { a, b } => {
            verify_vote(a, domain, set)?;
            verify_vote(b, domain, set)?;
            Ok(())
        }
        Evidence::DoublePropose { a, b } => {
            verify_signed_header(a, domain, set)?;
            verify_signed_header(b, domain, set)?;
            Ok(())
        }
    }
}

// ANAHTAR SAHİPLİĞİ / ROTASYON KANITI (§15)

/// `RegisterValidator`/`RotateConsensusKey` için sahiplik kanıtı digest'i:
/// konsensüs anahtarı, hesabın adresini (ve rotasyonda eski pubkey'i) imzalar
/// → başkasının pubkey'ini beyan etmek imkânsız.
pub fn key_ownership_digest(
    domain: &ConsensusDomain,
    account_address: &str,
    rotation_from: Option<&[u8; 32]>,
) -> Hash {
    let tag = if rotation_from.is_some() {
        DOMAIN_KEYROT
    } else {
        DOMAIN_KEYOWN
    };
    let mut extra = [0u8; 32];
    if let Some(old) = rotation_from {
        extra.copy_from_slice(old);
    }
    let mut payload = zagros_types::consensus::signing_payload(tag, domain, 0, 0, 0, 0, &extra);
    payload.extend_from_slice(account_address.to_ascii_lowercase().as_bytes());
    zagros_types::consensus::keccak256(&payload)
}

pub fn prove_key_ownership(
    kp: &ConsensusKeypair,
    domain: &ConsensusDomain,
    account_address: &str,
    rotation_from: Option<&[u8; 32]>,
) -> Vec<u8> {
    kp.sign_digest(&key_ownership_digest(
        domain,
        account_address,
        rotation_from,
    ))
}

pub fn verify_key_ownership(
    pubkey: &[u8; 32],
    proof: &[u8],
    domain: &ConsensusDomain,
    account_address: &str,
    rotation_from: Option<&[u8; 32]>,
) -> Result<()> {
    verify_digest(
        pubkey,
        &key_ownership_digest(domain, account_address, rotation_from),
        proof,
    )
}

// ANAHTAR DOSYASI

#[derive(Serialize, Deserialize)]
struct KeyFile {
    version: u8,
    scheme: String,
    public_key_hex: String,
    secret_key_hex: String,
}

/// Anahtarı JSON olarak yazar; dosya izinleri 0600 (Unix).
pub fn save_keyfile(kp: &ConsensusKeypair, path: &str) -> Result<()> {
    let kf = KeyFile {
        version: 1,
        scheme: "ed25519".into(),
        public_key_hex: hex::encode(kp.public_key()),
        secret_key_hex: hex::encode(kp.secret_bytes()),
    };
    let json = serde_json::to_string_pretty(&kf)
        .map_err(|e| ZagrosError::Other(format!("keyfile json: {e}")))?;
    if let Some(dir) = std::path::Path::new(path).parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir)
                .map_err(|e| ZagrosError::Other(format!("keyfile dizin: {e}")))?;
        }
    }
    std::fs::write(path, json).map_err(|e| ZagrosError::Other(format!("keyfile yaz: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| ZagrosError::Other(format!("keyfile izin: {e}")))?;
    }
    Ok(())
}

/// Anahtarı yükler. Gevşek izin (grup/diğer okuyabiliyor), yanlış şema/sürüm,
/// pubkey-secret uyuşmazlığı → `Err` (fail-closed).
pub fn load_keyfile(path: &str) -> Result<ConsensusKeypair> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta =
            std::fs::metadata(path).map_err(|e| ZagrosError::Other(format!("keyfile oku: {e}")))?;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(ZagrosError::Other(format!(
                "keyfile izinleri cok genis ({:o}); 0600 olmali: {path}",
                meta.permissions().mode() & 0o777
            )));
        }
    }
    let json = std::fs::read_to_string(path)
        .map_err(|e| ZagrosError::Other(format!("keyfile oku: {e}")))?;
    let kf: KeyFile = serde_json::from_str(&json)
        .map_err(|e| ZagrosError::Other(format!("keyfile json: {e}")))?;
    if kf.version != 1 || kf.scheme != "ed25519" {
        return Err(ZagrosError::Other(
            "keyfile surumu/semasi desteklenmiyor".into(),
        ));
    }
    let secret = hex::decode(&kf.secret_key_hex)
        .map_err(|e| ZagrosError::Other(format!("secret hex: {e}")))?;
    let secret: [u8; 32] = secret
        .try_into()
        .map_err(|_| ZagrosError::Other("secret 32 bayt degil".into()))?;
    let kp = ConsensusKeypair::from_secret_bytes(&secret);
    let pk = hex::decode(&kf.public_key_hex)
        .map_err(|e| ZagrosError::Other(format!("pubkey hex: {e}")))?;
    if pk.as_slice() != kp.public_key() {
        return Err(ZagrosError::Other(
            "keyfile public_key secret ile uyusmuyor".into(),
        ));
    }
    Ok(kp)
}

// TESTLER
#[cfg(test)]
mod tests {
    use super::*;
    use zagros_types::consensus::{ChainParams, ValidatorMember, VotePhase, NIL_HASH};

    fn domain() -> ConsensusDomain {
        ConsensusDomain::new(21072026, [7u8; 32])
    }

    fn set_with_keys(n: u16, epoch: u64) -> (ActiveValidatorSet, Vec<ConsensusKeypair>) {
        let kps: Vec<ConsensusKeypair> = (0..n).map(|_| ConsensusKeypair::generate()).collect();
        let set = ActiveValidatorSet {
            epoch,
            members: kps
                .iter()
                .enumerate()
                .map(|(i, k)| ValidatorMember {
                    address: format!("0x{:040x}", i + 1),
                    consensus_pubkey: k.public_key(),
                })
                .collect(),
        };
        (set, kps)
    }

    fn header(set: &ActiveValidatorSet, n: u64, round: u32, proposer: u16) -> BlockHeaderV2 {
        BlockHeaderV2 {
            version: BlockHeaderV2::VERSION,
            number: n,
            parent_hash: [0u8; 32],
            state_root: [3u8; 32],
            timestamp_ms: 1,
            tx_root: BlockHeaderV2::compute_tx_root(&[]),
            tx_count: 0,
            body_bytes: 10,
            epoch: set.epoch,
            validator_set_hash: set.hash(),
            round,
            proposer_idx: proposer,
            max_ruleset: 1,
            last_qc: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn vote(
        kp: &ConsensusKeypair,
        set: &ActiveValidatorSet,
        idx: u16,
        h: u64,
        r: u32,
        phase: VotePhase,
        hash: Hash,
        shadow: bool,
    ) -> Vote {
        let mut v = Vote {
            height: h,
            round: r,
            phase,
            block_hash: hash,
            validator_idx: idx,
            shadow,
            sig: vec![],
        };
        sign_vote(kp, &domain(), set.epoch, &mut v);
        v
    }

    #[test]
    fn sign_and_verify_digest_roundtrip_and_tamper() {
        let kp = ConsensusKeypair::generate();
        let d = [5u8; 32];
        let sig = kp.sign_digest(&d);
        assert_eq!(sig.len(), SIGNATURE_LEN);
        assert!(verify_digest(&kp.public_key(), &d, &sig).is_ok());
        let mut bad = sig.clone();
        bad[0] ^= 1;
        assert!(verify_digest(&kp.public_key(), &d, &bad).is_err());
        let mut d2 = d;
        d2[0] ^= 1;
        assert!(verify_digest(&kp.public_key(), &d2, &sig).is_err());
        assert!(
            verify_digest(&ConsensusKeypair::generate().public_key(), &d, &sig).is_err(),
            "baska anahtar"
        );
        assert!(
            verify_digest(&kp.public_key(), &d, &sig[..63]).is_err(),
            "kisa imza fail-closed"
        );
    }

    // TC-D1: çapraz domain / zincir / epoch imzaları geçmez
    #[test]
    fn vote_signature_is_domain_chain_epoch_bound() {
        let (set, kps) = set_with_keys(4, 2);
        let v = vote(
            &kps[1],
            &set,
            1,
            10,
            0,
            VotePhase::Prevote,
            [9u8; 32],
            false,
        );
        assert!(verify_vote(&v, &domain(), &set).is_ok());
        assert!(
            verify_vote(&v, &ConsensusDomain::new(1, [7u8; 32]), &set).is_err(),
            "chain_id"
        );
        assert!(
            verify_vote(&v, &ConsensusDomain::new(21072026, [8u8; 32]), &set).is_err(),
            "genesis_hash"
        );
        let mut other_epoch = set.clone();
        other_epoch.epoch = 3;
        assert!(verify_vote(&v, &domain(), &other_epoch).is_err(), "epoch");
        let mut as_shadow = v.clone();
        as_shadow.shadow = true;
        assert!(
            verify_vote(&as_shadow, &domain(), &set).is_err(),
            "gercek oy imzasi golge oy olarak gecmez"
        );
        let mut as_precommit = v.clone();
        as_precommit.phase = VotePhase::Precommit;
        assert!(
            verify_vote(&as_precommit, &domain(), &set).is_err(),
            "prevote imzasi precommit olarak gecmez"
        );
        let mut wrong_idx = v.clone();
        wrong_idx.validator_idx = 2;
        assert!(
            verify_vote(&wrong_idx, &domain(), &set).is_err(),
            "baska validator"
        );
        let mut out_of_set = v;
        out_of_set.validator_idx = 9;
        assert!(
            verify_vote(&out_of_set, &domain(), &set).is_err(),
            "kume disi indeks fail-closed"
        );
    }

    #[test]
    fn header_signature_requires_matching_proposer_epoch_and_set() {
        let (set, kps) = set_with_keys(5, 4);
        let h = header(&set, 7, 0, 2);
        let sh = sign_header(&kps[2], &domain(), h.clone());
        assert!(verify_signed_header(&sh, &domain(), &set).is_ok());
        let wrong = sign_header(&kps[3], &domain(), h.clone());
        assert!(
            verify_signed_header(&wrong, &domain(), &set).is_err(),
            "proposer_idx=2 ama imza 3"
        );
        let mut tampered = sh.clone();
        tampered.header.state_root[0] ^= 1;
        assert!(
            verify_signed_header(&tampered, &domain(), &set).is_err(),
            "icerik degisti"
        );
        let mut other = set.clone();
        other.epoch += 1;
        assert!(
            verify_signed_header(&sh, &domain(), &other).is_err(),
            "epoch/kume hash uyusmazligi"
        );
    }

    // TC-Q1: QC kur/doğrula; gölge ve nil oylar giremez (INV-L4)
    #[test]
    fn qc_build_and_verify() {
        let (set, kps) = set_with_keys(5, 1); // Q=4
        let h = header(&set, 3, 0, 0);
        let bh = h.hash();
        let mut votes: Vec<Vote> = (0..5u16)
            .map(|i| {
                vote(
                    &kps[i as usize],
                    &set,
                    i,
                    3,
                    0,
                    VotePhase::Precommit,
                    bh,
                    false,
                )
            })
            .collect();
        let qc = build_qc(&votes, &domain(), &set, 3, 0, bh).unwrap();
        assert_eq!(qc.signer_indices().len(), 5);
        assert!(verify_qc(&qc, &domain(), &set).is_ok());
        // tam Q ile
        let qc4 = build_qc(&votes[..4], &domain(), &set, 3, 0, bh).unwrap();
        assert!(verify_qc(&qc4, &domain(), &set).is_ok());
        // Q-1 → Err
        assert!(build_qc(&votes[..3], &domain(), &set, 3, 0, bh).is_err());
        // gölge oylar sayılmaz
        let shadow: Vec<Vote> = (0..5u16)
            .map(|i| {
                vote(
                    &kps[i as usize],
                    &set,
                    i,
                    3,
                    0,
                    VotePhase::Prevote,
                    bh,
                    true,
                )
            })
            .collect();
        assert!(
            build_qc(&shadow, &domain(), &set, 3, 0, bh).is_err(),
            "golge oylarla QC kurulamaz"
        );
        // prevote'lar precommit QC'si kuramaz
        let prevotes: Vec<Vote> = (0..5u16)
            .map(|i| {
                vote(
                    &kps[i as usize],
                    &set,
                    i,
                    3,
                    0,
                    VotePhase::Prevote,
                    bh,
                    false,
                )
            })
            .collect();
        assert!(build_qc(&prevotes, &domain(), &set, 3, 0, bh).is_err());
        // nil oylar sayılmaz
        let nils: Vec<Vote> = (0..5u16)
            .map(|i| {
                vote(
                    &kps[i as usize],
                    &set,
                    i,
                    3,
                    0,
                    VotePhase::Precommit,
                    NIL_HASH,
                    false,
                )
            })
            .collect();
        assert!(build_qc(&nils, &domain(), &set, 3, 0, bh).is_err());
        // tekrar eden validator tek sayılır
        votes.push(votes[0].clone());
        let qc_dup = build_qc(&votes, &domain(), &set, 3, 0, bh).unwrap();
        assert_eq!(qc_dup.signer_indices().len(), 5);
        // sahte imza içeren oy → build Err (fail-closed)
        let mut forged = votes[1].clone();
        forged.sig[5] ^= 1;
        assert!(build_qc(
            &[votes[0].clone(), forged, votes[2].clone(), votes[3].clone()],
            &domain(),
            &set,
            3,
            0,
            bh
        )
        .is_err());
        // QC içindeki bir imzayı boz → verify Err
        let mut bad = qc.clone();
        bad.sigs[2][0] ^= 1;
        assert!(verify_qc(&bad, &domain(), &set).is_err());
        // QC'yi başka kümeyle doğrulama → Err
        let (other, _) = set_with_keys(5, 1);
        assert!(verify_qc(&qc, &domain(), &other).is_err());
    }

    #[test]
    fn qc_with_shadow_signature_smuggled_in_is_rejected() {
        // Saldırgan: gölge oy imzasını gerçek precommit imzası gibi QC'ye sokar.
        let (set, kps) = set_with_keys(4, 1);
        let h = header(&set, 2, 0, 0);
        let bh = h.hash();
        let real: Vec<Vote> = (0..3u16)
            .map(|i| {
                vote(
                    &kps[i as usize],
                    &set,
                    i,
                    2,
                    0,
                    VotePhase::Precommit,
                    bh,
                    false,
                )
            })
            .collect();
        let shadow3 = vote(&kps[3], &set, 3, 2, 0, VotePhase::Precommit, bh, true);
        let mut qc = build_qc(&real, &domain(), &set, 2, 0, bh).unwrap(); // Q=3
        QuorumCertificate::set_signer(&mut qc.signers, 3);
        qc.sigs.push(shadow3.sig.clone());
        assert!(
            verify_qc(&qc, &domain(), &set).is_err(),
            "golge imza QC'de gecersiz (INV-L4)"
        );
    }

    #[test]
    fn evidence_verification() {
        let (set, kps) = set_with_keys(4, 5);
        let a = vote(
            &kps[2],
            &set,
            2,
            11,
            1,
            VotePhase::Precommit,
            [1u8; 32],
            false,
        );
        let b = vote(
            &kps[2],
            &set,
            2,
            11,
            1,
            VotePhase::Precommit,
            [2u8; 32],
            false,
        );
        assert!(verify_evidence(
            &Evidence::DoubleVote {
                a: a.clone(),
                b: b.clone()
            },
            &domain(),
            &set
        )
        .is_ok());
        // b başkası tarafından imzalanmış (sahte kanıt) → Err
        let forged = vote(
            &kps[3],
            &set,
            2,
            11,
            1,
            VotePhase::Precommit,
            [2u8; 32],
            false,
        );
        assert!(verify_evidence(
            &Evidence::DoubleVote {
                a: a.clone(),
                b: forged
            },
            &domain(),
            &set
        )
        .is_err());
        // DoublePropose
        let h1 = header(&set, 11, 1, 0);
        let mut h2 = h1.clone();
        h2.state_root = [8u8; 32];
        let ev = Evidence::DoublePropose {
            a: Box::new(sign_header(&kps[0], &domain(), h1.clone())),
            b: Box::new(sign_header(&kps[0], &domain(), h2.clone())),
        };
        assert!(verify_evidence(&ev, &domain(), &set).is_ok());
        let ev_bad = Evidence::DoublePropose {
            a: Box::new(sign_header(&kps[0], &domain(), h1)),
            b: Box::new(sign_header(&kps[1], &domain(), h2)),
        };
        assert!(
            verify_evidence(&ev_bad, &domain(), &set).is_err(),
            "farkli anahtar imzaladi"
        );
        // gölge equivocation da kanıt olabilir (Probation validator'ı da slash edilir)
        let sa = vote(&kps[1], &set, 1, 12, 0, VotePhase::Prevote, [1u8; 32], true);
        let sb = vote(&kps[1], &set, 1, 12, 0, VotePhase::Prevote, [2u8; 32], true);
        assert!(verify_evidence(&Evidence::DoubleVote { a: sa, b: sb }, &domain(), &set).is_ok());
    }

    #[test]
    fn key_ownership_and_rotation_proofs() {
        let kp = ConsensusKeypair::generate();
        let addr = "0x00000005668becb40d7eaafdae73ed6347932d49";
        let proof = prove_key_ownership(&kp, &domain(), addr, None);
        assert!(verify_key_ownership(&kp.public_key(), &proof, &domain(), addr, None).is_ok());
        assert!(verify_key_ownership(&kp.public_key(), &proof, &domain(), addr, None).is_ok());
        assert!(
            verify_key_ownership(
                &kp.public_key(),
                &proof,
                &domain(),
                "0x0000000000000000000000000000000000000001",
                None
            )
            .is_err(),
            "baska hesap"
        );
        assert!(
            verify_key_ownership(
                &kp.public_key(),
                &proof,
                &ConsensusDomain::new(1, [7u8; 32]),
                addr,
                None
            )
            .is_err(),
            "baska zincir"
        );
        let old = ConsensusKeypair::generate();
        let rot = prove_key_ownership(&kp, &domain(), addr, Some(&old.public_key()));
        assert!(verify_key_ownership(
            &kp.public_key(),
            &rot,
            &domain(),
            addr,
            Some(&old.public_key())
        )
        .is_ok());
        assert!(
            verify_key_ownership(&kp.public_key(), &rot, &domain(), addr, None).is_err(),
            "rotasyon kaniti sahiplik kaniti olarak gecmez"
        );
        assert!(verify_key_ownership(
            &kp.public_key(),
            &proof,
            &domain(),
            addr,
            Some(&old.public_key())
        )
        .is_err());
        // adres büyük/küçük harf duyarsız
        assert!(verify_key_ownership(
            &kp.public_key(),
            &proof,
            &domain(),
            &addr.to_uppercase(),
            None
        )
        .is_ok());
    }

    #[test]
    fn keyfile_roundtrip_and_fail_closed() {
        let dir = std::env::temp_dir().join(format!("zagros-keyfile-test-{}", std::process::id()));
        let path = dir.join("consensus.key").to_string_lossy().to_string();
        let kp = ConsensusKeypair::generate();
        save_keyfile(&kp, &path).unwrap();
        let loaded = load_keyfile(&path).unwrap();
        assert_eq!(loaded.public_key(), kp.public_key());
        assert_eq!(loaded.secret_bytes(), kp.secret_bytes());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(
                load_keyfile(&path).is_err(),
                "genis izinli keyfile YUKLENMEZ"
            );
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        // pubkey-secret uyuşmazlığı
        let json = std::fs::read_to_string(&path).unwrap();
        let tampered = json.replace(
            &hex::encode(kp.public_key()),
            &hex::encode(ConsensusKeypair::generate().public_key()),
        );
        std::fs::write(&path, tampered).unwrap();
        assert!(load_keyfile(&path).is_err());
        assert!(load_keyfile(&dir.join("yok.key").to_string_lossy()).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn chain_params_usable_from_crypto_crate() {
        assert!(ChainParams::genesis_defaults().validate().is_ok());
    }
}
