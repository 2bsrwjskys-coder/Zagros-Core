//! Deterministik süreç içi BFT simülatörü ve property testleri: ağ, zaman ve
//! rastgelelik simüle edilir (tohumlu xorshift, ms sayacı); aynı tohum ⇒ aynı iz.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use secp256k1::SecretKey;
use zagros_consensus::engine::{
    BftEngine, BlockVerifier, ChainTip, Message, NodeIdentity, Output, Proposal, QcClose,
    RuntimeVerifier, Step, ViewChangeReason,
};
use zagros_crypto::{build_qc, sign_header, sign_vote, ConsensusKeypair};
use zagros_executor::bridge::BridgeProposal;
use zagros_executor::{params, validator_set, Executor};
use zagros_primitives::{Hash, Result};
use zagros_runtime::Runtime;
use zagros_scheduler::Scheduler;
use zagros_state::manager::StateDbManager;
use zagros_state::State;
use zagros_storage::{Storage, StorageEngine};
use zagros_types::consensus::{
    keccak256, ActiveValidatorSet, BlockHeaderV2, ChainParams, ConsensusDomain, Evidence,
    QuorumCertificate, ScheduledUpgrade, ValidatorMember, ValidatorStatus, Vote, VotePhase,
    NIL_HASH,
};
use zagros_types::{AccountState, Transaction, TxType, CHAIN_ID};

// YARDIMCILAR

#[derive(Default)]
struct MemoryStorage {
    values: Mutex<HashMap<Vec<u8>, Vec<u8>>>,
}
impl Storage for MemoryStorage {
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
impl StorageEngine for MemoryStorage {
    fn write_batch(&self, kvs: &[(Vec<u8>, Option<Vec<u8>>)]) -> Result<()> {
        let mut values = self.values.lock().unwrap();
        for (k, v) in kvs {
            match v {
                Some(v) => {
                    values.insert(k.clone(), v.clone());
                }
                None => {
                    values.remove(k);
                }
            }
        }
        Ok(())
    }
}

struct XorShift(u64);
impl XorShift {
    fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next() % n
        }
    }
}

const T0: u64 = 1_000_000; // simülasyon başlangıcı (ms)
const T_BASE: u64 = 100; // sim ChainParams.t_base_ms
const BLOCK_INTERVAL: u64 = 100;

fn domain() -> ConsensusDomain {
    ConsensusDomain::new(CHAIN_ID, [7u8; 32])
}

/// Sim parametreleri: spec başlangıç değerleri, yalnız tempo/timer küçültülmüş
/// (alt sınırlar: block_interval ≥ 100 ms, t_base ≥ block_interval).
fn params() -> ChainParams {
    let mut p = ChainParams::genesis_defaults();
    p.block_interval_ms = BLOCK_INTERVAL;
    p.t_base_ms = T_BASE;
    p.idle_block_interval_s = 10; // alt sinir; heartbeat idle testi icin
    p.validate().unwrap();
    p
}

fn keypairs(n: usize) -> Vec<ConsensusKeypair> {
    (0..n)
        .map(|i| ConsensusKeypair::from_secret_bytes(&[(i as u8) + 1; 32]))
        .collect()
}

fn validator_set(kps: &[ConsensusKeypair], epoch: u64) -> ActiveValidatorSet {
    ActiveValidatorSet {
        epoch,
        members: kps
            .iter()
            .enumerate()
            .map(|(i, kp)| ValidatorMember {
                address: format!("0x{:040x}", i + 1),
                consensus_pubkey: kp.public_key(),
            })
            .collect(),
    }
}

fn genesis_tip() -> ChainTip {
    ChainTip {
        height: 0,
        hash: [9u8; 32],
        qc: None,
        timestamp_ms: T0 - 1_000,
    }
}

fn identity(kps: &[ConsensusKeypair], i: usize) -> NodeIdentity {
    NodeIdentity {
        idx: i as u16,
        keypair: ConsensusKeypair::from_secret_bytes(&kps[i].secret_bytes()),
    }
}

/// Saf, deterministik "yürütme": kök = keccak(parent ‖ number ‖ tx_root).
struct FakeVerifier;
impl BlockVerifier for FakeVerifier {
    fn simulate(
        &self,
        h: &BlockHeaderV2,
        _txs: &[Transaction],
        _b: &[BridgeProposal],
        _sv: &[zagros_types::consensus::ShadowVoteAttestation],
    ) -> Result<Hash> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&h.parent_hash);
        buf.extend_from_slice(&h.number.to_le_bytes());
        buf.extend_from_slice(&h.tx_root);
        Ok(keccak256(&buf))
    }
}

/// Yanlış kök üreten (hatalı/kötü niyetli proposer) doğrulayıcı.
struct WrongRootVerifier;
impl BlockVerifier for WrongRootVerifier {
    fn simulate(
        &self,
        _h: &BlockHeaderV2,
        _t: &[Transaction],
        _b: &[BridgeProposal],
        _sv: &[zagros_types::consensus::ShadowVoteAttestation],
    ) -> Result<Hash> {
        Ok([0xEE; 32])
    }
}

fn secret(seed: u8) -> SecretKey {
    SecretKey::from_slice(&[seed; 32]).unwrap()
}

fn transfer_tx(sender_seed: u8, nonce: u64, amount: u128, ts: u128) -> Transaction {
    let key = secret(sender_seed);
    let mut tx = Transaction {
        tx_id: [0; 32],
        tx_type: TxType::Transfer,
        sender: Transaction::address_from_secret_key(&key),
        amount,
        receiver: "0x2222222222222222222222222222222222222222".to_string(),
        payload: Vec::new(),
        signature: Vec::new(),
        timestamp: ts,
        nonce,
        // G9: ücret anlamlı olsun ki %20 üretici payı floor'da 0'a düşmesin
        // (10_000×2=20_000 raw → blok başına 4_000 raw üretici payı).
        gas_limit: 10_000,
        gas_price: 2,
        chain_id: CHAIN_ID,
    };
    let mut id = [sender_seed; 32];
    id[1..9].copy_from_slice(&nonce.to_le_bytes());
    tx.tx_id = id;
    tx.sign(&key);
    tx
}

fn extract_proposal(outs: &[Output]) -> Proposal {
    outs.iter()
        .find_map(|o| match o {
            Output::Broadcast(Message::Proposal(p)) => Some((**p).clone()),
            _ => None,
        })
        .expect("oneri yayini")
}

fn has_vote(outs: &[Output], phase: VotePhase, hash: Hash) -> bool {
    outs.iter()
        .any(|o| matches!(o, Output::Broadcast(Message::Vote(v)) if v.phase == phase && v.block_hash == hash))
}

fn has_dropped(outs: &[Output], needle: &str) -> bool {
    outs.iter()
        .any(|o| matches!(o, Output::Dropped(r) if r.contains(needle)))
}

// SİMÜLATÖR

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Behavior {
    Honest,
    /// Hiç mesaj göndermez (ölü proposer / çökmüş node).
    Silent,
    /// Aynı (h, r) için iki farklı (ikisi de "geçerli") öneri yayınlar.
    DoublePropose,
    /// Her oyunun yanında çelişen ikinci bir oy gönderir.
    DoubleVote,
    /// Önerisine yanlış state_root yazar.
    WrongRoot,
}

type NodeRuntime = Option<(Arc<dyn State>, Arc<Runtime>)>;

struct Node {
    engine: BftEngine,
    behavior: Behavior,
    runtime: NodeRuntime,
    verifier: Box<dyn BlockVerifier>,
    keypair: ConsensusKeypair,
    params: ChainParams,
    /// (height, block_hash, state_root, qc_round)
    committed: Vec<(u64, Hash, Hash, u32)>,
    /// G10: bu node'un beyan edeceği kural seti, GERÇEK driver'da binary
    /// sabitidir (SUPPORTED_RULESET) ve rebuild'lerde doğal olarak korunur;
    /// sim'de rebuild sonrası yeniden uygulanır (karışık-sürüm testleri için).
    local_max_ruleset: u32,
    evidence: Vec<Evidence>,
    dropped: Vec<String>,
    view_changes: Vec<(u64, u32, u32, ViewChangeReason)>,
    /// Bu node'un önereceği işlemler (height → txs).
    tx_source: HashMap<u64, Vec<Transaction>>,
    /// ⏱️ Her commit'te: (QC imzacı sayısı, kapanış sebebi).
    qc_info: Vec<(usize, QcClose)>,
}

struct Sim {
    nodes: Vec<Node>,
    queue: Vec<(u64, u64, usize, Message)>, // (deliver_at, seq, to, msg)
    seq: u64,
    now: u64,
    rng: XorShift,
    max_delay: u64,
    /// `links[from][to] == false` ⇒ mesaj düşer.
    links: Vec<Vec<bool>>,
    delivered: u64,
    /// ⏱️ Node'dan ÇIKAN her mesaja eklenen sabit gecikme (ms), "uzak
    /// validatör" (uzak bölgedeki doğrulayıcı vakası) benzetimi.
    extra_delay_from: Vec<u64>,
}

impl Sim {
    fn new(nodes: Vec<Node>, seed: u64, max_delay: u64) -> Self {
        let n = nodes.len();
        Self {
            nodes,
            queue: Vec::new(),
            seq: 0,
            now: T0,
            rng: XorShift::new(seed),
            max_delay,
            links: vec![vec![true; n]; n],
            delivered: 0,
            extra_delay_from: vec![0; n],
        }
    }

    fn set_isolated(&mut self, node: usize, isolated: bool) {
        for i in 0..self.nodes.len() {
            self.links[node][i] = !isolated;
            self.links[i][node] = !isolated;
        }
    }

    fn enqueue(&mut self, from: usize, to: usize, msg: Message) {
        let delay = 1 + self.rng.below(self.max_delay) + self.extra_delay_from[from];
        self.seq += 1;
        self.queue.push((self.now + delay, self.seq, to, msg));
    }

    fn send_all(&mut self, from: usize, msg: Message) {
        for to in 0..self.nodes.len() {
            if to == from || !self.links[from][to] {
                continue;
            }
            self.enqueue(from, to, msg.clone());
        }
    }

    fn send_some(&mut self, from: usize, msg: Message, pred: impl Fn(usize) -> bool) {
        for to in 0..self.nodes.len() {
            if to == from || !self.links[from][to] || !pred(to) {
                continue;
            }
            self.enqueue(from, to, msg.clone());
        }
    }

    fn boot(&mut self) {
        for i in 0..self.nodes.len() {
            let outs = {
                let node = &mut self.nodes[i];
                node.engine.start(self.now, node.verifier.as_ref())
            };
            self.process(i, outs);
        }
    }

    fn process(&mut self, i: usize, outs: Vec<Output>) {
        for out in outs {
            match out {
                Output::Broadcast(msg) => {
                    let behavior = self.nodes[i].behavior;
                    if behavior == Behavior::Silent {
                        continue;
                    }
                    if behavior == Behavior::DoubleVote {
                        if let Message::Vote(v) = &msg {
                            let mut alt = v.clone();
                            alt.block_hash = if v.block_hash == NIL_HASH {
                                [0xAA; 32]
                            } else {
                                NIL_HASH
                            };
                            let epoch = self.nodes[i].engine.validator_set().epoch;
                            sign_vote(&self.nodes[i].keypair, &domain(), epoch, &mut alt);
                            // Orijinal herkese, çelişen oy tek indekslilere (onlar
                            // ikisini de görüp kanıt üretir).
                            self.send_all(i, msg.clone());
                            self.send_some(i, Message::Vote(alt), |to| to % 2 == 1);
                            continue;
                        }
                    }
                    if behavior == Behavior::DoublePropose {
                        if let Message::Proposal(p) = &msg {
                            let mut alt_header = p.signed.header.clone();
                            alt_header.timestamp_ms += 1; // farklı hash, aynı gövde/kök
                            let mut alt = Proposal {
                                signed: sign_header(&self.nodes[i].keypair, &domain(), alt_header),
                                txs: p.txs.clone(),
                                bridge_proposals: Vec::new(),
                                shadow_votes: Vec::new(),
                                round: p.round,
                                valid_round: None,
                                sig: Vec::new(),
                            };
                            let epoch = self.nodes[i].engine.validator_set().epoch;
                            alt.sig = self.nodes[i]
                                .keypair
                                .sign_digest(&alt.envelope_digest(&domain(), epoch));
                            self.send_all(i, msg.clone());
                            self.send_some(i, Message::Proposal(Box::new(alt)), |to| to % 2 == 1);
                            continue;
                        }
                    }
                    self.send_all(i, msg);
                }
                Output::NeedProposal { height, .. } => {
                    let now = self.now;
                    let node = &mut self.nodes[i];
                    let txs = node.tx_source.remove(&height).unwrap_or_default();
                    let res = if node.behavior == Behavior::WrongRoot {
                        node.engine
                            .propose(now, txs, Vec::new(), Vec::new(), &WrongRootVerifier)
                    } else {
                        node.engine.propose(
                            now,
                            txs,
                            Vec::new(),
                            Vec::new(),
                            node.verifier.as_ref(),
                        )
                    };
                    let outs = res.expect("propose");
                    self.process(i, outs);
                }
                Output::Commit(block) => {
                    let now = self.now;
                    let node = &mut self.nodes[i];
                    let header = &block.proposal.signed.header;
                    // INV-C3: commit yalnız geçerli QC ile, her commit'te doğrula.
                    zagros_crypto::verify_qc(&block.qc, &domain(), node.engine.validator_set())
                        .expect("QC gecerli");
                    assert_eq!(block.qc.block_hash, block.proposal.block_hash());
                    let root = match &node.runtime {
                        Some((state, rt)) => {
                            let root = rt
                                .commit_block(
                                    header.number,
                                    (header.timestamp_ms / 1000) as u128,
                                    &block.proposal.txs,
                                    &block.proposal.bridge_proposals,
                                    header.last_qc.as_ref(),
                                    &block.proposal.shadow_votes,
                                    Some((header.epoch, header.proposer_idx, header.max_ruleset)),
                                    header.state_root,
                                )
                                .expect("commit_block");
                            // G8: gerçek sürücü her commit'te motoru state'ten yeniden kurar;
                            // simülatör `with_runtime=true`da aynı ilkeyi uygular, yoksa epoch
                            // geçen adversarial testler motoru eski kümede bırakırdı.
                            let new_set =
                                validator_set::load_active_set(state.as_ref()).expect("aktif kume");
                            let tip_set = validator_set::load_validator_set_at_epoch(
                                state.as_ref(),
                                block.qc.epoch,
                            )
                            .expect("tip_set epoch anlik goruntusu");
                            let pk = node.keypair.public_key();
                            let identity = new_set
                                .members
                                .iter()
                                .position(|m| m.consensus_pubkey == pk)
                                .map(|idx| NodeIdentity {
                                    idx: idx as u16,
                                    keypair: ConsensusKeypair::from_secret_bytes(
                                        &node.keypair.secret_bytes(),
                                    ),
                                });
                            let new_tip = ChainTip {
                                height: header.number,
                                hash: block.proposal.block_hash(),
                                qc: Some(block.qc.clone()),
                                timestamp_ms: header.timestamp_ms,
                            };
                            node.engine = BftEngine::new(
                                domain(),
                                node.params.clone(),
                                new_set,
                                identity,
                                new_tip,
                                Some(tip_set),
                            )
                            .expect("motor yeniden kurulamadi");
                            node.engine.set_local_max_ruleset(node.local_max_ruleset);
                            root
                        }
                        None => header.state_root,
                    };
                    node.committed.push((
                        header.number,
                        block.proposal.block_hash(),
                        root,
                        block.qc.round,
                    ));
                    node.qc_info
                        .push((block.qc.signer_indices().len(), block.qc_close));
                    let outs = node.engine.start(now, node.verifier.as_ref());
                    self.process(i, outs);
                }
                Output::Evidence(ev) => self.nodes[i].evidence.push(ev),
                Output::ViewChange {
                    height,
                    from_round,
                    to_round,
                    reason,
                } => {
                    self.nodes[i]
                        .view_changes
                        .push((height, from_round, to_round, reason));
                }
                Output::Dropped(reason) => self.nodes[i].dropped.push(reason),
            }
        }
    }

    /// Olay döngüsü: en erken olay (mesaj teslimi ya da timer) işlenir.
    /// `max_steps` adım ya da `until_ms` zamanına kadar.
    fn run(&mut self, max_steps: usize, until_ms: u64) {
        for _ in 0..max_steps {
            let next_msg = self
                .queue
                .iter()
                .enumerate()
                .min_by_key(|(_, (at, seq, _, _))| (*at, *seq))
                .map(|(pos, (at, _, _, _))| (pos, *at));
            let next_timer = self
                .nodes
                .iter()
                .enumerate()
                .filter_map(|(i, n)| n.engine.next_deadline().map(|d| (d, i)))
                .min();
            match (next_msg, next_timer) {
                (None, None) => return,
                (Some((pos, at)), timer) if timer.map(|(d, _)| at <= d).unwrap_or(true) => {
                    if at > until_ms {
                        return;
                    }
                    let (at, _, to, msg) = self.queue.swap_remove(pos);
                    self.now = at.max(self.now);
                    self.delivered += 1;
                    let outs = {
                        let node = &mut self.nodes[to];
                        node.engine.handle(msg, self.now, node.verifier.as_ref())
                    };
                    self.process(to, outs);
                }
                (_, Some((deadline, i))) => {
                    if deadline > until_ms {
                        return;
                    }
                    self.now = deadline.max(self.now);
                    let outs = {
                        let node = &mut self.nodes[i];
                        node.engine.tick(self.now, node.verifier.as_ref())
                    };
                    self.process(i, outs);
                }
                (Some(_), None) => unreachable!(),
            }
        }
    }

    fn honest(&self) -> impl Iterator<Item = &Node> {
        self.nodes.iter().filter(|n| n.behavior == Behavior::Honest)
    }

    /// Güvenlik (INV-C2/C3): dürüst node'ların commit zincirleri birbirinin
    /// önekidir (aynı yükseklikte farklı hash YOK, atlama YOK).
    fn assert_safety(&self) {
        let mut by_height: HashMap<u64, (Hash, Hash)> = HashMap::new();
        for n in self.honest() {
            for (expect, (h, bh, root, _)) in (1u64..).zip(n.committed.iter()) {
                assert_eq!(*h, expect, "yukseklik atlanmis");
                match by_height.get(h) {
                    Some((b, r)) => {
                        assert_eq!(b, bh, "h={h}: farkli blok commit edildi (SAFETY IHLALI)");
                        assert_eq!(r, root, "h={h}: farkli state_root");
                    }
                    None => {
                        by_height.insert(*h, (*bh, *root));
                    }
                }
            }
        }
    }

    fn min_honest_height(&self) -> u64 {
        self.honest()
            .map(|n| n.committed.len() as u64)
            .min()
            .unwrap_or(0)
    }
    fn max_honest_height(&self) -> u64 {
        self.honest()
            .map(|n| n.committed.len() as u64)
            .max()
            .unwrap_or(0)
    }
}

fn build_nodes(
    n: usize,
    behaviors: &[(usize, Behavior)],
    with_runtime: bool,
    heights_with_txs: u64,
) -> Vec<Node> {
    build_nodes_with_params(n, behaviors, with_runtime, heights_with_txs, params())
}

/// `build_nodes` gibi ama ChainParams dışarıdan; adversarial senaryolar paylaşılan
/// `params()`ı değiştirmeden özel süreler kullanır.
fn build_nodes_with_params(
    n: usize,
    behaviors: &[(usize, Behavior)],
    with_runtime: bool,
    heights_with_txs: u64,
    node_params: ChainParams,
) -> Vec<Node> {
    let kps = keypairs(n);
    let set = validator_set(&kps, 0);
    let mut nodes = Vec::new();
    for (i, kp) in kps.iter().enumerate() {
        let behavior = behaviors
            .iter()
            .find(|(j, _)| *j == i)
            .map(|(_, b)| *b)
            .unwrap_or(Behavior::Honest);
        let engine = BftEngine::new(
            domain(),
            node_params.clone(),
            set.clone(),
            Some(identity(&kps, i)),
            genesis_tip(),
            None,
        )
        .unwrap();
        let (runtime, verifier): (NodeRuntime, Box<dyn BlockVerifier>) = if with_runtime {
            let state: Arc<dyn State> =
                Arc::new(StateDbManager::new(Arc::new(MemoryStorage::default())));
            let sender = Transaction::address_from_secret_key(&secret(1));
            state
                .set_account(&sender, AccountState::new(1_000_000))
                .unwrap();
            // G8: BFT yolunda `advance_epoch_if_due` ChainParams + genesis zamanı +
            // küme ister (fail-closed); motorun kümesiyle birebir aynı küme state'e yazılır.
            params::store_chain_params(state.as_ref(), &node_params).unwrap();
            let ts_acc = AccountState {
                balance: (T0 / 1000) as u128,
                ..Default::default()
            };
            state
                .set_account(&zagros_types::GENESIS_TIMESTAMP_KEY.to_string(), ts_acc)
                .unwrap();
            validator_set::store_active_set(state.as_ref(), &set).unwrap();
            validator_set::store_active_set_epoch_snapshot(state.as_ref(), &set).unwrap();
            // G8: yeni küme hesapların `validator_status`undan hesaplanır; genesis
            // validatörlerin Active kaydı olmazsa küme MIN altına düşer, INV-S1 fallback eski kümeyi korur.
            let min_stake =
                params::min_validator_stake_zagros(state.as_ref(), &node_params).unwrap();
            for m in &set.members {
                let vacc = AccountState {
                    consensus_pubkey: m.consensus_pubkey,
                    validator_status: Some(zagros_types::consensus::ValidatorStatus::Active),
                    validator_status_epoch: 0,
                    staked_balance: min_stake,
                    is_registered_validator: true,
                    ..Default::default()
                };
                state.set_account(&m.address, vacc).unwrap();
            }
            // G9: %20 üretici payının akabilmesi için staker havuzu boş olmamalı
            // (total_staked=0 → tüm ücret Hazine'ye gider, üretici payı hiç doğmaz).
            let total_staked: u128 = min_stake.saturating_mul(set.members.len() as u128);
            state
                .set_account(
                    &"__GLOBAL_TOTAL_STAKED__".to_string(),
                    AccountState::new(total_staked),
                )
                .unwrap();
            state.flush().unwrap();
            let executor = Arc::new(Executor::new(state.clone()));
            let scheduler = Arc::new(Scheduler::new(executor.clone()));
            let rt = Arc::new(Runtime::new(state.clone(), executor, scheduler));
            (Some((state, rt.clone())), Box::new(RuntimeVerifier(rt)))
        } else {
            (None, Box::new(FakeVerifier))
        };
        let mut tx_source = HashMap::new();
        for h in 1..=heights_with_txs {
            // tx zamanı blok zamanından (≈ T0/1000 s) geride: gelecekte değil
            tx_source.insert(h, vec![transfer_tx(1, h - 1, 10, 900)]);
        }
        nodes.push(Node {
            engine,
            behavior,
            runtime,
            verifier,
            keypair: ConsensusKeypair::from_secret_bytes(&kp.secret_bytes()),
            params: node_params.clone(),
            committed: Vec::new(),
            local_max_ruleset: zagros_types::consensus::SUPPORTED_RULESET,
            evidence: Vec::new(),
            dropped: Vec::new(),
            view_changes: Vec::new(),
            qc_info: Vec::new(),
            tx_source,
        });
    }
    nodes
}

// G3 TESTLERİ (G4 ile güncellenmiş simülatörde)

#[test]
fn five_honest_nodes_commit_identical_chain_with_rotating_proposers() {
    let mut sim = Sim::new(build_nodes(5, &[], false, 0), 1, 3);
    sim.boot();
    sim.run(4_000, T0 + 60_000);
    sim.assert_safety();
    let h = sim.min_honest_height();
    assert!(h >= 15, "15+ blok beklenirdi, {h}");
    let mut proposers_seen = std::collections::HashSet::new();
    for (h, _, _, _) in &sim.nodes[0].committed {
        proposers_seen.insert((h % 5) as u16);
    }
    assert_eq!(
        proposers_seen.len(),
        5,
        "5 node'un hepsi en az bir blok onermeli"
    );
    // Sağlıklı ağda view-change yok, her blok tur 0'da
    for n in sim.honest() {
        assert!(n.view_changes.is_empty(), "{:?}", n.view_changes);
        assert!(n.committed.iter().all(|c| c.3 == 0));
    }
}

#[test]
fn twenty_one_nodes_with_random_delays_and_reordering_are_deterministic_and_safe() {
    let mut traces = Vec::new();
    for seed in [11u64, 11, 42] {
        let mut sim = Sim::new(build_nodes(21, &[], false, 0), seed, 40);
        sim.boot();
        sim.run(9_000, T0 + 600_000);
        sim.assert_safety();
        assert!(
            sim.min_honest_height() >= 6,
            "seed {seed}: en az 6 blok, {}",
            sim.min_honest_height()
        );
        let trace: Vec<(u64, Hash, u32)> = sim.nodes[0]
            .committed
            .iter()
            .map(|(h, b, _, r)| (*h, *b, *r))
            .collect();
        let vc: Vec<_> = sim.nodes[0].view_changes.clone();
        traces.push((seed, trace, sim.delivered, vc));
    }
    // Aynı tohum ⇒ birebir aynı iz (determinizm; view-change'ler dahil)
    assert_eq!(traces[0].1, traces[1].1);
    assert_eq!(traces[0].2, traces[1].2);
    assert_eq!(traces[0].3, traces[1].3);
}

#[test]
fn real_runtime_five_nodes_agree_on_state_root_block_by_block() {
    // 🚨 Bütçe: işlem yalnız ilk 6 yükseklikte, gerisi 10 sn idle ile gelir; 6 blok
    // ~60 sn ister, 200 sn ~3× pay bırakır. Dosyadaki tek gerçek runtime testleri (state_root mutabakatı).
    let mut sim = Sim::new(build_nodes(5, &[], true, 6), 3, 5);
    sim.boot();
    sim.run(2000, T0 + 200_000);
    sim.assert_safety();
    let h = sim.min_honest_height();
    assert!(h >= 6, "gercek runtime ile en az 6 blok, {h}");
    let roots: Vec<Hash> = sim
        .nodes
        .iter()
        .map(|n| n.runtime.as_ref().unwrap().0.state_root().unwrap())
        .collect();
    assert!(
        roots.iter().all(|r| *r == roots[0]),
        "node state kokleri farkli"
    );
    let last = sim.nodes[0].committed.last().unwrap();
    assert_eq!(last.2, roots[0]);
    let sender = Transaction::address_from_secret_key(&secret(1));
    assert_eq!(
        sim.nodes[0]
            .runtime
            .as_ref()
            .unwrap()
            .0
            .get_nonce(&sender)
            .unwrap(),
        6
    );
    assert_eq!(
        sim.nodes[4]
            .runtime
            .as_ref()
            .unwrap()
            .1
            .current_block_height()
            .unwrap() as u64,
        sim.nodes[4].committed.len() as u64
    );
}

/// G9 (§13.4): %20 pay her blokta gerçek proposer'a; blok üretmeyen almaz.
/// Eski sabit adres davranışında bu test kırmızı olurdu.
#[test]
fn g9_rotating_proposers_each_receive_their_own_blocks_reward_share() {
    // 🚨 Bütçe: 6 blok ~60 sn simüle zaman ister, 200 sn ~3× pay bırakır.
    let mut sim = Sim::new(build_nodes(5, &[], true, 6), 3, 5);
    sim.boot();
    sim.run(2000, T0 + 200_000);
    sim.assert_safety();
    assert!(sim.min_honest_height() >= 6, "{}", sim.min_honest_height());
    let set = validator_set(&keypairs(5), 0);
    let state = &sim.nodes[0].runtime.as_ref().unwrap().0;
    // Üretici = (h + qc.round) mod N — committed kaydındaki GERÇEK tur ile.
    let mut paid_idx = std::collections::HashSet::new();
    for (h, _bh, _root, round) in &sim.nodes[0].committed {
        paid_idx.insert(((h + *round as u64) % set.members.len() as u64) as usize);
    }
    assert!(
        paid_idx.len() >= 3,
        "rotasyon en az 3 farklı üretici ödüllendirmeli: {paid_idx:?}"
    );
    for (i, m) in set.members.iter().enumerate() {
        let bal = state.get_balance(&m.address).unwrap();
        if paid_idx.contains(&i) {
            assert!(
                bal > 0,
                "üretici {i} kendi bloklarının %20 payını almalı (bakiye 0)"
            );
        } else {
            assert_eq!(bal, 0, "blok üretmeyen {i} pay ALMAMALI (bakiye {bal})");
        }
    }
    // Deterministiklik: her dürüst node aynı bakiyeleri hesaplamış olmalı
    // (state_root eşitliğinin doğal sonucu; burada açık ve okunur kontrol).
    for n in sim.honest() {
        if let Some((st, _)) = &n.runtime {
            for m in &set.members {
                assert_eq!(
                    st.get_balance(&m.address).unwrap(),
                    state.get_balance(&m.address).unwrap()
                );
            }
        }
    }
}

/// G10 (§23) uçtan uca: 5 Runtime node, ScheduledUpgrade(target=2, epoch=1);
/// üreticiler max_ruleset=2 beyan eder, epoch 1 sınırında hazırlık (5/5) görülüp
/// active_ruleset 2 olur, zincir durmadan devam eder, kökler eşit.
#[test]
fn g10_seamless_upgrade_activates_at_epoch_boundary_without_stopping_the_chain() {
    // 300 sn epoch + genesis kaydırmasıyla epoch-1 sınırı sim'in ~6. saniyesine düşer.
    let mut p = params();
    p.epoch_seconds = 300;
    p.validate().unwrap();
    let epoch_seconds = p.epoch_seconds;
    let mut nodes = build_nodes_with_params(5, &[], true, 30, p);
    let genesis_ts = (T0 / 1000) - (epoch_seconds - 6); // sınır ts=1006 (+6 sn; 5/5 beyan ~3. snde tamam)
    for n in &mut nodes {
        n.local_max_ruleset = 2;
        n.engine.set_local_max_ruleset(2);
        let (state, _old_rt) = n.runtime.take().unwrap();
        // genesis zamanını kaydır (epoch 1 sınırı sim penceresinin içine düşsün)
        let ts_acc = AccountState {
            balance: genesis_ts as u128,
            ..Default::default()
        };
        state
            .set_account(&zagros_types::GENESIS_TIMESTAMP_KEY.to_string(), ts_acc)
            .unwrap();
        params::store_scheduled_upgrade(
            state.as_ref(),
            &ScheduledUpgrade {
                target_ruleset: 2,
                binary_sha256: [0xAB; 32],
                activation_epoch: 1,
            },
        )
        .unwrap();
        state.flush().unwrap();
        let executor = Arc::new(Executor::new(state.clone()));
        let scheduler = Arc::new(Scheduler::new(executor.clone()));
        let rt =
            Arc::new(Runtime::new(state.clone(), executor, scheduler).with_supported_ruleset(2));
        n.verifier = Box::new(RuntimeVerifier(rt.clone()));
        n.runtime = Some((state, rt));
    }
    let mut sim = Sim::new(nodes, 3, 5);
    sim.boot();
    sim.run(12_000, T0 + 60_000); // her blok ~300 adım; sınır (+6 sn ≈ h12) rahat geçilsin
    sim.assert_safety();
    let h = sim.min_honest_height();
    assert!(
        h >= 10,
        "yükseltme boyunca zincir akmaya devam etmeli, h={h}"
    );
    let set = validator_set(&keypairs(5), 0);
    for n in &sim.nodes {
        let (state, _) = n.runtime.as_ref().unwrap();
        let p = params::load_chain_params(state.as_ref()).unwrap();
        assert_eq!(
            p.active_ruleset, 2,
            "her node aktivasyonu AYNI şekilde işlemeli"
        );
        assert!(
            params::load_scheduled_upgrade(state.as_ref())
                .unwrap()
                .is_none(),
            "kayıt tek kullanımlık"
        );
        for m in &set.members {
            assert_eq!(
                params::ruleset_declaration(state.as_ref(), &m.address),
                2,
                "5/5 beyan zincirde olmalı"
            );
        }
    }
    // Kökler eşit, ORTAK son yükseklikte (koşu ortasında kesildiği için
    // node'lar 1 blok farklı uçta olabilir; anlık kök değil, aynı yüksekliğin
    // committed kökü karşılaştırılır, aktivasyon bloğu bu aralığın içinde).
    let common_h = sim
        .nodes
        .iter()
        .map(|n| n.committed.last().map(|c| c.0).unwrap_or(0))
        .min()
        .unwrap();
    assert!(common_h >= 10);
    let root_at = |n: &Node, h: u64| n.committed.iter().find(|c| c.0 == h).map(|c| c.2).unwrap();
    let expected = root_at(&sim.nodes[0], common_h);
    for n in &sim.nodes {
        assert_eq!(
            root_at(n, common_h),
            expected,
            "ortak yükseklik {common_h} kökleri eşit olmalı"
        );
    }
}

#[test]
fn double_proposing_byzantine_node_yields_evidence_and_never_splits_the_chain() {
    let mut sim = Sim::new(
        build_nodes(5, &[(1, Behavior::DoublePropose)], false, 0),
        8,
        4,
    );
    sim.boot();
    sim.run(3_000, T0 + 60_000);
    sim.assert_safety();
    assert!(sim.min_honest_height() >= 3, "{}", sim.min_honest_height());
    let ev = sim
        .honest()
        .flat_map(|n| n.evidence.iter())
        .filter(|e| matches!(e, Evidence::DoublePropose { .. }))
        .count();
    assert!(ev >= 1, "DoublePropose kaniti beklenirdi");
    for n in sim.honest() {
        for e in &n.evidence {
            zagros_crypto::verify_evidence(e, &domain(), n.engine.validator_set()).unwrap();
        }
    }
}

#[test]
fn double_voting_byzantine_node_is_detected_and_chain_stays_consistent() {
    let mut sim = Sim::new(
        build_nodes(5, &[(3, Behavior::DoubleVote)], false, 0),
        21,
        4,
    );
    sim.boot();
    sim.run(2_000, T0 + 60_000);
    sim.assert_safety();
    assert!(
        sim.min_honest_height() >= 5,
        "1 Byzantine / 5 ile zincir ilerlemeli"
    );
    let ev = sim
        .honest()
        .flat_map(|n| n.evidence.iter())
        .filter(|e| matches!(e, Evidence::DoubleVote { .. }) && e.validator_idx() == 3)
        .count();
    assert!(ev >= 1, "DoubleVote kaniti beklenirdi");
    for n in sim.honest() {
        for e in &n.evidence {
            zagros_crypto::verify_evidence(e, &domain(), n.engine.validator_set()).unwrap();
        }
    }
}

#[test]
fn oversized_or_misdeclared_body_is_rejected_and_cannot_be_proposed() {
    let kps = keypairs(5);
    let set = validator_set(&kps, 0);
    let mut p = params();
    p.max_block_bytes = 16 * 1024; // alt sinir; asagida tavani ASAN bir govde uretiliyor
    let mut proposer = BftEngine::new(
        domain(),
        p.clone(),
        set.clone(),
        Some(identity(&kps, 1)),
        genesis_tip(),
        None,
    )
    .unwrap();
    let mut validator = BftEngine::new(
        domain(),
        p.clone(),
        set.clone(),
        Some(identity(&kps, 2)),
        genesis_tip(),
        None,
    )
    .unwrap();
    proposer.start(T0, &FakeVerifier);
    validator.start(T0, &FakeVerifier);
    // 🚨 Govde, islem boyutundan BAGIMSIZ olarak tavani asmali: sabit bir islem
    // sayisi yazmak, tel formati kuculdugunde (bkz. `Transaction::encode_wire`)
    // testin sessizce anlamsizlasmasina yol acar, nitekim bir kez acti.
    let mut big: Vec<Transaction> = Vec::new();
    while zagros_types::consensus::block_body_bytes(&big) <= p.max_block_bytes {
        big.push(transfer_tx(1, big.len() as u64, 1, 5));
    }
    assert!(zagros_types::consensus::block_body_bytes(&big) > p.max_block_bytes);
    let err = proposer
        .propose(T0, big.clone(), Vec::new(), Vec::new(), &FakeVerifier)
        .unwrap_err();
    assert!(format!("{err:?}").contains("max_block_bytes"), "{err:?}");

    let mut loose = p.clone();
    loose.max_block_bytes = 1 << 20;
    let mut rogue = BftEngine::new(
        domain(),
        loose,
        set.clone(),
        Some(identity(&kps, 1)),
        genesis_tip(),
        None,
    )
    .unwrap();
    rogue.start(T0, &FakeVerifier);
    let outs = rogue
        .propose(T0, big, Vec::new(), Vec::new(), &FakeVerifier)
        .unwrap();
    let proposal = extract_proposal(&outs);
    let outs = validator.handle(
        Message::Proposal(Box::new(proposal.clone())),
        T0,
        &FakeVerifier,
    );
    assert!(has_dropped(&outs, "max_block_bytes"), "{outs:?}");
    assert!(has_vote(&outs, VotePhase::Prevote, NIL_HASH));

    let mut validator2 = BftEngine::new(
        domain(),
        p.clone(),
        set.clone(),
        Some(identity(&kps, 3)),
        genesis_tip(),
        None,
    )
    .unwrap();
    validator2.start(T0, &FakeVerifier);
    let mut lying = proposal.signed.header.clone();
    lying.body_bytes = 10;
    let mut lying_p = Proposal {
        signed: sign_header(&kps[1], &domain(), lying),
        txs: proposal.txs.clone(),
        bridge_proposals: Vec::new(),
        shadow_votes: Vec::new(),
        round: 0,
        valid_round: None,
        sig: Vec::new(),
    };
    lying_p.sig = kps[1].sign_digest(&lying_p.envelope_digest(&domain(), 0));
    let outs = validator2.handle(Message::Proposal(Box::new(lying_p)), T0, &FakeVerifier);
    assert!(has_dropped(&outs, "body_bytes"), "{outs:?}");
}

#[test]
fn engine_construction_is_fail_closed() {
    let kps = keypairs(5);
    let set = validator_set(&kps, 0);
    let bad = NodeIdentity {
        idx: 0,
        keypair: ConsensusKeypair::from_secret_bytes(&kps[1].secret_bytes()),
    };
    assert!(BftEngine::new(
        domain(),
        params(),
        set.clone(),
        Some(bad),
        genesis_tip(),
        None
    )
    .is_err());
    assert!(BftEngine::new(
        domain(),
        params(),
        set.clone(),
        None,
        ChainTip {
            height: 3,
            hash: [1; 32],
            qc: None,
            timestamp_ms: T0
        },
        None,
    )
    .is_err());
    let small = validator_set(&kps[..3], 0);
    assert!(BftEngine::new(domain(), params(), small, None, genesis_tip(), None).is_err());
    let mut obs = BftEngine::new(domain(), params(), set, None, genesis_tip(), None).unwrap();
    obs.start(T0, &FakeVerifier);
    assert!(obs
        .propose(T0, vec![], vec![], vec![], &FakeVerifier)
        .is_err());
    assert!(obs.heartbeat(T0).is_err());
}

#[test]
fn validator_set_rotation_at_height_boundary_changes_quorum_membership() {
    let kps = keypairs(6);
    let set5 = validator_set(&kps[..5], 0);
    let set6 = validator_set(&kps, 1);
    let mut e = BftEngine::new(
        domain(),
        params(),
        set5,
        Some(identity(&kps, 4)),
        genesis_tip(),
        None,
    )
    .unwrap();
    e.rotate_validator_set(set6.clone()).unwrap();
    assert_eq!(e.validator_set().len(), 6);
    assert_eq!(e.my_idx(), Some(4));
    assert_eq!(e.proposer_for(1, 0), 1);
    assert_eq!(e.proposer_for(5, 0), 5, "yeni uye rotasyona girdi");
    let set_without = validator_set(&kps[..4], 2);
    e.rotate_validator_set(set_without).unwrap();
    assert_eq!(e.my_idx(), None);
    // Tur aktifken değiştirilemez (fail-closed)
    e.start(T0, &FakeVerifier);
    assert!(e.rotate_validator_set(set6).is_err());
}

// G4 TESTLERİ — timeout / backoff / view-change / liveness

#[test]
fn timeouts_follow_spec_formula_with_cap() {
    let kps = keypairs(5);
    let mut p = params();
    p.t_base_ms = 1_500;
    p.block_interval_ms = 500;
    let e = BftEngine::new(
        domain(),
        p,
        validator_set(&kps, 0),
        None,
        genesis_tip(),
        None,
    )
    .unwrap();
    assert_eq!(e.t_propose(0), 1_500);
    assert_eq!(e.t_propose(1), 3_000);
    assert_eq!(e.t_propose(9), 15_000);
    assert_eq!(e.t_propose(50), 15_000, "tavan 10×T_base");
    assert_eq!(e.t_vote(0), 750);
    assert_eq!(e.t_vote(3), 3_000);
    assert_eq!(e.t_vote(100), 15_000);
}

#[test]
fn silent_proposer_is_skipped_by_timeout_and_view_change_without_safety_loss() {
    // h=1 proposer = node 1 (sessiz). Timeout → nil prevote → nil precommit → r=1 (node 2).
    let mut sim = Sim::new(build_nodes(5, &[(1, Behavior::Silent)], false, 0), 5, 3);
    sim.boot();
    sim.run(6_000, T0 + 120_000);
    sim.assert_safety();
    let h = sim.min_honest_height();
    assert!(h >= 8, "sessiz proposer atlanip zincir ilerlemeli: {h}");
    // h=1 tur 1'de, h=6 (proposer 1) tur 1'de commit; digerleri tur 0
    for n in sim.honest() {
        assert_eq!(n.committed[0].3, 1, "h=1 tur 1'de commit edilmeli");
        assert_eq!(n.committed[1].3, 0);
        assert_eq!(n.committed[5].3, 1, "h=6 proposer yine node 1 → tur 1");
        assert!(n
            .view_changes
            .iter()
            .any(|(h, from, to, _)| *h == 1 && *from == 0 && *to == 1));
        assert!(n.engine.stats().view_changes_total >= 2);
    }
}

#[test]
fn consecutive_proposer_failures_are_skipped_with_increasing_backoff() {
    // 7 node (Q=5, f=2): node 1 ve 2 sessiz. h=1: r0 → node1 ✗, r1 → node2 ✗, r2 → node3 ✓
    let mut sim = Sim::new(
        build_nodes(7, &[(1, Behavior::Silent), (2, Behavior::Silent)], false, 0),
        9,
        3,
    );
    sim.boot();
    sim.run(3_000, T0 + 120_000);
    sim.assert_safety();
    assert!(sim.min_honest_height() >= 3, "{}", sim.min_honest_height());
    for n in sim.honest() {
        assert_eq!(
            n.committed[0].3, 2,
            "h=1 ucuncu turda (node 3) commit edilmeli"
        );
        let vcs: Vec<_> = n.view_changes.iter().filter(|v| v.0 == 1).collect();
        assert_eq!(vcs.len(), 2, "{vcs:?}");
        assert!(vcs.iter().all(|v| v.1 + 1 == v.2), "tur monoton +1");
    }
    // Backoff: tur 1'in öneri timer'ı tur 0'ınkinden uzun (T_base×2 vs ×1) —
    // toplam h=1 süresi ≥ T_propose(0)+T_propose(1) = 300 ms (vote timer'ları hariç)
    let first_commit_time_lower_bound = T0 + 300;
    assert!(sim.now >= first_commit_time_lower_bound);
}

#[test]
fn delayed_old_round_messages_are_fail_closed_and_cannot_cause_divergence() {
    // Yüksek gecikme + sessiz node 1: tur değişimleri sırasında eski tur oyları
    // geç gelir. Hiçbiri adım değiştiremez; yalnız defter/QC için kullanılır.
    let mut sim = Sim::new(build_nodes(5, &[(1, Behavior::Silent)], false, 0), 77, 60);
    sim.boot();
    sim.run(3_000, T0 + 200_000);
    sim.assert_safety();
    assert!(sim.min_honest_height() >= 3, "{}", sim.min_honest_height());
    let old_round_drops = sim
        .honest()
        .flat_map(|n| n.dropped.iter())
        .filter(|d| d.contains("eski round"))
        .count();
    // Eski tur ÖNERİLERİ düşürülür (oylar deftere girer, sessizce). En az bir
    // eski-tur/ileri-tur olayı yaşanmış olmalı ki senaryo anlamlı olsun.
    let any_round_event = old_round_drops > 0 || sim.honest().any(|n| !n.view_changes.is_empty());
    assert!(any_round_event, "senaryo tur degisimi uretmedi");
}

#[test]
fn conflicting_proposals_across_rounds_respect_lock_and_pol() {
    // 4 node, Q=3. node0 tur 0'da X'e kilitlenir; tur 1'de farklı Y önerisi
    // (POL yok) → nil; X'in yeniden önerisi (valid_round=0) → X.
    let kps = keypairs(4);
    let set = validator_set(&kps, 0);
    let v = |i: usize, round: u32, phase: VotePhase, hash: Hash| {
        let mut v = Vote {
            height: 1,
            round,
            phase,
            block_hash: hash,
            validator_idx: i as u16,
            shadow: false,
            sig: vec![],
        };
        sign_vote(&kps[i], &domain(), 0, &mut v);
        Message::Vote(v)
    };
    let mut proposer1 = BftEngine::new(
        domain(),
        params(),
        set.clone(),
        Some(identity(&kps, 1)),
        genesis_tip(),
        None,
    )
    .unwrap();
    let mut node0 = BftEngine::new(
        domain(),
        params(),
        set.clone(),
        Some(identity(&kps, 0)),
        genesis_tip(),
        None,
    )
    .unwrap();
    proposer1.start(T0, &FakeVerifier);
    node0.start(T0, &FakeVerifier);
    let px = extract_proposal(
        &proposer1
            .propose(T0 + 5, vec![], vec![], vec![], &FakeVerifier)
            .unwrap(),
    );
    let x = px.block_hash();
    node0.handle(
        Message::Proposal(Box::new(px.clone())),
        T0 + 10,
        &FakeVerifier,
    );
    node0.handle(v(1, 0, VotePhase::Prevote, x), T0 + 11, &FakeVerifier);
    node0.handle(v(2, 0, VotePhase::Prevote, x), T0 + 12, &FakeVerifier);
    assert_eq!(node0.locked(), Some((0, x)));
    assert_eq!(node0.valid(), Some((0, x)));
    assert_eq!(node0.step(), Step::Precommit);

    // Precommit'ler gelmedi; precommit timer yok (Q precommit yok) → tur
    // atlama için f+1 = 2 validator'dan tur-1 oyu
    node0.handle(
        v(2, 1, VotePhase::Prevote, NIL_HASH),
        T0 + 50,
        &FakeVerifier,
    );
    assert_eq!(node0.round(), 0);
    let outs = node0.handle(
        v(3, 1, VotePhase::Prevote, NIL_HASH),
        T0 + 51,
        &FakeVerifier,
    );
    assert_eq!(node0.round(), 1, "f+1 ileri tur oyu → tur atlama");
    assert!(outs.iter().any(|o| matches!(
        o,
        Output::ViewChange {
            reason: ViewChangeReason::RoundSkip,
            ..
        }
    )));
    assert_eq!(node0.locked(), Some((0, x)), "kilit korunur");

    // Tur 1 proposer = node 2. Farklı Y önerisi (POL yok) → nil prevote.
    let mut proposer2 = BftEngine::new(
        domain(),
        params(),
        set.clone(),
        Some(identity(&kps, 2)),
        genesis_tip(),
        None,
    )
    .unwrap();
    proposer2.start(T0, &FakeVerifier);
    proposer2.handle(
        v(0, 1, VotePhase::Prevote, NIL_HASH),
        T0 + 52,
        &FakeVerifier,
    );
    proposer2.handle(
        v(3, 1, VotePhase::Prevote, NIL_HASH),
        T0 + 53,
        &FakeVerifier,
    );
    assert_eq!(proposer2.round(), 1);
    let py = extract_proposal(
        &proposer2
            .propose(
                T0 + 60,
                vec![transfer_tx(1, 0, 1, 5)],
                vec![],
                vec![],
                &FakeVerifier,
            )
            .unwrap(),
    );
    let y = py.block_hash();
    assert_ne!(x, y);
    let outs = node0.handle(Message::Proposal(Box::new(py)), T0 + 61, &FakeVerifier);
    assert!(
        has_vote(&outs, VotePhase::Prevote, NIL_HASH),
        "kilitliyken POL'suz Y'ye nil: {outs:?}"
    );
    assert!(!has_vote(&outs, VotePhase::Prevote, y));

    // Aynı turda yeniden öneri equivocation sayılır; temiz senaryo: node3 tur 1'de
    // X'e kilitli, tur 2'de X'i valid_round ile yeniden önerir.
    let mut node3 = BftEngine::new(
        domain(),
        params(),
        set.clone(),
        Some(identity(&kps, 3)),
        genesis_tip(),
        None,
    )
    .unwrap();
    node3.start(T0, &FakeVerifier);
    node3.handle(
        Message::Proposal(Box::new(px.clone())),
        T0 + 10,
        &FakeVerifier,
    );
    node3.handle(v(0, 0, VotePhase::Prevote, x), T0 + 11, &FakeVerifier);
    node3.handle(v(1, 0, VotePhase::Prevote, x), T0 + 12, &FakeVerifier);
    assert_eq!(node3.locked(), Some((0, x)));
    // tur 2'ye atla (f+1 oy)
    node3.handle(
        v(0, 2, VotePhase::Prevote, NIL_HASH),
        T0 + 100,
        &FakeVerifier,
    );
    node3.handle(
        v(1, 2, VotePhase::Prevote, NIL_HASH),
        T0 + 101,
        &FakeVerifier,
    );
    assert_eq!(node3.round(), 2);
    assert!(node3.is_proposer(), "(1+2) mod 4 = 3");
    let outs = node3
        .propose(
            T0 + 110,
            vec![transfer_tx(1, 0, 1, 5)],
            vec![],
            vec![],
            &FakeVerifier,
        )
        .unwrap();
    let rp = extract_proposal(&outs);
    assert_eq!(
        rp.block_hash(),
        x,
        "valid deger AYNI baslikla yeniden onerilir"
    );
    assert_eq!(rp.round, 2);
    assert_eq!(rp.valid_round, Some(0));
    assert!(has_vote(&outs, VotePhase::Prevote, x));

    // node0 (tur 1, X'e kilitli) bu tur-2 yeniden önerisini alır: önce tampon,
    // tur 2'ye geçince X'e prevote (kilitli hash ile aynı).
    node0.handle(
        Message::Proposal(Box::new(rp.clone())),
        T0 + 111,
        &FakeVerifier,
    );
    node0.handle(v(1, 2, VotePhase::Prevote, x), T0 + 112, &FakeVerifier);
    let outs = node0.handle(v(3, 2, VotePhase::Prevote, x), T0 + 113, &FakeVerifier);
    assert_eq!(node0.round(), 2);
    assert!(has_vote(&outs, VotePhase::Prevote, x), "{outs:?}");

    // Kilit açma (INV-C4): tur 1'de Z'ye Q prevote ama gövde yok; tur 2'de Z
    // valid_round=1 ile gelince POL ile kilit açılır, Z'ye prevote.
    let mut node_w = BftEngine::new(
        domain(),
        params(),
        set.clone(),
        Some(identity(&kps, 0)),
        genesis_tip(),
        None,
    )
    .unwrap();
    node_w.start(T0, &FakeVerifier);
    node_w.handle(
        Message::Proposal(Box::new(px.clone())),
        T0 + 10,
        &FakeVerifier,
    );
    node_w.handle(v(1, 0, VotePhase::Prevote, x), T0 + 11, &FakeVerifier);
    node_w.handle(v(2, 0, VotePhase::Prevote, x), T0 + 12, &FakeVerifier);
    assert_eq!(node_w.locked(), Some((0, x)));
    let mut p2b = BftEngine::new(
        domain(),
        params(),
        set.clone(),
        Some(identity(&kps, 2)),
        genesis_tip(),
        None,
    )
    .unwrap();
    p2b.start(T0, &FakeVerifier);
    p2b.handle(
        v(0, 1, VotePhase::Prevote, NIL_HASH),
        T0 + 20,
        &FakeVerifier,
    );
    p2b.handle(
        v(3, 1, VotePhase::Prevote, NIL_HASH),
        T0 + 21,
        &FakeVerifier,
    );
    let pz = extract_proposal(
        &p2b.propose(
            T0 + 30,
            vec![transfer_tx(1, 0, 7, 5)],
            vec![],
            vec![],
            &FakeVerifier,
        )
        .unwrap(),
    );
    let z = pz.block_hash();
    for i in [1usize, 2, 3] {
        node_w.handle(v(i, 1, VotePhase::Prevote, z), T0 + 40, &FakeVerifier);
    }
    assert_eq!(node_w.round(), 1);
    assert_eq!(node_w.locked(), Some((0, x)), "govde yokken kilit degismez");
    assert_eq!(node_w.valid(), Some((0, x)));
    // POL'suz (valid_round=None) Z önerisi tur 1'de gelse → nil (kilitli)
    let outs = node_w.handle(
        Message::Proposal(Box::new(pz.clone())),
        T0 + 41,
        &FakeVerifier,
    );
    // Gövde gelince tur-1 Q prevote + gövde ile kilit Z'ye geçer (INV-C4).
    assert!(has_vote(&outs, VotePhase::Prevote, NIL_HASH), "{outs:?}");
    assert_eq!(
        node_w.locked(),
        Some((1, z)),
        "Q prevote + govde → kilit yeni POL'e gecer"
    );
    assert_eq!(node_w.valid(), Some((1, z)));

    // Gövdesiz POL yolu: node_v X'e kilitli, tur 1'de Z'ye Q prevote görür
    // (gövde yok), tur 2'de Z valid_round=1 ile önerilir → prevote Z.
    let mut node_v = BftEngine::new(
        domain(),
        params(),
        set.clone(),
        Some(identity(&kps, 0)),
        genesis_tip(),
        None,
    )
    .unwrap();
    node_v.start(T0, &FakeVerifier);
    node_v.handle(
        Message::Proposal(Box::new(px.clone())),
        T0 + 10,
        &FakeVerifier,
    );
    node_v.handle(v(1, 0, VotePhase::Prevote, x), T0 + 11, &FakeVerifier);
    node_v.handle(v(2, 0, VotePhase::Prevote, x), T0 + 12, &FakeVerifier);
    for i in [1usize, 2, 3] {
        node_v.handle(v(i, 1, VotePhase::Prevote, z), T0 + 40, &FakeVerifier);
    }
    node_v.handle(
        v(1, 2, VotePhase::Prevote, NIL_HASH),
        T0 + 50,
        &FakeVerifier,
    );
    node_v.handle(
        v(2, 2, VotePhase::Prevote, NIL_HASH),
        T0 + 51,
        &FakeVerifier,
    );
    assert_eq!(node_v.round(), 2);
    assert_eq!(node_v.locked(), Some((0, x)));
    let mut rz = pz.clone();
    rz.round = 2;
    rz.valid_round = Some(1);
    rz.sig = kps[3].sign_digest(&rz.envelope_digest(&domain(), 0)); // proposer(1,2) = 3
    let outs = node_v.handle(
        Message::Proposal(Box::new(rz.clone())),
        T0 + 52,
        &FakeVerifier,
    );
    assert!(
        has_vote(&outs, VotePhase::Prevote, z),
        "POL ile kilit acilir: {outs:?}"
    );
    // Aynı öneri valid_round'suz gelseydi → nil (kilitli)
    let mut node_u = BftEngine::new(
        domain(),
        params(),
        set.clone(),
        Some(identity(&kps, 0)),
        genesis_tip(),
        None,
    )
    .unwrap();
    node_u.start(T0, &FakeVerifier);
    node_u.handle(
        Message::Proposal(Box::new(px.clone())),
        T0 + 10,
        &FakeVerifier,
    );
    node_u.handle(v(1, 0, VotePhase::Prevote, x), T0 + 11, &FakeVerifier);
    node_u.handle(v(2, 0, VotePhase::Prevote, x), T0 + 12, &FakeVerifier);
    node_u.handle(
        v(1, 2, VotePhase::Prevote, NIL_HASH),
        T0 + 50,
        &FakeVerifier,
    );
    node_u.handle(
        v(2, 2, VotePhase::Prevote, NIL_HASH),
        T0 + 51,
        &FakeVerifier,
    );
    let mut rz2 = pz.clone();
    rz2.round = 2;
    rz2.valid_round = None;
    rz2.sig = kps[3].sign_digest(&rz2.envelope_digest(&domain(), 0));
    let outs = node_u.handle(Message::Proposal(Box::new(rz2)), T0 + 52, &FakeVerifier);
    assert!(
        has_vote(&outs, VotePhase::Prevote, NIL_HASH),
        "POL'suz → nil: {outs:?}"
    );
}

#[test]
fn old_round_precommit_quorum_still_commits_and_bad_old_round_votes_are_rejected() {
    // node0 tur 1'de; tur 0'dan Q precommit(X) geç gelir → QC → commit
    // (spec §4: herhangi turdan geçerli QC). Bozuk imzalı eski oy → ret.
    let kps = keypairs(4);
    let set = validator_set(&kps, 0);
    let v = |i: usize, round: u32, phase: VotePhase, hash: Hash| {
        let mut v = Vote {
            height: 1,
            round,
            phase,
            block_hash: hash,
            validator_idx: i as u16,
            shadow: false,
            sig: vec![],
        };
        sign_vote(&kps[i], &domain(), 0, &mut v);
        v
    };
    let mut proposer1 = BftEngine::new(
        domain(),
        params(),
        set.clone(),
        Some(identity(&kps, 1)),
        genesis_tip(),
        None,
    )
    .unwrap();
    proposer1.start(T0, &FakeVerifier);
    let px = extract_proposal(
        &proposer1
            .propose(T0 + 5, vec![], vec![], vec![], &FakeVerifier)
            .unwrap(),
    );
    let x = px.block_hash();

    let mut node0 = BftEngine::new(
        domain(),
        params(),
        set.clone(),
        Some(identity(&kps, 0)),
        genesis_tip(),
        None,
    )
    .unwrap();
    node0.start(T0, &FakeVerifier);
    // Öneri hiç gelmedi; propose timer (100 ms) dolar → nil prevote
    let outs = node0.tick(T0 + 101, &FakeVerifier);
    assert!(has_vote(&outs, VotePhase::Prevote, NIL_HASH));
    assert_eq!(node0.step(), Step::Prevote);
    // Tur 1'e atla (f+1=2 oy)
    node0.handle(
        Message::Vote(v(2, 1, VotePhase::Prevote, NIL_HASH)),
        T0 + 150,
        &FakeVerifier,
    );
    node0.handle(
        Message::Vote(v(3, 1, VotePhase::Prevote, NIL_HASH)),
        T0 + 151,
        &FakeVerifier,
    );
    assert_eq!(node0.round(), 1);

    // Bozuk imzalı eski tur oyu → fail-closed
    let mut bad = v(1, 0, VotePhase::Precommit, x);
    bad.sig[0] ^= 0xFF;
    let outs = node0.handle(Message::Vote(bad), T0 + 160, &FakeVerifier);
    assert!(has_dropped(&outs, "oy imzasi"), "{outs:?}");

    // Geçerli eski tur precommit'leri (3 = Q) → QC kurulur, gövde yok → bekler
    for i in [1usize, 2, 3] {
        node0.handle(
            Message::Vote(v(i, 0, VotePhase::Precommit, x)),
            T0 + 170,
            &FakeVerifier,
        );
    }
    assert_eq!(node0.height(), 1, "govde olmadan commit YOK");
    // Eski tur önerisi yalnız bekleyen QC gövdesi olarak kabul edilir
    let outs = node0.handle(
        Message::Proposal(Box::new(px.clone())),
        T0 + 180,
        &FakeVerifier,
    );
    let committed = outs
        .iter()
        .find_map(|o| match o {
            Output::Commit(b) => Some(b.clone()),
            _ => None,
        })
        .expect("commit");
    assert_eq!(committed.qc.round, 0);
    assert_eq!(committed.qc.block_hash, x);
    assert_eq!(committed.rounds_used, 2);
    zagros_crypto::verify_qc(&committed.qc, &domain(), &set).unwrap();
    assert_eq!(node0.height(), 2);

    // Alakasız eski tur önerisi (QC beklemiyorken) → ret
    let mut other = BftEngine::new(
        domain(),
        params(),
        set.clone(),
        Some(identity(&kps, 0)),
        genesis_tip(),
        None,
    )
    .unwrap();
    other.start(T0, &FakeVerifier);
    other.handle(
        Message::Vote(v(2, 1, VotePhase::Prevote, NIL_HASH)),
        T0 + 10,
        &FakeVerifier,
    );
    other.handle(
        Message::Vote(v(3, 1, VotePhase::Prevote, NIL_HASH)),
        T0 + 11,
        &FakeVerifier,
    );
    assert_eq!(other.round(), 1);
    let outs = other.handle(Message::Proposal(Box::new(px)), T0 + 12, &FakeVerifier);
    assert!(has_dropped(&outs, "eski round"), "{outs:?}");
}

#[test]
fn heartbeat_from_idle_leader_prevents_view_change_until_idle_limit() {
    let kps = keypairs(4);
    let set = validator_set(&kps, 0);
    let mut leader = BftEngine::new(
        domain(),
        params(),
        set.clone(),
        Some(identity(&kps, 1)),
        genesis_tip(),
        None,
    )
    .unwrap();
    let mut follower = BftEngine::new(
        domain(),
        params(),
        set.clone(),
        Some(identity(&kps, 0)),
        genesis_tip(),
        None,
    )
    .unwrap();
    leader.start(T0, &FakeVerifier);
    follower.start(T0, &FakeVerifier);
    let first_deadline = follower.next_deadline().unwrap();
    assert_eq!(first_deadline, T0 + T_BASE);

    // Lider boşta: her 50 ms heartbeat → follower timer'ı ileri kayar
    let mut t = T0;
    for _ in 0..10 {
        t += 50;
        let outs = leader.heartbeat(t).unwrap();
        let hb = outs
            .iter()
            .find_map(|o| match o {
                Output::Broadcast(Message::Heartbeat(h)) => Some(h.clone()),
                _ => None,
            })
            .unwrap();
        let outs = follower.handle(Message::Heartbeat(hb), t, &FakeVerifier);
        assert!(outs.is_empty(), "{outs:?}");
        let outs = follower.tick(t, &FakeVerifier);
        assert!(outs.is_empty());
        assert_eq!(
            follower.step(),
            Step::Propose,
            "heartbeat'te view-change yok"
        );
        assert_eq!(follower.next_deadline(), Some(t + T_BASE));
    }
    // Lider olmayan node'dan heartbeat → ret
    let mut hb_bad = zagros_types::consensus::Heartbeat {
        height: 1,
        round: 0,
        timestamp_ms: t,
        validator_idx: 2,
        sig: vec![],
    };
    zagros_crypto::sign_heartbeat(&kps[2], &domain(), 0, &mut hb_bad);
    let outs = follower.handle(Message::Heartbeat(hb_bad), t, &FakeVerifier);
    assert!(has_dropped(&outs, "lider olmayan"));

    // İdle sınırı (10 s) dolunca heartbeat timer'ı sıfırlayamaz → timeout → nil
    let late = T0 + 10_000 + 1;
    let outs = leader.heartbeat(late).unwrap();
    let hb = outs
        .iter()
        .find_map(|o| match o {
            Output::Broadcast(Message::Heartbeat(h)) => Some(h.clone()),
            _ => None,
        })
        .unwrap();
    let outs = follower.handle(Message::Heartbeat(hb), late, &FakeVerifier);
    assert!(has_dropped(&outs, "bos blok vadesi"), "{outs:?}");
    let outs = follower.tick(late + T_BASE, &FakeVerifier);
    assert!(
        has_vote(&outs, VotePhase::Prevote, NIL_HASH),
        "idle siniri sonrasi timeout: {outs:?}"
    );
}

#[test]
fn wrong_state_root_proposer_is_skipped_via_nil_quorum_view_change() {
    let mut sim = Sim::new(build_nodes(5, &[(1, Behavior::WrongRoot)], false, 0), 2, 2);
    sim.boot();
    sim.run(4_000, T0 + 120_000);
    sim.assert_safety();
    assert!(sim.min_honest_height() >= 4, "{}", sim.min_honest_height());
    for n in sim.honest() {
        assert!(n
            .dropped
            .iter()
            .any(|d| d.contains("state_root uyusmazligi")));
        assert_eq!(n.committed[0].3, 1, "h=1 yanlis kok → tur 1 (node 2)");
        assert!(
            n.view_changes
                .iter()
                .any(|(h, _, _, r)| *h == 1 && *r == ViewChangeReason::NilQuorum),
            "{:?}",
            n.view_changes
        );
    }
}

#[test]
fn partition_below_quorum_halts_then_rejoins_and_progresses_without_divergence() {
    // 5 node, Q=4. İki node izole → 3 < Q → commit yok (timeout'lar tur
    // artırır ama QC imkânsız). Heal → tüm node'lar aynı yükseklikte devam eder.
    let mut sim = Sim::new(build_nodes(5, &[], false, 0), 4, 2);
    sim.set_isolated(3, true);
    sim.set_isolated(4, true);
    sim.boot();
    sim.run(3_000, T0 + 5_000);
    sim.assert_safety();
    assert_eq!(sim.max_honest_height(), 0, "Q altinda commit OLAMAZ");
    assert!(
        sim.nodes[0].engine.round() >= 2,
        "timeout'lar tur artirdi: {}",
        sim.nodes[0].engine.round()
    );
    assert!(sim.nodes[0].engine.stats().view_changes_total >= 2);

    sim.set_isolated(3, false);
    sim.set_isolated(4, false);
    sim.run(6_000, T0 + 120_000);
    sim.assert_safety();
    assert!(
        sim.min_honest_height() >= 5,
        "heal sonrasi ilerleme: {}",
        sim.min_honest_height()
    );
    // Heal sonrası geride kalan node'lar (3,4) tur atlama ile yetişti; sapma yok
    for n in &sim.nodes {
        assert_eq!(n.committed[0].1, sim.nodes[0].committed[0].1);
    }
}

#[test]
fn single_isolated_node_rejoining_at_same_height_catches_up_without_catch_up_protocol() {
    // 7 node (Q=5, f=2): node 6 izole iken zincir ilerler; izole node h=1'de
    // kalır (G6 catch-up yok), sapma yok, safety korunur.
    let mut sim = Sim::new(build_nodes(7, &[], false, 0), 13, 2);
    sim.set_isolated(6, true);
    sim.boot();
    sim.run(3_000, T0 + 30_000);
    sim.assert_safety();
    assert!(sim.nodes[0].committed.len() >= 3);
    assert_eq!(sim.nodes[6].committed.len(), 0);
    assert_eq!(sim.nodes[6].engine.height(), 1);
    sim.set_isolated(6, false);
    sim.run(3_000, T0 + 60_000);
    sim.assert_safety();
    // Geride kalan node eski yükseklik mesajlarını düşürür, ileriye dair olanları
    // tamponlar; commit üretmez (QC'siz commit yok), G6 catch-up'a kadar.
    assert_eq!(sim.nodes[6].committed.len(), 0);
    assert!(sim.nodes[6].engine.height() == 1);
}

#[test]
fn timeout_storm_under_extreme_delay_converges_with_backoff() {
    // Gecikme (≤ 400 ms) > T_propose(0)=100: ilk turlarda sürekli timeout;
    // backoff ile T büyür, sonunda commit. Safety korunur, view-change > 0.
    let mut sim = Sim::new(build_nodes(5, &[], false, 0), 99, 400);
    sim.boot();
    sim.run(20_000, T0 + 600_000);
    sim.assert_safety();
    assert!(
        sim.min_honest_height() >= 3,
        "firtina altinda ilerleme: {}",
        sim.min_honest_height()
    );
    let total_vc: u64 = sim
        .honest()
        .map(|n| n.engine.stats().view_changes_total)
        .sum();
    assert!(total_vc > 0, "timeout firtinasi view-change uretmeli");
    // Hiçbir commit QC'siz değil (Commit çıktısında verify_qc assert'i zaten çalıştı)
    for n in sim.honest() {
        assert!(
            n.committed.iter().all(|c| c.3 <= 20),
            "tur sayisi makul (backoff tavani)"
        );
    }
}

#[test]
fn no_commit_without_quorum_even_under_timeouts_and_round_skips() {
    // 4 node, Q=3; yalnız 2 dürüst node birbirini görür (diğer ikisi izole).
    // Ne kadar timeout/tur olursa olsun commit YOK.
    let mut sim = Sim::new(build_nodes(4, &[], false, 0), 5, 2);
    sim.set_isolated(2, true);
    sim.set_isolated(3, true);
    sim.boot();
    sim.run(5_000, T0 + 20_000);
    sim.assert_safety();
    assert_eq!(sim.max_honest_height(), 0);
    assert!(sim.nodes[0].engine.round() >= 3);
    assert!(sim.nodes[0].engine.stats().timeouts_total >= 3);
}

// G8 finalizasyon, 3-strike → jail → bond-lock, gerçek üretim yolu
// (commit_block + Executor + advance_epoch_if_due) ile; blok zaman damgaları
// kontrollü seçilir (epoch_seconds × 3 gerçek zaman beklenmez), QC'ler gerçek Ed25519 imzalı.
#[test]
fn silent_validator_accumulates_liveness_strikes_and_is_demoted_to_probation_via_real_epoch_boundaries(
) {
    let kps = keypairs(5);
    // 🚨 Tarih oynatma kapisi: canlilik v2 (Probation cezasi) yalniz
    // epoch >= LIVENESS_V2_ACTIVATION_EPOCH'ta gecerli; oncesi eski jail kurali.
    // Test bu yuzden dogrudan aktivasyon epoch'undan baslar.
    let v2_epoch = params::LIVENESS_V2_ACTIVATION_EPOCH;
    let base_set = validator_set(&kps, v2_epoch);
    let dom = domain();
    let p = params();
    p.validate().unwrap();

    let state: Arc<dyn State> = Arc::new(StateDbManager::new(Arc::new(MemoryStorage::default())));
    let genesis_ts_secs: u128 = (T0 / 1000) as u128;
    params::store_chain_params(state.as_ref(), &p).unwrap();
    let ts_acc = AccountState {
        balance: genesis_ts_secs,
        ..Default::default()
    };
    state
        .set_account(&zagros_types::GENESIS_TIMESTAMP_KEY.to_string(), ts_acc)
        .unwrap();
    validator_set::store_active_set(state.as_ref(), &base_set).unwrap();
    validator_set::store_active_set_epoch_snapshot(state.as_ref(), &base_set).unwrap();
    let min_stake = params::min_validator_stake_zagros(state.as_ref(), &p).unwrap();
    for m in &base_set.members {
        let vacc = AccountState {
            consensus_pubkey: m.consensus_pubkey,
            validator_status: Some(ValidatorStatus::Active),
            validator_status_epoch: v2_epoch,
            staked_balance: min_stake,
            is_registered_validator: true,
            ..Default::default()
        };
        state.set_account(&m.address, vacc).unwrap();
    }
    state.flush().unwrap();

    let executor = Arc::new(Executor::new(state.clone()));
    let scheduler = Arc::new(Scheduler::new(executor.clone()));
    let rt = Runtime::new(state.clone(), executor, scheduler);

    // Indeks 1 KALICI OLARAK SESSİZ, hiçbir QC'de onun imzası YOK (diğer 4
    // 5-üyeli kümede Q=4 sağlar, quorum onsuz da oluşur, gerçekçi: yalnız
    // BU validator'ın KENDİ katılımı ölçülür, zincirin ilerlemesi engellenmez).
    let silent_idx: u16 = 1;
    let silent_addr = base_set.members[silent_idx as usize].address.clone();

    // 🚨 Ceza Probation; gereken strike `effective_max_liveness_strikes` clamp'inden
    // (etkin 12). Sonraki her blok tam bir epoch sınırı aşar.
    let strikes_needed = params::effective_max_liveness_strikes(&p) as u64;
    let mut block_number: u64 = 1;
    for crossing in 0..(strikes_needed + 1) {
        let current_set = validator_set::load_active_set(state.as_ref()).unwrap();
        let epoch = current_set.epoch;
        let block_ts_secs =
            genesis_ts_secs + ((v2_epoch + crossing) * p.epoch_seconds) as u128 + 10;

        let block_hash = keccak256(&block_number.to_le_bytes());
        let mut votes = Vec::new();
        for (idx, kp) in kps.iter().enumerate() {
            if idx as u16 == silent_idx {
                continue;
            }
            let mut v = Vote {
                height: block_number,
                round: 0,
                phase: VotePhase::Precommit,
                block_hash,
                validator_idx: idx as u16,
                shadow: false,
                sig: Vec::new(),
            };
            sign_vote(kp, &dom, epoch, &mut v);
            votes.push(v);
        }
        let qc: QuorumCertificate =
            build_qc(&votes, &dom, &current_set, block_number, 0, block_hash)
                .expect("gercek Ed25519 imzalariyla GECERLI bir QC kurulmali (>=Q imza)");

        let root = rt
            .simulate_block(block_number, block_ts_secs, &[], &[], Some(&qc), &[], None)
            .expect("simulate_block (gercek uretim yolu) basarili olmali");
        rt.commit_block(
            block_number,
            block_ts_secs,
            &[],
            &[],
            Some(&qc),
            &[],
            None,
            root,
        )
        .expect("commit_block (gercek uretim yolu) basarili olmali");

        block_number += 1;
    }

    let acc = state
        .get_account(&silent_addr)
        .unwrap()
        .expect("sessiz validator hesabi");
    assert_eq!(
        acc.validator_status,
        Some(ValidatorStatus::Probation),
        "{strikes_needed} ardisik dusuk-katilim epoch'undan sonra validator PROBATION olmali (liveness={:?})",
        acc.liveness
    );
    assert_ne!(
        acc.validator_status,
        Some(ValidatorStatus::Jailed),
        "canlilik cezasi JAIL ETMEZ - jail yalniz equivocation'a ait"
    );
    assert_eq!(acc.jailed_until, 0, "canlilik cezasi jailed_until YAZMAZ");
    // Canlilik cezasi SERMAYEYE DOKUNMAZ: ne musadere, ne bond kilidi.
    assert_eq!(
        acc.staked_balance, min_stake,
        "canlilik cezasi musadere YAPMAZ"
    );
    assert_eq!(acc.bond_unlock_at, 0, "canlilik cezasi bond kilidi KURMAZ");
    assert_eq!(acc.liveness.strikes, 0, "ceza sonrasi sayac sifirlanir");

    // Probation'a düşen validator kümede olmamalı (5→4); circuit breaker 4→3'e izin vermezdi.
    let final_set = validator_set::load_active_set(state.as_ref()).unwrap();
    assert!(
        !final_set
            .members
            .iter()
            .any(|m| m.address.eq_ignore_ascii_case(&silent_addr)),
        "cezalandirilan validator aktif kumede KALMAMALI"
    );
    assert_eq!(
        final_set.len(),
        4,
        "kume 5'ten 4'e dusmeli (taban MIN_VALIDATORS'da, izin verilir)"
    );
}

// ⏱️ QC KAPANIŞ TOLERANSI (grace), kullanıcı kararı

/// Sim zamanlaması: T_BASE=100 → t_vote=50, grace tavanı=25. "Uzak" node'un
/// (idx 4) mesajları +15 ms geç gelir; diğerleri 1-3 ms.
fn far_node_sim(grace_ms: u64, far_delay: u64, behaviors: &[(usize, Behavior)]) -> Sim {
    let mut nodes = build_nodes(5, behaviors, false, 0);
    for n in nodes.iter_mut() {
        n.engine.set_qc_grace_ms(grace_ms);
    }
    let mut sim = Sim::new(nodes, 7, 3);
    sim.extra_delay_from[4] = far_delay;
    sim
}

fn qc_summary(sim: &Sim) -> (usize, usize, usize, usize, usize, usize) {
    // (toplam commit, N imzalı, N-1 imzalı, Full, GraceExpired, Clamped), honest node'ların hepsi
    let (mut total, mut full_n, mut short, mut full, mut expired, mut clamped) = (0, 0, 0, 0, 0, 0);
    for n in sim.honest() {
        for (signers, close) in &n.qc_info {
            total += 1;
            if *signers == 5 {
                full_n += 1
            } else {
                short += 1
            }
            match close {
                QcClose::Full => full += 1,
                QcClose::GraceExpired => expired += 1,
                QcClose::Clamped => clamped += 1,
                QcClose::Immediate => {}
            }
        }
    }
    (total, full_n, short, full, expired, clamped)
}

/// Taban: grace=0 (eski davranış) → uzak node'un oyu QC'lere sistematik olarak GİREMEZ.
#[test]
fn without_grace_the_far_validator_is_systematically_left_out_of_qcs() {
    let mut sim = far_node_sim(0, 15, &[]);
    sim.boot();
    sim.run(6_000, T0 + 30_000);
    sim.assert_safety();
    assert!(sim.min_honest_height() >= 10);
    let (total, _full_n, short, ..) = qc_summary(&sim);
    assert!(
        short * 2 > total,
        "uzak node'suz QC cogunlukta olmali: {short}/{total}"
    );
    // uzak node'un kendi gözünden bile (kendi oyu yerel, ötekiler 1-3 ms) sorun onun oyunun ötekilere geç varması
    let far_missing = sim
        .honest()
        .flat_map(|n| n.qc_info.iter())
        .filter(|(s, _)| *s < 5)
        .count();
    assert!(far_missing > 0);
}

/// Grace=20 (tavan 25 içinde): tüm N oy gelince ANINDA kapanır (Full), uzak node her QC'de.
/// Zaman aşımı/view-change yok; zincir ilerlemeye devam eder.
#[test]
fn with_grace_all_votes_are_awaited_and_qcs_include_the_far_validator() {
    let mut sim = far_node_sim(20, 15, &[]);
    sim.boot();
    sim.run(6_000, T0 + 30_000);
    sim.assert_safety();
    assert!(
        sim.min_honest_height() >= 10,
        "grace zinciri yavaslatmamali"
    );
    let (total, full_n, short, full, expired, clamped) = qc_summary(&sim);
    assert_eq!(
        short, 0,
        "grace ile hicbir QC eksik imzali olmamali ({short}/{total})"
    );
    assert_eq!(full_n, total);
    assert!(
        full > 0 && expired == 0 && clamped == 0,
        "full={full} expired={expired} clamped={clamped}"
    );
    for n in sim.honest() {
        assert!(n.view_changes.is_empty(), "{:?}", n.view_changes);
        assert_eq!(n.engine.stats().timeouts_total, 0);
    }
}

/// Bir validatör SESSİZ (oy vermiyor): grace dolar, Q imzayla kapanır (GraceExpired),
/// tur zaman aşımı ZİNCİRLENMEZ (view change yok), zincir ilerler.
#[test]
fn silent_validator_makes_grace_expire_without_view_changes() {
    let mut sim = far_node_sim(20, 0, &[(4, Behavior::Silent)]);
    sim.boot();
    sim.run(6_000, T0 + 30_000);
    sim.assert_safety();
    assert!(sim.min_honest_height() >= 10);
    let (total, full_n, short, full, expired, _clamped) = qc_summary(&sim);
    assert_eq!(full_n, 0, "sessiz node hicbir QC'de olamaz");
    assert_eq!(short, total);
    assert!(
        expired * 10 >= total * 9,
        "kapanislar grace dolunca olmali: expired={expired}/{total} full={full}"
    );
    for n in sim.honest() {
        // sessiz node'un kendi liderliği zaten propose timeout üretir (FM-C1); onun dışında yok
        let non_leader_vc = n.view_changes.iter().filter(|(h, ..)| (h % 5) != 4).count();
        assert_eq!(
            non_leader_vc, 0,
            "grace view-change uretmemeli: {:?}",
            n.view_changes
        );
    }
}

/// INVARIANT: grace, precommit deadline'ını ASLA geçemez. Tavanın çok üstünde bir
/// grace (200 ≫ t_vote 50) verilse bile motor beklemeyi kırpar (Clamped) ya da
/// hemen kapatır; zaman aşımı/view-change ÜRETMEZ, zincir ilerler.
#[test]
fn grace_never_exceeds_the_round_budget_even_if_misconfigured() {
    let mut sim = far_node_sim(200, 15, &[]);
    sim.boot();
    sim.run(6_000, T0 + 30_000);
    sim.assert_safety();
    assert!(
        sim.min_honest_height() >= 10,
        "kirpilan grace zinciri durdurmamali"
    );
    for n in sim.honest() {
        assert!(
            n.view_changes.is_empty(),
            "grace tur butcesini asip view-change uretti: {:?}",
            n.view_changes
        );
        assert_eq!(n.engine.stats().timeouts_total, 0);
    }
    let (total, _full_n, _short, _full, _expired, clamped) = qc_summary(&sim);
    assert!(clamped > 0 || total > 0);
}
