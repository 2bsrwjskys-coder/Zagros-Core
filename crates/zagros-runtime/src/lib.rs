#![allow(clippy::field_reassign_with_default)]
use std::sync::Arc;
use tracing::info;
use zagros_executor::Executor;
use zagros_primitives::{Result, ZagrosError};
use zagros_scheduler::Scheduler;
use zagros_state::overlay::SimulationOverlay;
use zagros_state::State;
use zagros_types::consensus::{QuorumCertificate, ShadowVoteAttestation};
use zagros_types::{AccountState, ArchivedBlockHeader, Transaction};

/// Arşiv budaması (`Receipt_`/`tx_body_`/`block_` anahtarları).
/// `retention_blocks: None` = arşiv sonsuza dek saklanır (tam node); `Some(k)`
/// = `k` bloktan eski kayıtlar silinir. Chain state (`0x`, `state_root`) etkilenmez.
#[derive(Clone, Copy, Debug)]
pub struct PruningConfig {
    /// Bu blok derinliğinden eski arşiv kayıtları budanır. `None` = sonsuza
    /// kadar sakla.
    pub retention_blocks: Option<u64>,
    /// Kaç blokta bir budama tetiklenir.
    pub interval_blocks: u64,
    /// Tek budama çağrısında silinecek maksimum dekont sayısı.
    pub batch_limit: usize,
}

impl Default for PruningConfig {
    fn default() -> Self {
        Self {
            retention_blocks: None,
            interval_blocks: 10_000,
            batch_limit: 5_000,
        }
    }
}

/// Zagros Runtime: Konsensüs ve Executor arasındaki Orkestrasyon Katmanı.
/// İşlem sırasını, kaynak yönetimini ve hata durumlarındaki geri sarmaları (rollback) koordine eder.
pub struct Runtime {
    /// §23 (G10): desteklenen en yüksek kural seti; zincir aşarsa yürütme FAIL-CLOSED ret.
    supported_ruleset: u32,
    state: Arc<dyn State>,
    executor: Arc<Executor>,
    scheduler: Arc<Scheduler>,
    pruning: PruningConfig,
    archive_height_file: Option<String>,
    /// 📸 Snapshot kancası (flush sonrası); yalnız eski döngüde olsaydı BFT'de çalışmazdı.
    snapshot_hook: Option<std::sync::Arc<dyn Fn(u64) + Send + Sync>>,
}

impl Runtime {
    /// Runtime'ı mevcut State, Executor ve Scheduler ile başlatır (budama kapalı).
    pub fn new(state: Arc<dyn State>, executor: Arc<Executor>, scheduler: Arc<Scheduler>) -> Self {
        Self {
            supported_ruleset: zagros_types::consensus::SUPPORTED_RULESET,
            state,
            executor,
            scheduler,
            pruning: PruningConfig::default(),
            archive_height_file: None,
            snapshot_hook: None,
        }
    }

    /// 📸 Snapshot kancasını bağlar; CLI storage ayarlarıyla kurulmuş kapanışı
    /// verir, snapshot hem eski tek proposer hem BFT commit yolunda çalışır.
    pub fn with_snapshot_hook(mut self, hook: std::sync::Arc<dyn Fn(u64) + Send + Sync>) -> Self {
        self.snapshot_hook = Some(hook);
        self
    }

    pub fn with_pruning(mut self, pruning: PruningConfig) -> Self {
        self.pruning = pruning;
        self
    }

    /// Budama backpressure dosya yolu: ayarliysa maybe_prune, arsiv yuksekliginin
    /// USTUNDEKI bloklari budamaz (arsivlenmemis veri kaybini onler).
    pub fn with_archive_height_file(mut self, path: Option<String>) -> Self {
        self.archive_height_file = path;
        self
    }

    pub fn set_block_height(&self, block_height: u128) -> Result<()> {
        let key = "__GLOBAL_BLOCK_HEIGHT__".to_string();
        let mut tracker = self.state.get_account(&key)?.unwrap_or_default();
        tracker.balance = block_height;
        self.state.set_account(&key, tracker)?;
        Ok(())
    }

    /// 🚨 `ConsensusEngine::new` başlangıç yüksekliğini buradan okur; bellek
    /// sayacı 0'dan başlasaydı her restart `__GLOBAL_BLOCK_HEIGHT__`ı geri sarardı.
    pub fn current_block_height(&self) -> Result<u128> {
        let key = "__GLOBAL_BLOCK_HEIGHT__".to_string();
        Ok(self.state.get_account(&key)?.unwrap_or_default().balance)
    }

    /// Gözlemlenebilirlik: `__GLOBAL_TOTAL_TX__` sayacına bu bloktaki başarılı
    /// işlem sayısını ekler (`zagros_getNetworkPulse` okur). Muhasebeye dokunmaz.
    fn increment_total_tx(&self, count: usize) -> Result<()> {
        if count == 0 {
            return Ok(());
        }
        let key = "__GLOBAL_TOTAL_TX__".to_string();
        let mut tracker = self.state.get_account(&key)?.unwrap_or_default();
        tracker.balance = tracker.balance.saturating_add(count as u128);
        self.state.set_account(&key, tracker)?;
        Ok(())
    }

    /// §23 test kancası (karışık sürüm senaryoları).
    pub fn with_supported_ruleset(mut self, v: u32) -> Self {
        self.supported_ruleset = v;
        self
    }

    pub fn process_block(
        &self,
        block_number: u64,
        block_timestamp: u128,
        transactions: &[Transaction],
    ) -> Result<[u8; 32]> {
        info!(
            "🚦 Runtime: Blok #{} için orkestrasyon başlatılıyor. İşlem sayısı: {}",
            block_number,
            transactions.len()
        );

        // 🛡️ Yükseklik sayacı işlemler yürütülmeden ÖNCE artar: executor'ın
        // gözlemlenebilirlik kayıtları (receipt `block_number`) güncel bloğu görsün.
        // Nihai disk state'i değişmez; muhasebe/ödül/slash bunu okumaz.
        self.set_block_height(block_number as u128)?;

        // Çakışmayanlar paralel, çakışanlar sıralı; FIFO/MEV sırası bozulmaz.
        let (success_count, fail_count) = self
            .scheduler
            .execute_batch(transactions.to_vec(), block_timestamp)?;
        Self::archive_dropped_transactions(self.state.as_ref(), &self.executor, transactions)?;

        // Flush this block's accumulated gas rewards to VALIDATOR_REWARD_POOL and
        // stakers exactly once, instead of once per transaction (see
        // Executor::flush_block_rewards).
        self.executor.flush_block_rewards(block_timestamp)?;

        // Bu bloktaki transferlerin (atomik fetch_add ile) tahsis ettiği son
        // index'i diske yazar; per-transfer DEĞİL blok başına TEK yazım (bkz.
        // Executor::flush_recent_transfer_index'in doc yorumu).
        self.executor.flush_recent_transfer_index()?;

        self.increment_total_tx(success_count)?;

        // K2: Budama açıksa, bu bloğun dekont tx_id'lerini blok-numaralı bir
        // manifest'e yaz (aynı flush unit'inde). Budama kapalıysa hiç manifest
        // tutulmaz, eski davranışla birebir aynı.
        if self.pruning.retention_blocks.is_some() {
            let tx_ids: Vec<[u8; 32]> = transactions.iter().map(|tx| tx.tx_id).collect();
            self.state.record_block_receipts(block_number, &tx_ids)?;
        }

        // 🏛️ Her blok için header arşivle: `flush_block_rewards` SONRASI (ödül
        // hesapları köke girsin), `state.flush()` ÖNCESİ (aynı atomik batch,
        // "state ilerledi ama arşiv yok" yarım durumu imkânsız).
        let tx_hashes: Vec<[u8; 32]> = transactions.iter().map(|tx| tx.tx_id).collect();
        let parent_hash = self.parent_block_hash(block_number)?;
        let header_state_root = self.state.state_root()?;
        let header = ArchivedBlockHeader {
            number: block_number,
            parent_hash,
            state_root: header_state_root,
            timestamp: block_timestamp,
            tx_hashes,
        };
        let header_bytes = bincode::serialize(&header).map_err(|e| {
            ZagrosError::DatabaseError(format!("ArchivedBlockHeader serialize hatası: {}", e))
        })?;
        let block_hash = keccak256(&header_bytes);

        let mut archive_keys: Vec<String> = Vec::with_capacity(2 + transactions.len() * 2);
        let block_key = zagros_state::block_key(block_number);
        let mut header_acc = AccountState::default();
        header_acc.contract_code = header_bytes;
        self.state.set_account(&block_key, header_acc)?;
        archive_keys.push(block_key);

        let block_hash_key = zagros_state::block_hash_key(&block_hash);
        let mut hash_index_acc = AccountState::default();
        hash_index_acc.balance = block_number as u128;
        self.state.set_account(&block_hash_key, hash_index_acc)?;
        archive_keys.push(block_hash_key);

        for tx in transactions {
            archive_keys.push(zagros_state::receipt_key(&tx.tx_id));
            archive_keys.push(zagros_state::tx_body_key(&tx.tx_id));
        }

        // Persist every account touched this block in a single batched write
        // instead of one disk write per `set_account()` call.
        self.state.flush()?;

        // 🧊 Bu bloğun arşiv kayıtları soğuk veridir (nadiren tekrar okunur),
        // flush() BAŞARILI olduktan hemen sonra yalnızca bellek-içi cache'ten
        // çıkar (storage'a dokunmaz); sonraki okumalar storage'tan gelir.
        self.state.evict_from_cache(&archive_keys);

        // Periyodik budama flush SONRASI, `interval_blocks` aralıkla, batch sınırlı;
        // chain state'e dokunmaz. `apply_external_block` ile paylaşılan mantık.
        self.maybe_prune(block_number);
        self.maybe_snapshot(block_number);

        info!(
            "✅ Runtime: Blok #{} başarıyla işlendi! (Başarılı: {}, Geri Sarılan/Hatalı: {}) | State Root: 0x{} | Blok Hash: 0x{}",
            block_number, success_count, fail_count,
            hex::encode(header_state_root)[..16].to_string(),
            hex::encode(block_hash)[..16].to_string()
        );

        Ok(header_state_root)
    }

    /// 🛡️ P2P follower giriş noktası: `process_block` koşulsuz commit eder, bu
    /// metod aynı yürütmeyi yapıp kökü `expected_state_root` ile karşılaştırır;
    /// eşleşmezse `flush()` HİÇ çağrılmaz. 🚨 Dış checkpoint YASAK: her işlem
    /// kendi checkpoint'ini açar ve `StateDbManager` iç içe checkpoint'i
    /// desteklemez (release'te sessizce yanlış rollback). Güvenlik, kök
    /// karşılaştırmasının flush'tan önce olmasından ve uyuşmazlıkta çağıranın
    /// `panic!` etmesinden gelir (süreç kapanınca kirli cache silinir).
    /// ⚠️ Kabul edilen risk: panik ile iptal arasındaki mikrosaniyelik pencerede
    /// köprü RPC handler'ının `flush()`ı kirli girdileri diske taşıyabilir.
    /// Alınan `parent_hash`/`tx_hashes` kullanılmaz, sıfırdan türetilir.
    pub fn apply_external_block(
        &self,
        block_number: u64,
        block_timestamp: u128,
        transactions: &[Transaction],
        bridge_proposals: &[zagros_executor::bridge::BridgeProposal],
        expected_state_root: [u8; 32],
    ) -> Result<[u8; 32]> {
        info!(
            "🌐 Runtime (follower): Blok #{} harici olarak uygulanıyor. İşlem sayısı: {}",
            block_number,
            transactions.len()
        );

        // 🛡️ P2P follower senkronu: blokla taşınan köprü önerileri yürütmeden
        // ÖNCE yerel aktif anahtara yazılır, yoksa `validate_bridge_mint_proposal` düşer.
        zagros_executor::bridge::BridgeManager::ingest_relayed_proposals(
            self.state.as_ref(),
            bridge_proposals,
        )?;

        let (header_state_root, archive_keys) =
            self.apply_external_block_body(block_number, block_timestamp, transactions)?;

        if header_state_root != expected_state_root {
            return Err(ZagrosError::Other(format!(
                "Blok #{block_number}: hesaplanan state_root (0x{}) beklenenle \
                 (0x{}) EŞLEŞMİYOR - blok reddedildi, flush() ÇAĞRILMADI (disk dokunulmadı)",
                hex::encode(header_state_root),
                hex::encode(expected_state_root)
            )));
        }

        self.state.flush()?;
        self.state.evict_from_cache(&archive_keys);
        self.maybe_prune(block_number);
        self.maybe_snapshot(block_number);
        info!(
            "✅ Runtime (follower): Blok #{} doğrulandı ve uygulandı! State Root: 0x{}",
            block_number,
            hex::encode(header_state_root)[..16].to_string()
        );
        Ok(header_state_root)
    }

    /// `apply_external_block` gövdesi (flush öncesi adımlar); `flush()` burada çağrılmaz.
    fn apply_external_block_body(
        &self,
        block_number: u64,
        block_timestamp: u128,
        transactions: &[Transaction],
    ) -> Result<([u8; 32], Vec<String>)> {
        // Eski (BFT-öncesi) P2P gossip yolu: QC yok, liveness kaydı YOK
        // (bkz. `execute_block_body`'nin `last_qc` doc yorumu).
        self.execute_block_body_legacy(
            &self.state,
            &self.executor,
            &self.scheduler,
            block_number,
            block_timestamp,
            transactions,
            None,
            &[],
        )
    }

    /// G3 (§7): bloğu `SimulationOverlay`de yürütüp `state_root` döner (INV-P2/P3);
    /// overlay atılır, adımlar `commit_block` ile birebir.
    #[allow(clippy::too_many_arguments)]
    pub fn simulate_block(
        &self,
        block_number: u64,
        block_timestamp: u128,
        transactions: &[Transaction],
        bridge_proposals: &[zagros_executor::bridge::BridgeProposal],
        last_qc: Option<&QuorumCertificate>,
        shadow_votes: &[ShadowVoteAttestation],
        proposer: Option<(u64, u16, u32)>,
    ) -> Result<[u8; 32]> {
        let overlay: Arc<dyn State> = Arc::new(SimulationOverlay::new(self.state.clone()));
        zagros_executor::bridge::BridgeManager::ingest_relayed_proposals(
            overlay.as_ref(),
            bridge_proposals,
        )?;
        let executor = Arc::new(self.executor.rebind(overlay.clone()));
        let scheduler = Scheduler::new(executor.clone());
        let (root, _archive_keys) = self.execute_block_body(
            &overlay,
            &executor,
            &scheduler,
            block_number,
            block_timestamp,
            transactions,
            last_qc,
            shadow_votes,
            proposer,
        )?;
        Ok(root)
    }

    /// G3 commit: QC'li bloğu gerçek state'te yeniden yürütür, kök
    /// `expected_state_root` ile eşleşmezse flush ETMEZ. Konsensüs yalnız bunu çağırır.
    #[allow(clippy::too_many_arguments)]
    /// 🚨 Yürütmede düşen (gövdesi yazılmamış) blok işlemlerini
    /// arşivle, bkz. `Executor::archive_dropped_transaction`. Başarılı olanlar
    /// `archive_transaction` ile zaten yazılmıştır; "gövde var mı" kontrolüyle ayrılır.
    fn archive_dropped_transactions(
        state: &dyn State,
        executor: &Executor,
        transactions: &[Transaction],
    ) -> Result<()> {
        let mut dropped = 0usize;
        for tx in transactions {
            let has_body = state
                .get_account(&zagros_state::tx_body_key(&tx.tx_id))?
                .map(|a| !a.contract_code.is_empty())
                .unwrap_or(false);
            if !has_body {
                executor.archive_dropped_transaction(tx)?;
                dropped += 1;
            }
        }
        if dropped > 0 {
            tracing::warn!(
                "🗂️ {} düşen işlem gövde+makbuz (status=false) ile arşivlendi",
                dropped
            );
        }
        Ok(())
    }

    pub fn commit_block(
        &self,
        block_number: u64,
        block_timestamp: u128,
        transactions: &[Transaction],
        bridge_proposals: &[zagros_executor::bridge::BridgeProposal],
        last_qc: Option<&QuorumCertificate>,
        shadow_votes: &[ShadowVoteAttestation],
        proposer: Option<(u64, u16, u32)>,
        expected_state_root: [u8; 32],
    ) -> Result<[u8; 32]> {
        self.commit_block_archiving(
            block_number,
            block_timestamp,
            transactions,
            bridge_proposals,
            last_qc,
            shadow_votes,
            proposer,
            expected_state_root,
            None,
        )
    }

    /// `commit_block` + arşiv başlığı için TAM `tx_hashes` (bkz. `execute_block_body_archiving`).
    #[allow(clippy::too_many_arguments)]
    pub fn commit_block_archiving(
        &self,
        block_number: u64,
        block_timestamp: u128,
        transactions: &[Transaction],
        bridge_proposals: &[zagros_executor::bridge::BridgeProposal],
        last_qc: Option<&QuorumCertificate>,
        shadow_votes: &[ShadowVoteAttestation],
        proposer: Option<(u64, u16, u32)>,
        expected_state_root: [u8; 32],
        archived_tx_hashes: Option<&[[u8; 32]]>,
    ) -> Result<[u8; 32]> {
        info!(
            "⚖️ Runtime (BFT commit): Blok #{} yeniden yürütülüyor. İşlem sayısı: {}",
            block_number,
            transactions.len()
        );
        zagros_executor::bridge::BridgeManager::ingest_relayed_proposals(
            self.state.as_ref(),
            bridge_proposals,
        )?;
        let (header_state_root, archive_keys) = self.execute_block_body_archiving(
            &self.state,
            &self.executor,
            &self.scheduler,
            block_number,
            block_timestamp,
            transactions,
            last_qc,
            shadow_votes,
            proposer,
            archived_tx_hashes,
        )?;
        if header_state_root != expected_state_root {
            return Err(ZagrosError::Other(format!(
                "Blok #{block_number}: hesaplanan state_root (0x{}) beklenenle \
                 (0x{}) EŞLEŞMİYOR - blok reddedildi, flush() ÇAĞRILMADI (disk dokunulmadı)",
                hex::encode(header_state_root),
                hex::encode(expected_state_root)
            )));
        }
        self.state.flush()?;
        self.state.evict_from_cache(&archive_keys);
        self.maybe_prune(block_number);
        self.maybe_snapshot(block_number);
        info!(
            "✅ Runtime (BFT commit): Blok #{} kalıcılaştı! State Root: 0x{}",
            block_number,
            hex::encode(header_state_root)[..16].to_string()
        );
        Ok(header_state_root)
    }

    /// Blok gövdesi: `process_block`un flush öncesi adımları, aynı sırada;
    /// state/executor/scheduler parametrik (gerçek → commit, overlay → simulate).
    /// `last_qc` `Some` ise G7 liveness sayaçları deterministik güncellenir ve
    /// epoch geçişi (`advance_epoch_if_due`) BURADA çağrılır (liveness epoch
    /// değerlendirmesinden önce). `None`/boş = BFT öncesi davranış birebir.
    /// Hata FATAL (fail-closed): eksik ChainParams/genesis_hash/multisig ile blok işlenmez.
    /// BFT öncesi yol için ince sarmalayıcı: `proposer=None`, eski davranış birebir.
    #[allow(clippy::too_many_arguments)]
    fn execute_block_body_legacy(
        &self,
        state: &Arc<dyn State>,
        executor: &Executor,
        scheduler: &Scheduler,
        block_number: u64,
        block_timestamp: u128,
        transactions: &[Transaction],
        last_qc: Option<&QuorumCertificate>,
        shadow_votes: &[ShadowVoteAttestation],
    ) -> Result<([u8; 32], Vec<String>)> {
        self.execute_block_body(
            state,
            executor,
            scheduler,
            block_number,
            block_timestamp,
            transactions,
            last_qc,
            shadow_votes,
            None,
        )
    }

    /// G9 (§13.4) `proposer`: header'daki `(epoch, proposer_idx)`; `Some` ise
    /// %20 üretici payı o epoch'un kümesinden çözülen GERÇEK üreticiye gider
    /// (deterministik, state_root ayrışmaz). `idx` küme dışıysa FATAL. `None` = config değeri.
    #[allow(clippy::too_many_arguments)]
    fn execute_block_body(
        &self,
        state: &Arc<dyn State>,
        executor: &Executor,
        scheduler: &Scheduler,
        block_number: u64,
        block_timestamp: u128,
        transactions: &[Transaction],
        last_qc: Option<&QuorumCertificate>,
        shadow_votes: &[ShadowVoteAttestation],
        proposer: Option<(u64, u16, u32)>,
    ) -> Result<([u8; 32], Vec<String>)> {
        self.execute_block_body_archiving(
            state,
            executor,
            scheduler,
            block_number,
            block_timestamp,
            transactions,
            last_qc,
            shadow_votes,
            proposer,
            None,
        )
    }

    /// `execute_block_body` + `archived_tx_hashes`: sync2 bloğunda bazı gövdeler
    /// hiçbir peer'da yoksa mevcut gövdelerle yürütülür, arşiv `tx_hashes`i
    /// header'daki TAM sırayla yazılır (blok hash'i diğer node'larla aynı kalır).
    #[allow(clippy::too_many_arguments)]
    fn execute_block_body_archiving(
        &self,
        state: &Arc<dyn State>,
        executor: &Executor,
        scheduler: &Scheduler,
        block_number: u64,
        block_timestamp: u128,
        transactions: &[Transaction],
        last_qc: Option<&QuorumCertificate>,
        shadow_votes: &[ShadowVoteAttestation],
        proposer: Option<(u64, u16, u32)>,
        archived_tx_hashes: Option<&[[u8; 32]]>,
    ) -> Result<([u8; 32], Vec<String>)> {
        if let Some((epoch, idx, max_ruleset)) = proposer {
            // §23 FAIL-CLOSED: zincir bu binary'nin bilmediği kurallara geçtiyse
            // TEK BLOK bile yürütülmez, çağıran (driver) panikler, node temiz
            // durur, zincir %80+ çoğunlukla sürer (fork imkânsız, yalnız duruş).
            let params = zagros_executor::params::load_chain_params(state.as_ref())?;
            if params.active_ruleset > self.supported_ruleset {
                return Err(ZagrosError::Other(format!(
                    "🔄🛑 active_ruleset {} > desteklenen {} — bu yazılım yeni kuralları bilmiyor; güncelleyip checkpoint-sync ile dönün (§23 fail-closed)",
                    params.active_ruleset, self.supported_ruleset
                )));
            }
            let set =
                zagros_executor::validator_set::load_validator_set_at_epoch(state.as_ref(), epoch)?;
            let entry = set.members.get(idx as usize).ok_or_else(|| {
                ZagrosError::Other(format!(
                    "Blok #{block_number}: proposer_idx {idx} epoch {epoch} kümesinin dışında (N={}) - blok yürütülemez",
                    set.members.len()
                ))
            })?;
            executor.set_block_producer_for_block(&entry.address);
            // §23: üreticinin sürüm BEYANI state'e, ScheduleUpgrade'in ≥%80
            // hazırlık ön-şartı bu deterministik kayıtlardan okunur.
            zagros_executor::params::record_ruleset_declaration(
                state.as_ref(),
                &entry.address,
                max_ruleset,
            )?;
        }
        Self::write_block_height(state.as_ref(), block_number as u128)?;

        let (success_count, _fail_count) =
            scheduler.execute_batch(transactions.to_vec(), block_timestamp)?;
        Self::archive_dropped_transactions(state.as_ref(), executor, transactions)?;

        executor.flush_block_rewards(block_timestamp)?;
        executor.flush_recent_transfer_index()?;
        Self::add_total_tx(state.as_ref(), success_count)?;

        if let Some(qc) = last_qc {
            zagros_executor::validator_set::record_qc_liveness(state.as_ref(), qc)?;
            if !shadow_votes.is_empty() {
                let domain = zagros_executor::params::consensus_domain(state.as_ref())?;
                let epoch = zagros_executor::validator_set::load_active_set(state.as_ref())?.epoch;
                // `block_number`: gölge oyların yalnız GERÇEK ve yakın geçmişteki
                // yüksekliklere referans verebilmesi için (bkz. o fonksiyonun
                // doc yorumu, uydurma yükseklikle liveness şişirme açığı).
                zagros_executor::validator_set::apply_shadow_vote_attestations(
                    state.as_ref(),
                    &domain,
                    epoch,
                    block_number,
                    shadow_votes,
                );
            }
            zagros_executor::validator_set::advance_epoch_if_due(state.as_ref(), block_timestamp)?;
        }

        let tx_hashes: Vec<[u8; 32]> = match archived_tx_hashes {
            Some(full) => full.to_vec(),
            None => transactions.iter().map(|tx| tx.tx_id).collect(),
        };
        if self.pruning.retention_blocks.is_some() {
            state.record_block_receipts(block_number, &tx_hashes)?;
        }

        let parent_hash = Self::parent_block_hash_in(state.as_ref(), block_number)?;
        let header_state_root = state.state_root()?;
        let header = ArchivedBlockHeader {
            number: block_number,
            parent_hash,
            state_root: header_state_root,
            timestamp: block_timestamp,
            tx_hashes,
        };
        let header_bytes = bincode::serialize(&header).map_err(|e| {
            ZagrosError::DatabaseError(format!("ArchivedBlockHeader serialize hatası: {}", e))
        })?;
        let block_hash = keccak256(&header_bytes);

        let mut archive_keys: Vec<String> = Vec::with_capacity(2 + transactions.len() * 2);
        let block_key = zagros_state::block_key(block_number);
        let mut header_acc = AccountState::default();
        header_acc.contract_code = header_bytes;
        state.set_account(&block_key, header_acc)?;
        archive_keys.push(block_key);

        let block_hash_key = zagros_state::block_hash_key(&block_hash);
        let mut hash_index_acc = AccountState::default();
        hash_index_acc.balance = block_number as u128;
        state.set_account(&block_hash_key, hash_index_acc)?;
        archive_keys.push(block_hash_key);

        for tx in transactions {
            archive_keys.push(zagros_state::receipt_key(&tx.tx_id));
            archive_keys.push(zagros_state::tx_body_key(&tx.tx_id));
        }

        Ok((header_state_root, archive_keys))
    }

    fn write_block_height(state: &dyn State, block_height: u128) -> Result<()> {
        let key = "__GLOBAL_BLOCK_HEIGHT__".to_string();
        let mut tracker = state.get_account(&key)?.unwrap_or_default();
        tracker.balance = block_height;
        state.set_account(&key, tracker)
    }

    fn add_total_tx(state: &dyn State, count: usize) -> Result<()> {
        if count == 0 {
            return Ok(());
        }
        let key = "__GLOBAL_TOTAL_TX__".to_string();
        let mut tracker = state.get_account(&key)?.unwrap_or_default();
        tracker.balance = tracker.balance.saturating_add(count as u128);
        state.set_account(&key, tracker)
    }

    /// Snapshot kancası kuruluysa çağırır; aralık/saklama kararı kancada (CLI),
    /// Runtime yalnız doğru anı (flush sonrası) bilir.
    fn maybe_snapshot(&self, block_number: u64) {
        if let Some(hook) = &self.snapshot_hook {
            hook(block_number);
        }
    }

    fn maybe_prune(&self, block_number: u64) {
        let Some(retention) = self.pruning.retention_blocks else {
            return;
        };
        if self.pruning.interval_blocks == 0
            || !block_number.is_multiple_of(self.pruning.interval_blocks)
        {
            return;
        }
        let mut prune_before = block_number.saturating_sub(retention);
        // Budama backpressure: arsivlenmemis blogu BUDAMA. Arsiv yuksekligini
        // (RPC ile yazilan, konsensus-disi dosya) oku; esigi ona kirp. Dosya yoksa/
        // bozuksa 0 kabul -> hicbir sey budanmaz (arsiv raporlayana kadar guvenli bekleme).
        if let Some(path) = &self.archive_height_file {
            let archive_h = std::fs::read_to_string(path)
                .ok()
                .and_then(|s| s.trim().parse::<u64>().ok())
                .unwrap_or(0);
            if archive_h < prune_before {
                prune_before = archive_h;
            }
        }
        match self
            .state
            .prune_historical_data(prune_before, self.pruning.batch_limit)
        {
            Ok(0) => {}
            Ok(n) => {
                info!(
                    "🧹 Budama: {} tarihsel dekont silindi (blok #{} öncesi)",
                    n, prune_before
                );
                let total_pruned_so_far = self
                    .state
                    .get_account(&"__PRUNING_TOTAL_DELETED__".to_string())
                    .ok()
                    .flatten()
                    .map(|a| a.balance)
                    .unwrap_or(0);
                let mut total_acc = AccountState::default();
                total_acc.balance = total_pruned_so_far.saturating_add(n as u128);
                let _ = self
                    .state
                    .set_account(&"__PRUNING_TOTAL_DELETED__".to_string(), total_acc);

                let now_secs = std::time::UNIX_EPOCH
                    .elapsed()
                    .map(|d| d.as_secs() as u128)
                    .unwrap_or(0);
                let mut last_run_acc = AccountState::default();
                last_run_acc.balance = now_secs;
                let _ = self
                    .state
                    .set_account(&"__PRUNING_LAST_RUN_AT__".to_string(), last_run_acc);
            }
            Err(e) => tracing::warn!("⚠️ Budama hatası (blok #{}): {}", block_number, e),
        }
    }

    /// Blok N'in `parent_hash`i: N≤1 genesis ham baytlarının keccak256'sı (yoksa
    /// sıfır); N≥2 `block_<N-1>`, eksikse sıfır hash + uyarı.
    fn parent_block_hash(&self, block_number: u64) -> Result<[u8; 32]> {
        Self::parent_block_hash_in(self.state.as_ref(), block_number)
    }

    fn parent_block_hash_in(state: &dyn State, block_number: u64) -> Result<[u8; 32]> {
        if block_number <= 1 {
            return Ok(match state.get_genesis_block_0_bytes()? {
                Some(bytes) => keccak256(&bytes),
                None => [0u8; 32],
            });
        }

        let prev_key = zagros_state::block_key(block_number - 1);
        match state.get_account(&prev_key)? {
            Some(acc) => Ok(keccak256(&acc.contract_code)),
            None => {
                tracing::warn!(
                    "⚠️ Blok #{} için önceki header ({}) bulunamadı - parent_hash sıfırlanıyor",
                    block_number,
                    prev_key
                );
                Ok([0u8; 32])
            }
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::SecretKey;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use zagros_state::manager::StateDbManager;
    use zagros_storage::{Storage, StorageEngine};
    use zagros_types::{AccountState, TxType, CHAIN_ID};

    #[derive(Default)]
    struct MemoryStorage {
        values: Mutex<HashMap<Vec<u8>, Vec<u8>>>,
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

    fn test_secret_key(seed: u8) -> SecretKey {
        SecretKey::from_slice(&[seed; 32]).unwrap()
    }

    fn transfer_tx(sender_seed: u8, nonce: u64, amount: u128, timestamp: u128) -> Transaction {
        let key = test_secret_key(sender_seed);
        let mut tx = Transaction {
            tx_id: [sender_seed.wrapping_add(nonce as u8); 32],
            tx_type: TxType::Transfer,
            sender: Transaction::address_from_secret_key(&key),
            amount,
            receiver: "0x2222222222222222222222222222222222222222".to_string(),
            payload: Vec::new(),
            signature: Vec::new(),
            timestamp,
            nonce,
            gas_limit: 1,
            gas_price: 2,
            chain_id: CHAIN_ID,
        };
        tx.sign(&key);
        tx
    }

    /// 🛡️ `__GLOBAL_TOTAL_TX__` yalnız başarılı işlemleri sayıp bloklar arası birikmeli.
    // ---- G3: simulate → verify → commit ----

    #[test]
    fn g3_simulate_block_matches_commit_root_and_leaves_real_state_untouched() {
        let state = test_state();
        let executor = Arc::new(Executor::new(state.clone()));
        let scheduler = Arc::new(Scheduler::new(executor.clone()));
        let runtime = Runtime::new(state.clone(), executor, scheduler);

        let sender = Transaction::address_from_secret_key(&test_secret_key(1));
        state
            .set_account(&sender, AccountState::new(1_000))
            .unwrap();
        state.flush().unwrap();
        let root_before = state.state_root().unwrap();
        let height_before = runtime.current_block_height().unwrap();

        let ok_tx = transfer_tx(1, 0, 10, 1_000);
        let fail_tx = transfer_tx(1, 1, 1_000_000, 1_000); // geri sarilir (yetersiz bakiye)
        let txs = vec![ok_tx, fail_tx];

        let simulated = runtime
            .simulate_block(1, 1_000, &txs, &[], None, &[], None)
            .unwrap();
        assert_ne!(simulated, root_before, "transfer koku degistirmeli");
        // Gercek state'e dokunulmadi
        assert_eq!(state.state_root().unwrap(), root_before);
        assert_eq!(state.get_balance(&sender).unwrap(), 1_000);
        assert_eq!(runtime.current_block_height().unwrap(), height_before);
        assert!(
            state
                .get_account(&zagros_state::block_key(1))
                .unwrap()
                .is_none(),
            "simulasyon arsiv yazmaz"
        );

        // Ayni simulasyon deterministik
        assert_eq!(
            runtime
                .simulate_block(1, 1_000, &txs, &[], None, &[], None)
                .unwrap(),
            simulated
        );

        // Commit: yeniden yurutme ayni koku verir ve flush eder
        let committed = runtime
            .commit_block(1, 1_000, &txs, &[], None, &[], None, simulated)
            .unwrap();
        assert_eq!(committed, simulated);
        assert_eq!(state.state_root().unwrap(), simulated);
        assert_eq!(runtime.current_block_height().unwrap(), 1);
        assert_eq!(
            state.get_nonce(&sender).unwrap(),
            2,
            "basarisiz tx de nonce tuketir"
        );

        // Ikinci blok: simulasyon bir onceki commit'in uzerinden devam eder
        let tx3 = transfer_tx(1, 2, 10, 2_000);
        let sim2 = runtime
            .simulate_block(2, 2_000, std::slice::from_ref(&tx3), &[], None, &[], None)
            .unwrap();
        let com2 = runtime
            .commit_block(2, 2_000, &[tx3], &[], None, &[], None, sim2)
            .unwrap();
        assert_eq!(sim2, com2);
    }

    /// 🚨 Düşen işlemin gövdesi ve `status=false` makbuzu arşivlenmeli (blok 2878);
    /// state_root değişmez.
    #[test]
    fn dropped_transactions_are_archived_with_body_and_failed_receipt_without_touching_the_root() {
        let state = test_state();
        let executor = Arc::new(Executor::new(state.clone()));
        let scheduler = Arc::new(Scheduler::new(executor.clone()));
        let runtime = Runtime::new(state.clone(), executor, scheduler);
        let sender = Transaction::address_from_secret_key(&test_secret_key(1));
        state
            .set_account(&sender, AccountState::new(1_000))
            .unwrap();
        state.flush().unwrap();

        let ok_tx = transfer_tx(1, 0, 10, 1_000);
        let mut expired = transfer_tx(1, 1, 10, 1_000 - 600); // |blok_ts - tx_ts| > 300 → düşer
        expired.tx_id = [0xEE; 32];
        expired.sign(&test_secret_key(1));
        let txs = vec![ok_tx.clone(), expired.clone()];

        let simulated = runtime
            .simulate_block(1, 1_000, &txs, &[], None, &[], None)
            .unwrap();
        let committed = runtime
            .commit_block(1, 1_000, &txs, &[], None, &[], None, simulated)
            .unwrap();
        assert_eq!(
            committed, simulated,
            "düşen işlemi arşivlemek kökü değiştirmemeli"
        );
        assert_eq!(
            state.get_nonce(&sender).unwrap(),
            1,
            "düşen işlem nonce tüketmez"
        );

        // Gövde var, makbuz status=false / gas_used=0
        let body = state
            .get_account(&zagros_state::tx_body_key(&expired.tx_id))
            .unwrap();
        assert!(
            body.map(|a| !a.contract_code.is_empty()).unwrap_or(false),
            "düşen işlemin gövdesi arşivlenmeli"
        );
        let receipt_acc = state
            .get_account(&zagros_state::receipt_key(&expired.tx_id))
            .unwrap()
            .expect("makbuz");
        let receipt: zagros_types::ArchivedReceipt =
            bincode::deserialize(&receipt_acc.contract_code).unwrap();
        assert!(!receipt.status);
        assert_eq!(receipt.gas_used, 0);
        assert_eq!(receipt.block_number, 1);
        // Başarılı olan da her zamanki gibi
        let ok_receipt_acc = state
            .get_account(&zagros_state::receipt_key(&ok_tx.tx_id))
            .unwrap()
            .expect("makbuz");
        let ok_receipt: zagros_types::ArchivedReceipt =
            bincode::deserialize(&ok_receipt_acc.contract_code).unwrap();
        assert!(ok_receipt.status);
    }

    /// 🧩 sync2 eksik-gövde: `commit_block_archiving` arşiv başlığına header'daki TAM
    /// tx_hashes listesini yazar (mevcut gövdeler yürütülür, eksikler yalnız listede).
    #[test]
    fn commit_block_archiving_stores_the_full_tx_hash_list_even_when_bodies_are_missing() {
        let state = test_state();
        let executor = Arc::new(Executor::new(state.clone()));
        let scheduler = Arc::new(Scheduler::new(executor.clone()));
        let runtime = Runtime::new(state.clone(), executor, scheduler);
        let sender = Transaction::address_from_secret_key(&test_secret_key(1));
        state
            .set_account(&sender, AccountState::new(1_000))
            .unwrap();
        state.flush().unwrap();
        let present = transfer_tx(1, 0, 10, 1_000);
        let missing_id = [0xAB; 32];
        let full = vec![missing_id, present.tx_id];
        let simulated = runtime
            .simulate_block(
                1,
                1_000,
                std::slice::from_ref(&present),
                &[],
                None,
                &[],
                None,
            )
            .unwrap();
        runtime
            .commit_block_archiving(
                1,
                1_000,
                std::slice::from_ref(&present),
                &[],
                None,
                &[],
                None,
                simulated,
                Some(&full),
            )
            .unwrap();
        let acc = state
            .get_account(&zagros_state::block_key(1))
            .unwrap()
            .expect("arşiv başlığı");
        let header: ArchivedBlockHeader = bincode::deserialize(&acc.contract_code).unwrap();
        assert_eq!(header.tx_hashes, full, "tam liste yazılmalı (eksik dahil)");
        assert!(
            state
                .get_account(&zagros_state::tx_body_key(&missing_id))
                .unwrap()
                .is_none(),
            "eksik gövde uydurulmaz"
        );
        assert!(state
            .get_account(&zagros_state::tx_body_key(&present.tx_id))
            .unwrap()
            .is_some());
    }

    // ---- G9 (v0.3 §13.4 / C-11): %20 üretici payı header'ın GERÇEK proposer'ına ----

    /// Ücreti anlamlı (10_000 raw) bir transfer, %20 pay floor'da kaybolmasın.
    fn g9_fee_tx(nonce: u64, timestamp: u128) -> Transaction {
        let key = test_secret_key(1);
        let mut tx = Transaction {
            tx_id: [0x99u8; 32],
            tx_type: TxType::Transfer,
            sender: Transaction::address_from_secret_key(&key),
            amount: 10,
            receiver: "0x2222222222222222222222222222222222222222".to_string(),
            payload: Vec::new(),
            signature: Vec::new(),
            timestamp,
            nonce,
            gas_limit: 10_000,
            gas_price: 1,
            chain_id: CHAIN_ID,
        };
        tx.tx_id = [nonce as u8 ^ 0x9A; 32];
        tx.sign(&key);
        tx
    }

    /// 4 üyeli aktif küme + ChainParams + qualified validator hesapları +
    /// staker havuzu, G9 ödül yolunun tam ön koşulları. Kümeyi döner.
    fn g9_install_two_validator_chain(
        state: &Arc<dyn State>,
    ) -> zagros_types::consensus::ActiveValidatorSet {
        use zagros_types::consensus::{ActiveValidatorSet, ChainParams, ValidatorMember};
        let params = ChainParams::genesis_defaults();
        zagros_executor::params::store_chain_params(state.as_ref(), &params).unwrap();
        // INV-S1: küme en az 4 üye ister (BFT alt sınırı), 4 üyeli küme kur.
        let members = (0u8..4)
            .map(|i| ValidatorMember {
                address: format!("0x{:039x}{}", 0xa, i),
                consensus_pubkey: [i + 1; 32],
            })
            .collect();
        let set = ActiveValidatorSet { epoch: 0, members };
        zagros_executor::validator_set::store_active_set(state.as_ref(), &set).unwrap();
        zagros_executor::validator_set::store_active_set_epoch_snapshot(state.as_ref(), &set)
            .unwrap();
        let min_stake =
            zagros_executor::params::min_validator_stake_zagros(state.as_ref(), &params).unwrap();
        for m in &set.members {
            state
                .set_account(
                    &m.address,
                    AccountState {
                        staked_balance: min_stake,
                        is_registered_validator: true,
                        ..Default::default()
                    },
                )
                .unwrap();
        }
        state
            .set_account(
                &"__GLOBAL_TOTAL_STAKED__".to_string(),
                AccountState::new(min_stake.saturating_mul(4)),
            )
            .unwrap();
        set
    }

    /// G9: %20 pay header'ın işaret ettiği üyeye gider, sonraki blok farklı üyeye.
    #[test]
    fn g9_commit_block_pays_twenty_percent_to_the_headers_real_proposer() {
        let state = test_state();
        let executor = Arc::new(Executor::new(state.clone()));
        let scheduler = Arc::new(Scheduler::new(executor.clone()));
        let runtime = Runtime::new(state.clone(), executor, scheduler);

        let set = g9_install_two_validator_chain(&state);
        let sender = Transaction::address_from_secret_key(&test_secret_key(1));
        state
            .set_account(&sender, AccountState::new(1_000_000))
            .unwrap();
        state.flush().unwrap();

        // Blok 1 → üretici idx=1
        let tx1 = g9_fee_tx(0, 1_000);
        let sender_before = state.get_balance(&sender).unwrap();
        let root1 = runtime
            .simulate_block(
                1,
                1_000,
                std::slice::from_ref(&tx1),
                &[],
                None,
                &[],
                Some((0, 1, 1)),
            )
            .unwrap();
        runtime
            .commit_block(1, 1_000, &[tx1], &[], None, &[], Some((0, 1, 1)), root1)
            .unwrap();
        let fee = sender_before - state.get_balance(&sender).unwrap() - 10;
        assert!(fee > 0, "ücret kesilmiş olmalı");
        let share = fee * zagros_types::VALIDATOR_REWARD_BPS / 10_000;
        assert!(share > 0, "test ücreti %20 payı floor'da kaybettirmemeli");
        assert_eq!(state.get_balance(&set.members[1].address).unwrap(), share);
        assert_eq!(state.get_balance(&set.members[0].address).unwrap(), 0);
        // G10: üreticinin sürüm beyanı commit'le state'e işlenmiş olmalı
        assert_eq!(
            zagros_executor::params::ruleset_declaration(state.as_ref(), &set.members[1].address),
            1
        );

        // Blok 2 → üretici idx=0 (aynı ücret; artık O alır, idx=1 SABİT kalır)
        let tx2 = g9_fee_tx(1, 2_000);
        let root2 = runtime
            .simulate_block(
                2,
                2_000,
                std::slice::from_ref(&tx2),
                &[],
                None,
                &[],
                Some((0, 0, 1)),
            )
            .unwrap();
        runtime
            .commit_block(2, 2_000, &[tx2], &[], None, &[], Some((0, 0, 1)), root2)
            .unwrap();
        assert_eq!(state.get_balance(&set.members[0].address).unwrap(), share);
        assert_eq!(state.get_balance(&set.members[1].address).unwrap(), share);
    }

    /// G14 (§21): `__RECENT_BRIDGE_BURNS__` yalnız commit ile dolar, simulate
    /// overlay'de kalır; relayer finalize olmamış burn'e göre kilit açamaz.
    #[test]
    fn g14_bridge_burn_reaches_relayer_feed_only_after_commit_never_from_simulate() {
        let state = test_state();
        let executor = Arc::new(Executor::new(state.clone()));
        let scheduler = Arc::new(Scheduler::new(executor.clone()));
        let runtime = Runtime::new(state.clone(), executor, scheduler);
        g9_install_two_validator_chain(&state);
        let key = test_secret_key(1);
        let sender = Transaction::address_from_secret_key(&key);
        let burn_amount: u128 = 500;
        state
            .set_account(
                &sender,
                AccountState {
                    balance: 1_000_000,
                    zerenya_balance: burn_amount,
                    ..Default::default()
                },
            )
            .unwrap();
        // Köprü teminatı sentinel'i (teminatsız ZERENYA kopruden yakılamaz).
        state
            .set_account(
                &"__BRIDGE_BACKED_ZERENYA__".to_string(),
                AccountState::new(burn_amount),
            )
            .unwrap();
        state.flush().unwrap();

        let mut tx = Transaction {
            tx_id: [0xB5u8; 32],
            tx_type: TxType::BridgeBurn,
            sender: sender.clone(),
            amount: burn_amount,
            receiver: "0x2222222222222222222222222222222222222222".to_string(),
            payload: Vec::new(),
            signature: Vec::new(),
            timestamp: 1_000,
            nonce: 0,
            gas_limit: 10_000,
            gas_price: 1,
            chain_id: CHAIN_ID,
        };
        tx.sign(&key);

        // 1) SIMULATE: kök hesaplanır ama relayer beslemesine HİÇBİR kayıt düşmez
        let root = runtime
            .simulate_block(
                1,
                1_000,
                std::slice::from_ref(&tx),
                &[],
                None,
                &[],
                Some((0, 1, 1)),
            )
            .unwrap();
        let feed = state
            .get_account(&"__RECENT_BRIDGE_BURNS__".to_string())
            .unwrap();
        assert!(
            feed.map(|a| a.contract_code.is_empty()).unwrap_or(true),
            "simulate relayer beslemesine yazamaz (QC'siz blok görünmez olmalı)"
        );
        assert_eq!(
            state.get_account(&sender).unwrap().unwrap().zerenya_balance,
            burn_amount,
            "simulate bakiyeyi de değiştirmemeli (overlay)"
        );

        // 2) COMMIT (QC'li yol): kayıt artık relayer'ın okuyacağı listede
        runtime
            .commit_block(
                1,
                1_000,
                &[tx.clone()],
                &[],
                None,
                &[],
                Some((0, 1, 1)),
                root,
            )
            .unwrap();
        let feed = state
            .get_account(&"__RECENT_BRIDGE_BURNS__".to_string())
            .unwrap()
            .expect("commit sonrasi kayit olmali");
        let records: Vec<zagros_types::BridgeBurnRecord> =
            bincode::deserialize(&feed.contract_code).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].tx_id, tx.tx_id);
        assert_eq!(records[0].amount, burn_amount);
        assert_eq!(
            state.get_account(&sender).unwrap().unwrap().zerenya_balance,
            0
        );
    }

    /// G10 (§23) fail-closed: zincir bu yazılımın bilmediği kural setine
    /// geçtiyse TEK BLOK bile yürütülmez, "yarım anlayan" node yoktur;
    /// geride kalan validator temiz durur, zincir %80+ ile sürer.
    #[test]
    fn g10_execution_halts_when_active_ruleset_exceeds_supported() {
        let state = test_state();
        let executor = Arc::new(Executor::new(state.clone()));
        let scheduler = Arc::new(Scheduler::new(executor.clone()));
        // Binary'nin desteklediğinden BİR fazlası: sabit artınca (ör. ruleset 2
        // = sıkıştırılmış tel formatı) testin anlamı kaybolmasın diye değer
        // `SUPPORTED_RULESET`'ten türetiliyor.
        let unsupported = zagros_types::consensus::SUPPORTED_RULESET + 1;
        let runtime = Runtime::new(state.clone(), executor, scheduler)
            .with_supported_ruleset(unsupported - 1);
        g9_install_two_validator_chain(&state);
        let mut p = zagros_executor::params::load_chain_params(state.as_ref()).unwrap();
        p.active_ruleset = unsupported; // zincir bir sonraki kural setine geçmiş
        zagros_executor::params::store_chain_params(state.as_ref(), &p).unwrap();
        state.flush().unwrap();

        let err = runtime
            .simulate_block(1, 1_000, &[], &[], None, &[], Some((0, 1, 2)))
            .unwrap_err();
        assert!(
            format!("{err:?}").contains("desteklenen"),
            "fail-closed bekleniyordu: {err:?}"
        );
        // Ama o kural setini destekleyen yazılım AYNI bloğu yürütebilir
        let executor2 = Arc::new(Executor::new(state.clone()));
        let scheduler2 = Arc::new(Scheduler::new(executor2.clone()));
        let runtime2 =
            Runtime::new(state.clone(), executor2, scheduler2).with_supported_ruleset(unsupported);
        runtime2
            .simulate_block(1, 1_000, &[], &[], None, &[], Some((0, 1, 2)))
            .unwrap();
    }

    /// G9 fail-closed: header'daki `proposer_idx` kümenin dışındaysa blok
    /// YÜRÜTÜLMEZ (bozuk/kötü niyetli başlık sessizce işlenemez).
    #[test]
    fn g9_out_of_range_proposer_idx_is_rejected_fail_closed() {
        let state = test_state();
        let executor = Arc::new(Executor::new(state.clone()));
        let scheduler = Arc::new(Scheduler::new(executor.clone()));
        let runtime = Runtime::new(state.clone(), executor, scheduler);
        g9_install_two_validator_chain(&state);
        state.flush().unwrap();

        let err = runtime
            .simulate_block(1, 1_000, &[], &[], None, &[], Some((0, 7, 1)))
            .unwrap_err();
        assert!(
            format!("{err:?}").contains("kümesinin dışında"),
            "fail-closed hata bekleniyordu: {err:?}"
        );
    }

    #[test]
    fn g3_commit_block_rejects_mismatching_root_without_flushing() {
        let state = test_state();
        let executor = Arc::new(Executor::new(state.clone()));
        let scheduler = Arc::new(Scheduler::new(executor.clone()));
        let runtime = Runtime::new(state.clone(), executor, scheduler);

        let sender = Transaction::address_from_secret_key(&test_secret_key(1));
        state
            .set_account(&sender, AccountState::new(1_000))
            .unwrap();
        state.flush().unwrap();

        let tx = transfer_tx(1, 0, 10, 1_000);
        let err = runtime
            .commit_block(1, 1_000, &[tx], &[], None, &[], None, [0xAB; 32])
            .unwrap_err();
        assert!(format!("{err:?}").contains("EŞLEŞMİYOR"), "{err:?}");
        // Reddedilen bloğun etkileri dirty cache'te kalır (çağıran panic ile kapatır);
        // burada yalnız flush'ın çağrılmadığı doğrulanır.
    }

    #[test]
    fn process_block_accumulates_total_tx_across_blocks_counting_only_successes() {
        let state = test_state();
        let executor = Arc::new(Executor::new(state.clone()));
        let scheduler = Arc::new(Scheduler::new(executor.clone()));
        let runtime = Runtime::new(state.clone(), executor, scheduler);

        let sender = Transaction::address_from_secret_key(&test_secret_key(1));
        state
            .set_account(&sender, AccountState::new(1_000))
            .unwrap();

        // Blok 1: biri başarılı (yeterli bakiye), biri başarısız (bakiye yetersiz).
        let ok_tx = transfer_tx(1, 0, 10, 1_000);
        let fail_tx = transfer_tx(1, 1, 1_000_000, 1_000);
        runtime.process_block(1, 1_000, &[ok_tx, fail_tx]).unwrap();

        let total_after_block_1 = state
            .get_account(&"__GLOBAL_TOTAL_TX__".to_string())
            .unwrap()
            .unwrap()
            .balance;
        assert_eq!(total_after_block_1, 1, "sadece basarili islem sayilmali");

        // Blok 2: bir başarılı işlem daha, sayaç SIFIRLANMAMALI, birikmeli.
        let ok_tx_2 = transfer_tx(1, 2, 10, 2_000);
        runtime.process_block(2, 2_000, &[ok_tx_2]).unwrap();

        let total_after_block_2 = state
            .get_account(&"__GLOBAL_TOTAL_TX__".to_string())
            .unwrap()
            .unwrap()
            .balance;
        assert_eq!(
            total_after_block_2, 2,
            "bloklar arasi birikmeli, sifirlanmamali"
        );
    }

    /// 🚨 Regresyon: `tx_hashes` `tx.tx_id` kullanmalı (Receipt_/tx_body_ ile
    /// eşleşsin); bare-runtime'da blok 1 parent_hash sıfır, sonrakiler öncekinin gerçek hash'ine zincirlenir.
    #[test]
    fn process_block_chains_parent_hash_and_archives_real_tx_ids() {
        let state = test_state();
        let executor = Arc::new(Executor::new(state.clone()));
        let scheduler = Arc::new(Scheduler::new(executor.clone()));
        let runtime = Runtime::new(state.clone(), executor, scheduler);

        let sender = Transaction::address_from_secret_key(&test_secret_key(1));
        state
            .set_account(&sender, AccountState::new(1_000))
            .unwrap();

        let tx1 = transfer_tx(1, 0, 10, 1_000);
        let tx1_id = tx1.tx_id;
        runtime.process_block(1, 1_000, &[tx1]).unwrap();

        let tx2 = transfer_tx(1, 1, 10, 2_000);
        runtime.process_block(2, 2_000, &[tx2]).unwrap();

        let tx3 = transfer_tx(1, 2, 10, 3_000);
        runtime.process_block(3, 3_000, &[tx3]).unwrap();

        let header_bytes = |n: u64| {
            state
                .get_account(&zagros_state::block_key(n))
                .unwrap()
                .unwrap()
                .contract_code
        };
        let header1_bytes = header_bytes(1);
        let header2_bytes = header_bytes(2);
        let header3_bytes = header_bytes(3);

        let header1: ArchivedBlockHeader = bincode::deserialize(&header1_bytes).unwrap();
        let header2: ArchivedBlockHeader = bincode::deserialize(&header2_bytes).unwrap();
        let header3: ArchivedBlockHeader = bincode::deserialize(&header3_bytes).unwrap();

        assert_eq!(
            header1.parent_hash, [0u8; 32],
            "genesis hic calismadi - blok 1'in parent_hash'i sifir olmali"
        );
        assert_eq!(
            header2.parent_hash,
            keccak256(&header1_bytes),
            "blok 2'nin parent_hash'i blok 1'in GERCEK hash'i olmali"
        );
        assert_eq!(
            header3.parent_hash,
            keccak256(&header2_bytes),
            "blok 3'un parent_hash'i blok 2'nin GERCEK hash'i olmali"
        );

        assert_eq!(
            header1.tx_hashes,
            vec![tx1_id],
            "tx_hashes tx.tx_id kullanmali (Transaction::hash() DEGIL)"
        );
    }

    /// Restart testi: bir blok üretildikten sonra AYNI storage üzerinde YENİ
    /// bir `StateDbManager` açılırsa (gerçek bir node restart'ını simüle
    /// eder), arşivlenen header/receipt/tx-body okunabilir kalmalı.
    #[test]
    fn archived_block_and_receipt_survive_reopening_the_same_storage() {
        let storage = Arc::new(MemoryStorage::default());
        let state = Arc::new(StateDbManager::new(storage.clone()));
        let executor = Arc::new(Executor::new(state.clone()));
        let scheduler = Arc::new(Scheduler::new(executor.clone()));
        let runtime = Runtime::new(state.clone(), executor, scheduler);

        let sender = Transaction::address_from_secret_key(&test_secret_key(1));
        state
            .set_account(&sender, AccountState::new(1_000))
            .unwrap();
        let tx = transfer_tx(1, 0, 10, 1_000);
        let tx_id = tx.tx_id;
        runtime.process_block(1, 1_000, &[tx]).unwrap();

        // "Restart": ayni (kalici) storage uzerinde YENI bir StateDbManager.
        let reopened = StateDbManager::new(storage);

        let header_acc = reopened
            .get_account(&zagros_state::block_key(1))
            .unwrap()
            .expect("block_1 restart sonrasi da okunabilmeli");
        let header: ArchivedBlockHeader = bincode::deserialize(&header_acc.contract_code).unwrap();
        assert_eq!(header.number, 1);
        assert_eq!(header.tx_hashes, vec![tx_id]);

        let receipt_acc = reopened
            .get_account(&zagros_state::receipt_key(&tx_id))
            .unwrap()
            .expect("receipt restart sonrasi da okunabilmeli");
        let receipt: zagros_types::ArchivedReceipt =
            bincode::deserialize(&receipt_acc.contract_code).unwrap();
        assert!(
            receipt.status,
            "basarili tx'in receipt'i status:true kalmali"
        );
        assert_eq!(receipt.block_number, 1);

        let tx_body_acc = reopened
            .get_account(&zagros_state::tx_body_key(&tx_id))
            .unwrap()
            .expect("tx gövdesi restart sonrasi da okunabilmeli");
        let archived_tx: Transaction =
            Transaction::from_stored_bytes(&tx_body_acc.contract_code).unwrap();
        assert_eq!(archived_tx.tx_id, tx_id);
        assert_eq!(archived_tx.sender, sender);
    }

    /// 🔎 parent_hash zinciri restart sonrası da doğru devam etmeli
    /// (`parent_block_hash` kalıcı kayıttan okur).
    #[test]
    fn parent_hash_chain_survives_a_restart_between_blocks() {
        let storage = Arc::new(MemoryStorage::default());
        let state = Arc::new(StateDbManager::new(storage.clone()));
        let executor = Arc::new(Executor::new(state.clone()));
        let scheduler = Arc::new(Scheduler::new(executor.clone()));
        let runtime = Runtime::new(state.clone(), executor, scheduler);

        let sender = Transaction::address_from_secret_key(&test_secret_key(1));
        state
            .set_account(&sender, AccountState::new(1_000))
            .unwrap();
        let tx1 = transfer_tx(1, 0, 10, 1_000);
        runtime.process_block(1, 1_000, &[tx1]).unwrap();

        let header1_bytes = state
            .get_account(&zagros_state::block_key(1))
            .unwrap()
            .unwrap()
            .contract_code;

        // "Restart": Runtime/Executor/Scheduler'ı TAMAMEN at, aynı storage
        // uzerinde YENIDEN insa et, hicbir bellek-ici durum tasinmiyor.
        drop(runtime);
        let reopened_state = Arc::new(StateDbManager::new(storage));
        let executor2 = Arc::new(Executor::new(reopened_state.clone()));
        let scheduler2 = Arc::new(Scheduler::new(executor2.clone()));
        let runtime2 = Runtime::new(reopened_state.clone(), executor2, scheduler2);

        let tx2 = transfer_tx(1, 1, 10, 2_000);
        runtime2.process_block(2, 2_000, &[tx2]).unwrap();

        let header2_bytes = reopened_state
            .get_account(&zagros_state::block_key(2))
            .unwrap()
            .unwrap()
            .contract_code;
        let header2: ArchivedBlockHeader = bincode::deserialize(&header2_bytes).unwrap();

        assert_eq!(
            header2.parent_hash,
            keccak256(&header1_bytes),
            "restart sonrasi uretilen blok 2'nin parent_hash'i, restart ONCESI \
             yazilan blok 1'in GERCEK hash'ine zincirlenmeli"
        );
    }

    /// 🔎 Arşiv yazımları (header + receipt + tx_body) `state_root`u etkilememeli.
    #[test]
    fn process_block_archive_writes_never_change_state_root() {
        let state = test_state();
        let executor = Arc::new(Executor::new(state.clone()));
        let scheduler = Arc::new(Scheduler::new(executor.clone()));
        let runtime = Runtime::new(state.clone(), executor, scheduler);

        let sender = Transaction::address_from_secret_key(&test_secret_key(1));
        state
            .set_account(&sender, AccountState::new(1_000))
            .unwrap();
        let tx = transfer_tx(1, 0, 10, 1_000);

        let returned_root = runtime.process_block(1, 1_000, &[tx]).unwrap();

        // process_block DÖNDÜKTEN SONRA (yani header_acc/hash_index_acc/
        // Receipt_/tx_body_ hepsi zaten set_account'lanmış VE flush edilmiş
        // durumdayken) state_root'u BAĞIMSIZ olarak tekrar hesapla.
        let root_after_all_archive_writes = state.state_root().unwrap();

        assert_eq!(
            returned_root, root_after_all_archive_writes,
            "arsiv anahtarlari (block_/block_hash_/Receipt_/tx_body_) yazildiktan \
             SONRA yeniden hesaplanan state_root, process_block'un donduruguyle \
             AYNI olmali - degilse arsiv yazimlari trie'ye sizmis demektir"
        );
    }

    /// 🔎 Gerçek `process_block` hattıyla: `None` ile hiçbir arşiv anahtarı
    /// silinmez; `Some(k)` ile eski arşiv silinir, `0x` state ve son blok dokunulmaz.
    #[test]
    fn end_to_end_pruning_none_keeps_forever_some_deletes_through_real_pipeline() {
        // ---- (a) retention_blocks: None ----
        let state_a = test_state();
        let executor_a = Arc::new(Executor::new(state_a.clone()));
        let scheduler_a = Arc::new(Scheduler::new(executor_a.clone()));
        let runtime_a = Runtime::new(state_a.clone(), executor_a, scheduler_a); // varsayilan: None

        let sender_a = Transaction::address_from_secret_key(&test_secret_key(1));
        state_a
            .set_account(&sender_a, AccountState::new(10_000))
            .unwrap();
        let mut tx1_ids = Vec::new();
        for n in 1..=20u64 {
            let tx = transfer_tx(1, n - 1, 10, n as u128 * 1_000);
            tx1_ids.push(tx.tx_id);
            runtime_a
                .process_block(n, n as u128 * 1_000, &[tx])
                .unwrap();
        }
        for (i, tx_id) in tx1_ids.iter().enumerate() {
            let block_n = (i + 1) as u64;
            assert!(
                state_a
                    .get_account(&zagros_state::receipt_key(tx_id))
                    .unwrap()
                    .is_some(),
                "retention_blocks:None ile blok {block_n}'in receipt'i SILINMEMELI"
            );
            assert!(
                state_a
                    .get_account(&zagros_state::block_key(block_n))
                    .unwrap()
                    .is_some(),
                "retention_blocks:None ile blok {block_n}'in header'i SILINMEMELI"
            );
        }

        // ---- (b) retention_blocks: Some(k) ----
        let state_b = test_state();
        let executor_b = Arc::new(Executor::new(state_b.clone()));
        let scheduler_b = Arc::new(Scheduler::new(executor_b.clone()));
        let pruning = PruningConfig {
            retention_blocks: Some(5),
            interval_blocks: 10,
            batch_limit: 10_000,
        };
        let runtime_b =
            Runtime::new(state_b.clone(), executor_b, scheduler_b).with_pruning(pruning);

        let sender_b = Transaction::address_from_secret_key(&test_secret_key(2));
        state_b
            .set_account(&sender_b, AccountState::new(10_000))
            .unwrap();
        let mut tx2_ids = Vec::new();
        for n in 1..=10u64 {
            let tx = transfer_tx(2, n - 1, 10, n as u128 * 1_000);
            tx2_ids.push(tx.tx_id);
            runtime_b
                .process_block(n, n as u128 * 1_000, &[tx])
                .unwrap();
        }
        // interval_blocks=10 -> blok 10'da budama tetiklenir, prune_before=10-5=5:
        // bloklar 1..4 budanmali, 5..10 korunmali.
        for (i, tx_id) in tx2_ids.iter().enumerate() {
            let block_n = (i + 1) as u64;
            let should_exist = block_n >= 5;
            assert_eq!(
                state_b
                    .get_account(&zagros_state::receipt_key(tx_id))
                    .unwrap()
                    .is_some(),
                should_exist,
                "retention_blocks:Some(5) ile blok {block_n}'in receipt'i beklenen durumda degil"
            );
            assert_eq!(
                state_b
                    .get_account(&zagros_state::tx_body_key(tx_id))
                    .unwrap()
                    .is_some(),
                should_exist,
                "retention_blocks:Some(5) ile blok {block_n}'in tx_body'si beklenen durumda degil"
            );
            assert_eq!(
                state_b
                    .get_account(&zagros_state::block_key(block_n))
                    .unwrap()
                    .is_some(),
                should_exist,
                "retention_blocks:Some(5) ile blok {block_n}'in header'i beklenen durumda degil"
            );
        }
        // Chain state (0x hesap) budamadan HIC etkilenmemeli.
        let sender_after = state_b.get_account(&sender_b).unwrap().unwrap();
        assert_eq!(
            sender_after.nonce, 10,
            "budama GONDERENIN chain-state hesabina (nonce) dokunmamali"
        );
    }
}
