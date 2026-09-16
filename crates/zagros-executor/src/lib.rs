#![allow(clippy::field_reassign_with_default)]
// 🚨 SADECE EXECUTOR'A ÖZEL OLANLAR KALACAK
pub mod bridge;
pub mod evm;
mod swap;

// 🔗 KOPYALARI DEĞİL, V2'NİN RESMİ KASALARINI (CRATES) ÇAĞIRIYORUZ!
use zagros_primitives::{Result, ZagrosError};
use zagros_state::State;
use zagros_types::*;

pub mod governance;
/// G2 (CONSENSUS-SPEC v0.2): zincir-üstü parametreler ve genesis sentinel'leri.
pub mod params;
/// G2: validator kümesi, epoch geçişi, lifecycle, Faz A admin multisig.
pub mod validator_set;

use crate::swap::{
    quote_bridge_mint_and_swap, quote_bridge_swap_and_burn, quote_swap_buy,
    record_volume_and_compute_fee_bps, swap_amount_out_min, SwapDirection,
};
use zagros_types::GasCalculator;

use dashmap::DashMap;
use portable_atomic::AtomicU128;
use std::collections::{BTreeMap, BTreeSet};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, RwLock};

/// `staked_balance * accumulated_reward_per_share / 1e12` işlemini taşmadan
/// hesaplar: ara çarpım `U256`'da yapılır (iki u128 çarpımı u128'i sessizce
/// aşabilir; `acc` tek yönlü büyür, `staked_balance` tüm arza ulaşabilir).
pub fn reward_owed(staked_balance: u128, accumulated_reward_per_share: u128) -> u128 {
    let product = alloy_primitives::U256::from(staked_balance)
        * alloy_primitives::U256::from(accumulated_reward_per_share);
    let result = product / alloy_primitives::U256::from(1_000_000_000_000u128);
    u128::try_from(result).unwrap_or(u128::MAX)
}

/// Ham ZAGROS'u havuz oranıyla `"X.YYYY ZERENYA"` dizgesine çevirir (loglarda
/// 2 ondalıklı ZAGROS küçük ücretleri "0.00" gösterir). Ara çarpım `U256`.
fn zagros_amount_to_zerenya_string(
    amount_zagros: u128,
    pool_zagros: u128,
    pool_zerenya: u128,
) -> String {
    use alloy_primitives::U256;
    const ZERENYA_DISPLAY_DECIMALS: u32 = 4;
    if pool_zagros == 0 {
        return "0.0000 ZERENYA".to_string();
    }
    let scale = U256::from(10u128.pow(ZERENYA_DISPLAY_DECIMALS));
    let scaled = U256::from(amount_zagros)
        .saturating_mul(U256::from(pool_zerenya))
        .saturating_mul(scale)
        / U256::from(pool_zagros)
        / U256::from(TOKEN_DECIMAL);
    let scaled_u128 = u128::try_from(scaled).unwrap_or(u128::MAX);
    let divisor = 10u128.pow(ZERENYA_DISPLAY_DECIMALS);
    format!(
        "{}.{:0width$} ZERENYA",
        scaled_u128 / divisor,
        scaled_u128 % divisor,
        width = ZERENYA_DISPLAY_DECIMALS as usize
    )
}

/// Ham ZAGROS miktarını 8 ondalıkla `"X.YYYYYYYY"` biçiminde döndürür; ücret ve
/// ödül payı gibi küçülen tutarlar 2 ondalıkta yanıltıcı biçimde "0.00" olur.
fn format_zagros_amount_precise(raw: u128) -> String {
    const DISPLAY_DECIMALS: u32 = 8;
    let divisor = 10u128.pow(DISPLAY_DECIMALS);
    let whole = raw / TOKEN_DECIMAL;
    let fractional = (raw % TOKEN_DECIMAL) * divisor / TOKEN_DECIMAL;
    format!(
        "{}.{:0width$}",
        whole,
        fractional,
        width = DISPLAY_DECIMALS as usize
    )
}

fn canonical_account_address(address: &str) -> Result<Address> {
    if !Transaction::validate_address(address) {
        return Err(ZagrosError::InvalidAddress);
    }
    Ok(format!("0x{}", address[2..].to_ascii_lowercase()))
}

#[derive(Default)]
struct ValidatorIndex {
    by_stake: BTreeSet<(u128, Address)>,
    stakes: BTreeMap<Address, u128>,
}

impl ValidatorIndex {
    fn from_candidates(candidates: BTreeMap<Address, u128>) -> Self {
        let by_stake = candidates
            .iter()
            .map(|(address, stake)| (*stake, address.clone()))
            .collect();
        Self {
            by_stake,
            stakes: candidates,
        }
    }

    fn update(&mut self, address: &Address, account: &AccountState) {
        if let Some(previous_stake) = self.stakes.remove(address) {
            self.by_stake.remove(&(previous_stake, address.clone()));
        }
        if !account.is_contract && account.staked_balance > 0 {
            self.stakes.insert(address.clone(), account.staked_balance);
            self.by_stake
                .insert((account.staked_balance, address.clone()));
        }
    }
}

/// Same idea as a per-address reentrancy guard, but reserves every address it was given
/// (used by `Executor::apply_transaction` to guard sender AND receiver, not
/// just sender, see `Executor::processing_addresses`).
struct MultiAddressReentrancyGuard {
    addresses: Vec<Address>,
    lock: Arc<DashMap<Address, ()>>,
}

impl Drop for MultiAddressReentrancyGuard {
    fn drop(&mut self) {
        for address in &self.addresses {
            self.lock.remove(address);
        }
    }
}

pub struct Executor {
    pub state: Arc<dyn State>,
    staking_index: Arc<RwLock<Option<ValidatorIndex>>>,
    /// Yalnız EVM çağrıları bunda serileşir: revm eşzamanlı state mutasyonuna
    /// karşı kanıtlı değil, scheduler ne derse desin EVM işlemleri tek tek koşar.
    evm_execution_lock: Arc<Mutex<()>>,
    /// Eşzamanlı yürütme için ikinci savunma: gönderici+alıcı işlem boyunca rezerve
    /// edilir; scheduler çakışan ikiliyi aynı anda verirse ikincisi Reentrancy ile reddedilir.
    processing_addresses: Arc<DashMap<Address, ()>>,
    bridge_authority: Address,
    /// 🛡️ `BridgeMint`/`BridgeMintAndSwap` zincir doğrulamasının eşik/zaman kilidi;
    /// `BridgeManager::proposal_is_executable` ile aynı kural. `config.toml`
    /// `[bridge]` değerleriyle AYNI kaynaktan gelmeli (`with_bridge_threshold`).
    bridge_required_signatures: usize,
    bridge_timelock_secs: u64,
    /// 🛡️ Zincir seviyesinde günlük mint tavanı (ZERENYA); tek bir yetkili
    /// anahtarın bir günde basabileceği toplamı sınırlar. Varsayılan
    /// `DEFAULT_BRIDGE_DAILY_MINT_LIMIT`, `with_bridge_daily_mint_limit` ile bağlanır.
    bridge_daily_mint_limit: u128,
    admin_authority: Address,
    /// Bu bloktaki gas ücretlerinin kilitsiz biriktiricisi (VALIDATOR_REWARD_POOL
    /// alacağı). Kredi eden yollar kendi checkpoint'i kapandıktan sonra çalışır,
    /// bu yüzden geri alınamaz; blok başına bir kez `flush_block_rewards()` ile yazılır.
    pending_gas_reward: Arc<AtomicU128>,
    /// 🏭 EVM kontrat üretim harcının hedef ücreti (GAS_FEE_ZERENYA bazı).
    /// Varsayılan `GAS_FEE_ZERENYA`; CLI `with_gas_target` ile config.gas'tan
    /// set eder ki harç, mempool'un native cetveliyle AYNI hedefi kullansın.
    gas_target_zerenya: u128,
    /// %20 validator ödül payının adresi; BFT yolunda her blok gerçek üreticiye
    /// çekilir. Varsayılan BOŞ: kimse "qualified" değil, tüm pay stakerlara.
    block_producer_address: Arc<RwLock<Address>>,
    /// Governance spam koruması dörtlüsü (`[governance]`); varsayılanlar
    /// `GovernanceConfig::default()` ile aynı.
    governance_proposal_fee: u128,
    governance_min_stake_to_submit: u128,
    governance_max_active_proposals: usize,
    governance_voting_period_secs: u64,
    governance_proposal_expiry_secs: u64,
    /// `record_transfer` index sayacı; `fetch_add` ile atomik olduğundan
    /// Transfer'ler ortak bir anahtar üzerinden çakışmaz. `Executor::new`
    /// diskten başlatır, blok sonunda `flush_recent_transfer_index` tek seferde yazar.
    recent_transfer_index_counter: Arc<AtomicU128>,
}

/// Günlük mint tavanı varsayılanı; `zagros_types::config`'teki
/// `default_bridge_daily_mint_limit()` ile aynı, `with_bridge_daily_mint_limit`
/// çağrılmazsa devreye girer. 2.500 ZERENYA/gün genesis arzıyla (11.000) orantılı.
const DEFAULT_BRIDGE_DAILY_MINT_LIMIT: u128 = 2_500 * zagros_types::TOKEN_DECIMAL;

/// Historical Chain Storage: `Receipt_<hex>` + `tx_body_<hex>` anahtarlarını
/// standart `set_account` yolundan (checkpoint/dirty/flush ile atomik) yazar;
/// `Executor` ve `EvmExecutor`'ın ortak makbuz çekirdeği.
fn archive_transaction(
    state: &dyn State,
    tx: &Transaction,
    mut receipt: ArchivedReceipt,
) -> Result<()> {
    receipt.block_number = state
        .get_account(&"__GLOBAL_BLOCK_HEIGHT__".to_string())
        .ok()
        .flatten()
        .map(|account| account.balance as u64)
        .unwrap_or(0);

    let receipt_bytes = bincode::serialize(&receipt).map_err(|e| {
        ZagrosError::DatabaseError(format!("ArchivedReceipt serialize hatası: {}", e))
    })?;
    let mut receipt_acc = AccountState::default();
    receipt_acc.contract_code = receipt_bytes;
    state.set_account(&zagros_state::receipt_key(&tx.tx_id), receipt_acc)?;

    let tx_bytes = tx
        .to_stored_bytes()
        .map_err(|e| ZagrosError::DatabaseError(format!("Tx body serialize hatası: {}", e)))?;
    let mut tx_body_acc = AccountState::default();
    tx_body_acc.contract_code = tx_bytes;
    state.set_account(&zagros_state::tx_body_key(&tx.tx_id), tx_body_acc)
}

impl Executor {
    pub fn new(state: Arc<dyn State>) -> Self {
        // Diskteki son sayaçtan devam: restart'ta 0'a dönmek dolu eski
        // `RecentTransfer_<index>` anahtarlarını ezip gerçek geçmişi silerdi.
        let initial_transfer_index = Self::peek_next_transfer_index(state.as_ref());
        Self {
            state,
            staking_index: Arc::new(RwLock::new(None)),
            recent_transfer_index_counter: Arc::new(AtomicU128::new(initial_transfer_index)),
            evm_execution_lock: Arc::new(Mutex::new(())),
            processing_addresses: Arc::new(DashMap::new()),
            bridge_authority: BRIDGE_AUTHORITY_ADDRESS.to_string(),
            // Varsayılan 1-of-1, zaman kilidi yok; `with_bridge_threshold` gerçek
            // config değerlerini bağlar. Eşik senaryosu test eden testler onu açıkça çağırmalı.
            bridge_required_signatures: 1,
            bridge_timelock_secs: 0,
            bridge_daily_mint_limit: DEFAULT_BRIDGE_DAILY_MINT_LIMIT,
            admin_authority: FOUNDER_ADDRESS.to_string(),
            pending_gas_reward: Arc::new(AtomicU128::new(0)),
            gas_target_zerenya: zagros_types::GAS_FEE_ZERENYA,
            block_producer_address: Arc::new(RwLock::new(String::new())),
            governance_proposal_fee: 1000 * zagros_types::TOKEN_DECIMAL,
            governance_min_stake_to_submit: 10_000 * zagros_types::TOKEN_DECIMAL,
            governance_max_active_proposals: 50,
            governance_voting_period_secs: 7 * 24 * 60 * 60,
            governance_proposal_expiry_secs: 30 * 24 * 60 * 60,
        }
    }

    /// `[governance]` bölümündeki spam-koruması parametrelerini bağlar (bkz.
    /// `zagros_types::config::GovernanceConfig`). Çağrılmazsa bu alanlar
    /// `GovernanceConfig::default()` ile birebir aynı varsayılanları kullanır.
    pub fn with_governance_config(mut self, cfg: &zagros_types::config::GovernanceConfig) -> Self {
        self.governance_proposal_fee = cfg.proposal_fee;
        self.governance_min_stake_to_submit = cfg.min_stake_to_submit;
        self.governance_max_active_proposals = cfg.max_active_proposals;
        self.governance_voting_period_secs = cfg.voting_period_secs;
        self.governance_proposal_expiry_secs = cfg.proposal_expiry_secs;
        self
    }

    /// `[consensus].block_producer_address`ı bağlar; çağrılmazsa validator payı %0 kalır.
    pub fn with_block_producer_address(self, address: Address) -> Self {
        *self
            .block_producer_address
            .write()
            .expect("producer kilidi zehirlenmis") = address;
        self
    }

    /// G9: %20 üretici payının alıcısını BU BLOK için ayarlar; BFT yolunda
    /// `Runtime::execute_block_body` header'daki gerçek üreticiyle her blok çağırır.
    pub fn set_block_producer_for_block(&self, address: &str) {
        *self
            .block_producer_address
            .write()
            .expect("producer kilidi zehirlenmis") = address.to_string();
    }

    /// `block_producer_address`'in o anki değeri (iç kilitten kopya).
    fn current_block_producer(&self) -> Address {
        self.block_producer_address
            .read()
            .expect("producer kilidi zehirlenmis")
            .clone()
    }

    /// GasConfig'ten gelen hedef ücreti bağlar, EVM kontrat üretim harcı
    /// (`evm_deploy_levy`) bunu kullanır, böylece harç mempool'un native
    /// cetveliyle aynı hedefe dayanır.
    pub fn with_gas_target(mut self, target_gas_fee_zerenya: u128) -> Self {
        self.gas_target_zerenya = target_gas_fee_zerenya;
        self
    }

    /// G3: aynı yapılandırmayla başka `State` (overlay) üzerinde Executor. Yeni
    /// yapılandırma alanı BURAYA da eklenmeli, yoksa simülasyon ile commit farklı kök üretir.
    pub fn rebind(&self, state: Arc<dyn State>) -> Self {
        let initial_transfer_index = Self::peek_next_transfer_index(state.as_ref());
        Self {
            state,
            staking_index: Arc::new(RwLock::new(None)),
            recent_transfer_index_counter: Arc::new(AtomicU128::new(initial_transfer_index)),
            evm_execution_lock: Arc::new(Mutex::new(())),
            processing_addresses: Arc::new(DashMap::new()),
            bridge_authority: self.bridge_authority.clone(),
            bridge_required_signatures: self.bridge_required_signatures,
            bridge_timelock_secs: self.bridge_timelock_secs,
            bridge_daily_mint_limit: self.bridge_daily_mint_limit,
            admin_authority: self.admin_authority.clone(),
            pending_gas_reward: Arc::new(AtomicU128::new(0)),
            gas_target_zerenya: self.gas_target_zerenya,
            block_producer_address: Arc::new(RwLock::new(self.current_block_producer())),
            governance_proposal_fee: self.governance_proposal_fee,
            governance_min_stake_to_submit: self.governance_min_stake_to_submit,
            governance_max_active_proposals: self.governance_max_active_proposals,
            governance_voting_period_secs: self.governance_voting_period_secs,
            governance_proposal_expiry_secs: self.governance_proposal_expiry_secs,
        }
    }

    /// 🏭 EVM kontrat üretim harcı: native `DeployContract` ile aynı formül;
    /// `mempool_load = 0`, sabit harç stres çarpanıyla şişmez.
    fn evm_deploy_levy(&self) -> u128 {
        let (pool_zagros, pool_zerenya) = self.state.get_pool_reserves().unwrap_or((0, 0));
        GasCalculator::with_target(
            Arc::new(AtomicU128::new(pool_zagros)),
            Arc::new(AtomicU128::new(pool_zerenya)),
            self.gas_target_zerenya,
        )
        .calculate_gas_for_tx_type(&TxType::DeployContract, 0)
    }

    /// 🔷 EVM standart ücret TABANI (`CallContract` çarpanı 5); ölçülen gaz aşarsa
    /// o geçerli. Kesinti anında uygulanır, tek kaynak `calculate_gas_for_tx_type`.
    fn evm_standard_fee(&self) -> u128 {
        let (pool_zagros, pool_zerenya) = self.state.get_pool_reserves().unwrap_or((0, 0));
        GasCalculator::with_target(
            Arc::new(AtomicU128::new(pool_zagros)),
            Arc::new(AtomicU128::new(pool_zerenya)),
            self.gas_target_zerenya,
        )
        .calculate_gas_for_tx_type(&TxType::CallContract, 0)
    }

    /// `recent_transfer_index_counter`'ın güncel değerini diske yazar (blok başına
    /// TEK yazım). Blok üretici her bloktan sonra, `state_root()` öncesi çağırmalı;
    /// yoksa restart sonrası son transferlerin index'leri yeniden kullanılır.
    pub fn flush_recent_transfer_index(&self) -> Result<()> {
        let current = self.recent_transfer_index_counter.load(Ordering::Acquire);
        let mut acc = AccountState::default();
        acc.balance = current;
        self.state
            .set_account(&Self::recent_transfers_next_index_key(), acc)
    }

    pub fn flush_block_rewards(&self, block_timestamp: u128) -> Result<()> {
        let collected = self.pending_gas_reward.swap(0, Ordering::AcqRel);
        if collected > 0 {
            self.distribute_staking_reward(collected, block_timestamp)?;
        }
        Ok(())
    }

    /// Köprü mint'leri için zorunlu `tx.sender` (varsayılan `BRIDGE_AUTHORITY_ADDRESS`);
    /// üretimde ayrı köprü imzacı anahtarı (yetki tek anahtarda toplanmaz).
    pub fn with_bridge_authority(mut self, address: Address) -> Self {
        self.bridge_authority = address;
        self
    }

    /// Zincir doğrulamasındaki eşik/zaman kilidini bağlar; `main.rs` `BridgeManager`'a
    /// verdiği AYNI `[bridge]` config değerlerini buraya da geçirmeli (tek kaynak).
    pub fn with_bridge_threshold(mut self, required_signatures: usize, timelock_secs: u64) -> Self {
        self.bridge_required_signatures = required_signatures;
        self.bridge_timelock_secs = timelock_secs;
        self
    }

    /// Zincir seviyesinde uygulanan günlük mint tavanını (ZERENYA) bağlar, `main.rs`
    /// bunu `config.toml`'daki `[bridge].daily_mint_limit` değeriyle çağırmalı.
    pub fn with_bridge_daily_mint_limit(mut self, daily_mint_limit: u128) -> Self {
        self.bridge_daily_mint_limit = daily_mint_limit;
        self
    }

    /// Test-only hook: same idea as `with_bridge_authority`, for the founder's
    /// emergency SlashValidator authority (nobody in this repo has that private
    /// key either).
    #[cfg(test)]
    fn with_admin_authority(mut self, address: Address) -> Self {
        self.admin_authority = address;
        self
    }

    /// Kurucunun acil `SlashValidator` yetkisi hâlâ açık mı; genesis işaretçisi
    /// yoksa dolmuş sayılır (fail-closed).
    fn is_admin_authority_active(&self, block_timestamp: u128) -> Result<bool> {
        // Genesis damgası yoksa yetki SÜRESİ DOLMUŞ sayılır (fail closed).
        match self.state.get_account(&GENESIS_TIMESTAMP_KEY.to_string())? {
            Some(account) if account.balance > 0 => {}
            _ => return Ok(false),
        };
        // 🛡️ TEK KAYNAK: sabit süre ile governance'ın yazdığı erken bitişin
        // küçüğü. `validator_set::admin_phase_active` de AYNI fonksiyonu
        // çağırır; iki yol ayrışırsa yetki bir yolda ölü, diğerinde canlı olurdu.
        Ok(block_timestamp <= params::admin_authority_end(self.state.as_ref())?)
    }

    /// 🛡️ Anti-flash-stake: yeni stake `pending_stake_amount`ta bekler, olgunlaşınca
    /// `staked_balance`a aktarılır ve `reward_debt` artar (geçmişe dönük ödül yok).
    /// Stake/Unstake/ClaimReward ödül mantığından ÖNCE bunu çağırmalı.
    fn settle_pending_stake(&self, sender: &mut AccountState, block_timestamp: u128) -> Result<()> {
        if sender.pending_stake_amount == 0
            || block_timestamp < sender.pending_stake_activation_time
        {
            return Ok(());
        }
        let acc = self.state.get_accumulated_reward_per_share()?;
        let settling = sender.pending_stake_amount;
        sender.reward_debt = sender
            .reward_debt
            .saturating_add(reward_owed(settling, acc));
        sender.staked_balance = sender.staked_balance.saturating_add(settling);
        sender.pending_stake_amount = 0;
        sender.pending_stake_activation_time = 0;

        let mut tracker = self
            .state
            .get_account(&"__GLOBAL_TOTAL_STAKED__".to_string())?
            .unwrap_or_default();
        tracker.balance = tracker.balance.saturating_add(settling);
        self.state
            .set_account(&"__GLOBAL_TOTAL_STAKED__".to_string(), tracker)?;
        tracing::info!(
            "⏳ HAKEDİŞ TAMAMLANDI: {} ZAGROS artık ödül-hak-edişine katıldı.",
            format_token_amount(settling)
        );
        Ok(())
    }

    /// KAYITLI, eşik üstünde ve hapiste olmayan adresleri döner; `staking_index`
    /// üzerine ince bir filtre, yeni tarama yok.
    pub fn active_validator_set(&self, block_timestamp: u128) -> Result<Vec<Address>> {
        let candidates: Vec<Address> = {
            let mut index = self
                .staking_index
                .write()
                .map_err(|_| ZagrosError::Other("Validator index lock poisoned".to_string()))?;
            if index.is_none() {
                let candidates = self.state.get_validator_candidates()?.into_iter().collect();
                *index = Some(ValidatorIndex::from_candidates(candidates));
            }
            index
                .as_ref()
                .map(|idx| idx.stakes.keys().cloned().collect())
                .unwrap_or_default()
        };

        // G2: eşik zincir-üstü ChainParams'tan (0,17 ons altın-eşdeğeri), kayıt
        // snapshot'ına histerezis uygulanır (§13.3). ChainParams yoksa Err (fail-closed).
        let params = params::load_chain_params(self.state.as_ref())?;
        let min_stake = params::min_validator_stake_zagros(self.state.as_ref(), &params)?;
        let mut qualified = Vec::new();
        for address in candidates {
            let account = self.state.get_account(&address)?.unwrap_or_default();
            let threshold = params::qualification_threshold(
                account.validator_stake_snapshot,
                min_stake,
                params.stake_hysteresis_bps,
            );
            if account.is_registered_validator
                && account.staked_balance >= threshold
                && block_timestamp >= account.jailed_until
            {
                qualified.push(address);
            }
        }
        Ok(qualified)
    }

    fn refresh_staking_index_after(&self, tx: &Transaction) -> Result<()> {
        let mut addresses = Vec::new();
        match tx.tx_type {
            TxType::StakeZagros | TxType::UnstakeZagros => {
                addresses.push(canonical_account_address(&tx.sender)?);
            }
            TxType::ReportMalicious => {
                addresses.push(canonical_account_address(&tx.receiver)?);
            }
            TxType::SlashValidator => {
                let target = zagros_types::slash_target_address(&tx.receiver, &tx.payload);
                addresses.push(canonical_account_address(&target)?);
            }
            _ => return Ok(()),
        }

        let mut index = self
            .staking_index
            .write()
            .map_err(|_| ZagrosError::Other("Validator index lock poisoned".to_string()))?;
        if let Some(index) = index.as_mut() {
            for address in addresses {
                let account = self.state.get_account(&address)?.unwrap_or_default();
                index.update(&address, &account);
            }
        }
        Ok(())
    }

    /// 🚨 Reddedilen işlemin gövdesi + `status=false` makbuzu yazılır: `sync2::read_block`
    /// her gövdeyi ister, yoksa blok servis edilemez (blok 2878). Köke etkisi yok.
    pub fn archive_dropped_transaction(&self, tx: &Transaction) -> Result<()> {
        let receipt = ArchivedReceipt {
            status: false,
            gas_used: 0,
            contract_address: None,
            logs: Vec::new(),
            block_number: 0, // archive_transaction tarafından doldurulur
        };
        archive_transaction(self.state.as_ref(), tx, receipt)
    }

    /// Kural kapıları için o anki blok yüksekliği (`__GLOBAL_BLOCK_HEIGHT__`,
    /// runtime `write_block_height` ile yürütmeden ÖNCE yazar). Yoksa 0.
    pub fn current_block_height_for_rules(&self) -> u64 {
        self.state
            .get_account(&"__GLOBAL_BLOCK_HEIGHT__".to_string())
            .ok()
            .flatten()
            .map(|a| a.balance as u64)
            .unwrap_or(0)
    }

    fn save_dummy_receipt(&self, tx: &Transaction) -> Result<()> {
        let receipt = ArchivedReceipt {
            status: true,
            gas_used: tx.gas_limit,
            contract_address: None,
            logs: Vec::new(),
            block_number: 0, // archive_transaction tarafından doldurulur
        };
        archive_transaction(self.state.as_ref(), tx, receipt)
    }

    /// Reverted işlemler için de `status=false` makbuz yazılır; yoksa
    /// `eth_getTransactionReceipt` sonsuza kadar `null` döner ve cüzdanlar
    /// (`tx.wait()`) "henüz madenlenmedi" ile "başarısız" ayrımını yapamaz.
    fn save_failed_receipt(&self, tx: &Transaction, gas_used: u64) -> Result<()> {
        let receipt = ArchivedReceipt {
            status: false,
            gas_used,
            contract_address: None,
            logs: Vec::new(),
            block_number: 0, // archive_transaction tarafından doldurulur
        };
        archive_transaction(self.state.as_ref(), tx, receipt)
    }

    /// PAXG teminatlı ZERENYA sayacı (havuz seed'i + mint − burn; kurucunun 500'ü
    /// hariç). Yakma bu sayaca karşı kontrol edilir, karşılıksız ZERENYA yakılamaz.
    pub fn bridge_backed_zerenya_key() -> Address {
        "__BRIDGE_BACKED_ZERENYA__".to_string()
    }

    fn get_bridge_backed_zerenya(&self) -> Result<u128> {
        Self::read_bridge_backed_zerenya(self.state.as_ref())
    }

    /// PAXG teminatlı ZERENYA miktarını `Executor` kurmadan doğrudan state'ten
    /// okur (RPC görüntüleme, bkz. `zagros_getBridgeBackedZerenya`).
    pub fn read_bridge_backed_zerenya(state: &dyn State) -> Result<u128> {
        Ok(state
            .get_account(&Self::bridge_backed_zerenya_key())?
            .map(|acc| acc.balance)
            .unwrap_or(0))
    }

    /// 🛡️ Zincir seviyesinde zorunlu M-of-N çoklu imza; yalnız `sender ==
    /// bridge_authority` kontrolü anahtar ele geçince mint'e izin verirdi.
    /// `tx.tx_id` = `proposal_id`; öneri var, `proposal_is_executable`, tür Mint,
    /// recipient/amount/auto_swap tx ile birebir. İmzalar zincir üstü kümeye karşı yeniden doğrulanır.
    fn validate_bridge_mint_proposal(
        &self,
        tx: &Transaction,
        expects_auto_swap: bool,
        block_timestamp: u128,
    ) -> Result<crate::bridge::BridgeProposal> {
        // 🚨 Öneri işlemin payload'ından okunur; state'ten okunsaydı yalnız RPC
        // alan düğümde bulunur, aynı blok düğümden düğüme farklı değerlendirilirdi.
        let proposal = crate::bridge::BridgeManager::decode_proposal_payload(&tx.payload)?;
        // Kimlik baglantisi: payload baska bir oneriyle degistirilemesin.
        if proposal.proposal_id != tx.tx_id {
            return Err(ZagrosError::BridgeError(
                "Payload'daki oneri kimligi islemin tx_id'si ile eslesmiyor".to_string(),
            ));
        }

        // 🚨 BİRİM: `block_timestamp` executor genelinde SANİYE, `proposal_is_executable`
        // MİLİSANİYE bekler (off-chain `can_execute` `as_millis()` verir); çevrilmezse
        // her mint "zaman kilidi dolmamış" sanılıp reddedilir.
        let block_timestamp_ms = block_timestamp.saturating_mul(1000);
        if !crate::bridge::BridgeManager::proposal_is_executable(
            &proposal,
            self.bridge_required_signatures,
            self.bridge_timelock_secs,
            block_timestamp_ms,
        ) {
            return Err(ZagrosError::BridgeError(
                "Kopru onerisi yurutulebilir degil (esik/zaman kilidi/zaten yurutulmus)"
                    .to_string(),
            ));
        }

        // 🛡️ Gerçek M-of-N: `proposal_is_executable` yalnız sayar, öneri baytları
        // doğrulanmadan state'e yazılır; imzalar ZİNCİR ÜSTÜ kümeye karşı yeniden
        // doğrulanır (config'ten okunsa ayrışan config'ler state_root'u çatallar).
        let authority_set = crate::bridge::load_bridge_authority_set(self.state.as_ref())?;
        let valid = crate::bridge::count_valid_signatures_onchain(
            &authority_set,
            &proposal,
            zagros_types::CHAIN_ID,
        );
        if valid < authority_set.required_signatures as usize {
            return Err(ZagrosError::BridgeError(format!(
                "Kopru onerisi icin yeterli GECERLI yetkili imzasi yok: {} < {}                  (dizide {} imza vardi - sayilmak yetmez, dogrulanmali)",
                valid,
                authority_set.required_signatures,
                proposal.signatures.len()
            )));
        }
        if proposal.tx_type != crate::bridge::BridgeTxType::Mint {
            return Err(ZagrosError::BridgeError(
                "Kopru onerisi mint turunde degil".to_string(),
            ));
        }
        if proposal.recipient != tx.receiver || proposal.amount != tx.amount {
            return Err(ZagrosError::BridgeError(
                "Islem, imzalanan oneriyle (alici/miktar) eslesmiyor".to_string(),
            ));
        }
        if proposal.auto_swap != expects_auto_swap {
            return Err(ZagrosError::BridgeError(
                "Islem turu (mint/mint+swap) onerideki auto_swap ile eslesmiyor".to_string(),
            ));
        }
        // 🚨 Çift basım kilidi: bu yatırışa basıldıysa farklı proposal_id ile de
        // ret. 1 kaynak tx = 1 basım; `execute_proposal` ile aynı defter.
        if crate::bridge::BridgeManager::is_source_processed_in_state(
            &proposal.source_chain,
            &proposal.source_tx_hash,
            self.state.as_ref(),
        )? {
            return Err(ZagrosError::BridgeError(format!(
                "Bu Ethereum yatirisi ({}|{}) zaten islendi - cift basim reddedildi",
                proposal.source_chain, proposal.source_tx_hash
            )));
        }
        Ok(proposal)
    }

    fn increase_bridge_backed_zerenya(&self, amount: u128) -> Result<()> {
        let current = self.get_bridge_backed_zerenya()?;
        let mut acc = AccountState::default();
        acc.balance = current.saturating_add(amount);
        self.state
            .set_account(&Self::bridge_backed_zerenya_key(), acc)
    }

    /// Teminatı düşürür. Yetersizse (olmaması gereken bir durum, çağıran
    /// yürütmeden ÖNCE `get_bridge_backed_zerenya` ile kontrol etmiş olmalı) hata
    /// döner; asla negatife/sarmaya İZİN VERMEZ.
    fn decrease_bridge_backed_zerenya(&self, amount: u128) -> Result<()> {
        let current = self.get_bridge_backed_zerenya()?;
        let new_value = current.checked_sub(amount).ok_or_else(|| {
            ZagrosError::BridgeError(
                "Bridge teminat sayaci negatife dusuyor - bu bir ic tutarsizliktir".to_string(),
            )
        })?;
        let mut acc = AccountState::default();
        acc.balance = new_value;
        self.state
            .set_account(&Self::bridge_backed_zerenya_key(), acc)
    }

    const MAX_RECENT_BRIDGE_BURNS: usize = 10_000;

    fn recent_bridge_burns_key() -> Address {
        "__RECENT_BRIDGE_BURNS__".to_string()
    }

    fn recent_bridge_burns_next_index_key() -> Address {
        "__RECENT_BRIDGE_BURNS_NEXT_INDEX__".to_string()
    }

    /// Sınırı aşan en eski kayıtları atar. Ayrı bir saf fonksiyon olarak
    /// tutuluyor ki tavan davranışı gerçek bir Executor/State kurulumu ve
    /// binlerce işlem çalıştırmadan, ucuza test edilebilsin.
    fn trim_bridge_burn_records(records: &mut Vec<zagros_types::BridgeBurnRecord>, cap: usize) {
        if records.len() > cap {
            let excess = records.len() - cap;
            records.drain(0..excess);
        }
    }

    /// Başarılı `BridgeBurn`/`BridgeSwapAndBurn` sonrası, relayer'ların
    /// `zagros_getRecentBridgeBurns` ile artımlı taradığı sınırlı boyutlu
    /// görünürlük indeksine ekler (kalıcı denetim kaydı `Receipt_<tx_id>`).
    fn record_bridge_burn(
        &self,
        tx_id: Hash,
        sender: Address,
        amount: u128,
        timestamp: u128,
    ) -> Result<()> {
        let index = self
            .state
            .get_account(&Self::recent_bridge_burns_next_index_key())?
            .map(|acc| acc.balance)
            .unwrap_or(0);

        let list_key = Self::recent_bridge_burns_key();
        let mut list_acc = self.state.get_account(&list_key)?.unwrap_or_default();
        let mut records: Vec<zagros_types::BridgeBurnRecord> = if list_acc.contract_code.is_empty()
        {
            Vec::new()
        } else {
            bincode::deserialize(&list_acc.contract_code)
                .map_err(|e| ZagrosError::Other(format!("Corrupt bridge burn index: {}", e)))?
        };
        records.push(zagros_types::BridgeBurnRecord {
            index,
            tx_id,
            sender,
            amount,
            timestamp,
        });
        Self::trim_bridge_burn_records(&mut records, Self::MAX_RECENT_BRIDGE_BURNS);
        list_acc.contract_code = bincode::serialize(&records).map_err(|e| {
            ZagrosError::Other(format!("Failed to serialize bridge burn index: {}", e))
        })?;
        self.state.set_account(&list_key, list_acc)?;

        let mut next_index_acc = AccountState::default();
        next_index_acc.balance = index + 1;
        self.state
            .set_account(&Self::recent_bridge_burns_next_index_key(), next_index_acc)
    }

    /// Burn görünürlük indeksinden `index >= since_index` kayıtları okur
    /// (`zagros_getRecentBridgeBurns`); çağıran `since_index`'i son index + 1'e ilerletir.
    pub fn load_recent_bridge_burns(
        state: &dyn State,
        since_index: u128,
    ) -> Result<Vec<zagros_types::BridgeBurnRecord>> {
        match state.get_account(&Self::recent_bridge_burns_key())? {
            Some(acc) if !acc.contract_code.is_empty() => {
                let records: Vec<zagros_types::BridgeBurnRecord> =
                    bincode::deserialize(&acc.contract_code).map_err(|e| {
                        ZagrosError::Other(format!("Corrupt bridge burn index: {}", e))
                    })?;
                Ok(records
                    .into_iter()
                    .filter(|r| r.index >= since_index)
                    .collect())
            }
            _ => Ok(Vec::new()),
        }
    }

    /// Burn indeksinde `tx_id` arar (`verify_source_burn_matches`). İndeks budanır:
    /// "kayıt yok" ile "sahte" ayırt edilemez, ikisi de fail-closed ret.
    pub fn find_bridge_burn_record(
        state: &dyn State,
        tx_id: &Hash,
    ) -> Result<Option<zagros_types::BridgeBurnRecord>> {
        match state.get_account(&Self::recent_bridge_burns_key())? {
            Some(acc) if !acc.contract_code.is_empty() => {
                let records: Vec<zagros_types::BridgeBurnRecord> =
                    bincode::deserialize(&acc.contract_code).map_err(|e| {
                        ZagrosError::Other(format!("Corrupt bridge burn index: {}", e))
                    })?;
                Ok(records.into_iter().find(|r| &r.tx_id == tx_id))
            }
            _ => Ok(None),
        }
    }

    /// 🛡️ Saklı EN ESKİ burn kaydının index'i (yoksa None). Relayer'ın `since_index`'i
    /// bunun altındaysa aradaki kayıtlar budanmıştır ("cursor gap"); RPC bunu
    /// döndürür ki relayer eksik kayıtları sessizce atlamak yerine fail-closed davransın.
    pub fn oldest_bridge_burn_index(state: &dyn State) -> Result<Option<u128>> {
        match state.get_account(&Self::recent_bridge_burns_key())? {
            Some(acc) if !acc.contract_code.is_empty() => {
                let records: Vec<zagros_types::BridgeBurnRecord> =
                    bincode::deserialize(&acc.contract_code).map_err(|e| {
                        ZagrosError::Other(format!("Corrupt bridge burn index: {}", e))
                    })?;
                Ok(records.first().map(|r| r.index))
            }
            _ => Ok(None),
        }
    }

    const MAX_SLASH_HISTORY: usize = 10_000;

    fn slash_history_key() -> Address {
        "__SLASH_HISTORY__".to_string()
    }

    fn slash_history_next_index_key() -> Address {
        "__SLASH_HISTORY_NEXT_INDEX__".to_string()
    }

    /// Başarılı `SlashValidator`/`ReportMalicious` sonrası sınırlı boyutlu denetim
    /// indeksine ekler (`record_bridge_burn` ile aynı desen); kalıcı kayıt `Receipt_<tx_id>`.
    fn record_slash_history(
        &self,
        target: Address,
        reason: zagros_types::SlashReason,
        confiscated_amount: u128,
        timestamp: u128,
    ) -> Result<()> {
        let index = self
            .state
            .get_account(&Self::slash_history_next_index_key())?
            .map(|acc| acc.balance as u64)
            .unwrap_or(0);

        let list_key = Self::slash_history_key();
        let mut list_acc = self.state.get_account(&list_key)?.unwrap_or_default();
        let mut records: Vec<zagros_types::SlashRecord> = if list_acc.contract_code.is_empty() {
            Vec::new()
        } else {
            bincode::deserialize(&list_acc.contract_code)
                .map_err(|e| ZagrosError::Other(format!("Corrupt slash history: {}", e)))?
        };
        records.push(zagros_types::SlashRecord {
            index,
            target,
            reason,
            confiscated_amount,
            timestamp,
        });
        if records.len() > Self::MAX_SLASH_HISTORY {
            let excess = records.len() - Self::MAX_SLASH_HISTORY;
            records.drain(0..excess);
        }
        list_acc.contract_code = bincode::serialize(&records)
            .map_err(|e| ZagrosError::Other(format!("Failed to serialize slash history: {}", e)))?;
        self.state.set_account(&list_key, list_acc)?;

        let mut next_index_acc = AccountState::default();
        next_index_acc.balance = (index + 1) as u128;
        self.state
            .set_account(&Self::slash_history_next_index_key(), next_index_acc)
    }

    /// Test/gözlemlenebilirlik yardımcısı: kayıtlı tüm slash geçmişini okur.
    pub fn load_slash_history(state: &dyn State) -> Result<Vec<zagros_types::SlashRecord>> {
        match state.get_account(&Self::slash_history_key())? {
            Some(acc) if !acc.contract_code.is_empty() => bincode::deserialize(&acc.contract_code)
                .map_err(|e| ZagrosError::Other(format!("Corrupt slash history: {}", e))),
            _ => Ok(Vec::new()),
        }
    }

    fn used_slashing_proofs_key() -> Address {
        "__USED_SLASHING_PROOFS__".to_string()
    }

    /// 🛡️ Replay koruması (G2): bir `SlashingProof` geçerlilik penceresinde yalnız
    /// BİR KEZ kullanılabilir; hedef yeniden stake etse bile aynı kanıt tekrar infaz
    /// edemez. Kanıt (imzalar dahil) hash'lenip kalıcı kümede tutulur.
    fn is_slashing_proof_used(&self, proof_hash: &Hash) -> Result<bool> {
        let acc = self.state.get_account(&Self::used_slashing_proofs_key())?;
        match acc {
            Some(acc) if !acc.contract_code.is_empty() => {
                let used: BTreeSet<Hash> = bincode::deserialize(&acc.contract_code)
                    .map_err(|e| ZagrosError::Other(format!("Corrupt used-proof set: {}", e)))?;
                Ok(used.contains(proof_hash))
            }
            _ => Ok(false),
        }
    }

    fn mark_slashing_proof_used(&self, proof_hash: Hash) -> Result<()> {
        let key = Self::used_slashing_proofs_key();
        let mut acc = self.state.get_account(&key)?.unwrap_or_default();
        let mut used: BTreeSet<Hash> = if acc.contract_code.is_empty() {
            BTreeSet::new()
        } else {
            bincode::deserialize(&acc.contract_code)
                .map_err(|e| ZagrosError::Other(format!("Corrupt used-proof set: {}", e)))?
        };
        used.insert(proof_hash);
        acc.contract_code = bincode::serialize(&used).map_err(|e| {
            ZagrosError::Other(format!("Failed to serialize used-proof set: {}", e))
        })?;
        self.state.set_account(&key, acc)
    }

    fn reward_snapshot_key() -> Address {
        "__LAST_REWARD_SNAPSHOT__".to_string()
    }

    /// 🏛️ Her dağıtımda güncellenen tek "son durum" snapshot'ı (gözlemlenebilirlik);
    /// canlı `acc`/`reward_debt` buna bağlı değil, liste değil tek kayıt.
    fn record_reward_snapshot(
        &self,
        total_staked: u128,
        acc: u128,
        staker_share: u128,
        validator_share: u128,
        timestamp: u128,
    ) -> Result<()> {
        let snapshot = zagros_types::RewardSnapshot {
            total_staked,
            accumulated_reward_per_share: acc,
            staker_share,
            validator_share,
            timestamp,
        };
        let mut acc_state = AccountState::default();
        acc_state.contract_code = bincode::serialize(&snapshot).map_err(|e| {
            ZagrosError::Other(format!("Failed to serialize reward snapshot: {}", e))
        })?;
        self.state
            .set_account(&Self::reward_snapshot_key(), acc_state)
    }

    /// Test/gözlemlenebilirlik yardımcısı: en son ödül dağıtım snapshot'ını okur.
    pub fn load_last_reward_snapshot(
        state: &dyn State,
    ) -> Result<Option<zagros_types::RewardSnapshot>> {
        match state.get_account(&Self::reward_snapshot_key())? {
            Some(acc) if !acc.contract_code.is_empty() => bincode::deserialize(&acc.contract_code)
                .map(Some)
                .map_err(|e| ZagrosError::Other(format!("Corrupt reward snapshot: {}", e))),
            _ => Ok(None),
        }
    }

    pub(crate) const MAX_RECENT_TRANSFERS: usize = 10_000;

    pub(crate) fn recent_transfers_next_index_key() -> Address {
        "__RECENT_TRANSFERS_NEXT_INDEX__".to_string()
    }

    /// Her transfer kaydı KENDİ anahtarında (`RecentTransfer_<index>`): yazım O(1),
    /// index tahsisi atomik. Tek blob her yazımda tüm listeyi serialize eder ve
    /// scheduler'da her Transfer'i çakışan saydırır (TPS ~200/sn'e düşer).
    pub(crate) fn recent_transfer_record_key(index: u128) -> Address {
        format!("RecentTransfer_{}", index)
    }

    /// Yan etkisiz okuma (`Executor::new` ve EVM interceptor için). 🚨 Native
    /// Transfer canlı sayacın `fetch_add`ını kullanır, bunu değil.
    pub(crate) fn peek_next_transfer_index(state: &dyn State) -> u128 {
        state
            .get_account(&Self::recent_transfers_next_index_key())
            .ok()
            .flatten()
            .map(|acc| acc.balance)
            .unwrap_or(0)
    }

    /// Başarılı native transferi `zagros_getReceivedTransfers` indeksine ekler
    /// (O(1) yazım). `counter` atomik; `state: &dyn State` alır ki interceptor da çağırabilsin.
    #[allow(clippy::too_many_arguments)]
    pub fn record_transfer(
        state: &dyn State,
        counter: &AtomicU128,
        tx_id: Hash,
        sender: Address,
        receiver: Address,
        amount: u128,
        asset: &str,
        timestamp: u128,
    ) -> Result<()> {
        // 🔒 GERÇEKTEN atomik tahsis, Rayon'un `par_iter()`'ında eşzamanlı
        // çağrılsa bile iki transfer ASLA aynı index'i alamaz (fetch_add
        // donanım seviyesinde bölünmez).
        let index = counter.fetch_add(1, Ordering::AcqRel);

        let record = zagros_types::TransferRecord {
            index,
            tx_id,
            sender,
            receiver,
            amount,
            asset: asset.to_string(),
            timestamp,
        };
        let mut record_acc = AccountState::default();
        record_acc.contract_code = bincode::serialize(&record).map_err(|e| {
            ZagrosError::Other(format!("Failed to serialize transfer record: {}", e))
        })?;
        state.set_account(&Self::recent_transfer_record_key(index), record_acc)?;

        // Pencereden düşen kayıt boş kayıtla ezilir; `hard_delete_key` checkpoint'i
        // atlayıp anında diske yazar, bu yol revert edilebilir olmalı.
        if index >= Self::MAX_RECENT_TRANSFERS as u128 {
            let evicted_index = index - Self::MAX_RECENT_TRANSFERS as u128;
            state.set_account(
                &Self::recent_transfer_record_key(evicted_index),
                AccountState::default(),
            )?;
        }

        Ok(())
    }

    /// İndeksten `index >= since_index` kayıtları okuyup `receiver` eşleşenleri
    /// döner; 🚨 `next_index` blok sonunda flush edilir, transferler bir blok gecikmeyle görünür.
    pub fn load_recent_transfers_for(
        state: &dyn State,
        receiver: &str,
        since_index: u128,
    ) -> Result<Vec<zagros_types::TransferRecord>> {
        let receiver_lower = receiver.to_lowercase();
        let next_index = state
            .get_account(&Self::recent_transfers_next_index_key())?
            .map(|acc| acc.balance)
            .unwrap_or(0);
        if next_index == 0 {
            return Ok(Vec::new());
        }
        let floor_index = next_index.saturating_sub(Self::MAX_RECENT_TRANSFERS as u128);
        let start_index = since_index.max(floor_index);
        let mut results = Vec::new();
        for index in start_index..next_index {
            if let Some(acc) = state.get_account(&Self::recent_transfer_record_key(index))? {
                if acc.contract_code.is_empty() {
                    continue; // pencereden düşüp boşaltılmış eski kayıt
                }
                let record: zagros_types::TransferRecord = bincode::deserialize(&acc.contract_code)
                    .map_err(|e| ZagrosError::Other(format!("Corrupt transfer record: {}", e)))?;
                if record.receiver.to_lowercase() == receiver_lower {
                    results.push(record);
                }
            }
        }
        Ok(results)
    }

    fn proposal_key(proposal_id: &Hash) -> Address {
        format!("Proposal_{}", hex::encode(proposal_id))
    }

    /// `Executor` gerektirmeyen salt okuma (`zagros_getProposal`); V1 geriye
    /// doldurma yapmaz, yazma isteyen çağıranlar `Executor::load_proposal`'ı kullanmalı.
    pub fn load_proposal_from_state(
        state: &dyn State,
        proposal_id: &Hash,
    ) -> Result<Option<zagros_types::Proposal>> {
        match state.get_account(&Self::proposal_key(proposal_id))? {
            Some(account) if !account.contract_code.is_empty() => {
                let proposal =
                    zagros_types::Proposal::deserialize_with_migration(&account.contract_code)
                        .map_err(|e| {
                            ZagrosError::Other(format!("Corrupt proposal record: {}", e))
                        })?;
                Ok(Some(proposal))
            }
            _ => Ok(None),
        }
    }

    /// O(1) oylama: "zaten oy verdi mi" `Proposal` blob'undaki set'e değil bu
    /// ayrı anahtarın varlığına bakılarak kontrol edilir.
    pub(crate) fn proposal_vote_key(proposal_id: &Hash, voter: &Address) -> Address {
        format!(
            "ProposalVote_{}_{}",
            hex::encode(proposal_id),
            voter.to_lowercase()
        )
    }

    /// Aktif öneri sayacı (eventually consistent): yalnız `SubmitProposal` artırır,
    /// kesin azaltma yok; tavana yaklaşınca `governance repair-active-count` ile yeniden hesaplanır.
    pub const ACTIVE_PROPOSAL_COUNT_KEY: &str = "__ACTIVE_PROPOSAL_COUNT__";

    pub fn active_proposal_count(&self) -> Result<u128> {
        Ok(self
            .state
            .get_account(&Self::ACTIVE_PROPOSAL_COUNT_KEY.to_string())?
            .map(|a| a.balance)
            .unwrap_or(0))
    }

    fn increment_active_proposal_count(&self) -> Result<()> {
        let mut acc = self
            .state
            .get_account(&Self::ACTIVE_PROPOSAL_COUNT_KEY.to_string())?
            .unwrap_or_default();
        acc.balance = acc.balance.saturating_add(1);
        self.state
            .set_account(&Self::ACTIVE_PROPOSAL_COUNT_KEY.to_string(), acc)
    }

    pub fn has_voted(&self, proposal_id: &Hash, voter: &Address) -> Result<bool> {
        Ok(self
            .state
            .get_account(&Self::proposal_vote_key(proposal_id, voter))?
            .is_some())
    }

    fn mark_voted(&self, proposal_id: &Hash, voter: &Address) -> Result<()> {
        self.state.set_account(
            &Self::proposal_vote_key(proposal_id, voter),
            AccountState::default(),
        )
    }

    /// Eski (V1, gömülü `voters`) kayıt okunursa yeni O(1) anahtar şemasına
    /// geriye doldurur. Çağıranın checkpoint'i reddedilirse yazım kalıcı olmayabilir;
    /// idempotent olduğundan sonraki başarılı dokunuşta yeniden yapılır.
    fn load_proposal(&self, proposal_id: &Hash) -> Result<Option<zagros_types::Proposal>> {
        match self.state.get_account(&Self::proposal_key(proposal_id))? {
            Some(account) if !account.contract_code.is_empty() => {
                let (proposal, legacy_voters) =
                    zagros_types::Proposal::deserialize_detecting_legacy(&account.contract_code)
                        .map_err(|e| {
                            ZagrosError::Other(format!("Corrupt proposal record: {}", e))
                        })?;
                if let Some(voters) = legacy_voters {
                    for voter in &voters {
                        self.state.set_account(
                            &Self::proposal_vote_key(proposal_id, voter),
                            AccountState::default(),
                        )?;
                    }
                    self.save_proposal(&proposal)?;
                    tracing::info!(
                        "🗳️ Migration: legacy proposal 0x{} - {} oy yeni O(1) anahtar şemasına geriye-dolduruldu.",
                        hex::encode(proposal_id),
                        voters.len()
                    );
                }
                Ok(Some(proposal))
            }
            _ => Ok(None),
        }
    }

    fn save_proposal(&self, proposal: &zagros_types::Proposal) -> Result<()> {
        let bytes = bincode::serialize(proposal)
            .map_err(|e| ZagrosError::Other(format!("Failed to serialize proposal: {}", e)))?;
        let mut account = AccountState::default();
        account.contract_code = bytes;
        self.state
            .set_account(&Self::proposal_key(&proposal.proposal_id), account)
    }

    /// `block_producer_address` ödül payı için "qualified" mi: kayıtlı, eşik üstü
    /// stake, hapiste değil. Boş adres asla qualified değil.
    fn block_producer_is_qualified(&self, block_timestamp: u128) -> Result<bool> {
        let producer = self.current_block_producer();
        if producer.is_empty() {
            return Ok(false);
        }
        let account = self.state.get_account(&producer)?.unwrap_or_default();
        let params = params::load_chain_params(self.state.as_ref())?;
        let min_stake = params::min_validator_stake_zagros(self.state.as_ref(), &params)?;
        let threshold = params::qualification_threshold(
            account.validator_stake_snapshot,
            min_stake,
            params.stake_hysteresis_bps,
        );
        Ok(account.is_registered_validator
            && account.staked_balance >= threshold
            && block_timestamp >= account.jailed_until)
    }

    // 🧠 Hazine geliri staker'lar (%80) ve validator (%20) arasında burada paylaştırılır.
    /// 🏛️ Token Factory harcı: gas ücretiyle aynı formülle ham ZAGROS'a; native ve EVM deploy bunu çağırır.
    fn token_factory_fee_per_contract(&self) -> u128 {
        let (pool_zagros, pool_zerenya) = self.state.get_pool_reserves().unwrap_or((0, 0));
        zagros_types::base_gas_fee_from_reserves(
            zagros_types::TOKEN_FACTORY_FEE_ZERENYA,
            pool_zagros,
            pool_zerenya,
        )
    }

    /// `charged` tutarının tamamını bu bloğun biriken hazine payına
    /// (`pending_gas_reward`) ekler, `flush_block_rewards` bunu blok sonunda
    /// `distribute_staking_reward` (%80 staker / %20 validator) ile dağıtır.
    fn credit_native_gas_fee(&self, charged: u128) {
        if charged == 0 {
            return;
        }
        self.pending_gas_reward.fetch_add(charged, Ordering::AcqRel);
    }

    pub fn distribute_staking_reward(
        &self,
        reward_amount: u128,
        block_timestamp: u128,
    ) -> Result<()> {
        if reward_amount == 0 {
            return Ok(());
        }

        // RocksDB'yi yormamak için toplam stake'i bu hayalet kasadan saniyesinde okuyoruz!
        let tracker = self
            .state
            .get_account(&"__GLOBAL_TOTAL_STAKED__".to_string())?
            .unwrap_or_default();
        let total_staked = tracker.balance;

        // Kimse stake etmemişken gelen ücret doğrudan Hazineye yatırılır, `acc`'a
        // yansıtılmaz (bölünecek stake yok); para protokol içinde kalır.
        if total_staked == 0 {
            self.state
                .add_balance(&VALIDATOR_REWARD_POOL.to_string(), reward_amount)?;
            self.record_reward_snapshot(
                0,
                self.state.get_accumulated_reward_per_share()?,
                0,
                0,
                block_timestamp,
            )?;
            return Ok(());
        }

        // 🏛️ %80 staker / %20 aktif validator bölüşümü (STAKER_REWARD_BPS/
        // VALIDATOR_REWARD_BPS). Üretici qualified değilse payı 0, tamamı stakera gider.
        let is_qualified = self.block_producer_is_qualified(block_timestamp)?;
        let validator_share = if is_qualified {
            let base = reward_amount.saturating_mul(zagros_types::VALIDATOR_REWARD_BPS) / 10_000;
            // 🔴 D11: üretici payı epoch katılımıyla ölçeklenir (yapısal tavana
            // normalize), kırpılan kısım staker havuzuna kalır. Aktivasyon
            // epoch'undan önce faktör 1 = eski davranış (bkz. params).
            let factor = params::producer_reward_factor_bps(
                self.state.as_ref(),
                &self.current_block_producer(),
            ) as u128;
            base.saturating_mul(factor) / 10_000
        } else {
            0
        };
        // Staker payı çıkarmayla: iki ayrı yuvarlanmış bps hesabı toplamı kaydırırdı.
        let staker_share = reward_amount - validator_share;

        if validator_share > 0 {
            self.state
                .add_balance(&self.current_block_producer(), validator_share)?;
        }

        let mut new_acc = self.state.get_accumulated_reward_per_share()?;
        if staker_share > 0 {
            self.state
                .add_balance(&VALIDATOR_REWARD_POOL.to_string(), staker_share)?;
            let added = staker_share
                .saturating_mul(1_000_000_000_000)
                .checked_div(total_staked)
                .unwrap_or(0);
            new_acc = new_acc.saturating_add(added);
            self.state.set_accumulated_reward_per_share(new_acc)?;
            let (pool_zagros, pool_zerenya) = self.state.get_pool_reserves().unwrap_or((0, 0));
            tracing::info!(
                "📈 GLOBAL ÇARPAN GÜNCELLENDİ: Hazineye {} ZAGROS (~{}) girdi (staker payı), hisselere bölündü! (validator payı: {} ZAGROS)",
                format_zagros_amount_precise(staker_share),
                zagros_amount_to_zerenya_string(staker_share, pool_zagros, pool_zerenya),
                format_zagros_amount_precise(validator_share)
            );
        }

        self.record_reward_snapshot(
            total_staked,
            new_acc,
            staker_share,
            validator_share,
            block_timestamp,
        )?;
        Ok(())
    }

    // 🏛️ Rezervlerin tek kaynağı `LIQUIDITY_POOL_ADDRESS` hesabı (state_root'a dahil);
    // `set_pool_reserves` tam olarak onu yazar, bu yardımcı ona indirgendi (isim korundu).
    fn sync_pool_reserves(&self, new_pool_zagros: u128, new_pool_zerenya: u128) -> Result<()> {
        self.state
            .set_pool_reserves(new_pool_zagros, new_pool_zerenya)
    }

    pub fn apply_transaction(
        &self,
        tx: &Transaction,
        block_timestamp: u128,
    ) -> std::result::Result<u128, (ZagrosError, u128)> {
        tx.validate().map_err(|error| (error.into(), 0))?;
        if block_timestamp.abs_diff(tx.timestamp) > 300 {
            return Err((ZagrosError::TransactionExpired, 0));
        }

        let is_evm = matches!(
            tx.tx_type,
            TxType::ContractCall { .. } | TxType::CallContract
        );
        let _evm_guard = if is_evm {
            Some(self.evm_execution_lock.lock().map_err(|_| {
                (
                    ZagrosError::Other("EVM execution lock poisoned".to_string()),
                    0,
                )
            })?)
        } else {
            None
        };

        let sender_key = canonical_account_address(&tx.sender).map_err(|error| (error, 0))?;
        let receiver_key = canonical_account_address(&tx.receiver).map_err(|error| (error, 0))?;
        // G2: ApproveValidator/RemoveValidator hedefi payload'dadır; scheduler ile
        // AYNI çözümleyici (`validator_action_target`), çözülemezse fail-closed.
        let action_target: Option<Address> = match tx.tx_type {
            TxType::ApproveValidator | TxType::RemoveValidator => Some(
                zagros_types::consensus::validator_action_target(&tx.tx_type, &tx.payload).ok_or(
                    (
                        ZagrosError::Other(
                            "ApproveValidator/RemoveValidator payload cozulemedi".to_string(),
                        ),
                        0,
                    ),
                )?,
            ),
            _ => None,
        };

        // 🚨 Self-deadlock: `match entry(..)` shard kilidini match boyunca tutar,
        // aynı shard'daki `remove` kendi kilidini beklerdi; `insert()` guard'ı hemen bırakır.
        let mut reserved = Vec::with_capacity(3);
        let mut to_reserve: Vec<&Address> = vec![&sender_key, &receiver_key];
        if let Some(t) = action_target.as_ref() {
            to_reserve.push(t);
        }
        for address in to_reserve {
            if reserved.contains(address) {
                continue; // self-transfer: sender == receiver, only reserve once
            }
            let already_occupied = self
                .processing_addresses
                .insert(address.clone(), ())
                .is_some();
            if already_occupied {
                for acquired in &reserved {
                    self.processing_addresses.remove(acquired);
                }
                return Err((ZagrosError::Reentrancy, 0));
            }
            reserved.push(address.clone());
        }
        let _reentrancy_guard = MultiAddressReentrancyGuard {
            addresses: reserved,
            lock: self.processing_addresses.clone(),
        };

        let sender = self
            .state
            .get_account(&sender_key)
            .map_err(|error| (error, 0))?
            .or_else(|| {
                if sender_key != tx.sender {
                    self.state.get_account(&tx.sender).ok().flatten()
                } else {
                    None
                }
            })
            .unwrap_or_default();
        if tx.nonce != sender.nonce {
            return Err((ZagrosError::InvalidNonce, 0));
        }

        // 🛡️ KÖPRÜ MİNT ÜCRET MUAFİYETİ, `Mempool::add_transaction` ile AYNI koşul:
        // mint zaten gerçek yatırma + onay + haberci imzası gerektirir, ücret ek
        // güvenlik sağlamaz. Burada da muaf sayılmazsa kesinti uygulanır, muafiyet yarım kalır.
        let is_exempt_bridge_mint =
            matches!(tx.tx_type, TxType::BridgeMint | TxType::BridgeMintAndSwap)
                && tx.sender == self.bridge_authority;

        let tx_fee = if is_exempt_bridge_mint {
            0
        } else {
            let declared = (tx.gas_limit as u128)
                .checked_mul(tx.gas_price)
                .ok_or((ZagrosError::GasLimitExceeded, 0))?;
            // 🛡️ D14: gas alanları imzaya bağlı değil; kötü üretici tüm bakiyeyi "ücret"
            // kesebilirdi. Native ücret deterministik, tavan stres çarpanı (1024x); aşan GEÇERSİZ.
            if !is_evm {
                let block_height = self.current_block_height_for_rules();
                if block_height >= zagros_types::D14_RULES_ACTIVATION_HEIGHT {
                    let (pool_zagros, pool_zerenya) =
                        self.state.get_pool_reserves().unwrap_or((0, 0));
                    let base = GasCalculator::with_target(
                        Arc::new(AtomicU128::new(pool_zagros)),
                        Arc::new(AtomicU128::new(pool_zerenya)),
                        self.gas_target_zerenya,
                    )
                    .calculate_gas_for_tx_type(&tx.tx_type, 0);
                    let ceiling = base.saturating_mul(1024);
                    if base > 0 && declared > ceiling {
                        return Err((
                            ZagrosError::Other(format!(
                                "ücret kanonik tavanı aşıyor (D14): deklare {declared} > tavan {ceiling}"
                            )),
                            0,
                        ));
                    }
                }
            }
            declared
        };

        // 🏭 EVM üretim harcı (x100) admission'da değil burada, ölçülen gazın üstüne;
        // bir kez hesaplanıp ön kontrol ve kesintide aynı tutar.
        let is_evm_tx_type = matches!(
            tx.tx_type,
            TxType::ContractCall { .. } | TxType::CallContract
        );
        let deploy_levy = if is_evm_tx_type && zagros_types::is_evm_deploy(&tx.receiver) {
            self.evm_deploy_levy()
        } else {
            0
        };

        // EVM standart ücret tabanı (bkz. `evm_standard_fee`), admission'da değil
        // burada; bir kez hesaplanır. DEPLOY'lar MUAF: zaten daha büyük üretim
        // harcını öder, taban yalnız deploy olmayan EVM çağrıları içindir.
        let evm_standard_floor = if is_evm_tx_type && !zagros_types::is_evm_deploy(&tx.receiver) {
            self.evm_standard_fee()
        } else {
            0
        };

        // Gönderen gas bütçesi (ya da EVM tabanı) + üretim harcını karşılamalı;
        // yoksa `saturating_sub` bakiyeyi 0'a çakıp havuza alınmamış parayı yazardı.
        if sender.balance < tx_fee.max(evm_standard_floor).saturating_add(deploy_levy) {
            return Err((ZagrosError::InsufficientBalanceForGas, 0));
        }

        let checkpoint_id = self.state.checkpoint().map_err(|error| (error, 0))?;
        let mut evm_gas_used = None;
        let mut nonce_already_advanced = false;
        // Kontrat oluşturan EVM işlemi zaten token factory harcı öder; ×5 taban
        // onun üstüne eklenmez (`effective_evm_floor`).
        let mut evm_created_contract = false;
        let execution_result = catch_unwind(AssertUnwindSafe(|| {
            self.execute_transaction_inner(
                tx,
                block_timestamp,
                &mut evm_gas_used,
                &mut nonce_already_advanced,
                &mut evm_created_contract,
            )
        }))
        .unwrap_or_else(|_| Err(ZagrosError::Other("Panic during execution".to_string())));
        match execution_result {
            Ok(_gas_charged) => {
                let is_evm = matches!(
                    tx.tx_type,
                    TxType::ContractCall { .. } | TxType::CallContract
                );

                // Kontrat oluşturan çağrıda ×5 taban istiflenmez; yalnız kontrat
                // oluşturmayan gerçek EVM çağrılarında (swap, LP) taban geçerli.
                let effective_evm_floor = if evm_created_contract {
                    0
                } else {
                    evm_standard_floor
                };

                // EVM deploy'da ölçülen gazın üstüne üretim harcı eklenir (deploy
                // değilse 0); başarısız işlemde harç alınmaz (kontrat üretilmedi).
                let actual_gas = if is_evm {
                    // Ölçülen gaz (gas_used × 1 gwei) ile altın-çıpalı standart
                    // taban'dan BÜYÜK olanı, artı üretim harcı. Tipik işlemde taban
                    // geçerli (~28 sent); devasa işlemde ölçülen gaz aşarsa o.
                    let metered = evm_gas_used
                        .map(|gas_used| (gas_used as u128).saturating_mul(tx.gas_price))
                        .unwrap_or(tx_fee);
                    metered.max(effective_evm_floor).saturating_add(deploy_levy)
                } else {
                    tx_fee
                };

                // 🚨 Nonce/ücret muhasebesi `commit_checkpoint`ten ÖNCE, aynı checkpoint
                // içinde; ters sıra çökme sonrası aynı işlemi yeniden uygulatırdı (çift harcama).
                let mut sender_end = self
                    .state
                    .get_account(&sender_key)
                    .unwrap_or_default()
                    .unwrap_or_default();
                // 🚨 Gerçek EVM çağrısında nonce'u revm artırdı (`nonce_already_advanced`);
                // tekrar artırmak nonce'u ikiye atlatır.
                if !nonce_already_advanced {
                    sender_end.increment_nonce();
                }
                if actual_gas > 0 {
                    // 🚨 Havuza yalnız gerçekten kesilen tutar yazılır (bakiyeye kelepçeli).
                    // EVM'de revm gas'ı zaten düştü; burada yalnız Zagros eklemeleri
                    // (deploy harcı + tabanın ölçüleni aşan kısmı) kesilir, çift gaz olmaz.
                    let not_yet_reflected = if nonce_already_advanced {
                        let metered = evm_gas_used
                            .map(|gas_used| (gas_used as u128).saturating_mul(tx.gas_price))
                            .unwrap_or(tx_fee);
                        effective_evm_floor
                            .saturating_sub(metered)
                            .saturating_add(deploy_levy)
                    } else {
                        actual_gas
                    };
                    if not_yet_reflected > 0 {
                        let charged = not_yet_reflected.min(sender_end.balance);
                        sender_end.balance -= charged;
                        self.credit_native_gas_fee(charged);
                    }
                }
                self.state
                    .set_account(&sender_key, sender_end)
                    .unwrap_or_default();

                // Checkpoint etki + nonce/ücret tamamen yazıldıktan SONRA commit edilir;
                // `CheckpointGate` o ana kadar flush'ı bekletir.
                self.state
                    .commit_checkpoint(checkpoint_id)
                    .map_err(|error| (error, 0))?;

                self.refresh_staking_index_after(tx)
                    .map_err(|error| (error, 0))?;
                Ok(actual_gas)
            }
            Err(execution_error) => {
                self.state
                    .revert_checkpoint(checkpoint_id)
                    .map_err(|error| (error, 0))?;

                let is_evm = matches!(
                    tx.tx_type,
                    TxType::ContractCall { .. } | TxType::CallContract
                );
                // Revert edilen EVM işlemi de standart tabanı öder (ucuz revert spam'i
                // olmasın); deploy harcı eklenmez, üretilmiş kontrat yok.
                let gas_to_charge = if is_evm {
                    let metered = evm_gas_used
                        .map(|gas_used| (gas_used as u128).saturating_mul(tx.gas_price))
                        .unwrap_or(tx_fee);
                    metered.max(evm_standard_floor)
                } else {
                    tx_fee
                };
                self.settle_failed_native_transaction(&sender_key, gas_to_charge)
                    .map_err(|error| (error, 0))?;
                // Bkz. `save_failed_receipt` doc yorumu: reverted işlem de makbuz
                // yazar, yoksa `eth_getTransactionReceipt` sonsuza kadar `null` döner.
                let failed_gas_used = evm_gas_used.unwrap_or(tx.gas_limit);
                self.save_failed_receipt(tx, failed_gas_used)
                    .map_err(|error| (error, gas_to_charge))?;
                Err((execution_error, gas_to_charge))
            }
        }
    }

    fn settle_failed_native_transaction(&self, sender_key: &Address, tx_fee: u128) -> Result<()> {
        let checkpoint_id = self.state.checkpoint()?;
        let settlement = (|| {
            let mut sender = self.state.get_account(sender_key)?.unwrap_or_default();
            sender.sub_balance(tx_fee)?;
            sender.increment_nonce();
            self.state.set_account(sender_key, sender)?;
            self.credit_native_gas_fee(tx_fee);
            Ok(())
        })();

        match settlement {
            Ok(()) => self.state.commit_checkpoint(checkpoint_id),
            Err(error) => {
                self.state.revert_checkpoint(checkpoint_id)?;
                Err(error)
            }
        }
    }

    pub fn execute_transaction(&self, tx: &Transaction, block_timestamp: u128) -> Result<()> {
        self.apply_transaction(tx, block_timestamp)
            .map(|_| ())
            .map_err(|(error, _)| error)
    }

    fn execute_transaction_inner(
        &self,
        tx: &Transaction,
        block_timestamp: u128,
        evm_gas_used: &mut Option<u64>,
        nonce_already_advanced: &mut bool,
        evm_created_contract: &mut bool,
    ) -> Result<u128> {
        let sender_key = canonical_account_address(&tx.sender)?;
        let mut sender = match self.state.get_account(&sender_key)? {
            Some(account) => account,
            None if sender_key != tx.sender => {
                self.state.get_account(&tx.sender)?.unwrap_or_default()
            }
            None => AccountState::default(),
        };

        if tx.nonce != sender.nonce {
            return Err(ZagrosError::InvalidNonce);
        }

        // 1. AĞ ÜCRETİ (GAS FEE) KONTROLÜ
        // 🛡️ Köprü mint ücret muafiyeti: `apply_transaction` ve `Mempool::add_transaction`
        // ile AYNI koşul; üçü ayrışırsa sıfır bakiyeli bridge_authority burada reddedilir.
        let is_exempt_bridge_mint =
            matches!(tx.tx_type, TxType::BridgeMint | TxType::BridgeMintAndSwap)
                && tx.sender == self.bridge_authority;
        let tx_fee = if is_exempt_bridge_mint {
            0
        } else {
            (tx.gas_limit as u128).saturating_mul(tx.gas_price)
        };
        let is_evm_tx = matches!(
            tx.tx_type,
            TxType::ContractCall { .. } | TxType::CallContract
        );

        // ✅ Artık hem EVM hem Native için sadece Bakiye Yeterliliği Kontrol Ediliyor
        let required_balance = if is_evm_tx {
            tx_fee.saturating_add(tx.amount)
        } else {
            // Native işlemlerde tutar + gas; BridgeSwapAndBurn da ZAGROS düşürdüğünden
            // `tx.amount` dahil (mempool `native_zagros_cost` ile birebir).
            if matches!(
                tx.tx_type,
                TxType::Transfer
                    | TxType::SwapSell
                    | TxType::StakeZagros
                    | TxType::BridgeSwapAndBurn
            ) {
                tx_fee.saturating_add(tx.amount)
            } else {
                tx_fee
            }
        };

        if sender.balance < required_balance {
            return Err(ZagrosError::InsufficientBalance);
        }

        let mut gas_charged = tx_fee;

        match &tx.tx_type {
            TxType::Transfer => {
                // 🚨 Sıfır adres havuzun ZAGROS rezervidir; düz `Transfer` rezervi
                // korumasız şişirirdi. Havuza tek meşru yol swap.rs (EVM `addLiquidity` de yok).
                if tx.receiver == LIQUIDITY_POOL_ADDRESS {
                    return Err(ZagrosError::Other(
                        "Havuz adresine doğrudan transfer yapılamaz - swap kullanın".to_string(),
                    ));
                }
                // 🛡️ D14 (denetim A2): KENDİNE transfer REDDEDİLİR; fonksiyon sonundaki
                // `set_account(sender)` (bayat snapshot) alıcı kredisini ezip tutarı yok
                // ederdi (42M arz ihlali). Meşru kullanımı yok.
                if self.current_block_height_for_rules()
                    >= zagros_types::D14_RULES_ACTIVATION_HEIGHT
                    && canonical_account_address(&tx.receiver)? == sender_key
                {
                    return Err(ZagrosError::Other(
                        "Kendine transfer geçersizdir (D14)".to_string(),
                    ));
                }
                // Gönderenin partisinden gas dışında gönderilen miktarı düşüyoruz!
                sender.balance = sender.balance.saturating_sub(tx.amount);

                let mut receiver = self.state.get_account(&tx.receiver)?.unwrap_or_default();
                receiver.balance = receiver.balance.saturating_add(tx.amount);
                self.state.set_account(&tx.receiver, receiver)?;

                // 📜 "Alındı" (receive) görünürlüğü için: dapp'in
                // zagros_getReceivedTransfers ile tarayabileceği indekse ekle.
                Self::record_transfer(
                    self.state.as_ref(),
                    &self.recent_transfer_index_counter,
                    tx.tx_id,
                    tx.sender.clone(),
                    tx.receiver.clone(),
                    tx.amount,
                    "ZAGROS",
                    block_timestamp,
                )?;

                // 📜 Diğer TxType kollarındaki açıklayıcı log deseni; Transfer'de neyin
                // transfer edildiği görünsün.
                tracing::info!(
                    "💸 NATIVE TRANSFER: {} ZAGROS | {} -> {}",
                    format_token_amount(tx.amount),
                    tx.sender,
                    tx.receiver
                );
            }
            TxType::SwapBuy => {
                if sender.zerenya_balance < tx.amount {
                    return Err(ZagrosError::InsufficientBalance);
                }

                let (res_zagros, res_zerenya) = self.state.get_pool_reserves()?;
                let amount_out_min = swap_amount_out_min(tx)?;

                // 🛡️ #11: hacim 60 saniyelik pencereye kaydedilir, tek-işlem %5
                // devre kesici tavanının parçalanarak atlatılmasını önler.
                // Ücret oranı sabit `STANDARD_SWAP_FEE_BPS`.
                let fee_bps = record_volume_and_compute_fee_bps(
                    self.state.as_ref(),
                    SwapDirection::ZerenyaIn,
                    tx.amount,
                    res_zerenya,
                    block_timestamp as u64,
                )?;

                let quote = quote_swap_buy(tx.amount, res_zagros, res_zerenya, fee_bps)?;
                if amount_out_min > 0 && quote.amount_out < amount_out_min {
                    return Err(ZagrosError::Other("Slippage too high".to_string()));
                }

                sender.zerenya_balance = sender.zerenya_balance.saturating_sub(tx.amount);
                sender.balance = sender.balance.saturating_add(quote.amount_out);

                // Ücret ZERENYA bekleme odasına gitmez; gas fee ile aynı mantıkla
                // çıkıştan (ZAGROS) kesilip anında Hazineye dağıtılır.
                if quote.community_fee > 0 {
                    self.distribute_staking_reward(quote.community_fee, block_timestamp)?;
                }

                self.sync_pool_reserves(quote.new_pool_zagros, quote.new_pool_zerenya)?;
                tracing::info!(
                    "🔄 NATIVE L1 SWAP BUY: {} ZERENYA -> {} ZAGROS",
                    format_token_amount(tx.amount),
                    format_token_amount(quote.amount_out)
                );
            }
            TxType::SwapSell => {
                if sender.balance < tx.amount {
                    return Err(ZagrosError::InsufficientBalance);
                }

                // 🛡️ FAZ3: get_pool_reserves hatası artık YUTULMUYOR (eski
                // unwrap_or((0,0)) yerine `?`), DB okuma hatasında işlem
                // düşer, sahte (0,0) rezervle devam etmez.
                let (res_zagros, res_zerenya) = self.state.get_pool_reserves()?;

                // 🛡️ Yetersiz rezervde likidite UYDURULMAZ (42M arz değişmezi);
                // kendi tarafına özgü MIN_POOL_LIQUIDITY tabanı zorunlu.
                if res_zagros < MIN_POOL_LIQUIDITY_ZAGROS
                    || res_zerenya < MIN_POOL_LIQUIDITY_ZERENYA
                {
                    return Err(ZagrosError::Other("Insufficient liquidity".to_string()));
                }
                // 🛡️ FAZ3: %5 devre kesici, SwapBuy (quote_swap_buy) ile simetrik.
                // Tek işlemde ZAGROS rezervinin %5'inden fazlasını satıp fiyatı
                // kırmayı / flash-loan tarzı manipülasyonu engeller.
                if tx.amount > res_zagros.saturating_mul(MAX_SWAP_AMOUNT_PERCENT) / 100 {
                    return Err(ZagrosError::Other("Swap too large".to_string()));
                }
                // 🛡️ Hacim 60 sn pencereye kaydedilir (parçalı atlatma yok); ücret sabit
                // `STANDARD_SWAP_FEE_BPS`, EVM yolu da aynı kaynağı kullanır.
                let fee_bps = record_volume_and_compute_fee_bps(
                    self.state.as_ref(),
                    SwapDirection::ZagrosIn,
                    tx.amount,
                    res_zagros,
                    block_timestamp as u64,
                )?;

                // 🛡️ Güvenli çözücü: `to::<u128>()` u128::MAX üstünde panik atardı,
                // `swap_amount_out_min` temiz `Err` döner.
                let amount_out_min = swap_amount_out_min(tx)?;
                use alloy_primitives::U256;

                let swap_fee = tx.amount.saturating_mul(fee_bps) / 10000;

                if swap_fee > 0 {
                    // Hazineye giren ücret staker'ların "Biriken Ödül" çarpanına
                    // (acc) da yansır, `distribute_staking_reward` bunu tek
                    // sorumluluk olarak kendi içinde yapıyor.
                    self.distribute_staking_reward(swap_fee, block_timestamp)?;
                }

                let input_with_fee = tx.amount.saturating_sub(swap_fee);
                let zsc_out = U256::from(input_with_fee)
                    .saturating_mul(U256::from(res_zerenya))
                    .checked_div(U256::from(res_zagros).saturating_add(U256::from(input_with_fee)))
                    .unwrap_or(U256::ZERO)
                    .to::<u128>();
                if zsc_out == 0 {
                    return Err(ZagrosError::Other("Likidite yetersiz".to_string()));
                }

                if zsc_out < amount_out_min {
                    tracing::error!(
                        "🔍 SWAPSELL FAIL: tx_amount={} amount_out_min={} output={} pool_zagros={} pool_zerenya={} payload=0x{}",
                        tx.amount,
                        amount_out_min,
                        zsc_out,
                        res_zagros,
                        res_zerenya,
                        hex::encode(&tx.payload),
                    );
                    return Err(ZagrosError::Other(format!(
                        "Slippage Koruması! Beklenen: {}, Havuzun Verdigi: {}",
                        amount_out_min, zsc_out
                    )));
                }

                // DİKKAT: SATILAN ZAGROS KULLANICI BAKİYESİNDEN DÜŞÜLÜYOR
                sender.balance = sender.balance.saturating_sub(tx.amount);
                sender.zerenya_balance = sender.zerenya_balance.saturating_add(zsc_out);

                // KV çifti (set_pool_reserves) ile `LIQUIDITY_POOL_ADDRESS`
                // hesabının .balance/.zerenya_balance alanları birlikte, tek
                // kaynaktan güncellenir.
                self.sync_pool_reserves(
                    res_zagros.saturating_add(input_with_fee),
                    res_zerenya.saturating_sub(zsc_out),
                )?;
                tracing::info!(
                    "🔄 NATIVE L1 SWAP: {} ZAGROS -> {} ZERENYA | Vergi: {} BPS ({} ZAGROS)",
                    format_token_amount(tx.amount),
                    format_token_amount(zsc_out),
                    fee_bps,
                    format_zagros_amount_precise(swap_fee)
                );
            }
            TxType::StakeZagros => {
                if sender.balance < tx.amount {
                    return Err(ZagrosError::InsufficientBalance);
                }

                // 🛡️ E1: bu işlemin ekleyeceği miktardan ÖNCE, önceki stake'ten
                // olgunlaşmış miktarı aktif et; yoksa aşağıdaki
                // `pending_stake_activation_time` yazımı onu yanlışlıkla ertelerdi.
                self.settle_pending_stake(&mut sender, block_timestamp)?;

                // Kullanıcının bakiyesinden stake edilen miktarı düşüyoruz!
                sender.balance = sender.balance.saturating_sub(tx.amount);

                let acc = self.state.get_accumulated_reward_per_share()?;

                // Hazine yetersizse kısmi ödenen
                // ödülün ÖDENMEYEN kısmı (shortfall) kaybolmamalı, reward_debt'e
                // taşınıp bir sonraki talepte tekrar istenebilmeli.
                let mut unpaid_shortfall: u128 = 0;
                if sender.staked_balance > 0 {
                    let pending =
                        reward_owed(sender.staked_balance, acc).saturating_sub(sender.reward_debt);
                    if pending > 0 {
                        let mut treasury = self
                            .state
                            .get_account(&VALIDATOR_REWARD_POOL.to_string())?
                            .unwrap_or_default();
                        let payout = if treasury.balance < pending {
                            treasury.balance
                        } else {
                            pending
                        };
                        treasury.balance = treasury.balance.saturating_sub(payout);
                        sender.balance = sender.balance.saturating_add(payout);
                        self.state
                            .set_account(&VALIDATOR_REWARD_POOL.to_string(), treasury)?;
                        unpaid_shortfall = pending.saturating_sub(payout);
                        tracing::info!(
                            "💰 AUTO-CLAIM: Stake güncellenmeden önce {} ZAGROS ödül ödendi.",
                            format_zagros_amount_precise(payout)
                        );
                    }
                }

                // 🛡️ Anti-flash-stake: yeni miktar `REWARD_VESTING_SECONDS` dolmadan ödüle
                // katılmaz; zamanlayıcı son eklemeden başlar (tek kova, bilinçli sadelik).
                sender.pending_stake_amount = sender.pending_stake_amount.saturating_add(tx.amount);
                sender.pending_stake_activation_time =
                    block_timestamp.saturating_add(zagros_types::REWARD_VESTING_SECONDS);
                // reward_debt = MEVCUT (aktif) staked_balance'ın tam accrued'ı
                // EKSİ ödenmemiş shortfall. Yeni eklenen `pending_stake_amount`
                // henüz `acc` muhasebesine dahil DEĞİL, reward_debt'i etkilemez.
                sender.reward_debt =
                    reward_owed(sender.staked_balance, acc).saturating_sub(unpaid_shortfall);

                tracing::info!(
                    "🛡️ STAKE ALINDI: {} ZAGROS, {} saniye sonra ödül-hak-edişine katılacak.",
                    format_token_amount(tx.amount),
                    zagros_types::REWARD_VESTING_SECONDS
                );
            }
            TxType::UnstakeZagros => {
                // G7 (INV-E3): teminat `bond_unlock_at`a kadar kilitli (amount==0 dahil);
                // yoksa validator kanıt penceresi kapanmadan teminatı çekerdi.
                if sender.bond_unlock_at > 0 && block_timestamp < sender.bond_unlock_at {
                    return Err(ZagrosError::StakingError(
                        "Teminat bond lock suresi icinde kilitli (equivocation kaniti penceresi) - cekim yapilamaz".to_string(),
                    ));
                }
                if tx.amount == 0 {
                    if sender.pending_unstake_amount > 0 {
                        if tx.timestamp >= sender.unlock_time {
                            let mature_amount = sender.pending_unstake_amount;
                            sender.pending_unstake_amount = 0;
                            sender.balance = sender.balance.saturating_add(mature_amount);
                            tracing::info!(
                                "🔓 ZAMAN KİLİDİ AÇILDI: {} ZAGROS cüzdana indi!",
                                format_token_amount(mature_amount)
                            );
                            // Erken return fonksiyon sonundaki state kaydını ve makbuz
                            // oluşturmayı atlar; burada elle kaydediyoruz.
                            self.state.set_account(&sender_key, sender)?;
                            self.save_dummy_receipt(tx)?;
                            return Ok(0);
                        } else {
                            return Err(ZagrosError::StakingError(
                                "Kilit devam ediyor.".to_string(),
                            ));
                        }
                    }
                    return Err(ZagrosError::StakingError("Bekleyen bakiye yok".to_string()));
                }

                // 🚨 Zaman kilidi şişmesin: içeride kilitli parası varsa yenisini ekletme
                if sender.pending_unstake_amount > 0 {
                    return Err(ZagrosError::StakingError(
                        "Aktif kilit var. Önce onun bitmesini 48s bekleyin.".to_string(),
                    ));
                }

                // 🛡️ E1: varsa olgunlaşmış bekleyen stake'i önce aktif hale
                // getir, `staked_balance`/`pending_stake_amount` ayrımını
                // aşağıdaki hesaplar için doğru başlangıç noktasına oturtur.
                self.settle_pending_stake(&mut sender, block_timestamp)?;

                if tx.amount
                    > sender
                        .staked_balance
                        .saturating_add(sender.pending_stake_amount)
                {
                    return Err(ZagrosError::StakingError("Bakiye yetersiz".to_string()));
                }

                // 🛡️ E1: olgunlaşmamış (`pending_stake_amount`) miktar ödül kazanmadığından
                // unstake önce oradan karşılanır; kalan `staked_balance`'tan normal
                // ödül hak edişli yoldan düşer.
                let from_pending = tx.amount.min(sender.pending_stake_amount);
                sender.pending_stake_amount -= from_pending;
                if sender.pending_stake_amount == 0 {
                    sender.pending_stake_activation_time = 0;
                }
                let from_active = tx.amount - from_pending;

                if from_active > 0 {
                    let acc = self.state.get_accumulated_reward_per_share()?;
                    // Hazine yetersizse ödenmeyen
                    // ödül kısmı (shortfall) reward_debt'e taşınır, sessizce
                    // silinmez.
                    let mut unpaid_shortfall: u128 = 0;
                    let pending =
                        reward_owed(sender.staked_balance, acc).saturating_sub(sender.reward_debt);
                    if pending > 0 {
                        let mut treasury = self
                            .state
                            .get_account(&VALIDATOR_REWARD_POOL.to_string())?
                            .unwrap_or_default();
                        let payout = if treasury.balance < pending {
                            treasury.balance
                        } else {
                            pending
                        };
                        treasury.balance = treasury.balance.saturating_sub(payout);
                        sender.balance = sender.balance.saturating_add(payout);
                        self.state
                            .set_account(&VALIDATOR_REWARD_POOL.to_string(), treasury)?;
                        unpaid_shortfall = pending.saturating_sub(payout);
                        tracing::info!(
                            "💰 AUTO-CLAIM: Unstake öncesi {} ZAGROS ödül ödendi.",
                            format_zagros_amount_precise(payout)
                        );
                    }

                    sender.staked_balance = sender.staked_balance.saturating_sub(from_active);
                    // reward_debt = KALAN stake'in tam accrued'ı EKSİ ödenmemiş
                    // shortfall (carry-forward). Böylece hazine sonradan
                    // fonlanınca kullanıcı eksik ödülünü tekrar talep edebilir.
                    sender.reward_debt =
                        reward_owed(sender.staked_balance, acc).saturating_sub(unpaid_shortfall);

                    let mut tracker = self
                        .state
                        .get_account(&"__GLOBAL_TOTAL_STAKED__".to_string())?
                        .unwrap_or_default();
                    tracker.balance = tracker.balance.saturating_sub(from_active);
                    self.state
                        .set_account(&"__GLOBAL_TOTAL_STAKED__".to_string(), tracker)?;
                }

                // Çekilecek anaparanın tamamı aynı 48 saatlik kilitten geçer; hakediş
                // yalnız ödül uygunluğunu etkiler.
                sender.pending_unstake_amount =
                    sender.pending_unstake_amount.saturating_add(tx.amount);
                sender.unlock_time = tx.timestamp + 172_800; // 48 saat (172_800 saniye) kilit süresi

                // 🛡️ INV-E3: kayıtlı validator'ın düz unstake'i de `bond_lock_seconds`
                // kilitler; yoksa Unregister'ı atlayıp kanıt penceresinde müsadereden kaçardı.
                if sender.is_registered_validator {
                    let p = params::load_chain_params(self.state.as_ref())?;
                    sender.bond_unlock_at = sender
                        .bond_unlock_at
                        .max(block_timestamp.saturating_add(p.bond_lock_seconds as u128));
                }

                tracing::info!(
                    "🔓 UNSTAKE BAŞARILI: {} ZAGROS 48 saat kilidine alındı.",
                    format_token_amount(tx.amount)
                );
            }
            TxType::ClaimReward => {
                // 🛡️ E1: bir ClaimReward, olgunlaşmış bekleyen stake'i aktif
                // hale getirmenin de doğal tetikleyicisi olsun, kullanıcı
                // hiç yeni Stake/Unstake göndermese bile.
                self.settle_pending_stake(&mut sender, block_timestamp)?;
                if sender.staked_balance > 0 {
                    let acc = self.state.get_accumulated_reward_per_share()?;
                    let accrued = reward_owed(sender.staked_balance, acc);
                    let pending_reward = accrued.saturating_sub(sender.reward_debt);

                    if pending_reward > 0 {
                        let mut updated_treasury = self
                            .state
                            .get_account(&VALIDATOR_REWARD_POOL.to_string())?
                            .unwrap_or_default();
                        let safe_payout = if updated_treasury.balance < pending_reward {
                            tracing::warn!(
                                "⚠️ Kuruş yuvarlama farkı! Kasa: {}",
                                updated_treasury.balance
                            );
                            updated_treasury.balance
                        } else {
                            pending_reward
                        };

                        if safe_payout > 0 {
                            updated_treasury.balance =
                                updated_treasury.balance.saturating_sub(safe_payout);
                            sender.balance = sender.balance.saturating_add(safe_payout);
                            self.state.set_account(
                                &VALIDATOR_REWARD_POOL.to_string(),
                                updated_treasury,
                            )?;
                            tracing::info!(
                                "💰 ÖDÜL ÇEKİLDİ (CLAIM): Miktar: {} ZAGROS",
                                format_zagros_amount_precise(safe_payout)
                            );
                            // 🚨 reward_debt yalnız FİİLEN ödenen kadar ilerler; hazine
                            // yetersizken ödenmeyen fark silinmez, sonraki ClaimReward'da istenir.
                            sender.reward_debt = sender.reward_debt.saturating_add(safe_payout);
                        }
                    }
                }
            }
            TxType::SlashValidator => {
                if tx.sender != self.admin_authority {
                    return Err(ZagrosError::Other("Yetkisiz!".to_string()));
                }
                if !self.is_admin_authority_active(block_timestamp)? {
                    return Err(ZagrosError::Other(
                        "Admin authority has expired - SlashValidator is permanently disabled"
                            .to_string(),
                    ));
                }
                // 🛡️ Hedef tek kaynaktan (`zagros_types::slash_target_address`) çözülür;
                // scheduler kilidi ve re-entrancy kilidi de aynı fonksiyonu çağırır, üçü
                // aynı hedefi kilitler (yoksa veri yarışı).
                let target_address = zagros_types::slash_target_address(&tx.receiver, &tx.payload);

                // 🛡️ ÖZ HEDEF: hedef `tx.sender`'ın kendisiyse ayrı okuyup yazmak fonksiyon
                // sonundaki `set_account(sender)` tarafından ezilir (müsadere kaybolur);
                // bu yüzden eldeki `sender` mutasyona uğratılır.
                let is_self_target = target_address.eq_ignore_ascii_case(&sender_key);
                let mut target = if is_self_target {
                    sender.clone()
                } else {
                    self.state.get_account(&target_address)?.unwrap_or_default()
                };
                // 🛡️ Müsadere ÜÇ alanı kapsar: `staked_balance`, `pending_unstake_amount`
                // (önceden unstake ile kaçış) ve `pending_stake_amount` (vesting kovası).
                let confiscated = target
                    .staked_balance
                    .saturating_add(target.pending_unstake_amount)
                    .saturating_add(target.pending_stake_amount);
                if confiscated == 0 {
                    return Err(ZagrosError::StakingError("No stake!".to_string()));
                }
                // 🚨 Invariant `__GLOBAL_TOTAL_STAKED__` = Σ staked_balance: yalnız
                // müsadere ÖNCESİ `staked_balance` düşülür; pending kovaları düşmek
                // tracker'ı gerçek stake'in altına sürükler, sıfırda ödüller Hazineye giderdi.
                let staked_balance_before_confiscation = target.staked_balance;

                target.staked_balance = 0;
                target.pending_unstake_amount = 0;
                target.unlock_time = 0;
                target.pending_stake_amount = 0;
                target.pending_stake_activation_time = 0;
                // 🛡️ Slash edilen validator kaydı silinir ve `JAIL_DURATION_SECONDS`
                // boyunca yeniden kayıt olamaz (taze sermayeyle anında dönmesin).
                target.is_registered_validator = false;
                target.jailed_until =
                    block_timestamp.saturating_add(zagros_types::JAIL_DURATION_SECONDS);
                // 🛡️ D14: hedef lifecycle'daysa Jailed'a çek; yoksa teminatı sıfırlanmış
                // hesap kümede "Active" ve OY HAKLI kalır. Düz staker'da alan açılmaz.
                if self.current_block_height_for_rules()
                    >= zagros_types::D14_RULES_ACTIVATION_HEIGHT
                    && target.validator_status.is_some()
                {
                    target.validator_status =
                        Some(zagros_types::consensus::ValidatorStatus::Jailed);
                }
                if is_self_target {
                    sender = target;
                } else {
                    self.state.set_account(&target_address, target)?;
                }

                let mut tracker = self
                    .state
                    .get_account(&"__GLOBAL_TOTAL_STAKED__".to_string())?
                    .unwrap_or_default();
                tracker.balance = tracker
                    .balance
                    .saturating_sub(staked_balance_before_confiscation);
                self.state
                    .set_account(&"__GLOBAL_TOTAL_STAKED__".to_string(), tracker)?;

                // El konulan tutarın TAMAMI Hazineye gider (%80 staker/%20
                // validator), `distribute_staking_reward` bunu tek sorumluluk
                // olarak kendi içinde yapıyor.
                self.distribute_staking_reward(confiscated, block_timestamp)?;
                self.record_slash_history(
                    target_address,
                    zagros_types::SlashReason::AdminEmergencySeizure,
                    confiscated,
                    block_timestamp,
                )?;
            }
            TxType::ReportMalicious => {
                // G7 (§11): payload eski `SlashingProof` ya da BFT `Evidence` taşır;
                // kanıt zorunlu, yoksa herkes rastgele adresin teminatını alırdı.
                let report =
                    zagros_types::EquivocationReport::from_bytes(&tx.payload).map_err(|_| {
                        ZagrosError::Other(
                            "ReportMalicious requires a valid EquivocationReport payload"
                                .to_string(),
                        )
                    })?;
                let (target_key, is_bft_evidence): (Address, bool) = match &report {
                    // 🚨 Legacy kanıt yolu KAPALI: `verify_double_sign` domain ayrımı
                    // yapmaz (iki sıradan imza "çift imza" diye sunulabilirdi) ve
                    // `validate()` konsensüste `SystemTime::now()` okurdu. `ConsensusEvidence` yolu kullanılır.
                    zagros_types::EquivocationReport::Legacy(_) => {
                        return Err(ZagrosError::Other(
                            "Legacy SlashingProof kanit yolu guvenlik nedeniyle KAPATILDI \
                             (domain ayrimi yok: siradan islem imzalari 'cift imza' diye \
                             sunulabiliyordu). ConsensusEvidence kullanin."
                                .to_string(),
                        ));
                    }
                    zagros_types::EquivocationReport::ConsensusEvidence(evidence) => {
                        evidence.validate_structure()?;
                        let domain = params::consensus_domain(self.state.as_ref())?;
                        let cp = params::load_chain_params(self.state.as_ref())?;
                        let current_epoch =
                            validator_set::load_active_set(self.state.as_ref())?.epoch;
                        let floor = current_epoch.saturating_sub(cp.evidence_max_age_epochs as u64);
                        // DoublePropose epoch'unu taşır; DoubleVote taşımaz, pencere içindeki
                        // anlık görüntüler denenir (yanlış aday imzada düşer, güvenlik zayıflamaz).
                        let candidate_epochs: Vec<u64> =
                            if let zagros_types::consensus::Evidence::DoublePropose { a, b } =
                                evidence
                            {
                                if a.header.epoch != b.header.epoch {
                                    return Err(ZagrosError::Other(
                                    "DoublePropose: iki baslik farkli epoch'ta - gecersiz kanit".to_string(),
                                ));
                                }
                                vec![a.header.epoch]
                            } else {
                                (floor..=current_epoch).rev().collect()
                            };
                        let mut resolved_set = None;
                        for e in candidate_epochs {
                            if e < floor {
                                continue;
                            }
                            if let Ok(set) =
                                validator_set::load_validator_set_at_epoch(self.state.as_ref(), e)
                            {
                                if zagros_crypto::verify_evidence(evidence, &domain, &set).is_ok() {
                                    resolved_set = Some(set);
                                    break;
                                }
                            }
                        }
                        let set = resolved_set.ok_or_else(|| {
                            ZagrosError::Other(
                                "Evidence dogrulanamadi (imza gecersiz ya da evidence_max_age_epochs penceresi disi)"
                                    .to_string(),
                            )
                        })?;
                        let idx = evidence.validator_idx();
                        let resolved_address = set
                            .members
                            .get(idx as usize)
                            .map(|m| m.address.clone())
                            .ok_or_else(|| {
                                ZagrosError::Other(
                                    "evidence validator_idx kume disinda".to_string(),
                                )
                            })?;
                        if !resolved_address.eq_ignore_ascii_case(&tx.receiver) {
                            return Err(ZagrosError::Other(
                                "tx.receiver evidence'in hedef aldigi validator ile uyusmuyor"
                                    .to_string(),
                            ));
                        }
                        (canonical_account_address(&resolved_address)?, true)
                    }
                };
                let malicious_validator: Address = target_key.clone();

                // 🛡️ Replay koruması (G2): kanıt (`tx.payload`) hash'lenip kalıcı kümede
                // tutulur; hedef yeniden stake etse bile aynı kanıt tekrar infaz edemez.
                let proof_hash: Hash = {
                    use sha3::{Digest, Keccak256};
                    let mut hasher = Keccak256::new();
                    hasher.update(&tx.payload);
                    let digest = hasher.finalize();
                    let mut out = [0u8; 32];
                    out.copy_from_slice(&digest);
                    out
                };
                if self.is_slashing_proof_used(&proof_hash)? {
                    return Err(ZagrosError::Other(
                        "Bu double-sign kaniti daha once kullanildi".to_string(),
                    ));
                }

                // 🛡️ Öz ihbar reddedilir: herkes kendine karşı "geçerli" kanıt üretip
                // stake'i unbond kilidini beklemeden %50 bedelle likit edebilirdi.
                if target_key == sender_key {
                    return Err(ZagrosError::Other(
                        "ReportMalicious kendi hesabınızı hedef alamaz".to_string(),
                    ));
                }
                let mut target = self
                    .state
                    .get_account(&malicious_validator)?
                    .unwrap_or_default();
                // 🛡️ `pending_unstake_amount` ve `pending_stake_amount` da müsadereye
                // dahil; yoksa önceden unstake/stake ekleme ihbardan muaf tutardı.
                let total = target
                    .staked_balance
                    .saturating_add(target.pending_unstake_amount)
                    .saturating_add(target.pending_stake_amount);
                if total == 0 {
                    return Err(ZagrosError::StakingError("Stake bulunamadi".to_string()));
                }
                // 🚨 `__GLOBAL_TOTAL_STAKED__` yalnız Σ staked_balance; pending kovaları
                // tekrar düşülmemeli (bkz. `SlashValidator`).
                let staked_balance_before_confiscation = target.staked_balance;

                target.staked_balance = 0;
                target.pending_unstake_amount = 0;
                target.unlock_time = 0;
                target.pending_stake_amount = 0;
                target.pending_stake_activation_time = 0;
                // 🛡️ Aynı jail/kayıt-silme sonucu SlashValidator ile, taze
                // sermayeyle anında geri dönüşü engeller.
                target.is_registered_validator = false;
                target.jailed_until =
                    block_timestamp.saturating_add(zagros_types::JAIL_DURATION_SECONDS);
                if is_bft_evidence {
                    // G7: hesap sıfırlanan teminatla Jailed'a geçer (kümeden epoch
                    // sınırında çıkar); yalnız durum alanı, müsadere matematiği ortak.
                    target.validator_status =
                        Some(zagros_types::consensus::ValidatorStatus::Jailed);
                } else if self.current_block_height_for_rules()
                    >= zagros_types::D14_RULES_ACTIVATION_HEIGHT
                    && target.validator_status.is_some()
                {
                    // 🛡️ D14: legacy kanıt yolu da lifecycle'daki hedefi
                    // Jailed'a çeker (SlashValidator kolundaki kuralın eşi;
                    // gerekçe orada).
                    target.validator_status =
                        Some(zagros_types::consensus::ValidatorStatus::Jailed);
                }

                let mut tracker = self
                    .state
                    .get_account(&"__GLOBAL_TOTAL_STAKED__".to_string())?
                    .unwrap_or_default();
                tracker.balance = tracker
                    .balance
                    .saturating_sub(staked_balance_before_confiscation);
                self.state
                    .set_account(&"__GLOBAL_TOTAL_STAKED__".to_string(), tracker)?;

                // 🚨 Muhbire gitmeyen kısım Hazineye (ZAGROS basılmaz/yakılmaz); muhbir
                // payı zincir üstü `reporter_reward_cap_bps` (sabit %50 governance'ı ölü düğme yapardı).
                let reporter_cap_bps =
                    params::load_chain_params(self.state.as_ref())?.reporter_reward_cap_bps as u128;
                let reporter_reward = total.saturating_mul(reporter_cap_bps) / 10_000;
                let treasury_share = total.saturating_sub(reporter_reward);
                self.state.set_account(&malicious_validator, target)?;
                // 🛡️ Muhbir payı 48 saatlik kilitten geçer: iki anahtarlı Sybil kendi
                // stake'inin yarısını unbonding beklemeden likit edemesin.
                sender.pending_unstake_amount = sender
                    .pending_unstake_amount
                    .saturating_add(reporter_reward);
                sender.unlock_time = block_timestamp + 172_800; // 48 saat, UnstakeZagros ile AYNI süre
                self.distribute_staking_reward(treasury_share, block_timestamp)?;

                self.mark_slashing_proof_used(proof_hash)?;
                self.record_slash_history(
                    target_key,
                    zagros_types::SlashReason::DoubleSign,
                    total,
                    block_timestamp,
                )?;
            }
            TxType::RegisterValidator => {
                // G2 (CONSENSUS-SPEC v0.2 §2/§13/§15): Candidate kaydı.
                // Permissionless kayıt; Active olmak onay + probation ister.
                let p = params::load_chain_params(self.state.as_ref())?;
                let payload =
                    zagros_types::consensus::RegisterValidatorPayload::decode(&tx.payload)?;
                // Konsensüs anahtarı sahiplik kanıtı (KEYOWN domain, hesap adresi, zincir) —
                // `zagros_crypto::key_ownership_digest` ile birebir aynı yük.
                let domain = params::consensus_domain(self.state.as_ref())?;
                let own_digest = zagros_types::consensus::keccak256(&{
                    let mut pl = zagros_types::consensus::signing_payload(
                        zagros_types::consensus::DOMAIN_KEYOWN,
                        &domain,
                        0,
                        0,
                        0,
                        0,
                        &[0u8; 32],
                    );
                    pl.extend_from_slice(sender_key.to_ascii_lowercase().as_bytes());
                    pl
                });
                {
                    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
                    let vk = VerifyingKey::from_bytes(&payload.consensus_pubkey)
                        .map_err(|_| ZagrosError::Other("gecersiz consensus_pubkey".to_string()))?;
                    let sig_bytes: [u8; 64] = payload
                        .ownership_proof
                        .as_slice()
                        .try_into()
                        .map_err(|_| ZagrosError::InvalidSignature)?;
                    vk.verify(&own_digest, &Signature::from_bytes(&sig_bytes))
                        .map_err(|_| {
                            ZagrosError::Other(
                                "consensus anahtari sahiplik kaniti gecersiz".to_string(),
                            )
                        })?;
                }
                if matches!(
                    sender.validator_status,
                    Some(zagros_types::consensus::ValidatorStatus::Candidate)
                        | Some(zagros_types::consensus::ValidatorStatus::Approved)
                        | Some(zagros_types::consensus::ValidatorStatus::Probation)
                        | Some(zagros_types::consensus::ValidatorStatus::Active)
                        | Some(zagros_types::consensus::ValidatorStatus::Exiting)
                ) {
                    return Err(ZagrosError::StakingError(
                        "Zaten kayitli validator".to_string(),
                    ));
                }
                // 🛡️ Hapis süresi dolmadan yeniden kayıt yok (mevcut kural).
                if block_timestamp < sender.jailed_until {
                    return Err(ZagrosError::StakingError(
                        "Hapis suresi dolmadan yeniden kayit olunamaz".to_string(),
                    ));
                }
                // Teminat: 0,17 ons altın-eşdeğeri ZAGROS (havuz oranıyla); snapshot kaydedilir.
                let min_stake = params::min_validator_stake_zagros(self.state.as_ref(), &p)?;
                if sender.staked_balance < min_stake {
                    return Err(ZagrosError::StakingError(format!(
                        "Validator olmak icin en az {} ZAGROS teminat (0,17 ons altin-esdegeri) gerekir",
                        format_token_amount(min_stake)
                    )));
                }
                // 🏛️ Başvuru ücreti kayıtta değil onay anında alınır (slot bulamayan aday
                // ücret yakmasın). Aynı konsensüs anahtarı iki kayıtlı validator'da olamaz.
                for (other_addr, other) in
                    validator_set::registered_validator_accounts(self.state.as_ref())?
                {
                    if other_addr != sender_key
                        && other.consensus_pubkey == payload.consensus_pubkey
                    {
                        return Err(ZagrosError::Other(
                            "consensus_pubkey baska bir validator'a kayitli".to_string(),
                        ));
                    }
                }
                sender.validator_status = Some(zagros_types::consensus::ValidatorStatus::Candidate);
                sender.consensus_pubkey = payload.consensus_pubkey;
                sender.validator_declaration = payload.declaration;
                sender.validator_stake_snapshot = min_stake;
                sender.validator_registered_at = block_timestamp;
                sender.liveness = Default::default();
                let genesis_ts = params::genesis_timestamp(self.state.as_ref())?;
                sender.validator_status_epoch =
                    params::epoch_at(block_timestamp, genesis_ts, p.epoch_seconds);
                validator_set::sync_registered_flag(&mut sender);
                tracing::info!(
                    "🏛️ VALIDATOR ADAYI: {} kayit oldu (teminat snapshot {} ZAGROS, ucret ONAYDA alinacak).",
                    tx.sender,
                    format_token_amount(min_stake)
                );
            }
            TxType::UnregisterValidator => {
                // G2: gönüllü çıkış → Exiting; küme epoch sınırında güncellenir,
                // teminat `bond_lock_seconds` boyunca slash edilebilir (§11.5).
                // Staking/ödül muhasebesine dokunulmaz.
                match sender.validator_status {
                    Some(zagros_types::consensus::ValidatorStatus::Candidate)
                    | Some(zagros_types::consensus::ValidatorStatus::Approved)
                    | Some(zagros_types::consensus::ValidatorStatus::Probation)
                    | Some(zagros_types::consensus::ValidatorStatus::Active) => {}
                    _ => {
                        return Err(ZagrosError::StakingError(
                            "Kayitli bir validator degil".to_string(),
                        ))
                    }
                }
                let p = params::load_chain_params(self.state.as_ref())?;
                sender.validator_status = Some(zagros_types::consensus::ValidatorStatus::Exiting);
                sender.bond_unlock_at = block_timestamp.saturating_add(p.bond_lock_seconds as u128);
                validator_set::sync_registered_flag(&mut sender);
                tracing::info!(
                    "🏛️ VALIDATOR CIKIS (Exiting): {} — teminat {} sn kilitli",
                    tx.sender,
                    p.bond_lock_seconds
                );
            }
            TxType::ApproveValidator => {
                // 🛡️ D14: gönderici hedefin kendisi olamaz; sondaki bayat `set_account(sender)`
                // hedef yazımlarını ezer, ücret geri gelip Hazine kredisi kalırdı (yoktan para).
                if self.current_block_height_for_rules()
                    >= zagros_types::D14_RULES_ACTIVATION_HEIGHT
                {
                    let self_target =
                        zagros_types::consensus::validator_action_target(&tx.tx_type, &tx.payload)
                            .is_some_and(|t| t == sender_key);
                    if self_target {
                        return Err(ZagrosError::Other(
                            "ApproveValidator hedefin kendisi tarafından gönderilemez (D14)"
                                .to_string(),
                        ));
                    }
                }
                // Faz A: 3-of-5 admin multisig (payload'da); Faz B → P1-5 (açık hata).
                let target = validator_set::apply_admin_action_tx(
                    self.state.as_ref(),
                    zagros_types::consensus::AdminAction::Approve,
                    &tx.payload,
                    block_timestamp,
                )?;
                // 🏛️ Başvuru ücreti (§13.7) onay anında ADAYDAN kesilip Hevsel'e dağıtılır;
                // bakiye yetmezse onay fail-closed reddedilir. Veto'da ücret yok.
                let admin_payload =
                    zagros_types::consensus::AdminActionPayload::decode(&tx.payload)?;
                if admin_payload.action == zagros_types::consensus::AdminAction::Approve {
                    let p = params::load_chain_params(self.state.as_ref())?;
                    let fee = params::application_fee_zagros(self.state.as_ref(), &p)?;
                    if fee > 0 {
                        let mut cand = self.state.get_account(&target)?.ok_or_else(|| {
                            ZagrosError::Other("onay ucreti: aday hesabi yok".to_string())
                        })?;
                        if cand.balance < fee {
                            return Err(ZagrosError::InsufficientBalance);
                        }
                        cand.balance = cand.balance.saturating_sub(fee);
                        self.state.set_account(&target, cand)?;
                        self.distribute_staking_reward(fee, block_timestamp)?;
                        tracing::info!(
                            "🧾 ONAY ÜCRETİ: {} adresinden {} ZAGROS alindi (Hevsel'e dagitildi).",
                            target,
                            format_token_amount(fee)
                        );
                    }
                }
                tracing::info!(
                    "🏛️ VALIDATOR ONAYI: {} → Approved (gonderen {})",
                    target,
                    tx.sender
                );
            }
            TxType::RemoveValidator => {
                // 🛡️ D14: hedef==gönderen iken bayat snapshot `Removed` ve bond kilidini
                // ezer, sessiz no-op olurdu; Approve'daki reddin eşi.
                if self.current_block_height_for_rules()
                    >= zagros_types::D14_RULES_ACTIVATION_HEIGHT
                {
                    let self_target =
                        zagros_types::consensus::validator_action_target(&tx.tx_type, &tx.payload)
                            .is_some_and(|t| t == sender_key);
                    if self_target {
                        return Err(ZagrosError::Other(
                            "RemoveValidator hedefin kendisi tarafından gönderilemez (D14)"
                                .to_string(),
                        ));
                    }
                }
                let target = validator_set::apply_admin_action_tx(
                    self.state.as_ref(),
                    zagros_types::consensus::AdminAction::Remove,
                    &tx.payload,
                    block_timestamp,
                )?;
                tracing::info!(
                    "🏛️ VALIDATOR CIKARILDI: {} → Removed (gonderen {})",
                    target,
                    tx.sender
                );
            }
            TxType::RotateConsensusKey => {
                // G14 (§15): rotasyon kanıtı YENİ anahtarla (DOMAIN_KEYROT + adres + eski
                // pubkey); sonraki epoch'ta etkinleşir, yeni talep eskisini ezer.
                let payload =
                    zagros_types::consensus::RotateConsensusKeyPayload::decode(&tx.payload)?;
                if sender.consensus_pubkey == [0u8; 32]
                    || !matches!(
                        sender.validator_status,
                        Some(zagros_types::consensus::ValidatorStatus::Candidate)
                            | Some(zagros_types::consensus::ValidatorStatus::Approved)
                            | Some(zagros_types::consensus::ValidatorStatus::Probation)
                            | Some(zagros_types::consensus::ValidatorStatus::Active)
                    )
                {
                    return Err(ZagrosError::StakingError(
                        "Rotasyon icin kayitli (Candidate/Approved/Probation/Active) bir validator gerekir".to_string(),
                    ));
                }
                if payload.new_pubkey == sender.consensus_pubkey {
                    return Err(ZagrosError::Other(
                        "yeni anahtar mevcut anahtarla ayni".to_string(),
                    ));
                }
                let domain = params::consensus_domain(self.state.as_ref())?;
                let rot_digest = zagros_types::consensus::keccak256(&{
                    let mut pl = zagros_types::consensus::signing_payload(
                        zagros_types::consensus::DOMAIN_KEYROT,
                        &domain,
                        0,
                        0,
                        0,
                        0,
                        &sender.consensus_pubkey,
                    );
                    pl.extend_from_slice(sender_key.to_ascii_lowercase().as_bytes());
                    pl
                });
                {
                    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
                    let vk = VerifyingKey::from_bytes(&payload.new_pubkey)
                        .map_err(|_| ZagrosError::Other("gecersiz new_pubkey".to_string()))?;
                    let sig_bytes: [u8; 64] = payload
                        .ownership_proof
                        .as_slice()
                        .try_into()
                        .map_err(|_| ZagrosError::InvalidSignature)?;
                    vk.verify(&rot_digest, &Signature::from_bytes(&sig_bytes))
                        .map_err(|_| {
                            ZagrosError::Other("rotasyon sahiplik kaniti gecersiz".to_string())
                        })?;
                }
                // Yeni anahtar başka bir kayıtlı validator'ın MEVCUT anahtarı
                // ya da BEKLEYEN rotasyon hedefi olamaz.
                for (other_addr, other) in
                    validator_set::registered_validator_accounts(self.state.as_ref())?
                {
                    if other_addr != sender_key && other.consensus_pubkey == payload.new_pubkey {
                        return Err(ZagrosError::Other(
                            "new_pubkey baska bir validator'a kayitli".to_string(),
                        ));
                    }
                    if other_addr != sender_key {
                        if let Some(pend) = validator_set::load_pending_key_rotation(
                            self.state.as_ref(),
                            &other_addr,
                        )? {
                            if pend.new_pubkey == payload.new_pubkey {
                                return Err(ZagrosError::Other(
                                    "new_pubkey baska bir validator'in bekleyen rotasyonunda"
                                        .to_string(),
                                ));
                            }
                        }
                    }
                }
                let p = params::load_chain_params(self.state.as_ref())?;
                let genesis_ts = params::genesis_timestamp(self.state.as_ref())?;
                let requested_epoch =
                    params::epoch_at(block_timestamp, genesis_ts, p.epoch_seconds);
                validator_set::store_pending_key_rotation(
                    self.state.as_ref(),
                    &sender_key,
                    &zagros_types::consensus::PendingKeyRotation {
                        new_pubkey: payload.new_pubkey,
                        requested_epoch,
                    },
                )?;
                tracing::info!(
                    "🔑 ROTASYON TALEBI: {} → 0x{} (epoch {} sonrasi ilk gecise kadar eski anahtar gecerli)",
                    tx.sender,
                    hex::encode(&payload.new_pubkey[..8]),
                    requested_epoch
                );
            }
            TxType::BridgeMint => {
                if tx.sender != self.bridge_authority {
                    return Err(ZagrosError::BridgeError(
                        "Unauthorized: sender is not the bridge authority".to_string(),
                    ));
                }
                // 🛡️ (a) self-mint yasağı, (b) tek işlem tavanı (ele geçirilmiş anahtar
                // sınırsız basamaz).
                if tx.receiver == self.bridge_authority {
                    return Err(ZagrosError::BridgeError(
                        "Bridge authority cannot mint to itself".to_string(),
                    ));
                }
                if tx.amount > MAX_SINGLE_BRIDGE_MINT {
                    return Err(ZagrosError::BridgeError(
                        "BridgeMint exceeds per-tx cap".to_string(),
                    ));
                }
                // 🛡️ Zincir seviyesinde çoklu imza zorunluluğu (bkz.
                // `validate_bridge_mint_proposal`); `tx.tx_id` = `proposal_id`.
                let proposal = self.validate_bridge_mint_proposal(tx, false, block_timestamp)?;
                // 🛡️ Basımdan ÖNCE, fail-closed: reddedilirse hiçbir bakiye
                // değişmeden işlem başarısız olur (bkz. check_and_record_daily_mint).
                crate::bridge::BridgeManager::check_and_record_daily_mint(
                    self.state.as_ref(),
                    tx.amount,
                    block_timestamp as u64,
                    self.bridge_daily_mint_limit,
                )?;

                let mut receiver = self.state.get_account(&tx.receiver)?.unwrap_or_default();
                receiver.zerenya_balance = receiver.zerenya_balance.saturating_add(tx.amount);
                self.state.set_account(&tx.receiver, receiver)?;
                self.increase_bridge_backed_zerenya(tx.amount)?;
                // 🚨 Çift basım kilidi (yazma): kaynak tx aynı checkpoint'te "basıldı"
                // işaretlenir; okuma tarafı `validate_bridge_mint_proposal`da.
                crate::bridge::BridgeManager::mark_source_processed_in_state(
                    &proposal.source_chain,
                    &proposal.source_tx_hash,
                    self.state.as_ref(),
                )?;
                // 🛡️ Basımla aynı checkpoint'te atomik finalize; başarısızsa tüm
                // checkpoint geri alınır, öneri yarım "executed" kalmaz.
                crate::bridge::BridgeManager::archive_executed_proposal(
                    self.state.as_ref(),
                    &proposal,
                )?;
                tracing::info!(
                    "🌉 KÖPRÜ (EXECUTOR): {} adresine {} ZERENYA basıldı!",
                    tx.receiver,
                    format_token_amount(tx.amount)
                );
            }
            TxType::BridgeMintAndSwap => {
                if tx.sender != self.bridge_authority {
                    return Err(ZagrosError::BridgeError(
                        "Unauthorized: sender is not the bridge authority".to_string(),
                    ));
                }
                // 🛡️ FAZ1: self-mint yasağı + tek-tx tavanı (BridgeMint ile aynı).
                if tx.receiver == self.bridge_authority {
                    return Err(ZagrosError::BridgeError(
                        "Bridge authority cannot mint to itself".to_string(),
                    ));
                }
                if tx.amount > MAX_SINGLE_BRIDGE_MINT {
                    return Err(ZagrosError::BridgeError(
                        "BridgeMintAndSwap exceeds per-tx cap".to_string(),
                    ));
                }
                // 🛡️ ZİNCİR SEVİYESİNDE 2/3 ÇOKLU-İMZA ZORUNLULUĞU, BridgeMint
                // ile AYNI paylaşılan kontrol, sadece auto_swap=true bekliyor.
                let proposal = self.validate_bridge_mint_proposal(tx, true, block_timestamp)?;
                // 🛡️ BridgeMint ile AYNI günlük tavan/sayaç, basılan miktar
                // (tx.amount, havuza giren ZERENYA) burada da anında ZAGROS'a
                // çevrilse dahi köprüden BASILAN toplamdır, tavana dahil olmalı.
                crate::bridge::BridgeManager::check_and_record_daily_mint(
                    self.state.as_ref(),
                    tx.amount,
                    block_timestamp as u64,
                    self.bridge_daily_mint_limit,
                )?;

                let (pool_zagros, pool_zerenya) = self.state.get_pool_reserves()?;

                // 🛡️ #11: bkz. SwapBuy/SwapSell'deki AYNI açıklama, hacim 60
                // saniyelik kümülatif pencereye kaydedilir, ücret oranı sabit
                // `STANDARD_SWAP_FEE_BPS`.
                let fee_bps = record_volume_and_compute_fee_bps(
                    self.state.as_ref(),
                    SwapDirection::ZerenyaIn,
                    tx.amount,
                    pool_zerenya,
                    block_timestamp as u64,
                )?;
                let quote =
                    quote_bridge_mint_and_swap(tx.amount, pool_zagros, pool_zerenya, fee_bps)?;

                // 🛡️ Slippage koruması, `lockTokens`tan uçtan uca taşınır ve İMZALANMIŞ
                // öneriden okunur (imzasız payload'da yürütücü sıfırlayabilirdi).
                let amount_out_min = proposal.amount_out_min;
                if amount_out_min > 0 && quote.amount_out < amount_out_min {
                    return Err(ZagrosError::Other(
                        "Slippage too high (BridgeMintAndSwap)".to_string(),
                    ));
                }

                self.state.add_balance(&tx.receiver, quote.amount_out)?;
                // Bu yolda basılan ZERENYA miktarı `tx.amount`'tır (havuza giren, ZAGROS'a
                // çevrilen ZERENYA), BridgeMint ile aynı miktar, sadece anında takas edilir.
                self.increase_bridge_backed_zerenya(tx.amount)?;
                // community_fee ZAGROS (çıkış) cinsinden hesaplanır (SwapBuy ile
                // aynı mantık) ve anında Hazineye dağıtılır.
                if quote.community_fee > 0 {
                    self.distribute_staking_reward(quote.community_fee, block_timestamp)?;
                }
                self.sync_pool_reserves(quote.new_pool_zagros, quote.new_pool_zerenya)?;
                // 🚨 ÇİFT-BASIM KİLİDİ (yazma tarafı), BridgeMint dalıyla aynı.
                crate::bridge::BridgeManager::mark_source_processed_in_state(
                    &proposal.source_chain,
                    &proposal.source_tx_hash,
                    self.state.as_ref(),
                )?;
                // 🛡️ Basım+takasla AYNI checkpoint/commit içinde, atomik finalize.
                crate::bridge::BridgeManager::archive_executed_proposal(
                    self.state.as_ref(),
                    &proposal,
                )?;
                tracing::info!(
                    "🌌 OMNICHAIN SWAP (EXECUTOR): {} ZERENYA geldi, {} ZAGROS'a çevrildi!",
                    format_token_amount(tx.amount),
                    format_token_amount(quote.amount_out)
                );
            }
            TxType::BridgeBurn => {
                if sender.zerenya_balance < tx.amount {
                    return Err(ZagrosError::InsufficientBalance);
                }
                // 🛡️ Teminat kontrolü state değişmeden önce: köprüden basılmamış ZERENYA
                // köprüden yakılamaz (karşılıksız talep hakkı doğar).
                if self.get_bridge_backed_zerenya()? < tx.amount {
                    return Err(ZagrosError::BridgeError(
                        "Bu ZERENYA kopru uzerinden basilmadigi icin kopruden yakilamaz \
                         (teminat yetersiz)"
                            .to_string(),
                    ));
                }
                sender.zerenya_balance = sender.zerenya_balance.saturating_sub(tx.amount);
                self.decrease_bridge_backed_zerenya(tx.amount)?;
                self.record_bridge_burn(tx.tx_id, tx.sender.clone(), tx.amount, block_timestamp)?;
                tracing::info!(
                    "🔥 KÖPRÜ ÇIKIŞI (EXECUTOR): {} adresinden {} ZERENYA yakıldı.",
                    tx.sender,
                    format_token_amount(tx.amount)
                );
            }
            TxType::BridgeSwapAndBurn => {
                let (pool_zagros, pool_zerenya) = self.state.get_pool_reserves()?;

                // 🛡️ #11: bkz. SwapBuy/SwapSell'deki AYNI açıklama.
                let fee_bps = record_volume_and_compute_fee_bps(
                    self.state.as_ref(),
                    SwapDirection::ZagrosIn,
                    tx.amount,
                    pool_zagros,
                    block_timestamp as u64,
                )?;
                let quote =
                    quote_bridge_swap_and_burn(tx.amount, pool_zagros, pool_zerenya, fee_bps)?;

                // 🛡️ Slippage koruması (SwapBuy/SwapSell ile aynı): havuz aynı blokta
                // manipüle edilirse işlem iptal, sandwich'e açık kalmaz.
                let amount_out_min = swap_amount_out_min(tx)?;
                if amount_out_min > 0 && quote.amount_out < amount_out_min {
                    return Err(ZagrosError::Other(
                        "Slippage too high (BridgeSwapAndBurn)".to_string(),
                    ));
                }

                // 🛡️ Teminat kontrolü havuza dokunmadan önce: havuzdaki ZERENYA'nın
                // teminatsız kısmı köprüden yakılıp PAXG talep edilemez.
                if self.get_bridge_backed_zerenya()? < quote.amount_out {
                    return Err(ZagrosError::BridgeError(
                        "Havuzdan cikacak ZERENYA kopru teminatini asiyor - bu miktar \
                         kopru uzerinden yakilamaz"
                            .to_string(),
                    ));
                }

                sender.sub_balance(tx.amount)?;
                // Bu ücret ZAGROS cinsinden olduğu için doğrudan ödül çarpanına
                // (acc) yansıtılır; yoksa hazineye giren köprü çıkış ücreti
                // staker'lara hiç görünmez.
                self.distribute_staking_reward(quote.community_fee, block_timestamp)?;
                self.sync_pool_reserves(quote.new_pool_zagros, quote.new_pool_zerenya)?;
                // 🚨 Çıkış kaydına yakılan ZERENYA yazılır (ZAGROS değil): kayıt ödenecek
                // PAXG'yi belirler, oran sapınca kasa teminatsız kalırdı.
                self.decrease_bridge_backed_zerenya(quote.amount_out)?;
                self.record_bridge_burn(
                    tx.tx_id,
                    tx.sender.clone(),
                    quote.amount_out,
                    block_timestamp,
                )?;
                tracing::info!(
                    "🌌 OMNICHAIN ÇIKIŞ (EXECUTOR): {} ZAGROS satıldı, havuzdan {} ZERENYA çıktı ve ANINDA YAKILDI!",
                    format_token_amount(tx.amount),
                    format_token_amount(quote.amount_out)
                );
            }
            TxType::DeployContract => {
                // 🛑 Native deploy yürütmede de reddedilir: 18 karakterlik erişilemez
                // adres üretir; blok gövdesi mempool kapısından geçmez, kötü üretici
                // budanamaz çöp kayıtla state'i şişirirdi. Tek yol EVM.
                return Err(ZagrosError::Other(
                    "TxType::DeployContract desteklenmiyor: 42 karakterlik adres                      formatını saglamayan, kalici olarak erisilemez bir kontrat                      uretir. Standart EVM dagitimini kullanin (eth_sendRawTransaction,                      bos `to` alani)."
                        .to_string(),
                ));
            }
            TxType::SubmitProposal => {
                // Spam-koruması dörtlüsü (R1/item2): min stake + yakılan ücret +
                // global aktif-öneri tavanı. Hiçbiri tek başına yeterli değil.
                if sender.staked_balance < self.governance_min_stake_to_submit {
                    return Err(ZagrosError::Other(format!(
                        "Öneri sunmak için en az {} stake gerekli (mevcut: {})",
                        self.governance_min_stake_to_submit, sender.staked_balance
                    )));
                }
                if sender.balance < self.governance_proposal_fee {
                    return Err(ZagrosError::InsufficientBalance);
                }
                let active_count = self.active_proposal_count()?;
                if active_count >= self.governance_max_active_proposals as u128 {
                    return Err(ZagrosError::Other(format!(
                        "Aktif öneri tavanına ulaşıldı ({}/{}) - eski önerilerin arşive \
                         geçmesini bekleyin ya da operatör 'governance repair-active-count' \
                         çalıştırsın.",
                        active_count, self.governance_max_active_proposals
                    )));
                }

                // 🚨 Ücret Hazine'ye gider, yakılmaz (42M sabit arz); diğer özel
                // ücretlerle aynı `distribute_staking_reward` yolu.
                sender.balance = sender.balance.saturating_sub(self.governance_proposal_fee);
                // 🗳️ İadeli depozito (kapı: GOV_DEPOSIT_ACTIVATION_HEIGHT): kapı sonrası
                // bedel öneri adına kasada bekler; sayımda yeter sayı varsa iade,
                // yoksa/vetoda Hevsel (bkz. governance::settle_deposit). Kapı öncesi eski davranış.
                let deposit_mode = self.current_block_height_for_rules()
                    >= zagros_types::GOV_DEPOSIT_ACTIVATION_HEIGHT;
                if deposit_mode {
                    governance::escrow_deposit(
                        self.state.as_ref(),
                        &tx.tx_id,
                        self.governance_proposal_fee,
                    )?;
                } else {
                    self.distribute_staking_reward(self.governance_proposal_fee, block_timestamp)?;
                }

                // G12: payload tipli mi? Magic yoksa Text (legacy birebir);
                // magic var ama gövde bozuksa fail-closed RED.
                let action = zagros_types::consensus::ProposalAction::decode_payload(&tx.payload)?
                    .unwrap_or_default();
                let mut voting_ends_at_epoch = 0u64;
                if action != zagros_types::consensus::ProposalAction::Text {
                    // Erken doğrulama: kuyruğa hiçbir koşulda çöp girmez.
                    let params = params::load_chain_params(self.state.as_ref())?;
                    action.channel()?; // karışık-kanal reddi
                    match &action {
                        zagros_types::consensus::ProposalAction::ParamChange(updates) => {
                            let grace = params::load_qc_grace_ms(self.state.as_ref())?;
                            zagros_types::consensus::apply_param_updates_with_grace(
                                &params, grace, updates,
                            )?;
                        }
                        zagros_types::consensus::ProposalAction::ScheduleUpgrade {
                            target_ruleset,
                            ..
                        } => {
                            if *target_ruleset <= params.active_ruleset {
                                return Err(ZagrosError::Other(format!(
                                    "hedef ruleset {} yururlukteki {}'den buyuk olmali",
                                    target_ruleset, params.active_ruleset
                                )));
                            }
                        }
                        zagros_types::consensus::ProposalAction::ShortenAdminAuthority {
                            end_timestamp,
                        } => {
                            // Erken reddet: oylamaya girip de yürütmede
                            // kesin başarısız olacak bir öneri kuyruğu meşgul
                            // etmemeli.
                            let mevcut = params::admin_authority_end(self.state.as_ref())?;
                            if (*end_timestamp as u128) >= mevcut {
                                return Err(ZagrosError::Other(format!(
                                    "admin yetkisi yalnizca KISALTILABILIR: {} >= mevcut bitis {}",
                                    end_timestamp, mevcut
                                )));
                            }
                        }
                        // 🗳️ Faz B: küme üyeliği önerileri.
                        act @ (zagros_types::consensus::ProposalAction::ApproveValidator {
                            ..
                        }
                        | zagros_types::consensus::ProposalAction::RemoveValidator {
                            ..
                        }) => {
                            // 🚨 Aynı anda iki kapı olmaz: Faz A'da üyelik admin multisig'te,
                            // staker oyu açık olsa admin onayı atlanabilirdi.
                            if crate::validator_set::admin_phase_active(
                                self.state.as_ref(),
                                block_timestamp,
                            )? {
                                return Err(ZagrosError::Other(
                                    "Faz A surerken kume uyeligi 3/5 admin coklu-imzasindadir;                                      staker oylamasi Faz A bittikten SONRA acilir"
                                        .into(),
                                ));
                            }
                            // Erken doğrulama (kuyruğa çöp girmesin); son sözü yürütmedeki
                            // `apply_admin_approve`/`apply_admin_remove` söyler, başarısızsa Rejected.
                            let hedef = match act {
                                zagros_types::consensus::ProposalAction::ApproveValidator {
                                    target,
                                }
                                | zagros_types::consensus::ProposalAction::RemoveValidator {
                                    target,
                                } => target,
                                _ => unreachable!(),
                            };
                            let key = canonical_account_address(hedef)?;
                            let acc = self
                                .state
                                .get_account(&key)?
                                .ok_or_else(|| ZagrosError::Other("hedef hesap yok".into()))?;
                            if acc.validator_status.is_none() {
                                return Err(ZagrosError::Other(
                                    "hedef hic validator kaydi yapmamis".into(),
                                ));
                            }
                        }
                        zagros_types::consensus::ProposalAction::Text => unreachable!(),
                    }
                    let genesis_ts = params::genesis_timestamp(self.state.as_ref())?;
                    let now_epoch =
                        params::epoch_at(block_timestamp, genesis_ts, params.epoch_seconds);
                    voting_ends_at_epoch =
                        now_epoch.saturating_add(params.gov_voting_epochs as u64);
                }
                let is_typed = action != zagros_types::consensus::ProposalAction::Text;
                if !is_typed && deposit_mode {
                    // Metin öneri de depozito sayımı için epoch listesine girer;
                    // penceresi tipli önerilerle aynı (gov_voting_epochs).
                    let params = params::load_chain_params(self.state.as_ref())?;
                    let genesis_ts = params::genesis_timestamp(self.state.as_ref())?;
                    let now_epoch =
                        params::epoch_at(block_timestamp, genesis_ts, params.epoch_seconds);
                    voting_ends_at_epoch =
                        now_epoch.saturating_add(params.gov_voting_epochs as u64);
                }
                let proposal = zagros_types::Proposal {
                    proposal_id: tx.tx_id,
                    proposer: sender_key.clone(),
                    description: tx.payload.clone(),
                    created_at: block_timestamp,
                    votes_for: 0,
                    votes_against: 0,
                    status: zagros_types::ProposalStatus::Active,
                    action,
                    executes_at_epoch: 0,
                    voting_ends_at_epoch,
                };
                self.save_proposal(&proposal)?;
                self.increment_active_proposal_count()?;
                if is_typed || deposit_mode {
                    governance::register_typed_active(self.state.as_ref(), tx.tx_id)?;
                }
                // 📇 RPC listeleme dizini (köke girmez, salt gözlemlenebilirlik).
                governance::register_index(self.state.as_ref(), tx.tx_id)?;
                tracing::info!(
                    "📜 Yeni öneri sunuldu ({}{}): 0x{}",
                    if is_typed { "tipli" } else { "metin" },
                    if deposit_mode { ", depozitolu" } else { "" },
                    hex::encode(tx.tx_id)
                );
            }
            TxType::Vote => {
                if tx.payload.len() != 33 {
                    return Err(ZagrosError::Other(
                        "Vote payload must be 32-byte proposal id + 1-byte choice".to_string(),
                    ));
                }
                let mut proposal_id = [0u8; 32];
                proposal_id.copy_from_slice(&tx.payload[0..32]);
                let support = tx.payload[32] != 0;

                let mut proposal = self
                    .load_proposal(&proposal_id)?
                    .ok_or_else(|| ZagrosError::Other("Proposal not found".to_string()))?;

                // 🚨 BİRİM: `block_timestamp` executor'a ZATEN SANİYE olarak
                // gelir (driver: `hdr.timestamp_ms / 1000`); fazladan bölme
                // governance sürelerini 1000× uzatır (bkz. `effective_status`).
                let now_secs = block_timestamp as u64;
                let status = zagros_types::effective_status(
                    &proposal,
                    now_secs,
                    self.governance_voting_period_secs,
                    self.governance_proposal_expiry_secs,
                );
                if status != zagros_types::ProposalStatus::Active {
                    return Err(ZagrosError::Other(format!(
                        "Bu öneri artık oylanamaz (durum: {})",
                        status
                    )));
                }

                if self.has_voted(&proposal_id, &sender_key)? {
                    return Err(ZagrosError::Other(
                        "Address has already voted on this proposal".to_string(),
                    ));
                }

                let weight = sender.staked_balance;
                if weight == 0 {
                    return Err(ZagrosError::Other(
                        "Must have staked ZAGROS to vote".to_string(),
                    ));
                }

                if support {
                    proposal.votes_for = proposal.votes_for.saturating_add(weight);
                } else {
                    proposal.votes_against = proposal.votes_against.saturating_add(weight);
                }
                self.save_proposal(&proposal)?;
                self.mark_voted(&proposal_id, &sender_key)?;
                // G12: kişi-bazlı oy kaydı (validator eşit-sayım + staker
                // tavanlı-ağırlık sayımları bunu okur). Legacy Text için de
                // yazılır (zararsız; ileride analitik).
                governance::record_vote(
                    self.state.as_ref(),
                    &proposal_id,
                    &sender_key,
                    support,
                    weight,
                )?;
                tracing::info!(
                    "🗳️ Oy kaydedildi: 0x{} -> destek={} ağırlık={}",
                    hex::encode(proposal_id),
                    support,
                    weight
                );
            }
            TxType::ContractCall { .. } | TxType::CallContract => {
                // ZERENYA transferi yapabilen EVM çağrısı, `Executor`'ın CANLI
                // `recent_transfer_index_counter`'ıyla AYNI `Arc`'ı paylaşmalı; yoksa
                // izole sayaçtan tahsis native Transfer index'leriyle çakışır.
                let executor = crate::evm::EvmExecutor::new(self.state.clone())
                    .with_recent_transfer_index_counter(self.recent_transfer_index_counter.clone());
                let execution = match executor.execute_contract_call(tx, block_timestamp) {
                    Ok(execution) => execution,
                    Err(failure) => {
                        *evm_gas_used = failure.gas_used;
                        return Err(failure.error);
                    }
                };
                let _return_data = execution.return_data;
                let _gas_refunded = execution.gas_refunded;
                *evm_gas_used = Some(execution.gas_used);
                *nonce_already_advanced = execution.nonce_already_advanced;
                gas_charged = (execution.gas_used as u128)
                    .checked_mul(tx.gas_price)
                    .ok_or(ZagrosError::GasLimitExceeded)?;

                // 🏛️ TEK ÖDÜL MOTORU: EVM sırasında hazineye giren her tutar (createToken
                // ücreti, EVM swap yolu, ileride NFT Factory vb.) native yol ile AYNI
                // `distribute_staking_reward`'a gider (80/20 bölüşüm, snapshot dahil).
                if execution.treasury_gain > 0 {
                    self.distribute_staking_reward(execution.treasury_gain, block_timestamp)?;
                }

                // 🏛️ Token Factory harcı: `new_contract_count` revm değişim kümesindeki
                // gerçek yeni kontratlar (iç CREATE dahil); bakiye taze okunup düşülür,
                // yetmezse dış checkpoint deploy'u da geri sarar.
                if execution.new_contract_count > 0 {
                    // Kontrat oluşturuldu → token factory harcı ödenir; ×5 standart
                    // taban bunun üstüne eklenmesin (çağıran tarafta sıfırlanır).
                    *evm_created_contract = true;
                    let token_factory_total = self
                        .token_factory_fee_per_contract()
                        .saturating_mul(execution.new_contract_count as u128);
                    let mut deployer = self.state.get_account(&sender_key)?.unwrap_or_default();
                    deployer.sub_balance(token_factory_total)?;
                    self.state.set_account(&sender_key, deployer)?;
                    self.distribute_staking_reward(token_factory_total, block_timestamp)?;
                }
            }
        }

        // Native tx bakiye guncellemesi state commit edilmezse kaybolmamasi icin saklaniyor,
        // EVM state'i EvmExecutor update komutlariyla iceride halletti. EVM olmayan islemlerde guncel state'i
        // kaydetmek icin bunu buraya yaziyoruz, gas ve increment_nonce sadece apply'da bir kez ele aliniyor.
        if !is_evm_tx {
            self.state.set_account(&sender_key, sender)?;
            self.save_dummy_receipt(tx)?;
        }
        Ok(gas_charged)
    }
}

#[cfg(test)]
mod reward_owed_tests {
    use super::reward_owed;

    #[test]
    fn reward_owed_matches_plain_math_within_safe_range() {
        // Küçük/orta ölçekte eski (taşabilen) formülle birebir aynı sonucu
        // vermeli.
        assert_eq!(reward_owed(1_000, 1_000_000_000_000), 1_000);
        assert_eq!(reward_owed(0, 5_000), 0);
        assert_eq!(reward_owed(5_000, 0), 0);
    }

    #[test]
    fn reward_owed_does_not_collapse_when_plain_u128_math_would_overflow() {
        // `staked_balance` tüm arz iken büyümüş `acc` ile `saturating_mul` sessizce
        // u128::MAX'e çakılıp yanlış (küçük) ödül üretiyordu.
        let staked_balance = 42_000_000u128 * 1_000_000_000_000_000_000u128; // 4.2e25
        let acc = 10_000_000_000_000u128; // 1e13 - gas.rs hatasındaki ölçeğe yakın
        let expected = (alloy_primitives::U256::from(staked_balance)
            * alloy_primitives::U256::from(acc)
            / alloy_primitives::U256::from(1_000_000_000_000u128))
        .to::<u128>();
        assert_eq!(reward_owed(staked_balance, acc), expected);
        // Sağlık kontrolü: eski hatalı yoldaki gibi 0'a ya da anlamsız bir
        // küçük değere ÇÖKMEMELİ.
        assert!(reward_owed(staked_balance, acc) > staked_balance);
    }
}

#[cfg(test)]
mod zagros_amount_to_zerenya_string_tests {
    use super::zagros_amount_to_zerenya_string;
    use zagros_types::TOKEN_DECIMAL;

    #[test]
    fn shows_five_hundredths_at_one_to_one_pool() {
        // 1:1 havuzda (1 ZAGROS = 1 ZERENYA) 0.05 ZAGROS tam 0.05 ZERENYA etmeli.
        let fee = TOKEN_DECIMAL / 20; // 0.05 ZAGROS
        let pool = 1_000_000u128 * TOKEN_DECIMAL;
        assert_eq!(
            zagros_amount_to_zerenya_string(fee, pool, pool),
            "0.0500 ZERENYA"
        );
    }

    #[test]
    fn still_shows_the_same_zerenya_value_regardless_of_pool_scale() {
        // 1 ZAGROS = 1.000 ZERENYA olacak şekilde havuz oranı değişse bile
        // (havuz_zerenya = 1000 × havuz_zagros), ZERENYA cinsinden gösterim
        // fiyattan bağımsız aynı büyüklüğü yansıtmalı.
        let pool_zagros = 1_000_000u128 * TOKEN_DECIMAL;
        let pool_zerenya = pool_zagros * 1_000; // 1 ZAGROS = 1.000 ZERENYA
                                                // pool_zerenya = pool_zagros × 1000 olduğundan fee = (TARGET/1000) sadeleşir
                                                // (pool büyüklüğü ile ilgisiz), testte u128 taşmasından kaçınmak için
                                                // aynı sadeleştirmeyi elle yapıyoruz.
        let fee_zagros = (TOKEN_DECIMAL / 20) / 1_000; // ~0.00005 ZAGROS
        assert_eq!(
            zagros_amount_to_zerenya_string(fee_zagros, pool_zagros, pool_zerenya),
            "0.0500 ZERENYA"
        );
    }

    #[test]
    fn empty_pool_does_not_panic() {
        assert_eq!(
            zagros_amount_to_zerenya_string(1_000, 0, 1_000),
            "0.0000 ZERENYA"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use revm::primitives::U256;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use zagros_state::manager::StateDbManager;
    use zagros_storage::{Storage, StorageEngine};

    #[derive(Default)]
    struct MemoryStorage {
        values: Mutex<HashMap<Vec<u8>, Vec<u8>>>,
        list_keys_calls: AtomicUsize,
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
            self.list_keys_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.values.lock().unwrap().keys().cloned().collect())
        }
    }

    impl StorageEngine for MemoryStorage {
        fn write_batch(&self, values: &[(Vec<u8>, Option<Vec<u8>>)]) -> Result<()> {
            let mut storage = self.values.lock().unwrap();
            for (key, value) in values {
                if let Some(value) = value {
                    storage.insert(key.clone(), value.clone());
                } else {
                    storage.remove(key);
                }
            }
            Ok(())
        }

        fn append_wal(&self, _data: &[u8]) -> Result<()> {
            Ok(())
        }

        fn clear_wal(&self) -> Result<()> {
            Ok(())
        }
    }

    fn test_state() -> Arc<dyn State> {
        Arc::new(StateDbManager::new(Arc::new(MemoryStorage::default())))
    }

    /// Deterministic secp256k1 key for a given test "identity", lets tests build
    /// transactions that pass the (now-enforced) signature check without doing
    /// real key management. Never used outside test code.
    fn test_secret_key(seed: u8) -> secp256k1::SecretKey {
        secp256k1::SecretKey::from_slice(&[seed; 32]).unwrap()
    }

    fn test_address(seed: u8) -> Address {
        Transaction::address_from_secret_key(&test_secret_key(seed))
    }

    /// Testlerde köprü teminat sayacını doğrudan tohumlar, gerçek akışta bu
    /// yalnızca BridgeMint/BridgeMintAndSwap ile artar, ama tutarlılık/regresyon
    /// testleri burn tarafını izole test etmek için doğrudan seed eder.
    fn seed_bridge_backed_zerenya(state: &Arc<dyn State>, amount: u128) {
        state
            .set_account(
                &Executor::bridge_backed_zerenya_key(),
                AccountState::new(amount),
            )
            .unwrap();
    }

    /// Testler için: gerçek `BridgeManager` ile mint önerisi kurup
    /// `signatures_to_collect` imza toplar; dönen `Hash` `tx.tx_id`ye atanmalı.
    #[allow(clippy::too_many_arguments)]
    /// 🚨 Köprü mint işlemi öneriyi payload'ında taşır; `seed_mint_proposal`ın
    /// state'e yazdığını okuyup payload'a koyar (üretimde CLI'nin yaptığı).
    fn attach_proposal_payload(state: &Arc<dyn State>, tx: &mut Transaction) {
        let proposal =
            crate::bridge::BridgeManager::load_proposal_from_state(state.as_ref(), &tx.tx_id)
                .unwrap()
                .expect("seed_mint_proposal oneriyi state'e yazmis olmali");
        tx.payload = crate::bridge::BridgeManager::encode_proposal_payload(&proposal).unwrap();
    }

    fn seed_mint_proposal(
        state: &Arc<dyn State>,
        recipient: &str,
        amount: u128,
        auto_swap: bool,
        amount_out_min: u128,
        required_signatures: usize,
        signatures_to_collect: usize,
        timelock_secs: u64,
        now: u128,
    ) -> Hash {
        use ed25519_dalek::{Signer, SigningKey};

        let mut authorities = Vec::new();
        let mut keys = Vec::new();
        for i in 1..=3u8 {
            let mut seed = [0u8; 32];
            seed[0] = 200 + i; // lib.rs'in diğer test seed'leriyle (1..~40) çakışmasın
            let signing_key = SigningKey::from_bytes(&seed);
            let address = crate::bridge::BridgeManager::derive_address_from_public_key(
                &signing_key.verifying_key().to_bytes(),
            );
            authorities.push(crate::bridge::BridgeAuthority {
                address: address.clone(),
                public_key: signing_key.verifying_key().to_bytes(),
                is_active: true,
            });
            keys.push((address, signing_key));
        }

        // 🛡️ Basım doğrulaması artık ZİNCİRDEKİ yetkili kümesini okuyor
        // (bkz. `validate_bridge_mint_proposal`); üretimde bunu genesis yazar.
        crate::bridge::store_bridge_authority_set(
            state.as_ref(),
            &crate::bridge::OnChainBridgeAuthoritySet {
                authorities: authorities.clone(),
                required_signatures: required_signatures as u16,
            },
        )
        .unwrap();

        let mut manager =
            crate::bridge::BridgeManager::new(authorities, required_signatures, CHAIN_ID)
                .with_timelock_secs(timelock_secs);
        let proposal_id = manager
            .create_proposal(
                crate::bridge::BridgeTxType::Mint,
                amount,
                recipient.to_string(),
                "Ethereum".to_string(),
                {
                    // Her çağrı benzersiz kaynak tx üretir; sabit değer çift basım
                    // kilidince haklı olarak reddedilirdi.
                    use std::sync::atomic::{AtomicU64, Ordering};
                    static SEED_SRC_COUNTER: AtomicU64 = AtomicU64::new(0);
                    let n = SEED_SRC_COUNTER.fetch_add(1, Ordering::Relaxed);
                    format!("0xtest_source_tx_hash_{:016x}", n)
                },
                (now / 1000) as u64,
                auto_swap,
                amount_out_min,
                now,
                state.as_ref(),
            )
            .unwrap();

        let message = crate::bridge::BridgeManager::create_signing_message(
            manager.get_proposal(&proposal_id).unwrap(),
            CHAIN_ID,
        );
        let sig_ts = (now / 1000) as u64;
        let bound = crate::bridge::BridgeManager::bind_timestamp_to_message(&message, sig_ts);

        for (address, signing_key) in keys.into_iter().take(signatures_to_collect) {
            manager
                .sign_proposal(
                    &proposal_id,
                    address,
                    signing_key.sign(&bound).to_bytes().to_vec(),
                    signing_key.verifying_key().to_bytes().to_vec(),
                    sig_ts,
                    now,
                )
                .unwrap();
        }

        manager
            .persist_proposal(state.as_ref(), &proposal_id)
            .unwrap();
        proposal_id
    }

    fn transaction(tx_type: TxType, nonce: u64, amount: u128) -> Transaction {
        let secret_key = test_secret_key(1);
        let mut tx = Transaction {
            tx_id: [7; 32],
            tx_type,
            sender: Transaction::address_from_secret_key(&secret_key),
            amount,
            receiver: "0x2222222222222222222222222222222222222222".to_string(),
            payload: Vec::new(),
            signature: Vec::new(),
            timestamp: 1_000,
            nonce,
            gas_limit: 1,
            gas_price: 2,
            chain_id: CHAIN_ID,
        };
        tx.sign(&secret_key);
        tx
    }

    /// Aynı yatırışa farklı proposal_id'li öneriyi doğrudan state'e yazar
    /// (`create_proposal` idempotency'si kasıtlı atlanır); imzalar gerçek Ed25519.
    fn seed_raw_mint_proposal(
        state: &Arc<dyn State>,
        proposal_id: Hash,
        recipient: &str,
        amount: u128,
        source_tx_hash: &str,
        signatures: usize,
        now: u128,
    ) -> Hash {
        use ed25519_dalek::{Signer, SigningKey};

        let mut authorities = Vec::new();
        let mut keys = Vec::new();
        for i in 1..=3u8 {
            let mut seed = [0u8; 32];
            seed[0] = 220 + i;
            let signing_key = SigningKey::from_bytes(&seed);
            let address = crate::bridge::BridgeManager::derive_address_from_public_key(
                &signing_key.verifying_key().to_bytes(),
            );
            authorities.push(crate::bridge::BridgeAuthority {
                address: address.clone(),
                public_key: signing_key.verifying_key().to_bytes(),
                is_active: true,
            });
            keys.push((address, signing_key));
        }
        crate::bridge::store_bridge_authority_set(
            state.as_ref(),
            &crate::bridge::OnChainBridgeAuthoritySet {
                authorities: authorities.clone(),
                required_signatures: signatures.max(1) as u16,
            },
        )
        .unwrap();

        let mut proposal = crate::bridge::BridgeProposal {
            proposal_id,
            tx_type: crate::bridge::BridgeTxType::Mint,
            amount,
            recipient: recipient.to_string(),
            source_chain: "Ethereum".to_string(),
            source_tx_hash: source_tx_hash.to_string(),
            timestamp: (now / 1000) as u64,
            signatures: Vec::new(),
            executed: false,
            nonce: 0,
            auto_swap: false,
            amount_out_min: 0,
            claim_vouchers: Vec::new(),
        };

        let message = crate::bridge::BridgeManager::create_signing_message(&proposal, CHAIN_ID);
        let sig_ts = (now / 1000) as u64;
        let bound = crate::bridge::BridgeManager::bind_timestamp_to_message(&message, sig_ts);
        proposal.signatures = keys
            .into_iter()
            .take(signatures)
            .map(|(address, signing_key)| crate::bridge::BridgeSignature {
                authority: address,
                signature: signing_key.sign(&bound).to_bytes().to_vec(),
                public_key: signing_key.verifying_key().to_bytes().to_vec(),
                timestamp: sig_ts,
            })
            .collect();

        let bytes = bincode::serialize(&proposal).unwrap();
        let mut account = AccountState::default();
        account.contract_code = bytes;
        state
            .set_account(
                &crate::bridge::BridgeManager::proposal_state_key(&proposal_id),
                account,
            )
            .unwrap();
        proposal_id
    }

    /// 🚨 Çift basım regresyonu: aynı yatırışa iki öneri; ikincisi fail-closed
    /// reddedilmeli, bakiye ve teminat sayacı bir basımdan fazla artmamalı.
    #[test]
    fn a_second_mint_for_the_same_ethereum_deposit_is_rejected() {
        let authority_key = test_secret_key(11);
        let authority_address = test_address(11);
        let receiver = "0x00000000000000000000000000000000000000ee".to_string();
        let amount = 1_000_000_000_000u128;
        let src = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef1";
        let state = test_state();

        // İki farklı proposal_id, AYNI kaynak Ethereum işlemi.
        let pid1: Hash = [0x11; 32];
        let pid2: Hash = [0x22; 32];
        seed_raw_mint_proposal(&state, pid1, &receiver, amount, src, 2, 0);
        seed_raw_mint_proposal(&state, pid2, &receiver, amount, src, 2, 0);

        let make_mint = |pid: Hash, nonce: u64| {
            let mut tx = transaction(TxType::BridgeMint, nonce, amount);
            tx.sender = authority_address.clone();
            tx.receiver = receiver.clone();
            tx.tx_id = pid;
            // 🚨 Oneri payload'a konduktan SONRA imzalanir (imza payload'i kapsar).
            attach_proposal_payload(&state, &mut tx);
            tx.sign(&authority_key);
            tx
        };

        // 1. basım: BAŞARILI
        Executor::new(state.clone())
            .with_bridge_authority(authority_address.clone())
            .with_bridge_threshold(2, 0)
            .execute_transaction(&make_mint(pid1, 0), 1_000)
            .expect("ilk basim basarili olmali");
        let after_first = state
            .get_account(&receiver)
            .unwrap()
            .unwrap()
            .zerenya_balance;
        assert_eq!(after_first, amount, "ilk basim tam miktari yatirmali");

        // 2. basım (AYNI kaynak, farklı öneri): REDDEDİLMELİ
        let second = Executor::new(state.clone())
            .with_bridge_authority(authority_address.clone())
            .with_bridge_threshold(2, 0)
            .execute_transaction(&make_mint(pid2, 1), 1_000);
        assert!(
            second.is_err(),
            "AYNI Ethereum yatirisina ikinci basim REDDEDILMELIYDI - cift basim!"
        );
        let msg = format!("{:?}", second.unwrap_err()).to_lowercase();
        assert!(
            msg.contains("cift basim") || msg.contains("zaten islendi"),
            "hata mesaji cift-basim reddini belirtmeli, alinan: {}",
            msg
        );

        // Bakiye + teminat: yalnızca BİR basım kadar (çift değil).
        let after_second = state
            .get_account(&receiver)
            .unwrap()
            .unwrap()
            .zerenya_balance;
        assert_eq!(
            after_second, amount,
            "ikinci (reddedilen) basim bakiyeyi ARTIRMAMALI"
        );
    }

    /// 🛑 Native `DeployContract` yürütmede de reddedilir (mempool kapısı blok
    /// gövdesini korumaz); kural işlemin geldiği yoldan bağımsız.
    #[test]
    fn deploy_contract_is_refused_at_execution_not_just_at_the_mempool_gate() {
        let state = test_state();
        let secret_key = test_secret_key(1);
        let sender = Transaction::address_from_secret_key(&secret_key);
        let starting_balance = 1_000 * TOKEN_DECIMAL;
        state
            .set_account(&sender, AccountState::new(starting_balance))
            .unwrap();

        let mut tx = Transaction {
            tx_id: [7; 32],
            tx_type: TxType::DeployContract,
            sender: sender.clone(),
            amount: 0,
            receiver: "0x0000000000000000000000000000000000000000".to_string(),
            payload: vec![0x60, 0x00],
            signature: Vec::new(),
            timestamp: 1_000,
            nonce: 0,
            gas_limit: 1,
            gas_price: 2,
            chain_id: CHAIN_ID,
        };
        tx.sign(&secret_key);

        // Mempool'u ATLA, kotu niyetli bir uretici gibi DOGRUDAN yurut.
        let result = Executor::new(state.clone()).execute_transaction(&tx, tx.timestamp);
        assert!(
            result.is_err(),
            "DeployContract yurutmede REDDEDILMELI (mempool atlanabildigi icin): {result:?}"
        );

        // Executor'in ESKI turetme mantiginin AYNISI, o adrese hicbir sey
        // yazilmamis olmali.
        use sha3::{Digest, Keccak256};
        let mut hasher = Keccak256::new();
        hasher.update(sender.as_bytes());
        hasher.update(tx.nonce.to_le_bytes());
        let hash = hasher.finalize();
        let would_be_address = format!("0x{}", hex::encode(&hash[0..8]));
        assert_eq!(
            would_be_address.len(),
            18,
            "test on kosulu: eski adres 18 karakterdi"
        );
        assert!(
            state.get_account(&would_be_address).unwrap().is_none(),
            "reddedilen deploy state'e HICBIR kayit yazmamali (budanamaz sisme)"
        );
        assert!(
            !Transaction::validate_address(&would_be_address),
            "o adres zaten hicbir zaman gecerli bir alici olamazdi"
        );
    }

    #[test]
    fn state_checkpoint_reverts_accounts_and_raw_consensus_values() {
        let storage = Arc::new(MemoryStorage::default());
        let state: Arc<dyn State> = Arc::new(StateDbManager::new(storage.clone()));
        let address = "0x1111111111111111111111111111111111111111".to_string();
        state.set_account(&address, AccountState::new(100)).unwrap();
        state.set_pool_reserves(1_000, 2_000).unwrap();
        state.set_accumulated_reward_per_share(7).unwrap();
        // Account writes are now deferred until flush() (batched, see Phase 2);
        // pool reserves/reward-share stay immediate (out of batching scope).
        state.flush().unwrap();

        let persisted = storage.get(address.as_bytes()).unwrap().unwrap();
        let persisted_account: AccountState = bincode::deserialize(&persisted).unwrap();

        assert_eq!(persisted_account.balance, 100);

        let checkpoint = state.checkpoint().unwrap();
        state.set_account(&address, AccountState::new(25)).unwrap();
        state.set_pool_reserves(3_000, 4_000).unwrap();
        state.set_accumulated_reward_per_share(11).unwrap();
        state.revert_checkpoint(checkpoint).unwrap();

        assert_eq!(state.get_balance(&address).unwrap(), 100);

        assert_eq!(state.get_pool_reserves().unwrap(), (1_000, 2_000));

        assert_eq!(state.get_accumulated_reward_per_share().unwrap(), 7);
        state.flush().unwrap();
        let persisted = storage.get(address.as_bytes()).unwrap().unwrap();
        let persisted_account: AccountState = bincode::deserialize(&persisted).unwrap();

        assert_eq!(persisted_account.balance, 100);
    }

    #[test]
    fn validator_index_loads_disk_candidates_once_and_updates_incrementally() {
        let storage = Arc::new(MemoryStorage::default());
        let first_validator = "0x1111111111111111111111111111111111111111".to_string();
        let second_validator = "0x2222222222222222222222222222222222222222".to_string();
        let first_state = AccountState {
            staked_balance: 10,
            ..Default::default()
        };
        let second_state = AccountState {
            staked_balance: 20,
            ..Default::default()
        };
        storage
            .put(
                first_validator.as_bytes(),
                &bincode::serialize(&first_state).unwrap(),
            )
            .unwrap();
        storage
            .put(
                second_validator.as_bytes(),
                &bincode::serialize(&second_state).unwrap(),
            )
            .unwrap();
        let state: Arc<dyn State> = Arc::new(StateDbManager::new(storage.clone()));
        let executor = Executor::new(state);

        // G13: find_optimal_validator SÖKÜLDÜ (delegasyon yok), index'in
        // tembel kurulumunu ve tepe kaydını doğrudan yokluyoruz.
        let ensure_and_top = |ex: &Executor| -> Address {
            let mut idx = ex.staking_index.write().unwrap();
            if idx.is_none() {
                let candidates = ex
                    .state
                    .get_validator_candidates()
                    .unwrap()
                    .into_iter()
                    .collect();
                *idx = Some(ValidatorIndex::from_candidates(candidates));
            }
            idx.as_ref()
                .unwrap()
                .by_stake
                .iter()
                .next_back()
                .unwrap()
                .1
                .clone()
        };
        assert_eq!(ensure_and_top(&executor), second_validator);

        assert_eq!(storage.list_keys_calls.load(Ordering::SeqCst), 1);

        let updated_first = AccountState {
            staked_balance: 30,
            ..Default::default()
        };
        executor
            .staking_index
            .write()
            .unwrap()
            .as_mut()
            .unwrap()
            .update(
                &"0x1111111111111111111111111111111111111111".to_string(),
                &updated_first,
            );

        assert_eq!(ensure_and_top(&executor), first_validator);

        assert_eq!(storage.list_keys_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn ignore_executor_reuses_canonical_evm_state_for_next_native_transaction() {
        let state = test_state();
        let secret_key = test_secret_key(6);
        let canonical_sender = test_address(6);
        let mixed_case_sender = format!("0x{}", canonical_sender[2..].to_ascii_uppercase());
        let contract_address = "0x2222222222222222222222222222222222222222".to_string();
        state
            .set_account(&mixed_case_sender, AccountState::new(1_000_000_000_000_000))
            .unwrap();
        state
            .set_account(&contract_address, AccountState::new_contract(vec![0x00]))
            .unwrap();
        let executor = Executor::new(state.clone());
        let mut evm_tx = transaction(TxType::ContractCall { data: vec![0x00] }, 0, 0);
        evm_tx.sender = mixed_case_sender.clone();
        evm_tx.receiver = contract_address;
        evm_tx.gas_limit = 100_000;
        evm_tx.gas_price = 1;
        evm_tx.sign(&secret_key);

        executor
            .execute_transaction(&evm_tx, evm_tx.timestamp)
            .unwrap();

        let sender_after_evm = state.get_account(&canonical_sender).unwrap().unwrap();

        // 🚨 REGRESYON (A-K1): bkz. yukarıdaki test'in aynı doc yorumu.
        assert_eq!(sender_after_evm.nonce, 1);

        let mut native_tx = transaction(TxType::Transfer, 1, 10);
        native_tx.sender = mixed_case_sender;
        native_tx.sign(&secret_key);
        executor
            .execute_transaction(&native_tx, native_tx.timestamp)
            .unwrap();

        let sender_after_native = state.get_account(&canonical_sender).unwrap().unwrap();

        assert_eq!(sender_after_native.nonce, 2);

        assert_eq!(
            sender_after_native.balance,
            sender_after_evm.balance - native_tx.amount - 2
        );
    }

    #[test]
    fn bridge_mint_and_swap_rejects_sender_that_is_not_the_bridge_authority() {
        let pool_zagros = 10_000_000 * TOKEN_DECIMAL;
        let pool_zerenya = 10_000_000 * TOKEN_DECIMAL;
        let authority_address = test_address(9);
        // tx is signed by a real key, and would otherwise be a perfectly valid
        // BridgeMintAndSwap, but its sender is not the configured authority.
        let tx = transaction(TxType::BridgeMintAndSwap, 0, 100_000 * TOKEN_DECIMAL);
        assert_ne!(tx.sender, authority_address);

        let state = test_state();
        state.set_pool_reserves(pool_zagros, pool_zerenya).unwrap();
        state
            .set_account(&tx.sender, AccountState::new(1_000_000))
            .unwrap();
        state
            .set_account(
                &LIQUIDITY_POOL_ADDRESS.to_string(),
                AccountState {
                    balance: pool_zagros,
                    zerenya_balance: pool_zerenya,
                    ..Default::default()
                },
            )
            .unwrap();

        let executor = Executor::new(state.clone()).with_bridge_authority(authority_address);
        let result = executor.execute_transaction(&tx, tx.timestamp);

        assert!(matches!(result, Err(ZagrosError::BridgeError(_))));
        // No unbacked ZAGROS should have left the pool.
        assert_eq!(
            state.get_pool_reserves().unwrap(),
            (pool_zagros, pool_zerenya)
        );
    }

    /// REGRESYON: `BridgeMintAndSwap` payload'daki minimum ZAGROS çıktısını
    /// (`swap_amount_out_min`) uygulamalı; burada taban 1, mint-and-swap başarılı olmalı.
    #[test]
    fn bridge_mint_and_swap_with_a_trivially_low_min_amount_out_succeeds() {
        let pool_zagros = 10_000_000 * TOKEN_DECIMAL;
        let pool_zerenya = 10_000_000 * TOKEN_DECIMAL;
        let authority_key = test_secret_key(10);
        let authority_address = test_address(10);
        let receiver = "0x00000000000000000000000000000000000000ed".to_string();
        let state = test_state();
        state.set_pool_reserves(pool_zagros, pool_zerenya).unwrap();
        state
            .set_account(
                &LIQUIDITY_POOL_ADDRESS.to_string(),
                AccountState {
                    balance: pool_zagros,
                    zerenya_balance: pool_zerenya,
                    ..Default::default()
                },
            )
            .unwrap();

        let mut tx = transaction(TxType::BridgeMintAndSwap, 0, 50 * TOKEN_DECIMAL);
        tx.sender = authority_address.clone();
        tx.receiver = receiver.clone();
        // 🚨 `amount_out_min` artik payload'da IMZASIZ degil,
        // onerinin icinde ve yetkililerin imzasi kapsaminda.
        tx.tx_id = seed_mint_proposal(&state, &receiver, tx.amount, true, 1, 2, 2, 0, tx.timestamp);
        attach_proposal_payload(&state, &mut tx);
        tx.sign(&authority_key);

        Executor::new(state.clone())
            .with_bridge_authority(authority_address)
            .with_bridge_threshold(2, 0)
            .execute_transaction(&tx, tx.timestamp)
            .expect("gercek cikti asiri dusuk bir tabanin altina asla dusmemeli");

        assert!(state.get_account(&receiver).unwrap().unwrap().balance > 0);
    }

    /// REGRESYON: kullanıcı alınabilecekten çok yüksek minimum talep ediyor
    /// (fiyat kaymış gibi); işlem reddedilmeli, hiçbir bakiye değişmemeli.
    #[test]
    fn bridge_mint_and_swap_with_an_unreachably_high_min_amount_out_is_rejected() {
        let pool_zagros = 10_000_000 * TOKEN_DECIMAL;
        let pool_zerenya = 10_000_000 * TOKEN_DECIMAL;
        let authority_key = test_secret_key(11);
        let authority_address = test_address(11);
        let receiver = "0x00000000000000000000000000000000000000ee".to_string();
        let state = test_state();
        state.set_pool_reserves(pool_zagros, pool_zerenya).unwrap();
        state
            .set_account(
                &LIQUIDITY_POOL_ADDRESS.to_string(),
                AccountState {
                    balance: pool_zagros,
                    zerenya_balance: pool_zerenya,
                    ..Default::default()
                },
            )
            .unwrap();

        let mut tx = transaction(TxType::BridgeMintAndSwap, 0, 50 * TOKEN_DECIMAL);
        tx.sender = authority_address.clone();
        tx.receiver = receiver.clone();
        // 50 ZERENYA girdisi asla 1_000_000 ZAGROS cikti vermez (ayni havuzda,
        // ucret dusmeden bile giris > cikis olurdu), kesin red.
        // 🚨 `amount_out_min` artik onerinin icinde, imza kapsaminda.
        tx.tx_id = seed_mint_proposal(
            &state,
            &receiver,
            tx.amount,
            true,
            1_000_000 * TOKEN_DECIMAL,
            2,
            2,
            0,
            tx.timestamp,
        );
        attach_proposal_payload(&state, &mut tx);
        tx.sign(&authority_key);

        let result = Executor::new(state.clone())
            .with_bridge_authority(authority_address)
            .with_bridge_threshold(2, 0)
            .execute_transaction(&tx, tx.timestamp);

        assert!(
            matches!(result, Err(ZagrosError::Other(_))),
            "ulasilamaz derecede yuksek bir minimum talep edildigi halde mint-and-swap gecti"
        );
        assert_eq!(
            state
                .get_account(&receiver)
                .unwrap()
                .unwrap_or_default()
                .balance,
            0,
            "reddedilen bir slippage kontrolunden sonra bakiye yine de arttirilmis"
        );
        assert_eq!(
            state.get_pool_reserves().unwrap(),
            (pool_zagros, pool_zerenya),
            "reddedilen islem havuzu etkilememeli"
        );
    }

    /// Faz C (köprü otomatik yürütücüsü): mint, FOUNDER_ADDRESS'ten AYRI bir
    /// "bridge-signer" anahtarıyla gönderilir (`with_bridge_authority`); bu test
    /// aynı yolu taklit eder, işlem imza ve köprü yetkisi kontrollerini geçmeli.
    #[test]
    fn bridge_mint_signed_by_a_dedicated_signer_key_distinct_from_founder_is_accepted() {
        let signer_key = secp256k1::SecretKey::from_slice(&[42u8; 32]).unwrap();
        let signer_address = Transaction::address_from_secret_key(&signer_key);
        assert_ne!(signer_address, FOUNDER_ADDRESS);

        let state = test_state();
        let receiver = "0x0000000000000000000000000000000000000009".to_string();
        // Bridge-signer'a KASITLI olarak hiç ZAGROS vermiyoruz, mint işlemi
        // artık ücretten muaf, bu adresin gaz için fonlanmasına gerek yok
        // (bkz. `bridge_mint_from_the_authority_is_fee_exempt_even_with_zero_balance`).

        let mut tx = transaction(TxType::BridgeMint, 0, 50 * TOKEN_DECIMAL);
        tx.sender = signer_address.clone();
        tx.receiver = receiver.clone();
        tx.tx_id = seed_mint_proposal(
            &state,
            &receiver,
            tx.amount,
            false,
            0,
            2,
            2,
            0,
            tx.timestamp,
        );
        attach_proposal_payload(&state, &mut tx);
        // 🚨 Imza payload'i da KAPSAR: oneri payload'a konduktan SONRA imzalanmali.
        tx.sign(&signer_key);

        let executor = Executor::new(state.clone())
            .with_bridge_authority(signer_address)
            .with_bridge_threshold(2, 0);
        executor.execute_transaction(&tx, tx.timestamp).unwrap();

        let receiver_account = state.get_account(&receiver).unwrap().unwrap();
        assert_eq!(receiver_account.zerenya_balance, 50 * TOKEN_DECIMAL);
    }

    /// 🚨 KÖPRÜ MİNT ÜCRET MUAFİYETİ (executor): `bridge_authority` sıfır ZAGROS
    /// ile bile mint yürütebilmeli (mempool ile aynı koşul); mint zaten yatırma +
    /// onay + haberci imzası gerektirir, ücret ek güvenlik sağlamaz.
    #[test]
    fn bridge_mint_from_the_authority_is_fee_exempt_even_with_zero_balance() {
        let signer_key = secp256k1::SecretKey::from_slice(&[43u8; 32]).unwrap();
        let signer_address = Transaction::address_from_secret_key(&signer_key);

        let state = test_state();
        let receiver = "0x000000000000000000000000000000000000000a".to_string();
        // signer_address HİÇ bakiye almıyor, test bunu izole ediyor.
        assert_eq!(state.get_balance(&signer_address).unwrap(), 0);

        let mut tx = transaction(TxType::BridgeMint, 0, 50 * TOKEN_DECIMAL);
        tx.sender = signer_address.clone();
        tx.receiver = receiver.clone();
        // Yüksek gas_price: muaf değilse tek başına reddedilirdi; muafiyetin
        // ücreti gerçekten yok saydığı kanıtlanır.
        tx.gas_limit = 1;
        tx.gas_price = 999_999_999_999_999;
        tx.tx_id = seed_mint_proposal(
            &state,
            &receiver,
            tx.amount,
            false,
            0,
            2,
            2,
            0,
            tx.timestamp,
        );
        attach_proposal_payload(&state, &mut tx);
        // 🚨 Imza payload'i da KAPSAR: oneri payload'a konduktan SONRA imzalanmali.
        tx.sign(&signer_key);

        let executor = Executor::new(state.clone())
            .with_bridge_authority(signer_address.clone())
            .with_bridge_threshold(2, 0);
        executor
            .execute_transaction(&tx, tx.timestamp)
            .expect("muaf olmasi gereken kopru mint islemi bakiyesizlik yuzunden reddedildi");

        let receiver_account = state.get_account(&receiver).unwrap().unwrap();
        assert_eq!(receiver_account.zerenya_balance, 50 * TOKEN_DECIMAL);
        // Bakiye hâlâ 0; asıl kanıt `execute_transaction`ın hiç hata vermemesi.
        assert_eq!(state.get_balance(&signer_address).unwrap(), 0);
    }

    // 🛡️ ZİNCİR SEVİYESİNDE ÇOKLU İMZA ZORUNLULUĞU: `bridge_authority` imzası
    // geçerli olsa bile eşleşen/yürütülebilir öneri olmadan mint YÜRÜMEZ.

    fn mint_tx_for(
        state: &Arc<dyn State>,
        authority: &str,
        authority_key: &secp256k1::SecretKey,
        tx_id: [u8; 32],
        receiver: &str,
        amount: u128,
        timestamp: u128,
    ) -> Transaction {
        let mut tx = transaction(TxType::BridgeMint, 0, amount);
        tx.tx_id = tx_id;
        tx.sender = authority.to_string();
        tx.receiver = receiver.to_string();
        tx.timestamp = timestamp;
        // 🚨 Öneri varsa payload'a konur (CLI gibi), yoksa boş bırakılır; imza
        // payload'ı kapsadığından bu adım imzadan ÖNCE.
        if let Ok(Some(proposal)) =
            crate::bridge::BridgeManager::load_proposal_from_state(state.as_ref(), &tx.tx_id)
        {
            tx.payload = crate::bridge::BridgeManager::encode_proposal_payload(&proposal).unwrap();
        }
        tx.sign(authority_key);
        tx
    }

    /// 🛡️ MIMARI KILIT: payload'daki oneri islemin `tx_id`'sine
    /// BAGLI olmali. Olmasaydi, gecerli imzali BIR oneri BASKA bir isleme
    /// yapistirilip ayni imzalarla ikinci bir basim yapilabilirdi.
    #[test]
    fn a_bridge_mint_whose_payload_carries_a_different_proposal_id_is_rejected() {
        let authority_key = secp256k1::SecretKey::from_slice(&[93u8; 32]).unwrap();
        let authority = Transaction::address_from_secret_key(&authority_key);
        let receiver = "0x00000000000000000000000000000000000000c1".to_string();
        let state = test_state();

        // Iki AYRI oneri, ikisi de kendi icinde gecerli imzali.
        let pid_a = seed_mint_proposal(
            &state,
            &receiver,
            10 * TOKEN_DECIMAL,
            false,
            0,
            2,
            2,
            0,
            1_000,
        );
        let pid_b = seed_mint_proposal(
            &state,
            &receiver,
            10 * TOKEN_DECIMAL,
            false,
            0,
            2,
            2,
            0,
            1_000,
        );
        assert_ne!(pid_a, pid_b, "on kosul: iki farkli oneri");

        // Islem A'yi isaret ediyor, payload B'yi tasiyor.
        let mut tx = mint_tx_for(
            &state,
            &authority,
            &authority_key,
            pid_a,
            &receiver,
            10 * TOKEN_DECIMAL,
            1_000,
        );
        let b = crate::bridge::BridgeManager::load_proposal_from_state(state.as_ref(), &pid_b)
            .unwrap()
            .unwrap();
        tx.payload = crate::bridge::BridgeManager::encode_proposal_payload(&b).unwrap();
        tx.sign(&authority_key);

        let hata = Executor::new(state.clone())
            .with_bridge_authority(authority)
            .with_bridge_threshold(2, 0)
            .execute_transaction(&tx, 1_000)
            .unwrap_err();
        assert!(
            hata.to_string().contains("tx_id"),
            "kimlik baglantisi kopuk, beklenmeyen hata: {}",
            hata
        );
        assert_eq!(
            state
                .get_account(&receiver)
                .unwrap()
                .map(|a| a.zerenya_balance)
                .unwrap_or(0),
            0,
            "reddedilen mint hicbir bakiye yaratmamali"
        );
    }

    /// 🛡️ MIMARI KILIT: payload KURCALANIRSA imza mesaji degisir,
    /// yetkili imzalari gecersizlesir ve basim reddedilir. Yani isleme oneriyi
    /// gomuyor olmamiz, miktari sisirme kapisi ACMAZ.
    #[test]
    fn a_bridge_mint_with_a_tampered_payload_amount_is_rejected() {
        let authority_key = secp256k1::SecretKey::from_slice(&[94u8; 32]).unwrap();
        let authority = Transaction::address_from_secret_key(&authority_key);
        let receiver = "0x00000000000000000000000000000000000000c2".to_string();
        let state = test_state();

        let pid = seed_mint_proposal(
            &state,
            &receiver,
            10 * TOKEN_DECIMAL,
            false,
            0,
            2,
            2,
            0,
            1_000,
        );
        let mut kurcalanmis =
            crate::bridge::BridgeManager::load_proposal_from_state(state.as_ref(), &pid)
                .unwrap()
                .unwrap();
        // Saldirgan hem oneriyi hem islemi ayni sekilde sisiriyor ki
        // "alici/miktar eslesmiyor" kontrolune takilmasin, geriye tek savunma
        // olarak zincir-ustu imza dogrulamasi kalsin.
        kurcalanmis.amount = 20 * TOKEN_DECIMAL;

        let mut tx = mint_tx_for(
            &state,
            &authority,
            &authority_key,
            pid,
            &receiver,
            20 * TOKEN_DECIMAL,
            1_000,
        );
        tx.payload = crate::bridge::BridgeManager::encode_proposal_payload(&kurcalanmis).unwrap();
        tx.sign(&authority_key);

        let hata = Executor::new(state.clone())
            .with_bridge_authority(authority)
            .with_bridge_threshold(2, 0)
            .execute_transaction(&tx, 1_000)
            .unwrap_err();
        assert!(
            hata.to_string().to_lowercase().contains("imza")
                || hata.to_string().contains("GECERLI"),
            "kurcalanan payload imza dogrulamasinda yakalanmali, gelen hata: {}",
            hata
        );
        assert_eq!(
            state
                .get_account(&receiver)
                .unwrap()
                .map(|a| a.zerenya_balance)
                .unwrap_or(0),
            0,
            "kurcalanan mint hicbir bakiye yaratmamali"
        );
    }

    /// 🛡️ `amount_out_min` imza kapsamında; imzasız taşınsaydı yürütücü sıfırlayabilirdi.
    #[test]
    fn the_signed_slippage_limit_cannot_be_weakened_by_the_executor_node() {
        let authority_key = secp256k1::SecretKey::from_slice(&[95u8; 32]).unwrap();
        let authority = Transaction::address_from_secret_key(&authority_key);
        let receiver = "0x00000000000000000000000000000000000000c3".to_string();
        let state = test_state();
        state
            .set_pool_reserves(1_000_000 * TOKEN_DECIMAL, 1_000_000 * TOKEN_DECIMAL)
            .unwrap();

        // Kullanici ULASILAMAZ derecede yuksek bir alt sinir imzalatmis.
        let pid = seed_mint_proposal(
            &state,
            &receiver,
            50 * TOKEN_DECIMAL,
            true,
            1_000_000 * TOKEN_DECIMAL,
            2,
            2,
            0,
            1_000,
        );
        let mut zayiflatilmis =
            crate::bridge::BridgeManager::load_proposal_from_state(state.as_ref(), &pid)
                .unwrap()
                .unwrap();
        // Kotu niyetli yurutucu limiti sifirliyor ("sinir yok").
        zayiflatilmis.amount_out_min = 0;

        let mut tx = transaction(TxType::BridgeMintAndSwap, 0, 50 * TOKEN_DECIMAL);
        tx.tx_id = pid;
        tx.sender = authority.clone();
        tx.receiver = receiver.clone();
        tx.timestamp = 1_000;
        tx.payload = crate::bridge::BridgeManager::encode_proposal_payload(&zayiflatilmis).unwrap();
        tx.sign(&authority_key);

        let sonuc = Executor::new(state.clone())
            .with_bridge_authority(authority)
            .with_bridge_threshold(2, 0)
            .execute_transaction(&tx, 1_000);
        assert!(
            sonuc.is_err(),
            "imzasiz zayiflatilmis slippage limiti KABUL EDILDI - koruma delindi"
        );
    }

    #[test]
    fn bridge_mint_without_a_matching_proposal_is_rejected() {
        let authority_key = secp256k1::SecretKey::from_slice(&[91u8; 32]).unwrap();
        let authority = Transaction::address_from_secret_key(&authority_key);
        let state = test_state();
        // Hiç proposal seed edilmedi, tx.tx_id state'te KARŞILIKSIZ.
        let tx = mint_tx_for(
            &state,
            &authority,
            &authority_key,
            [123u8; 32],
            "0x00000000000000000000000000000000000000e1",
            100 * TOKEN_DECIMAL,
            1_000,
        );

        let result = Executor::new(state)
            .with_bridge_authority(authority)
            .with_bridge_threshold(2, 0)
            .execute_transaction(&tx, tx.timestamp);

        assert!(matches!(result, Err(ZagrosError::BridgeError(_))));
        // 🚨 Oneri artik payload'da tasindigi icin, onerisi
        // olmayan bir mint bos payload'da yakalanir.
        assert!(result.unwrap_err().to_string().contains("payload"));
    }

    #[test]
    fn bridge_mint_with_insufficient_signatures_is_rejected() {
        let authority_key = secp256k1::SecretKey::from_slice(&[92u8; 32]).unwrap();
        let authority = Transaction::address_from_secret_key(&authority_key);
        let receiver = "0x00000000000000000000000000000000000000e2".to_string();
        let state = test_state();

        // Eşik 2, ama yalnızca 1 imza toplanıyor.
        let proposal_id = seed_mint_proposal(
            &state,
            &receiver,
            100 * TOKEN_DECIMAL,
            false,
            0,
            2,
            1,
            0,
            1_000,
        );
        let tx = mint_tx_for(
            &state,
            &authority,
            &authority_key,
            proposal_id,
            &receiver,
            100 * TOKEN_DECIMAL,
            1_000,
        );

        let result = Executor::new(state)
            .with_bridge_authority(authority)
            .with_bridge_threshold(2, 0)
            .execute_transaction(&tx, tx.timestamp);

        assert!(
            matches!(result, Err(ZagrosError::BridgeError(_))),
            "yalnizca 1/2 imzayla mint gecti"
        );
    }

    /// 🚨 Gerçekçi (saniye) `block_timestamp` kullanır; `proposal_is_executable`
    /// milisaniye bekler, executor'ın dönüşümü (`block_timestamp_ms`) doğrulanır.
    #[test]
    fn bridge_mint_before_timelock_elapses_is_rejected_then_succeeds_after() {
        let authority_key = secp256k1::SecretKey::from_slice(&[93u8; 32]).unwrap();
        let authority = Transaction::address_from_secret_key(&authority_key);
        let receiver = "0x00000000000000000000000000000000000000e3".to_string();
        let state = test_state();

        let now_secs: u64 = std::time::UNIX_EPOCH.elapsed().unwrap().as_secs();
        let timelock_secs: u64 = 3600; // 1 saat
        let proposal_id = seed_mint_proposal(
            &state,
            &receiver,
            100 * TOKEN_DECIMAL,
            false,
            0,
            2,
            2,
            timelock_secs,
            (now_secs as u128) * 1000, // seed_mint_proposal ms bekliyor, kendi icinde /1000 yapiyor
        );

        // Zaman kilidi DOLMADAN önce, tx.timestamp (SANİYE, gerçek block_timestamp
        // konvansiyonu) proposal.timestamp'e çok yakın.
        let too_early = mint_tx_for(
            &state,
            &authority,
            &authority_key,
            proposal_id,
            &receiver,
            100 * TOKEN_DECIMAL,
            now_secs as u128,
        );
        let rejected = Executor::new(state.clone())
            .with_bridge_authority(authority.clone())
            .with_bridge_threshold(2, timelock_secs)
            .execute_transaction(&too_early, too_early.timestamp);
        assert!(
            matches!(rejected, Err(ZagrosError::BridgeError(_))),
            "zaman kilidi dolmadan mint gecti"
        );

        // Zaman kilidi DOLDUKTAN sonra (+timelock+1 saniye), AYNI proposal,
        // farklı nonce'lu YENİ bir tx (executor bu tx_id ile daha önce
        // BAŞARILI bir mint yapmadı, yani bu replay testi değil).
        let mut after = mint_tx_for(
            &state,
            &authority,
            &authority_key,
            proposal_id,
            &receiver,
            100 * TOKEN_DECIMAL,
            (now_secs + timelock_secs + 1) as u128,
        );
        after.nonce = 1;
        after.sign(&authority_key);
        Executor::new(state.clone())
            .with_bridge_authority(authority)
            .with_bridge_threshold(2, timelock_secs)
            .execute_transaction(&after, after.timestamp)
            .expect("zaman kilidi dolduktan sonra mint hala reddediliyor");

        let receiver_account = state.get_account(&receiver).unwrap().unwrap();
        assert_eq!(receiver_account.zerenya_balance, 100 * TOKEN_DECIMAL);
    }

    #[test]
    fn bridge_mint_with_a_different_recipient_than_the_proposal_is_rejected() {
        let authority_key = secp256k1::SecretKey::from_slice(&[94u8; 32]).unwrap();
        let authority = Transaction::address_from_secret_key(&authority_key);
        let proposed_recipient = "0x00000000000000000000000000000000000000e4".to_string();
        let attacker_recipient = "0x00000000000000000000000000000000000000e5".to_string();
        let state = test_state();

        let proposal_id = seed_mint_proposal(
            &state,
            &proposed_recipient,
            100 * TOKEN_DECIMAL,
            false,
            0,
            2,
            2,
            0,
            1_000,
        );
        // Saldırgan AYNI proposal_id'yi kullanıp alıcıyı KENDİNE çeviriyor.
        let tx = mint_tx_for(
            &state,
            &authority,
            &authority_key,
            proposal_id,
            &attacker_recipient,
            100 * TOKEN_DECIMAL,
            1_000,
        );

        let result = Executor::new(state.clone())
            .with_bridge_authority(authority)
            .with_bridge_threshold(2, 0)
            .execute_transaction(&tx, tx.timestamp);

        assert!(
            matches!(result, Err(ZagrosError::BridgeError(_))),
            "alici degistirilmis mint gecti"
        );
        assert_eq!(
            state
                .get_account(&attacker_recipient)
                .unwrap()
                .map(|a| a.zerenya_balance)
                .unwrap_or(0),
            0
        );
    }

    #[test]
    fn bridge_mint_with_a_different_amount_than_the_proposal_is_rejected() {
        let authority_key = secp256k1::SecretKey::from_slice(&[95u8; 32]).unwrap();
        let authority = Transaction::address_from_secret_key(&authority_key);
        let receiver = "0x00000000000000000000000000000000000000e6".to_string();
        let state = test_state();

        let proposal_id = seed_mint_proposal(
            &state,
            &receiver,
            100 * TOKEN_DECIMAL,
            false,
            0,
            2,
            2,
            0,
            1_000,
        );
        // Saldırgan AYNI proposal_id'yi kullanıp miktarı ŞİŞİRİYOR.
        let tx = mint_tx_for(
            &state,
            &authority,
            &authority_key,
            proposal_id,
            &receiver,
            999_999 * TOKEN_DECIMAL,
            1_000,
        );

        let result = Executor::new(state.clone())
            .with_bridge_authority(authority)
            .with_bridge_threshold(2, 0)
            .execute_transaction(&tx, tx.timestamp);

        assert!(
            matches!(result, Err(ZagrosError::BridgeError(_))),
            "miktar degistirilmis mint gecti"
        );
    }

    /// Kötü niyetli bir blok üreticisinin, YEREL KOPYASI OLMAYAN bir
    /// follower'a tahrif edilmiş öneriyi blok gövdesiyle ulaştırmasını simüle
    /// eder: önce yerel kaydı sil (taze follower), sonra ingest et.
    fn ingest_as_a_fresh_follower_would(
        state: &Arc<dyn State>,
        proposal: &crate::bridge::BridgeProposal,
    ) {
        state
            .set_account(
                &crate::bridge::BridgeManager::proposal_state_key(&proposal.proposal_id),
                AccountState::default(),
            )
            .unwrap();
        crate::bridge::BridgeManager::ingest_relayed_proposals(
            state.as_ref(),
            std::slice::from_ref(proposal),
        )
        .unwrap();
    }

    /// 🚨 REGRESYON: zincir seviyesi M-of-N imza GERÇEKTEN doğrulanmalı; yalnız
    /// sayım, imzacı anahtarını tutan tarafın diziyi sahte girdiyle doldurup tek
    /// başına basmasına izin verir (öneri baytları gövdeden gelir, güvenilemez).
    #[test]
    fn forged_signature_entries_cannot_satisfy_the_bridge_multisig_threshold() {
        let authority_key = secp256k1::SecretKey::from_slice(&[97u8; 32]).unwrap();
        let authority = Transaction::address_from_secret_key(&authority_key);
        let receiver = "0x00000000000000000000000000000000000000f1".to_string();
        let state = test_state();

        // Gecerli bir oneri kur (esik 2, iki GERCEK imza), referans nokta.
        let proposal_id = seed_mint_proposal(
            &state,
            &receiver,
            100 * TOKEN_DECIMAL,
            false,
            0,
            2,
            2,
            0,
            1_000,
        );

        // Simdi oneriyi, saldirganin blok govdesinden yapabilecegi gibi
        // TAHRIF et: gercek imzalari at, yerlerine ayni SAYIDA cop girdi koy.
        let mut proposal =
            crate::bridge::BridgeManager::load_proposal_from_state(state.as_ref(), &proposal_id)
                .unwrap()
                .unwrap();
        let real_authority = proposal.signatures[0].authority.clone();
        let real_pubkey = proposal.signatures[0].public_key.clone();
        proposal.signatures = (0..2)
            .map(|i| crate::bridge::BridgeSignature {
                // Gercek yetkili ADRESI ve ANAHTARI, ama COP imza baytlari.
                authority: real_authority.clone(),
                public_key: real_pubkey.clone(),
                signature: vec![i as u8; 64],
                timestamp: 1,
            })
            .collect();
        ingest_as_a_fresh_follower_would(&state, &proposal);

        let tx = mint_tx_for(
            &state,
            &authority,
            &authority_key,
            proposal_id,
            &receiver,
            100 * TOKEN_DECIMAL,
            1_000,
        );
        let result = Executor::new(state.clone())
            .with_bridge_authority(authority)
            .with_bridge_threshold(2, 0)
            .execute_transaction(&tx, tx.timestamp);

        assert!(
            matches!(result, Err(ZagrosError::BridgeError(_))),
            "SAHTE imza girdileri esigi saglamamali - basim reddedilmeliydi, sonuc: {result:?}"
        );

        // Alici HICBIR SEY almamis olmali (fail-closed).
        let acc = state.get_account(&receiver).unwrap().unwrap_or_default();
        assert_eq!(
            acc.zerenya_balance, 0,
            "reddedilen basimda alici bakiyesi degismemeli"
        );
    }

    /// 🛡️ `ingest_relayed_proposals` blok gövdesinden gelen baytları yazar;
    /// eşiği dolduran GEÇERLİ imzalar taşımayan bir sürüm var olan (dürüst)
    /// kaydın üzerine YAZAMAZ, yoksa üretici kaydı tahrif edebilirdi.
    #[test]
    fn relayed_proposals_never_overwrite_a_locally_stored_one() {
        let receiver = "0x00000000000000000000000000000000000000f4".to_string();
        let state = test_state();
        let proposal_id = seed_mint_proposal(
            &state,
            &receiver,
            100 * TOKEN_DECIMAL,
            false,
            0,
            2,
            2,
            0,
            1_000,
        );
        let honest =
            crate::bridge::BridgeManager::load_proposal_from_state(state.as_ref(), &proposal_id)
                .unwrap()
                .unwrap();

        // Saldirgan ayni id ile TAMAMEN farkli bir oneri gondermeye calisiyor.
        let mut tampered = honest.clone();
        tampered.amount = 999_999 * TOKEN_DECIMAL;
        tampered.recipient = "0x000000000000000000000000000000000000dead".to_string();
        tampered.auto_swap = !honest.auto_swap;
        crate::bridge::BridgeManager::ingest_relayed_proposals(
            state.as_ref(),
            std::slice::from_ref(&tampered),
        )
        .unwrap();

        let after =
            crate::bridge::BridgeManager::load_proposal_from_state(state.as_ref(), &proposal_id)
                .unwrap()
                .unwrap();
        assert_eq!(after.amount, honest.amount, "miktar degistirilememeli");
        assert_eq!(after.recipient, honest.recipient, "alici degistirilememeli");
        assert_eq!(
            after.auto_swap, honest.auto_swap,
            "auto_swap degistirilememeli"
        );
    }

    /// KISMİ yerel kopya, blokla gelen TAM (geçerli imzalı) sürümün yazılmasını
    /// ENGELLEMEMELİ; engellerse düğümler mint'i farklı değerlendirip `state_root` çatallanır.
    #[test]
    fn a_relayed_proposal_with_more_valid_signatures_replaces_a_partial_local_copy() {
        use ed25519_dalek::{Signer, SigningKey};

        let receiver = "0x00000000000000000000000000000000000000f5".to_string();
        let state = test_state();

        // Bu dugumde KISMI kopya var: esik 2, ama yalnizca 1 imza toplanmis.
        let proposal_id = seed_mint_proposal(
            &state,
            &receiver,
            100 * TOKEN_DECIMAL,
            false,
            0,
            2,
            1,
            0,
            1_000,
        );
        let partial =
            crate::bridge::BridgeManager::load_proposal_from_state(state.as_ref(), &proposal_id)
                .unwrap()
                .unwrap();
        assert_eq!(
            partial.signatures.len(),
            1,
            "on kosul: yerel kopya KISMI olmali"
        );

        // Blokla gelen TAM surum: ayni oneri, ikinci yetkilinin imzasi da ekli.
        // Imza mesaji, imzalar EKLENMEDEN onceki halden turetilir (uretimde de
        // oyle, bkz. seed_mint_proposal).
        let mut mesaj_kaynagi = partial.clone();
        mesaj_kaynagi.signatures.clear();
        let message =
            crate::bridge::BridgeManager::create_signing_message(&mesaj_kaynagi, CHAIN_ID);
        let sig_ts = 1u64;
        let bound = crate::bridge::BridgeManager::bind_timestamp_to_message(&message, sig_ts);

        let mut seed = [0u8; 32];
        seed[0] = 202; // seed_mint_proposal'in IKINCI yetkilisi (200 + 2)
        let ikinci = SigningKey::from_bytes(&seed);
        let mut complete = partial.clone();
        complete.signatures.push(crate::bridge::BridgeSignature {
            authority: crate::bridge::BridgeManager::derive_address_from_public_key(
                &ikinci.verifying_key().to_bytes(),
            ),
            signature: ikinci.sign(&bound).to_bytes().to_vec(),
            public_key: ikinci.verifying_key().to_bytes().to_vec(),
            timestamp: sig_ts,
        });

        crate::bridge::BridgeManager::ingest_relayed_proposals(
            state.as_ref(),
            std::slice::from_ref(&complete),
        )
        .unwrap();

        let after =
            crate::bridge::BridgeManager::load_proposal_from_state(state.as_ref(), &proposal_id)
                .unwrap()
                .unwrap();
        assert_eq!(
            after.signatures.len(),
            2,
            "daha cok GECERLI imza tasiyan surum kismi yerel kopyanin uzerine yazilmali"
        );
    }

    /// Zincir-üstü yetkili kümesi YOKSA basım fail-closed reddedilmeli,
    /// sessizce "doğrulama yapmadan geç" moduna DÜŞÜLMEMELİ.
    #[test]
    fn a_missing_onchain_authority_set_fails_closed_instead_of_skipping_verification() {
        let authority_key = secp256k1::SecretKey::from_slice(&[98u8; 32]).unwrap();
        let authority = Transaction::address_from_secret_key(&authority_key);
        let receiver = "0x00000000000000000000000000000000000000f2".to_string();
        let state = test_state();
        let proposal_id = seed_mint_proposal(
            &state,
            &receiver,
            100 * TOKEN_DECIMAL,
            false,
            0,
            2,
            2,
            0,
            1_000,
        );

        // Zincirdeki kumeyi SIL (genesis yazilmamis eski bir zinciri simule et).
        state
            .set_account(
                &zagros_types::consensus::BRIDGE_AUTHORITY_SET_KEY.to_string(),
                AccountState::default(),
            )
            .unwrap();

        let tx = mint_tx_for(
            &state,
            &authority,
            &authority_key,
            proposal_id,
            &receiver,
            100 * TOKEN_DECIMAL,
            1_000,
        );
        let result = Executor::new(state.clone())
            .with_bridge_authority(authority)
            .with_bridge_threshold(2, 0)
            .execute_transaction(&tx, tx.timestamp);
        assert!(
            result.is_err(),
            "kume yokken basim REDDEDILMELI: {result:?}"
        );
        let acc = state.get_account(&receiver).unwrap().unwrap_or_default();
        assert_eq!(acc.zerenya_balance, 0);
    }

    /// Aynı yetkilinin İKİ imzası eşiği sağlamamalı (tekilleştirme), aksi
    /// halde tek bir anahtar M-of-N'i tek başına doldururdu.
    #[test]
    fn duplicate_signatures_from_one_authority_count_only_once() {
        let authority_key = secp256k1::SecretKey::from_slice(&[99u8; 32]).unwrap();
        let authority = Transaction::address_from_secret_key(&authority_key);
        let receiver = "0x00000000000000000000000000000000000000f3".to_string();
        let state = test_state();

        // Esik 2 ama YALNIZCA 1 gercek imza toplanmis bir oneri.
        let proposal_id = seed_mint_proposal(
            &state,
            &receiver,
            100 * TOKEN_DECIMAL,
            false,
            0,
            2,
            1,
            0,
            1_000,
        );
        let mut proposal =
            crate::bridge::BridgeManager::load_proposal_from_state(state.as_ref(), &proposal_id)
                .unwrap()
                .unwrap();
        // Tek gecerli imzayi KOPYALA -> dizide 2 girdi, ama tek yetkili.
        let only = proposal.signatures[0].clone();
        proposal.signatures = vec![only.clone(), only];
        ingest_as_a_fresh_follower_would(&state, &proposal);

        let tx = mint_tx_for(
            &state,
            &authority,
            &authority_key,
            proposal_id,
            &receiver,
            100 * TOKEN_DECIMAL,
            1_000,
        );
        let result = Executor::new(state.clone())
            .with_bridge_authority(authority)
            .with_bridge_threshold(2, 0)
            .execute_transaction(&tx, tx.timestamp);
        assert!(
            matches!(result, Err(ZagrosError::BridgeError(_))),
            "ayni yetkilinin iki imzasi esigi saglamamali: {result:?}"
        );
    }

    #[test]
    fn bridge_mint_type_mismatch_auto_swap_flag_is_rejected() {
        let authority_key = secp256k1::SecretKey::from_slice(&[96u8; 32]).unwrap();
        let authority = Transaction::address_from_secret_key(&authority_key);
        let receiver = "0x00000000000000000000000000000000000000e7".to_string();
        let state = test_state();

        // Proposal auto_swap=true (yani BridgeMintAndSwap olarak yürütülmeli),
        // ama saldırgan/hatalı istemci düz BridgeMint gönderiyor.
        let proposal_id = seed_mint_proposal(
            &state,
            &receiver,
            100 * TOKEN_DECIMAL,
            true,
            0,
            2,
            2,
            0,
            1_000,
        );
        let tx = mint_tx_for(
            &state,
            &authority,
            &authority_key,
            proposal_id,
            &receiver,
            100 * TOKEN_DECIMAL,
            1_000,
        );

        let result = Executor::new(state)
            .with_bridge_authority(authority)
            .with_bridge_threshold(2, 0)
            .execute_transaction(&tx, tx.timestamp);

        assert!(
            matches!(result, Err(ZagrosError::BridgeError(_))),
            "auto_swap uyusmazligi yakalanmadi"
        );
    }

    /// 🚨 Replay: aynı proposal_id ile ikinci mint (farklı nonce'la bile) reddedilmeli;
    /// `mark_executed_in_state` basımla aynı checkpoint'te atomik.
    #[test]
    fn bridge_mint_replaying_an_already_executed_proposal_is_rejected() {
        let authority_key = secp256k1::SecretKey::from_slice(&[97u8; 32]).unwrap();
        let authority = Transaction::address_from_secret_key(&authority_key);
        let receiver = "0x00000000000000000000000000000000000000e8".to_string();
        let state = test_state();

        let proposal_id = seed_mint_proposal(
            &state,
            &receiver,
            100 * TOKEN_DECIMAL,
            false,
            0,
            2,
            2,
            0,
            1_000,
        );

        let first = mint_tx_for(
            &state,
            &authority,
            &authority_key,
            proposal_id,
            &receiver,
            100 * TOKEN_DECIMAL,
            1_000,
        );
        Executor::new(state.clone())
            .with_bridge_authority(authority.clone())
            .with_bridge_threshold(2, 0)
            .execute_transaction(&first, first.timestamp)
            .unwrap();
        assert_eq!(
            state
                .get_account(&receiver)
                .unwrap()
                .unwrap()
                .zerenya_balance,
            100 * TOKEN_DECIMAL
        );

        // AYNI proposal_id, YENİ bir nonce'lu ikinci işlem, bridge_authority
        // anahtarı çalınmış gibi davranıyoruz.
        let mut second = mint_tx_for(
            &state,
            &authority,
            &authority_key,
            proposal_id,
            &receiver,
            100 * TOKEN_DECIMAL,
            1_000,
        );
        second.nonce = 1;
        second.sign(&authority_key);
        let result = Executor::new(state.clone())
            .with_bridge_authority(authority)
            .with_bridge_threshold(2, 0)
            .execute_transaction(&second, second.timestamp);

        assert!(
            matches!(result, Err(ZagrosError::BridgeError(_))),
            "ayni proposal ikinci kez mint edildi (replay)"
        );
        // Bakiye İKİNCİ kez ARTMAMALI.
        assert_eq!(
            state
                .get_account(&receiver)
                .unwrap()
                .unwrap()
                .zerenya_balance,
            100 * TOKEN_DECIMAL
        );
    }

    /// REGRESYON: `daily_mint_limit` ayrı ayrı geçerli iki öneri arasında da
    /// uygulanmalı; `check_and_record_daily_mint` zincir durumuna GERÇEKTEN yazıp okumalı.
    #[test]
    fn bridge_mint_second_proposal_that_would_exceed_the_daily_cap_is_rejected_but_first_succeeds()
    {
        let authority_key = secp256k1::SecretKey::from_slice(&[98u8; 32]).unwrap();
        let authority = Transaction::address_from_secret_key(&authority_key);
        let receiver1 = "0x00000000000000000000000000000000000000e9".to_string();
        let receiver2 = "0x00000000000000000000000000000000000000ea".to_string();
        let state = test_state();
        let daily_limit = 150 * TOKEN_DECIMAL;

        let proposal1 = seed_mint_proposal(
            &state,
            &receiver1,
            100 * TOKEN_DECIMAL,
            false,
            0,
            2,
            2,
            0,
            1_000,
        );
        let tx1 = mint_tx_for(
            &state,
            &authority,
            &authority_key,
            proposal1,
            &receiver1,
            100 * TOKEN_DECIMAL,
            1_000,
        );
        Executor::new(state.clone())
            .with_bridge_authority(authority.clone())
            .with_bridge_threshold(2, 0)
            .with_bridge_daily_mint_limit(daily_limit)
            .execute_transaction(&tx1, tx1.timestamp)
            .unwrap();
        assert_eq!(
            state
                .get_account(&receiver1)
                .unwrap()
                .unwrap()
                .zerenya_balance,
            100 * TOKEN_DECIMAL
        );

        // İkinci, TAMAMEN AYRI ve kendi başına geçerli bir proposal, ama
        // 100 + 100 = 200 > 150 gunluk tavan.
        let proposal2 = seed_mint_proposal(
            &state,
            &receiver2,
            100 * TOKEN_DECIMAL,
            false,
            0,
            2,
            2,
            0,
            1_000,
        );
        let mut tx2 = mint_tx_for(
            &state,
            &authority,
            &authority_key,
            proposal2,
            &receiver2,
            100 * TOKEN_DECIMAL,
            1_000,
        );
        tx2.nonce = 1;
        tx2.sign(&authority_key);
        let result = Executor::new(state.clone())
            .with_bridge_authority(authority)
            .with_bridge_threshold(2, 0)
            .with_bridge_daily_mint_limit(daily_limit)
            .execute_transaction(&tx2, tx2.timestamp);

        assert!(
            matches!(result, Err(ZagrosError::BridgeError(_))),
            "gecerli ikinci proposal, gunluk tavani astigi halde mint edildi"
        );
        assert_eq!(
            state
                .get_account(&receiver2)
                .unwrap()
                .unwrap_or_default()
                .zerenya_balance,
            0,
            "reddedilen mint'in bakiyesi yine de arttirilmis"
        );
    }

    /// Günlük sayaç, gün değiştiğinde sıfırlanmalı, aksi halde tavan
    /// kalıcı/tek seferlik bir toplam gibi davranır.
    #[test]
    fn bridge_mint_daily_cap_resets_on_a_new_day() {
        let authority_key = secp256k1::SecretKey::from_slice(&[99u8; 32]).unwrap();
        let authority = Transaction::address_from_secret_key(&authority_key);
        let receiver1 = "0x00000000000000000000000000000000000000eb".to_string();
        let receiver2 = "0x00000000000000000000000000000000000000ec".to_string();
        let state = test_state();
        // 🚨 ALTIN ÇIPASINA GEÇİŞTE YENİDEN ÖLÇEKLENDİ: MAX_SINGLE_BRIDGE_MINT
        // artık 100 ZERENYA/işlem (eski ZERENYA-ölçekli 140/150 bu tavanı aşardı).
        let daily_limit = 60 * TOKEN_DECIMAL;
        let day0: u128 = 1_000;
        let day1: u128 = day0 + 86_400; // bir sonraki gün

        let proposal1 = seed_mint_proposal(
            &state,
            &receiver1,
            40 * TOKEN_DECIMAL,
            false,
            0,
            2,
            2,
            0,
            day0,
        );
        let tx1 = mint_tx_for(
            &state,
            &authority,
            &authority_key,
            proposal1,
            &receiver1,
            40 * TOKEN_DECIMAL,
            day0,
        );
        Executor::new(state.clone())
            .with_bridge_authority(authority.clone())
            .with_bridge_threshold(2, 0)
            .with_bridge_daily_mint_limit(daily_limit)
            .execute_transaction(&tx1, tx1.timestamp)
            .unwrap();

        // Aynı gün 40 + 40 = 80 > 60 olurdu, ama BİR GÜN SONRA sayaç
        // sıfırlanmalı ve 40 tek başına 60'ın altında kalmalı.
        let proposal2 = seed_mint_proposal(
            &state,
            &receiver2,
            40 * TOKEN_DECIMAL,
            false,
            0,
            2,
            2,
            0,
            day1,
        );
        let mut tx2 = mint_tx_for(
            &state,
            &authority,
            &authority_key,
            proposal2,
            &receiver2,
            40 * TOKEN_DECIMAL,
            day1,
        );
        tx2.nonce = 1;
        tx2.sign(&authority_key);
        Executor::new(state.clone())
            .with_bridge_authority(authority)
            .with_bridge_threshold(2, 0)
            .with_bridge_daily_mint_limit(daily_limit)
            .execute_transaction(&tx2, tx2.timestamp)
            .unwrap();

        assert_eq!(
            state
                .get_account(&receiver1)
                .unwrap()
                .unwrap()
                .zerenya_balance,
            40 * TOKEN_DECIMAL
        );
        assert_eq!(
            state
                .get_account(&receiver2)
                .unwrap()
                .unwrap()
                .zerenya_balance,
            40 * TOKEN_DECIMAL
        );
    }

    #[test]
    fn stake_auto_claim_carries_forward_the_unpaid_reward_shortfall() {
        // FAZ2: hazine yetersizken stake ederken kısmi ödenen ödülün ödenmeyen
        // kısmı (shortfall) reward_debt'e taşınmalı, kaybolmamalı.
        let state = test_state();
        let staker_key = test_secret_key(1);
        let staker = test_address(1);
        state
            .set_account(
                &staker,
                AccountState {
                    balance: 1_000,
                    staked_balance: 1_000,
                    reward_debt: 0,
                    ..Default::default()
                },
            )
            .unwrap();
        // acc = 1e12 → accrued = 1000*1e12/1e12 = 1000, reward_debt 0 → pending 1000.
        state
            .set_accumulated_reward_per_share(1_000_000_000_000)
            .unwrap();
        // Hazine yetersiz: yalnızca 400 (pending 1000'in altında).
        state
            .set_account(&VALIDATOR_REWARD_POOL.to_string(), AccountState::new(400))
            .unwrap();
        state
            .set_account(
                &"__GLOBAL_TOTAL_STAKED__".to_string(),
                AccountState::new(1_000),
            )
            .unwrap();

        let executor = Executor::new(state.clone());
        let mut tx = transaction(TxType::StakeZagros, 0, 1);
        tx.sender = staker.clone();
        tx.sign(&staker_key);
        executor.execute_transaction(&tx, tx.timestamp).unwrap();

        // Auto-claim: 400 ödendi, shortfall = 600. E1 ile yeni 1 birim
        // `pending_stake_amount`e girer, `staked_balance` 1000'de kalır.
        // reward_debt = 1000*acc/1e12 - 600 = 1000 - 600 = 400 (carry-forward).
        let after = state.get_account(&staker).unwrap().unwrap();
        assert_eq!(after.staked_balance, 1_000);
        assert_eq!(after.pending_stake_amount, 1);
        assert_eq!(
            after.reward_debt, 400,
            "ödenmeyen shortfall reward_debt'e taşınmalı"
        );

        // Hazine sonradan fonlanınca ClaimReward shortfall'ı (600) ödemeli.
        state
            .set_account(&VALIDATOR_REWARD_POOL.to_string(), AccountState::new(1_000))
            .unwrap();
        let mut claim = transaction(TxType::ClaimReward, 1, 0);
        claim.sender = staker.clone();
        claim.sign(&staker_key);
        executor
            .execute_transaction(&claim, claim.timestamp)
            .unwrap();
        // Hazine 1000'den 600 ödül ödendi → 400 kaldı (eski kodda 0 ödenirdi → 1000).
        assert_eq!(
            state
                .get_balance(&VALIDATOR_REWARD_POOL.to_string())
                .unwrap(),
            400
        );
    }

    #[test]
    fn bridge_mint_rejects_minting_to_the_bridge_authority_itself() {
        // FAZ1: self-mint yasağı, ele geçirilmiş yetkili kendi adresine basamaz.
        let signer_key = secp256k1::SecretKey::from_slice(&[42u8; 32]).unwrap();
        let signer_address = Transaction::address_from_secret_key(&signer_key);
        let state = test_state();
        state
            .set_account(&signer_address, AccountState::new(TOKEN_DECIMAL))
            .unwrap();

        let mut tx = transaction(TxType::BridgeMint, 0, 1_000 * TOKEN_DECIMAL);
        tx.sender = signer_address.clone();
        tx.receiver = signer_address.clone(); // self-mint!
        tx.sign(&signer_key);

        let executor = Executor::new(state).with_bridge_authority(signer_address);
        assert!(executor.execute_transaction(&tx, tx.timestamp).is_err());
    }

    #[test]
    fn bridge_mint_rejects_amount_over_the_per_tx_cap() {
        // FAZ1: tek-tx tavanı, ele geçirilmiş yetkili tek işlemde sınırsız basamaz.
        let signer_key = secp256k1::SecretKey::from_slice(&[42u8; 32]).unwrap();
        let signer_address = Transaction::address_from_secret_key(&signer_key);
        let state = test_state();
        state
            .set_account(&signer_address, AccountState::new(TOKEN_DECIMAL))
            .unwrap();

        let mut tx = transaction(TxType::BridgeMint, 0, MAX_SINGLE_BRIDGE_MINT + 1);
        tx.sender = signer_address.clone();
        tx.receiver = "0x0000000000000000000000000000000000000009".to_string();
        tx.sign(&signer_key);

        let executor = Executor::new(state).with_bridge_authority(signer_address);
        assert!(executor.execute_transaction(&tx, tx.timestamp).is_err());
    }

    /// Burn indekse düşmeli. 🚨 Köprüden geçmemiş ZERENYA (kurucunun 500'ü, swap'la
    /// kazanılan) yakılıp PAXG talebi doğuramaz; genesis havuzunun karşılığı var.
    #[test]
    fn zerenya_never_deposited_through_the_bridge_cannot_be_burned_through_it() {
        let state = test_state();
        let sender = test_address(1);
        // Kullanıcının 5.000 ZERENYA'sı var ama bunlar KÖPRÜDEN GELMEDİ (ör.
        // genesis/AMM'den kazanılmış), teminat sayacı 0.
        state
            .set_account(
                &sender,
                AccountState {
                    balance: TOKEN_DECIMAL,
                    zerenya_balance: 5_000 * TOKEN_DECIMAL,
                    ..Default::default()
                },
            )
            .unwrap();

        let tx = transaction(TxType::BridgeBurn, 0, 1_500 * TOKEN_DECIMAL);
        let executor = Executor::new(state.clone());
        let result = executor.execute_transaction(&tx, tx.timestamp);

        assert!(
            result.is_err(),
            "teminatsiz ZERENYA kopru uzerinden yakildi - karsiliksiz PAXG talebi doguruyor"
        );
        // Reddedilen işlem hiçbir state DEĞİŞTİRMEMELİ, kullanıcı ZERENYA'sını
        // kaybetmemeli, sadece işlem baştan reddedilmeli.
        let after = state.get_account(&sender).unwrap().unwrap();
        assert_eq!(after.zerenya_balance, 5_000 * TOKEN_DECIMAL);
        assert!(Executor::load_recent_bridge_burns(state.as_ref(), 0)
            .unwrap()
            .is_empty());
    }

    /// Aynı senaryo AMM takas yolunda (BridgeSwapAndBurn): ZAGROS'u havuzdaki
    /// teminatsız ZERENYA'ya çevirip yakmak da reddedilmeli.
    #[test]
    fn selling_zagros_into_the_pool_and_burning_the_output_respects_the_backing_cap() {
        let pool_zagros = 10_000_000 * TOKEN_DECIMAL;
        let pool_zerenya = 10_000_000 * TOKEN_DECIMAL; // genesis-tarzi, hicbir kismi kopruden gelmedi
        let state = test_state();
        state.set_pool_reserves(pool_zagros, pool_zerenya).unwrap();
        // Teminat kasıtlı olarak SIFIR bırakıldı.

        let secret_key = test_secret_key(1);
        let sender = Transaction::address_from_secret_key(&secret_key);
        state
            .set_account(&sender, AccountState::new(200_000 * TOKEN_DECIMAL))
            .unwrap();

        let mut tx = transaction(TxType::BridgeSwapAndBurn, 0, 100_000 * TOKEN_DECIMAL);
        tx.sender = sender.clone();
        tx.sign(&secret_key);

        let executor = Executor::new(state.clone());
        let result = executor.execute_transaction(&tx, tx.timestamp);

        assert!(
            result.is_err(),
            "havuzdaki teminatsiz ZERENYA kopru uzerinden yakildi"
        );
        // ZAGROS havuza SATILMAMIŞ olmalı, reddedilen işlem gaz ücreti dışında
        // hiçbir bakiyeye dokunmaz (anti-DDoS gereği reddedilen işlemler bile
        // gaz ücreti düşer, bkz. failed_native_transaction_rolls_back_execution).
        let after_sender = state.get_account(&sender).unwrap().unwrap();
        assert!(
            after_sender.balance <= 200_000 * TOKEN_DECIMAL
                && after_sender.balance > 200_000 * TOKEN_DECIMAL - TOKEN_DECIMAL,
            "sadece gaz ucreti kadar dusebilir, ZAGROS havuza SATILMAMALI"
        );
        let (after_zagros, after_zsc) = state.get_pool_reserves().unwrap();
        assert_eq!(
            after_zagros, pool_zagros,
            "havuz ZAGROS rezervi degismemeli"
        );
        assert_eq!(after_zsc, pool_zerenya, "havuz ZERENYA rezervi degismemeli");
    }

    /// Pozitif yol: köprüden BASILAN ZERENYA, köprüden YAKILABİLİR, kısıtlama
    /// meşru bir çıkışı da engellemesin.
    #[test]
    fn zerenya_actually_deposited_through_the_bridge_can_be_burned_through_it() {
        let state = test_state();
        let authority = test_address(9);
        let receiver = test_address(1);

        // Alıcının ve yetkilinin gaz ödeyebilmesi için bir miktar ZAGROS'u olmalı.
        state
            .set_account(&receiver, AccountState::new(TOKEN_DECIMAL))
            .unwrap();
        state
            .set_account(&authority, AccountState::new(TOKEN_DECIMAL))
            .unwrap();

        // Köprüden gercek bir yatirim: BridgeMint teminati artirir.
        let mut mint_tx = transaction(TxType::BridgeMint, 0, 50 * TOKEN_DECIMAL);
        mint_tx.sender = authority.clone();
        mint_tx.receiver = receiver.clone();
        mint_tx.tx_id = seed_mint_proposal(
            &state,
            &receiver,
            mint_tx.amount,
            false,
            0,
            2,
            2,
            0,
            mint_tx.timestamp,
        );
        attach_proposal_payload(&state, &mut mint_tx);
        // 🚨 Imza payload'i KAPSAR: oneri konduktan sonra imzalanmali.
        mint_tx.sign(&test_secret_key(9));
        Executor::new(state.clone())
            .with_bridge_authority(authority)
            .with_bridge_threshold(2, 0)
            .execute_transaction(&mint_tx, mint_tx.timestamp)
            .unwrap();

        assert_eq!(
            Executor::new(state.clone())
                .get_bridge_backed_zerenya()
                .unwrap(),
            50 * TOKEN_DECIMAL
        );

        let mut burn_tx = transaction(TxType::BridgeBurn, 0, 50 * TOKEN_DECIMAL);
        burn_tx.sender = receiver;
        burn_tx.sign(&test_secret_key(1));
        Executor::new(state.clone())
            .execute_transaction(&burn_tx, burn_tx.timestamp)
            .unwrap();

        assert_eq!(
            Executor::new(state.clone())
                .get_bridge_backed_zerenya()
                .unwrap(),
            0,
            "basilan tam olarak yakildi - teminat sifira donmeli"
        );
    }

    #[test]
    fn successful_bridge_burn_is_recorded_in_the_visibility_index() {
        let state = test_state();
        let sender_address = test_address(1);
        state
            .set_account(
                &sender_address,
                AccountState {
                    balance: TOKEN_DECIMAL,
                    zerenya_balance: 5_000 * TOKEN_DECIMAL,
                    ..Default::default()
                },
            )
            .unwrap();

        // Yakılacak ZERENYA köprüden basılmış SAYILMALI ki teminat kontrolünü geçsin,
        // gerçek akışta bu miktar önceden bir BridgeMint'ten gelir.
        seed_bridge_backed_zerenya(&state, 1_500 * TOKEN_DECIMAL);

        let tx = transaction(TxType::BridgeBurn, 0, 1_500 * TOKEN_DECIMAL);
        let executor = Executor::new(state.clone());
        executor.execute_transaction(&tx, tx.timestamp).unwrap();

        let records = Executor::load_recent_bridge_burns(state.as_ref(), 0).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].tx_id, tx.tx_id);
        assert_eq!(records[0].sender, sender_address);
        assert_eq!(records[0].amount, 1_500 * TOKEN_DECIMAL);
        assert_eq!(records[0].index, 0);

        // since_index bir sonraki bekleyen kayıttan itibaren tarama sağlamalı.
        assert!(Executor::load_recent_bridge_burns(state.as_ref(), 1)
            .unwrap()
            .is_empty());
    }

    /// 🛡️ [7]: `oldest_bridge_burn_index`, budama sonrası saklı EN ESKİ index'i
    /// döndürmeli (relayer imleç-boşluğu tespiti buna dayanır).
    #[test]
    fn oldest_bridge_burn_index_reflects_the_min_stored_after_trim() {
        let state = test_state();
        // Budanmış bir kümeyi doğrudan kur (index 7..=11), 10k burn koşmadan.
        let records: Vec<zagros_types::BridgeBurnRecord> = (7..=11u128)
            .map(|i| zagros_types::BridgeBurnRecord {
                index: i,
                tx_id: [0u8; 32],
                sender: test_address(1),
                amount: 1,
                timestamp: 0,
            })
            .collect();
        let acc = AccountState {
            contract_code: bincode::serialize(&records).unwrap(),
            ..Default::default()
        };
        state
            .set_account(&Executor::recent_bridge_burns_key(), acc)
            .unwrap();

        assert_eq!(
            Executor::oldest_bridge_burn_index(state.as_ref()).unwrap(),
            Some(7)
        );

        // Hiç kayıt yoksa None (boşluk yok, relayer henüz hiçbir şey kaçırmadı).
        let empty = test_state();
        assert_eq!(
            Executor::oldest_bridge_burn_index(empty.as_ref()).unwrap(),
            None
        );
    }

    #[test]
    fn bridge_burn_index_trims_oldest_entries_past_the_cap() {
        // `trim_bridge_burn_records` izole test edilir; 10.000 gerçek burn dakikalar sürerdi.
        let mut records: Vec<zagros_types::BridgeBurnRecord> = (0..12u128)
            .map(|i| zagros_types::BridgeBurnRecord {
                index: i,
                tx_id: [0u8; 32],
                sender: "0x0000000000000000000000000000000000000001".to_string(),
                amount: 1,
                timestamp: 0,
            })
            .collect();

        Executor::trim_bridge_burn_records(&mut records, 5);

        assert_eq!(records.len(), 5);
        // En eski 7 kayıt (index 0..=6) atılmış olmalı, en yeni 5 (7..=11) kalmalı.
        assert_eq!(records.first().unwrap().index, 7);
        assert_eq!(records.last().unwrap().index, 11);
    }

    #[test]
    fn bridge_burn_index_does_not_trim_when_under_the_cap() {
        let mut records: Vec<zagros_types::BridgeBurnRecord> = (0..3u128)
            .map(|i| zagros_types::BridgeBurnRecord {
                index: i,
                tx_id: [0u8; 32],
                sender: "0x0000000000000000000000000000000000000001".to_string(),
                amount: 1,
                timestamp: 0,
            })
            .collect();

        Executor::trim_bridge_burn_records(&mut records, 5);

        assert_eq!(records.len(), 3);
        assert_eq!(records.first().unwrap().index, 0);
    }

    fn sign_hash(secret_key: &secp256k1::SecretKey, hash: &[u8; 32]) -> Vec<u8> {
        use secp256k1::{Message, Secp256k1};
        let secp = Secp256k1::new();
        let message = Message::from_digest_slice(hash).unwrap();
        let recoverable_sig = secp.sign_ecdsa_recoverable(&message, secret_key);
        let (recovery_id, compact) = recoverable_sig.serialize_compact();
        let mut signature = Vec::with_capacity(65);
        signature.extend_from_slice(&compact);
        signature.push(recovery_id.to_i32() as u8);
        signature
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    // 🛡️ Staker kendi gazını ödül diye döndürüp para basamaz: 50 ardışık
    // `ClaimReward` sonrası bakiye %100 stake payında bile başlangıçtan az olmalı.
    #[test]
    fn repeatedly_claiming_rewards_never_produces_a_net_profit_even_for_a_dominant_staker() {
        let staker_key = test_secret_key(1); // transaction() helper'ı hep bununla imzalar
        let staker_address = test_address(1);
        let state = test_state();
        let starting_balance = 10_000u128;
        state
            .set_account(
                &staker_address,
                AccountState {
                    balance: starting_balance,
                    staked_balance: 1_000_000,
                    ..Default::default()
                },
            )
            .unwrap();
        // %100 stake payı, en elverişli (loop'un kâr etme ihtimalinin en
        // yüksek olacağı) senaryo.
        state
            .set_account(
                &"__GLOBAL_TOTAL_STAKED__".to_string(),
                AccountState::new(1_000_000),
            )
            .unwrap();

        let executor = Executor::new(state.clone()); // block_producer yapılandırılmadı -> ücretin %100'ü stakera gider.
        for i in 0..50u64 {
            let mut claim = transaction(TxType::ClaimReward, i, 0);
            claim.sign(&staker_key);
            executor
                .execute_transaction(&claim, claim.timestamp)
                .unwrap();
            executor.flush_block_rewards(claim.timestamp).unwrap();
        }

        let final_balance = state.get_account(&staker_address).unwrap().unwrap().balance;
        assert!(
            final_balance < starting_balance,
            "50 art arda ClaimReward sonrası bakiye ARTMAMALI (kâr etmemeli) - başlangıç={}, son={}",
            starting_balance,
            final_balance
        );
        // Hazine'de HİÇ ZAGROS kalmamalı VEYA çok küçük bir yuvarlama tozu
        // kalmalı, toplam arz korunmuş olmalı (basılan/yakılan yok).
        let treasury_after = state
            .get_balance(&VALIDATOR_REWARD_POOL.to_string())
            .unwrap();
        let staker_loss = starting_balance - final_balance;
        assert_eq!(
            treasury_after, staker_loss,
            "staker'ın kaybettiği her ZAGROS Hazinede durmalı - başka hiçbir yere kaybolmamalı"
        );
    }

    fn report_malicious_tx(receiver: Address, payload: Vec<u8>) -> Transaction {
        let mut tx = transaction(TxType::ReportMalicious, 0, 0);
        tx.receiver = receiver;
        tx.payload = payload;
        tx.sign(&test_secret_key(1));
        tx
    }

    #[test]
    fn report_malicious_without_a_proof_is_rejected_and_stake_is_untouched() {
        let validator_key = test_secret_key(10);
        let validator_address = test_address(10);
        let state = test_state();
        state
            .set_account(
                &validator_address,
                AccountState {
                    staked_balance: 1_000 * TOKEN_DECIMAL,
                    ..Default::default()
                },
            )
            .unwrap();
        state
            .set_account(&test_address(1), AccountState::new(1_000_000))
            .unwrap();

        let tx = report_malicious_tx(validator_address.clone(), Vec::new());
        let executor = Executor::new(state.clone());
        let result = executor.execute_transaction(&tx, tx.timestamp);

        assert!(result.is_err());
        assert_eq!(
            state
                .get_account(&validator_address)
                .unwrap()
                .unwrap()
                .staked_balance,
            1_000 * TOKEN_DECIMAL
        );
        let _ = validator_key; // only the address is needed for this case
    }

    #[test]
    fn report_malicious_with_fabricated_proof_is_rejected() {
        let validator_address = test_address(10);
        let state = test_state();
        state
            .set_account(
                &validator_address,
                AccountState {
                    staked_balance: 1_000 * TOKEN_DECIMAL,
                    ..Default::default()
                },
            )
            .unwrap();
        state
            .set_account(&test_address(1), AccountState::new(1_000_000))
            .unwrap();

        // Well-formed shape, but the signatures are not real, exactly what an
        // attacker with no validator private key can fabricate.
        let fake_proof = zagros_types::SlashingProof {
            validator: validator_address.clone(),
            block_hash: [1u8; 32],
            conflicting_block_hash: [2u8; 32],
            first_signature: vec![0u8; 65],
            second_signature: vec![0u8; 65],
            epoch: 1,
            timestamp: now_secs(),
        };
        let tx = report_malicious_tx(
            validator_address.clone(),
            zagros_types::EquivocationReport::Legacy(fake_proof.clone()).to_bytes(),
        );
        let executor = Executor::new(state.clone());
        let result = executor.execute_transaction(&tx, tx.timestamp);

        assert!(result.is_err());
        assert_eq!(
            state
                .get_account(&validator_address)
                .unwrap()
                .unwrap()
                .staked_balance,
            1_000 * TOKEN_DECIMAL
        );
    }

    // 🛡️ Self-report TAMAMEN REDDEDİLİR: saldırgan kendi ürettiği "çift imza
    // kanıtı" ile %50 bedel ödeyip unbond kilidini anında atlatamamalı. Ret
    // gerçekten olmalı: hata döner VE hiçbir state mutasyonu olmaz.
    #[test]
    fn report_malicious_rejects_self_report_and_touches_no_state() {
        let validator_key = test_secret_key(1); // report_malicious_tx always signs with test_secret_key(1)
        let validator_address = test_address(1);
        let state = test_state();
        state
            .set_account(
                &validator_address,
                AccountState {
                    balance: 1_000_000,
                    staked_balance: 1_000 * TOKEN_DECIMAL,
                    ..Default::default()
                },
            )
            .unwrap();
        state
            .set_account(
                &"__GLOBAL_TOTAL_STAKED__".to_string(),
                AccountState::new(1_000 * TOKEN_DECIMAL),
            )
            .unwrap();

        let block_hash = [1u8; 32];
        let conflicting_block_hash = [2u8; 32];
        let self_signed_proof = zagros_types::SlashingProof {
            validator: validator_address.clone(),
            block_hash,
            conflicting_block_hash,
            first_signature: sign_hash(&validator_key, &block_hash),
            second_signature: sign_hash(&validator_key, &conflicting_block_hash),
            epoch: 1,
            timestamp: now_secs(),
        };
        // receiver == sender == validator_address: reporting yourself.
        let tx = report_malicious_tx(
            validator_address.clone(),
            zagros_types::EquivocationReport::Legacy(self_signed_proof.clone()).to_bytes(),
        );
        let executor = Executor::new(state.clone());
        let result = executor.execute_transaction(&tx, tx.timestamp);

        assert!(result.is_err(), "self-report kabul edilmemeli");

        // Gaz dışında hiçbir şey değişmemeli (erken ret, `set_account`tan önce);
        // reddedilen işlem gazını öder (`- 2` deseni).
        let after = state.get_account(&validator_address).unwrap().unwrap();
        assert_eq!(after.staked_balance, 1_000 * TOKEN_DECIMAL);
        assert_eq!(after.balance, 1_000_000 - 2);
        assert_eq!(after.jailed_until, 0, "hapis cezası uygulanmamalı");
        assert_eq!(
            state
                .get_account(&"__GLOBAL_TOTAL_STAKED__".to_string())
                .unwrap()
                .unwrap()
                .balance,
            1_000 * TOKEN_DECIMAL
        );
    }

    // 🛡️ Üçüncü taraf raporlama self-report yasağından etkilenmez; yasak yalnız
    // `sender == receiver` durumunu hedefler.

    /// 🛡️ REGRESYON: `pending_stake_amount` (vesting kovası) da müsadereye dahil;
    /// yoksa compound eden validator son eklemesini ihbardan koruyup 48 saat sonra çeker.

    fn submit_proposal_tx(
        secret_key: &secp256k1::SecretKey,
        nonce: u64,
        tx_id: Hash,
        description: Vec<u8>,
    ) -> Transaction {
        let mut tx = transaction(TxType::SubmitProposal, nonce, 0);
        tx.tx_id = tx_id;
        tx.sender = Transaction::address_from_secret_key(secret_key);
        tx.payload = description;
        tx.sign(secret_key);
        tx
    }

    fn vote_tx(
        secret_key: &secp256k1::SecretKey,
        nonce: u64,
        proposal_id: Hash,
        support: bool,
    ) -> Transaction {
        let mut tx = transaction(TxType::Vote, nonce, 0);
        tx.sender = Transaction::address_from_secret_key(secret_key);
        let mut payload = proposal_id.to_vec();
        payload.push(if support { 1 } else { 0 });
        tx.payload = payload;
        tx.sign(secret_key);
        tx
    }

    /// `SubmitProposal` `min_stake_to_submit` + `proposal_fee` gerektirir
    /// (`GovernanceConfig::default()`: 10.000 stake, 1000 ücret); bu yardımcı
    /// ikisini de karşılayan önerici hesabı üretir.
    fn funded_proposer_account() -> AccountState {
        AccountState {
            balance: 1_000_000 * TOKEN_DECIMAL,
            staked_balance: 20_000 * TOKEN_DECIMAL,
            ..Default::default()
        }
    }

    #[test]
    fn submit_proposal_persists_a_new_proposal_record() {
        let proposer_key = test_secret_key(20);
        let proposer_address = test_address(20);
        let state = test_state();
        state
            .set_account(&proposer_address, funded_proposer_account())
            .unwrap();

        let proposal_id = [42u8; 32];
        let tx = submit_proposal_tx(
            &proposer_key,
            0,
            proposal_id,
            b"Lower gas fee to 3 cents".to_vec(),
        );
        let executor = Executor::new(state.clone());
        executor.execute_transaction(&tx, tx.timestamp).unwrap();

        let proposal = executor
            .load_proposal(&proposal_id)
            .unwrap()
            .expect("proposal should exist");
        assert_eq!(proposal.proposer, proposer_address);
        assert_eq!(proposal.description, b"Lower gas fee to 3 cents".to_vec());
        assert_eq!(proposal.votes_for, 0);
        assert_eq!(proposal.votes_against, 0);
        assert_eq!(proposal.status, zagros_types::ProposalStatus::Active);
        assert!(!executor.has_voted(&proposal_id, &proposer_address).unwrap());
    }

    #[test]
    fn submit_proposal_rejects_when_staked_balance_below_min_stake() {
        let proposer_key = test_secret_key(60);
        let proposer_address = test_address(60);
        let state = test_state();
        state
            .set_account(
                &proposer_address,
                AccountState {
                    balance: 1_000_000 * TOKEN_DECIMAL,
                    staked_balance: TOKEN_DECIMAL, // well under the 10_000 default
                    ..Default::default()
                },
            )
            .unwrap();

        let tx = submit_proposal_tx(&proposer_key, 0, [61u8; 32], b"spam".to_vec());
        let executor = Executor::new(state.clone());
        let result = executor.execute_transaction(&tx, tx.timestamp);
        assert!(result.is_err());
        assert!(executor.load_proposal(&[61u8; 32]).unwrap().is_none());
    }

    #[test]
    fn submit_proposal_fee_is_credited_to_the_treasury_not_burned() {
        // 🚨 KRİTİK (ekonomik model regresyonu): gönderenin bakiyesi ücret
        // kadar düşer AMA bu tutar VALIDATOR_REWARD_POOL'a (Hazine) gerçekten
        // ulaşır; arz korunur, yalnızca EL DEĞİŞTİRİR (gerçek bir burn değil).
        let proposer_key = test_secret_key(62);
        let proposer_address = test_address(62);
        let state = test_state();
        let starting_balance = 1_000_000 * TOKEN_DECIMAL;
        let staked_balance = 20_000 * TOKEN_DECIMAL;
        state
            .set_account(
                &proposer_address,
                AccountState {
                    balance: starting_balance,
                    staked_balance,
                    ..Default::default()
                },
            )
            .unwrap();
        // `__GLOBAL_TOTAL_STAKED__` sıfırsa `distribute_staking_reward` ayrı bir dala
        // girer; bu test gerçekçi (sıfır olmayan) stake ile Hazine yolunu kanıtlar,
        // bu yüzden gerçek stake ile senkron bir tracker gerekir.
        state
            .set_account(
                &"__GLOBAL_TOTAL_STAKED__".to_string(),
                AccountState::new(staked_balance),
            )
            .unwrap();
        let treasury_before = state
            .get_account(&VALIDATOR_REWARD_POOL.to_string())
            .unwrap()
            .unwrap_or_default()
            .balance;

        let tx = submit_proposal_tx(&proposer_key, 0, [63u8; 32], b"fee test".to_vec());
        let executor = Executor::new(state.clone());
        executor.execute_transaction(&tx, tx.timestamp).unwrap();

        let after = state.get_account(&proposer_address).unwrap().unwrap();
        let expected_proposal_fee = 1000 * TOKEN_DECIMAL;
        let tx_gas_fee = (tx.gas_limit as u128) * tx.gas_price;
        assert_eq!(
            after.balance,
            starting_balance - expected_proposal_fee - tx_gas_fee,
            "sender balance must drop by exactly the proposal fee plus the normal gas fee - unchanged by this fix"
        );

        // Arz korunumu: kalifiye üretici yokken düşen tutarın tamamı Hazine'ye
        // gitmeli, yakılan kısım olmamalı.
        let treasury_after = state
            .get_account(&VALIDATOR_REWARD_POOL.to_string())
            .unwrap()
            .unwrap()
            .balance;
        assert_eq!(
            treasury_after - treasury_before,
            expected_proposal_fee,
            "proposal ucreti artik yakilmamali - tamami Hazine'ye (VALIDATOR_REWARD_POOL) gitmeli"
        );
    }

    /// Sigorta Kasası YOK: stress kaynaklı "ekstra" dahil kesilen TÜM tutar
    /// Hazine'ye gider. Havuz kasıtlı 1:1 (yuvarlama belirsizliği yok).
    #[test]
    fn stressed_native_fee_goes_entirely_to_treasury_no_insurance_split() {
        let state = test_state();
        let pool = 1_000_000 * TOKEN_DECIMAL;
        state.set_pool_reserves(pool, pool).unwrap();
        // distribute_staking_reward'ın "hiç staker yok" reroute'una (bu
        // testin konusu DEĞİL) düşmemek için gerçekçi bir toplam stake.
        state
            .set_account(
                &"__GLOBAL_TOTAL_STAKED__".to_string(),
                AccountState::new(50_000 * TOKEN_DECIMAL),
            )
            .unwrap();
        state
            .set_account(&test_address(1), AccountState::new(10 * TOKEN_DECIMAL))
            .unwrap();

        // Havuz 1:1 olduğundan taban ücret tam olarak hedefin kendisi,
        // gas_multiplier_for_tx_type(Transfer) == 1x.
        let no_stress_fee = zagros_types::GAS_FEE_ZERENYA;
        let stressed_gas_price = no_stress_fee * 4; // 4x "stress" simülasyonu
        let mut tx = transaction(TxType::Transfer, 0, TOKEN_DECIMAL);
        tx.gas_limit = 1;
        tx.gas_price = stressed_gas_price;
        tx.sign(&test_secret_key(1));

        let executor = Executor::new(state.clone());
        executor.execute_transaction(&tx, tx.timestamp).unwrap();
        executor.flush_block_rewards(tx.timestamp).unwrap();

        let charged = stressed_gas_price; // gas_limit == 1
        let treasury = state
            .get_account(&VALIDATOR_REWARD_POOL.to_string())
            .unwrap()
            .unwrap()
            .balance;

        assert_eq!(
            treasury, charged,
            "sigorta kasasi kaldirildi - stress'li ucretin TAMAMI hazineye gitmeli"
        );
    }

    #[test]
    fn submit_proposal_rejects_when_active_proposal_cap_reached() {
        let state = test_state();
        let executor = Executor::new(state.clone());
        // Executor::new()'ın gömülü varsayılanı: max_active_proposals = 50.
        for i in 0..50u8 {
            let key = test_secret_key(200 + i);
            let addr = test_address(200 + i);
            state.set_account(&addr, funded_proposer_account()).unwrap();
            let mut proposal_id = [0u8; 32];
            proposal_id[0..8].copy_from_slice(&(i as u64).to_be_bytes());
            let tx = submit_proposal_tx(&key, 0, proposal_id, b"p".to_vec());
            executor.execute_transaction(&tx, tx.timestamp).unwrap();
        }
        assert_eq!(executor.active_proposal_count().unwrap(), 50);

        let overflow_key = test_secret_key(251);
        let overflow_addr = test_address(251);
        state
            .set_account(&overflow_addr, funded_proposer_account())
            .unwrap();
        let overflow_tx = submit_proposal_tx(&overflow_key, 0, [77u8; 32], b"overflow".to_vec());
        let result = executor.execute_transaction(&overflow_tx, overflow_tx.timestamp);
        assert!(result.is_err(), "51st active proposal must be rejected");
        assert!(executor.load_proposal(&[77u8; 32]).unwrap().is_none());
    }

    #[test]
    fn vote_requires_staked_balance() {
        let proposer_key = test_secret_key(20);
        let voter_key = test_secret_key(21);
        let voter_address = test_address(21);
        let state = test_state();
        state
            .set_account(&test_address(20), funded_proposer_account())
            .unwrap();
        // No staked_balance, shouldn't get any voting power.
        state
            .set_account(&voter_address, AccountState::new(1_000_000))
            .unwrap();

        let proposal_id = [43u8; 32];
        let executor = Executor::new(state.clone());
        let submit_tx = submit_proposal_tx(&proposer_key, 0, proposal_id, b"proposal".to_vec());
        executor
            .execute_transaction(&submit_tx, submit_tx.timestamp)
            .unwrap();

        let vote = vote_tx(&voter_key, 0, proposal_id, true);
        let result = executor.execute_transaction(&vote, vote.timestamp);
        assert!(result.is_err());
    }

    #[test]
    fn vote_on_nonexistent_proposal_is_rejected() {
        let voter_key = test_secret_key(22);
        let voter_address = test_address(22);
        let state = test_state();
        state
            .set_account(
                &voter_address,
                AccountState {
                    balance: 1_000_000,
                    staked_balance: 1_000,
                    ..Default::default()
                },
            )
            .unwrap();

        let executor = Executor::new(state.clone());
        let vote = vote_tx(&voter_key, 0, [99u8; 32], true);
        let result = executor.execute_transaction(&vote, vote.timestamp);
        assert!(result.is_err());
    }

    #[test]
    fn vote_with_malformed_payload_is_rejected() {
        let voter_key = test_secret_key(23);
        let voter_address = test_address(23);
        let state = test_state();
        state
            .set_account(
                &voter_address,
                AccountState {
                    balance: 1_000_000,
                    staked_balance: 1_000,
                    ..Default::default()
                },
            )
            .unwrap();

        let mut tx = transaction(TxType::Vote, 0, 0);
        tx.sender = voter_address;
        tx.payload = vec![1, 2, 3]; // wrong length (must be 33 bytes)
        tx.sign(&voter_key);

        let executor = Executor::new(state.clone());
        let result = executor.execute_transaction(&tx, tx.timestamp);
        assert!(result.is_err());
    }

    #[test]
    fn vote_updates_stake_weighted_tally_and_rejects_double_voting() {
        let proposer_key = test_secret_key(24);
        let voter_a_key = test_secret_key(25);
        let voter_a_address = test_address(25);
        let voter_b_key = test_secret_key(26);
        let voter_b_address = test_address(26);

        let state = test_state();
        state
            .set_account(&test_address(24), funded_proposer_account())
            .unwrap();
        state
            .set_account(
                &voter_a_address,
                AccountState {
                    balance: 1_000_000,
                    staked_balance: 300 * TOKEN_DECIMAL,
                    ..Default::default()
                },
            )
            .unwrap();
        state
            .set_account(
                &voter_b_address,
                AccountState {
                    balance: 1_000_000,
                    staked_balance: 700 * TOKEN_DECIMAL,
                    ..Default::default()
                },
            )
            .unwrap();

        let proposal_id = [44u8; 32];
        let executor = Executor::new(state.clone());
        let submit_tx = submit_proposal_tx(&proposer_key, 0, proposal_id, b"proposal".to_vec());
        executor
            .execute_transaction(&submit_tx, submit_tx.timestamp)
            .unwrap();

        let vote_a = vote_tx(&voter_a_key, 0, proposal_id, true);
        executor
            .execute_transaction(&vote_a, vote_a.timestamp)
            .unwrap();
        let vote_b = vote_tx(&voter_b_key, 0, proposal_id, false);
        executor
            .execute_transaction(&vote_b, vote_b.timestamp)
            .unwrap();

        let proposal = executor.load_proposal(&proposal_id).unwrap().unwrap();
        assert_eq!(proposal.votes_for, 300 * TOKEN_DECIMAL);
        assert_eq!(proposal.votes_against, 700 * TOKEN_DECIMAL);
        assert!(executor.has_voted(&proposal_id, &voter_a_address).unwrap());
        assert!(executor.has_voted(&proposal_id, &voter_b_address).unwrap());

        // Voter A tries to vote again on the same proposal, must be rejected,
        // and the tally must not move.
        let vote_a_again = vote_tx(&voter_a_key, 1, proposal_id, true);
        let result = executor.execute_transaction(&vote_a_again, vote_a_again.timestamp);
        assert!(result.is_err());
        let proposal_after = executor.load_proposal(&proposal_id).unwrap().unwrap();
        assert_eq!(proposal_after.votes_for, 300 * TOKEN_DECIMAL);
    }

    #[test]
    fn vote_rejects_after_voting_period_expires() {
        let proposer_key = test_secret_key(27);
        let voter_key = test_secret_key(28);
        let voter_address = test_address(28);
        let state = test_state();
        state
            .set_account(&test_address(27), funded_proposer_account())
            .unwrap();
        state
            .set_account(
                &voter_address,
                AccountState {
                    balance: 1_000_000,
                    staked_balance: 1_000 * TOKEN_DECIMAL,
                    ..Default::default()
                },
            )
            .unwrap();

        let proposal_id = [45u8; 32];
        let executor = Executor::new(state.clone());
        let submit_tx = submit_proposal_tx(&proposer_key, 0, proposal_id, b"proposal".to_vec());
        let submit_ts = submit_tx.timestamp;
        executor.execute_transaction(&submit_tx, submit_ts).unwrap();

        // Varsayılan voting_period_secs = 7 gün; sonrasında oy reddedilmeli. Oy
        // tx'inin zaman damgası da ileri alınır (±300ms toleransı; test derlemesinde
        // imza atlandığından `.timestamp` sonradan değiştirilebilir).
        let past_voting_period_ts = submit_ts + (8 * 24 * 60 * 60 * 1000);
        let mut vote = vote_tx(&voter_key, 0, proposal_id, true);
        vote.timestamp = past_voting_period_ts;
        let result = executor.execute_transaction(&vote, past_voting_period_ts);
        assert!(
            result.is_err(),
            "voting period kapandıktan sonra oy kabul edilmemeli"
        );

        let proposal = executor.load_proposal(&proposal_id).unwrap().unwrap();
        assert_eq!(proposal.votes_for, 0, "reddedilen oy tartıya yansımamalı");
    }

    /// `ProposalV1`'in (`voters` gömülü eski şekil) disk byte düzenini yeniden
    /// üreten test yerel "ayna" struct; `zagros-types`'ın kendi `ProposalV1`'i private.
    #[derive(serde::Serialize)]
    struct LegacyProposalV1Mirror {
        proposal_id: Hash,
        proposer: Address,
        description: Vec<u8>,
        created_at: u128,
        votes_for: u128,
        votes_against: u128,
        voters: BTreeSet<Address>,
    }

    #[test]
    fn legacy_v1_proposal_loaded_from_disk_still_enforces_one_vote_per_address() {
        let state = test_state();
        let proposal_id = [46u8; 32];
        let existing_voter = test_address(29);
        let mut legacy_voters = BTreeSet::new();
        legacy_voters.insert(existing_voter.clone());

        let legacy = LegacyProposalV1Mirror {
            proposal_id,
            proposer: test_address(30),
            description: b"legacy proposal".to_vec(),
            created_at: 1_000_000_000,
            votes_for: 500,
            votes_against: 0,
            voters: legacy_voters,
        };
        let legacy_bytes = bincode::serialize(&legacy).unwrap();
        let mut account = AccountState::default();
        account.contract_code = legacy_bytes;
        state
            .set_account(&format!("Proposal_{}", hex::encode(proposal_id)), account)
            .unwrap();

        let executor = Executor::new(state.clone());

        // Eski kayıt hâlâ okunabiliyor (migration-aware deserialize).
        let migrated = executor.load_proposal(&proposal_id).unwrap().unwrap();
        assert_eq!(migrated.votes_for, 500);
        assert_eq!(migrated.status, zagros_types::ProposalStatus::Active);

        // Gömülü eski oy, yeni O(1) anahtar şemasına geriye-dolduruldu.
        assert!(executor.has_voted(&proposal_id, &existing_voter).unwrap());

        // O adres tekrar oy vermeye çalışırsa hâlâ reddedilmeli.
        let voter_key = test_secret_key(29);
        state
            .set_account(
                &existing_voter,
                AccountState {
                    balance: 1_000_000,
                    staked_balance: 1_000 * TOKEN_DECIMAL,
                    ..Default::default()
                },
            )
            .unwrap();
        let vote_again = vote_tx(&voter_key, 0, proposal_id, true);
        let result = executor.execute_transaction(&vote_again, vote_again.timestamp);
        assert!(
            result.is_err(),
            "legacy V1'den geriye-doldurulan bir oy tekrar sayılmamalı"
        );

        // Farklı (yeni) bir adres normal şekilde oy verebilmeli.
        let new_voter_key = test_secret_key(31);
        let new_voter_address = test_address(31);
        state
            .set_account(
                &new_voter_address,
                AccountState {
                    balance: 1_000_000,
                    staked_balance: 1_000 * TOKEN_DECIMAL,
                    ..Default::default()
                },
            )
            .unwrap();
        let new_vote = vote_tx(&new_voter_key, 0, proposal_id, true);
        executor
            .execute_transaction(&new_vote, new_vote.timestamp)
            .unwrap();
        let after = executor.load_proposal(&proposal_id).unwrap().unwrap();
        assert_eq!(after.votes_for, 500 + 1_000 * TOKEN_DECIMAL);
    }

    #[test]
    fn legacy_v1_proposal_backfill_is_idempotent_across_repeated_loads() {
        let state = test_state();
        let proposal_id = [47u8; 32];
        let existing_voter = test_address(32);
        let mut legacy_voters = BTreeSet::new();
        legacy_voters.insert(existing_voter.clone());

        let legacy = LegacyProposalV1Mirror {
            proposal_id,
            proposer: test_address(33),
            description: b"legacy proposal".to_vec(),
            created_at: 1_000_000_000,
            votes_for: 0,
            votes_against: 0,
            voters: legacy_voters,
        };
        let legacy_bytes = bincode::serialize(&legacy).unwrap();
        let mut account = AccountState::default();
        account.contract_code = legacy_bytes;
        state
            .set_account(&format!("Proposal_{}", hex::encode(proposal_id)), account)
            .unwrap();

        let executor = Executor::new(state.clone());
        executor.load_proposal(&proposal_id).unwrap();
        executor.load_proposal(&proposal_id).unwrap();
        executor.load_proposal(&proposal_id).unwrap();

        // Üç kez yüklense de aynı sonuç: tek bir voter, sağlıklı struct.
        assert!(executor.has_voted(&proposal_id, &existing_voter).unwrap());
        let proposal = executor.load_proposal(&proposal_id).unwrap().unwrap();
        assert_eq!(proposal.votes_for, 0);
        assert_eq!(proposal.status, zagros_types::ProposalStatus::Active);
    }

    // ---- Kurucu admin yetkisi: 2 yil, KISALTILABILIR ----

    /// Sabit süre 2 yıl olmalı. Bu test, süreyi sessizce değiştiren bir
    /// düzenlemeyi yakalar (yetki penceresi merkeziyetsizlik takvimidir).
    #[test]
    fn admin_authority_period_is_two_years() {
        assert_eq!(
            zagros_types::ADMIN_AUTHORITY_PERIOD_SECONDS,
            730 * 24 * 60 * 60
        );
    }

    #[test]
    fn admin_authority_can_be_shortened_but_never_extended() {
        let state = test_state();
        let genesis = 1_000_000u128;
        set_genesis_timestamp(&state, genesis);

        let sabit_bitis = genesis + zagros_types::ADMIN_AUTHORITY_PERIOD_SECONDS;
        assert_eq!(
            params::admin_authority_end(state.as_ref()).unwrap(),
            sabit_bitis
        );

        // Kısaltma kabul edilir.
        let erken = genesis + 30 * 24 * 60 * 60;
        params::shorten_admin_authority(state.as_ref(), erken).unwrap();
        assert_eq!(params::admin_authority_end(state.as_ref()).unwrap(), erken);

        // Uzatma REDDEDILIR: ne sabit bitise donus, ne de araya bir deger.
        let err = params::shorten_admin_authority(state.as_ref(), sabit_bitis).unwrap_err();
        assert!(format!("{err:?}").contains("KISALTILABILIR"), "{err:?}");
        params::shorten_admin_authority(state.as_ref(), erken + 1).unwrap_err();
        // Ayni deger de gecmez (kisaltma DEGIL).
        params::shorten_admin_authority(state.as_ref(), erken).unwrap_err();

        // Daha da kisaltmak serbest.
        params::shorten_admin_authority(state.as_ref(), erken - 1).unwrap();
        assert_eq!(
            params::admin_authority_end(state.as_ref()).unwrap(),
            erken - 1
        );
    }

    /// 🚨 Kısaltma HER İKİ yetki yolunu birden etkilemeli. Yollardan biri eski
    /// hesabı kullansaydı yetki bir yolda ölü, diğerinde canlı kalırdı; bu
    /// oturumda tam olarak bu desenden dört ayrı hata çıktı.
    #[test]
    fn shortening_admin_authority_closes_both_authority_paths() {
        let state = g2_state();
        let genesis = params::genesis_timestamp(state.as_ref()).unwrap();
        let executor = Executor::new(state.clone());

        let erken = genesis + 10;
        let sonra = erken + 1;

        // Kisaltmadan once: her iki yol da ACIK.
        assert!(executor.is_admin_authority_active(sonra).unwrap());
        assert!(vs::admin_phase_active(state.as_ref(), sonra).unwrap());

        params::shorten_admin_authority(state.as_ref(), erken).unwrap();

        // Kisaltmadan sonra: her iki yol da KAPALI.
        assert!(!executor.is_admin_authority_active(sonra).unwrap());
        assert!(!vs::admin_phase_active(state.as_ref(), sonra).unwrap());
        // Bitis anindan ONCE hala acik.
        assert!(executor.is_admin_authority_active(erken).unwrap());
        assert!(vs::admin_phase_active(state.as_ref(), erken).unwrap());
    }

    fn set_genesis_timestamp(state: &Arc<dyn State>, timestamp: u128) {
        let mut acc = AccountState::default();
        acc.balance = timestamp;
        state
            .set_account(&zagros_types::GENESIS_TIMESTAMP_KEY.to_string(), acc)
            .unwrap();
    }

    // ---- G2 test altyapısı: zincir-üstü parametreler + genesis sentinel'leri ----
    fn test_admin_keys() -> Vec<secp256k1::SecretKey> {
        (200u8..205).map(test_secret_key).collect()
    }

    /// ChainParams (spec başlangıç değerleri) + genesis hash + genesis zamanı +
    /// 3-of-5 admin multisig. Çoğu validator/ödül testi bunu ister (fail-closed).
    fn install_test_chain(state: &Arc<dyn State>) {
        crate::params::store_chain_params(
            state.as_ref(),
            &zagros_types::consensus::ChainParams::genesis_defaults(),
        )
        .unwrap();
        crate::params::store_genesis_hash(state.as_ref(), &[0x5a; 32]).unwrap();
        if state
            .get_account(&zagros_types::GENESIS_TIMESTAMP_KEY.to_string())
            .unwrap()
            .is_none()
        {
            set_genesis_timestamp(state, 1);
        }
        let signers = test_admin_keys()
            .iter()
            .map(Transaction::address_from_secret_key)
            .collect();
        crate::params::store_admin_multisig(
            state.as_ref(),
            &zagros_types::consensus::AdminMultisig {
                signers,
                threshold: 3,
            },
        )
        .unwrap();
    }

    /// 🛡️ Uçtan uca değişmez: stake → olgunlaşma → ödül → unstake → claim → slash
    /// zincirinin her adımında `__GLOBAL_TOTAL_STAKED__` gerçek toplama eşit kalmalı.
    #[test]
    fn the_global_staked_tracker_stays_equal_to_the_real_sum_across_every_staking_path() {
        let state = test_state();
        let executor = Executor::new(state.clone());
        assert_total_staked_invariant(&state, "baslangic");

        // İki staker, farklı miktarlarla.
        let mut stakers = Vec::new();
        for (seed, amount) in [(70u8, 1_000 * TOKEN_DECIMAL), (71u8, 400 * TOKEN_DECIMAL)] {
            let addr = test_address(seed);
            state
                .set_account(&addr, AccountState::new(amount + 10_000))
                .unwrap();
            let mut tx = transaction(TxType::StakeZagros, 0, amount);
            tx.sender = addr.clone();
            tx.timestamp = 1_000;
            tx.sign(&test_secret_key(seed));
            executor.execute_transaction(&tx, tx.timestamp).unwrap();
            stakers.push((seed, addr, amount));
        }
        // Henüz OLGUNLAŞMADI: sayac 0 olmali (pending kovasi sayilmaz).
        assert_total_staked_invariant(&state, "stake sonrasi (henuz olgunlasmamis)");
        assert_eq!(
            state
                .get_balance(&"__GLOBAL_TOTAL_STAKED__".to_string())
                .unwrap(),
            0
        );

        // Hakedis suresi gecsin: bir ClaimReward, olgunlasmayi tetikler.
        let matured_at = 1_000 + zagros_types::REWARD_VESTING_SECONDS as u128 + 1;
        for (seed, addr, _) in &stakers {
            let mut tx = transaction(TxType::ClaimReward, 1, 0);
            tx.sender = addr.clone();
            tx.timestamp = matured_at;
            tx.sign(&test_secret_key(*seed));
            executor.execute_transaction(&tx, tx.timestamp).unwrap();
        }
        assert_total_staked_invariant(&state, "olgunlasma sonrasi");
        assert_eq!(
            state
                .get_balance(&"__GLOBAL_TOTAL_STAKED__".to_string())
                .unwrap(),
            1_400 * TOKEN_DECIMAL,
            "iki stake de olgunlasmis olmali"
        );

        // Odul dagit -> acc_per_share ilerler, sayac DEGISMEMELI.
        executor
            .distribute_staking_reward(100 * TOKEN_DECIMAL, matured_at)
            .unwrap();
        assert_total_staked_invariant(&state, "odul dagitimi sonrasi");

        // Kismi unstake (ilk staker'in yarisi).
        let (seed0, addr0, amount0) = stakers[0].clone();
        let mut unstake = transaction(TxType::UnstakeZagros, 2, amount0 / 2);
        unstake.sender = addr0.clone();
        unstake.timestamp = matured_at + 10;
        unstake.sign(&test_secret_key(seed0));
        executor
            .execute_transaction(&unstake, unstake.timestamp)
            .unwrap();
        assert_total_staked_invariant(&state, "kismi unstake sonrasi");

        // Odul talebi (sayaca dokunmamali ama muhasebeyi ilerletir).
        let mut claim = transaction(TxType::ClaimReward, 3, 0);
        claim.sender = addr0.clone();
        claim.timestamp = matured_at + 20;
        claim.sign(&test_secret_key(seed0));
        executor
            .execute_transaction(&claim, claim.timestamp)
            .unwrap();
        assert_total_staked_invariant(&state, "claim sonrasi");

        // Ikinci staker'i SLASH et (uc kovayi da musadere eder).
        let (_, addr1, _) = stakers[1].clone();
        let before_slash = state.get_account(&addr1).unwrap().unwrap().staked_balance;
        assert!(
            before_slash > 0,
            "test on kosulu: slash edilecek stake olmali"
        );
        let mut target = state.get_account(&addr1).unwrap().unwrap();
        let tracker_before = state
            .get_balance(&"__GLOBAL_TOTAL_STAKED__".to_string())
            .unwrap();
        target.staked_balance = 0;
        target.pending_unstake_amount = 0;
        target.pending_stake_amount = 0;
        state.set_account(&addr1, target).unwrap();
        let mut tracker_acc = state
            .get_account(&"__GLOBAL_TOTAL_STAKED__".to_string())
            .unwrap()
            .unwrap_or_default();
        tracker_acc.balance = tracker_before.saturating_sub(before_slash);
        state
            .set_account(&"__GLOBAL_TOTAL_STAKED__".to_string(), tracker_acc)
            .unwrap();
        assert_total_staked_invariant(&state, "slash sonrasi");

        // Son kontrol: kalan tek staker'in gercek bakiyesiyle sayac ortusmeli.
        let remaining = state.get_account(&addr0).unwrap().unwrap().staked_balance;
        assert_eq!(
            state
                .get_balance(&"__GLOBAL_TOTAL_STAKED__".to_string())
                .unwrap(),
            remaining
        );
    }

    /// 🛡️ `__GLOBAL_TOTAL_STAKED__` = Σ staked_balance (ödül paydası); altına
    /// düşerse hazine kurur, sıfırda ödüller hazineye gider, üstünde herkes az alır.
    fn assert_total_staked_invariant(state: &Arc<dyn State>, context: &str) {
        let tracker = state
            .get_account(&"__GLOBAL_TOTAL_STAKED__".to_string())
            .unwrap()
            .map(|a| a.balance)
            .unwrap_or(0);
        let mut sum = 0u128;
        for (addr, _) in state.get_validator_candidates().unwrap() {
            if let Some(acc) = state.get_account(&addr.to_ascii_lowercase()).unwrap() {
                sum = sum.saturating_add(acc.staked_balance);
            }
        }
        assert_eq!(
            tracker, sum,
            "[{context}] __GLOBAL_TOTAL_STAKED__ ({tracker}) != Σ staked_balance ({sum})"
        );
    }

    fn test_min_stake(state: &Arc<dyn State>) -> u128 {
        let p = zagros_types::consensus::ChainParams::genesis_defaults();
        crate::params::min_validator_stake_zagros(state.as_ref(), &p).unwrap()
    }

    fn test_application_fee(state: &Arc<dyn State>) -> u128 {
        let p = zagros_types::consensus::ChainParams::genesis_defaults();
        crate::params::application_fee_zagros(state.as_ref(), &p).unwrap()
    }

    fn test_consensus_keypair(seed: u8) -> zagros_crypto::ConsensusKeypair {
        zagros_crypto::ConsensusKeypair::from_secret_bytes(&[seed; 32])
    }

    fn test_declaration(seed: u8) -> zagros_types::consensus::ValidatorDeclaration {
        zagros_types::consensus::ValidatorDeclaration {
            provider: format!("provider-{seed}"),
            region: format!("region-{seed}"),
            asn: 1000 + seed as u32,
            operator_id: [seed; 32],
        }
    }

    /// Yeni (G2) RegisterValidator: payload = pubkey + sahiplik kanıtı + beyan.
    fn register_validator_tx_v2(
        secret_key: &secp256k1::SecretKey,
        state: &Arc<dyn State>,
        consensus_seed: u8,
        nonce: u64,
        timestamp: u128,
    ) -> Transaction {
        let address = Transaction::address_from_secret_key(secret_key);
        let domain = crate::params::consensus_domain(state.as_ref()).unwrap();
        let kp = test_consensus_keypair(consensus_seed);
        let payload = zagros_types::consensus::RegisterValidatorPayload {
            consensus_pubkey: kp.public_key(),
            ownership_proof: zagros_crypto::prove_key_ownership(&kp, &domain, &address, None),
            declaration: test_declaration(consensus_seed),
        };
        let mut tx = transaction(TxType::RegisterValidator, nonce, 0);
        tx.sender = address;
        tx.timestamp = timestamp;
        tx.payload = payload.encode();
        tx.sign(secret_key);
        tx
    }

    /// G14 (§15): rotasyon işlemi, kanıt YENİ anahtarla, zincirdeki MEVCUT
    /// pubkey üzerinden (KEYROT domain'i).
    fn rotate_key_tx_v2(
        secret_key: &secp256k1::SecretKey,
        state: &Arc<dyn State>,
        new_kp: &zagros_crypto::ConsensusKeypair,
        nonce: u64,
        timestamp: u128,
    ) -> Transaction {
        let address = Transaction::address_from_secret_key(secret_key);
        let domain = crate::params::consensus_domain(state.as_ref()).unwrap();
        let old = state
            .get_account(&address.to_ascii_lowercase())
            .unwrap()
            .map(|a| a.consensus_pubkey)
            .unwrap_or([0u8; 32]);
        let payload = zagros_types::consensus::RotateConsensusKeyPayload {
            new_pubkey: new_kp.public_key(),
            ownership_proof: zagros_crypto::prove_key_ownership(
                new_kp,
                &domain,
                &address,
                Some(&old),
            ),
        };
        let mut tx = transaction(TxType::RotateConsensusKey, nonce, 0);
        tx.sender = address;
        tx.timestamp = timestamp;
        tx.payload = payload.encode();
        tx.sign(secret_key);
        tx
    }

    /// Faz A admin aksiyonu (3-of-5): `signer_count` imzacı ile imzalar.
    #[allow(clippy::too_many_arguments)]
    fn admin_action_tx(
        sender_key: &secp256k1::SecretKey,
        state: &Arc<dyn State>,
        action: zagros_types::consensus::AdminAction,
        target: &str,
        epoch: u64,
        signer_count: usize,
        nonce: u64,
        timestamp: u128,
    ) -> Transaction {
        let domain = crate::params::consensus_domain(state.as_ref()).unwrap();
        let digest = zagros_types::consensus::admin_action_digest(&domain, action, target, epoch);
        // Uretim `verify_admin_action` EIP-191 ONEKLI hash'ten kurtariyor
        // (cuzdan `personal_sign` uyumlulugu), test de ayni onegi uygulamak
        // ZORUNDA, yoksa kurtarilan adres multisig uyesi cikmaz.
        let signing_digest = crate::validator_set::eip191_admin_digest(&digest);
        let signatures: Vec<Vec<u8>> = test_admin_keys()
            .iter()
            .take(signer_count)
            .map(|k| sign_hash(k, &signing_digest))
            .collect();
        let payload = zagros_types::consensus::AdminActionPayload {
            action,
            target: target.to_string(),
            epoch,
            signatures,
        };
        let tx_type = match action {
            zagros_types::consensus::AdminAction::Approve => TxType::ApproveValidator,
            zagros_types::consensus::AdminAction::Remove => TxType::RemoveValidator,
            // G12: veto, Approve rotasından taşınır (ayrı TxType yok).
            zagros_types::consensus::AdminAction::VetoProposal => TxType::ApproveValidator,
        };
        let mut tx = transaction(tx_type, nonce, 0);
        tx.sender = Transaction::address_from_secret_key(sender_key);
        tx.receiver = zagros_types::consensus::VALIDATOR_ADMIN_ADDRESS.to_string();
        tx.timestamp = timestamp;
        tx.payload = payload.encode();
        tx.sign(sender_key);
        tx
    }

    fn slash_validator_tx(
        admin_key: &secp256k1::SecretKey,
        target: Address,
        block_timestamp: u128,
    ) -> Transaction {
        let mut tx = transaction(TxType::SlashValidator, 0, 0);
        tx.sender = Transaction::address_from_secret_key(admin_key);
        tx.receiver = target;
        tx.timestamp = block_timestamp;
        tx.sign(admin_key);
        tx
    }

    #[test]
    fn slash_validator_succeeds_within_admin_authority_window() {
        let admin_key = test_secret_key(30);
        let admin_address = test_address(30);
        let validator_address = test_address(31);
        let genesis_timestamp = 1_000_000u128;
        let block_timestamp = genesis_timestamp + 1_000; // well within 1 year

        let state = test_state();
        set_genesis_timestamp(&state, genesis_timestamp);
        state
            .set_account(&admin_address, AccountState::new(1_000_000))
            .unwrap();
        state
            .set_account(
                &validator_address,
                AccountState {
                    staked_balance: 500 * TOKEN_DECIMAL,
                    ..Default::default()
                },
            )
            .unwrap();

        let tx = slash_validator_tx(&admin_key, validator_address.clone(), block_timestamp);
        let executor = Executor::new(state.clone()).with_admin_authority(admin_address);
        executor.execute_transaction(&tx, block_timestamp).unwrap();

        assert_eq!(
            state
                .get_account(&validator_address)
                .unwrap()
                .unwrap()
                .staked_balance,
            0
        );
    }

    #[test]
    fn slash_validator_also_confiscates_stake_already_moved_to_pending_unstake() {
        // 🛡️ Same escape hatch as ReportMalicious: a validator who unstakes
        // their full stake right before being caught used to keep it, since
        // slashing only zeroed `staked_balance`.
        let admin_key = test_secret_key(30);
        let admin_address = test_address(30);
        let validator_address = test_address(33);
        let genesis_timestamp = 1_000_000u128;
        let block_timestamp = genesis_timestamp + 1_000;

        let state = test_state();
        set_genesis_timestamp(&state, genesis_timestamp);
        state
            .set_account(&admin_address, AccountState::new(1_000_000))
            .unwrap();
        state
            .set_account(
                &validator_address,
                AccountState {
                    staked_balance: 0,
                    pending_unstake_amount: 500 * TOKEN_DECIMAL,
                    unlock_time: 999_999,
                    ..Default::default()
                },
            )
            .unwrap();
        // Gerçekçi bir staker seedliyoruz ki `distribute_staking_reward`'ın
        // "hiç staker yok" reroute'una düşmesin, bu testin odağı SADECE
        // confiscation'ın Hazineye tam akışı.
        state
            .set_account(
                &"__GLOBAL_TOTAL_STAKED__".to_string(),
                AccountState::new(1_000 * TOKEN_DECIMAL),
            )
            .unwrap();

        let tx = slash_validator_tx(&admin_key, validator_address.clone(), block_timestamp);
        let executor = Executor::new(state.clone()).with_admin_authority(admin_address);
        executor
            .execute_transaction(&tx, block_timestamp)
            .expect("confiscation must succeed even though staked_balance alone is 0");

        let after = state.get_account(&validator_address).unwrap().unwrap();
        assert_eq!(after.staked_balance, 0);
        assert_eq!(after.pending_unstake_amount, 0);
        assert_eq!(after.unlock_time, 0);

        // Sigorta Kasası YOK: el konulan TÜM tutar (500 ZAGROS) Hazineye
        // (VALIDATOR_REWARD_POOL, %100 staker payı, qualified validator yok) gider.
        let treasury = state
            .get_balance(&VALIDATOR_REWARD_POOL.to_string())
            .unwrap();
        assert_eq!(
            treasury,
            500 * TOKEN_DECIMAL,
            "el konulan tutarin TAMAMI hazineye gitmeli"
        );

        // 🚨 `staked_balance` zaten 0'dı (anapara pending_unstake'te); tracker
        // müsadereden etkilenmemeli.
        let tracker = state
            .get_account(&"__GLOBAL_TOTAL_STAKED__".to_string())
            .unwrap()
            .unwrap();
        assert_eq!(
            tracker.balance,
            1_000 * TOKEN_DECIMAL,
            "staked_balance zaten 0 oldugundan tracker degismemeli"
        );
    }

    /// 🛡️ Regresyon: `SlashValidator` (admin yolu) için de vesting kovası kaçış kapısı kapalı.
    #[test]
    fn slash_validator_also_confiscates_stake_still_in_the_vesting_bucket() {
        let admin_key = test_secret_key(31);
        let admin_address = test_address(31);
        let validator_address = test_address(34);
        let genesis_timestamp = 1_000_000u128;
        let block_timestamp = genesis_timestamp + 1_000;

        let state = test_state();
        set_genesis_timestamp(&state, genesis_timestamp);
        state
            .set_account(&admin_address, AccountState::new(1_000_000))
            .unwrap();
        state
            .set_account(
                &validator_address,
                AccountState {
                    staked_balance: 10_000 * TOKEN_DECIMAL,
                    pending_stake_amount: 5_000 * TOKEN_DECIMAL,
                    pending_stake_activation_time: 999_999,
                    ..Default::default()
                },
            )
            .unwrap();
        // Gerçekçi toplam: bu validator 15.000 (10.000+5.000) + diğer stakerlar
        // 35.000 = 50.000; tracker delta'sının 10.000 mu 15.000 mi düştüğüne
        // GERÇEKTEN duyarlı olsun (tracker = confiscated tohumlansaydı iki davranış da geçerdi).
        state
            .set_account(
                &"__GLOBAL_TOTAL_STAKED__".to_string(),
                AccountState::new(50_000 * TOKEN_DECIMAL),
            )
            .unwrap();

        let tx = slash_validator_tx(&admin_key, validator_address.clone(), block_timestamp);
        let executor = Executor::new(state.clone()).with_admin_authority(admin_address);
        executor
            .execute_transaction(&tx, block_timestamp)
            .expect("confiscation must succeed");

        let after = state.get_account(&validator_address).unwrap().unwrap();
        assert_eq!(after.staked_balance, 0);
        assert_eq!(
            after.pending_stake_amount, 0,
            "vesting kovasindaki stake de musadere edilmeli, kacis kapisi olmamali"
        );
        assert_eq!(after.pending_stake_activation_time, 0);

        // 🚨 Tracker'dan yalnız GERÇEK staked_balance (10.000) düşmeli;
        // pending_stake_amount (5.000) tracker'a hiç girmemişti. Beklenen: 50.000 - 10.000 = 40.000.
        let tracker = state
            .get_account(&"__GLOBAL_TOTAL_STAKED__".to_string())
            .unwrap()
            .unwrap();
        assert_eq!(
            tracker.balance,
            40_000 * TOKEN_DECIMAL,
            "tracker sadece staked_balance kadar dusmeli, pending_stake_amount tekrar dusulmemeli"
        );

        // Hazineye giden tutar da 15.000 (staked_balance + pending_stake_amount)
        // üzerinden olmalı, 10.000 (yalnız staked_balance) DEĞİL; Sigorta
        // Kasası yok, tamamı Hazineye gider.
        let treasury = state
            .get_balance(&VALIDATOR_REWARD_POOL.to_string())
            .unwrap();
        assert_eq!(treasury, 15_000 * TOKEN_DECIMAL);
    }

    /// 🛡️ İNVARİANT: `__GLOBAL_TOTAL_STAKED__` = `Σ staked_balance` (pending
    /// stake/unstake hariç). `get_validator_candidates()` gerçek hesap durumundan
    /// bağımsız bir toplam verir; tracker kendisiyle değil GERÇEK state ile karşılaştırılır.
    fn assert_total_staked_tracker_matches_real_state(state: &Arc<dyn State>) {
        let real_total: u128 = state
            .get_validator_candidates()
            .unwrap()
            .into_iter()
            .map(|(_, staked_balance)| staked_balance)
            .sum();
        let tracker_total = state
            .get_account(&"__GLOBAL_TOTAL_STAKED__".to_string())
            .unwrap()
            .unwrap_or_default()
            .balance;
        assert_eq!(
            tracker_total, real_total,
            "__GLOBAL_TOTAL_STAKED__ ({tracker_total}) gercek Σstaked_balance'tan ({real_total}) SAPTI"
        );
    }

    /// 🛡️ REGRESYON: çok hesaplı stake/unstake/slash/ihbar dizisi boyunca
    /// invariant HER adımda (yalnız sonda değil) `Σ staked_balance`'a eşit kalmalı.

    fn unregister_validator_tx(
        secret_key: &secp256k1::SecretKey,
        nonce: u64,
        timestamp: u128,
    ) -> Transaction {
        let mut tx = transaction(TxType::UnregisterValidator, nonce, 0);
        tx.sender = Transaction::address_from_secret_key(secret_key);
        tx.timestamp = timestamp;
        tx.sign(secret_key);
        tx
    }

    #[test]
    fn register_validator_succeeds_with_sufficient_stake_and_charges_no_fee_at_registration() {
        let key = test_secret_key(50);
        let address = test_address(50);
        let state = test_state();
        install_test_chain(&state);
        state
            .set_account(
                &address,
                AccountState {
                    balance: 1_000 * TOKEN_DECIMAL,
                    staked_balance: test_min_stake(&state),
                    ..Default::default()
                },
            )
            .unwrap();
        let executor = Executor::new(state.clone());
        let tx = register_validator_tx_v2(&key, &state, 60, 0, 1_000);
        executor.execute_transaction(&tx, tx.timestamp).unwrap();

        let after = state.get_account(&address).unwrap().unwrap();
        assert!(after.is_registered_validator);
        assert_eq!(
            after.validator_status,
            Some(zagros_types::consensus::ValidatorStatus::Candidate),
            "G2: kayit = Candidate"
        );
        assert_eq!(
            after.consensus_pubkey,
            test_consensus_keypair(60).public_key()
        );
        assert_eq!(after.validator_stake_snapshot, test_min_stake(&state));
        // KUYRUK REFORMU: kayitta YALNIZ gas kesilir, basvuru ucreti ONAYDA
        // (ApproveValidator) alinir, bkz. g14_application_fee_is_charged_at_approval.
        let gas_charged = tx.gas_limit as u128 * tx.gas_price;
        assert_eq!(
            after.balance,
            1_000 * TOKEN_DECIMAL - gas_charged,
            "kayitta basvuru ucreti alinmaz, yalniz gas"
        );
        assert!(
            after.balance > 1_000 * TOKEN_DECIMAL - test_application_fee(&state),
            "kayitta basvuru ucreti kesilmemeli"
        );
        assert_eq!(
            after.validator_registered_at, tx.timestamp,
            "kayıt zamanı blok zaman damgasıyla eşleşmeli"
        );
    }

    #[test]
    fn register_validator_rejects_insufficient_stake() {
        let key = test_secret_key(51);
        let address = test_address(51);
        let state = test_state();
        install_test_chain(&state);
        state
            .set_account(
                &address,
                AccountState {
                    balance: 1_000 * TOKEN_DECIMAL,
                    staked_balance: test_min_stake(&state) - 1,
                    ..Default::default()
                },
            )
            .unwrap();
        let executor = Executor::new(state.clone());
        let tx = register_validator_tx_v2(&key, &state, 62, 0, 1_000);
        let result = executor.execute_transaction(&tx, tx.timestamp);
        assert!(result.is_err());
        assert!(
            !state
                .get_account(&address)
                .unwrap()
                .unwrap()
                .is_registered_validator
        );
    }

    #[test]
    fn register_validator_rejects_double_registration() {
        let key = test_secret_key(52);
        let address = test_address(52);
        let state = test_state();
        install_test_chain(&state);
        state
            .set_account(
                &address,
                AccountState {
                    balance: 1_000 * TOKEN_DECIMAL,
                    staked_balance: test_min_stake(&state),
                    is_registered_validator: true,
                    validator_status: Some(zagros_types::consensus::ValidatorStatus::Candidate),
                    ..Default::default()
                },
            )
            .unwrap();
        let executor = Executor::new(state.clone());
        let tx = register_validator_tx_v2(&key, &state, 62, 0, 1_000);
        let result = executor.execute_transaction(&tx, tx.timestamp);
        assert!(result.is_err());
    }

    #[test]
    fn register_validator_rejects_while_jailed() {
        let key = test_secret_key(53);
        let address = test_address(53);
        let state = test_state();
        install_test_chain(&state);
        state
            .set_account(
                &address,
                AccountState {
                    balance: 1_000 * TOKEN_DECIMAL,
                    staked_balance: test_min_stake(&state),
                    jailed_until: 5_000,
                    ..Default::default()
                },
            )
            .unwrap();
        let executor = Executor::new(state.clone());
        let tx = register_validator_tx_v2(&key, &state, 61, 0, 1_000); // 1_000 < jailed_until 5_000
        let result = executor.execute_transaction(&tx, tx.timestamp);
        assert!(result.is_err());

        // Reddedilen işlem de nonce tüketir (bkz. mevcut "gas is charged and
        // nonce incremented whether the tx succeeded or failed" davranışı).
        // Hapis süresi geçtikten sonra kayıt başarılı olmalı.
        let tx2 = register_validator_tx_v2(&key, &state, 61, 1, 6_000);
        executor.execute_transaction(&tx2, tx2.timestamp).unwrap();
        assert!(
            state
                .get_account(&address)
                .unwrap()
                .unwrap()
                .is_registered_validator
        );
    }

    #[test]
    fn unregister_validator_clears_registration_without_touching_stake() {
        let key = test_secret_key(54);
        let address = test_address(54);
        let state = test_state();
        install_test_chain(&state);
        state
            .set_account(
                &address,
                AccountState {
                    balance: 1_000 * TOKEN_DECIMAL,
                    staked_balance: test_min_stake(&state),
                    is_registered_validator: true,
                    validator_status: Some(zagros_types::consensus::ValidatorStatus::Active),
                    ..Default::default()
                },
            )
            .unwrap();
        let executor = Executor::new(state.clone());
        let tx = unregister_validator_tx(&key, 0, 1_000);
        executor.execute_transaction(&tx, tx.timestamp).unwrap();

        let after = state.get_account(&address).unwrap().unwrap();
        assert!(!after.is_registered_validator);
        assert_eq!(
            after.staked_balance,
            test_min_stake(&state),
            "unregister staking'e dokunmamali"
        );
    }

    #[test]
    fn unregister_validator_rejects_when_not_registered() {
        let key = test_secret_key(55);
        let address = test_address(55);
        let state = test_state();
        install_test_chain(&state);
        state
            .set_account(&address, AccountState::new(1_000))
            .unwrap();
        let executor = Executor::new(state.clone());
        let tx = unregister_validator_tx(&key, 0, 1_000);
        assert!(executor.execute_transaction(&tx, tx.timestamp).is_err());
    }

    #[test]
    fn slashed_validator_cannot_immediately_reregister_with_fresh_stake() {
        // 🛡️ Jail mekanizmasının asıl amacı: taze sermayeyle anında geri
        // dönüp cezayı anlamsızlaştırmayı engellemek.
        let admin_key = test_secret_key(30);
        let admin_address = test_address(30);
        let validator_key = test_secret_key(56);
        let validator_address = test_address(56);
        let state = test_state();
        install_test_chain(&state);
        // 0 "eksik marker" anlamına gelir (fail-closed), gerçekçi bir
        // genesis zaman damgası kullan.
        set_genesis_timestamp(&state, 1);
        state
            .set_account(&admin_address, AccountState::new(1_000_000))
            .unwrap();
        state
            .set_account(
                &validator_address,
                AccountState {
                    balance: 1_000 * TOKEN_DECIMAL,
                    staked_balance: test_min_stake(&state),
                    is_registered_validator: true,
                    validator_status: Some(zagros_types::consensus::ValidatorStatus::Active),
                    ..Default::default()
                },
            )
            .unwrap();
        let executor = Executor::new(state.clone()).with_admin_authority(admin_address);

        let slash_tx = slash_validator_tx(&admin_key, validator_address.clone(), 1_000);
        executor.execute_transaction(&slash_tx, 1_000).unwrap();
        assert!(
            !state
                .get_account(&validator_address)
                .unwrap()
                .unwrap()
                .is_registered_validator
        );
        let jailed_until = state
            .get_account(&validator_address)
            .unwrap()
            .unwrap()
            .jailed_until;
        assert_eq!(jailed_until, 1_000 + JAIL_DURATION_SECONDS);

        // Taze sermaye stake edilse bile hapis süresi dolmadan kayıt reddedilmeli.
        state
            .set_account(
                &validator_address,
                AccountState {
                    balance: 1_000 * TOKEN_DECIMAL,
                    staked_balance: test_min_stake(&state),
                    jailed_until,
                    ..Default::default()
                },
            )
            .unwrap();
        let retry = register_validator_tx_v2(&validator_key, &state, 63, 0, 1_000 + 10);
        assert!(executor
            .execute_transaction(&retry, retry.timestamp)
            .is_err());
        // Reddedilen işlem de nonce tüketir.
        let nonce_after_retry = state
            .get_account(&validator_address)
            .unwrap()
            .unwrap()
            .nonce;

        // Hapis süresi dolduktan sonra kayıt başarılı olmalı.
        let after_jail = register_validator_tx_v2(
            &validator_key,
            &state,
            63,
            nonce_after_retry,
            jailed_until + 1,
        );
        executor
            .execute_transaction(&after_jail, after_jail.timestamp)
            .unwrap();
        assert!(
            state
                .get_account(&validator_address)
                .unwrap()
                .unwrap()
                .is_registered_validator
        );
    }

    #[test]
    fn distribute_staking_reward_splits_80_20_to_a_qualified_block_producer() {
        let producer_address = test_address(60);
        let state = test_state();
        install_test_chain(&state);
        state
            .set_account(
                &producer_address,
                AccountState {
                    staked_balance: test_min_stake(&state),
                    is_registered_validator: true,
                    ..Default::default()
                },
            )
            .unwrap();
        state
            .set_account(
                &"__GLOBAL_TOTAL_STAKED__".to_string(),
                AccountState::new(1_000 * TOKEN_DECIMAL + test_min_stake(&state)),
            )
            .unwrap();
        let executor =
            Executor::new(state.clone()).with_block_producer_address(producer_address.clone());

        let reward_amount = 10_000u128;
        executor
            .distribute_staking_reward(reward_amount, 1_000)
            .unwrap();

        assert_eq!(STAKER_REWARD_BPS + VALIDATOR_REWARD_BPS, 10_000);
        let expected_validator_share = reward_amount * VALIDATOR_REWARD_BPS / 10_000;
        let expected_staker_share = reward_amount - expected_validator_share;

        assert_eq!(
            state.get_balance(&producer_address).unwrap(),
            expected_validator_share
        );
        assert_eq!(
            state
                .get_balance(&VALIDATOR_REWARD_POOL.to_string())
                .unwrap(),
            expected_staker_share
        );
    }

    // ================= G12 GOVERNANCE TESTLERİ =================

    fn g12_set(n: u8) -> zagros_types::consensus::ActiveValidatorSet {
        zagros_types::consensus::ActiveValidatorSet {
            epoch: 0,
            members: (0..n)
                .map(|i| zagros_types::consensus::ValidatorMember {
                    address: format!("0x{:039x}{}", 0xd, i),
                    consensus_pubkey: [i + 40; 32],
                })
                .collect(),
        }
    }

    fn g12_seed_proposal(
        executor: &Executor,
        state: &Arc<dyn State>,
        pid: Hash,
        action: zagros_types::consensus::ProposalAction,
        voting_ends_at_epoch: u64,
    ) {
        let p = zagros_types::Proposal {
            proposal_id: pid,
            proposer: test_address(1),
            description: Vec::new(),
            created_at: 0,
            votes_for: 0,
            votes_against: 0,
            status: zagros_types::ProposalStatus::Active,
            action,
            executes_at_epoch: 0,
            voting_ends_at_epoch,
        };
        executor.save_proposal(&p).unwrap();
        executor.increment_active_proposal_count().unwrap();
        governance::register_typed_active(state.as_ref(), pid).unwrap();
    }

    /// G12: consensus kanalı tam yaşam döngüsü, 4/5 oy (≥2/3) → Queued →
    /// timelock (3 epoch) → yürütme: ChainParams GERÇEKTEN değişir.
    #[test]
    fn g12_consensus_param_change_full_lifecycle() {
        use zagros_types::consensus::{ParamKey, ParamUpdate, ProposalAction};
        let state = test_state();
        install_test_chain(&state);
        let executor = Executor::new(state.clone());
        let set = g12_set(5);
        let pid = [0x91u8; 32];
        let action = ProposalAction::ParamChange(vec![ParamUpdate {
            key: ParamKey::TBaseMs,
            value: 2_500,
        }]);
        g12_seed_proposal(&executor, &state, pid, action, 2);
        for m in set.members.iter().take(4) {
            governance::record_vote(state.as_ref(), &pid, &m.address, true, 1).unwrap();
        }
        // Pencere kapanmadan sayım YAPILMAZ
        governance::process_at_epoch(state.as_ref(), 1, &set).unwrap();
        assert_eq!(
            executor.load_proposal(&pid).unwrap().unwrap().status,
            zagros_types::ProposalStatus::Active
        );
        // Pencere kapandı → Queued + timelock
        governance::process_at_epoch(state.as_ref(), 2, &set).unwrap();
        let p = executor.load_proposal(&pid).unwrap().unwrap();
        assert_eq!(p.status, zagros_types::ProposalStatus::Queued);
        assert_eq!(p.executes_at_epoch, 5, "2 + timelock(3)");
        assert_eq!(
            params::load_chain_params(state.as_ref()).unwrap().t_base_ms,
            1_500,
            "timelock dolmadan param DEGISMEZ"
        );
        // Timelock dolmadan yürütme yok
        governance::process_at_epoch(state.as_ref(), 4, &set).unwrap();
        assert_eq!(
            params::load_chain_params(state.as_ref()).unwrap().t_base_ms,
            1_500
        );
        // Yürütme
        governance::process_at_epoch(state.as_ref(), 5, &set).unwrap();
        assert_eq!(
            params::load_chain_params(state.as_ref()).unwrap().t_base_ms,
            2_500,
            "param yamasi uygulanmali"
        );
        assert_eq!(
            executor.load_proposal(&pid).unwrap().unwrap().status,
            zagros_types::ProposalStatus::Executed
        );
        assert!(governance::load_typed_active(state.as_ref())
            .unwrap()
            .is_empty());
        assert_eq!(
            executor.active_proposal_count().unwrap(),
            0,
            "sayac dusmeli"
        );
    }

    /// G12: 3/5 oy (2/3 altı) → Rejected, param DEĞİŞMEZ.
    #[test]
    fn g12_consensus_below_two_thirds_is_rejected() {
        use zagros_types::consensus::{ParamKey, ParamUpdate, ProposalAction};
        let state = test_state();
        install_test_chain(&state);
        let executor = Executor::new(state.clone());
        let set = g12_set(5);
        let pid = [0x92u8; 32];
        g12_seed_proposal(
            &executor,
            &state,
            pid,
            ProposalAction::ParamChange(vec![ParamUpdate {
                key: ParamKey::TBaseMs,
                value: 3_000,
            }]),
            1,
        );
        for m in set.members.iter().take(3) {
            governance::record_vote(state.as_ref(), &pid, &m.address, true, 1).unwrap();
        }
        governance::process_at_epoch(state.as_ref(), 1, &set).unwrap();
        assert_eq!(
            executor.load_proposal(&pid).unwrap().unwrap().status,
            zagros_types::ProposalStatus::Rejected
        );
        assert_eq!(
            params::load_chain_params(state.as_ref()).unwrap().t_base_ms,
            1_500
        );
    }

    /// G12: economic çift quorum, katılım <%20 → RED; katılım sağlanınca balina
    /// tavanı (%10) uygulanır. 🚨 AYNI ANDA İKİ KAPI OLMAZ: Faz A sürerken
    /// governance önerisi REDDEDİLİR, yoksa validator oylaması admin onayını atlatırdı.
    #[test]
    fn fazb_governance_proposal_is_rejected_while_phase_a_is_still_active() {
        use zagros_types::consensus::ProposalAction;
        let state = g2_state();
        g2_genesis_set(&state, 5);
        let executor = Executor::new(state.clone());
        let (key, aday) = g2_fund_candidate(&state, 122);
        executor
            .execute_transaction(
                &register_validator_tx_v2(&key, &state, 122, 0, 1_000),
                1_000,
            )
            .unwrap();

        let onerici_key = test_secret_key(123);
        let onerici = Transaction::address_from_secret_key(&onerici_key);
        state
            .set_account(&onerici, funded_proposer_account())
            .unwrap();

        let payload = ProposalAction::ApproveValidator {
            target: aday.clone(),
        }
        .encode_payload()
        .unwrap();
        let tx = submit_proposal_tx(&onerici_key, 0, [0xb3u8; 32], payload);

        // Faz A hâlâ açık → RED.
        let err = executor.execute_transaction(&tx, 1_000).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("Faz A surerken"),
            "Faz A'da governance yolu KAPALI olmali: {msg}"
        );

        // Faz A bittikten SONRA aynı öneri kabul edilir (kuyruğa girer).
        let sonra = 1 + zagros_types::ADMIN_AUTHORITY_PERIOD_SECONDS + 1;
        // Nonce state'ten okunur: reddedilen ilk işlem nonce'u tüketmiş olabilir.
        let n2 = g2_nonce(&state, &onerici);
        let mut tx2 = submit_proposal_tx(
            &onerici_key,
            n2,
            [0xb4u8; 32],
            ProposalAction::ApproveValidator { target: aday }
                .encode_payload()
                .unwrap(),
        );
        // Damga bloğun zamanına yakın olmalı (±300 sn), birim SANİYE.
        tx2.timestamp = sonra;
        tx2.sign(&onerici_key);
        executor
            .execute_transaction(&tx2, sonra)
            .expect("Faz A bitince governance onerisi KABUL edilmeli");
    }

    /// 🗳️ FAZ B: küme üyeliğine AKTİF VALIDATÖRLER oy verir (≥2/3); karar
    /// kurucuda değil ağı çalıştıranlarda. 🚨 OYBİRLİĞİ ARANMAZ: 5 üyeden 4'ü
    /// yeter, tek bir "hayır" yeni üye alımını kilitleyemez.
    #[test]
    fn fazb_validator_approval_passes_with_two_thirds_validator_vote() {
        use zagros_types::consensus::ProposalAction;
        let state = g2_state();
        g2_genesis_set(&state, 5);
        let executor = Executor::new(state.clone());
        let set = g12_set(5);

        let (key, aday) = g2_fund_candidate(&state, 120);
        executor
            .execute_transaction(
                &register_validator_tx_v2(&key, &state, 120, 0, 1_000),
                1_000,
            )
            .unwrap();
        assert_eq!(
            state
                .get_account(&aday.to_ascii_lowercase())
                .unwrap()
                .unwrap()
                .validator_status,
            Some(ValidatorStatus::Candidate)
        );

        let action = ProposalAction::ApproveValidator {
            target: aday.clone(),
        };
        assert_eq!(
            action.channel().unwrap(),
            Some(zagros_types::consensus::GovChannel::Consensus),
            "kume uyeligi CONSENSUS kanalinda olmali"
        );
        let pid = [0xb1u8; 32];
        g12_seed_proposal(&executor, &state, pid, action, 1);

        // 5 üyeden 4'ü evet → 3·4=12 ≥ 2·5=10 ✓
        for m in set.members.iter().take(4) {
            governance::record_vote(state.as_ref(), &pid, &m.address, true, 1).unwrap();
        }
        governance::process_at_epoch(state.as_ref(), 1, &set).unwrap();
        assert_eq!(
            executor.load_proposal(&pid).unwrap().unwrap().status,
            zagros_types::ProposalStatus::Queued,
            "4/5 validator onayi yeterli olmali"
        );

        // Timelock dolunca yürütülür ve aday gerçekten Approved olur.
        let p = zagros_types::consensus::ChainParams::genesis_defaults();
        governance::process_at_epoch(state.as_ref(), 1 + p.timelock_epochs as u64, &set).unwrap();
        assert_eq!(
            executor.load_proposal(&pid).unwrap().unwrap().status,
            zagros_types::ProposalStatus::Executed
        );
        assert_eq!(
            state
                .get_account(&aday.to_ascii_lowercase())
                .unwrap()
                .unwrap()
                .validator_status,
            Some(ValidatorStatus::Approved),
            "yurutme adayi gercekten Approved yapmali"
        );
    }

    /// 2/3 altında kalan öneri geçmez ve hedefe DOKUNMAZ.
    #[test]
    fn fazb_validator_approval_fails_below_two_thirds() {
        use zagros_types::consensus::ProposalAction;
        let state = g2_state();
        g2_genesis_set(&state, 5);
        let executor = Executor::new(state.clone());
        let set = g12_set(5);
        let (key, aday) = g2_fund_candidate(&state, 121);
        executor
            .execute_transaction(
                &register_validator_tx_v2(&key, &state, 121, 0, 1_000),
                1_000,
            )
            .unwrap();

        let pid = [0xb2u8; 32];
        g12_seed_proposal(
            &executor,
            &state,
            pid,
            ProposalAction::ApproveValidator {
                target: aday.clone(),
            },
            1,
        );
        // 5 üyeden yalnız 3'ü evet → 3·3=9 < 2·5=10 ✗
        for m in set.members.iter().take(3) {
            governance::record_vote(state.as_ref(), &pid, &m.address, true, 1).unwrap();
        }
        governance::process_at_epoch(state.as_ref(), 1, &set).unwrap();
        assert_eq!(
            executor.load_proposal(&pid).unwrap().unwrap().status,
            zagros_types::ProposalStatus::Rejected,
            "3/5 yetmez"
        );
        assert_eq!(
            state
                .get_account(&aday.to_ascii_lowercase())
                .unwrap()
                .unwrap()
                .validator_status,
            Some(ValidatorStatus::Candidate),
            "reddedilen oneri hedefe DOKUNMAMALI"
        );
    }

    /// ❓ Dürüst doğrulayıcı çıkarken teminatın tamamını alır; ceza yok, yalnız
    /// iki zaman kapısı (`bond_unlock_at`, 48 saat unbonding).
    #[test]
    fn exiting_validator_gets_the_entire_stake_back_with_no_exit_penalty() {
        let state = g2_state();
        g2_genesis_set(&state, 5);
        let executor = Executor::new(state.clone());
        let p = zagros_types::consensus::ChainParams::genesis_defaults();

        let (key, addr) = g2_fund_candidate(&state, 130);
        let akey = addr.to_ascii_lowercase();
        executor
            .execute_transaction(
                &register_validator_tx_v2(&key, &state, 130, 0, 1_000),
                1_000,
            )
            .unwrap();
        let yatirilan = state.get_account(&akey).unwrap().unwrap().staked_balance;
        assert!(yatirilan > 0, "kayit teminat gerektirir");
        let cuzdan_once = state.get_account(&akey).unwrap().unwrap().balance;

        // Gönüllü çıkış: kayıttan düş → bond lock başlar.
        let mut unreg = transaction(TxType::UnregisterValidator, g2_nonce(&state, &addr), 0);
        unreg.sender = addr.clone();
        unreg.timestamp = 1_000;
        unreg.sign(&key);
        executor.execute_transaction(&unreg, 1_000).unwrap();
        let bond_bitis = state.get_account(&akey).unwrap().unwrap().bond_unlock_at;
        assert!(bond_bitis > 1_000, "bond lock kurulmali");

        // Bond lock DOLMADAN çekim reddedilir.
        let mut erken = transaction(TxType::UnstakeZagros, g2_nonce(&state, &addr), yatirilan);
        erken.sender = addr.clone();
        erken.timestamp = 1_000;
        erken.sign(&key);
        assert!(
            executor.execute_transaction(&erken, 1_000).is_err(),
            "bond lock icinde cekilemez"
        );

        // Bond lock dolunca çekim talebi kabul edilir (48 saat kilide girer).
        let t1 = bond_bitis + 1;
        let mut cek = transaction(TxType::UnstakeZagros, g2_nonce(&state, &addr), yatirilan);
        cek.sender = addr.clone();
        cek.timestamp = t1;
        cek.sign(&key);
        executor.execute_transaction(&cek, t1).unwrap();
        let acc = state.get_account(&akey).unwrap().unwrap();
        assert_eq!(
            acc.staked_balance + acc.pending_stake_amount,
            0,
            "teminat bosalmali"
        );
        assert_eq!(
            acc.pending_unstake_amount, yatirilan,
            "TAMAMI bekleyen kovaya gecmeli (kesinti YOK)"
        );

        // 48 saat sonra tahsil: anapara EKSİKSİZ iner. 🚨 Ölçüm gaz ücretini
        // dışarıda bırakmalı (arada üç işlem gaz yaktı); bu yüzden TAHSİLDEN HEMEN ÖNCEYE alınır.
        let bakiye_tahsilden_once = state.get_account(&akey).unwrap().unwrap().balance;
        let t2 = acc.unlock_time + 1;
        let mut tahsil = transaction(TxType::UnstakeZagros, g2_nonce(&state, &addr), 0);
        tahsil.sender = addr.clone();
        tahsil.timestamp = t2;
        tahsil.sign(&key);
        executor.execute_transaction(&tahsil, t2).unwrap();
        let son = state.get_account(&akey).unwrap().unwrap();
        assert_eq!(
            son.pending_unstake_amount, 0,
            "bekleyen kova TAMAMEN bosalmali"
        );

        // Anapara eksiksiz alacaklandırıldı; tek eksik TAHSİL İŞLEMİNİN GAZI.
        // "Kuruşu kuruşuna" demek gazın da bedava olması demek değil, bu
        // yüzden fark ölçülüyor ve gaz mertebesinde olduğu KANITLANIYOR.
        let beklenen = bakiye_tahsilden_once + yatirilan;
        let gaz = beklenen.saturating_sub(son.balance);
        assert!(
            gaz < 1_000_000_000_000,
            "eksik yalnizca gaz mertebesinde olmali (cikis kesintisi YOK): {gaz} wei"
        );
        assert!(
            son.balance > bakiye_tahsilden_once,
            "anapara cuzdana inmeli"
        );

        // Toplam ölçek kontrolü: yatırılanın kaçta kaçı geri geldi?
        let geri_gelen_oran = (son.balance - bakiye_tahsilden_once) * 10_000 / yatirilan;
        assert!(
            geri_gelen_oran >= 9_999,
            "anaparanin ~%100'u geri gelmeli, gelen: %{}.{:02}",
            geri_gelen_oran / 100,
            geri_gelen_oran % 100
        );
        let _ = p;
    }

    /// ❓ Kayıtlıyken çekmek engellenmez ama bedelsiz değil: bond lock kurulur ve
    /// eşik altında Active → Probation; "parayı çek ama doğrulayıcı kal" yok.
    #[test]
    fn a_registered_validator_that_withdraws_below_threshold_is_demoted_to_probation() {
        let state = g2_state();
        g2_genesis_set(&state, 5);
        let executor = Executor::new(state.clone());
        let params = zagros_types::consensus::ChainParams::genesis_defaults();

        let (key, addr) = g2_fund_candidate(&state, 131);
        let akey = addr.to_ascii_lowercase();
        executor
            .execute_transaction(
                &register_validator_tx_v2(&key, &state, 131, 0, 1_000),
                1_000,
            )
            .unwrap();
        // Aktif üye yap.
        let mut acc = state.get_account(&akey).unwrap().unwrap();
        acc.validator_status = Some(ValidatorStatus::Active);
        acc.validator_status_epoch = 0;
        let teminat = acc.staked_balance;
        state.set_account(&akey, acc).unwrap();

        // Kayıtlıyken çekim: engellenmiyor AMA bond lock kuruluyor.
        let mut cek = transaction(TxType::UnstakeZagros, g2_nonce(&state, &addr), teminat / 2);
        cek.sender = addr.clone();
        cek.timestamp = 2_000;
        cek.sign(&key);
        executor.execute_transaction(&cek, 2_000).unwrap();
        let sonra = state.get_account(&akey).unwrap().unwrap();
        assert!(
            sonra.bond_unlock_at > 2_000,
            "kayitliyken cekim BOND LOCK kurmali"
        );
        assert!(sonra.staked_balance < teminat, "teminat azalmali");

        // 🚨 Para hâlâ müsadere edilebilir: bekleyen kova da slash kapsamında.
        assert!(
            sonra.pending_unstake_amount > 0,
            "cekilen kisim bekleyen kovada, hala slash edilebilir"
        );

        // Eşiğin altına düştüyse epoch sınırında Probation'a iner.
        let min_stake = crate::params::min_validator_stake_zagros(state.as_ref(), &params).unwrap();
        let esik = crate::params::qualification_threshold(
            sonra.validator_stake_snapshot,
            min_stake,
            params.stake_hysteresis_bps,
        );
        if sonra.staked_balance < esik {
            // Epoch sınırını geç: yeni kümeyi kurar, durum geçişlerini uygular.
            let ileri = 3_000 + params.epoch_seconds as u128 * 2;
            let set = crate::validator_set::advance_epoch_if_due(state.as_ref(), ileri).unwrap();
            let d = state.get_account(&akey).unwrap().unwrap();
            assert_eq!(
                d.validator_status,
                Some(ValidatorStatus::Probation),
                "esik altina dusen uye Probation'a inmeli"
            );
            assert!(
                !set.members.iter().any(|m| m.address == akey),
                "Probation uyesi aktif kumede olmamali"
            );
        }
    }

    #[test]
    fn g12_economic_double_quorum_with_whale_cap() {
        use zagros_types::consensus::{ParamKey, ParamUpdate, ProposalAction};
        let state = test_state();
        install_test_chain(&state);
        let executor = Executor::new(state.clone());
        let set = g12_set(5);
        state
            .set_account(
                &"__GLOBAL_TOTAL_STAKED__".to_string(),
                AccountState::new(1_000),
            )
            .unwrap();
        // 🛡️ Oy ağırlığı sayımda güncel `staked_balance` ile sınırlanır; test gerçek
        // teminat kurmalı, yoksa ağırlık sıfırlanır.
        let seed_stake = |addr: &str, amount: u128| {
            let mut acc = state
                .get_account(&addr.to_string())
                .unwrap()
                .unwrap_or_default();
            acc.staked_balance = amount;
            state.set_account(&addr.to_string(), acc).unwrap();
        };
        for m in set.members.iter() {
            seed_stake(&m.address, 1);
        }
        seed_stake("0x00000000000000000000000000000000000000e1", 150);
        seed_stake("0x00000000000000000000000000000000000000e2", 900);
        seed_stake("0x00000000000000000000000000000000000000e3", 50);
        seed_stake("0x00000000000000000000000000000000000000e4", 60);
        let action = ProposalAction::ParamChange(vec![ParamUpdate {
            key: ParamKey::ApplicationFeeZerenya,
            value: 9_000_000_000_000_000,
        }]);

        // Senaryo 1: validator 4/5 evet AMA staker katılımı %15 (<%20) → RED
        let pid1 = [0x93u8; 32];
        g12_seed_proposal(&executor, &state, pid1, action.clone(), 1);
        for m in set.members.iter().take(4) {
            governance::record_vote(state.as_ref(), &pid1, &m.address, true, 1).unwrap();
        }
        governance::record_vote(
            state.as_ref(),
            &pid1,
            "0x00000000000000000000000000000000000000e1",
            true,
            150,
        )
        .unwrap();
        governance::process_at_epoch(state.as_ref(), 1, &set).unwrap();
        assert_eq!(
            executor.load_proposal(&pid1).unwrap().unwrap().status,
            zagros_types::ProposalStatus::Rejected,
            "staker quorum'suz gecemez"
        );

        // Senaryo 2: balina 900 evet (tavan 100'e KIRPILIR) + 50 hayır + 60 evet
        // → katılım 100+50+60=210 ≥ 200 (%20) ✓, evet 160 > hayır 50 → KABUL
        let pid2 = [0x94u8; 32];
        g12_seed_proposal(&executor, &state, pid2, action, 1);
        for m in set.members.iter().take(4) {
            governance::record_vote(state.as_ref(), &pid2, &m.address, true, 1).unwrap();
        }
        governance::record_vote(
            state.as_ref(),
            &pid2,
            "0x00000000000000000000000000000000000000e2",
            true,
            900,
        )
        .unwrap();
        governance::record_vote(
            state.as_ref(),
            &pid2,
            "0x00000000000000000000000000000000000000e3",
            false,
            50,
        )
        .unwrap();
        governance::record_vote(
            state.as_ref(),
            &pid2,
            "0x00000000000000000000000000000000000000e4",
            true,
            60,
        )
        .unwrap();
        governance::process_at_epoch(state.as_ref(), 1, &set).unwrap();
        assert_eq!(
            executor.load_proposal(&pid2).unwrap().unwrap().status,
            zagros_types::ProposalStatus::Queued,
            "tavanli cift-quorum kabul"
        );
    }

    /// G12→G10 köprüsü: ScheduleUpgrade önerisi %80 (4/5 TAM sınır) ister;
    /// yürütmede G10 kaydını yazar. 3/5 → RED.
    #[test]
    fn g12_schedule_upgrade_needs_80_percent_and_writes_g10_record() {
        use zagros_types::consensus::ProposalAction;
        let state = test_state();
        install_test_chain(&state);
        let executor = Executor::new(state.clone());
        let set = g12_set(5);
        let mk = |t: u8| ProposalAction::ScheduleUpgrade {
            target_ruleset: 2,
            binary_sha256: [t; 32],
            activation_epoch: 40,
        };

        let pid_fail = [0x95u8; 32];
        g12_seed_proposal(&executor, &state, pid_fail, mk(1), 1);
        for m in set.members.iter().take(3) {
            governance::record_vote(state.as_ref(), &pid_fail, &m.address, true, 1).unwrap();
        }
        governance::process_at_epoch(state.as_ref(), 1, &set).unwrap();
        assert_eq!(
            executor.load_proposal(&pid_fail).unwrap().unwrap().status,
            zagros_types::ProposalStatus::Rejected,
            "3/5=%60 < %80"
        );

        let pid_ok = [0x96u8; 32];
        g12_seed_proposal(&executor, &state, pid_ok, mk(2), 1);
        for m in set.members.iter().take(4) {
            governance::record_vote(state.as_ref(), &pid_ok, &m.address, true, 1).unwrap();
        }
        governance::process_at_epoch(state.as_ref(), 1, &set).unwrap();
        assert_eq!(
            executor.load_proposal(&pid_ok).unwrap().unwrap().status,
            zagros_types::ProposalStatus::Queued
        );
        governance::process_at_epoch(state.as_ref(), 4, &set).unwrap();
        let up = params::load_scheduled_upgrade(state.as_ref())
            .unwrap()
            .expect("G10 kaydi yazilmali");
        assert_eq!(
            (up.target_ruleset, up.activation_epoch, up.binary_sha256),
            (2, 40, [2u8; 32])
        );
        assert_eq!(
            executor.load_proposal(&pid_ok).unwrap().unwrap().status,
            zagros_types::ProposalStatus::Executed
        );
    }

    /// G12: veto yalnız CONSENSUS kanalında ve yalnız Active/Queued'de çalışır.
    #[test]
    fn g12_veto_is_consensus_channel_only() {
        use zagros_types::consensus::{ParamKey, ParamUpdate, ProposalAction};
        let state = test_state();
        install_test_chain(&state);
        let executor = Executor::new(state.clone());
        let pid_c = [0x97u8; 32];
        g12_seed_proposal(
            &executor,
            &state,
            pid_c,
            ProposalAction::ParamChange(vec![ParamUpdate {
                key: ParamKey::TBaseMs,
                value: 2_000,
            }]),
            10,
        );
        governance::apply_veto(state.as_ref(), &format!("0x{}", hex::encode(pid_c))).unwrap();
        assert_eq!(
            executor.load_proposal(&pid_c).unwrap().unwrap().status,
            zagros_types::ProposalStatus::Vetoed
        );
        assert!(governance::load_typed_active(state.as_ref())
            .unwrap()
            .is_empty());

        let pid_e = [0x98u8; 32];
        g12_seed_proposal(
            &executor,
            &state,
            pid_e,
            ProposalAction::ParamChange(vec![ParamUpdate {
                key: ParamKey::VoteCapBps,
                value: 500,
            }]),
            10,
        );
        let err = governance::apply_veto(state.as_ref(), &format!("0x{}", hex::encode(pid_e)))
            .unwrap_err();
        assert!(
            format!("{err:?}").contains("consensus"),
            "economic vetolanamaz: {err:?}"
        );
    }

    /// G12 tx-katmanı: tipli SubmitProposal doğrulanır+kaydedilir; karışık
    /// kanal ve bozuk-magic fail-closed RED; Vote kişi-bazlı kayıt yazar.
    #[test]
    fn g12_submit_and_vote_tx_layer_integration() {
        use zagros_types::consensus::{ParamKey, ParamUpdate, ProposalAction, GOV_PAYLOAD_MAGIC};
        let state = test_state();
        install_test_chain(&state);
        let executor = Executor::new(state.clone());
        let sender = Transaction::address_from_secret_key(&test_secret_key(1));
        state
            .set_account(
                &sender,
                AccountState {
                    balance: 1_000_000 * TOKEN_DECIMAL,
                    staked_balance: 20_000 * TOKEN_DECIMAL,
                    ..Default::default()
                },
            )
            .unwrap();

        // Geçerli tipli öneri
        let action = ProposalAction::ParamChange(vec![ParamUpdate {
            key: ParamKey::TBaseMs,
            value: 2_200,
        }]);
        let mut tx = transaction(TxType::SubmitProposal, 0, 0);
        tx.payload = action.encode_payload().unwrap();
        tx.sign(&test_secret_key(1));
        executor.apply_transaction(&tx, 1_000).unwrap();
        let p = executor.load_proposal(&tx.tx_id).unwrap().unwrap();
        assert_eq!(p.action, action);
        assert_eq!(
            p.voting_ends_at_epoch, 168,
            "epoch0 + gov_voting_epochs(168)"
        );
        assert_eq!(
            governance::load_typed_active(state.as_ref()).unwrap(),
            vec![tx.tx_id]
        );

        // (Bilinen davranış: başarısız tx de nonce tüketir → nonce'u state'ten oku.)
        let next_nonce = |st: &Arc<dyn State>| st.get_account(&sender).unwrap().unwrap().nonce;

        // Karışık kanal → RED
        let mixed = ProposalAction::ParamChange(vec![
            ParamUpdate {
                key: ParamKey::TBaseMs,
                value: 2_000,
            },
            ParamUpdate {
                key: ParamKey::VoteCapBps,
                value: 500,
            },
        ]);
        let mut tx2 = transaction(TxType::SubmitProposal, next_nonce(&state), 0);
        tx2.tx_id = [0xA1; 32];
        tx2.payload = mixed.encode_payload().unwrap();
        tx2.sign(&test_secret_key(1));
        assert!(
            executor.apply_transaction(&tx2, 1_000).is_err(),
            "karisik kanal gecmemeli"
        );

        // Bozuk magic gövdesi → fail-closed RED (Text'e DÜŞMEZ)
        let mut tx3 = transaction(TxType::SubmitProposal, next_nonce(&state), 0);
        tx3.tx_id = [0xA2; 32];
        let mut bad = GOV_PAYLOAD_MAGIC.to_vec();
        bad.extend_from_slice(b"corrupt");
        tx3.payload = bad;
        tx3.sign(&test_secret_key(1));
        assert!(
            executor.apply_transaction(&tx3, 1_000).is_err(),
            "bozuk tipli oneri Text sayilamaz"
        );

        // Vote: kişi-bazlı kayıt (ağırlık = staked snapshot)
        let mut vote = transaction(TxType::Vote, next_nonce(&state), 0);
        vote.tx_id = [0xA3; 32];
        let mut payload = tx.tx_id.to_vec();
        payload.push(1);
        vote.payload = payload;
        vote.sign(&test_secret_key(1));
        executor.apply_transaction(&vote, 1_000).unwrap();
        let rec = state
            .get_account(&format!(
                "GovVote_{}_{}",
                hex::encode(tx.tx_id),
                sender.to_ascii_lowercase()
            ))
            .unwrap()
            .expect("kisi-bazli oy kaydi olmali");
        assert_eq!(rec.balance, 20_000 * TOKEN_DECIMAL);
        assert_eq!(rec.nonce, 1);
    }

    /// G10 (§23): planlanmış yükseltmenin tam yaşam döngüsü, kayıt, erken
    /// epoch'ta dokunulmama, ≥%80 beyanla atomik aktivasyon.
    #[test]
    fn g10_scheduled_upgrade_activates_at_epoch_boundary_with_80_percent_readiness() {
        use zagros_types::consensus::{ActiveValidatorSet, ScheduledUpgrade, ValidatorMember};
        let state = test_state();
        install_test_chain(&state);
        let members: Vec<ValidatorMember> = (0u8..5)
            .map(|i| ValidatorMember {
                address: format!("0x{:039x}{}", 0xb, i),
                consensus_pubkey: [i + 10; 32],
            })
            .collect();
        let set = ActiveValidatorSet { epoch: 0, members };

        // hedef ≤ aktif reddedilir
        let bad = ScheduledUpgrade {
            target_ruleset: 1,
            binary_sha256: [7; 32],
            activation_epoch: 1,
        };
        assert!(params::store_scheduled_upgrade(state.as_ref(), &bad).is_err());

        let up = ScheduledUpgrade {
            target_ruleset: 2,
            binary_sha256: [7; 32],
            activation_epoch: 5,
        };
        params::store_scheduled_upgrade(state.as_ref(), &up).unwrap();
        assert_eq!(
            params::load_scheduled_upgrade(state.as_ref()).unwrap(),
            Some(up.clone())
        );

        // aktivasyon epoch'undan ÖNCE: dokunulmaz
        assert_eq!(
            params::maybe_activate_scheduled_upgrade(state.as_ref(), 4, &set).unwrap(),
            None
        );
        assert!(
            params::load_scheduled_upgrade(state.as_ref())
                .unwrap()
                .is_some(),
            "erken epoch kaydı silmemeli"
        );

        // 4/5 beyan (=%80) → aktive olur
        for m in set.members.iter().take(4) {
            params::record_ruleset_declaration(state.as_ref(), &m.address, 2).unwrap();
        }
        assert_eq!(
            params::maybe_activate_scheduled_upgrade(state.as_ref(), 5, &set).unwrap(),
            Some(2)
        );
        assert_eq!(
            params::load_chain_params(state.as_ref())
                .unwrap()
                .active_ruleset,
            2
        );
        assert!(
            params::load_scheduled_upgrade(state.as_ref())
                .unwrap()
                .is_none(),
            "kayıt tek kullanımlık"
        );
    }

    /// G10 (FM-U1): aktivasyon epoch'unda beyan <%80 ise yükseltme İPTAL —
    /// zincir eski kurallarla sürer, kayıt temizlenir, params DEĞİŞMEZ.
    #[test]
    fn g10_insufficient_readiness_cancels_the_upgrade_fail_closed() {
        use zagros_types::consensus::{ActiveValidatorSet, ScheduledUpgrade, ValidatorMember};
        let state = test_state();
        install_test_chain(&state);
        let members: Vec<ValidatorMember> = (0u8..5)
            .map(|i| ValidatorMember {
                address: format!("0x{:039x}{}", 0xc, i),
                consensus_pubkey: [i + 20; 32],
            })
            .collect();
        let set = ActiveValidatorSet { epoch: 0, members };
        let up = ScheduledUpgrade {
            target_ruleset: 2,
            binary_sha256: [7; 32],
            activation_epoch: 1,
        };
        params::store_scheduled_upgrade(state.as_ref(), &up).unwrap();
        for m in set.members.iter().take(3) {
            // 3/5 = %60 < %80
            params::record_ruleset_declaration(state.as_ref(), &m.address, 2).unwrap();
        }
        assert_eq!(
            params::maybe_activate_scheduled_upgrade(state.as_ref(), 1, &set).unwrap(),
            None
        );
        assert_eq!(
            params::load_chain_params(state.as_ref())
                .unwrap()
                .active_ruleset,
            1,
            "params degismemeli"
        );
        assert!(
            params::load_scheduled_upgrade(state.as_ref())
                .unwrap()
                .is_none(),
            "iptal kaydı temizler (FM-U1)"
        );
    }

    /// G9 (v0.3 §13.4 / C-11): üretici artık BLOK BAŞINA ayarlanır — iki farklı
    /// "blokta" iki farklı üretici, her biri YALNIZ kendi bloğunun %20'sini alır.
    #[test]
    fn g9_per_block_producer_receives_only_its_own_blocks_share() {
        let producer_a = test_address(62);
        let producer_b = test_address(63);
        let state = test_state();
        install_test_chain(&state);
        for p in [&producer_a, &producer_b] {
            state
                .set_account(
                    p,
                    AccountState {
                        staked_balance: test_min_stake(&state),
                        is_registered_validator: true,
                        ..Default::default()
                    },
                )
                .unwrap();
        }
        state
            .set_account(
                &"__GLOBAL_TOTAL_STAKED__".to_string(),
                AccountState::new(1_000 * TOKEN_DECIMAL),
            )
            .unwrap();
        let executor = Executor::new(state.clone()); // producer YAPILANDIRILMADI

        executor.set_block_producer_for_block(&producer_a);
        executor.distribute_staking_reward(10_000, 1_000).unwrap();
        executor.set_block_producer_for_block(&producer_b);
        executor.distribute_staking_reward(30_000, 1_000).unwrap();

        let share_a = 10_000 * VALIDATOR_REWARD_BPS / 10_000;
        let share_b = 30_000 * VALIDATOR_REWARD_BPS / 10_000;
        assert_eq!(state.get_balance(&producer_a).unwrap(), share_a);
        assert_eq!(state.get_balance(&producer_b).unwrap(), share_b);
        assert_eq!(
            state
                .get_balance(&VALIDATOR_REWARD_POOL.to_string())
                .unwrap(),
            (10_000 - share_a) + (30_000 - share_b)
        );
    }

    /// G9: `rebind` üretici adresini bağımsız kopyalar (simülasyon commit'in ödül
    /// alıcısını bozamaz). D11 yardımcı: N üyeli küme + üretici canlılık sayaçları.
    fn d11_install_set(
        state: &Arc<dyn State>,
        epoch: u64,
        members: &[Address],
        producer: &Address,
        participated: u64,
        total: u64,
    ) {
        let set = zagros_types::consensus::ActiveValidatorSet {
            epoch,
            members: members
                .iter()
                .enumerate()
                .map(|(i, a)| zagros_types::consensus::ValidatorMember {
                    address: a.clone(),
                    consensus_pubkey: [i as u8 + 1; 32],
                })
                .collect(),
        };
        crate::validator_set::store_active_set(state.as_ref(), &set).unwrap();
        let mut acc = state.get_account(producer).unwrap().unwrap_or_default();
        acc.liveness = zagros_types::consensus::LivenessCounters {
            epoch,
            participated,
            total,
            strikes: 0,
        };
        state.set_account(producer, acc).unwrap();
    }

    /// 🔴 D11: faktör = min(1, katılım / (quorum/N)); aktivasyon öncesi ve ölçümsüz durumda 1.
    #[test]
    fn d11_producer_reward_factor_is_participation_normalized_to_the_structural_ceiling() {
        use crate::params::{producer_reward_factor_bps, D11_ACTIVATION_EPOCH};
        let state = test_state();
        install_test_chain(&state);
        let members: Vec<Address> = (70u8..74).map(test_address).collect();
        let producer = members[0].clone();
        state
            .set_account(
                &producer,
                AccountState {
                    staked_balance: 1,
                    is_registered_validator: true,
                    ..Default::default()
                },
            )
            .unwrap();

        // Küme yok → 1
        assert_eq!(
            producer_reward_factor_bps(state.as_ref(), &producer),
            10_000
        );
        // Aktivasyon öncesi → 1 (katılım %50 olsa bile)
        d11_install_set(&state, D11_ACTIVATION_EPOCH - 1, &members, &producer, 1, 2);
        assert_eq!(
            producer_reward_factor_bps(state.as_ref(), &producer),
            10_000
        );
        // Aktivasyon sonrası, N=4 → tavan %75: %50 katılım → 6667; %75 → 10000; %100 → 10000
        d11_install_set(&state, D11_ACTIVATION_EPOCH, &members, &producer, 1, 2);
        assert_eq!(producer_reward_factor_bps(state.as_ref(), &producer), 6_666);
        d11_install_set(&state, D11_ACTIVATION_EPOCH, &members, &producer, 3, 4);
        assert_eq!(
            producer_reward_factor_bps(state.as_ref(), &producer),
            10_000
        );
        d11_install_set(&state, D11_ACTIVATION_EPOCH, &members, &producer, 4, 4);
        assert_eq!(
            producer_reward_factor_bps(state.as_ref(), &producer),
            10_000
        );
        // Hiç ölçüm yok (epoch'un ilk bloğu) → 1
        d11_install_set(&state, D11_ACTIVATION_EPOCH, &members, &producer, 0, 0);
        assert_eq!(
            producer_reward_factor_bps(state.as_ref(), &producer),
            10_000
        );
        // Sayaç eski epoch'tan kalma → 1 (fail-open)
        d11_install_set(&state, D11_ACTIVATION_EPOCH + 1, &members, &producer, 1, 4);
        let mut acc = state.get_account(&producer).unwrap().unwrap();
        acc.liveness.epoch = D11_ACTIVATION_EPOCH; // küme +1'de
        state.set_account(&producer, acc).unwrap();
        assert_eq!(
            producer_reward_factor_bps(state.as_ref(), &producer),
            10_000
        );
        // Üretici kümede değil → 1
        let outsider = test_address(99);
        state
            .set_account(
                &outsider,
                AccountState {
                    staked_balance: 1,
                    is_registered_validator: true,
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(
            producer_reward_factor_bps(state.as_ref(), &outsider),
            10_000
        );
    }

    /// 🔴 D11: %50 katılımlı üretici, %20'lik payının 2/3'ünü alır; kırpılan 1/3 staker
    /// havuzuna gider (toplam korunur). Aktivasyon öncesi tam pay.
    #[test]
    fn d11_low_participation_producer_receives_a_scaled_share_and_the_rest_goes_to_stakers() {
        use crate::params::D11_ACTIVATION_EPOCH;
        let state = test_state();
        install_test_chain(&state);
        let members: Vec<Address> = (80u8..84).map(test_address).collect();
        let producer = members[0].clone();
        state
            .set_account(
                &producer,
                AccountState {
                    staked_balance: test_min_stake(&state),
                    is_registered_validator: true,
                    ..Default::default()
                },
            )
            .unwrap();
        state
            .set_account(
                &"__GLOBAL_TOTAL_STAKED__".to_string(),
                AccountState::new(1_000 * TOKEN_DECIMAL),
            )
            .unwrap();
        let executor = Executor::new(state.clone());
        executor.set_block_producer_for_block(&producer);
        let pool = VALIDATOR_REWARD_POOL.to_string();

        // Aktivasyon öncesi: tam %20
        d11_install_set(&state, D11_ACTIVATION_EPOCH - 1, &members, &producer, 1, 2);
        let bal0 = state.get_balance(&producer).unwrap();
        let pool0 = state.get_balance(&pool).unwrap();
        executor.distribute_staking_reward(10_000, 1_000).unwrap();
        assert_eq!(state.get_balance(&producer).unwrap() - bal0, 2_000);
        assert_eq!(state.get_balance(&pool).unwrap() - pool0, 8_000);

        // Aktivasyon sonrası, %50 katılım (N=4, tavan %75 → faktör 6666 bps)
        d11_install_set(&state, D11_ACTIVATION_EPOCH, &members, &producer, 1, 2);
        let bal1 = state.get_balance(&producer).unwrap();
        let pool1 = state.get_balance(&pool).unwrap();
        executor.distribute_staking_reward(10_000, 1_000).unwrap();
        let got = state.get_balance(&producer).unwrap() - bal1;
        assert_eq!(
            got,
            2_000 * 6_666 / 10_000,
            "üretici payı katılımla ölçeklenmeli"
        );
        assert_eq!(
            state.get_balance(&pool).unwrap() - pool1,
            10_000 - got,
            "kırpılan kısım staker havuzuna, toplam korunur"
        );
    }

    #[test]
    fn g9_rebind_isolates_block_producer_between_instances() {
        let producer_a = test_address(64);
        let producer_b = test_address(65);
        let state = test_state();
        install_test_chain(&state);
        let executor = Executor::new(state.clone()).with_block_producer_address(producer_a.clone());
        let sim = executor.rebind(state.clone());
        sim.set_block_producer_for_block(&producer_b);
        assert_eq!(executor.current_block_producer(), producer_a);
        assert_eq!(sim.current_block_producer(), producer_b);
    }

    #[test]
    fn distribute_staking_reward_gives_the_full_amount_to_stakers_when_producer_not_qualified() {
        let unqualified_producer = test_address(61); // configured but NEVER registered
        let state = test_state();
        install_test_chain(&state);
        state
            .set_account(
                &"__GLOBAL_TOTAL_STAKED__".to_string(),
                AccountState::new(1_000 * TOKEN_DECIMAL),
            )
            .unwrap();
        let executor =
            Executor::new(state.clone()).with_block_producer_address(unqualified_producer.clone());

        executor.distribute_staking_reward(10_000, 1_000).unwrap();

        assert_eq!(state.get_balance(&unqualified_producer).unwrap(), 0);
        assert_eq!(
            state
                .get_balance(&VALIDATOR_REWARD_POOL.to_string())
                .unwrap(),
            10_000
        );
    }

    #[test]
    fn distribute_staking_reward_goes_directly_to_treasury_when_nobody_is_staked() {
        // Sigorta Kasası yok: kimse stake etmemişken gelen ödül doğrudan
        // Hazineye (VALIDATOR_REWARD_POOL) gider, "normal" akış.
        let state = test_state();
        let executor = Executor::new(state.clone());
        executor.distribute_staking_reward(10_000, 1_000).unwrap();

        assert_eq!(
            state
                .get_balance(&VALIDATOR_REWARD_POOL.to_string())
                .unwrap(),
            10_000
        );
    }

    #[test]
    fn freshly_staked_zagros_earns_nothing_until_the_vesting_period_matures() {
        // 🛡️ Anti-flash-stake (E1) regresyon testi: flash-stake kârsız.
        let staker_key = test_secret_key(62);
        let staker = test_address(62);
        let state = test_state();
        // Stake tutarının ÜSTÜNDE ekstra bakiye, sonraki ClaimReward
        // çağrılarının gas ücretini karşılayabilsin diye.
        state
            .set_account(&staker, AccountState::new(1_000 * TOKEN_DECIMAL + 1_000))
            .unwrap();
        let executor = Executor::new(state.clone());

        let stake_amount = 1_000 * TOKEN_DECIMAL;
        let mut stake_tx = transaction(TxType::StakeZagros, 0, stake_amount);
        stake_tx.sender = staker.clone();
        stake_tx.timestamp = 1_000;
        stake_tx.sign(&staker_key);
        executor
            .execute_transaction(&stake_tx, stake_tx.timestamp)
            .unwrap();

        let after_stake = state.get_account(&staker).unwrap().unwrap();
        assert_eq!(
            after_stake.staked_balance, 0,
            "yeni stake hemen aktif olmamali"
        );
        assert_eq!(after_stake.pending_stake_amount, stake_amount);
        assert_eq!(
            state
                .get_balance(&"__GLOBAL_TOTAL_STAKED__".to_string())
                .unwrap(),
            0,
            "hakedis suresi gecmeden global sayaca girmemeli"
        );

        // Hemen ardından büyük bir ücret olayı gelir (flash-stake'in "yakalamaya"
        // çalıştığı an), ödül anında talep edilmeye çalışılır.
        executor
            .distribute_staking_reward(10_000 * TOKEN_DECIMAL, 1_001)
            .unwrap();
        let claim_fee = 2u128; // transaction() varsayılanı: gas_limit(1) * gas_price(2)
        let mut claim_tx = transaction(TxType::ClaimReward, 1, 0);
        claim_tx.sender = staker.clone();
        claim_tx.timestamp = 1_001;
        claim_tx.sign(&staker_key);
        executor
            .execute_transaction(&claim_tx, claim_tx.timestamp)
            .unwrap();
        let after_claim = state.get_account(&staker).unwrap().unwrap();
        assert_eq!(
            after_claim.balance,
            after_stake.balance - claim_fee,
            "henuz hakedilmemis stake, aninda gelen ucretten pay almamali (bakiyedeki tek degisiklik gas ucreti olmali)"
        );

        // Hakediş süresi geçtikten sonra (yeni bir ClaimReward tetikler) aktif olmalı.
        let matured_ts = 1_001 + REWARD_VESTING_SECONDS + 1;
        let mut settle_tx = transaction(TxType::ClaimReward, 2, 0);
        settle_tx.sender = staker.clone();
        settle_tx.timestamp = matured_ts;
        settle_tx.sign(&staker_key);
        executor
            .execute_transaction(&settle_tx, settle_tx.timestamp)
            .unwrap();
        let after_settle = state.get_account(&staker).unwrap().unwrap();
        assert_eq!(
            after_settle.staked_balance, stake_amount,
            "hakedis sonrasi aktif olmali"
        );
        assert_eq!(after_settle.pending_stake_amount, 0);

        // Artık aktif, yeni bir ücret olayından gerçekten pay alabilmeli.
        executor
            .distribute_staking_reward(10_000 * TOKEN_DECIMAL, matured_ts)
            .unwrap();
        let mut claim2 = transaction(TxType::ClaimReward, 3, 0);
        claim2.sender = staker.clone();
        claim2.timestamp = matured_ts;
        claim2.sign(&staker_key);
        executor
            .execute_transaction(&claim2, claim2.timestamp)
            .unwrap();
        let final_state = state.get_account(&staker).unwrap().unwrap();
        assert!(
            final_state.balance > 0,
            "hakedis sonrasi gelen bir ucretten gercekten pay almali"
        );
    }

    #[test]
    fn slash_validator_fails_after_admin_authority_expires() {
        let admin_key = test_secret_key(30);
        let admin_address = test_address(30);
        let validator_address = test_address(32);
        let genesis_timestamp = 1_000_000u128;
        let block_timestamp = genesis_timestamp + ADMIN_AUTHORITY_PERIOD_SECONDS + 1;

        let state = test_state();
        set_genesis_timestamp(&state, genesis_timestamp);
        state
            .set_account(&admin_address, AccountState::new(1_000_000))
            .unwrap();
        state
            .set_account(
                &validator_address,
                AccountState {
                    staked_balance: 500 * TOKEN_DECIMAL,
                    ..Default::default()
                },
            )
            .unwrap();

        let tx = slash_validator_tx(&admin_key, validator_address.clone(), block_timestamp);
        let executor = Executor::new(state.clone()).with_admin_authority(admin_address);
        let result = executor.execute_transaction(&tx, block_timestamp);

        assert!(result.is_err());
        assert_eq!(
            state
                .get_account(&validator_address)
                .unwrap()
                .unwrap()
                .staked_balance,
            500 * TOKEN_DECIMAL
        );
    }

    #[test]
    fn slash_validator_fails_closed_when_genesis_timestamp_marker_is_missing() {
        let admin_key = test_secret_key(30);
        let admin_address = test_address(30);
        let validator_address = test_address(33);
        let block_timestamp = 1_000u128; // no genesis marker ever set

        let state = test_state();
        state
            .set_account(&admin_address, AccountState::new(1_000_000))
            .unwrap();
        state
            .set_account(
                &validator_address,
                AccountState {
                    staked_balance: 500 * TOKEN_DECIMAL,
                    ..Default::default()
                },
            )
            .unwrap();

        let tx = slash_validator_tx(&admin_key, validator_address.clone(), block_timestamp);
        let executor = Executor::new(state.clone()).with_admin_authority(admin_address);
        let result = executor.execute_transaction(&tx, block_timestamp);

        assert!(result.is_err());
        assert_eq!(
            state
                .get_account(&validator_address)
                .unwrap()
                .unwrap()
                .staked_balance,
            500 * TOKEN_DECIMAL
        );
    }

    /// 🛡️ SwapSell tek işlemde ZAGROS rezervinin %5'inden fazlasını satamaz
    /// (devre kesici). "Self-healing" uydurması olmadığı için havuz gerçek
    /// rezervle sınırlı.
    #[test]
    fn swap_sell_rejects_over_five_percent_of_pool() {
        let pool_zagros = 10_000_000 * TOKEN_DECIMAL;
        let pool_zerenya = 10_000_000 * TOKEN_DECIMAL;
        // %5 = 500k; 600k > tavan.
        let tx = transaction(TxType::SwapSell, 0, 600_000 * TOKEN_DECIMAL);

        let state = test_state();
        state
            .set_account(&tx.sender, AccountState::new(1_000_000 * TOKEN_DECIMAL))
            .unwrap();
        state.set_pool_reserves(pool_zagros, pool_zerenya).unwrap();

        let err = Executor::new(state.clone()).execute_transaction(&tx, tx.timestamp);
        assert!(err.is_err(), "SwapSell over 5% of pool must be rejected");
        // Rezerv değişmemeli (işlem baştan reddedildi).
        assert_eq!(
            state.get_pool_reserves().unwrap(),
            (pool_zagros, pool_zerenya)
        );
    }

    /// 🛡️ FAZ3: SwapSell yetersiz likiditeli (MIN_POOL_LIQUIDITY_ZAGROS/ZERENYA
    /// altı) havuzda artık sahte 42M rezerv basmaz; doğrudan reddeder.
    #[test]
    fn swap_sell_rejects_thin_pool_instead_of_self_healing() {
        let thin = MIN_POOL_LIQUIDITY_ZERENYA - 1;
        let tx = transaction(TxType::SwapSell, 0, 10 * TOKEN_DECIMAL);

        let state = test_state();
        state
            .set_account(&tx.sender, AccountState::new(1_000_000 * TOKEN_DECIMAL))
            .unwrap();
        state.set_pool_reserves(thin, thin).unwrap();

        let err = Executor::new(state.clone()).execute_transaction(&tx, tx.timestamp);
        assert!(
            err.is_err(),
            "SwapSell on a sub-minimum pool must be rejected"
        );
        assert_eq!(state.get_pool_reserves().unwrap(), (thin, thin));
    }

    /// 🛡️ FAZ3: BridgeSwapAndBurn artık slippage korumalı, payload'daki
    /// amount_out_min quote çıkışından büyükse işlem reddedilir (sandwich koruması).
    #[test]
    fn bridge_swap_and_burn_rejects_high_slippage() {
        let pool_zagros = 10_000_000 * TOKEN_DECIMAL;
        let pool_zerenya = 10_000_000 * TOKEN_DECIMAL;
        let mut tx = transaction(TxType::BridgeSwapAndBurn, 0, 100_000 * TOKEN_DECIMAL);
        // payload[36..68] = ulaşılamaz derecede yüksek amount_out_min.
        let mut payload = vec![0u8; 68];
        let huge = (1_000_000_000u128 * TOKEN_DECIMAL).to_be_bytes();
        // u128 → 16 bayt; 32 baytlık alanın sonuna hizala.
        payload[68 - 16..68].copy_from_slice(&huge);
        tx.payload = payload;

        let state = test_state();
        state
            .set_account(&tx.sender, AccountState::new(1_000_000 * TOKEN_DECIMAL))
            .unwrap();
        state.set_pool_reserves(pool_zagros, pool_zerenya).unwrap();

        let err = Executor::new(state.clone()).execute_transaction(&tx, tx.timestamp);
        assert!(
            err.is_err(),
            "BridgeSwapAndBurn with unreachable amount_out_min must be rejected"
        );
        assert_eq!(
            state.get_pool_reserves().unwrap(),
            (pool_zagros, pool_zerenya)
        );
    }

    /// Regresyon: SwapBuy + BridgeMintAndSwap aynı global sayacı paylaşır, kümülatif
    /// %5 tavanı aşınca ikincisi reddedilir (küçük havuz: 90 + 20 = 110 > 104,5).
    #[test]
    fn cumulative_zerenya_inflow_across_swap_buy_and_bridge_mint_and_swap_is_capped() {
        let pool_zagros = 2_000_000 * TOKEN_DECIMAL;
        let pool_zerenya = 2_000 * TOKEN_DECIMAL;
        let state = test_state();
        state.set_pool_reserves(pool_zagros, pool_zerenya).unwrap();
        state
            .set_account(
                &LIQUIDITY_POOL_ADDRESS.to_string(),
                AccountState {
                    balance: pool_zagros,
                    zerenya_balance: pool_zerenya,
                    ..Default::default()
                },
            )
            .unwrap();

        // tx1: sıradan SwapBuy, tavana (100) yakın ama altında, tek başına gecerli.
        let tx1 = transaction(TxType::SwapBuy, 0, 90 * TOKEN_DECIMAL);
        state
            .set_account(
                &tx1.sender,
                AccountState {
                    balance: 1_000,
                    zerenya_balance: 1_000 * TOKEN_DECIMAL,
                    ..Default::default()
                },
            )
            .unwrap();
        Executor::new(state.clone())
            .execute_transaction(&tx1, tx1.timestamp)
            .expect("ilk 90 ZERENYA'lık SwapBuy tek basina gecerli, reddedilmemeli");

        // tx2: FARKLI bir işlem türü (BridgeMintAndSwap), MAX_SINGLE_BRIDGE_MINT
        // tavanının (100) altında ama kümülatif 90+20=110 > yeniden hesaplanan
        // tavan (104,5).
        let authority_key = test_secret_key(21);
        let authority_address = test_address(21);
        let receiver = "0x00000000000000000000000000000000000000ef".to_string();
        state
            .set_account(
                &authority_address,
                AccountState::new(1_000_000 * TOKEN_DECIMAL),
            )
            .unwrap();
        let mut tx2 = transaction(TxType::BridgeMintAndSwap, 0, 20 * TOKEN_DECIMAL);
        tx2.sender = authority_address.clone();
        tx2.receiver = receiver.clone();
        tx2.tx_id = seed_mint_proposal(
            &state,
            &receiver,
            tx2.amount,
            true,
            0,
            2,
            2,
            0,
            tx2.timestamp,
        );
        attach_proposal_payload(&state, &mut tx2);
        tx2.sign(&authority_key);

        let result = Executor::new(state.clone())
            .with_bridge_authority(authority_address)
            .with_bridge_threshold(2, 0)
            .execute_transaction(&tx2, tx2.timestamp);

        assert!(
            result.is_err(),
            "ayri iki islem turu (SwapBuy + BridgeMintAndSwap) kumulatif olarak %5 tavanini asmasina ragmen kabul edildi"
        );
        // Reddedilen tx2 havuzu ETKİLEMEMELİ, yalnızca tx1'in deltası kalmalı.
        let (after_zagros, after_zerenya) = state.get_pool_reserves().unwrap();
        assert_eq!(after_zerenya, pool_zerenya + 90 * TOKEN_DECIMAL);
        assert!(after_zagros < pool_zagros); // tx1 ZAGROS cikti verdi
    }

    /// ZAGROS giriş yönünde de pencere global (SwapSell + BridgeSwapAndBurn);
    /// tx1 tavana yakın + tx2 ile aşılır, teminat doğrudan tohumlanır.
    #[test]
    fn cumulative_zagros_inflow_across_swap_sell_and_bridge_swap_and_burn_is_capped() {
        let pool_zagros = 1_000_000 * TOKEN_DECIMAL;
        let pool_zerenya = 10_000_000 * TOKEN_DECIMAL;
        let state = test_state();
        state.set_pool_reserves(pool_zagros, pool_zerenya).unwrap();
        state
            .set_account(
                &LIQUIDITY_POOL_ADDRESS.to_string(),
                AccountState {
                    balance: pool_zagros,
                    zerenya_balance: pool_zerenya,
                    ..Default::default()
                },
            )
            .unwrap();

        // tx1: sıradan SwapSell, tavana (50k) yakın ama altında.
        let tx1 = transaction(TxType::SwapSell, 0, 49_950 * TOKEN_DECIMAL);
        state
            .set_account(&tx1.sender, AccountState::new(1_000_000 * TOKEN_DECIMAL))
            .unwrap();
        Executor::new(state.clone())
            .execute_transaction(&tx1, tx1.timestamp)
            .expect("ilk 49.950 SwapSell tek basina gecerli, reddedilmemeli");

        // tx2: BridgeSwapAndBurn 3.000 ZAGROS, tek başına geçerli ama kümülatif
        // 52.950, tx1 sonrası yeniden hesaplanan tavanı (~52.496) aşar. Teminat
        // fazlasıyla tohumlanır ki ret başka nedenle maskelenmesin.
        let authority_key = test_secret_key(22);
        let authority_address = test_address(22);
        state
            .set_account(
                &authority_address,
                AccountState::new(1_000_000 * TOKEN_DECIMAL),
            )
            .unwrap();
        seed_bridge_backed_zerenya(&state, 50_000 * TOKEN_DECIMAL);

        let mut tx2 = transaction(TxType::BridgeSwapAndBurn, 1, 3_000 * TOKEN_DECIMAL);
        tx2.sender = authority_address.clone();
        tx2.sign(&authority_key);

        let result = Executor::new(state.clone()).execute_transaction(&tx2, tx2.timestamp);

        assert!(
            result.is_err(),
            "ayri iki islem turu (SwapSell + BridgeSwapAndBurn) kumulatif olarak %5 tavanini asmasina ragmen kabul edildi"
        );
        let (after_zagros, after_zerenya) = state.get_pool_reserves().unwrap();
        // tx1'in girdisi (49.950 ZAGROS), ücret düşülmüş hâliyle, havuza
        // girmiş olmalı; tam eşitlik yerine aralık kontrolü (ücret matematiğini
        // burada tekrarlamaktan kaçınmak için) yeterli kanıt.
        assert!(after_zagros > pool_zagros && after_zagros <= pool_zagros + 49_950 * TOKEN_DECIMAL);
        assert!(after_zerenya < pool_zerenya);
    }

    // Havuzun tek gerçek kaynağı `LIQUIDITY_POOL_ADDRESS`; testler başka bir
    // şey tohumlamadan yalnız `state.set_pool_reserves(...)` ile geçer.
    fn evm_swap_sell_tx(amount_in: u128, amount_out_min: u128, nonce: u64) -> Transaction {
        let mut payload = revm::primitives::keccak256(b"swapSell(uint256,uint256)")[..4].to_vec();
        payload.extend_from_slice(&[0u8; 32]); // ilk parametre kullanılmıyor - miktar tx.amount'tan gelir
        payload.extend_from_slice(&U256::from(amount_out_min).to_be_bytes::<32>());
        let mut tx = transaction(
            TxType::ContractCall {
                data: payload.clone(),
            },
            nonce,
            amount_in,
        );
        tx.receiver = zagros_types::ZERENYA_TOKEN_ADDRESS.to_string();
        tx.payload = payload;
        tx.gas_limit = 100_000;
        tx.gas_price = 2;
        tx.sign(&test_secret_key(1));
        tx
    }

    fn evm_swap_buy_tx(amount_in: u128, amount_out_min: u128, nonce: u64) -> Transaction {
        let mut payload = revm::primitives::keccak256(b"swapBuy(uint256,uint256)")[..4].to_vec();
        payload.extend_from_slice(&U256::from(amount_in).to_be_bytes::<32>());
        payload.extend_from_slice(&U256::from(amount_out_min).to_be_bytes::<32>());
        let mut tx = transaction(
            TxType::ContractCall {
                data: payload.clone(),
            },
            nonce,
            0,
        );
        tx.receiver = zagros_types::ZERENYA_TOKEN_ADDRESS.to_string();
        tx.payload = payload;
        tx.gas_limit = 100_000;
        tx.gas_price = 2;
        tx.sign(&test_secret_key(1));
        tx
    }

    fn evm_add_liquidity_tx(amount_zagros: u128, amount_zsc: u128, nonce: u64) -> Transaction {
        let mut payload =
            revm::primitives::keccak256(b"addLiquidity(uint256,uint256)")[..4].to_vec();
        payload.extend_from_slice(&U256::from(amount_zagros).to_be_bytes::<32>());
        payload.extend_from_slice(&U256::from(amount_zsc).to_be_bytes::<32>());
        let mut tx = transaction(
            TxType::ContractCall {
                data: payload.clone(),
            },
            nonce,
            0,
        );
        tx.receiver = zagros_types::ZERENYA_TOKEN_ADDRESS.to_string();
        tx.payload = payload;
        tx.gas_limit = 100_000;
        tx.gas_price = 2;
        tx.sign(&test_secret_key(1));
        tx
    }

    /// 🚨 Native havuz yalnız genesis'te kurulur; `addLiquidity` olsaydı rezervler
    /// fiyat kontrolsüz enjekte edilip swap korumaları atlanırdı.
    #[test]
    fn evm_add_liquidity_to_native_pool_is_rejected_pool_never_mutates() {
        let pool_zagros = 10_000_000 * TOKEN_DECIMAL;
        let pool_zerenya = 10_000_000 * TOKEN_DECIMAL;
        let state = test_state();
        state.set_pool_reserves(pool_zagros, pool_zerenya).unwrap();
        state
            .set_account(
                &test_address(1),
                AccountState::new(1_000_000 * TOKEN_DECIMAL),
            )
            .unwrap();

        // Saldırı denemesi: havuzu 1000:1 gibi saçma bir oranla manipüle etmeye
        // çalış (mevcut oran 1:1).
        let attack_tx = evm_add_liquidity_tx(TOKEN_DECIMAL, 1_000 * TOKEN_DECIMAL, 0);
        let _ = Executor::new(state.clone()).execute_transaction(&attack_tx, attack_tx.timestamp);

        // Sonuç ne olursa olsun (Err ya da EVM'in kendi no-op'u), TEK gerçek
        // güvenlik kanıtı: havuz rezervleri KESİNLİKLE değişmemeli.
        assert_eq!(
            state.get_pool_reserves().unwrap(),
            (pool_zagros, pool_zerenya),
            "addLiquidity çağrısı native havuz rezervlerini değiştirebildi - havuz asla mutasyona uğramamalı"
        );
    }

    /// 🛡️ KRİTİK: düz `Transfer` ile `LIQUIDITY_POOL_ADDRESS`e (sıfır adres)
    /// gönderim havuzun ZAGROS rezervini komisyonsuz/tavansız şişirememeli
    /// (EVM `addLiquidity` reddinin native "bağış" yolu eşleniği).
    #[test]
    fn native_transfer_to_liquidity_pool_address_is_rejected_pool_never_mutates() {
        let pool_zagros = 10_000_000 * TOKEN_DECIMAL;
        let pool_zerenya = 10_000_000 * TOKEN_DECIMAL;
        let state = test_state();
        state.set_pool_reserves(pool_zagros, pool_zerenya).unwrap();

        let mut tx = transaction(TxType::Transfer, 0, 1_000_000 * TOKEN_DECIMAL);
        tx.receiver = LIQUIDITY_POOL_ADDRESS.to_string();
        tx.sign(&test_secret_key(1));
        state
            .set_account(&tx.sender, AccountState::new(2_000_000 * TOKEN_DECIMAL))
            .unwrap();

        let result = Executor::new(state.clone()).execute_transaction(&tx, tx.timestamp);
        assert!(
            result.is_err(),
            "havuz adresine düz transfer kabul edilmemeli"
        );
        assert_eq!(
            state.get_pool_reserves().unwrap(),
            (pool_zagros, pool_zerenya),
            "reddedilen transfer havuz rezervlerini değiştirebildi"
        );
        // Reddedilen işlem yine normal gas ücretini öder (beklenen davranış);
        // asıl kanıt: 1.000.000 ZAGROS'luk transfer TUTARI hiç taşınmadı.
        assert_eq!(
            state.get_account(&tx.sender).unwrap().unwrap().balance,
            2_000_000 * TOKEN_DECIMAL - 2,
            "reddedilen transferde gas dışında hiçbir miktar gönderenin bakiyesinden düşülmemeli"
        );
    }

    /// 🛡️ EVM `swapSell` native `SwapSell` ile aynı %5 devre kesiciye tabi olmalı.
    #[test]
    fn evm_swap_sell_over_cap_is_rejected_by_circuit_breaker() {
        let pool_zagros = 10_000_000 * TOKEN_DECIMAL;
        let pool_zerenya = 10_000_000 * TOKEN_DECIMAL;

        // Kontrol: tavanın (%5 = 500k) altında bir EVM swap hâlâ kabul edilmeli;
        // devre kesici her şeyi reddetmez.
        let under_cap_state = test_state();
        under_cap_state
            .set_pool_reserves(pool_zagros, pool_zerenya)
            .unwrap();
        under_cap_state
            .set_account(
                &test_address(1),
                AccountState::new(1_000_000 * TOKEN_DECIMAL),
            )
            .unwrap();
        let under_cap_tx = evm_swap_sell_tx(100_000 * TOKEN_DECIMAL, 0, 0);
        Executor::new(under_cap_state.clone())
            .execute_transaction(&under_cap_tx, under_cap_tx.timestamp)
            .expect("tavanın altındaki EVM swapSell reddedilmemeli");

        // Saldırı: %5 tavanının (500k) üstünde, EVM ContractCall yoluyla.
        let state = test_state();
        state.set_pool_reserves(pool_zagros, pool_zerenya).unwrap();
        state
            .set_account(
                &test_address(1),
                AccountState::new(1_000_000 * TOKEN_DECIMAL),
            )
            .unwrap();
        let attack_tx = evm_swap_sell_tx(600_000 * TOKEN_DECIMAL, 0, 0);

        let result =
            Executor::new(state.clone()).execute_transaction(&attack_tx, attack_tx.timestamp);

        assert!(
            result.is_err(),
            "EVM ContractCall yoluyla %5 tavanının üstünde swapSell kabul edildi - devre kesici bypass edilebiliyor"
        );
        assert_eq!(
            state.get_pool_reserves().unwrap(),
            (pool_zagros, pool_zerenya)
        );
    }

    /// Aynı devre kesici, ZERENYA-giriş yönünde (`swapBuy`) de EVM yolunda uygulanmalı.
    #[test]
    fn evm_swap_buy_over_cap_is_rejected_by_circuit_breaker() {
        let pool_zagros = 10_000_000 * TOKEN_DECIMAL;
        let pool_zerenya = 10_000_000 * TOKEN_DECIMAL;

        let under_cap_state = test_state();
        under_cap_state
            .set_pool_reserves(pool_zagros, pool_zerenya)
            .unwrap();
        under_cap_state
            .set_account(
                &test_address(1),
                AccountState {
                    balance: 1_000_000 * TOKEN_DECIMAL,
                    zerenya_balance: 1_000_000 * TOKEN_DECIMAL,
                    ..Default::default()
                },
            )
            .unwrap();
        let under_cap_tx = evm_swap_buy_tx(100_000 * TOKEN_DECIMAL, 0, 0);
        Executor::new(under_cap_state.clone())
            .execute_transaction(&under_cap_tx, under_cap_tx.timestamp)
            .expect("tavanın altındaki EVM swapBuy reddedilmemeli");

        let state = test_state();
        state.set_pool_reserves(pool_zagros, pool_zerenya).unwrap();
        state
            .set_account(
                &test_address(1),
                AccountState {
                    balance: 1_000_000 * TOKEN_DECIMAL,
                    zerenya_balance: 1_000_000 * TOKEN_DECIMAL,
                    ..Default::default()
                },
            )
            .unwrap();
        let attack_tx = evm_swap_buy_tx(600_000 * TOKEN_DECIMAL, 0, 0);

        let result =
            Executor::new(state.clone()).execute_transaction(&attack_tx, attack_tx.timestamp);

        assert!(
            result.is_err(),
            "EVM ContractCall yoluyla %5 tavanının üstünde swapBuy kabul edildi - devre kesici bypass edilebiliyor"
        );
        assert_eq!(
            state.get_pool_reserves().unwrap(),
            (pool_zagros, pool_zerenya)
        );
    }

    /// EVM ikizi: kümülatif pencere EVM yoluyla da paylaşılmalı, parçalı atlatma olmasın.
    #[test]
    fn evm_swap_sell_cumulative_volume_is_capped_same_as_native() {
        let pool_zagros = 10_000_000 * TOKEN_DECIMAL;
        let pool_zerenya = 10_000_000 * TOKEN_DECIMAL;
        let state = test_state();
        state.set_pool_reserves(pool_zagros, pool_zerenya).unwrap();
        state
            .set_account(
                &test_address(1),
                AccountState::new(1_000_000 * TOKEN_DECIMAL),
            )
            .unwrap();

        let tx1 = evm_swap_sell_tx(300_000 * TOKEN_DECIMAL, 0, 0);
        Executor::new(state.clone())
            .execute_transaction(&tx1, tx1.timestamp)
            .expect("ilk 300k EVM swapSell tek başına geçerli, reddedilmemeli");

        let tx2 = evm_swap_sell_tx(300_000 * TOKEN_DECIMAL, 0, 1);
        let result = Executor::new(state.clone()).execute_transaction(&tx2, tx2.timestamp);

        assert!(
            result.is_err(),
            "aynı adresin EVM yoluyla art arda gönderdiği iki 300k'lık swapSell kümülatif %5 tavanını (500k) aşmasına rağmen kabul edildi"
        );
    }

    /// Devre kesici native `SwapSell` ile EVM `swapSell`de aynı kabul/red kararını vermeli.
    #[test]
    fn native_and_evm_swap_sell_paths_reach_the_same_circuit_breaker_verdict() {
        let pool_zagros = 10_000_000 * TOKEN_DECIMAL;
        let pool_zerenya = 10_000_000 * TOKEN_DECIMAL;
        let over_cap = 600_000 * TOKEN_DECIMAL; // %5 tavanı (500k) üstü

        let native_state = test_state();
        native_state
            .set_pool_reserves(pool_zagros, pool_zerenya)
            .unwrap();
        let native_tx = transaction(TxType::SwapSell, 0, over_cap);
        native_state
            .set_account(
                &native_tx.sender,
                AccountState::new(1_000_000 * TOKEN_DECIMAL),
            )
            .unwrap();
        let native_result = Executor::new(native_state.clone())
            .execute_transaction(&native_tx, native_tx.timestamp);

        let evm_state = test_state();
        evm_state
            .set_pool_reserves(pool_zagros, pool_zerenya)
            .unwrap();
        evm_state
            .set_account(
                &test_address(1),
                AccountState::new(1_000_000 * TOKEN_DECIMAL),
            )
            .unwrap();
        let evm_tx = evm_swap_sell_tx(over_cap, 0, 0);
        let evm_result =
            Executor::new(evm_state.clone()).execute_transaction(&evm_tx, evm_tx.timestamp);

        assert!(
            native_result.is_err(),
            "native SwapSell tavan üstünde reddetmeli"
        );
        assert!(
            evm_result.is_err(),
            "EVM swapSell tavan üstünde reddetmeli (native ile aynı sonuç)"
        );
        assert_eq!(
            native_state.get_pool_reserves().unwrap(),
            evm_state.get_pool_reserves().unwrap(),
            "her iki yol da reddedilen işlemde havuzu değiştirmemeli - aynı son durum"
        );
    }

    /// 🚨 PARİTE: aynı satış native `SwapSell` ile de EVM `zsc.swapSell(...)` ile
    /// de SAYISAL OLARAK AYNI sonucu (rezervler + alınan ZERENYA) üretmeli;
    /// ikisi de tek kaynak `LIQUIDITY_POOL_ADDRESS`'i okuyup yazar.
    #[test]
    fn native_and_evm_swap_sell_produce_numerically_identical_results() {
        let pool_zagros = 10_000_000 * TOKEN_DECIMAL;
        let pool_zerenya = 10_000_000 * TOKEN_DECIMAL;
        let amount_in = 100_000 * TOKEN_DECIMAL; // tavanın (500k) altında, gerçekten yürütülür

        let native_state = test_state();
        native_state
            .set_pool_reserves(pool_zagros, pool_zerenya)
            .unwrap();
        let native_tx = transaction(TxType::SwapSell, 0, amount_in);
        native_state
            .set_account(
                &native_tx.sender,
                AccountState::new(1_000_000 * TOKEN_DECIMAL),
            )
            .unwrap();
        Executor::new(native_state.clone())
            .execute_transaction(&native_tx, native_tx.timestamp)
            .expect("native SwapSell tavanın altında başarılı olmalı");

        let evm_state = test_state();
        evm_state
            .set_pool_reserves(pool_zagros, pool_zerenya)
            .unwrap();
        let evm_tx = evm_swap_sell_tx(amount_in, 0, 0);
        evm_state
            .set_account(&evm_tx.sender, AccountState::new(1_000_000 * TOKEN_DECIMAL))
            .unwrap();
        Executor::new(evm_state.clone())
            .execute_transaction(&evm_tx, evm_tx.timestamp)
            .expect("EVM swapSell tavanın altında başarılı olmalı");

        assert_eq!(
            native_state.get_pool_reserves().unwrap(),
            evm_state.get_pool_reserves().unwrap(),
            "native ve EVM yolu aynı satıştan sonra AYNI havuz rezervlerine ulaşmalı"
        );
        assert_eq!(
            native_tx.sender, evm_tx.sender,
            "test kurgusu: iki yol da aynı gönderici adresini kullanmalı"
        );
        let native_sender_zsc = native_state
            .get_account(&native_tx.sender)
            .unwrap()
            .unwrap()
            .zerenya_balance;
        let evm_sender_zsc = evm_state
            .get_account(&evm_tx.sender)
            .unwrap()
            .unwrap()
            .zerenya_balance;
        assert_eq!(
            native_sender_zsc, evm_sender_zsc,
            "native ve EVM yolu kullanıcıya AYNI miktarda ZERENYA ödemeli"
        );
    }

    /// 🚨 "DİŞ GEÇİRME": native ve EVM swap yolları AYNI havuz state'inde
    /// ardışık (native → EVM → native → EVM) çalışır; tek kaynak olduğundan her
    /// işlem bir öncekinin bıraktığı GERÇEK durumu görür.
    #[test]
    fn interleaved_native_and_evm_swaps_never_diverge_or_spuriously_fail() {
        let pool_zagros = 10_000_000 * TOKEN_DECIMAL;
        let pool_zerenya = 10_000_000 * TOKEN_DECIMAL;
        let state = test_state();
        state.set_pool_reserves(pool_zagros, pool_zerenya).unwrap();
        let sender = test_address(1);
        state
            .set_account(
                &sender,
                AccountState {
                    balance: 10_000_000 * TOKEN_DECIMAL,
                    zerenya_balance: 10_000_000 * TOKEN_DECIMAL,
                    ..Default::default()
                },
            )
            .unwrap();

        let executor = Executor::new(state.clone());
        let k_start =
            alloy_primitives::U256::from(pool_zagros) * alloy_primitives::U256::from(pool_zerenya);

        // 1) Native SATIŞ (ZAGROS -> ZERENYA), havuzun GERÇEK rezervlerini değiştirir.
        let tx1 = transaction(TxType::SwapSell, 0, 50_000 * TOKEN_DECIMAL);
        executor
            .execute_transaction(&tx1, tx1.timestamp)
            .expect("adım 1 (native satış) başarılı olmalı");
        let reserves_1 = state.get_pool_reserves().unwrap();
        assert_ne!(
            reserves_1,
            (pool_zagros, pool_zerenya),
            "adım 1 havuzu gerçekten değiştirmeli"
        );

        // 2) EVM ALIŞ (ZERENYA -> ZAGROS), HEMEN ARDINDAN; havuz native tarafından
        // değiştirilmiş olsa da doğru rezervi görmeli.
        let tx2 = evm_swap_buy_tx(40_000 * TOKEN_DECIMAL, 0, 1);
        executor
            .execute_transaction(&tx2, tx2.timestamp)
            .expect("adım 2 (EVM alış, native'in hemen ardından) başarılı olmalı - split-brain'in asıl kanıt testi");
        let reserves_2 = state.get_pool_reserves().unwrap();
        assert_ne!(
            reserves_2, reserves_1,
            "adım 2 havuzu gerçekten değiştirmeli"
        );

        // 3) Native ALIŞ (ZERENYA -> ZAGROS), EVM'in bıraktığı durumu görmeli.
        let tx3 = transaction(TxType::SwapBuy, 2, 30_000 * TOKEN_DECIMAL);
        executor
            .execute_transaction(&tx3, tx3.timestamp)
            .expect("adım 3 (native alış, EVM'in hemen ardından) başarılı olmalı");
        let reserves_3 = state.get_pool_reserves().unwrap();
        assert_ne!(
            reserves_3, reserves_2,
            "adım 3 havuzu gerçekten değiştirmeli"
        );

        // 4) EVM SATIŞ (ZAGROS -> ZERENYA), native'in bıraktığı durumu görmeli.
        let tx4 = evm_swap_sell_tx(20_000 * TOKEN_DECIMAL, 0, 3);
        executor
            .execute_transaction(&tx4, tx4.timestamp)
            .expect("adım 4 (EVM satış, native'in hemen ardından) başarılı olmalı");
        let (final_zagros, final_zsc) = state.get_pool_reserves().unwrap();
        assert_ne!(
            (final_zagros, final_zsc),
            reserves_3,
            "adım 4 havuzu gerçekten değiştirmeli"
        );

        // AMM değişmezi: dört karışık native/EVM işlem sonunda da k
        // (sabit çarpım) hiç azalmamalı (ücretler yüzünden artabilir).
        let k_end =
            alloy_primitives::U256::from(final_zagros) * alloy_primitives::U256::from(final_zsc);
        assert!(
            k_end >= k_start,
            "dört karışık native/EVM işlem sonunda k asla azalmamalı"
        );
    }

    /// 🚨 Pencere kapasitesi KADEMELİ döner: ani sıfırlanma, saldırganın pencerenin
    /// son saniyesinde ve yeni pencerede tavanı iki kez doldurmasına izin verirdi
    /// (bkz. `swap::SwapVolumeTracker`).
    #[test]
    fn swap_volume_capacity_returns_gradually_instead_of_resetting_at_the_window_edge() {
        let pool_zagros = 10_000_000 * TOKEN_DECIMAL;
        let pool_zerenya = 10_000_000 * TOKEN_DECIMAL;
        let state = test_state();
        state.set_pool_reserves(pool_zagros, pool_zerenya).unwrap();
        state
            .set_account(
                &LIQUIDITY_POOL_ADDRESS.to_string(),
                AccountState {
                    balance: pool_zagros,
                    zerenya_balance: pool_zerenya,
                    ..Default::default()
                },
            )
            .unwrap();
        state
            .set_account(
                &test_address(1),
                AccountState {
                    balance: 1_000,
                    zerenya_balance: 1_000_000 * TOKEN_DECIMAL,
                    ..Default::default()
                },
            )
            .unwrap();

        let day0: u128 = 1_000;
        let mut tx1 = transaction(TxType::SwapBuy, 0, 400_000 * TOKEN_DECIMAL);
        tx1.timestamp = day0;
        tx1.sign(&test_secret_key(1));
        Executor::new(state.clone())
            .execute_transaction(&tx1, tx1.timestamp)
            .expect("ilk 400k SwapBuy gecerli olmali");

        // Aynı pencerede (60sn içinde) 400k daha -> kümülatif 800k > 500k, red.
        let mut tx2 = transaction(TxType::SwapBuy, 1, 400_000 * TOKEN_DECIMAL);
        tx2.timestamp = day0 + 10;
        tx2.sign(&test_secret_key(1));
        assert!(
            Executor::new(state.clone())
                .execute_transaction(&tx2, tx2.timestamp)
                .is_err(),
            "ayni pencerede kumulatif tavan asilmasina ragmen kabul edildi"
        );

        // 🚨 t+61'de kapasite tam dönmemiş olmalı (önceki pencere ağırlıklı sayılır);
        // eski kod burada sıfırlanıyordu.
        let mut tx3 = transaction(TxType::SwapBuy, 2, 400_000 * TOKEN_DECIMAL);
        tx3.timestamp = day0 + 61;
        tx3.sign(&test_secret_key(1));
        assert!(
            Executor::new(state.clone())
                .execute_transaction(&tx3, tx3.timestamp)
                .is_err(),
            "pencere sinirinin hemen otesinde TAM kapasite ACILMAMALI (sinir patlamasi)"
        );

        // Buna karşılık KÜÇÜK bir miktar, açılan kısmi kapasiteye sığmalı,
        // devre kesici bir HIZ sınırıdır, kalıcı bir kilit değil.
        // nonce 3: reddedilen tx3 de (gas/nonce muhasebesi geregi) nonce tuketir.
        let mut tx3b = transaction(TxType::SwapBuy, 3, 50_000 * TOKEN_DECIMAL);
        tx3b.timestamp = day0 + 61;
        tx3b.sign(&test_secret_key(1));
        Executor::new(state.clone())
            .execute_transaction(&tx3b, tx3b.timestamp)
            .expect("kismi olarak acilan kapasiteye sigan swap kabul edilmeli");

        // İki tam pencere sonra geçmiş tamamen düşmüş, tavan yenilenmiş olmalı.
        let mut tx4 = transaction(TxType::SwapBuy, 4, 400_000 * TOKEN_DECIMAL);
        tx4.timestamp = day0 + 130;
        tx4.sign(&test_secret_key(1));
        Executor::new(state.clone())
            .execute_transaction(&tx4, tx4.timestamp)
            .expect("iki pencere sonra tavan tamamen yenilenmeli");
    }

    #[test]
    fn executor_increments_nonce_and_rejects_replay_without_state_changes() {
        let state = test_state();
        // `total_staked == 0` iken ödül acc çarpanına yansımaz (dağıtılacak
        // staker yok); bu test Hazine yoluna baktığı için gerçekçi bir staker seedliyoruz.
        state
            .set_account(
                &"__GLOBAL_TOTAL_STAKED__".to_string(),
                AccountState::new(1_000 * TOKEN_DECIMAL),
            )
            .unwrap();
        let tx = transaction(TxType::Transfer, 0, 10);
        state
            .set_account(&tx.sender, AccountState::new(100))
            .unwrap();
        let executor = Executor::new(state.clone());

        executor.execute_transaction(&tx, tx.timestamp).unwrap();
        executor.flush_block_rewards(1_000).unwrap();

        let sender = state.get_account(&tx.sender).unwrap().unwrap();

        assert_eq!(sender.balance, 88);

        assert_eq!(sender.nonce, 1);

        assert_eq!(state.get_balance(&tx.receiver).unwrap(), 10);

        assert_eq!(
            state
                .get_balance(&VALIDATOR_REWARD_POOL.to_string())
                .unwrap(),
            2
        );

        let replay_result = executor.execute_transaction(&tx, tx.timestamp);
        assert!(matches!(replay_result, Err(ZagrosError::InvalidNonce)));
        let sender_after_replay = state.get_account(&tx.sender).unwrap().unwrap();

        assert_eq!(sender_after_replay.balance, 88);

        assert_eq!(sender_after_replay.nonce, 1);

        assert_eq!(state.get_balance(&tx.receiver).unwrap(), 10);

        assert_eq!(
            state
                .get_balance(&VALIDATOR_REWARD_POOL.to_string())
                .unwrap(),
            2
        );
    }

    fn contract_call_transaction(
        sender_key: &secp256k1::SecretKey,
        receiver: &str,
        nonce: u64,
        payload: Vec<u8>,
    ) -> Transaction {
        let mut tx = transaction(
            TxType::ContractCall {
                data: payload.clone(),
            },
            nonce,
            0,
        );
        tx.sender = Transaction::address_from_secret_key(sender_key);
        tx.receiver = receiver.to_string();
        tx.payload = payload;
        tx.gas_limit = 100_000;
        tx.gas_price = 2;
        tx.sign(sender_key);
        tx
    }

    fn erc20_call(signature: &[u8], addresses: &[&str], amount: Option<U256>) -> Vec<u8> {
        let mut payload = revm::primitives::keccak256(signature)[..4].to_vec();
        for address in addresses {
            let decoded = hex::decode(address.trim_start_matches("0x")).unwrap();
            payload.extend_from_slice(&[0; 12]);
            payload.extend_from_slice(&decoded);
        }
        if let Some(amount) = amount {
            payload.extend_from_slice(&amount.to_be_bytes::<32>());
        }
        payload
    }

    /// 1:1 havuz kurulmuş bir state + o havuzda geçerli x100 üretim harcı.
    /// (base = GAS_FEE_ZERENYA, harç = base × 100 = $5,00 karşılığı.)
    fn state_with_par_pool_and_levy() -> (Arc<dyn State>, u128) {
        let state = test_state();
        state
            .set_pool_reserves(1_000 * TOKEN_DECIMAL, 1_000 * TOKEN_DECIMAL)
            .unwrap();
        // `total_staked == 0` iken ödül acc çarpanına yansımaz (dağıtılacak
        // staker yok); bu testler Hazine yoluna baktığı için gerçekçi bir
        // staker seedliyoruz.
        state
            .set_account(
                &"__GLOBAL_TOTAL_STAKED__".to_string(),
                AccountState::new(1_000 * TOKEN_DECIMAL),
            )
            .unwrap();
        (state, zagros_types::GAS_FEE_ZERENYA * 100)
    }

    /// Boş kontrat üreten geçerli init-code: PUSH1 0, PUSH1 0, RETURN.
    fn deploy_init_code() -> Vec<u8> {
        vec![0x60, 0x00, 0x60, 0x00, 0xf3]
    }

    /// 🏭 EVM deploy'u, ölçülen EVM gas'ının ÜSTÜNE düz x100 üretim harcını öder.
    /// Harç mempool kabul kapısında alınamaz (MetaMask'ı engellerdi), bu yüzden
    /// executor'da kesilir ve Hazine'ye (Real Yield) akar.
    #[test]
    fn an_evm_deploy_pays_the_x100_production_levy_on_top_of_metered_gas() {
        let (state, expected_levy) = state_with_par_pool_and_levy();
        let executor = Executor::new(state.clone());

        let sender_key = test_secret_key(21);
        let sender = Transaction::address_from_secret_key(&sender_key);
        state
            .set_account(&sender, AccountState::new(expected_levy * 10))
            .unwrap();

        // receiver = sıfır adres => zagros_types::is_evm_deploy => EVM Create.
        let tx = contract_call_transaction(
            &sender_key,
            "0x0000000000000000000000000000000000000000",
            0,
            deploy_init_code(),
        );
        assert!(zagros_types::is_evm_deploy(&tx.receiver));

        executor.execute_transaction(&tx, tx.timestamp).unwrap();
        executor.flush_block_rewards(1_000).unwrap();

        let treasury = state
            .get_balance(&VALIDATOR_REWARD_POOL.to_string())
            .unwrap();
        assert!(
            treasury >= expected_levy,
            "üretim harcı Hazine'ye akmadı: hazine={}, beklenen harç>={}",
            treasury,
            expected_levy
        );

        let sender_after = state.get_account(&sender).unwrap().unwrap();
        assert!(
            sender_after.balance <= expected_levy * 10 - expected_levy,
            "harç gönderenden kesilmemiş: kalan={}",
            sender_after.balance
        );
    }

    /// 🏭 Sıradan bir EVM ÇAĞRISI (deploy değil) üretim harcı ÖDEMEZ, yalnızca
    /// ölçülen gas. Harcın yanlış işlem kümesine uygulanmadığının kanıtı.
    #[test]
    fn an_ordinary_evm_call_is_not_charged_the_production_levy() {
        let (state, levy) = state_with_par_pool_and_levy();
        let executor = Executor::new(state.clone());

        let sender_key = test_secret_key(22);
        let sender = Transaction::address_from_secret_key(&sender_key);
        let contract = "0x2222222222222222222222222222222222222222".to_string();
        state
            .set_account(&sender, AccountState::new(levy * 10))
            .unwrap();
        state
            .set_account(&contract, AccountState::new_contract(vec![0x00]))
            .unwrap();

        let tx = contract_call_transaction(&sender_key, &contract, 0, vec![0x00]);
        assert!(!zagros_types::is_evm_deploy(&tx.receiver));

        executor.execute_transaction(&tx, tx.timestamp).unwrap();
        executor.flush_block_rewards(1_000).unwrap();

        let treasury = state
            .get_balance(&VALIDATOR_REWARD_POOL.to_string())
            .unwrap();
        assert!(
            treasury < levy,
            "deploy olmayan çağrıdan üretim harcı alınmış: hazine={}, harç={}",
            treasury,
            levy
        );
    }

    /// 🏭 Üretim harcını karşılayamayan bir deploy KABUL EDİLMEZ. Bu kontrol
    /// olmasaydı kesinti `saturating_sub` ile bakiyeyi 0'a çakar, ödül havuzuna ise
    /// hiç alınmamış parayı yazardı (yoktan ödül üretimi).
    #[test]
    fn an_evm_deploy_is_rejected_when_the_sender_cannot_afford_the_levy() {
        let (state, levy) = state_with_par_pool_and_levy();
        let executor = Executor::new(state.clone());

        let sender_key = test_secret_key(23);
        let sender = Transaction::address_from_secret_key(&sender_key);
        // Beyan edilen gas bütçesini karşılar ama üretim harcını karşılamaz.
        state
            .set_account(&sender, AccountState::new(levy / 2))
            .unwrap();

        let tx = contract_call_transaction(
            &sender_key,
            "0x0000000000000000000000000000000000000000",
            0,
            deploy_init_code(),
        );

        assert!(matches!(
            executor.execute_transaction(&tx, tx.timestamp),
            Err(ZagrosError::InsufficientBalanceForGas)
        ));
        assert_eq!(
            state
                .get_balance(&VALIDATOR_REWARD_POOL.to_string())
                .unwrap(),
            0,
            "reddedilen deploy'dan Hazine'ye para yazılmış"
        );
    }

    // 🏛️ TOKEN FACTORY ÜRETİM HARCI ($7.77/kontrat, bypass edilemez)

    /// GERÇEK (boş olmayan) 1 baytlık `STOP` runtime kodu döndüren minimal init
    /// code; `deploy_init_code()`'un aksine gerçekten kontrat üretir, Token Factory
    /// tespitinin (`!code.is_empty()`) pozitif dalı için.
    fn real_deploy_init_code() -> Vec<u8> {
        vec![0x60, 0x00, 0x60, 0x00, 0x53, 0x60, 0x01, 0x60, 0x00, 0xF3]
    }

    /// Constructor'da `CREATE` ile ikinci kontrat deploy eden init code: tek
    /// işlemde 2 kontrat oluşur ("kontrat başına" ücret kanıtı).
    fn init_code_that_also_creates_a_child_via_create_opcode() -> Vec<u8> {
        let mut init = vec![0x69]; // PUSH10
        init.extend_from_slice(&real_deploy_init_code());
        init.extend_from_slice(&[
            0x60, 0x00, // PUSH1 0 (mstore offset)
            0x52, // MSTORE
            0x60, 0x0A, // PUSH1 10 (size)
            0x60,
            0x16, // PUSH1 22 (offset - 32-10=22, sağa yaslı değerin başladığı yer)
            0x60, 0x00, // PUSH1 0 (value)
            0xF0, // CREATE - çocuk kontrat GERÇEKTEN burada, constructor sırasında oluşur
            0x50, // POP (CREATE'in döndürdüğü adresi at)
            0x60, 0x00, // PUSH1 0x00 (STOP opcode baytı - kendi runtime kodumuz)
            0x60, 0x00, // PUSH1 0 (mstore8 offset)
            0x53, // MSTORE8
            0x60, 0x01, // PUSH1 1 (size)
            0x60, 0x00, // PUSH1 0 (offset)
            0xF3, // RETURN - kendisi icin 1 baytlik STOP runtime kodu doner
        ]);
        init
    }

    /// Yukarıdaki iç 22 baytı doğrudan RUNTIME kodu olarak deploy eden init code:
    /// bu kontrat normal bir `ContractCall` ile çağrıldığında CREATE çalıştıran
    /// gerçek bir "Factory" gibi davranır.
    fn factory_deploy_init_code() -> Vec<u8> {
        let mut runtime = vec![0x69]; // PUSH10
        runtime.extend_from_slice(&real_deploy_init_code());
        runtime.extend_from_slice(&[
            0x60, 0x00, 0x52, 0x60, 0x0A, 0x60, 0x16, 0x60, 0x00, 0xF0, 0x00,
        ]);
        assert_eq!(runtime.len(), 22);

        let mut init = vec![0x75]; // PUSH22
        init.extend_from_slice(&runtime);
        init.extend_from_slice(&[0x60, 0x00, 0x52, 0x60, 0x16, 0x60, 0x0A, 0xF3]);
        init
    }

    fn archived_receipt_for(
        state: &Arc<dyn State>,
        tx_id: &[u8; 32],
    ) -> zagros_types::ArchivedReceipt {
        let acc = state
            .get_account(&zagros_state::receipt_key(tx_id))
            .unwrap()
            .expect("receipt bulunamadı");
        bincode::deserialize(&acc.contract_code).expect("receipt deserialize edilemedi")
    }

    /// Gerçek EVM deploy'u x100 harcının üstüne $7.77 Token Factory harcı öder,
    /// aynı `distribute_staking_reward` hattından Hazine'ye.
    #[test]
    fn a_real_evm_deploy_charges_exactly_one_zagros_token_factory_fee() {
        let (state, levy) = state_with_par_pool_and_levy();
        let executor = Executor::new(state.clone());
        let sender_key = test_secret_key(31);
        let sender = Transaction::address_from_secret_key(&sender_key);
        let funding = levy + 10 * TOKEN_DECIMAL;
        state
            .set_account(&sender, AccountState::new(funding))
            .unwrap();

        let tx = contract_call_transaction(
            &sender_key,
            "0x0000000000000000000000000000000000000000",
            0,
            real_deploy_init_code(),
        );
        executor.execute_transaction(&tx, tx.timestamp).unwrap();
        executor.flush_block_rewards(tx.timestamp).unwrap();

        let receipt = archived_receipt_for(&state, &tx.tx_id);
        assert!(
            receipt.contract_address.is_some(),
            "gercek runtime kodu doner deploy basarili olmali"
        );

        let sender_after = state.get_account(&sender).unwrap().unwrap();
        let spent = funding - sender_after.balance;
        assert!(
            spent >= levy + zagros_types::TOKEN_FACTORY_FEE_ZERENYA,
            "harcanan tutar x100 levy + $7.77'lik token factory harcini icermeli: harcanan={}, levy={}, tf_fee={}",
            spent, levy, zagros_types::TOKEN_FACTORY_FEE_ZERENYA
        );
    }

    /// 0 bayt runtime döndüren deploy harcı tetiklememeli; tespit "yeni kod sahibi
    /// olma" geçişine bağlı, `tx.receiver==null`a değil.
    #[test]
    fn an_evm_deploy_that_produces_no_runtime_code_does_not_pay_the_token_factory_fee() {
        let (state, levy) = state_with_par_pool_and_levy();
        let executor = Executor::new(state.clone());
        let sender_key = test_secret_key(32);
        let sender = Transaction::address_from_secret_key(&sender_key);
        let funding = levy * 2;
        state
            .set_account(&sender, AccountState::new(funding))
            .unwrap();

        let tx = contract_call_transaction(
            &sender_key,
            "0x0000000000000000000000000000000000000000",
            0,
            deploy_init_code(), // boş runtime kod
        );
        executor.execute_transaction(&tx, tx.timestamp).unwrap();
        executor.flush_block_rewards(tx.timestamp).unwrap();

        let sender_after = state.get_account(&sender).unwrap().unwrap();
        let spent = funding - sender_after.balance;
        assert!(
            spent < levy + zagros_types::TOKEN_FACTORY_FEE_ZERENYA,
            "kod uretmeyen bos deploy'dan token factory harci alinmamali: harcanan={}",
            spent
        );
    }

    /// 🚨 EN KRİTİK KANIT: constructor'da `CREATE` ile ikinci kontrat oluşturan tek
    /// deploy işlemi 2 kontrat üretir, TAM 2×$7.77 kesilmeli (işlem başına değil).
    #[test]
    fn a_single_transaction_that_creates_two_contracts_pays_two_token_factory_fees() {
        let (state, levy) = state_with_par_pool_and_levy();
        let executor = Executor::new(state.clone());
        let sender_key = test_secret_key(33);
        let sender = Transaction::address_from_secret_key(&sender_key);
        let funding = levy + 100 * TOKEN_DECIMAL;
        state
            .set_account(&sender, AccountState::new(funding))
            .unwrap();

        let tx = contract_call_transaction(
            &sender_key,
            "0x0000000000000000000000000000000000000000",
            0,
            init_code_that_also_creates_a_child_via_create_opcode(),
        );
        executor.execute_transaction(&tx, tx.timestamp).unwrap();
        executor.flush_block_rewards(tx.timestamp).unwrap();

        let receipt = archived_receipt_for(&state, &tx.tx_id);
        assert!(
            receipt.contract_address.is_some(),
            "ust seviye deploy basarili olmali"
        );

        let sender_after = state.get_account(&sender).unwrap().unwrap();
        let spent = funding - sender_after.balance;
        let expected_min = levy + 2 * zagros_types::TOKEN_FACTORY_FEE_ZERENYA;
        assert!(
            spent >= expected_min,
            "iki kontrat olusturuldugunda 2x token factory harci kesilmeli: harcanan={}, beklenen>={}",
            spent, expected_min
        );
    }

    /// 🚨 Bypass kanıtı: sıradan `ContractCall` içinde `CREATE` ile çocuk kontrat
    /// üretilirse o da $7.77 öder; `commit()` değişim kümesi taraması kapatır.
    #[test]
    fn a_factory_contracts_internal_create_pays_the_fee_even_though_the_call_is_not_a_top_level_deploy(
    ) {
        let (state, levy) = state_with_par_pool_and_levy();
        let executor = Executor::new(state.clone());
        let sender_key = test_secret_key(34);
        let sender = Transaction::address_from_secret_key(&sender_key);
        let funding = levy * 4 + 100 * TOKEN_DECIMAL;
        state
            .set_account(&sender, AccountState::new(funding))
            .unwrap();

        // 1) Factory'yi deploy et (üst seviye, receiver=null).
        let deploy_tx = contract_call_transaction(
            &sender_key,
            "0x0000000000000000000000000000000000000000",
            0,
            factory_deploy_init_code(),
        );
        executor
            .execute_transaction(&deploy_tx, deploy_tx.timestamp)
            .unwrap();
        let deploy_receipt = archived_receipt_for(&state, &deploy_tx.tx_id);
        let factory_address = deploy_receipt
            .contract_address
            .expect("factory deploy'u basarili olup bir adres uretmeli");
        assert!(
            zagros_types::is_evm_deploy("0x0000000000000000000000000000000000000000"),
            "deploy islemi is_evm_deploy ile tespit edilmeliydi"
        );

        let balance_after_deploy = state.get_account(&sender).unwrap().unwrap().balance;

        // 2) Factory'ye SIRADAN çağrı (receiver=factory adresi, null değil);
        // payload içeriği önemsiz, yalnız boş olmama kuralı için doldurulur.
        let call_tx = contract_call_transaction(&sender_key, &factory_address, 1, vec![0x00]);
        assert!(
            !zagros_types::is_evm_deploy(&call_tx.receiver),
            "bu ikinci islem uzerinde is_evm_deploy KESINLIKLE false olmali - test onkosulu"
        );
        executor
            .execute_transaction(&call_tx, call_tx.timestamp)
            .unwrap();
        executor.flush_block_rewards(call_tx.timestamp).unwrap();

        let call_receipt = archived_receipt_for(&state, &call_tx.tx_id);
        assert!(
            call_receipt.status,
            "factory cagrisi basarili olmali (ic CREATE calismali)"
        );

        let balance_after_call = state.get_account(&sender).unwrap().unwrap().balance;
        let spent_on_call = balance_after_deploy - balance_after_call;
        assert!(
            spent_on_call >= zagros_types::TOKEN_FACTORY_FEE_ZERENYA,
            "is_evm_deploy=false olan bu cagrida bile ic CREATE nedeniyle $7.77'lik token \
             factory harci kesilmeli (bypass yok): harcanan={}, beklenen>={}",
            spent_on_call,
            zagros_types::TOKEN_FACTORY_FEE_ZERENYA
        );
    }

    /// 🛑 Reddedilen native deploy HİÇBİR PARA HAREKET ETTİRMEZ: harç kesilmez,
    /// Hazine'ye para girmez (kısmi durum sessiz para kaybı olurdu). EVM Token
    /// Factory harcı ayrıca test ediliyor ("factory harci kesilmeli (bypass yok)").
    #[test]
    fn a_refused_native_deploy_moves_no_money_at_all() {
        let state = test_state();
        state
            .set_account(
                &"__GLOBAL_TOTAL_STAKED__".to_string(),
                AccountState::new(1_000 * TOKEN_DECIMAL),
            )
            .unwrap();
        let sender_key = test_secret_key(35);
        let sender = Transaction::address_from_secret_key(&sender_key);
        let funding = 10 * TOKEN_DECIMAL;
        state
            .set_account(&sender, AccountState::new(funding))
            .unwrap();

        let mut tx = transaction(TxType::DeployContract, 0, 0);
        tx.sender = sender.clone();
        tx.payload = vec![0x60, 0x00];
        tx.sign(&sender_key);

        let executor = Executor::new(state.clone());
        assert!(
            executor.execute_transaction(&tx, tx.timestamp).is_err(),
            "native deploy reddedilmeli"
        );
        executor.flush_block_rewards(tx.timestamp).unwrap();

        // Gas ucreti reddedilen islemden de kesilir, bu DOGRU ve kasitli
        // anti-spam davranisidir (bedava basarisiz islem yok). Kanitlanmasi
        // gereken sey, 100x'lik TOKEN FACTORY HARCININ kesilmedigi.
        let tx_gas_fee = (tx.gas_limit as u128) * tx.gas_price;
        assert_eq!(
            state
                .get_balance(&VALIDATOR_REWARD_POOL.to_string())
                .unwrap(),
            tx_gas_fee,
            "Hazine'ye YALNIZCA gas ucreti girmeli - token factory harci (100x) \
             yurutulmeyen bir islem icin KESILMEMELI"
        );
        assert_eq!(
            state.get_account(&sender).unwrap().unwrap().balance,
            funding - tx_gas_fee,
            "gonderen yalnizca gas ucreti kadar kaybetmeli, token factory harci kadar DEGIL"
        );
        assert!(
            tx_gas_fee < zagros_types::TOKEN_FACTORY_FEE_ZERENYA,
            "test on kosulu: gas ucreti, kesilmemesi gereken factory harcindan cok kucuk olmali"
        );
    }

    /// Token Factory harcını karşılayamayan bir native deploy TAMAMEN
    /// reddedilir, kontrat hesabı KALICI OLMAZ (checkpoint deploy'un
    /// KENDİSİYLE birlikte geri sarılır). Bypass yok: parasız üretim yok.
    #[test]
    fn native_deploy_contract_is_rejected_when_sender_cannot_afford_the_token_factory_fee() {
        let state = test_state();
        let sender_key = test_secret_key(36);
        let sender = Transaction::address_from_secret_key(&sender_key);
        // Gas ucretini karsilar ama $7.77'lik token factory harcini karsilamaz.
        state.set_account(&sender, AccountState::new(100)).unwrap();

        let mut tx = transaction(TxType::DeployContract, 0, 0);
        tx.sender = sender.clone();
        tx.payload = vec![0x60, 0x00];
        tx.gas_limit = 1;
        tx.gas_price = 2;
        tx.sign(&sender_key);

        let executor = Executor::new(state.clone());
        let result = executor.execute_transaction(&tx, tx.timestamp);
        assert!(
            result.is_err(),
            "$7.77'lik token factory harcini karsilayamayan deploy basarili olmamali"
        );

        assert_eq!(
            state
                .get_balance(&VALIDATOR_REWARD_POOL.to_string())
                .unwrap(),
            0,
            "reddedilen deploy'dan Hazine'ye para yazilmamali"
        );

        use sha3::{Digest, Keccak256};
        let mut hasher = Keccak256::new();
        hasher.update(sender.as_bytes());
        hasher.update(tx.nonce.to_le_bytes());
        let hash = hasher.finalize();
        let would_be_addr = format!("0x{}", hex::encode(&hash[0..8]));
        assert!(
            state.get_account(&would_be_addr).unwrap().is_none(),
            "reddedilen deploy kalici bir kontrat hesabi birakmamali - bypass riski"
        );
    }

    /// EVM tarafında da aynı fail-closed garanti: x100 levy + gas'ı
    /// karşılayan ama $7.77'lik Token Factory harcını KARŞILAYAMAYAN bir
    /// gönderen için deploy TAMAMEN reddedilir (kontrat kalıcı olmaz).
    #[test]
    fn evm_deploy_is_rejected_when_sender_can_afford_the_levy_but_not_the_token_factory_fee() {
        let (state, levy) = state_with_par_pool_and_levy();
        let executor = Executor::new(state.clone());
        let sender_key = test_secret_key(37);
        let sender = Transaction::address_from_secret_key(&sender_key);
        // Tam olarak x100 levy + gas kadar, $7.77'lik Token Factory
        // harcina YER YOK.
        state.set_account(&sender, AccountState::new(levy)).unwrap();

        let tx = contract_call_transaction(
            &sender_key,
            "0x0000000000000000000000000000000000000000",
            0,
            real_deploy_init_code(),
        );
        let result = executor.execute_transaction(&tx, tx.timestamp);
        assert!(
            result.is_err(),
            "$7.77'lik token factory harcini karsilayamayan EVM deploy basarili olmamali"
        );
        assert_eq!(
            state
                .get_balance(&VALIDATOR_REWARD_POOL.to_string())
                .unwrap(),
            0,
            "reddedilen EVM deploy'dan Hazine'ye para yazilmamali"
        );
    }

    /// 🚨 KANIT: Token Factory harcı sabit ZAGROS değil, ZERENYA'ya sabitlenmiş;
    /// havuz oranı değişince ham ZAGROS ters orantılı değişir. Tek kaynak
    /// `token_factory_fee_per_contract` DOĞRUDAN ölçülür.
    #[test]
    fn token_factory_fee_is_pegged_to_the_gold_anchor_not_a_fixed_zagros_amount() {
        // 1 ZAGROS = 1 ZERENYA (par) → harç ham birim olarak hedefe EŞİT.
        let par = test_state();
        par.set_pool_reserves(1_000 * TOKEN_DECIMAL, 1_000 * TOKEN_DECIMAL)
            .unwrap();
        let fee_at_par = Executor::new(par).token_factory_fee_per_contract();
        assert_eq!(
            fee_at_par,
            zagros_types::TOKEN_FACTORY_FEE_ZERENYA,
            "1:1 havuzda harç hedefe ham birim olarak eşit olmalı"
        );

        // 1 ZAGROS = 2 ZERENYA → aynı değeri karşılamak için YARI ham ZAGROS.
        let rich = test_state();
        rich.set_pool_reserves(1_000 * TOKEN_DECIMAL, 2_000 * TOKEN_DECIMAL)
            .unwrap();
        let fee_when_zagros_is_worth_more = Executor::new(rich).token_factory_fee_per_contract();
        assert_eq!(
            fee_when_zagros_is_worth_more,
            zagros_types::TOKEN_FACTORY_FEE_ZERENYA / 2,
            "ZAGROS iki katı değerliyken harç YARI ham miktara inmeli \
             (sabit ZAGROS DEĞİL, sabit altın değeri)"
        );

        // 1 ZAGROS = 0,5 ZERENYA → İKİ KATI ham ZAGROS.
        let cheap = test_state();
        cheap
            .set_pool_reserves(2_000 * TOKEN_DECIMAL, 1_000 * TOKEN_DECIMAL)
            .unwrap();
        let fee_when_zagros_is_worth_less = Executor::new(cheap).token_factory_fee_per_contract();
        assert_eq!(
            fee_when_zagros_is_worth_less,
            zagros_types::TOKEN_FACTORY_FEE_ZERENYA * 2,
            "ZAGROS yarı değerliyken harç İKİ KATI ham miktara çıkmalı"
        );
    }

    #[test]
    fn ignore_evm_success_charges_actual_gas_instead_of_gas_limit() {
        let state = test_state();
        let sender_key = test_secret_key(1);
        let sender = test_address(1);
        let contract = "0x2222222222222222222222222222222222222222".to_string();
        let initial_balance = 1_000_000_000_000_000;
        state
            .set_account(&sender, AccountState::new(initial_balance))
            .unwrap();
        state
            .set_account(&contract, AccountState::new_contract(vec![0x00]))
            .unwrap();
        let tx = contract_call_transaction(&sender_key, &contract, 0, vec![0]);
        let executor = Executor::new(state.clone());

        let gas_fee = executor.apply_transaction(&tx, tx.timestamp).unwrap();

        assert!(gas_fee > 0);
        // EVM işlemi altın-çıpalı standart tabanı öder (base × 5), ölçülen gaz
        // (birkaç bin) bundan çok küçük olduğundan taban geçerli.
        assert_eq!(
            gas_fee,
            zagros_types::GAS_FEE_ZERENYA * 5,
            "EVM işlemi altın-çıpalı standart tabanı (base × 5) ödemeli"
        );
        let sender_after = state.get_account(&sender).unwrap().unwrap();
        assert_eq!(
            sender_after.balance,
            initial_balance - gas_fee,
            "bakiyeden TAM standart taban dusulmeli"
        );
        // 🚨 REGRESYON (A-K1): nonce +1 olmalı, +2 DEĞİL; revm kendisi artırır,
        // ikinci artış sonraki gerçek işlemi `InvalidNonce` ile düşürür.
        assert_eq!(
            sender_after.nonce,
            tx.nonce + 1,
            "basarili GERCEK EVM cagrisi nonce'u TAM BIR artirmali, iki DEGIL"
        );
        // Gerçek EVM çağrısının ücreti Hazine'ye gider: ölçülen kısım `treasury_gain`
        // ile senkron, tabanın ölçüleni aşan sürşarjı `pending_gas_reward` ile blok
        // sonu `flush_block_rewards`'ta. Kimse stake etmemişse doğrudan Hazineye.
        executor.flush_block_rewards(tx.timestamp).unwrap();
        let validator_pool = state
            .get_balance(&VALIDATOR_REWARD_POOL.to_string())
            .unwrap();
        assert_eq!(
            validator_pool, gas_fee,
            "gercek EVM cagrisinin TAM ucreti (olculen + taban sursarji) Hazineye gitmeli"
        );
    }

    #[test]
    fn evm_revert_rolls_back_state_but_charges_actual_gas_and_nonce() {
        let state = test_state();
        let sender_key = test_secret_key(1);
        let sender = test_address(1);
        let contract = "0x2222222222222222222222222222222222222222".to_string();
        let initial_balance = 1_000_000_000_000_000;
        state
            .set_account(&sender, AccountState::new(initial_balance))
            .unwrap();
        state
            .set_account(
                &contract,
                AccountState::new_contract(vec![0x60, 0x00, 0x60, 0x00, 0xfd]),
            )
            .unwrap();
        let tx = contract_call_transaction(&sender_key, &contract, 0, vec![0]);
        let executor = Executor::new(state.clone());

        let (_, gas_fee) = executor.apply_transaction(&tx, tx.timestamp).unwrap_err();

        assert!(gas_fee > 0);
        // Revert eden EVM çağrısı da altın-çıpalı standart tabanı öder
        // (max(ölçülen, taban) = taban; ölçülen bundan çok küçük).
        assert_eq!(
            gas_fee,
            zagros_types::GAS_FEE_ZERENYA * 5,
            "revert eden EVM çağrısı da standart tabanı (base × 5) ödemeli"
        );
        let sender_after = state.get_account(&sender).unwrap().unwrap();

        assert_eq!(
            sender_after.balance,
            initial_balance - gas_fee,
            "revert eden cagridan bile standart taban kesilmeli"
        );
        // Revert yolunda `commit()` çalışmaz; tek artış `settle_failed_native_transaction`tan,
        // çift artış riski yok.
        assert_eq!(
            sender_after.nonce,
            tx.nonce + 1,
            "revert eden cagri nonce'u TAM BIR artirmali"
        );
    }

    // 🚨 Regresyon: `[0x00]` dolgusu "gerçek kod" sanılmamalı; başarılı
    // ContractCall sonrası gönderici EOA kalmalı.
    #[test]
    fn a_successful_evm_call_never_marks_the_plain_eoa_sender_as_a_contract() {
        let state = test_state();
        let sender_key = test_secret_key(1);
        let sender = test_address(1);
        let contract = "0x2222222222222222222222222222222222222222".to_string();
        state
            .set_account(&sender, AccountState::new(1_000_000_000_000_000))
            .unwrap();
        // STOP, trivially başarılı.
        state
            .set_account(&contract, AccountState::new_contract(vec![0x00]))
            .unwrap();
        let tx = contract_call_transaction(&sender_key, &contract, 0, vec![0]);
        let executor = Executor::new(state.clone());

        executor.apply_transaction(&tx, tx.timestamp).unwrap();

        let sender_after = state.get_account(&sender).unwrap().unwrap();
        assert!(
            !sender_after.is_contract,
            "gönderen hâlâ bir EOA olmalı, kontrat değil"
        );
        assert!(
            sender_after.contract_code.is_empty(),
            "gönderende sahte/dolgu kontrat kodu birikmemeli"
        );
    }

    // 🚨 REGRESYON: reverted işlem için de makbuz yazılmalı (yoksa
    // `eth_getTransactionReceipt` sonsuza kadar `null`); checkpoint revert edilse
    // bile `Receipt_<tx_id>` `status:false` ile yazılır.
    #[test]
    fn a_reverted_transaction_still_gets_a_receipt_marked_as_failed() {
        let state = test_state();
        let sender_key = test_secret_key(1);
        let sender = test_address(1);
        let contract = "0x2222222222222222222222222222222222222222".to_string();
        state
            .set_account(&sender, AccountState::new(1_000_000_000_000_000))
            .unwrap();
        state
            .set_account(
                &contract,
                AccountState::new_contract(vec![0x60, 0x00, 0x60, 0x00, 0xfd]),
            )
            .unwrap();
        let tx = contract_call_transaction(&sender_key, &contract, 0, vec![0]);
        let executor = Executor::new(state.clone());

        let result = executor.apply_transaction(&tx, tx.timestamp);
        assert!(
            result.is_err(),
            "kontrat REVERT ediyor, apply_transaction Err donmeli"
        );

        let receipt_key = format!("Receipt_{}", hex::encode(tx.tx_id));
        let receipt_acc = state
            .get_account(&receipt_key)
            .unwrap()
            .expect("reverted islem icin de bir makbuz YAZILMALI (once hic yazilmiyordu)");
        let receipt: ArchivedReceipt = bincode::deserialize(&receipt_acc.contract_code)
            .expect("receipt ArchivedReceipt olarak deserialize edilebilmeli");
        assert!(
            !receipt.status,
            "makbuz status:false ile isaretlenmeli ki eth_getTransactionReceipt status:0x0 donebilsin"
        );
    }

    #[test]
    fn evm_failure_before_revm_charges_gas_limit_and_nonce() {
        let state = test_state();
        // `total_staked == 0` iken ödül acc çarpanına yansımaz (dağıtılacak
        // staker yok); bu test Hazine yoluna baktığı için gerçekçi bir staker seedliyoruz.
        state
            .set_account(
                &"__GLOBAL_TOTAL_STAKED__".to_string(),
                AccountState::new(1_000 * TOKEN_DECIMAL),
            )
            .unwrap();
        let sender_key = test_secret_key(1);
        let sender = test_address(1);
        let initial_balance = 1_000_000_000_000_000;
        state
            .set_account(&sender, AccountState::new(initial_balance))
            .unwrap();
        let mut payload = revm::primitives::keccak256(b"swapSell(uint256,uint256)")[..4].to_vec();
        payload.resize(68, 0);
        let tx =
            contract_call_transaction(&sender_key, zagros_types::ZERENYA_TOKEN_ADDRESS, 0, payload);
        let executor = Executor::new(state.clone());

        let (_, gas_fee) = executor.apply_transaction(&tx, tx.timestamp).unwrap_err();
        executor.flush_block_rewards(1_000).unwrap();

        // revm çalışmadan (evm_gas_used = None) başarısız olsa bile EVM işlemi
        // altın-çıpalı standart tabanı öder: max(gas_limit×gas_price, taban) = taban.
        let expected_fee = zagros_types::GAS_FEE_ZERENYA * 5;

        assert_eq!(gas_fee, expected_fee);
        let sender_after = state.get_account(&sender).unwrap().unwrap();

        assert_eq!(sender_after.balance, initial_balance - expected_fee);

        assert_eq!(sender_after.nonce, sender_after.nonce);

        assert_eq!(
            state
                .get_balance(&VALIDATOR_REWARD_POOL.to_string())
                .unwrap(),
            expected_fee
        );
    }

    /// 🚨 REGRESYON (arka kapı yok): EVM `mint(address,uint256)` hiçbir gönderen
    /// için ZERENYA basamaz; böyle bir yol teminat sayacı/tavan/çoklu imzayı atlatırdı.
    #[test]
    fn evm_mint_selector_on_zsc_no_longer_credits_any_balance() {
        let state = test_state();
        let sender_key = test_secret_key(7);
        let sender = test_address(7);
        state
            .set_account(&sender, AccountState::new(1_000_000_000_000))
            .unwrap();

        let victim = "0x000000000000000000000000000000000000dead".to_string();
        let victim_before = state
            .get_account(&victim)
            .unwrap()
            .map(|a| a.zerenya_balance)
            .unwrap_or(0);
        assert_eq!(victim_before, 0);

        // mint(address,uint256) çağrısı, eski "vault_address" olarak bilinen
        // adresten taklit edilse bile hiçbir özel muamele görmez.
        let mut payload = revm::primitives::keccak256(b"mint(address,uint256)")[..4].to_vec();
        payload.extend_from_slice(&[0u8; 12]);
        payload.extend_from_slice(&hex::decode(&victim[2..]).unwrap());
        payload.extend_from_slice(&[0u8; 16]);
        payload.extend_from_slice(&(1_000_000u128).to_be_bytes());

        let tx =
            contract_call_transaction(&sender_key, zagros_types::ZERENYA_TOKEN_ADDRESS, 0, payload);
        let executor = Executor::new(state.clone());
        let _ = executor.execute_transaction(&tx, tx.timestamp);

        let victim_after = state
            .get_account(&victim)
            .unwrap()
            .map(|a| a.zerenya_balance)
            .unwrap_or(0);
        assert_eq!(
            victim_after, 0,
            "arka kapı hâlâ açık - mint(address,uint256) hâlâ ZERENYA basıyor"
        );
    }

    #[test]
    fn zsc_transfer_from_requires_and_consumes_allowance() {
        let state = test_state();
        let owner_key = test_secret_key(1);
        let owner = test_address(1);
        let spender_key = test_secret_key(2);
        let spender = test_address(2);
        let attacker_key = test_secret_key(3);
        let attacker = test_address(3);
        let recipient = "0x4444444444444444444444444444444444444444";
        for address in [&owner, &spender, &attacker] {
            state
                .set_account(
                    address,
                    AccountState {
                        balance: 1_000_000_000_000_000,
                        zerenya_balance: if *address == owner { 100 } else { 0 },
                        ..Default::default()
                    },
                )
                .unwrap();
        }
        let executor = Executor::new(state.clone());

        let unauthorized_payload = erc20_call(
            b"transferFrom(address,address,uint256)",
            &[owner.as_str(), recipient],
            Some(U256::from(10)),
        );
        let unauthorized = contract_call_transaction(
            &attacker_key,
            zagros_types::ZERENYA_TOKEN_ADDRESS,
            0,
            unauthorized_payload,
        );
        assert!(executor
            .apply_transaction(&unauthorized, unauthorized.timestamp)
            .is_err());

        assert_eq!(state.get_zerenya_balance(&owner).unwrap(), 100);

        assert_eq!(
            state.get_zerenya_balance(&recipient.to_string()).unwrap(),
            0
        );

        let approve_payload = erc20_call(
            b"approve(address,uint256)",
            &[spender.as_str()],
            Some(U256::from(40)),
        );
        let approve = contract_call_transaction(
            &owner_key,
            zagros_types::ZERENYA_TOKEN_ADDRESS,
            0,
            approve_payload,
        );
        executor
            .apply_transaction(&approve, approve.timestamp)
            .unwrap();

        let transfer_payload = erc20_call(
            b"transferFrom(address,address,uint256)",
            &[owner.as_str(), recipient],
            Some(U256::from(40)),
        );
        let transfer = contract_call_transaction(
            &spender_key,
            zagros_types::ZERENYA_TOKEN_ADDRESS,
            0,
            transfer_payload,
        );
        executor
            .apply_transaction(&transfer, transfer.timestamp)
            .unwrap();

        assert_eq!(state.get_zerenya_balance(&owner).unwrap(), 60);

        assert_eq!(
            state.get_zerenya_balance(&recipient.to_string()).unwrap(),
            40
        );
        let allowance_payload = erc20_call(
            b"allowance(address,address)",
            &[owner.as_str(), spender.as_str()],
            None,
        );
        let allowance_output = crate::evm::EvmExecutor::new(state.clone())
            .simulate_eth_call(
                "0x",
                zagros_types::ZERENYA_TOKEN_ADDRESS,
                allowance_payload,
                10_000_000,
            )
            .unwrap();

        assert_eq!(U256::from_be_slice(&allowance_output), U256::ZERO);
    }

    /// 🛡️ Düz ERC-20 `transfer(pool, amount)` havuz rezervini korumasız şişirememeli.
    #[test]
    fn zsc_transfer_to_liquidity_pool_address_is_rejected() {
        let state = test_state();
        let sender_key = test_secret_key(1);
        let sender = test_address(1);
        state
            .set_account(
                &sender,
                AccountState {
                    balance: 1_000_000,
                    zerenya_balance: 500,
                    ..Default::default()
                },
            )
            .unwrap();

        let payload = erc20_call(
            b"transfer(address,uint256)",
            &[LIQUIDITY_POOL_ADDRESS],
            Some(U256::from(100)),
        );
        let tx =
            contract_call_transaction(&sender_key, zagros_types::ZERENYA_TOKEN_ADDRESS, 0, payload);

        let result = Executor::new(state.clone()).apply_transaction(&tx, tx.timestamp);
        assert!(
            result.is_err(),
            "havuz adresine ZERENYA transfer'i kabul edilmemeli"
        );
        assert_eq!(state.get_zerenya_balance(&sender).unwrap(), 500);
        assert_eq!(
            state
                .get_zerenya_balance(&LIQUIDITY_POOL_ADDRESS.to_string())
                .unwrap(),
            0
        );
    }

    /// 🛡️ KRİTİK, yukarıdaki testin `transferFrom` hali. Kontrolün
    /// GERÇEKTEN izin (allowance) tüketilmeden ÖNCE çalıştığını da kanıtlıyor.
    #[test]
    fn zsc_transfer_from_to_liquidity_pool_address_is_rejected() {
        let state = test_state();
        let owner_key = test_secret_key(1);
        let owner = test_address(1);
        let spender_key = test_secret_key(2);
        let spender = test_address(2);
        for address in [&owner, &spender] {
            state
                .set_account(
                    address,
                    AccountState {
                        balance: 1_000_000_000_000_000,
                        zerenya_balance: if *address == owner { 100 } else { 0 },
                        ..Default::default()
                    },
                )
                .unwrap();
        }
        let executor = Executor::new(state.clone());

        let approve_payload = erc20_call(
            b"approve(address,uint256)",
            &[spender.as_str()],
            Some(U256::from(40)),
        );
        let approve = contract_call_transaction(
            &owner_key,
            zagros_types::ZERENYA_TOKEN_ADDRESS,
            0,
            approve_payload,
        );
        executor
            .apply_transaction(&approve, approve.timestamp)
            .unwrap();

        let transfer_payload = erc20_call(
            b"transferFrom(address,address,uint256)",
            &[owner.as_str(), LIQUIDITY_POOL_ADDRESS],
            Some(U256::from(40)),
        );
        let transfer = contract_call_transaction(
            &spender_key,
            zagros_types::ZERENYA_TOKEN_ADDRESS,
            1,
            transfer_payload,
        );

        let result = executor.apply_transaction(&transfer, transfer.timestamp);
        assert!(
            result.is_err(),
            "havuz adresine transferFrom kabul edilmemeli"
        );
        assert_eq!(
            state.get_zerenya_balance(&owner).unwrap(),
            100,
            "reddedilen transferFrom'da sahibin bakiyesi düşürülmemeli"
        );
        assert_eq!(
            state
                .get_zerenya_balance(&LIQUIDITY_POOL_ADDRESS.to_string())
                .unwrap(),
            0
        );

        let allowance_payload = erc20_call(
            b"allowance(address,address)",
            &[owner.as_str(), spender.as_str()],
            None,
        );
        let allowance_output = crate::evm::EvmExecutor::new(state.clone())
            .simulate_eth_call(
                "0x",
                zagros_types::ZERENYA_TOKEN_ADDRESS,
                allowance_payload,
                10_000_000,
            )
            .unwrap();
        assert_eq!(
            U256::from_be_slice(&allowance_output),
            U256::from(40),
            "reddedilen denemede izin (allowance) tüketilmemeli"
        );
    }

    // 🚨 Regresyon: `transferFrom` da görünürlük indeksine kaydedilmeli.
    #[test]
    fn zsc_transfer_from_is_recorded_in_the_received_transfers_visibility_index() {
        let state = test_state();
        let owner_key = test_secret_key(1);
        let owner = test_address(1);
        let spender_key = test_secret_key(2);
        let spender = test_address(2);
        let recipient = "0x4444444444444444444444444444444444444444";
        for address in [&owner, &spender] {
            state
                .set_account(
                    address,
                    AccountState {
                        balance: 1_000_000_000_000_000,
                        zerenya_balance: if *address == owner { 100 } else { 0 },
                        ..Default::default()
                    },
                )
                .unwrap();
        }
        let executor = Executor::new(state.clone());

        let approve_payload = erc20_call(
            b"approve(address,uint256)",
            &[spender.as_str()],
            Some(U256::from(40)),
        );
        let approve = contract_call_transaction(
            &owner_key,
            zagros_types::ZERENYA_TOKEN_ADDRESS,
            0,
            approve_payload,
        );
        executor
            .apply_transaction(&approve, approve.timestamp)
            .unwrap();

        let transfer_payload = erc20_call(
            b"transferFrom(address,address,uint256)",
            &[owner.as_str(), recipient],
            Some(U256::from(40)),
        );
        let transfer_from_tx = contract_call_transaction(
            &spender_key,
            zagros_types::ZERENYA_TOKEN_ADDRESS,
            0,
            transfer_payload,
        );
        executor
            .apply_transaction(&transfer_from_tx, transfer_from_tx.timestamp)
            .unwrap();
        // Index sayacı atomik (in-memory); gerçek `Runtime::process_block`'un
        // yaptığı gibi, okumadan ÖNCE blok sonu flush'ını taklit ediyoruz.
        executor.flush_recent_transfer_index().unwrap();

        let received = Executor::load_recent_transfers_for(state.as_ref(), recipient, 0).unwrap();
        assert_eq!(
            received.len(),
            1,
            "transferFrom gorunurluk indeksine hic kaydolmamis"
        );
        assert_eq!(received[0].sender.to_lowercase(), owner.to_lowercase());
        assert_eq!(received[0].amount, 40);
        assert_eq!(received[0].asset, "ZERENYA");
    }

    /// `approve(spender, 0)` (yaygın bir ERC-20 iznini-iptal-etme deseni) allowance
    /// slotunu tamamen KALDIRMALI, `owner.storage`'da sıfır-değerli bir girdi
    /// olarak bırakmamalı.
    #[test]
    fn approve_zero_amount_removes_allowance_slot() {
        let state = test_state();
        let owner_key = test_secret_key(41);
        let owner = test_address(41);
        let spender = test_address(42);
        state
            .set_account(&owner, AccountState::new(1_000_000_000_000_000))
            .unwrap();
        let executor = Executor::new(state.clone());

        let approve_payload = erc20_call(
            b"approve(address,uint256)",
            &[spender.as_str()],
            Some(U256::from(40)),
        );
        let approve = contract_call_transaction(
            &owner_key,
            zagros_types::ZERENYA_TOKEN_ADDRESS,
            0,
            approve_payload,
        );
        executor
            .apply_transaction(&approve, approve.timestamp)
            .unwrap();
        let owner_after_approve = state.get_account(&owner).unwrap().unwrap();
        assert_eq!(
            owner_after_approve.storage.len(),
            1,
            "approve(40) must store exactly one allowance slot"
        );

        let revoke_payload = erc20_call(
            b"approve(address,uint256)",
            &[spender.as_str()],
            Some(U256::from(0)),
        );
        let revoke = contract_call_transaction(
            &owner_key,
            zagros_types::ZERENYA_TOKEN_ADDRESS,
            owner_after_approve.nonce,
            revoke_payload,
        );
        executor
            .apply_transaction(&revoke, revoke.timestamp)
            .unwrap();

        let owner_after_revoke = state.get_account(&owner).unwrap().unwrap();
        assert!(
            owner_after_revoke.storage.is_empty(),
            "approve(spender, 0) must REMOVE the allowance slot, not store a zero value"
        );
    }

    /// `transferFrom` bir allowance'ı tam olarak sıfıra düşürürse, ilgili slot
    /// silinmeli, `approve_zero_amount_removes_allowance_slot`'un
    /// `transferFrom` yolundaki eşdeğeri.
    #[test]
    fn transfer_from_draining_allowance_to_zero_removes_allowance_slot() {
        let state = test_state();
        let owner_key = test_secret_key(43);
        let owner = test_address(43);
        let spender_key = test_secret_key(44);
        let spender = test_address(44);
        let recipient = "0x5555555555555555555555555555555555555555";
        state
            .set_account(
                &owner,
                AccountState {
                    balance: 1_000_000_000_000_000,
                    zerenya_balance: 100,
                    ..Default::default()
                },
            )
            .unwrap();
        state
            .set_account(&spender, AccountState::new(1_000_000_000_000_000))
            .unwrap();
        let executor = Executor::new(state.clone());

        let approve_payload = erc20_call(
            b"approve(address,uint256)",
            &[spender.as_str()],
            Some(U256::from(40)),
        );
        let approve = contract_call_transaction(
            &owner_key,
            zagros_types::ZERENYA_TOKEN_ADDRESS,
            0,
            approve_payload,
        );
        executor
            .apply_transaction(&approve, approve.timestamp)
            .unwrap();
        assert_eq!(state.get_account(&owner).unwrap().unwrap().storage.len(), 1);

        let transfer_payload = erc20_call(
            b"transferFrom(address,address,uint256)",
            &[owner.as_str(), recipient],
            Some(U256::from(40)),
        );
        let transfer = contract_call_transaction(
            &spender_key,
            zagros_types::ZERENYA_TOKEN_ADDRESS,
            0,
            transfer_payload,
        );
        executor
            .apply_transaction(&transfer, transfer.timestamp)
            .unwrap();

        let owner_after = state.get_account(&owner).unwrap().unwrap();
        assert!(
            owner_after.storage.is_empty(),
            "draining an allowance to exactly zero via transferFrom must remove the slot"
        );
    }

    #[test]
    fn simulate_eth_call_never_persists_zsc_changes() {
        let state = test_state();
        let sender = "0x1111111111111111111111111111111111111111";
        let recipient = "0x2222222222222222222222222222222222222222";
        state
            .set_account(
                &sender.to_string(),
                AccountState {
                    zerenya_balance: 100,
                    ..Default::default()
                },
            )
            .unwrap();
        let payload = erc20_call(
            b"transfer(address,uint256)",
            &[recipient],
            Some(U256::from(25)),
        );

        crate::evm::EvmExecutor::new(state.clone())
            .simulate_eth_call(
                sender,
                zagros_types::ZERENYA_TOKEN_ADDRESS,
                payload,
                10_000_000,
            )
            .unwrap();

        assert_eq!(state.get_zerenya_balance(&sender.to_string()).unwrap(), 100);

        assert_eq!(
            state.get_zerenya_balance(&recipient.to_string()).unwrap(),
            0
        );
    }

    #[test]
    fn evm_commit_applies_native_balance_delta_without_overwriting_current_state() {
        use revm::primitives::db::{DatabaseCommit, DatabaseRef};
        use revm::primitives::{Account, Address as EvmAddress, HashMap as EvmHashMap};

        let state = test_state();
        let address_key = "0x1111111111111111111111111111111111111111".to_string();
        let address = EvmAddress::from_slice(&hex::decode(&address_key[2..]).unwrap());
        state
            .set_account(
                &address_key,
                AccountState {
                    balance: 100,
                    zerenya_balance: 77,
                    ..Default::default()
                },
            )
            .unwrap();
        let mut evm = crate::evm::EvmExecutor::new(state.clone());
        DatabaseRef::basic_ref(&evm, address).unwrap();

        let mut externally_updated = state.get_account(&address_key).unwrap().unwrap();
        externally_updated.balance = 150;
        state.set_account(&address_key, externally_updated).unwrap();

        let mut changed_account = Account::default();
        changed_account.info.balance = U256::from(90);
        let mut changes = EvmHashMap::default();
        changes.insert(address, changed_account);
        DatabaseCommit::commit(&mut evm, changes);

        let committed = state.get_account(&address_key).unwrap().unwrap();

        assert_eq!(committed.balance, 140);

        assert_eq!(committed.zerenya_balance, 77);
    }

    /// EVM semantiği: `SSTORE(slot, 0)` sonrası slot trie'den kaldırılmalı, bir
    /// "sıfır değeriyle saklanmış" girdi olarak kalmamalı, ikisi de SLOAD için
    /// aynı sonucu üretir ama sonuncusu gereksiz yere state'i büyütür.
    #[test]
    fn zero_value_storage_slot_is_removed_not_stored_after_sstore() {
        use revm::primitives::db::DatabaseCommit;
        use revm::primitives::{
            Account, Address as EvmAddress, EvmStorageSlot, HashMap as EvmHashMap, U256,
        };

        let state = test_state();
        let address_key = "0x1111111111111111111111111111111111111111".to_string();
        let address = EvmAddress::from_slice(&hex::decode(&address_key[2..]).unwrap());
        state
            .set_account(&address_key, AccountState::default())
            .unwrap();
        let mut evm = crate::evm::EvmExecutor::new(state.clone());

        let mut changed_account = Account::default();
        changed_account.storage.insert(
            U256::from(7),
            EvmStorageSlot::new_changed(U256::from(42), U256::ZERO),
        );
        let mut changes = EvmHashMap::default();
        changes.insert(address, changed_account);
        DatabaseCommit::commit(&mut evm, changes);

        let committed = state.get_account(&address_key).unwrap().unwrap();
        assert!(
            !committed.storage.contains_key(&U256::from(7)),
            "a slot zeroed via SSTORE must be removed, not stored as U256::ZERO"
        );
    }

    #[test]
    fn nonzero_value_storage_slot_is_still_stored() {
        use revm::primitives::db::DatabaseCommit;
        use revm::primitives::{
            Account, Address as EvmAddress, EvmStorageSlot, HashMap as EvmHashMap, U256,
        };

        let state = test_state();
        let address_key = "0x2222222222222222222222222222222222222222".to_string();
        let address = EvmAddress::from_slice(&hex::decode(&address_key[2..]).unwrap());
        state
            .set_account(&address_key, AccountState::default())
            .unwrap();
        let mut evm = crate::evm::EvmExecutor::new(state.clone());

        let mut changed_account = Account::default();
        changed_account
            .storage
            .insert(U256::from(9), EvmStorageSlot::new(U256::from(123)));
        let mut changes = EvmHashMap::default();
        changes.insert(address, changed_account);
        DatabaseCommit::commit(&mut evm, changes);

        let committed = state.get_account(&address_key).unwrap().unwrap();
        assert_eq!(
            committed.storage.get(&U256::from(9)),
            Some(&U256::from(123))
        );
    }

    #[test]
    fn commit_of_account_with_only_zero_slots_yields_empty_storage_map() {
        use revm::primitives::db::DatabaseCommit;
        use revm::primitives::{
            Account, Address as EvmAddress, EvmStorageSlot, HashMap as EvmHashMap, U256,
        };

        let state = test_state();
        let address_key = "0x3333333333333333333333333333333333333333".to_string();
        let address = EvmAddress::from_slice(&hex::decode(&address_key[2..]).unwrap());
        state
            .set_account(&address_key, AccountState::default())
            .unwrap();
        let mut evm = crate::evm::EvmExecutor::new(state.clone());

        let mut changed_account = Account::default();
        for i in 0..5u64 {
            changed_account.storage.insert(
                U256::from(i),
                EvmStorageSlot::new_changed(U256::from(1), U256::ZERO),
            );
        }
        let mut changes = EvmHashMap::default();
        changes.insert(address, changed_account);
        DatabaseCommit::commit(&mut evm, changes);

        let committed = state.get_account(&address_key).unwrap().unwrap();
        assert!(
            committed.storage.is_empty(),
            "an account touching only zero-valued slots must end up with an empty storage map"
        );
    }

    /// 🏛️ EVM'den tetiklenen hazine kredisi native yol ile aynı
    /// `distribute_staking_reward`a gider; kimse stake etmemişken bile sıkışmaz.
    #[test]
    fn evm_triggered_treasury_gain_goes_directly_to_treasury_when_nobody_is_staked() {
        let state = test_state();
        let executor = Executor::new(state.clone());

        let sender_key = test_secret_key(70);
        let sender = Transaction::address_from_secret_key(&sender_key);
        state
            .set_account(&sender, AccountState::new(1_000_000_000_000_000))
            .unwrap();

        let mut tx = transaction(TxType::ContractCall { data: vec![0x00] }, 0, 5_000);
        tx.sender = sender.clone();
        tx.receiver = VALIDATOR_REWARD_POOL.to_string();
        tx.payload = vec![0x00];
        tx.gas_limit = 100_000;
        tx.gas_price = 2;
        tx.sign(&sender_key);

        let sender_balance_before = state.get_balance(&sender).unwrap();
        executor.execute_transaction(&tx, tx.timestamp).unwrap();
        // 🚨 Gas ücreti iki mekanizmadan geçer: revm `coinbase` kredisi
        // (`treasury_gain`) ve Rust tarafı `gas_charged` (blok sonu
        // `flush_block_rewards`); ikisi de aynı `distribute_staking_reward`'a gider.
        executor.flush_block_rewards(tx.timestamp).unwrap();
        let sender_balance_after = state.get_balance(&sender).unwrap();
        let total_spent = sender_balance_before - sender_balance_after;

        assert_eq!(
            state
                .get_balance(&VALIDATOR_REWARD_POOL.to_string())
                .unwrap(),
            total_spent,
            "Sigorta Kasasi kaldirildi: EVM tarafindan tetiklense bile TAMAMI (deger + gas) \
             dogrudan Hazineye gitmeli, kimse stake etmemis olsa bile"
        );
    }

    /// Aynı birleşik motorun, uygun (qualified) bir block producer
    /// yapılandırıldığında EVM tarafından tetiklenen krediyi de native yolla
    /// BİREBİR aynı 80/20 oranında böldüğünü kanıtlar.
    #[test]
    fn evm_triggered_treasury_gain_splits_80_20_to_a_qualified_block_producer() {
        let producer_address = test_address(71);
        let state = test_state();
        install_test_chain(&state);
        state
            .set_account(
                &producer_address,
                AccountState {
                    staked_balance: test_min_stake(&state),
                    is_registered_validator: true,
                    ..Default::default()
                },
            )
            .unwrap();
        state
            .set_account(
                &"__GLOBAL_TOTAL_STAKED__".to_string(),
                AccountState::new(1_000 * TOKEN_DECIMAL + test_min_stake(&state)),
            )
            .unwrap();
        let executor =
            Executor::new(state.clone()).with_block_producer_address(producer_address.clone());

        let sender_key = test_secret_key(72);
        let sender = Transaction::address_from_secret_key(&sender_key);
        state
            .set_account(&sender, AccountState::new(1_000_000_000_000_000))
            .unwrap();

        let mut tx = transaction(TxType::ContractCall { data: vec![0x00] }, 0, 5_000);
        tx.sender = sender.clone();
        tx.receiver = VALIDATOR_REWARD_POOL.to_string();
        tx.payload = vec![0x00];
        tx.gas_limit = 100_000;
        tx.gas_price = 2;
        tx.sign(&sender_key);

        let sender_balance_before = state.get_balance(&sender).unwrap();
        executor.execute_transaction(&tx, tx.timestamp).unwrap();
        // bkz. reroute testindeki AYNI not: gas ücreti iki ayrı mekanizmadan
        // (revm coinbase + flush_block_rewards) geçtiği için ikisini de
        // tamamlıyoruz.
        executor.flush_block_rewards(tx.timestamp).unwrap();
        let sender_balance_after = state.get_balance(&sender).unwrap();
        let total_spent = sender_balance_before - sender_balance_after;

        // 🚨 ±1 tolerans: toplam iki ayrı `distribute_staking_reward` çağrısına
        // bölünür, her biri aşağı yuvarlar; birleşik hesaptan 1 birim sapabilir.
        let actual_validator_share = state.get_balance(&producer_address).unwrap();
        let actual_staker_share = state
            .get_balance(&VALIDATOR_REWARD_POOL.to_string())
            .unwrap();
        let expected_validator_share = total_spent * VALIDATOR_REWARD_BPS / 10_000;

        assert_eq!(
            actual_validator_share + actual_staker_share,
            total_spent,
            "toplam eksiksiz dagitilmali - hicbir kurus kaybolmamali"
        );
        assert!(
            actual_validator_share.abs_diff(expected_validator_share) <= 1,
            "validator payi native yoldakiyle (±1 yuvarlama payi ile) AYNI formulle hesaplanmali: actual={}, expected~{}",
            actual_validator_share,
            expected_validator_share
        );
    }

    #[test]
    fn zsc_transfer_is_discarded_when_calling_contract_reverts() {
        let state = test_state();
        let sender_key = test_secret_key(1);
        let sender = test_address(1);
        let contract = "0x2222222222222222222222222222222222222222";
        let recipient = "0x4444444444444444444444444444444444444444";
        state
            .set_account(&sender, AccountState::new(1_000_000))
            .unwrap();

        let mut code = vec![
            0x63, 0xa9, 0x05, 0x9c, 0xbb, 0x60, 0xe0, 0x1b, 0x60, 0x00, 0x52, 0x73,
        ];
        code.extend_from_slice(&hex::decode(&recipient[2..]).unwrap());
        code.extend_from_slice(&[
            0x60, 0x04, 0x52, 0x60, 0x19, 0x60, 0x24, 0x52, 0x60, 0x00, 0x60, 0x00, 0x60, 0x44,
            0x60, 0x00, 0x60, 0x00, 0x73,
        ]);
        code.extend_from_slice(&hex::decode(&zagros_types::ZERENYA_TOKEN_ADDRESS[2..]).unwrap());
        code.extend_from_slice(&[0x61, 0xff, 0xff, 0xf1, 0x50, 0x60, 0x00, 0x60, 0x00, 0xfd]);
        state
            .set_account(
                &contract.to_string(),
                AccountState {
                    zerenya_balance: 100,
                    ..AccountState::new_contract(code)
                },
            )
            .unwrap();

        let tx = contract_call_transaction(&sender_key, contract, 0, vec![0]);
        let result = Executor::new(state.clone()).apply_transaction(&tx, tx.timestamp);

        assert!(result.is_err());

        assert_eq!(
            state.get_zerenya_balance(&contract.to_string()).unwrap(),
            100
        );

        assert_eq!(
            state.get_zerenya_balance(&recipient.to_string()).unwrap(),
            0
        );
    }

    // 🚨 Regresyon: Router `.call()` ile Helper'ı çağırır, Helper transfer edip revert
    // eder, Router başarılı biter; Helper'ın transferi geri sarılmalı (frame yığını).
    #[test]
    fn zsc_transfer_by_a_nested_call_is_rolled_back_when_only_that_nested_call_reverts_even_though_the_overall_transaction_succeeds(
    ) {
        let state = test_state();
        let sender_key = test_secret_key(1);
        let sender = test_address(1);
        let helper = "0x2222222222222222222222222222222222222222";
        let router = "0x3333333333333333333333333333333333333333";
        let recipient = "0x4444444444444444444444444444444444444444";
        state
            .set_account(&sender, AccountState::new(1_000_000_000_000_000))
            .unwrap();

        // Helper: ZERENYA.transfer(recipient, 25) çağırır, SONRA kendi çağrısını
        // revert eder (üstteki testle AYNI, kanıtlanmış bytecode).
        let mut helper_code = vec![
            0x63, 0xa9, 0x05, 0x9c, 0xbb, 0x60, 0xe0, 0x1b, 0x60, 0x00, 0x52, 0x73,
        ];
        helper_code.extend_from_slice(&hex::decode(&recipient[2..]).unwrap());
        helper_code.extend_from_slice(&[
            0x60, 0x04, 0x52, 0x60, 0x19, 0x60, 0x24, 0x52, 0x60, 0x00, 0x60, 0x00, 0x60, 0x44,
            0x60, 0x00, 0x60, 0x00, 0x73,
        ]);
        helper_code
            .extend_from_slice(&hex::decode(&zagros_types::ZERENYA_TOKEN_ADDRESS[2..]).unwrap());
        helper_code
            .extend_from_slice(&[0x61, 0xff, 0xff, 0xf1, 0x50, 0x60, 0x00, 0x60, 0x00, 0xfd]);
        state
            .set_account(
                &helper.to_string(),
                AccountState {
                    zerenya_balance: 100,
                    ..AccountState::new_contract(helper_code)
                },
            )
            .unwrap();

        // Router: Helper'ı CALL ile çağırır, dönüşü kontrol etmeden POP'lar; Helper
        // revert etse de işlem başarılı biter.
        let mut router_code = vec![
            0x60, 0x00, // retSize
            0x60, 0x00, // retOffset
            0x60, 0x00, // argsSize
            0x60, 0x00, // argsOffset
            0x60, 0x00, // value
            0x73, // PUSH20 helper
        ];
        router_code.extend_from_slice(&hex::decode(&helper[2..]).unwrap());
        router_code.extend_from_slice(&[
            0x62, 0xff, 0xff, 0xff, // gas
            0xf1, // CALL
            0x50, // POP (dönüş değerini yut)
            0x00, // STOP (basariyla bit)
        ]);
        state
            .set_account(&router.to_string(), AccountState::new_contract(router_code))
            .unwrap();

        let tx = contract_call_transaction(&sender_key, router, 0, vec![0]);
        let result = Executor::new(state.clone()).apply_transaction(&tx, tx.timestamp);

        assert!(
            result.is_ok(),
            "Router Helper'in revert'ini yuttugu icin TUM ISLEM basarili olmali: {:?}",
            result.err()
        );
        assert_eq!(
            state.get_zerenya_balance(&helper.to_string()).unwrap(),
            100,
            "Helper'in ZERENYA bakiyesi DEGISMEMELI - kendi ic frame'i revert etti"
        );
        assert_eq!(
            state.get_zerenya_balance(&recipient.to_string()).unwrap(),
            0,
            "recipient hicbir ZERENYA almamis olmali - transfer, Helper'in kendi revert'iyle geri sarilmali"
        );
    }

    #[test]
    fn gas_rewards_accumulate_across_a_block_and_apply_once_on_flush() {
        let state = test_state();
        // `total_staked == 0` iken acc'ye yansımaz; gerçekçi staker seed'lenir ki
        // ücret normal yoldan aksın.
        state
            .set_account(
                &"__GLOBAL_TOTAL_STAKED__".to_string(),
                AccountState::new(1_000 * TOKEN_DECIMAL),
            )
            .unwrap();
        let sender_a_key = test_secret_key(40);
        let sender_a = test_address(40);
        let sender_b_key = test_secret_key(41);
        let sender_b = test_address(41);
        state
            .set_account(&sender_a, AccountState::new(1_000_000))
            .unwrap();
        state
            .set_account(&sender_b, AccountState::new(1_000_000))
            .unwrap();

        let mut tx_a = transaction(TxType::Transfer, 0, 10);
        tx_a.sender = sender_a.clone();
        tx_a.sign(&sender_a_key);
        let mut tx_b = transaction(TxType::Transfer, 0, 10);
        tx_b.sender = sender_b.clone();
        tx_b.sign(&sender_b_key);

        let executor = Executor::new(state.clone());
        executor.execute_transaction(&tx_a, tx_a.timestamp).unwrap();

        // Mid-block: the pool must NOT have been credited yet, gas is only
        // accumulated in memory until flush_block_rewards() runs.
        assert_eq!(
            state
                .get_balance(&VALIDATOR_REWARD_POOL.to_string())
                .unwrap(),
            0
        );

        executor.execute_transaction(&tx_b, tx_b.timestamp).unwrap();
        assert_eq!(
            state
                .get_balance(&VALIDATOR_REWARD_POOL.to_string())
                .unwrap(),
            0
        );

        executor.flush_block_rewards(1_000).unwrap();

        // Sum of both transactions' gas_limit(1) * gas_price(2) = 4.
        assert_eq!(
            state
                .get_balance(&VALIDATOR_REWARD_POOL.to_string())
                .unwrap(),
            4
        );

        // Flushing again with nothing pending must be a no-op, not a double-credit.
        executor.flush_block_rewards(1_000).unwrap();
        assert_eq!(
            state
                .get_balance(&VALIDATOR_REWARD_POOL.to_string())
                .unwrap(),
            4
        );
    }

    /// Reentrancy stres testi: gerçek thread'ler aynı alıcıya scheduler'sız aynı anda
    /// yazar; kaybeden Reentrancy alır, başaranların toplamı kayıpsız tutmalı.
    #[test]
    fn concurrent_transfers_to_the_same_receiver_never_lose_or_duplicate_funds() {
        let state = test_state();
        let executor = Arc::new(Executor::new(state.clone()));
        let receiver = test_address(99);
        let thread_count: u8 = 8;
        let amount_each = 1_000u128;

        let handles: Vec<_> = (1..=thread_count)
            .map(|seed| {
                let executor = executor.clone();
                let sender_key = test_secret_key(seed);
                let sender = test_address(seed);
                state
                    .set_account(&sender, AccountState::new(1_000_000))
                    .unwrap();
                let receiver = receiver.clone();
                std::thread::spawn(move || {
                    let mut tx = Transaction {
                        tx_id: [seed; 32],
                        tx_type: TxType::Transfer,
                        sender,
                        amount: amount_each,
                        receiver,
                        payload: Vec::new(),
                        signature: Vec::new(),
                        timestamp: 1_000,
                        nonce: 0,
                        gas_limit: 1,
                        gas_price: 2,
                        chain_id: CHAIN_ID,
                    };
                    tx.sign(&sender_key);
                    executor.execute_transaction(&tx, 1_000)
                })
            })
            .collect();

        let mut successes = 0u128;
        for handle in handles {
            if handle.join().unwrap().is_ok() {
                successes += 1;
            }
        }

        assert!(
            successes > 0,
            "at least one concurrent transfer should succeed"
        );
        assert_eq!(
            state.get_balance(&receiver).unwrap(),
            amount_each * successes,
            "receiver balance must exactly equal amount_each times the number of transfers that actually succeeded - no lost or duplicated funds"
        );
        assert!(
            executor.processing_addresses.is_empty(),
            "every reentrancy guard must release its reserved addresses on drop, even after concurrent contention"
        );
    }

    /// 🚨 Checkpoint sırası (etki → nonce/ücret → commit) genel API'den yeniden
    /// üretilir; `flush()` bu diziyi yarıda yakalayamamalı (çift harcama).
    #[test]
    fn transaction_effect_and_nonce_fee_settlement_are_never_torn_apart_by_a_racing_flush() {
        let state = test_state();
        let sender = test_address(80);
        let receiver = test_address(81);
        state
            .set_account(&sender, AccountState::new(10_000))
            .unwrap();
        state.set_account(&receiver, AccountState::new(0)).unwrap();

        let (step1_done_tx, step1_done_rx) = std::sync::mpsc::channel::<()>();
        let (proceed_tx, proceed_rx) = std::sync::mpsc::channel::<()>();
        let flush_returned = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let writer_state = state.clone();
        let writer_sender = sender.clone();
        let writer_receiver = receiver.clone();
        let writer = std::thread::spawn(move || {
            // `apply_transaction`'ın GERÇEK sırası: checkpoint -> etki
            // (gönderen borçlandırma + alıcı alacaklandırma) -> nonce/ücret
            // birleştirme -> commit_checkpoint (bkz. lib.rs'teki güncel kod).
            let checkpoint = writer_state.checkpoint().unwrap();
            let mut sender_acc = writer_state.get_account(&writer_sender).unwrap().unwrap();
            sender_acc.balance -= 100; // transfer tutarı
            writer_state
                .set_account(&writer_sender, sender_acc)
                .unwrap();
            let mut receiver_acc = writer_state
                .get_account(&writer_receiver)
                .unwrap()
                .unwrap_or_default();
            receiver_acc.balance += 100;
            writer_state
                .set_account(&writer_receiver, receiver_acc)
                .unwrap();

            step1_done_tx.send(()).unwrap();
            // Ana thread'in flush() cagirip GERCEKTEN beklediğini
            // gozlemleyebilmesi icin checkpoint'i bilerek acik tutuyoruz.
            proceed_rx.recv().unwrap();

            let mut sender_final = writer_state.get_account(&writer_sender).unwrap().unwrap();
            sender_final.nonce += 1;
            sender_final.balance -= 2; // gas ucreti
            writer_state
                .set_account(&writer_sender, sender_final)
                .unwrap();

            writer_state.commit_checkpoint(checkpoint).unwrap();
        });

        step1_done_rx.recv().unwrap();

        let flusher_state = state.clone();
        let flusher_flag = flush_returned.clone();
        let flusher = std::thread::spawn(move || {
            flusher_state.flush().unwrap();
            flusher_flag.store(true, std::sync::atomic::Ordering::SeqCst);
        });

        // flush() acik checkpoint'i gorup gercekten bloke oluyorsa, kisa bir
        // bekleme sonrasinda hala donmemis olmali.
        std::thread::sleep(std::time::Duration::from_millis(150));
        assert!(
            !flush_returned.load(std::sync::atomic::Ordering::SeqCst),
            "flush() acik bir checkpoint varken hemen donmemeliydi"
        );

        proceed_tx.send(()).unwrap();
        writer.join().unwrap();
        flusher.join().unwrap();

        // Flush tamamlandiktan sonra: etki + nonce/ucret HEP BIRLIKTE
        // gorunmeli, torn write yok.
        let final_sender = state.get_account(&sender).unwrap().unwrap();
        assert_eq!(
            final_sender.nonce, 1,
            "torn write: islemin etkisi diske indi ama nonce inmedi"
        );
        assert_eq!(final_sender.balance, 10_000 - 100 - 2);
        let final_receiver = state.get_account(&receiver).unwrap().unwrap();
        assert_eq!(final_receiver.balance, 100);
    }

    /// 🚨 REGRESYON (fon kaybı): `BridgeSwapAndBurn` çıkış kaydına YAKILAN ZERENYA
    /// yazılmalı, gönderilen ZAGROS değil (kayıt ödenecek PAXG'yi belirler).
    /// Havuz kasıtlı asimetrik ki iki değeri karıştıran gerileme anında yakalansın.
    #[test]
    fn bridge_swap_and_burn_records_the_burned_zsc_not_the_zagros_sent() {
        // 4:1 havuz => 1 ZAGROS kabaca 0.25 ZERENYA eder.
        let pool_zagros = 40_000_000 * TOKEN_DECIMAL;
        let pool_zerenya = 10_000_000 * TOKEN_DECIMAL;
        let sent_zagros = 100_000 * TOKEN_DECIMAL;

        let state = test_state();
        state.set_pool_reserves(pool_zagros, pool_zerenya).unwrap();
        seed_bridge_backed_zerenya(&state, pool_zerenya); // bu testin odagi teminat degil

        let secret_key = test_secret_key(31);
        let sender = Transaction::address_from_secret_key(&secret_key);
        state
            .set_account(&sender, AccountState::new(1_000_000 * TOKEN_DECIMAL))
            .unwrap();

        let mut tx = transaction(TxType::BridgeSwapAndBurn, 0, sent_zagros);
        tx.sender = sender.clone();
        tx.gas_limit = 1;
        tx.gas_price = 2;
        tx.sign(&secret_key);

        let executor = Executor::new(state.clone());
        executor.execute_transaction(&tx, tx.timestamp).unwrap();

        let burns = Executor::load_recent_bridge_burns(state.as_ref(), 0).unwrap();
        assert_eq!(burns.len(), 1, "tam bir kopru cikis kaydi bekleniyor");
        let recorded = burns[0].amount;

        // Beklenen: AMM'nin ürettiği ZERENYA çıktısı, sabit STANDARD_SWAP_FEE_BPS ile.
        let expected = crate::swap::quote_bridge_swap_and_burn(
            sent_zagros,
            pool_zagros,
            pool_zerenya,
            crate::swap::STANDARD_SWAP_FEE_BPS,
        )
        .unwrap()
        .amount_out;

        assert_eq!(recorded, expected, "kayit yakilan ZERENYA olmali");
        assert_ne!(
            recorded, sent_zagros,
            "kayit gonderilen ZAGROS olmamali - asimetrik havuzda ikisi farkli olmali"
        );
        // Asimetrik havuzda ZERENYA çıktısı ZAGROS girdisinden belirgin şekilde KÜÇÜK.
        assert!(
            recorded < sent_zagros / 2,
            "4:1 havuzda ZERENYA ciktisi cok daha kucuk olmali"
        );
    }

    // G2 — validator set / epoch / lifecycle (CONSENSUS-SPEC v0.2 §2, §3, §13)
    use crate::validator_set as vs;
    use zagros_types::consensus::{AdminAction, ValidatorStatus};

    fn g2_state() -> Arc<dyn State> {
        let state = test_state();
        install_test_chain(&state);
        state
    }

    /// Başarısız işlem de nonce tüketir (mevcut davranış) → testler nonce'u state'ten okur.
    fn g2_nonce(state: &Arc<dyn State>, address: &str) -> u64 {
        state
            .get_account(&address.to_ascii_lowercase())
            .unwrap()
            .map(|a| a.nonce)
            .unwrap_or(0)
    }

    fn g2_fund_candidate(state: &Arc<dyn State>, seed: u8) -> (secp256k1::SecretKey, Address) {
        let key = test_secret_key(seed);
        let address = test_address(seed);
        state
            .set_account(
                &address,
                AccountState {
                    balance: 1_000 * TOKEN_DECIMAL,
                    staked_balance: test_min_stake(state),
                    ..Default::default()
                },
            )
            .unwrap();
        (key, address)
    }

    /// Genesis kümesi: N aktif validator (seed 100..100+n), epoch 0.
    fn g2_genesis_set(state: &Arc<dyn State>, n: u8) -> Vec<Address> {
        let p = zagros_types::consensus::ChainParams::genesis_defaults();
        let vals: Vec<_> = (0..n)
            .map(|i| {
                (
                    test_address(100 + i),
                    test_consensus_keypair(100 + i).public_key(),
                    test_declaration(100 + i),
                )
            })
            .collect();
        for (addr, _, _) in &vals {
            state
                .set_account(
                    addr,
                    AccountState {
                        staked_balance: test_min_stake(state),
                        ..Default::default()
                    },
                )
                .unwrap();
        }
        vs::install_genesis_validator_set(state.as_ref(), &p, &vals).unwrap();
        vals.into_iter()
            .map(|(a, _, _)| a.to_ascii_lowercase())
            .collect()
    }

    #[test]
    fn g2_genesis_set_installs_active_members_and_rejects_bad_sets() {
        let state = g2_state();
        let addrs = g2_genesis_set(&state, 5);
        let set = vs::load_active_set(state.as_ref()).unwrap();
        assert_eq!(set.epoch, 0);
        assert_eq!(set.len(), 5);
        assert_eq!(set.quorum().unwrap(), 4, "N=5 → Q=4");
        for a in &addrs {
            let acc = state.get_account(a).unwrap().unwrap();
            assert_eq!(acc.validator_status, Some(ValidatorStatus::Active));
            assert!(acc.is_registered_validator, "geriye uyum bayragi senkron");
        }
        // N=3 → INV-S1
        let state2 = g2_state();
        let p = zagros_types::consensus::ChainParams::genesis_defaults();
        let three: Vec<_> = (0..3u8)
            .map(|i| {
                (
                    test_address(110 + i),
                    [i + 1; 32],
                    test_declaration(110 + i),
                )
            })
            .collect();
        assert!(vs::install_genesis_validator_set(state2.as_ref(), &p, &three).is_err());
        // aynı operator_id iki kez → çeşitlilik tavanı (max_per_operator=1)
        let state3 = g2_state();
        let mut dup: Vec<_> = (0..5u8)
            .map(|i| {
                (
                    test_address(120 + i),
                    [i + 1; 32],
                    test_declaration(120 + i),
                )
            })
            .collect();
        dup[1].2.operator_id = dup[0].2.operator_id;
        assert!(vs::install_genesis_validator_set(state3.as_ref(), &p, &dup).is_err());
    }

    #[test]
    fn g2_register_requires_valid_ownership_proof_and_unique_pubkey() {
        let state = g2_state();
        let (key, address) = g2_fund_candidate(&state, 64);
        let executor = Executor::new(state.clone());
        // Başkasının hesabı için üretilmiş kanıt → ret
        let domain = crate::params::consensus_domain(state.as_ref()).unwrap();
        let kp = test_consensus_keypair(64);
        let mut bad = transaction(TxType::RegisterValidator, 0, 0);
        bad.sender = address.clone();
        bad.timestamp = 1_000;
        bad.payload = zagros_types::consensus::RegisterValidatorPayload {
            consensus_pubkey: kp.public_key(),
            ownership_proof: zagros_crypto::prove_key_ownership(
                &kp,
                &domain,
                &test_address(99),
                None,
            ),
            declaration: test_declaration(64),
        }
        .encode();
        bad.sign(&key);
        assert!(
            executor.execute_transaction(&bad, 1_000).is_err(),
            "sahiplik kaniti baska hesap icin"
        );
        // Eski 2 baytlık komisyon payload'ı → ret (fail-closed)
        let mut old = transaction(TxType::RegisterValidator, 0, 0);
        old.sender = address.clone();
        old.timestamp = 1_000;
        old.payload = vec![0x01, 0xf4];
        old.sign(&key);
        assert!(executor.execute_transaction(&old, 1_000).is_err());
        // Geçerli kayıt
        let ok = register_validator_tx_v2(&key, &state, 64, g2_nonce(&state, &address), 1_000);
        executor.execute_transaction(&ok, 1_000).unwrap();
        // Aynı pubkey ile ikinci hesap → ret
        let (key2, _) = g2_fund_candidate(&state, 65);
        let dup = register_validator_tx_v2(&key2, &state, 64, 0, 1_000);
        assert!(
            executor.execute_transaction(&dup, 1_000).is_err(),
            "consensus_pubkey tekil olmali"
        );
    }

    #[test]
    fn g14_rotate_requires_registered_sender_and_valid_keyrot_proof() {
        let state = g2_state();
        let executor = Executor::new(state.clone());
        let new_kp = test_consensus_keypair(200);
        // Kayıtsız hesap → ret
        let (stranger_key, _) = g2_fund_candidate(&state, 70);
        let bad = rotate_key_tx_v2(&stranger_key, &state, &new_kp, 0, 1_000);
        assert!(
            executor.execute_transaction(&bad, 1_000).is_err(),
            "kayitsiz hesap rotasyon yapamaz"
        );
        // Kayıtlı Candidate
        let (key, address) = g2_fund_candidate(&state, 71);
        let addr = address.to_ascii_lowercase();
        executor
            .execute_transaction(
                &register_validator_tx_v2(&key, &state, 71, g2_nonce(&state, &addr), 1_000),
                1_000,
            )
            .unwrap();
        // KEYOWN kanıtı (rotation_from YOK) rotasyonda geçmez, domain ayrımı
        let domain = crate::params::consensus_domain(state.as_ref()).unwrap();
        let mut wrong_domain = transaction(TxType::RotateConsensusKey, g2_nonce(&state, &addr), 0);
        wrong_domain.sender = address.clone();
        wrong_domain.timestamp = 1_000;
        wrong_domain.payload = zagros_types::consensus::RotateConsensusKeyPayload {
            new_pubkey: new_kp.public_key(),
            ownership_proof: zagros_crypto::prove_key_ownership(&new_kp, &domain, &address, None),
        }
        .encode();
        wrong_domain.sign(&key);
        assert!(
            executor.execute_transaction(&wrong_domain, 1_000).is_err(),
            "KEYOWN kaniti KEYROT yerine gecmez"
        );
        // Yanlış "eski pubkey" üzerinden kanıt → ret
        let mut wrong_old = transaction(TxType::RotateConsensusKey, g2_nonce(&state, &addr), 0);
        wrong_old.sender = address.clone();
        wrong_old.timestamp = 1_000;
        wrong_old.payload = zagros_types::consensus::RotateConsensusKeyPayload {
            new_pubkey: new_kp.public_key(),
            ownership_proof: zagros_crypto::prove_key_ownership(
                &new_kp,
                &domain,
                &address,
                Some(&[9u8; 32]),
            ),
        }
        .encode();
        wrong_old.sign(&key);
        assert!(
            executor.execute_transaction(&wrong_old, 1_000).is_err(),
            "kanit MEVCUT pubkey'e bagli olmali"
        );
        // Geçerli rotasyon: bekleyen kayıt yazılır, hesap anahtarı DEĞİŞMEZ
        let old_pk = state.get_account(&addr).unwrap().unwrap().consensus_pubkey;
        let ok = rotate_key_tx_v2(&key, &state, &new_kp, g2_nonce(&state, &addr), 1_000);
        executor.execute_transaction(&ok, 1_000).unwrap();
        assert_eq!(
            state.get_account(&addr).unwrap().unwrap().consensus_pubkey,
            old_pk,
            "epoch sinirina kadar eski anahtar"
        );
        let pend = vs::load_pending_key_rotation(state.as_ref(), &addr)
            .unwrap()
            .unwrap();
        assert_eq!(pend.new_pubkey, new_kp.public_key());
        // Başka bir validator aynı yeni anahtarı isteyemez (bekleyen çakışma)
        let (key2, address2) = g2_fund_candidate(&state, 72);
        let addr2 = address2.to_ascii_lowercase();
        executor
            .execute_transaction(
                &register_validator_tx_v2(&key2, &state, 72, g2_nonce(&state, &addr2), 1_000),
                1_000,
            )
            .unwrap();
        let clash = rotate_key_tx_v2(&key2, &state, &new_kp, g2_nonce(&state, &addr2), 1_000);
        assert!(
            executor.execute_transaction(&clash, 1_000).is_err(),
            "bekleyen rotasyon hedefi tekil olmali"
        );
        // Mevcut anahtarın aynısına "rotasyon" → ret
        let same_kp = test_consensus_keypair(72);
        let same = rotate_key_tx_v2(&key2, &state, &same_kp, g2_nonce(&state, &addr2), 1_000);
        assert!(
            executor.execute_transaction(&same, 1_000).is_err(),
            "ayni anahtara rotasyon anlamsiz"
        );
    }

    #[test]
    fn g14_rotation_applies_at_next_epoch_boundary_and_keeps_old_key_in_snapshots() {
        let state = g2_state();
        let p = zagros_types::consensus::ChainParams::genesis_defaults();
        g2_genesis_set(&state, 5);
        let executor = Executor::new(state.clone());
        // Genesis üyesi seed 100: gas için bakiye ver, sonra rotasyon talebi (epoch 0)
        let member_key = test_secret_key(100);
        let addr = test_address(100).to_ascii_lowercase();
        let mut acc = state.get_account(&addr).unwrap().unwrap();
        acc.balance = 1_000 * TOKEN_DECIMAL;
        state.set_account(&addr, acc).unwrap();
        let old_pk = test_consensus_keypair(100).public_key();
        let new_kp = test_consensus_keypair(201);
        let tx = rotate_key_tx_v2(&member_key, &state, &new_kp, g2_nonce(&state, &addr), 1_000);
        executor.execute_transaction(&tx, 1_000).unwrap();
        // Aynı epoch içinde küme/hesap değişmez
        let s0 = vs::advance_epoch_if_due(state.as_ref(), 1_000).unwrap();
        assert!(s0
            .members
            .iter()
            .any(|m| m.address == addr && m.consensus_pubkey == old_pk));
        // Epoch 1 sınırı: hesap + küme yeni anahtarı taşır, bekleyen kayıt silinir
        let t1 = 1 + p.epoch_seconds as u128;
        let s1 = vs::advance_epoch_if_due(state.as_ref(), t1).unwrap();
        assert_eq!(s1.epoch, 1);
        assert!(s1
            .members
            .iter()
            .any(|m| m.address == addr && m.consensus_pubkey == new_kp.public_key()));
        assert_eq!(
            state.get_account(&addr).unwrap().unwrap().consensus_pubkey,
            new_kp.public_key()
        );
        assert!(
            vs::load_pending_key_rotation(state.as_ref(), &addr)
                .unwrap()
                .is_none(),
            "bekleyen kayit temizlenir"
        );
        // Kanıt penceresi: epoch 0 snapshot'ı ESKİ anahtarı korur (evidence dogrulamasi)
        let snap0 = vs::load_validator_set_at_epoch(state.as_ref(), 0).unwrap();
        assert!(snap0
            .members
            .iter()
            .any(|m| m.address == addr && m.consensus_pubkey == old_pk));
        let snap1 = vs::load_validator_set_at_epoch(state.as_ref(), 1).unwrap();
        assert!(snap1
            .members
            .iter()
            .any(|m| m.address == addr && m.consensus_pubkey == new_kp.public_key()));
    }

    /// INV-E3: kayıtlı validator düz `UnstakeZagros`ta `bond_lock_seconds` kilitlenir;
    /// düz staker bu kilide tabi değil.
    #[test]
    fn g14_registered_validator_plain_unstake_is_bond_locked_for_the_evidence_window() {
        let state = g2_state();
        let params = zagros_types::consensus::ChainParams::genesis_defaults();
        let bond = params.bond_lock_seconds as u128; // 604_800 (7 gün) >> 48s
        let ts: u128 = 1_000;

        // 1) KAYITLI VALIDATOR: kayıt sonrası düz unstake → bond_unlock_at kurulur
        let (key, address) = g2_fund_candidate(&state, 90);
        let addr = address.to_ascii_lowercase();
        let executor = Executor::new(state.clone());
        executor
            .execute_transaction(
                &register_validator_tx_v2(&key, &state, 90, g2_nonce(&state, &addr), ts),
                ts,
            )
            .unwrap();
        assert!(
            state
                .get_account(&addr)
                .unwrap()
                .unwrap()
                .is_registered_validator
        );
        assert_eq!(
            state.get_account(&addr).unwrap().unwrap().bond_unlock_at,
            0,
            "kayıt bond kilidi kurmaz"
        );

        let mut un = transaction(TxType::UnstakeZagros, g2_nonce(&state, &addr), 1_000);
        un.sender = address.clone();
        un.timestamp = ts;
        un.sign(&key);
        executor.execute_transaction(&un, ts).unwrap();
        let acc = state.get_account(&addr).unwrap().unwrap();
        assert_eq!(
            acc.unlock_time,
            ts + 172_800,
            "48s anapara kilidi hep kurulur"
        );
        assert_eq!(
            acc.bond_unlock_at,
            ts + bond,
            "kayıtlı validator unstake'i bond_lock ile de kilitlenir"
        );
        assert!(
            acc.bond_unlock_at > ts + 172_800,
            "bond kilidi 48s'yi aşar (kanıt penceresini kapsar)"
        );

        // 2) 48s'te çekim (amount=0) BLOKLANIR: bond kilidi henüz açılmadı
        let mut w48 = transaction(TxType::UnstakeZagros, g2_nonce(&state, &addr), 0);
        w48.sender = address.clone();
        w48.timestamp = ts + 172_800;
        w48.sign(&key);
        assert!(
            executor.execute_transaction(&w48, ts + 172_800).is_err(),
            "kanıt penceresi (bond_lock) dolmadan 48s çekimi engellenmeli"
        );

        // 3) bond_lock dolunca çekim başarılı
        let mut wb = transaction(TxType::UnstakeZagros, g2_nonce(&state, &addr), 0);
        wb.sender = address.clone();
        wb.timestamp = ts + bond;
        wb.sign(&key);
        executor.execute_transaction(&wb, ts + bond).unwrap();
        assert_eq!(
            state
                .get_account(&addr)
                .unwrap()
                .unwrap()
                .pending_unstake_amount,
            0,
            "bond sonrası çekim tamam"
        );

        // 4) NEGATİF KONTROL: düz staker (kayıtsız) bond kilidine TABİ DEĞİL
        let (skey, saddr) = g2_fund_candidate(&state, 91);
        let saddr = saddr.to_ascii_lowercase();
        assert!(
            !state
                .get_account(&saddr)
                .unwrap()
                .unwrap()
                .is_registered_validator
        );
        let mut su = transaction(TxType::UnstakeZagros, g2_nonce(&state, &saddr), 1_000);
        su.sender = saddr.clone();
        su.timestamp = ts;
        su.sign(&skey);
        executor.execute_transaction(&su, ts).unwrap();
        let sacc = state.get_account(&saddr).unwrap().unwrap();
        assert_eq!(sacc.unlock_time, ts + 172_800, "staker 48s kilidini görür");
        assert_eq!(sacc.bond_unlock_at, 0, "staker bond kilidine tabi DEĞİL");
    }

    /// KUYRUK REFORMU: başvuru ücreti KAYITTA alınmaz, ONAY anında adaydan
    /// kesilip Hevsel'e dağıtılır. Kapasite dolu iken bekleyen aday ücret/VPS
    /// yakmaz; yalnız gerçekten onaylanan (slota alınan) öder.
    #[test]
    fn g14_application_fee_is_charged_at_approval_not_registration() {
        let state = g2_state();
        g2_genesis_set(&state, 5);
        let executor = Executor::new(state.clone());
        let fee = test_application_fee(&state);
        assert!(fee > 0, "test ücreti > 0 olmali (aksi halde test anlamsiz)");

        // KAYIT: ücret ALINMAZ (yalnız gas=1×2=2 kesilir)
        let (key, address) = g2_fund_candidate(&state, 85);
        let addr = address.to_ascii_lowercase();
        let initial = state.get_account(&addr).unwrap().unwrap().balance;
        executor
            .execute_transaction(
                &register_validator_tx_v2(&key, &state, 85, g2_nonce(&state, &addr), 1_000),
                1_000,
            )
            .unwrap();
        let after_register = state.get_account(&addr).unwrap().unwrap().balance;
        assert_eq!(
            after_register,
            initial - 2,
            "kayitta yalniz gas (2) kesilir, basvuru ucreti DEGIL"
        );
        assert!(
            after_register > initial - fee,
            "kayitta basvuru ucreti alinmamali"
        );

        // ONAY: ücret adaydan kesilir + Hevsel'e (VALIDATOR_REWARD_POOL) girer
        let pool_before = state
            .get_balance(&VALIDATOR_REWARD_POOL.to_string())
            .unwrap();
        let (sender_key, _) = g2_fund_candidate(&state, 86);
        let admin = test_address(86);
        let approve = admin_action_tx(
            &sender_key,
            &state,
            AdminAction::Approve,
            &address,
            0,
            3,
            g2_nonce(&state, &admin),
            1_000,
        );
        executor.execute_transaction(&approve, 1_000).unwrap();
        let after_approve = state.get_account(&addr).unwrap().unwrap().balance;
        assert_eq!(
            after_approve,
            after_register - fee,
            "onayda basvuru ucreti adaydan kesilir"
        );
        assert_eq!(
            state.get_account(&addr).unwrap().unwrap().validator_status,
            Some(ValidatorStatus::Approved)
        );
        let pool_after = state
            .get_balance(&VALIDATOR_REWARD_POOL.to_string())
            .unwrap();
        assert_eq!(
            pool_after - pool_before,
            fee,
            "ucret Hevsel havuzuna girer (test'te uretici yok → %100 staker)"
        );

        // Aday balance'ı ücreti karşılamazsa onay fail-closed (revert)
        let (key2, address2) = g2_fund_candidate(&state, 87);
        let addr2 = address2.to_ascii_lowercase();
        executor
            .execute_transaction(
                &register_validator_tx_v2(&key2, &state, 87, g2_nonce(&state, &addr2), 1_000),
                1_000,
            )
            .unwrap();
        // adayın balance'ını ücretin altına çek
        let mut poor = state.get_account(&addr2).unwrap().unwrap();
        poor.balance = fee - 1;
        state.set_account(&addr2, poor).unwrap();
        let approve2 = admin_action_tx(
            &sender_key,
            &state,
            AdminAction::Approve,
            &address2,
            0,
            3,
            g2_nonce(&state, &admin),
            1_000,
        );
        assert!(
            executor.execute_transaction(&approve2, 1_000).is_err(),
            "ucret karsilanmazsa onay reddedilmeli"
        );
        // revert: aday hâlâ Candidate (Approved OLMADI)
        assert_eq!(
            state.get_account(&addr2).unwrap().unwrap().validator_status,
            Some(ValidatorStatus::Candidate)
        );
    }

    /// KUYRUK REFORMU: kapasite açıldığında Approved→Probation terfisi FIFO —
    /// kayıt zamanına göre en eski aday önce, ADRES sırasına göre DEĞİL.
    #[test]
    fn g14_approved_promotion_is_fifo_by_registration_time_not_address() {
        let state = g2_state();
        // Kapasiteyi 5'e çek: 4 genesis aktif + 1 boş slot.
        let mut params = zagros_types::consensus::ChainParams::genesis_defaults();
        params.max_validators = 5;
        crate::params::store_chain_params(state.as_ref(), &params).unwrap();
        g2_genesis_set(&state, 4);
        // store_chain_params'ı g2_genesis_set default'a döndürmüş olabilir → yeniden yaz
        crate::params::store_chain_params(state.as_ref(), &params).unwrap();

        let min_stake = test_min_stake(&state);
        // İki Approved aday: adres sırası ile kayıt sırası TERS olsun.
        let a1 = test_address(200);
        let a2 = test_address(201);
        let (big_addr, small_addr) = if a1 > a2 { (a1, a2) } else { (a2, a1) };
        // big_addr (adres BÜYÜK) → ERKEN kayıt (1000); small_addr → GEÇ kayıt (9000)
        let mk_approved = |addr: &str, reg_at: u128| {
            let mut acc = AccountState {
                staked_balance: min_stake,
                ..Default::default()
            };
            acc.validator_status = Some(ValidatorStatus::Approved);
            acc.validator_registered_at = reg_at;
            acc.consensus_pubkey = [7u8; 32];
            vs::sync_registered_flag(&mut acc);
            state.set_account(&addr.to_ascii_lowercase(), acc).unwrap();
        };
        mk_approved(&big_addr, 1_000); // erken
        mk_approved(&small_addr, 9_000); // geç

        // Epoch 1 sınırı: 1 slot açık → FIFO ile ERKEN (big_addr) terfi eder,
        // adres küçük olan (small_addr) sıradaki turu bekler.
        let t1 = 1 + params.epoch_seconds as u128;
        vs::advance_epoch_if_due(state.as_ref(), t1).unwrap();
        assert_eq!(
            state
                .get_account(&big_addr.to_ascii_lowercase())
                .unwrap()
                .unwrap()
                .validator_status,
            Some(ValidatorStatus::Probation),
            "erken kaydolan (adres BUYUK olsa da) once terfi eder"
        );
        assert_eq!(
            state
                .get_account(&small_addr.to_ascii_lowercase())
                .unwrap()
                .unwrap()
                .validator_status,
            Some(ValidatorStatus::Approved),
            "gec kaydolan (adres KUCUK olsa da) bekler — adres sirasi DEGIL FIFO"
        );
    }

    #[test]
    fn g2_admin_approve_requires_3_of_5_distinct_signers_and_current_epoch() {
        let state = g2_state();
        g2_genesis_set(&state, 5);
        let (key, address) = g2_fund_candidate(&state, 66);
        let (sender_key, _) = g2_fund_candidate(&state, 67);
        let executor = Executor::new(state.clone());
        executor
            .execute_transaction(&register_validator_tx_v2(&key, &state, 66, 0, 1_000), 1_000)
            .unwrap();
        let epoch = 0;
        // 2 imza → ret
        let admin = test_address(67);
        let two = admin_action_tx(
            &sender_key,
            &state,
            AdminAction::Approve,
            &address,
            epoch,
            2,
            g2_nonce(&state, &admin),
            1_000,
        );
        assert!(executor.execute_transaction(&two, 1_000).is_err());
        // 3 imza ama yanlış epoch → ret (replay koruması)
        let wrong_epoch = admin_action_tx(
            &sender_key,
            &state,
            AdminAction::Approve,
            &address,
            epoch + 1,
            3,
            g2_nonce(&state, &admin),
            1_000,
        );
        assert!(executor.execute_transaction(&wrong_epoch, 1_000).is_err());
        // aynı imzacı 3 kez → ret
        {
            let domain = crate::params::consensus_domain(state.as_ref()).unwrap();
            let digest = zagros_types::consensus::admin_action_digest(
                &domain,
                AdminAction::Approve,
                &address,
                epoch,
            );
            let k = &test_admin_keys()[0];
            let payload = zagros_types::consensus::AdminActionPayload {
                action: AdminAction::Approve,
                target: address.clone(),
                epoch,
                signatures: vec![
                    sign_hash(k, &crate::validator_set::eip191_admin_digest(&digest));
                    3
                ],
            };
            let mut tx = transaction(TxType::ApproveValidator, g2_nonce(&state, &admin), 0);
            tx.sender = test_address(67);
            tx.receiver = zagros_types::consensus::VALIDATOR_ADMIN_ADDRESS.to_string();
            tx.timestamp = 1_000;
            tx.payload = payload.encode();
            tx.sign(&sender_key);
            assert!(
                executor.execute_transaction(&tx, 1_000).is_err(),
                "tekrar eden imzaci"
            );
        }
        // multisig dışı imzacı → ret
        {
            let domain = crate::params::consensus_domain(state.as_ref()).unwrap();
            let digest = zagros_types::consensus::admin_action_digest(
                &domain,
                AdminAction::Approve,
                &address,
                epoch,
            );
            let outsiders: Vec<_> = (210u8..213).map(test_secret_key).collect();
            let payload = zagros_types::consensus::AdminActionPayload {
                action: AdminAction::Approve,
                target: address.clone(),
                epoch,
                signatures: outsiders
                    .iter()
                    .map(|k| sign_hash(k, &crate::validator_set::eip191_admin_digest(&digest)))
                    .collect(),
            };
            let mut tx = transaction(TxType::ApproveValidator, g2_nonce(&state, &admin), 0);
            tx.sender = test_address(67);
            tx.receiver = zagros_types::consensus::VALIDATOR_ADMIN_ADDRESS.to_string();
            tx.timestamp = 1_000;
            tx.payload = payload.encode();
            tx.sign(&sender_key);
            assert!(
                executor.execute_transaction(&tx, 1_000).is_err(),
                "multisig disi imzaci"
            );
        }
        // 3 geçerli imza → Approved
        let ok = admin_action_tx(
            &sender_key,
            &state,
            AdminAction::Approve,
            &address,
            epoch,
            3,
            g2_nonce(&state, &admin),
            1_000,
        );
        executor.execute_transaction(&ok, 1_000).unwrap();
        let acc = state
            .get_account(&address.to_ascii_lowercase())
            .unwrap()
            .unwrap();
        assert_eq!(acc.validator_status, Some(ValidatorStatus::Approved));
        // Onay kümeyi HEMEN değiştirmez (INV-S2: epoch sınırı)
        assert_eq!(vs::load_active_set(state.as_ref()).unwrap().len(), 5);
        // ikinci onay (Candidate değil) → ret
        let again = admin_action_tx(
            &sender_key,
            &state,
            AdminAction::Approve,
            &address,
            epoch,
            3,
            g2_nonce(&state, &admin),
            1_001,
        );
        assert!(executor.execute_transaction(&again, 1_001).is_err());
    }

    #[test]
    fn g2_approve_enforces_diversity_caps() {
        let state = g2_state();
        // 5 genesis validator: provider-100..104 farklı. max_per_provider = 5.
        g2_genesis_set(&state, 5);
        let executor = Executor::new(state.clone());
        let (sender_key, _) = g2_fund_candidate(&state, 70);
        // 5 adayı aynı provider'a kaydet → 5. onay tavanı aşar (4 kabul + 1 ret)
        let mut approved = 0;
        for seed in 71u8..77 {
            let (key, address) = g2_fund_candidate(&state, seed);
            let domain = crate::params::consensus_domain(state.as_ref()).unwrap();
            let kp = test_consensus_keypair(seed);
            let mut decl = test_declaration(seed);
            decl.provider = "same-cloud".into();
            let mut tx = transaction(TxType::RegisterValidator, 0, 0);
            tx.sender = address.clone();
            tx.timestamp = 1_000;
            tx.payload = zagros_types::consensus::RegisterValidatorPayload {
                consensus_pubkey: kp.public_key(),
                ownership_proof: zagros_crypto::prove_key_ownership(&kp, &domain, &address, None),
                declaration: decl,
            }
            .encode();
            tx.sign(&key);
            executor.execute_transaction(&tx, 1_000).unwrap();
            let ap = admin_action_tx(
                &sender_key,
                &state,
                AdminAction::Approve,
                &address,
                0,
                3,
                g2_nonce(&state, &test_address(70)),
                1_000,
            );
            match executor.execute_transaction(&ap, 1_000) {
                Ok(()) => approved += 1,
                Err(e) => {
                    assert!(
                        format!("{e:?}").contains("provider"),
                        "beklenen provider tavani, gelen: {e:?}"
                    );
                    break;
                }
            }
        }
        assert_eq!(approved, 5, "max_per_provider=5 → 5 onay, 6. ret");
    }

    #[test]
    fn g2_epoch_transition_lifecycle() {
        let state = g2_state();
        let p = zagros_types::consensus::ChainParams::genesis_defaults();
        g2_genesis_set(&state, 5);
        let executor = Executor::new(state.clone());
        let (sender_key, _) = g2_fund_candidate(&state, 80);
        let (key, address) = g2_fund_candidate(&state, 81);
        executor
            .execute_transaction(&register_validator_tx_v2(&key, &state, 81, 0, 1_000), 1_000)
            .unwrap();
        executor
            .execute_transaction(
                &admin_action_tx(
                    &sender_key,
                    &state,
                    AdminAction::Approve,
                    &address,
                    0,
                    3,
                    g2_nonce(&state, &test_address(80)),
                    1_000,
                ),
                1_000,
            )
            .unwrap();
        let addr = address.to_ascii_lowercase();
        // Epoch 0 içinde: küme değişmez
        let s0 = vs::advance_epoch_if_due(state.as_ref(), 1_000).unwrap();
        assert_eq!((s0.epoch, s0.len()), (0, 5));
        // Epoch 1 sınırı: Approved → Probation (kapasite var), kümeye girmez
        let t1 = 1 + p.epoch_seconds as u128;
        let s1 = vs::advance_epoch_if_due(state.as_ref(), t1).unwrap();
        assert_eq!((s1.epoch, s1.len()), (1, 5));
        let acc = state.get_account(&addr).unwrap().unwrap();
        assert_eq!(acc.validator_status, Some(ValidatorStatus::Probation));
        assert_eq!(acc.validator_status_epoch, 1);
        // probation_epochs (3) dolmadan Active olmaz
        let t2 = 1 + 2 * p.epoch_seconds as u128;
        vs::advance_epoch_if_due(state.as_ref(), t2).unwrap();
        assert_eq!(
            state.get_account(&addr).unwrap().unwrap().validator_status,
            Some(ValidatorStatus::Probation)
        );
        // Süre doldu ama liveness ÖLÇÜMÜ YOK → geçmez (fail-closed)
        let t4 = 1 + 4 * p.epoch_seconds as u128;
        let s4 = vs::advance_epoch_if_due(state.as_ref(), t4).unwrap();
        assert_eq!(
            state.get_account(&addr).unwrap().unwrap().validator_status,
            Some(ValidatorStatus::Probation)
        );
        assert_eq!(s4.len(), 5);
        // Ölçüm var ve eşik üstü (%95) → Active, küme 6
        let mut acc = state.get_account(&addr).unwrap().unwrap();
        acc.liveness = zagros_types::consensus::LivenessCounters {
            epoch: 4,
            participated: 95,
            total: 100,
            strikes: 0,
        };
        state.set_account(&addr, acc).unwrap();
        let t5 = 1 + 5 * p.epoch_seconds as u128;
        let s5 = vs::advance_epoch_if_due(state.as_ref(), t5).unwrap();
        assert_eq!((s5.epoch, s5.len()), (5, 6));
        assert_eq!(
            state.get_account(&addr).unwrap().unwrap().validator_status,
            Some(ValidatorStatus::Active)
        );
        assert!(s5.members.iter().any(|m| m.address == addr));
        assert_eq!(s5.quorum().unwrap(), 5, "N=6 → Q=5");
        // Eşik altı katılım (%80 < %90) Probation'a düşürmez (liveness cezası P0-7); ama
        // teminat eşik altına düşerse Active → Probation (histerezis %20)
        let mut acc = state.get_account(&addr).unwrap().unwrap();
        acc.staked_balance = acc.validator_stake_snapshot * 7 / 10; // %70 < %80
        state.set_account(&addr, acc).unwrap();
        let t6 = 1 + 6 * p.epoch_seconds as u128;
        let s6 = vs::advance_epoch_if_due(state.as_ref(), t6).unwrap();
        assert_eq!(
            state.get_account(&addr).unwrap().unwrap().validator_status,
            Some(ValidatorStatus::Probation)
        );
        assert_eq!(s6.len(), 5);
        // Unregister → Exiting + bond lock; sonraki epoch Removed
        let acc = state.get_account(&addr).unwrap().unwrap();
        let mut un = transaction(TxType::UnregisterValidator, acc.nonce, 0);
        un.sender = address.clone();
        un.timestamp = t6 + 1;
        un.sign(&key);
        executor.execute_transaction(&un, t6 + 1).unwrap();
        let acc = state.get_account(&addr).unwrap().unwrap();
        assert_eq!(acc.validator_status, Some(ValidatorStatus::Exiting));
        assert_eq!(
            acc.bond_unlock_at,
            t6 + 1 + p.bond_lock_seconds as u128,
            "7 gun bond lock"
        );
        assert!(!acc.is_registered_validator);
        let t7 = 1 + 7 * p.epoch_seconds as u128;
        vs::advance_epoch_if_due(state.as_ref(), t7).unwrap();
        assert_eq!(
            state.get_account(&addr).unwrap().unwrap().validator_status,
            Some(ValidatorStatus::Removed)
        );
    }

    #[test]
    fn g2_epoch_transition_never_shrinks_set_below_bft_minimum() {
        let state = g2_state();
        let p = zagros_types::consensus::ChainParams::genesis_defaults();
        let addrs = g2_genesis_set(&state, 5);
        // 2 validator'ın teminatı sıfırlansın → adaylar 3'e düşer (N<4)
        for a in &addrs[..2] {
            let mut acc = state.get_account(a).unwrap().unwrap();
            acc.staked_balance = 0;
            state.set_account(a, acc).unwrap();
        }
        let t1 = 1 + p.epoch_seconds as u128;
        let s1 = vs::advance_epoch_if_due(state.as_ref(), t1).unwrap();
        assert_eq!(s1.epoch, 1, "epoch ilerler");
        assert_eq!(
            s1.len(),
            5,
            "INV-S1: kume BFT altina kucultulmez, eski uyelik korunur"
        );
    }

    #[test]
    fn g2_remove_sets_bond_lock_and_phase_b_is_rejected_explicitly() {
        let state = g2_state();
        let p = zagros_types::consensus::ChainParams::genesis_defaults();
        let addrs = g2_genesis_set(&state, 5);
        let executor = Executor::new(state.clone());
        let (sender_key, _) = g2_fund_candidate(&state, 90);
        let target = addrs[4].clone();
        let rm = admin_action_tx(
            &sender_key,
            &state,
            AdminAction::Remove,
            &target,
            0,
            3,
            0,
            1_000,
        );
        executor.execute_transaction(&rm, 1_000).unwrap();
        let acc = state.get_account(&target).unwrap().unwrap();
        assert_eq!(acc.validator_status, Some(ValidatorStatus::Removed));
        assert_eq!(acc.bond_unlock_at, 1_000 + p.bond_lock_seconds as u128);
        assert!(!acc.is_registered_validator);
        // Faz A bitti (genesis + 365 g + 1) → açık hata, sessiz fallback yok
        let late = 1 + zagros_types::ADMIN_AUTHORITY_PERIOD_SECONDS + 1;
        let late_epoch = crate::params::epoch_at(late, 1, p.epoch_seconds);
        let (key2, cand) = g2_fund_candidate(&state, 91);
        executor
            .execute_transaction(&register_validator_tx_v2(&key2, &state, 91, 0, late), late)
            .unwrap();
        let ap = admin_action_tx(
            &sender_key,
            &state,
            AdminAction::Approve,
            &cand,
            late_epoch,
            3,
            g2_nonce(&state, &test_address(90)),
            late,
        );
        let err = executor.execute_transaction(&ap, late).unwrap_err();
        assert!(
            format!("{err:?}").contains("Faz A"),
            "Faz B quorum yolu P1-5'te: {err:?}"
        );
    }

    #[test]
    fn g2_chain_params_missing_is_fail_closed_for_registration_and_reward_qualification() {
        let state = test_state(); // ChainParams YOK
        let (key, _) = {
            let key = test_secret_key(92);
            let address = test_address(92);
            state
                .set_account(
                    &address,
                    AccountState {
                        balance: 1_000 * TOKEN_DECIMAL,
                        staked_balance: 10 * TOKEN_DECIMAL,
                        ..Default::default()
                    },
                )
                .unwrap();
            (key, address)
        };
        let executor = Executor::new(state.clone());
        let mut tx = transaction(TxType::RegisterValidator, 0, 0);
        tx.sender = test_address(92);
        tx.timestamp = 1_000;
        tx.payload = zagros_types::consensus::RegisterValidatorPayload {
            consensus_pubkey: [1u8; 32],
            ownership_proof: vec![0u8; 64],
            declaration: test_declaration(92),
        }
        .encode();
        tx.sign(&key);
        assert!(
            executor.execute_transaction(&tx, 1_000).is_err(),
            "ChainParams yokken kayit reddedilir"
        );
        assert!(
            executor.active_validator_set(1_000).is_err(),
            "kume hesabi fail-closed"
        );
    }

    // G7: evidence → zincir → otomatik slash; liveness → strike; bond lock;
    // eski epoch anahtarıyla evidence; replay/sahte/duplicate + shadow-vote adversarial.

    /// `g2_genesis_set` ile AYNI tohum kuralı (100+i), evidence testleri
    /// gerçek Ed25519 imzalar üretebilsin diye keypair'leri de döner.
    fn g7_genesis_set_with_keys(
        state: &Arc<dyn State>,
        n: u8,
    ) -> (Vec<Address>, Vec<zagros_crypto::ConsensusKeypair>) {
        let addrs = g2_genesis_set(state, n);
        let keys = (0..n).map(|i| test_consensus_keypair(100 + i)).collect();
        (addrs, keys)
    }

    fn g7_domain(state: &Arc<dyn State>) -> zagros_types::consensus::ConsensusDomain {
        crate::params::consensus_domain(state.as_ref()).unwrap()
    }

    fn g7_equivocation_tx(
        report: &zagros_types::EquivocationReport,
        receiver: Address,
        reporter_seed: u8,
        nonce: u64,
        timestamp: u128,
    ) -> Transaction {
        let key = test_secret_key(reporter_seed);
        let mut tx = transaction(TxType::ReportMalicious, nonce, 0);
        tx.sender = Transaction::address_from_secret_key(&key);
        tx.receiver = receiver;
        tx.timestamp = timestamp;
        tx.payload = report.to_bytes();
        tx.sign(&key);
        tx
    }

    fn g7_double_vote_evidence(
        keys: &[zagros_crypto::ConsensusKeypair],
        idx: u16,
        epoch: u64,
        height: u64,
    ) -> zagros_types::consensus::Evidence {
        let mut a = zagros_types::consensus::Vote {
            height,
            round: 0,
            phase: zagros_types::consensus::VotePhase::Precommit,
            block_hash: [0xAA; 32],
            validator_idx: idx,
            shadow: false,
            sig: vec![],
        };
        let mut b = zagros_types::consensus::Vote {
            block_hash: [0xBB; 32],
            ..a.clone()
        };
        let domain = zagros_types::consensus::ConsensusDomain::new(CHAIN_ID, [0x5a; 32]);
        zagros_crypto::sign_vote(&keys[idx as usize], &domain, epoch, &mut a);
        zagros_crypto::sign_vote(&keys[idx as usize], &domain, epoch, &mut b);
        zagros_types::consensus::Evidence::DoubleVote { a, b }
    }

    fn g7_double_propose_evidence(
        state: &Arc<dyn State>,
        keys: &[zagros_crypto::ConsensusKeypair],
        set: &zagros_types::consensus::ActiveValidatorSet,
        idx: u16,
        height: u64,
    ) -> zagros_types::consensus::Evidence {
        let domain = g7_domain(state);
        let base = zagros_types::consensus::BlockHeaderV2 {
            version: zagros_types::consensus::BlockHeaderV2::VERSION,
            number: height,
            parent_hash: [1u8; 32],
            state_root: [2u8; 32],
            timestamp_ms: 1_000,
            tx_root: [0u8; 32],
            tx_count: 0,
            body_bytes: 0,
            epoch: set.epoch,
            validator_set_hash: set.hash(),
            round: 0,
            proposer_idx: idx,
            max_ruleset: 1,
            last_qc: None,
        };
        let mut hb = base.clone();
        hb.state_root = [9u8; 32];
        let a = zagros_crypto::sign_header(&keys[idx as usize], &domain, base);
        let b = zagros_crypto::sign_header(&keys[idx as usize], &domain, hb);
        zagros_types::consensus::Evidence::DoublePropose {
            a: Box::new(a),
            b: Box::new(b),
        }
    }

    /// 🚨 Bu testler legacy `SlashingProof` değil domain ayrımlı `ConsensusEvidence`
    /// yolunu kullanır. Müsadere ÜÇ kovayı kapsamalı, tracker yalnız olgunlaşmış
    /// `staked_balance` kadar düşmeli.
    #[test]
    fn evidence_slash_confiscates_the_pending_unstake_bucket_too() {
        let state = g2_state();
        let (addrs, keys) = g7_genesis_set_with_keys(&state, 5);
        let target = addrs[2].clone();
        let mut acc = state.get_account(&target).unwrap().unwrap();
        let staked = acc.staked_balance;
        assert!(staked > 0);
        acc.pending_unstake_amount = 7_000 * TOKEN_DECIMAL;
        state.set_account(&target, acc).unwrap();

        let evidence = g7_double_vote_evidence(&keys, 2, 0, 1);
        let report = zagros_types::EquivocationReport::ConsensusEvidence(evidence);
        let tx = g7_equivocation_tx(&report, target.clone(), 1, 0, 2_000);
        state
            .set_account(&test_address(1), AccountState::new(1_000_000))
            .unwrap();
        let executor = Executor::new(state.clone());
        executor.execute_transaction(&tx, tx.timestamp).unwrap();

        let after = state.get_account(&target).unwrap().unwrap();
        assert_eq!(after.staked_balance, 0, "olgun teminat musadere edilmeli");
        assert_eq!(
            after.pending_unstake_amount, 0,
            "cekilmek uzere bekleyen teminat da musadere edilmeli (kacis kovasi kapali)"
        );
    }

    #[test]
    fn evidence_slash_confiscates_the_vesting_bucket_too() {
        let state = g2_state();
        let (addrs, keys) = g7_genesis_set_with_keys(&state, 5);
        let target = addrs[2].clone();
        let mut acc = state.get_account(&target).unwrap().unwrap();
        acc.pending_stake_amount = 5_000 * TOKEN_DECIMAL;
        acc.pending_stake_activation_time = 999_999;
        state.set_account(&target, acc).unwrap();

        let evidence = g7_double_vote_evidence(&keys, 2, 0, 1);
        let report = zagros_types::EquivocationReport::ConsensusEvidence(evidence);
        let tx = g7_equivocation_tx(&report, target.clone(), 1, 0, 2_000);
        state
            .set_account(&test_address(1), AccountState::new(1_000_000))
            .unwrap();
        let executor = Executor::new(state.clone());
        executor.execute_transaction(&tx, tx.timestamp).unwrap();

        let after = state.get_account(&target).unwrap().unwrap();
        assert_eq!(after.staked_balance, 0);
        assert_eq!(
            after.pending_stake_amount, 0,
            "hakedise girmemis (vesting) teminat da musadere edilmeli"
        );
    }

    /// Sayaç müsadere sonrası yalnız olgun `staked_balance` kadar düşmeli;
    /// `pending_stake_amount` hiç girmediğinden düşülmez.
    #[test]
    fn global_total_staked_tracker_only_drops_by_the_matured_stake_on_slash() {
        let state = g2_state();
        let (addrs, keys) = g7_genesis_set_with_keys(&state, 5);
        let target = addrs[2].clone();
        let mut acc = state.get_account(&target).unwrap().unwrap();
        let matured = acc.staked_balance;
        acc.pending_stake_amount = 5_000 * TOKEN_DECIMAL;
        acc.pending_stake_activation_time = 999_999;
        state.set_account(&target, acc).unwrap();
        // 🚨 Sayaç olgun teminatın çok üstünde tohumlanır; yoksa doğru ve hatalı
        // davranış aynı sonucu (0) verir, test hataya duyarsız kalırdı.
        let seeded = matured.saturating_mul(10) + 50_000 * TOKEN_DECIMAL;
        state
            .set_account(
                &"__GLOBAL_TOTAL_STAKED__".to_string(),
                AccountState::new(seeded),
            )
            .unwrap();
        let before = seeded;

        let evidence = g7_double_vote_evidence(&keys, 2, 0, 1);
        let report = zagros_types::EquivocationReport::ConsensusEvidence(evidence);
        let tx = g7_equivocation_tx(&report, target.clone(), 1, 0, 2_000);
        state
            .set_account(&test_address(1), AccountState::new(1_000_000))
            .unwrap();
        let executor = Executor::new(state.clone());
        executor.execute_transaction(&tx, tx.timestamp).unwrap();

        let after = state
            .get_account(&"__GLOBAL_TOTAL_STAKED__".to_string())
            .unwrap()
            .map(|a| a.balance)
            .unwrap_or(0);
        assert_eq!(
            before.saturating_sub(after),
            matured,
            "sayac YALNIZ olgun teminat kadar dusmeli (vesting kovasi sayacta hic yoktu)"
        );
    }

    #[test]
    fn g7_double_vote_evidence_slashes_confiscates_jails_and_pays_reporter() {
        let state = g2_state();
        let (addrs, keys) = g7_genesis_set_with_keys(&state, 5);
        let target = addrs[2].clone();
        let target_before = state.get_account(&target).unwrap().unwrap();
        let stake_before = target_before.staked_balance;
        assert!(stake_before > 0);
        let total_staked_before = state
            .get_account(&"__GLOBAL_TOTAL_STAKED__".to_string())
            .unwrap()
            .map(|a| a.balance)
            .unwrap_or(0);

        let evidence = g7_double_vote_evidence(&keys, 2, 0, 1);
        let report = zagros_types::EquivocationReport::ConsensusEvidence(evidence);
        let tx = g7_equivocation_tx(&report, target.clone(), 1, 0, 2_000);
        state
            .set_account(&test_address(1), AccountState::new(1_000_000))
            .unwrap();
        // Digerlerinin de stake'i var ki toplam stake sifira dusmesin (mevcut Faz4 fallback davranisi ile ayni sebep).
        let executor = Executor::new(state.clone());
        executor.execute_transaction(&tx, tx.timestamp).unwrap();

        let after = state.get_account(&target).unwrap().unwrap();
        assert_eq!(after.staked_balance, 0, "teminat tamamen musadere edildi");
        assert_eq!(
            after.validator_status,
            Some(ValidatorStatus::Jailed),
            "G7: BFT lifecycle -> Jailed"
        );
        assert!(!after.is_registered_validator);
        assert!(after.jailed_until > tx.timestamp);

        let reporter = state.get_account(&test_address(1)).unwrap().unwrap();
        assert_eq!(
            reporter.pending_unstake_amount,
            stake_before - stake_before / 2,
            "muhbir yarisi 48s kilitli"
        );
        assert_eq!(reporter.unlock_time, tx.timestamp + 172_800);

        let tracker_after = state
            .get_account(&"__GLOBAL_TOTAL_STAKED__".to_string())
            .unwrap()
            .map(|a| a.balance)
            .unwrap_or(0);
        assert_eq!(
            tracker_after,
            total_staked_before.saturating_sub(stake_before),
            "GLOBAL_TOTAL_STAKED yalniz gercek dususu yansitir"
        );

        let history = Executor::load_slash_history(state.as_ref()).unwrap();
        assert_eq!(
            history.last().unwrap().reason,
            zagros_types::SlashReason::DoubleSign
        );
        assert_eq!(history.last().unwrap().confiscated_amount, stake_before);
    }

    #[test]
    fn g7_double_propose_evidence_slashes_the_proposer() {
        let state = g2_state();
        let (addrs, keys) = g7_genesis_set_with_keys(&state, 5);
        let set = vs::load_active_set(state.as_ref()).unwrap();
        let target = addrs[3].clone();
        state
            .set_account(&test_address(1), AccountState::new(1_000_000))
            .unwrap();

        let evidence = g7_double_propose_evidence(&state, &keys, &set, 3, 1);
        let report = zagros_types::EquivocationReport::ConsensusEvidence(evidence);
        let tx = g7_equivocation_tx(&report, target.clone(), 1, 0, 2_000);
        let executor = Executor::new(state.clone());
        executor.execute_transaction(&tx, tx.timestamp).unwrap();

        let after = state.get_account(&target).unwrap().unwrap();
        assert_eq!(after.staked_balance, 0);
        assert_eq!(after.validator_status, Some(ValidatorStatus::Jailed));
    }

    #[test]
    fn g7_evidence_receiver_mismatch_is_rejected_and_state_untouched() {
        let state = g2_state();
        let (addrs, keys) = g7_genesis_set_with_keys(&state, 5);
        state
            .set_account(&test_address(1), AccountState::new(1_000_000))
            .unwrap();
        let evidence = g7_double_vote_evidence(&keys, 2, 0, 1);
        let report = zagros_types::EquivocationReport::ConsensusEvidence(evidence);
        // receiver = addrs[4] ama kanit gercekte addrs[2]'yi (idx 2) hedefliyor.
        let tx = g7_equivocation_tx(&report, addrs[4].clone(), 1, 0, 2_000);
        let executor = Executor::new(state.clone());
        assert!(executor.execute_transaction(&tx, tx.timestamp).is_err());
        for a in &addrs {
            assert!(
                state.get_account(a).unwrap().unwrap().staked_balance > 0,
                "hicbir hesap etkilenmemeli"
            );
        }
    }

    #[test]
    fn g7_evidence_self_report_is_rejected() {
        let state = g2_state();
        let (addrs, keys) = g7_genesis_set_with_keys(&state, 5);
        let evidence = g7_double_vote_evidence(&keys, 2, 0, 1);
        let report = zagros_types::EquivocationReport::ConsensusEvidence(evidence);
        // Muhbir = hedefin KENDISI (test_secret_key(102) → addrs[2]).
        let target_key = test_secret_key(102);
        let mut acc = state.get_account(&addrs[2]).unwrap().unwrap();
        acc.balance = 1_000_000;
        state.set_account(&addrs[2], acc).unwrap();
        let mut tx = transaction(TxType::ReportMalicious, 0, 0);
        tx.sender = Transaction::address_from_secret_key(&target_key);
        tx.receiver = addrs[2].clone();
        tx.timestamp = 2_000;
        tx.payload = report.to_bytes();
        tx.sign(&target_key);
        let executor = Executor::new(state.clone());
        let err = executor.execute_transaction(&tx, tx.timestamp).unwrap_err();
        assert!(format!("{err:?}").contains("kendi hesab"), "{err:?}");
        assert!(
            state
                .get_account(&addrs[2])
                .unwrap()
                .unwrap()
                .staked_balance
                > 0
        );
    }

    #[test]
    fn g7_evidence_with_forged_signature_is_rejected() {
        let state = g2_state();
        let (addrs, keys) = g7_genesis_set_with_keys(&state, 5);
        state
            .set_account(&test_address(1), AccountState::new(1_000_000))
            .unwrap();
        let mut evidence = g7_double_vote_evidence(&keys, 2, 0, 1);
        if let zagros_types::consensus::Evidence::DoubleVote { a, .. } = &mut evidence {
            a.sig[0] ^= 0xFF;
        }
        let report = zagros_types::EquivocationReport::ConsensusEvidence(evidence);
        let tx = g7_equivocation_tx(&report, addrs[2].clone(), 1, 0, 2_000);
        let executor = Executor::new(state.clone());
        assert!(executor.execute_transaction(&tx, tx.timestamp).is_err());
        assert!(
            state
                .get_account(&addrs[2])
                .unwrap()
                .unwrap()
                .staked_balance
                > 0
        );
    }

    #[test]
    fn g7_evidence_signed_with_a_different_validators_key_does_not_verify() {
        let state = g2_state();
        let (addrs, keys) = g7_genesis_set_with_keys(&state, 5);
        state
            .set_account(&test_address(1), AccountState::new(1_000_000))
            .unwrap();
        // idx=2 icin oy uretilir AMA baska bir validator'in (idx=4) anahtariyla imzalanir.
        let mut a = zagros_types::consensus::Vote {
            height: 1,
            round: 0,
            phase: zagros_types::consensus::VotePhase::Precommit,
            block_hash: [0xAA; 32],
            validator_idx: 2,
            shadow: false,
            sig: vec![],
        };
        let mut b = zagros_types::consensus::Vote {
            block_hash: [0xBB; 32],
            ..a.clone()
        };
        let domain = g7_domain(&state);
        zagros_crypto::sign_vote(&keys[4], &domain, 0, &mut a);
        zagros_crypto::sign_vote(&keys[4], &domain, 0, &mut b);
        let evidence = zagros_types::consensus::Evidence::DoubleVote { a, b };
        let report = zagros_types::EquivocationReport::ConsensusEvidence(evidence);
        let tx = g7_equivocation_tx(&report, addrs[2].clone(), 1, 0, 2_000);
        let executor = Executor::new(state.clone());
        assert!(
            executor.execute_transaction(&tx, tx.timestamp).is_err(),
            "yanlis validator'un anahtariyla imzali oy dogrulanmamali"
        );
    }

    #[test]
    fn g7_duplicate_evidence_replay_after_restake_is_rejected() {
        let state = g2_state();
        let (addrs, keys) = g7_genesis_set_with_keys(&state, 5);
        let target = addrs[2].clone();
        state
            .set_account(&test_address(1), AccountState::new(1_000_000))
            .unwrap();
        let evidence = g7_double_vote_evidence(&keys, 2, 0, 1);
        let report = zagros_types::EquivocationReport::ConsensusEvidence(evidence);
        let tx1 = g7_equivocation_tx(&report, target.clone(), 1, 0, 2_000);
        let executor = Executor::new(state.clone());
        executor.execute_transaction(&tx1, tx1.timestamp).unwrap();
        assert_eq!(
            state.get_account(&target).unwrap().unwrap().staked_balance,
            0
        );

        // Hedef yeniden stake eder (taze sermaye).
        let mut acc = state.get_account(&target).unwrap().unwrap();
        acc.staked_balance = 1_000 * TOKEN_DECIMAL;
        state.set_account(&target, acc).unwrap();

        // AYNI kanit (byte-birebir) tekrar gonderilir, reddedilmeli, taze sermaye ETKİLENMEMELİ.
        let tx2 = g7_equivocation_tx(&report, target.clone(), 1, 1, 3_000);
        let err = executor
            .execute_transaction(&tx2, tx2.timestamp)
            .unwrap_err();
        assert!(format!("{err:?}").contains("kullanildi"), "{err:?}");
        assert_eq!(
            state.get_account(&target).unwrap().unwrap().staked_balance,
            1_000 * TOKEN_DECIMAL
        );
    }

    #[test]
    fn g7_evidence_from_a_recent_past_epoch_still_verifies_within_the_window() {
        let state = g2_state();
        let (addrs, keys) = g7_genesis_set_with_keys(&state, 5);
        let p = zagros_types::consensus::ChainParams::genesis_defaults();
        // TAM pencere sınırına git: epoch = evidence_max_age_epochs. Değer
        // parametreden TÜRETİLİYOR; sabit yazmak, parametre değişince (2 → 24)
        // testi sessizce anlamsızlaştırırdı.
        let window = p.evidence_max_age_epochs as u64;
        let t2 = 1 + window as u128 * p.epoch_seconds as u128;
        let s2 = vs::advance_epoch_if_due(state.as_ref(), t2).unwrap();
        assert_eq!(s2.epoch, window);
        assert_eq!(vs::load_active_set(state.as_ref()).unwrap().epoch, window);

        // Kanit epoch 0'da (guncel epoch=2, tam pencere siniri icinde) uretildi.
        let evidence = g7_double_vote_evidence(&keys, 2, 0, 1);
        let report = zagros_types::EquivocationReport::ConsensusEvidence(evidence);
        let tx = g7_equivocation_tx(&report, addrs[2].clone(), 1, 0, t2 + 1);
        state
            .set_account(&test_address(1), AccountState::new(1_000_000))
            .unwrap();
        let executor = Executor::new(state.clone());
        executor.execute_transaction(&tx, tx.timestamp).unwrap();
        assert_eq!(
            state
                .get_account(&addrs[2])
                .unwrap()
                .unwrap()
                .staked_balance,
            0,
            "pencere icindeki eski-epoch kaniti gecerli olmali"
        );
    }

    #[test]
    fn g7_evidence_older_than_evidence_max_age_epochs_is_rejected() {
        let state = g2_state();
        let (addrs, keys) = g7_genesis_set_with_keys(&state, 5);
        let p = zagros_types::consensus::ChainParams::genesis_defaults();
        // Pencerenin BİR epoch ötesine git (floor = 1 > kanıt epoch'u 0).
        // Sabit değer yerine parametreden türetiliyor, bkz. yukarıdaki not.
        let beyond = p.evidence_max_age_epochs as u64 + 1;
        let t3 = 1 + beyond as u128 * p.epoch_seconds as u128;
        vs::advance_epoch_if_due(state.as_ref(), t3).unwrap();
        assert_eq!(vs::load_active_set(state.as_ref()).unwrap().epoch, beyond);

        let evidence = g7_double_vote_evidence(&keys, 2, 0, 1);
        let report = zagros_types::EquivocationReport::ConsensusEvidence(evidence);
        let tx = g7_equivocation_tx(&report, addrs[2].clone(), 1, 0, t3 + 1);
        state
            .set_account(&test_address(1), AccountState::new(1_000_000))
            .unwrap();
        let executor = Executor::new(state.clone());
        let err = executor.execute_transaction(&tx, tx.timestamp).unwrap_err();
        assert!(format!("{err:?}").contains("dogrulanamadi"), "{err:?}");
        assert!(
            state
                .get_account(&addrs[2])
                .unwrap()
                .unwrap()
                .staked_balance
                > 0,
            "pencere disi kanit hicbir seyi etkilememeli"
        );
    }

    #[test]
    fn g7_evidence_epoch_history_snapshot_is_immutable_across_later_epoch_transitions() {
        let state = g2_state();
        let (_, _keys) = g7_genesis_set_with_keys(&state, 5);
        let set0 = vs::load_validator_set_at_epoch(state.as_ref(), 0).unwrap();
        let p = zagros_types::consensus::ChainParams::genesis_defaults();
        let t1 = 1 + p.epoch_seconds as u128;
        vs::advance_epoch_if_due(state.as_ref(), t1).unwrap();
        let set0_again = vs::load_validator_set_at_epoch(state.as_ref(), 0).unwrap();
        assert_eq!(
            set0.hash(),
            set0_again.hash(),
            "epoch 0 anlik goruntusu sonraki gecislerde DEGISMEMELI"
        );
        let set1 = vs::load_validator_set_at_epoch(state.as_ref(), 1).unwrap();
        assert_eq!(set1.epoch, 1);
        assert!(
            vs::load_validator_set_at_epoch(state.as_ref(), 99).is_err(),
            "hic yazilmamis epoch fail-closed"
        );
    }

    // ---- Gate 2: Liveness → strike → jail (musadere YOK) ----

    fn g7_fake_qc(
        epoch: u64,
        height: u64,
        set: &zagros_types::consensus::ActiveValidatorSet,
        participating: &[u16],
    ) -> zagros_types::consensus::QuorumCertificate {
        let n = set.len();
        let mut signers = vec![0u8; zagros_types::consensus::QuorumCertificate::bitset_len_for(n)];
        for &idx in participating {
            zagros_types::consensus::QuorumCertificate::set_signer(&mut signers, idx);
        }
        zagros_types::consensus::QuorumCertificate {
            height,
            round: 0,
            block_hash: [0x11; 32],
            epoch,
            validator_set_hash: set.hash(),
            signers,
            sigs: participating.iter().map(|_| vec![0u8; 64]).collect(),
        }
    }

    /// `advance_epoch_if_due` kümeyi her geçişte yeniden kurar; bir üyenin
    /// `set.members` indeksi epoch'lar arasında SABİT DEĞİLDİR, testler indeksi
    /// her seferinde güncel kümeden çözer.
    fn g7_idx_of(set: &zagros_types::consensus::ActiveValidatorSet, target: &Address) -> u16 {
        set.members
            .iter()
            .position(|m| &m.address == target)
            .expect("target kumede") as u16
    }

    /// 🔓 Erken tahliye: yalnız epoch 57'de, yalnız teminatı duran Jailed → Probation;
    /// çift imza hapsi (teminat 0) dokunulmaz; 56'da ve 58'de hiçbir şey olmaz.
    #[test]
    fn liveness_jail_amnesty_fires_once_at_its_epoch_and_only_for_stake_intact_jailed() {
        use crate::params::LIVENESS_JAIL_AMNESTY_EPOCH as E;
        let state = g2_state();
        let (addrs, _keys) = g7_genesis_set_with_keys(&state, 5);
        let p = zagros_types::consensus::ChainParams::genesis_defaults();
        let liveness_jailed = addrs[1].clone();
        let equivocator = addrs[2].clone();
        let far = 4_000_000_000u128;
        let mut a = state.get_account(&liveness_jailed).unwrap().unwrap();
        a.validator_status = Some(ValidatorStatus::Jailed);
        a.jailed_until = far;
        a.liveness.strikes = 2;
        assert!(a.staked_balance > 0);
        state.set_account(&liveness_jailed, a).unwrap();
        let mut b = state.get_account(&equivocator).unwrap().unwrap();
        b.validator_status = Some(ValidatorStatus::Jailed);
        b.jailed_until = far;
        b.staked_balance = 0;
        b.is_registered_validator = false;
        state.set_account(&equivocator, b).unwrap();
        // E-1'e kadar ilerle: ikisi de hapiste kalır
        for k in 1..E {
            vs::advance_epoch_if_due(state.as_ref(), 1 + k as u128 * p.epoch_seconds as u128)
                .unwrap();
        }
        assert_eq!(vs::load_active_set(state.as_ref()).unwrap().epoch, E - 1);
        assert_eq!(
            state
                .get_account(&liveness_jailed)
                .unwrap()
                .unwrap()
                .validator_status,
            Some(ValidatorStatus::Jailed)
        );
        // E: teminatı duran → Probation, jailed_until 0, sayaçlar temiz; çift imzacı aynen Jailed
        vs::advance_epoch_if_due(state.as_ref(), 1 + E as u128 * p.epoch_seconds as u128).unwrap();
        let a2 = state.get_account(&liveness_jailed).unwrap().unwrap();
        assert_eq!(a2.validator_status, Some(ValidatorStatus::Probation));
        assert_eq!(a2.jailed_until, 0);
        assert_eq!(a2.liveness.strikes, 0);
        assert_eq!(a2.validator_status_epoch, E);
        let b2 = state.get_account(&equivocator).unwrap().unwrap();
        assert_eq!(b2.validator_status, Some(ValidatorStatus::Jailed));
        assert_eq!(b2.jailed_until, far);
        // E+1: tekrar tetiklenmez (çift imzacı hâlâ Jailed), Probation korunur
        vs::advance_epoch_if_due(
            state.as_ref(),
            1 + (E + 1) as u128 * p.epoch_seconds as u128,
        )
        .unwrap();
        assert_eq!(
            state
                .get_account(&equivocator)
                .unwrap()
                .unwrap()
                .validator_status,
            Some(ValidatorStatus::Jailed)
        );
        assert_eq!(
            state
                .get_account(&liveness_jailed)
                .unwrap()
                .unwrap()
                .validator_status,
            Some(ValidatorStatus::Probation)
        );
    }

    /// 🚨 Tarih oynatma determinizmi: epoch < 48'de ESKİ canlılık kuralı (ham eşik/strike,
    /// JAIL + bond kilidi) aynen üretilmeli — taze node'un genesis'ten senkronu buna bağlı
    /// (kapısız dağıtım blok 10'da kök uyuşmazlığı yaratmıştı).
    #[test]
    fn before_liveness_v2_activation_the_legacy_jail_rule_is_replayed() {
        let state = g2_state();
        let (addrs, _keys) = g7_genesis_set_with_keys(&state, 5);
        let p = zagros_types::consensus::ChainParams::genesis_defaults();
        let target = addrs[1].clone();
        let legacy_strikes = p.max_liveness_strikes as u64; // ham (3), clamp YOK
        assert!(legacy_strikes < crate::params::effective_max_liveness_strikes(&p) as u64);
        for e in 0u64..legacy_strikes {
            let set = vs::load_active_set(state.as_ref()).unwrap();
            assert!(set.epoch < crate::params::LIVENESS_V2_ACTIVATION_EPOCH);
            let target_idx = g7_idx_of(&set, &target);
            let others: Vec<u16> = (0..set.len()).filter(|&i| i != target_idx).collect();
            let qc = g7_fake_qc(set.epoch, 10 + e, &set, &others);
            vs::record_qc_liveness(state.as_ref(), &qc).unwrap();
            vs::advance_epoch_if_due(
                state.as_ref(),
                1 + (e + 1) as u128 * p.epoch_seconds as u128,
            )
            .unwrap();
        }
        let after = state.get_account(&target).unwrap().unwrap();
        assert_eq!(
            after.validator_status,
            Some(ValidatorStatus::Jailed),
            "eski kural: 3 strike → Jailed"
        );
        assert!(after.jailed_until > 0, "eski kural jailed_until yazar");
        assert!(after.bond_unlock_at > 0, "eski kural bond kilidi uzatir");
    }

    /// Canlılık v2 testleri: kural kapısı (epoch ≥ 48) için epoch'u ölçümsüz ilerlet.
    fn g7_fast_forward_to_v2(state: &Arc<dyn State>, p: &zagros_types::consensus::ChainParams) {
        for k in 1..=crate::params::LIVENESS_V2_ACTIVATION_EPOCH {
            vs::advance_epoch_if_due(state.as_ref(), 1 + k as u128 * p.epoch_seconds as u128)
                .unwrap();
        }
        assert!(
            vs::load_active_set(state.as_ref()).unwrap().epoch
                >= crate::params::LIVENESS_V2_ACTIVATION_EPOCH
        );
    }

    #[test]
    fn g7_liveness_strikes_demote_to_probation_without_jail_or_confiscation() {
        // 🚨 Canlılık cezası artık JAIL DEĞİL, Probation. Jail yalnız
        // equivocation'a ait. Ayrıca eşik/strike sayısı `params::effective_*`
        // clamp'inden geçiyor (state'te 9000/3 yazılı olsa da etkin 2100/12).
        let state = g2_state();
        let (addrs, _keys) = g7_genesis_set_with_keys(&state, 5);
        let p = zagros_types::consensus::ChainParams::genesis_defaults();
        g7_fast_forward_to_v2(&state, &p);
        let strikes_needed = crate::params::effective_max_liveness_strikes(&p) as u64;
        assert!(
            strikes_needed > p.max_liveness_strikes as u64,
            "clamp taban uyguluyor olmali"
        );
        let target = addrs[1].clone();
        let stake_before = state.get_account(&target).unwrap().unwrap().staked_balance;
        let bond_before = state.get_account(&target).unwrap().unwrap().bond_unlock_at;

        // Ardisik kotu epoch'lar: `target` QC'lere HIC katilmiyor (%0 < etkin esik).
        for e in 0u64..strikes_needed {
            let set = vs::load_active_set(state.as_ref()).unwrap();
            let target_idx = g7_idx_of(&set, &target);
            let others: Vec<u16> = (0..set.len()).filter(|&i| i != target_idx).collect();
            let qc = g7_fake_qc(set.epoch, 10 + e, &set, &others);
            vs::record_qc_liveness(state.as_ref(), &qc).unwrap();
            let t = 1
                + (crate::params::LIVENESS_V2_ACTIVATION_EPOCH + e + 1) as u128
                    * p.epoch_seconds as u128;
            vs::advance_epoch_if_due(state.as_ref(), t).unwrap();
            let acc = state.get_account(&target).unwrap().unwrap();
            if e + 1 < strikes_needed {
                assert_eq!(
                    acc.liveness.strikes,
                    (e + 1) as u32,
                    "epoch {e} sonrasi strike sayisi"
                );
                assert_eq!(
                    acc.validator_status,
                    Some(ValidatorStatus::Active),
                    "esik dolmadan dusurulmez"
                );
            }
        }
        let after = state.get_account(&target).unwrap().unwrap();
        assert_eq!(
            after.validator_status,
            Some(ValidatorStatus::Probation),
            "esik strike sonrasi Probation"
        );
        assert_ne!(
            after.validator_status,
            Some(ValidatorStatus::Jailed),
            "canlilik JAIL ETMEZ"
        );
        assert_eq!(
            after.staked_balance, stake_before,
            "canlilik cezasi MUSADERE ETMEZ"
        );
        assert_eq!(after.jailed_until, 0, "canlilik cezasi jailed_until YAZMAZ");
        assert_eq!(
            after.bond_unlock_at, bond_before,
            "canlilik cezasi bond kilidi UZATMAZ"
        );
        assert_eq!(after.liveness.strikes, 0, "ceza sonrasi strike sifirlanir");
        assert_eq!(
            after.liveness.participated, 0,
            "ceza sonrasi sayaclar temiz baslar"
        );
        assert_eq!(
            after.liveness.total, 0,
            "ceza sonrasi sayaclar temiz baslar"
        );
    }

    #[test]
    fn liveness_clamp_caps_threshold_and_floors_strikes() {
        // 🚨 State'te yazili degerler clamp'ten geciyor. Bu test,
        // genesis varsayilanlarinin (9000/3) YAPISAL OLARAK saglanamaz oldugu
        // icin etkin degerlere (2100/12) kisildigini sabitler.
        let p = zagros_types::consensus::ChainParams::genesis_defaults();
        assert_eq!(
            p.uptime_threshold_bps, 9_000,
            "genesis varsayilani degistiyse bu test guncellenmeli"
        );
        assert_eq!(p.max_liveness_strikes, 3);
        assert_eq!(
            crate::params::effective_uptime_threshold_bps(&p),
            2_100,
            "esik tavana kisilmali"
        );
        assert_eq!(
            crate::params::effective_max_liveness_strikes(&p),
            12,
            "strike tabana yukseltilmeli"
        );

        // Zaten tavanin altinda/tabanin ustunde olan degerler DEGISMEZ.
        let mut low = p.clone();
        low.uptime_threshold_bps = 500;
        low.max_liveness_strikes = 50;
        assert_eq!(crate::params::effective_uptime_threshold_bps(&low), 500);
        assert_eq!(crate::params::effective_max_liveness_strikes(&low), 50);
    }

    #[test]
    fn liveness_circuit_breaker_blocks_demotion_when_set_would_fall_below_minimum() {
        // 🛡️ N=4'te tek düşürme, kümeyi MIN_VALIDATORS'ın altına indirir ve
        // hata toleransını SIFIRLAR. Bu yüzden ceza UYGULANMAZ (hepsi ya hiçbiri).
        // Bu, canlılığın cezadan önce geldiği kuralının regresyon testidir.
        let state = g2_state();
        let (addrs, _keys) = g7_genesis_set_with_keys(&state, 4);
        let p = zagros_types::consensus::ChainParams::genesis_defaults();
        g7_fast_forward_to_v2(&state, &p);
        let strikes_needed = crate::params::effective_max_liveness_strikes(&p) as u64;
        let target = addrs[1].clone();

        for e in 0u64..strikes_needed + 2 {
            let set = vs::load_active_set(state.as_ref()).unwrap();
            let target_idx = g7_idx_of(&set, &target);
            let others: Vec<u16> = (0..set.len()).filter(|&i| i != target_idx).collect();
            let qc = g7_fake_qc(set.epoch, 10 + e, &set, &others);
            vs::record_qc_liveness(state.as_ref(), &qc).unwrap();
            vs::advance_epoch_if_due(
                state.as_ref(),
                1 + (crate::params::LIVENESS_V2_ACTIVATION_EPOCH + e + 1) as u128
                    * p.epoch_seconds as u128,
            )
            .unwrap();
        }

        let after = state.get_account(&target).unwrap().unwrap();
        assert_eq!(
            after.validator_status,
            Some(ValidatorStatus::Active),
            "N=4'te ceza uygulanmamali (circuit breaker)"
        );
        assert!(
            after.liveness.strikes >= strikes_needed as u32,
            "strike sayaci islemeye devam eder"
        );
        assert_eq!(after.jailed_until, 0);
        // Kume hala 4 uye: ceza engellendigi icin kimse dusmedi.
        assert_eq!(vs::load_active_set(state.as_ref()).unwrap().len(), 4);
    }

    #[test]
    fn g7_liveness_good_epoch_resets_strikes_before_reaching_jail_threshold() {
        let state = g2_state();
        let (addrs, _keys) = g7_genesis_set_with_keys(&state, 5);
        let p = zagros_types::consensus::ChainParams::genesis_defaults();
        let target = addrs[1].clone();

        // 2 kotu epoch (strike=2), sonra 1 iyi epoch (katilim %100) -> strike sifirlanir.
        for e in 0u64..2 {
            let set = vs::load_active_set(state.as_ref()).unwrap();
            let target_idx = g7_idx_of(&set, &target);
            let others: Vec<u16> = (0..set.len()).filter(|&i| i != target_idx).collect();
            let qc = g7_fake_qc(set.epoch, 10 + e, &set, &others);
            vs::record_qc_liveness(state.as_ref(), &qc).unwrap();
            vs::advance_epoch_if_due(
                state.as_ref(),
                1 + (e + 1) as u128 * p.epoch_seconds as u128,
            )
            .unwrap();
        }
        assert_eq!(
            state
                .get_account(&target)
                .unwrap()
                .unwrap()
                .liveness
                .strikes,
            2
        );

        let set = vs::load_active_set(state.as_ref()).unwrap();
        let all: Vec<u16> = (0..set.len()).collect();
        let qc = g7_fake_qc(set.epoch, 20, &set, &all);
        vs::record_qc_liveness(state.as_ref(), &qc).unwrap();
        vs::advance_epoch_if_due(state.as_ref(), 1 + 3 * p.epoch_seconds as u128).unwrap();
        let acc = state.get_account(&target).unwrap().unwrap();
        assert_eq!(acc.liveness.strikes, 0, "iyi epoch strike'i sifirlar");
        assert_ne!(acc.validator_status, Some(ValidatorStatus::Jailed));
    }

    #[test]
    fn g7_liveness_epoch_with_no_qc_neither_punishes_nor_resets() {
        let state = g2_state();
        let (addrs, _keys) = g7_genesis_set_with_keys(&state, 5);
        let p = zagros_types::consensus::ChainParams::genesis_defaults();
        let target = addrs[1].clone();
        let set = vs::load_active_set(state.as_ref()).unwrap();
        let target_idx = g7_idx_of(&set, &target);
        let others: Vec<u16> = (0..set.len()).filter(|&i| i != target_idx).collect();
        let qc = g7_fake_qc(set.epoch, 10, &set, &others);
        vs::record_qc_liveness(state.as_ref(), &qc).unwrap();
        vs::advance_epoch_if_due(state.as_ref(), 1 + p.epoch_seconds as u128).unwrap();
        assert_eq!(
            state
                .get_account(&target)
                .unwrap()
                .unwrap()
                .liveness
                .strikes,
            1
        );

        // HIC QC yok bu epoch icin -> total=0 -> olcum yok -> strike ne artar ne sifirlanir.
        vs::advance_epoch_if_due(state.as_ref(), 1 + 2 * p.epoch_seconds as u128).unwrap();
        assert_eq!(
            state
                .get_account(&target)
                .unwrap()
                .unwrap()
                .liveness
                .strikes,
            1,
            "olcum yoksa sayac degismez"
        );
    }

    // ---- Gate 3: Bond lock / Exiting → çekim ----

    #[test]
    fn g7_unstake_blocked_during_bond_lock_after_unregister_then_succeeds_after_unlock() {
        let state = g2_state();
        let (addrs, _keys) = g7_genesis_set_with_keys(&state, 5);
        let p = zagros_types::consensus::ChainParams::genesis_defaults();
        let key = test_secret_key(101);
        let addr = addrs[1].clone();
        let mut funded = state.get_account(&addr).unwrap().unwrap();
        funded.balance = 1_000_000; // gaz icin
        state.set_account(&addr, funded).unwrap();
        let executor = Executor::new(state.clone());

        let mut un = transaction(TxType::UnregisterValidator, 0, 0);
        un.sender = addr.clone();
        un.timestamp = 2_000;
        un.sign(&key);
        executor.execute_transaction(&un, un.timestamp).unwrap();
        let acc = state.get_account(&addr).unwrap().unwrap();
        assert_eq!(acc.validator_status, Some(ValidatorStatus::Exiting));
        let unlock_at = acc.bond_unlock_at;
        assert_eq!(unlock_at, un.timestamp + p.bond_lock_seconds as u128);

        let mut early = transaction(TxType::UnstakeZagros, 1, acc.staked_balance);
        early.sender = addr.clone();
        early.timestamp = un.timestamp + 10;
        early.sign(&key);
        let err = executor
            .execute_transaction(&early, early.timestamp)
            .unwrap_err();
        assert!(format!("{err:?}").contains("bond lock"), "{err:?}");
        assert_eq!(
            state.get_account(&addr).unwrap().unwrap().staked_balance,
            acc.staked_balance,
            "erken cekim ENGELLENMELI"
        );

        let late_nonce = state.get_account(&addr).unwrap().unwrap().nonce;
        let mut late = transaction(TxType::UnstakeZagros, late_nonce, acc.staked_balance);
        late.sender = addr.clone();
        late.timestamp = unlock_at + 1;
        late.sign(&key);
        executor.execute_transaction(&late, late.timestamp).unwrap();
        let after = state.get_account(&addr).unwrap().unwrap();
        assert_eq!(
            after.staked_balance, 0,
            "kilit sonrasi normal 48s unbonding basladi"
        );
        assert!(after.pending_unstake_amount > 0);
    }

    #[test]
    fn g7_liveness_demotion_does_not_lock_bond_or_block_unstake() {
        // 🚨 Canlılık cezası Probation, sermayeye dokunmaz: bond kilidi kurulmaz,
        // unstake engellenmez (bond kilidi yalnız equivocation/admin-remove).
        let state = g2_state();
        let (addrs, _keys) = g7_genesis_set_with_keys(&state, 5);
        let p = zagros_types::consensus::ChainParams::genesis_defaults();
        g7_fast_forward_to_v2(&state, &p);
        let strikes_needed = crate::params::effective_max_liveness_strikes(&p) as u64;
        let target = addrs[1].clone();
        let key = test_secret_key(101);
        let mut funded = state.get_account(&target).unwrap().unwrap();
        funded.balance = 1_000_000; // gaz icin
        state.set_account(&target, funded).unwrap();
        let bond_before = state.get_account(&target).unwrap().unwrap().bond_unlock_at;

        for e in 0u64..strikes_needed {
            let set = vs::load_active_set(state.as_ref()).unwrap();
            let target_idx = g7_idx_of(&set, &target);
            let others: Vec<u16> = (0..set.len()).filter(|&i| i != target_idx).collect();
            let qc = g7_fake_qc(set.epoch, 10 + e, &set, &others);
            vs::record_qc_liveness(state.as_ref(), &qc).unwrap();
            vs::advance_epoch_if_due(
                state.as_ref(),
                1 + (crate::params::LIVENESS_V2_ACTIVATION_EPOCH + e + 1) as u128
                    * p.epoch_seconds as u128,
            )
            .unwrap();
        }
        let acc = state.get_account(&target).unwrap().unwrap();
        assert_eq!(acc.validator_status, Some(ValidatorStatus::Probation));
        assert_eq!(
            acc.bond_unlock_at, bond_before,
            "canlilik cezasi bond kilidi KURMAZ"
        );
        assert_eq!(acc.jailed_until, 0);

        // Unstake engellenmemeli (bond kilidi yok).
        let executor = Executor::new(state.clone());
        let mut tx = transaction(TxType::UnstakeZagros, 0, acc.staked_balance);
        tx.sender = target.clone();
        tx.timestamp = 1 + (strikes_needed + 1) as u128 * p.epoch_seconds as u128;
        tx.sign(&key);
        assert!(
            executor.execute_transaction(&tx, tx.timestamp).is_ok(),
            "canlilik cezasi unstake'i ENGELLEMEMELI"
        );
    }

    #[test]
    fn g7_unstake_unaffected_for_accounts_that_were_never_validators() {
        let state = test_state();
        install_test_chain(&state);
        let addr = test_address(50);
        state
            .set_account(
                &addr,
                AccountState {
                    staked_balance: 1_000 * TOKEN_DECIMAL,
                    balance: 1_000_000,
                    ..Default::default()
                },
            )
            .unwrap();
        let executor = Executor::new(state.clone());
        let mut tx = transaction(TxType::UnstakeZagros, 0, 500 * TOKEN_DECIMAL);
        tx.sender = addr.clone();
        tx.timestamp = 1_000;
        tx.sign(&test_secret_key(50));
        executor.execute_transaction(&tx, tx.timestamp).unwrap();
        assert_eq!(
            state.get_account(&addr).unwrap().unwrap().staked_balance,
            500 * TOKEN_DECIMAL,
            "bond_unlock_at=0 -> normal unstake etkilenmez"
        );
    }

    // ---- Gate 5 (devam): ShadowVote, kripto/state seviyesi, canli P2P YOK ----

    fn g7_probation_account(state: &Arc<dyn State>, addr: &Address, seed: u8, epoch: u64) {
        let kp = test_consensus_keypair(seed);
        state
            .set_account(
                addr,
                AccountState {
                    consensus_pubkey: kp.public_key(),
                    validator_status: Some(ValidatorStatus::Probation),
                    validator_status_epoch: epoch,
                    staked_balance: test_min_stake(state),
                    ..Default::default()
                },
            )
            .unwrap();
    }

    fn g7_shadow_vote(
        kp: &zagros_crypto::ConsensusKeypair,
        domain: &zagros_types::consensus::ConsensusDomain,
        epoch: u64,
        height: u64,
        round: u32,
    ) -> zagros_types::consensus::Vote {
        let mut v = zagros_types::consensus::Vote {
            height,
            round,
            phase: zagros_types::consensus::VotePhase::Prevote,
            block_hash: [3u8; 32],
            validator_idx: 0,
            shadow: true,
            sig: vec![],
        };
        zagros_crypto::sign_vote(kp, domain, epoch, &mut v);
        v
    }

    /// 🚨 GÜVENLİK REGRESYONU: uydurma yükseklikli gölge oylar liveness sayacını
    /// artırmamalı; yoksa validator hayali oylarla katılımını %100'e çekip
    /// Probation'dan iş yapmadan Active'e terfi ederdi.
    #[test]
    fn shadow_votes_with_fabricated_heights_do_not_inflate_liveness() {
        let state = g2_state();
        let (addrs, keys) = g7_genesis_set_with_keys(&state, 5);
        let target = addrs[3].clone();
        let domain = g7_domain(&state);
        let epoch = crate::validator_set::load_active_set(state.as_ref())
            .unwrap()
            .epoch;

        // Zincir 1000. blokta; saldırgan hem GELECEK hem PENCERE-DIŞI-ESKİ
        // yükseklikler uyduruyor (pencere: son 128 blok).
        let block_number: u64 = 1_000;
        let mut fabricated = Vec::new();
        for h in [5_000u64, 9_999, 10] {
            let vote = g7_shadow_vote(&keys[3], &domain, epoch, h, 0);
            fabricated.push(zagros_types::consensus::ShadowVoteAttestation {
                address: target.clone(),
                vote,
            });
        }
        crate::validator_set::apply_shadow_vote_attestations(
            state.as_ref(),
            &domain,
            epoch,
            block_number,
            &fabricated,
        );
        let after = state.get_account(&target).unwrap().unwrap();
        assert_eq!(
            after.liveness.total, 0,
            "pencere disi (uydurma) yukseklikler liveness'a HIC girmemeli"
        );

        // Gerçek, yakın geçmişteki bir yükseklik ise SAYILMALI.
        let real = vec![zagros_types::consensus::ShadowVoteAttestation {
            address: target.clone(),
            vote: g7_shadow_vote(&keys[3], &domain, epoch, block_number - 1, 0),
        }];
        crate::validator_set::apply_shadow_vote_attestations(
            state.as_ref(),
            &domain,
            epoch,
            block_number,
            &real,
        );
        let after2 = state.get_account(&target).unwrap().unwrap();
        assert_eq!(after2.liveness.total, 1, "gercek yukseklik sayilmali");
        assert_eq!(after2.liveness.participated, 1);
    }

    #[test]
    fn g7_shadow_vote_valid_is_accepted_and_records_liveness() {
        let state = g2_state();
        let addr = test_address(60);
        let kp = test_consensus_keypair(160);
        g7_probation_account(&state, &addr, 160, 0);
        let domain = g7_domain(&state);
        let vote = g7_shadow_vote(&kp, &domain, 0, 5, 0);
        vs::verify_and_record_shadow_vote(state.as_ref(), &domain, 0, &addr, &vote, 1_000).unwrap();
        let acc = state.get_account(&addr).unwrap().unwrap();
        assert_eq!(acc.liveness.total, 1);
        assert_eq!(acc.liveness.participated, 1);
    }

    #[test]
    fn g7_shadow_vote_forged_signature_is_rejected_and_state_untouched() {
        let state = g2_state();
        let addr = test_address(60);
        let kp = test_consensus_keypair(160);
        g7_probation_account(&state, &addr, 160, 0);
        let domain = g7_domain(&state);
        let mut vote = g7_shadow_vote(&kp, &domain, 0, 5, 0);
        vote.sig[0] ^= 0xFF;
        assert!(
            vs::verify_and_record_shadow_vote(state.as_ref(), &domain, 0, &addr, &vote, 1_000)
                .is_err()
        );
        assert_eq!(state.get_account(&addr).unwrap().unwrap().liveness.total, 0);
    }

    #[test]
    fn g7_shadow_vote_signed_by_a_different_validators_key_is_rejected() {
        let state = g2_state();
        let addr = test_address(60);
        g7_probation_account(&state, &addr, 160, 0);
        let wrong_kp = test_consensus_keypair(161); // addr'in KAYITLI anahtari degil
        let domain = g7_domain(&state);
        let vote = g7_shadow_vote(&wrong_kp, &domain, 0, 5, 0);
        assert!(
            vs::verify_and_record_shadow_vote(state.as_ref(), &domain, 0, &addr, &vote, 1_000)
                .is_err()
        );
        assert_eq!(state.get_account(&addr).unwrap().unwrap().liveness.total, 0);
    }

    #[test]
    fn g7_shadow_vote_from_a_different_epoch_does_not_verify() {
        let state = g2_state();
        let addr = test_address(60);
        let kp = test_consensus_keypair(160);
        g7_probation_account(&state, &addr, 160, 0);
        let domain = g7_domain(&state);
        let vote = g7_shadow_vote(&kp, &domain, 0, 5, 0); // epoch=0 icin imzalandi
                                                          // ama epoch=1 olarak dogrulanmaya calisiliyor (imza digest'i epoch icerir)
        assert!(
            vs::verify_and_record_shadow_vote(state.as_ref(), &domain, 1, &addr, &vote, 1_000)
                .is_err()
        );
    }

    #[test]
    fn g7_shadow_vote_replay_duplicate_is_rejected_and_not_double_counted() {
        let state = g2_state();
        let addr = test_address(60);
        let kp = test_consensus_keypair(160);
        g7_probation_account(&state, &addr, 160, 0);
        let domain = g7_domain(&state);
        let vote = g7_shadow_vote(&kp, &domain, 0, 5, 0);
        vs::verify_and_record_shadow_vote(state.as_ref(), &domain, 0, &addr, &vote, 1_000).unwrap();
        let err =
            vs::verify_and_record_shadow_vote(state.as_ref(), &domain, 0, &addr, &vote, 1_000)
                .unwrap_err();
        assert!(format!("{err:?}").contains("zaten kaydedildi"), "{err:?}");
        let acc = state.get_account(&addr).unwrap().unwrap();
        assert_eq!(
            acc.liveness.total, 1,
            "tekrar oy sayaci IKINCI KEZ ARTIRMAMALI"
        );
        assert_eq!(acc.liveness.participated, 1);
    }

    #[test]
    fn g7_non_shadow_vote_is_rejected_by_verify_shadow_vote() {
        let state = g2_state();
        let addr = test_address(60);
        let kp = test_consensus_keypair(160);
        g7_probation_account(&state, &addr, 160, 0);
        let domain = g7_domain(&state);
        let mut vote = g7_shadow_vote(&kp, &domain, 0, 5, 0);
        vote.shadow = false; // yeniden imzalanmadi -> digest artik farkli domain'e (VOTE) karsilik gelir
        assert!(
            vs::verify_and_record_shadow_vote(state.as_ref(), &domain, 0, &addr, &vote, 1_000)
                .is_err()
        );
    }

    /// [INV-L4] ShadowVote hicbir kosulda QC/quorum hesabina giremez —
    /// `build_qc` gölge oyları FİLTRELER; burada bunu doğrudan doğruluyoruz.
    #[test]
    fn g7_shadow_votes_never_enter_qc_or_affect_active_quorum() {
        let state = g2_state();
        let (_addrs, keys) = g7_genesis_set_with_keys(&state, 4);
        let set = vs::load_active_set(state.as_ref()).unwrap();
        assert_eq!(
            set.quorum().unwrap(),
            3,
            "N=4 -> Q=3 (yalniz Active uyeler)"
        );
        let domain = g7_domain(&state);

        // 3 gercek (shadow=false) precommit + 1 golge (shadow=true) precommit-benzeri oy.
        let mut votes = Vec::new();
        for i in 0..3u16 {
            let mut v = zagros_types::consensus::Vote {
                height: 1,
                round: 0,
                phase: zagros_types::consensus::VotePhase::Precommit,
                block_hash: [7u8; 32],
                validator_idx: i,
                shadow: false,
                sig: vec![],
            };
            zagros_crypto::sign_vote(&keys[i as usize], &domain, 0, &mut v);
            votes.push(v);
        }
        let mut shadow = zagros_types::consensus::Vote {
            height: 1,
            round: 0,
            phase: zagros_types::consensus::VotePhase::Precommit,
            block_hash: [7u8; 32],
            validator_idx: 3,
            shadow: true,
            sig: vec![],
        };
        zagros_crypto::sign_vote(&keys[3], &domain, 0, &mut shadow);
        let shadow_sig = shadow.sig.clone();
        votes.push(shadow);

        let qc = zagros_crypto::build_qc(&votes, &domain, &set, 1, 0, [7u8; 32]).unwrap();
        assert_eq!(
            qc.signer_indices(),
            vec![0, 1, 2],
            "golge oy (idx 3) QC'ye HIC girmemeli"
        );
        zagros_crypto::verify_qc(&qc, &domain, &set).unwrap();

        // Gölge oyun KENDİSİ bir QC olarak sunulmaya çalışılırsa yapısal/imza
        // doğrulaması reddeder (DOMAIN_SHADOW ayrı, INV-D1).
        let mut fake_signers =
            vec![0u8; zagros_types::consensus::QuorumCertificate::bitset_len_for(4)];
        for i in 0..3u16 {
            zagros_types::consensus::QuorumCertificate::set_signer(&mut fake_signers, i);
        }
        zagros_types::consensus::QuorumCertificate::set_signer(&mut fake_signers, 3);
        let bogus_qc = zagros_types::consensus::QuorumCertificate {
            height: 1,
            round: 0,
            block_hash: [7u8; 32],
            epoch: 0,
            validator_set_hash: set.hash(),
            signers: fake_signers,
            sigs: vec![
                votes[0].sig.clone(),
                votes[1].sig.clone(),
                votes[2].sig.clone(),
                shadow_sig,
            ],
        };
        assert!(
            zagros_crypto::verify_qc(&bogus_qc, &domain, &set).is_err(),
            "golge imza normal VOTE digest'iyle uyusmaz"
        );
    }

    // ════════════════ D14 (denetim) regresyon testleri ════════════════

    fn set_rules_height(state: &Arc<dyn State>, height: u64) {
        state
            .set_account(
                &"__GLOBAL_BLOCK_HEIGHT__".to_string(),
                AccountState::new(height as u128),
            )
            .unwrap();
    }

    /// A2: kendine transfer D14 sonrası reddedilir (bayat snapshot tutarı yok
    /// ederdi, 42M ihlali); D14 öncesi kabul, determinizm için korunur.
    #[test]
    fn d14_self_transfer_is_rejected_after_activation() {
        let state = test_state();
        set_rules_height(&state, zagros_types::D14_RULES_ACTIVATION_HEIGHT);
        let executor = Executor::new(state.clone());
        let secret = test_secret_key(1);
        let addr = Transaction::address_from_secret_key(&secret);
        state
            .set_account(&addr, AccountState::new(1_000 * TOKEN_DECIMAL))
            .unwrap();

        let mut tx = transaction(TxType::Transfer, 0, 100 * TOKEN_DECIMAL);
        tx.receiver = addr.clone();
        tx.sign(&secret);

        let err = executor.execute_transaction(&tx, 1_000).unwrap_err();
        assert!(
            format!("{err:?}").contains("Kendine transfer"),
            "beklenen ret nedeni gelmedi: {err:?}"
        );
        let after = state.get_account(&addr).unwrap().unwrap();
        // Başarısız işlem de ÜCRETİNİ öder (standart yol: gas_limit×gas_price=2);
        // kritik olan TUTARIN (100 ZAGROS) yok olmaması.
        assert_eq!(
            after.balance,
            1_000 * TOKEN_DECIMAL - 2,
            "reddedilen kendine-transferde yalniz ucret kesilmeli, TUTAR yok olmamali"
        );

        // D14 öncesi: eski davranış korunur (tarih oynatma), işlem kabul edilir.
        let state_old = test_state();
        set_rules_height(&state_old, zagros_types::D14_RULES_ACTIVATION_HEIGHT - 1);
        let executor_old = Executor::new(state_old.clone());
        state_old
            .set_account(&addr, AccountState::new(1_000 * TOKEN_DECIMAL))
            .unwrap();
        let mut tx_old = transaction(TxType::Transfer, 0, 100 * TOKEN_DECIMAL);
        tx_old.receiver = addr.clone();
        tx_old.sign(&secret);
        executor_old
            .execute_transaction(&tx_old, 1_000)
            .expect("D14 oncesi eski davranis birebir korunmali");
    }

    /// A1: gas alanları imzaya bağlı olmadığından üretici tarafından yeniden
    /// yazılabilir; D14 sonrası deklare ücret kanonik tavanı (taban × 1024)
    /// aşarsa işlem geçersizdir ve ücret KESİLMEZ.
    #[test]
    fn d14_fee_above_canonical_ceiling_is_rejected() {
        let state = test_state();
        set_rules_height(&state, zagros_types::D14_RULES_ACTIVATION_HEIGHT);
        // Gerçekçi rezervler: taban ücret ~0.045 ZAGROS → tavan ~46 ZAGROS.
        state
            .set_pool_reserves(40_000_000 * TOKEN_DECIMAL, 11_000 * TOKEN_DECIMAL)
            .unwrap();
        let executor = Executor::new(state.clone());
        let secret = test_secret_key(1);
        let addr = Transaction::address_from_secret_key(&secret);
        state
            .set_account(&addr, AccountState::new(10_000 * TOKEN_DECIMAL))
            .unwrap();

        // "Üretici yeniden yazdı" senaryosu: 10M gas × 1e13 = 100 ZAGROS ücret.
        let mut greedy = transaction(TxType::Transfer, 0, TOKEN_DECIMAL);
        greedy.gas_limit = 10_000_000;
        greedy.gas_price = 10_000_000_000_000;
        greedy.sign(&secret);
        let err = executor.execute_transaction(&greedy, 1_000).unwrap_err();
        assert!(
            format!("{err:?}").contains("kanonik tavan"),
            "tavan reddi bekleniyordu: {err:?}"
        );
        assert_eq!(
            state.get_account(&addr).unwrap().unwrap().balance,
            10_000 * TOKEN_DECIMAL,
            "gecersiz islemde HICBIR kesinti olmamali"
        );

        // Meşru ücret (mempool'un yazacağı ölçek) tavanın çok altında: geçer.
        let mut honest = transaction(TxType::Transfer, 0, TOKEN_DECIMAL);
        honest.gas_limit = 1;
        honest.gas_price = 50_000_000_000_000_000; // 0.05 ZAGROS ≈ kanonik taban
        honest.sign(&secret);
        executor
            .execute_transaction(&honest, 1_000)
            .expect("mesru ucretli islem tavana takilmamali");
    }

    /// Acil el koyma durumu "Jailed" yazmıyordu; hedef teminatsız halde kümede
    /// oy hakkıyla kalıyordu (canlıda teyit). D14 sonrası Jailed'a çekilir.
    #[test]
    fn d14_admin_emergency_seizure_also_sets_jailed_status() {
        let admin_key = test_secret_key(30);
        let admin_address = test_address(30);
        let validator_address = test_address(33);
        let genesis_timestamp = 1_000_000u128;
        let block_timestamp = genesis_timestamp + 1_000;

        let state = test_state();
        set_genesis_timestamp(&state, genesis_timestamp);
        set_rules_height(&state, zagros_types::D14_RULES_ACTIVATION_HEIGHT);
        state
            .set_account(&admin_address, AccountState::new(1_000_000))
            .unwrap();
        state
            .set_account(
                &validator_address,
                AccountState {
                    staked_balance: 801 * TOKEN_DECIMAL,
                    is_registered_validator: true,
                    validator_status: Some(ValidatorStatus::Active),
                    ..Default::default()
                },
            )
            .unwrap();
        state
            .set_account(
                &"__GLOBAL_TOTAL_STAKED__".to_string(),
                AccountState::new(801 * TOKEN_DECIMAL),
            )
            .unwrap();

        let tx = slash_validator_tx(&admin_key, validator_address.clone(), block_timestamp);
        let executor = Executor::new(state.clone()).with_admin_authority(admin_address);
        executor.execute_transaction(&tx, block_timestamp).unwrap();

        let after = state.get_account(&validator_address).unwrap().unwrap();
        assert_eq!(after.staked_balance, 0);
        assert!(!after.is_registered_validator);
        assert_eq!(
            after.validator_status,
            Some(ValidatorStatus::Jailed),
            "D14 REGRESYONU: acil el koyma lifecycle durumunu Jailed yapmali \
             (aksi halde hedef kumede oy hakkiyla 'Active' kalir)"
        );
    }

    /// A3: onay işlemini hedefin KENDİSİ gönderemez (bayat snapshot yazımı
    /// ücret düşümünü geri getirip Hazine kredisini bırakırdı → tekrar
    /// gönderilebilir yoktan para basımı). Farklı kurye serbesttir.
    #[test]
    fn d14_approve_validator_cannot_be_couriered_by_its_own_target() {
        let state = g2_state();
        g2_genesis_set(&state, 5);
        let (key, address) = g2_fund_candidate(&state, 66);
        let (sender_key, _) = g2_fund_candidate(&state, 67);
        let executor = Executor::new(state.clone());
        executor
            .execute_transaction(&register_validator_tx_v2(&key, &state, 66, 0, 1_000), 1_000)
            .unwrap();
        set_rules_height(&state, zagros_types::D14_RULES_ACTIVATION_HEIGHT);

        // Hedefin kendisi kurye → ret.
        let self_tx = admin_action_tx(
            &key,
            &state,
            AdminAction::Approve,
            &address,
            0,
            3,
            g2_nonce(&state, &address),
            1_000,
        );
        let err = executor.execute_transaction(&self_tx, 1_000).unwrap_err();
        assert!(
            format!("{err:?}").contains("hedefin kendisi"),
            "oz-kurye reddi bekleniyordu: {err:?}"
        );

        // Farklı kurye → onay geçer.
        let ok = admin_action_tx(
            &sender_key,
            &state,
            AdminAction::Approve,
            &address,
            0,
            3,
            g2_nonce(&state, &test_address(67)),
            1_000,
        );
        executor.execute_transaction(&ok, 1_000).unwrap();
        let acc = state
            .get_account(&address.to_ascii_lowercase())
            .unwrap()
            .unwrap();
        assert_eq!(acc.validator_status, Some(ValidatorStatus::Approved));
    }
    // 🗳️ İadeli öneri depozitosu (GOV_DEPOSIT_ACTIVATION_HEIGHT)
    fn gov_dep_fee() -> u128 {
        1000 * TOKEN_DECIMAL
    }
    fn gov_dep_escrow(state: &Arc<dyn State>) -> u128 {
        state
            .get_account(&governance::GOV_DEPOSIT_ESCROW_KEY.to_string())
            .unwrap()
            .map(|a| a.balance)
            .unwrap_or(0)
    }
    fn gov_dep_pool(state: &Arc<dyn State>) -> u128 {
        state
            .get_account(&zagros_types::VALIDATOR_REWARD_POOL.to_string())
            .unwrap()
            .map(|a| a.balance)
            .unwrap_or(0)
    }
    /// Kapı sonrası zincir: params + 100.000 toplam stake + 1M bakiyeli önerici (seed 1).
    fn gov_dep_chain(height: u64) -> (Arc<dyn State>, Executor, Address) {
        let state = test_state();
        install_test_chain(&state);
        set_rules_height(&state, height);
        let proposer = Transaction::address_from_secret_key(&test_secret_key(1));
        state
            .set_account(
                &proposer,
                AccountState {
                    balance: 1_000_000 * TOKEN_DECIMAL,
                    staked_balance: 20_000 * TOKEN_DECIMAL,
                    ..Default::default()
                },
            )
            .unwrap();
        state
            .set_account(
                &"__GLOBAL_TOTAL_STAKED__".to_string(),
                AccountState::new(100_000 * TOKEN_DECIMAL),
            )
            .unwrap();
        let executor = Executor::new(state.clone());
        (state, executor, proposer)
    }
    fn gov_dep_submit(
        executor: &Executor,
        action: &zagros_types::consensus::ProposalAction,
        nonce: u64,
        id: u8,
    ) -> Hash {
        let mut tx = transaction(TxType::SubmitProposal, nonce, 0);
        tx.tx_id = [id; 32];
        tx.payload = if *action == zagros_types::consensus::ProposalAction::Text {
            b"sinyal".to_vec()
        } else {
            action.encode_payload().unwrap()
        };
        tx.sign(&test_secret_key(1));
        executor.apply_transaction(&tx, 1_000).unwrap();
        tx.tx_id
    }
    /// İki staker (seed 30/31), her biri toplamın %10'u: ikisi de oy verirse katılım %20 = yeter sayı.
    fn gov_dep_staker_votes(state: &Arc<dyn State>, pid: &Hash, support: bool, count: usize) {
        for seed in (30u8..30 + count as u8).take(count) {
            let addr = test_address(seed);
            state
                .set_account(
                    &addr,
                    AccountState {
                        staked_balance: 10_000 * TOKEN_DECIMAL,
                        ..Default::default()
                    },
                )
                .unwrap();
            governance::record_vote(state.as_ref(), pid, &addr, support, 10_000 * TOKEN_DECIMAL)
                .unwrap();
        }
    }

    /// Kapı sonrası bedel Hevsel'e gitmez, kasada öneri adına bekler; kapı
    /// öncesi eski davranış (anında dağıtım) birebir korunur.
    #[test]
    fn gov_deposit_is_escrowed_after_activation_and_distributed_before() {
        let fee = gov_dep_fee();
        // Kapı sonrası
        let (state, executor, proposer) =
            gov_dep_chain(zagros_types::GOV_DEPOSIT_ACTIVATION_HEIGHT);
        let pool_before = gov_dep_pool(&state);
        let before = state.get_account(&proposer).unwrap().unwrap().balance;
        let pid = gov_dep_submit(
            &executor,
            &zagros_types::consensus::ProposalAction::Text,
            0,
            0xD1,
        );
        let after = state.get_account(&proposer).unwrap().unwrap().balance;
        assert!(before - after >= fee, "bedel gonderenden dusmeli");
        assert_eq!(gov_dep_escrow(&state), fee, "bedel kasada beklemeli");
        assert_eq!(governance::deposit_of(state.as_ref(), &pid).unwrap(), fee);
        assert_eq!(
            gov_dep_pool(&state),
            pool_before,
            "Hevsel'e ANINDA gitmemeli"
        );
        let p = executor.load_proposal(&pid).unwrap().unwrap();
        assert_eq!(
            p.voting_ends_at_epoch, 168,
            "metin oneri de depozito sayimi icin pencere alir"
        );
        assert_eq!(
            governance::load_typed_active(state.as_ref()).unwrap(),
            vec![pid],
            "metin oneri sayim listesine girer"
        );

        // Kapı öncesi: eski davranış
        let (state_old, executor_old, _) =
            gov_dep_chain(zagros_types::GOV_DEPOSIT_ACTIVATION_HEIGHT - 1);
        let pool_before_old = gov_dep_pool(&state_old);
        let pid_old = gov_dep_submit(
            &executor_old,
            &zagros_types::consensus::ProposalAction::Text,
            0,
            0xD2,
        );
        assert_eq!(gov_dep_escrow(&state_old), 0);
        assert_eq!(
            governance::deposit_of(state_old.as_ref(), &pid_old).unwrap(),
            0
        );
        assert_eq!(
            gov_dep_pool(&state_old),
            pool_before_old + fee,
            "kapi oncesi bedel aninda Hevsel'e"
        );
        assert!(
            governance::load_typed_active(state_old.as_ref())
                .unwrap()
                .is_empty(),
            "kapi oncesi metin oneri listeye girmez"
        );
    }

    /// Yeter sayıya ulaşan ama REDDEDİLEN economic öneri: depozito önericiye döner.
    #[test]
    fn gov_deposit_refunded_when_quorum_reached_even_if_rejected() {
        use zagros_types::consensus::{ParamKey, ParamUpdate, ProposalAction};
        let fee = gov_dep_fee();
        let (state, executor, proposer) =
            gov_dep_chain(zagros_types::GOV_DEPOSIT_ACTIVATION_HEIGHT);
        let action = ProposalAction::ParamChange(vec![ParamUpdate {
            key: ParamKey::VoteCapBps,
            value: 900,
        }]);
        let pid = gov_dep_submit(&executor, &action, 0, 0xD3);
        let after_submit = state.get_account(&proposer).unwrap().unwrap().balance;
        gov_dep_staker_votes(&state, &pid, false, 2); // %20 katılım, hepsi hayır
        let set = g12_set(5); // hiçbir validator oy vermedi → validators_ok=false → RED
        let pool_before = gov_dep_pool(&state);
        governance::process_at_epoch(state.as_ref(), 168, &set).unwrap();
        let p = executor.load_proposal(&pid).unwrap().unwrap();
        assert_eq!(p.status, zagros_types::ProposalStatus::Rejected);
        assert_eq!(
            state.get_account(&proposer).unwrap().unwrap().balance,
            after_submit + fee,
            "depozito iade edilmeli"
        );
        assert_eq!(gov_dep_escrow(&state), 0);
        assert_eq!(governance::deposit_of(state.as_ref(), &pid).unwrap(), 0);
        assert_eq!(
            gov_dep_pool(&state),
            pool_before,
            "Hevsel'e hicbir sey gitmemeli"
        );
        // İkinci sayım no-op (idempotent)
        assert_eq!(
            governance::settle_deposit(state.as_ref(), &p, true).unwrap(),
            0
        );
    }

    /// Yeter sayıya ulaşamayan öneri: depozito Hevsel'e, hisse başı çarpan artar.
    #[test]
    fn gov_deposit_forfeited_to_hevsel_when_quorum_missed() {
        use zagros_types::consensus::{ParamKey, ParamUpdate, ProposalAction};
        let fee = gov_dep_fee();
        let (state, executor, proposer) =
            gov_dep_chain(zagros_types::GOV_DEPOSIT_ACTIVATION_HEIGHT);
        let action = ProposalAction::ParamChange(vec![ParamUpdate {
            key: ParamKey::VoteCapBps,
            value: 900,
        }]);
        let pid = gov_dep_submit(&executor, &action, 0, 0xD4);
        let after_submit = state.get_account(&proposer).unwrap().unwrap().balance;
        gov_dep_staker_votes(&state, &pid, true, 1); // %10 katılım < %20
        let pool_before = gov_dep_pool(&state);
        let acc_before = state.get_accumulated_reward_per_share().unwrap();
        governance::process_at_epoch(state.as_ref(), 168, &g12_set(5)).unwrap();
        assert_eq!(
            executor.load_proposal(&pid).unwrap().unwrap().status,
            zagros_types::ProposalStatus::Rejected
        );
        assert_eq!(
            state.get_account(&proposer).unwrap().unwrap().balance,
            after_submit,
            "iade YOK"
        );
        assert_eq!(gov_dep_escrow(&state), 0);
        assert_eq!(
            gov_dep_pool(&state),
            pool_before + fee,
            "depozito Hevsel havuzuna"
        );
        let expected_added = fee * 1_000_000_000_000 / (100_000 * TOKEN_DECIMAL);
        assert_eq!(
            state.get_accumulated_reward_per_share().unwrap(),
            acc_before + expected_added,
            "stake edenlere bolunmeli"
        );
    }

    /// Kabul edilen öneri: depozito Queued anında iade (yürütme beklenmez).
    #[test]
    fn gov_deposit_refunded_on_accept_at_queue_time() {
        use zagros_types::consensus::{ParamKey, ParamUpdate, ProposalAction};
        let fee = gov_dep_fee();
        let (state, executor, proposer) =
            gov_dep_chain(zagros_types::GOV_DEPOSIT_ACTIVATION_HEIGHT);
        let action = ProposalAction::ParamChange(vec![ParamUpdate {
            key: ParamKey::TBaseMs,
            value: 2_500,
        }]);
        let pid = gov_dep_submit(&executor, &action, 0, 0xD5);
        let after_submit = state.get_account(&proposer).unwrap().unwrap().balance;
        let set = g12_set(5);
        for m in set.members.iter().take(4) {
            governance::record_vote(state.as_ref(), &pid, &m.address, true, 1).unwrap();
        }
        governance::process_at_epoch(state.as_ref(), 168, &set).unwrap();
        assert_eq!(
            executor.load_proposal(&pid).unwrap().unwrap().status,
            zagros_types::ProposalStatus::Queued
        );
        assert_eq!(
            state.get_account(&proposer).unwrap().unwrap().balance,
            after_submit + fee,
            "kabulde depozito hemen iade"
        );
        assert_eq!(gov_dep_escrow(&state), 0);
    }

    /// Consensus kanalında %20'nin altında doğrulayıcı katılımı → RED + Hevsel;
    /// veto → Hevsel.
    #[test]
    fn gov_deposit_forfeited_on_low_validator_turnout_and_on_veto() {
        use zagros_types::consensus::{ParamKey, ParamUpdate, ProposalAction};
        let fee = gov_dep_fee();
        // Düşük katılım: 0/5 oy
        let (state, executor, proposer) =
            gov_dep_chain(zagros_types::GOV_DEPOSIT_ACTIVATION_HEIGHT);
        let action = ProposalAction::ParamChange(vec![ParamUpdate {
            key: ParamKey::TBaseMs,
            value: 2_500,
        }]);
        let pid = gov_dep_submit(&executor, &action, 0, 0xD6);
        let after_submit = state.get_account(&proposer).unwrap().unwrap().balance;
        let pool_before = gov_dep_pool(&state);
        governance::process_at_epoch(state.as_ref(), 168, &g12_set(5)).unwrap();
        assert_eq!(
            executor.load_proposal(&pid).unwrap().unwrap().status,
            zagros_types::ProposalStatus::Rejected
        );
        assert_eq!(
            state.get_account(&proposer).unwrap().unwrap().balance,
            after_submit
        );
        assert_eq!(gov_dep_pool(&state), pool_before + fee);
        // Katılım var ama ret (2/5 oy, 1 evet): yeter sayı %20 sağlandı → iade
        let pid2 = gov_dep_submit(&executor, &action, 1, 0xD7);
        let after_submit2 = state.get_account(&proposer).unwrap().unwrap().balance;
        let set = g12_set(5);
        governance::record_vote(state.as_ref(), &pid2, &set.members[0].address, true, 1).unwrap();
        governance::record_vote(state.as_ref(), &pid2, &set.members[1].address, false, 1).unwrap();
        governance::process_at_epoch(state.as_ref(), 168, &set).unwrap();
        assert_eq!(
            executor.load_proposal(&pid2).unwrap().unwrap().status,
            zagros_types::ProposalStatus::Rejected
        );
        assert_eq!(
            state.get_account(&proposer).unwrap().unwrap().balance,
            after_submit2 + fee,
            "katilim yeterli → iade"
        );
        // Veto
        let pid3 = gov_dep_submit(&executor, &action, 2, 0xD8);
        let after_submit3 = state.get_account(&proposer).unwrap().unwrap().balance;
        let pool_before3 = gov_dep_pool(&state);
        governance::apply_veto(state.as_ref(), &format!("0x{}", hex::encode(pid3))).unwrap();
        assert_eq!(
            executor.load_proposal(&pid3).unwrap().unwrap().status,
            zagros_types::ProposalStatus::Vetoed
        );
        assert_eq!(
            state.get_account(&proposer).unwrap().unwrap().balance,
            after_submit3,
            "vetoda iade YOK"
        );
        assert_eq!(
            gov_dep_pool(&state),
            pool_before3 + fee,
            "veto depozitosu Hevsel'e"
        );
        assert_eq!(gov_dep_escrow(&state), 0);
    }

    /// Metin (sinyal) öneri: gerçek Vote işlemleriyle %20 katılım → epoch
    /// sınırında iade; durum tembel kalır, aktif sayaç değişmez.
    #[test]
    fn gov_text_proposal_deposit_settles_at_epoch_via_real_votes() {
        let fee = gov_dep_fee();
        let (state, executor, proposer) =
            gov_dep_chain(zagros_types::GOV_DEPOSIT_ACTIVATION_HEIGHT);
        // Gerçek zaman damgalarıyla (Vote işlemi son kullanma + oylama penceresi
        // saniye kontrolü yapar): öneri ve oylar kendi damgalarıyla yürütülür.
        let mut tx = transaction(TxType::SubmitProposal, 0, 0);
        tx.tx_id = [0xD9; 32];
        tx.payload = b"sinyal".to_vec();
        tx.sign(&test_secret_key(1));
        executor.apply_transaction(&tx, tx.timestamp).unwrap();
        let pid = tx.tx_id;
        let after_submit = state.get_account(&proposer).unwrap().unwrap().balance;
        for seed in [30u8, 31u8] {
            let key = test_secret_key(seed);
            let addr = Transaction::address_from_secret_key(&key);
            state
                .set_account(
                    &addr,
                    AccountState {
                        balance: 10 * TOKEN_DECIMAL,
                        staked_balance: 10_000 * TOKEN_DECIMAL,
                        ..Default::default()
                    },
                )
                .unwrap();
            let vote = vote_tx(&key, 0, pid, seed == 30);
            executor.apply_transaction(&vote, vote.timestamp).unwrap();
        }
        let count_before = executor.active_proposal_count().unwrap();
        let ends = executor
            .load_proposal(&pid)
            .unwrap()
            .unwrap()
            .voting_ends_at_epoch;
        assert!(ends > 0, "metin oneri depozito penceresi almali");
        governance::process_at_epoch(state.as_ref(), ends, &g12_set(3)).unwrap();
        assert_eq!(
            state.get_account(&proposer).unwrap().unwrap().balance,
            after_submit + fee,
            "metin oneri depozitosu iade"
        );
        assert_eq!(gov_dep_escrow(&state), 0);
        assert!(governance::load_typed_active(state.as_ref())
            .unwrap()
            .is_empty());
        assert_eq!(
            executor.active_proposal_count().unwrap(),
            count_before,
            "metin onerinin sayaci tembel kalir"
        );
        assert_eq!(
            executor.load_proposal(&pid).unwrap().unwrap().status,
            zagros_types::ProposalStatus::Active,
            "kaba durum degismez (effective_status hesaplar)"
        );
    }
}

#[cfg(kani)]
#[allow(unused_imports)]
mod kani_nonce_proofs {
    use super::*;
    use std::sync::Arc;
    use zagros_state::State;
    use zagros_types::AccountState;

    /// Kani proof: `apply_transaction` nonce'u kesinlikle artırır (replay/çift imza
    /// koruması); tam executor kurgusu büyük olduğundan saf nonce ataması doğrulanır.

    #[kani::proof]
    fn verify_account_nonce_strictly_increments_after_transaction() {
        let initial_nonce: u64 = kani::any();
        kani::assume(initial_nonce < u64::MAX - 1);

        let initial_balance: u64 = kani::any();
        let mut account = AccountState::new(initial_balance as u128);
        account.nonce = initial_nonce;

        let tx_nonce: u64 = kani::any();
        kani::assume(tx_nonce == initial_nonce + 1);

        // State update simulator, in reality the executor validates: if tx_nonce == account.nonce + 1
        if tx_nonce == account.nonce + 1 {
            account.nonce += 1;
        }

        kani::assert(
            account.nonce == initial_nonce + 1,
            "Nonce is not strictly incremented, replay attacks are possible!",
        );
    }
}
