use rayon::prelude::*;
use std::collections::HashSet;
use std::sync::Arc;
use tracing::info;
use zagros_executor::Executor;
use zagros_primitives::{Address, Result};
use zagros_types::{Transaction, TxType, LIQUIDITY_POOL_ADDRESS, VALIDATOR_REWARD_POOL};

// Stake/Unstake/ClaimReward/SlashValidator/ReportMalicious, sender/receiver
// dışında bu sanal global muhasebe hesabına dokunur (`settle_pending_stake`).
// Dize executor'daki literal ile TAM eşleşmeli.
const GLOBAL_TOTAL_STAKED_ADDRESS: &str = "__GLOBAL_TOTAL_STAKED__";

// `record_transfer` her kaydı kendi anahtarında tutar ve index tahsisi
// atomiktir; bu jeton zamanlama için gerekmez, EVM dalında zararsız durur,
// testler sayaç anahtarına bu adla erişir. Executor literal'iyle TAM eşleşmeli.
const RECENT_TRANSFERS_ADDRESS: &str = "__RECENT_TRANSFERS_NEXT_INDEX__";

// PARALEL ZAMANLAYICI (SCHEDULER) VE ÇATIŞMA ÇÖZÜCÜ
pub struct Scheduler {
    executor: Arc<Executor>,
}

impl Scheduler {
    pub fn new(executor: Arc<Executor>) -> Self {
        Self { executor }
    }

    /// EVM (`ContractCall`/`CallContract`) mi; `touched_addresses` ve
    /// `execute_batch`'in "EVM her zaman sıralı" kuralı AYNI tanımı kullanmalı.
    fn is_evm_tx(tx: &Transaction) -> bool {
        matches!(
            tx.tx_type,
            TxType::ContractCall { .. } | TxType::CallContract
        )
    }

    /// Testlerin kullandığı kısayol: D14 kuralları AÇIK varsayılır.
    #[cfg(test)]
    fn touched_addresses(tx: &Transaction) -> Vec<Address> {
        Self::touched_addresses_at(tx, true)
    }

    /// `d14`: `D14_RULES_ACTIVATION_HEIGHT` kuralları etkin mi (tarih oynatma
    /// determinizmi için ESKİ bloklar eski jeton kümesiyle sınıflandırılmalı).
    fn touched_addresses_at(tx: &Transaction, d14: bool) -> Vec<Address> {
        let mut addresses = vec![tx.sender.clone(), tx.receiver.clone()];

        let is_evm = Self::is_evm_tx(tx);
        // Tüm Bridge* türleri muhafazakar olarak burada; yanlış paralellik kaybı yarıştan ucuz.
        let touches_pool = matches!(
            tx.tx_type,
            TxType::SwapBuy
                | TxType::SwapSell
                | TxType::BridgeMint
                | TxType::BridgeMintAndSwap
                | TxType::BridgeBurn
                | TxType::BridgeSwapAndBurn
        );
        // G2: ApproveValidator/RemoveValidator hedefi payload'da, executor ile
        // AYNI çözümleyici (`validator_action_target`); çözülemezse executor zaten
        // fail-closed reddeder, burada yalnız çakışma kilidi için eklenir.
        if let Some(target) =
            zagros_types::consensus::validator_action_target(&tx.tx_type, &tx.payload)
        {
            addresses.push(target);
        }
        if is_evm || touches_pool {
            addresses.push(LIQUIDITY_POOL_ADDRESS.to_string());
            // 🛡️ Bu grubun hepsi `distribute_staking_reward` ile VALIDATOR_REWARD_POOL'a
            // yazar; staking grubuyla ortak jeton olmadan SwapBuy + ClaimReward
            // paralel çalışıp atomik olmayan add_balance yarışı yapardı.
            addresses.push(VALIDATOR_REWARD_POOL.to_string());
            // Bu jeton EVM için gereksiz ama zararsız: EVM zaten koşulsuz sıralı
            // gruba gider; gerçek koruma `record_transfer`ın atomik sayacı.
            if is_evm {
                addresses.push(RECENT_TRANSFERS_ADDRESS.to_string());
            }
        }

        // 🚀 Native `Transfer` için ortak jeton YOK: index tahsisi atomik, farklı
        // sender/receiver'lı transferler gerçekten paralel (ortak jeton TPS'i ~200'e düşürürdü).

        // 🛡️ `Vote` `Proposal_<id>`de get→set yapar; jeton olmadan iki oy paralel
        // koşup oy kaybederdi. Format `Executor::proposal_key` ile aynı.
        if matches!(tx.tx_type, TxType::Vote) && tx.payload.len() >= 32 {
            addresses.push(format!("Proposal_{}", hex::encode(&tx.payload[0..32])));
        }
        // 🛡️ `SubmitProposal` aynı `Proposal_<id>` anahtarını YARATIR (`tx_id` =
        // proposal_id); aynı bloktaki Vote paralel koşup "Proposal not found"
        // ile yanlış reddedilebilirdi (sıra bağımlılığı).
        if matches!(tx.tx_type, TxType::SubmitProposal) {
            addresses.push(format!("Proposal_{}", hex::encode(tx.tx_id)));
            // 🛡️ `SubmitProposal` `__ACTIVE_PROPOSAL_COUNT__`ta atomik olmayan
            // get-then-set yapar; farklı id'li iki öneri paralel koşup sayacı ezerdi
            // (40 eşzamanlı gönderimde 12 kayıp). Anahtar `ACTIVE_PROPOSAL_COUNT_KEY` ile aynı.
            addresses.push(Executor::ACTIVE_PROPOSAL_COUNT_KEY.to_string());
        }

        // 🛡️ Stake/Unstake/ClaimReward/SlashValidator/ReportMalicious/
        // ApproveValidator/SubmitProposal hepsi VALIDATOR_REWARD_POOL ve/veya
        // GLOBAL_TOTAL_STAKED üzerinde atomik olmayan get-then-set yapar
        // (`settle_pending_stake`, `distribute_staking_reward`). Ortak jetonla
        // hep aynı sıralı grupta toplanırlar; yanlış paralellik kaybı veri yarışından ucuzdur.
        let touches_staking_accounting = matches!(
            tx.tx_type,
            TxType::StakeZagros
                | TxType::UnstakeZagros
                | TxType::ClaimReward
                | TxType::SlashValidator
                | TxType::ReportMalicious
                | TxType::ApproveValidator
        ) || (d14 && matches!(tx.tx_type, TxType::SubmitProposal));
        if touches_staking_accounting {
            addresses.push(VALIDATOR_REWARD_POOL.to_string());
            addresses.push(GLOBAL_TOTAL_STAKED_ADDRESS.to_string());
        }
        // SlashValidator sentinel `to` ile gelmişse `tx.receiver` gerçek hedef
        // değildir; `slash_target_address` executor'la aynı tek kaynak.
        if matches!(tx.tx_type, TxType::SlashValidator) {
            addresses.push(zagros_types::slash_target_address(
                &tx.receiver,
                &tx.payload,
            ));
        }

        // 🛡️ D14: kilit jetonları küçük harfe kanonikleştirilir; `0xABC…` ile
        // `0xabc…` iki ayrı hesap sayılıp aynı hesaba dokunan işlemler paralel
        // kovaya düşebiliyordu. Yalnız adres biçimli jetonlar dönüştürülür.
        if d14 {
            for a in addresses.iter_mut() {
                if a.len() == 42 && (a.starts_with("0x") || a.starts_with("0X")) {
                    *a = a.to_ascii_lowercase();
                }
            }
        }

        addresses
    }

    /// Girdileri paralel/sıralı gruplara ayırır; EVM hep sıralı. 🚨 `classify`
    /// kilidi blok 811'den itibaren (tarih oynatma). DEĞİŞTİRİLEMEZ.
    pub const CLASSIFY_LOCK_ACTIVATION_HEIGHT: u64 = 811;

    /// Testlerin kullandığı kısayol: D14 kuralları AÇIK varsayılır.
    #[cfg(test)]
    fn classify_at(
        transactions: Vec<Transaction>,
        lock_conflicting: bool,
    ) -> (Vec<Transaction>, Vec<Transaction>) {
        Self::classify_at_rules(transactions, lock_conflicting, true)
    }

    fn classify_at_rules(
        transactions: Vec<Transaction>,
        lock_conflicting: bool,
        d14: bool,
    ) -> (Vec<Transaction>, Vec<Transaction>) {
        let mut independent_txs = Vec::new();
        let mut conflicting_txs = Vec::new();
        let mut locked_accounts: HashSet<Address> = HashSet::new();

        for tx in transactions {
            if Self::is_evm_tx(&tx) {
                // 🛡️ D14: EVM işlemi de adreslerini kilitler; yoksa aynı göndericinin
                // sonraki Transfer'i paralel kovaya düşüp InvalidNonce ile kaybolurdu.
                if d14 {
                    locked_accounts.extend(Self::touched_addresses_at(&tx, d14));
                }
                conflicting_txs.push(tx);
                continue;
            }
            let touched = Self::touched_addresses_at(&tx, d14);
            if touched
                .iter()
                .any(|address| locked_accounts.contains(address))
            {
                // 🚨 Sıralı gruptaki işlemin adresleri de kilitlenir; yoksa aynı göndericinin
                // sonraki işlemi paralel gruba girip InvalidNonce ile düşerdi.
                if lock_conflicting {
                    locked_accounts.extend(touched);
                }
                conflicting_txs.push(tx);
            } else {
                locked_accounts.extend(touched);
                independent_txs.push(tx);
            }
        }

        (independent_txs, conflicting_txs)
    }

    /// Bir blokluk işlemi çatışanlara ayırıp çekirdeklere dağıtır. FIFO sırası
    /// (MEV koruması) asla yeniden sıralanmaz; iki grup da giriş sırasını korur.
    /// 🚨 EVM işlemleri `touched_addresses`e bakılmaksızın HER ZAMAN sıralı
    /// gruba gider: `commit()` kontrat içi dokunulan her adrese yazar ve bu
    /// adresler statik bilinemez; paralel havuza girse bağımsız bir native
    /// işlemle üçüncü bir adreste yarışırdı. Döner: (başarılı, başarısız).
    pub fn execute_batch(
        &self,
        transactions: Vec<Transaction>,
        current_timestamp: u128,
    ) -> Result<(usize, usize)> {
        if transactions.is_empty() {
            return Ok((0, 0));
        }

        info!(
            "🚦 Scheduler: {} adet işlem trafik polisine ulaştı.",
            transactions.len()
        );

        // Blok yüksekliği runtime tarafından execute_batch'ten ÖNCE yazılır (`write_block_height`).
        let height = self.executor.current_block_height_for_rules();
        let lock_conflicting = height >= Self::CLASSIFY_LOCK_ACTIVATION_HEIGHT;
        let d14 = height >= zagros_types::D14_RULES_ACTIVATION_HEIGHT;
        let (independent_txs, conflicting_txs) =
            Self::classify_at_rules(transactions, lock_conflicting, d14);

        let independent_total = independent_txs.len();
        let conflicting_total = conflicting_txs.len();
        info!(
            "⚡ Trafik Analizi: {} işlem %100 Paralel, {} işlem Sıralı (Sequential) işlenecek.",
            independent_total, conflicting_total
        );

        // PARALEL İNFAZ (Rayon ile Multi-Core)
        let success_count = independent_txs
            .par_iter()
            .filter_map(
                |tx| match self.executor.execute_transaction(tx, current_timestamp) {
                    Ok(_) => Some(1),
                    Err(e) => {
                        tracing::error!(
                            "❌ Scheduler (paralel): İşlem reddedildi (TX: {}), Sebep: {:?}",
                            hex::encode(&tx.tx_id[..8]),
                            e
                        );
                        None
                    }
                },
            )
            .count();

        // SIRALI İNFAZ (Paylaşımlı kaynağa dokunanlar)
        let mut fallback_success = 0;
        for tx in conflicting_txs {
            match self.executor.execute_transaction(&tx, current_timestamp) {
                Ok(_) => fallback_success += 1,
                Err(e) => {
                    tracing::error!(
                        "❌ Scheduler (sıralı): İşlem reddedildi (TX: {}), Sebep: {:?}",
                        hex::encode(&tx.tx_id[..8]),
                        e
                    );
                }
            }
        }

        info!(
            "🏁 Scheduler Turu Bitti: {} Paralel Başarı, {} Sıralı Başarı.",
            success_count, fallback_success
        );

        let total_success = success_count + fallback_success;
        let total_fail =
            (independent_total - success_count) + (conflicting_total - fallback_success);
        Ok((total_success, total_fail))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::SecretKey;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use zagros_state::manager::StateDbManager;
    use zagros_state::State;
    use zagros_storage::{Storage, StorageEngine};
    use zagros_types::{AccountState, CHAIN_ID, TOKEN_DECIMAL, VALIDATOR_REWARD_POOL};

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

    fn test_address(seed: u8) -> Address {
        Transaction::address_from_secret_key(&test_secret_key(seed))
    }

    fn transfer_tx(
        sender_seed: u8,
        receiver: &Address,
        nonce: u64,
        amount: u128,
        timestamp: u128,
    ) -> Transaction {
        let key = test_secret_key(sender_seed);
        let mut tx_id = [0u8; 32];
        tx_id[0] = sender_seed;
        tx_id[1] = nonce as u8;
        let mut tx = Transaction {
            tx_id,
            tx_type: TxType::Transfer,
            sender: Transaction::address_from_secret_key(&key),
            amount,
            receiver: receiver.clone(),
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

    fn swap_buy_tx(sender_seed: u8, nonce: u64, amount: u128, timestamp: u128) -> Transaction {
        let key = test_secret_key(sender_seed);
        let mut tx_id = [0u8; 32];
        tx_id[0] = sender_seed;
        tx_id[1] = nonce as u8;
        tx_id[2] = 0xAB;
        let mut tx = Transaction {
            tx_id,
            tx_type: TxType::SwapBuy,
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

    fn staking_tx(
        tx_type: TxType,
        sender_seed: u8,
        nonce: u64,
        amount: u128,
        timestamp: u128,
    ) -> Transaction {
        let key = test_secret_key(sender_seed);
        let mut tx_id = [0u8; 32];
        tx_id[0] = sender_seed;
        tx_id[1] = nonce as u8;
        tx_id[2] = 0xCD;
        let sender = Transaction::address_from_secret_key(&key);
        let mut tx = Transaction {
            tx_id,
            tx_type,
            sender: sender.clone(),
            amount,
            receiver: sender,
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

    /// `tx_id`'yi kasıtlı olarak `proposal_id` yapar, `TxType::SubmitProposal`
    /// kolunun (zagros-executor/src/lib.rs) `proposal.proposal_id = tx.tx_id`
    /// ataması ile AYNI.
    fn submit_proposal_tx(
        sender_seed: u8,
        proposal_id: [u8; 32],
        nonce: u64,
        timestamp: u128,
    ) -> Transaction {
        let key = test_secret_key(sender_seed);
        let sender = Transaction::address_from_secret_key(&key);
        let mut tx = Transaction {
            tx_id: proposal_id,
            tx_type: TxType::SubmitProposal,
            sender: sender.clone(),
            amount: 0,
            receiver: sender,
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

    fn vote_tx(
        sender_seed: u8,
        proposal_id: [u8; 32],
        support: bool,
        nonce: u64,
        timestamp: u128,
    ) -> Transaction {
        let key = test_secret_key(sender_seed);
        let mut tx_id = [0u8; 32];
        tx_id[0] = sender_seed;
        tx_id[1] = nonce as u8;
        tx_id[2] = 0xF0;
        let mut payload = proposal_id.to_vec();
        payload.push(if support { 1 } else { 0 });
        let sender = Transaction::address_from_secret_key(&key);
        let mut tx = Transaction {
            tx_id,
            tx_type: TxType::Vote,
            sender: sender.clone(),
            amount: 0,
            receiver: sender,
            payload,
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

    fn setup_pool_state(pool_zagros: u128, pool_zsc: u128) -> Arc<dyn State> {
        let state = test_state();
        state.set_pool_reserves(pool_zagros, pool_zsc).unwrap();
        state
            .set_account(
                &LIQUIDITY_POOL_ADDRESS.to_string(),
                AccountState {
                    balance: pool_zagros,
                    zerenya_balance: pool_zsc,
                    ..Default::default()
                },
            )
            .unwrap();
        state
    }

    #[test]
    fn independent_transfers_are_parallelized_and_conserve_total_supply() {
        let state = test_state();
        // `total_staked == 0` iken ücret doğrudan Hazine'ye gider; gerçekçi staker seed'lenir.
        state
            .set_account(
                &"__GLOBAL_TOTAL_STAKED__".to_string(),
                AccountState::new(1_000 * TOKEN_DECIMAL),
            )
            .unwrap();
        let executor = Arc::new(Executor::new(state.clone()));
        let scheduler = Scheduler::new(executor.clone());

        let n: u8 = 50;
        let initial_balance = 1_000_000u128;
        let transfer_amount = 100u128;
        let fee = 2u128; // gas_limit(1) * gas_price(2)

        let mut senders = Vec::new();
        let mut receivers = Vec::new();
        let mut txs = Vec::new();
        for i in 1..=n {
            let sender = test_address(i);
            let receiver = test_address(100 + i); // 101..=150, disjoint from senders 1..=50
            state
                .set_account(&sender, AccountState::new(initial_balance))
                .unwrap();
            senders.push(sender);
            receivers.push(receiver.clone());
            txs.push(transfer_tx(i, &receiver, 0, transfer_amount, 1_000));
        }

        let (success, fail) = scheduler.execute_batch(txs, 1_000).unwrap();
        assert_eq!(success, n as usize);
        assert_eq!(fail, 0);
        executor.flush_block_rewards(1_000).unwrap();

        for sender in &senders {
            let acc = state.get_account(sender).unwrap().unwrap();
            assert_eq!(acc.balance, initial_balance - transfer_amount - fee);
            assert_eq!(acc.nonce, 1);
        }
        for receiver in &receivers {
            let acc = state.get_account(receiver).unwrap().unwrap();
            assert_eq!(acc.balance, transfer_amount);
        }
        let reward_pool = state
            .get_balance(&VALIDATOR_REWARD_POOL.to_string())
            .unwrap();
        assert_eq!(reward_pool, fee * n as u128);
    }

    #[test]
    fn same_sender_transactions_are_correctly_serialized() {
        let state = test_state();
        let executor = Arc::new(Executor::new(state.clone()));
        let scheduler = Scheduler::new(executor);

        let sender = test_address(1);
        state
            .set_account(&sender, AccountState::new(1_000_000))
            .unwrap();
        let receiver_a = test_address(2);
        let receiver_b = test_address(3);

        let tx1 = transfer_tx(1, &receiver_a, 0, 100, 1_000);
        let tx2 = transfer_tx(1, &receiver_b, 1, 100, 1_000);

        let (success, fail) = scheduler.execute_batch(vec![tx1, tx2], 1_000).unwrap();
        assert_eq!(success, 2);
        assert_eq!(fail, 0);

        let sender_acc = state.get_account(&sender).unwrap().unwrap();
        assert_eq!(sender_acc.nonce, 2);
        assert_eq!(sender_acc.balance, 1_000_000 - 200 - 4);
        assert_eq!(state.get_balance(&receiver_a).unwrap(), 100);
        assert_eq!(state.get_balance(&receiver_b).unwrap(), 100);
    }

    /// 🚨 Aynı göndericinin ilk işlemi sıralı gruba düşünce ikincisi paralel
    /// gruba girip önce çalışıyor, InvalidNonce ile kayboluyordu; `classify`
    /// sıralı gruba giden işlemin adreslerini de kilitlemeli.
    #[test]
    fn a_later_same_sender_tx_never_runs_before_its_predecessor_that_landed_in_the_sequential_lane()
    {
        let state = test_state();
        // Kural kapısı: kilit yalnız blok ≥ 811 (tarih oynatma determinizmi)
        state
            .set_account(
                &"__GLOBAL_BLOCK_HEIGHT__".to_string(),
                AccountState::new(Scheduler::CLASSIFY_LOCK_ACTIVATION_HEIGHT as u128),
            )
            .unwrap();
        let executor = Arc::new(Executor::new(state.clone()));
        let scheduler = Scheduler::new(executor);

        let alice = test_address(1);
        let bob = test_address(2);
        let shared_receiver = test_address(3); // ör. yük testindeki ortak sink
        let other_receiver = test_address(4);
        state
            .set_account(&alice, AccountState::new(1_000_000))
            .unwrap();
        state
            .set_account(&bob, AccountState::new(1_000_000))
            .unwrap();

        // Blok sırası: alice→shared (paralel, shared'ı kilitler),
        // bob→shared (shared kilitli → SIRALI; bob KİLİTLENMİYORDU),
        // bob→other nonce 1 (eski kodda paralel → bob nonce 0'dan ÖNCE çalışırdı).
        let tx_alice = transfer_tx(1, &shared_receiver, 0, 100, 1_000);
        let tx_bob_0 = transfer_tx(2, &shared_receiver, 0, 100, 1_000);
        let tx_bob_1 = transfer_tx(2, &other_receiver, 1, 100, 1_000);

        let (success, fail) = scheduler
            .execute_batch(vec![tx_alice, tx_bob_0, tx_bob_1], 1_000)
            .unwrap();
        assert_eq!(
            fail, 0,
            "aynı göndericinin ardışık işlemi sessizce düşmemeli"
        );
        assert_eq!(success, 3);

        let bob_acc = state.get_account(&bob).unwrap().unwrap();
        assert_eq!(bob_acc.nonce, 2);
        assert_eq!(bob_acc.balance, 1_000_000 - 200 - 4);
        assert_eq!(state.get_balance(&shared_receiver).unwrap(), 200);
        assert_eq!(state.get_balance(&other_receiver).unwrap(), 100);
    }

    /// Tarih oynatma: blok < 811'de ESKİ sınıflandırma (kilit yok) korunur, aynı
    /// senaryo bob'un 2. işlemini düşürür (eski zincir böyle yürüdü; taze node aynı
    /// kökü bulmalı).
    #[test]
    fn before_the_activation_height_the_legacy_classification_still_drops_the_later_tx() {
        let state = test_state();
        state
            .set_account(
                &"__GLOBAL_BLOCK_HEIGHT__".to_string(),
                AccountState::new((Scheduler::CLASSIFY_LOCK_ACTIVATION_HEIGHT - 1) as u128),
            )
            .unwrap();
        let executor = Arc::new(Executor::new(state.clone()));
        let scheduler = Scheduler::new(executor);
        let shared = test_address(3);
        state
            .set_account(&test_address(1), AccountState::new(1_000_000))
            .unwrap();
        state
            .set_account(&test_address(2), AccountState::new(1_000_000))
            .unwrap();
        let (s, f) = scheduler
            .execute_batch(
                vec![
                    transfer_tx(1, &shared, 0, 100, 1_000),
                    transfer_tx(2, &shared, 0, 100, 1_000),
                    transfer_tx(2, &test_address(4), 1, 100, 1_000),
                ],
                1_000,
            )
            .unwrap();
        assert_eq!(
            (s, f),
            (2, 1),
            "eski kural: bob nonce1 paralelde önce çalışıp düşer"
        );
        assert_eq!(
            state.get_account(&test_address(2)).unwrap().unwrap().nonce,
            1
        );
    }

    #[test]
    fn concurrent_swaps_against_one_pool_match_sequential_execution() {
        let pool_zagros = 10_000_000 * TOKEN_DECIMAL;
        let pool_zsc = 10_000_000 * TOKEN_DECIMAL;
        let n: u8 = 10;
        let amount = 10_000 * TOKEN_DECIMAL;

        let txs: Vec<Transaction> = (1..=n).map(|i| swap_buy_tx(i, 0, amount, 1_000)).collect();

        // Run through the scheduler.
        let scheduled_state = setup_pool_state(pool_zagros, pool_zsc);
        let scheduled_executor = Arc::new(Executor::new(scheduled_state.clone()));
        for i in 1..=n {
            scheduled_state
                .set_account(
                    &test_address(i),
                    AccountState {
                        balance: 100,
                        zerenya_balance: 1_000_000 * TOKEN_DECIMAL,
                        ..Default::default()
                    },
                )
                .unwrap();
        }
        let scheduler = Scheduler::new(scheduled_executor);
        let (success, fail) = scheduler.execute_batch(txs.clone(), 1_000).unwrap();
        assert_eq!(fail, 0);
        assert_eq!(success, n as usize);
        let scheduled_reserves = scheduled_state.get_pool_reserves().unwrap();

        // Run the exact same transactions sequentially, in original order,
        // directly through the executor, no scheduler involved.
        let sequential_state = setup_pool_state(pool_zagros, pool_zsc);
        let sequential_executor = Executor::new(sequential_state.clone());
        for i in 1..=n {
            sequential_state
                .set_account(
                    &test_address(i),
                    AccountState {
                        balance: 100,
                        zerenya_balance: 1_000_000 * TOKEN_DECIMAL,
                        ..Default::default()
                    },
                )
                .unwrap();
        }
        for tx in &txs {
            sequential_executor.execute_transaction(tx, 1_000).unwrap();
        }
        let sequential_reserves = sequential_state.get_pool_reserves().unwrap();

        assert_eq!(
            scheduled_reserves, sequential_reserves,
            "pool reserves after scheduled (parallel-eligible but pool-serialized) execution \
             must byte-for-byte match sequential execution in original order"
        );
    }

    #[test]
    fn failing_transactions_in_a_parallel_batch_dont_corrupt_other_accounts() {
        let state = test_state();
        let executor = Arc::new(Executor::new(state.clone()));
        let scheduler = Scheduler::new(executor);

        let n: u8 = 20;
        let mut txs = Vec::new();
        for i in 1..=n {
            let sender = test_address(i);
            let receiver = test_address(100 + i);
            if i % 3 == 0 {
                // Enough for gas (fee=2) but not for amount(100)+fee, fails
                // inside execute_transaction_inner, after the checkpoint is
                // already open, exercising the revert-but-charge-gas path.
                state.set_account(&sender, AccountState::new(3)).unwrap();
            } else {
                state
                    .set_account(&sender, AccountState::new(1_000_000))
                    .unwrap();
            }
            txs.push(transfer_tx(i, &receiver, 0, 100, 1_000));
        }

        let expected_fail = (1..=n).filter(|i| i % 3 == 0).count();
        let (success, fail) = scheduler.execute_batch(txs, 1_000).unwrap();
        assert_eq!(fail, expected_fail);
        assert_eq!(success, n as usize - expected_fail);

        for i in 1..=n {
            let sender = test_address(i);
            let receiver = test_address(100 + i);
            let sender_acc = state.get_account(&sender).unwrap().unwrap();
            // Gas is charged and nonce incremented whether the tx succeeded or
            // failed, matches existing single-threaded semantics.
            assert_eq!(sender_acc.nonce, 1);
            if i % 3 == 0 {
                assert_eq!(sender_acc.balance, 3 - 2);
                assert!(
                    state.get_account(&receiver).unwrap().is_none(),
                    "a failed transfer must never have credited its receiver"
                );
            } else {
                assert_eq!(sender_acc.balance, 1_000_000 - 100 - 2);
                assert_eq!(state.get_balance(&receiver).unwrap(), 100);
            }
        }
    }

    #[test]
    fn contract_calls_are_always_placed_in_the_pool_conflict_domain() {
        let tx = Transaction {
            tx_id: [0u8; 32],
            tx_type: TxType::ContractCall {
                data: vec![1, 2, 3],
            },
            sender: test_address(1),
            amount: 0,
            receiver: test_address(2),
            payload: vec![1, 2, 3],
            signature: Vec::new(),
            timestamp: 0,
            nonce: 0,
            gas_limit: 1,
            gas_price: 1,
            chain_id: CHAIN_ID,
        };
        let touched = Scheduler::touched_addresses(&tx);
        assert!(touched.contains(&LIQUIDITY_POOL_ADDRESS.to_string()));

        let legacy_call = Transaction {
            tx_type: TxType::CallContract,
            ..tx
        };
        let touched_legacy = Scheduler::touched_addresses(&legacy_call);
        assert!(touched_legacy.contains(&LIQUIDITY_POOL_ADDRESS.to_string()));
    }

    #[test]
    fn plain_transfers_do_not_touch_the_pool_conflict_domain() {
        let tx = transfer_tx(1, &test_address(2), 0, 100, 0);
        let touched = Scheduler::touched_addresses(&tx);
        assert!(!touched.contains(&LIQUIDITY_POOL_ADDRESS.to_string()));
    }

    /// 🚨 EVM işlemi bloğun ilk işlemi olsa bile (kilitler boşken) paralel
    /// havuza ASLA girmemeli; dinamik dokunduğu adreste yarışabilirdi.
    #[test]
    fn an_evm_transaction_is_never_classified_as_independent_even_when_it_is_first() {
        let evm_tx = Transaction {
            tx_id: [0u8; 32],
            tx_type: TxType::ContractCall {
                data: vec![1, 2, 3],
            },
            sender: test_address(1),
            amount: 0,
            receiver: test_address(2),
            payload: vec![1, 2, 3],
            signature: Vec::new(),
            timestamp: 0,
            nonce: 0,
            gas_limit: 1,
            gas_price: 1,
            chain_id: CHAIN_ID,
        };
        // Tamamen ILGISIZ bir native transfer, EVM tx'in sender/receiver'i
        // VEYA herhangi bir deklare edilmis paylasilan jetonuyla (LIQUIDITY_
        // POOL_ADDRESS vb.) hicbir ortak adresi yok.
        let unrelated_transfer = transfer_tx(50, &test_address(51), 0, 100, 0);

        let (independent, conflicting) =
            Scheduler::classify_at(vec![evm_tx.clone(), unrelated_transfer.clone()], true);

        assert!(
            !independent.iter().any(Scheduler::is_evm_tx),
            "EVM islemi independent (paralel) gruba girmemeliydi"
        );
        assert_eq!(
            conflicting.len(),
            1,
            "EVM islemi conflicting (sirali) gruba girmeliydi"
        );
        assert!(Scheduler::is_evm_tx(&conflicting[0]));
        // Ilgisiz native transfer, EVM ile hicbir adres paylasmadigindan hala
        // bagimsiz/paralel kalabilmeli, bu fix'in performans maliyetini
        // gereksiz yere buyutmedigini de kanitlar.
        assert_eq!(independent.len(), 1);
        assert_eq!(independent[0].tx_id, unrelated_transfer.tx_id);
    }

    /// Aynı kanıt, eski (`CallContract`) EVM yolu için de geçerli.
    #[test]
    fn a_legacy_call_contract_transaction_is_never_classified_as_independent() {
        let evm_tx = Transaction {
            tx_id: [0u8; 32],
            tx_type: TxType::CallContract,
            sender: test_address(1),
            amount: 0,
            receiver: test_address(2),
            payload: vec![1, 2, 3],
            signature: Vec::new(),
            timestamp: 0,
            nonce: 0,
            gas_limit: 1,
            gas_price: 1,
            chain_id: CHAIN_ID,
        };
        let (independent, conflicting) = Scheduler::classify_at(vec![evm_tx], true);
        assert!(independent.is_empty());
        assert_eq!(conflicting.len(), 1);
    }

    #[test]
    fn staking_operations_touch_the_shared_global_accounting_keys() {
        let stake = staking_tx(TxType::StakeZagros, 1, 0, 100, 0);
        let unstake = staking_tx(TxType::UnstakeZagros, 2, 0, 100, 0);
        let claim = staking_tx(TxType::ClaimReward, 3, 0, 0, 0);

        for tx in [&stake, &unstake, &claim] {
            let touched = Scheduler::touched_addresses(tx);
            assert!(
                touched.contains(&VALIDATOR_REWARD_POOL.to_string()),
                "{:?} must lock VALIDATOR_REWARD_POOL",
                tx.tx_type
            );
            assert!(
                touched.contains(&GLOBAL_TOTAL_STAKED_ADDRESS.to_string()),
                "{:?} must lock GLOBAL_TOTAL_STAKED_ADDRESS",
                tx.tx_type
            );
        }
    }

    #[test]
    fn slash_validator_locks_the_real_target_even_behind_the_evm_sentinel_receiver() {
        let tx = staking_tx(TxType::SlashValidator, 1, 0, 0, 0);
        let mut tx = Transaction {
            receiver: zagros_types::SLASH_VALIDATOR_ADDRESS.to_string(),
            payload: test_address(9).into_bytes(),
            ..tx
        };
        tx.sign(&test_secret_key(1));

        let touched = Scheduler::touched_addresses(&tx);
        assert!(
            touched.contains(&test_address(9)),
            "must resolve and lock the real target hidden in payload, not just the sentinel receiver"
        );
        assert!(touched.contains(&VALIDATOR_REWARD_POOL.to_string()));
        assert!(touched.contains(&GLOBAL_TOTAL_STAKED_ADDRESS.to_string()));
    }

    /// Regresyon: farklı göndericilerden Stake/Claim/Unstake ortak muhasebe
    /// anahtarlarında yarışmamalı; scheduler sonucu saf sıralı yürütmeyle aynı olmalı.
    #[test]
    fn concurrent_staking_operations_match_sequential_execution() {
        let staked_balance = 100_000u128;
        let treasury_seed = 10_000_000u128;
        let acc_per_share = 1_000_000_000_000u128; // 1e12 -> reward_owed == staked_balance

        let build_state = || -> Arc<dyn State> {
            let state = test_state();
            state
                .set_account(
                    &GLOBAL_TOTAL_STAKED_ADDRESS.to_string(),
                    AccountState::new(staked_balance * 3),
                )
                .unwrap();
            state
                .set_account(
                    &VALIDATOR_REWARD_POOL.to_string(),
                    AccountState::new(treasury_seed),
                )
                .unwrap();
            state
                .set_accumulated_reward_per_share(acc_per_share)
                .unwrap();
            for seed in [1u8, 2, 3] {
                state
                    .set_account(
                        &test_address(seed),
                        AccountState {
                            balance: 1_000_000,
                            staked_balance,
                            ..Default::default()
                        },
                    )
                    .unwrap();
            }
            state
        };

        // 1 stake (sender 1), 2 claim reward (sender 2), 3 unstake (sender 3).
        let txs = vec![
            staking_tx(TxType::StakeZagros, 1, 0, 5_000, 1_000),
            staking_tx(TxType::ClaimReward, 2, 0, 0, 1_000),
            staking_tx(TxType::UnstakeZagros, 3, 0, 20_000, 1_000),
        ];

        // Scheduler üzerinden (paralel-uygun gruplama uygulanır).
        let scheduled_state = build_state();
        let scheduled_executor = Arc::new(Executor::new(scheduled_state.clone()));
        let scheduler = Scheduler::new(scheduled_executor);
        let (success, fail) = scheduler.execute_batch(txs.clone(), 1_000).unwrap();
        assert_eq!(fail, 0);
        assert_eq!(success, 3);

        // Aynı işlemler, aynı sırada, tamamen sıralı, scheduler yok.
        let sequential_state = build_state();
        let sequential_executor = Executor::new(sequential_state.clone());
        for tx in &txs {
            sequential_executor.execute_transaction(tx, 1_000).unwrap();
        }

        for seed in [1u8, 2, 3] {
            let addr = test_address(seed);
            let scheduled_acc = scheduled_state.get_account(&addr).unwrap().unwrap();
            let sequential_acc = sequential_state.get_account(&addr).unwrap().unwrap();
            assert_eq!(
                scheduled_acc.balance, sequential_acc.balance,
                "sender {seed} balance diverged"
            );
            assert_eq!(
                scheduled_acc.staked_balance, sequential_acc.staked_balance,
                "sender {seed} staked_balance diverged"
            );
            assert_eq!(
                scheduled_acc.pending_stake_amount, sequential_acc.pending_stake_amount,
                "sender {seed} pending_stake_amount diverged"
            );
            assert_eq!(
                scheduled_acc.pending_unstake_amount, sequential_acc.pending_unstake_amount,
                "sender {seed} pending_unstake_amount diverged"
            );
            assert_eq!(
                scheduled_acc.reward_debt, sequential_acc.reward_debt,
                "sender {seed} reward_debt diverged"
            );
        }

        assert_eq!(
            scheduled_state
                .get_balance(&GLOBAL_TOTAL_STAKED_ADDRESS.to_string())
                .unwrap(),
            sequential_state
                .get_balance(&GLOBAL_TOTAL_STAKED_ADDRESS.to_string())
                .unwrap(),
            "__GLOBAL_TOTAL_STAKED__ diverged between scheduled and sequential execution"
        );
        assert_eq!(
            scheduled_state
                .get_balance(&VALIDATOR_REWARD_POOL.to_string())
                .unwrap(),
            sequential_state
                .get_balance(&VALIDATOR_REWARD_POOL.to_string())
                .unwrap(),
            "VALIDATOR_REWARD_POOL diverged between scheduled and sequential execution"
        );
    }

    /// SwapBuy ve ClaimReward farklı sender'lı; yalnız ortak VALIDATOR_REWARD_POOL
    /// jetonu aynı gruba zorlar.
    #[test]
    fn swap_buy_and_claim_reward_share_validator_reward_pool_lock() {
        let swap = swap_buy_tx(1, 0, 100, 0);
        let claim = staking_tx(TxType::ClaimReward, 2, 0, 0, 0);

        let touched_swap = Scheduler::touched_addresses(&swap);
        let touched_claim = Scheduler::touched_addresses(&claim);
        assert!(
            touched_swap.contains(&VALIDATOR_REWARD_POOL.to_string()),
            "SwapBuy must lock VALIDATOR_REWARD_POOL"
        );
        assert!(
            touched_claim.contains(&VALIDATOR_REWARD_POOL.to_string()),
            "ClaimReward must lock VALIDATOR_REWARD_POOL"
        );
    }

    /// Regresyon: aynı blokta SwapBuy + ClaimReward VALIDATOR_REWARD_POOL'da
    /// yarışmamalı; sonuç saf sıralı yürütmeyle aynı olmalı.
    #[test]
    fn concurrent_swap_buy_and_claim_reward_match_sequential_execution() {
        let pool_zagros = 10_000_000 * TOKEN_DECIMAL;
        let pool_zsc = 10_000_000 * TOKEN_DECIMAL;
        let swap_amount = 200_000 * TOKEN_DECIMAL; // pool'un %2'si - devre kesiciyi (%5) tetiklemez
        let acc_per_share = 1_000_000_000_000u128; // 1e12 -> reward_owed == staked_balance
        let claimer_staked = 100_000u128;

        let build_state = || -> Arc<dyn State> {
            let state = setup_pool_state(pool_zagros, pool_zsc);
            // total_staked>0: SwapBuy'ın community_fee'si `distribute_staking_reward`
            // üzerinden doğrudan VALIDATOR_REWARD_POOL'a yönlenir.
            state
                .set_account(
                    &"__GLOBAL_TOTAL_STAKED__".to_string(),
                    AccountState::new(1_000 * TOKEN_DECIMAL),
                )
                .unwrap();
            state
                .set_accumulated_reward_per_share(acc_per_share)
                .unwrap();
            state
                .set_account(
                    &VALIDATOR_REWARD_POOL.to_string(),
                    AccountState::new(10_000_000 * TOKEN_DECIMAL),
                )
                .unwrap();
            state
                .set_account(
                    &test_address(1),
                    AccountState {
                        balance: 100,
                        zerenya_balance: swap_amount.saturating_mul(2),
                        ..Default::default()
                    },
                )
                .unwrap();
            state
                .set_account(
                    &test_address(2),
                    AccountState {
                        balance: 100,
                        staked_balance: claimer_staked,
                        ..Default::default()
                    },
                )
                .unwrap();
            state
        };

        let txs = vec![
            swap_buy_tx(1, 0, swap_amount, 1_000),
            staking_tx(TxType::ClaimReward, 2, 0, 0, 1_000),
        ];

        let scheduled_state = build_state();
        let scheduled_executor = Arc::new(Executor::new(scheduled_state.clone()));
        let scheduler = Scheduler::new(scheduled_executor);
        let (success, fail) = scheduler.execute_batch(txs.clone(), 1_000).unwrap();
        assert_eq!(fail, 0);
        assert_eq!(success, 2);

        let sequential_state = build_state();
        let sequential_executor = Executor::new(sequential_state.clone());
        for tx in &txs {
            sequential_executor.execute_transaction(tx, 1_000).unwrap();
        }

        let scheduled_reward = scheduled_state
            .get_balance(&VALIDATOR_REWARD_POOL.to_string())
            .unwrap();
        let sequential_reward = sequential_state
            .get_balance(&VALIDATOR_REWARD_POOL.to_string())
            .unwrap();
        assert_eq!(
            scheduled_reward, sequential_reward,
            "VALIDATOR_REWARD_POOL diverged between scheduled and sequential execution"
        );
    }

    /// `record_transfer`'ın index tahsisi atomik (`fetch_add`) olduğundan
    /// native Transfer'in RECENT_TRANSFERS_ADDRESS'i kilitlemesine gerek yok;
    /// farklı sender/receiver'lı iki Transfer gerçekten paralel çalışabilir.
    #[test]
    fn transfer_no_longer_locks_recent_transfers_after_atomic_counter_fix() {
        let transfer = transfer_tx(1, &test_address(2), 0, 100, 0);
        let contract_call = Transaction {
            tx_id: [0u8; 32],
            tx_type: TxType::ContractCall {
                data: vec![1, 2, 3],
            },
            sender: test_address(3),
            amount: 0,
            receiver: test_address(4),
            payload: vec![1, 2, 3],
            signature: Vec::new(),
            timestamp: 0,
            nonce: 0,
            gas_limit: 1,
            gas_price: 1,
            chain_id: CHAIN_ID,
        };

        let touched_transfer = Scheduler::touched_addresses(&transfer);
        // Index tahsisi atomik olduğu için Transfer, RECENT_TRANSFERS_ADDRESS'i
        // KİLİTLEMEZ; farklı sender/receiver'lı iki Transfer bağımsız/paralel
        // sayılabilir (bkz. `classify` üzerindeki testler).
        assert!(
            !touched_transfer.contains(&RECENT_TRANSFERS_ADDRESS.to_string()),
            "Transfer artık RECENT_TRANSFERS_ADDRESS'i kilitlememeli (atomik sayaç düzeltmesi)"
        );
        // ContractCall zaten `classify`'da `is_evm_tx` kuralıyla touched_addresses'e
        // HİÇ bakılmadan koşulsuz sıralı gruba gidiyor (bkz. o testler), burada
        // sadece bu fonksiyonun panic atmadığını doğruluyoruz.
        let _touched_call = Scheduler::touched_addresses(&contract_call);
    }

    /// Regresyon: 50 bağımsız Transfer paralel çalışsa da kayıt sayısı, index
    /// sırası ve her transferin tam bir kez görünmesi korunmalı.
    #[test]
    fn concurrent_transfers_preserve_recent_transfer_index() {
        let state = test_state();
        let executor = Arc::new(Executor::new(state.clone()));
        let scheduler = Scheduler::new(executor.clone());

        let n: u8 = 50;
        let mut txs = Vec::new();
        for i in 1..=n {
            let sender = test_address(i);
            let receiver = test_address(100 + i);
            state
                .set_account(&sender, AccountState::new(1_000_000))
                .unwrap();
            txs.push(transfer_tx(i, &receiver, 0, 100, 1_000));
        }

        let (success, fail) = scheduler.execute_batch(txs, 1_000).unwrap();
        assert_eq!(fail, 0);
        assert_eq!(success, n as usize);

        // Blok sonu flush'ı taklit edilir; yoksa diskteki sayaç 0 görünür.
        executor.flush_recent_transfer_index().unwrap();

        // Kayıtlar ayrı `RecentTransfer_<index>` anahtarlarında; doğrulama sayaç
        // anahtarı + çapraz crate `load_recent_transfers_for` üzerinden.
        let next_index = state
            .get_account(&RECENT_TRANSFERS_ADDRESS.to_string())
            .unwrap()
            .map(|acc| acc.balance)
            .unwrap_or(0);
        assert_eq!(
            next_index, n as u128,
            "sayaç tam olarak {} kez artmalıydı, {} bulundu (kayıp veya çift artış)",
            n, next_index
        );

        let mut seen_indices: std::collections::HashSet<u128> = std::collections::HashSet::new();
        for i in 1..=n {
            let sender = test_address(i);
            let receiver = test_address(100 + i);
            let matching =
                Executor::load_recent_transfers_for(state.as_ref(), &receiver, 0).unwrap();
            assert_eq!(
                matching.len(),
                1,
                "sender {i} -> receiver {} transferi kayıp ya da tekrarlanmış",
                100 + i
            );
            assert!(
                matching[0].sender.eq_ignore_ascii_case(&sender),
                "receiver {} kaydındaki sender yanlış",
                100 + i
            );
            assert!(
                seen_indices.insert(matching[0].index),
                "index {} birden fazla transfer tarafından paylaşılmış",
                matching[0].index
            );
        }
        assert_eq!(
            seen_indices.len(),
            n as usize,
            "benzersiz index sayısı {} olmalı",
            n
        );
    }

    /// F-scheduler-vote-race: aynı öneriye oy veren, FARKLI sender'lara sahip
    /// iki Vote işlemi, sadece `Proposal_<id>` anahtarının HER İKİSİNDE de
    /// ortak token olarak bulunması onları aynı çakışan gruba zorlayabilir.
    #[test]
    fn two_votes_on_the_same_proposal_share_the_proposal_lock() {
        let proposal_id = [0x42u8; 32];
        let vote1 = vote_tx(1, proposal_id, true, 0, 0);
        let vote2 = vote_tx(2, proposal_id, false, 0, 0);

        let touched1 = Scheduler::touched_addresses(&vote1);
        let touched2 = Scheduler::touched_addresses(&vote2);
        let expected_key = format!("Proposal_{}", hex::encode(proposal_id));
        assert!(
            touched1.contains(&expected_key),
            "first Vote must lock the Proposal_<id> key"
        );
        assert!(
            touched2.contains(&expected_key),
            "second Vote must lock the Proposal_<id> key"
        );
    }

    /// F-scheduler-vote-race (devamı): `SubmitProposal`'ın KENDİSİ de aynı
    /// `Proposal_<id>` anahtarını (kendi `tx_id`'si üzerinden) kilitlemeli,
    /// aksi halde aynı bloktaki bir Vote, henüz yazılmamış öneriyle yarışabilir.
    #[test]
    fn submit_proposal_shares_the_proposal_lock_with_its_own_votes() {
        let proposal_id = [0x99u8; 32];
        let submit = submit_proposal_tx(1, proposal_id, 0, 0);
        let vote = vote_tx(2, proposal_id, true, 0, 0);

        let touched_submit = Scheduler::touched_addresses(&submit);
        let touched_vote = Scheduler::touched_addresses(&vote);
        let expected_key = format!("Proposal_{}", hex::encode(proposal_id));
        assert!(
            touched_submit.contains(&expected_key),
            "SubmitProposal must lock the Proposal_<id> key it creates"
        );
        assert!(touched_vote.contains(&expected_key));
    }

    /// Regresyon: aynı blokta SubmitProposal + aynı öneriye 2 Vote paralel
    /// çalışmamalı; hiçbir oy kaybolmamalı (saf sıralı ile karşılaştırılır).
    #[test]
    fn concurrent_votes_on_the_same_proposal_match_sequential_execution() {
        let proposal_id = [0x77u8; 32];

        let build_state = || -> Arc<dyn State> {
            let state = test_state();
            // `Executor::new()`'ın gömülü governance varsayılanları: min_stake_
            // to_submit = 10_000 * TOKEN_DECIMAL, proposal_fee = 1000 * TOKEN_DECIMAL.
            state
                .set_account(
                    &test_address(1),
                    AccountState {
                        balance: 1_000_000 * zagros_types::TOKEN_DECIMAL,
                        staked_balance: 20_000 * zagros_types::TOKEN_DECIMAL,
                        ..Default::default()
                    },
                )
                .unwrap();
            for seed in [2u8, 3] {
                state
                    .set_account(
                        &test_address(seed),
                        AccountState {
                            balance: 100,
                            staked_balance: 100_000,
                            ..Default::default()
                        },
                    )
                    .unwrap();
            }
            state
        };

        let txs = vec![
            submit_proposal_tx(1, proposal_id, 0, 1_000),
            vote_tx(2, proposal_id, true, 0, 1_000),
            vote_tx(3, proposal_id, false, 0, 1_000),
        ];

        let scheduled_state = build_state();
        let scheduled_executor = Arc::new(Executor::new(scheduled_state.clone()));
        let scheduler = Scheduler::new(scheduled_executor);
        let (success, fail) = scheduler.execute_batch(txs.clone(), 1_000).unwrap();
        assert_eq!(fail, 0);
        assert_eq!(success, 3);

        let sequential_state = build_state();
        let sequential_executor = Executor::new(sequential_state.clone());
        for tx in &txs {
            sequential_executor.execute_transaction(tx, 1_000).unwrap();
        }

        let load_proposal = |state: &Arc<dyn State>| -> zagros_types::Proposal {
            let key = format!("Proposal_{}", hex::encode(proposal_id));
            let acc = state.get_account(&key).unwrap().unwrap();
            zagros_types::Proposal::deserialize_with_migration(&acc.contract_code).unwrap()
        };
        let scheduled_proposal = load_proposal(&scheduled_state);
        let sequential_proposal = load_proposal(&sequential_state);

        // O(1) oylama refactor'ü sonrası oy sayısı `Proposal.voters` yerine
        // ayrı `ProposalVote_<id>_<addr>` anahtarlarına bakılarak sayılıyor,
        // bkz. `Executor::has_voted`.
        let scheduled_executor_check = Executor::new(scheduled_state.clone());
        let sequential_executor_check = Executor::new(sequential_state.clone());
        for seed in [2u8, 3] {
            let voter = test_address(seed);
            assert!(
                scheduled_executor_check
                    .has_voted(&proposal_id, &voter)
                    .unwrap(),
                "her iki oy da kaydedilmeli, hiçbiri kaybolmamalı (scheduled)"
            );
            assert!(
                sequential_executor_check
                    .has_voted(&proposal_id, &voter)
                    .unwrap(),
                "her iki oy da kaydedilmeli, hiçbiri kaybolmamalı (sequential)"
            );
        }
        assert_eq!(
            scheduled_proposal.votes_for, sequential_proposal.votes_for,
            "votes_for diverged between scheduled and sequential execution"
        );
        assert_eq!(
            scheduled_proposal.votes_against, sequential_proposal.votes_against,
            "votes_against diverged between scheduled and sequential execution"
        );
    }

    /// 🛡️ Farklı id/sender'lı iki SubmitProposal `ACTIVE_PROPOSAL_COUNT_KEY`
    /// jetonunu paylaşıp SIRALI çalışmalı. Mutasyon doğrulaması: jeton satırı
    /// kaldırılınca test düşer, geri eklenince geçer.
    #[test]
    fn two_different_submit_proposals_now_share_the_active_count_conflict_token() {
        let submit_a = submit_proposal_tx(1, [0xAAu8; 32], 0, 0);
        let submit_b = submit_proposal_tx(2, [0xBBu8; 32], 0, 0);

        let touched_a = Scheduler::touched_addresses(&submit_a);
        let touched_b = Scheduler::touched_addresses(&submit_b);

        assert!(
            touched_a.contains(&Executor::ACTIVE_PROPOSAL_COUNT_KEY.to_string()),
            "DÜZELTME REGRESYONU: SubmitProposal artık __ACTIVE_PROPOSAL_COUNT__'ü \
             bir çakışma jetonu olarak eklemeli, eklemiyor: {:?}",
            touched_a
        );
        assert!(
            touched_b.contains(&Executor::ACTIVE_PROPOSAL_COUNT_KEY.to_string()),
            "DÜZELTME REGRESYONU: SubmitProposal artık __ACTIVE_PROPOSAL_COUNT__'ü \
             bir çakışma jetonu olarak eklemeli, eklemiyor: {:?}",
            touched_b
        );
        assert!(
            touched_a.iter().any(|a| touched_b.contains(a)),
            "DÜZELTME REGRESYONU: farklı proposal_id'lere sahip iki SubmitProposal \
             artık en az bir ortak jeton (ACTIVE_PROPOSAL_COUNT_KEY) paylaşmalı - \
             paylaşmıyorsa scheduler bunları yeniden bağımsız/paralel sayar \
             ({:?} vs {:?}).",
            touched_a,
            touched_b
        );
    }

    /// 🛡️ 40 eşzamanlı SubmitProposal'da aktif öneri sayacında KESİN sıfır
    /// kayıp (`==`); ortak jeton olmadan ~12 kayıp gözlenmişti.
    #[test]
    fn many_concurrent_submit_proposals_have_zero_lost_updates_after_the_conflict_token_fix() {
        const N: u8 = 40;
        let build_state = || -> Arc<dyn State> {
            let state = test_state();
            for seed in 1..=N {
                state
                    .set_account(
                        &test_address(seed),
                        AccountState {
                            balance: 1_000_000 * zagros_types::TOKEN_DECIMAL,
                            staked_balance: 20_000 * zagros_types::TOKEN_DECIMAL,
                            ..Default::default()
                        },
                    )
                    .unwrap();
            }
            state
        };

        let txs: Vec<Transaction> = (1..=N)
            .map(|seed| {
                let mut proposal_id = [0u8; 32];
                proposal_id[0] = seed;
                submit_proposal_tx(seed, proposal_id, 0, 0)
            })
            .collect();

        let scheduled_state = build_state();
        let scheduled_executor = Arc::new(Executor::new(scheduled_state.clone()));
        let scheduler = Scheduler::new(scheduled_executor.clone());
        let (success, fail) = scheduler.execute_batch(txs.clone(), 0).unwrap();
        assert_eq!(fail, 0, "hiçbir SubmitProposal reddedilmemeliydi");
        assert_eq!(success, N as usize);

        let scheduled_count = scheduled_executor.active_proposal_count().unwrap();
        // 🛡️ GEVŞEK `<=` değil, KESİN `==`: 40 eşzamanlı SubmitProposal
        // gönderiminde KAYIP OLMAMALI.
        assert_eq!(
            scheduled_count,
            N as u128,
            "DÜZELTME REGRESYONU: {} eşzamanlı SubmitProposal sonrası \
             __ACTIVE_PROPOSAL_COUNT__ {} olmalıydı (sıfır kayıp), {} kayıp \
             güncelleme tespit edildi - ACTIVE_PROPOSAL_COUNT_KEY çakışma \
             jetonu artık touched_addresses'te değil mi?",
            N,
            N,
            N as u128 - scheduled_count
        );
    }

    // ════════════════ D14 (denetim) regresyon testleri ════════════════

    /// A4: kilit jetonu büyük/küçük harfe duyarlı OLMAMALI. Aynı hesabın
    /// karışık harfli yazımı ikinci işlemi paralel kovaya düşürüp kök
    /// ayrışması üretebiliyordu; D14 ile ikisi aynı kilide çarpar.
    #[test]
    fn d14_mixed_case_receiver_conflicts_with_lowercase_receiver() {
        let hot = test_address(9); // küçük harf kanonik
        let hot_upper = format!("0x{}", hot[2..].to_ascii_uppercase());
        let tx_lower = transfer_tx(1, &hot, 0, 100, 0);
        let mut tx_upper = transfer_tx(2, &hot_upper, 0, 100, 0);
        tx_upper.tx_id[0] = 99;

        let (independent, conflicting) =
            Scheduler::classify_at_rules(vec![tx_lower, tx_upper], true, true);
        assert_eq!(independent.len(), 1, "yalniz ilk islem paralel olabilir");
        assert_eq!(
            conflicting.len(),
            1,
            "D14 REGRESYONU: karisik harfli alici ayni hesaptir, kilide carpmali"
        );

        // Eski kurallar (d14=false): bilinen hatali davranis KORUNUR (tarih
        // oynatma determinizmi), iki islem de paralel sayilir.
        let hot2 = test_address(9);
        let hot2_upper = format!("0x{}", hot2[2..].to_ascii_uppercase());
        let a = transfer_tx(1, &hot2, 0, 100, 0);
        let b = transfer_tx(2, &hot2_upper, 0, 100, 0);
        let (ind_old, _) = Scheduler::classify_at_rules(vec![a, b], true, false);
        assert_eq!(ind_old.len(), 2, "eski kurallar birebir korunmali");
    }

    /// A8: EVM işlemi adreslerini kilitlemeli; sonraki native transfer paralel
    /// kovada önce koşup nonce sırasını bozardı.
    #[test]
    fn d14_a_native_tx_after_same_sender_evm_tx_lands_in_the_sequential_lane() {
        let sender_seed = 3u8;
        let evm_tx = Transaction {
            tx_id: [7u8; 32],
            tx_type: TxType::ContractCall {
                data: vec![1, 2, 3],
            },
            sender: test_address(sender_seed),
            amount: 0,
            receiver: test_address(4),
            payload: vec![1, 2, 3],
            signature: vec![0u8; 64],
            timestamp: 0,
            nonce: 0,
            gas_limit: 1,
            gas_price: 1,
            chain_id: CHAIN_ID,
        };
        let later_transfer = transfer_tx(sender_seed, &test_address(5), 1, 50, 0);

        let (independent, conflicting) =
            Scheduler::classify_at_rules(vec![evm_tx.clone(), later_transfer.clone()], true, true);
        assert!(
            independent.is_empty(),
            "D14 REGRESYONU: ayni gondericinin sonraki islemi paralel kovaya dustu (sessiz kayip)"
        );
        assert_eq!(
            conflicting.len(),
            2,
            "ikisi de sirali kovada, blok sirasi korunur"
        );

        // Eski kurallar: bilinen hatali davranis korunur (transfer paralelde).
        let (ind_old, conf_old) =
            Scheduler::classify_at_rules(vec![evm_tx, later_transfer], true, false);
        assert_eq!(ind_old.len(), 1);
        assert_eq!(conf_old.len(), 1);
    }

    /// A7: SubmitProposal, ödül muhasebesi jetonlarını taşımalı ki farklı
    /// gönderili bir stake/claim/swap ile paralel çalışıp Hazine/acc
    /// üzerinde lost-update yapamasın.
    #[test]
    fn d14_submit_proposal_carries_the_staking_accounting_tokens() {
        let mut proposal_id = [0u8; 32];
        proposal_id[0] = 42;
        let sp = submit_proposal_tx(1, proposal_id, 0, 0);
        let touched = Scheduler::touched_addresses_at(&sp, true);
        assert!(
            touched.contains(&VALIDATOR_REWARD_POOL.to_string()),
            "D14 REGRESYONU: SubmitProposal odul havuzu jetonunu tasimali"
        );
        assert!(touched.contains(&GLOBAL_TOTAL_STAKED_ADDRESS.to_string()));
        // Eski kurallar: jetonlar YOK (tarih oynatma birebir).
        let touched_old = Scheduler::touched_addresses_at(&sp, false);
        assert!(!touched_old.contains(&VALIDATOR_REWARD_POOL.to_string()));
    }
}
