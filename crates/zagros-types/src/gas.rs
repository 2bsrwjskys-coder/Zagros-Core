// Zagros Network, Gas Fee Management
// Dinamik gas hesaplama ve Anti-DDoS koruması

use crate::*;
use alloy_primitives::U256;
use portable_atomic::AtomicU128;
use std::sync::atomic::Ordering;
use std::sync::Arc;

/// Ham ZAGROS taban gas ücreti: `gas_fee_zerenya * pool_zagros / pool_zerenya`;
/// ZAGROS'un altın karşılığı ne olursa olsun hedef ZERENYA değerindedir. Saf:
/// mempool ve RPC aynı hedefi kullanır. 🚨 TAŞMA: ara çarpım `U256`da; organik
/// rezervlerde GCD 1'e düşer ve u128 çarpımı sessizce taşıp ücreti binlerce kat küçültürdü.
pub fn base_gas_fee_from_reserves(
    target_gas_fee_zerenya: u128,
    pool_zagros: u128,
    pool_zerenya: u128,
) -> u128 {
    // Havuz henüz kurulmadıysa (ör. test/genesis öncesi) hedefi olduğu gibi döndür.
    if pool_zerenya == 0 {
        return target_gas_fee_zerenya;
    }
    let product = U256::from(target_gas_fee_zerenya) * U256::from(pool_zagros);
    let result = product / U256::from(pool_zerenya);
    u128::try_from(result).unwrap_or(u128::MAX)
}

/// 🛡️ Anti-DDoS üstel stres çarpanı: eşik aşımının her `STRESS_STEP` (5000)
/// işlemi çarpanı ikiye katlar, tavan 1024x (50k → 1x, 55k → 2x, 100k → 1024x).
/// Tek kaynak: mempool asgari kabul ücreti ve RPC'nin gömdüğü ücret aynı çarpanı kullanır.
pub fn ddos_stress_multiplier(mempool_load: usize, ddos_threshold: usize) -> u128 {
    const STRESS_STEP: usize = 5000;
    if mempool_load <= ddos_threshold {
        return 1;
    }
    let excess = mempool_load - ddos_threshold;
    let exponent = (excess / STRESS_STEP).min(10) as u32; // tavan 2^10 = 1024x
    2u128.saturating_pow(exponent)
}

/// İşlem türünün taban ücret çarpanı. Basit (sabit) transfer 1x öderken, ekstra
/// iş yükü olan işlemler (swap, staking, köprü, kontrat) katları öder. Bkz.
/// `GasCalculator::calculate_gas_for_tx_type`, oradaki çarpanlarla birebir aynı;
/// `ContractCall` yalnızca orada ayrıca veri-boyutuna göre ek ücret alır.
pub fn gas_multiplier_for_tx_type(tx_type: &TxType) -> u128 {
    match tx_type {
        TxType::Transfer => 1,
        TxType::SwapBuy | TxType::SwapSell => 2,
        TxType::StakeZagros | TxType::UnstakeZagros => 2,
        TxType::BridgeMint
        | TxType::BridgeBurn
        | TxType::BridgeMintAndSwap
        | TxType::BridgeSwapAndBurn => 3,
        TxType::DeployContract => 100,
        TxType::CallContract => 5,
        TxType::ContractCall { .. } => 5,
        TxType::SubmitProposal => 10,
        TxType::Vote => 1,
        TxType::ClaimReward => 2,
        TxType::ReportMalicious => 10,
        TxType::SlashValidator => 10,
        TxType::RegisterValidator | TxType::UnregisterValidator | TxType::RotateConsensusKey => 2,
        // Admin/quorum yetkili küme işlemleri: SlashValidator ile aynı sınıf.
        TxType::ApproveValidator | TxType::RemoveValidator => 10,
    }
}

/// 🔷 EIP-2028 intrinsic gas: `21.000 + calldata` (sıfır bayt 4, diğer 16);
/// anti-DDoS tabanının "iş" ayağı. Saf: mempool kapısı ve `evm_min_fee` aynı kaynaktan okur.
pub fn evm_intrinsic_gas(calldata: &[u8]) -> u128 {
    let calldata_gas: u128 = calldata
        .iter()
        .map(|byte| {
            if *byte == 0 {
                EVM_CALLDATA_GAS_ZERO
            } else {
                EVM_CALLDATA_GAS_NONZERO
            }
        })
        .sum();
    EVM_INTRINSIC_GAS_BASE.saturating_add(calldata_gas)
}

/// Gas fee calculator with dynamic pricing and Anti-DDoS protection
pub struct GasCalculator {
    /// Zagros pool balance (atomic for thread-safety)
    pool_zagros: Arc<AtomicU128>,

    /// ZERENYA pool balance (atomic for thread-safety)
    pool_zerenya: Arc<AtomicU128>,

    /// Base gas fee in ZERENYA (18-decimal ham birim)
    target_gas_fee_zerenya: u128,

    /// DDoS threshold
    ddos_threshold: usize,

    /// `enable_dynamic_gas`: `false` ise havuz oranı ölçeklemesi atlanır, doğrudan
    /// hedef döner. Anti-DDoS kalkanı bu bayraktan bağımsız, hep aktif.
    dynamic_pricing_enabled: bool,
}

impl GasCalculator {
    /// Create new gas calculator with the default 0,0000125 ZERENYA target
    /// (`GAS_FEE_ZERENYA`, 18-decimal ham skala). Testler ve config
    /// gerekmeyen yollar bunu kullanır.
    pub fn new(pool_zagros: Arc<AtomicU128>, pool_zerenya: Arc<AtomicU128>) -> Self {
        Self::with_target(pool_zagros, pool_zerenya, GAS_FEE_ZERENYA)
    }

    /// `GasConfig.gas_fee_zerenya`'dan okunan hedef ücretle kurar (phantom
    /// config bağlandı). CLI bunu config değeriyle çağırır; böylece hem mempool
    /// taban ücreti hem de RPC'nin gömdüğü sabit ücret aynı hedefi kullanır.
    pub fn with_target(
        pool_zagros: Arc<AtomicU128>,
        pool_zerenya: Arc<AtomicU128>,
        target_gas_fee_zerenya: u128,
    ) -> Self {
        Self {
            pool_zagros,
            pool_zerenya,
            target_gas_fee_zerenya,
            ddos_threshold: DDOS_THRESHOLD,
            dynamic_pricing_enabled: true,
        }
    }

    /// `MempoolConfig.ddos_threshold`'ı bağlar (phantom config giderildi, F4).
    /// CLI bunu config değeriyle çağırır; böylece hem asgari kabul ücreti hem de
    /// zincir üstü sabit ücretin stress çarpanı AYNI eşiği kullanır.
    pub fn with_ddos_threshold(mut self, ddos_threshold: usize) -> Self {
        self.ddos_threshold = ddos_threshold;
        self
    }

    /// `GasConfig.enable_dynamic_gas`'ı bağlar (phantom config giderildi).
    /// `false` verildiğinde havuz-oranı ölçeklemesi devre dışı kalır; Anti-DDoS
    /// stress çarpanı bundan etkilenmez (bkz. `dynamic_pricing_enabled` alan
    /// dokümanı).
    pub fn with_dynamic_pricing_enabled(mut self, enabled: bool) -> Self {
        self.dynamic_pricing_enabled = enabled;
        self
    }

    /// Havuz oranına göre dinamik taban ücret: (Hedef_ZERENYA × Havuz_ZAGROS) /
    /// Havuz_ZERENYA; ücret ZAGROS fiyatından bağımsız hep GAS_FEE_ZERENYA değerindedir.
    pub fn calculate_base_gas_fee(&self) -> u128 {
        if !self.dynamic_pricing_enabled {
            // Havuz oranına göre ölçekleme kapalı, sabit hedef ücret.
            return self.target_gas_fee_zerenya;
        }
        let p_zagros = self.pool_zagros.load(Ordering::Acquire);
        let p_zerenya = self.pool_zerenya.load(Ordering::Acquire);
        // Tek gerçek kaynak: saf base_gas_fee_from_reserves (bkz. modül başı).
        // Hedef ücret bu calculator'ın (config'ten gelebilen) alanından okunur.
        base_gas_fee_from_reserves(self.target_gas_fee_zerenya, p_zagros, p_zerenya)
    }

    /// Zincir üstü ücret kesintisinin (zagros-rpc) mempool taban ücretiyle AYNI
    /// hedefi kullanabilmesi için hedef ücreti dışa açar.
    pub fn target_gas_fee_zerenya(&self) -> u128 {
        self.target_gas_fee_zerenya
    }

    /// Calculate gas fee with Anti-DDoS multiplier
    /// When mempool is under stress, gas fees increase EXPONENTIALLY
    /// to prevent spam attacks and DDoS
    pub fn calculate_dynamic_gas_fee(&self, mempool_load: usize) -> u128 {
        // 🛡️ ANTI-DDOS: taban ücret × üstel stress çarpanı (tek kaynak:
        // ddos_stress_multiplier). Eşik matematiği için o fonksiyonun dokümanına
        // bakınız (varsayılan 50.000; stress fiilen 55.000'de başlar).
        self.calculate_base_gas_fee()
            .saturating_mul(self.stress_multiplier(mempool_load))
    }

    /// Bu calculator'ın eşiğine göre anlık stress çarpanı. zagros-rpc'nin sabit
    /// ücret kesintisi de mempool ile AYNI çarpanı buradan alır.
    pub fn stress_multiplier(&self, mempool_load: usize) -> u128 {
        ddos_stress_multiplier(mempool_load, self.ddos_threshold)
    }

    /// Anti-DDoS eşiği (mempool bu değeri aşınca stress moduna geçer). Config'ten
    /// gelir (bkz. `with_ddos_threshold`); mempool `is_under_stress` bunu kullanır.
    pub fn ddos_threshold(&self) -> usize {
        self.ddos_threshold
    }

    /// Operatör paneli şeffaflığı (`zagros_getEffectiveConfig`): `[gas].
    /// enable_dynamic_gas`'ın GERÇEKTEN bu çalışan örnekte hangi değerde
    /// olduğunu dışa açar, config dosyasında ne yazdığını değil, node'un
    /// FİİLEN uyguladığı değeri.
    pub fn dynamic_pricing_enabled(&self) -> bool {
        self.dynamic_pricing_enabled
    }

    /// 🔷 EVM için dinamik anti-DDoS taban: `intrinsic × 1 gwei × stres çarpanı`.
    /// Normal yük 2,1e13 wei (MetaMask'ın 1e14 beyanı geçer); stres modunda
    /// 1024x'e kadar. Çarpan native cetvelle aynı kaynaktan; ücret executor'da Hazine'ye akar.
    pub fn evm_min_fee(&self, calldata: &[u8], mempool_load: usize) -> u128 {
        evm_intrinsic_gas(calldata)
            .saturating_mul(MIN_EVM_GAS_PRICE_WEI)
            .saturating_mul(self.stress_multiplier(mempool_load))
    }

    /// Native cetvel (hedef taban × tür çarpanı). 🚨 EVM türleri buraya düşmemeli,
    /// onlar `evm_min_fee`; yönlendirme `Mempool::min_required_fee`de.
    pub fn calculate_gas_for_tx_type(&self, tx_type: &TxType, mempool_load: usize) -> u128 {
        let base_gas = self.calculate_dynamic_gas_fee(mempool_load);

        // ContractCall ayrıca veri-boyutuna göre ek ücret alır; diğer tüm türler
        // sabit çarpanı kullanır (bkz. gas_multiplier_for_tx_type, zincir üstü
        // ücret kesintisiyle ORTAK kaynak).
        match tx_type {
            TxType::ContractCall { data } => {
                // Gas cost based on data size + base execution cost
                // Base: 5x, plus 1 gas per 32 bytes of data
                let data_gas = (data.len() as u128).div_ceil(32); // Round up to nearest 32 bytes
                base_gas
                    .saturating_mul(gas_multiplier_for_tx_type(tx_type))
                    .saturating_add(base_gas.saturating_mul(data_gas) / 100)
            }
            other => base_gas.saturating_mul(gas_multiplier_for_tx_type(other)),
        }
    }

    /// Havuz oranından ZAGROS'un ZERENYA fiyatı. 🚨 Dolar fiyatı DEĞİL, sistemde
    /// fiat oracle'ı yok; dolar isteyen harici altın fiyatıyla kendisi çarpmalı.
    pub fn get_zagros_price_in_zerenya(&self) -> f64 {
        let p_zagros = self.pool_zagros.load(Ordering::Acquire);
        let p_zerenya = self.pool_zerenya.load(Ordering::Acquire);

        if p_zagros == 0 {
            return 0.0;
        }

        // Price = Pool_Zerenya / Pool_Zagros
        (p_zerenya as f64) / (p_zagros as f64)
    }

    /// Update pool balances (called after swaps)
    pub fn update_pools(&self, zagros_amount: i128, zerenya_amount: i128) {
        self.pool_zagros
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                Some(if zagros_amount >= 0 {
                    current.saturating_add(zagros_amount as u128)
                } else {
                    current.saturating_sub(zagros_amount.unsigned_abs())
                })
            })
            .expect("pool update closure always returns Some");

        self.pool_zerenya
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                Some(if zerenya_amount >= 0 {
                    current.saturating_add(zerenya_amount as u128)
                } else {
                    current.saturating_sub(zerenya_amount.unsigned_abs())
                })
            })
            .expect("pool update closure always returns Some");
    }

    /// Havuz atomiklerini zincir rezervleriyle mutlak eşitler (`update_pools`
    /// delta uygular); blok kapanışında tek satır, drift birikmez.
    pub fn sync_pools(&self, zagros_reserve: u128, zerenya_reserve: u128) {
        self.pool_zagros.store(zagros_reserve, Ordering::Release);
        self.pool_zerenya.store(zerenya_reserve, Ordering::Release);
    }

    /// Get pool balances
    pub fn get_pool_balances(&self) -> (u128, u128) {
        (
            self.pool_zagros.load(Ordering::Acquire),
            self.pool_zerenya.load(Ordering::Acquire),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base_gas_calculation() {
        let pool_zagros = Arc::new(AtomicU128::new(GENESIS_POOL_ZAGROS));
        let pool_zerenya = Arc::new(AtomicU128::new(GENESIS_POOL_ZERENYA));

        let calculator = GasCalculator::new(pool_zagros, pool_zerenya);
        let gas = calculator.calculate_base_gas_fee();

        assert!(gas > 0);
    }

    #[test]
    fn test_anti_ddos_multiplier() {
        let pool_zagros = Arc::new(AtomicU128::new(GENESIS_POOL_ZAGROS));
        let pool_zerenya = Arc::new(AtomicU128::new(GENESIS_POOL_ZERENYA));

        let calculator = GasCalculator::new(pool_zagros, pool_zerenya);

        // Normal load
        let gas_normal = calculator.calculate_dynamic_gas_fee(1000);

        // High load (DDoS attack)
        let gas_stress = calculator.calculate_dynamic_gas_fee(DDOS_THRESHOLD + 5_000);

        // Gas should be higher under stress
        assert!(gas_stress > gas_normal);
    }

    #[test]
    fn test_zagros_price_calculation() {
        // Salt bir oran testi (dolarla ilgisi yok): havuzlar eşitken oran tam 1 olmalı.
        let pool_zagros = Arc::new(AtomicU128::new(42_000_000 * TOKEN_DECIMAL));
        let pool_zerenya = Arc::new(AtomicU128::new(42_000_000 * TOKEN_DECIMAL));

        let calculator = GasCalculator::new(pool_zagros, pool_zerenya);
        let price = calculator.get_zagros_price_in_zerenya();

        assert!((price - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_gas_for_different_tx_types() {
        let pool_zagros = Arc::new(AtomicU128::new(GENESIS_POOL_ZAGROS));
        let pool_zerenya = Arc::new(AtomicU128::new(GENESIS_POOL_ZERENYA));

        let calculator = GasCalculator::new(pool_zagros, pool_zerenya);

        let transfer_gas = calculator.calculate_gas_for_tx_type(&TxType::Transfer, 1000);
        let contract_gas = calculator.calculate_gas_for_tx_type(&TxType::DeployContract, 1000);

        // Contract deployment should be more expensive
        assert!(contract_gas > transfer_gas);
    }

    #[test]
    fn base_gas_fee_is_exactly_target_at_one_to_one_pool() {
        // Havuz 1:1 iken taban ücret tam GAS_FEE_ZERENYA = TARGET'e eşit.
        let base = base_gas_fee_from_reserves(
            GAS_FEE_ZERENYA,
            1_000 * TOKEN_DECIMAL,
            1_000 * TOKEN_DECIMAL,
        );
        assert_eq!(base, GAS_FEE_ZERENYA);
    }

    #[test]
    fn base_gas_fee_stays_worth_the_same_zerenya_amount_regardless_of_zagros_price() {
        // Tanımlayıcı bağıntı: base * pool_zerenya == TARGET * pool_zagros;
        // küçük, tam bölünebilen havuz değerleriyle taşmadan doğrulanır.
        let cases = [
            (1_000u128, 1_000u128), // 1 ZAGROS = 1 ZERENYA
            (1_000, 1_000_000),     // ZAGROS pahalı (az ZAGROS = çok ZERENYA)
            (1_000_000, 1_000),     // ZAGROS ucuz
        ];
        for (pool_zagros, pool_zerenya) in cases {
            let base = base_gas_fee_from_reserves(GAS_FEE_ZERENYA, pool_zagros, pool_zerenya);
            assert_eq!(
                base.saturating_mul(pool_zerenya),
                GAS_FEE_ZERENYA.saturating_mul(pool_zagros),
                "fiyat {pool_zagros}:{pool_zerenya} havuzunda ücret hedeften sapmamalı"
            );
        }
    }

    #[test]
    fn base_gas_fee_does_not_collapse_on_organic_non_round_reserves() {
        // Canlıdan ölçülmüş GCD'si küçük rezerv çifti: eski GCD yolu u128'i sessizce
        // taşırıp ücreti binlerce kat küçültüyordu; sonuç mikro ücrete çökmemeli.
        let pool_zagros = 41_497_706_733_550_846_506_741_079u128;
        let pool_zerenya = 42_508_372_072_855_007_511_347_679u128;
        let base = base_gas_fee_from_reserves(GAS_FEE_ZERENYA, pool_zagros, pool_zerenya);
        assert_eq!(base, 12_202_804_033_058);
        // Sağlık kontrolü: sonuç hedefin makul bir ölçeğinde olmalı, eski
        // hatanın ürettiği gibi ~1000-6000x küçük değil.
        assert!(base > GAS_FEE_ZERENYA / 10);
    }

    #[test]
    fn ddos_stress_multiplier_follows_the_threshold_step_math() {
        let t = 50_000; // varsayılan DDOS_THRESHOLD
        assert_eq!(ddos_stress_multiplier(0, t), 1);
        assert_eq!(ddos_stress_multiplier(50_000, t), 1); // eşikte henüz yok
        assert_eq!(ddos_stress_multiplier(54_999, t), 1); // aşım < 5000
        assert_eq!(ddos_stress_multiplier(55_000, t), 2); // ilk adım
        assert_eq!(ddos_stress_multiplier(60_000, t), 4);
        assert_eq!(ddos_stress_multiplier(65_000, t), 8);
        assert_eq!(ddos_stress_multiplier(100_000, t), 1024); // tavan 2^10
        assert_eq!(ddos_stress_multiplier(500_000, t), 1024); // tavan aşılmaz
    }

    #[test]
    fn dynamic_gas_fee_scales_with_stress_and_uses_the_configured_threshold() {
        let pool = GENESIS_POOL_ZAGROS;
        let calc = GasCalculator::new(
            Arc::new(AtomicU128::new(pool)),
            Arc::new(AtomicU128::new(pool)),
        )
        .with_ddos_threshold(100); // küçük eşik: testte stress'i tetiklemek için
        assert_eq!(calc.ddos_threshold(), 100);

        let base = calc.calculate_base_gas_fee();
        // yük eşiğin altında → 1x
        assert_eq!(calc.calculate_dynamic_gas_fee(50), base);
        // yük eşik + 5000 → 2x (mempool ile AYNI çarpan)
        assert_eq!(
            calc.calculate_dynamic_gas_fee(5_100),
            base.saturating_mul(2)
        );
        assert_eq!(calc.stress_multiplier(5_100), 2);
    }

    #[test]
    fn gas_multipliers_match_workload_weight() {
        assert_eq!(gas_multiplier_for_tx_type(&TxType::Transfer), 1);
        assert_eq!(gas_multiplier_for_tx_type(&TxType::SwapBuy), 2);
        assert_eq!(gas_multiplier_for_tx_type(&TxType::SwapSell), 2);
        assert_eq!(gas_multiplier_for_tx_type(&TxType::BridgeMint), 3);
        assert_eq!(gas_multiplier_for_tx_type(&TxType::DeployContract), 100);
    }

    #[test]
    fn evm_intrinsic_gas_follows_eip_2028() {
        // 21.000 taban; sıfır bayt 4 gas, sıfır olmayan bayt 16 gas.
        assert_eq!(evm_intrinsic_gas(&[]), EVM_INTRINSIC_GAS_BASE);
        assert_eq!(evm_intrinsic_gas(&[0x00, 0x00]), EVM_INTRINSIC_GAS_BASE + 8);
        assert_eq!(
            evm_intrinsic_gas(&[0xff, 0xff]),
            EVM_INTRINSIC_GAS_BASE + 32
        );
    }

    /// 🔷 EVM anti-DDoS kalkanının çekirdek iddiası: sakin ağda meşru bir cüzdanın
    /// beyanı tabanı GEÇER, ağ spam altındayken AYNI beyan YETMEZ.
    #[test]
    fn evm_min_fee_explodes_under_ddos_stress() {
        let calculator = GasCalculator::new(
            Arc::new(AtomicU128::new(1000 * TOKEN_DECIMAL)),
            Arc::new(AtomicU128::new(1000 * TOKEN_DECIMAL)),
        );
        let calldata = [0xabu8; 4];
        // MetaMask'ın tipik beyanı: 100.000 gas @ 1 gwei.
        let wallet_declares = 100_000u128 * 1_000_000_000;

        // Sakin ağ: taban = (21.000 + 4×16) × 1 gwei.
        let calm = calculator.evm_min_fee(&calldata, 0);
        assert_eq!(calm, (EVM_INTRINSIC_GAS_BASE + 64) * MIN_EVM_GAS_PRICE_WEI);
        assert!(
            wallet_declares > calm,
            "meşru cüzdan sakin ağda engellenmemeli"
        );

        // Stress tavanı (2^10 = 1024x): spam mali olarak imkânsızlaşır.
        let stressed = calculator.evm_min_fee(&calldata, DDOS_THRESHOLD + 50_000);
        assert_eq!(stressed, calm * 1024);
        assert!(
            wallet_declares < stressed,
            "stress altında aynı beyan hâlâ geçiyor - kalkan çalışmıyor"
        );
    }

    #[test]
    fn test_pool_update() {
        let pool_zagros = Arc::new(AtomicU128::new(1000 * TOKEN_DECIMAL));
        let pool_zerenya = Arc::new(AtomicU128::new(1000 * TOKEN_DECIMAL));

        let calculator = GasCalculator::new(pool_zagros.clone(), pool_zerenya.clone());

        // Simulate a swap: add 100 Zagros, remove 100 ZERENYA
        calculator.update_pools(100 * TOKEN_DECIMAL as i128, -100 * TOKEN_DECIMAL as i128);

        let (new_zagros, new_zerenya) = calculator.get_pool_balances();

        assert_eq!(new_zagros, 1100 * TOKEN_DECIMAL);
        assert_eq!(new_zerenya, 900 * TOKEN_DECIMAL);
    }

    #[test]
    fn test_sync_pools_overwrites_absolute_reserves_regardless_of_prior_state() {
        let calculator = GasCalculator::new(
            Arc::new(AtomicU128::new(1000 * TOKEN_DECIMAL)),
            Arc::new(AtomicU128::new(1000 * TOKEN_DECIMAL)),
        );

        // Bir blokta kaç swap olduğundan bağımsız olarak, tek çağrı nihai
        // rezervlere eşitler, önceki değer ne olursa olsun.
        calculator.sync_pools(4200 * TOKEN_DECIMAL, 3800 * TOKEN_DECIMAL);

        assert_eq!(
            calculator.get_pool_balances(),
            (4200 * TOKEN_DECIMAL, 3800 * TOKEN_DECIMAL)
        );
    }

    #[test]
    fn test_pool_balances_preserve_values_above_u64() {
        let large_balance = (u64::MAX as u128) + TOKEN_DECIMAL;
        let calculator = GasCalculator::new(
            Arc::new(AtomicU128::new(large_balance)),
            Arc::new(AtomicU128::new(large_balance)),
        );

        calculator.update_pools(TOKEN_DECIMAL as i128, -(TOKEN_DECIMAL as i128));

        assert_eq!(
            calculator.get_pool_balances(),
            (large_balance + TOKEN_DECIMAL, large_balance - TOKEN_DECIMAL)
        );
    }

    #[test]
    fn test_concurrent_pool_updates_are_not_lost() {
        let calculator = Arc::new(GasCalculator::new(
            Arc::new(AtomicU128::new(0)),
            Arc::new(AtomicU128::new(0)),
        ));
        let mut workers = Vec::new();

        for _ in 0..8 {
            let calculator = calculator.clone();
            workers.push(std::thread::spawn(move || {
                for _ in 0..1_000 {
                    calculator.update_pools(1, 1);
                }
            }));
        }

        for worker in workers {
            worker.join().unwrap();
        }

        assert_eq!(calculator.get_pool_balances(), (8_000, 8_000));
    }
}
