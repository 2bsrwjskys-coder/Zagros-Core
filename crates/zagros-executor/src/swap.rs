use alloy_primitives::U256;
use serde::{Deserialize, Serialize};
use zagros_primitives::{Result, ZagrosError};
use zagros_state::State;
use zagros_types::{
    Transaction, MAX_SWAP_AMOUNT_PERCENT, MIN_POOL_LIQUIDITY_ZAGROS, MIN_POOL_LIQUIDITY_ZERENYA,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SwapBuyQuote {
    pub(crate) amount_out: u128,     // Kullanıcıya net teslim edilen ZAGROS
    pub(crate) raw_amount_out: u128, // Ücret kesilmeden önceki AMM çıktısı (ZAGROS)
    // Ücret ZERENYA (giriş) yerine ZAGROS (çıkış) üzerinden kesilir; gas fee ile aynı
    // mantık, anında Hazineye (distribute_staking_reward, %80/%20) aktarılır, ZERENYA
    // bekleme odası/Mega-Swap yok.
    pub(crate) community_fee: u128,
    pub(crate) new_pool_zagros: u128,
    pub(crate) new_pool_zerenya: u128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BridgeSwapQuote {
    pub(crate) amount_out: u128,
    pub(crate) community_fee: u128,
    pub(crate) new_pool_zagros: u128,
    pub(crate) new_pool_zerenya: u128,
}

pub(crate) fn swap_amount_out_min(tx: &Transaction) -> Result<u128> {
    if tx.payload.len() < 68 {
        return Ok(0);
    }

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&tx.payload[36..68]);
    u128::try_from(U256::from_be_bytes(bytes))
        .map_err(|_| ZagrosError::Other("Invalid swap amount".to_string()))
}

/// Sabit, tekdüze swap ücreti (baz puan), %0.10. Balina vergisi (trade
/// büyüklüğüne göre artan ücret eğrisi) YOK; tüm swap/köprü yönleri
/// (SwapBuy, SwapSell, BridgeMintAndSwap, BridgeSwapAndBurn) trade
/// büyüklüğünden bağımsız olarak bu SABİT oranı öder.
pub(crate) const STANDARD_SWAP_FEE_BPS: u128 = 10;

/// `MAX_SWAP_AMOUNT_PERCENT` devre kesicisinin parçalı atlatılmasını önler.
/// 🚨 Adres limiti DEĞİL, havuz seviyesinde GLOBAL kesici (adres bazlı olsaydı
/// Sybil ile atlanırdı; meşru işlemlerin payı paylaşması kabul edilmiş ödünleşim).
/// `check_and_record_daily_mint` şablonu: state'e yazılan zaman dilimli sayaç,
/// işlemle aynı checkpoint'te (revert olursa sayaç da geri alınır).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SwapDirection {
    /// SwapBuy + BridgeMintAndSwap yönü (ZERENYA havuza girer, ZAGROS çıkar),
    /// `pool_zerenya`'ye karşı ölçülür (mevcut tek-işlem kontrolüyle AYNI taban).
    ZerenyaIn,
    /// SwapSell + BridgeSwapAndBurn yönü (ZAGROS havuza girer, ZERENYA çıkar),
    /// `pool_zagros`'a karşı ölçülür.
    ZagrosIn,
}

/// Kümülatif hacim penceresinin süresi. Magic number DEĞİL, adlandırılmış bir
/// protokol parametresi, ileride governance/config üzerinden ayarlanabilir
/// hale getirilebilir (bugün sabit).
pub(crate) const SWAP_VOLUME_WINDOW_SECS: u64 = 60;

fn swap_volume_tracker_key() -> zagros_types::Address {
    "__SWAP_VOLUME_WINDOW__".to_string()
}

/// Eski (v1) sabit-pencere biçimi. YALNIZCA geriye dönük okuma için tutuluyor:
/// `SwapVolumeTracker`'a geçiş sırasında diskte kalmış kayıtlar bununla çözülüp
/// taşınır (bkz. `load_tracker`). Yeni kayıt ASLA bu biçimde yazılmaz.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LegacyFixedWindowTracker {
    window_start_secs: u64,
    cumulative_zerenya_in: u128,
    cumulative_zagros_in: u128,
}

/// 🛡️ Kayan pencere sayacı: sabit pencere sınırında saldırgan t=59 ve t=60'ta
/// %5 + %5 takas edip limitin iki katını hareket ettirirdi. İki kova:
/// `etkin = current + previous * (PENCERE - gecen) / PENCERE`; sınırda önceki
/// pencere tam ağırlıkla sayılır. Kovalar yalnız atanır, tek bölme okuma anında;
/// yerinde azaltma yuvarlama sapması biriktirirdi (determinizm).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SwapVolumeTracker {
    /// Yürürlükteki pencerenin başlangıcı, `SWAP_VOLUME_WINDOW_SECS`'e HİZALI
    /// (`t, t % PENCERE`). Hizalama, tüm node'ların aynı pencere sınırlarını
    /// görmesini garanti eder.
    window_start_secs: u64,
    current_zerenya_in: u128,
    current_zagros_in: u128,
    previous_zerenya_in: u128,
    previous_zagros_in: u128,
}

impl SwapVolumeTracker {
    fn fresh(block_timestamp_secs: u64) -> Self {
        Self {
            window_start_secs: Self::align(block_timestamp_secs),
            current_zerenya_in: 0,
            current_zagros_in: 0,
            previous_zerenya_in: 0,
            previous_zagros_in: 0,
        }
    }

    fn align(secs: u64) -> u64 {
        secs - (secs % SWAP_VOLUME_WINDOW_SECS)
    }

    /// Pencereyi `block_timestamp_secs`'e ilerletir: bir pencere geçtiyse
    /// yürürlükteki kova `previous`'a kayar, iki veya daha fazla pencere
    /// geçtiyse ikisi de sıfırlanır (o kadar sessizlikten sonra taşınacak
    /// geçmiş yoktur).
    fn advance_to(&mut self, block_timestamp_secs: u64) {
        let aligned = Self::align(block_timestamp_secs);
        if aligned <= self.window_start_secs {
            return;
        }
        if aligned.saturating_sub(self.window_start_secs) >= SWAP_VOLUME_WINDOW_SECS * 2 {
            self.previous_zerenya_in = 0;
            self.previous_zagros_in = 0;
        } else {
            self.previous_zerenya_in = self.current_zerenya_in;
            self.previous_zagros_in = self.current_zagros_in;
        }
        self.current_zerenya_in = 0;
        self.current_zagros_in = 0;
        self.window_start_secs = aligned;
    }

    /// Bu yöndeki AĞIRLIKLANDIRILMIŞ etkin hacim (bkz. tip doc yorumu).
    fn effective(&self, direction: SwapDirection, block_timestamp_secs: u64) -> u128 {
        let (current, previous) = match direction {
            SwapDirection::ZerenyaIn => (self.current_zerenya_in, self.previous_zerenya_in),
            SwapDirection::ZagrosIn => (self.current_zagros_in, self.previous_zagros_in),
        };
        let elapsed = block_timestamp_secs
            .saturating_sub(self.window_start_secs)
            .min(SWAP_VOLUME_WINDOW_SECS);
        let remaining = (SWAP_VOLUME_WINDOW_SECS - elapsed) as u128;
        let weighted = previous.saturating_mul(remaining) / SWAP_VOLUME_WINDOW_SECS as u128;
        current.saturating_add(weighted)
    }

    fn add(&mut self, direction: SwapDirection, amount: u128) {
        match direction {
            SwapDirection::ZerenyaIn => {
                self.current_zerenya_in = self.current_zerenya_in.saturating_add(amount)
            }
            SwapDirection::ZagrosIn => {
                self.current_zagros_in = self.current_zagros_in.saturating_add(amount)
            }
        }
    }
}

/// Diskteki sayacı okur; yeni biçim çözülemezse eski (sabit pencere) biçim
/// denenip taşınır. İkisi de çözülemezse HATA (bozuk state "temiz sayaç" sayılmaz).
fn load_tracker(
    state: &dyn State,
    key: &zagros_types::Address,
    block_timestamp_secs: u64,
) -> Result<SwapVolumeTracker> {
    let account = state
        .get_account(key)
        .map_err(|e| ZagrosError::Other(format!("Swap volume tracker read error: {}", e)))?;
    let Some(account) = account.filter(|a| !a.contract_code.is_empty()) else {
        return Ok(SwapVolumeTracker::fresh(block_timestamp_secs));
    };
    if let Ok(tracker) = bincode::deserialize::<SwapVolumeTracker>(&account.contract_code) {
        return Ok(tracker);
    }
    // Taşıma: eski sabit-pencere kaydını yürürlükteki kovaya koy. Muhafazakâr
    // yön, taşınan hacim SAYILMAYA devam eder, yükseltme anında limit
    // gevşemez.
    match bincode::deserialize::<LegacyFixedWindowTracker>(&account.contract_code) {
        Ok(legacy) => Ok(SwapVolumeTracker {
            window_start_secs: SwapVolumeTracker::align(legacy.window_start_secs),
            current_zerenya_in: legacy.cumulative_zerenya_in,
            current_zagros_in: legacy.cumulative_zagros_in,
            previous_zerenya_in: 0,
            previous_zagros_in: 0,
        }),
        Err(e) => Err(ZagrosError::Other(format!(
            "Corrupt swap volume tracker (ne yeni ne eski bicim cozulebildi): {}",
            e
        ))),
    }
}

/// Kümülatif devre kesici (bkz. `SwapDirection`, `SwapVolumeTracker`). `amount`
/// gerçekten yürütülecek miktar; quote sonrası, state mutasyonundan ÖNCE
/// çağrılır (fail-closed). Döner: işlem sonrası ağırlıklı etkin hacim.
pub(crate) fn check_and_record_swap_volume(
    state: &dyn State,
    direction: SwapDirection,
    amount: u128,
    pool_reserve: u128,
    block_timestamp_secs: u64,
) -> Result<u128> {
    let key = swap_volume_tracker_key();
    let mut tracker = load_tracker(state, &key, block_timestamp_secs)?;
    tracker.advance_to(block_timestamp_secs);

    let current = tracker.effective(direction, block_timestamp_secs);
    let new_effective = current
        .checked_add(amount)
        .ok_or_else(|| ZagrosError::Other("Swap volume counter overflow".to_string()))?;
    let cap = pool_reserve.saturating_mul(MAX_SWAP_AMOUNT_PERCENT) / 100;
    if new_effective > cap {
        return Err(ZagrosError::Other(format!(
            "Swap too large (cumulative window limit exceeded): {} + {} > {}",
            current, amount, cap
        )));
    }
    tracker.add(direction, amount);

    let bytes = bincode::serialize(&tracker).map_err(|e| {
        ZagrosError::Other(format!("Failed to serialize swap volume tracker: {}", e))
    })?;
    let mut account = state
        .get_account(&key)
        .map_err(|e| ZagrosError::Other(format!("Swap volume tracker read error: {}", e)))?
        .unwrap_or_default();
    account.contract_code = bytes;
    state
        .set_account(&key, account)
        .map_err(|e| ZagrosError::Other(format!("Swap volume tracker write error: {}", e)))?;
    Ok(new_effective)
}

/// Hacim penceresine ekler (sert %5 tavan tekil + kümülatif) ve sabit
/// `STANDARD_SWAP_FEE_BPS` döner; tüm swap/köprü yönleri aynı oranı öder.
pub(crate) fn record_volume_and_compute_fee_bps(
    state: &dyn State,
    direction: SwapDirection,
    amount: u128,
    pool_reserve: u128,
    block_timestamp_secs: u64,
) -> Result<u128> {
    check_and_record_swap_volume(state, direction, amount, pool_reserve, block_timestamp_secs)?;
    Ok(STANDARD_SWAP_FEE_BPS)
}

pub(crate) fn quote_swap_buy(
    amount_in: u128,
    pool_zagros: u128,
    pool_zerenya: u128,
    fee_bps: u128,
) -> Result<SwapBuyQuote> {
    if pool_zagros < MIN_POOL_LIQUIDITY_ZAGROS || pool_zerenya < MIN_POOL_LIQUIDITY_ZERENYA {
        return Err(ZagrosError::Other("Insufficient liquidity".to_string()));
    }
    if amount_in > pool_zerenya.saturating_mul(MAX_SWAP_AMOUNT_PERCENT) / 100 {
        return Err(ZagrosError::Other("Swap too large".to_string()));
    }

    // Tüm amount_in havuza girer, ücret ham çıktıdan (ZAGROS) kesilip anında
    // Hazineye dağıtılır; `fee_bps` çağıran hesaplar (`record_volume_and_compute_fee_bps`).
    let raw_amount_out = U256::from(amount_in)
        .saturating_mul(U256::from(pool_zagros))
        .checked_div(U256::from(pool_zerenya).saturating_add(U256::from(amount_in)))
        .unwrap_or(U256::ZERO)
        .to::<u128>();

    if raw_amount_out == 0 {
        return Err(ZagrosError::Other("Insufficient liquidity".to_string()));
    }

    let swap_fee = raw_amount_out.saturating_mul(fee_bps) / 10_000;
    let amount_out = raw_amount_out.saturating_sub(swap_fee);

    if amount_out == 0 {
        return Err(ZagrosError::Other("Insufficient liquidity".to_string()));
    }

    Ok(SwapBuyQuote {
        amount_out,
        raw_amount_out,
        community_fee: swap_fee,
        new_pool_zagros: pool_zagros.saturating_sub(raw_amount_out),
        new_pool_zerenya: pool_zerenya.saturating_add(amount_in),
    })
}

pub(crate) fn quote_bridge_mint_and_swap(
    amount: u128,
    pool_zagros: u128,
    pool_zerenya: u128,
    fee_bps: u128,
) -> Result<BridgeSwapQuote> {
    if pool_zagros < MIN_POOL_LIQUIDITY_ZAGROS || pool_zerenya < MIN_POOL_LIQUIDITY_ZERENYA {
        return Err(ZagrosError::Other("Insufficient liquidity".to_string()));
    }
    if amount == 0 {
        return Err(ZagrosError::Other("Insufficient liquidity".to_string()));
    }
    // `quote_swap_buy` ile aynı devre kesici: köprü mint'i tek işlemde havuzun
    // ZAGROS rezervini boşaltamamalı (tutarın arkasında köprü beyanı dışında teminat yok).
    if amount > pool_zerenya.saturating_mul(MAX_SWAP_AMOUNT_PERCENT) / 100 {
        return Err(ZagrosError::Other("Swap too large".to_string()));
    }
    // Bu işlem de ZERENYA -> ZAGROS yönünde olduğu için (SwapBuy ile aynı mantık),
    // ücret girişten (ZERENYA) değil çıkıştan (ZAGROS) kesilir; community_fee
    // doğrudan ZAGROS cinsinden ve anında dağıtılabilir. `fee_bps` çağıran
    // tarafından hesaplanır (bkz. `record_volume_and_compute_fee_bps`).
    let raw_amount_out = U256::from(amount)
        .saturating_mul(U256::from(pool_zagros))
        .checked_div(U256::from(pool_zerenya).saturating_add(U256::from(amount)))
        .unwrap_or(U256::ZERO)
        .to::<u128>();
    if raw_amount_out == 0 || raw_amount_out > pool_zagros {
        return Err(ZagrosError::Other("Insufficient liquidity".to_string()));
    }
    let swap_fee = raw_amount_out.saturating_mul(fee_bps) / 10_000;
    let amount_out = raw_amount_out.saturating_sub(swap_fee);
    if amount_out == 0 {
        return Err(ZagrosError::Other("Insufficient liquidity".to_string()));
    }
    Ok(BridgeSwapQuote {
        amount_out,
        community_fee: swap_fee,
        new_pool_zagros: pool_zagros - raw_amount_out,
        new_pool_zerenya: pool_zerenya.saturating_add(amount),
    })
}

pub(crate) fn quote_bridge_swap_and_burn(
    amount: u128,
    pool_zagros: u128,
    pool_zerenya: u128,
    fee_bps: u128,
) -> Result<BridgeSwapQuote> {
    if amount == 0
        || pool_zagros < MIN_POOL_LIQUIDITY_ZAGROS
        || pool_zerenya < MIN_POOL_LIQUIDITY_ZERENYA
    {
        return Err(ZagrosError::Other("Insufficient liquidity".to_string()));
    }
    // 🛡️ FAZ3: Diğer üç yön gibi %5 devre kesici (flash-loan / fiyat
    // manipülasyonu koruması), girişin (ZAGROS) MAX_SWAP_AMOUNT_PERCENT'inden
    // fazlasını tek işlemde satıp havuzu kırmayı engeller.
    if amount > pool_zagros.saturating_mul(MAX_SWAP_AMOUNT_PERCENT) / 100 {
        return Err(ZagrosError::Other("Swap too large".to_string()));
    }
    let swap_fee = amount.saturating_mul(fee_bps) / 10_000;
    let amount_in_after_fee = amount.saturating_sub(swap_fee);
    let amount_out = U256::from(amount_in_after_fee)
        .saturating_mul(U256::from(pool_zerenya))
        .checked_div(U256::from(pool_zagros).saturating_add(U256::from(amount_in_after_fee)))
        .unwrap_or(U256::ZERO)
        .to::<u128>();
    if amount_out == 0 || amount_out > pool_zerenya {
        return Err(ZagrosError::Other("Insufficient liquidity".to_string()));
    }
    Ok(BridgeSwapQuote {
        amount_out,
        community_fee: swap_fee,
        new_pool_zagros: pool_zagros.saturating_add(amount_in_after_fee),
        new_pool_zerenya: pool_zerenya - amount_out,
    })
}

#[cfg(test)]
mod faz3_tests {
    use super::*;

    // Rahat bir havuz: her iki tarafta da MIN_POOL_LIQUIDITY'nin çok üstünde.
    const BIG: u128 = 100_000_000 * zagros_types::TOKEN_DECIMAL;

    #[test]
    fn bridge_swap_and_burn_quote_accepts_small_amount() {
        // Havuzun %5'inin altında bir çıkış → geçerli.
        let amount = BIG / 100; // %1
        let quote = quote_bridge_swap_and_burn(amount, BIG, BIG, 500).unwrap();
        assert!(quote.amount_out > 0);
    }

    #[test]
    fn bridge_swap_and_burn_quote_rejects_over_five_percent() {
        // 🛡️ FAZ3: girişin (ZAGROS) %5'inden büyük çıkış devre kesiciyle reddedilir.
        let over = BIG.saturating_mul(MAX_SWAP_AMOUNT_PERCENT) / 100 + 1;
        let err = quote_bridge_swap_and_burn(over, BIG, BIG, 500);
        assert!(
            err.is_err(),
            "over-5% BridgeSwapAndBurn quote must be rejected"
        );
    }

    #[test]
    fn bridge_swap_and_burn_quote_rejects_thin_pool() {
        // 🛡️ MIN_POOL_LIQUIDITY altındaki havuzda hiç işlem yapılamaz
        // ("sanal 42M havuz" self-healing uydurması yok).
        let thin = MIN_POOL_LIQUIDITY_ZERENYA - 1;
        let err = quote_bridge_swap_and_burn(thin / 100, thin, thin, 500);
        assert!(
            err.is_err(),
            "sub-MIN_POOL_LIQUIDITY pool must reject swaps"
        );
    }

    #[test]
    fn swap_fee_is_flat_regardless_of_trade_size() {
        // Balina vergisi YOK: küçük de büyük de (devre kesici tavanının
        // altında kalan) her trade AYNI sabit STANDARD_SWAP_FEE_BPS oranını öder.
        let small = BIG / 1000; // %0.1 etki
        let large = BIG / 30; // ~%3.3 etki - devre kesici tavanının (%5) altında ama eskiden balina vergisini tetiklerdi
        let small_quote = quote_swap_buy(small, BIG, BIG, STANDARD_SWAP_FEE_BPS).unwrap();
        let large_quote = quote_swap_buy(large, BIG, BIG, STANDARD_SWAP_FEE_BPS).unwrap();
        assert_eq!(
            small_quote.community_fee,
            small_quote.raw_amount_out * STANDARD_SWAP_FEE_BPS / 10_000
        );
        assert_eq!(
            large_quote.community_fee,
            large_quote.raw_amount_out * STANDARD_SWAP_FEE_BPS / 10_000
        );
    }

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

    #[test]
    fn record_volume_and_compute_fee_bps_always_returns_the_flat_rate() {
        let storage = std::sync::Arc::new(MemoryStorage::default());
        let state = zagros_state::manager::StateDbManager::new(storage);
        let fee_bps = record_volume_and_compute_fee_bps(
            &state,
            SwapDirection::ZerenyaIn,
            BIG / 30, // ~%3.3 etki - eskiden balina vergisini tetiklerdi
            BIG,
            1_000,
        )
        .unwrap();
        assert_eq!(fee_bps, STANDARD_SWAP_FEE_BPS);
    }

    // DEVRE KESİCİ, kayan pencere (sınır patlaması regresyonu)

    fn fresh_state() -> zagros_state::manager::StateDbManager {
        zagros_state::manager::StateDbManager::new(std::sync::Arc::new(MemoryStorage::default()))
    }

    /// Havuzun %5'i, tek pencerede izin verilen tavan.
    fn cap_of(pool: u128) -> u128 {
        pool.saturating_mul(MAX_SWAP_AMOUNT_PERCENT) / 100
    }

    /// 🚨 Regresyon: sabit pencere sınırında tavan iki kez doldurulup limitin
    /// iki katı bir saniyede hareket ettirilebiliyordu.
    #[test]
    fn the_circuit_breaker_cannot_be_doubled_by_straddling_a_window_boundary() {
        let state = fresh_state();
        let pool = BIG;
        let cap = cap_of(pool);

        // Pencerenin SON saniyesinde tavanı doldur (pencere [0, 60)).
        check_and_record_swap_volume(&state, SwapDirection::ZerenyaIn, cap, pool, 59)
            .expect("tavana kadar olan ilk swap kabul edilmeli");

        // Bir saniye sonra YENİ pencere basliyor. Eski kodda burada tavan
        // yeniden ACILIYORDU; artik onceki pencere TAM agirlikla sayilir.
        let err = check_and_record_swap_volume(&state, SwapDirection::ZerenyaIn, cap, pool, 60)
            .expect_err("pencere siniri devre kesiciyi SIFIRLAMAMALI");
        assert!(
            format!("{err:?}").contains("cumulative window limit"),
            "red gerekcesi kumulatif pencere limiti olmali: {err:?}"
        );

        // Kucuk bir miktar da gecmemeli, pencere gercekten dolu.
        assert!(
            check_and_record_swap_volume(&state, SwapDirection::ZerenyaIn, cap / 100, pool, 60)
                .is_err(),
            "sinirin hemen otesinde kapasite ACILMAMALI"
        );
    }

    /// Ağırlık pencere boyunca DOĞRUSAL olarak iner: bir pencere sonra önceki
    /// kova yarı ağırlıkta sayılır, tam pencere sonra hiç sayılmaz. Devre
    /// kesici bir HIZ sınırıdır, kalıcı bir tavan değil.
    #[test]
    fn circuit_breaker_capacity_returns_gradually_as_the_window_slides() {
        let state = fresh_state();
        let pool = BIG;
        let cap = cap_of(pool);

        check_and_record_swap_volume(&state, SwapDirection::ZerenyaIn, cap, pool, 0)
            .expect("ilk swap tavana kadar kabul edilmeli");

        // t=90: pencere [60,120), gecen=30 -> onceki kova yari agirlikta (cap/2).
        // Yani ~cap/2 kadar yeni kapasite acilmis olmali.
        assert!(
            check_and_record_swap_volume(&state, SwapDirection::ZerenyaIn, cap / 2 - 1, pool, 90)
                .is_ok(),
            "yarim pencere sonra kapasitenin yarisi acilmali"
        );
        assert!(
            check_and_record_swap_volume(&state, SwapDirection::ZerenyaIn, cap / 2, pool, 90)
                .is_err(),
            "acilan kapasitenin OTESI hala reddedilmeli"
        );

        // Tam iki pencere sonra gecmis tamamen dusmus olmali.
        let state2 = fresh_state();
        check_and_record_swap_volume(&state2, SwapDirection::ZerenyaIn, cap, pool, 0).unwrap();
        assert!(
            check_and_record_swap_volume(&state2, SwapDirection::ZerenyaIn, cap, pool, 120).is_ok(),
            "iki pencere sonra tavan tamamen yenilenmeli"
        );
    }

    /// İki yön (ZERENYA giren / ZAGROS giren) BİRBİRİNDEN BAĞIMSIZ sayılır,
    /// bir yöndeki hacim diğer yönün kapasitesini yemez.
    #[test]
    fn the_two_swap_directions_have_independent_circuit_breaker_budgets() {
        let state = fresh_state();
        let pool = BIG;
        let cap = cap_of(pool);
        check_and_record_swap_volume(&state, SwapDirection::ZerenyaIn, cap, pool, 10).unwrap();
        check_and_record_swap_volume(&state, SwapDirection::ZagrosIn, cap, pool, 10)
            .expect("ters yonun kendi butcesi olmali");
    }

    /// Çalışan bir zincirde ikili yükseltmesi swap'leri KIRMAMALI: diskteki
    /// eski (sabit pencere) kayıt okunup taşınmalı ve taşınan hacim SAYILMAYA
    /// devam etmeli (yükseltme anında limit gevşememeli).
    #[test]
    fn a_legacy_fixed_window_record_is_migrated_without_loosening_the_limit() {
        let state = fresh_state();
        let pool = BIG;
        let cap = cap_of(pool);

        // Eski bicimde, tavani DOLDURMUS bir kayit yaz.
        let legacy = LegacyFixedWindowTracker {
            window_start_secs: 0,
            cumulative_zerenya_in: cap,
            cumulative_zagros_in: 0,
        };
        let mut account = zagros_types::AccountState::default();
        account.contract_code = bincode::serialize(&legacy).unwrap();
        zagros_state::State::set_account(&state, &swap_volume_tracker_key(), account).unwrap();

        // Ayni pencere icinde ek hacim KABUL EDILMEMELI.
        assert!(
            check_and_record_swap_volume(&state, SwapDirection::ZerenyaIn, cap / 10, pool, 30)
                .is_err(),
            "tasinan eski hacim sayilmaya devam etmeli - yukseltme limiti gevsetemez"
        );
    }

    /// Bozuk (ne yeni ne eski biçimde çözülemeyen) bir sayaç SESSİZCE temiz
    /// sayılmamalı, bu, devre kesicinin sıfırlanması demek olurdu.
    #[test]
    fn a_corrupt_tracker_is_an_error_not_a_silently_reset_circuit_breaker() {
        let state = fresh_state();
        let mut account = zagros_types::AccountState::default();
        account.contract_code = vec![0xff; 7]; // hicbir bicime uymaz
        zagros_state::State::set_account(&state, &swap_volume_tracker_key(), account).unwrap();
        assert!(
            check_and_record_swap_volume(&state, SwapDirection::ZerenyaIn, 1, BIG, 5).is_err(),
            "bozuk sayac HATA vermeli, temiz sayilmamali"
        );
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    #[kani::unwind(1)]
    fn verify_amm_k_invariant_swap_buy() {
        // Sembolik (rastgele) girdiler, Çok büyük sayıları kırpmak için sınırlar çekiyoruz (x*y=k taşmasın)
        let amount_in: u128 = kani::any();
        let pool_zagros: u128 = kani::any();
        let pool_zerenya: u128 = kani::any();

        // 1. Minimum Likidite Varsayımı (0'a bölme ve likidite yokluğu sorunu yaşamamak için)
        kani::assume(pool_zagros >= zagros_types::MIN_POOL_LIQUIDITY_ZAGROS);
        kani::assume(pool_zerenya >= zagros_types::MIN_POOL_LIQUIDITY_ZERENYA);
        // Maksimum mantıklı sayılar (128 bit çarpımda taşmamak için 64 bit sınırında tutuyoruz)
        kani::assume(pool_zagros <= u64::MAX as u128);
        kani::assume(pool_zerenya <= u64::MAX as u128);

        // 2. Maksimum Swap Boyutu Varsayımı
        // Sözleşmedeki gerçek tavana (MAX_SWAP_AMOUNT_PERCENT = %5) saygı duyalım;
        // %5'i aşan girişler quote_swap_buy tarafından zaten Err ile reddedilir.
        let max_swap = pool_zerenya.saturating_mul(zagros_types::MAX_SWAP_AMOUNT_PERCENT) / 100;
        kani::assume(amount_in > 0);
        kani::assume(amount_in <= max_swap);

        // Swap işlemi (ZERENYA verip Zagros alıyoruz); `fee_bps` artık çağıran
        // tarafından hesaplanıp geçiriliyor, burada sabit %5 (500bps) ile
        // k-değişmezini doğruluyoruz, hangi fee_bps olursa olsun matematik
        // aynı (fee her zaman çıkıştan kesilir, k asla azalmaz).
        let result = quote_swap_buy(amount_in, pool_zagros, pool_zerenya, 500);

        // Eğer başarılı olduysa Sabit Ürün kuralları bozuluyor mu kontrol et
        if let Ok(quote) = result {
            let k_before = alloy_primitives::U256::from(pool_zagros)
                .saturating_mul(alloy_primitives::U256::from(pool_zerenya));

            let k_after = alloy_primitives::U256::from(quote.new_pool_zagros)
                .saturating_mul(alloy_primitives::U256::from(quote.new_pool_zerenya));

            // Sabit Ürün Asla Azalmamalı (x*y >= k), Likidite havuzu soyulamaz kuralı\!
            assert!(
                k_after >= k_before,
                "AMM liquidity pool constant (k) decreased!"
            );

            // Kullanıcı bedava token alamamalı
            assert!(quote.amount_out > 0);
        }
    }
}
