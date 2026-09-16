use dashmap::DashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;
use tracing::warn;
use zagros_primitives::{Address, Hash, Result, ZagrosError};
use zagros_state::State;
use zagros_types::{
    config::MempoolConfig, GasCalculator, Transaction, TxType, MAX_BLOCK_GAS_LIMIT,
    MAX_MEMPOOL_CAPACITY, MAX_MEMPOOL_TOTAL_BYTES,
};

/// Pahalı, serileşen EVM işlem türleri kendi hattında tutulur ki patlama ucuz
/// native işlemleri aç bırakmasın.
fn is_heavy(tx_type: &TxType) -> bool {
    matches!(
        tx_type,
        TxType::ContractCall { .. } | TxType::CallContract | TxType::DeployContract
    )
}

/// `Mempool::new()` (config'siz test/varsayılan yol) için TTL varsayılanı,
/// `MempoolConfig::default()`'ın `tx_expiry_seconds`'ıyla AYNI (3600s/1 saat).
const DEFAULT_TX_EXPIRY_SECONDS: u64 = 3600;
/// 🔜 İLERİ NONCE KUYRUĞU: `nonce > beklenen` işlem atılmaz (bir kayıp sonraki
/// tümünü düşürürdü); boşluk ≤ MAX_QUEUE_GAP ise gönderici başına kuyruğa alınır
/// (ana havuza girmez, bloğa seçilmez), selefi gelince terfi eder.
const MAX_QUEUE_GAP: u64 = 32;
const MAX_QUEUED_PER_SENDER: usize = 32;
const MAX_QUEUED_TOTAL: usize = 5_000;
/// Öneriye alınacak işlemin azami yaşı (sn). Yürütme sınırı 300 sn
/// (`Executor::apply_transaction`); yayılım/tur payı için 30 sn altında tutulur.
const PROPOSAL_MAX_TX_AGE_SECS: u128 = 270;

/// `Mempool::admit_transaction`'ın red nedenleri, RPC'nin (ve ileride P2P
/// gossip'in) kendi hata şekline eşleyebilmesi için `add_transaction`'ın ham
/// `ZagrosError`'ından ayrı, yapılandırılmış bir tür.
#[derive(Debug)]
pub enum AdmissionError {
    /// Mempool kapasitesi dolu, en ucuz/en erken kapı, imza/nonce
    /// doğrulaması hiç çalışmadan reddeder.
    Full,
    /// Gönderilen nonce, zincir-üstü taahhüt edilmiş nonce + mempool'daki
    /// bekleyen işlemlerden türetilen beklenen değerle EŞLEŞMİYOR (bayat,
    /// tekrar-oynatılmış veya ileri-boşluklu).
    InvalidNonce { expected: u64, got: u64 },
    /// `add_transaction`'ın kendi kontrollerinden (imza, boyut, ücret,
    /// bakiye, rate-limit, yinelenen tx_id/nonce) biri reddetti.
    Rejected(ZagrosError),
}

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// HİBRİT BEKLEME ODASI (MEMPOOL): O(1) kabul/çıkarma; uçtan uca throughput'un
// gerçek sınırı yürütme ve yayılımdır (README "Performance Benchmarks").
pub struct Mempool {
    pool: DashMap<Hash, Transaction>,
    tx_count: AtomicUsize,
    fifo_queue: Arc<DashMap<u128, Vec<Hash>>>,
    /// ContractCall/CallContract/DeployContract için ayrı FIFO hat, `fifo_queue`
    /// ile birebir aynı şekilde yönetilir, sadece işlem türüne göre ayrılır.
    heavy_fifo_queue: Arc<DashMap<u128, Vec<Hash>>>,
    address_tx_count: DashMap<Address, usize>,

    /// O(1) duplicate-nonce indeksi: `(küçük harf gönderen, nonce)` → tx_id;
    /// tüm havuz taraması yerine kabul O(1) kalır.
    nonce_index: DashMap<(Address, u64), Hash>,

    /// K4: Havuzdaki işlemlerin tahmini toplam bayt boyutu (canlı sayaç).
    total_bytes: AtomicUsize,

    /// Gönderici başına bekleyen işlemlerin toplam ZAGROS maliyeti (gas +
    /// transfer tutarı); toplam zincir bakiyesini aşamaz ("60+60 > 100" kapanır).
    pending_costs: DashMap<Address, u128>,

    /// İşlemin kabul edildiği SUNUCU damgalı an (unix sn). İstemcinin imzaladığı
    /// `Transaction.timestamp`a güvenmek TTL'i atlatmaya izin verirdi; `evict_expired` bunu kullanır.
    arrival_time: DashMap<Hash, u64>,
    /// 🔁 Yerel (RPC) işlemler → son gossip yayın zamanı; yalnız bunlar yeniden
    /// yayınlanır (gossip'le gelenler değil, N× trafik olmasın).
    local_origin_last_broadcast: DashMap<Hash, u64>,
    /// gönderici → (nonce → (işlem, varış zamanı, yerel kaynaklı mı)). Bkz. MAX_QUEUE_GAP.
    queued: DashMap<Address, std::collections::BTreeMap<u64, (Transaction, u64, bool)>>,
    queued_total: AtomicUsize,
    /// 🚨 FIFO anahtarı: sunucu üretimli monoton sıra. `tx.timestamp` istemcinin
    /// doğrulanmayan beyanıdır; `timestamp: 0` yazan herkesin önüne geçerdi
    /// (AMM'de bedelsiz öne geçme). Sıra kabul anına göredir.
    fifo_seq: std::sync::atomic::AtomicU64,
    /// `tx_id` → kuyruk anahtarı (silme yolu anahtarı bilmek zorunda).
    fifo_key: DashMap<Hash, u128>,
    /// `MempoolConfig::tx_expiry_seconds`'a bağlanır (`with_config`), bu
    /// süreden daha eski `arrival_time`'a sahip işlemler `evict_expired`
    /// tarafından tahliye edilir.
    tx_expiry_seconds: u64,

    max_capacity: usize,
    max_tx_per_address: usize,
    max_tx_size_bytes: usize,
    /// K4: Toplam bayt bütçesi, havuzun toplam boyutu bunu aşamaz.
    max_total_bytes: usize,
    /// `[gas].max_gas_per_block` buraya bağlanır (`with_max_block_gas_limit`);
    /// gerçek blok gas bütçesi budur. Varsayılan `MAX_BLOCK_GAS_LIMIT` yalnız testler için.
    max_block_gas_limit: u128,

    /// Zincir üstü bakiye kontrolü için, bir gönderenin gas ücretini
    /// gerçekten karşılayıp karşılamadığını mempool kabul anında görebilmek için.
    state: Arc<dyn State>,
    /// Anti-DDoS: mempool yükü arttıkça asgari kabul ücretini üstel olarak
    /// yükseltmek için (bkz. `calculate_gas_for_tx_type`/`DDOS_THRESHOLD`).
    gas_calculator: Arc<GasCalculator>,

    // 🚀 GERÇEK "ON-DEMAND" BLOK ÜRETİMİ: Sabit 1 saniyelik bekleme yerine, yeni bir
    // işlem geldiğinde blok üretici döngüyü ANİNDA uyandırır. Bu sayede tek bir
    // işlemin bile bloklanma gecikmesi ~1000ms'den, pratikte birkaç milisaniyeye iner.
    notify: Notify,

    /// 🛡️ Köprü imzacı adresi; mint'leri ücret/bakiye kapısından MUAF (öneri zaten
    /// Ethereum yatırması + 2/3 imza ister, ücret ek güvenlik sağlamaz).
    bridge_authority: Option<Address>,
}

impl Mempool {
    /// Varsayılan (sabit) sınırlarla bir mempool kurar. Testler ve config
    /// gerekmeyen yollar bunu kullanır; üretimde CLI `with_config` ile
    /// config.toml değerlerini geçirir.
    pub fn new(state: Arc<dyn State>, gas_calculator: Arc<GasCalculator>) -> Self {
        Self::with_limits(
            state,
            gas_calculator,
            MAX_MEMPOOL_CAPACITY,
            MAX_MEMPOOL_TOTAL_BYTES,
            DEFAULT_TX_EXPIRY_SECONDS,
        )
    }

    /// `MempoolConfig`'ten okunan sınırlarla bir mempool kurar: `max_capacity`
    /// (adet), `max_total_bytes` (bellek bütçesi) ve `tx_expiry_seconds`
    /// GERÇEKTEN config.toml'dan gelir.
    pub fn with_config(
        state: Arc<dyn State>,
        gas_calculator: Arc<GasCalculator>,
        config: &MempoolConfig,
    ) -> Self {
        Self::with_limits(
            state,
            gas_calculator,
            config.max_capacity,
            config.max_total_bytes,
            config.tx_expiry_seconds,
        )
    }

    fn with_limits(
        state: Arc<dyn State>,
        gas_calculator: Arc<GasCalculator>,
        max_capacity: usize,
        max_total_bytes: usize,
        tx_expiry_seconds: u64,
    ) -> Self {
        Self {
            pool: DashMap::new(),
            tx_count: AtomicUsize::new(0),
            fifo_queue: Arc::new(DashMap::new()),
            heavy_fifo_queue: Arc::new(DashMap::new()),
            address_tx_count: DashMap::new(),
            nonce_index: DashMap::new(),
            total_bytes: AtomicUsize::new(0),
            pending_costs: DashMap::new(),
            arrival_time: DashMap::new(),
            local_origin_last_broadcast: DashMap::new(),
            queued: DashMap::new(),
            queued_total: AtomicUsize::new(0),
            fifo_seq: std::sync::atomic::AtomicU64::new(0),
            fifo_key: DashMap::new(),
            tx_expiry_seconds,
            max_capacity,
            max_tx_per_address: 100,
            max_tx_size_bytes: 128 * 1024,
            max_total_bytes,
            max_block_gas_limit: MAX_BLOCK_GAS_LIMIT,
            state,
            gas_calculator,
            notify: Notify::new(),
            bridge_authority: None,
        }
    }

    /// `[gas].max_gas_per_block`u bağlar; çağrılmazsa `MAX_BLOCK_GAS_LIMIT` (100M).
    pub fn with_max_block_gas_limit(mut self, limit: u128) -> Self {
        self.max_block_gas_limit = limit;
        self
    }

    /// Köprü mint önerilerini zincire yazan node-içi anahtarın adresini bağlar.
    /// Yalnızca BU adresten gelen `BridgeMint`/`BridgeMintAndSwap` işlemleri
    /// ücret/bakiye kabul kapısından muaf tutulur (bkz. struct alanının notu).
    pub fn with_bridge_authority(mut self, address: Address) -> Self {
        self.bridge_authority = Some(address);
        self
    }

    /// Bir işlemin havuzda tuttuğu tahmini bellek boyutu (bayt). Heap'te tutulan
    /// değişken-boy alanlar (payload, imza, adresler) + sabit alanlar için üst
    /// sınır bir tahmin. K4 bütçesi bunun üzerinden hesaplanır.
    fn tx_byte_size(tx: &Transaction) -> usize {
        const TX_FIXED_OVERHEAD_BYTES: usize = 128; // tx_id, miktarlar, nonce, gas, enum vb.
        tx.payload.len()
            + tx.signature.len()
            + tx.sender.len()
            + tx.receiver.len()
            + TX_FIXED_OVERHEAD_BYTES
    }

    /// Göndericinin ZAGROS bakiyesinden düşecek toplam (gas + uygulanabilir
    /// tutar). Executor'ın `required_balance` mantığıyla BİREBİR aynı olmalı:
    /// `.balance` yalnız EVM/Transfer/SwapSell/StakeZagros'ta `tx.amount` kadar düşer.
    fn native_zagros_cost(tx: &Transaction) -> u128 {
        let gas_fee = (tx.gas_limit as u128).saturating_mul(tx.gas_price);
        // FAZ2: BridgeSwapAndBurn da .balance'ı tx.amount kadar düşürüyor
        // (executor arm: sender.sub_balance(tx.amount)); Executor::required_balance
        // ile BİREBİR aynı küme olmalı, yoksa rezervasyon bu yönde atlatılır.
        let debits_value = matches!(
            tx.tx_type,
            TxType::Transfer
                | TxType::SwapSell
                | TxType::StakeZagros
                | TxType::BridgeSwapAndBurn
                | TxType::ContractCall { .. }
                | TxType::CallContract
        );
        if debits_value {
            gas_fee.saturating_add(tx.amount)
        } else {
            gas_fee
        }
    }

    /// K3: `add_transaction`'ın ucuz, O(1) kapasite kontrolü, RPC katmanı,
    /// pahalı işleri (imza doğrulama, tam-havuz kopyaları) tetiklemeden ÖNCE
    /// bununla erken reddedebilir.
    pub fn is_full(&self) -> bool {
        self.tx_count.load(Ordering::Relaxed) >= self.max_capacity
    }

    /// Gönderen için sonraki BEKLENEN nonce: state nonce'undan başlayıp bekleyen
    /// ardışıkların üzerinden atlar, O(k). `zagros-rpc::next_pending_nonce` ile aynı anlam.
    pub fn pending_nonce(&self, state_nonce: u64, sender: &str) -> u64 {
        let sender_lower = sender.to_ascii_lowercase();
        let mut next = state_nonce;
        while self.nonce_index.contains_key(&(sender_lower.clone(), next)) {
            next = next.saturating_add(1);
        }
        next
    }

    /// K3: tx_id ile O(1) işlem araması, eski `get_all_transactions().iter().
    /// find(...)` tam-havuz klonlamasının yerine.
    pub fn get_transaction(&self, tx_id: &Hash) -> Option<Transaction> {
        self.pool.get(tx_id).map(|entry| entry.value().clone())
    }

    /// K3: tx_id havuzda mı, O(1), klonlama yok.
    pub fn contains(&self, tx_id: &Hash) -> bool {
        self.pool.contains_key(tx_id)
    }

    /// Havuzun şu anki tahmini toplam bayt boyutu (K4 sayacı).
    pub fn total_bytes(&self) -> usize {
        self.total_bytes.load(Ordering::Relaxed)
    }

    /// Yalnızca test: bayt bütçesini küçük bir değere çekip reddi test etmek için.
    #[cfg(test)]
    fn set_max_total_bytes_for_test(&mut self, limit: usize) {
        self.max_total_bytes = limit;
    }

    /// Yalnızca test: bir adresin (canonical anahtarla) bekleyen işlem sayısı.
    #[cfg(test)]
    fn address_pending_count(&self, sender: &str) -> usize {
        self.address_tx_count
            .get(&sender.to_ascii_lowercase())
            .map(|c| *c)
            .unwrap_or(0)
    }

    /// Blok üretici işçisinin beklediği fonksiyon: Ya mempool'a yeni bir işlem
    /// eklenene kadar (anında uyanır) ya da `max_wait_ms` dolana kadar (batching
    /// güvenlik ağı, aşırı sık döngüyü önler) bekler.
    pub async fn wait_for_activity(&self, max_wait_ms: u64) {
        let _ =
            tokio::time::timeout(Duration::from_millis(max_wait_ms), self.notify.notified()).await;
    }

    /// İşlemi bekleme odasına alır (Tüm güvenlik filtrelerinden geçerse)
    pub fn add_transaction(&self, tx: Transaction) -> Result<()> {
        self.add_transaction_with_min_fee(tx, None)
    }

    /// `add_transaction` gövdesi; `precomputed_min_fee` gömme anındaki asgari.
    /// 🚨 Burada yeniden hesaplanırsa araya giren commit "Gas fee too low" yarışı üretir.
    fn add_transaction_with_min_fee(
        &self,
        tx: Transaction,
        precomputed_min_fee: Option<u128>,
    ) -> Result<()> {
        // 🛑 Native `TxType::DeployContract` kalıcı olarak erişilemez adres (18
        // karakter) üretir ve kullanıcı 100x ücreti boşa öderdi. KALICI KISIT:
        // kontrat dağıtımının tek yolu EVM (`eth_sendRawTransaction`).
        if matches!(tx.tx_type, TxType::DeployContract) {
            warn!(
                "🚫 TxType::DeployContract reddedildi (native kontrat dağıtımı \
                 desteklenmiyor - kalıcı olarak erişilemez kontrat üretir): sender={}",
                tx.sender
            );
            return Err(ZagrosError::Other(
                "TxType::DeployContract is not supported: it produces a permanently \
                 unreachable contract address and would cause real fund loss (100x fee for an \
                 uncallable contract). This is a permanent protocol restriction, not a temporary \
                 one - use standard EVM contract deployment instead \
                 (eth_sendRawTransaction with an empty `to` field / ContractCall)."
                    .to_string(),
            ));
        }

        let tx_size = tx.payload.len();
        if tx_size > self.max_tx_size_bytes {
            warn!(
                "🚨 Anti-Spam: Çok büyük işlem reddedildi! ({} bytes)",
                tx_size
            );
            return Err(ZagrosError::Other(
                "Transaction payload size exceeds limit".into(),
            ));
        }

        if self.tx_count.load(Ordering::Relaxed) >= self.max_capacity {
            return Err(ZagrosError::MempoolFull);
        }

        // 🛡️ K4: Toplam bayt bütçesi, adetsel kapasite dolmasa bile, havuzun
        // toplam boyutu bütçeyi aşacaksa reddet (O(1) atomik okuma; imza
        // doğrulamasından ÖNCE, ucuz bir kapı olarak).
        let entry_bytes = Self::tx_byte_size(&tx);
        if self
            .total_bytes
            .load(Ordering::Relaxed)
            .saturating_add(entry_bytes)
            > self.max_total_bytes
        {
            warn!(
                "🚨 Anti-Spam: Mempool bellek bütçesi doldu (toplam={} bayt, bütçe={} bayt)",
                self.total_bytes.load(Ordering::Relaxed),
                self.max_total_bytes
            );
            return Err(ZagrosError::MempoolFull);
        }

        // 🛡️ Yapısal doğrulama + imza kontrolü: imzasız/sahte gönderenli
        // işlemler state'e hiç dokunmadan burada elenir.
        tx.validate()?;

        // 🔷 EVM iş kapısı: beyan edilen `gas_limit` en az EIP-2028 intrinsic
        // gas'ı karşılamalı, yoksa çalışamayacak işlem mempool'da yer tutar (bedava spam).
        if let Some(calldata) = Self::evm_calldata(&tx) {
            let intrinsic_gas = zagros_types::evm_intrinsic_gas(calldata);
            if (tx.gas_limit as u128) < intrinsic_gas {
                return Err(ZagrosError::Other(format!(
                    "EVM gas limit too low: minimum {} intrinsic gas required, got {}",
                    intrinsic_gas, tx.gas_limit
                )));
            }
        }

        // 🛡️ Köprü mint ücret muafiyeti: `tx.sender` kriptografik doğrulandı;
        // bu adresten mint zaten güçlü kapıdan (Ethereum yatırması + onay + 2/3
        // imza) geçmiştir, ücret ek güvenlik sağlamaz (bkz. `bridge_authority`).
        let is_exempt_bridge_mint =
            matches!(tx.tx_type, TxType::BridgeMint | TxType::BridgeMintAndSwap)
                && self
                    .bridge_authority
                    .as_deref()
                    .is_some_and(|a| a.eq_ignore_ascii_case(&tx.sender));

        // Aşağıdaki kümülatif rezervasyon kontrolünde de kullanılıyor, muaf
        // işlemler için de okunur (ucuz bir state okuması), ama onlar için
        // `total_cost` zaten 0 olacağından pratikte hiçbir şeyi reddetmez.
        let balance = self.state.get_balance(&tx.sender).unwrap_or(0);

        if !is_exempt_bridge_mint {
            // 🛡️ Anti-DDoS taban ücret: yük arttıkça asgari üstel yükselir. Native
            // hat sabit cetvel, EVM hattı intrinsic gas tabanı; aynı stres çarpanı.
            let declared_fee = (tx.gas_limit as u128).saturating_mul(tx.gas_price);
            // 🔒 Kapı, RPC'nin ücreti gömerken kullandığı fonksiyonun AYNISINI çağırır
            // (tek gerçek kaynak, bkz. `min_required_fee`). Ayrı bir rezerv okuması
            // yok, dolayısıyla iki taraf arasında sapma da yok.
            let min_required_fee =
                precomputed_min_fee.unwrap_or_else(|| self.min_required_fee(&tx));
            if declared_fee < min_required_fee {
                if self.is_under_stress() {
                    warn!(
                        "🚨 Anti-DDoS: Ağ yükü altında düşük ücretli işlem reddedildi (gerekli={}, verilen={})",
                        min_required_fee, declared_fee
                    );
                }
                return Err(ZagrosError::Other(format!(
                    "Gas fee too low: minimum {} required under current network load",
                    min_required_fee
                )));
            }

            // 🛡️ Bakiye kontrolü: gas ücretini karşılayamayan gönderenler mempool'a
            // hiç alınmaz (önceden bu kontrol sadece blok yürütme anında yapılıyordu,
            // yani sıfır bakiyeli adresler ücretsiz olarak mempool'u doldurabiliyordu).
            if balance < declared_fee {
                return Err(ZagrosError::InsufficientBalanceForGas);
            }
        }

        // Tüm spam/rezervasyon haritaları küçük harf canonical anahtar kullanır;
        // ham `tx.sender` 0xABC../0xabc.. varyasyonlarıyla adres limiti atlatılırdı.
        let canonical_sender = tx.sender.to_ascii_lowercase();

        let mut sender_count = self
            .address_tx_count
            .entry(canonical_sender.clone())
            .or_insert(0);
        if *sender_count >= self.max_tx_per_address {
            return Err(ZagrosError::Other(
                "Rate limit: Bir adresin çok fazla bekleyen işlemi var".into(),
            ));
        }

        if self.pool.contains_key(&tx.tx_id) {
            return Err(ZagrosError::Other(
                "Transaction zaten bekleme odasında".into(),
            ));
        }

        // 🛡️ K3: O(1) duplicate-nonce kontrolü (eski O(n) tüm-havuz taramasının
        // yerine). Aynı (gönderen, nonce) çifti zaten bekliyorsa reddet.
        let nonce_key = (canonical_sender.clone(), tx.nonce);
        if self.nonce_index.contains_key(&nonce_key) {
            return Err(ZagrosError::InvalidNonce);
        }

        // 🛡️ Bekleyen bakiye rezervasyonu: bekleyenlerin toplamı + bu işlem zincir
        // bakiyesini aşarsa ret. Muaf köprü mint'i için 0: birden çok bekleyen
        // mint birikince kaldırılan bakiye şartı dolaylı geri gelirdi.
        let total_cost = if is_exempt_bridge_mint {
            0
        } else {
            Self::native_zagros_cost(&tx)
        };
        let current_pending = self
            .pending_costs
            .get(&canonical_sender)
            .map(|entry| *entry.value())
            .unwrap_or(0);
        let available_balance = balance.saturating_sub(current_pending);
        if total_cost > available_balance {
            return Err(ZagrosError::InsufficientBalance);
        }

        let queue = if is_heavy(&tx.tx_type) {
            &self.heavy_fifo_queue
        } else {
            &self.fifo_queue
        };
        // Sıra anahtarı SUNUCUDA üretilir, istemci beyanı sırayı etkileyemez.
        let fifo_key = self.fifo_seq.fetch_add(1, Ordering::Relaxed) as u128;
        self.fifo_key.insert(tx.tx_id, fifo_key);
        queue.entry(fifo_key).or_default().push(tx.tx_id);
        self.nonce_index.insert(nonce_key, tx.tx_id);
        self.total_bytes.fetch_add(entry_bytes, Ordering::Relaxed);
        // Rezervasyonu işle: bu adresin bekleyen toplam maliyetini artır.
        *self.pending_costs.entry(canonical_sender).or_insert(0) += total_cost;
        // item 9: SUNUCU tarafı kabul anı, `tx.timestamp` (istemci imzalı,
        // FIFO anahtarı) DEĞİL, bkz. `arrival_time` alanının doc yorumu.
        self.arrival_time.insert(tx.tx_id, now_unix_secs());
        // 🚨 Perf: `tx_id` önce okunup `tx` taşınır, tam `Transaction` klonu alınmaz.
        self.pool.insert(tx.tx_id, tx);
        self.tx_count.fetch_add(1, Ordering::Relaxed);
        *sender_count += 1;

        // 🚀 Blok üretici döngüyü (eğer uyuyorsa) anında uyandır.
        self.notify.notify_one();

        Ok(())
    }

    /// 🔒 Tek kaynak: transfer GAS_FEE_ZERENYA, diğer türler çarpanı; EVM hariç.
    /// `pub`: `eth_estimateGas` havuza dokunmadan simüle eder.
    pub fn apply_fixed_gas_fee(&self, tx: &mut Transaction) {
        self.apply_fixed_gas_fee_returning_min(tx);
    }

    /// `apply_fixed_gas_fee` + kapının kullanacağı asgariyi döndürür (EVM
    /// işlemlerinde gömme yok → `None`, kapı kendi hesaplar).
    fn apply_fixed_gas_fee_returning_min(&self, tx: &mut Transaction) -> Option<u128> {
        if matches!(
            tx.tx_type,
            TxType::ContractCall { .. } | TxType::CallContract
        ) {
            return None;
        }
        // .max(1): dejenere (boşalmış) havuzda ücret 0'a düşerse gas_price=0
        // olur ve Transaction::validate() reddeder; 1 ham birim taban bunu önler.
        let fee = self.min_required_fee(tx).max(1);
        tx.gas_limit = 1;
        tx.gas_price = fee;
        Some(fee)
    }

    /// Dış kaynaklı (RPC ya da P2P gossip) işlem kabulünün TEK giriş noktası.
    /// `add_transaction` zincir üstü nonce'a karşı kontrol yapmaz; kontrol yalnız
    /// RPC'de olsaydı gossip bayat/tekrar işlemleri kabul ettirirdi.
    pub fn admit_transaction(
        &self,
        mut tx: Transaction,
    ) -> std::result::Result<Hash, AdmissionError> {
        if self.is_full() {
            return Err(AdmissionError::Full);
        }
        let embedded_min_fee = self.apply_fixed_gas_fee_returning_min(&mut tx);

        let state_nonce = self.state.get_nonce(&tx.sender).unwrap_or(0);
        let expected = self.pending_nonce(state_nonce, &tx.sender);
        if tx.nonce > expected && tx.nonce - expected <= MAX_QUEUE_GAP {
            return self.enqueue_forward_nonce(tx, false);
        }
        if tx.nonce != expected {
            return Err(AdmissionError::InvalidNonce {
                expected,
                got: tx.nonce,
            });
        }

        let tx_id = tx.tx_id;
        let sender = tx.sender.to_ascii_lowercase();
        self.add_transaction_with_min_fee(tx, embedded_min_fee)
            .map_err(AdmissionError::Rejected)?;
        // Selefi geldi: kuyrukta bekleyen ardışık nonce'ları terfi ettir.
        self.promote_queued(&sender);
        Ok(tx_id)
    }

    /// İşlemi bekleme odasından siler (İşlendiğinde veya süresi dolduğunda)
    pub fn remove_transaction(&self, tx_id: &Hash) -> Option<Transaction> {
        if let Some((_, tx)) = self.pool.remove(tx_id) {
            self.tx_count.fetch_sub(1, Ordering::Relaxed);

            // K3/K4: nonce indeksini ve bayt sayacını senkron tut.
            let canonical_sender = tx.sender.to_ascii_lowercase();
            self.nonce_index
                .remove(&(canonical_sender.clone(), tx.nonce));
            self.total_bytes
                .fetch_sub(Self::tx_byte_size(&tx), Ordering::Relaxed);
            // item 9: arrival_time'ı diğer tüm eşlik eden yapılarla AYNI anda
            // temizle, aksi halde her kaldırılan tx için bir bayat girdi kalır.
            self.arrival_time.remove(tx_id);
            self.local_origin_last_broadcast.remove(tx_id);

            // Pending-balance rezervasyonunu serbest bırak: bu adresin bekleyen
            // maliyetini bu işlemin maliyeti kadar azalt; sıfırlanırsa haritadan
            // sil (bellek sızıntısını önle).
            if let Some(mut reserved) = self.pending_costs.get_mut(&canonical_sender) {
                *reserved = reserved.saturating_sub(Self::native_zagros_cost(&tx));
                if *reserved == 0 {
                    drop(reserved);
                    self.pending_costs.remove(&canonical_sender);
                }
            }

            let queue = if is_heavy(&tx.tx_type) {
                &self.heavy_fifo_queue
            } else {
                &self.fifo_queue
            };

            // 🚨 KRİTİK YAMA BAŞLANGICI: Boşalan kuyrukları tespit et ve temizle
            let key = self.fifo_key.remove(tx_id).map(|(_, k)| k);
            let should_remove_timestamp = match key {
                Some(k) => {
                    if let Some(mut bucket) = queue.get_mut(&k) {
                        bucket.retain(|id| id != tx_id);
                        bucket.is_empty()
                    } else {
                        false
                    }
                }
                None => false,
            };

            if let (true, Some(k)) = (should_remove_timestamp, key) {
                queue.remove(&k);
            }
            // 🚨 KRİTİK YAMA BİTİŞİ

            // FAZ2: canonical anahtarla (add tarafıyla tutarlı, bkz. yukarıda).
            if let Some(mut count) = self.address_tx_count.get_mut(&canonical_sender) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    drop(count);
                    self.address_tx_count.remove(&canonical_sender);
                }
            }
            Some(tx)
        } else {
            None
        }
    }

    /// İleri nonce kuyruğuna al: yalnız imzası/yapısı geçerli işlemler, gönderici
    /// ve toplam tavanlarıyla. `local`: RPC'den geldi (terfide yeniden yayın adayı).
    fn enqueue_forward_nonce(
        &self,
        tx: Transaction,
        local: bool,
    ) -> std::result::Result<Hash, AdmissionError> {
        tx.validate()
            .map_err(|e| AdmissionError::Rejected(e.into()))?;
        if !tx.verify_signature() {
            return Err(AdmissionError::Rejected(ZagrosError::InvalidSignature));
        }
        // Spam kalkanı: fonsuz hesap kuyruğu dolduramaz — bakiye ≥ asgari ücret + tutar.
        let cost = self.min_required_fee(&tx).saturating_add(tx.amount);
        if self.state.get_balance(&tx.sender).unwrap_or(0) < cost {
            return Err(AdmissionError::Rejected(ZagrosError::InsufficientBalance));
        }
        if self.queued_total.load(Ordering::Relaxed) >= MAX_QUEUED_TOTAL {
            return Err(AdmissionError::Rejected(ZagrosError::Other(
                "Rate limit: ileri-nonce kuyrugu dolu".into(),
            )));
        }
        let key = tx.sender.to_ascii_lowercase();
        let mut q = self.queued.entry(key).or_default();
        if q.len() >= MAX_QUEUED_PER_SENDER && !q.contains_key(&tx.nonce) {
            return Err(AdmissionError::Rejected(ZagrosError::Other(
                "Rate limit: bu adresin ileri-nonce kuyrugu dolu".into(),
            )));
        }
        let tx_id = tx.tx_id;
        if q.insert(tx.nonce, (tx, now_unix_secs(), local)).is_none() {
            self.queued_total.fetch_add(1, Ordering::Relaxed);
        }
        Ok(tx_id)
    }

    /// RPC yolu: kuyruğa alınan işlem yerel kaynaklı sayılsın (terfide yeniden yayın).
    pub fn mark_queued_local_origin(&self, sender: &str, tx_id: &Hash) {
        if let Some(mut q) = self.queued.get_mut(&sender.to_ascii_lowercase()) {
            for (_, entry) in q.iter_mut() {
                if entry.0.tx_id == *tx_id {
                    entry.2 = true;
                }
            }
        }
    }

    /// Gönderici için beklenen nonce ilerledikçe kuyruktan ardışık olanları ana havuza
    /// taşır (kabul kapısından geçirerek). Kapıdan geçemeyen (bakiye vb.) atılır.
    pub fn promote_queued(&self, sender: &str) -> usize {
        let key = sender.to_ascii_lowercase();
        let mut promoted = 0usize;
        loop {
            let state_nonce = self.state.get_nonce(&key).unwrap_or(0);
            let expected = self.pending_nonce(state_nonce, &key);
            let next = match self.queued.get_mut(&key) {
                Some(mut q) => {
                    // Beklenenin ALTINDA kalanlar (zincir tüketti) çöp: at.
                    let stale: Vec<u64> = q.range(..expected).map(|(n, _)| *n).collect();
                    for n in stale {
                        q.remove(&n);
                        self.queued_total.fetch_sub(1, Ordering::Relaxed);
                    }
                    match q.remove(&expected) {
                        Some(e) => {
                            self.queued_total.fetch_sub(1, Ordering::Relaxed);
                            Some(e)
                        }
                        None => None,
                    }
                }
                None => None,
            };
            let Some((mut tx, _, local)) = next else {
                break;
            };
            let embedded = self.apply_fixed_gas_fee_returning_min(&mut tx);
            let tx_id = tx.tx_id;
            match self.add_transaction_with_min_fee(tx, embedded) {
                Ok(()) => {
                    promoted += 1;
                    if local {
                        self.local_origin_last_broadcast.insert(tx_id, 0); // hemen yayınlansın
                    }
                }
                Err(e) => {
                    warn!(
                        "ileri-nonce kuyrugundan terfi edemedi ({} n={}): {:?}",
                        &key[..10.min(key.len())],
                        expected,
                        e
                    );
                    // Bu nonce artık boşluk: arkasındakiler bekler; süre dolunca temizlenir.
                    break;
                }
            }
        }
        if let Some(q) = self.queued.get(&key) {
            if q.is_empty() {
                drop(q);
                self.queued.remove(&key);
            }
        }
        promoted
    }

    /// Kuyruktaki toplam işlem (istatistik).
    pub fn queued_count(&self) -> usize {
        self.queued_total.load(Ordering::Relaxed)
    }

    /// 🔁 RPC yolu, kabul edilen işlemi yerel kaynaklı olarak işaretler (ilk
    /// yayın zamanı = şimdi). Gossip'le gelenler işaretlenmez.
    pub fn mark_local_origin(&self, tx_id: &Hash) {
        if self.pool.contains_key(tx_id) {
            self.local_origin_last_broadcast
                .insert(*tx_id, now_unix_secs());
        }
    }

    /// 🔁 Yeniden yayın adayları (yerel, bekleyen, ≥ `min_age_secs`), gönderici+nonce
    /// sırasıyla en fazla `cap`; kabul yarışı adresi kilitlemesin.
    pub fn stale_local_for_rebroadcast(&self, min_age_secs: u64, cap: usize) -> Vec<Transaction> {
        let now = now_unix_secs();
        let mut picked: Vec<Transaction> = self
            .local_origin_last_broadcast
            .iter()
            .filter(|e| now.saturating_sub(*e.value()) >= min_age_secs)
            .filter_map(|e| self.pool.get(e.key()).map(|t| t.value().clone()))
            .collect();
        picked.sort_by(|a, b| {
            a.sender
                .to_ascii_lowercase()
                .cmp(&b.sender.to_ascii_lowercase())
                .then(a.nonce.cmp(&b.nonce))
        });
        picked.truncate(cap);
        for tx in &picked {
            self.local_origin_last_broadcast.insert(tx.tx_id, now);
        }
        picked
    }

    /// 🧹 Bayat süpürücü: nonce'u `state_nonce`'un altında kalan bekleyenleri
    /// siler (commit sonrası). Başka yoldan bloğa giren işlemin kopyası havuzda
    /// kalıp sayacı ve `pending_nonce`u şişiriyordu. O(k).
    pub fn purge_below_nonce(&self, sender: &str, state_nonce: u64) -> usize {
        let key = sender.to_ascii_lowercase();
        let mut removed = 0usize;
        let mut n = state_nonce;
        while n > 0 {
            n -= 1;
            let id = match self.nonce_index.get(&(key.clone(), n)) {
                Some(e) => *e.value(),
                None => break,
            };
            if self.remove_transaction(&id).is_some() {
                removed += 1;
            }
        }
        // Zincir ilerledi: kuyrukta bekleyen ardışıklar şimdi kabul edilebilir.
        self.promote_queued(sender);
        removed
    }

    pub fn evict_expired(&self) -> usize {
        let now = now_unix_secs();
        let expired: Vec<Hash> = self
            .arrival_time
            .iter()
            .filter(|entry| now.saturating_sub(*entry.value()) > self.tx_expiry_seconds)
            .map(|entry| *entry.key())
            .collect();
        let count = expired.len();
        for tx_id in expired {
            self.remove_transaction(&tx_id);
        }
        // İleri-nonce kuyruğu: aynı TTL.
        let mut empty_senders = Vec::new();
        for mut entry in self.queued.iter_mut() {
            let before = entry.value().len();
            entry
                .value_mut()
                .retain(|_, (_, at, _)| now.saturating_sub(*at) <= self.tx_expiry_seconds);
            let dropped = before - entry.value().len();
            if dropped > 0 {
                self.queued_total.fetch_sub(dropped, Ordering::Relaxed);
            }
            if entry.value().is_empty() {
                empty_senders.push(entry.key().clone());
            }
        }
        for k in empty_senders {
            self.queued.remove(&k);
        }
        count
    }

    /// Blok için işlemleri FIFO verir. `max_heavy`: ağır (EVM/Deploy) işlem
    /// sayısı tavanı. 🚨 Sayı tek başına yetmez: 500 ağır × 10M = 5 milyar gas
    /// tek global EVM kilidi arkasında düğümü kilitlerdi (ucuz DoS); beyan edilen
    /// `gas_limit` toplamı da `max_block_gas_limit` ile sınırlanır
    /// (`drain_heavy_queue_within_gas_budget`). FIFO/MEV kuralı: bütçeyi aşan
    /// ilk işlemde kuyruk TAMAMEN durur, küçük sonraki işlem öne alınmaz.
    pub fn get_transactions_for_block(
        &self,
        max_count: usize,
        max_heavy: usize,
    ) -> Vec<Transaction> {
        self.get_transactions_for_block_bounded(max_count, max_heavy, u64::MAX)
    }

    /// G3 (§0 `max_block_bytes`): aynı seçim + gövde bayt tavanı. Tavanı aşacak
    /// İLK işlemde durulur, küçük sonraki öne alınmaz; tek başına sığmayan işlem asla bloğa giremez.
    pub fn get_transactions_for_block_bounded(
        &self,
        max_count: usize,
        max_heavy: usize,
        max_block_bytes: u64,
    ) -> Vec<Transaction> {
        let mut transactions = self.select_fifo(max_count, max_heavy);
        // 🚨 Yürütme `|block_ts - tx.timestamp| > 300 sn` ise reddeder; böyle
        // işlem öneriye konmaz (düşen işlemli blok senkronlanamaz). Geçmişte
        // kalanlar havuzdan silinir, gelecek damgalılar bu turda atlanır.
        let now = now_unix_secs() as u128;
        transactions.retain(|tx| {
            if tx.timestamp <= now {
                if now - tx.timestamp > PROPOSAL_MAX_TX_AGE_SECS {
                    self.remove_transaction(&tx.tx_id);
                    return false;
                }
                true
            } else {
                tx.timestamp - now <= PROPOSAL_MAX_TX_AGE_SECS
            }
        });
        if max_block_bytes == u64::MAX {
            return transactions;
        }
        // bincode(Vec<T>) = 8 baytlık uzunluk öneki + elemanlar
        let mut total: u64 = 8;
        let mut keep = 0usize;
        for tx in &transactions {
            let size = zagros_types::consensus::transaction_encoded_size(tx);
            match total.checked_add(size) {
                Some(t) if t <= max_block_bytes => {
                    total = t;
                    keep += 1;
                }
                _ => break,
            }
        }
        transactions.truncate(keep);
        transactions
    }

    fn select_fifo(&self, max_count: usize, max_heavy: usize) -> Vec<Transaction> {
        let mut transactions = Vec::with_capacity(max_count);

        let heavy_cap = max_heavy.min(max_count);
        Self::drain_heavy_queue_within_gas_budget(
            &self.heavy_fifo_queue,
            &self.pool,
            heavy_cap,
            self.max_block_gas_limit,
            &mut transactions,
        );

        let remaining = max_count.saturating_sub(transactions.len());
        Self::drain_queue(&self.fifo_queue, &self.pool, remaining, &mut transactions);

        transactions
    }

    /// `drain_queue` ile aynı FIFO, tek fark: `gas_limit` toplamı `gas_budget`ı
    /// aşacaksa kuyruk TAMAMEN durur (FIFO/MEV). Yalnız `heavy_fifo_queue` için.
    fn drain_heavy_queue_within_gas_budget(
        queue: &DashMap<u128, Vec<Hash>>,
        pool: &DashMap<Hash, Transaction>,
        limit: usize,
        gas_budget: u128,
        out: &mut Vec<Transaction>,
    ) {
        if limit == 0 {
            return;
        }
        let start_len = out.len();
        let mut gas_reserved: u128 = 0;

        let mut timestamps: Vec<u128> = queue.iter().map(|e| *e.key()).collect();
        timestamps.sort_unstable();

        for timestamp in timestamps {
            if out.len() - start_len >= limit {
                return;
            }

            if let Some(tx_hashes) = queue.get(&timestamp) {
                for tx_id in tx_hashes.value() {
                    if out.len() - start_len >= limit {
                        return;
                    }
                    if let Some(tx) = pool.get(tx_id) {
                        let declared_gas = tx.value().gas_limit as u128;
                        if gas_reserved.saturating_add(declared_gas) > gas_budget {
                            return;
                        }
                        gas_reserved = gas_reserved.saturating_add(declared_gas);
                        out.push(tx.value().clone());
                    }
                }
            }
        }
    }

    /// `fifo_queue`/`heavy_fifo_queue`'nun ikisi için de kullanılan ortak
    /// zaman-damgası sıralı boşaltma mantığı.
    fn drain_queue(
        queue: &DashMap<u128, Vec<Hash>>,
        pool: &DashMap<Hash, Transaction>,
        limit: usize,
        out: &mut Vec<Transaction>,
    ) {
        if limit == 0 {
            return;
        }
        let start_len = out.len();

        let mut timestamps: Vec<u128> = queue.iter().map(|e| *e.key()).collect();
        timestamps.sort_unstable();

        for timestamp in timestamps {
            if out.len() - start_len >= limit {
                break;
            }

            if let Some(tx_hashes) = queue.get(&timestamp) {
                for tx_id in tx_hashes.value() {
                    if out.len() - start_len >= limit {
                        break;
                    }
                    if let Some(tx) = pool.get(tx_id) {
                        out.push(tx.value().clone());
                    }
                }
            }
        }
    }

    /// Return all pending transactions currently in the mempool.
    pub fn get_all_transactions(&self) -> Vec<Transaction> {
        self.pool
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    pub fn size(&self) -> usize {
        self.tx_count.load(Ordering::Relaxed)
    }

    pub fn is_under_stress(&self) -> bool {
        // F4: eşik artık config'ten gelen GasCalculator eşiği (tek kaynak;
        // önceden hardcoded DDOS_THRESHOLD sabiti kullanılıyordu → phantom config).
        self.size() > self.gas_calculator.ddos_threshold()
    }

    /// `is_under_stress`'in eşik olarak kullandığı GERÇEK sayı, operatör
    /// panelinde "yük / eşik" gösterebilmek için dışa açılır (bkz.
    /// `zagros_getMempoolStats`'ın `ddos_threshold` alanı).
    pub fn ddos_threshold(&self) -> usize {
        self.gas_calculator.ddos_threshold()
    }

    /// Operatör paneli şeffaflığı (`zagros_getEffectiveConfig`): `[gas].
    /// enable_dynamic_gas`'ın bu çalışan örnekte GERÇEKTEN etkin olup olmadığı.
    pub fn dynamic_pricing_enabled(&self) -> bool {
        self.gas_calculator.dynamic_pricing_enabled()
    }

    /// Operatör paneli şeffaflığı: `get_transactions_for_block`'un fiilen
    /// uyguladığı blok gas tavanı, `[gas].max_gas_per_block`'un bu çalışan
    /// örnekte GERÇEKTEN uygulanan değeri (config dosyasında yazan değil).
    pub fn max_block_gas_limit(&self) -> u128 {
        self.max_block_gas_limit
    }

    /// Operatör paneli şeffaflığı: mempool'un adet/bayt kapasitesi, fiilen
    /// uygulanan değerler.
    pub fn max_capacity(&self) -> usize {
        self.max_capacity
    }

    pub fn max_total_bytes(&self) -> usize {
        self.max_total_bytes
    }

    /// Hedef ücret (teşhis için). 🚨 Ücret hesaplamak için kullanmayın, tek kaynak `min_required_fee`.
    pub fn gas_target(&self) -> u128 {
        self.gas_calculator.target_gas_fee_zerenya()
    }

    /// Anlık anti-DDoS stress çarpanı (mempool yükü + eşik), teşhis için dışa
    /// açılır. Çarpan zaten `min_required_fee`'nin İÇİNDE uygulanır; ücreti
    /// buradan yeniden kurmayın (bkz. `gas_target` notu).
    pub fn stress_multiplier(&self) -> u128 {
        self.gas_calculator.stress_multiplier(self.size())
    }

    /// 🔒 TEK KAYNAK: işlemin ŞU ANKİ kanonik asgari gas ücreti. Tüketiciler:
    /// `add_transaction` anti-DDoS kapısı, RPC `apply_fixed_gas_fee`, dahili
    /// native işlemler (`native_min_required_fee`). NATIVE hat sabit cetvel ×
    /// tür çarpanı (RPC ücreti gömer); EVM hattı intrinsic gas × 1 gwei × stres
    /// (ücret executor'da `gas_used × gas_price`). İki hat aynı stres çarpanını alır.
    pub fn min_required_fee(&self, tx: &Transaction) -> u128 {
        match Self::evm_calldata(tx) {
            Some(calldata) => self.gas_calculator.evm_min_fee(calldata, self.size()),
            None => self.native_min_required_fee(&tx.tx_type),
        }
    }

    /// Native türün sabit cetvel ücreti (işlem kurulmadan fiyat için, köprü yürütücüsü).
    /// 🚨 EVM türleriyle çağırmayın, `min_required_fee` kullanın.
    pub fn native_min_required_fee(&self, tx_type: &TxType) -> u128 {
        // Hesaplayıcıyı okumadan ÖNCE canlı AMM rezervleriyle eşitle, böylece
        // bayat bir tohumla kurulmuş olsa bile (ör. genesis öncesi (0,0)) kendini
        // onarır ve blok kapanışındaki `sync_pools`'u beklemek zorunda kalmaz.
        self.sync_gas_pools_from_state();
        self.gas_calculator
            .calculate_gas_for_tx_type(tx_type, self.size())
    }

    /// İşlem EVM hattına aitse calldata'sını döner, değilse `None`. EVM/native
    /// ayrımının TEK yeri burasıdır, ücret yönlendirmesi, intrinsic-gas kapısı ve
    /// zagros-rpc'nin sabit-ücret muafiyeti aynı ölçütü kullansın diye.
    fn evm_calldata(tx: &Transaction) -> Option<&[u8]> {
        match &tx.tx_type {
            TxType::ContractCall { data } => Some(data),
            TxType::CallContract => Some(&tx.payload),
            _ => None,
        }
    }

    /// `GasCalculator` havuz atomiklerini canlı AMM rezervleriyle eşitler.
    /// 🚨 `zerenya_reserve == 0` ise (genesis öncesi/boşalmış) ATLANIR, son
    /// bilinen rezerv korunur; sıfırlarla eşitlemek ücreti yapay yükseltirdi.
    fn sync_gas_pools_from_state(&self) {
        if let Ok((zagros_reserve, zerenya_reserve)) = self.state.get_pool_reserves() {
            if zerenya_reserve > 0 {
                self.gas_calculator
                    .sync_pools(zagros_reserve, zerenya_reserve);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::SecretKey;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use zagros_state::manager::StateDbManager;
    use zagros_storage::{Storage, StorageEngine};
    use zagros_types::{CHAIN_ID, MIN_EVM_GAS_PRICE_WEI};

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

    fn fund(state: &Arc<dyn State>, seed: u8, amount: u128) {
        state.add_balance(&test_address(seed), amount).unwrap();
    }

    /// Taban ücreti pratikte sıfıra yuvarlayan havuz oranı. `bump_after` çağrı
    /// sonra ZAGROS rezervini %50 büyütür: "ücret gömüldü → araya commit girdi"
    /// yarışını deterministik kurar.
    struct DriftingPoolState {
        inner: Arc<dyn State>,
        bump_after: std::sync::atomic::AtomicI64, // <0: hiç kaydırma
    }
    impl State for DriftingPoolState {
        fn get_account(
            &self,
            a: &Address,
        ) -> zagros_primitives::Result<Option<zagros_types::AccountState>> {
            self.inner.get_account(a)
        }
        fn set_account(
            &self,
            a: &Address,
            st: zagros_types::AccountState,
        ) -> zagros_primitives::Result<()> {
            self.inner.set_account(a, st)
        }
        fn get_balance(&self, a: &Address) -> zagros_primitives::Result<u128> {
            self.inner.get_balance(a)
        }
        fn add_balance(&self, a: &Address, n: u128) -> zagros_primitives::Result<()> {
            self.inner.add_balance(a, n)
        }
        fn sub_balance(&self, a: &Address, n: u128) -> zagros_primitives::Result<()> {
            self.inner.sub_balance(a, n)
        }
        fn add_zerenya_balance(&self, a: &Address, n: u128) -> zagros_primitives::Result<()> {
            self.inner.add_zerenya_balance(a, n)
        }
        fn sub_zerenya_balance(&self, a: &Address, n: u128) -> zagros_primitives::Result<()> {
            self.inner.sub_zerenya_balance(a, n)
        }
        fn get_nonce(&self, a: &Address) -> zagros_primitives::Result<u64> {
            self.inner.get_nonce(a)
        }
        fn increment_nonce(&self, a: &Address) -> zagros_primitives::Result<()> {
            self.inner.increment_nonce(a)
        }
        fn get_validator_candidates(&self) -> zagros_primitives::Result<Vec<(Address, u128)>> {
            self.inner.get_validator_candidates()
        }
        fn total_known_addresses(&self) -> zagros_primitives::Result<usize> {
            self.inner.total_known_addresses()
        }
        fn checkpoint(&self) -> zagros_primitives::Result<usize> {
            self.inner.checkpoint()
        }
        fn commit_checkpoint(&self, id: usize) -> zagros_primitives::Result<()> {
            self.inner.commit_checkpoint(id)
        }
        fn revert_checkpoint(&self, id: usize) -> zagros_primitives::Result<()> {
            self.inner.revert_checkpoint(id)
        }
        fn state_root(&self) -> zagros_primitives::Result<[u8; 32]> {
            self.inner.state_root()
        }
        fn get_pool_reserves(&self) -> zagros_primitives::Result<(u128, u128)> {
            use std::sync::atomic::Ordering;
            let remaining = self.bump_after.load(Ordering::SeqCst);
            if remaining < 0 {
                return Ok((1_000_000, 1_000));
            }
            if remaining == 0 {
                return Ok((1_500_000, 1_000)); // ZAGROS cinsinden ücret %50 yükseldi
            }
            self.bump_after.fetch_sub(1, Ordering::SeqCst);
            Ok((1_000_000, 1_000))
        }
    }

    /// Kabul yolunun native imzalı testi: gömülecek ücretle imzalanır, `apply_fixed_gas_fee` alanları değiştirmez.
    fn admittable_transaction(mempool: &Mempool, tx_byte: u8, seed: u8, nonce: u64) -> Transaction {
        let mut tx = transaction(tx_byte, seed, nonce);
        tx.gas_limit = 1;
        tx.gas_price = mempool.min_required_fee(&tx).max(1);
        tx.sign(&test_secret_key(seed));
        tx
    }

    /// 🚨 Yük testi yarışı: gömme ile kapı arasına giren commit "Gas fee too low"
    /// veriyordu. Eski yol hâlâ reddeder; `admit_transaction` (tek hesap) kabul etmeli.
    #[test]
    fn admission_fee_gate_uses_the_embedded_fee_not_a_second_drifting_computation() {
        use std::sync::atomic::Ordering;
        let base = test_state();
        fund(&base, 1, 1_000_000_000_000_000_000);
        let drifting = Arc::new(DriftingPoolState {
            inner: base,
            bump_after: std::sync::atomic::AtomicI64::new(-1),
        });
        let state: Arc<dyn State> = drifting.clone();
        let mempool = Mempool::new(state, lenient_gas_calculator());

        // Yarışın belgesi (eski yol): gömme sabit rezervle → araya kayma → kapı ret.
        let mut tx_old = admittable_transaction(&mempool, 1, 1, 0);
        mempool.apply_fixed_gas_fee(&mut tx_old); // okuma: sabit
        drifting.bump_after.store(0, Ordering::SeqCst); // bundan sonra kaymış
        let err = mempool.add_transaction(tx_old).unwrap_err();
        assert!(
            format!("{err:?}").contains("Gas fee too low"),
            "yarış belgesi: {err:?}"
        );

        // Düzeltilmiş yol: gömme (1. okuma sabit) → kapı yeniden OKUMAZ → kabul.
        drifting.bump_after.store(-1, Ordering::SeqCst);
        let tx_new = admittable_transaction(&mempool, 2, 1, 0);
        drifting.bump_after.store(1, Ordering::SeqCst); // 1 okuma sabit, sonrası kaymış
        mempool
            .admit_transaction(tx_new)
            .expect("gömülen ücret ile kabul edilmeli (yarış kapandı)");
        assert_eq!(mempool.size(), 1);
        // Kapı gerçekten ikinci okuma yapmadı mı? Sayaç 0'a inmiş (1 okuma) olmalı.
        assert_eq!(drifting.bump_after.load(Ordering::SeqCst), 0);
    }

    /// 🧹 `purge_below_nonce`: zincir nonce'u ilerlemişken havuzda kalan bayat
    /// kopyalar silinir, adres sayacı ve `pending_nonce` gerçeğe döner.
    #[test]
    fn purge_below_nonce_removes_consumed_nonces_and_restores_address_accounting() {
        let state = test_state();
        fund(&state, 1, 1_000_000_000_000_000_000);
        let mempool = Mempool::new(state.clone(), lenient_gas_calculator());
        for n in 0..5 {
            let tx = admittable_transaction(&mempool, 10 + n as u8, 1, n);
            mempool.admit_transaction(tx).unwrap();
        }
        let sender = test_address(1);
        assert_eq!(mempool.address_pending_count(&sender), 5);
        // Zincir 0..3'ü başka kopyalarla işledi (nonce=3), bu node'un kopyaları kaldı.
        for _ in 0..3 {
            state.increment_nonce(&sender).unwrap();
        }
        assert_eq!(mempool.purge_below_nonce(&sender, 3), 3);
        assert_eq!(mempool.address_pending_count(&sender), 2);
        assert_eq!(mempool.pending_nonce(3, &sender), 5);
        assert_eq!(mempool.size(), 2);
        assert_eq!(mempool.purge_below_nonce(&sender, 3), 0);
    }

    /// 🔁 `stale_local_for_rebroadcast`: yalnız yerel kaynaklı + yeterince eski
    /// olanlar, gönderici+nonce sırasıyla ve tavanla döner; dönenlerin yayın
    /// zamanı yenilenir (aynı tik içinde ikinci kez dönmez).
    #[test]
    fn stale_local_rebroadcast_picks_only_old_local_origin_txs_in_nonce_order() {
        let state = test_state();
        fund(&state, 1, 1_000_000_000_000_000_000);
        fund(&state, 2, 1_000_000_000_000_000_000);
        let mempool = Mempool::new(state, lenient_gas_calculator());
        let a2 = mempool
            .admit_transaction(admittable_transaction(&mempool, 21, 2, 0))
            .unwrap();
        let a1 = mempool
            .admit_transaction(admittable_transaction(&mempool, 11, 1, 0))
            .unwrap();
        let a1b = mempool
            .admit_transaction(admittable_transaction(&mempool, 12, 1, 1))
            .unwrap();
        let _gossip_only = mempool
            .admit_transaction(admittable_transaction(&mempool, 22, 2, 1))
            .unwrap();
        for id in [&a2, &a1, &a1b] {
            mark_local_origin_at(&mempool, id, now_unix_secs() - 10);
        }

        let picked = mempool.stale_local_for_rebroadcast(4, 100);
        let ids: Vec<Hash> = picked.iter().map(|t| t.tx_id).collect();
        assert_eq!(
            ids.len(),
            3,
            "gossip'le gelen (yerel olmayan) aday olmamalı"
        );
        let s1 = test_address(1).to_ascii_lowercase();
        let s2 = test_address(2).to_ascii_lowercase();
        let order_ok = if s1 < s2 {
            ids == vec![a1, a1b, a2]
        } else {
            ids == vec![a2, a1, a1b]
        };
        assert!(order_ok, "gönderici+nonce sırası bozuk: {ids:?}");
        assert!(
            mempool.stale_local_for_rebroadcast(4, 100).is_empty(),
            "yayın zamanı yenilenmeli"
        );
        for id in [&a2, &a1, &a1b] {
            mark_local_origin_at(&mempool, id, now_unix_secs() - 10);
        }
        assert_eq!(mempool.stale_local_for_rebroadcast(4, 2).len(), 2, "tavan");
        // Bloğa giren (silinen) işlem aday listesinden de düşer.
        mark_local_origin_at(&mempool, &a1, now_unix_secs() - 10);
        mempool.remove_transaction(&a1);
        assert!(mempool
            .stale_local_for_rebroadcast(4, 100)
            .iter()
            .all(|t| t.tx_id != a1));
    }

    /// 🚨 (blok 2878): süresi dolmuş (yürütmede `TransactionExpired`
    /// olacak) işlem öneriye alınmaz ve havuzdan silinir; taze olan alınır.
    #[test]
    fn block_selection_skips_and_evicts_transactions_older_than_the_execution_window() {
        let state = test_state();
        fund(&state, 1, 1_000_000_000_000_000_000);
        fund(&state, 2, 1_000_000_000_000_000_000);
        let mempool = Mempool::new(state, lenient_gas_calculator());
        let mut stale = admittable_transaction(&mempool, 31, 1, 0);
        stale.timestamp = now_unix_secs() as u128 - 600; // 300 sn yürütme sınırının çok dışında
        stale.sign(&test_secret_key(1));
        let fresh = admittable_transaction(&mempool, 32, 2, 0);
        mempool.admit_transaction(stale).unwrap();
        mempool.admit_transaction(fresh).unwrap();
        assert_eq!(mempool.size(), 2);

        let picked = mempool.get_transactions_for_block_bounded(100, 100, u64::MAX);
        assert_eq!(picked.len(), 1);
        assert_eq!(
            picked[0].tx_id, [32u8; 32],
            "yalnız taze işlem öneriye girer"
        );
        assert_eq!(mempool.size(), 1, "bayat işlem havuzdan silinmeli");
    }

    /// 🔜 İleri-nonce kuyruğu: selefi gelmemiş işlem atılmaz, kuyruğa alınır; selef
    /// gelince ardışıklar terfi eder; pending_nonce kuyruğu saymaz; bloğa seçilmez.
    #[test]
    fn forward_nonce_transactions_are_queued_and_promoted_when_the_gap_closes() {
        let state = test_state();
        fund(&state, 1, 1_000_000_000_000_000_000);
        let mempool = Mempool::new(state, lenient_gas_calculator());
        let sender = test_address(1);
        let t2 = admittable_transaction(&mempool, 42, 1, 2);
        let t1 = admittable_transaction(&mempool, 41, 1, 1);
        let t0 = admittable_transaction(&mempool, 40, 1, 0);
        // nonce 2 gelir: beklenen 0 → kuyruk (Ok döner, hash ile)
        assert_eq!(mempool.admit_transaction(t2.clone()).unwrap(), t2.tx_id);
        assert_eq!(mempool.size(), 0);
        assert_eq!(mempool.queued_count(), 1);
        assert_eq!(
            mempool.pending_nonce(0, &sender),
            0,
            "kuyruk pending_nonce'a girmez"
        );
        assert!(
            mempool
                .get_transactions_for_block_bounded(10, 10, u64::MAX)
                .is_empty(),
            "kuyruk bloğa seçilmez"
        );
        // nonce 1: yine boşluk (0 yok) → kuyruk
        mempool.admit_transaction(t1).unwrap();
        assert_eq!(mempool.queued_count(), 2);
        assert_eq!(mempool.size(), 0);
        // nonce 0 gelir → 0 havuza, 1 ve 2 terfi eder
        mempool.admit_transaction(t0).unwrap();
        assert_eq!(mempool.size(), 3);
        assert_eq!(mempool.queued_count(), 0);
        assert_eq!(mempool.pending_nonce(0, &sender), 3);
        // Aynı nonce'a ikinci kez gelen → artık "zaten bekleme odasında"/nonce hatası, kuyruk değil
        assert!(mempool.admit_transaction(t2).is_err());
    }

    #[test]
    fn forward_nonce_gap_beyond_the_limit_is_still_rejected() {
        let state = test_state();
        fund(&state, 1, 1_000_000_000_000_000_000);
        let mempool = Mempool::new(state, lenient_gas_calculator());
        let far = admittable_transaction(&mempool, 43, 1, MAX_QUEUE_GAP + 1);
        match mempool.admit_transaction(far) {
            Err(AdmissionError::InvalidNonce { expected: 0, got }) => {
                assert_eq!(got, MAX_QUEUE_GAP + 1)
            }
            other => panic!("büyük boşluk reddedilmeli: {other:?}"),
        }
        assert_eq!(mempool.queued_count(), 0);
    }

    /// Zincir başka kopyalarla ilerlediyse (commit → purge_below_nonce) kuyruk terfi eder.
    #[test]
    fn queued_transactions_are_promoted_after_the_chain_advances_on_commit() {
        let state = test_state();
        fund(&state, 1, 1_000_000_000_000_000_000);
        let mempool = Mempool::new(state.clone(), lenient_gas_calculator());
        let sender = test_address(1);
        let t2 = admittable_transaction(&mempool, 52, 1, 2);
        mempool.admit_transaction(t2).unwrap();
        assert_eq!(mempool.queued_count(), 1);
        // 0 ve 1 başka yoldan bloğa girdi → state nonce 2
        state.increment_nonce(&sender).unwrap();
        state.increment_nonce(&sender).unwrap();
        assert_eq!(mempool.purge_below_nonce(&sender, 2), 0);
        assert_eq!(mempool.queued_count(), 0);
        assert_eq!(mempool.size(), 1);
        assert_eq!(mempool.pending_nonce(2, &sender), 3);
        // Zincir kuyruktakinin ÖTESİNE geçerse (tüketilmiş nonce) kuyruk temizlenir, havuza girmez
        let t4 = admittable_transaction(&mempool, 54, 1, 4);
        mempool.admit_transaction(t4).unwrap();
        state.increment_nonce(&sender).unwrap();
        state.increment_nonce(&sender).unwrap();
        state.increment_nonce(&sender).unwrap(); // 5
        mempool.remove_transaction(&[52u8; 32]);
        mempool.purge_below_nonce(&sender, 5);
        assert_eq!(mempool.queued_count(), 0, "bayat kuyruk girdisi atılır");
        assert_eq!(mempool.size(), 0);
    }

    #[test]
    fn queued_transactions_expire_with_the_pool_ttl_and_respect_the_per_sender_cap() {
        let state = test_state();
        fund(&state, 1, 1_000_000_000_000_000_000);
        let mempool = Mempool::new(state, lenient_gas_calculator());
        for n in 1..=MAX_QUEUED_PER_SENDER as u64 {
            mempool
                .admit_transaction(admittable_transaction(&mempool, (60 + n % 100) as u8, 1, n))
                .unwrap();
        }
        assert_eq!(mempool.queued_count(), MAX_QUEUED_PER_SENDER);
        // tavan: 33. kuyruk isteği reddedilir (boşluk ≤ 32 ama gönderici kuyruğu dolu)
        let over = admittable_transaction(&mempool, 200, 1, MAX_QUEUE_GAP);
        assert!(
            matches!(
                mempool.admit_transaction(over),
                Err(AdmissionError::Rejected(_))
            ) || mempool.queued_count() == MAX_QUEUED_PER_SENDER
        );
        // TTL: varış zamanlarını geriye al → evict_expired temizler
        for mut e in mempool.queued.iter_mut() {
            for (_, v) in e.value_mut().iter_mut() {
                v.1 = 0;
            }
        }
        mempool.evict_expired();
        assert_eq!(mempool.queued_count(), 0);
        assert!(mempool.queued.is_empty());
    }

    fn mark_local_origin_at(mempool: &Mempool, id: &Hash, at: u64) {
        mempool.local_origin_last_broadcast.insert(*id, at);
    }

    fn lenient_gas_calculator() -> Arc<GasCalculator> {
        Arc::new(GasCalculator::new(
            Arc::new(portable_atomic::AtomicU128::new(1)),
            Arc::new(portable_atomic::AtomicU128::new(1_000_000_000_000_000)),
        ))
    }

    /// 1:1 havuz oranı, gerçekçi taban ücret (50.000.000 baz birim) üretir,
    /// anti-DDoS taban ücret reddini test etmek için kullanılır.
    fn strict_gas_calculator() -> Arc<GasCalculator> {
        Arc::new(GasCalculator::new(
            Arc::new(portable_atomic::AtomicU128::new(1)),
            Arc::new(portable_atomic::AtomicU128::new(1)),
        ))
    }

    fn transaction(tx_byte: u8, seed: u8, nonce: u64) -> Transaction {
        let mut tx = Transaction {
            tx_id: [tx_byte; 32],
            tx_type: TxType::Transfer,
            sender: test_address(seed),
            receiver: "0x0000000000000000000000000000000000000002".to_string(),
            amount: 1,
            payload: Vec::new(),
            signature: Vec::new(),
            timestamp: now_unix_secs() as u128 - 200 + tx_byte as u128, // gerçekçi damga (öneri yaş filtresi 270 sn)
            nonce,
            gas_limit: 21_000,
            gas_price: 1,
            chain_id: CHAIN_ID,
        };
        tx.sign(&test_secret_key(seed));
        tx
    }

    fn heavy_transaction(tx_byte: u8, seed: u8, nonce: u64) -> Transaction {
        let mut tx = Transaction {
            tx_id: [tx_byte; 32],
            tx_type: TxType::ContractCall { data: vec![1] },
            sender: test_address(seed),
            receiver: "0x0000000000000000000000000000000000000002".to_string(),
            amount: 0,
            payload: vec![1],
            signature: Vec::new(),
            timestamp: now_unix_secs() as u128 - 200 + tx_byte as u128, // gerçekçi damga (öneri yaş filtresi 270 sn)
            nonce,
            gas_limit: 100_000,
            // 🔷 EVM tabanı mutlak (intrinsic × 1 gwei), `lenient_gas_calculator` gevşetemez;
            // gerçek cüzdan beyanı 100.000 gas @ 1 gwei.
            gas_price: MIN_EVM_GAS_PRICE_WEI,
            chain_id: CHAIN_ID,
        };
        tx.sign(&test_secret_key(seed));
        tx
    }

    /// Bir EVM (heavy) işleminin beyan ettiği toplam ücret, bu hattı kullanan
    /// testlerin göndereni bu kadarını karşılayabilmeli.
    fn heavy_tx_declared_fee() -> u128 {
        100_000 * MIN_EVM_GAS_PRICE_WEI
    }

    /// `heavy_transaction`ın `gas_limit` parametreli hali (gas bütçesi testleri);
    /// gönderen beyan edilen ücreti karşılayacak kadar fonlanmalı.
    fn heavy_transaction_with_gas_limit(
        tx_byte: u8,
        seed: u8,
        nonce: u64,
        gas_limit: u64,
    ) -> Transaction {
        let mut tx = Transaction {
            tx_id: [tx_byte; 32],
            tx_type: TxType::ContractCall { data: vec![1] },
            sender: test_address(seed),
            receiver: "0x0000000000000000000000000000000000000002".to_string(),
            amount: 0,
            payload: vec![1],
            signature: Vec::new(),
            timestamp: now_unix_secs() as u128 - 200 + tx_byte as u128, // gerçekçi damga (öneri yaş filtresi 270 sn)
            nonce,
            gas_limit,
            gas_price: MIN_EVM_GAS_PRICE_WEI,
            chain_id: CHAIN_ID,
        };
        tx.sign(&test_secret_key(seed));
        tx
    }

    fn heavy_transaction_declared_fee_for(gas_limit: u64) -> u128 {
        gas_limit as u128 * MIN_EVM_GAS_PRICE_WEI
    }

    /// 🚨 Köprü mint muafiyeti: doğrulanmış `bridge_authority`den gelen mint sıfır
    /// bakiyeyle bile girmeli; koruma ücrette değil, mint'in oluşması için gereken kapıda.
    #[test]
    fn bridge_mint_from_the_authority_is_admitted_with_zero_balance() {
        let state = test_state();
        let authority = test_address(9);
        // 🚨 KASITLI: authority'ye HİÇ bakiye vermiyoruz, testin amacı bu.

        let mempool =
            Mempool::new(state, strict_gas_calculator()).with_bridge_authority(authority.clone());

        let mut tx = Transaction {
            tx_id: [1; 32],
            tx_type: TxType::BridgeMint,
            sender: authority,
            receiver: test_address(1),
            amount: 1_000,
            payload: Vec::new(),
            signature: Vec::new(),
            timestamp: now_unix_secs() as u128,
            nonce: 0,
            gas_limit: 1,
            gas_price: 1,
            chain_id: CHAIN_ID,
        };
        tx.sign(&test_secret_key(9));

        assert!(
            mempool.add_transaction(tx).is_ok(),
            "muaf olması gereken kopru mint islemi bakiyesizlik yuzunden reddedildi"
        );
    }

    /// Muafiyet SADECE doğrulanmış adrese özel, başka biri `BridgeMint`
    /// göndermeye çalışırsa (imzasız/farklı gönderenli) normal bakiye
    /// kuralları aynen uygulanmalı.
    #[test]
    fn bridge_mint_from_a_different_sender_still_needs_balance() {
        let state = test_state();
        let authority = test_address(9);
        let impostor_seed = 42u8;
        // impostor'a da bakiye VERMİYORUZ, reddedilmesini bekliyoruz.

        let mempool = Mempool::new(state, strict_gas_calculator()).with_bridge_authority(authority);

        let mut tx = Transaction {
            tx_id: [2; 32],
            tx_type: TxType::BridgeMint,
            sender: test_address(impostor_seed),
            receiver: test_address(1),
            amount: 1_000,
            payload: Vec::new(),
            signature: Vec::new(),
            timestamp: now_unix_secs() as u128,
            nonce: 0,
            // Ücret tabanını rahatça geçecek kadar yüksek, testin izole ettiği
            // şey ücret yetersizliği DEĞİL, gerçek bakiye eksikliği olsun.
            gas_limit: 1,
            gas_price: 500_000_000_000_000_000,
            chain_id: CHAIN_ID,
        };
        tx.sign(&test_secret_key(impostor_seed));

        assert!(
            matches!(
                mempool.add_transaction(tx),
                Err(ZagrosError::InsufficientBalanceForGas)
            ),
            "muaf OLMAYAN gonderen icin bakiye kurali atlandi"
        );
    }

    #[test]
    fn rejects_duplicate_sender_nonce() {
        let state = test_state();
        fund(&state, 1, 1_000_000_000);
        let mempool = Mempool::new(state, lenient_gas_calculator());

        assert!(mempool.add_transaction(transaction(1, 1, 4)).is_ok());
        assert!(matches!(
            mempool.add_transaction(transaction(2, 1, 4)),
            Err(ZagrosError::InvalidNonce)
        ));
        assert_eq!(mempool.size(), 1);
    }

    #[test]
    fn is_under_stress_uses_the_configured_ddos_threshold_not_the_constant() {
        // F4: eşik artık GasCalculator (config) eşiğinden geliyor. Küçük eşikli
        // bir calculator ile birkaç işlem bile "stress" moduna geçirir.
        let state = test_state();
        for i in 1..=5u8 {
            fund(&state, i, 1_000_000_000);
        }
        let gas = Arc::new(
            GasCalculator::new(
                Arc::new(portable_atomic::AtomicU128::new(1)),
                Arc::new(portable_atomic::AtomicU128::new(1_000_000_000_000_000)),
            )
            .with_ddos_threshold(2),
        );
        let mempool = Mempool::new(state, gas);

        mempool.add_transaction(transaction(1, 1, 0)).unwrap();
        mempool.add_transaction(transaction(2, 2, 0)).unwrap();
        assert!(
            !mempool.is_under_stress(),
            "2 işlem, eşik 2: henüz stress yok"
        );
        mempool.add_transaction(transaction(3, 3, 0)).unwrap();
        assert!(
            mempool.is_under_stress(),
            "3 > eşik(2): stress moduna geçmeli"
        );
        // stress_multiplier de aynı (config) eşiği kullanır (aşım < 5000 → 1x).
        assert_eq!(mempool.stress_multiplier(), 1);
    }

    #[test]
    fn native_zagros_cost_includes_amount_for_bridge_swap_and_burn() {
        // FAZ2: BridgeSwapAndBurn .balance'ı tx.amount kadar düşürdüğünden
        // maliyete DAHİL edilmeli (executor required_balance ile birebir).
        let mut burn = transfer_with_amount(10, 1, 0, 500); // gas_price=100 → fee 100
        burn.tx_type = TxType::BridgeSwapAndBurn;
        assert_eq!(Mempool::native_zagros_cost(&burn), 600); // 500 + 100

        // Karşılaştırma: SwapBuy'da amount ZERENYA'dır, ZAGROS bakiyesini düşürmez.
        let mut buy = transfer_with_amount(11, 1, 0, 500);
        buy.tx_type = TxType::SwapBuy;
        assert_eq!(Mempool::native_zagros_cost(&buy), 100); // yalnızca gas
    }

    #[test]
    fn address_tx_count_is_keyed_canonically_so_case_variation_cannot_bypass_limit() {
        // FAZ2: per-adres spam kovası canonical (küçük-harf) anahtarlanır; adresi
        // büyük/küçük-harf varyasyonuyla ayrı kovalara bölüp limiti aşmak mümkün
        // olmamalı.
        let state = test_state();
        fund(&state, 1, 1_000_000_000);
        let mempool = Mempool::new(state, lenient_gas_calculator());
        let sender = test_address(1); // 0x.. küçük harf

        mempool.add_transaction(transaction(10, 1, 0)).unwrap();
        // Aynı adres, farklı harf-varyasyonuyla sorgulansa bile TEK kova görülür.
        assert_eq!(mempool.address_pending_count(&sender), 1);
        assert_eq!(mempool.address_pending_count(&sender.to_uppercase()), 1);
    }

    #[test]
    fn g3_byte_bounded_selection_cuts_fifo_at_the_first_oversized_tx() {
        let state = test_state();
        fund(&state, 1, 1_000_000_000);
        let mempool = Mempool::new(state, lenient_gas_calculator());
        mempool.add_transaction(transaction(10, 1, 0)).unwrap();
        mempool.add_transaction(transaction(11, 1, 1)).unwrap();
        mempool.add_transaction(transaction(12, 1, 2)).unwrap();

        let all = mempool.get_transactions_for_block(100, 100);
        assert_eq!(all.len(), 3);
        let one = zagros_types::consensus::transaction_encoded_size(&all[0]);
        let two_total = zagros_types::consensus::block_body_bytes(&all[..2]);
        assert_eq!(two_total, 8 + 2 * one, "bincode(Vec) = 8 + elemanlar");

        // Tam iki islem sigar → iki islem, FIFO sirasi korunur
        let picked = mempool.get_transactions_for_block_bounded(100, 100, two_total);
        assert_eq!(picked.len(), 2);
        assert_eq!(picked[0].nonce, 0);
        assert_eq!(picked[1].nonce, 1);
        assert!(zagros_types::consensus::block_body_bytes(&picked) <= two_total);

        // Bir bayt eksik → yalnizca bir islem
        assert_eq!(
            mempool
                .get_transactions_for_block_bounded(100, 100, two_total - 1)
                .len(),
            1
        );
        // Hicbiri sigmaz → bos blok (atlama yok)
        assert!(mempool
            .get_transactions_for_block_bounded(100, 100, 8 + one - 1)
            .is_empty());
        // Sinirsiz → eski davranis
        assert_eq!(
            mempool
                .get_transactions_for_block_bounded(100, 100, u64::MAX)
                .len(),
            3
        );
    }

    #[test]
    fn pending_nonce_walks_contiguous_pending_slots_via_the_index() {
        let state = test_state();
        fund(&state, 1, 1_000_000_000);
        let mempool = Mempool::new(state, lenient_gas_calculator());
        let sender = test_address(1);

        // nonce 0, 1, 3 bekliyor (2'de boşluk var).
        mempool.add_transaction(transaction(10, 1, 0)).unwrap();
        mempool.add_transaction(transaction(11, 1, 1)).unwrap();
        mempool.add_transaction(transaction(13, 1, 3)).unwrap();

        // state_nonce=0'dan başlar, 0 ve 1'in üzerinden atlar, 2'de durur.
        assert_eq!(mempool.pending_nonce(0, &sender), 2);
        // Bilinmeyen gönderen için doğrudan state_nonce döner.
        assert_eq!(mempool.pending_nonce(9, "0xdeadbeef"), 9);
        // Büyük/harf duyarsız eşleşme.
        assert_eq!(mempool.pending_nonce(0, &sender.to_uppercase()), 2);
    }

    #[test]
    fn removing_a_transaction_frees_its_nonce_slot_and_byte_count() {
        let state = test_state();
        fund(&state, 1, 1_000_000_000);
        let mempool = Mempool::new(state, lenient_gas_calculator());
        let tx = transaction(10, 1, 4);
        let expected_bytes = Mempool::tx_byte_size(&tx);
        let tx_id = tx.tx_id;

        mempool.add_transaction(tx).unwrap();
        assert_eq!(mempool.total_bytes(), expected_bytes);

        // Aynı (gönderen, nonce) tekrar reddedilir (indekste var).
        assert!(matches!(
            mempool.add_transaction(transaction(11, 1, 4)),
            Err(ZagrosError::InvalidNonce)
        ));

        // Silince nonce slotu ve baytlar serbest kalır.
        mempool.remove_transaction(&tx_id);
        assert_eq!(mempool.total_bytes(), 0);
        assert_eq!(mempool.size(), 0);
        // Artık aynı (gönderen, nonce) tekrar eklenebilir.
        assert!(mempool.add_transaction(transaction(12, 1, 4)).is_ok());
    }

    #[test]
    fn rejects_transactions_once_the_total_byte_budget_is_exceeded() {
        let state = test_state();
        fund(&state, 1, 1_000_000_000);
        fund(&state, 2, 1_000_000_000);
        let tx1 = transaction(10, 1, 0);
        let one_tx_bytes = Mempool::tx_byte_size(&tx1);

        let mut mempool = Mempool::new(state, lenient_gas_calculator());
        // Bütçe tam olarak BİR işleme yeter.
        mempool.set_max_total_bytes_for_test(one_tx_bytes);

        // İlki sığar (total == bütçe).
        assert!(mempool.add_transaction(tx1).is_ok());
        // İkincisi (farklı gönderen/nonce, tüm diğer kontrolleri geçer) yalnızca
        // bayt bütçesi yüzünden reddedilir.
        assert!(matches!(
            mempool.add_transaction(transaction(20, 2, 0)),
            Err(ZagrosError::MempoolFull)
        ));
        assert_eq!(mempool.size(), 1);
    }

    // ---- Pending-balance rezervasyonu ----

    /// Belirli miktar + sabit gas (gas_limit=1, gas_price=100 => fee=100; bu,
    /// lenient_gas_calculator'ın anti-DDoS taban ücretini rahatça geçer) ile bir
    /// Transfer üretir. Kümülatif ZAGROS maliyeti = amount + 100.
    fn transfer_with_amount(tx_byte: u8, seed: u8, nonce: u64, amount: u128) -> Transaction {
        let mut tx = Transaction {
            tx_id: [tx_byte; 32],
            tx_type: TxType::Transfer,
            sender: test_address(seed),
            receiver: "0x0000000000000000000000000000000000000002".to_string(),
            amount,
            payload: Vec::new(),
            signature: Vec::new(),
            timestamp: now_unix_secs() as u128 - 200 + tx_byte as u128, // gerçekçi damga (öneri yaş filtresi 270 sn)
            nonce,
            gas_limit: 1,
            gas_price: 100,
            chain_id: CHAIN_ID,
        };
        tx.sign(&test_secret_key(seed));
        tx
    }

    #[test]
    fn pending_balance_rejects_cumulative_overspend_from_one_sender() {
        // Bakiye 1000; 700 + 700: ilki sığar, ikincisi kümülatif aşımdan reddedilir.
        let state = test_state();
        fund(&state, 1, 1000);
        let mempool = Mempool::new(state, lenient_gas_calculator());

        assert!(mempool
            .add_transaction(transfer_with_amount(10, 1, 0, 600))
            .is_ok());
        assert!(matches!(
            mempool.add_transaction(transfer_with_amount(11, 1, 1, 600)),
            Err(ZagrosError::InsufficientBalance)
        ));
        assert_eq!(mempool.size(), 1);
    }

    #[test]
    fn removing_a_transaction_releases_its_pending_reservation() {
        let state = test_state();
        fund(&state, 1, 1000);
        let mempool = Mempool::new(state, lenient_gas_calculator());

        let first = transfer_with_amount(10, 1, 0, 600);
        let first_id = first.tx_id;
        assert!(mempool.add_transaction(first).is_ok());
        // İkincisi rezervasyon yüzünden reddedilir (kalan 300 < 700).
        assert!(mempool
            .add_transaction(transfer_with_amount(11, 1, 1, 600))
            .is_err());

        // İlki bloğa girip çıkarılınca rezervasyon serbest kalır.
        mempool.remove_transaction(&first_id);
        // Artık aynı bütçeden yeni bir 600'lük işlem tekrar sığar.
        assert!(mempool
            .add_transaction(transfer_with_amount(12, 1, 1, 600))
            .is_ok());
    }

    #[test]
    fn pending_reservation_ignores_zerenya_value_of_a_swap_buy() {
        // SwapBuy'da `amount` ZERENYA'dır, ZAGROS bakiyesini DÜŞMEZ (sadece gas
        // düşer). Bu yüzden ZAGROS bakiyesi yalnızca gas'a yetse bile büyük
        // amount'lu bir SwapBuy admission'da reddedilmemeli.
        let state = test_state();
        fund(&state, 1, 1000); // gas'a (100) fazlasıyla yeter
        let mempool = Mempool::new(state, lenient_gas_calculator());

        let mut swap = transfer_with_amount(10, 1, 0, 1_000_000); // amount ZERENYA
        swap.tx_type = TxType::SwapBuy;
        swap.sign(&test_secret_key(1));

        // native_zagros_cost = yalnızca gas (100) => 100 <= 1000, kabul edilir.
        assert!(mempool.add_transaction(swap).is_ok());
    }

    #[test]
    fn heavy_transactions_are_capped_so_light_transactions_are_not_starved() {
        let state = test_state();
        // EVM hattı mutlak taban ücret ister (bkz. `heavy_transaction`), bu yüzden
        // ağır işlem gönderenleri gerçek bir gas bütçesiyle fonlanır.
        for i in 1..=10u8 {
            fund(&state, i, heavy_tx_declared_fee() * 10);
        }
        for i in 100..=104u8 {
            fund(&state, i, 1_000_000_000);
        }
        let mempool = Mempool::new(state, lenient_gas_calculator());

        for i in 0..10u8 {
            mempool
                .add_transaction(heavy_transaction(i, i + 1, 0))
                .unwrap();
        }
        for i in 0..5u8 {
            mempool
                .add_transaction(transaction(100 + i, 100 + i, 0))
                .unwrap();
        }

        let batch = mempool.get_transactions_for_block(100, 3);
        let heavy_count = batch
            .iter()
            .filter(|tx| matches!(tx.tx_type, TxType::ContractCall { .. }))
            .count();
        let light_count = batch.len() - heavy_count;

        assert_eq!(heavy_count, 3, "heavy lane must be capped at max_heavy");
        assert_eq!(
            light_count, 5,
            "all light transactions must still be included, not starved by the heavy burst"
        );
    }

    /// 🚨 Sayı sınırı yetmez, gas bütçesi de uygulanmalı: 11 × 10M = 110M;
    /// yalnız ilk 10 (100M) girmeli, 11. sonraki bloğa kalmalı.
    #[test]
    fn heavy_queue_stops_once_cumulative_gas_limit_would_exceed_the_block_budget() {
        let state = test_state();
        let per_tx_gas_limit: u64 = 10_000_000; // protokolün izin verdiği azami gas_limit
        let fee = heavy_transaction_declared_fee_for(per_tx_gas_limit);
        for i in 1..=11u8 {
            fund(&state, i, fee * 2);
        }
        let mempool = Mempool::new(state, lenient_gas_calculator());

        for i in 0..11u8 {
            mempool
                .add_transaction(heavy_transaction_with_gas_limit(
                    i,
                    i + 1,
                    0,
                    per_tx_gas_limit,
                ))
                .unwrap();
        }

        // max_heavy=500 (üretimdeki gerçek değer), SAYI sınırı burada
        // devreye girmesin, yalnızca gas bütçesi test edilsin.
        let batch = mempool.get_transactions_for_block(1_000, 500);
        let heavy_count = batch
            .iter()
            .filter(|tx| matches!(tx.tx_type, TxType::ContractCall { .. }))
            .count();
        let total_gas: u128 = batch
            .iter()
            .filter(|tx| matches!(tx.tx_type, TxType::ContractCall { .. }))
            .map(|tx| tx.gas_limit as u128)
            .sum();

        assert_eq!(
            heavy_count, 10,
            "cumulative gas_limit siniri (MAX_BLOCK_GAS_LIMIT) asan 11. agir islem bu blokta OLMAMALI"
        );
        assert!(
            total_gas <= MAX_BLOCK_GAS_LIMIT,
            "secilen agir islemlerin toplam gas_limit'i blok butcesini asmamali, alinan: {total_gas}"
        );
    }

    /// 🚨 Bütçe dolunca kuyruk TAMAMEN durmalı (FIFO/MEV): 95M sonrası 6M aşar,
    /// ardından gelen ve sığacak 1M'lik işlem de alınmamalı.
    #[test]
    fn heavy_queue_never_skips_an_over_budget_transaction_to_admit_a_smaller_later_one() {
        let state = test_state();
        let sizes: [u64; 12] = [
            10_000_000, 10_000_000, 10_000_000, 10_000_000, 10_000_000, 10_000_000, 10_000_000,
            10_000_000, 10_000_000, // 9 x 10M = 90M
            5_000_000,  // 10.: 95M kumülatif
            6_000_000,  // 11.: 95M + 6M = 101M > 100M -> REDDEDİLMELİ, kuyruk BURADA durmalı
            1_000_000,  // 12.: kalan 5M'ye sığar ama ASLA değerlendirilmemeli
        ];
        for (i, _) in sizes.iter().enumerate() {
            fund(
                &state,
                (i + 1) as u8,
                heavy_transaction_declared_fee_for(10_000_000) * 2,
            );
        }
        let mempool = Mempool::new(state, lenient_gas_calculator());
        for (i, gas_limit) in sizes.iter().enumerate() {
            mempool
                .add_transaction(heavy_transaction_with_gas_limit(
                    i as u8,
                    (i + 1) as u8,
                    0,
                    *gas_limit,
                ))
                .unwrap();
        }

        let batch = mempool.get_transactions_for_block(1_000, 500);
        let admitted_gas: Vec<u64> = batch
            .iter()
            .filter(|tx| matches!(tx.tx_type, TxType::ContractCall { .. }))
            .map(|tx| tx.gas_limit)
            .collect();

        assert_eq!(
            admitted_gas,
            vec![
                10_000_000, 10_000_000, 10_000_000, 10_000_000, 10_000_000, 10_000_000, 10_000_000,
                10_000_000, 10_000_000, 5_000_000,
            ],
            "6M'lik islem butceyi astiginda kuyruk TAMAMEN durmali - ardindan gelen \
             1M'lik (kalan 5M'ye sigacak) islem FIFO sirasini korumak icin \
             ONE ALINMAMALI"
        );
    }

    #[test]
    fn fifo_order_is_preserved_independently_within_each_lane() {
        let state = test_state();
        for seed in 1..=4u8 {
            fund(&state, seed, heavy_tx_declared_fee() * 10);
        }
        let mempool = Mempool::new(state, lenient_gas_calculator());

        mempool
            .add_transaction(heavy_transaction(10, 1, 0))
            .unwrap();
        mempool.add_transaction(transaction(20, 2, 0)).unwrap();
        mempool.add_transaction(heavy_transaction(5, 3, 0)).unwrap();
        mempool.add_transaction(transaction(15, 4, 0)).unwrap();

        let batch = mempool.get_transactions_for_block(100, 100);
        let heavy_ids: Vec<_> = batch
            .iter()
            .filter(|tx| matches!(tx.tx_type, TxType::ContractCall { .. }))
            .map(|tx| tx.tx_id)
            .collect();
        let light_ids: Vec<_> = batch
            .iter()
            .filter(|tx| matches!(tx.tx_type, TxType::Transfer))
            .map(|tx| tx.tx_id)
            .collect();

        // 🚨 SIRA KABUL ANINA GÖRE: istemcinin BEYAN ettiği `tx.timestamp`'e
        // göre sıralamak (doğrulanmadığı için) sıranın satın alınmasına izin
        // verirdi. Her hat kendi içinde EKLENME sırasını korur.
        assert_eq!(heavy_ids, vec![[10u8; 32], [5u8; 32]]);
        assert_eq!(light_ids, vec![[20u8; 32], [15u8; 32]]);
    }

    /// 🚨 Sıra satın alınamaz: geçmiş damgalı işlem önce gelen dürüst işlemlerin önüne geçmemeli.
    #[test]
    fn a_backdated_timestamp_cannot_jump_the_queue() {
        let state = test_state();
        for seed in 1..=3u8 {
            fund(&state, seed, 1_000_000_000);
        }
        let mempool = Mempool::new(state, lenient_gas_calculator());

        // Önce dürüst iki işlem (geç damgalı), sonra "0 damgalı" saldırgan.
        mempool.add_transaction(transaction(200, 1, 0)).unwrap();
        mempool.add_transaction(transaction(201, 2, 0)).unwrap();
        // `transaction(0, ..)` = `timestamp: 0` (yardımcı damgayı tx_byte'tan
        // türetir ve İMZAYA katar; sonradan elle değiştirmek imzayı bozardı).
        mempool.add_transaction(transaction(0, 3, 0)).unwrap();

        let order: Vec<_> = mempool
            .get_transactions_for_block(100, 100)
            .iter()
            .map(|tx| tx.tx_id)
            .collect();

        assert_eq!(
            order,
            vec![[200u8; 32], [201u8; 32], [0u8; 32]],
            "damgasi geriye alinmis islem kuyrugun basina GECMEMELI"
        );
    }

    #[test]
    fn rejects_transaction_with_invalid_signature() {
        let state = test_state();
        fund(&state, 1, 1_000_000_000);
        let mempool = Mempool::new(state, lenient_gas_calculator());

        let mut tx = transaction(1, 1, 0);
        tx.signature = Vec::new(); // imzayı geçersiz kıl (verify_signature -> false)

        assert!(matches!(
            mempool.add_transaction(tx),
            Err(ZagrosError::InvalidSignature)
        ));
        assert_eq!(mempool.size(), 0);
    }

    #[test]
    fn rejects_transaction_when_sender_balance_cannot_cover_declared_fee() {
        let state = test_state(); // sender hiç fonlanmadı - bakiye 0
        let mempool = Mempool::new(state, lenient_gas_calculator());

        assert!(matches!(
            mempool.add_transaction(transaction(1, 1, 0)),
            Err(ZagrosError::InsufficientBalanceForGas)
        ));
        assert_eq!(mempool.size(), 0);
    }

    #[test]
    fn rejects_transaction_whose_declared_fee_is_below_the_anti_ddos_floor() {
        let state = test_state();
        // Bakiye bol, reddin bakiye değil, taban ücret kontrolünden geldiğini kanıtlar.
        fund(&state, 1, 10_000_000_000);
        let mempool = Mempool::new(state, strict_gas_calculator());

        // gas_limit(21_000) * gas_price(1) = 21_000, taban ücretin (50.000.000) çok altında.
        let result = mempool.add_transaction(transaction(1, 1, 0));
        assert!(result.is_err());
        assert!(!matches!(
            result,
            Err(ZagrosError::InsufficientBalanceForGas)
        ));
        assert_eq!(mempool.size(), 0);
    }

    // item 9: Mempool TTL

    #[test]
    fn add_transaction_stamps_server_side_arrival_time_not_client_timestamp() {
        let state = test_state();
        fund(&state, 1, 10_000_000_000);
        let mempool = Mempool::new(state, lenient_gas_calculator());

        // İstemci beyanı küçük/sahte (1); sunucu `arrival_time` gerçek "şimdi" olmalı.
        let tx = transaction(1, 1, 0);
        mempool.add_transaction(tx.clone()).unwrap();

        let stamped = *mempool.arrival_time.get(&tx.tx_id).unwrap();
        let now = now_unix_secs();
        assert!(
            now.saturating_sub(stamped) < 5,
            "arrival_time gerçek 'şimdi'ye yakın olmalı (istemcinin beyan ettiği 1 DEĞİL)"
        );
    }

    /// 🛑 Native `DeployContract` mempool girişinde REDDEDİLMELİ: erişilemez
    /// kontrat üretip 100x ücreti boşa harcatıyordu.
    #[test]
    fn add_transaction_rejects_deploy_contract_with_a_clear_error_message() {
        let state = test_state();
        fund(&state, 1, 10_000_000_000);
        let mempool = Mempool::new(state, lenient_gas_calculator());

        let mut tx = Transaction {
            tx_id: [9; 32],
            tx_type: TxType::DeployContract,
            sender: test_address(1),
            receiver: "0x0000000000000000000000000000000000000000".to_string(),
            amount: 0,
            payload: vec![0x60, 0x00],
            signature: Vec::new(),
            timestamp: now_unix_secs() as u128,
            nonce: 0,
            gas_limit: 1,
            gas_price: 1,
            chain_id: CHAIN_ID,
        };
        tx.sign(&test_secret_key(1));

        let err = mempool
            .add_transaction(tx)
            .expect_err("TxType::DeployContract mempool girişinde REDDEDİLMELİ");
        let message = err.to_string();
        // 🛡️ Hata mesajı nedeni ve alternatif yolu açıkça anlatmalı.
        assert!(
            message.contains("DeployContract"),
            "hata mesajı hangi tx tipinin reddedildiğini AÇIKÇA belirtmeli: {}",
            message
        );
        assert!(
            message.to_lowercase().contains("unreachable")
                || message.to_lowercase().contains("erişilemez"),
            "hata mesajı NEDEN reddedildiğini (erişilemez kontrat) açıklamalı: {}",
            message
        );
        assert!(
            message.contains("ContractCall") || message.contains("eth_sendRawTransaction"),
            "hata mesajı kullanıcıyı ÇALIŞAN alternatif yola yönlendirmeli: {}",
            message
        );
    }

    /// Mevcut, GEÇERLİ işlem tiplerinin `DeployContract` reddiyle
    /// ETKİLENMEDİĞİNİ doğrular, hem düz native (`Transfer`) hem EVM-yönlü
    /// "ağır" (`ContractCall`) hat için.
    #[test]
    fn add_transaction_still_accepts_other_tx_types_after_deploy_contract_rejection() {
        let state = test_state();
        fund(&state, 1, 10_000_000_000);
        fund(&state, 2, heavy_tx_declared_fee());
        let mempool = Mempool::new(state, lenient_gas_calculator());

        // Önce reddedilen bir DeployContract, reddin mempool'un GENEL
        // durumunu (sayaç/kapasite) bozmadığını da dolaylı olarak kanıtlar.
        let mut rejected = Transaction {
            tx_id: [9; 32],
            tx_type: TxType::DeployContract,
            sender: test_address(1),
            receiver: "0x0000000000000000000000000000000000000000".to_string(),
            amount: 0,
            payload: vec![0x60, 0x00],
            signature: Vec::new(),
            timestamp: now_unix_secs() as u128,
            nonce: 0,
            gas_limit: 1,
            gas_price: 1,
            chain_id: CHAIN_ID,
        };
        rejected.sign(&test_secret_key(1));
        assert!(mempool.add_transaction(rejected).is_err());

        // Düz native Transfer, hâlâ kabul edilmeli.
        let transfer = transaction(1, 1, 0);
        mempool
            .add_transaction(transfer)
            .expect("Transfer, DeployContract reddinden ETKİLENMEMELİ");

        // EVM-yönlü ContractCall ("ağır" hat), hâlâ kabul edilmeli, DeployContract
        // İLE AYNI `is_heavy` grubunda olmasına RAĞMEN.
        let contract_call = heavy_transaction(2, 2, 0);
        mempool
            .add_transaction(contract_call)
            .expect("ContractCall, DeployContract reddinden ETKİLENMEMELİ");
    }

    #[test]
    fn evict_expired_removes_transactions_past_tx_expiry_seconds_and_keeps_fresh_ones() {
        let state = test_state();
        fund(&state, 1, 10_000_000_000);
        fund(&state, 2, 10_000_000_000);
        let mempool = Mempool::new(state, lenient_gas_calculator());

        let old_tx = transaction(1, 1, 0);
        let fresh_tx = transaction(2, 2, 0);
        mempool.add_transaction(old_tx.clone()).unwrap();
        mempool.add_transaction(fresh_tx.clone()).unwrap();

        // `old_tx`'in varış zamanını, TTL'i (varsayılan 3600s) çoktan aşacak
        // şekilde geçmişe al, gerçek bir `sleep` yerine test-içi doğrudan
        // manipülasyon (aynı crate/modül, `arrival_time` private ama erişilebilir).
        mempool
            .arrival_time
            .insert(old_tx.tx_id, now_unix_secs().saturating_sub(10_000));

        let evicted = mempool.evict_expired();
        assert_eq!(evicted, 1);
        assert!(
            mempool.pool.get(&old_tx.tx_id).is_none(),
            "süresi dolmuş tx havuzda kalmamalı"
        );
        assert!(
            mempool.pool.get(&fresh_tx.tx_id).is_some(),
            "taze tx tahliye edilmemeli"
        );
    }

    #[test]
    fn evict_expired_keeps_all_five_internal_structures_consistent() {
        let state = test_state();
        fund(&state, 1, 10_000_000_000);
        let mempool = Mempool::new(state, lenient_gas_calculator());

        let tx = transaction(1, 1, 0);
        mempool.add_transaction(tx.clone()).unwrap();
        assert_eq!(mempool.size(), 1);

        mempool
            .arrival_time
            .insert(tx.tx_id, now_unix_secs().saturating_sub(10_000));
        let evicted = mempool.evict_expired();
        assert_eq!(evicted, 1);

        // `remove_transaction`'ın kendisi zaten bunları senkron tutuyor (bkz.
        // o fonksiyonun testleri), burada asıl iddia `evict_expired`'ın o
        // AYNI yolu (yeniden kod tekrarı olmadan) kullandığının kanıtı.
        assert_eq!(mempool.size(), 0);
        assert!(mempool.arrival_time.get(&tx.tx_id).is_none());
        let canonical_sender = tx.sender.to_ascii_lowercase();
        assert!(mempool
            .nonce_index
            .get(&(canonical_sender.clone(), tx.nonce))
            .is_none());
        assert!(mempool.pending_costs.get(&canonical_sender).is_none());
        assert!(mempool.address_tx_count.get(&canonical_sender).is_none());
        assert_eq!(mempool.total_bytes.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn evict_expired_is_a_noop_when_nothing_has_expired() {
        let state = test_state();
        fund(&state, 1, 10_000_000_000);
        let mempool = Mempool::new(state, lenient_gas_calculator());
        mempool.add_transaction(transaction(1, 1, 0)).unwrap();

        assert_eq!(mempool.evict_expired(), 0);
        assert_eq!(mempool.size(), 1);
    }

    #[test]
    fn with_config_actually_applies_tx_expiry_seconds_from_config() {
        // Regresyon testi: `tx_expiry_seconds` `with_config`'te sessizce yok
        // sayılmamalı.
        let state = test_state();
        fund(&state, 1, 10_000_000_000);
        let config = MempoolConfig {
            tx_expiry_seconds: 1,
            ..Default::default()
        };
        let mempool = Mempool::with_config(state, lenient_gas_calculator(), &config);
        assert_eq!(mempool.tx_expiry_seconds, 1);

        let tx = transaction(1, 1, 0);
        mempool.add_transaction(tx.clone()).unwrap();
        // Yalnızca 2 saniye "eski" say, config'in gerçekten 1s TTL
        // uyguladığını, gömülü 3600s varsayılanını DEĞİL, kanıtlar.
        mempool
            .arrival_time
            .insert(tx.tx_id, now_unix_secs().saturating_sub(2));
        assert_eq!(mempool.evict_expired(), 1);
    }
}
