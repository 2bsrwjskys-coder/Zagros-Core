use zagros_primitives::{Address, Hash, Result};
use zagros_types::AccountState;
pub mod manager;
pub mod overlay;
pub mod trie;

pub use overlay::SimulationOverlay;

// Historical Chain Storage anahtar biçimleri: yazan ve okuyan/budayan taraflar
// yalnız bu fonksiyonlardan üretir (drift imkânsız). `0x` önekli değil, state_root'a girmez.
pub fn receipt_key(tx_id: &Hash) -> Address {
    format!("Receipt_{}", hex::encode(tx_id))
}

pub fn tx_body_key(tx_id: &Hash) -> Address {
    format!("tx_body_{}", hex::encode(tx_id))
}

/// `ArchivedBlockHeader`'ın anahtarı (N≥1). Genesis'in `block_0`'ı bu deseni
/// KULLANMAZ (bkz. `State::get_genesis_block_0_bytes`).
pub fn block_key(number: u64) -> Address {
    format!("block_{}", number)
}

/// G6: yükseklik N'in konsensüs kaydı `bincode((BlockHeaderV2, QuorumCertificate))`
/// — `/zagros/sync/2` catch-up sunucusu buradan okur; `block_<N>` ile birlikte
/// budanır. `0x` öneksiz: state_root'a girmez.
pub fn consensus_block_key(number: u64) -> Address {
    format!("consensus_block_{}", number)
}

/// Hash→numara ters indeksi.
pub fn block_hash_key(hash: &Hash) -> Address {
    format!("block_hash_{}", hex::encode(hash))
}

// STATE API (AKILLI MUHASEBECİ ARAYÜZÜ)
pub trait State: Send + Sync {
    fn get_account(&self, address: &Address) -> Result<Option<AccountState>>;
    fn set_account(&self, address: &Address, state: AccountState) -> Result<()>;

    fn get_balance(&self, address: &Address) -> Result<u128>;
    fn add_balance(&self, address: &Address, amount: u128) -> Result<()>;
    fn sub_balance(&self, address: &Address, amount: u128) -> Result<()>;
    fn add_zerenya_balance(&self, address: &Address, amount: u128) -> Result<()>;
    fn sub_zerenya_balance(&self, address: &Address, amount: u128) -> Result<()>;

    fn get_zerenya_balance(&self, address: &Address) -> Result<u128> {
        Ok(self
            .get_account(address)?
            .map(|a| a.zerenya_balance)
            .unwrap_or(0))
    }

    fn get_nonce(&self, address: &Address) -> Result<u64>;
    fn increment_nonce(&self, address: &Address) -> Result<()>;

    fn get_validator_candidates(&self) -> Result<Vec<(Address, u128)>>;

    /// 🛡️ Dashboard/gözlemlenebilirlik amaçlı: şu ana kadar görülmüş TÜM
    /// `0x` adreslerinin sayısı. YENİ bir sayaç DEĞİL, zaten Merkle
    /// `state_root` için tutulan `address_index`'in (bkz. `StateDbManager`)
    /// boyutunu döner; `zagros_getNetworkPulse` bunu kullanır.
    fn total_known_addresses(&self) -> Result<usize>;

    /// 🚨 Tek seferlik onarım: `commit()` eski hatası normal cüzdanları
    /// `is_contract=true` + `contract_code=[0x00]` ile damgalamıştı; tam bu imzayı
    /// taşıyan hesaplar EOA'ya çevrilir. Varsayılan no-op (overlay'in kalıcı durumu yok).
    fn repair_stale_evm_default_bytecode_corruption(&self) -> Result<usize> {
        Ok(0)
    }

    // 🏛️ Reward akümülatörü LIQUIDITY_POOL_ADDRESS depolama slot'unda (state_root'ta);
    // varsayılan metotlar get/set_account üzerinden, override gerekmez.
    fn get_accumulated_reward_per_share(&self) -> Result<u128> {
        Ok(self
            .get_account(&zagros_types::LIQUIDITY_POOL_ADDRESS.to_string())?
            .unwrap_or_default()
            .get_reward_per_share())
    }

    fn set_accumulated_reward_per_share(&self, amount: u128) -> Result<()> {
        let mut pool = self
            .get_account(&zagros_types::LIQUIDITY_POOL_ADDRESS.to_string())?
            .unwrap_or_default();
        pool.set_reward_per_share(amount);
        self.set_account(&zagros_types::LIQUIDITY_POOL_ADDRESS.to_string(), pool)
    }

    // 🚀 Native AMM rezervleri ayrı ham anahtarda değil, `LIQUIDITY_POOL_ADDRESS`
    // hesabının .balance/.zerenya_balance alanlarında: doğal olarak state_root'a
    // girer, çift yazma ve "senkronu unutma" sınıfı kalkar. Varsayılan metotlar
    // get/set_account üzerinden, StateDbManager ve SimulationOverlay otomatik miras alır.
    fn get_pool_reserves(&self) -> Result<(u128, u128)> {
        let pool = self
            .get_account(&zagros_types::LIQUIDITY_POOL_ADDRESS.to_string())?
            .unwrap_or_default();
        Ok((pool.balance, pool.zerenya_balance))
    }

    fn set_pool_reserves(&self, zagros_reserve: u128, zerenya_reserve: u128) -> Result<()> {
        // Diğer hesap alanlarını koru: get → yalnızca rezerv alanlarını değiştir → set.
        let mut pool = self
            .get_account(&zagros_types::LIQUIDITY_POOL_ADDRESS.to_string())?
            .unwrap_or_default();
        pool.balance = zagros_reserve;
        pool.zerenya_balance = zerenya_reserve;
        self.set_account(&zagros_types::LIQUIDITY_POOL_ADDRESS.to_string(), pool)
    }

    /// ⏱️ ZAMAN MAKİNESİ (SNAPSHOT & ROLLBACK)
    fn checkpoint(&self) -> Result<usize>;

    /// İşlem başarılı olursa, geri dönüş noktasını siler.
    fn commit_checkpoint(&self, checkpoint_id: usize) -> Result<()>;

    /// İşlem başarısız olursa, her şeyi o anlık görüntüye geri sarar! (Sızıntı Kalkanı)
    fn revert_checkpoint(&self, checkpoint_id: usize) -> Result<()>;

    /// Ağın anlık matematiksel mührünü (State Root) hesaplar.
    fn state_root(&self) -> Result<[u8; 32]>;

    /// G3 (§7, INV-P2): state + override'lar için kökü gerçek state'e dokunmadan
    /// hesaplar (`SimulationOverlay::state_root`). Varsayılan FAIL-CLOSED `Err`.
    fn state_root_with_overrides(
        &self,
        _overrides: &[(Address, Option<AccountState>)],
    ) -> Result<[u8; 32]> {
        Err(zagros_primitives::ZagrosError::Other(
            "state_root_with_overrides bu State tarafından desteklenmiyor".into(),
        ))
    }

    /// Bekleyen (henüz diske yazılmamış) değişiklikleri kalıcı depoya yazar.
    /// Varsayılan davranış no-op'tur; sadece toplu/gecikmeli yazma yapan
    /// implementasyonların (örn. StateDbManager) bunu geçersiz kılması gerekir.
    fn flush(&self) -> Result<()> {
        Ok(())
    }

    /// Bloğun tx_id'lerini blok numarasına göre manifest olarak kaydeder (budama
    /// için). Varsayılan no-op; yalnız budama açıkken çağrılır.
    fn record_block_receipts(&self, _block_number: u64, _tx_ids: &[Hash]) -> Result<()> {
        Ok(())
    }

    /// `prune_before_block`tan eski dekont ve manifestleri siler, çağrı başına en
    /// fazla `batch_limit`. Chain state'i ASLA etkilemez. Varsayılan no-op (0).
    fn prune_historical_data(
        &self,
        _prune_before_block: u64,
        _batch_limit: usize,
    ) -> Result<usize> {
        Ok(0)
    }

    /// Bloğun arşiv anahtarlarını flush sonrası yalnız bellek cache'inden çıkarır
    /// (storage'a dokunmaz); soğuk veri sıcak `0x` cache'ini şişirmesin. Varsayılan no-op.
    fn evict_from_cache(&self, _keys: &[Address]) {}

    /// Genesis `block_0`ının ham baytları (`set_account` dışında yazıldığından
    /// `get_account` çözemez); blok 1 `parent_hash`i için. Varsayılan `None`.
    fn get_genesis_block_0_bytes(&self) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }
}
