//! 🛠️ KÖPRÜ KURTARMA ARACI: bir harici kaynak işlemini "zaten işlendi" olarak
//! kalıcı işaretler; düğüm o kaynak için ne öneri oluşturur ne yürütür. Mükerrer
//! koruma öncesi oluşmuş, hâlâ bekleyen mükerrer öneriler için.
//! Kullanım (ÖNCE düğümü durdurun, RocksDB tek yazara izin verir):
//! ```bash
//! cargo run --release -p zagros-cli --bin bridge_recover -- \
//!     config.toml Ethereum 0xb17479a1... 0x62ca9c57...
//! ```
//! 🚨 Yanlış işaretleme meşru yatırmayı sonsuza dek kredilendirilemez kılar ve
//! GERİ ALINAMAZ; her hash için karşılığın verildiğini bağımsız doğrulayın.

use std::sync::Arc;
use zagros_executor::bridge::{BridgeAuthority, BridgeManager};
use zagros_state::manager::StateDbManager;
use zagros_storage::rocksdb_impl::RocksDbStorage;
use zagros_types::config::ZagrosConfig;
use zagros_types::CHAIN_ID;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!(
            "Kullanim: {} <config.toml> <source_chain> <source_tx_hash> [<source_tx_hash> ...]",
            args[0]
        );
        eprintln!("\n🚨 Duğumu ONCE durdurun. Yanlis isaretleme GERI ALINAMAZ.");
        std::process::exit(2);
    }

    let config = ZagrosConfig::from_file(&args[1]).expect("config.toml okunamadi");
    let source_chain = &args[2];
    let hashes = &args[3..];

    let storage = Arc::new(
        RocksDbStorage::open(&config.storage.db_path)
            .expect("RocksDB acilamadi - dugum hala calisiyor olabilir"),
    );
    let state = Arc::new(StateDbManager::new(storage));

    // Yetkili kümesi ve eşik, düğümün açılışta kullandığıyla AYNI kaynaktan
    // gelmeli; aksi halde geri yüklenen yönetici farklı davranır.
    let authorities: Vec<BridgeAuthority> = if config.bridge.authorities.is_empty() {
        BridgeManager::default_authorities()
    } else {
        config
            .bridge
            .authorities
            .iter()
            .map(|a| BridgeAuthority {
                address: a.address.clone(),
                public_key: {
                    let bytes = hex::decode(a.public_key_hex.trim_start_matches("0x"))
                        .expect("yetkili public_key_hex cozulemedi");
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&bytes);
                    key
                },
                is_active: true,
            })
            .collect()
    };
    let required = if config.bridge.authorities.is_empty() {
        2
    } else {
        config.bridge.required_signatures
    };

    let manager = BridgeManager::load_from_state(state.as_ref(), authorities, required, CHAIN_ID)
        .expect("kopru durumu diskten okunamadi");

    let mut newly_marked = 0;
    for hash in hashes {
        if manager
            .is_source_processed(source_chain, hash, state.as_ref())
            .expect("is_source_processed okunamadi")
        {
            println!("• {} zaten isaretliydi - degisiklik yok", hash);
            continue;
        }
        manager
            .mark_source_processed(source_chain, hash, state.as_ref())
            .expect("mark_source_processed diske yazilamadi");
        newly_marked += 1;
        println!("✓ {} artik ISLENMIS olarak isaretli", hash);
    }

    if newly_marked == 0 {
        println!("\nHicbir degisiklik yok - disk yazilmadi.");
        return;
    }

    manager
        .persist_meta(state.as_ref())
        .expect("kopru meta diske yazilamadi");

    println!(
        "\n✅ {} kaynak islem isaretlendi ve diske yazildi.\n\
         Bu kaynaklar icin artik ne yeni oneri olusur ne de bekleyen bir oneri yurutulur.",
        newly_marked
    );
}
