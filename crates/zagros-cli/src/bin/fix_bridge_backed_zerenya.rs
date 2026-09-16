//! 🛠️ TEK SEFERLİK DÜZELTME: genesis'te `GENESIS_POOL_ZERENYA` ile yanlış seed
//! edilen `bridge_backed_zerenya` sayacından o kadarını düşer (genesis havuzu
//! yalnız AMM dengesi için var, gerçek PAXG karşılığı yok).
//! ```bash
//! cargo run --release -p zagros-cli --bin fix_bridge_backed_zerenya -- config.toml
//! ```
//! 🚨 Geri alınamaz state değişikliği; düğümü durdurup `zagros-data/state` yedeği alın.

use std::sync::Arc;
use zagros_executor::Executor;
use zagros_state::manager::StateDbManager;
use zagros_state::State;
use zagros_storage::rocksdb_impl::RocksDbStorage;
use zagros_types::config::ZagrosConfig;
use zagros_types::{AccountState, GENESIS_POOL_ZERENYA};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Kullanim: {} <config.toml>", args[0]);
        eprintln!("\n🚨 Duğumu ONCE durdurun. Bu degisiklik GERI ALINAMAZ.");
        std::process::exit(2);
    }

    let config = ZagrosConfig::from_file(&args[1]).expect("config.toml okunamadi");

    let storage = Arc::new(
        RocksDbStorage::open(&config.storage.db_path)
            .expect("RocksDB acilamadi - dugum hala calisiyor olabilir"),
    );
    let state = Arc::new(StateDbManager::new(storage));

    let current = Executor::read_bridge_backed_zerenya(state.as_ref())
        .expect("bridge_backed_zerenya okunamadi");

    println!("Mevcut bridge_backed_zerenya: {} (ham birim)", current);
    println!(
        "  = {}.{:018} ZERENYA",
        current / 10u128.pow(18),
        current % 10u128.pow(18)
    );

    if current < GENESIS_POOL_ZERENYA {
        eprintln!(
            "\n❌ Mevcut deger ({}) GENESIS_POOL_ZERENYA'dan ({}) kucuk - \
             bu duzeltme zaten uygulanmis olabilir, veya beklenmeyen bir durum var. \
             ELLE KONTROL EDIN, hicbir sey yazilmadi.",
            current, GENESIS_POOL_ZERENYA
        );
        std::process::exit(1);
    }

    let corrected = current - GENESIS_POOL_ZERENYA;

    println!(
        "\nDuzeltilmis deger (GENESIS_POOL_ZERENYA cikarilmis): {} (ham birim)",
        corrected
    );
    println!(
        "  = {}.{:018} ZERENYA",
        corrected / 10u128.pow(18),
        corrected % 10u128.pow(18)
    );
    println!("\nBu, SADECE gercek kopru mint/burn islemlerinden gelen net miktardir.");

    let acc = AccountState {
        balance: corrected,
        ..Default::default()
    };
    state
        .set_account(&Executor::bridge_backed_zerenya_key(), acc)
        .expect("duzeltilmis deger yazilamadi");

    state.flush().expect("diske flush edilemedi");

    // Aynı süreç içinde, TAZE bir State okuması ile doğrula (cache'ten değil,
    // gerçekten diske indi mi diye).
    drop(state);
    let storage2 = Arc::new(
        RocksDbStorage::open(&config.storage.db_path).expect("dogrulama icin RocksDB acilamadi"),
    );
    let state2 = Arc::new(StateDbManager::new(storage2));
    let verified =
        Executor::read_bridge_backed_zerenya(state2.as_ref()).expect("dogrulama okumasi basarisiz");

    if verified == corrected {
        println!(
            "\n✅ Diske yazildi ve DOGRULANDI (yeni surecte tekrar okundu): {} (ham birim)",
            verified
        );
    } else {
        eprintln!(
            "\n❌ DOGRULAMA BASARISIZ: yazilan {} ama okunan {} - node'u BASLATMAYIN, durumu inceleyin.",
            corrected, verified
        );
        std::process::exit(1);
    }
}
