//! 🔐 Köprü çoklu imza yetkilisi anahtar üreteci: `default_authorities()` herkesçe
//! bilinen test anahtarlarıdır; üretimde `[[bridge.authorities]]` bu araçla doldurulur.
//! Adres türetmesi `derive_address_from_public_key` ile (kopya sessizce ayrışırdı).
//! ```text
//! cargo run --release -p zagros-tests --bin bridge_keygen -- 3
//! ```
//! 🚨 Gizli anahtarlar yalnız stdout'a yazılır; üçü AYRI yerlerde saklanmalı.

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use zagros_executor::bridge::BridgeManager;

fn main() {
    let count: usize = std::env::args()
        .nth(1)
        .and_then(|arg| arg.parse().ok())
        .unwrap_or(3);

    if count < 2 {
        eprintln!("En az 2 yetkili üretilmeli (eşik minimum 2-of-n).");
        std::process::exit(1);
    }

    println!("# ============================================================");
    println!("# config.toml'a YAPIŞTIRIN ([bridge] bölümü)");
    println!("# ============================================================");
    println!("[bridge]");
    // n yetkili için makul eşik: çoğunluk (2-of-3, 3-of-5, ...).
    println!("required_signatures = {}", count / 2 + 1);
    println!();

    let mut secrets = Vec::new();

    for index in 1..=count {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().to_bytes();
        // TEK KAYNAK: düğümün kullandığı türetmenin ta kendisi.
        let address = BridgeManager::derive_address_from_public_key(&public_key);

        println!("[[bridge.authorities]]");
        println!("address = \"{}\"", address);
        println!("public_key_hex = \"0x{}\"", hex::encode(public_key));
        println!("is_active = true");
        println!();

        secrets.push((index, address, hex::encode(signing_key.to_bytes())));
    }

    println!("# ============================================================");
    println!("# 🚨 GİZLİ ANAHTARLAR - config.toml'a YAZILMAZ.");
    println!("# Her biri AYRI bir yetkilinin relayer'ında saklanır");
    println!("# (relayer.toml -> [identity].zagros_signing_key_hex).");
    println!("# Üçü aynı yerde durursa 2-of-3 eşiği anlamsızlaşır.");
    println!("# ============================================================");
    for (index, address, secret_hex) in &secrets {
        println!("# yetkili {} ({})", index, address);
        println!("#   zagros_signing_key_hex = \"0x{}\"", secret_hex);
    }
}
