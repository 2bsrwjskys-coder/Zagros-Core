//! 🔐 Relayer kimlik üreteci: Ed25519 (Zagros yetkilisi, `[[bridge.authorities]]`)
//! + secp256k1 (Ethereum imzacısı, gateway `isRelayer`). 🚨 Gizli anahtarlar yalnız
//! dosyaya (0600), stdout'a asla; araç üretileceği makinede çalıştırılmalı.
//! ```text
//! relayer_keygen <cikti-dosyasi.json>
//! ```
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use sha3::{Digest, Keccak256};

fn keccak_addr(bytes: &[u8]) -> String {
    let mut h = Keccak256::new();
    h.update(bytes);
    let d = h.finalize();
    format!("0x{}", hex::encode(&d[12..]))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("kullanim: {} <cikti-dosyasi.json>", args[0]);
        std::process::exit(2);
    }
    let path = &args[1];
    if std::path::Path::new(path).exists() {
        eprintln!("🛑 dosya ZATEN VAR: {path} — mevcut kimligin uzerine yazmayi reddediyorum");
        std::process::exit(1);
    }

    // Zagros yetkilisi (Ed25519)
    let ed = SigningKey::generate(&mut OsRng);
    let ed_pub = ed.verifying_key().to_bytes();
    let zagros_addr = keccak_addr(&ed_pub);

    // Ethereum imzacisi (secp256k1)
    let secp = secp256k1::Secp256k1::new();
    let (eth_sk, eth_pk) = secp.generate_keypair(&mut rand::thread_rng());
    // Ethereum adresi = keccak(uncompressed pubkey[1..])[12..]
    let eth_addr = keccak_addr(&eth_pk.serialize_uncompressed()[1..]);

    let json = format!(
        "{{\n  \"zagros_signing_key_hex\": \"{}\",\n  \"zagros_public_key_hex\": \"{}\",\n  \"zagros_authority_address\": \"{}\",\n  \"ethereum_signing_key_hex\": \"{}\",\n  \"ethereum_address\": \"{}\"\n}}\n",
        hex::encode(ed.to_bytes()),
        hex::encode(ed_pub),
        zagros_addr,
        hex::encode(eth_sk.secret_bytes()),
        eth_addr
    );
    std::fs::write(path, json).expect("kimlik dosyasi yazilamadi");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("izinler ayarlanamadi");
    }

    println!("# kimlik yazildi: {path} (0600, gizli anahtarlar SADECE burada)");
    println!("zagros_authority_address={zagros_addr}");
    println!("zagros_public_key_hex={}", hex::encode(ed_pub));
    println!("ethereum_address={eth_addr}");
}
