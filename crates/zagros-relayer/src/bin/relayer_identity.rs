//! `relayerN.toml`un kimliğini yazdırır (Ed25519 pubkey, Zagros yetkili adresi,
//! Ethereum adresi); bunlar `[[bridge.authorities]]` ve `isRelayer`e elle yazılır,
//! relayer kümede yoksa başlamadığından tavuk-yumurta olurdu. Gizli anahtar YAZDIRMAZ.
//! Kullanım: relayer_identity <relayerN.toml>
use ed25519_dalek::SigningKey;
use secp256k1::{Secp256k1, SecretKey};
use serde::Deserialize;
use sha3::{Digest, Keccak256};

#[derive(Deserialize)]
struct Identity {
    zagros_signing_key_hex: String,
    ethereum_signing_key_hex: String,
}

#[derive(Deserialize)]
struct Doc {
    identity: Identity,
}

fn decode32(label: &str, s: &str) -> [u8; 32] {
    let bytes = hex::decode(s.trim().trim_start_matches("0x"))
        .unwrap_or_else(|e| fatal(&format!("{label} hex degil: {e}")));
    bytes
        .try_into()
        .unwrap_or_else(|_| fatal(&format!("{label} 32 bayt degil")))
}

fn fatal(msg: &str) -> ! {
    eprintln!("HATA: {msg}");
    std::process::exit(1);
}

fn main() {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("Kullanim: relayer_identity <relayerN.toml>");
        std::process::exit(2);
    };
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| fatal(&format!("{path}: {e}")));
    let doc: Doc = toml::from_str(&text).unwrap_or_else(|e| fatal(&format!("{path}: {e}")));

    let ed = SigningKey::from_bytes(&decode32(
        "zagros_signing_key_hex",
        &doc.identity.zagros_signing_key_hex,
    ));
    let pubkey = ed.verifying_key().to_bytes();
    // Node'daki `BridgeManager::derive_address_from_public_key` ile AYNI kural:
    // keccak256(pubkey)'in son 20 baytı.
    let zagros_addr = &Keccak256::digest(pubkey)[12..];

    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&decode32(
        "ethereum_signing_key_hex",
        &doc.identity.ethereum_signing_key_hex,
    ))
    .unwrap_or_else(|e| fatal(&format!("secp256k1 anahtari gecersiz: {e}")));
    let uncompressed = sk.public_key(&secp).serialize_uncompressed();
    let eth_addr = &Keccak256::digest(&uncompressed[1..])[12..];

    println!("dosya            : {path}");
    println!("zagros_pubkey_hex: {}", hex::encode(pubkey));
    println!("zagros_adres     : 0x{}", hex::encode(zagros_addr));
    println!("ethereum_adres   : 0x{}", hex::encode(eth_addr));
}
