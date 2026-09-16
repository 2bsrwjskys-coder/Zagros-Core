//! Mainnet `config.toml`unu doğrular ve konsensüs kritik bölümlerin parmak
//! izini basar: `[genesis]`, `[bridge]` ve `network_id` tüm node'larda birebir
//! aynı olmalı, yoksa farklı genesis state_root üretilir. Parmak izi yalnız ortak
//! alanları kapsar (yol, IP, anahtar, ödül adresi node'a özeldir).
//! Kullanım: config_check <config.toml> [config2.toml ...]
use sha3::{Digest, Keccak256};
use zagros_types::config::ZagrosConfig;

fn fingerprint(c: &ZagrosConfig) -> (String, Vec<String>) {
    let mut h = Keccak256::new();
    let mut lines = Vec::new();

    h.update(b"network_id:");
    h.update(c.network.network_id.to_le_bytes());
    lines.push(format!("network_id           : {}", c.network.network_id));

    h.update(b"bridge:");
    h.update((c.bridge.required_signatures as u64).to_le_bytes());
    h.update(c.bridge.timelock_secs.to_le_bytes());
    lines.push(format!(
        "kopru esigi/timelock : {}/{} imza, {} sn",
        c.bridge.required_signatures,
        c.bridge.authorities.len(),
        c.bridge.timelock_secs
    ));
    for a in &c.bridge.authorities {
        h.update(a.address.to_lowercase().as_bytes());
        h.update(a.public_key_hex.to_lowercase().as_bytes());
        h.update([u8::from(a.is_active)]);
    }

    h.update(b"eth:");
    h.update(c.bridge.ethereum.chain_id.to_le_bytes());
    h.update(
        c.bridge
            .ethereum
            .gateway_contract_address
            .to_lowercase()
            .as_bytes(),
    );
    h.update(
        c.bridge
            .ethereum
            .unlock_token_address
            .to_lowercase()
            .as_bytes(),
    );
    h.update(c.bridge.ethereum.unlock_token_decimals.to_le_bytes());
    for r in &c.bridge.ethereum.relayer_eth_addresses {
        h.update(r.to_lowercase().as_bytes());
    }
    lines.push(format!(
        "gateway (eth {})      : {}",
        c.bridge.ethereum.chain_id, c.bridge.ethereum.gateway_contract_address
    ));
    lines.push(format!(
        "fis kanali           : {}",
        if c.bridge.ethereum.is_claim_voucher_enabled() {
            "ACIK"
        } else {
            "KAPALI"
        }
    ));

    h.update(b"genesis:");
    match &c.genesis.admin_multisig {
        Some(m) => {
            h.update([m.threshold]);
            for s in &m.signers {
                h.update(s.to_lowercase().as_bytes());
            }
            lines.push(format!(
                "admin multisig       : {}/{}",
                m.threshold,
                m.signers.len()
            ));
        }
        None => lines.push("admin multisig       : YOK".to_string()),
    }
    for v in &c.genesis.validators {
        h.update(v.address.to_lowercase().as_bytes());
        h.update(v.consensus_pubkey_hex.to_lowercase().as_bytes());
        h.update(v.provider.as_bytes());
        h.update(v.region.as_bytes());
        h.update(v.asn.to_le_bytes());
        h.update(v.operator_id_hex.to_lowercase().as_bytes());
    }
    lines.push(format!(
        "genesis validator    : {} adet",
        c.genesis.validators.len()
    ));
    lines.push(format!(
        "replay guard         : {}",
        c.genesis
            .replay_guard_file
            .as_deref()
            .unwrap_or("YOK (eski zincir islemleri oynatilabilir)")
    ));

    (hex::encode(h.finalize()), lines)
}

fn main() {
    let paths: Vec<String> = std::env::args().skip(1).collect();
    if paths.is_empty() {
        eprintln!("Kullanim: config_check <config.toml> [config2.toml ...]");
        std::process::exit(2);
    }

    let mut seen: Option<String> = None;
    let mut ayrisma = false;
    for p in &paths {
        let cfg = match ZagrosConfig::from_file(p) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("❌ {p}: {e}");
                std::process::exit(1);
            }
        };
        let (fp, lines) = fingerprint(&cfg);
        println!("=== {p} ===");
        for l in lines {
            println!("  {l}");
        }
        println!("  konsensus parmak izi : {fp}");
        println!(
            "  (node'a ozel) uretici: {}",
            cfg.consensus.block_producer_address
        );
        match &seen {
            None => seen = Some(fp),
            Some(first) if *first != fp => ayrisma = true,
            _ => {}
        }
        println!();
    }

    if paths.len() > 1 {
        if ayrisma {
            eprintln!("❌ AYRIŞMA: dosyaların konsensüs parmak izleri AYNI DEĞİL. Genesis başlatılmamalı.");
            std::process::exit(1);
        }
        println!("✅ {} dosyanın konsensüs parmak izi AYNI.", paths.len());
    }
}
