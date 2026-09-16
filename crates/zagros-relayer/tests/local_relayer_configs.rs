//! Aynı makinedeki relayer yapılandırmaları ayrışık olmalı: aynı `data_dir`
//! RocksDB kilidiyle açılmaz, aynı Ed25519 kimliği 2-of-3 eşiğini asla sağlamaz,
//! aynı Ethereum kimliği kontratta reddedilir. Dosyalar `.gitignore`da; yoksa test sessizce atlanır.

use std::collections::HashSet;

const CONFIGS: [&str; 3] = ["relayer.toml", "relayer2.toml", "relayer3.toml"];

#[test]
fn local_relayer_configs_are_fully_distinct() {
    // API anahtarı taşıyan uçlar ${VAR} ile referanslandığı için .env gerekir.
    let _ = dotenvy::from_path(concat!(env!("CARGO_MANIFEST_DIR"), "/../../.env"));

    let paths: Vec<String> = CONFIGS
        .iter()
        .map(|f| format!("{}/{}", env!("CARGO_MANIFEST_DIR"), f))
        .collect();

    if paths.iter().any(|p| !std::path::Path::new(p).exists()) {
        eprintln!("relayer*.toml bulunamadi (gizli dosyalar) - test atlaniyor.");
        return;
    }

    let mut data_dirs = HashSet::new();
    let mut zagros_authorities = HashSet::new();
    let mut ethereum_addresses = HashSet::new();

    for (name, path) in CONFIGS.iter().zip(&paths) {
        let config = zagros_relayer::config::RelayerConfig::from_file(path)
            .unwrap_or_else(|e| panic!("{} yuklenemedi: {}", name, e));

        let zagros = config
            .zagros_authority_address()
            .unwrap_or_else(|e| panic!("{} Zagros kimligi turetilemedi: {}", name, e));
        let ethereum = config
            .ethereum_address()
            .unwrap_or_else(|e| panic!("{} Ethereum kimligi turetilemedi: {}", name, e));

        assert!(
            data_dirs.insert(config.data_dir.clone()),
            "{}: data_dir baska bir relayer ile AYNI ({}) - ikinci relayer RocksDB \
             kilidi yuzunden acilamaz",
            name,
            config.data_dir
        );
        assert!(
            zagros_authorities.insert(zagros.clone()),
            "{}: Ed25519 yetkili adresi baska bir relayer ile AYNI ({}) - iki relayer \
             tek yetkili sayilir ve 2-of-3 esigi asla saglanmaz",
            name,
            zagros
        );
        assert!(
            ethereum_addresses.insert(ethereum.clone()),
            "{}: Ethereum adresi baska bir relayer ile AYNI ({}) - kontratin artan-adres \
             tekillik kurali ikinci imzayi reddeder",
            name,
            ethereum
        );
    }

    // 🚨 Zaman kilidi DÜĞÜMLE aynı olmalı. Ayrışırsa relayer ya erken fiş üretir
    // (kilit korumasını delerek) ya da hiç üretmez (çekimler sessizce durur),
    // ikisi de log'a bakmadan fark edilmez.
    let node_config_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../config.toml");
    if std::path::Path::new(node_config_path).exists() {
        let node = zagros_types::config::ZagrosConfig::from_file(node_config_path)
            .expect("dugum config.toml yuklenemedi");
        for (name, path) in CONFIGS.iter().zip(&paths) {
            let config = zagros_relayer::config::RelayerConfig::from_file(path).unwrap();
            assert_eq!(
                config.bridge.timelock_secs, node.bridge.timelock_secs,
                "{}: zaman kilidi dugumle AYRISIYOR (relayer {} sn, dugum {} sn)",
                name, config.bridge.timelock_secs, node.bridge.timelock_secs
            );
        }
    }

    // Ayni sekilde M-of-N esigi ve yetkili kumesi de dugumle ortusmeli.
    if std::path::Path::new(node_config_path).exists() {
        let node = zagros_types::config::ZagrosConfig::from_file(node_config_path).unwrap();
        let node_keys: std::collections::BTreeSet<String> = node
            .bridge
            .authorities
            .iter()
            .map(|a| a.public_key_hex.trim_start_matches("0x").to_lowercase())
            .collect();
        for (name, path) in CONFIGS.iter().zip(&paths) {
            let config = zagros_relayer::config::RelayerConfig::from_file(path).unwrap();
            let relayer_keys: std::collections::BTreeSet<String> = config
                .bridge
                .authorities
                .iter()
                .map(|k| k.trim_start_matches("0x").to_lowercase())
                .collect();
            assert_eq!(
                relayer_keys, node_keys,
                "{}: yetkili kumesi dugumle AYRISIYOR",
                name
            );
            assert_eq!(
                config.bridge.required_signatures, node.bridge.required_signatures,
                "{}: M-of-N esigi dugumle AYRISIYOR",
                name
            );
        }
    }
}
