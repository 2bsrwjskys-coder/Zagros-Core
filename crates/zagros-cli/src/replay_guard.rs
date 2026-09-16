//! G13 (§16.2): replay_guard. chain_id mainnet'te aynı kaldığından (21072026)
//! test zincirinde imzalanmış işlem yeniden oynatılabilirdi. Dondurulan son
//! state'ten: (1) nonce>0 adresler genesis'te `final_nonce + 1`den başlar;
//! (2) 🚨 `BridgeProcessedSource_*` anahtarları aynen taşınır, yoksa eski
//! Ethereum yatırmaları "hiç işlenmemiş" görünüp karşılıksız mint edilebilirdi.
//! Dosya biçimi: `<0x-adres> <final_nonce>` ve `SRC <BridgeProcessedSource_...>` satırları.
use std::path::Path;

use zagros_primitives::{Result, ZagrosError};
use zagros_state::State;
use zagros_storage::rocksdb_impl::RocksDbStorage;
use zagros_storage::Storage;
use zagros_types::AccountState;

/// Köprünün "bu kaynak-zincir yatırması zaten kredilendirildi" state anahtarı
/// öneki (bkz. zagros-executor bridge.rs `processed_source_key`).
const PROCESSED_SOURCE_PREFIX: &str = "BridgeProcessedSource_";

/// Bir hesabın replay-guard girdisi.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayGuardEntry {
    pub address: String,
    pub final_nonce: u64,
}

/// replay_guard verisi: hesap nonce'ları + köprü işlenmiş-kaynak anahtarları.
/// İkisi birlikte taze genesis'te hem işlem-replay'ini hem köprü-yatırma-replay'ini
/// kapatır.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReplayGuardData {
    pub nonces: Vec<ReplayGuardEntry>,
    /// Tam `BridgeProcessedSource_<chain>|<hash>` anahtarları (aynen taşınır).
    pub processed_sources: Vec<String>,
}

fn is_account_address(key: &str) -> bool {
    key.len() == 42
        && (key.starts_with("0x") || key.starts_with("0X"))
        && key[2..].chars().all(|c| c.is_ascii_hexdigit())
}

/// Dondurulmuş bir `zagros-data/state` dizininden nonce>0 hesapları VE köprü
/// işlenmiş-kaynak anahtarlarını çıkarır. Çıktı sıralıdır (deterministik dosya —
/// genesis_hash'e girer).
pub fn export_from_state_dir<P: AsRef<Path>>(state_dir: P) -> Result<ReplayGuardData> {
    let storage = RocksDbStorage::open(state_dir)?;
    let mut nonces = Vec::new();
    let mut processed_sources = Vec::new();
    for key in storage.list_keys()? {
        let Ok(key_str) = String::from_utf8(key.clone()) else {
            continue;
        };
        if is_account_address(&key_str) {
            let Some(bytes) = Storage::get(&storage, &key)? else {
                continue;
            };
            let account = AccountState::deserialize_with_migration(&bytes)
                .map_err(|e| ZagrosError::DatabaseError(format!("{key_str} decode: {e}")))?;
            // 🛡️ Keyless deployment adresleri (deployer ve kanonik 0xcA11..CA11)
            // hariç: nonce taşınmaz, yoksa CREATE adresi kayar ya da CreateCollision
            // ile kanonik kontrat üretilemez olur (canlıda yaşandı). Replay riski yok.
            if account.nonce > 0 && !zagros_types::is_replay_guard_nonce_exempt(&key_str) {
                nonces.push(ReplayGuardEntry {
                    address: key_str.to_ascii_lowercase(),
                    final_nonce: account.nonce,
                });
            }
        } else if key_str.starts_with(PROCESSED_SOURCE_PREFIX) {
            // Köprü işlenmiş-kaynak: değeri önemli değil (varlık = işlendi),
            // yalnız anahtarı taşırız.
            processed_sources.push(key_str);
        }
    }
    nonces.sort_by(|a, b| a.address.cmp(&b.address));
    nonces.dedup_by(|a, b| a.address == b.address);
    processed_sources.sort();
    processed_sources.dedup();
    Ok(ReplayGuardData {
        nonces,
        processed_sources,
    })
}

pub fn to_file_format(data: &ReplayGuardData) -> String {
    let mut out = String::new();
    for e in &data.nonces {
        out.push_str(&format!("{} {}\n", e.address, e.final_nonce));
    }
    for s in &data.processed_sources {
        out.push_str(&format!("SRC {}\n", s));
    }
    out
}

/// Dosyayı ayrıştırır, bozuk satır fail-closed (sessiz atlama YOK: eksik bir
/// adres/kaynak, replay kapısının o kalem için AÇIK kalması demektir).
/// `SRC ` öneki olmayan satırlar eski (nonce-only) biçimle geriye uyumludur.
pub fn parse_file(content: &str) -> Result<ReplayGuardData> {
    let mut nonces = Vec::new();
    let mut processed_sources = Vec::new();
    for (i, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(src) = line.strip_prefix("SRC ") {
            let src = src.trim();
            if !src.starts_with(PROCESSED_SOURCE_PREFIX) {
                return Err(ZagrosError::ConfigError(format!(
                    "replay_guard satır {}: SRC anahtarı '{PROCESSED_SOURCE_PREFIX}' ile başlamalı: {src}",
                    i + 1
                )));
            }
            processed_sources.push(src.to_string());
            continue;
        }
        let mut parts = line.split_whitespace();
        let (Some(addr), Some(nonce_s), None) = (parts.next(), parts.next(), parts.next()) else {
            return Err(ZagrosError::ConfigError(format!(
                "replay_guard satır {}: '<adres> <nonce>' veya 'SRC <anahtar>' bekleniyordu: {line}",
                i + 1
            )));
        };
        if !is_account_address(addr) {
            return Err(ZagrosError::ConfigError(format!(
                "replay_guard satır {}: geçersiz adres: {addr}",
                i + 1
            )));
        }
        let final_nonce: u64 = nonce_s.parse().map_err(|_| {
            ZagrosError::ConfigError(format!(
                "replay_guard satır {}: geçersiz nonce: {nonce_s}",
                i + 1
            ))
        })?;
        nonces.push(ReplayGuardEntry {
            address: addr.to_ascii_lowercase(),
            final_nonce,
        });
    }
    Ok(ReplayGuardData {
        nonces,
        processed_sources,
    })
}

/// Genesis'te uygular: her hesap `final_nonce + 1`den başlar (bakiye korunur),
/// köprü kaynak anahtarları aynen yazılır (köke dahil). Döner: uygulanan kalem sayısı.
pub fn apply_to_genesis(state: &dyn State, data: &ReplayGuardData) -> Result<usize> {
    for e in &data.nonces {
        let mut acc: AccountState = state.get_account(&e.address)?.unwrap_or_default();
        acc.nonce = e.final_nonce.saturating_add(1);
        state.set_account(&e.address, acc)?;
    }
    for s in &data.processed_sources {
        // is_source_processed_in_state bu anahtarın VARLIĞINA bakar; değer
        // önemsiz (default). bridge.rs mark_source_processed_in_state ile aynı.
        state.set_account(s, AccountState::default())?;
    }
    Ok(data.nonces.len() + data.processed_sources.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rejects_malformed_lines_fail_closed() {
        assert!(parse_file("0x1111111111111111111111111111111111111111 5\n").is_ok());
        assert!(parse_file("# yorum\n\n0x2222222222222222222222222222222222222222 1\n").is_ok());
        assert!(parse_file("bozuk satir\n").is_err(), "eksik alan gecmemeli");
        assert!(parse_file("0x123 5\n").is_err(), "kisa adres gecmemeli");
        assert!(parse_file("0x1111111111111111111111111111111111111111 abc\n").is_err());
        assert!(parse_file("0x1111111111111111111111111111111111111111 5 fazla\n").is_err());
        // SRC satırı: doğru önek kabul, yanlış önek red.
        assert!(parse_file("SRC BridgeProcessedSource_Ethereum|0xabc\n").is_ok());
        assert!(
            parse_file("SRC KotuOnek_xyz\n").is_err(),
            "yanlis SRC oneki gecmemeli"
        );
    }

    #[test]
    fn roundtrip_format_is_deterministic() {
        let data = ReplayGuardData {
            nonces: vec![
                ReplayGuardEntry {
                    address: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
                    final_nonce: 7,
                },
                ReplayGuardEntry {
                    address: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                    final_nonce: 3,
                },
            ],
            processed_sources: vec![
                "BridgeProcessedSource_Ethereum|0xdeadbeef".into(),
                "BridgeProcessedSource_Ethereum|0xfeedface".into(),
            ],
        };
        let text = to_file_format(&data);
        assert_eq!(parse_file(&text).unwrap(), data);
    }

    #[test]
    fn old_nonce_only_files_still_parse() {
        // Geriye uyumluluk: SRC satırı olmayan eski dosyalar sorunsuz parse edilir.
        let d = parse_file("0x1111111111111111111111111111111111111111 5\n").unwrap();
        assert_eq!(d.nonces.len(), 1);
        assert!(d.processed_sources.is_empty());
    }
}
