//! Node'un kalıcı libp2p kimliği. 🛡️ Köprü yetkili anahtarından KASITLI ayrı:
//! yalnız restart'lar arası kararlı `PeerId` için, dış kayıt gerektirmez; sızması
//! fon/imza riski değil, yine de dosya izni 0600.

use libp2p::identity::Keypair;
use std::fs;
use std::path::Path;
use zagros_primitives::ZagrosError;

/// `node_key_path`'te bir kimlik varsa yükler, yoksa yeni bir ed25519
/// `Keypair` üretip aynı yola (protobuf-encoded) yazar. Üst dizin yoksa
/// oluşturulur. Unix'te dosya `0600` izniyle yazılır (özel anahtar).
pub fn load_or_generate(node_key_path: &str) -> Result<Keypair, ZagrosError> {
    let path = Path::new(node_key_path);

    if path.exists() {
        let bytes = fs::read(path).map_err(|e| {
            ZagrosError::P2pError(format!(
                "node_key_path okunamadı ({}): {}",
                node_key_path, e
            ))
        })?;
        return Keypair::from_protobuf_encoding(&bytes).map_err(|e| {
            ZagrosError::P2pError(format!(
                "node_key_path bozuk/okunamaz ({}): {}",
                node_key_path, e
            ))
        });
    }

    let keypair = Keypair::generate_ed25519();
    let encoded = keypair
        .to_protobuf_encoding()
        .map_err(|e| ZagrosError::P2pError(format!("yeni kimlik serileştirilemedi: {}", e)))?;

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| {
                ZagrosError::P2pError(format!(
                    "node_key_path üst dizini oluşturulamadı ({:?}): {}",
                    parent, e
                ))
            })?;
        }
    }

    fs::write(path, &encoded).map_err(|e| {
        ZagrosError::P2pError(format!(
            "node_key_path yazılamadı ({}): {}",
            node_key_path, e
        ))
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(path, perms).map_err(|e| {
            ZagrosError::P2pError(format!(
                "node_key_path izinleri ayarlanamadı ({}): {}",
                node_key_path, e
            ))
        })?;
    }

    Ok(keypair)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_and_persists_a_new_identity_on_first_call() {
        let tmp = tempfile::tempdir().unwrap();
        let key_path = tmp.path().join("node_key");
        let key_path_str = key_path.to_str().unwrap();

        assert!(!key_path.exists());
        let keypair = load_or_generate(key_path_str).unwrap();
        assert!(key_path.exists(), "ilk çağrı kimliği diske yazmalı");

        let peer_id = keypair.public().to_peer_id();
        assert!(!peer_id.to_string().is_empty());
    }

    #[test]
    fn second_call_loads_the_same_identity_not_a_new_one() {
        let tmp = tempfile::tempdir().unwrap();
        let key_path = tmp.path().join("nested").join("node_key");
        let key_path_str = key_path.to_str().unwrap();

        let first = load_or_generate(key_path_str).unwrap();
        let second = load_or_generate(key_path_str).unwrap();

        assert_eq!(
            first.public().to_peer_id(),
            second.public().to_peer_id(),
            "aynı yoldan ikinci yükleme AYNI PeerId'yi vermeli, yeni bir kimlik ÜRETMEMELİ"
        );
    }

    #[cfg(unix)]
    #[test]
    fn persisted_key_file_has_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let key_path = tmp.path().join("node_key");
        load_or_generate(key_path.to_str().unwrap()).unwrap();

        let mode = fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "özel anahtar dosyası sadece sahibi tarafından okunabilir olmalı"
        );
    }
}
