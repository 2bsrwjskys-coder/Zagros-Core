//! 🎟️ EIP-712 claim dijesti, `ZagrosBridgeGateway.claimDigest()` ile birebir.
//! Kullanıcı `claimTokens`ı kendi cüzdanından çağırır, haberciler zincir dışında
//! imzalar. Modül `zagros-types`ta: relayer imzalarken, rpc doğrularken AYNI dijesti üretmeli.

use sha3::{Digest, Keccak256};

/// `EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)`
const EIP712_DOMAIN_TYPE: &str =
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";

/// Kontrattaki `CLAIM_TYPEHASH`'in tip dizesi.
const CLAIM_TYPE: &str =
    "Claim(address token,address recipient,uint256 amount,bytes32 zagrosTxHash)";

/// Kontratın `EIP712("ZagrosBridgeGateway", "1")` çağrısıyla aynı olmalı.
const DOMAIN_NAME: &str = "ZagrosBridgeGateway";
const DOMAIN_VERSION: &str = "1";

fn keccak(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&out);
    result
}

/// 20 baytlık adresi 32 baytlık ABI kelimesine sola sıfır dolgusuyla yerleştirir.
fn address_word(address: &[u8; 20]) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(address);
    word
}

fn u64_word(value: u64) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    word
}

/// EIP-712 domain separator. `chain_id` ve `gateway` (verifyingContract) burada
/// hash'lendiği için, bir deployment için üretilen imza BAŞKA bir deployment'ta
/// geçersizdir, replay saldırısını kapatan mekanizma budur.
pub fn claim_domain_separator(chain_id: u64, gateway: &[u8; 20]) -> [u8; 32] {
    let mut buffer = Vec::with_capacity(160);
    buffer.extend_from_slice(&keccak(EIP712_DOMAIN_TYPE.as_bytes()));
    buffer.extend_from_slice(&keccak(DOMAIN_NAME.as_bytes()));
    buffer.extend_from_slice(&keccak(DOMAIN_VERSION.as_bytes()));
    buffer.extend_from_slice(&u64_word(chain_id));
    buffer.extend_from_slice(&address_word(gateway));
    keccak(&buffer)
}

/// Habercilerin imzalayacağı EIP-712 dijesti.
/// `amount_be` tutarın 32 baytlık BIG-ENDIAN gösterimidir (uint256). Böylece bu
/// modül u128/U256 gibi tip seçimlerinden bağımsız kalır ve çağıranlar kendi
/// sayı tiplerini kullanmakta serbest olur.
pub fn claim_digest(
    chain_id: u64,
    gateway: &[u8; 20],
    token: &[u8; 20],
    recipient: &[u8; 20],
    amount_be: &[u8; 32],
    zagros_tx_hash: &[u8; 32],
) -> [u8; 32] {
    let mut struct_buffer = Vec::with_capacity(160);
    struct_buffer.extend_from_slice(&keccak(CLAIM_TYPE.as_bytes()));
    struct_buffer.extend_from_slice(&address_word(token));
    struct_buffer.extend_from_slice(&address_word(recipient));
    struct_buffer.extend_from_slice(amount_be);
    struct_buffer.extend_from_slice(zagros_tx_hash);
    let struct_hash = keccak(&struct_buffer);

    let separator = claim_domain_separator(chain_id, gateway);

    let mut digest_buffer = Vec::with_capacity(66);
    digest_buffer.extend_from_slice(b"\x19\x01");
    digest_buffer.extend_from_slice(&separator);
    digest_buffer.extend_from_slice(&struct_hash);
    keccak(&digest_buffer)
}

/// `0x` önekli olabilen 40 haneli hex adresi 20 bayta çevirir.
pub fn parse_eth_address(value: &str) -> Option<[u8; 20]> {
    let trimmed = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(trimmed).ok()?;
    if bytes.len() != 20 {
        return None;
    }
    let mut address = [0u8; 20];
    address.copy_from_slice(&bytes);
    Some(address)
}

/// `0x` önekli olabilen 64 haneli hex hash'i 32 bayta çevirir.
pub fn parse_h256(value: &str) -> Option<[u8; 32]> {
    let trimmed = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(trimmed).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);
    Some(hash)
}

/// u128 tutarı uint256 big-endian kelimeye çevirir.
pub fn amount_to_be_bytes(amount: u128) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[16..].copy_from_slice(&amount.to_be_bytes());
    word
}

/// `r || s || v` imzasından adresi kurtarır; kontratın `ECDSA.recover`ı gibi
/// `v` 27/28 ve low-S şart (yüksek-S ikizi aynı yetkiden iki imza sayılırdı).
pub fn recover_claim_signer(digest: &[u8; 32], signature: &[u8; 65]) -> Option<[u8; 20]> {
    use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
    use secp256k1::{Message, Secp256k1};

    let recovery_id = match signature[64] {
        27 => 0i32,
        28 => 1i32,
        _ => return None,
    };

    // secp256k1 kütüphanesi `from_compact`'te yüksek-S'i reddetmez; açıkça
    // kontrol ediyoruz (secp256k1n/2 üstü).
    const HALF_ORDER: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b,
        0x20, 0xa0,
    ];
    if signature[32..64] > HALF_ORDER[..] {
        return None;
    }

    let recovery_id = RecoveryId::from_i32(recovery_id).ok()?;
    let recoverable = RecoverableSignature::from_compact(&signature[..64], recovery_id).ok()?;
    let message = Message::from_digest_slice(digest).ok()?;
    let public_key = Secp256k1::new()
        .recover_ecdsa(&message, &recoverable)
        .ok()?;

    let uncompressed = public_key.serialize_uncompressed();
    let hashed = keccak(&uncompressed[1..]);
    let mut address = [0u8; 20];
    address.copy_from_slice(&hashed[12..]);
    Some(address)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 🚨 Dijest gerçek kontratın `claimDigest()` çıktısıyla birebir olmalı
    /// (Hardhat, chainId 31337); şema kayarsa tüm çekimler sessizce çalışmazdı.
    #[test]
    fn digest_matches_the_deployed_contract_vector() {
        let digest = claim_digest(
            31337,
            &parse_eth_address("0x5FbDB2315678afecb367f032d93F642f64180aa3").unwrap(),
            &parse_eth_address("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap(),
            &parse_eth_address("0x4F0B2551e2c46292de5E32941c3277541E9e4568").unwrap(),
            &amount_to_be_bytes(1_234_567),
            &[0xabu8; 32],
        );
        assert_eq!(
            format!("0x{}", hex::encode(digest)),
            "0xfb14e361e44e2e62961badce40549db9272a4d1c94e12da5355dedfddbdd3d86"
        );
    }

    #[test]
    fn claim_typehash_matches_the_contract() {
        assert_eq!(
            format!("0x{}", hex::encode(keccak(CLAIM_TYPE.as_bytes()))),
            "0x9421269c91b6d2e2827c56ac8ccf947c0e284473c4a4c4c4fc6d97b806bae2c0"
        );
    }

    #[test]
    fn digest_is_bound_to_chain_id_and_gateway() {
        let gateway = parse_eth_address("0x5FbDB2315678afecb367f032d93F642f64180aa3").unwrap();
        let other = parse_eth_address("0x1111111111111111111111111111111111111111").unwrap();
        let token = parse_eth_address("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap();
        let recipient = parse_eth_address("0x4F0B2551e2c46292de5E32941c3277541E9e4568").unwrap();
        let amount = amount_to_be_bytes(1_234_567);

        let reference = claim_digest(31337, &gateway, &token, &recipient, &amount, &[0xab; 32]);
        assert_ne!(
            reference,
            claim_digest(1, &gateway, &token, &recipient, &amount, &[0xab; 32])
        );
        assert_ne!(
            reference,
            claim_digest(31337, &other, &token, &recipient, &amount, &[0xab; 32])
        );
    }

    #[test]
    fn recover_round_trips_a_signature_back_to_its_signer() {
        use secp256k1::{Message, Secp256k1, SecretKey};

        let secret_key = SecretKey::from_slice(&[9u8; 32]).unwrap();
        let digest = [0x33u8; 32];

        let secp = Secp256k1::new();
        let message = Message::from_digest_slice(&digest).unwrap();
        let (recovery_id, compact) = secp
            .sign_ecdsa_recoverable(&message, &secret_key)
            .serialize_compact();
        let mut signature = [0u8; 65];
        signature[..64].copy_from_slice(&compact);
        signature[64] = 27 + recovery_id.to_i32() as u8;

        let recovered = recover_claim_signer(&digest, &signature).expect("recover basarili olmali");

        let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
        let uncompressed = public_key.serialize_uncompressed();
        let expected = &keccak(&uncompressed[1..])[12..];
        assert_eq!(&recovered[..], expected);
    }

    #[test]
    fn recover_rejects_an_out_of_range_v_byte() {
        let mut signature = [1u8; 65];
        signature[64] = 0; // 27/28 disi
        assert!(recover_claim_signer(&[0x33u8; 32], &signature).is_none());
    }

    /// 🚀 Canlı mainnet doğrulaması: gerçek `ZagrosBridgeGateway` (0xbeda78b7…)
    /// `claimDigest()` çıktısı, üretim domain'i (chainId 1 + gerçek adres).
    #[test]
    fn digest_matches_the_live_mainnet_gateway() {
        // 🚨 Değerleri değiştirmeyin: gerçek kontrattan alınmış tarihsel referans
        // (ZSC/USDC dönemi); girdi değişirse pinlenmiş kanıt anlamsızlaşır.
        let digest = claim_digest(
            1, // Ethereum mainnet
            &parse_eth_address("0xbeda78b7526e2c1cad82c94fe91fcbf9612e521f").unwrap(),
            &parse_eth_address("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap(), // tarihsel örnek girdi (USDC), bkz. yukarıdaki not
            &parse_eth_address("0x4F0B2551e2c46292de5E32941c3277541E9e4568").unwrap(),
            &amount_to_be_bytes(2_500_000), // tarihsel örnek girdi
            &[0xabu8; 32],
        );
        assert_eq!(
            format!("0x{}", hex::encode(digest)),
            "0x796d721c868a55debcfa5d35308d77823835a74ed3e63eab7dd47f9df66535df"
        );
    }
}
