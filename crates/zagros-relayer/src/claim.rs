//! 🎟️ EIP-712 claim fişi üretimi: çekimi kullanıcı kendi gas'ıyla tetikler,
//! haberciler yalnız zincir dışında fiş imzalar (merkezi ETH cüzdanı gerekmez).
//! 🔒 Dijest formülü `zagros_types::eip712`de tek kaynak, düğüm de aynı fonksiyonu çağırır.

use secp256k1::{Message, Secp256k1, SecretKey};

use ethers_core::types::{Address as EthAddress, H256, U256};
use zagros_types::eip712;

/// `zagros_types::eip712::claim_digest`'in ethers tipleriyle çalışan sarmalayıcısı.
/// `ZagrosBridgeGateway.claimDigest(...)` ile AYNI değeri üretir.
pub fn claim_digest(
    chain_id: u64,
    gateway: EthAddress,
    token: EthAddress,
    recipient: EthAddress,
    amount: U256,
    zagros_tx_hash: H256,
) -> H256 {
    let mut amount_be = [0u8; 32];
    amount.to_big_endian(&mut amount_be);

    H256::from(eip712::claim_digest(
        chain_id,
        &gateway.to_fixed_bytes(),
        &token.to_fixed_bytes(),
        &recipient.to_fixed_bytes(),
        &amount_be,
        &zagros_tx_hash.to_fixed_bytes(),
    ))
}

/// Claim dijestini imzalar, `r || s || v` (65 bayt, `v` 27/28, low-S);
/// OpenZeppelin `ECDSA.recover` yüksek-S ve diğer `v` değerlerini reddeder.
pub fn sign_claim(secret_key: &SecretKey, digest: H256) -> [u8; 65] {
    let secp = Secp256k1::signing_only();
    let message =
        Message::from_digest_slice(digest.as_bytes()).expect("digest is exactly 32 bytes");
    let recoverable = secp.sign_ecdsa_recoverable(&message, secret_key);
    let (recovery_id, compact) = recoverable.serialize_compact();

    let mut signature = [0u8; 65];
    signature[..64].copy_from_slice(&compact);
    signature[64] = 27 + recovery_id.to_i32() as u8;
    signature
}

/// Tek habercinin imza fişi; kullanıcı `requiredSignatures` adet toplar. Fişler
/// gizli değildir, tek başına eşiği sağlamaz, herkese açık taşınması güvenli.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimVoucher {
    /// Zagros'taki burn işleminin hash'i, kontratta çift-harcama anahtarı.
    pub zagros_tx_hash: H256,
    pub token: EthAddress,
    pub recipient: EthAddress,
    pub amount: U256,
    /// İmzayı üreten habercinin Ethereum adresi (kontratın `isRelayer`
    /// kümesinde olmalı). Kullanıcı fişleri bu adrese göre ARTAN sırada dizmeli.
    pub signer: EthAddress,
    /// 65 baytlık `r || s || v`.
    pub signature: [u8; 65],
}

impl ClaimVoucher {
    pub fn signature_hex(&self) -> String {
        format!("0x{}", hex::encode(self.signature))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    /// Ethers sarmalayıcısı, paylaşılan çekirdekle aynı sonucu vermeli, yani
    /// kontrattan alınan referans vektörü buradan da geçmeli.
    #[test]
    fn wrapper_reproduces_the_on_chain_contract_vector() {
        let digest = claim_digest(
            31337,
            EthAddress::from_str("0x5FbDB2315678afecb367f032d93F642f64180aa3").unwrap(),
            EthAddress::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap(),
            EthAddress::from_str("0x4F0B2551e2c46292de5E32941c3277541E9e4568").unwrap(),
            U256::from(1_234_567u64),
            H256::from([0xabu8; 32]),
        );
        assert_eq!(
            format!("0x{}", hex::encode(digest.as_bytes())),
            "0xfb14e361e44e2e62961badce40549db9272a4d1c94e12da5355dedfddbdd3d86"
        );
    }

    /// İmzalanan fiş, düğümün doğrulamada kullandığı `recover_claim_signer` ile
    /// imzalayana geri çözülmeli, üretim ve doğrulama uçları uyumlu olmalı.
    #[test]
    fn signed_voucher_recovers_to_the_signing_relayer() {
        let secret_key = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let digest = H256::from([0x11u8; 32]);
        let signature = sign_claim(&secret_key, digest);

        assert!(
            signature[64] == 27 || signature[64] == 28,
            "v = {}",
            signature[64]
        );

        let recovered =
            zagros_types::eip712::recover_claim_signer(&digest.to_fixed_bytes(), &signature)
                .expect("imza cozulebilmeli");

        // Transaction::address_from_secret_key aynı Keccak(pubkey)[12..] türetmesini
        // kullanır, kurtarılan adres onunla eşleşmeli.
        let expected = zagros_types::Transaction::address_from_secret_key(&secret_key);
        assert_eq!(format!("0x{}", hex::encode(recovered)), expected);
    }
}
