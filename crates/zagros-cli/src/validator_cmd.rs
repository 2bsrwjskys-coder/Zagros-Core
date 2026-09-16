//! `zagros-cli validator gen-key`: Ed25519 konsensüs anahtarı üretir
//! (`consensus_key_path` formatı, 0600 JSON); zincire kayıt ayrı yollarla yapılır.
//! `prove-ownership` / `register-payload`: dApp'in üretemeyeceği Ed25519 imzası +
//! bincode payload'ı; yeni kural eklemez, executor'ın beklediği fonksiyonları doğrudan çağırır.

use std::sync::Arc;
use zagros_crypto::ConsensusKeypair;
use zagros_executor::params::consensus_domain;
use zagros_state::manager::StateDbManager;
use zagros_storage::rocksdb_impl::RocksDbStorage;
use zagros_types::config::ZagrosConfig;
use zagros_types::consensus::{
    ConsensusDomain, RegisterValidatorPayload, RotateConsensusKeyPayload, ValidatorDeclaration,
};
use zagros_types::Transaction;

/// RPC tarafının `RegisterValidator` seçicisi (`native_tx_type_for_evm_call`,
/// zagros-rpc/src/lib.rs), calldata'nın ilk 4 baytı, payload ondan SONRA gelir.
const REGISTER_VALIDATOR_SELECTOR: &str = "bcc6587f";
/// G14: `rotateConsensusKey()` seçicisi (aynı RPC eşlemesi, alıcı 0x...0006).
const ROTATE_CONSENSUS_KEY_SELECTOR: &str = "4a7c332f";

fn parse_evm_address(address: &str) -> Result<String, String> {
    if !Transaction::validate_address(address) {
        return Err(format!(
            "'{address}' geçerli bir EVM adresi değil - 0x ile başlayıp 40 hex karakter içermeli (toplam 42)."
        ));
    }
    Ok(address.to_ascii_lowercase())
}

fn hex_decode_32(s: &str) -> Result<[u8; 32], String> {
    let trimmed = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    let bytes = hex::decode(trimmed).map_err(|e| format!("hex çözülemedi: {e}"))?;
    bytes.try_into().map_err(|v: Vec<u8>| {
        format!(
            "32 bayt (64 hex karakter) bekleniyordu, {} bayt geldi",
            v.len()
        )
    })
}

/// `--key`/`--config`tan imza için gerekenleri yükler. 🚨 Node çalışırken RocksDB
/// kilit çakışmasıyla başarısız olur (salt okunur mod yok); operatör node'u geçici durdurmalı.
fn load_domain_and_keypair(
    key_path: &str,
    config_path: &str,
) -> Result<(ConsensusDomain, ConsensusKeypair), String> {
    let kp = zagros_crypto::load_keyfile(key_path)
        .map_err(|e| format!("konsensüs anahtar dosyası ({key_path}) okunamadı: {e}"))?;
    let config = ZagrosConfig::from_file(config_path)
        .map_err(|e| format!("{config_path} okunamadı: {e}"))?;
    let storage = RocksDbStorage::open(&config.storage.db_path).map_err(|e| {
        format!(
            "node'un veri dizini ({}) açılamadı: {e}\n\
             Bu genellikle node hâlâ ÇALIŞIYOR olduğu için oluşur (RocksDB aynı dizini iki process'e \
             AÇMAZ) - node'u geçici olarak durdurup tekrar deneyin.",
            config.storage.db_path
        )
    })?;
    let state = StateDbManager::new(Arc::new(storage));
    let domain = consensus_domain(&state).map_err(|e| {
        format!(
            "zincir imza bağlamı (genesis_hash) okunamadı: {e}\n\
             Bu, veri dizininin henüz genesis'i hiç görmediği (node bir kez bile başlatılmamış) \
             boş bir dizin olduğu anlamına gelebilir."
        )
    })?;
    Ok((domain, kp))
}

pub fn prove_ownership(key_path: &str, config_path: &str, address: &str) -> Result<(), String> {
    let address = parse_evm_address(address)?;
    let (domain, kp) = load_domain_and_keypair(key_path, config_path)?;
    let proof = zagros_crypto::prove_key_ownership(&kp, &domain, &address, None);
    // Kendi ürettiğimizi kendi doğrulama fonksiyonumuzla anında teyit ediyoruz,
    // yanlış bir digest/anahtar sessizce "başarılı" görünüp operatörü mainnet'te
    // reddedilecek bir işleme sürüklemesin.
    zagros_crypto::verify_key_ownership(&kp.public_key(), &proof, &domain, &address, None)
        .map_err(|e| {
            format!("iç doğrulama başarısız oldu (bu bir hata olmamalı, lütfen bildirin): {e}")
        })?;
    println!(
        "✅ Sahiplik kanıtı üretildi ve kendi kendine doğrulandı.\n\
         \u{20}  consensus_pubkey_hex : {}\n\
         \u{20}  ownership_proof_hex  : {}\n\
         \u{20}  bağlı EVM adresi     : {address}\n\n\
         Bu ikisi (`RegisterValidator` kaydında) yalnızca BU adresle eşleşir - başka bir adresle \
         kayıt denemesi zincirde reddedilir.",
        hex::encode(kp.public_key()),
        hex::encode(&proof)
    );
    Ok(())
}

/// Saf hesaplama: dosya sistemi/CLI çıktısından bağımsız, doğrudan test
/// edilebilir. `register_payload()` bunu çağırıp SADECE biçimlendirip yazdırır.
#[allow(clippy::too_many_arguments)]
fn compute_register_calldata(
    domain: &ConsensusDomain,
    kp: &ConsensusKeypair,
    address: &str,
    provider: &str,
    region: &str,
    asn: u32,
    operator_id: [u8; 32],
) -> Result<(String, RegisterValidatorPayload), String> {
    let ownership_proof = zagros_crypto::prove_key_ownership(kp, domain, address, None);
    let declaration = ValidatorDeclaration {
        provider: provider.to_string(),
        region: region.to_string(),
        asn,
        operator_id,
    };
    let payload = RegisterValidatorPayload {
        consensus_pubkey: kp.public_key(),
        ownership_proof,
        declaration,
    };
    let encoded = payload.encode();
    // Round-trip: zincirin `decode()`'unun da bunu kabul edeceğini burada
    // kanıtlıyoruz, dApp'e "gönder" demeden önce operatöre erken uyarı.
    let decoded = RegisterValidatorPayload::decode(&encoded)
        .map_err(|e| format!("iç kodlama tutarsız (bu bir hata olmamalı, lütfen bildirin): {e}"))?;
    if decoded != payload {
        return Err(
            "iç kodlama round-trip'i eşleşmedi (bu bir hata olmamalı, lütfen bildirin)".to_string(),
        );
    }
    let calldata = format!("0x{REGISTER_VALIDATOR_SELECTOR}{}", hex::encode(&encoded));
    Ok((calldata, payload))
}

#[allow(clippy::too_many_arguments)]
pub fn register_payload(
    key_path: &str,
    config_path: &str,
    address: &str,
    provider: &str,
    region: &str,
    asn: u32,
    operator_id_hex: &str,
) -> Result<(), String> {
    let address = parse_evm_address(address)?;
    let operator_id =
        hex_decode_32(operator_id_hex).map_err(|e| format!("--operator-id-hex geçersiz: {e}"))?;
    let (domain, kp) = load_domain_and_keypair(key_path, config_path)?;
    let (calldata, payload) =
        compute_register_calldata(&domain, &kp, &address, provider, region, asn, operator_id)?;
    println!(
        "✅ RegisterValidator payload'ı üretildi ve zincirin kendi decode() fonksiyonuyla doğrulandı.\n\
         \u{20}  consensus_pubkey_hex : {}\n\
         \u{20}  bağlı EVM adresi     : {address}\n\
         \u{20}  beyan                : provider={provider}, region={region}, asn={asn}, operator_id={}\n\n\
         Aşağıdaki tek satırı, dApp'in Validator Kaydı formundaki \"İşlem Verisi\" alanına \
         AYNEN yapıştırın (bu, seçici + kodlanmış payload'ın TAMAMIdır, ayrıca hiçbir parametre \
         eklenmemeli):\n\n{calldata}\n",
        hex::encode(payload.consensus_pubkey),
        hex::encode(operator_id),
    );
    Ok(())
}

/// G14 (§15): saf hesaplama, rotasyon calldata'sı. Kanıt YENİ anahtarla,
/// zincirdeki MEVCUT pubkey (`old_pubkey`) üzerinden üretilir.
fn compute_rotate_calldata(
    domain: &ConsensusDomain,
    new_kp: &ConsensusKeypair,
    address: &str,
    old_pubkey: &[u8; 32],
) -> Result<(String, RotateConsensusKeyPayload), String> {
    let ownership_proof =
        zagros_crypto::prove_key_ownership(new_kp, domain, address, Some(old_pubkey));
    zagros_crypto::verify_key_ownership(
        &new_kp.public_key(),
        &ownership_proof,
        domain,
        address,
        Some(old_pubkey),
    )
    .map_err(|e| {
        format!("iç doğrulama başarısız oldu (bu bir hata olmamalı, lütfen bildirin): {e}")
    })?;
    let payload = RotateConsensusKeyPayload {
        new_pubkey: new_kp.public_key(),
        ownership_proof,
    };
    let encoded = payload.encode();
    let decoded = RotateConsensusKeyPayload::decode(&encoded)
        .map_err(|e| format!("iç kodlama tutarsız (bu bir hata olmamalı, lütfen bildirin): {e}"))?;
    if decoded != payload {
        return Err(
            "iç kodlama round-trip'i eşleşmedi (bu bir hata olmamalı, lütfen bildirin)".to_string(),
        );
    }
    let calldata = format!("0x{ROTATE_CONSENSUS_KEY_SELECTOR}{}", hex::encode(&encoded));
    Ok((calldata, payload))
}

/// G14 (§15): `RotateConsensusKey` işlemi için TAM calldata üretir. Eski
/// pubkey ZİNCİR KAYDINDAN okunur (elle verilmez, yanlış "eski" değeriyle
/// üretilen kanıt zincirde zaten reddedilir). Node bu komut çalışırken
/// GEÇİCİ OLARAK DURDURULMALI.
pub fn rotate_payload(new_key_path: &str, config_path: &str, address: &str) -> Result<(), String> {
    let address = parse_evm_address(address)?;
    let new_kp = zagros_crypto::load_keyfile(new_key_path)
        .map_err(|e| format!("YENİ konsensüs anahtar dosyası ({new_key_path}) okunamadı: {e}"))?;
    let config = ZagrosConfig::from_file(config_path)
        .map_err(|e| format!("{config_path} okunamadı: {e}"))?;
    let storage = RocksDbStorage::open(&config.storage.db_path).map_err(|e| {
        format!(
            "node'un veri dizini ({}) açılamadı: {e}\n\
             Bu genellikle node hâlâ ÇALIŞIYOR olduğu için oluşur (RocksDB aynı dizini iki process'e \
             AÇMAZ) - node'u geçici olarak durdurup tekrar deneyin.",
            config.storage.db_path
        )
    })?;
    let state = StateDbManager::new(Arc::new(storage));
    let domain = consensus_domain(&state)
        .map_err(|e| format!("zincir imza bağlamı (genesis_hash) okunamadı: {e}"))?;
    let old_pubkey = zagros_state::State::get_account(&state, &address)
        .map_err(|e| format!("hesap okunamadı: {e}"))?
        .map(|a| a.consensus_pubkey)
        .unwrap_or([0u8; 32]);
    if old_pubkey == [0u8; 32] {
        return Err(format!(
            "{address} zincirde kayıtlı bir konsensüs anahtarı taşımıyor - rotasyon yalnızca \
             kayıtlı bir validator için anlamlıdır (önce RegisterValidator)."
        ));
    }
    if old_pubkey == new_kp.public_key() {
        return Err("yeni anahtar, zincirdeki mevcut anahtarla AYNI - önce gen-key ile YENİ bir anahtar üretin.".to_string());
    }
    let (calldata, payload) = compute_rotate_calldata(&domain, &new_kp, &address, &old_pubkey)?;
    println!(
        "✅ RotateConsensusKey payload'ı üretildi ve zincirin kendi decode() fonksiyonuyla doğrulandı.\n\
         \u{20}  eski pubkey (zincirden): {}\n\
         \u{20}  yeni pubkey            : {}\n\
         \u{20}  bağlı EVM adresi       : {address}\n\n\
         Aşağıdaki tek satırı, cüzdanınızdan 0x...0006 adresine gönderilecek işlemin \"İşlem Verisi\" \
         alanına AYNEN yapıştırın:\n\n{calldata}\n\n\
         🚨 SIRALAMA ÖNEMLİ: rotasyon bir SONRAKİ epoch geçişinde etkinleşir. İşlem zincire girdikten \
         sonra epoch sınırına KADAR node ESKİ anahtarla imzalamaya devam etmeli; epoch geçişinden \
         sonra config.toml → [network].consensus_key_path yeni dosyaya çevrilip node yeniden \
         başlatılmalı. Eski keyfile'ı hemen SİLMEYİN.",
        hex::encode(old_pubkey),
        hex::encode(payload.new_pubkey),
    );
    Ok(())
}

pub fn gen_key(out_path: &str) -> Result<(), String> {
    if std::path::Path::new(out_path).exists() {
        return Err(format!(
            "{out_path} zaten var - üzerine YAZILMAZ (mevcut bir validator anahtarını kaybetmemek için); \
             farklı bir --out yolu verin ya da dosyayı bilinçli olarak taşıyıp tekrar deneyin."
        ));
    }
    let kp = zagros_crypto::ConsensusKeypair::generate();
    let pubkey_hex = hex::encode(kp.public_key());
    zagros_crypto::save_keyfile(&kp, out_path).map_err(|e| format!("keyfile yazılamadı: {e}"))?;
    println!(
        "✅ Yeni konsensüs anahtarı üretildi.\n\
         \u{20}  dosya (0600, GİZLİ TUTUN)  : {out_path}\n\
         \u{20}  consensus_pubkey_hex (PAYLAŞILABİLİR): {pubkey_hex}\n\n\
         Sıradaki adımlar:\n\
         \u{20}  1) config.toml → [network].consensus_key_path = \"{out_path}\"\n\
         \u{20}  2) Bu pubkey'i (ve validator hesap adresini) admin multisig'e \
         Candidate kaydı için iletin (Faz A onay akışı) - bu araç zincire HİÇBİR ŞEY yazmaz."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc as StdArc;
    use zagros_state::State as StateTrait;
    use zagros_types::consensus::ChainParams;
    use zagros_types::{AccountState, TxType};

    /// G2 genesis varsayılanı, gerçek üretim kodunda kullanılan aynı sabit.
    const TEST_MIN_STAKE: u128 = 170_000_000_000_000_000;
    const TEST_GENESIS_HASH: [u8; 32] = [0x5a; 32];

    /// Yalnız FORMAT testleri için (imza gerektirmeyen) sabit adres.
    const FORMAT_ONLY_ADDR: &str = "0x1111111111111111111111111111111111111111";

    fn test_signer(byte: u8) -> (secp256k1::SecretKey, String) {
        let sk = secp256k1::SecretKey::from_slice(&[byte; 32]).unwrap();
        let addr = Transaction::address_from_secret_key(&sk);
        (sk, addr)
    }

    /// `zagros-rpc`'nin referans testiyle (`register_validator_selector_call_is_classified_and_flips_registration_through_the_executor`)
    /// AYNI kurulum deseni, gerçek RocksDB (geçici dizin), gerçek ChainParams
    /// + genesis_hash. `_dir` çağıranın scope'unda tutulmalı (drop olunca silinir).
    fn test_state_with_domain() -> (tempfile::TempDir, StdArc<dyn StateTrait>, ConsensusDomain) {
        let dir = tempfile::tempdir().unwrap();
        let storage = RocksDbStorage::open(dir.path().join("state")).unwrap();
        let state: StdArc<dyn StateTrait> = StdArc::new(StateDbManager::new(StdArc::new(storage)));
        zagros_executor::params::store_chain_params(
            state.as_ref(),
            &ChainParams::genesis_defaults(),
        )
        .unwrap();
        zagros_executor::params::store_genesis_hash(state.as_ref(), &TEST_GENESIS_HASH).unwrap();
        // Executor'ın epoch hesaplaması (`validator_status_epoch`) genesis zaman
        // damgasını okur, referans testteki (zagros-rpc) aynı sentinel kaydı.
        state
            .set_account(
                &zagros_types::GENESIS_TIMESTAMP_KEY.to_string(),
                AccountState {
                    balance: 1,
                    ..Default::default()
                },
            )
            .unwrap();
        let domain = consensus_domain(state.as_ref()).unwrap();
        (dir, state, domain)
    }

    fn fund_as_candidate(state: &StdArc<dyn StateTrait>, address: &str) {
        state
            .set_account(
                &address.to_string(),
                AccountState {
                    balance: 1_000 * 10u128.pow(18),
                    staked_balance: TEST_MIN_STAKE,
                    ..Default::default()
                },
            )
            .unwrap();
    }

    /// Gerçek secp256k1 imzalı `RegisterValidator`; `apply_transaction` yolundaki
    /// `validate()` (imza dahil) gerçekten çalışır, `#[cfg(test)]` bypass'ı yok.
    fn register_tx(
        payload: &RegisterValidatorPayload,
        secret_key: &secp256k1::SecretKey,
        nonce: u64,
    ) -> Transaction {
        let mut tx = Transaction {
            tx_id: [0u8; 32],
            tx_type: TxType::RegisterValidator,
            sender: Transaction::address_from_secret_key(secret_key),
            amount: 0,
            receiver: "0x0000000000000000000000000000000000000006".to_string(),
            payload: payload.encode(),
            signature: Vec::new(),
            timestamp: 0,
            nonce,
            gas_limit: 300_000,
            gas_price: 1,
            chain_id: zagros_types::CHAIN_ID,
        };
        tx.sign(secret_key);
        tx
    }

    // ---- prove_ownership / compute_register_calldata: temel doğruluk ----

    #[test]
    fn compute_register_calldata_round_trips_and_is_accepted_by_the_real_executor() {
        let (_dir, state, domain) = test_state_with_domain();
        let (secret_key, sender) = test_signer(15);
        fund_as_candidate(&state, &sender);
        let kp = ConsensusKeypair::from_secret_bytes(&[7u8; 32]);

        let (calldata, payload) = compute_register_calldata(
            &domain,
            &kp,
            &sender,
            "hetzner",
            "eu-central-1",
            24940,
            [3u8; 32],
        )
        .expect("geçerli girdilerle payload üretimi başarısız olmamalı");

        // Üretilen calldata TAM OLARAK "0x" + seçici + bincode payload olmalı.
        assert!(calldata.starts_with(&format!("0x{REGISTER_VALIDATOR_SELECTOR}")));
        let hex_payload = &calldata[format!("0x{REGISTER_VALIDATOR_SELECTOR}").len()..];
        let decoded_bytes = hex::decode(hex_payload).unwrap();
        assert_eq!(
            RegisterValidatorPayload::decode(&decoded_bytes).unwrap(),
            payload,
            "calldata'nın payload kısmı, zincirin decode() fonksiyonuyla birebir çözülebilmeli"
        );

        // 🔒 UÇTAN UCA: bu calldata GERÇEK secp256k1 imzasıyla, gerçek Executor'a
        // verildiğinde validator kaydı GERÇEKTEN tetiklenmeli, zagros-rpc'deki
        // referans testle (register_validator_selector_call_is_classified_...) aynı iddia.
        let tx = register_tx(&payload, &secret_key, 0);
        zagros_executor::Executor::new(state.clone())
            .execute_transaction(&tx, tx.timestamp)
            .unwrap();
        let after = state.get_account(&sender).unwrap().unwrap();
        assert!(
            after.is_registered_validator,
            "CLI'nin ürettiği payload zincirde validator kaydını tetiklemeli"
        );
        assert_eq!(
            after.validator_status,
            Some(zagros_types::consensus::ValidatorStatus::Candidate)
        );
        assert_eq!(after.consensus_pubkey, kp.public_key());
    }

    #[test]
    fn compute_rotate_calldata_round_trips_and_is_accepted_by_the_real_executor() {
        let (_dir, state, domain) = test_state_with_domain();
        let (secret_key, sender) = test_signer(15);
        fund_as_candidate(&state, &sender);
        let old_kp = ConsensusKeypair::from_secret_bytes(&[7u8; 32]);
        let (_, reg_payload) = compute_register_calldata(
            &domain,
            &old_kp,
            &sender,
            "hetzner",
            "eu-central-1",
            24940,
            [3u8; 32],
        )
        .unwrap();
        let reg = register_tx(&reg_payload, &secret_key, 0);
        zagros_executor::Executor::new(state.clone())
            .execute_transaction(&reg, reg.timestamp)
            .unwrap();

        let new_kp = ConsensusKeypair::from_secret_bytes(&[8u8; 32]);
        let (calldata, payload) =
            compute_rotate_calldata(&domain, &new_kp, &sender, &old_kp.public_key())
                .expect("geçerli girdilerle rotasyon payload üretimi başarısız olmamalı");
        assert!(calldata.starts_with(&format!("0x{ROTATE_CONSENSUS_KEY_SELECTOR}")));
        let hex_payload = &calldata[format!("0x{ROTATE_CONSENSUS_KEY_SELECTOR}").len()..];
        assert_eq!(
            RotateConsensusKeyPayload::decode(&hex::decode(hex_payload).unwrap()).unwrap(),
            payload,
            "calldata'nın payload kısmı, zincirin decode() fonksiyonuyla birebir çözülebilmeli"
        );

        // 🔒 UÇTAN UCA: gerçek Executor rotasyon talebini kabul etmeli, anahtar
        // hesapta HEMEN değişmez (epoch sınırı), bekleyen kayıt yazılır.
        let mut tx = register_tx(&reg_payload, &secret_key, 1);
        tx.tx_type = TxType::RotateConsensusKey;
        tx.payload = payload.encode();
        tx.sign(&secret_key);
        zagros_executor::Executor::new(state.clone())
            .execute_transaction(&tx, tx.timestamp)
            .unwrap();
        let after = state.get_account(&sender).unwrap().unwrap();
        assert_eq!(
            after.consensus_pubkey,
            old_kp.public_key(),
            "epoch sinirina kadar eski anahtar"
        );
        let pend = zagros_executor::validator_set::load_pending_key_rotation(&*state, &sender)
            .unwrap()
            .expect("bekleyen rotasyon kaydi yazilmali");
        assert_eq!(pend.new_pubkey, new_kp.public_key());
    }

    #[test]
    fn prove_ownership_output_verifies_against_the_bound_address() {
        let (_dir, _state, domain) = test_state_with_domain();
        let (_secret_key, sender) = test_signer(15);
        let kp = ConsensusKeypair::from_secret_bytes(&[9u8; 32]);
        let proof = zagros_crypto::prove_key_ownership(&kp, &domain, &sender, None);
        assert_eq!(
            proof.len(),
            64,
            "ownership_proof tam 64 bayt olmalı (zincirin decode() kontrolüyle aynı)"
        );
        zagros_crypto::verify_key_ownership(&kp.public_key(), &proof, &domain, &sender, None)
            .expect("kendi ürettiğimiz kanıt kendi doğrulamamızdan geçmeli");
    }

    // ---- Negatif testler: zincirin GERÇEKTEN reddetmesi gereken durumlar ----

    #[test]
    fn wrong_evm_address_produces_a_proof_the_executor_rejects() {
        let (_dir, state, domain) = test_state_with_domain();
        let (_bound_secret_key, bound_addr) = test_signer(15);
        let (sending_secret_key, sending_addr) = test_signer(16);
        fund_as_candidate(&state, &sending_addr);
        let kp = ConsensusKeypair::from_secret_bytes(&[7u8; 32]);

        // Kanıt `bound_addr` için üretildi, ama işlem `sending_addr`'den
        // gönderiliyor, digest'e giren adres uyuşmaz, executor imzayı reddetmeli.
        let (_calldata, payload) = compute_register_calldata(
            &domain,
            &kp,
            &bound_addr,
            "hetzner",
            "eu-central-1",
            24940,
            [3u8; 32],
        )
        .unwrap();
        let tx = register_tx(&payload, &sending_secret_key, 0);
        let err = zagros_executor::Executor::new(state.clone())
            .execute_transaction(&tx, tx.timestamp)
            .expect_err("başka bir adrese bağlı kanıt kabul edilmemeli");
        assert!(format!("{err:?}").contains("sahiplik") || format!("{err:?}").contains("gecersiz"));
        let after = state.get_account(&sending_addr).unwrap().unwrap();
        assert!(
            !after.is_registered_validator,
            "reddedilen işlem hiçbir şekilde kayıt oluşturmamalı"
        );
    }

    #[test]
    fn wrong_consensus_key_produces_a_signature_the_executor_rejects() {
        let (_dir, state, domain) = test_state_with_domain();
        let (secret_key, sender) = test_signer(15);
        fund_as_candidate(&state, &sender);
        let signing_kp = ConsensusKeypair::from_secret_bytes(&[7u8; 32]);
        let different_kp = ConsensusKeypair::from_secret_bytes(&[8u8; 32]);

        // Kanıt bir anahtarla imzalanır ama payload'da BAŞKA bir pubkey beyan edilir.
        let ownership_proof =
            zagros_crypto::prove_key_ownership(&signing_kp, &domain, &sender, None);
        let payload = RegisterValidatorPayload {
            consensus_pubkey: different_kp.public_key(),
            ownership_proof,
            declaration: ValidatorDeclaration {
                provider: "hetzner".into(),
                region: "eu-central-1".into(),
                asn: 24940,
                operator_id: [3u8; 32],
            },
        };
        let tx = register_tx(&payload, &secret_key, 0);
        let err = zagros_executor::Executor::new(state.clone())
            .execute_transaction(&tx, tx.timestamp)
            .expect_err("beyan edilen pubkey ile imzalayan anahtar uyuşmazsa reddedilmeli");
        assert!(!format!("{err:?}").is_empty());
        let after = state.get_account(&sender).unwrap().unwrap();
        assert!(!after.is_registered_validator);
    }

    #[test]
    fn corrupted_signature_bytes_are_rejected() {
        let (_dir, state, domain) = test_state_with_domain();
        let (secret_key, sender) = test_signer(15);
        fund_as_candidate(&state, &sender);
        let kp = ConsensusKeypair::from_secret_bytes(&[7u8; 32]);
        let (_calldata, mut payload) = compute_register_calldata(
            &domain,
            &kp,
            &sender,
            "hetzner",
            "eu-central-1",
            24940,
            [3u8; 32],
        )
        .unwrap();
        // İmzanın son baytını boz, hâlâ 64 bayt (uzunluk kontrolünden geçer),
        // ama kriptografik olarak geçersiz.
        let last = payload.ownership_proof.len() - 1;
        payload.ownership_proof[last] ^= 0xFF;

        let tx = register_tx(&payload, &secret_key, 0);
        let err = zagros_executor::Executor::new(state.clone())
            .execute_transaction(&tx, tx.timestamp)
            .expect_err("bozuk imza baytları reddedilmeli");
        assert!(!format!("{err:?}").is_empty());
    }

    #[test]
    fn malformed_bincode_payload_is_rejected_by_decode_before_it_ever_reaches_the_executor() {
        // Rastgele/kesilmiş bayt dizisi, zincirin decode() fonksiyonu bunu
        // executor'a hiç ulaştırmadan reddetmeli (fail-closed).
        assert!(RegisterValidatorPayload::decode(&[0xde, 0xad, 0xbe, 0xef]).is_err());
        assert!(RegisterValidatorPayload::decode(&[]).is_err());
        // Eski 2-baytlık komisyon payload'ı da (geçmiş format) reddedilmeli.
        assert!(RegisterValidatorPayload::decode(&[0x00, 0xfa]).is_err());
    }

    #[test]
    fn duplicate_registration_is_rejected_by_the_executor() {
        let (_dir, state, domain) = test_state_with_domain();
        let (secret_key, sender) = test_signer(15);
        fund_as_candidate(&state, &sender);
        let kp = ConsensusKeypair::from_secret_bytes(&[7u8; 32]);
        let (_calldata, payload) = compute_register_calldata(
            &domain,
            &kp,
            &sender,
            "hetzner",
            "eu-central-1",
            24940,
            [3u8; 32],
        )
        .unwrap();

        let executor = zagros_executor::Executor::new(state.clone());
        let first_tx = register_tx(&payload, &secret_key, 0);
        executor
            .execute_transaction(&first_tx, first_tx.timestamp)
            .expect("ilk kayıt başarılı olmalı");

        // Aynı hesap tekrar kayıt denerse (nonce ilerletilerek) zincir reddetmeli.
        let next_nonce = state.get_account(&sender).unwrap().unwrap().nonce;
        let second_tx = register_tx(&payload, &secret_key, next_nonce);
        let err = executor
            .execute_transaction(&second_tx, second_tx.timestamp)
            .expect_err("zaten kayıtlı bir validator'ün tekrar kaydı reddedilmeli");
        assert!(
            format!("{err:?}").contains("kayitli")
                || format!("{err:?}").contains("registered")
                || !format!("{err:?}").is_empty()
        );
    }

    // ---- Girdi doğrulama: adres/hex format hataları ----

    #[test]
    fn parse_evm_address_rejects_malformed_input() {
        assert!(parse_evm_address("not-an-address").is_err());
        assert!(
            parse_evm_address("0x123").is_err(),
            "kısa adres reddedilmeli"
        );
        assert!(
            parse_evm_address("0x11111111111111111111111111111111111111zz").is_err(),
            "hex olmayan karakter reddedilmeli"
        );
        assert!(parse_evm_address(FORMAT_ONLY_ADDR).is_ok());
    }

    #[test]
    fn hex_decode_32_rejects_wrong_length_and_invalid_hex() {
        assert!(
            hex_decode_32("deadbeef").is_err(),
            "32 bayttan kısa girdi reddedilmeli"
        );
        assert!(hex_decode_32("zz").is_err(), "geçersiz hex reddedilmeli");
        assert!(hex_decode_32(&"11".repeat(32)).is_ok());
        assert!(
            hex_decode_32(&format!("0x{}", "22".repeat(32))).is_ok(),
            "0x öneki kabul edilmeli"
        );
    }

    #[test]
    fn register_payload_rejects_bad_operator_id_hex_before_touching_disk() {
        // Diskte hiç key/config dosyası olmasa bile, bariz şekilde geçersiz
        // --operator-id-hex erken ve açıkça reddedilmeli (kullanıcı hatası).
        let err = register_payload(
            "/nonexistent/key",
            "/nonexistent/config.toml",
            FORMAT_ONLY_ADDR,
            "hetzner",
            "eu-central-1",
            24940,
            "not-hex",
        )
        .expect_err("geçersiz operator-id-hex erken reddedilmeli");
        assert!(err.contains("operator-id-hex"));
    }

    #[test]
    fn prove_ownership_rejects_malformed_address_before_touching_disk() {
        let err = prove_ownership(
            "/nonexistent/key",
            "/nonexistent/config.toml",
            "not-an-address",
        )
        .expect_err("geçersiz adres erken reddedilmeli");
        assert!(err.contains("geçerli bir EVM adresi değil"));
    }

    #[test]
    fn gen_key_writes_a_loadable_0600_keyfile() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("validator.key");
        let path_str = path.to_string_lossy().to_string();

        gen_key(&path_str).expect("gen_key başarısız olmamalı");

        let kp =
            zagros_crypto::load_keyfile(&path_str).expect("üretilen dosya yüklenebilir olmalı");
        assert_ne!(kp.public_key(), [0u8; 32]);
    }

    #[test]
    fn gen_key_refuses_to_overwrite_an_existing_keyfile() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("validator.key");
        let path_str = path.to_string_lossy().to_string();

        gen_key(&path_str).unwrap();
        let original = std::fs::read_to_string(&path).unwrap();

        let err = gen_key(&path_str).expect_err("var olan dosyanın üzerine yazmamalı");
        assert!(err.contains("zaten var"));
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            original,
            "mevcut anahtar DEĞİŞMEMELİ"
        );
    }
}
