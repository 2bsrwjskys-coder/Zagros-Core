// Zagros Relayer, Giden Akış: Zagros burn → off-chain unlock-intent önerisi
// (BridgeTxType::Burn, koordinasyon verisi) → haberciler Ed25519 ile 2-of-3
// imzalar → eşik + zaman kilidi sonrası her haberci EIP-712 claim fişi üretip
// `zagros_submitClaimVoucher` ile düğüme bırakır → kullanıcı fişleri alıp
// `claimTokens`ı KENDİ gas'ıyla çağırır.
// 🚨 HABERCİLER ETHEREUM'A İŞLEM GÖNDERMEZ (merkezi ETH cüzdanı gerekmesin);
// atanmış sunucu, liveness fallback, `submit_unlock` YOKTUR. Çift çekim
// koruması zincirde (`processedHashes`).

use crate::store::{RelayerStore, RetryOutcome};
use crate::zagros_client::{ClientError, ZagrosClient};
use ed25519_dalek::SigningKey;
use ethers_core::types::{Address as EthAddress, H256, U256};
use secp256k1::SecretKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zagros_executor::bridge::{BridgeManager, BridgeProposal, BridgeSignature, BridgeTxType};

/// item 13: yeniden deneme kuyruğuna konan bir burn'ü tekrar `handle_new_burn`
/// ile işleyebilmek için gereken minimum veri, `zagros_watcher::BurnRecord`'un
/// bincode ile serileştirilebilen, kuyruğa özgü alt kümesi.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BurnRetryPayload {
    tx_id_hex: String,
    sender: String,
    amount: u128,
}

/// İki ayrı adres uzayı: Ed25519 / Zagros yetkilisi (`BridgeManager` önerilerini
/// imzalar, adres pubkey keccak'ından) ve secp256k1 / Ethereum imzacısı (claim
/// fişlerini imzalar, Gateway `isRelayer` kümesinde; işlem göndermez, ETH gerekmez).
pub struct OutboundRelayer {
    pub client: ZagrosClient,
    pub store: RelayerStore,
    pub zagros_signing_key: SigningKey,
    pub zagros_authority_address: String,
    pub ethereum_signing_key: SecretKey,
    pub ethereum_relayer_address: EthAddress,
    pub gateway_contract_address: EthAddress,
    pub unlock_token_address: EthAddress,
    /// Hedef ERC20 ondalığı (PAXG = 18); dijeste ölçeklenmiş tutar girer, düğümle aynı olmalı.
    pub unlock_token_decimals: u32,
    /// Ethereum zincir kimliği (mainnet = 1), EIP-712 domain'i için.
    /// Aşağıdaki `chain_id` (Zagros) ile KARIŞTIRILMAMALIDIR.
    pub ethereum_chain_id: u64,
    /// Zagros zincir kimliği, öneri imzalama mesajına girer.
    pub chain_id: u64,
    /// 🛡️ Güvenilen yetkili kümesi + eşik, config'ten (dev seed'den değil); imzalar yalnız buna karşı doğrulanır.
    pub trusted_authorities: BridgeManager,
    /// Cursor gap'te otomatik kurtarma; varsayılan kapalı (yalnız ERROR + operatör müdahalesi).
    pub auto_recover_cursor_gap: bool,
}

impl OutboundRelayer {
    /// Burn kaydını unlock-intent önerisine çevirir ve kendi onayını ekler;
    /// işlenmiş burn için `Ok(None)`. Burn'ü yapan Zagros adresi doğrudan Ethereum alıcısıdır.
    pub async fn handle_new_burn(
        &self,
        burn_tx_id_hex: &str,
        burn_sender: &str,
        burn_amount: u128,
        now_unix_secs: u64,
    ) -> Result<Option<String>, ClientError> {
        let tx_id_bytes = decode_burn_tx_id(burn_tx_id_hex).ok_or_else(|| {
            ClientError::UnexpectedShape(format!("bad burn tx_id: {}", burn_tx_id_hex))
        })?;

        if self
            .store
            .is_zagros_burn_handled(&tx_id_bytes)
            .unwrap_or(false)
        {
            return Ok(None);
        }

        let proposal_id = self
            .client
            .propose_bridge_action(
                &self.zagros_signing_key,
                &self.zagros_authority_address,
                BridgeTxType::Burn,
                burn_sender,
                burn_amount,
                "Zagros",
                burn_tx_id_hex,
                now_unix_secs,
                false,
                // Burn/unlock-intent yönünde slippage kavramı yok, yalnızca
                // BridgeMintAndSwap (giriş yönü) için anlamlı.
                0,
                self.chain_id,
            )
            .await?;

        self.store
            .mark_zagros_burn_handled(&tx_id_bytes)
            .map_err(|e| ClientError::Transport(e.to_string()))?;

        self.sign_zagros_proposal(&proposal_id, now_unix_secs)
            .await?;

        Ok(Some(proposal_id))
    }

    /// Bir öneriyi sunucudan geri okuyup kendi Ed25519 onayımızı ekler,
    /// `inbound::InboundRelayer::sign_proposal_by_id` ile aynı desen.
    pub async fn sign_zagros_proposal(
        &self,
        proposal_id_hex: &str,
        now_unix_secs: u64,
    ) -> Result<bool, ClientError> {
        let proposal_json = self.client.get_bridge_proposal(proposal_id_hex).await?;
        let message =
            signing_message_from_json(&proposal_json, self.chain_id).ok_or_else(|| {
                ClientError::UnexpectedShape(format!(
                    "cannot reconstruct signing message from {:?}",
                    proposal_json
                ))
            })?;

        self.client
            .sign_bridge_proposal(
                &self.zagros_signing_key,
                &self.zagros_authority_address,
                proposal_id_hex,
                &message,
                now_unix_secs,
            )
            .await
    }

    /// Bekleyen burn önerilerini tarayıp imzalar; "already signed" zararsız (idempotent).
    pub async fn discover_and_cosign_pending_unlocks(&self, now_unix_secs: u64) -> usize {
        let pending = match self.client.get_pending_bridge_proposals().await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("Bekleyen öneriler alınamadı: {}", e);
                return 0;
            }
        };

        let mut newly_signed = 0;
        for proposal_json in &pending {
            if proposal_json.get("tx_type").and_then(|v| v.as_str()) != Some("burn") {
                continue;
            }
            let Some(proposal_id) = proposal_json.get("proposal_id").and_then(|v| v.as_str())
            else {
                continue;
            };
            let Some(message) = signing_message_from_json(proposal_json, self.chain_id) else {
                continue;
            };

            // 🔇 Kendi imzamız zaten varsa deneme (bkz. inbound'daki eşleniği):
            // her taramada reddedilen bir istek göndermek düğüm log'unu
            // doldurup gerçek hataları görünmez kılıyordu.
            if crate::inbound::already_signed_by(proposal_json, &self.zagros_authority_address) {
                continue;
            }

            match self
                .client
                .sign_bridge_proposal(
                    &self.zagros_signing_key,
                    &self.zagros_authority_address,
                    proposal_id,
                    &message,
                    now_unix_secs,
                )
                .await
            {
                Ok(_) => newly_signed += 1,
                Err(ClientError::Rpc { message, .. })
                    if message.to_lowercase().contains("already signed") => {}
                Err(e) => tracing::warn!("Öneri imzalanamadı (0x{}): {}", proposal_id, e),
            }
        }
        newly_signed
    }

    /// Eşik ve kilidi geçmiş burn önerileri için EIP-712 fişi üretir (saf, göndermez);
    /// RPC beyanına güvenmez, imzalar kendi kümesine karşı doğrulanır.
    pub fn build_claim_vouchers(&self, pending: &[Value], now_unix_secs: u64) -> Vec<ReadyVoucher> {
        // 🔒 Relayer'ın kendi güvendiği küme + eşik CONFIG'ten; ele geçirilmiş
        // node sahte `signers` üretse bile geçerli Ed25519 imzası uyduramaz.
        let trusted = &self.trusted_authorities;
        let mut prepared = Vec::new();

        for proposal_json in pending {
            if proposal_json.get("tx_type").and_then(|v| v.as_str()) != Some("burn") {
                continue;
            }

            // RPC'nin can_execute/signers beyanına GÜVENME: tam öneriyi (imzalar
            // dahil) yeniden inşa edip imzaları bağımsız doğrula.
            let Some(proposal) = proposal_with_signatures_from_json(proposal_json) else {
                continue;
            };

            let valid = trusted.count_valid_authority_signatures(&proposal);
            if valid < trusted.required_signatures() {
                tracing::warn!(
                    target: "security::bridge",
                    "K1: bağımsız imza doğrulaması eşiği geçmedi (geçerli {}/{}), unlock ATLANIYOR: 0x{}",
                    valid,
                    trusted.required_signatures(),
                    hex::encode(proposal.proposal_id)
                );
                continue;
            }

            // Zaman kilidini bağımsız doğrula: öneri bu andan itibaren
            // yürütülebilir (executable) olur.
            let executable_at = proposal.timestamp.saturating_add(trusted.timelock_period());
            if now_unix_secs < executable_at {
                continue;
            }

            // amount/recipient/source_tx_hash create_signing_message tarafından
            // hash'lendiği için, yukarıdaki 2-of-3 doğrulaması bunları da
            // kriptografik olarak bağlar. Bu yüzden doğrulanmış proposal'dan okuyoruz.
            let proposal_id_hex = format!("0x{}", hex::encode(proposal.proposal_id));
            // Bu relayer'ın kendi (yerel) idempotency kaydı, fişimi zaten
            // bıraktıysam tekrar üretme. Düğüm tarafı da idempotent, bu yalnızca
            // gereksiz ağ trafiğini önler.
            if self
                .store
                .is_unlock_submitted(&proposal_id_hex)
                .unwrap_or(false)
            {
                continue;
            }

            let (Some(recipient), Some(zagros_tx_hash)) = (
                parse_eth_address(&proposal.recipient),
                parse_h256(&proposal.source_tx_hash),
            ) else {
                continue;
            };

            // 🔢 ZERENYA (18) → hedef ERC20 ondalığı; kontrata giden tutar dijeste
            // girer, düğüm aynı paylaşılan fonksiyonla doğrular. Ölçeklenmiş tutar 0
            // ise fiş üretilmez (kontrat revert eder, kullanıcı gas yakar); anomali loglanır.
            let Some(scaled) = zagros_types::bridge_amount::scale_zerenya_to_token(
                proposal.amount,
                self.unlock_token_decimals,
            ) else {
                tracing::error!(
                    target: "security::bridge",
                    "🛑 Çekim tutarı {} ham ZERENYA, {}-ondalıklı token'da SIFIRA ölçekleniyor - \
                     fiş üretilmedi (öneri {}). Yakılan ZERENYA geri alınamaz; asgari yakma \
                     tutarı kuralı gerekiyor.",
                    proposal.amount,
                    self.unlock_token_decimals,
                    proposal_id_hex
                );
                continue;
            };

            if scaled.dust > 0 {
                tracing::warn!(
                    "🔢 Çekim aşağı yuvarlandı: {} ham ZERENYA → {} token birimi ({} ham ZERENYA artık, \
                     ödenmiyor) - öneri {}",
                    proposal.amount,
                    scaled.token_amount,
                    scaled.dust,
                    proposal_id_hex
                );
            }

            let digest = crate::claim::claim_digest(
                self.ethereum_chain_id,
                self.gateway_contract_address,
                self.unlock_token_address,
                recipient,
                U256::from(scaled.token_amount),
                zagros_tx_hash,
            );
            let signature = crate::claim::sign_claim(&self.ethereum_signing_key, digest);

            prepared.push(ReadyVoucher {
                proposal_id: proposal_id_hex,
                voucher: crate::claim::ClaimVoucher {
                    zagros_tx_hash,
                    token: self.unlock_token_address,
                    recipient,
                    amount: U256::from(scaled.token_amount),
                    signer: self.ethereum_relayer_address,
                    signature,
                },
            });
        }

        prepared
    }

    /// Üretilen fişleri düğüme bırakır. Her fiş bağımsızdır; biri reddedilirse
    /// diğerleri denenmeye devam eder (bir önerideki sorun tüm turu düşürmemeli).
    pub async fn submit_claim_vouchers(&self, ready: &[ReadyVoucher]) {
        for item in ready {
            match self
                .client
                .submit_claim_voucher(&item.proposal_id, &item.voucher.signature_hex())
                .await
            {
                Ok(collected) => {
                    // Yerel idempotency: bu öneri için fişimi bıraktım.
                    let _ = self.store.mark_unlock_submitted(&item.proposal_id);
                    tracing::info!(
                        "🎟️ Claim fişi bırakıldı (öneri {} → düğümde toplam {} fiş)",
                        item.proposal_id,
                        collected
                    );
                }
                Err(e) => tracing::warn!("claim fişi bırakılamadı ({}): {}", item.proposal_id, e),
            }
        }
    }

    /// Tek outbound turu, ağ hatasında panik yok: 1) yeni burn'leri tara
    /// (cursor gap fail-closed), başarısızlar yeniden deneme kuyruğuna; 2) zamanı
    /// gelen yeniden denemeler; 3) bekleyen unlock önerilerini eş imzala.
    pub async fn poll_once(&self, cursor: &mut u128, now_unix_secs: u64) {
        // 1. Yeni burn'leri tara.
        match self.client.get_recent_bridge_burns(*cursor).await {
            Ok(resp) => match crate::zagros_watcher::parse_burns_response(&resp, *cursor) {
                Ok(records) => {
                    // Her kayıt bağımsız denenir; başarısız index'ler toplanıp
                    // `next_cursor_after_partial_failure` güvenli imleci hesaplar.
                    let mut failed_indices = Vec::new();
                    for r in &records {
                        if let Err(e) = self
                            .handle_new_burn(&r.tx_id_hex, &r.sender, r.amount, now_unix_secs)
                            .await
                        {
                            tracing::warn!("burn işlenemedi ({}): {}", r.tx_id_hex, e);
                            failed_indices.push(r.index);

                            // Ayrıca yeniden deneme kuyruğuna al: sonraki kayıt
                            // yığılsa bile bu burn üstel geri çekilmeyle bağımsız
                            // denenir; `handle_new_burn` idempotent, çift işlem yok.
                            let payload = BurnRetryPayload {
                                tx_id_hex: r.tx_id_hex.clone(),
                                sender: r.sender.clone(),
                                amount: r.amount,
                            };
                            match bincode::serialize(&payload) {
                                Ok(bytes) => {
                                    if let Err(enqueue_err) =
                                        self.store.enqueue_retry(&r.tx_id_hex, bytes, now_unix_secs)
                                    {
                                        tracing::warn!(
                                            "burn yeniden deneme kuyruğuna eklenemedi ({}): {}",
                                            r.tx_id_hex,
                                            enqueue_err
                                        );
                                    }
                                }
                                Err(e) => tracing::warn!(
                                    "burn retry payload'u serileştirilemedi ({}): {}",
                                    r.tx_id_hex,
                                    e
                                ),
                            }
                        }
                    }
                    *cursor = crate::zagros_watcher::next_cursor_after_partial_failure(
                        *cursor,
                        &records,
                        &failed_indices,
                    );
                    // İmleç yalnız tur sonunda kalıcılaşır; persist hatası yok
                    // sayılır, en kötü restart eski imleçten devam eder (idempotent).
                    if let Err(e) = self.store.set_outbound_cursor(*cursor) {
                        tracing::warn!("outbound cursor kalıcı hale getirilemedi: {}", e);
                    }
                }
                Err(gap) => {
                    if self.auto_recover_cursor_gap {
                        // Opt-in kurtarma: budanmış aralık bu relayer için kalıcı
                        // atlanır, yedekli relayer'lara güvenilir.
                        *cursor = gap.oldest_available_index;
                        if let Err(e) = self.store.set_outbound_cursor(*cursor) {
                            tracing::error!(
                                target: "security::bridge",
                                "🛑 CURSOR GAP: {} — auto_recover_cursor_gap=true ile imleç {}'e \
                                 ilerletildi AMA kalıcı hale getirilemedi ({}); bir restart eski \
                                 imleçten aynı boşluğa TEKRAR takılabilir.",
                                gap, gap.oldest_available_index, e
                            );
                        } else {
                            tracing::error!(
                                target: "security::bridge",
                                "🛑 CURSOR GAP (OTOMATİK KURTARILDI): {} — auto_recover_cursor_gap=true \
                                 olduğu için imleç {}'e ilerletildi; [{}, {}) aralığındaki burn'ler bu \
                                 relayer için KALICI OLARAK atlandı. Yedekli relayer'ların bu aralığı \
                                 kapsadığından emin olun.",
                                gap, gap.oldest_available_index, gap.requested_since_index, gap.oldest_available_index
                            );
                        }
                    } else {
                        // 🛡️ [7]: FAIL-CLOSED (varsayılan), imleci İLERLETME, sessizce atlama.
                        tracing::error!(
                            target: "security::bridge",
                            "🛑 CURSOR GAP: {} — re-sync/alarm gerekli; imleç ilerletilmiyor \
                             (auto_recover_cursor_gap=false, fail-closed). Manuel kurtarma için: \
                             `cursor_recover show --config <relayer.toml>` ile mevcut durumu inceleyip \
                             `cursor_recover set-outbound-cursor --cursor {} --config <relayer.toml>` \
                             çalıştırın (operatör onayı gerektirir).",
                            gap,
                            gap.oldest_available_index
                        );
                    }
                }
            },
            Err(e) => tracing::warn!("recent bridge burns alınamadı: {}", e),
        }

        // 2. item 13: daha önce başarısız olup yeniden deneme kuyruğuna
        //    alınmış burn'leri, zamanı gelenler için tekrar dene.
        match self.store.due_retries(now_unix_secs) {
            Ok(due) => {
                for entry in due {
                    let Ok(payload) = bincode::deserialize::<BurnRetryPayload>(&entry.payload)
                    else {
                        tracing::warn!("bozuk burn retry payload'u (id={}), atlanıyor", entry.id);
                        continue;
                    };
                    match self
                        .handle_new_burn(
                            &payload.tx_id_hex,
                            &payload.sender,
                            payload.amount,
                            now_unix_secs,
                        )
                        .await
                    {
                        Ok(_) => {
                            // Ok(None) da başarı: doğal keşif önce işlemiş olabilir (idempotent).
                            if let Err(e) = self.store.remove_retry(&entry.id) {
                                tracing::warn!(
                                    "retry kuyruğundan kaldırılamadı ({}): {}",
                                    entry.id,
                                    e
                                );
                            }
                        }
                        Err(e) => {
                            tracing::warn!("burn yeniden denemesi başarısız ({}): {}", entry.id, e);
                            match self.store.reschedule_retry(&entry, now_unix_secs) {
                                Ok(RetryOutcome::DeadLettered) => tracing::error!(
                                    target: "security::bridge",
                                    "🛑 burn {} maksimum yeniden deneme sayısını aştı, \
                                     dead-letter'a taşındı - operatör incelemesi gerekiyor.",
                                    entry.id
                                ),
                                Ok(RetryOutcome::Rescheduled) => {}
                                Err(store_err) => tracing::warn!(
                                    "retry yeniden zamanlanamadı ({}): {}",
                                    entry.id,
                                    store_err
                                ),
                            }
                        }
                    }
                }
            }
            Err(e) => tracing::warn!("yeniden deneme kuyruğu okunamadı: {}", e),
        }

        // 3. Bekleyen unlock önerilerini co-sign et.
        self.discover_and_cosign_pending_unlocks(now_unix_secs)
            .await;

        // 4. Hazır çekimler için claim fişi üret ve düğüme bırak.
        //    Ethereum bağlantısı GEREKMEZ, fiş üretimi tamamen zincir dışıdır.
        let pending = self
            .client
            .get_pending_bridge_proposals()
            .await
            .unwrap_or_default();
        let ready = self.build_claim_vouchers(&pending, now_unix_secs);
        if !ready.is_empty() {
            self.submit_claim_vouchers(&ready).await;
        }
    }

    /// 🌉 FAZ4: Graceful-shutdown destekli outbound döngüsü.
    pub async fn run_loop(
        &self,
        poll_interval_secs: u64,
        mut cancel: tokio::sync::watch::Receiver<bool>,
    ) {
        // F-outbound-cursor: önce kalıcı imleci oku (yoksa/bozuksa 0'dan
        // başlar), artık her restart'ta baştan taramıyoruz.
        let mut cursor: u128 = self.store.get_outbound_cursor().unwrap_or(0);
        tracing::info!("🌉 Outbound tarama imleci {}'den devam ediyor.", cursor);
        let mut ticker =
            tokio::time::interval(std::time::Duration::from_secs(poll_interval_secs.max(1)));
        tracing::info!(
            "🌉 Outbound relayer döngüsü devrede (interval {}s). Ethereum bağlantısı \
             GEREKMEZ: haberci yalnızca zincir dışı claim fişi imzalar.",
            poll_interval_secs.max(1)
        );
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    self.poll_once(&mut cursor, crate::now_unix_secs()).await;
                }
                _ = cancel.changed() => {
                    if *cancel.borrow() {
                        break;
                    }
                }
            }
        }
        tracing::info!("🛑 Outbound relayer döngüsü durduruldu (graceful shutdown).");
    }
}

/// Bir öneri için üretilmiş, düğüme bırakılmaya hazır claim fişi.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadyVoucher {
    /// Fişin ait olduğu köprü önerisinin kimliği (0x, 32 bayt hex).
    pub proposal_id: String,
    pub voucher: crate::claim::ClaimVoucher,
}

fn decode_burn_tx_id(tx_id_hex: &str) -> Option<[u8; 32]> {
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(tx_id_hex.trim_start_matches("0x"), &mut bytes).ok()?;
    Some(bytes)
}

fn parse_eth_address(hex_str: &str) -> Option<EthAddress> {
    let stripped = hex_str.trim_start_matches("0x");
    let bytes = hex::decode(stripped).ok()?;
    if bytes.len() != 20 {
        return None;
    }
    Some(EthAddress::from_slice(&bytes))
}

fn parse_h256(hex_str: &str) -> Option<H256> {
    let stripped = hex_str.trim_start_matches("0x");
    let bytes = hex::decode(stripped).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    Some(H256::from_slice(&bytes))
}

/// RPC JSON'undan imzaları dahil TAM `BridgeProposal` inşa eder (relayer imzaları
/// bağımsız doğrulasın); zorunlu alan eksikse `None`. `inbound.rs`teki eşi
/// kasıtlı olarak paylaşılmıyor.
fn proposal_with_signatures_from_json(value: &Value) -> Option<BridgeProposal> {
    let proposal_id = decode_burn_tx_id(value.get("proposal_id")?.as_str()?)?;
    let tx_type = match value.get("tx_type")?.as_str()? {
        "mint" => BridgeTxType::Mint,
        "burn" => BridgeTxType::Burn,
        _ => return None,
    };
    let signatures = value
        .get("signatures")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(parse_bridge_signature_json).collect())
        .unwrap_or_default();

    Some(BridgeProposal {
        proposal_id,
        tx_type,
        amount: value.get("amount")?.as_str()?.parse().ok()?,
        recipient: value.get("recipient")?.as_str()?.to_string(),
        source_chain: value.get("source_chain")?.as_str()?.to_string(),
        source_tx_hash: value.get("source_tx_hash")?.as_str()?.to_string(),
        timestamp: value.get("timestamp")?.as_str()?.parse().ok()?,
        signatures,
        executed: value.get("executed")?.as_bool()?,
        nonce: value.get("nonce")?.as_str()?.parse().ok()?,
        auto_swap: value.get("auto_swap")?.as_bool()?,
        amount_out_min: value
            .get("amount_out_min")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        claim_vouchers: Vec::new(),
    })
}

fn parse_bridge_signature_json(value: &Value) -> Option<BridgeSignature> {
    Some(BridgeSignature {
        authority: value.get("authority")?.as_str()?.to_string(),
        signature: decode_hex_bytes(value.get("signature")?.as_str()?)?,
        public_key: decode_hex_bytes(value.get("public_key")?.as_str()?)?,
        timestamp: value.get("timestamp")?.as_str()?.parse().ok()?,
    })
}

fn decode_hex_bytes(hex_str: &str) -> Option<Vec<u8>> {
    hex::decode(hex_str.trim_start_matches("0x")).ok()
}

fn signing_message_from_json(value: &Value, chain_id: u64) -> Option<Vec<u8>> {
    let proposal_id = decode_burn_tx_id(value.get("proposal_id")?.as_str()?)?;
    let tx_type = match value.get("tx_type")?.as_str()? {
        "mint" => BridgeTxType::Mint,
        "burn" => BridgeTxType::Burn,
        _ => return None,
    };

    let reconstructed = BridgeProposal {
        proposal_id,
        tx_type,
        amount: value.get("amount")?.as_str()?.parse().ok()?,
        recipient: value.get("recipient")?.as_str()?.to_string(),
        source_chain: value.get("source_chain")?.as_str()?.to_string(),
        source_tx_hash: value.get("source_tx_hash")?.as_str()?.to_string(),
        timestamp: value.get("timestamp")?.as_str()?.parse().ok()?,
        signatures: Vec::new(),
        executed: value.get("executed")?.as_bool()?,
        nonce: value.get("nonce")?.as_str()?.parse().ok()?,
        auto_swap: value.get("auto_swap")?.as_bool()?,
        amount_out_min: value
            .get("amount_out_min")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        claim_vouchers: Vec::new(),
    };

    Some(BridgeManager::create_signing_message(
        &reconstructed,
        chain_id,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const TEST_TIMELOCK_SECS: u64 = 24 * 60 * 60;

    /// Default yetkililerle geçerli Ed25519 imzalı burn önerisi JSON'u.
    /// `can_execute` kasıtlı hep `true`: relayer buna güvenmeden doğrulamalı.
    fn signed_burn_proposal_json(num_valid_sigs: usize, timestamp: u64, nonce: u64) -> Value {
        use ed25519_dalek::Signer;

        let proposal = BridgeProposal {
            proposal_id: [0x01; 32],
            tx_type: BridgeTxType::Burn,
            amount: 1000,
            recipient: format!("0x{}", "02".repeat(20)),
            source_chain: "Zagros".to_string(),
            source_tx_hash: format!("0x{}", "03".repeat(32)),
            timestamp,
            signatures: Vec::new(),
            executed: false,
            nonce,
            auto_swap: false,
            amount_out_min: 0,
            claim_vouchers: Vec::new(),
        };
        let message = BridgeManager::create_signing_message(&proposal, zagros_types::CHAIN_ID);
        // 🛡️ FAZ4: imza, mesaj + imzanın kendi timestamp'ine bağlı türetilmiş
        // mesaj üzerinden atılır (count_valid_authority_signatures da öyle doğrular).
        let bound = BridgeManager::bind_timestamp_to_message(&message, timestamp);

        let signatures: Vec<Value> = (1..=num_valid_sigs as u8)
            .map(|seed| {
                let mut seed_bytes = [0u8; 32];
                seed_bytes[0] = seed;
                let sk = SigningKey::from_bytes(&seed_bytes);
                let pk = sk.verifying_key().to_bytes();
                let authority = BridgeManager::derive_address_from_public_key(&pk);
                let sig = sk.sign(&bound);
                json!({
                    "authority": authority,
                    "signature": format!("0x{}", hex::encode(sig.to_bytes())),
                    "public_key": format!("0x{}", hex::encode(pk)),
                    "timestamp": timestamp.to_string(),
                })
            })
            .collect();

        json!({
            "proposal_id": format!("0x{}", "01".repeat(32)),
            "tx_type": "burn",
            "amount": "1000",
            "recipient": format!("0x{}", "02".repeat(20)),
            "source_chain": "Zagros",
            "source_tx_hash": format!("0x{}", "03".repeat(32)),
            "timestamp": timestamp.to_string(),
            "nonce": nonce.to_string(),
            "executed": false,
            "auto_swap": false,
            "signatures": signatures,
            // `signers` alanı artık atanmış-sunucu seçimi için KULLANILMIYOR
            // (Ed25519 yetkili adresleri; adres-uzayı ayrımı). Seçim
            // relayer_eth_addresses + nonce'a dayanır.
            "signers": [],
            "can_execute": true,
        })
    }

    #[test]
    fn build_claim_vouchers_skips_when_independent_verification_finds_too_few_signatures() {
        let outbound = test_outbound_relayer();
        // Sadece 1 geçerli imza (eşik 2). Zaman kilidi geçmiş olsa bile atlanmalı.
        let pending = vec![signed_burn_proposal_json(1, 0, 3)];
        assert!(outbound
            .build_claim_vouchers(&pending, TEST_TIMELOCK_SECS + 10)
            .is_empty());
    }

    #[test]
    fn build_claim_vouchers_rejects_a_forged_can_execute_with_no_valid_signatures() {
        // 🔒 K1'in ASIL kanıtı: ele geçirilmiş bir RPC node'u can_execute:true +
        // bizi içeren signers uydursa AMA hiç geçerli imza olmasa, relayer yine de
        // GERÇEK unlockTokens() hazırlamamalı.
        let outbound = test_outbound_relayer();
        let forged = json!({
            "proposal_id": format!("0x{}", "01".repeat(32)),
            "tx_type": "burn",
            "amount": "1000",
            "recipient": format!("0x{}", "02".repeat(20)),
            "source_chain": "Zagros",
            "source_tx_hash": format!("0x{}", "03".repeat(32)),
            "timestamp": "0",
            "nonce": "7",
            "executed": false,
            "auto_swap": false,
            "signatures": [],                      // hiç geçerli imza yok
            "signers": [my_eth_address_str()],     // uydurma imzalayan listesi
            "can_execute": true,                   // uydurma yürütülebilir bayrağı
        });
        assert!(outbound
            .build_claim_vouchers(&[forged], TEST_TIMELOCK_SECS + 10)
            .is_empty());
    }

    #[test]
    fn build_claim_vouchers_rejects_signatures_from_non_authority_keys() {
        // Eşik kadar (2) imza VAR ama yetkili OLMAYAN anahtarlardan (seed 40,41).
        // Bağımsız doğrulama bunları güvendiği kümede bulamaz -> atlanır.
        use ed25519_dalek::Signer;
        let outbound = test_outbound_relayer();
        let proposal = BridgeProposal {
            proposal_id: [0x01; 32],
            tx_type: BridgeTxType::Burn,
            amount: 1000,
            recipient: format!("0x{}", "02".repeat(20)),
            source_chain: "Zagros".to_string(),
            source_tx_hash: format!("0x{}", "03".repeat(32)),
            timestamp: 0,
            signatures: Vec::new(),
            executed: false,
            nonce: 7,
            auto_swap: false,
            amount_out_min: 0,
            claim_vouchers: Vec::new(),
        };
        let message = BridgeManager::create_signing_message(&proposal, zagros_types::CHAIN_ID);
        let sigs: Vec<Value> = [40u8, 41u8]
            .iter()
            .map(|&seed| {
                let mut seed_bytes = [0u8; 32];
                seed_bytes[0] = seed;
                let sk = SigningKey::from_bytes(&seed_bytes);
                let pk = sk.verifying_key().to_bytes();
                let sig = sk.sign(&message);
                json!({
                    "authority": BridgeManager::derive_address_from_public_key(&pk),
                    "signature": format!("0x{}", hex::encode(sig.to_bytes())),
                    "public_key": format!("0x{}", hex::encode(pk)),
                    "timestamp": "0",
                })
            })
            .collect();
        let pending = vec![json!({
            "proposal_id": format!("0x{}", "01".repeat(32)),
            "tx_type": "burn",
            "amount": "1000",
            "recipient": format!("0x{}", "02".repeat(20)),
            "source_chain": "Zagros",
            "source_tx_hash": format!("0x{}", "03".repeat(32)),
            "timestamp": "0",
            "nonce": "7",
            "executed": false,
            "auto_swap": false,
            "signatures": sigs,
            "signers": [my_eth_address_str()],
            "can_execute": true,
        })];
        assert!(outbound
            .build_claim_vouchers(&pending, TEST_TIMELOCK_SECS + 10)
            .is_empty());
    }

    #[test]
    fn build_claim_vouchers_skips_before_the_timelock_elapses() {
        let outbound = test_outbound_relayer();
        // 2 geçerli imza ama zaman kilidi henüz dolmadı (now == timestamp).
        let now = 1_000u64;
        let pending = vec![signed_burn_proposal_json(2, now, 3)];
        assert!(outbound.build_claim_vouchers(&pending, now).is_empty());
    }

    #[test]
    fn build_claim_vouchers_skips_proposals_already_marked_submitted_locally() {
        let outbound = test_outbound_relayer();
        let proposal_id = format!("0x{}", "01".repeat(32));
        outbound.store.mark_unlock_submitted(&proposal_id).unwrap();

        let pending = vec![signed_burn_proposal_json(2, 0, 3)];
        assert!(outbound
            .build_claim_vouchers(&pending, TEST_TIMELOCK_SECS + 10)
            .is_empty());
    }

    fn my_eth_address_str() -> String {
        format!("0x{}", hex::encode(test_ethereum_address().as_bytes()))
    }

    fn test_ethereum_address() -> EthAddress {
        EthAddress::repeat_byte(0xAB)
    }
    fn test_outbound_relayer() -> OutboundRelayer {
        use std::collections::HashMap;
        use std::sync::{Arc, Mutex};
        use zagros_storage::Storage;

        #[derive(Default)]
        struct MemoryStorage {
            values: Mutex<HashMap<Vec<u8>, Vec<u8>>>,
        }
        impl Storage for MemoryStorage {
            fn get(&self, key: &[u8]) -> zagros_primitives::Result<Option<Vec<u8>>> {
                Ok(self.values.lock().unwrap().get(key).cloned())
            }
            fn put(&self, key: &[u8], value: &[u8]) -> zagros_primitives::Result<()> {
                self.values
                    .lock()
                    .unwrap()
                    .insert(key.to_vec(), value.to_vec());
                Ok(())
            }
            fn delete(&self, key: &[u8]) -> zagros_primitives::Result<()> {
                self.values.lock().unwrap().remove(key);
                Ok(())
            }
            fn contains(&self, key: &[u8]) -> zagros_primitives::Result<bool> {
                Ok(self.values.lock().unwrap().contains_key(key))
            }
            fn list_keys(&self) -> zagros_primitives::Result<Vec<Vec<u8>>> {
                Ok(self.values.lock().unwrap().keys().cloned().collect())
            }
        }

        OutboundRelayer {
            client: ZagrosClient::new("http://127.0.0.1:1".to_string()),
            store: RelayerStore::new(Arc::new(MemoryStorage::default())),
            zagros_signing_key: SigningKey::from_bytes(&[1u8; 32]),
            zagros_authority_address: "0x0000000000000000000000000000000000000001".to_string(),
            ethereum_signing_key: SecretKey::from_slice(&[9u8; 32]).unwrap(),
            ethereum_relayer_address: test_ethereum_address(),
            gateway_contract_address: EthAddress::repeat_byte(0xCC),
            unlock_token_address: EthAddress::repeat_byte(0xDD),
            chain_id: zagros_types::CHAIN_ID,
            unlock_token_decimals: 18,
            ethereum_chain_id: 1,
            // Testte dev seed'li kanonik küme meşrudur (imzalar da onunla üretiliyor).
            trusted_authorities: BridgeManager::default_bridge_manager(zagros_types::CHAIN_ID),
            auto_recover_cursor_gap: false,
        }
    }

    /// Outbound döngüsü iptal sinyaliyle temiz durmalı; ulaşılamaz RPC'de
    /// `poll_once` panik atmadan devam eder.
    #[tokio::test]
    async fn outbound_run_loop_stops_on_graceful_shutdown() {
        let relayer = std::sync::Arc::new(test_outbound_relayer());
        let (tx, rx) = tokio::sync::watch::channel(false);
        let handle = {
            let relayer = relayer.clone();
            tokio::spawn(async move { relayer.run_loop(1, rx).await })
        };

        // İlk tick hemen çalışır (dead RPC → warn, panik yok); sonra iptal gönder.
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        tx.send(true).unwrap();

        // Döngü, cancel'dan sonra derhal (bir sonraki tick'i beklemeden) dönmeli.
        let joined = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
        assert!(
            joined.is_ok(),
            "run_loop must return promptly after graceful cancel"
        );
        assert!(joined.unwrap().is_ok(), "loop task must not panic");
    }

    /// poll_once, ulaşılamaz RPC + köprü yokken bile panik atmadan tamamlanmalı.
    #[tokio::test]
    async fn outbound_poll_once_is_resilient_to_a_dead_rpc() {
        let relayer = test_outbound_relayer();
        let mut cursor = 0u128;
        relayer.poll_once(&mut cursor, 1_700_000_000).await;
        // Ulaşılamaz RPC → hiçbir kayıt işlenmedi → cursor 0 kalmalı.
        assert_eq!(cursor, 0);
    }

    /// Restart simülasyonu: kalıcı imleç 5000'den devam etmeli, 0'a dönmemeli.
    #[tokio::test]
    async fn outbound_cursor_survives_a_relayer_restart() {
        let relayer = test_outbound_relayer();
        relayer.store.set_outbound_cursor(5_000).unwrap();

        // "Restart": run_loop'un başlangıçta yaptığı okumanın aynısı.
        let resumed_cursor = relayer.store.get_outbound_cursor().unwrap_or(0);
        assert_eq!(resumed_cursor, 5_000);
    }

    /// 3 kayıttan (100-102) 101 hata verirse kalıcı imleç 101'i ASLA atlamamalı,
    /// restart sonrası hâlâ taranabilir kalmalı.
    #[tokio::test]
    async fn outbound_cursor_after_a_partial_failure_survives_a_restart_and_can_retry() {
        let relayer = test_outbound_relayer();
        let records = vec![
            crate::zagros_watcher::BurnRecord {
                index: 100,
                tx_id_hex: "0xa".into(),
                sender: "0x1".into(),
                amount: 1,
            },
            crate::zagros_watcher::BurnRecord {
                index: 101,
                tx_id_hex: "0xb".into(),
                sender: "0x2".into(),
                amount: 1,
            },
            crate::zagros_watcher::BurnRecord {
                index: 102,
                tx_id_hex: "0xc".into(),
                sender: "0x3".into(),
                amount: 1,
            },
        ];
        // poll_once'un gerçekte yaptığı hesap: 101 başarısız oldu.
        let safe_cursor =
            crate::zagros_watcher::next_cursor_after_partial_failure(0, &records, &[101]);
        assert_eq!(safe_cursor, 101);
        relayer.store.set_outbound_cursor(safe_cursor).unwrap();

        // "Restart": run_loop'un başlangıçta yaptığı okumanın aynısı.
        let resumed_cursor = relayer.store.get_outbound_cursor().unwrap_or(0);
        assert_eq!(
            resumed_cursor, 101,
            "başarısız 2. kayıt (index 101) atlanmamalı, restart sonrası tekrar taranabilir kalmalı"
        );
    }

    /// Budama sınırını aşan kalıcı imleçle restart CursorGapError'a takılmamalı.
    #[tokio::test]
    async fn outbound_cursor_persistence_prevents_the_post_prune_gap_deadlock() {
        let relayer = test_outbound_relayer();
        // Relayer restart ÖNCESİ 10.001. burne kadar gerçekten yetişmişti.
        relayer.store.set_outbound_cursor(10_001).unwrap();

        // Sunucu MAX_RECENT_BRIDGE_BURNS=10_000 penceresini budadı, en eski
        // saklanan kayıt artık 1 (toplam >10_000 burn olduğunu simüle eder).
        let oldest_index_after_pruning = 1u128;

        let resumed_cursor = relayer.store.get_outbound_cursor().unwrap_or(0);
        assert_eq!(resumed_cursor, 10_001);
        assert!(
            crate::zagros_watcher::detect_cursor_gap(
                resumed_cursor,
                Some(oldest_index_after_pruning)
            )
            .is_ok(),
            "persisted cursor must stay ahead of the pruning boundary across a restart"
        );

        // Kontrast: her restart'ta cursor=0 davranışı AYNI budama durumunda
        // kalıcı olarak kilitlenirdi.
        assert!(
            crate::zagros_watcher::detect_cursor_gap(0, Some(oldest_index_after_pruning)).is_err(),
            "sanity check: a reset-to-zero cursor WOULD have hit the gap this fix avoids"
        );
    }

    // Retry kuyruğu entegrasyonu, GERÇEK zagros-rpc sunucusuna karşı
    // (`tests/outbound_integration.rs::spawn_test_server` kopyası).

    // 🛡️ SABİT PORT YOK: `cargo test` entegrasyon testlerini ayrı süreçte
    // koşturur, sabit tabanlı sayaç "Address already in use" ile rastgele
    // düşerdi. Port 0 ile işletim sistemi seçer, bağlanan adres geri okunur.

    /// Mock RPC sunucusunu BOŞ bir portta başlatır ve `(state, port)` döner,
    /// port çağrı anında işletim sistemi tarafından seçilir.
    async fn item13_spawn_mock_rpc_server() -> (std::sync::Arc<dyn zagros_state::State>, u16) {
        use warp::Filter;

        let tmp_dir = tempfile::tempdir().unwrap();
        let storage = std::sync::Arc::new(
            zagros_storage::rocksdb_impl::RocksDbStorage::open(tmp_dir.path().to_str().unwrap())
                .unwrap(),
        );
        let state: std::sync::Arc<dyn zagros_state::State> =
            std::sync::Arc::new(zagros_state::manager::StateDbManager::new(storage));
        let returned_state = state.clone();
        let gas_calculator = std::sync::Arc::new(zagros_types::GasCalculator::new(
            std::sync::Arc::new(portable_atomic::AtomicU128::new(1)),
            std::sync::Arc::new(portable_atomic::AtomicU128::new(1_000_000_000_000_000)),
        ));
        let mempool =
            std::sync::Arc::new(zagros_mempool::Mempool::new(state.clone(), gas_calculator));
        let bridge_manager = std::sync::Arc::new(std::sync::Mutex::new(
            BridgeManager::default_bridge_manager(zagros_types::CHAIN_ID),
        ));
        let tx_cache = std::sync::Arc::new(dashmap::DashMap::new());

        let route = warp::post()
            .and(warp::body::bytes())
            .and_then(move |body: bytes::Bytes| {
                let state = state.clone();
                let mempool = mempool.clone();
                let tx_cache = tx_cache.clone();
                let bridge_manager = bridge_manager.clone();
                async move {
                    let req: zagros_rpc::RpcRequest =
                        serde_json::from_slice(&body).expect("valid JSON-RPC request");
                    let response = zagros_rpc::RpcServer::handle_request(
                        req,
                        state,
                        mempool,
                        tx_cache,
                        bridge_manager,
                        zagros_rpc::EvmSimulationLimits::default(),
                    );
                    Ok::<_, std::convert::Infallible>(warp::reply::json(&response))
                }
            });

        // Port 0 = "bos bir port sec". `bind_ephemeral` FIILEN baglanan adresi
        // doner, yani hazir olma beklemesine de gerek kalmaz.
        let (addr, server) = warp::serve(route).bind_ephemeral(([127, 0, 0, 1], 0));
        tokio::spawn(async move {
            let _keep_alive = tmp_dir;
            server.await;
        });
        (returned_state, addr.port())
    }

    /// Verilen RPC ve depoyla `OutboundRelayer`; dev-seed yetkilisiyle (seed 1)
    /// imzalar ki gerçek sunucu öneriyi kabul etsin.
    fn item13_test_relayer(rpc_url: String, store: RelayerStore) -> OutboundRelayer {
        item15_test_relayer_with_auto_recover(rpc_url, store, false)
    }

    fn item15_test_relayer_with_auto_recover(
        rpc_url: String,
        store: RelayerStore,
        auto_recover_cursor_gap: bool,
    ) -> OutboundRelayer {
        // `BridgeManager::default_authorities()` yalnızca İLK bayt'ı seed
        // olarak kullanır (kalanı sıfır), `[1u8; 32]` (her bayt 1) farklı
        // bir anahtardır ve sunucunun kanonik yetkili kümesinde YOKTUR.
        let mut seed = [0u8; 32];
        seed[0] = 1;
        let zagros_signing_key = SigningKey::from_bytes(&seed);
        let zagros_authority_address = BridgeManager::derive_address_from_public_key(
            &zagros_signing_key.verifying_key().to_bytes(),
        );
        OutboundRelayer {
            client: ZagrosClient::new(rpc_url),
            store,
            zagros_signing_key,
            zagros_authority_address,
            ethereum_signing_key: SecretKey::from_slice(&[9u8; 32]).unwrap(),
            ethereum_relayer_address: test_ethereum_address(),
            gateway_contract_address: EthAddress::repeat_byte(0xCC),
            unlock_token_address: EthAddress::repeat_byte(0xDD),
            chain_id: zagros_types::CHAIN_ID,
            unlock_token_decimals: 18,
            ethereum_chain_id: 1,
            trusted_authorities: BridgeManager::default_bridge_manager(zagros_types::CHAIN_ID),
            auto_recover_cursor_gap,
        }
    }

    /// Gerçek `BridgeMint` (teminat) + `BridgeBurn` uygular, `(tx_id_hex, sender)`
    /// döner (`tests/outbound_integration.rs` senaryosunun aynısı).
    fn item13_execute_real_burn(
        state: &std::sync::Arc<dyn zagros_state::State>,
        seed: u8,
        tx_id_byte: u8,
        amount: u128,
        now: u64,
    ) -> (String, String) {
        let burn_secret_key = secp256k1::SecretKey::from_slice(&[seed; 32]).unwrap();
        let burn_sender = zagros_types::Transaction::address_from_secret_key(&burn_secret_key);
        let burn_tx_id_bytes = [tx_id_byte; 32];
        let burn_tx_id_hex = format!("0x{}", hex::encode(burn_tx_id_bytes));

        let mint_authority_key =
            secp256k1::SecretKey::from_slice(&[seed.wrapping_add(1); 32]).unwrap();
        let mint_authority =
            zagros_types::Transaction::address_from_secret_key(&mint_authority_key);
        state
            .set_account(
                &mint_authority,
                zagros_types::AccountState::new(1_000_000_000_000_000_000),
            )
            .unwrap();
        state
            .set_account(
                &burn_sender,
                zagros_types::AccountState::new(1_000_000_000_000_000_000),
            )
            .unwrap();

        let now_ms = (now as u128) * 1000;
        let mut mint_authorities = Vec::new();
        let mut mint_keys = Vec::new();
        for i in 1..=3u8 {
            let mut ed_seed = [0u8; 32];
            ed_seed[0] = seed.wrapping_add(100).wrapping_add(i);
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&ed_seed);
            let address = BridgeManager::derive_address_from_public_key(
                &signing_key.verifying_key().to_bytes(),
            );
            mint_authorities.push(zagros_executor::bridge::BridgeAuthority {
                address: address.clone(),
                public_key: signing_key.verifying_key().to_bytes(),
                is_active: true,
            });
            mint_keys.push((address, signing_key));
        }
        // 🛡️ Basim dogrulamasi artik ZINCIRDEKI yetkili kumesini okuyor
        // (bkz. Executor::validate_bridge_mint_proposal); uretimde bunu genesis
        // yazar, testte burada kurulur.
        zagros_executor::bridge::store_bridge_authority_set(
            state.as_ref(),
            &zagros_executor::bridge::OnChainBridgeAuthoritySet {
                authorities: mint_authorities.clone(),
                required_signatures: 2,
            },
        )
        .unwrap();
        let mut mint_manager = BridgeManager::new(mint_authorities, 2, zagros_types::CHAIN_ID);
        let mint_proposal_id = mint_manager
            .create_proposal(
                BridgeTxType::Mint,
                amount,
                burn_sender.clone(),
                "Ethereum".to_string(),
                format!("0xcollateral_{}", tx_id_byte),
                (now_ms / 1000) as u64,
                false,
                0,
                now_ms,
                state.as_ref(),
            )
            .unwrap();
        let message = BridgeManager::create_signing_message(
            mint_manager.get_proposal(&mint_proposal_id).unwrap(),
            zagros_types::CHAIN_ID,
        );
        let sig_ts = (now_ms / 1000) as u64;
        let bound = BridgeManager::bind_timestamp_to_message(&message, sig_ts);
        for (address, signing_key) in mint_keys.iter().take(2) {
            mint_manager
                .sign_proposal(
                    &mint_proposal_id,
                    address.clone(),
                    ed25519_dalek::Signer::sign(signing_key, &bound)
                        .to_bytes()
                        .to_vec(),
                    signing_key.verifying_key().to_bytes().to_vec(),
                    sig_ts,
                    now_ms,
                )
                .unwrap();
        }
        mint_manager
            .persist_proposal(state.as_ref(), &mint_proposal_id)
            .unwrap();

        let mut mint_tx = zagros_types::Transaction {
            tx_id: mint_proposal_id,
            tx_type: zagros_types::TxType::BridgeMint,
            sender: mint_authority.clone(),
            receiver: burn_sender.clone(),
            amount,
            payload: Vec::new(),
            signature: Vec::new(),
            timestamp: now_ms,
            nonce: 0,
            gas_limit: 1,
            gas_price: 1,
            chain_id: zagros_types::CHAIN_ID,
        };
        // 🚨 Mimari degisikligi: mint islemi oneriyi (imzalariyla)
        // payload'inda tasir; imza payload'i da kapsar, o yuzden SIGN'dan once.
        mint_tx.payload = zagros_executor::bridge::BridgeManager::encode_proposal_payload(
            &zagros_executor::bridge::BridgeManager::load_proposal_from_state(
                state.as_ref(),
                &mint_proposal_id,
            )
            .unwrap()
            .unwrap(),
        )
        .unwrap();
        mint_tx.sign(&mint_authority_key);
        zagros_executor::Executor::new(state.clone())
            .with_bridge_authority(mint_authority.clone())
            .with_bridge_threshold(2, 0)
            .execute_transaction(&mint_tx, mint_tx.timestamp)
            .unwrap();

        let mut burn_tx = zagros_types::Transaction {
            tx_id: burn_tx_id_bytes,
            tx_type: zagros_types::TxType::BridgeBurn,
            sender: burn_sender.clone(),
            receiver: "0x0000000000000000000000000000000000000002".to_string(),
            amount,
            payload: Vec::new(),
            signature: Vec::new(),
            timestamp: now as u128,
            nonce: 0,
            gas_limit: 21_000,
            gas_price: 1,
            chain_id: zagros_types::CHAIN_ID,
        };
        burn_tx.sign(&burn_secret_key);
        zagros_executor::Executor::new(state.clone())
            .execute_transaction(&burn_tx, burn_tx.timestamp)
            .unwrap();
        (burn_tx_id_hex, burn_sender)
    }

    /// Kanıt 1: ulaşılamayan sunucuda kuyruğa alınan burn, sunucu dönünce
    /// (aynı depoya bakan yeni relayer) kuyruk tahliyesiyle işlenir ve silinir.
    #[tokio::test]
    async fn failed_burn_processing_is_enqueued_for_retry_and_succeeds_on_next_due_attempt() {
        let (state, port) = item13_spawn_mock_rpc_server().await;
        let rpc_url = format!("http://127.0.0.1:{port}");
        let now = crate::now_unix_secs();
        let (burn_tx_id_hex, burn_sender) = item13_execute_real_burn(&state, 91, 0x13, 2_000, now);

        let store_dir = tempfile::tempdir().unwrap();
        let store_storage: std::sync::Arc<dyn zagros_storage::Storage> = std::sync::Arc::new(
            zagros_storage::rocksdb_impl::RocksDbStorage::open(store_dir.path().to_str().unwrap())
                .unwrap(),
        );

        // 1) Ölü sunucuya karşı ilk deneme GERÇEK bir ağ hatasıyla başarısız olur.
        let dead = item13_test_relayer(
            "http://127.0.0.1:1".to_string(),
            RelayerStore::new(store_storage.clone()),
        );
        dead.handle_new_burn(&burn_tx_id_hex, &burn_sender, 2_000, now)
            .await
            .expect_err("dead RPC must fail with a real network error");

        // 2) `poll_once`'un başarısızlıkta yaptığı AYNI kaydı elle kuyruğa al
        //    (üretim kodundaki enqueue çağrısının bire bir aynısı).
        let payload = BurnRetryPayload {
            tx_id_hex: burn_tx_id_hex.clone(),
            sender: burn_sender.clone(),
            amount: 2_000,
        };
        dead.store
            .enqueue_retry(&burn_tx_id_hex, bincode::serialize(&payload).unwrap(), now)
            .unwrap();
        assert_eq!(dead.store.due_retries(now).unwrap().len(), 1);

        // 3) `cursor` bilinçli olarak burn indeksinin ötesinde: canlı tarama bu
        //    burn'ü görmesin, başarı yalnız retry kuyruğunun eseri olsun.
        let alive = item13_test_relayer(rpc_url, RelayerStore::new(store_storage.clone()));
        let mut cursor: u128 = 999_999;
        alive.poll_once(&mut cursor, now).await;

        assert!(
            alive.store.due_retries(now + 10_000).unwrap().is_empty(),
            "başarılı retry sonrası kuyrukta kalmamalı"
        );
        assert!(
            alive.store.list_dead_letters().unwrap().is_empty(),
            "başarılı retry dead-letter'a düşmemeli"
        );
        assert!(
            alive.store.is_zagros_burn_handled(&[0x13u8; 32]).unwrap(),
            "retry başarıyla tamamlandıktan sonra burn kalıcı olarak 'handled' olmalı"
        );
    }

    /// Kanıt 2: burn hem kuyrukta hem canlı tarama aralığındaysa tek turda
    /// öneri yalnız BİR kez oluşur (`is_zagros_burn_handled` kapısı).
    #[tokio::test]
    async fn burn_retry_and_natural_cursor_rediscovery_do_not_double_process() {
        let (state, port) = item13_spawn_mock_rpc_server().await;
        let rpc_url = format!("http://127.0.0.1:{port}");
        let now = crate::now_unix_secs();
        let (burn_tx_id_hex, burn_sender) = item13_execute_real_burn(&state, 92, 0x14, 3_000, now);

        let store_dir = tempfile::tempdir().unwrap();
        let store_storage: std::sync::Arc<dyn zagros_storage::Storage> = std::sync::Arc::new(
            zagros_storage::rocksdb_impl::RocksDbStorage::open(store_dir.path().to_str().unwrap())
                .unwrap(),
        );
        let relayer = item13_test_relayer(rpc_url, RelayerStore::new(store_storage));

        // Önceki (varsayımsal) başarısız bir turdan kalma retry kaydı, AYNI
        // burn için. `cursor=0` bırakıyoruz ki adım-1 (canlı tarama) bu
        // burn'ü DOĞAL olarak da keşfetsin, iki yol aynı turda çakışsın.
        let payload = BurnRetryPayload {
            tx_id_hex: burn_tx_id_hex.clone(),
            sender: burn_sender.clone(),
            amount: 3_000,
        };
        relayer
            .store
            .enqueue_retry(&burn_tx_id_hex, bincode::serialize(&payload).unwrap(), now)
            .unwrap();

        let mut cursor: u128 = 0;
        relayer.poll_once(&mut cursor, now).await;

        assert!(relayer.store.is_zagros_burn_handled(&[0x14u8; 32]).unwrap());
        assert!(
            relayer.store.due_retries(now + 10_000).unwrap().is_empty(),
            "işlenmiş burn retry kuyruğunda kalmamalı"
        );

        let pending = relayer.client.get_pending_bridge_proposals().await.unwrap();
        let matching = pending
            .iter()
            .filter(|p| {
                p.get("source_tx_hash").and_then(|v| v.as_str()) == Some(burn_tx_id_hex.as_str())
            })
            .count();
        assert_eq!(
            matching, 1,
            "aynı burn için TEK bir öneri oluşmalı, çift-işlenme olmamalı (bulunan: {})",
            matching
        );
    }

    // item 15: cursor gap, varsayılan fail-closed + opt-in otomatik kurtarma

    /// Budanmış burn indeksini doğrudan yazar; sunucu `oldest_index` raporlar,
    /// `poll_once` CursorGapError yoluna girer.
    fn item15_seed_pruned_bridge_burn_index(
        state: &std::sync::Arc<dyn zagros_state::State>,
        oldest_index: u128,
    ) {
        let records = vec![zagros_types::BridgeBurnRecord {
            index: oldest_index,
            tx_id: [0u8; 32],
            sender: "0x0000000000000000000000000000000000000009".to_string(),
            amount: 1,
            timestamp: 1,
        }];
        let acc = zagros_types::AccountState {
            contract_code: bincode::serialize(&records).unwrap(),
            ..Default::default()
        };
        state
            .set_account(&"__RECENT_BRIDGE_BURNS__".to_string(), acc)
            .unwrap();
    }

    /// item 15 KANIT (1): `auto_recover_cursor_gap=false` (varsayılan) iken
    /// bir cursor gap tespit edildiğinde imleç DEĞİŞMEZ ve DİSKE HİÇBİR ŞEY
    /// YAZILMAZ, mevcut fail-closed davranış aynen korunur.
    #[tokio::test]
    async fn cursor_gap_with_auto_recover_disabled_leaves_cursor_unchanged_and_logs_error() {
        let (state, port) = item13_spawn_mock_rpc_server().await;
        let rpc_url = format!("http://127.0.0.1:{port}");
        item15_seed_pruned_bridge_burn_index(&state, 5_000);

        let store_dir = tempfile::tempdir().unwrap();
        let store_storage: std::sync::Arc<dyn zagros_storage::Storage> = std::sync::Arc::new(
            zagros_storage::rocksdb_impl::RocksDbStorage::open(store_dir.path().to_str().unwrap())
                .unwrap(),
        );
        let relayer =
            item15_test_relayer_with_auto_recover(rpc_url, RelayerStore::new(store_storage), false);

        let mut cursor: u128 = 0;
        relayer.poll_once(&mut cursor, crate::now_unix_secs()).await;

        assert_eq!(cursor, 0, "fail-closed: bellekteki imleç ilerletilmemeli");
        assert_eq!(
            relayer.store.get_outbound_cursor().unwrap(),
            0,
            "fail-closed: kalıcı imleç de değişmemeli"
        );
    }

    /// item 15 KANIT (2): `auto_recover_cursor_gap=true` iken imleç sunucunun
    /// bildirdiği `oldest_available_index`'e ilerletilir VE kalıcı hale gelir.
    #[tokio::test]
    async fn cursor_gap_with_auto_recover_enabled_advances_cursor_to_oldest_available_index() {
        let (state, port) = item13_spawn_mock_rpc_server().await;
        let rpc_url = format!("http://127.0.0.1:{port}");
        item15_seed_pruned_bridge_burn_index(&state, 5_000);

        let store_dir = tempfile::tempdir().unwrap();
        let store_storage: std::sync::Arc<dyn zagros_storage::Storage> = std::sync::Arc::new(
            zagros_storage::rocksdb_impl::RocksDbStorage::open(store_dir.path().to_str().unwrap())
                .unwrap(),
        );
        let relayer =
            item15_test_relayer_with_auto_recover(rpc_url, RelayerStore::new(store_storage), true);

        let mut cursor: u128 = 0;
        relayer.poll_once(&mut cursor, crate::now_unix_secs()).await;

        assert_eq!(
            cursor, 5_000,
            "auto_recover_cursor_gap=true: bellekteki imleç oldest_available_index'e ilerlemeli"
        );
        assert_eq!(
            relayer.store.get_outbound_cursor().unwrap(),
            5_000,
            "auto_recover_cursor_gap=true: ilerletilen imleç kalıcı hale de gelmeli"
        );
    }

    /// Otomatik kurtarmayla ilerletilen imleç restart sonrası da görünür olmalı.
    #[tokio::test]
    async fn cursor_gap_auto_recovery_persists_the_advanced_cursor_across_a_simulated_restart() {
        let (state, port) = item13_spawn_mock_rpc_server().await;
        let rpc_url = format!("http://127.0.0.1:{port}");
        item15_seed_pruned_bridge_burn_index(&state, 7_777);

        let store_dir = tempfile::tempdir().unwrap();
        let store_storage: std::sync::Arc<dyn zagros_storage::Storage> = std::sync::Arc::new(
            zagros_storage::rocksdb_impl::RocksDbStorage::open(store_dir.path().to_str().unwrap())
                .unwrap(),
        );
        let relayer = item15_test_relayer_with_auto_recover(
            rpc_url.clone(),
            RelayerStore::new(store_storage.clone()),
            true,
        );
        let mut cursor: u128 = 0;
        relayer.poll_once(&mut cursor, crate::now_unix_secs()).await;
        assert_eq!(cursor, 7_777);

        // "Restart": `run_loop`'un başlangıçta yaptığı okumanın aynısı, AYNI
        // depoya bakan YENİ bir relayer.
        let restarted =
            item15_test_relayer_with_auto_recover(rpc_url, RelayerStore::new(store_storage), true);
        let resumed_cursor = restarted.store.get_outbound_cursor().unwrap_or(0);
        assert_eq!(
            resumed_cursor, 7_777,
            "restart sonrası imleç 0'a değil, otomatik kurtarmanın yazdığı değere dönmeli"
        );
    }
}
