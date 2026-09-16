// Zagros Relayer, Gelen Akış (Ethereum yatırma → Zagros mint önerisi):
// onaylı `TokensLockedEvent` idempotency deposunda kontrol edilir,
// `zagros_proposeBridgeAction` ile öneri oluşturulur ve kendi Ed25519 onayı
// hemen eklenir. Ayrıca başkalarının oluşturduğu bekleyen mint önerileri
// keşfedilip onaylanır (bağımsız relayer'larla 2-of-3 için zorunlu).

use crate::ethereum_watcher::TokensLockedEvent;
use crate::store::RelayerStore;
use crate::zagros_client::{ClientError, ZagrosClient};
use ed25519_dalek::SigningKey;
use serde_json::Value;
use zagros_executor::bridge::{BridgeManager, BridgeProposal, BridgeTxType};

/// Bu yetkilinin imzası önerinin `signatures` dizisinde var mı.
/// `signers` alanına değil, gerçek imza kayıtlarına bakıyoruz, ikisi de
/// düğümden gelse bile `signatures` daha spesifik ve doğrulanabilir bir veri.
pub fn already_signed_by(proposal_json: &Value, authority_address: &str) -> bool {
    proposal_json
        .get("signatures")
        .and_then(|v| v.as_array())
        .map(|sigs| {
            sigs.iter().any(|s| {
                s.get("authority")
                    .and_then(|a| a.as_str())
                    .is_some_and(|a| a.eq_ignore_ascii_case(authority_address))
            })
        })
        .unwrap_or(false)
}

pub struct InboundRelayer {
    pub client: ZagrosClient,
    pub store: RelayerStore,
    pub signing_key: SigningKey,
    pub authority_address: String,
    pub chain_id: u64,
    pub source_chain_name: String,
    /// Kilitlenen ERC20'nin ondalığı (PAXG = 18, ZERENYA ile aynı). 🚨 Çıkış
    /// ayağındaki `unlock_token_decimals` ile AYNI olmalı; ayrışırsa köprü bir
    /// yönde basıp diğer yönde fazlasını öder.
    pub token_decimals: u32,
}

impl InboundRelayer {
    /// Onaylanmış Ethereum yatırmasını Zagros mint önerisine çevirir; daha önce
    /// işlenmişse `Ok(None)` (idempotency deposu). `event.sender` doğrudan Zagros alıcısıdır.
    pub async fn handle_confirmed_deposit(
        &self,
        event: &TokensLockedEvent,
        now_unix_secs: u64,
    ) -> Result<Option<String>, ClientError> {
        let eth_tx_hash = format!("0x{}", hex::encode(event.eth_tx_hash.as_bytes()));

        if self
            .store
            .is_ethereum_deposit_handled(&eth_tx_hash)
            .unwrap_or(false)
        {
            return Ok(None);
        }

        let recipient = format!("0x{}", hex::encode(event.sender.as_bytes()));

        // 🔢 ERC20 ondalığı → ZERENYA ondalığı (çıkışın tam tersi, aynı paylaşılan
        // modül). 🚨 Çarpım zorunlu: 6 ondalıklı varlıkta ham tutar geçseydi
        // kullanıcı 2 birim yatırıp 0.000000000002 ZERENYA alırdı.
        let raw_amount = event.amount.as_u128();
        let Some(amount) =
            zagros_types::bridge_amount::scale_token_to_zerenya(raw_amount, self.token_decimals)
        else {
            // Ölçeklenemeyen tutar sessizce yutulmamalı: para zaten kasada
            // kilitli, operatörün müdahale etmesi gerekiyor.
            return Err(ClientError::UnexpectedShape(format!(
                "yatirma tutari olceklenemedi (tutar={} ham, ondalik={}) tx={}",
                raw_amount, self.token_decimals, eth_tx_hash
            )));
        };

        let proposal_id = self
            .client
            .propose_bridge_action(
                &self.signing_key,
                &self.authority_address,
                BridgeTxType::Mint,
                &recipient,
                amount,
                &self.source_chain_name,
                &eth_tx_hash,
                now_unix_secs,
                // Kullanıcının zincirdeki talebini AYNEN taşı. Burası sabit
                // `false` idi: "ZAGROS'a çevir" diyen kullanıcı sessizce düz
                // ZERENYA alıyordu.
                event.auto_swap,
                // 🛡️ Kullanıcının slippage talebi de AYNI şekilde zincirdeki
                // olaydan aynen taşınır, başka hiçbir yerde "varsayılan" bir
                // tolerans hesaplanmaz.
                event.min_amount_out.as_u128(),
                self.chain_id,
            )
            .await?;

        let proposal_id_bytes = decode_proposal_id(&proposal_id).ok_or_else(|| {
            ClientError::UnexpectedShape(format!("bad proposal_id: {}", proposal_id))
        })?;
        self.store
            .mark_ethereum_deposit_handled(&eth_tx_hash, &proposal_id_bytes)
            .map_err(|e| ClientError::Transport(e.to_string()))?;

        self.sign_proposal_by_id(&proposal_id, now_unix_secs)
            .await?;

        Ok(Some(proposal_id))
    }

    /// Bir öneriyi sunucudan (proposal_id ile) geri okuyup, `timestamp`/
    /// `nonce` almak için, bunlar istemcide asla önceden bilinmez, kendi
    /// Ed25519 onayımızı ekler.
    pub async fn sign_proposal_by_id(
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
                &self.signing_key,
                &self.authority_address,
                proposal_id_hex,
                &message,
                now_unix_secs,
            )
            .await
    }

    /// Başkasının oluşturduğu mint önerisinin alanlarının GERÇEKTEN Ethereum'daki
    /// `TokensLocked` olayına karşılık geldiğini kendi bağlantısıyla doğrular.
    /// `Err` dönerse imza KESİNLİKLE atılmamalı (fail-closed).
    async fn verify_mint_proposal_against_ethereum<S: crate::ethereum_watcher::EthLogSource>(
        &self,
        source: &S,
        proposal_json: &Value,
        confirmation_depth: u64,
    ) -> Result<(), String> {
        let source_tx_hash = proposal_json
            .get("source_tx_hash")
            .and_then(|v| v.as_str())
            .ok_or("proposal'da source_tx_hash yok")?;
        let mut tx_hash_bytes = [0u8; 32];
        hex::decode_to_slice(source_tx_hash.trim_start_matches("0x"), &mut tx_hash_bytes)
            .map_err(|_| format!("gecersiz source_tx_hash formati: {}", source_tx_hash))?;
        let tx_hash = ethers_core::types::H256::from(tx_hash_bytes);

        let logs = source
            .transaction_receipt_logs(tx_hash)
            .await?
            .ok_or_else(|| {
                format!(
                    "islem Ethereum'da bulunamadi (uydurma olabilir): {}",
                    source_tx_hash
                )
            })?;

        let event = logs
            .iter()
            .find_map(crate::ethereum_watcher::decode_tokens_locked)
            .ok_or_else(|| {
                format!(
                    "islemde gecerli bir TokensLocked olayi yok: {}",
                    source_tx_hash
                )
            })?;

        let latest = source.latest_block_number().await?;
        if !crate::ethereum_watcher::is_confirmed(event.block_number, latest, confirmation_depth) {
            return Err(format!(
                "onay derinligi yetersiz (blok {}, guncel {}, gereken derinlik {})",
                event.block_number, latest, confirmation_depth
            ));
        }

        let expected_recipient = format!("0x{}", hex::encode(event.sender.as_bytes()));
        let actual_recipient = proposal_json
            .get("recipient")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !actual_recipient.eq_ignore_ascii_case(&expected_recipient) {
            return Err(format!(
                "recipient uyusmuyor: proposal={} zincir={}",
                actual_recipient, expected_recipient
            ));
        }

        let expected_amount = zagros_types::bridge_amount::scale_token_to_zerenya(
            event.amount.as_u128(),
            self.token_decimals,
        )
        .ok_or("zincirdeki tutar olceklenemedi")?;
        let actual_amount: u128 = proposal_json
            .get("amount")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok())
            .ok_or("proposal'da amount yok/gecersiz")?;
        if actual_amount != expected_amount {
            return Err(format!(
                "amount uyusmuyor: proposal={} zincir={}",
                actual_amount, expected_amount
            ));
        }

        let actual_auto_swap = proposal_json
            .get("auto_swap")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if actual_auto_swap != event.auto_swap {
            return Err(format!(
                "auto_swap uyusmuyor: proposal={} zincir={}",
                actual_auto_swap, event.auto_swap
            ));
        }

        let expected_min_out = event.min_amount_out.as_u128();
        let actual_min_out: u128 = proposal_json
            .get("amount_out_min")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        if actual_min_out != expected_min_out {
            return Err(format!(
                "amount_out_min uyusmuyor: proposal={} zincir={}",
                actual_min_out, expected_min_out
            ));
        }

        Ok(())
    }

    /// Bekleyen mint önerilerini tarayıp imzalar ("already signed" zararsız);
    /// döner: bu turda yeni imza sayısı. 🛡️ `source` ZORUNLU: kendisi
    /// oluşturmadığı HER öneri imzadan önce Ethereum'a karşı doğrulanır;
    /// doğrulanamazsa ya da Ethereum'a erişilemiyorsa imza ATILMAZ (fail-closed).
    pub async fn discover_and_cosign_pending_mints<S: crate::ethereum_watcher::EthLogSource>(
        &self,
        source: &S,
        confirmation_depth: u64,
        now_unix_secs: u64,
    ) -> usize {
        let pending = match self.client.get_pending_bridge_proposals().await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("Bekleyen öneriler alınamadı: {}", e);
                return 0;
            }
        };

        let mut newly_signed = 0;
        for proposal_json in &pending {
            if proposal_json.get("tx_type").and_then(|v| v.as_str()) != Some("mint") {
                continue;
            }
            let Some(proposal_id) = proposal_json.get("proposal_id").and_then(|v| v.as_str())
            else {
                continue;
            };
            let Some(message) = signing_message_from_json(proposal_json, self.chain_id) else {
                continue;
            };

            // 🔇 Kendi imzamız varsa hiç deneme: her 3 sn'de "already signed" WARN
            // gürültü yapardı. Güvenlik kararı değil; düğüm yalan söylese en kötü
            // imzamızı eklemeyiz (canlılık), güvenlikte hâlâ hiçbir şeye güvenilmez.
            if already_signed_by(proposal_json, &self.authority_address) {
                continue;
            }

            // 🛡️ Bağımsız doğrulama, imzadan önce, her seferinde: bu öneriyi başkası
            // önerdi, onun sözüne değil kendi Ethereum bağlantıma güveniyorum.
            if let Err(e) = self
                .verify_mint_proposal_against_ethereum(source, proposal_json, confirmation_depth)
                .await
            {
                tracing::warn!(
                    target: "security::bridge",
                    "🚨 Bekleyen mint onerisi (0x{}) bagimsiz dogrulamadan gecemedi, imzalanmiyor: {}",
                    proposal_id, e
                );
                continue;
            }

            match self
                .client
                .sign_bridge_proposal(
                    &self.signing_key,
                    &self.authority_address,
                    proposal_id,
                    &message,
                    now_unix_secs,
                )
                .await
            {
                Ok(_) => newly_signed += 1,
                Err(ClientError::Rpc { message, .. })
                    if message.to_lowercase().contains("already signed") =>
                {
                    // Beklenen, bu öneriyi zaten daha önce imzalamışız.
                }
                Err(e) => tracing::warn!("Öneri imzalanamadı (0x{}): {}", proposal_id, e),
            }
        }
        newly_signed
    }

    /// Tek Ethereum tarama turu: head + `TokensLocked` log'ları, onay derinliğini
    /// geçenler idempotent mint önerisi olur. İmleç YALNIZ tüm olaylar hatasız
    /// işlendiyse ilerler (yatırma kaçırılmaz); ağ hatası `Err` (döngü backoff).
    /// Geride kalınmışsa tek turda birden çok parça, `MAX_CHUNKS_PER_TURN` ile sınırlı.
    pub async fn pump_once<S: crate::ethereum_watcher::EthLogSource>(
        &self,
        source: &S,
        params: crate::ethereum_watcher::ScanParams,
        last_processed: &mut Option<u64>,
    ) -> Result<usize, String> {
        const MAX_CHUNKS_PER_TURN: usize = 200;
        // 🚨 Parçalar arası aralık: paylaşımlı RPC uçları art arda `eth_getLogs`i
        // hız sınırına takar (-32005). Yetişme sonrası tur başına tek parça, bekleme yok.
        const CHUNK_PAUSE: std::time::Duration = std::time::Duration::from_millis(250);

        let latest = source.latest_block_number().await?;
        let mut handled = 0usize;

        for chunk_index in 0..MAX_CHUNKS_PER_TURN {
            if chunk_index > 0 {
                tokio::time::sleep(CHUNK_PAUSE).await;
            }
            let Some((from, to)) =
                crate::ethereum_watcher::catch_up_range(*last_processed, latest, params)
            else {
                break; // onaylanmış yeni blok yok - yetişildi
            };

            let logs = source.tokens_locked_logs(from, to).await?;
            let events =
                crate::ethereum_watcher::confirmed_events(&logs, latest, params.confirmation_depth);

            let now = crate::now_unix_secs();
            let mut all_ok = true;
            for ev in &events {
                match self.handle_confirmed_deposit(ev, now).await {
                    Ok(Some(_)) => handled += 1,
                    Ok(None) => {} // idempotent - zaten işlenmiş
                    // 🚨 "Zaten yürütüldü"/"Proposal already exists" HATA DEĞİL,
                    // idempotency'nin kendisi; hata sayılsa depo sıfırlanıp baştan
                    // taramada imleç ilk eski yatırmada sonsuza dek kilitlenirdi.
                    Err(e)
                        if {
                            let m = e.to_string();
                            m.contains("zaten yurutuldu") || m.contains("already exists")
                        } =>
                    {
                        // Yerel depoya da islenmis olarak yaz ki bir sonraki
                        // turda ayni RPC gidis-donusu hic yapilmasin.
                        let _ = self.store.mark_ethereum_deposit_handled(
                            &format!("0x{}", hex::encode(ev.eth_tx_hash.as_bytes())),
                            &[0u8; 32],
                        );
                    }
                    Err(e) => {
                        all_ok = false;
                        tracing::warn!(
                            "deposit işlenemedi (eth_tx 0x{}): {}",
                            hex::encode(ev.eth_tx_hash.as_bytes()),
                            e
                        );
                    }
                }
            }

            // İmleci yalnızca HER şey başarılıysa ilerlet, aksi halde aralık
            // yeniden taranır (kaçırma yok; idempotency store çift-işlemeyi
            // engeller). Hata varsa bu turda ilerlemeyi de bırakıyoruz.
            if !all_ok {
                return Ok(handled);
            }

            // 🚨 İlerleme yoksa dur: yetişme sonrası `catch_up_range` reorg tamponu
            // yüzünden hep aynı pencereyi döner; kontrol olmadan aynı aralık
            // `MAX_CHUNKS_PER_TURN` kez taranıp hız sınırına takılırdı.
            let made_progress = *last_processed != Some(to);
            *last_processed = Some(to);
            if !made_progress {
                break;
            }
        }

        Ok(handled)
    }

    /// `TokensLocked` tarama döngüsü: ağ hatasında üstel geri çekilmeyle yeniden
    /// dener, `cancel` ile temiz kapanış. `reset_cursor`: kalıcı imleç yok sayılıp
    /// `params.start_block`tan başlar.
    pub async fn run_event_subscription_loop<S: crate::ethereum_watcher::EthLogSource>(
        &self,
        source: &S,
        params: crate::ethereum_watcher::ScanParams,
        poll_interval_secs: u64,
        reset_cursor: bool,
        mut cancel: tokio::sync::watch::Receiver<bool>,
    ) {
        use std::time::Duration;
        let mut last_processed: Option<u64> = if reset_cursor {
            None
        } else {
            match self.store.get_inbound_cursor() {
                Ok(cursor) => cursor,
                Err(e) => {
                    tracing::warn!(
                        "⚠️ Kalıcı inbound cursor okunamadı ({}) - {}'dan başlanıyor.",
                        e,
                        params.start_block
                    );
                    None
                }
            }
        };
        if let Some(cursor) = last_processed {
            tracing::info!(
                "🌉 Ethereum tarama imleci {}'den devam ediyor (kalıcı).",
                cursor
            );
        } else if reset_cursor {
            tracing::warn!(
                "⚠️ reset_inbound_cursor=true - kalıcı imleç YOK SAYILDI, {}'dan (start_block) \
                 tam yeniden tarama yapılacak. Bunu kalıcı olarak AÇIK bırakmayın.",
                params.start_block
            );
        }
        let mut backoff = Duration::from_secs(1);
        let max_backoff = Duration::from_secs(60);
        let mut ticker = tokio::time::interval(Duration::from_secs(poll_interval_secs.max(1)));
        tracing::info!(
            "🌉 Ethereum event pump devrede (interval {}s, onay derinliği {}, \
             başlangıç bloğu {}, pencere {} blok).",
            poll_interval_secs.max(1),
            params.confirmation_depth,
            params.start_block,
            params.max_range
        );
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    // 🚨 Tarama iptal sinyaliyle yarıştırılır (uzun yetişme kapanışı
                    // geciktirmesin); yarım tarama zararsız, imleç yalnız tamamlanan parçada ilerler.
                    let pumped = tokio::select! {
                        result = self.pump_once(source, params, &mut last_processed) => result,
                        _ = cancel.changed() => {
                            if *cancel.borrow() { break; }
                            continue;
                        }
                    };
                    match pumped {
                        Ok(n) => {
                            if n > 0 {
                                tracing::info!("🌉 Event pump: {} yeni deposit mint önerisine çevrildi.", n);
                            }
                            backoff = Duration::from_secs(1); // başarıda backoff sıfırla

                            // item 12: imleci SADECE başarılı bir tur sonrası
                            // kalıcı hale getir, `outbound.rs::poll_once`'un
                            // "sadece başarıda persist et" sözleşmesiyle AYNI.
                            if let Some(cursor) = last_processed {
                                if let Err(e) = self.store.set_inbound_cursor(cursor) {
                                    tracing::warn!("inbound cursor kalıcı hale getirilemedi: {}", e);
                                }
                            }

                            // 🛡️ Eş imza YALNIZ burada, Ethereum'a gerçekten erişilen
                            // turlarda; bağlantı yoksa bu relayer eş imzalamaz
                            // (fail-closed, canlılık kaybı ama güvenlik ihlali değil).
                            let co_signed = self
                                .discover_and_cosign_pending_mints(
                                    source,
                                    params.confirmation_depth,
                                    crate::now_unix_secs(),
                                )
                                .await;
                            if co_signed > 0 {
                                tracing::info!(
                                    "🌉 Inbound: {} bekleyen mint önerisi bağımsız doğrulamadan geçip co-sign edildi.",
                                    co_signed
                                );
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                "⚠️ Event pump/WS hatası: {} - {:?} sonra yeniden denenecek (reconnect backoff).",
                                e, backoff
                            );
                            tokio::select! {
                                _ = tokio::time::sleep(backoff) => {}
                                _ = cancel.changed() => { if *cancel.borrow() { break; } }
                            }
                            backoff = crate::ethereum_watcher::next_backoff(backoff, max_backoff);
                            // 🚨 Kalıcı ölen WS oturumuyla denemek 35 saat boşa döndü;
                            // her hata turunda bağlantı SIFIRDAN kurulur (`reconnect`).
                            match source.reconnect().await {
                                Ok(()) => tracing::info!("🔁 Ethereum WS istemcisi yeniden kuruldu - bir sonraki turda taze bağlantı kullanılacak."),
                                Err(re) => tracing::warn!("⚠️ WS yeniden kurulamadı ({}) - mevcut istemciyle tekrar denenecek.", re),
                            }
                        }
                    }
                }
                _ = cancel.changed() => {
                    if *cancel.borrow() {
                        break;
                    }
                }
            }
        }
        tracing::info!("🛑 Ethereum event pump durduruldu (graceful shutdown).");
    }
}

fn decode_proposal_id(proposal_id_hex: &str) -> Option<[u8; 32]> {
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(proposal_id_hex.trim_start_matches("0x"), &mut bytes).ok()?;
    Some(bytes)
}

/// RPC JSON'undan `BridgeProposal` inşa edip `create_signing_message` çağırır;
/// öneriyi kendisi oluşturmamış relayer imza mesajını böyle üretir.
fn signing_message_from_json(value: &Value, chain_id: u64) -> Option<Vec<u8>> {
    let proposal_id = decode_proposal_id(value.get("proposal_id")?.as_str()?)?;
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
        // create_signing_message şunu kullanıyor: proposal_id/tx_type/amount/
        // recipient/source_chain/source_tx_hash/timestamp/nonce. signatures ve
        // executed hash'e girmiyor, o yüzden burada boş/placeholder olabilir.
        signatures: Vec::new(),
        executed: value.get("executed")?.as_bool()?,
        nonce: value.get("nonce")?.as_str()?.parse().ok()?,
        auto_swap: value.get("auto_swap")?.as_bool()?,
        // amount_out_min imzaya dahil (bkz. create_signing_message), eski
        // proposal'larda alan yoktu, RPC JSON'u yine de her zaman yazar
        // (serde default 0), bu yüzden burada zorunlu okunabilir.
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

    /// Testler icin: sinirsiz pencere, 0'dan baslar (mock kaynak kucuk blok
    /// numaralari kullanir).
    fn test_scan_params() -> crate::ethereum_watcher::ScanParams {
        crate::ethereum_watcher::ScanParams {
            confirmation_depth: 12,
            reorg_buffer: 6,
            start_block: 0,
            max_range: u64::MAX,
        }
    }
    use super::*;
    use serde_json::json;

    #[test]
    fn signing_message_reconstruction_matches_the_original() {
        let proposal = BridgeProposal {
            proposal_id: [7u8; 32],
            tx_type: BridgeTxType::Mint,
            amount: 1_000,
            recipient: "0x0000000000000000000000000000000000000009".to_string(),
            source_chain: "Ethereum".to_string(),
            source_tx_hash: "0xdeadbeef".to_string(),
            timestamp: 1_700_000_000,
            signatures: Vec::new(),
            executed: false,
            nonce: 42,
            auto_swap: false,
            amount_out_min: 0,
            claim_vouchers: Vec::new(),
        };
        let expected = BridgeManager::create_signing_message(&proposal, 21072026);

        let json_value = json!({
            "proposal_id": format!("0x{}", hex::encode(proposal.proposal_id)),
            "tx_type": "mint",
            "recipient": proposal.recipient,
            "amount": proposal.amount.to_string(),
            "source_chain": proposal.source_chain,
            "source_tx_hash": proposal.source_tx_hash,
            "timestamp": proposal.timestamp.to_string(),
            "nonce": proposal.nonce.to_string(),
            "signatures_collected": 0,
            "executed": false,
            "can_execute": false,
            "auto_swap": false,
        });

        let reconstructed = signing_message_from_json(&json_value, 21072026).unwrap();
        assert_eq!(reconstructed, expected);
    }

    #[test]
    fn signing_message_reconstruction_fails_gracefully_on_missing_fields() {
        let sparse = json!({ "proposal_id": "0x0101", "tx_type": "mint" });
        assert!(signing_message_from_json(&sparse, 21072026).is_none());
    }

    #[test]
    fn decode_proposal_id_accepts_both_prefixed_and_bare_hex() {
        let hex_str = "07".repeat(32);
        assert_eq!(decode_proposal_id(&hex_str), Some([7u8; 32]));
        assert_eq!(
            decode_proposal_id(&format!("0x{}", hex_str)),
            Some([7u8; 32])
        );
    }

    // ---- 🌉 FAZ4: lifecycle / graceful shutdown ----

    #[derive(Default)]
    struct MemoryStorage {
        values: std::sync::Mutex<std::collections::HashMap<Vec<u8>, Vec<u8>>>,
    }
    impl zagros_storage::Storage for MemoryStorage {
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

    fn test_inbound_relayer() -> InboundRelayer {
        test_inbound_relayer_with_store(RelayerStore::new(std::sync::Arc::new(
            MemoryStorage::default(),
        )))
    }

    /// item 12 testleri için: aynı alttaki `storage`'ı paylaşan bir
    /// `RelayerStore` verilebilsin ki "restart" simülasyonu (aynı storage,
    /// yeni `InboundRelayer`) mümkün olsun.
    fn test_inbound_relayer_with_store(store: RelayerStore) -> InboundRelayer {
        InboundRelayer {
            client: ZagrosClient::new("http://127.0.0.1:1".to_string()),
            store,
            signing_key: SigningKey::from_bytes(&[1u8; 32]),
            authority_address: "0x0000000000000000000000000000000000000001".to_string(),
            chain_id: zagros_types::CHAIN_ID,
            source_chain_name: "Ethereum".to_string(),
            token_decimals: 6,
        }
    }

    // ---- 🌉 FAZ4: event pump (mockable EthLogSource) ----

    /// `receipts` gerçek `eth_getTransactionReceipt`i taklit eder (anahtar yoksa
    /// `Ok(None)`, uydurma tx); `receipt_error` doluysa her çağrı `Err` (Ethereum yok).
    #[derive(Default)]
    struct MockLogSource {
        latest: u64,
        logs: Vec<ethers_core::types::Log>,
        receipts: std::collections::HashMap<ethers_core::types::H256, Vec<ethers_core::types::Log>>,
        receipt_error: Option<String>,
    }

    impl crate::ethereum_watcher::EthLogSource for MockLogSource {
        async fn latest_block_number(&self) -> Result<u64, String> {
            Ok(self.latest)
        }
        async fn tokens_locked_logs(
            &self,
            _from: u64,
            _to: u64,
        ) -> Result<Vec<ethers_core::types::Log>, String> {
            Ok(self.logs.clone())
        }
        async fn transaction_receipt_logs(
            &self,
            tx_hash: ethers_core::types::H256,
        ) -> Result<Option<Vec<ethers_core::types::Log>>, String> {
            if let Some(e) = &self.receipt_error {
                return Err(e.clone());
            }
            Ok(self.receipts.get(&tx_hash).cloned())
        }
    }

    /// `tokens_locked_logs` cagri sayisini sayan mock, gereksiz RPC trafigini
    /// olcmek icin.
    struct CountingLogSource {
        latest: u64,
        calls: std::sync::atomic::AtomicUsize,
    }

    impl crate::ethereum_watcher::EthLogSource for CountingLogSource {
        async fn latest_block_number(&self) -> Result<u64, String> {
            Ok(self.latest)
        }
        async fn tokens_locked_logs(
            &self,
            _from: u64,
            _to: u64,
        ) -> Result<Vec<ethers_core::types::Log>, String> {
            self.calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(Vec::new())
        }
        async fn transaction_receipt_logs(
            &self,
            _tx_hash: ethers_core::types::H256,
        ) -> Result<Option<Vec<ethers_core::types::Log>>, String> {
            Ok(None)
        }
    }

    // ---- #10: verify_mint_proposal_against_ethereum ----

    /// `LiveEthereum`'un çağırırken kullanacağı gibi ("Ethereum'a erişilemiyor")
    /// her zaman `Err` döndürür.
    struct FailingLogSource;

    impl crate::ethereum_watcher::EthLogSource for FailingLogSource {
        async fn latest_block_number(&self) -> Result<u64, String> {
            Err("connection reset".to_string())
        }
        async fn tokens_locked_logs(
            &self,
            _from: u64,
            _to: u64,
        ) -> Result<Vec<ethers_core::types::Log>, String> {
            Err("connection reset".to_string())
        }
        async fn transaction_receipt_logs(
            &self,
            _tx_hash: ethers_core::types::H256,
        ) -> Result<Option<Vec<ethers_core::types::Log>>, String> {
            Err("connection reset".to_string())
        }
    }

    fn sample_event_for_verification() -> TokensLockedEvent {
        TokensLockedEvent {
            sender: ethers_core::types::H160::repeat_byte(0x42),
            token: ethers_core::types::H160::repeat_byte(0x99),
            amount: ethers_core::types::U256::from(5_000u64), // 6 ondalik -> 5000*1e12 ZERENYA
            auto_swap: false,
            min_amount_out: ethers_core::types::U256::zero(),
            deposit_timestamp: ethers_core::types::U256::from(1_700_000_000u64),
            eth_tx_hash: ethers_core::types::H256::repeat_byte(0x11),
            block_number: 12_345,
        }
    }

    fn log_for_event(event: &TokensLockedEvent) -> ethers_core::types::Log {
        use ethers_core::abi::{encode, Token};
        let topic0 = crate::ethereum_watcher::tokens_locked_event_abi().signature();
        let data = encode(&[
            Token::Uint(event.amount),
            Token::Bool(event.auto_swap),
            Token::Uint(event.min_amount_out),
            Token::Uint(event.deposit_timestamp),
        ]);
        ethers_core::types::Log {
            address: ethers_core::types::H160::repeat_byte(0xCC),
            topics: vec![
                topic0,
                ethers_core::types::H256::from(event.sender),
                ethers_core::types::H256::from(event.token),
            ],
            data: ethers_core::types::Bytes::from(data),
            block_hash: None,
            block_number: Some(event.block_number.into()),
            transaction_hash: Some(event.eth_tx_hash),
            transaction_index: None,
            log_index: None,
            transaction_log_index: None,
            log_type: None,
            removed: Some(false),
        }
    }

    /// `bridge_proposal_json`'un (zagros-rpc) ürettiği şeklin aynısı, yalnızca
    /// `verify_mint_proposal_against_ethereum`'un okuduğu alanlar.
    fn proposal_json_matching(event: &TokensLockedEvent, token_decimals: u32) -> Value {
        let amount = zagros_types::bridge_amount::scale_token_to_zerenya(
            event.amount.as_u128(),
            token_decimals,
        )
        .unwrap();
        json!({
            "source_tx_hash": format!("0x{}", hex::encode(event.eth_tx_hash.as_bytes())),
            "recipient": format!("0x{}", hex::encode(event.sender.as_bytes())),
            "amount": amount.to_string(),
            "auto_swap": event.auto_swap,
            "amount_out_min": event.min_amount_out.as_u128().to_string(),
        })
    }

    /// #10 KANIT (1): gerçek, eşleşen bir TokensLocked receipt varsa doğrulama
    /// başarılı olur.
    #[tokio::test]
    async fn verification_succeeds_for_a_real_matching_receipt() {
        let relayer = test_inbound_relayer();
        let event = sample_event_for_verification();
        let mut receipts = std::collections::HashMap::new();
        receipts.insert(event.eth_tx_hash, vec![log_for_event(&event)]);
        let source = MockLogSource {
            latest: event.block_number + 12,
            receipts,
            ..Default::default()
        };
        let proposal = proposal_json_matching(&event, relayer.token_decimals);

        relayer
            .verify_mint_proposal_against_ethereum(&source, &proposal, 12)
            .await
            .expect("gercek ve eslesen bir receipt dogrulamayi gecmeli");
    }

    /// #10 KANIT (2): source_tx_hash Ethereum'da hiç yoksa (uydurma) doğrulama
    /// reddedilir.
    #[tokio::test]
    async fn verification_rejects_a_nonexistent_source_tx_hash() {
        let relayer = test_inbound_relayer();
        let event = sample_event_for_verification();
        // `receipts` haritasi BOS, bu tx_hash Ethereum'da hic yok.
        let source = MockLogSource {
            latest: event.block_number + 12,
            ..Default::default()
        };
        let proposal = proposal_json_matching(&event, relayer.token_decimals);

        let err = relayer
            .verify_mint_proposal_against_ethereum(&source, &proposal, 12)
            .await
            .expect_err("uydurma source_tx_hash dogrulamayi GECMEMELI");
        assert!(err.contains("bulunamadi"), "hata mesaji: {}", err);
    }

    /// #10 KANIT (3): işlem gerçek ama proposal'daki alan(lar) zincirdeki
    /// olayla uyuşmuyorsa (uydurma/yanlış miktar) doğrulama reddedilir.
    #[tokio::test]
    async fn verification_rejects_a_real_receipt_with_mismatched_amount() {
        let relayer = test_inbound_relayer();
        let event = sample_event_for_verification();
        let mut receipts = std::collections::HashMap::new();
        receipts.insert(event.eth_tx_hash, vec![log_for_event(&event)]);
        let source = MockLogSource {
            latest: event.block_number + 12,
            receipts,
            ..Default::default()
        };
        let mut proposal = proposal_json_matching(&event, relayer.token_decimals);
        // Gercekte zincirde olandan 1000 kat fazla talep ediliyor.
        let real_amount: u128 = proposal["amount"].as_str().unwrap().parse().unwrap();
        proposal["amount"] = json!((real_amount * 1000).to_string());

        let err = relayer
            .verify_mint_proposal_against_ethereum(&source, &proposal, 12)
            .await
            .expect_err("miktar uyusmazligi dogrulamayi GECMEMELI");
        assert!(err.contains("amount uyusmuyor"), "hata mesaji: {}", err);
    }

    /// #10 KANIT (4): işlem gerçek ve alanlar eşleşiyor ama onay derinliği
    /// yetersizse (çok yeni blok) doğrulama reddedilir.
    #[tokio::test]
    async fn verification_rejects_insufficient_confirmation_depth() {
        let relayer = test_inbound_relayer();
        let event = sample_event_for_verification();
        let mut receipts = std::collections::HashMap::new();
        receipts.insert(event.eth_tx_hash, vec![log_for_event(&event)]);
        // Yalnizca 3 blok onayi var, 12 gerekiyor.
        let source = MockLogSource {
            latest: event.block_number + 3,
            receipts,
            ..Default::default()
        };
        let proposal = proposal_json_matching(&event, relayer.token_decimals);

        let err = relayer
            .verify_mint_proposal_against_ethereum(&source, &proposal, 12)
            .await
            .expect_err("yetersiz onay derinligi dogrulamayi GECMEMELI");
        assert!(err.contains("onay derinligi"), "hata mesaji: {}", err);
    }

    /// #10 KANIT (5): Ethereum'a erişilemiyorsa (ağ hatası) fail-closed,
    /// doğrulama reddedilir, panik atmaz.
    #[tokio::test]
    async fn verification_fails_closed_when_ethereum_is_unreachable() {
        let relayer = test_inbound_relayer();
        let event = sample_event_for_verification();
        let proposal = proposal_json_matching(&event, relayer.token_decimals);

        let err = relayer
            .verify_mint_proposal_against_ethereum(&FailingLogSource, &proposal, 12)
            .await
            .expect_err("Ethereum erisilemezken dogrulama GECMEMELI (fail-closed)");
        assert!(err.contains("connection reset"), "hata mesaji: {}", err);
    }

    /// 🚨 Regresyon: yetişme sonrası parça döngüsü aynı pencereyi tekrar
    /// taramamalı (200 kez `eth_getLogs` seli, hız sınırı).
    #[tokio::test]
    async fn a_caught_up_pump_does_not_rescan_the_same_window_repeatedly() {
        use std::sync::atomic::Ordering;

        let relayer = test_inbound_relayer();
        let source = CountingLogSource {
            latest: 100,
            calls: std::sync::atomic::AtomicUsize::new(0),
        };

        // Ilk tur: 0..88 taranir, imlec 88'e gelir.
        let mut last = None;
        relayer
            .pump_once(&source, test_scan_params(), &mut last)
            .await
            .unwrap();
        assert_eq!(last, Some(88));
        let after_first = source.calls.load(Ordering::Relaxed);
        assert!(
            after_first <= 2,
            "ilk yetisme birkac cagri olmali, {} oldu",
            after_first
        );

        // Ikinci tur: yetisilmis durumda. Reorg tamponu ayni pencereyi dondurur
        // ama pump BIR kez tarayip durmali, 200 kez degil.
        relayer
            .pump_once(&source, test_scan_params(), &mut last)
            .await
            .unwrap();
        let after_second = source.calls.load(Ordering::Relaxed) - after_first;
        assert_eq!(
            after_second, 1,
            "yetisilmis durumda tur basina TEK tarama bekleniyor, {} oldu",
            after_second
        );
    }

    #[tokio::test]
    async fn pump_advances_cursor_over_a_confirmed_empty_range() {
        // latest 100, depth 12 → confirmed_tip 88; log yok → imleç 88'e ilerler.
        let relayer = test_inbound_relayer();
        let source = MockLogSource {
            latest: 100,
            logs: vec![],
            ..Default::default()
        };
        let mut last = None;
        let n = relayer
            .pump_once(&source, test_scan_params(), &mut last)
            .await
            .unwrap();
        assert_eq!(n, 0);
        assert_eq!(last, Some(88));
    }

    #[tokio::test]
    async fn pump_does_nothing_when_no_blocks_are_confirmed_yet() {
        // latest 5 < depth 12 → onaylanmış blok yok → imleç ilerlemez.
        let relayer = test_inbound_relayer();
        let source = MockLogSource {
            latest: 5,
            logs: vec![],
            ..Default::default()
        };
        let mut last = None;
        let n = relayer
            .pump_once(&source, test_scan_params(), &mut last)
            .await
            .unwrap();
        assert_eq!(n, 0);
        assert_eq!(last, None);
    }

    #[tokio::test]
    async fn event_subscription_loop_stops_on_graceful_shutdown() {
        let relayer = std::sync::Arc::new(test_inbound_relayer());
        let source = std::sync::Arc::new(MockLogSource {
            latest: 100,
            logs: vec![],
            ..Default::default()
        });
        let (tx, rx) = tokio::sync::watch::channel(false);
        let handle = {
            let relayer = relayer.clone();
            let source = source.clone();
            tokio::spawn(async move {
                relayer
                    .run_event_subscription_loop(source.as_ref(), test_scan_params(), 1, false, rx)
                    .await
            })
        };

        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        tx.send(true).unwrap();

        let joined = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
        assert!(
            joined.is_ok(),
            "event pump must return promptly after graceful cancel"
        );
        assert!(joined.unwrap().is_ok(), "pump task must not panic");
    }

    // ---- item 12: kalıcı inbound cursor ----

    /// `tokens_locked_logs`'a geçilen `(from, to)` aralıklarını kaydeder,
    /// döngünün taramaya nereden başladığını (kalıcı imleçten mi,
    /// `start_block`'tan mı) doğrudan gözlemlemek için.
    #[derive(Default)]
    struct RecordingLogSource {
        latest: u64,
        calls: std::sync::Mutex<Vec<(u64, u64)>>,
    }
    impl crate::ethereum_watcher::EthLogSource for RecordingLogSource {
        async fn latest_block_number(&self) -> Result<u64, String> {
            Ok(self.latest)
        }
        async fn tokens_locked_logs(
            &self,
            from: u64,
            to: u64,
        ) -> Result<Vec<ethers_core::types::Log>, String> {
            self.calls.lock().unwrap().push((from, to));
            Ok(Vec::new())
        }
        async fn transaction_receipt_logs(
            &self,
            _tx_hash: ethers_core::types::H256,
        ) -> Result<Option<Vec<ethers_core::types::Log>>, String> {
            Ok(None)
        }
    }

    /// İlk `tokens_locked_logs` çağrısı her zaman `Err` döner, sonrakiler
    /// başarılı olur, "ilk tur başarısız, ikinci tur başarılı" senaryosunu
    /// (imleç yalnızca başarıdan SONRA kalıcı hale gelmeli) test etmek için.
    #[derive(Default)]
    struct FlakyLogSource {
        latest: u64,
        calls: std::sync::atomic::AtomicUsize,
    }
    impl crate::ethereum_watcher::EthLogSource for FlakyLogSource {
        async fn latest_block_number(&self) -> Result<u64, String> {
            Ok(self.latest)
        }
        async fn tokens_locked_logs(
            &self,
            _from: u64,
            _to: u64,
        ) -> Result<Vec<ethers_core::types::Log>, String> {
            if self
                .calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                == 0
            {
                Err("simulated Ethereum RPC failure".to_string())
            } else {
                Ok(Vec::new())
            }
        }
        async fn transaction_receipt_logs(
            &self,
            _tx_hash: ethers_core::types::H256,
        ) -> Result<Option<Vec<ethers_core::types::Log>>, String> {
            Ok(None)
        }
    }

    #[tokio::test]
    async fn run_event_subscription_loop_seeds_last_processed_from_persisted_cursor() {
        let storage: std::sync::Arc<dyn zagros_storage::Storage> =
            std::sync::Arc::new(MemoryStorage::default());
        RelayerStore::new(storage.clone())
            .set_inbound_cursor(50)
            .unwrap();
        let relayer =
            std::sync::Arc::new(test_inbound_relayer_with_store(RelayerStore::new(storage)));
        let source = std::sync::Arc::new(RecordingLogSource {
            latest: 100,
            ..Default::default()
        });

        let (tx, rx) = tokio::sync::watch::channel(false);
        let handle = {
            let relayer = relayer.clone();
            let source = source.clone();
            tokio::spawn(async move {
                relayer
                    .run_event_subscription_loop(source.as_ref(), test_scan_params(), 1, false, rx)
                    .await
            })
        };
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        tx.send(true).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), handle)
            .await
            .expect("dongu zaman asimina ugramadan durmali")
            .expect("dongu gorevi panik atmamali");

        let calls = source.calls.lock().unwrap();
        assert!(!calls.is_empty(), "en az bir tarama yapilmis olmali");
        // test_scan_params(): reorg_buffer=6 -> beklenen ilk `from` = 51 - 6 = 45
        // (kalici imlecten devam), start_block=0'dan DEGIL.
        assert_eq!(
            calls[0].0, 45,
            "tarama kalici imlecten (50) devam etmeli, start_block'tan degil"
        );
    }

    #[tokio::test]
    async fn run_event_subscription_loop_ignores_persisted_cursor_when_reset_flag_set() {
        let storage: std::sync::Arc<dyn zagros_storage::Storage> =
            std::sync::Arc::new(MemoryStorage::default());
        RelayerStore::new(storage.clone())
            .set_inbound_cursor(50)
            .unwrap();
        let relayer =
            std::sync::Arc::new(test_inbound_relayer_with_store(RelayerStore::new(storage)));
        let source = std::sync::Arc::new(RecordingLogSource {
            latest: 100,
            ..Default::default()
        });

        let (tx, rx) = tokio::sync::watch::channel(false);
        let handle = {
            let relayer = relayer.clone();
            let source = source.clone();
            tokio::spawn(async move {
                relayer
                    .run_event_subscription_loop(source.as_ref(), test_scan_params(), 1, true, rx)
                    .await
            })
        };
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        tx.send(true).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), handle)
            .await
            .expect("dongu zaman asimina ugramadan durmali")
            .expect("dongu gorevi panik atmamali");

        let calls = source.calls.lock().unwrap();
        assert!(!calls.is_empty(), "en az bir tarama yapilmis olmali");
        assert_eq!(
            calls[0].0, 0,
            "reset_cursor=true iken kalici imlec YOK SAYILMALI, start_block'tan (0) baslanmali"
        );
    }

    #[tokio::test]
    async fn run_event_subscription_loop_persists_cursor_only_after_a_successful_pump() {
        let storage: std::sync::Arc<dyn zagros_storage::Storage> =
            std::sync::Arc::new(MemoryStorage::default());
        let assertion_store = RelayerStore::new(storage.clone());
        let relayer =
            std::sync::Arc::new(test_inbound_relayer_with_store(RelayerStore::new(storage)));
        let source = std::sync::Arc::new(FlakyLogSource {
            latest: 100,
            ..Default::default()
        });

        assert_eq!(
            assertion_store.get_inbound_cursor().unwrap(),
            None,
            "basarisiz ilk turdan once imlec yok olmali"
        );

        // İlk tur `FlakyLogSource` tarafından reddedilir (1sn backoff'a girer),
        // ikinci tur başarılı olur, imlecin YALNIZCA ikinci turdan sonra kalıcı
        // hale geldiğini görebilmek için ikinci tura yetecek kadar bekliyoruz.
        let (tx, rx) = tokio::sync::watch::channel(false);
        let handle = {
            let relayer = relayer.clone();
            let source = source.clone();
            tokio::spawn(async move {
                relayer
                    .run_event_subscription_loop(source.as_ref(), test_scan_params(), 1, false, rx)
                    .await
            })
        };
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        tx.send(true).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(10), handle)
            .await
            .expect("dongu zaman asimina ugramadan durmali")
            .expect("dongu gorevi panik atmamali");

        assert_eq!(
            assertion_store.get_inbound_cursor().unwrap(),
            Some(88),
            "yalnizca basarili bir tur SONRASI imlec kalici hale gelmeli"
        );
    }
    // ---- vakası: ölü WS oturumu reconnect ile iyileşmeli ----

    /// `reconnect()` çağrılana kadar HER okuması başarısız olan, reconnect
    /// sonrası sağlıklı `MockLogSource` gibi davranan kaynak, 35 saatlik
    /// "aynı ölü istemciyle sonsuz deneme" vakasının birim düzeyde modeli.
    struct DeadUntilReconnectedSource {
        healed: std::sync::atomic::AtomicBool,
        reconnect_calls: std::sync::atomic::AtomicUsize,
    }

    impl crate::ethereum_watcher::EthLogSource for DeadUntilReconnectedSource {
        async fn latest_block_number(&self) -> Result<u64, String> {
            if self.healed.load(std::sync::atomic::Ordering::SeqCst) {
                Ok(100)
            } else {
                Err("Websocket closed unexpectedly".to_string())
            }
        }
        async fn tokens_locked_logs(
            &self,
            _from: u64,
            _to: u64,
        ) -> Result<Vec<ethers_core::types::Log>, String> {
            if self.healed.load(std::sync::atomic::Ordering::SeqCst) {
                Ok(vec![])
            } else {
                Err("Websocket closed unexpectedly".to_string())
            }
        }
        async fn transaction_receipt_logs(
            &self,
            _tx_hash: ethers_core::types::H256,
        ) -> Result<Option<Vec<ethers_core::types::Log>>, String> {
            if self.healed.load(std::sync::atomic::Ordering::SeqCst) {
                Ok(None)
            } else {
                Err("Websocket closed unexpectedly".to_string())
            }
        }
        async fn reconnect(&self) -> Result<(), String> {
            self.reconnect_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.healed.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn a_dead_ws_source_recovers_after_reconnect_is_called() {
        use crate::ethereum_watcher::EthLogSource;
        let source = DeadUntilReconnectedSource {
            healed: std::sync::atomic::AtomicBool::new(false),
            reconnect_calls: std::sync::atomic::AtomicUsize::new(0),
        };
        // Ölü durumda okuma başarısız, eski davranışta döngü sonsuza dek
        // burada kalırdı.
        assert!(source.latest_block_number().await.is_err());
        // Pump döngüsünün hata dalının artık her turda yaptığı çağrı:
        source.reconnect().await.expect("reconnect başarılı olmalı");
        // Taze bağlantı: okuma iyileşti, iyileşme TEK reconnect ile geldi.
        assert_eq!(source.latest_block_number().await, Ok(100));
        assert_eq!(
            source
                .reconnect_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
    }

    /// Varsayılan (no-op) reconnect: bağlantı kavramı olmayan mock'lar trait
    /// güncellemesinden etkilenmez, FailingLogSource reconnect SONRASI da
    /// hata döndürmeye devam eder (no-op sözleşmesinin kanıtı).
    #[tokio::test]
    async fn default_reconnect_is_a_noop_for_sources_without_connections() {
        use crate::ethereum_watcher::EthLogSource;
        let source = FailingLogSource;
        assert!(source.reconnect().await.is_ok());
        assert!(source.latest_block_number().await.is_err());
    }
}
