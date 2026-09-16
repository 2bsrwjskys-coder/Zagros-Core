// Zagros Relayer, Ethereum tarafı izleyici: `TokensLocked` decode + onay
// derinliği (reorg güvenliği); bağlantı kurma ve saf decode/onay mantığı (ağsız test edilebilir).

use ethers_core::abi::{Event, EventParam, ParamType, RawLog};
use ethers_core::types::{Address as EthAddress, Filter, Log, H256, U256};
use ethers_providers::{Middleware, Provider, ProviderError, Ws};
use secp256k1::SecretKey;
use std::sync::Arc;
use std::time::Duration;

/// Zincirden okunmuş, henüz onay derinliğini geçip geçmediği
/// değerlendirilmemiş ham bir `TokensLocked` olayı.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokensLockedEvent {
    pub sender: EthAddress,
    pub token: EthAddress,
    pub amount: U256,
    /// Kullanıcı Ethereum'da "otomatik ZAGROS'a çevir" kutusunu işaretledi mi.
    /// Zincirdeki olayın parçası; Zagros mint önerisine AYNEN taşınmalıdır,
    /// aksi halde kullanıcının talebi sessizce düşer ve düz ZERENYA alır.
    pub auto_swap: bool,
    /// 🛡️ Kullanıcının `lockTokens`'ta belirttiği minimum ZAGROS çıktısı
    /// (yalnızca `auto_swap=true` iken anlamlı). Zincirdeki olayın PARÇASI,
    /// böylece hiçbir relayer/node bunu sessizce değiştiremez; `BridgeProposal`'a
    /// AYNEN taşınmalı, aksi halde kullanıcının slippage koruması sessizce düşer.
    pub min_amount_out: U256,
    pub deposit_timestamp: U256,
    pub eth_tx_hash: H256,
    pub block_number: u64,
}

/// `TokensLocked(address indexed sender, address indexed token, uint256 amount,
/// bool autoSwapToZagros, uint256 minAmountOut, uint256 timestamp)` ABI tanımı;
/// topic0 buradan türer. 🚨 KONTRATLA BİREBİR AYNI OLMALI: tek parametre
/// eksikse hash başka çıkar, filtre hiç eşleşmez (`bool` eksikken haberci
/// aylarca sıfır olay gördü, PAXG kasada kaldı). `minAmountOut` topic0'ı
/// değiştirir, yeni Gateway deploy'u gerektirir; eski kontratı bu kod çözemez.
pub fn tokens_locked_event_abi() -> Event {
    Event {
        name: "TokensLocked".to_string(),
        inputs: vec![
            EventParam {
                name: "sender".to_string(),
                kind: ParamType::Address,
                indexed: true,
            },
            EventParam {
                name: "token".to_string(),
                kind: ParamType::Address,
                indexed: true,
            },
            EventParam {
                name: "amount".to_string(),
                kind: ParamType::Uint(256),
                indexed: false,
            },
            EventParam {
                name: "autoSwapToZagros".to_string(),
                kind: ParamType::Bool,
                indexed: false,
            },
            EventParam {
                name: "minAmountOut".to_string(),
                kind: ParamType::Uint(256),
                indexed: false,
            },
            EventParam {
                name: "timestamp".to_string(),
                kind: ParamType::Uint(256),
                indexed: false,
            },
        ],
        anonymous: false,
    }
}

/// Ethereum WebSocket uç noktasına bağlanır (`eth_subscribe` için gerekli,
/// HTTP polling ile event'ler kaçırılabilir).
pub async fn connect(ws_url: &str) -> Result<Arc<Provider<Ws>>, ProviderError> {
    let provider = Provider::<Ws>::connect(ws_url).await?;
    Ok(Arc::new(provider))
}

/// Ham bir RPC log'unu `TokensLockedEvent`'e çözer. `log.transaction_hash`/
/// `log.block_number` eksikse (örn. hâlâ pending bir log) `None` döner, bir
/// olay onay derinliği mantığına asla eksik bilgiyle giremez.
pub fn decode_tokens_locked(log: &Log) -> Option<TokensLockedEvent> {
    let raw = RawLog {
        topics: log.topics.clone(),
        data: log.data.to_vec(),
    };
    let parsed = tokens_locked_event_abi().parse_log(raw).ok()?;

    let sender = parsed
        .params
        .iter()
        .find(|p| p.name == "sender")?
        .value
        .clone()
        .into_address()?;
    let token = parsed
        .params
        .iter()
        .find(|p| p.name == "token")?
        .value
        .clone()
        .into_address()?;
    let amount = parsed
        .params
        .iter()
        .find(|p| p.name == "amount")?
        .value
        .clone()
        .into_uint()?;
    let auto_swap = parsed
        .params
        .iter()
        .find(|p| p.name == "autoSwapToZagros")?
        .value
        .clone()
        .into_bool()?;
    let min_amount_out = parsed
        .params
        .iter()
        .find(|p| p.name == "minAmountOut")?
        .value
        .clone()
        .into_uint()?;
    let deposit_timestamp = parsed
        .params
        .iter()
        .find(|p| p.name == "timestamp")?
        .value
        .clone()
        .into_uint()?;

    Some(TokensLockedEvent {
        sender,
        token,
        amount,
        auto_swap,
        min_amount_out,
        deposit_timestamp,
        eth_tx_hash: log.transaction_hash?,
        block_number: log.block_number?.as_u64(),
    })
}

/// Bir olayın en az `confirmation_depth` blok onayı alıp almadığını
/// belirler (reorg güvenliği, Zagros tarafında bu kavram yok, tek-düğüm/
/// anlık kesinlik, ama Ethereum tarafı için zorunlu).
pub fn is_confirmed(event_block: u64, latest_block: u64, confirmation_depth: u64) -> bool {
    latest_block.saturating_sub(event_block) >= confirmation_depth
}

// 🌉 FAZ4: SAF (ağsız, tam test edilebilir) yardımcılar, reconnect backoff,
// gap/reorg tarama aralığı ve onaylanmış-olay filtresi.

/// Üstel geri çekilme: her başarısız denemede süre 2 katına çıkar, `max`'ta
/// sınırlanır. WS koptuğunda yeniden bağlanma bekleme süresi için.
pub fn next_backoff(current: Duration, max: Duration) -> Duration {
    current.saturating_mul(2).min(max)
}

/// Olay taramasının parametreleri. Tek tek argüman olarak taşınırlarsa imzalar
/// şişer ve çağrı yerlerinde sıraları kolayca karışır (hepsi `u64`).
#[derive(Debug, Clone, Copy)]
pub struct ScanParams {
    /// Kaç blok onay beklenecek (reorg güvenliği).
    pub confirmation_depth: u64,
    /// Yeniden bağlanma/reorg sonrası kaç blok geriye dönülüp yeniden taranacak.
    pub reorg_buffer: u64,
    /// İlk taramanın başlayacağı blok (kasanın deploy bloğu).
    pub start_block: u64,
    /// Tek `eth_getLogs` çağrısının azami blok aralığı (sağlayıcı limiti).
    pub max_range: u64,
}

/// Sonraki tarama aralığı: yalnız onaylı tip'e kadar (`latest - confirmation_depth`),
/// `from` = son işlenen + 1 eksi `reorg_buffer` (idempotent yeniden tarama);
/// yeni onaylı blok yoksa `None`. 🚨 `start_block`: ilk tarama buradan, 0'dan
/// değil (kasa blok 25,6 M'de; sağlayıcılar tüm zinciri reddeder).
/// `max_range`: tek `eth_getLogs` çağrısının azami blok sayısı, yetişme parçalı.
pub fn catch_up_range(
    last_processed: Option<u64>,
    latest_block: u64,
    params: ScanParams,
) -> Option<(u64, u64)> {
    let ScanParams {
        confirmation_depth,
        reorg_buffer,
        start_block,
        max_range,
    } = params;
    let confirmed_tip = latest_block.checked_sub(confirmation_depth)?;
    let from = match last_processed {
        Some(l) => l.saturating_add(1).saturating_sub(reorg_buffer),
        None => start_block,
    };
    if from > confirmed_tip {
        return None;
    }
    // Pencereyi sağlayıcı limitine kırp. max_range=0 anlamsız olduğu için en az 1.
    let span = max_range.max(1);
    let to = confirmed_tip.min(from.saturating_add(span - 1));
    Some((from, to))
}

/// Ham log'lardan yalnızca decode edilebilen VE onay derinliğini geçmiş
/// `TokensLockedEvent`'leri süzer (saf, event pump'ın çekirdek karar mantığı).
pub fn confirmed_events(
    logs: &[Log],
    latest_block: u64,
    confirmation_depth: u64,
) -> Vec<TokensLockedEvent> {
    logs.iter()
        .filter_map(decode_tokens_locked)
        .filter(|ev| is_confirmed(ev.block_number, latest_block, confirmation_depth))
        .collect()
}

// 🌉 FAZ4: Mockable Ethereum soyutlamaları, iş mantığı canlı düğüm olmadan
// (in-memory Mock ile) test edilebilsin diye.

/// Inbound event pump'ın ihtiyaç duyduğu Ethereum OKUMALARI. Canlı impl
/// `LiveEthereum`, testler in-memory bir mock kullanır.
#[allow(async_fn_in_trait)]
pub trait EthLogSource {
    /// Zincirin en son (head) blok numarası.
    async fn latest_block_number(&self) -> Result<u64, String>;
    /// Gateway'deki `[from_block, to_block]` aralığındaki `TokensLocked` log'ları.
    async fn tokens_locked_logs(&self, from_block: u64, to_block: u64) -> Result<Vec<Log>, String>;
    /// İşlemin gerçekten var olup olmadığını ve loglarını doğrudan sorgular;
    /// bekleyen mint önerisi blok taramasız doğrulanır. Yoksa `Ok(None)` (eş imza RED).
    async fn transaction_receipt_logs(&self, tx_hash: H256) -> Result<Option<Vec<Log>>, String>;

    /// 🚨 Ölü WS istemcisiyle sonsuz yeniden deneme 35 saat sürmüştü; pump
    /// döngüsü her hata turunda bunu çağırır. Varsayılan no-op (mock'lar).
    async fn reconnect(&self) -> Result<(), String> {
        Ok(())
    }
}

/// `EthLogSource` + `EthereumBridge`'in canlı (Provider<Ws>-destekli)
/// implementasyonu. Ağ-dokunan tüm Ethereum işlemleri burada toplanır;
/// döngüler bu trait'ler üzerinden çalıştığı için mock'lanabilir kalır.
pub struct LiveEthereum {
    /// RwLock: `reconnect()` ölü WS oturumunu TAZE bir bağlantıyla değiştirir;
    /// okuma yolları kilidi yalnızca Arc klonlayacak kadar tutar.
    pub provider: tokio::sync::RwLock<Arc<Provider<Ws>>>,
    /// `reconnect()`'in yeniden bağlanabilmesi için saklanan uç nokta.
    pub ws_url: String,
    pub gateway: EthAddress,
    pub ethereum_signing_key: SecretKey,
    pub ethereum_relayer_address: EthAddress,
}

impl EthLogSource for LiveEthereum {
    async fn latest_block_number(&self) -> Result<u64, String> {
        let provider = self.provider.read().await.clone();
        provider
            .get_block_number()
            .await
            .map(|n| n.as_u64())
            .map_err(|e| format!("get_block_number: {}", e))
    }

    async fn tokens_locked_logs(&self, from_block: u64, to_block: u64) -> Result<Vec<Log>, String> {
        let filter = Filter::new()
            .address(self.gateway)
            .from_block(from_block)
            .to_block(to_block)
            .topic0(tokens_locked_event_abi().signature());
        let provider = self.provider.read().await.clone();
        provider
            .get_logs(&filter)
            .await
            .map_err(|e| format!("get_logs(TokensLocked): {}", e))
    }

    async fn transaction_receipt_logs(&self, tx_hash: H256) -> Result<Option<Vec<Log>>, String> {
        let provider = self.provider.read().await.clone();
        let receipt = provider
            .get_transaction_receipt(tx_hash)
            .await
            .map_err(|e| format!("get_transaction_receipt: {}", e))?;
        // 🛡️ Gateway adres filtresi burada da uygulanır: aynı topic0'lı ama başka
        // kontrattan gelen sahte log `decode_tokens_locked` ile ayırt edilemezdi.
        Ok(receipt.map(|r| {
            r.logs
                .into_iter()
                .filter(|log| log.address == self.gateway)
                .collect()
        }))
    }
    async fn reconnect(&self) -> Result<(), String> {
        // Önce YENİ bağlantı kurulur, ancak başarılıysa eskisiyle yer
        // değiştirilir, kurulamazsa elde ölü de olsa mevcut istemci kalır ve
        // bir sonraki tur yeniden dener (asla istemcisiz kalınmaz).
        let fresh = connect(&self.ws_url)
            .await
            .map_err(|e| format!("WS yeniden bağlanamadı ({}): {}", self.ws_url, e))?;
        *self.provider.write().await = fresh;
        Ok(())
    }
}

// `EthereumBridge` YOK: çekim kullanıcının `claimTokens`ıyla, haberci Ethereum'a
// işlem göndermez; çift çekim koruması kontratın `processedHashes`inde.

#[cfg(test)]
mod tests {
    use super::*;

    /// 🚨 Eski (V1) ABI'ye karşı sabitleme, donmuş yerel kopyayla: ABI drift
    /// düzeltmesinin (`bool` eksikliği) kanıtı production fonksiyonundan bağımsız korunur.
    mod against_the_live_mainnet_contract_pending_redeploy {
        use super::*;

        /// Ana ağdaki gerçek (henüz `minAmountOut` İÇERMEYEN) `TokensLocked`
        /// log'larının topic0'ı.
        const ONCHAIN_TOPIC0: &str =
            "56ef88e773deda20c9509513ed9d7d3904af442a3520b3444810c1e72427cc2e";

        /// Şu an mainnet'te YAŞAYAN kontratın ESKİ (minAmountOut'suz) ABI'si,
        /// yalnızca bu tarihsel regresyon testi için donmuş bir kopya.
        fn legacy_pre_slippage_event_abi() -> Event {
            Event {
                name: "TokensLocked".to_string(),
                inputs: vec![
                    EventParam {
                        name: "sender".to_string(),
                        kind: ParamType::Address,
                        indexed: true,
                    },
                    EventParam {
                        name: "token".to_string(),
                        kind: ParamType::Address,
                        indexed: true,
                    },
                    EventParam {
                        name: "amount".to_string(),
                        kind: ParamType::Uint(256),
                        indexed: false,
                    },
                    EventParam {
                        name: "autoSwapToZagros".to_string(),
                        kind: ParamType::Bool,
                        indexed: false,
                    },
                    EventParam {
                        name: "timestamp".to_string(),
                        kind: ParamType::Uint(256),
                        indexed: false,
                    },
                ],
                anonymous: false,
            }
        }

        #[test]
        fn topic0_matches_the_currently_deployed_contract() {
            let computed = hex::encode(legacy_pre_slippage_event_abi().signature().as_bytes());
            assert_eq!(
                computed, ONCHAIN_TOPIC0,
                "Bu tarihsel ABI kopyasi bile mainnet'teki GERCEK (henuz \
                 redeploy edilmemis) kontrattan ayristi - bu asla olmamali, \
                 cunku bu kopya donduruldu"
            );
        }

        /// Ana ağdan gerçek yatırma log'u (blok 25625007): ZSC/USDC döneminden
        /// tarihsel işlem, token adı DEĞİŞTİRİLEMEZ. Yerel eski ABI ile elle çözülür.
        #[test]
        fn decodes_a_real_mainnet_deposit_log_under_the_legacy_abi() {
            let log = Log {
                address: "0xbeda78b7526e2c1cad82c94fe91fcbf9612e521f"
                    .parse()
                    .unwrap(),
                topics: vec![
                    H256::from_slice(&hex::decode(ONCHAIN_TOPIC0).unwrap()),
                    H256::from_slice(
                        &hex::decode(
                            "0000000000000000000000004f0b2551e2c46292de5e32941c3277541e9e4568",
                        )
                        .unwrap(),
                    ),
                    H256::from_slice(
                        &hex::decode(
                            "000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
                        )
                        .unwrap(),
                    ),
                ],
                data: ethers_core::types::Bytes::from(
                    hex::decode(
                        "00000000000000000000000000000000000000000000000000000000001e8480\
                         0000000000000000000000000000000000000000000000000000000000000000\
                         000000000000000000000000000000000000000000000000000000006a67777f"
                            .replace(['\\', '\n', ' '], ""),
                    )
                    .unwrap(),
                ),
                block_hash: None,
                block_number: Some(25_625_007u64.into()),
                transaction_hash: Some(H256::repeat_byte(0x62)),
                transaction_index: None,
                log_index: None,
                transaction_log_index: None,
                log_type: None,
                removed: Some(false),
            };

            let raw = RawLog {
                topics: log.topics.clone(),
                data: log.data.to_vec(),
            };
            let parsed = legacy_pre_slippage_event_abi()
                .parse_log(raw)
                .expect("gercek ana ag log'u cozulemedi");
            let amount = parsed
                .params
                .iter()
                .find(|p| p.name == "amount")
                .unwrap()
                .value
                .clone()
                .into_uint()
                .unwrap();
            let auto_swap = parsed
                .params
                .iter()
                .find(|p| p.name == "autoSwapToZagros")
                .unwrap()
                .value
                .clone()
                .into_bool()
                .unwrap();

            assert_eq!(amount, U256::from(2_000_000u64), "2.00 USDC");
            assert!(!auto_swap);

            // Ve bu tutar ZERENYA'ye ölçeklendiğinde tam 2 ZERENYA etmeli.
            let zerenya = zagros_types::bridge_amount::scale_token_to_zerenya(amount.as_u128(), 6)
                .expect("olcekleme basarisiz");
            assert_eq!(zerenya, 2_000_000_000_000_000_000);
        }
    }

    /// 🚧 Yeni kontrat henüz deploy edilmediğinden gerçek veriyle pinlenemiyor;
    /// topic0'ın tanımdan tutarlı türediği ve 6 alanlı log'un çözüldüğü kanıtlanır.
    mod against_the_upgraded_contract {
        use super::*;
        use ethers_core::abi::{encode, Token};
        use ethers_core::types::{Bytes, H160};

        #[test]
        fn decodes_a_synthetic_log_with_min_amount_out() {
            let sender = H160::repeat_byte(0x11);
            let token = H160::repeat_byte(0x22);
            let amount = U256::from(2_000_000u64);
            let min_amount_out = U256::from(1_950_000u64);
            let timestamp = U256::from(1_800_000_000u64);

            let log = Log {
                address: H160::repeat_byte(0x33),
                topics: vec![
                    tokens_locked_event_abi().signature(),
                    H256::from(sender),
                    H256::from(token),
                ],
                data: Bytes::from(encode(&[
                    Token::Uint(amount),
                    Token::Bool(true),
                    Token::Uint(min_amount_out),
                    Token::Uint(timestamp),
                ])),
                block_hash: None,
                block_number: Some(1_000u64.into()),
                transaction_hash: Some(H256::repeat_byte(0x44)),
                transaction_index: None,
                log_index: None,
                transaction_log_index: None,
                log_type: None,
                removed: Some(false),
            };

            let event = decode_tokens_locked(&log).expect("yeni ABI ile cozulemedi");
            assert_eq!(event.amount, amount);
            assert!(event.auto_swap);
            assert_eq!(event.min_amount_out, min_amount_out);
            assert_eq!(event.deposit_timestamp, timestamp);
        }
    }

    use ethers_core::abi::{encode, Token};
    use ethers_core::types::{Bytes, H160};

    fn sample_log() -> Log {
        let sender = H160::repeat_byte(0xAA);
        let token = H160::repeat_byte(0xBB);
        let amount = U256::from(1_000u64);
        let min_amount_out = U256::from(900u64);
        let timestamp = U256::from(1_700_000_000u64);

        let topic0 = tokens_locked_event_abi().signature();
        let topic1 = H256::from(sender);
        let topic2 = H256::from(token);
        let data = encode(&[
            Token::Uint(amount),
            Token::Bool(false),
            Token::Uint(min_amount_out),
            Token::Uint(timestamp),
        ]);

        Log {
            address: H160::repeat_byte(0xCC),
            topics: vec![topic0, topic1, topic2],
            data: Bytes::from(data),
            block_hash: None,
            block_number: Some(999u64.into()),
            transaction_hash: Some(H256::repeat_byte(0xDD)),
            transaction_index: None,
            log_index: None,
            transaction_log_index: None,
            log_type: None,
            removed: Some(false),
        }
    }

    #[test]
    fn decodes_a_well_formed_tokens_locked_log() {
        let event = decode_tokens_locked(&sample_log()).expect("should decode");
        assert_eq!(event.sender, H160::repeat_byte(0xAA));
        assert_eq!(event.token, H160::repeat_byte(0xBB));
        assert_eq!(event.amount, U256::from(1_000u64));
        assert_eq!(event.min_amount_out, U256::from(900u64));
        assert_eq!(event.deposit_timestamp, U256::from(1_700_000_000u64));
        assert_eq!(event.block_number, 999);
    }

    #[test]
    fn returns_none_for_a_log_missing_the_transaction_hash() {
        let mut log = sample_log();
        log.transaction_hash = None;
        assert!(decode_tokens_locked(&log).is_none());
    }

    #[test]
    fn returns_none_for_mismatched_event_data() {
        let mut log = sample_log();
        log.data = Bytes::from(vec![0u8; 4]); // too short to be two uint256s
        assert!(decode_tokens_locked(&log).is_none());
    }

    #[test]
    fn confirmation_depth_gate() {
        assert!(!is_confirmed(100, 105, 12), "5 confirmations < 12 required");
        assert!(is_confirmed(100, 112, 12), "exactly 12 confirmations");
        assert!(is_confirmed(100, 200, 12), "well past the required depth");
        // Bir olay her zaman kendi bloğunda "henüz onaylanmamış" sayılmalı.
        assert!(!is_confirmed(100, 100, 12));
    }

    // ---- 🌉 FAZ4: reconnect backoff + gap/reorg + confirmed-event filtresi ----

    #[test]
    fn backoff_doubles_and_caps_at_max() {
        let max = Duration::from_secs(60);
        assert_eq!(
            next_backoff(Duration::from_secs(1), max),
            Duration::from_secs(2)
        );
        assert_eq!(
            next_backoff(Duration::from_secs(16), max),
            Duration::from_secs(32)
        );
        assert_eq!(
            next_backoff(Duration::from_secs(30), max),
            Duration::from_secs(60)
        );
        // Tavana ulaşıp aşmamalı.
        assert_eq!(
            next_backoff(Duration::from_secs(60), max),
            Duration::from_secs(60)
        );
        assert_eq!(
            next_backoff(Duration::from_secs(100), max),
            Duration::from_secs(60)
        );
    }

    /// Sinirsiz pencere: sadece onay derinligi + reorg tamponu davranisi.
    fn unbounded(confirmation_depth: u64, reorg_buffer: u64) -> ScanParams {
        ScanParams {
            confirmation_depth,
            reorg_buffer,
            start_block: 0,
            max_range: u64::MAX,
        }
    }

    #[test]
    fn catch_up_range_respects_confirmation_depth_and_reorg_buffer() {
        // latest 100, depth 12 → confirmed_tip 88.
        // İlk tarama (last=None) → (0, 88).
        assert_eq!(catch_up_range(None, 100, unbounded(12, 6)), Some((0, 88)));
        // last=50 → from = 51 - 6 (reorg buffer geri çekme) = 45, to = 88.
        assert_eq!(
            catch_up_range(Some(50), 100, unbounded(12, 6)),
            Some((45, 88))
        );
        // Onaylanmış blok yok (latest < depth) → None.
        assert_eq!(catch_up_range(None, 10, unbounded(12, 6)), None);
        // last tip'te, buffer 0 → yeni onaylanmış blok yok → None.
        assert_eq!(catch_up_range(Some(88), 100, unbounded(12, 0)), None);
        // last tip'te ama buffer>0 → son birkaç blok yeniden taranır (idempotent).
        assert_eq!(
            catch_up_range(Some(88), 100, unbounded(12, 6)),
            Some((83, 88))
        );
    }

    /// 🚨 İlk tarama 0'DAN DEĞİL, kasanın deploy bloğundan başlamalı.
    /// 0'dan başlamak hem anlamsız (kontrat yoktu) hem de sağlayıcı limitleri
    /// yüzünden sorguyu tamamen reddettirip HİÇBİR mevduatın görülmemesine yol açar.
    #[test]
    fn the_first_scan_starts_at_the_gateway_deploy_block_not_genesis() {
        let params = ScanParams {
            confirmation_depth: 12,
            reorg_buffer: 6,
            start_block: 25_623_389,
            max_range: u64::MAX,
        };
        assert_eq!(
            catch_up_range(None, 25_623_500, params),
            Some((25_623_389, 25_623_488))
        );
    }

    /// 🚨 Pencere sağlayıcı limitine kırpılmalı (Alchemy ücretsiz plan: 10 blok).
    /// Kırpılmazsa `eth_getLogs` reddedilir ve event pump hiç çalışmaz.
    #[test]
    fn the_window_is_clamped_to_the_provider_limit() {
        let params = ScanParams {
            confirmation_depth: 12,
            reorg_buffer: 0,
            start_block: 1_000,
            max_range: 10,
        };
        // confirmed_tip = 5_000 - 12 = 4_988 ama pencere 10 blokla sınırlı.
        assert_eq!(catch_up_range(None, 5_000, params), Some((1_000, 1_009)));
        // Sonraki tur: 1_010'dan itibaren yine 10 blok.
        assert_eq!(
            catch_up_range(Some(1_009), 5_000, params),
            Some((1_010, 1_019))
        );
        // Tip'e yaklaşıldığında pencere DEĞİL, tip sınırlar.
        assert_eq!(
            catch_up_range(Some(4_985), 5_000, params),
            Some((4_986, 4_988))
        );
    }

    /// max_range = 0 anlamsızdır; en az 1 bloka yuvarlanmalı (sonsuz döngü olmasın).
    #[test]
    fn a_zero_max_range_still_advances_by_one_block() {
        let params = ScanParams {
            confirmation_depth: 0,
            reorg_buffer: 0,
            start_block: 100,
            max_range: 0,
        };
        assert_eq!(catch_up_range(None, 200, params), Some((100, 100)));
    }

    #[test]
    fn confirmed_events_keeps_only_confirmed_decodable_logs() {
        let logs = vec![sample_log()]; // blok 999
                                       // latest 1011, depth 12 → 12 onay → dahil.
        assert_eq!(confirmed_events(&logs, 1011, 12).len(), 1);
        // latest 1005, depth 12 → 6 onay → hariç.
        assert!(confirmed_events(&logs, 1005, 12).is_empty());
        // decode edilemeyen log (bozuk data) süzülmeli.
        let mut bad = sample_log();
        bad.data = Bytes::from(vec![0u8; 4]);
        assert!(confirmed_events(&[bad], 2000, 12).is_empty());
    }
}
