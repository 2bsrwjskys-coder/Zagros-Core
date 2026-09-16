// Zagros JSON-RPC istemcisi (propose/sign/get-pending/get-recent-burns);
// düz reqwest + serde_json yeterli.

use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use zagros_executor::bridge::BridgeTxType;

#[derive(Debug)]
pub enum ClientError {
    Transport(String),
    /// Sunucunun döndürdüğü gerçek bir JSON-RPC hata nesnesi (örn. -32602
    /// InvalidParams, bkz. zagros-rpc'deki Timestamp Drift Guard).
    Rpc {
        code: i64,
        message: String,
    },
    /// Sunucu 200 döndü ama beklenen alanları içermiyor.
    UnexpectedShape(String),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Transport(msg) => write!(f, "transport error: {}", msg),
            ClientError::Rpc { code, message } => write!(f, "RPC error {}: {}", code, message),
            ClientError::UnexpectedShape(msg) => write!(f, "unexpected response shape: {}", msg),
        }
    }
}

impl std::error::Error for ClientError {}

pub struct ZagrosClient {
    http: reqwest::Client,
    rpc_url: String,
}

impl ZagrosClient {
    pub fn new(rpc_url: String) -> Self {
        Self {
            // 🚨 Açık timeout (30 sn): varsayılanla sonsuz asılı kalınabilir.
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                // Transport error kök nedeni: idle keep-alive bağlantıyı upstream ~60 sn
                // sonra kapatıyor, sonraki istek ölü bağlantıyı kullanıyordu. Havuz kapalı,
                // her istek taze bağlantı (haberci seyrek çağırır, maliyet önemsiz).
                .pool_max_idle_per_host(0)
                .build()
                .expect("reqwest istemcisi kurulamadi"),
            rpc_url,
        }
    }

    async fn call(&self, method: &str, params: Vec<Value>) -> Result<Value, ClientError> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });

        let response = self
            .http
            .post(&self.rpc_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))?;

        let parsed: Value = response
            .json()
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))?;

        // Standart JSON-RPC 2.0 hata nesnesi, şu an sadece Timestamp Drift
        // Guard (zagros-rpc) bunu kullanıyor (-32602 InvalidParams).
        if let Some(error) = parsed.get("error") {
            return Err(ClientError::Rpc {
                code: error.get("code").and_then(|c| c.as_i64()).unwrap_or(0),
                message: error
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("")
                    .to_string(),
            });
        }

        let result = parsed
            .get("result")
            .cloned()
            .ok_or_else(|| ClientError::UnexpectedShape("missing \"result\" field".to_string()))?;

        // Köprü uçlarında hata `result` içine gömülü `{"error": "..."}` döner;
        // kontrol edilmezse "zaten imzalanmış" reddi başarı sanılır (idempotency kırılırdı).
        if let Some(embedded_error) = result.get("error").and_then(|v| v.as_str()) {
            return Err(ClientError::Rpc {
                code: 0,
                message: embedded_error.to_string(),
            });
        }

        Ok(result)
    }

    /// `zagros_proposeBridgeAction`: alanlar `propose_request_message` ile aynı
    /// kanonik mesaja hash'lenip Ed25519 ile imzalanır (sunucu durumu gerekmez).
    #[allow(clippy::too_many_arguments)]
    pub async fn propose_bridge_action(
        &self,
        signing_key: &SigningKey,
        authority_address: &str,
        tx_type: BridgeTxType,
        recipient: &str,
        amount: u128,
        source_chain: &str,
        source_tx_hash: &str,
        timestamp: u64,
        auto_swap: bool,
        amount_out_min: u128,
        chain_id: u64,
    ) -> Result<String, ClientError> {
        let message = zagros_executor::bridge::BridgeManager::propose_request_message(
            &tx_type,
            &recipient.to_string(),
            amount,
            source_chain,
            source_tx_hash,
            timestamp,
            auto_swap,
            amount_out_min,
            chain_id,
        );
        let signature = signing_key.sign(&message);
        let tx_type_str = match tx_type {
            BridgeTxType::Mint => "mint",
            BridgeTxType::Burn => "burn",
        };

        let params = vec![
            json!(tx_type_str),
            json!(recipient),
            json!(amount.to_string()),
            json!(source_chain),
            json!(source_tx_hash),
            json!(timestamp.to_string()),
            json!(auto_swap),
            json!(amount_out_min.to_string()),
            json!(authority_address),
            json!(hex::encode(signing_key.verifying_key().to_bytes())),
            json!(hex::encode(signature.to_bytes())),
        ];

        let result = self.call("zagros_proposeBridgeAction", params).await?;
        result
            .get("proposal_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| {
                ClientError::UnexpectedShape(format!(
                    "propose response missing proposal_id: {:?}",
                    result
                ))
            })
    }

    /// `zagros_signBridgeProposal`: kanonik mesaj proposal_id/nonce içerdiğinden
    /// önerinin tam içeriği önce sunucudan alınmalı; alanlar parametre olarak gelir.
    #[allow(clippy::too_many_arguments)]
    pub async fn sign_bridge_proposal(
        &self,
        signing_key: &SigningKey,
        authority_address: &str,
        proposal_id_hex: &str,
        proposal_signing_message: &[u8],
        timestamp: u64,
    ) -> Result<bool, ClientError> {
        // 🛡️ Sunucu imzayı mesaj + bu imzanın timestamp'ine bağlı türetilmiş mesaja
        // karşı doğrular (`bind_timestamp_to_message`); `timestamp` imza kapsamına girer.
        let bound = zagros_executor::bridge::BridgeManager::bind_timestamp_to_message(
            proposal_signing_message,
            timestamp,
        );
        let signature = signing_key.sign(&bound);

        let params = vec![
            json!(proposal_id_hex),
            json!(authority_address),
            json!(hex::encode(signing_key.verifying_key().to_bytes())),
            json!(hex::encode(signature.to_bytes())),
            json!(timestamp.to_string()),
        ];

        let result = self.call("zagros_signBridgeProposal", params).await?;
        Ok(result
            .get("can_execute")
            .and_then(|v| v.as_bool())
            .unwrap_or(false))
    }

    /// 🎟️ Burn önerisi için EIP-712 claim fişini düğüme bırakır; kullanıcı
    /// `claimTokens`a geçirir. Ayrı kimlik doğrulaması yok, fiş kendini doğrular
    /// (giden HTTP yeter, port açılmaz). Döner: o öneri için toplam fiş sayısı.
    pub async fn submit_claim_voucher(
        &self,
        proposal_id_hex: &str,
        signature_hex: &str,
    ) -> Result<usize, ClientError> {
        let params = vec![json!(proposal_id_hex), json!(signature_hex)];
        let result = self.call("zagros_submitClaimVoucher", params).await?;
        Ok(result
            .get("vouchers_collected")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize)
    }

    /// `zagros_getBridgeProposal`: onay için gereken `timestamp`/`nonce`u almanın
    /// tek yolu (nonce sunucuda atanır, istemci önceden bilemez).
    pub async fn get_bridge_proposal(&self, proposal_id_hex: &str) -> Result<Value, ClientError> {
        let params = vec![json!(proposal_id_hex)];
        self.call("zagros_getBridgeProposal", params).await
    }

    /// `zagros_getPendingBridgeProposals`, kimlik doğrulaması gerekmez.
    pub async fn get_pending_bridge_proposals(&self) -> Result<Vec<Value>, ClientError> {
        let result = self
            .call("zagros_getPendingBridgeProposals", vec![])
            .await?;
        result
            .get("proposals")
            .and_then(|v| v.as_array())
            .cloned()
            .ok_or_else(|| ClientError::UnexpectedShape(format!("{:?}", result)))
    }

    /// `zagros_getRecentBridgeBurns`, kimlik doğrulaması gerekmez. Ham yanıtı
    /// (`{ burns, oldest_index }`) döndürür; imleç-boşluğu (cursor gap) tespiti
    /// için `oldest_index` gerektiğinden, ayrıştırma + fail-closed boşluk kontrolü
    /// `zagros_watcher::parse_burns_response` içinde yapılır (🛡️ [7]).
    pub async fn get_recent_bridge_burns(&self, since_index: u128) -> Result<Value, ClientError> {
        let params = vec![json!(since_index.to_string())];
        self.call("zagros_getRecentBridgeBurns", params).await
    }
}
