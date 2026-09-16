//! Follower senkronizasyon durum makinesi: gossip'te boşluk görülünce çağrılır.
//! Tek proposer modelinde fork yok, akış doğrusal: iste, uygula, gerekirse tekrar iste.

use libp2p::request_response::OutboundRequestId;
use libp2p::PeerId;
use std::sync::Arc;
use zagros_runtime::Runtime;
use zagros_state::State;
use zagros_types::{ArchivedBlockHeader, Transaction};

use crate::messages::{SyncBlock, SyncRequest, SyncResponse};

/// Devam eden tek dış senkronizasyon isteği; bekleyen istek varken yeni boşluk
/// yok sayılır (sonraki turda denenir), peer'a aşırı yüklenilmez.
pub struct PendingSync {
    pub peer: PeerId,
    pub request_id: OutboundRequestId,
    /// Nihai hedef yükseklik, yanıt `sync_batch_size` ile kırpılmışsa
    /// (hâlâ `target`'ın altındaysak) aynı peer'a devam isteği gönderilir.
    pub target: u64,
}

/// Bir boşluk tespit edildiğinde çağrılır. Zaten bekleyen bir istek varsa
/// `None` döner (çağıran hiçbir şey göndermez). `peer` çağıran tarafından
/// seçilir (bkz. `service.rs`'in bağlı-peer listesi).
pub fn request_missing_range(current_height: u64, target_height: u64) -> SyncRequest {
    SyncRequest::GetBlockRange {
        from: current_height + 1,
        to: target_height,
    }
}

/// `SyncRequest`e kendi diskten cevap; herhangi bir node servis edebilir,
/// `block_<N>`/`tx_body_<hash>` kayıtları bağımsız yürütüldüğünden proposer'la aynı.
pub fn build_response(
    state: &Arc<dyn State>,
    request: SyncRequest,
    max_blocks: u64,
) -> SyncResponse {
    match request {
        SyncRequest::GetStatus => {
            let tip_number = state
                .get_account(&"__GLOBAL_BLOCK_HEIGHT__".to_string())
                .ok()
                .flatten()
                .map(|a| a.balance as u64)
                .unwrap_or(0);
            SyncResponse::Status { tip_number }
        }
        SyncRequest::GetBlockRange { from, to } => {
            let clamped_to = to.min(from.saturating_add(max_blocks.saturating_sub(1)));
            let mut blocks = Vec::new();
            for height in from..=clamped_to {
                match read_block(state, height) {
                    Some(block) => blocks.push(block),
                    // Bu yükseklik yok (budanmış/hiç üretilmemiş), burada DUR,
                    // kısmi bir aralık dön (boş olabilir) yerine boşluklu bir
                    // dizi dönmek istemcinin sıralı-uygulama varsayımını bozar.
                    None => break,
                }
            }
            if blocks.is_empty() {
                SyncResponse::NotAvailable
            } else {
                SyncResponse::BlockRange(blocks)
            }
        }
    }
}

fn read_block(state: &Arc<dyn State>, height: u64) -> Option<SyncBlock> {
    let header_acc = state
        .get_account(&zagros_state::block_key(height))
        .ok()
        .flatten()?;
    let header: ArchivedBlockHeader = bincode::deserialize(&header_acc.contract_code).ok()?;

    let mut transactions = Vec::with_capacity(header.tx_hashes.len());
    for tx_id in &header.tx_hashes {
        let tx_acc = state
            .get_account(&zagros_state::tx_body_key(tx_id))
            .ok()
            .flatten()?;
        let tx: Transaction = Transaction::from_stored_bytes(&tx_acc.contract_code).ok()?;
        transactions.push(tx);
    }

    // 🛡️ P2P follower senkronizasyon hatası kök-neden düzeltmesi,
    // bkz. `BridgeManager::collect_proposals_for_relay`'in doc yorumu.
    let bridge_proposals = zagros_executor::bridge::BridgeManager::collect_proposals_for_relay(
        state.as_ref(),
        &transactions,
    );

    Some(SyncBlock {
        header,
        transactions,
        bridge_proposals,
    })
}

/// Bir `SyncResponse::BlockRange` yanıtını sırayla uygular. Bir blok state_root
/// uyuşmazlığı/yürütme hatasıyla REDDEDİLİRSE bu FATAL'dır (bkz. `service::
/// handle_gossip_block`'un AYNI felsefesi), `Err` döner, çağıran panikler.
/// Başarıyla uygulanan blok sayısını döner (hepsi uygulandıysa `blocks.len()`).
pub fn apply_synced_blocks(
    runtime: &Arc<Runtime>,
    blocks: Vec<SyncBlock>,
) -> Result<usize, String> {
    let mut applied = 0;
    for block in blocks {
        let current = runtime.current_block_height().unwrap_or(0) as u64;
        if block.header.number <= current {
            // Bayat/yinelenen, başka bir yoldan (ör. eşzamanlı gossip) zaten
            // uygulanmış olabilir, hata SAYILMAZ.
            applied += 1;
            continue;
        }
        if block.header.number != current + 1 {
            return Err(format!(
                "senkronize edilen blok #{} beklenenle ({}) sıralı DEĞİL",
                block.header.number,
                current + 1
            ));
        }
        runtime
            .apply_external_block(
                block.header.number,
                block.header.timestamp,
                &block.transactions,
                &block.bridge_proposals,
                block.header.state_root,
            )
            .map_err(|e| {
                format!(
                    "blok #{} senkronizasyon sırasında reddedildi: {e:?}",
                    block.header.number
                )
            })?;
        applied += 1;
    }
    Ok(applied)
}
