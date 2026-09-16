// Zagros Relayer: Ethereum yatırmalarını (TokensLocked) Zagros mint önerilerine,
// Zagros çıkışlarını (BridgeBurn) unlock-intent önerilerine çevirir.

pub mod claim;
pub mod config;
pub mod cursor_recover_cmd;
pub mod ethereum_watcher;
pub mod inbound;
pub mod outbound;
pub mod store;
pub mod zagros_client;
pub mod zagros_watcher;

/// Duvar-saati Unix saniyesi. Köprü imzalarının tazelik penceresi (drift guard)
/// gerçek zamanı gerektirdiğinden relayer döngüleri her turda bunu kullanır.
pub fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
