//! `ZagrosBehaviour` ve `Swarm`: TCP+Noise+Yamux, gossipsub, identify, isteğe
//! bağlı mdns. Kademlia DHT kasıtlı yok: küçük bilinen küme için statik
//! `bootstrap_nodes` yeter, DHT gereksiz saldırı yüzeyi eklerdi.

use std::time::Duration;

use libp2p::request_response;
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::swarm::NetworkBehaviour;
use libp2p::{
    connection_limits, gossipsub, identify, identity::Keypair, mdns, noise, tcp, yamux,
    StreamProtocol, Swarm, SwarmBuilder,
};
use zagros_primitives::ZagrosError;
use zagros_types::config::NetworkConfig;

use crate::codec::{Sync2Codec, SyncCodec};
use crate::messages::{block_topic, consensus_topic, peers_topic, tx_topic};

const PROTOCOL_VERSION: &str = "/zagros/1.0.0";
const SYNC_PROTOCOL: &str = "/zagros/sync/1";
/// G6: QC'li catch-up (spec §9). `/sync/1` ile yan yana yaşar.
const SYNC2_PROTOCOL: &str = "/zagros/sync/2";

#[derive(NetworkBehaviour)]
pub struct ZagrosBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub identify: identify::Behaviour,
    pub mdns: Toggle<mdns::tokio::Behaviour>,
    pub sync: request_response::Behaviour<SyncCodec>,
    pub sync2: request_response::Behaviour<Sync2Codec>,
    /// 🛡️ `max_peers` transport seviyesinde `libp2p-connection-limits` ile
    /// UYGULANIR; yoksa sınırsız gelen bağlantı kabul edilirdi.
    pub connection_limits: connection_limits::Behaviour,
    /// 🛡️ Sentry mimarisi: `private_peers` doluysa YALNIZ o
    /// PeerId'lerle bağlantı (gelen+giden) kabul edilir; başka herkes Noise el
    /// sıkışmasından hemen sonra, gossip/sync'e ulaşmadan düşürülür. Boşsa
    /// (sentry/RPC/açık düğüm) Toggle kapalı → davranış değişmez.
    pub allow_list:
        Toggle<libp2p::allow_block_list::Behaviour<libp2p::allow_block_list::AllowedPeers>>,
}

/// `private_peers`/`sentry_addrs` gibi listelerden PeerId çıkarır; `/p2p/`
/// taşımayan girişler atlanır (config doğrulaması zaten reddediyor).
pub fn peer_ids_of(addrs: &[String]) -> Vec<libp2p::PeerId> {
    addrs
        .iter()
        .filter_map(|a| a.parse::<libp2p::Multiaddr>().ok())
        .filter_map(|m| {
            m.iter().find_map(|p| match p {
                libp2p::multiaddr::Protocol::P2p(id) => Some(id),
                _ => None,
            })
        })
        .collect()
}

/// `keypair`'in `PeerId`'sini ve gossipsub tx topic'ini `network_id`'ye göre
/// hazırlayıp dinlemeye başlayan tam yapılandırılmış bir `Swarm` döner.
/// Çağıran (bkz. `zagros-cli/src/main.rs`, Faz 3), döneni doğrudan `tasks:
/// JoinSet` içine spawn edilecek servis döngüsüne (`crate::service::run`) verir.
pub fn build_swarm(
    keypair: Keypair,
    config: &NetworkConfig,
) -> Result<Swarm<ZagrosBehaviour>, ZagrosError> {
    let mut swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|e| ZagrosError::P2pError(format!("TCP/Noise/Yamux taşıması kurulamadı: {e}")))?
        .with_behaviour(|key| {
            // `TryIntoBehaviour`, `Result<B, Box<dyn Error + Send + Sync>>` için
            // tanımlı, çıplak `String` DEĞİL (bkz. libp2p::builder::phase::
            // behaviour'daki `impl TryIntoBehaviour for Result<B, Box<dyn ...>>`).
            let build = || -> Result<ZagrosBehaviour, Box<dyn std::error::Error + Send + Sync>> {
                // Gossipsub: bloklar büyük olabildiğinden 16 MiB tavan. G5: mesajlar
                // uygulama doğrulaması olmadan yayılmaz (`validate_messages`).
                let gossipsub_config = gossipsub::ConfigBuilder::default()
                    .max_transmit_size(16 * 1024 * 1024)
                    .validation_mode(gossipsub::ValidationMode::Strict)
                    .validate_messages()
                    .build()
                    .map_err(|e| format!("gossipsub config kurulamadı: {e}"))?;
                let gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossipsub_config,
                )
                .map_err(|e| format!("gossipsub davranışı kurulamadı: {e}"))?;

                // 🛡️ Validatör (private_peers dolu) dinleme adreslerini identify
                // ile İLAN ETMEZ: sentry'ler validatörün adresini öğrense bile ağa
                // yaymaz; yabancı bir peer identify'dan validatörü bulamaz.
                let identify = identify::Behaviour::new(
                    identify::Config::new(PROTOCOL_VERSION.to_string(), key.public())
                        .with_hide_listen_addrs(!config.private_peers.is_empty()),
                );

                let mdns = mdns::tokio::Behaviour::new(
                    mdns::Config::default(),
                    key.public().to_peer_id(),
                )?;

                let sync = request_response::Behaviour::new(
                    [(
                        StreamProtocol::new(SYNC_PROTOCOL),
                        request_response::ProtocolSupport::Full,
                    )],
                    request_response::Config::default(),
                );

                let sync2 = request_response::Behaviour::new(
                    [(
                        StreamProtocol::new(SYNC2_PROTOCOL),
                        request_response::ProtocolSupport::Full,
                    )],
                    request_response::Config::default(),
                );

                // 🛡️ Kurulu bağlantı tavanı = max_peers + duyurulmuş validatör sentry'lerine
                // ayrılmış slotlar (yalnız açık düğümde); uygulama service.rs'te.
                let reserved = if config.private_peers.is_empty() {
                    config.reserved_validator_slots
                } else {
                    0
                };
                let connection_limits = connection_limits::Behaviour::new(
                    connection_limits::ConnectionLimits::default()
                        .with_max_established(Some(config.max_peers as u32 + reserved))
                        // Aynı peer'dan en fazla 2 bağlantı (libp2p yeniden
                        // arama çakışmaları için 1 yerine 2); tek bir kimliğin
                        // tüm slotları doldurması imkânsız.
                        .with_max_established_per_peer(Some(2))
                        // Gelen yönlü tavan: slotların en fazla 2/3'ü dışarıdan
                        // gelen bağlantılara; kalan 1/3 bizim aradığımız
                        // (bootstrap/duyurulmuş) peer'lara hep açık kalır.
                        .with_max_established_incoming(Some(
                            ((config.max_peers as u32 + reserved) * 2) / 3,
                        ))
                        // 🛡️ El sıkışma aşamasındaki bağlantılar da sınırlanır: `with_max_established`
                        // yalnız kurulmuşları sayar, saldırgan binlerce yarı açık bağlantıyla
                        // bellek/soket tüketebilirdi. Tavan `max_peers` ile aynı.
                        .with_max_pending_incoming(Some(config.max_peers as u32))
                        .with_max_pending_outgoing(Some(config.max_peers as u32)),
                );

                let allow_list = if config.private_peers.is_empty() {
                    None
                } else {
                    let mut b = libp2p::allow_block_list::Behaviour::<
                        libp2p::allow_block_list::AllowedPeers,
                    >::default();
                    for id in peer_ids_of(&config.private_peers) {
                        b.allow_peer(id);
                    }
                    Some(b)
                };

                Ok(ZagrosBehaviour {
                    gossipsub,
                    identify,
                    mdns: Toggle::from(if config.mdns_enabled {
                        Some(mdns)
                    } else {
                        None
                    }),
                    sync,
                    sync2,
                    connection_limits,
                    allow_list: Toggle::from(allow_list),
                })
            };
            build()
        })
        .map_err(|e| ZagrosError::P2pError(format!("ağ davranışı kurulamadı: {e}")))?
        // 🛡️ libp2p varsayılan bağlantı+el sıkışma bütçesi 10 sn; kıtalar arası
        // topolojide tek TCP retransmisyonu aşıyor, 40+ saat boyunca tüm sağlayıcı
        // çiftlerinde "Failed to negotiate ... Timeout" ile kanıtlandı (tcpdump: MTU
        // sorunu yok), canlılık kaybı ve haksız jail üretiyordu. 45 sn sınırlı ama bol pay bırakır.
        .with_swarm_config(std::convert::identity)
        .with_connection_timeout(Duration::from_secs(45))
        .build();

    swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&tx_topic(config.network_id))
        .map_err(|e| ZagrosError::P2pError(format!("tx topic'ine abone olunamadı: {e}")))?;
    swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&block_topic(config.network_id))
        .map_err(|e| ZagrosError::P2pError(format!("blok topic'ine abone olunamadı: {e}")))?;
    swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&consensus_topic(config.network_id))
        .map_err(|e| ZagrosError::P2pError(format!("konsensus topic'ine abone olunamadı: {e}")))?;
    swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&peers_topic(config.network_id))
        .map_err(|e| ZagrosError::P2pError(format!("peers topic'ine abone olunamadı: {e}")))?;

    // 🛡️ Sentry/açık düğümün dışarıya duyuracağı adresi (NAT/bulut arkasında
    // dinleme adresi 0.0.0.0/özel IP olur, identify'da işe yaramaz).
    if let Some(ext) = &config.external_addr {
        match ext.parse::<libp2p::Multiaddr>() {
            Ok(addr) => swarm.add_external_address(addr),
            Err(e) => tracing::warn!("⚠️ Geçersiz external_addr ({ext}): {e}"),
        }
    }

    let listen_addr: libp2p::Multiaddr = config.listen_addr.parse().map_err(|e| {
        ZagrosError::P2pError(format!(
            "geçersiz network.listen_addr ({}): {e}",
            config.listen_addr
        ))
    })?;
    swarm
        .listen_on(listen_addr)
        .map_err(|e| ZagrosError::P2pError(format!("dinleme başlatılamadı: {e}")))?;

    for addr in &config.dial_targets() {
        match addr.parse::<libp2p::Multiaddr>() {
            Ok(multiaddr) => {
                if let Err(e) = swarm.dial(multiaddr) {
                    tracing::warn!("⚠️ Bootstrap peer aranamadı ({addr}): {e}");
                }
            }
            Err(e) => tracing::warn!("⚠️ Geçersiz bootstrap adresi ({addr}): {e}"),
        }
    }

    Ok(swarm)
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::core::ConnectedPoint;
    use libp2p::swarm::behaviour::ConnectionEstablished;
    use libp2p::swarm::{ConnectionId, FromSwarm};

    // 🛡️ `max_peers` gerçekten uygulanmalı: gerçek Swarm/TCP yerine (zamanlama
    // deterministik değil) `connection_limits::Behaviour` aynı şekilde kurulup
    // trait metotları doğrudan çağrılır, saf mantık testi.
    #[test]
    fn connection_limits_behaviour_rejects_a_second_connection_beyond_max_established() {
        let mut limits = connection_limits::Behaviour::new(
            connection_limits::ConnectionLimits::default().with_max_established(Some(1)),
        );

        let peer_a = libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id();
        let peer_b = libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id();
        let local_addr: libp2p::Multiaddr = "/ip4/127.0.0.1/tcp/1".parse().unwrap();
        let send_back_addr: libp2p::Multiaddr = "/ip4/127.0.0.1/tcp/2".parse().unwrap();
        let endpoint = ConnectedPoint::Listener {
            local_addr: local_addr.clone(),
            send_back_addr: send_back_addr.clone(),
        };

        // İlk bağlantı: limit (1) henüz doldurulmadı, kabul edilmeli.
        let first = limits.handle_established_inbound_connection(
            ConnectionId::new_unchecked(1),
            peer_a,
            &local_addr,
            &send_back_addr,
        );
        assert!(
            first.is_ok(),
            "ilk bağlantı (limit dolu değilken) kabul edilmeli"
        );

        // `check_limit`'in gördüğü sayaç yalnızca `on_swarm_event` ile
        // artıyor (bkz. `libp2p-connection-limits` kaynağı), `build_swarm`ın
        // ürettiği gerçek bir Swarm'da bunu swarm'ın kendisi tetikler, burada
        // elle simüle ediyoruz.
        limits.on_swarm_event(FromSwarm::ConnectionEstablished(ConnectionEstablished {
            peer_id: peer_a,
            connection_id: ConnectionId::new_unchecked(1),
            endpoint: &endpoint,
            failed_addresses: &[],
            other_established: 0,
        }));

        // İkinci bağlantı: limit (1) artık DOLU, reddedilmeli.
        let second = limits.handle_established_inbound_connection(
            ConnectionId::new_unchecked(2),
            peer_b,
            &local_addr,
            &send_back_addr,
        );
        assert!(
            second.is_err(),
            "ikinci bağlantı (limit=1 dolu iken) REDDEDİLMELİ"
        );
    }

    #[test]
    fn connection_limits_behaviour_allows_unlimited_connections_when_max_peers_is_generous() {
        let mut limits = connection_limits::Behaviour::new(
            connection_limits::ConnectionLimits::default().with_max_established(Some(50)),
        );
        let peer = libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id();
        let local_addr: libp2p::Multiaddr = "/ip4/127.0.0.1/tcp/1".parse().unwrap();
        let send_back_addr: libp2p::Multiaddr = "/ip4/127.0.0.1/tcp/2".parse().unwrap();

        let result = limits.handle_established_inbound_connection(
            ConnectionId::new_unchecked(1),
            peer,
            &local_addr,
            &send_back_addr,
        );
        assert!(
            result.is_ok(),
            "varsayılan (cömert) max_peers ile ilk bağlantı kabul edilmeli"
        );
    }
}
