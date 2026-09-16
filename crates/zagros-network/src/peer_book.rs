//! G11 (§9 Redial): peer adres defteri + üstel geri çekilmeli yeniden arama;
//! saf durum makinesi, servis `due()` sorar. Yalnız açılışta bağlanan follower,
//! proposer restart edilince 3+ gün sessizce kopuk kaldı; artık 2 sn'den 60 sn
//! tavanına katlanan aralıklarla inatla aranır, bağlanınca sayaç sıfırlanır.
use std::collections::HashMap;

use libp2p::{Multiaddr, PeerId};

/// İlk yeniden-arama gecikmesi.
pub const BACKOFF_BASE_MS: u64 = 2_000;
/// Geri-çekilme tavanı, peer günlerce kapalı olsa bile en geç dakikada bir denenir.
pub const BACKOFF_CAP_MS: u64 = 60_000;

#[derive(Debug)]
struct Entry {
    addr: Multiaddr,
    /// `/p2p/<id>` bileşeninden ya da kurulan bağlantıdan öğrenilen kimlik.
    peer_id: Option<PeerId>,
    connected: bool,
    /// Üst üste başarısız deneme sayısı (bağlantı kurulunca sıfırlanır).
    failures: u32,
    /// Bu zamandan önce yeniden aranmaz (ms, çağıranın saatiyle).
    next_attempt_ms: u64,
    /// `due()` ile verildi, sonucu (Established/Error) henüz gelmedi.
    in_flight: bool,
}

impl Entry {
    fn backoff_ms(&self) -> u64 {
        BACKOFF_CAP_MS.min(BACKOFF_BASE_MS.saturating_shl(self.failures.min(16)))
        // 2s,4s,8s,...,60s
    }
}

/// `saturating_shl` std'de yok, küçük yardımcı.
trait SatShl {
    fn saturating_shl(self, n: u32) -> u64;
}
impl SatShl for u64 {
    fn saturating_shl(self, n: u32) -> u64 {
        if n >= 63 {
            u64::MAX
        } else {
            self.checked_shl(n).unwrap_or(u64::MAX)
        }
    }
}

fn peer_id_of(addr: &Multiaddr) -> Option<PeerId> {
    addr.iter().find_map(|p| match p {
        libp2p::multiaddr::Protocol::P2p(id) => Some(id),
        _ => None,
    })
}

#[derive(Debug, Default)]
pub struct PeerBook {
    entries: Vec<Entry>,
    /// PeerId → entries index (öğrenilen kimlikler; hata olaylarını eşlemek için).
    by_peer: HashMap<PeerId, usize>,
}

impl PeerBook {
    /// Bootstrap adresleriyle kurar. İlk deneme `build_swarm`'da zaten
    /// yapıldığı için hepsi "in_flight" başlar, sonucu (bağlantı ya da hata)
    /// olay döngüsünden gelir; gelmezse ilk `due()` süresi dolunca yeniden aranır.
    pub fn new(bootstrap: Vec<Multiaddr>) -> Self {
        let mut book = PeerBook::default();
        for addr in bootstrap {
            book.insert(addr, true);
        }
        book
    }

    /// Duyurudan öğrenilecek adres tavanı: `add_known` girdileri süresiz aranır,
    /// tavansız tek validatör onlarca adres duyurup her düğüme sonsuz dial attırırdı.
    const MAX_LEARNED_ADDRS: usize = 64;

    /// 🛡️ Duyurudan öğrenilen sentry adresi, bootstrap gibi
    /// kalıcı olarak deftere girer (kopunca yeniden aranır). Zaten varsa no-op.
    /// D14: defter `MAX_LEARNED_ADDRS`'ı aşacaksa yeni adres SESSİZCE alınmaz.
    pub fn add_known(&mut self, addr: Multiaddr) {
        if self.entries.len() >= Self::MAX_LEARNED_ADDRS
            && !self.entries.iter().any(|e| e.addr == addr)
        {
            tracing::warn!(
                "peer defteri tavani ({}) dolu, duyuru adresi alinmadi",
                Self::MAX_LEARNED_ADDRS
            );
            return;
        }
        self.insert(addr, true);
    }

    fn insert(&mut self, addr: Multiaddr, in_flight: bool) {
        if self.entries.iter().any(|e| e.addr == addr) {
            return;
        }
        let peer_id = peer_id_of(&addr);
        let idx = self.entries.len();
        self.entries.push(Entry {
            addr,
            peer_id,
            connected: false,
            failures: 0,
            next_attempt_ms: 0,
            in_flight,
        });
        if let Some(p) = peer_id {
            self.by_peer.insert(p, idx);
        }
    }

    fn idx_of_peer(&self, peer: &PeerId) -> Option<usize> {
        self.by_peer.get(peer).copied()
    }

    /// Bağlantı kuruldu: sayaç sıfırlanır. Gelen bağlantının geçici portu yeniden
    /// aramada işe yaramaz; yalnız defterde olan adresler güncellenir, yeni kayıt açılmaz.
    pub fn connected(&mut self, peer: PeerId, _remote_addr: &Multiaddr) {
        if let Some(i) = self.idx_of_peer(&peer) {
            let e = &mut self.entries[i];
            e.connected = true;
            e.failures = 0;
            e.in_flight = false;
            return;
        }
        // Kimliği adres bileşeninden eşleşen (henüz peer_id öğrenmemiş) kayıt?
        for (i, e) in self.entries.iter_mut().enumerate() {
            if e.peer_id.is_none() && e.in_flight {
                // Tek in-flight kimliksiz kayıt varsayımı: kimliği öğren.
                e.peer_id = Some(peer);
                e.connected = true;
                e.failures = 0;
                e.in_flight = false;
                self.by_peer.insert(peer, i);
                return;
            }
        }
    }

    /// Bağlantı koptu: hemen değil, taban gecikmeden sonra yeniden aranır.
    pub fn disconnected(&mut self, peer: &PeerId, now_ms: u64) {
        if let Some(i) = self.idx_of_peer(peer) {
            let e = &mut self.entries[i];
            e.connected = false;
            e.in_flight = false;
            e.next_attempt_ms = now_ms.saturating_add(BACKOFF_BASE_MS);
        }
    }

    /// Giden arama başarısız: geri-çekilme katlanır.
    /// `peer=None` (libp2p kimliği çözemedi) → tüm in-flight kayıtlar cezalanır.
    pub fn dial_failed(&mut self, peer: Option<&PeerId>, now_ms: u64) {
        let bump = |e: &mut Entry, now_ms: u64| {
            e.in_flight = false;
            e.failures = e.failures.saturating_add(1);
            e.next_attempt_ms = now_ms.saturating_add(e.backoff_ms());
        };
        match peer.and_then(|p| self.idx_of_peer(p)) {
            Some(i) => bump(&mut self.entries[i], now_ms),
            None => {
                for e in self
                    .entries
                    .iter_mut()
                    .filter(|e| e.in_flight && !e.connected)
                {
                    bump(e, now_ms);
                }
            }
        }
    }

    /// Sırası gelen (bağlı olmayan, süresi dolmuş, uçuşta olmayan) adresler.
    /// Dönenler in_flight işaretlenir, sonuç olayı gelene ya da bir sonraki
    /// backoff penceresine kadar tekrar verilmez (çifte arama önlenir).
    pub fn due(&mut self, now_ms: u64, is_banned: impl Fn(&PeerId) -> bool) -> Vec<Multiaddr> {
        let mut out = Vec::new();
        for e in self.entries.iter_mut() {
            if e.connected || e.in_flight || now_ms < e.next_attempt_ms {
                continue;
            }
            if e.peer_id.as_ref().is_some_and(&is_banned) {
                continue;
            }
            e.in_flight = true;
            // Sonuç olayı hiç gelmezse (nadiren yutulabilir) kilitli kalmasın:
            // bir sonraki pencerede yeniden değerlendirilir.
            e.next_attempt_ms = now_ms.saturating_add(e.backoff_ms().max(BACKOFF_BASE_MS));
            out.push(e.addr.clone());
        }
        out
    }

    /// (izleme/log) bağlı olmayan bilinen adres sayısı.
    pub fn disconnected_count(&self) -> usize {
        self.entries.iter().filter(|e| !e.connected).count()
    }
}

/// Config'teki string listesini ayrıştırır (geçersizler loglanıp atlanır) —
/// `build_swarm`'daki ilk-deneme ayrıştırmasıyla aynı tolerans.
pub fn parse_bootstrap(addrs: &[String]) -> Vec<Multiaddr> {
    addrs
        .iter()
        .filter_map(|a| match a.parse::<Multiaddr>() {
            Ok(m) => Some(m),
            Err(e) => {
                tracing::warn!("⚠️ Geçersiz bootstrap adresi ({a}): {e}");
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(port: u16, with_peer: bool) -> Multiaddr {
        let mut a: Multiaddr = format!("/ip4/127.0.0.1/tcp/{port}").parse().unwrap();
        if with_peer {
            let kp = libp2p::identity::Keypair::generate_ed25519();
            a.push(libp2p::multiaddr::Protocol::P2p(kp.public().to_peer_id()));
        }
        a
    }

    #[test]
    fn backoff_doubles_and_caps_then_resets_on_connect() {
        let a = addr(4001, true);
        let peer = peer_id_of(&a).unwrap();
        let mut book = PeerBook::new(vec![a.clone()]);

        // build_swarm'ın ilk denemesi başarısız oldu diyelim:
        book.dial_failed(Some(&peer), 0);
        assert!(
            book.due(0, |_| false).is_empty(),
            "backoff dolmadan verilmez"
        );
        assert_eq!(
            book.due(4_000, |_| false).len(),
            1,
            "2s×2^1=4s'te sirasi gelir"
        );
        // verilen tekrar verilmez (in_flight)
        assert!(book.due(4_000, |_| false).is_empty());

        // arka arkaya basarisizlik → tavana dayanir
        let mut now = 4_000;
        for _ in 0..10 {
            book.dial_failed(Some(&peer), now);
            now += 61_000;
            let d = book.due(now, |_| false);
            assert_eq!(d.len(), 1, "tavan 60s: her 61s'te mutlaka sirasi gelmeli");
        }

        // baglanti kuruldu → sayac sifir; kopunca taban gecikmeyle geri gelir
        book.connected(peer, &a);
        assert!(
            book.due(now + 120_000, |_| false).is_empty(),
            "bagliyken aranmaz"
        );
        book.disconnected(&peer, now);
        assert!(book.due(now + BACKOFF_BASE_MS - 1, |_| false).is_empty());
        assert_eq!(
            book.due(now + BACKOFF_BASE_MS, |_| false).len(),
            1,
            "sifirlanan sayacla taban gecikme"
        );
    }

    #[test]
    fn banned_peers_are_never_redialed_and_unknown_failure_bumps_inflight() {
        let a1 = addr(4002, true);
        let a2 = addr(4003, true);
        let p1 = peer_id_of(&a1).unwrap();
        let mut book = PeerBook::new(vec![a1, a2]);
        // ikisi de in_flight baslar; kimliksiz hata → ikisi de cezalanir
        book.dial_failed(None, 0);
        let due = book.due(10_000, |p| *p == p1); // p1 banli
        assert_eq!(due.len(), 1, "banli peer asla aranmaz, digeri aranir");
    }

    #[test]
    fn inbound_connection_learns_identity_of_pending_bootstrap_without_peer_component() {
        let a = addr(4004, false); // /p2p'siz bootstrap adresi
        let mut book = PeerBook::new(vec![a.clone()]);
        let kp = libp2p::identity::Keypair::generate_ed25519();
        let peer = kp.public().to_peer_id();
        book.connected(peer, &a);
        book.disconnected(&peer, 1_000);
        assert_eq!(
            book.due(1_000 + BACKOFF_BASE_MS, |_| false).len(),
            1,
            "kimlik ogrenildi, kopunca yeniden aranir"
        );
    }
}
