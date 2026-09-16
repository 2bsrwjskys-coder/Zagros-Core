# Özel (Private) Mainnet: 2-VPS P2P Kurulum Rehberi

Bu rehber, tamamen kapalı/özel bir ağda (sadece sizin sunucularınız, başka
validator yok) iki farklı VPS sağlayıcısı arasında `zagros-network` P2P
katmanını canlıya almak için hazırlandı. Sunucular elinize geçtiğinde
`<VPS-A-IP>` / `<VPS-B-IP>` / `<kullanıcı_adınız>` yerlerini gerçek
değerlerle değiştirip sırayla uygulayın.

Roller: **VPS-A = proposer** (blok üretir), **VPS-B = follower** (senkron
kalır, kendi blok üretmez).

---

## 1. Ön koşullar (her iki sunucuda)

```bash
sudo apt update && sudo apt install -y build-essential clang pkg-config libssl-dev git curl

# Rust kurulumu
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

Donanım: README'deki gibi en az 8GB RAM, 50GB disk (küçük/orta ölçek
tek-validator varsayımıyla ayarlanmış RocksDB tuning'i için yeterli).

## 2. Private GitHub erişimi + kod çekme (her iki sunucuda)

Depo private olduğu için, yerelde yaptığımız gibi her sunucuda ayrı ayrı
`gh` ile giriş yapmanız gerekiyor (headless sunucuda da çalışır, "device
code" akışı size bir URL/kod verir, onu kendi laptopunuzun tarayıcısında
açarsınız):

```bash
(curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg \
  && sudo chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg \
  && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null \
  && sudo apt update && sudo apt install gh -y)

gh auth login
# What account? GitHub.com → HTTPS → Yes (authenticate Git) → Login with a web browser

git clone <PRIVATE_REPO_URL>
cd Zagros-Mainnet-Node
cargo build --release
```

İlk derleme (özellikle RocksDB/revm bağımlılıkları yüzünden) biraz uzun
sürebilir, sabırlı olun.

## 3. Firewall (her iki sunucuda)

```bash
sudo ufw allow 30303/tcp   # P2P - ZORUNLU, iki sunucu birbirini bununla bulur
sudo ufw allow 8545/tcp    # RPC HTTP - sadece dışarıdan erişmek isterseniz
sudo ufw allow 8546/tcp    # RPC WS   - aynı şekilde opsiyonel
sudo ufw enable
```

**Dikkat:** çoğu VPS sağlayıcısında (DigitalOcean, Hetzner, AWS, vb.)
işletim sistemi firewall'ından (ufw) AYRI bir de sağlayıcı panelinde
"Security Group / Cloud Firewall" katmanı olur. Orada da aynı 30303 portunu
her iki sunucunun karşılıklı IP'sine (ya da tamamen açık) izin vermeniz
gerekir, yoksa ufw doğru olsa bile bağlantı kurulmaz.

## 4. config.toml — VPS-A (proposer)

```bash
cp config.example.toml config.toml
```

`config.toml` içinde `[network]`:
```toml
enable_p2p = true
is_proposer = true
mdns_enabled = false   # ayrı sunucular internet üzerinden - mDNS işe yaramaz
bootstrap_nodes = []   # proposer ilk açılan node, boş kalır
```

`[consensus]`:
```toml
block_producer_address = "0xSizinCüzdanAdresiniz"
```

## 5. Proposer'ı başlat, PeerId'yi al

```bash
./target/release/zagros-cli
```

Log çıktısında şöyle bir satır arayın:
```
🌐 P2P dinleniyor: /ip4/0.0.0.0/tcp/30303/p2p/12D3KooW...
```

`/p2p/12D3KooW...` kısmını not edin, follower'ın `bootstrap_nodes`'una bu
gerekecek (aşağıda `0.0.0.0` yerine VPS-A'nın GERÇEK genel IP'sini
kullanacaksınız).

**Not:** ilk açılışta genesis burada oluşur. `zagros-data` dizini bomboş bir
sunucuda başlatıldığından emin olun (daha önce başka bir amaçla
kullanılmış, eski state içeren bir dizin varsa silin).

## 6. config.toml — VPS-B (follower)

```bash
cp config.example.toml config.toml
```

`[network]`:
```toml
enable_p2p = true
is_proposer = false
mdns_enabled = false
bootstrap_nodes = ["/ip4/<VPS-A-GERÇEK-IP>/tcp/30303/p2p/12D3KooW..."]
```

`block_producer_address` boş kalabilir, follower blok üretmiyor.

## 7. Follower'ı başlat, doğrula

```bash
./target/release/zagros-cli
```

Loglarda "🤝 Peer bağlandı" mesajını görmelisiniz. Genesis'in kendisi
(GENESIS_TIMESTAMP artık sabit olduğu için) iki sunucuda da bit-birebir
aynı olacak; gerçek senkronu görmek için VPS-A'nın RPC'sine bir işlem
gönderip (`eth_sendRawTransaction`) blok ürettirin, ardından VPS-B'nin
aynı blok yüksekliğine ve aynı `state_root`'a ulaştığını kontrol edin.

## 8. Kalıcı çalıştırma (systemd, her iki sunucuda)

SSH oturumu kapanınca process ölmesin diye:

```bash
sudo nano /etc/systemd/system/zagros.service
```
```ini
[Unit]
Description=Zagros Node
After=network.target

[Service]
Type=simple
User=<kullanıcı_adınız>
WorkingDirectory=/home/<kullanıcı_adınız>/Zagros-Project
ExecStart=/home/<kullanıcı_adınız>/Zagros-Project/target/release/zagros-cli
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now zagros
sudo journalctl -u zagros -f   # canlı log takibi
```

## 9. Güncelleme akışı (kod değişikliği sonrası)

Yerelde geliştirip push ettikten sonra, her sunucuda:

```bash
cd ~/Zagros-Project
git pull
cargo build --release
sudo systemctl restart zagros
```

`config.toml` `.gitignore`'da olduğu için `git pull` bunu hiç etkilemez,
her sunucu kendi proposer/follower ayarını korur.

## Bilinen sınırlamalar

- Bu rehber sadece P2P bağlantısını kapsar. Köprü/PAXG kilitleme testi
  ayrı bir engebe (Bridge Gateway redeploy) bağlı, bu rehberle çözülmüyor.
- mDNS sadece aynı yerel ağda işe yarar; iki farklı VPS sağlayıcısı arasında
  `mdns_enabled = false` şart, yoksa zaten bir şey kaybetmezsiniz ama gereksiz.
- NAT arkasında (ev sunucusu gibi) bir makine eklemek isterseniz ayrıca port
  yönlendirme gerekir; VPS'ler genelde doğrudan genel IP'ye sahip olduğu için
  bu senaryoda sorun yaşamamanız beklenir.
