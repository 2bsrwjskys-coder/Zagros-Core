# Zagros Doğrulayıcı Operatör Rehberi

Bu belge, bir Zagros validator node'unu işleten operatörün günlük ve acil durum
prosedürlerini tanımlar. Konsensüs modeli: **ZagrosBFT** (eşit oylu, sırayla
blok üreten deterministik BFT — CONSENSUS-SPEC v0.3). Tüm komutlar
`zagros-cli` binary'si üzerinden çalışır; node çalışırken RocksDB dizinini
ikinci bir process açamayacağı için "node'u durdurun" denilen adımlar
ATLANAMAZ.

---

## 1. Anahtar üretimi ve saklama

Dört ayrı anahtar türü vardır ve BİRBİRİNİN YERİNE GEÇMEZ:

| Anahtar | Tür | Nerede |
|---|---|---|
| Hesap (cüzdan) | secp256k1 | Operatörün cüzdanı (Ledger/hardware önerilir) |
| Konsensüs | Ed25519 | `[network].consensus_key_path` keyfile (0600) |
| P2P kimliği | Ed25519 | `[network].node_key_path` (otomatik üretilir) |
| Köprü (yalnız yetkili node) | Ed25519 | `[bridge]` — validator'lara KOPYALANMAZ |

Konsensüs anahtarı üretimi:

```
zagros-cli validator gen-key --out consensus.key
```

- Keyfile 0600 izinle yazılır; yedeğini ŞİFRELİ ortamda tutun.
- Mümkünse keyfile'ı ayrı bir disk/volume'da tutun; HSM kullanımı bu sürümde
  desteklenmiyor, telafi edici kontrol: makine erişimini sıkın (SSH anahtarı +
  fail2ban + ufw), anahtar ele geçirme şüphesinde HEMEN rotasyon .
- Hesap anahtarı ile konsensüs anahtarını AYNI makinede tutmayın; kayıt ve
  rotasyon calldata'ları soğuk tarafta üretilebilir.

## 2. Kayıt (RegisterValidator) + beyan

Ön koşullar: hesapta teminat (0,17 ons altın-eşdeğeri ZAGROS, havuz oranıyla)
stake edilmiş olmalı + başvuru ücreti kadar serbest bakiye.

1. Node'u geçici durdurun (RocksDB kilidi).
2. Calldata üretin (beyan alanları ZORUNLU ve doğru olmalı — çeşitlilik
   tavanları provider/region/ASN/operator üzerinden uygulanır):

```
zagros-cli validator register-payload \
  --key consensus.key --config config.toml \
  --address 0xSIZIN_CUZDAN \
  --provider hetzner --region eu-central-1 --asn 24940 \
  --operator-id-hex <64-hex-kimlik-hash>
```

3. Çıkan tek satırı cüzdanınızdan `0x...0006` adresine giden işlemin veri
   alanına yapıştırıp gönderin. Kayıt sizi **Candidate** yapar; Faz A'da admin
   multisig onayı (Approved) + `probation_epochs` kadar gözlem (Probation)
   sonrası kümeye girersiniz (Active).

## 3. Probation takibi

- Probation'da ödül YOKTUR; katılım (`participation_bps`) ölçülür.
- `/health` çıktısındaki `validators` ve kendi hesabınızın durumu dApp/RPC
  üzerinden izlenebilir; eşik: `uptime_threshold_bps` (genesis %90).
- Probation süresi dolduğunda katılım eşiğin ÜZERİNDEyse ve teminat
  yerindeyse otomatik Active olursunuz; ölçüm yoksa fail-closed geçmezsiniz —
  node'unuzun gerçekten oy/gölge-oy ürettiğinden emin olun.

## 4. Konsensüs anahtarı rotasyonu

Ne zaman: şüpheli erişim, makine değişimi, periyodik hijyen (6-12 ayda bir).

1. YENİ anahtar üretin (eski dosyanın ÜZERİNE YAZMAYIN):

```
zagros-cli validator gen-key --out consensus-v2.key
```

2. Node'u geçici durdurup rotasyon calldata'sı üretin (eski pubkey zincir
   kaydından otomatik okunur):

```
zagros-cli validator rotate-payload \
  --new-key consensus-v2.key --config config.toml --address 0xSIZIN_CUZDAN
```

3. Node'u ESKİ anahtarla yeniden başlatın, calldata'yı cüzdandan `0x...0006`
   adresine gönderin.
4. Rotasyon bir SONRAKİ epoch geçişinde etkinleşir (INV-K1). Epoch sınırından
   SONRA: node'u durdurun → `config.toml [network].consensus_key_path =
   "consensus-v2.key"` → başlatın.
5. Eski keyfile'ı `evidence_max_age_epochs` penceresi kapanana kadar saklayın
   (eski anahtarla equivocation kanıtı hâlâ doğrulanır/slash edilir), sonra
   güvenli biçimde imha edin.

Sıralama hatası belirtisi: epoch geçti ama config hâlâ eski anahtardaysa node
oy üretemez (küme yeni pubkey bekler) → liveness strike birikir. Çözüm:
config'i yeni dosyaya çevirip yeniden başlatmak.

## 5. İzleme: /health, /metrics ve alarmlar

Node RPC portunda iki salt-okunur uç sunar:

- `GET /health` → JSON: `height`, `epoch`, `active_ruleset`, `validators`,
  `mempool_pending`, `consensus{commits_total, view_changes_total,
  last_commit_unix_ms, catch_up_active, state_root_mismatch_total,
  peers_connected}`.
- `GET /metrics` → Prometheus text format (aynı veriler `zagros_*` adlarıyla).

Önerilen Prometheus alarm kuralları:

```
# Lag: 60 sn'den uzun süre commit yok (boş mempool'da heartbeat/boş blok
# beklenir; eşiği idle_block_interval_s'e göre ayarlayın)
time() - zagros_last_commit_unix_ms/1000 > 60

# View-change fırtınası (lider arızaları / ağ sorunu)
rate(zagros_view_changes_total[5m]) > 0.2

# KRİTİK: kök uyuşmazlığı — normalde HEP 0; artış = bug/kötü peer, acil bakın
increase(zagros_state_root_mismatch_total[10m]) > 0

# Yalnızlaşma: peer sayısı düştü
zagros_peers_connected < 2

# Takılı catch-up
zagros_catch_up_active == 1  (15 dk boyunca)
```

Ayrıca `[alerts].webhook_url` (Discord/Slack biçimi) node-içi kenar-tetikli
alarmları (jail, Anti-DDoS stres, üretim durması) ayrıca gönderir — ikisi
birbirinin yedeğidir, ikisini de kurun.

## 6. Snapshot / yedekleme

- Otomatik: `[storage] snapshot_interval_blocks` + `max_snapshots_to_retain`.
- Elle: `zagros-cli snapshot create`, listeleme `zagros-cli snapshot list`,
  geri yükleme YENİ (var olmayan) bir dizine `zagros-cli snapshot restore`.
- Yedeği makine DIŞINA kopyalayın (rsync ile; `--delete` kullanacaksanız önce
  hedefte sunucuya özel dosyaları dışlayın). Felaket senaryosu: temiz makine +
  snapshot restore + aynı config → node catch-up ile yetişir; state_root her
  blokta yeniden doğrulandığı için yanlış/eksik snapshot fail-closed durur.

## 7. Sorunsuz yükseltme

1. Yeni binary duyurulduğunda: HERHANGİ BİR ANDA node'u durdurup binary'yi
   değiştirin, başlatın. Yeni binary eski kurallarla çalışmaya devam eder ve
   ürettiği blok başlıklarında `max_ruleset` beyanını otomatik taşır.
2. Governance'ta `ScheduleUpgrade` önerisi %80 oy + %80 hazırlık beyanıyla
   kabul olunca aktivasyon epoch'u zincire yazılır; epoch sınırında TÜM ağ
   atomik olarak yeni kural setine geçer — restart/koordinasyon GEREKMEZ.
3. Binary'yi GÜNCELLEMEMİŞ bir node aktivasyon anında fail-closed DURUR
   (yarım anlayan node yoktur). Çözüm: binary'yi güncelle → başlat →
   checkpoint-sync/catch-up ile yetişir.
4. Hazırlık yetersizse (< %80 beyan) kayıt epoch sınırında İPTAL olur (FM-U1)
   — ağ eski kurallarla kesintisiz devam eder.

## 8. Acil durum modu

- **>f validator offline** (commit yok, `zagros_peers_connected` normal ama
  `last_commit` ilerlemiyor): zincir GÜVENLİ şekilde durmuştur (safety >
  liveness). Panik yok: operatörler koordine olur, düşen node'lar açılır ya da
  `RemoveValidator` ile küme küçültülüp f yeniden hesaplanır.
- **Kök uyuşmazlığı (kendi node'unuz commit'te panic ile durdu, INV-P3)**:
  node'u YENİDEN BAŞLATMAYIN; logu kaydedin, diğer operatörlerle
  karşılaştırın. Çoğunluk sizinle aynıysa bug'dır → acil yükseltme süreci.
  Yalnız sizdeyse disk/snapshot bozulması → temiz dizine snapshot restore.
- **Anahtar kaybı**: konsensüs anahtarı kayıpsa node oy üretemez → liveness
  jail'e düşersiniz; hesap anahtarınızla 4. bölümdeki rotasyonu yapın (rotasyon HESAP
  imzasıyla gönderilir, kayıp konsensüs anahtarı gerekmez).
- **Anahtar ele geçirilmesi**: derhal 4. bölümdeki rotasyonu + diğer operatörlere haber.
  Saldırganın eski anahtarla equivocation'ı, kanıt penceresi boyunca SİZİN
  teminatınızdan slash edilir — bu yüzden rotasyonu geciktirmeyin.
- **Multisig imzacı kaybı (Faz A)**: kalan imzacılar 3-of-5'i hâlâ
  karşılıyorsa işlemler sürer; karşılamıyorsa Faz B'ye erken geçiş gündeme
  alınır (governance).

## 9. Mainnet geçiş günü aracı

Private zincir DONDURULDUKTAN sonra, mainnet genesis'inden ÖNCE:

```
replay_guard_export <eski-state-dizini> replay_guard.txt
# config.toml → [genesis].replay_guard_file = "./replay_guard.txt"
```

Bu, testnet'te işlem yapmış her adresi mainnet'te `son_nonce+1`'den başlatır
(chain_id aynı kaldığı için replay penceresini kapatır) ve dosya
genesis_hash'e girer — tüm validator'lar AYNI dosyayı kullanmalıdır.
