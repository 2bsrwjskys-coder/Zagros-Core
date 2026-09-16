# Zagros Doğrulayıcı Olma Rehberi (adım adım)

Bu rehber, sıfırdan bir Zagros doğrulayıcısı olmak isteyen biri için baştan sona
tek yoldur. Teknik ayrıntılar kurulum paketinin içindeki README'de ve
[OPERATOR-RUNBOOK.md](OPERATOR-RUNBOOK.md) dosyasında; burada sıra ve karar
noktaları var. Aynı akış görsel olarak zagros.network → Öğren → **Diyagram**
bölümünde ("Doğrulayıcı" sekmesi) anlatılır.

## 0. Bilmen gerekenler

- Doğrulayıcıların oyu eşittir; stake miktarı oy gücü değil, teminattır.
- Ödül her blokta ücretlerden gelir: %20 bloğu üreten doğrulayıcıya, %80 stake
  edenlere. Doğrulayıcı olarak stake ettiğin ZAGROS ayrıca %80'lik havuzdan da pay alır.
- Asgari teminat 0,17 ons altın karşılığı ZAGROS (canlı karşılığı dApp'te yazar).
- Küme tavanı bugün 10 doğrulayıcı; yer yoksa başvurun sırada bekler (kayıt
  zamanına göre sıra). Tavan yönetişimle yükseltilir.
- Katılım kurucu yetkisi döneminde (31 Ağustos 2028'e kadar) 3/5 yönetim
  onayıyla; sonrasında doğrulayıcı oyuyla.
- İade edilmeyen küçük bir başvuru ücreti var (0,005 ons altın karşılığı
  ZAGROS); ödül havuzuna gider.

## 1. Sunucu

Sıradan bir VPS yeter: en az 4 vCPU, 8 GB RAM, 100 GB SSD, kararlı bağlantı,
Ubuntu 22.04 ya da 24.04. Mevcut doğrulayıcılardan **farklı bir sağlayıcı ve
bölge** seç; aynı sağlayıcıda yığılma kod tarafından reddedilir (çeşitlilik süzgeci).
İstersen validatörün önüne ayrı bir makinede sentry düğüm koyabilirsin
(paket bunu da kurar); zorunlu değildir.

**Disk şişmez.** Doğrulayıcı düğümü budama yapar: durum ve son 100.000 blok
(yaklaşık 14 gün) diskte tutulur, daha eskisi silinir; disk kullanımı sabit
bir pencerede kalır ve yıllar geçse de büyümez. Tam geçmiş arşiv düğümlerinde
(rpc.zagrosnetwork.com) ve ZagrosRadar'da saklanır; doğrulayıcının onu
taşımasına gerek yoktur. Ayrıntı: dApp → Öğren → Akademi → "Disk Neden Şişmez?".

## 2. Cüzdan

Bir EVM cüzdanı (MetaMask, Rabby ya da dApp'teki Zagros Cüzdanı). Stake, gaz
ve ödüller bu adrese bağlanır; özel anahtarı sunucuya asla koyma. Sunucuda
yalnız konsensüs anahtarı (Ed25519) durur, paket onu kendisi üretir ve
gerekirse zincir üstünde döndürülür.

## 3. Paketi indir, doğrula, kur

```bash
curl -fsSLO https://rpc.zagros.network/validator/zagros-validator-package.tgz
curl -fsSLO https://rpc.zagros.network/validator/zagros-validator-package.tgz.sha256
sha256sum -c zagros-validator-package.tgz.sha256      # "OK" görmelisin
tar -xzf zagros-validator-package.tgz && cd zagros-validator
./install.sh --addr 0xSENIN_CUZDAN_ADRESIN --provider <sağlayıcı> --region <bölge> --asn <asn>
```

Tek komut: ikiliyi kurar, konsensüs anahtarını üretir, ağla birebir aynı
config'i yazar, systemd servisini açar, güvenlik duvarını ayarlar, düğümü
snapshot'tan başlatır ve öz-denetim çalıştırır. Yedek kaynak:
`https://rpc.zagrosnetwork.com/validator/` (aynı dosyalar).

Sağlıklı mı diye istediğin an:

```bash
./zagros-node-selfcheck.sh --addr 0xSENIN_CUZDAN_ADRESIN
```

Yeşil ise devam. Sarı genelde "senkron bekliyor", kırmızı ise ekranda ne
düzelteceğin yazar.

## 4. Stake (dApp)

zagros.network → cüzdanını bağla → **Stake** sekmesi:

1. En az asgari teminat kadar ZAGROS stake et (asgari dApp'te canlı yazar).
2. **1 saat bekle**: stake edilen miktar hakediş süresi dolmadan kesinleşmez.
3. Süre dolunca küçük bir ikinci stake yap (1 ZAGROS yeter) ya da "Ödülleri Topla"ya
   bas; bekleyen miktar ancak hesaba yeni bir işlem dokununca kesinleşir. Bunu
   yapmadan kayıt gönderirsen zincir "en az … teminat gerekir" der.

## 5. Kayıt (dApp, Öğren bölümü)

Düğüm senkron olduktan sonra sunucuda kayıt verisini üret:

```bash
./make-register-payload.sh --addr 0xSENIN_CUZDANIN --provider <sağlayıcı> --region <bölge> --asn <asn>
```

Çıktı tek satır calldata'dır (`register-payload.txt`'e de yazılır). Sonra
zagros.network → **Öğren → Akademi → "Zagros Validatör olmak"** bölümünün **en
altındaki** "Validator Kaydı" formuna bu satırı yapıştır ve gönder. Zaman
penceresi yok. Artık **Aday (Candidate)** durumundasın.

Kayıt işlemini düğüm çalışırken yaptıysan, onaylandıktan sonra düğümü bir kez
yeniden başlat: `systemctl restart zagros-node`.

## 6. Onay ve kümeye giriş

- **Onay**: yönetim 3/5 çoklu imzayla onaylar → **Onaylı (Approved)**. Bekleme
  normaldir; durumunu öz-denetimle ya da ZagrosRadar'ın Doğrulayıcılar sayfasından görürsün.
- **Deneme (Probation)**: sonraki epoch (epoch 2 saat) kümeye girersin; yaklaşık
  3 epoch tam katılımdan sonra **Aktif** olursun ve blok üretmeye başlarsın.
- Canlılık düşerse ceza kademelidir (deneme süresine dönüş); çift imza
  kanıtlanırsa teminat müsadere edilir. Dürüst ve açık bir düğüm için ikisi de gündeme gelmez.

## 7. İzleme

- `./zagros-node-selfcheck.sh` (istediğin an), `/health` ve `/metrics` uçları,
  systemd günlükleri: `journalctl -u zagros-node -f`.
- ZagrosRadar → Doğrulayıcılar: canlılık, durum, teminat, ödül çarpanı herkese açık.
- Snapshot ve yükseltme adımları: [OPERATOR-RUNBOOK.md](OPERATOR-RUNBOOK.md).

## 8. Yardım ve iletişim

Takıldığın her adımda yaz; başvuru öncesi soru sormak da serbest:

- E-posta: mail@zagros.network (doğrulayıcı başvurusu ve destek)
- Telegram: https://t.me/zagrosnetwork
- Hakkında ve İletişim: https://zagros.network/hakkinda/

Öğren bölümünde **Diyagram** akışın görsel hali, **Akademi** yazılı ve canlı
rakamlı halidir; ikisi de çalışan koddan doğrulanmıştır.
