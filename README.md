# KOBİ Tehdit İstihbaratı Portalı

KOBİ'ler için sunucusuz, ücretsiz, GitHub Pages üzerinde çalışan bir siber tehdit istihbaratı (CTI) portalı.
Açık kaynak tehdit verilerini her 4 saatte bir GitHub Actions ile toplar, statik JSON dosyalarına dönüştürür ve
tarayıcıda çalışan bir arayüzle sunar. Veritabanı, sunucu veya ücretli API gerekmez.

## Ne işe yarar?

| Bölüm | KOBİ için anlamı |
|---|---|
| **Genel bakış** | Meteoroloji uyarısı gibi tek bakışta durum: Yeşil / Sarı / Turuncu / Kırmızı. Öncelikli işler, son haberler, haftalık trend. |
| **Zafiyetler** | CISA KEV (aktif istismar edilen zafiyetler) + FIRST EPSS. Envanterinize, fidye yazılımı kullanımına ve istismar olasılığına göre puanlanır. CSV dışa aktarım. |
| **Varlıklarım** | Kullandığınız üreticileri/ürünleri tanımlarsınız (FortiGate, Exchange, MikroTik, NAS, ESXi…). Tüm portal bu listeye göre kişiselleşir. Veriler yalnızca tarayıcıda (localStorage) kalır. |
| **IOC arama** | Log'lardaki IP, alan adı, URL, hash değerlerini yapıştırın; abuse.ch ve USOM verisinde tarayıcı içinde aranır. Defang (`hxxp`, `[.]`) desteklenir. VirusTotal, AbuseIPDB, Shodan, urlscan bağlantıları. |
| **Engelleme listeleri** | Güvenlik duvarının doğrudan çekebileceği düz metin listeler: `feeds/ip-blocklist.txt`, `domain-blocklist.txt`, `url-blocklist.txt`, `mikrotik-blocklist.rsc`. FortiGate, MikroTik, pfSense/OPNsense, Pi-hole kurulum adımları. |
| **Haberler** | CISA, The Hacker News, BleepingComputer, SANS ISC, Microsoft MSRC RSS akışları; envanterle ilgili ve KEV'deki CVE'leri içeren haberler işaretlenir. |
| **Fidye yazılımı** | ransomware.live verisiyle Türkiye'deki (veya tüm dünyadaki) mağdurlar, aktif gruplar ve hedeflenen sektörler. |
| **Temel hijyen** | MFA, yedekleme, RDP, segmentasyon, 5651 kayıtları, KVKK 72 saat bildirimi gibi 20 temel kontrol. |
| **Haftalık bülten** | Yönetime veya müşteriye gönderilecek tek sayfalık özet. Yazdır / PDF olarak kaydet. |
| **Kaynaklar** | Her veri kaynağının son çalışmadaki durumu ve puanlama yöntemi. |

## Kurulum (5 dakika)

1. GitHub'da yeni bir depo oluşturun ve bu klasörün içeriğini yükleyin (`.github` klasörü dahil).
2. **Settings › Pages › Build and deployment › Source** alanını **GitHub Actions** yapın.
3. **Actions** sekmesinde iş akışlarını etkinleştirin, ardından **"CTI verisini güncelle ve yayınla" › Run workflow** ile ilk çalıştırmayı başlatın.
4. Birkaç dakika sonra portal `https://<kullanıcı>.github.io/<depo>/` adresinde yayında olur. Sonrasında her 4 saatte bir kendiliğinden güncellenir.

> Depoda örnek olarak **demo verisi** bulunur; sayfanın üstündeki sarı şerit gerçek veri gelince kaybolur.

### Opsiyonel ayarlar

**Settings › Secrets and variables › Actions** altına eklenebilir:

| Secret | Açıklama |
|---|---|
| `ABUSECH_AUTH_KEY` | abuse.ch ücretsiz Auth-Key ([auth.abuse.ch](https://auth.abuse.ch/)). abuse.ch bazı uçlar için anahtar istiyorsa bunu ekleyin. |
| `RANSOMWARELIVE_KEY` | ransomware.live PRO API anahtarı. Yoksa ücretsiz uç kullanılır. |

`config.json` dosyasından şunları değiştirebilirsiniz:
- `site.title`, `site.organization` — başlık ve kuruluş adı
- `rss` — haber kaynakları (Türkçe kaynak eklemek için RSS/Atom adresi yeterli)
- `ransomware_country` — fidye yazılımı bölümünde izlenecek ülke kodu (varsayılan `TR`)
- `blocklist_allow` — engelleme listelerine **asla** girmemesi gereken alan adları (google.com, microsoft.com, gov.tr vb.). Hatalı pozitif görürseniz buraya ekleyin.
- `sources` — istemediğiniz kaynağı `false` yaparak kapatın

Güncelleme sıklığı `.github/workflows/update-cti.yml` içindeki `cron` satırındadır.

## Yerelde çalıştırma

```bash
python scripts/fetch_feeds.py          # gerçek kaynaklardan veri topla
python scripts/fetch_feeds.py --demo   # internet olmadan demo veri üret
python -m http.server 8000             # http://localhost:8000
```

Yalnızca Python standart kütüphanesi kullanılır; `pip install` gerekmez.

## Mimari

```
GitHub Actions (cron 4 saat)
  └─ scripts/fetch_feeds.py
       ├─ CISA KEV ─┐
       ├─ FIRST EPSS├─► data/kev.json
       ├─ Feodo / URLhaus / ThreatFox / USOM ─► data/iocs.json ─► feeds/*.txt, *.rsc
       ├─ RSS akışları ─► data/news.json
       └─ ransomware.live ─► data/ransomware.json
  └─ GitHub Pages'e yayın
Tarayıcı: index.html + assets/js/app.js (bağımlılıksız, tüm eşleştirme istemcide)
```

- Bir kaynak hata verirse önceki verisi korunur; hata **Kaynaklar** sayfasında görünür.
- Veriler her çalışmada depoya da işlenir, böylece geçmişe dönük değişiklikler `git log` ile izlenebilir.
- Tüm dış veriler HTML olarak kaçışlanır (XSS'e karşı); bağlantılar yalnızca `http(s)` ise oluşturulur.

## Önemli notlar

- **Engelleme listelerini önce izleme modunda deneyin.** Açık kaynak listeler hatalı pozitif içerebilir.
- Zafiyet eşleştirme üretici/ürün adına dayanır, **sürüm kontrolü yapmaz**. Eşleşen her kaydı kendi sürümünüzle doğrulayın.
- GitHub Pages siteleri herkese açıktır (Enterprise planda özel Pages hariç). Portal kuruluşa özel veri yayınlamaz; envanter ve kontrol listesi yalnızca kullanıcının tarayıcısında tutulur. Yine de kuruluş adını `config.json`'a yazmak istemiyorsanız boş bırakın ve bülten ekranından tarayıcıya özel girin.
- Sayfada `noindex` etiketi vardır; arama motorlarında listelenmez.

## Veri kaynakları ve lisanslar

- [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — kamuya açık
- [FIRST EPSS](https://www.first.org/epss/) — kamuya açık
- [abuse.ch](https://abuse.ch/) Feodo Tracker, URLhaus, ThreatFox — CC0
- [USOM](https://www.usom.gov.tr/adres) — Ulusal Siber Olaylara Müdahale Merkezi zararlı bağlantılar
- [ransomware.live](https://www.ransomware.live/) — kullanım koşullarına tabi
