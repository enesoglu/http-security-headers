# HTTP Güvenlik Başlıkları Analiz ve Skorlama Aracı

Türkiye'deki popüler web sitelerinin HTTP güvenlik başlıklarını analiz eden,
eksik veya yanlış yapılandırılmış başlıkları tespit eden, A-F arası harf notu
veren ve karşılaştırmalı raporlar üreten bir Python komut satırı aracıdır.

Araç; tek bir URL'i veya bir URL listesini analiz edebilir, sonuçları renkli
terminal tabloları, JSON, CSV, Markdown raporu ve grafikler (PNG) olarak
dışa aktarabilir.

## Kurulum

Python 3.10 veya üzeri gereklidir. Sanal ortam (venv) kullanılması önerilir:

```bash
git clone https://github.com/<kullanici-adi>/http-security-headers.git
cd http-security-headers

python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
```

## Kullanım

**Tek bir URL'i analiz et (terminalde renkli tablo):**

```bash
python main.py --url https://www.akbank.com
```

**Detaylı (verbose) analiz - her başlığın değeri ve tespitleri:**

```bash
python main.py --url https://www.akbank.com --verbose
```

**Bir dosyadaki URL listesini toplu analiz et:**

```bash
python main.py --file data/turkish_sites.txt
```

**Sonuçları JSON olarak dışa aktar:**

```bash
python main.py --file data/turkish_sites.txt --output json
```

**Tüm çıktı formatlarını (JSON + CSV + Markdown + grafikler) üret:**

```bash
python main.py --file data/turkish_sites.txt --output all
```

### Argümanlar

| Argüman      | Açıklama                                                          | Varsayılan |
|--------------|--------------------------------------------------------------------|------------|
| `--url`      | Analiz edilecek tek bir URL                                         | -          |
| `--file`     | Her satırda bir URL içeren dosya yolu                               | -          |
| `--output`   | Çıktı formatı: `terminal`, `json`, `csv`, `markdown`, `all`         | `terminal` |
| `--timeout`  | İstek zaman aşımı (saniye)                                          | `10`       |
| `--verbose`  | Her site için detaylı başlık analizini gösterir                    | kapalı     |

`--url` ve `--file` birlikte kullanılamaz; ikisinden biri belirtilmelidir.

## Çıktı Formatları

| Format     | Açıklama                                                                 | Konum                                  |
|------------|---------------------------------------------------------------------------|-----------------------------------------|
| Terminal   | Renkli özet tablo (Site, Skor, Not, Eksik Başlıklar, Kritik Sorunlar)      | Ekran                                    |
| JSON       | Zaman damgalı, Türkçe karakter destekli ham analiz verisi                  | `output/reports/analysis_*.json`         |
| CSV        | Excel uyumlu (UTF-8 BOM), karşılaştırma için sütunlu özet                  | `output/reports/analysis_*.csv`          |
| Markdown   | Akademik formatta özet istatistikler, karşılaştırmalı tablo ve detaylar    | `output/reports/analysis_*.md`           |
| PNG        | Skor karşılaştırması, not dağılımı ve başlık kullanım oranı grafikleri     | `output/charts/{scores,grades,coverage}_*.png` |

`output/` klasörü `.gitignore` içinde tanımlıdır ve depoya dahil edilmez.

## Skorlama Sistemi

Her güvenlik başlığı bir ağırlığa sahiptir; toplam skor, başlıkların doğrulama
puanlarının (0-1) ağırlıklarıyla çarpılıp toplam ağırlığa bölünmesiyle 0-100
arasında bir yüzdeye dönüştürülür. Site HTTPS kullanmıyorsa toplam skordan
**%20 ceza** uygulanır.

| Başlık                          | Ağırlık | Korur                                    |
|---------------------------------|---------|-------------------------------------------|
| Content-Security-Policy          | 25      | XSS, veri enjeksiyonu                      |
| Strict-Transport-Security (HSTS) | 20      | MITM, SSL stripping                        |
| X-Frame-Options                  | 15      | Clickjacking                               |
| X-Content-Type-Options           | 10      | MIME sniffing                              |
| Referrer-Policy                  | 10      | Bilgi sızıntısı                            |
| Permissions-Policy               | 10      | Yetkisiz tarayıcı özelliği kullanımı       |
| X-XSS-Protection (legacy)        | 5       | XSS (eski tarayıcılar)                     |
| Cross-Origin-Opener-Policy        | 5       | Cross-origin pencere referansı saldırıları |
| Cross-Origin-Embedder-Policy      | 5       | Cross-origin veri sızıntısı                |
| Cross-Origin-Resource-Policy      | 5       | Cross-origin kaynak hırsızlığı             |

### Harf Notları

| Skor Aralığı | Not |
|--------------|-----|
| 90 - 100     | A+  |
| 80 - 89      | A   |
| 70 - 79      | B   |
| 60 - 69      | C   |
| 50 - 59      | D   |
| 0 - 49       | F   |

## Test Çalıştırma

```bash
pytest tests/
```

## Proje Yapısı

```
http-security-headers/
├── .gitignore
├── README.md
├── requirements.txt
├── main.py
├── src/
│   ├── __init__.py
│   ├── analyzer.py        # HTTP isteği ve başlık toplama
│   ├── scorer.py           # Ağırlıklı skor ve harf notu hesaplama
│   ├── headers_config.py   # Başlık tanımları ve doğrulayıcılar
│   ├── reporter.py          # JSON / CSV / Markdown raporları
│   └── visualizer.py        # Grafikler (PNG)
├── data/
│   └── turkish_sites.txt    # Analiz edilecek örnek site listesi
├── output/                   # Üretilen rapor ve grafikler (git'e dahil değil)
└── tests/
    └── test_analyzer.py      # Birim testleri
```

## Lisans

Bu proje [MIT Lisansı](https://opensource.org/licenses/MIT) ile lisanslanmıştır.
