# 🔥 JMeter Stres Test — Mersel DSS Signer

Bu paket, **canlı/staging ortamda gerçek HSM** (network HSM — Thales Luna /
Utimaco / SafeNet / yerel HSM) arkasında çalışan signer API'ye yük basmak
için kurgulandı.

> **Senaryo:** Sana bir endpoint URL'i veriliyor (örn. `https://signer.prod.local`)
> + bir verifier URL'i (örn. `https://verifier.prod.local`). Tüm HSM detayı —
> sürücü, PIN, session count, sertifika seçimi, mTLS, log rotation — sunucu
> tarafının derdi. **JMeter sadece HTTP istemcisi**: XAdES'e sürekli concurrent,
> PAdES'e ara ara istek atar, opsiyonel olarak her imzayı verifier'a doğrulatır,
> sonuçları derleyip dashboard üretir.

---

## 🎒 Test Makinene Taşıma (3 Adım)

Repo'yu test makinesine kopyalamaya **gerek yok**. Tek yapacağın:

### 1) Bundle hazırla (geliştirici makinesinde, repo içinde, bir kez)

```bash
# Klasör + tarball
./devops/load-tests/jmeter/prepare-bundle.sh /tmp/signer-loadtest --tgz
```

Çıktı:

```
✅ Bundle hazır: /tmp/signer-loadtest
   📦 Boyut       : 5.3M
   📄 XAdES dosya : 10
   📄 PAdES dosya : 4

📦 Tarball : /tmp/signer-loadtest.tgz (76K)
```

İçinde:

```
/tmp/signer-loadtest/
├── run.sh                   # Launcher (bundle-aware)
├── signer-stress.jmx        # JMeter test planı (verifier round-trip INLINE)
├── xades-fixtures.csv       # Path'ler bundle-relative (xades/...)
├── pades-fixtures.csv
├── xades/                   # 10 XAdES fixture (e-fatura, e-arşiv, HR-XML…)
├── pades/                   # 4 PAdES fixture
└── README.md                # Bundle-spesifik kısa kullanım kılavuzu
```

### 2) Test makinesine gönder

```bash
# Tarball ile
scp /tmp/signer-loadtest.tgz user@test-host:/opt/
ssh user@test-host 'cd /opt && tar -xzf signer-loadtest.tgz'

# veya rsync ile (klasör halinde)
rsync -av /tmp/signer-loadtest/ user@test-host:/opt/signer-loadtest/
```

Test makinesinde **tek bağımlılık: JMeter 5.6+**.

```bash
# Linux test host'unda
sudo apt-get install -y default-jdk
wget https://dlcdn.apache.org/jmeter/binaries/apache-jmeter-5.6.3.tgz
tar -xzf apache-jmeter-5.6.3.tgz
export PATH="$PWD/apache-jmeter-5.6.3/bin:$PATH"

# macOS
brew install jmeter
```

### 3) Koş

```bash
ssh user@test-host
cd /opt/signer-loadtest

# Yalnızca imza testi (signer API stres)
./run.sh --host signer.prod.local --port 443 --protocol https

# İmza + her isteğin Verifier API ile doğrulanması
./run.sh \
  --host signer.prod.local --port 443 --protocol https \
  --verify --verifier-url https://verifier.prod.local

# Auth gerekiyorsa
AUTH_HEADER="Bearer eyJ..." ./run.sh \
  --host signer.prod.local --port 443 --protocol https \
  --verify --verifier-url https://verifier.prod.local
```

Çıktı `/opt/signer-loadtest/results/<timestamp>-<profile>/report/index.html`
altında. HTTP server'lar üzerinden açmak için:

```bash
cd /opt/signer-loadtest/results/<timestamp>-<profile>/report
python3 -m http.server 8888       # tarayıcıdan http://test-host:8888
# veya scp ile yerel makineye çek, dosyaya çift tıkla
```

### Kendi fixture'larınla bundle

Repo'daki default fixture'lara ek olarak kendi XML/PDF'lerini de paketle:

```bash
./devops/load-tests/jmeter/prepare-bundle.sh /tmp/signer-loadtest \
  --extra-xades /home/me/musteri-fatura-1.xml \
  --extra-xades /home/me/musteri-fatura-2.xml \
  --extra-pades /home/me/musteri-sozlesme.pdf \
  --tgz
```

Veya sadece kendi fixture'larınla (repo default'larını dahil etme):

```bash
./devops/load-tests/jmeter/prepare-bundle.sh /tmp/signer-loadtest \
  --no-defaults \
  --extra-xades /home/me/musteri-fatura.xml \
  --extra-pades /home/me/musteri-sozlesme.pdf \
  --tgz
```

`prepare-bundle.sh --help` ile tüm opsiyonlar.

---

## 🖥️ JMeter GUI ile Kullanım

CLI'ya alternatif olarak `signer-stress.jmx`'i doğrudan JMeter masaüstü
uygulamasında açıp yönetebilirsin. Hem repo içinden hem de `prepare-bundle.sh`
ile üretilen bundle'dan aynı şekilde çalışır.

> ⚠️ **ÖNEMLİ — JMeter resmi tavsiyesi:** GUI **plan oluşturma, debug ve sanity
> test'leri** için tasarlanmıştır. **Büyük yük testlerinde** (yüzlerce thread,
> uzun süre) GUI'nin kendisi RAM/CPU yer ve listener'lar (özellikle View Results
> Tree) sonuçları çarpıtır. Gerçek stres/soak/spike koşumları için **mutlaka
> CLI** (`./run.sh` veya `jmeter -n`) kullan. Sanity / parametre tweak / debug
> için GUI ideal.

### Açma

```bash
# JMeter'ı HERHANGİ BİR DİZİNDEN aç. CWD bağımlılığı YOK.
# Plan içindeki "setUp — Resolve Paths" thread group, fixture/CSV/verifier
# script path'lerini layout-aware (repo / bundle) şekilde otomatik çözer.

# Repo içinden
jmeter -t /abs/path/to/repo/devops/load-tests/jmeter/plan/signer-stress.jmx

# Bundle içinden
jmeter -t /opt/signer-loadtest/signer-stress.jmx

# Veya boş JMeter aç, sonra File → Open ile .jmx'i seç
jmeter
```

> Test planını **kaydetme** (`Ctrl+S`) — repo'ya git diff bırakır. Sadece koş.
> Parametre değişikliklerini commit'lemek istiyorsan `prepare-bundle.sh`'a
> yansıt veya `-J<param>=...` ile geç.

> **Path resolution garantisi:** Test başlangıcında "setUp — Resolve Paths"
> sampler'ı çalışır ve JMeter log'una (`jmeter.log`) şu satırları basar:
> ```
> ===== Path resolution (layout=REPO|BUNDLE, planDir=...) =====
>   FIXTURE_BASE_DIR = ...
>   XADES_CSV        = ...
>   PADES_CSV        = ...
>   VERIFIER_SCRIPT  = ...
> ```
> CSV/script bulunamazsa aynı sampler `WARN [setUp] ... bulunamadı: ...` log'lar.

### Sol panelde göreceğin yapı

```
Mersel DSS Signer — Stress Test
├── Stress Test Variables          ← TÜM PARAMETRELER BURADA (host, port, vs.)
├── HTTP Request Defaults
├── HTTP Cookie Manager
├── HTTP Header Manager (auth)
│   └── Inject Authorization (if AUTH_HEADER non-empty)
├── setUp — Resolve Paths           ← Test başında 1 kere çalışır
│   └── Resolve Paths               (CSV/script path'lerini auto-resolve eder)
├── XAdES — Sustained Load          ← Thread Group #1
│   ├── XAdES Fixture CSV
│   └── POST /v1/xadessign
│       ├── HTTP 200 OK              [Response Assertion]
│       ├── x-signature-value header var mı?
│       └── Verify XAdES (conditional)   ← Verifier PostProcessor
├── PAdES — Sporadic Load           ← Thread Group #2
│   ├── PAdES Fixture CSV
│   ├── PAdES Throughput Limiter     [Constant Throughput Timer]
│   └── POST /v1/padessign
│       ├── HTTP 200 OK
│       ├── application/pdf content-type
│       └── Verify PAdES (conditional)
├── View Results Tree (debug — GUI'de Enable et)        [DISABLED]
├── Aggregate Report (özet — GUI'de Enable et)          [DISABLED]
└── Summary Report (GUI'de Enable et)                   [DISABLED]
```

### Parametreleri GUI'den değiştirme

**Sol panelde "Stress Test Variables"** node'una tıkla. Sağda User Defined
Variables tablosu açılır. Şu satırları doğrudan düzenle:

| Variable             | Anlamı                                       | Örnek                                |
| -------------------- | -------------------------------------------- | ------------------------------------ |
| `HOST`               | Hedef host                                   | `signer.prod.local`                  |
| `PORT`               | Hedef port                                   | `443`                                |
| `PROTOCOL`           | http/https                                   | `https`                              |
| `DURATION_SEC`       | Test süresi (sn)                             | `300`                                |
| `XADES_THREADS`      | XAdES eş zamanlı kullanıcı                    | `50`                                 |
| `PADES_THREADS`      | PAdES eş zamanlı kullanıcı                    | `2`                                  |
| `PADES_RPM`          | PAdES istek/dakika                            | `6`                                  |
| `AUTH_HEADER`        | Bearer token (boş = header gönderme)         | `Bearer eyJ...`                      |
| `VERIFIER_ENABLED`   | `true` → verifier round-trip aktif           | `true`                               |
| `VERIFIER_URL`       | Verifier API endpoint                         | `https://verifier.prod.local`        |
| `VERIFIER_LEVEL`     | `SIMPLE` veya `COMPREHENSIVE`                | `SIMPLE`                             |

> Varsayılan değerler `${__P(...,DEFAULT)}` formundadır. GUI'de bu hücrenin
> üstüne yazdığın değer, CLI'da `-J<param>=...` ile aynıdır. Override hep
> sağında bıraktığın değerden gelir.

### CSV / fixture / verifier-script path'leri (otomatik resolve)

Sol panelde **"XAdES Fixture CSV"** ve **"PAdES Fixture CSV"** node'larına
tıkla. Filename hücresinde `${__P(xadesCsv,)}` / `${__P(padesCsv,)}` görürsün.
HTTPSampler altındaki **"Send Files With the Request"** kısmında ise
`${__P(fixtureBaseDir,)}/${filePath}` (XAdES) ve
`${__P(fixtureBaseDir,)}/${padesFilePath}` (PAdES) yazar.

Bu property'ler **boş bırakılırsa** test başındaki `setUp — Resolve Paths`
sampler'ı tarafından otomatik doldurulur:

| Property          | Repo layout default                              | Bundle layout default                   |
| ----------------- | ------------------------------------------------ | --------------------------------------- |
| `fixtureBaseDir`  | `<repo-root>` (plan'ın 4 üst dizini)             | `<bundle-root>` (plan dizini)           |
| `xadesCsv`        | `<repo-root>/devops/load-tests/jmeter/data/...`  | `<bundle-root>/xades-fixtures.csv`      |
| `padesCsv`        | `<repo-root>/devops/load-tests/jmeter/data/...`  | `<bundle-root>/pades-fixtures.csv`      |
| `verifierScript`  | _yok — JMX'te INLINE (CDATA)_                    | _yok — JMX'te INLINE (CDATA)_           |

> Layout tespiti `xades-fixtures.csv`'nin plan ile aynı klasörde olup olmadığına
> bakarak yapılır (bundle ise plan-dizini, değilse 4 üst dizin repo-root).

Kendi path'ini geçmek istersen JMeter Properties dialog'unda (`Options → SSL
Manager`'ın altındaki Properties yok — onun yerine CLI'dan `-JfixtureBaseDir=...`
ile, GUI'de "Test Plan" sağ panelindeki **Test Plan Variables** kısmına ekle:
örn. `xadesCsv` = `/home/me/custom-xades.csv`). Bu değer setUp tarafından
override edilmez.

### Koşum (GUI)

1. **Yeşil ▶ butonu** (üst menü çubuğu) ile başlat.
2. Alt status bar'da aktif thread sayısı + geçen süre.
3. Durdurmak için **kırmızı ⏹** (graceful) veya **🛑** (immediate).
4. Koşum tamamlanınca **Tools → Generate HTML Report**:
   - Results file: `<bir önce kaydettiğin JTL>`
   - Output directory: boş bir klasör
   - JMeter properties: default
   - **Generate** → CLI ile aynı HTML dashboard üretilir.

### Listener'ları açmak (yapacaksan **küçük testte**)

1. **View Results Tree** üzerine **sağ tık → Enable**.
2. Sanity testini koş (5 thread, 30 sn — _baseline değil!_).
3. Sol panel "View Results Tree" → sağda request/response detayları
   (header'lar, body, latency). Verifier subresult'ları da
   ağaç altında "Verify XAdES" / "Verify PAdES" olarak görünür.
4. Tamamlandıktan sonra **tekrar Disable** et — sonraki koşumları kasmasın.

> **Asla** `View Results Tree` enabled iken `--stress` veya `--soak` yapma.
> 200 thread × 5 dk = ~milyonlarca sample, JMeter heap'i şişer.

### GUI tipik kullanım senaryoları

| Senaryo                                       | GUI mu yoksa CLI mı?                          |
| --------------------------------------------- | --------------------------------------------- |
| **Plan'ı görsel olarak incelemek**            | GUI                                           |
| **Parametre değerlerini ayarlamak**           | GUI (sonra `-J<param>=...` ile CLI'da geç)    |
| **Tek/birkaç request'i debug etmek**          | GUI + View Results Tree (5 thread, 30sn)       |
| **Sanity / smoke**                            | İkisi de OK (GUI biraz daha kolay)            |
| **Baseline / stress / soak / spike**          | **CLI ZORUNLU** — GUI sonuçları çarpıtır       |
| **CI/CD pipeline'da**                         | CLI (`jmeter -n` veya `./run.sh`)             |

### "GUI'de bir saniye, hızlıca tweak'leyip koşmak" iş akışı

```bash
# 1) Aç
jmeter -t devops/load-tests/jmeter/plan/signer-stress.jmx

# 2) Sol panelde "Stress Test Variables"a tıkla → HOST=signer.prod.local yap
#    Verifier istiyorsan → VERIFIER_ENABLED=true, VERIFIER_URL=https://verifier.prod.local
#    XADES_THREADS=5, PADES_THREADS=1, DURATION_SEC=30 (sanity)

# 3) Yeşil ▶ ile koş

# 4) Bittikten sonra Tools → Generate HTML Report ile dashboard üret

# 5) Memnunsan, aynı parametrelerle CLI'da büyük koşum:
./devops/load-tests/jmeter/run.sh --stress \
  --host signer.prod.local \
  --verify --verifier-url https://verifier.prod.local
```

---

## ⚡ TL;DR (repo içinden — geliştirme döngüsü)

```bash
# 1) Endpoint'i bir kez manuel doğrula (PFX/HSM/network hepsi ayakta mı?)
curl -X POST https://signer.prod.local/v1/xadessign \
  -F "Document=@resources/test-fixtures/xades/efatura.xml" \
  -F "DocumentType=UblDocument" \
  -o /tmp/signed.xml -D /tmp/headers.txt
grep -i x-signature-value /tmp/headers.txt  # bu satırı görmen ŞART

# 2) Sadece imza — baseline (50 XAdES + 2 PAdES @ 6/dk, 5 dk)
./devops/load-tests/jmeter/run.sh \
  --host signer.prod.local --port 443 --protocol https

# 2-alt) İmza + her isteğin Verifier API ile doğrulanması
./devops/load-tests/jmeter/run.sh \
  --host signer.prod.local --port 443 --protocol https \
  --verify --verifier-url https://verifier.prod.local

# 2-alt) Kendi fixture klasörünle
./devops/load-tests/jmeter/run.sh \
  --host signer.prod.local --port 443 --protocol https \
  --data-dir /home/me/my-fixtures \
  --verify --verifier-url https://verifier.prod.local

# 3) Raporu aç
open devops/load-tests/jmeter/results/<timestamp>-baseline/report/index.html
```

---

## 📦 Repo Paket İçeriği

```
devops/load-tests/jmeter/
├── plan/
│   └── signer-stress.jmx        # JMeter test planı (parametrik, verifier script INLINE)
├── data/
│   ├── xades-fixtures.csv       # 10 XAdES fixture (e-fatura/e-arşiv/HR-XML/UBL)
│   └── pades-fixtures.csv       # 4 PAdES fixture (küçük/büyük/A3/TR-karakter)
├── run.sh                       # CLI launcher (bundle-aware + HTML dashboard)
├── prepare-bundle.sh            # Self-contained test paketi üretici
├── .gitignore                   # results/ commit'lenmiyor
└── README.md
```

> `prepare-bundle.sh` ile üretilen taşınabilir bundle'ın layout'u farklıdır
> (`xades/` + `pades/` düz, CSV path'leri yeniden yazılmış). Detay:
> ["🎒 Test Makinene Taşıma"](#-test-makinene-ta%C5%9F%C4%B1ma-3-ad%C4%B1m).

### Test planında ne var?

İki Thread Group **paralel** çalışır:

| Thread Group               | Endpoint            | Davranış                                           | Default                                       |
| -------------------------- | ------------------- | -------------------------------------------------- | --------------------------------------------- |
| **XAdES — Sustained Load** | `POST /v1/xadessign` | Tam gaz, throttling yok                            | 50 thread × test süresi                       |
| **PAdES — Sporadic Load**  | `POST /v1/padessign` | `Constant Throughput Timer` ile RPM cap            | 2 thread, **6 req/dk** (≈ 10sn'de 1)          |

Her sampler'da:
- **CSV Data Set** ile fixture rotasyonu — her iterasyon farklı dosya, gateway/CDN cache yanılgısı yok
- **Response Assertion**: 200 + XAdES için `x-signature-value` header (gerçekten imzalandı mı), PAdES için `application/pdf` content-type
- **Multipart upload** — controller'daki `MultipartFile Document` kontratıyla birebir aynı
- **Opsiyonel Authorization header** — `AUTH_HEADER` env varsa JSR223 PreProcessor injekte eder, boşsa hiç eklemez
- **Opsiyonel Verifier round-trip** — `VERIFIER_ENABLED=true` ise her başarılı imza, `mersel-dss-verifier-api`'ye POST edilip `valid:true` kontrolü yapılır; başarısızsa parent sampler da fail (ayrıntı: ["🔍 Verifier API Entegrasyonu"](#-verifier-api-entegrasyonu))

---

## 🚀 Kullanım

### 1) JMeter kurulumu (test makinesinde)

```bash
# macOS
brew install jmeter

# Linux (manuel)
# https://jmeter.apache.org/download_jmeter.cgi → 5.6.x indir, PATH'e ekle
```

### 2) Endpoint sanity (PIN lockout sigortası)

Yük atmadan **önce** tek istekle imzanın gerçekten dönüp döndüğünü doğrula. PFX
yerine gerçek HSM kullanan endpointlerde yanlış PIN üst üste denenirse HSM
operatörünün ekranına bir alarm düşer; gereksiz dikkat çekme:

```bash
curl -X POST https://signer.prod.local/v1/xadessign \
  -F "Document=@resources/test-fixtures/xades/efatura.xml" \
  -F "DocumentType=UblDocument" \
  -o /tmp/signed.xml -D /tmp/headers.txt -k

# Auth gerekiyorsa:
curl -X POST https://signer.prod.local/v1/xadessign \
  -H "Authorization: Bearer $TOKEN" \
  -F "Document=@resources/test-fixtures/xades/efatura.xml" \
  -F "DocumentType=UblDocument" \
  -o /tmp/signed.xml -D /tmp/headers.txt -k

grep -i x-signature-value /tmp/headers.txt
```

`x-signature-value` header'ı dönüyorsa endpoint çalışıyor demektir.
**Dönmüyorsa yük testine başlama** — sebep bulunmadan istek yığma.

### 3) Yük ver

```bash
# Baseline (default): 50 XAdES sustained + 2 PAdES @ 6/dk, 5 dakika
./devops/load-tests/jmeter/run.sh \
  --host signer.prod.local --port 443 --protocol https

# Smoke / CI sanity (5 thread, 30 sn)
./devops/load-tests/jmeter/run.sh --smoke \
  --host signer.prod.local --port 443 --protocol https

# Kapasite tavanı arama (200 XAdES + 5 PAdES @ 18/dk, 15 dakika)
./devops/load-tests/jmeter/run.sh --stress \
  --host signer.prod.local --port 443 --protocol https

# Endurance / leak avı (100 XAdES + 3 PAdES, 1 saat)
./devops/load-tests/jmeter/run.sh --soak \
  --host signer.prod.local --port 443 --protocol https

# Spike / ani trafik (500 XAdES + 10 PAdES @ 30/dk, 2 dakika)
./devops/load-tests/jmeter/run.sh --spike \
  --host signer.prod.local --port 443 --protocol https
```

### 4) Auth gerekiyorsa

Sunucu Bearer token / API key bekliyorsa:

```bash
AUTH_HEADER="Bearer eyJhbGciOiJIUzI1NiIs..." \
  ./devops/load-tests/jmeter/run.sh \
  --host signer.prod.local --port 443 --protocol https
```

Plan, JSR223 PreProcessor ile her sampler'a otomatik enjekte eder. `AUTH_HEADER`
boş geldiğinde header **hiç** eklenmez.

### 5) İnce ayar (env override)

```bash
XADES_THREADS=300 \
PADES_RPM=24 \
DURATION_SEC=1800 \
RESPONSE_TIMEOUT=180000 \
JVM_HEAP=4g \
  ./devops/load-tests/jmeter/run.sh \
  --host signer.prod.local --port 443 --protocol https
```

Çıktı:

```
✅ HTML rapor : devops/load-tests/jmeter/results/20260521-180000-baseline/report/index.html
📄 Raw JTL    : .../result.jtl
🪵 JMeter log : .../jmeter.log
```

---

## 📊 Profile Karşılaştırması

| Profil        | XAdES threads | PAdES threads | PAdES RPM | Duration | Ramp-up | Response TO | Amaç                                     |
| ------------- | -------------:| -------------:| ---------:| --------:| -------:| -----------:| ---------------------------------------- |
| `--smoke`     |             5 |             1 |         4 |    30 sn |    5 sn |        60 s | CI sanity, endpoint hayatta mı?           |
| _(baseline)_  |            50 |             2 |         6 |    5 dk  |   30 sn |        60 s | Production benzeri tipik yük              |
| `--stress`    |           200 |             5 |        18 |   15 dk  |   60 sn |        60 s | Kapasite tavanı arama                     |
| `--soak`      |           100 |             3 |        12 |    1 sa  |   60 sn |       120 s | Memory / HSM session / TLS handshake leak |
| `--spike`     |           500 |            10 |        30 |    2 dk  |    5 sn |        60 s | Ani trafik → backlog & connection pool    |

Tipik kapasite planlama sırası: `--smoke` → _baseline_ → `--stress` → `--soak`.

---

## 🔍 Verifier API Entegrasyonu

Her başarılı imzayı, ayrı bir endpoint olarak verilen
[`mersel-dss-verifier-api`](https://github.com/mersel-dss/mersel-dss-verifier-api-java)'ye
gönderip "gerçekten geçerli mi?" kontrolünü ek bir adım olarak çalıştırabilirsin.

**Default: KAPALI.** Çünkü ek trafik, ek latency, ek hata yüzeyi — sadece
istediğinde açılır.

### Açma

```bash
./devops/load-tests/jmeter/run.sh \
  --host signer.prod.local --port 443 --protocol https \
  --verify --verifier-url https://verifier.prod.local
```

### Nasıl çalışıyor

Her sampler'ın altındaki `JSR223 PostProcessor` Groovy script'ini çalıştırır.
Script **JMX'in `<script>` CDATA'sında inline gömülü** — harici dosya gerekmez,
test plan tek-dosya self-contained. (İleri seviye kullanıcılar
`-JverifierScript=/abs/path.groovy` ile kendi script'lerini geçip inline'ı
override edebilir; o zaman JMeter dosyayı önceler.) Akış:

1. `VERIFIER_ENABLED=true` mu? Değilse **hemen `return`** — zero overhead.
2. Sign sampler başarılı mı? Değilse atla (gürültü önler).
3. İmzalı response body'sini bytes olarak al → multipart `signedDocument`,
   `level=SIMPLE` ile `POST /api/v1/verify/signature`'a gönder.
4. JSON cevapta `"valid":true` var mı? Hızlı substring check (Jackson parse
   hot-path'te GC pressure yapar — verifier şeması stabil).
5. Sonuç **SubResult** olarak parent sampler'a iliştirilir → dashboard'da
   ayrı "VERIFY XAdES" / "VERIFY PAdES" satırı çıkar.
6. Verify başarısız (`valid:false`, non-200, exception) → parent sampler da
   `failed` işaretlenir → genel başarı oranına yansır.

**Performans optimizasyonları script içinde:**
- HttpClient lazy-init + tüm thread'lerce paylaşılan connection pool
  (`maxConnTotal=1000`, `maxConnPerRoute=500`) → her verify'da TCP/TLS handshake yok.
- `disableAutomaticRetries()` — yük testinde retry yanıltıcı metrikler üretir.
- `level=SIMPLE` default — `COMPREHENSIVE` 5–20× daha yavaş, gerçek imza
  geçerlilik regression'ı için SIMPLE yeterli.
- `AUTH_HEADER` set'liyse aynı token verifier'a da iletilir (aynı IDP arkasında).

### Parametre ayarı

```bash
# COMPREHENSIVE level (tam DSS validasyonu — yavaş)
./run.sh --verify --verifier-url ... --verifier-level COMPREHENSIVE --host ...

# Verifier socket timeout artır (büyük belge / yavaş validator)
./run.sh --verify --verifier-url ... --verifier-timeout 60000 --host ...

# Aynı Bearer token hem signer hem verifier için
AUTH_HEADER="Bearer eyJ..." \
  ./run.sh --verify --verifier-url ... --host ...
```

### Dashboard'da ne göreceksin

JMeter HTML raporu sample label'larını ayrı satırlarda gösterir:

| Label                     | Anlamı                                                |
| ------------------------- | ----------------------------------------------------- |
| `POST /v1/xadessign`      | Sign tarafı (servis + HSM)                            |
| `VERIFY XAdES`            | Verifier round-trip (subresult — sign'ın ALT satırı)  |
| `POST /v1/padessign`      | Sign tarafı                                            |
| `VERIFY PAdES`            | Verifier round-trip                                    |

**Kıyaslama tablosu**: sign p95 = 250ms, verify p95 = 80ms → end-to-end (e2e)
"imzala + doğrula" gerçek user pipeline yaklaşık **330ms**. Bu kombinasyonu
SLA hedefiyle kıyaslayabilirsin.

**Hata senaryoları** (verifier subresult'unda görünür):
- `valid:false` döndü → response body'sinde `validationErrors` listesi loglanır
- `VERIFY_ERROR` response code → verifier-api erişilemez veya timeout
- 5xx + "No implementation found for ICMSUtils" → verifier-api eksik DSS
  modülüyle build edilmiş (downstream sorun, sign tarafı sağlam)

---

## 📁 Dış Fixture'lar (Custom Belgeler) & JAR-only Deploy

Test ortamına repo'yu açamayan / sadece JMeter + JAR ile deploy edenler için
fixture'ları **tamamen dışarıdan** verebilirsin.

### Senaryo A: Repo'daki fixture'lar yeter (default)

Bir şey yapma. `run.sh` herhangi bir path argümanı geçmez; JMX içindeki
`setUp — Resolve Paths` sampler'ı `data/xades-fixtures.csv` ve
`data/pades-fixtures.csv`'i layout-aware şekilde otomatik bulur. CSV içindeki
path'ler repo root'a relative (`resources/test-fixtures/...`) ve
`${__P(fixtureBaseDir,)}` (= repo root, setUp tarafından doldurulur) ile
prefix'lenip doğru dosyaya çözülür. **CWD'den bağımsız çalışır.**

### Senaryo B: Kendi fixture klasörün (önerilen)

Hazırla:

```
/home/me/load-fixtures/
├── xades-fixtures.csv
├── pades-fixtures.csv
├── xades/
│   ├── ozel-fatura-1.xml
│   ├── ozel-fatura-2.xml
│   └── ...
└── pades/
    ├── sozlesme.pdf
    └── ...
```

CSV içeriği — **absolute path** veya `run.sh`'ın çağrıldığı dizine göre
relative:

`/home/me/load-fixtures/xades-fixtures.csv`:
```csv
filePath,documentType,mimeType
/home/me/load-fixtures/xades/ozel-fatura-1.xml,UblDocument,application/xml
/home/me/load-fixtures/xades/ozel-fatura-2.xml,UblDocument,application/xml
```

`/home/me/load-fixtures/pades-fixtures.csv`:
```csv
filePath,mimeType
/home/me/load-fixtures/pades/sozlesme.pdf,application/pdf
```

Çalıştır:

```bash
./devops/load-tests/jmeter/run.sh \
  --host signer.prod.local --port 443 --protocol https \
  --data-dir /home/me/load-fixtures
```

`--data-dir` altında **`xades-fixtures.csv`** ve **`pades-fixtures.csv`**
beklenir. CSV ya da klasör yoksa script açıkça hata verir (`exit 5`).

### Senaryo C: Tek tek CSV override

Sadece XAdES'i kendi setiyle değiştir, PAdES için repo default kullan:

```bash
./devops/load-tests/jmeter/run.sh \
  --host signer.prod.local --port 443 --protocol https \
  --xades-csv /home/me/my-xades-custom.csv
```

### Senaryo D: Manuel JMeter çağrısı (run.sh kullanmadan)

Bundle'ı çıkardığın klasörden, `run.sh` olmadan direkt JMeter çağrısı:

```bash
cd /opt/signer-loadtest

jmeter -n \
  -t signer-stress.jmx \
  -l /tmp/result.jtl \
  -j /tmp/jmeter.log \
  -e -o /tmp/report \
  -Jhost=signer.prod.local \
  -Jport=443 \
  -Jprotocol=https \
  -Jduration=300 \
  -JxadesThreads=50 \
  -JpadesThreads=2 \
  -JpadesRpm=6 \
  -JxadesCsv=./xades-fixtures.csv \
  -JpadesCsv=./pades-fixtures.csv \
  -JverifierEnabled=true \
  -JverifierUrl=https://verifier.prod.local \
  -JauthHeader="Bearer eyJ..."
```

CI/CD entegrasyonunda faydalı; `run.sh`'ın profile soyutlamasına ihtiyacın
yoksa direkt bu satırı koş.

---

## 📈 Dashboard Yorumlama

Apache JMeter dashboard otomatik üretilir. Endpoint arkasındaki HSM-backed
signer için bakılacak metrikler:

| Metrik                          | Yorumu                                                                              |
| ------------------------------- | ----------------------------------------------------------------------------------- |
| **APDEX**                       | 1.0'a yakın iyi. <0.8 ise endpoint zorlanıyor.                                       |
| **Throughput (RPS)**            | Sürdürülebilir tavan. Network HSM tipik: cluster'a göre 50–500+ RPS.                |
| **p50 / Median**                | İmza başına typical RT (network + HSM + serialize). 100–400ms makul.                |
| **p95 / p99**                   | Tail latency — kuyruk + GC + HSM session pool kontention.                            |
| **Errors %**                    | %0 olmalı. >0 ise per-request breakdown'a in.                                        |
| **XAdES vs PAdES per-request**  | PAdES her zaman daha yavaş (PDF stream + CAdES embed). XAdES p95 PAdES isteği gelince sıçrıyor mu? |
| **Throughput over time**        | Düz çizgi → sağlıklı. Sönüyor → leak / pool exhaustion / GC tuned-out.               |

### Çapraz okuma — sunucu tarafı

Test devam ederken sunucu ekibinden ya da kendin `actuator/prometheus`'tan
çek:

```bash
curl -sk https://signer.prod.local/actuator/prometheus \
  | grep -E '(http_server_requests_seconds_(count|sum|max)|jvm_memory_used_bytes|process_files_open_files|tomcat_threads_busy)'
```

Karşılaştır:
- **Client p95** (JMeter dashboard) **vs Server p95** (`http_server_requests_seconds`'ten hesap) → fark = ağ + JMeter overhead.
- **`process_files_open_files`** zamanla artıyorsa → PKCS#11 session / file descriptor leak.
- **`tomcat_threads_busy` doyuyor** → Tomcat thread pool yetmiyor, `server.tomcat.threads.max` artır.

---

## 🧯 Sık Karşılaşılan Tuzaklar

| Belirti                                       | Olası sebep                                              | Çözüm                                                                                  |
| --------------------------------------------- | -------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| Tüm istekler `Connection refused`             | Yanlış host/port veya endpoint kapalı                    | `curl` ile manuel doğrula; firewall/VPN kontrol et.                                    |
| Tüm istekler `401`                            | Auth gerekiyor                                           | `AUTH_HEADER="Bearer ..." ./run.sh ...`                                                |
| Tüm istekler `400` `INVALID_INPUT`            | Multipart parametresi farklı                              | Endpoint kontratı değişmiş olabilir; controller'a bak.                                 |
| `SSLHandshakeException`                       | HTTPS endpoint + self-signed sertifika                   | JMeter default'ta SSL doğrulamayı atlar; `protocol=https` set ettiğine emin ol.       |
| `Read timed out`                              | HSM yavaş / büyük PDF                                    | `--response-timeout 180000` veya `RESPONSE_TIMEOUT=300000`                             |
| Throughput zamanla düşüyor                    | Leak (memory / HSM session / TLS handshake / FD)         | `actuator/prometheus`'tan trend al; bir `--soak` koş, server restart sonrası kıyasla. |
| Bir noktadan sonra error %'i sıçrıyor         | Connection pool / Tomcat thread / HSM session doydu      | Server tarafında `server.tomcat.threads.max`, HSM `MAX_SESSION_COUNT` arttır.          |
| JMeter OOM (`java.lang.OutOfMemoryError`)     | JTL büyüyor + heap düşük; verifier açıkken response body 2× memory | `JVM_HEAP=4g ./run.sh ...`                                                             |
| CSV "File not found"                          | Script repo root'tan çalıştırılmadı veya CSV'de relative path | Komutu **repo root**'tan çalıştır, ya da CSV'de absolute path kullan.                |
| `VERIFY_ERROR` subresult'ı çoğalıyor          | Verifier endpoint timeout / unreachable / 5xx             | `--verifier-timeout 60000`, ya da verifier-api log'una bak.                            |
| Verifier `valid:false` dönüyor                | İmza geçersiz veya trust anchor yok                       | Tek bir imzayı `curl` ile verifier'a yolla, response body'deki `validationErrors` listesini incele. |
| Verifier `No implementation found for ICMSUtils` | Verifier-api image'ı eksik DSS modülüyle build edilmiş   | Downstream sorun — verifier ekibine bildir; bu repo'nun değil.                          |
| `Script file '...verifier-bridge.groovy' is not a file` | **Eski JMX kullanıyorsun.** Bu repo'da artık script JMX'in içine gömülü, harici dosya yok. | Repodan/bundle'dan yeni `signer-stress.jmx`'i al, JMeter'ı restart et. |
| `--verifier-script /custom.groovy` verdim ama bulamıyor | Verdiğin path yanlış               | Absolute path ver veya flag'i atla → inline kullanılır.                |

---

## ⚙️ Parametre Referansı

Hepsi env veya `-J<isim>=value` ile geçilir. `run.sh` env → `-J`
mapping'ini otomatik yapar.

| Parametre           | Default     | Anlamı                                                       |
| ------------------- | ----------- | ------------------------------------------------------------ |
| `host`              | `localhost` | Hedef host (FQDN veya IP)                                    |
| `port`              | `8085`      | Hedef port                                                   |
| `protocol`          | `http`      | `http` / `https`                                             |
| `duration`          | `300`       | Saniye cinsinden test süresi (her iki thread group)           |
| `xadesThreads`      | `50`        | XAdES eş zamanlı kullanıcı                                    |
| `xadesRampup`       | `30`        | XAdES ramp-up süresi (sn)                                    |
| `padesThreads`      | `2`         | PAdES eş zamanlı kullanıcı                                    |
| `padesRampup`       | `5`         | PAdES ramp-up (sn)                                           |
| `padesRpm`          | `6`         | PAdES req/dakika (Constant Throughput Timer cap)              |
| `connectTimeout`    | `5000`      | ms                                                           |
| `responseTimeout`   | `60000`     | ms (büyük PDF veya yavaş HSM için artır)                      |
| `authHeader`        | _(boş)_     | `Authorization` header value (örn. `Bearer ...`). Boşsa hiç eklenmez. |
| `fixtureBaseDir`    | (setUp resolve) | Fixture root dizini (repo-root veya bundle-root, layout-aware)  |
| `xadesCsv`          | (setUp resolve) | XAdES fixture CSV mutlak path                                   |
| `padesCsv`          | (setUp resolve) | PAdES fixture CSV mutlak path                                   |
| `verifierEnabled`   | `false`     | `true` → her başarılı imza verifier-api'ye yollanır               |
| `verifierUrl`       | _(boş)_     | Verifier endpoint base URL (örn. `https://verifier.prod.local`)  |
| `verifierLevel`     | `SIMPLE`    | `SIMPLE` (perf) veya `COMPREHENSIVE` (tam DSS validasyonu)      |
| `verifierTimeout`   | `30000`     | Verifier socket timeout (ms)                                     |
| `verifierScript`    | _(boş — inline)_ | Default: JMX'in içine gömülü script. Sadece harici dosya ile override gerekirse `/abs/path.groovy` ver. |

### Script flag'leri

| Flag                       | Anlamı                                                |
| -------------------------- | ----------------------------------------------------- |
| `--smoke` / `--quick`      | CI sanity profili                                     |
| `--stress`                 | Kapasite tavanı profili                                |
| `--soak`                   | Endurance profili (1 saat)                            |
| `--spike`                  | Ani trafik profili                                    |
| `--host <h>`               | Hedef host override                                   |
| `--port <p>`               | Hedef port override                                   |
| `--protocol http\|https`   | Protokol override                                     |
| `--duration <sec>`         | Süre override                                         |
| `--xades-threads <n>`      | XAdES thread sayısı override                          |
| `--pades-threads <n>`      | PAdES thread sayısı override                          |
| `--pades-rpm <n>`          | PAdES req/dakika override                             |
| `--response-timeout <ms>`  | Response timeout override                             |
| `--skip-health`            | Pre-flight `actuator/health` kontrolünü atla (kapalıysa) |
| `--verify`                 | Verifier round-trip'i aç                              |
| `--no-verify`              | Verifier round-trip'i kapat (explicit)                |
| `--verifier-url <url>`     | Verifier base URL (`--verify`'i de aktive eder)        |
| `--verifier-level SIMPLE\|COMPREHENSIVE` | Validation level                       |
| `--verifier-timeout <ms>`  | Verifier socket timeout                                |
| `--verifier-script <path>` | Bridge groovy script path (JAR-only deploy için)       |
| `--data-dir <path>`        | Fixture klasörü (CSV'ler bu altında aranır)            |
| `--xades-csv <path>`       | XAdES CSV path override (data-dir'i de override eder) |
| `--pades-csv <path>`       | PAdES CSV path override                                |

---

## 🔌 İleri Seviye

### Backend Listener (Prometheus / InfluxDB)

`.jmx`'i GUI'de aç → ilgili Thread Group altına Backend Listener ekle:

- **InfluxDB v2**: `Backend Listener → InfluxdbBackendListenerClient`
- **Prometheus**: [jmeter-prometheus-plugin](https://github.com/johrstrom/jmeter-prometheus-plugin)

Sunucunun kendi `/actuator/prometheus`'u ile çakıştırınca **client-RT vs
server-RT** delta'sı net çıkar — gerçek network/JMeter overhead'i ölçersin.

### mTLS

Sunucu mTLS bekliyorsa JMeter'a client cert geçirmen lazım:

```bash
export JVM_ARGS="-Djavax.net.ssl.keyStore=/path/to/client.p12 \
                 -Djavax.net.ssl.keyStorePassword=... \
                 -Djavax.net.ssl.keyStoreType=PKCS12"
./devops/load-tests/jmeter/run.sh --host ... --protocol https
```

Veya `jmeter.properties`'ta:

```properties
https.use.cached.ssl.context=false
https.keyStoreStartIndex=0
https.keyStoreEndIndex=0
```

### Distributed mode (büyük yük)

Tek JMeter makinesi ~500–1000 thread'i kaldırır. Daha fazlası için master/slave:

```bash
# Slave node
jmeter-server -Djava.rmi.server.hostname=<slave-ip>

# Master
jmeter -n -t plan/signer-stress.jmx -R slave1-ip,slave2-ip ...
```

---

**Operasyonel kural:** Bu paket **prod'a stres atan** bir araç. Test ekibiyle
ve sunucu ekibiyle önceden saat/profil planı yap (özellikle `--stress` ve
`--spike` için). Yerleşik bulut tabanlı muhasebe çözümlerinin "load test = canlı
sürpriz" alışkanlığını burada üretmeyelim.
