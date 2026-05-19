# Mersel DSS Signer — Run / Debug Profilleri

> **TL;DR** — Repo'yu klonla, JDK 8+ kurulu olsun, IDE'de aç. `.run/` klasöründeki "Signer · Default (KURUM01 RSA-2048)" config'iyle direkt Run veya Debug bas. PFX repo'da hazır, ortam değişkeni set etmek gerekmiyor.

Bu doküman üç farklı geliştirici kanalını anlatır:

1. **IntelliJ IDEA / Cursor** — `.run/*.run.xml` shared configurations
2. **VS Code** — `.vscode/launch.json` + `.vscode/tasks.json`
3. **CLI** — `scripts/dev-run.sh` (POSIX) ve `scripts/dev-run.bat` (Windows)

Üç kanal da aynı **Spring profile katmanlarını** kullanır; farklı bir keystore'a geçmek için tek tıkla / tek argümanla profil değişiyor.

---

## 1. Spring Profile Mimarisi

Bu repo "composable" Spring profile yaklaşımıyla çalışır. Her profile **tek bir konuya** sahiptir, üst üste yığılır:

| Profile | Sorumluluk |
|---|---|
| `local` | Network'i kapatır (CertificateChain offline, KamuSM TSP off, trusted root resolver no-op), DEBUG log seviyesini açar. **Tüm dev senaryolar bunu içerir.** |
| `pfx-kurum01-rsa2048` | KURUM01 RSA-2048 test PFX (default sahnede otomatik aktif) |
| `pfx-kurum02-rsa2048` | KURUM02 RSA-2048 (sm.gov.tr sahipli) |
| `pfx-kurum02-ec384` | KURUM02 EC-P384 — ECDSA imza yolu testi |
| `pfx-kurum03-rsa2048` | KURUM03 RSA-2048 |
| `pfx-kurum03-ec384` | KURUM03 EC-P384 |
| `mali-muhur-akis-mac` | TÜBİTAK Mali Mühür AKİS macOS sürücüsü (`/usr/local/lib/libakisp11.dylib`) |
| `mali-muhur-akis-linux` | Mali Mühür AKİS Linux sürücüsü (`/usr/local/lib/libakisp11.so`) |
| `mali-muhur-akis-windows` | Mali Mühür AKİS Windows sürücüsü (`C:/Windows/System32/akisp11.dll`) |

### Aktivasyon Kuralı

Her zaman **`local` + bir alt-profile** birlikte aktive edilir:

```
--spring.profiles.active=local,pfx-kurum02-ec384
--spring.profiles.active=local,mali-muhur-akis-mac
```

`local` ortak ortam ayarlarını tek bir yerden çekmemizi sağlıyor (DRY); alt-profile yalnızca keystore'a özgü override'ları taşır.

### PFX vs HSM — Neden Ayrı?

- **PFX profilleri** repo'daki KamuSM publicly published test sertifikalarını kullanır. PIN dosya adında açıkta; geliştirici hiçbir env var girmek zorunda değil. Üç OS'te de aynı dosya çalışır — `PFX_PATH` repo-relatif.
- **HSM profilleri** OS'in PKCS#11 sürücü yolunu farklı yerden aldığı için ayrılmıştır. Operatör akıllı kart takıp `CERTIFICATE_PIN` env'ini doldurur; PFX'in aksine kart bağımlı olduğu için profile dosyasında PIN tutulmaz.

---

## 2. IntelliJ IDEA / Cursor

`.run/` klasörü repo'ya commit'li; IDE bunları otomatik tanır.

### Mevcut configurations

| Config adı | Profile | Notu |
|---|---|---|
| `Signer · Default (KURUM01 RSA-2048)` | `local,pfx-kurum01-rsa2048` | Yeni geliştirici için başlangıç noktası |
| `Signer · PFX RSA-2048 (KURUM02 sm.gov.tr)` | `local,pfx-kurum02-rsa2048` | sm.gov.tr sahipli alternatif RSA |
| `Signer · PFX EC-384 (KURUM02)` | `local,pfx-kurum02-ec384` | ECDSA r||s plain regression testi için |
| `Signer · PFX RSA-2048 (KURUM03)` | `local,pfx-kurum03-rsa2048` | Üçüncü kurum, RSA |
| `Signer · PFX EC-384 (KURUM03)` | `local,pfx-kurum03-ec384` | Üçüncü kurum, EC |
| `Signer · Mali Mühür AKİS (macOS)` | `local,mali-muhur-akis-mac` | Gerçek AKİS kartı + PIN |
| `Signer · Mali Mühür AKİS (Linux)` | `local,mali-muhur-akis-linux` | Gerçek AKİS kartı + PIN |
| `Signer · Mali Mühür AKİS (Windows)` | `local,mali-muhur-akis-windows` | Gerçek AKİS kartı + PIN |
| `CLI · List PFX Certificates (KURUM01)` | (yok — `--list-certificates`) | Spring kalkmaz, sadece PFX içeriğini stdout'a basar |
| `Tests · Unit (mvn test)` | — | Default suite (377 test, ~50 sn) |
| `Tests · XAdES SigningTime (issue 7)` | — | Issue #7 regression suite |
| `Tests · Verifier E2E (Docker)` | — | Verifier-e2e tag'li suite (Docker gerekir) |

### Run / Debug

1. IntelliJ üst-sağ Run dropdown'ından config'i seç.
2. **Run** (▶) veya **Debug** (🐞). Debug breakpoint'leri direkt çalışır.
3. HSM senaryolarında ilk run öncesi config'i "Edit Configurations…" ile aç, `CERTIFICATE_PIN` env'inde `REPLACE_WITH_YOUR_PIN` yazısını **kendi PIN'inle** değiştir.

> **JDK ayarı**: IntelliJ "Project Structure → Project SDK" sekmesinden 8+ bir JDK seçtiğin sürece bu config'ler ek JRE path'i istemez. Repo Java 8 baseline ile build edilir.

---

## 3. VS Code (Java Extension Pack)

`.vscode/launch.json` aynı senaryoları VS Code Java debugger'ına maple eder.

### Run / Debug

1. **Run and Debug** panelini aç (`Ctrl+Shift+D` / `⇧⌘D`).
2. Üstteki dropdown'dan senaryoyu seç (örn. `Signer :: PFX EC-384 (KURUM02)`).
3. Yeşil ▶ butonuna bas — debugger attach edilir.

HSM senaryolarında `launch.json` içindeki `env.CERTIFICATE_PIN` field'ını kendi PIN'inle değiştir.

### Tasks

`.vscode/tasks.json` aşağıdaki Maven hedeflerini sağlar:

- **mvn test (unit)** — default test suite (`Ctrl+Shift+B` ile çağrılan default)
- **mvn test - XAdES SigningTime (issue 7)** — sadece SigningTime regression
- **mvn test - Verifier E2E (Docker)** — verifier-e2e tag'li
- **mvn spring-boot:run (local default)** — terminal'de Spring Boot başlatır

`Ctrl+Shift+P` → "Tasks: Run Task" ile çağrılır.

---

## 4. CLI (IDE'siz)

JDK + Maven kurulu makinede IDE açmadan koşmak için.

```bash
# Default (KURUM01 RSA), OS auto-detect
./scripts/dev-run.sh

# Diğer senaryolar
./scripts/dev-run.sh kurum02-ec384
./scripts/dev-run.sh kurum03-rsa2048

# Mali Mühür AKİS — OS'a göre doğru profile seçilir
CERTIFICATE_PIN=1234 ./scripts/dev-run.sh mali-muhur-akis

# Mevcut senaryoları listele
./scripts/dev-run.sh list
```

Windows:

```bat
REM Default
scripts\dev-run.bat

REM EC-P384
scripts\dev-run.bat kurum02-ec384

REM HSM (PIN env ile)
set CERTIFICATE_PIN=1234
scripts\dev-run.bat mali-muhur-akis
```

Script `OSTYPE` / `uname` ile OS tespiti yapar, `mvn` veya `./mvnw` arar; HSM senaryosunda PIN yoksa fail-fast davranır.

---

## 5. Sertifika Listeleme (Smoke Test)

Spring container kaldırmadan PFX'in sağlıklı olduğunu hızlıca doğrulamak için:

**IntelliJ**: `CLI · List PFX Certificates (KURUM01)` config'ini çalıştır.

**VS Code**: `CLI :: List PFX Certificates (KURUM01)` debug config'ini çalıştır.

**CLI (POSIX)**:

```bash
PFX_PATH=resources/test-certs/testkurum01_rsa2048@test.com.tr_614573.pfx \
CERTIFICATE_PIN=614573 \
mvn -q exec:java -Dexec.mainClass=io.mersel.dss.signer.api.SignatureApplication \
                  -Dexec.args="--list-certificates"
```

---

## 6. Sık Karşılaşılan Sorunlar

### "PFX dosyası bulunamadı"

PFX yolu **repo-relatif** (`resources/test-certs/...`). IDE Run Configuration `WORKING_DIRECTORY=$PROJECT_DIR$` koymuş; eğer dosya bulunamıyorsa çalışma dizini repo kökü değil demektir. `.run/*.run.xml` içindeki `WORKING_DIRECTORY` değerini kontrol et.

### HSM "token bulunamadı"

1. Kart fiziksel olarak takılı mı? (macOS: `pcsctest`, Linux: `pcsc_scan`, Windows: cihaz yöneticisi)
2. `PKCS11_LIBRARY` env'i doğru yolu gösteriyor mu? Profile dosyasındaki default'lar OS-spesifik ama operatör farklı kurulum yaptıysa env override gerekir.
3. macOS'ta AKİS sürücüsü `CKR_ARGUMENTS_BAD` veriyorsa `PKCS11_NULL_INIT_ARGS=true` zaten `application-mali-muhur-akis-mac.properties`'te aktif.

### "Active Profiles ekranda görünmüyor"

IntelliJ Spring Boot run config'inde "Active Profiles" alanı boşsa, "Edit Configurations…" → ilgili config'i seç → "Active Profiles" alanını kontrol et. Bu repo'daki configs `local,pfx-kurum01-rsa2048` formatında (virgülle ayrılmış) bekler.

### Production'a Sızma Endişesi

`local` profile **sadece** explicit aktivasyon ile yüklenir. Production deployment `java -jar` ile çalıştırıldığında `SPRING_PROFILES_ACTIVE` set edilmediği için bu dosyalar hiç parse edilmez. Test PFX'leri repo'da olmasına rağmen production env'ine taşınmaz; production'da HSM'den PIN gelir.

---

## 7. Yeni Senaryo Eklemek

1. Yeni `application-pfx-<key>.properties` veya `application-mali-muhur-<key>-<os>.properties` dosyasını oluştur.
2. `.run/` altına bir XML kopyala-yapıştır, `ACTIVE_PROFILES` değerini güncelle.
3. `.vscode/launch.json` array'ine yeni entry ekle.
4. `scripts/dev-run.sh` ve `dev-run.bat` `resolve_profile` switch'lerine ekle.
5. Bu dokümandaki tabloları güncelle.

> Tek bir kaynaktan profile metadata yönetmek istersek (örn. JSON), `dev-run.sh` o JSON'u tüketen bir templating'e geçirilebilir. Şu an 5 PFX + 3 HSM kombinasyonu için manuel düzen yeterli; sahnede daha fazla cert tipi çoğalırsa o yapıyı kurarız.
