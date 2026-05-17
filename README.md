# 🔐 Sign API

Türkiye e-imza standartlarına uygun elektronik imza (XAdES, PAdES, WS-Security) servisi.

[![CI](https://github.com/mersel-dss/mersel-dss-server-signer-java/actions/workflows/ci.yml/badge.svg)](https://github.com/mersel-dss/mersel-dss-server-signer-java/actions/workflows/ci.yml)
[![Integration Tests](https://github.com/mersel-dss/mersel-dss-server-signer-java/actions/workflows/integration-tests.yml/badge.svg)](https://github.com/mersel-dss/mersel-dss-server-signer-java/actions/workflows/integration-tests.yml)
[![Publish Evidence Pages](https://github.com/mersel-dss/mersel-dss-server-signer-java/actions/workflows/publish-pages.yml/badge.svg)](https://github.com/mersel-dss/mersel-dss-server-signer-java/actions/workflows/publish-pages.yml)

**📊 Kanıt-temelli test merkezi: [Evidence Site →](https://mersel-dss.github.io/mersel-dss-server-signer-java/)**
&nbsp;&nbsp;·&nbsp;&nbsp; 290+ E2E test (XAdES/CAdES/PAdES/WS-Security) · Her imzalı dosyanın yanında `mersel-verifier-api` doğrulama yanıtı · JaCoCo coverage · OpenAPI · OWASP Dependency-Check raporları her main push'unda otomatik yayımlanır.

> **Local preview** — Pages'e push edilenin birebir aynısını kendi makinende görmek için:
>
> ```bash
> ./scripts/serve-pages-locally.sh --fast       # unit testler + Allure + JaCoCo + landing (≈ 2 dk)
> ./scripts/serve-pages-locally.sh              # tam koşum (unit + E2E + OWASP + OpenAPI snapshot)
> ./scripts/serve-pages-locally.sh --skip-tests # mevcut target/'i kullan (en hızlı sanity)
> ```
>
> Script `pages-output/` klasörünü üretir ve `http://localhost:8765/`'te serve eder (Allure, JaCoCo,
> Scalar API Reference, OWASP — hepsi tek tarayıcı sekmesinde). Detaylı flag listesi için `--help`.

[Java](https://www.oracle.com/java/)
[Spring Boot](https://spring.io/projects/spring-boot)
[License](LICENSE)
[DSS](https://github.com/esig/dss)
[Version](https://github.com/mersel-dss/mersel-dss-server-signer-java/releases)
[Tests](https://dss.mersel.dev/sign-api/testing)
[GHCR](https://github.com/mersel-dss/mersel-dss-server-signer-java/pkgs/container/mersel-dss-server-signer-java)
[PRs Welcome](CONTRIBUTING.md)

---

## 🙌 Katkıda Bulunanlar

Bu projeye emek veren herkese içtenlikle teşekkür ederiz. Kod katkısı yapan, önerileriyle geliştirmeye yön veren veya hataları fark edip bildiren herkes, projenin bugün olduğu noktaya gelmesinde önemli bir paya sahip.

Aynı şekilde, geliştirme sürecinde destek sunan kurumlara da ayrıca teşekkür ederiz.Birlikte hareket etmenin, bilgiyi paylaşmanın ve ortak bir değeri büyütmenin kıymetini çok iyi biliyoruz.

Açık kaynağın gücüne inanıyor ve birlikte daha iyisini üretmeye devam ediyoruz. 🚀

### Bireysel Katkı Sahipleri


| Katkıda Bulunan                                  | Kurum                                                |
| ------------------------------------------------ | ---------------------------------------------------- |
| [@hasanyildiz](https://github.com/hasanyildiz)   | İZİBİZ Bilişim Teknolojileri Anonim Şirketi          |
| [@emresimsk](https://github.com/emresimsk)       | IDECON DANIŞMANLIK HİZMETLERİ ANONİM ŞİRKETİ         |
| [@Burak-Attila](https://github.com/Burak-Attila) | EDM Bilişim                                          |
| [@batuhanonerr](https://github.com/batuhanonerr) | NİLVERA YAZILIM VE BİLİŞİM HİZMETLERİ TİC. LTD. ŞTİ. |
| [@ozlemkzn](https://github.com/ozlemkzn)         | e-Platform Bulut Bilişim A.Ş.                        |


### Kurumsal Destekçiler


| Kurum      | Katkı Türü         |
| ---------- | ------------------ |
| İzibiz     | Geliştirme desteği |
| İdecon     | Geliştirme desteği |
| EDM        | Geliştirme desteği |
| NİLVERA    | Geliştirme desteği |
| e-Platform | Geliştirme desteği |


### Öne Çıkan Pull Request / Issue Katkıları


| Tür | Referans                                                                   | Açıklama                                                      | Katkıda Bulunan                                  |
| --- | -------------------------------------------------------------------------- | ------------------------------------------------------------- | ------------------------------------------------ |
| PR  | [#3](https://github.com/mersel-dss/mersel-dss-server-signer-java/pull/3)   | TÜBİTAK XAdES için ECDSA doğrulama özelleştirmeleri           | [@hasanyildiz](https://github.com/hasanyildiz)   |
| PR  | [#6](https://github.com/mersel-dss/mersel-dss-server-signer-java/pull/6)   | PKCS#11 `slot` ve `slotListIndex` yapılandırması geliştirmesi | [@hasanyildiz](https://github.com/hasanyildiz)   |
| PR  | [#8](https://github.com/mersel-dss/mersel-dss-server-signer-java/pull/8)   | WS-Security imzalama düzeltmesi                               | [@batuhanonerr](https://github.com/batuhanonerr) |
| PR  | [#10](https://github.com/mersel-dss/mersel-dss-server-signer-java/pull/10) | UBLExtensions eksik element oluşturma düzeltmesi              | [@batuhanonerr](https://github.com/batuhanonerr) |
| PR  | [#11](https://github.com/mersel-dss/mersel-dss-server-signer-java/pull/11) | CAdES-BES imzalama desteği                                    | [@Burak-Attila](https://github.com/Burak-Attila) |
| PR  | [#12](https://github.com/mersel-dss/mersel-dss-server-signer-java/pull/12) | e-Bilet rapor tipi ve XAdES-A desteği                         | [@ozlemkzn](https://github.com/ozlemkzn)         |


---

## 📚 Tam Dökümantasyon

### 👉 [Sign Platform Dökümanları](https://dss.mersel.dev) 👈

**Tüm detaylı dökümantasyon merkezi dökümantasyon sitesinde bulunur:**

- 📖 Kurulum ve yapılandırma
- 🚀 Hızlı başlangıç kılavuzu
- 🔐 Sertifika yönetimi ve seçimi
- ⚙️ Docker ve Kubernetes deployment
- 📊 Monitoring ve performance tuning
- ⏰ Zaman damgası servisi
- 🇹🇷 TÜBİTAK entegrasyonu
- 💡 Kod örnekleri ve kullanım senaryoları
- 🔧 DSS override detayları
- 🧪 Test stratejileri
- 🔒 Güvenlik en iyi pratikleri

---

## ⚡ Hızlı Başlangıç

### Test Sertifikası ile (5 Dakika)

**Unix/Linux/macOS:**

```bash
./scripts/unix/quick-start-with-test-certs.sh
```

**Windows:**

```powershell
.\scripts\windows\quick-start-with-test-certs.ps1
```

### Docker ile

```bash
cd devops/docker
docker-compose up -d
```

### Manuel

```bash
mvn spring-boot:run
```

> Tek komut yeter. `spring-boot-maven-plugin` otomatik olarak `local`
> profile'ını aktif eder → [`application-local.properties`](src/main/resources/application-local.properties)
> yüklenir → repo'daki test PFX (`resources/test-certs/testkurum01_rsa2048@...`)
> + dummy PIN ile uygulama anında ayağa kalkar. **Production'a sızmaz**: jar
> doğrudan `java -jar` ile başlatıldığında bu profile aktif olmaz, prod-grade
> env variable'lar (`PFX_PATH`, `CERTIFICATE_PIN`, vb.) zorunlu kalır.

Profile'sız (kendi PFX'inizle) çalıştırmak isterseniz:

```bash
export PFX_PATH=/path/to/your.pfx
export CERTIFICATE_PIN=your-pin
mvn spring-boot:run -Dspring-boot.run.profiles=
```

- **API:** [http://localhost:8085](http://localhost:8085)
- **Docs:** [http://localhost:8085/](http://localhost:8085/) (Scalar UI)
- **Health:** [http://localhost:8085/actuator/health](http://localhost:8085/actuator/health)

---

## 🎯 Özellikler

- ✅ **XAdES**: e-Fatura, e-Arşiv, XML imzalama
- ✅ **CAdES**: CMS tabanlı elektronik imzalama (CAdES-BES)
- ✅ **PAdES**: PDF dijital imzalama
- ✅ **WS-Security**: SOAP imzalama
- ✅ **Timestamp**: RFC 3161 (TÜBİTAK ESYA desteği)
- ✅ **HSM/PKCS#11**: Donanım güvenlik modülü
- ✅ **KamuSM Root Sertifika Desteği** - Online ve Offline mod desteği
  - **Online Mod**: Otomatik olarak [http://depo.kamusm.gov.tr/depo/SertifikaDeposu.xml](http://depo.kamusm.gov.tr/depo/SertifikaDeposu.xml) adresinden yüklenir
  - **Offline Mod**: Yerel dosya sisteminden belirtilen path'ten yüklenir
- ✅ **Production Ready**: Monitoring, logging, metrics

---

## 📖 Örnek Kullanım

```bash
# e-Fatura imzalama
curl -X POST http://localhost:8085/v1/xadessign \
  -F "document=@efatura.xml" \
  -F "documentType=UblDocument" \
  -o signed-efatura.xml

# PDF imzalama
curl -X POST http://localhost:8085/v1/padessign \
  -F "document=@document.pdf" \
  -o signed.pdf
```

**Daha fazla örnek:** [Örnekler](https://dss.mersel.dev/examples)

---

## 🛠️ Gereksinimler

- Java 8+
- Maven 3.6+
- PFX sertifikası veya HSM

---

## 📂 Proje Yapısı

```
sign-api/
├── src/main/java/              # Java kaynak kodları
├── devops/                     # Docker, K8s, monitoring
├── scripts/                    # Yardımcı scriptler
├── resources/test-certs/       # Test sertifikaları (PFX)
├── resources/test-fixtures/    # E2E fixture'lar (XAdES, WS-Security)
└── examples/                   # Kullanım örnekleri
```

---

## 🧪 Testler

```bash
# Hızlı: 270+ unit/servis testi (ek kurulum yok)
mvn test
```

İki ek **integration** test grubu da var; default `mvn test`'te dışlanır.

### `verifier-e2e` — DSS Verifier API roundtrip

CAdES/PAdES/XAdES imzala → Testcontainers ile ayağa kalkan verifier API'ye gönder → `TOTAL_PASSED` bekle. **Gereksinim:** Docker daemon.

```bash
mvn test -Dgroups=verifier-e2e -DexcludedGroups=
```

### `pkcs11-integration` — Gerçek SoftHSM2 + IAIK PKCS#11

Her PFX test sertifikası gerçek bir SoftHSM2 token'a yüklenir; IAIK wrapper üzerinden `C_Sign` çağrılır. Üst seviye `XadesSoftHsmVerifierE2ETest` ayrıca verifier API ile uçtan-uca doğrular (5 PFX × 5 XAdES belge = 25 senaryo).

#### Yol 1 — Sıfır kurulum (önerilen)

Sadece Docker yeter; native bağımlılıklar container içindedir.

```bash
./scripts/run-pkcs11-tests.sh
```

İlk koşumda ~600MB image build edilir, sonra layer-cached. macOS / Linux / WSL2 üzerinde **bit-for-bit aynı ortam**, CI runner'ı ile de aynı.

#### Yol 2 — Host'a native kur (IDE'den koşturmak istiyorsan)


| Platform            | Kurulum                                                                                          |
| ------------------- | ------------------------------------------------------------------------------------------------ |
| **macOS**           | `brew install softhsm opensc` (+ Apple Silicon ise arm64 JDK 8: `sdk install java 8.0.492-zulu`) |
| **Ubuntu / Debian** | `sudo apt-get install -y softhsm2 opensc`                                                        |
| **Fedora / RHEL**   | `sudo dnf install -y softhsm opensc`                                                             |
| **Windows**         | WSL2 + yukarıdaki Ubuntu komutu (Windows native desteklenmiyor)                                  |


```bash
mvn test -Dgroups=pkcs11-integration -DexcludedGroups=
```

> Native araç bulunamazsa testler **sessizce atlanır** (build kırılmaz). CI'da (`.github/workflows/integration-tests.yml`) her PR'da otomatik koşar; eksik araç durumunda CI workflow'u açıkça fail eder.

---

## ⚙️ Konfigürasyon

### Güvenilir Kök Sertifika Resolver Kullanımı

Sistem üç farklı resolver tipini destekler. `TRUSTED_ROOT_RESOLVER_TYPE` parametresi ile seçim yapılır.

#### 1. KamuSM XML Depo Online (Varsayılan)

Varsayılan olarak, KamuSM root ve ara sertifikaları **otomatik** olarak şu adresten yüklenir:

- [http://depo.kamusm.gov.tr/depo/SertifikaDeposu.xml](http://depo.kamusm.gov.tr/depo/SertifikaDeposu.xml)

Bu sayede her zaman güncel sertifikalar kullanılır. Periyodik olarak otomatik yenilenir (varsayılan: her gün saat 03:15).

```bash
export TRUSTED_ROOT_RESOLVER_TYPE=kamusm-online
export KAMUSM_ROOT_URL=http://depo.kamusm.gov.tr/depo/SertifikaDeposu.xml
export KAMUSM_ROOT_REFRESH_CRON="0 15 3 * * *"  # Her gün saat 03:15
```

#### 2. KamuSM XML Depo Offline

Offline ortamlarda veya internet bağlantısı olmayan sistemlerde, KamuSM sertifika deposunu yerel dosya sisteminden yükleyebilirsiniz:

```bash
export TRUSTED_ROOT_RESOLVER_TYPE=kamusm-offline
export KAMUSM_ROOT_OFFLINE_PATH=file:/path/to/SertifikaDeposu.xml
# veya classpath'ten
export KAMUSM_ROOT_OFFLINE_PATH=classpath:certs/SertifikaDeposu.xml
```

**Offline Mod Kullanım Senaryoları:**

- Air-gapped (izole) sistemler
- İnternet bağlantısı olmayan ortamlar
- Güvenlik gereksinimleri nedeniyle dış bağlantı kısıtlamaları
- Yerel sertifika deposu kullanımı

**Not:** Offline modda sertifikalar sadece uygulama başlangıcında yüklenir. Otomatik yenileme yapılmaz.

#### 3. Certificate Folder Resolver

Belirtilen klasördeki tüm `.crt`, `.cer` ve `.pem` dosyalarını güvenilir kök sertifika olarak yükler. Bu resolver, özel sertifika klasörlerinden sertifika yüklemek için idealdir.

```bash
export TRUSTED_ROOT_RESOLVER_TYPE=certificate-folder
export TRUSTED_ROOT_CERT_FOLDER_PATH=/path/to/certificates
# veya file: prefix ile
export TRUSTED_ROOT_CERT_FOLDER_PATH=file:/path/to/certificates
```

**Certificate Folder Resolver Kullanım Senaryoları:**

- Özel sertifika klasörlerinden yükleme
- Kurumsal CA sertifikalarının toplu yüklenmesi
- Test ortamlarında özel sertifika kullanımı
- Farklı kaynaklardan sertifika birleştirme

**Not:** Klasördeki tüm geçerli sertifika dosyaları otomatik olarak yüklenir. Alt klasörler taranmaz.

---

## 🔗 Önemli Bağlantılar


| Dosya                                        | Açıklama                     |
| -------------------------------------------- | ---------------------------- |
| **[dss.mersel.dev](https://dss.mersel.dev)** | 📚 **Merkezi Dökümantasyon** |
| [LICENSE](LICENSE)                           | MIT Lisansı                  |
| [CHANGELOG.md](CHANGELOG.md)                 | Versiyon geçmişi             |
| [CONTRIBUTING.md](CONTRIBUTING.md)           | Katkıda bulunma rehberi      |
| [SECURITY.md](SECURITY.md)                   | Güvenlik politikası          |
| [TEST_CERTIFICATES.md](TEST_CERTIFICATES.md) | Test sertifikaları           |
| [DSS_OVERRIDE.md](DSS_OVERRIDE.md)           | DSS özelleştirmeleri         |


---

## 🤝 Katkıda Bulunma

[CONTRIBUTING.md](CONTRIBUTING.md) dosyasına bakın.

---

## 📄 Lisans

[MIT](LICENSE)

---

## 💡 Hatırlatma

**Detaylı dökümantasyon, API referansları, deployment rehberleri ve tüm güncellemeler için:**

### 👉 [https://dss.mersel.dev](https://dss.mersel.dev) merkezi dökümantasyon sitesini ziyaret edin! 📚
