# Changelog

Tüm önemli değişiklikler bu dosyada dokümante edilmektedir.

Format [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) standardına dayanmaktadır,
ve bu proje [Semantic Versioning](https://semver.org/spec/v2.0.0.html) kullanmaktadır.

## [Unreleased]

### Added
- 🎫 **e-Bilet Rapor Desteği** (PR [#12](https://github.com/mersel-dss/mersel-dss-server-signer-java/pull/12)) - Katkıcı: [@ozlemkzn](https://github.com/ozlemkzn) / e-Platform Bulut Bilişim A.Ş.
- 🧪 **Yeni Test Coverage** - 22 yeni test (toplam: 115)
- 🐳 **GHCR Desteği** - Docker Hub + GHCR'e tek workflow'dan paralel push
- 📦 **Docker Image İçinde 5 Test Sertifikası** - Runtime'da `-e` ile değiştirilebilir

### Changed
- 🔄 **GitHub Actions Konsolidasyonu** - 3 workflow → 2 workflow, sıfır çakışma
- ⬆️ **Actions v3 → v4** - Deprecated action hataları giderildi
- 🐳 **Dockerfile** - Mevcut test sertifikaları image'a gömüldü, varsayılan ENV'ler eklendi

### Fixed
- 🐛 **XAdES-A Yükseltme Hatası** - e-Bilet raporları XAdES-B'de kalıyordu
- 🔧 **CI Workflow** - `actions/upload-artifact@v3` deprecated hatası

---

## [0.3.0] - 2026-03-11

### Added
- 🎫 **e-Bilet Rapor İmzalama** (PR [#12](https://github.com/mersel-dss/mersel-dss-server-signer-java/pull/12))
  - `EBiletReport` document type (`DocumentType` enum)
  - `NS_BILET` XML namespace sabiti (`XmlConstants`)
  - e-Bilet rapor belgelerinde `baslik` elemanı altına imza yerleştirme (`XAdESDocumentPlacementService`)
  - e-Bilet raporları için XAdES-A seviyesine yükseltme
  - e-Bilet imzalama sonrası OCSP cache temizliği
  - Katkıcı: [@ozlemkzn](https://github.com/ozlemkzn) / e-Platform Bulut Bilişim A.Ş.

- 🧪 **Test Coverage Artışı** - 22 yeni test eklendi (93 → 115)
  - `XAdESDocumentPlacementServiceTest` - e-Bilet, e-Arşiv, UBL ve OtherXml belge yerleştirme testleri
  - `XAdESLevelUpgradeServiceTest` - XAdES-A yükseltme/atlama ve timestamp servis testleri
  - `XadesControllerTest` - e-Bilet document type controller testleri

- 🐳 **GHCR (GitHub Container Registry) Desteği**
  - `ghcr.io/mersel-dss/mersel-dss-server-signer-java:latest`
  - Multi-platform: `linux/amd64`, `linux/arm64`
  - Smoke test: container başlatılıp health check doğrulanıyor
  - Docker Hub ve GHCR'e tek workflow'dan paralel push

- 📦 **Docker Image İçinde Test Sertifikaları** - Hazır kullanıma uygun 5 sertifika
  - `testkurum01_rsa2048@test.com.tr` (RSA-2048, parola: 614573) - **varsayılan**
  - `testkurum02_ec384@test.com.tr` (EC-384, parola: 825095)
  - `testkurum02_rsa2048@sm.gov.tr` (RSA-2048, parola: 059025)
  - `testkurum03_ec384@test.com.tr` (EC-384, parola: 540425)
  - `testkurum03_rsa2048@test.com.tr` (RSA-2048, parola: 181193)
  - Güvenilir köklere (KamuSM) uyumlu, zincir doğrulaması çalışıyor
  - `docker run -e PFX_PATH=... -e CERTIFICATE_PIN=... -e CERTIFICATE_ALIAS=...` ile runtime'da değiştirilebilir

### Changed
- 🔄 **GitHub Actions Workflow Konsolidasyonu** - 3 workflow → 2 workflow, sıfır çakışma
  - `ci.yml`: PR ve develop branch'te çalışır (build + test + code quality)
  - `docker.yml`: main push ve tag'lerde çalışır (test → Docker Hub + GHCR push + smoke test)
  - Eski workflow'lar silindi: `docker-publish.yml`, `ghcr-publish.yml`
  - Her push'ta 3x build+test yerine 1x çalışıyor
- ⬆️ **GitHub Actions Versiyon Güncellemeleri**
  - `actions/checkout@v3` → `@v4`
  - `actions/setup-java@v3` → `@v4`
  - `actions/upload-artifact@v3` → `@v4`
  - `mvn validate -B` adımı eklendi (lokal bağımlılık kurulumu)
- 🐳 **Dockerfile Güncellendi** - Test sertifikaları ile production-ready
  - Mevcut test sertifikaları image'a gömülüyor (`/app/test-certs/`)
  - Varsayılan ENV'ler: `PFX_PATH`, `CERTIFICATE_PIN=614573`, `CERTIFICATE_ALIAS=1`

### Fixed
- 🐛 **XAdES-A Yükseltme Hatası** - e-Bilet raporları için XAdES-A yükseltme yapılmıyordu
  - `XAdESLevelUpgradeService`: `EBiletReport` document type eksikti, XAdES-B'de kalıyordu
  - OCSP cache temizliği çalışıyor ama yükseltme atlanıyordu (tutarsızlık)
  - Log mesajları dinamik hale getirildi (document type bilgisi)
- 🔧 **CI Workflow Hatası** - `actions/upload-artifact@v3` deprecated olduğu için build başarısız oluyordu

---

## [0.2.1] - 2026-03-03

### Added
- 🔏 **CAdES İmza Desteği** (PR [#11](https://github.com/mersel-dss/mersel-dss-server-signer-java/pull/11))
  - DSS kütüphanesi ile CAdES-BES imzalama
  - Katkıcı: [@Burak-Attila](https://github.com/Burak-Attila)

---

## [0.2.0] - 2026-03-02

### Fixed
- 🐛 **UBLExtensions Hiyerarşisi** (PR [#10](https://github.com/mersel-dss/mersel-dss-server-signer-java/pull/10))
  - Eksik `UBLExtensions/UBLExtension/ExtensionContent` hiyerarşisi otomatik oluşturuluyor
  - Kısmi UBLExtensions yapısı graceful olarak handle ediliyor
  - Import'lar ve hata yönetimi iyileştirildi
  - Katkıcı: [@batuhanonerr](https://github.com/batuhanonerr)

---

## [0.1.5] - 2026-02-19

### Changed
- 🔧 **Kriptografik İyileştirmeler** - İmza işleme ve şifreleme fonksiyonelliği geliştirildi

### Fixed
- 🐛 **UBLExtensions Auto-Create** - Eksik `UBLExtensions/UBLExtension/ExtensionContent` yapısı otomatik oluşturuluyor

---

## [0.1.4] - 2026-02-04

### Fixed
- 🐛 **WS-Security signDocument** (PR [#8](https://github.com/mersel-dss/mersel-dss-server-signer-java/pull/8))
  - WS-Security imzalama hatası düzeltildi
  - Katkıcı: [@batuhanonerr](https://github.com/batuhanonerr)
- 🐛 **Zip Okuma Problemi** - Zip dosyalarının okunmasındaki hata giderildi

---

## [0.1.3] - 2025-11-16

### Added
- 🔌 **PKCS#11 Slot Yapılandırması** (PR [#6](https://github.com/mersel-dss/mersel-dss-server-signer-java/pull/6))
  - `PKCS11_SLOT` ve `PKCS11_SLOT_LIST_INDEX` parametreleri ayrı ayrı kullanılabilir
  - Katkıcı: [@hasanyildiz](https://github.com/hasanyildiz)

---

## [0.1.2] - 2025-11-13

### Fixed
- 🐛 **TÜBİTAK ECDSA Doğrulama** (PR [#3](https://github.com/mersel-dss/mersel-dss-server-signer-java/pull/3))
  - TÜBİTAK XAdES için ECDSA doğrulama iyileştirmeleri
  - TÜBİTAK customization for XAdES BES signature
  - Katkıcı: [@hasanyildiz](https://github.com/hasanyildiz)

---

## [0.1.1] - 2025-11-10

### Added
- ⏰ **RFC 3161 Zaman Damgası Servisi**
  - `POST /api/timestamp/get` - RFC 3161 uyumlu timestamp
  - `POST /api/timestamp/validate` - Timestamp doğrulama
  - `GET /api/timestamp/status` - TSP sunucu durumu
  - `TimestampStatusDto` eklendi
  - TÜBİTAK ESYA, KAMUSM ve standart TSP sunucuları desteği
  - 22 unit test (TimestampServiceTest + TimestampControllerTest)

- 🔧 **Güvenilir Kök Sertifika Resolver Sistemi**
  - **KamuSM XML Depo Online Resolver**: İnternet üzerinden otomatik indirme ve periyodik güncelleme
  - **KamuSM XML Depo Offline Resolver**: Air-gapped sistemler için yerel dosya
  - **Certificate Folder Resolver**: Klasördeki .crt/.cer/.pem dosyalarını yükleme
  - `trusted.root.resolver.type=kamusm-online|kamusm-offline|certificate-folder`

- 🔐 **Sertifika Listeleme API'si**
  - `GET /api/certificates/list` - Keystore'daki tüm sertifikaları listele
  - `GET /api/certificates/info` - Keystore tipi ve parametreleri
  - `--list-certificates` CLI argümanı (Spring context olmadan)
  - OID, Key Usage, Extended Key Usage, Certificate Policies bilgileri

- 🎨 **Scalar API Documentation** - Swagger UI yerine modern Scalar arayüzü

- 📊 **Prometheus Metrics Export**
  - `/actuator/prometheus` - 40+ metrik
  - HTTP, JVM, System, Tomcat metrikleri
  - Percentile histogram (p50, p95, p99)

- 🔍 **Spring Boot Actuator**
  - `/actuator/health`, `/actuator/info`
  - Kubernetes liveness/readiness probe desteği

### Changed
- 🌐 **CORS** - Timestamp ve signature header'ları exposed headers'a eklendi
- 🔧 **Sertifika Yapılandırması** - `CERTIFICATE_ALIAS` ve `CERTIFICATE_SERIAL_NUMBER` opsiyonel
- 🎯 **SignatureApplication** - `--list-certificates`, `--help`, `--version` CLI argümanları

### Fixed
- 🐛 CI workflow ve test hataları düzeltildi
- 🐛 Docker publish workflow düzeltildi

---

## [0.1.0] - 2025-11-07

### 🎉 İlk Public Release

#### Added
- 🐳 **Docker & Docker Compose Desteği**
  - Multi-stage Dockerfile (Maven build + Eclipse Temurin 8 JRE)
  - docker-compose.yml ile Prometheus + Grafana monitoring stack
  - Non-root user, built-in health check, ~250MB image
- 🖥️ **Cross-Platform Script Desteği**
  - Unix/Linux/macOS bash script'leri (`scripts/unix/`)
  - Windows PowerShell script'leri (`scripts/windows/`)
  - Docker helper script'leri (test kurum başlatma)
- 📂 **DevOps Organizasyonu** - `devops/docker/`, `devops/monitoring/`, `devops/kubernetes/`
- 🚀 **Hızlı Başlatma Script'leri** - Test sertifikaları ile tek komutla başlatma
- 🔐 **Test Sertifikaları** - 3 adet test PFX (`resources/test-certs/`)
- 📚 **Kapsamlı Dokümantasyon** - MONITORING.md, ACTUATOR_ENDPOINTS.md, CERTIFICATE_SELECTION.md
- 📝 **SECURITY.md** - Güvenlik politikası ve best practices
- 🔒 **CORS Yapılandırması** - Güvenli cross-origin resource sharing
- 🛡️ **Security Headers** - XSS, Clickjacking koruması
- 📊 **Performance Guide** - JVM tuning rehberi (docs/PERFORMANCE.md)
- 🧪 **Unit Testler** - Temel servis ve controller testleri
- 📋 **CHANGELOG.md** - Versiyon geçmişi takibi

#### Changed
- ♻️ **Log Yönetimi** - logback-spring.xml, rolling file appenders, ayrı error.log/signature.log
- 📦 **Dependency Güncellemeleri** (JDK 1.8 uyumlu)
  - Spring Boot: 2.3.7 → 2.7.18
  - Jackson: 2.11.2 → 2.15.3
  - BouncyCastle: 1.50 → 1.70
  - Apache HttpClient: 4.5.10 → 4.5.14
  - SpringDoc OpenAPI: 1.4.8 → 1.7.0
  - Sentry: 4.1.0 → 6.34.0

#### Fixed
- 🐛 Log dosyalarının ana dizinde oluşması sorunu
- 📝 application.properties syntax düzeltmeleri
- 🔧 Maven compiler encoding yapılandırması

---

## [0.0.1] - 2025-10-XX

### İlk İç Versiyon
- ✅ XAdES imzalama (e-Fatura, e-Arşiv, e-İrsaliye)
- ✅ PAdES imzalama
- ✅ WS-Security imzalama
- ✅ TÜBİTAK timestamp entegrasyonu
- ✅ HSM (PKCS#11) desteği
- ✅ DSS kütüphanesi custom override'ları
- ✅ OCSP/CRL cache mekanizması
- ✅ KamuSM root sertifikası desteği

---

## Gelecek Sürümler

### v0.4.0 (Planlanan)
- Kubernetes manifests
- Rate limiting
- API Authentication
- Asenkron imzalama
- Batch imzalama

### v0.5.0 (Planlanan)
- WebSocket bildirimler
- Kafka/RabbitMQ entegrasyonu
- Dashboard UI
