# 🔐 Sign API

Türkiye e-imza standartlarına uygun elektronik imza (XAdES, PAdES, WS-Security) servisi.

[![Java](https://img.shields.io/badge/Java-8+-orange.svg)](https://www.oracle.com/java/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-2.7-green.svg)](https://spring.io/projects/spring-boot)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![DSS](https://img.shields.io/badge/DSS-6.3-blue.svg)](https://github.com/esig/dss)
[![Version](https://img.shields.io/badge/version-0.1.0-brightgreen.svg)](https://github.com/mersel-dss/mersel-dss-server-signer-java/releases)
[![Tests](https://img.shields.io/badge/tests-22%20passed-success.svg)](https://dss.mersel.dev/sign-api/testing)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

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
export PFX_PATH=./resources/test-certs/testkurum01@test.com.tr_614573.pfx
export CERTIFICATE_PIN=614573
mvn spring-boot:run
```

**API:** http://localhost:8085  
**Docs:** http://localhost:8085/ (Scalar UI)  
**Health:** http://localhost:8085/actuator/health

---

## 🎯 Özellikler

- ✅ **XAdES**: e-Fatura, e-Arşiv, XML imzalama
- ✅ **PAdES**: PDF dijital imzalama
- ✅ **WS-Security**: SOAP imzalama
- ✅ **Timestamp**: RFC 3161 (TÜBİTAK ESYA desteği)
- ✅ **HSM/PKCS#11**: Donanım güvenlik modülü
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
├── src/main/java/          # Java kaynak kodları
├── devops/                 # Docker, K8s, monitoring
├── scripts/                # Yardımcı scriptler
├── resources/test-certs/   # Test sertifikaları
└── examples/               # Kullanım örnekleri
```

---

## 🔗 Önemli Bağlantılar

| Dosya | Açıklama |
|-------|----------|
| [**dss.mersel.dev**](https://dss.mersel.dev) | 📚 **Merkezi Dökümantasyon** |
| [LICENSE](LICENSE) | MIT Lisansı |
| [CHANGELOG.md](CHANGELOG.md) | Versiyon geçmişi |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Katkıda bulunma rehberi |
| [SECURITY.md](SECURITY.md) | Güvenlik politikası |
| [TEST_CERTIFICATES.md](TEST_CERTIFICATES.md) | Test sertifikaları |
| [DSS_OVERRIDE.md](DSS_OVERRIDE.md) | DSS özelleştirmeleri |

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
