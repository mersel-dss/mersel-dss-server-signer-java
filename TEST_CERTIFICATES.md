# 🔐 Test Sertifikaları Rehberi

Bu repo, hızlı başlatma ve test amaçlı 3 adet önceden yapılandırılmış PFX sertifikası içerir.

## ⚠️ ÖNEMLİ UYARI

**Bu test sertifikaları SADECE geliştirme ve test ortamları içindir.**

**❌ Production ortamında ASLA bu test sertifikalarını kullanmayın!**

Production için mutlaka resmi, güvenilir bir Certificate Authority (CA) tarafından imzalanmış sertifikalar kullanın.

## 📦 Hazır Test Sertifikaları

Repo içinde aşağıdaki test sertifikaları bulunmaktadır:

| Dosya Adı | Parola | Konum |
|-----------|--------|-------|
| `testkurum01@test.com.tr_614573.pfx` | `614573` | `resources/test-certs/` |
| `testkurum02@sm.gov.tr_059025.pfx` | `059025` | `resources/test-certs/` |
| `testkurum3@test.com.tr_181193.pfx` | `181193` | `resources/test-certs/` |

> **💡 Not:** Dosya isimlerinde alt tire (`_`) karakterinden sonraki kısım paroladır.

## 🚀 Hızlı Başlatma


### Yöntem 1: İnteraktif Script

**Unix/Linux/macOS:**
```bash
./scripts/unix/quick-start-with-test-certs.sh
```

**Windows (PowerShell):**
```powershell
.\scripts\windows\quick-start-with-test-certs.ps1
```

Bu script'ler:
- ✅ Sertifika seçimi yapmanızı sağlar
- ✅ Otomatik olarak environment variables'ları ayarlar
- ✅ İsteğe bağlı TÜBİTAK timestamp yapılandırması sunar
- ✅ Uygulamayı başlatır

### Yöntem 2: Manuel Başlatma

#### Test Sertifikası 1 ile:

```bash
export PFX_PATH=./resources/test-certs/testkurum01@test.com.tr_614573.pfx
export CERTIFICATE_PIN=614573
export CERTIFICATE_ALIAS=1
export IS_TUBITAK_TSP=false

mvn spring-boot:run
```

#### Test Sertifikası 2 ile:

```bash
export PFX_PATH=./resources/test-certs/testkurum02@sm.gov.tr_059025.pfx
export CERTIFICATE_PIN=059025
export CERTIFICATE_ALIAS=1
export IS_TUBITAK_TSP=false

mvn spring-boot:run
```

#### Test Sertifikası 3 ile:

```bash
export PFX_PATH=./resources/test-certs/testkurum3@test.com.tr_181193.pfx
export CERTIFICATE_PIN=181193
export CERTIFICATE_ALIAS=1
export IS_TUBITAK_TSP=false

mvn spring-boot:run
```

## 🧪 Test Etme

### Otomatik Test Script'i

Tüm API endpoint'lerini test etmek için:

```bash
# API'yi başlattıktan sonra
./scripts/test-with-bundled-certs.sh
```

Bu script şunları test eder:
- ✅ XAdES (Genel XML) imzalama
- ✅ XAdES (e-Fatura/UBL) imzalama
- ✅ PAdES (PDF) imzalama
- ✅ WS-Security (SOAP) imzalama
- ✅ Health check endpoint
- ✅ TÜBİTAK kontör sorgulama (eğer aktifse)

### Manuel Test Örnekleri

#### 1. Basit XML İmzalama

```bash
# Test XML oluştur
cat > test.xml << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<TestDocument>
  <Message>Merhaba Dünya</Message>
</TestDocument>
EOF

# İmzala
curl -X POST http://localhost:8085/v1/xadessign \
  -F "document=@test.xml" \
  -F "documentType=None" \
  -o signed-test.xml

# Sonucu görüntüle
cat signed-test.xml
```

#### 2. e-Fatura İmzalama

```bash
curl -X POST http://localhost:8085/v1/xadessign \
  -F "document=@efatura.xml" \
  -F "documentType=UblDocument" \
  -o signed-efatura.xml
```

#### 3. PDF İmzalama

```bash
curl -X POST http://localhost:8085/v1/padessign \
  -F "document=@document.pdf" \
  -F "appendMode=false" \
  -o signed-document.pdf
```

#### 4. SOAP İmzalama

```bash
curl -X POST http://localhost:8085/v1/wssecuritysign \
  -F "document=@soap-envelope.xml" \
  -F "soap1Dot2=false" \
  -o signed-soap.xml
```

## 🔍 Sertifika Bilgilerini Görüntüleme

Test sertifikaları hakkında detaylı bilgi almak için:

```bash
# Sertifika 1
keytool -list -v -keystore resources/test-certs/testkurum01@test.com.tr_614573.pfx \
  -storetype PKCS12 -storepass 614573

# Sertifika 2
keytool -list -v -keystore resources/test-certs/testkurum02@sm.gov.tr_059025.pfx \
  -storetype PKCS12 -storepass 059025

# Sertifika 3
keytool -list -v -keystore resources/test-certs/testkurum3@test.com.tr_181193.pfx \
  -storetype PKCS12 -storepass 181193
```

Veya daha basit:

```bash
./examples/find-certificate-info.sh pfx resources/test-certs/testkurum01@test.com.tr_614573.pfx 614573
```

## 📊 Farklı Sertifikalar ile Test

Aynı anda farklı sertifikalar kullanarak karşılaştırma yapmak için:

```bash
# Terminal 1 - Sertifika 1 ile
export PFX_PATH=./resources/test-certs/testkurum01@test.com.tr_614573.pfx
export CERTIFICATE_PIN=614573
export CERTIFICATE_ALIAS=1
export SERVER_PORT=8085
mvn spring-boot:run

# Terminal 2 - Sertifika 2 ile
export PFX_PATH=./resources/test-certs/testkurum02@sm.gov.tr_059025.pfx
export CERTIFICATE_PIN=059025
export CERTIFICATE_ALIAS=1
export SERVER_PORT=8086
mvn spring-boot:run

# Terminal 3 - Sertifika 3 ile
export PFX_PATH=./resources/test-certs/testkurum3@test.com.tr_181193.pfx
export CERTIFICATE_PIN=181193
export CERTIFICATE_ALIAS=1
export SERVER_PORT=8087
mvn spring-boot:run
```

## 🔄 Çoklu Sertifika Testi

Tüm sertifikalarla sırayla test yapmak için:

```bash
#!/bin/bash

for cert in 1 2 3; do
  case $cert in
    1)
      PFX="resources/test-certs/testkurum01@test.com.tr_614573.pfx"
      PIN="614573"
      ;;
    2)
      PFX="resources/test-certs/testkurum02@sm.gov.tr_059025.pfx"
      PIN="059025"
      ;;
    3)
      PFX="resources/test-certs/testkurum3@test.com.tr_181193.pfx"
      PIN="181193"
      ;;
  esac
  
  echo "🔐 Sertifika $cert ile test ediliyor: $PFX"
  
  export PFX_PATH="$PFX"
  export CERTIFICATE_PIN="$PIN"
  export CERTIFICATE_ALIAS=1
  export IS_TUBITAK_TSP=false
  
  # Uygulamayı başlat (arka planda)
  mvn spring-boot:run > /dev/null 2>&1 &
  APP_PID=$!
  
  # API'nin başlamasını bekle
  sleep 15
  
  # Test
  curl -X POST http://localhost:8085/v1/xadessign \
    -F "document=@test.xml" \
    -F "documentType=None" \
    -o "signed-with-cert${cert}.xml"
  
  # Uygulamayı durdur
  kill $APP_PID
  wait $APP_PID 2>/dev/null
  
  echo "✅ Sertifika $cert ile test tamamlandı"
  echo ""
  sleep 2
done

echo "🎉 Tüm testler tamamlandı!"
ls -lh signed-with-cert*.xml
```

## ⚠️ Önemli Notlar

### Test Sertifikaları Hakkında

1. **Sadece Test Amaçlı**: Bu sertifikalar **sadece geliştirme ve test** ortamları içindir
2. **Production'da Kullanmayın**: Gerçek imzalama işlemleri için resmi, güvenilir bir CA'dan sertifika alın
3. **Güvenlik**: Test sertifikalarının parolaları dosya isimlerinde açıkça görünmektedir
4. **Self-Signed**: Bu sertifikalar self-signed olup, güvenilir bir sertifika otoritesi tarafından imzalanmamıştır

### Timestamp Kullanımı

Test sertifikaları ile **TÜBİTAK timestamp kullanmanız önerilmez**:

```bash
# Test için timestamp devre dışı
export IS_TUBITAK_TSP=false
```

Timestamp testi için gerçek bir TÜBİTAK hesabı ve kontörü gereklidir.

### İmza Doğrulama

Test sertifikaları ile oluşturulan imzalar:
- ✅ Yapısal olarak geçerlidir
- ✅ İmza algoritmaları doğru çalışır
- ❌ Sertifika güven zinciri kontrolünde başarısız olabilir
- ❌ Resmi e-Fatura/e-Belge sistemlerinde kabul edilmez

## 🔄 Sertifika Değiştirme

Çalışan bir API'de sertifikayı değiştirmek için:

1. Uygulamayı durdurun (`Ctrl+C`)
2. Yeni environment variables ayarlayın
3. Uygulamayı yeniden başlatın

```bash
# Sertifikayı değiştir
export PFX_PATH=./resources/test-certs/testkurum02@sm.gov.tr_059025.pfx
export CERTIFICATE_PIN=059025
export CERTIFICATE_ALIAS=1

# Yeniden başlat
mvn spring-boot:run
```

## 🆚 Sertifika Karşılaştırması

| Özellik | Test Sertifikası 1 | Test Sertifikası 2 | Test Sertifikası 3 |
|---------|-------------------|--------------------|--------------------|
| Email | testkurum01@test.com.tr | testkurum02@sm.gov.tr | testkurum3@test.com.tr |
| Parola | 614573 | 059025 | 181193 |
| Kullanım | Test Kurum 1 | Test Kurum 2 (Kamu) | Test Kurum 3 |
| Dosya Boyutu | ~1.5 KB | ~1.5 KB | ~1.5 KB |

## 📚 İlgili Dökümanlar

- [Hızlı Başlangıç](https://dss.mersel.dev/getting-started/quick-start) - Genel hızlı başlangıç rehberi
- [Ana Dokümantasyon](https://dss.mersel.dev) - Merkezi dokümantasyon
- [Sertifika Seçimi](https://dss.mersel.dev/sign-api/certificate-selection) - Sertifika seçimi
- [SECURITY.md](SECURITY.md) - Güvenlik en iyi uygulamaları
- [examples/README.md](examples/README.md) - Kullanım örnekleri

## 🔍 API Sağlık Kontrolü

API'nin çalışıp çalışmadığını kontrol etmek için:

```bash
# Sağlık kontrolü
curl http://localhost:8085/actuator/health

# Başarılı yanıt:
# {"status":"UP"}

# Uygulama bilgileri
curl http://localhost:8085/actuator/info
```

## 💡 İpuçları

### Hızlı Test Döngüsü

```bash
# 1. API'yi başlat
./scripts/quick-start-with-test-certs.sh

# 2. Başka bir terminalde test et
./scripts/test-with-bundled-certs.sh

# 3. Sonuçları incele
ls -lh /tmp/*/signed-*
```

### Hata Ayıklama

Test sırasında sorun yaşarsanız:

```bash
# Environment variables'ları kontrol et
env | grep -E "PFX|CERTIFICATE|TUBITAK"

# Sertifika dosyasını kontrol et
file $PFX_PATH
ls -lh $PFX_PATH

# Log'ları takip et
tail -f logs/application.log
```

### Clean Start

Tüm cache ve log'ları temizleyerek baştan başlamak için:

```bash
# Maven temizle
mvn clean

# Log'ları temizle
rm -f logs/*.log

# Yeniden başlat
./scripts/quick-start-with-test-certs.sh
```

## 🤝 Katkıda Bulunma

Yeni test sertifikaları veya test script'leri eklemek için:

1. Sertifikayı `resources/` klasörüne ekleyin
2. Bu dökümanı güncelleyin
3. Test script'lerini güncelleyin
4. Pull request gönderin

## 📞 Destek

Sorun yaşıyorsanız:

1. **Dokümantasyonu kontrol edin**: [README.md](README.md)
2. **Log'lara bakın**: `logs/error.log`
3. **Test script'ini çalıştırın**: `./scripts/test-with-bundled-certs.sh`
4. **Issue açın**: [GitHub Issues](https://github.com/mersel-dss/mersel-dss-server-signer-java/issues)

---

**Keyifli testler! 🧪🔐**

