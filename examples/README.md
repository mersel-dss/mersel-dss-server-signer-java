# Örnek Kullanımlar

Bu dizinde Sign API'yi farklı şekillerde kullanmak için örnekler bulunmaktadır.

## 📁 Dizin Yapısı

```
examples/
├── curl/                           # Bash/cURL script örnekleri
│   ├── sign-efatura.sh
│   ├── sign-pdf.sh
│   ├── sign-soap.sh
│   └── check-tubitak-credit.sh
├── find-certificate-info.sh        # Sertifika bilgilerini bulma
├── postman/                        # Postman koleksiyonu
│   └── sign-api.postman_collection.json
└── README.md                       # Bu dosya
```

## 🚀 Hızlı Başlangıç

### 0. Sertifika Bilgilerini Bulma

API'yi kullanmadan önce, keystore'unuzdaki sertifika bilgilerini öğrenmek için:

```bash
# PFX dosyası için
./find-certificate-info.sh pfx /path/to/certificate.pfx password

# PKCS#11 (HSM) için
./find-certificate-info.sh pkcs11 /usr/lib/softhsm/libsofthsm2.so 0 1234
```

Script çıktısı size:
- Sertifika alias'larını
- Serial number'ları (hexadecimal)
- Subject bilgilerini
- Geçerlilik tarihlerini
- Environment variable örneklerini gösterecektir

📘 **Detaylı bilgi:** [Sertifika Seçimi](https://dss.mersel.dev/sign-api/certificate-selection)

### 1. cURL ile Test

En basit yöntem - terminal üzerinden doğrudan test:

```bash
cd examples/curl
chmod +x *.sh

# e-Fatura imzalama
./sign-efatura.sh your-invoice.xml

# PDF imzalama
./sign-pdf.sh document.pdf

# Kontör sorgulama
./check-tubitak-credit.sh
```

Detaylar için: [curl/README.md](curl/README.md)

### 2. Postman ile Test

GUI üzerinden test etmek için:

1. Postman'ı açın
2. `File` → `Import` → `sign-api.postman_collection.json`
3. Collection'da `Variables` sekmesinden `baseUrl` ayarlayın
4. İstediğiniz endpoint'i seçin ve test dosyasını yükleyin

## 📖 Kullanım Senaryoları

### Senaryo 1: e-Fatura İmzalama

```bash
# 1. e-Fatura XML'i hazırlayın
cat > efatura.xml << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2">
  <cbc:ID>INV-2024-001</cbc:ID>
  ...
</Invoice>
EOF

# 2. İmzalayın
curl -X POST http://localhost:8085/v1/xadessign \
  -F "document=@efatura.xml" \
  -F "documentType=UblDocument" \
  -o signed-efatura.xml

# 3. İmzayı doğrulayın (opsiyonel - doğrulama servisi gerekir)
# xmlsec1 verify --trusted-pem ca-cert.pem signed-efatura.xml
```

### Senaryo 2: PDF Çoklu İmzalama

```bash
# 1. İlk imza
curl -X POST http://localhost:8085/v1/padessign \
  -F "document=@document.pdf" \
  -F "appendMode=false" \
  -o signed-once.pdf

# 2. İkinci imza ekle (append mode)
curl -X POST http://localhost:8085/v1/padessign \
  -F "document=@signed-once.pdf" \
  -F "appendMode=true" \
  -o signed-twice.pdf

# PDF'de kaç imza var kontrol et
pdfinfo signed-twice.pdf | grep Signature
```

### Senaryo 3: SOAP Web Service Entegrasyonu

```bash
# 1. SOAP isteği hazırla
cat > soap-request.xml << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetQuote xmlns="http://example.com/">
      <symbol>AAPL</symbol>
    </GetQuote>
  </soap:Body>
</soap:Envelope>
EOF

# 2. WS-Security ile imzala
curl -X POST http://localhost:8085/v1/wssecuritysign \
  -F "document=@soap-request.xml" \
  -F "soap1Dot2=false" \
  -o signed-soap.xml

# 3. İmzalı SOAP'ı web servisine gönder
curl -X POST https://api.example.com/service \
  -H "Content-Type: text/xml" \
  --data-binary @signed-soap.xml
```

### Senaryo 4: Batch (Toplu) İmzalama

```bash
# Dizindeki tüm XML dosyalarını imzala
for file in invoices/*.xml; do
  echo "İmzalanıyor: $file"
  curl -X POST http://localhost:8085/v1/xadessign \
    -F "document=@$file" \
    -F "documentType=UblDocument" \
    -o "signed-$(basename "$file")"
done
```

## 🔧 Yapılandırma

### Environment Variables

Script'lerde kullanılabilecek değişkenler:

```bash
# API base URL
export API_URL=http://localhost:8085

# Timeout (curl için)
export CURL_TIMEOUT=30

# Çalıştır
./sign-efatura.sh
```

### Custom API Configuration

Farklı bir sunucu kullanmak için:

```bash
# Development
API_URL=http://dev-server:8085 ./sign-efatura.sh

# Production
API_URL=https://sign-api.example.com ./sign-efatura.sh
```

## 🧪 Test Dosyaları

Test için örnek dosyalar oluşturma:

```bash
# Minimal XML
echo '<?xml version="1.0"?><root><test>data</test></root>' > test.xml

# Minimal PDF (ghostscript gerekir)
echo 'Hello World' | gs -sDEVICE=pdfwrite -o test.pdf -

# SOAP 1.1 zarfı
cat > soap-test.xml << 'EOF'
<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <test>data</test>
  </soap:Body>
</soap:Envelope>
EOF
```

## 📊 Performance Testing

API'yi yük testi için:

```bash
# Apache Bench ile
ab -n 100 -c 10 -p efatura.xml -T "multipart/form-data" \
  http://localhost:8085/v1/xadessign

# wrk ile
wrk -t4 -c100 -d30s http://localhost:8085/index.html
```

## 🐛 Hata Ayıklama

### Verbose Mode

cURL ile detaylı çıktı:

```bash
curl -v -X POST http://localhost:8085/v1/xadessign \
  -F "document=@efatura.xml" \
  -F "documentType=UblDocument"
```

### Log Kontrolü

API loglarını takip edin:

```bash
# Genel loglar
tail -f logs/application.log

# Sadece hatalar
tail -f logs/error.log

# İmzalama operasyonları
tail -f logs/signature.log
```

## 💡 İpuçları

1. **Büyük Dosyalar:** Timeout sürelerini artırın
   ```bash
   curl --max-time 120 ...
   ```

2. **Zaman Damgası:** TÜBİTAK kontörünüzü düzenli kontrol edin
   ```bash
   ./check-tubitak-credit.sh
   ```

3. **İmza Doğrulama:** İmzalı dosyaları saklayın ve düzenli olarak doğrulayın

4. **Batch İşlemler:** Paralel işlem için `xargs` veya `parallel` kullanın
   ```bash
   ls invoices/*.xml | parallel -j 4 ./sign-efatura.sh {}
   ```

## 📚 Ek Kaynaklar

- [API Dokümantasyonu](http://localhost:8085/index.html)
- [Sertifika Seçimi Rehberi](https://dss.mersel.dev/sign-api/certificate-selection)
- [DSS Override Dokümantasyonu](../DSS_OVERRIDE.md)
- [Güvenlik Politikası](../SECURITY.md)
- [Performance Guide](https://dss.mersel.dev/sign-api/performance)

## 🤝 Katkıda Bulunma

Yeni örnekler eklemek için:

1. Örneğinizi ilgili dizine ekleyin
2. README'yi güncelleyin
3. Test edin
4. Pull request açın

---

**Not:** Tüm örnekler localhost için yapılandırılmıştır. Production ortamında HTTPS ve authentication kullanın.


