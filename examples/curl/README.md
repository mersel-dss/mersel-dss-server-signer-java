# cURL Örnekleri

Bu dizinde API'yi test etmek için kullanabileceğiniz cURL script örnekleri bulunur.

## Mevcut Örnekler

### İmzalama Örnekleri

- **sign-pdf.sh** - PDF belgeleri için PAdES imzası
- **sign-efatura.sh** - e-Fatura için XAdES imzası
- **sign-soap.sh** - SOAP envelope için WS-Security imzası
- **check-tubitak-credit.sh** - TÜBİTAK ESYA kontör sorgulaması

### Zaman Damgası Örnekleri

- **timestamp-example.sh** - RFC 3161 zaman damgası alma ve doğrulama örnekleri
  - Servis durumu kontrolü
  - Basit metin için timestamp alma
  - Dosya için timestamp alma
  - Timestamp doğrulama (orijinal veri ile)
  - Timestamp doğrulama (sadece token ile)
  - Farklı hash algoritmaları ile test
  - Hata senaryoları

## Kullanım

Script'leri çalıştırmadan önce çalıştırma izni verin:

```bash
chmod +x *.sh
```

### Zaman Damgası Örneğini Çalıştırma

```bash
# Timestamp servisini test et
./timestamp-example.sh
```

Script otomatik olarak:
1. ✅ Servis durumunu kontrol eder
2. ✅ Metin için timestamp alır
3. ✅ Timestamp'i doğrular
4. ✅ Farklı senaryoları test eder
5. ✅ Sonuçları renkli çıktı ile gösterir

### Gereksinimler

Tüm script'ler için:
- `curl` - API çağrıları için
- `jq` - JSON parsing için
- Çalışan bir servis instance'ı (varsayılan: http://localhost:8080)

Timestamp script'i için ek olarak:
- Yapılandırılmış TS_SERVER_HOST ortam değişkeni

## Yapılandırma

Servislerin farklı bir URL'de çalıştığı durumda, script içindeki BASE_URL değişkenini değiştirin:

```bash
BASE_URL="http://your-server:8080"
```

## Daha Fazla Bilgi

- [Timestamp Dokümantasyonu](https://dss.mersel.dev/sign-api/timestamp)
- [API Dokümantasyonu](https://dss.mersel.dev)
- [Swagger UI](http://localhost:8080/index.html)
