# Zaman Damgası (Timestamp) Servisi

Bu dokümantasyon, RFC 3161 standardına uygun zaman damgası alma ve doğrulama API'sini açıklar.

## İçindekiler

1. [Genel Bakış](#genel-bakış)
2. [Yapılandırma](#yapılandırma)
3. [API Endpoint'leri](#api-endpointleri)
4. [Kullanım Örnekleri](#kullanım-örnekleri)
5. [Hata Kodları](#hata-kodları)

## Genel Bakış

Zaman damgası servisi, herhangi bir binary belge için RFC 3161 standardına uygun zaman damgası (timestamp) almanızı ve doğrulamanızı sağlar.

### Özellikler

- ✅ RFC 3161 standardına tam uyumluluk
- ✅ Herhangi bir binary belge için zaman damgası alma
- ✅ TSQ (Time Stamp Query) otomatik oluşturma
- ✅ TSR (Time Stamp Response) parsing ve işleme
- ✅ Kapsamlı zaman damgası doğrulama
- ✅ Çoklu hash algoritması desteği (SHA-1, SHA-256, SHA-384, SHA-512, SHA3-*)
- ✅ TÜBİTAK ESYA desteği
- ✅ Standart RFC 3161 TSP sunucuları desteği

## Yapılandırma

### Ortam Değişkenleri

Zaman damgası servisi için aşağıdaki ortam değişkenlerini yapılandırın:

```bash
# Timestamp sunucu URL'si (zorunlu)
TS_SERVER_HOST=http://zd.kamusm.gov.tr

# TÜBİTAK ESYA için (opsiyonel)
IS_TUBITAK_TSP=true
TS_USER_ID=123456
TS_USER_PASSWORD=your_password

# Standart HTTP Basic Auth için (opsiyonel)
TS_USER_ID=username
TS_USER_PASSWORD=password
```

### Desteklenen TSP Sunucuları

#### 1. KAMUSM (Kamu Sertifikasyon Merkezi)

```bash
TS_SERVER_HOST=http://zd.kamusm.gov.tr
IS_TUBITAK_TSP=false
```

#### 2. TÜBİTAK ESYA

```bash
TS_SERVER_HOST=http://zd.kamusm.gov.tr
IS_TUBITAK_TSP=true
TS_USER_ID=123456
TS_USER_PASSWORD=your_password
```

#### 3. E-Tugra

```bash
TS_SERVER_HOST=http://tzd.e-tugra.com.tr
IS_TUBITAK_TSP=false
```

## API Endpoint'leri

### 1. Zaman Damgası Alma

Binary belge için zaman damgası alır.

**Endpoint:** `POST /api/timestamp/get`

**Request Type:** `multipart/form-data`

**Form Parameters:**

| Alan | Tip | Zorunlu | Açıklama |
|------|-----|---------|----------|
| document | file | ✅ | Zaman damgası alınacak dosya (herhangi bir binary dosya) |
| hashAlgorithm | string | ❌ | Hash algoritması (varsayılan: SHA256) |

**Desteklenen Hash Algoritmaları:**
- SHA1
- SHA224
- SHA256 (varsayılan)
- SHA384
- SHA512

**Response:**
- **Content-Type:** `application/octet-stream`
- **Body:** Binary timestamp token (.tst dosyası)
- **Headers:**
  - `Content-Disposition: attachment; filename=timestamp.tst`
  - `X-Timestamp-Time: 2025-11-07T14:30:00Z` (Zaman damgası zamanı)
  - `X-Timestamp-TSA: CN=KAMUSM Zaman Damgası, O=Kamu SM, C=TR` (TSA bilgisi)
  - `X-Timestamp-Serial: 123456789` (Seri numarası)
  - `X-Timestamp-Hash-Algorithm: SHA256` (Hash algoritması)
  - `X-Timestamp-Nonce: 1234567890123456` (Nonce, varsa)

### 2. Zaman Damgası Doğrulama

Zaman damgasının geçerliliğini doğrular.

**Endpoint:** `POST /api/timestamp/validate`

**Request Type:** `multipart/form-data`

**Form Parameters:**

| Alan | Tip | Zorunlu | Açıklama |
|------|-----|---------|----------|
| timestampToken | file | ✅ | Timestamp token dosyası (.tst veya binary) |
| originalDocument | file | ❌ | Orijinal belge dosyası (hash doğrulaması için) |

**Response:**
```json
{
  "valid": true,
  "timestamp": "2025-11-07T14:30:00Z",
  "tsaName": "CN=KAMUSM Zaman Damgası, O=Kamu SM, C=TR",
  "hashAlgorithm": "2.16.840.1.101.3.4.2.1",
  "serialNumber": "123456789",
  "nonce": "1234567890123456",
  "signatureAlgorithm": "1.2.840.113549.1.1.11",
  "tsaCertificate": "MIIFYzCCBEugAwIBAgIQPh...",
  "certificateValid": true,
  "certificateNotBefore": "2024-01-01T00:00:00Z",
  "certificateNotAfter": "2026-01-01T00:00:00Z",
  "hashVerified": true,
  "errors": [],
  "message": "Zaman damgası geçerli ve doğrulandı"
}
```

### 3. Servis Durumu

Timestamp servisinin yapılandırma durumunu kontrol eder.

**Endpoint:** `GET /api/timestamp/status`

**Response:**
```json
{
  "configured": true,
  "message": "Timestamp servisi aktif"
}
```

## Kullanım Örnekleri

#### 1. Basit Metin İçin Zaman Damgası Alma

```bash
#!/bin/bash

# Metin dosyası oluştur
echo "Hello World!" > test.txt

# Zaman damgası al - binary olarak gelir (.tst)
curl -X POST http://localhost:8080/api/timestamp/get \
  -F "document=@test.txt" \
  -F "hashAlgorithm=SHA256" \
  -o timestamp.tst \
  -i  # Header'ları da göster

# Header'larda metadata bilgileri var:
# X-Timestamp-Time: 2025-11-07T14:30:00Z
# X-Timestamp-TSA: CN=KAMUSM...
# X-Timestamp-Serial: 123456789
```

#### 2. Dosya İçin Zaman Damgası Alma

```bash
#!/bin/bash

FILE_PATH="document.pdf"

# Zaman damgası al - binary olarak gelir, header'larda metadata var
curl -X POST http://localhost:8080/api/timestamp/get \
  -F "document=@$FILE_PATH" \
  -F "hashAlgorithm=SHA256" \
  -o timestamp.tst \
  -D headers.txt

echo "Zaman damgası kaydedildi: timestamp.tst"
echo ""
echo "Metadata (header'lardan):"
cat headers.txt | grep -i "X-Timestamp"
```

#### 3. Zaman Damgası Doğrulama

```bash
#!/bin/bash

# Orijinal dosya ile doğrula
curl -X POST http://localhost:8080/api/timestamp/validate \
  -F "timestampToken=@timestamp.tst" \
  -F "originalDocument=@document.pdf" | jq .
```

#### 4. Sadece Token Doğrulama (Orijinal Veri Olmadan)

```bash
#!/bin/bash

# Sadece token ile doğrula (hash kontrolü olmadan)
curl -X POST http://localhost:8080/api/timestamp/validate \
  -F "timestampToken=@timestamp.tst" | jq .
```

#### 5. Header'lardan Metadata Okuma

```bash
#!/bin/bash

# Timestamp al ve header'ları kaydet
curl -X POST http://localhost:8080/api/timestamp/get \
  -F "document=@document.pdf" \
  -o timestamp.tst \
  -D headers.txt

# Metadata bilgilerini oku
echo "Zaman: $(grep X-Timestamp-Time headers.txt | cut -d' ' -f2-)"
echo "TSA: $(grep X-Timestamp-TSA headers.txt | cut -d' ' -f2-)"
echo "Serial: $(grep X-Timestamp-Serial headers.txt | cut -d' ' -f2-)"
echo "Hash: $(grep X-Timestamp-Hash-Algorithm headers.txt | cut -d' ' -f2-)"
```

#### 6. Farklı Hash Algoritmaları

```bash
#!/bin/bash

# SHA256 ile
curl -X POST http://localhost:8080/api/timestamp/get \
  -F "document=@file.pdf" \
  -F "hashAlgorithm=SHA256" \
  -o timestamp-sha256.tst

# SHA512 ile
curl -X POST http://localhost:8080/api/timestamp/get \
  -F "document=@file.pdf" \
  -F "hashAlgorithm=SHA512" \
  -o timestamp-sha512.tst
```

## Hata Kodları

| Kod | Açıklama |
|-----|----------|
| TIMESTAMP_NOT_CONFIGURED | Timestamp servisi yapılandırılmamış |
| TIMESTAMP_ERROR | Genel timestamp hatası |
| VALIDATION_ERROR | Doğrulama hatası |
| INTERNAL_ERROR | Sunucu hatası |

## Güvenlik Notları

1. **Nonce Kullanımı**: Replay attack'lere karşı koruma için `useNonce: true` kullanın
2. **Hash Algoritması**: Güvenlik için minimum SHA-256 kullanın
3. **Orijinal Veri**: Doğrulama sırasında orijinal veriyi sağlayarak hash kontrolü yapın
4. **Sertifika Kontrolü**: TSA sertifikasının geçerlilik tarihlerini kontrol edin
5. **Token Saklama**: Timestamp token'larını güvenli bir şekilde saklayın

## Sık Sorulan Sorular

### 1. Timestamp token'ı ne kadar süre geçerlidir?

Timestamp token'ı, TSA sertifikasının geçerlilik süresi boyunca geçerlidir. Genellikle bu süre 2-5 yıldır.

### 2. Hangi dosya türleri desteklenir?

Herhangi bir binary dosya desteklenir: PDF, XML, Office belgeleri, resimler, videolar vb.

### 3. Maksimum dosya boyutu nedir?

API seviyesinde bir sınırlama yoktur, ancak TSP sunucusu sınırlamaları geçerlidir. Genellikle 10-50 MB arası.

### 4. Offline doğrulama mümkün mü?

Evet, timestamp token'ı ve TSA sertifikası ile offline doğrulama yapılabilir.

### 5. Birden fazla TSP sunucusu kullanabilir miyim?

Şu anda tek bir TSP sunucusu yapılandırılabilir. Birden fazla sunucu için uygulama seviyesinde yönetim gerekir.

## Teknik Detaylar

### RFC 3161 Uyumluluğu

Bu implementasyon RFC 3161 standardına tam uyumludur:
- TSQ (Time Stamp Query) formatı
- TSR (Time Stamp Response) formatı
- Accuracy ve ordering field desteği
- Nonce kullanımı
- Certificate inclusion

### Kullanılan Kütüphaneler

- **BouncyCastle**: TSP implementasyonu için
- **DSS (Digital Signature Service)**: EU standartlarına uygunluk
- **Spring Boot**: REST API framework

## Destek ve İletişim

Sorularınız veya önerileriniz için:
- Issue açın: [GitHub Issues](https://github.com/your-repo/issues)
- Dokümantasyon: [README.md](../README.md)

