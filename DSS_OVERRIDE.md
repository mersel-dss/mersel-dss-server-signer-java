# DSS Kütüphanesi Override Dokümantasyonu 🔧

Bu doküman, EU DSS (Digital Signature Service) kütüphanesinin Türkiye e-imza standartlarına (özellikle TÜBİTAK BES formatı) uyarlanması için yapılan değişiklikleri açıklar.

## İçindekiler

- [DSS Kütüphanesi Override Dokümantasyonu 🔧](#dss-kütüphanesi-override-dokümantasyonu-)
  - [İçindekiler](#i̇çindekiler)
  - [Genel Bakış](#genel-bakış)
  - [Override Edilen Dosyalar](#override-edilen-dosyalar)
  - [Detaylı Override Açıklamaları](#detaylı-override-açıklamaları)
    - [1. Reference Sıralaması (TÜBİTAK BES Uyumu)](#1-reference-sıralaması-tübi̇tak-bes-uyumu)
      - [Problem](#problem)
      - [Etki](#etki)
      - [Çözüm](#çözüm)
      - [Etkilenen Bileşenler](#etkilenen-bileşenler)
    - [2. KeyInfo Sertifika Zinciri](#2-keyinfo-sertifika-zinciri)
      - [Problem](#problem-1)
      - [TÜBİTAK Standardı](#tübi̇tak-standardı)
      - [Çözüm](#çözüm-1)
      - [Etkilenen Bileşenler](#etkilenen-bileşenler-1)
    - [3. KeyInfo KeyValue (RSAKeyValue)](#3-keyinfo-keyvalue-rsakeyvalue)
      - [Problem](#problem-2)
      - [TÜBİTAK Standardı](#tübi̇tak-standardı-1)
      - [Çözüm](#çözüm-2)
      - [Etkilenen Bileşenler](#etkilenen-bileşenler-2)
    - [4. Base64 Satır Sonları (76 Karakter)](#4-base64-satır-sonları-76-karakter)
      - [Problem](#problem-3)
      - [TÜBİTAK Standardı](#tübi̇tak-standardı-2)
      - [Çözüm](#çözüm-3)
      - [Etkilenen Bileşenler](#etkilenen-bileşenler-3)
    - [5. CanonicalizationMethod (Timestamp)](#5-canonicalizationmethod-timestamp)
      - [Problem](#problem-4)
      - [TÜBİTAK Çıktısı](#tübi̇tak-çıktısı)
      - [Mevcut Durum](#mevcut-durum)
      - [Etkilenen Bileşenler](#etkilenen-bileşenler-4)
    - [6. OCSP/CRL Cache Mekanizması](#6-ocspcrl-cache-mekanizması)
      - [Problem](#problem-5)
      - [Çözüm](#çözüm-4)
      - [Cache Özellikleri](#cache-özellikleri)
      - [Etkilenen Bileşenler](#etkilenen-bileşenler-5)
    - [7. CRL Number Ekleme](#7-crl-number-ekleme)
      - [Problem](#problem-6)
      - [İMZAGER Gereksinimi](#i̇mzager-gereksinimi)
      - [Çözüm](#çözüm-5)
      - [Etkilenen Bileşenler](#etkilenen-bileşenler-6)
      - [Upstream Katkı](#upstream-katkı)
  - [Etkilenen Bileşenler](#etkilenen-bileşenler-7)
    - [🎯 İmza Seviyeleri](#-i̇mza-seviyeleri)
    - [📄 Belge Tipleri](#-belge-tipleri)
    - [🔧 Servisler](#-servisler)
  - [Özet Tablo](#özet-tablo)
  - [Katkıda Bulunanlar](#katkıda-bulunanlar)
  - [Lisans ve Atıf](#lisans-ve-atıf)

---

## Genel Bakış

EU DSS kütüphanesi, Avrupa standartlarına (ETSI XAdES, PAdES, CAdES) göre tasarlanmış güçlü bir dijital imza framework'üdür. Ancak, Türkiye'deki e-imza uygulamalarında (özellikle e-Fatura, e-Arşiv Raporu gibi sistemlerde) TÜBİTAK BES formatı ve İMZAGER gibi doğrulayıcıların beklentileri nedeniyle bazı özelleştirmeler gerekmiştir.

Bu projede, DSS kütüphanesinin kaynak kodundan **6 ana sınıf** proje içine kopyalanmış ve **özgün paket yapısı korunarak** (`.../eu/europa/esig/dss/xades/signature/`) özelleştirilmiştir. Bu sayede:

- ✅ DSS kütüphanesinin geri kalanı değişmeden kullanılır
- ✅ Sadece gerekli sınıflar override edilir
- ✅ Değişiklikler kod içinde açıkça işaretlenmiştir (`########################OVERRIDE_DSS#########################`)
- ✅ Gelecekte DSS güncellemelerinde hangi kısımların merge edilmesi gerektiği bellidir

## Override Edilen Dosyalar

Aşağıdaki DSS sınıfları proje içinde override edilmiştir:


| Dosya                             | Paket                                | Ana Değişiklik                                                                                                            |
| --------------------------------- | ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------- |
| `XAdESSignatureBuilder.java`      | `eu.europa.esig.dss.xades.signature` | Reference sıralaması + KeyInfo sadece imzacı sertifikası + KeyValue (RSAKeyValue) + **SigningTime configurable timezone** |
| `XAdESLevelBaselineT.java`        | `eu.europa.esig.dss.xades.signature` | 76 karakter base64 satır sonları                                                                                          |
| `XAdESLevelC.java`                | `eu.europa.esig.dss.xades.signature` | OCSP/CRL cache + CRL Number                                                                                               |
| `XAdESLevelXL.java`               | `eu.europa.esig.dss.xades.signature` | 76 karakter base64 (XL seviyesi)                                                                                          |
| `XAdESLevelA.java`                | `eu.europa.esig.dss.xades.signature` | Arşiv timestamp'leri için base64                                                                                          |
| `DetachedSignatureBuilder.java`   | `eu.europa.esig.dss.xades.signature` | Detached imza özellikleri                                                                                                 |
| `XAdESSigningTimeZoneHolder.java` | `eu.europa.esig.dss.xades.signature` | **DSS-dışı yardımcı:** SigningTime zaman dilimini taşıyan statik singleton                                                |


> **Not:** Bu dosyaların **orijinal DSS lisansı** (LGPL v2.1) korunmuştur ve her dosyanın başında lisans bilgisi mevcuttur.

---

## Detaylı Override Açıklamaları

### 1. Reference Sıralaması (TÜBİTAK BES Uyumu)

**📁 Dosya:** `XAdESSignatureBuilder.java` (satır 231-266)

#### Problem

DSS kütüphanesinin orijinal kodunda, `ds:SignedInfo` içindeki `ds:Reference` elemanlarının sırası TÜBİTAK BES formatı ile uyumsuzdur.

**DSS Orijinal Sırası:**

```xml
<ds:SignedInfo>
    <ds:Reference URI="#r-data-001">          <!-- 1. Data/Object -->
    <ds:Reference URI="#xades-...">           <!-- 2. SignedProperties -->
    <ds:Reference URI="#keyInfo-...">         <!-- 3. KeyInfo -->
</ds:SignedInfo>
```

**TÜBİTAK BES Beklentisi:**

```xml
<ds:SignedInfo>
    <ds:Reference URI="#xades-...">           <!-- 1. SignedProperties (İLK) -->
    <ds:Reference URI="#r-data-001">          <!-- 2. Data/Object -->
    <ds:Reference URI="#keyInfo-...">         <!-- 3. KeyInfo (SON) -->
</ds:SignedInfo>
```

#### Etki

Yanlış sıralama nedeniyle:

- ❌ TÜBİTAK doğrulayıcısı, Enveloped imzaları bile **Detached** olarak algılar
- ❌ `<ds:Transform Algorithm="...#enveloped-signature"/>` elementi göz ardı edilir
- ❌ İmza doğrulama başarısız olur veya yanlış imza türü rapor edilir

#### Çözüm

Reference elemanlarının ekleniş sırası değiştirilmiştir:

```java
// ########################OVERRIDE_DSS#########################
// TÜBİTAK BES uyumlu sıralama:
incorporateReferenceSignedProperties();  // İlk olarak (SignedProperties)
incorporateReferences();                 // İkinci olarak (Data/Object)
incorporateReferenceKeyInfo();           // Son olarak (KeyInfo)
// #############################################################
```

#### Etkilenen Bileşenler

- ✅ Tüm XAdES imza tipleri (Enveloped, Enveloping, Detached, Internally Detached)
- ✅ e-Fatura, e-Arşiv Raporu, e-İrsaliye vb.

---

### 2. KeyInfo Sertifika Zinciri

**📁 Dosya:** `XAdESSignatureBuilder.java` (satır 556-577)

#### Problem

DSS, `<ds:KeyInfo>` elemanına sertifika zincirinin **tamamını** ekler:

```xml
<ds:KeyInfo>
    <ds:X509Data>
        <ds:X509Certificate>MII... [İmzacı Sertifikası]</ds:X509Certificate>
        <ds:X509Certificate>MII... [Ara CA Sertifikası]</ds:X509Certificate>
        <ds:X509Certificate>MII... [Kök CA Sertifikası]</ds:X509Certificate>
    </ds:X509Data>
</ds:KeyInfo>
```

#### TÜBİTAK Standardı

TÜBİTAK XAdES uygulama kılavuzu gereği, `KeyInfo` içinde **sadece imzacı sertifikası** olmalıdır:

```xml
<ds:KeyInfo>
    <ds:X509Data>
        <ds:X509Certificate>MII... [Sadece İmzacı Sertifikası]</ds:X509Certificate>
    </ds:X509Data>
</ds:KeyInfo>
```

> **Neden?** Sertifika zinciri XAdES-C/XL seviyelerinde `<xades:CertificateValues>` içine ayrıca eklenir. KeyInfo'da zinciri tekrarlamak gereksizdir ve format uyumsuzluğu yaratır.

#### Çözüm

```java
// ########################OVERRIDE_DSS#########################
// DSS orijinali: certificates = params.getCertificateChain();
// TÜBİTAK uyumlu: Sadece imzacı sertifikası
List<CertificateToken> certificates = new ArrayList<>();
certificates.add(params.getSigningCertificate());
// #############################################################
```

#### Etkilenen Bileşenler

- ✅ Tüm XAdES imzalar (B, T, C, XL, A seviyeleri)
- ✅ KeyInfo referansı içeren imzalar

---

### 3. KeyInfo KeyValue (RSAKeyValue)

**📁 Dosya:** `XAdESSignatureBuilder.java` (satır 598-717)

#### Problem

DSS, `<ds:KeyInfo>` elemanına **sadece X509Data** ekler, public key bilgisini içeren `<ds:KeyValue>` elemanını eklemez:

```xml
<ds:KeyInfo>
    <ds:X509Data>
        <ds:X509Certificate>MII... [İmzacı Sertifikası]</ds:X509Certificate>
    </ds:X509Data>
    <!-- EKSIK: KeyValue elementi -->
</ds:KeyInfo>
```

#### TÜBİTAK Standardı

TÜBİTAK XAdES uygulama kılavuzu gereği, `KeyInfo` içinde X509Data'dan sonra **KeyValue** (RSAKeyValue) elemanı da bulunmalıdır:

```xml
<ds:KeyInfo>
    <ds:X509Data>
        <ds:X509Certificate>MII... [İmzacı Sertifikası]</ds:X509Certificate>
    </ds:X509Data>
    <ds:KeyValue>
        <ds:RSAKeyValue>
            <ds:Modulus>
xjFp9zQP5bK8mNvYdHcR7xLpWqY3sT4uVwZaBcDeFgHiJkLmNoP9qRsTuVwXyZaBcDeF
gHiJkLmNoP9qRsTuVwXyZaBcDeFgHiJkLmNoP9qRsTuVwXyZaBcDeFgHiJkLmNoP9qRsT
uVwXyZaBcDeFgHiJkLmNoP9qRsTuVwXy...
            </ds:Modulus>
            <ds:Exponent>AQAB</ds:Exponent>
        </ds:RSAKeyValue>
    </ds:KeyValue>
</ds:KeyInfo>
```

> **Neden?** 
>
> - KeyValue elemanı, sertifikaya ek olarak public key bilgisini doğrudan XML içinde sağlar
> - TÜBİTAK BES formatına uyum için zorunludur
> - **Modulus değeri 76 karakterde satır sonuna gitmeli** (RFC 2045 base64 standardı)
> - **Exponent genelde kısa değerdir** (AQAB gibi), satır sonuna gitmeye gerek yok

#### Çözüm

`addRSAKeyValue()` metodu oluşturulmuş ve `incorporateKeyInfo()` metoduna eklenmiştir:

```java
// ########################OVERRIDE_DSS#########################
// Tübitak XAdES uygulama kılavuzu gereği KeyInfo içinde X509Data'dan 
// sonra KeyValue (RSAKeyValue) eklenmesi gerekiyor.
addRSAKeyValue(keyInfoElement, params.getSigningCertificate());
// #############################################################
```

**addRSAKeyValue() İmplementasyonu:**

```java
private void addRSAKeyValue(final Element keyInfoElement, final CertificateToken token) {
    PublicKey publicKey = token.getPublicKey();
    
    if (!(publicKey instanceof RSAPublicKey)) {
        LOG.warn("Public key is not RSA type, skipping KeyValue element");
        return;
    }
    
    RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
    BigInteger modulus = rsaPublicKey.getModulus();
    BigInteger exponent = rsaPublicKey.getPublicExponent();
    
    final String xmldsigUri = getXmldsigNamespace().getUri();
    final String xmldsigPrefix = getXmldsigNamespace().getPrefix();
    
    // <ds:KeyValue>
    final Element keyValueElement = documentDom.createElementNS(xmldsigUri, xmldsigPrefix + ":KeyValue");
    keyInfoElement.appendChild(keyValueElement);
    
    // <ds:RSAKeyValue>
    final Element rsaKeyValueElement = documentDom.createElementNS(xmldsigUri, xmldsigPrefix + ":RSAKeyValue");
    keyValueElement.appendChild(rsaKeyValueElement);
    
    // <ds:Modulus> - TÜBİTAK standart base64 (76 karakter satır sonu)
    final Element modulusElement = documentDom.createElementNS(xmldsigUri, xmldsigPrefix + ":Modulus");
    modulusElement.setTextContent(XadesUtil.formatWithBase64(modulus.toByteArray()));
    rsaKeyValueElement.appendChild(modulusElement);
    
    // <ds:Exponent> - Kısa değer (genelde AQAB), formatlamaya gerek yok
    final Element exponentElement = documentDom.createElementNS(xmldsigUri, xmldsigPrefix + ":Exponent");
    exponentElement.setTextContent(Utils.toBase64(exponent.toByteArray()));
    rsaKeyValueElement.appendChild(exponentElement);
}
```

**Özellikler:**

- ✅ RSA Public Key desteği (Modulus + Exponent)
- ✅ Non-RSA sertifikalar için graceful degradation (warning log + skip)
- ✅ **Modulus için TÜBİTAK standart Base64 encoding** (76 karakterde satır sonu - XadesUtil.formatWithBase64)
- ✅ **Exponent için standart Base64** (genelde kısa değer - AQAB, formatlamaya gerek yok)
- ✅ XML DSig namespace uyumu (getXmldsigNamespace() kullanımı)

#### Etkilenen Bileşenler

- ✅ Tüm XAdES imzalar (B, T, C, XL, A seviyeleri)
- ✅ RSA tabanlı sertifikalar (ECC/DSA için eklenmez)
- ✅ TÜBİTAK BES format doğrulama

---

### 4. Base64 Satır Sonları (76 Karakter)

**📁 Dosyalar:** 

- `XAdESLevelBaselineT.java` (satır 282-294, 353-365, 394-406)
- `XadesUtil.java` (yardımcı sınıf)

#### Problem

DSS, base64-encoded değerleri **tek satırda** üretir:

```xml
<xades:EncapsulatedX509Certificate>MIIFkTCCBHmgAwIBAgIQAbcde...</xades:EncapsulatedX509Certificate>
```

#### TÜBİTAK Standardı

TÜBİTAK ve RFC 2045 standardına göre, base64 değerler **76 karakterde satır sonuna** gitmeli:

```xml
<xades:EncapsulatedX509Certificate>
MIIFkTCCBHmgAwIBAgIQAbcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123
456789+/ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/ABCDEFGHIJKLMNOPQRSTUVWXYZ012345
6789+/ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456
</xades:EncapsulatedX509Certificate>
```

#### Çözüm

`XadesUtil` yardımcı sınıfı oluşturulmuş ve satır sonlu base64 üretimi sağlanmıştır:

```java
// ########################OVERRIDE_DSS#########################
// Orijinal: DomUtils.setTextNode(documentDom, element, Utils.toBase64(bytes));
// TÜBİTAK uyumlu:
XadesUtil.createEncapsulatedCertificateElement(
    documentDom, parentDom, getXadesNamespace(), certificateToken.getEncoded()
);
// #############################################################
```

**XadesUtil Metotları:**

- `createEncapsulatedCertificateElement()` - Sertifikalar için
- `createEncapsulatedCRLElement()` - CRL'ler için
- `createEncapsulatedOCSPElement()` - OCSP yanıtları için
- `formatWithBase64()` - Timestamp'ler için (genel amaçlı)

#### Etkilenen Bileşenler

- ✅ `<xades:CertificateValues>` (XL seviyesi)
- ✅ `<xades:RevocationValues>` (XL seviyesi)
- ✅ `<xades:EncapsulatedTimeStamp>` (T, LT, LTA seviyeleri)

---

### 5. CanonicalizationMethod (Timestamp)

**📁 Dosya:** `XAdESLevelBaselineT.java` (satır 669-698)

#### Problem

DSS, timestamp elemanlarına **her zaman** `<ds:CanonicalizationMethod>` ekler:

```xml
<xades:SignatureTimeStamp>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
    <xades:EncapsulatedTimeStamp>MII...</xades:EncapsulatedTimeStamp>
</xades:SignatureTimeStamp>
```

#### TÜBİTAK Çıktısı

TÜBİTAK'tan alınan örnek imzalarda `CanonicalizationMethod` **bulunmuyor**:

```xml
<xades:SignatureTimeStamp>
    <xades:EncapsulatedTimeStamp>MII...</xades:EncapsulatedTimeStamp>
</xades:SignatureTimeStamp>
```

#### Mevcut Durum

Bu override **opsiyonel** olarak işaretlenmiştir:

```java
// ########################OVERRIDE_DSS#########################
// ŞU ANKİ DURUM: CanonicalizationMethod EKLENİYOR (DSS varsayılan)
//
// KULLANIM:
// - TÜBİTAK ile tam uyum için: Aşağıdaki satırı comment yapın
// - EN 319 132-1 uyumu için: Olduğu gibi bırakın
incorporateC14nMethod(timeStampDom, timestampC14nMethod);
// #############################################################
```

> **Not:** Bu farklılık doğrulamada sorun yaratmamaktadır. EN 319 132-1 standardına göre bu element zorunludur, ancak TÜBİTAK çıktılarında yer almamaktadır.

#### Etkilenen Bileşenler

- ✅ `<xades:SignatureTimeStamp>` (T seviyesi)
- ✅ `<xades:ArchiveTimeStamp>` (A seviyesi)

---

### 6. OCSP/CRL Cache Mekanizması

**📁 Dosya:** `XAdESLevelC.java` (satır 61-650)

#### Problem

DSS'de **ciddi bir sorun** vardır: XAdES-C ve XAdES-XL seviyelerinde OCSP/CRL yanıtları **iki kez ayrı ayrı** çekilir.

**XAdES-C Seviyesi (Referanslar):**

```xml
<xades:CompleteRevocationRefs>
    <xades:OCSPRefs>
        <xades:OCSPRef>
            <xades:DigestValue>ABC123...</xades:DigestValue>  <!-- İlk OCSP çağrısı -->
        </xades:OCSPRef>
    </xades:OCSPRefs>
</xades:CompleteRevocationRefs>
```

**XAdES-XL Seviyesi (Gömülü Değerler):**

```xml
<xades:RevocationValues>
    <xades:OCSPValues>
        <xades:EncapsulatedOCSPValue>MII...</xades:EncapsulatedOCSPValue>  <!-- İkinci OCSP çağrısı -->
    </xades:OCSPValues>
</xades:RevocationValues>
```

**Sonuç:**

- ❌ İki OCSP yanıtı farklı olabilir (OCSP nonce, timestamp farkı)
- ❌ DigestValue eşleşmez
- ❌ XAdES-A doğrulaması başarısız olur

#### Çözüm

**Thread-safe, imza-özel OCSP cache** mekanizması geliştirilmiştir:

```java
// ########################OVERRIDE_DSS#########################
protected static final ConcurrentHashMap<String, ConcurrentHashMap<String, OCSPToken>> 
    ocspCacheBySignature = new ConcurrentHashMap<>();

protected String currentSignatureId;
// #############################################################
```

**İş Akışı:**

1️⃣ **C Seviyesi (Reference oluşturma):**

```java
// OCSP token alınır
OCSPToken ocspToken = fetchFromOCSP(certificate);

// Cache'e kaydedilir (sertifika base64 ile key olarak)
String certKey = Utils.toBase64(certificate.getEncoded());
ocspCacheBySignature.get(signatureId).put(certKey, ocspToken);

// Digest hesaplanır
byte[] digest = ocspToken.getDigest(digestAlgorithm);
```

2️⃣ **XL Seviyesi (Gömülü değer ekleme):**

```java
// Cache'den aynı OCSP alınır
OCSPToken cachedOcspToken = ocspCacheBySignature.get(signatureId).get(certKey);

// Aynı binary kullanılır
byte[] ocspBytes = cachedOcspToken.getEncoded();
```

3️⃣ **Cleanup (Memory leak önleme):**

```java
// İmza işlemi bittiğinde
XAdESLevelC.cleanupOcspCache(signatureId);
```

#### Cache Özellikleri

- ✅ **Thread-safe:** `ConcurrentHashMap` kullanımı
- ✅ **İmza-özel:** Her imza kendi cache'ine sahip
- ✅ **Otomatik temizlik:** İmza bitince cache silinir
- ✅ **Fallback:** 5 dakikadan eski cache'ler periyodik temizlenir

#### Etkilenen Bileşenler

- ✅ XAdES-C seviyesi (OCSP/CRL referansları)
- ✅ XAdES-XL seviyesi (OCSP/CRL gömülü değerleri)
- ✅ XAdES-A seviyesi (arşiv timestamp'leri)
- ✅ e-Arşiv Raporu (otomatik XAdES-A yükseltme)

---

### 7a. SigningTime Timezone (Issue #7)

**📁 Dosyalar:**

- `XAdESSignatureBuilder.java` (`incorporateSigningTime()` metodu)
- `XAdESSigningTimeZoneHolder.java` (DSS-dışı yardımcı)

#### Problem

DSS upstream'in {@code incorporateSigningTime()} metodu, imza zamanını
{@code DomUtils.createXMLGregorianCalendar(Date)} ile üretir ve **her zaman
UTC** ({@code 2025-11-19T11:22:52Z}) basar. Bu, ETSI EN 319 132-1 ile
uyumludur, ancak:

- TÜBİTAK MA3 referans imzaları {@code +03:00} ofseti ile yazar
(örn. {@code 2025-11-19T14:22:52+03:00}) — bu farklılık
[issue #7](https://github.com/mersel-dss/mersel-dss-server-signer-java/issues/7)'de
raporlandı.
- İMZAGER gibi lokal araçlar XML'i okurken UTC değeri gösterir, kullanıcının
bilgisayar saati Istanbul olduğunda görsel kafa karışıklığı yaratır.

#### Çözüm

`<SigningTime>` çıktısının zaman dilimi **parametrik** hale getirildi.
{@code xsd:dateTime} grameri zaten hem {@code Z} hem de {@code +HH:MM}
formatlarını kabul ettiği için bu değişiklik standart dışı değildir.

**Default:** {@code +03:00} (TÜBİTAK MA3 ile birebir aynı).
**ENV ile değiştirilebilir:** {@code XADES_SIGNING_TIME_ZONE=Z} ile UTC'ye dönülür.

```java
// ########################OVERRIDE_DSS#########################
// DSS orijinali (UTC sabit):
//   final XMLGregorianCalendar xmlGregorianCalendar = DomUtils.createXMLGregorianCalendar(signingDate);
//   final String xmlSigningTime = xmlGregorianCalendar.toXMLFormat();
// TÜBİTAK uyumu için configurable timezone (default +03:00, ENV ile değiştirilebilir).
final String xmlSigningTime = XAdESSigningTimeZoneHolder.formatSigningTime(signingDate);
// #############################################################
```

**{@code XAdESSigningTimeZoneHolder} — DSS değil, köprü helper:** Spring
container'ında {@code SignatureConfiguration} açılışta
{@code XADES_SIGNING_TIME_ZONE} property'sini parse edip
{@code setZone(ZoneId)} ile statik field'ı doldurur. Spring dışı testlerde
default {@code +03:00} kalır.

#### Geçerli Değerler


| ENV değeri               | Çıktı örneği                      | Notu                                |
| ------------------------ | --------------------------------- | ----------------------------------- |
| {@code +03:00} (default) | {@code 2025-11-19T14:22:52+03:00} | TÜBİTAK MA3 uyumlu                  |
| {@code Z} / {@code UTC}  | {@code 2025-11-19T11:22:52Z}      | ETSI saf yorumu                     |
| {@code +05:30}           | {@code 2025-11-19T16:52:52+05:30} | İleride farklı pazar için           |
| {@code Europe/Istanbul}  | {@code 2025-11-19T14:22:52+03:00} | DST destekli (TR için fark üretmez) |


> Geçersiz string (örn. {@code "+3"}, {@code "Bogus/Mars"}) verilirse uygulama
> açılışta {@code DateTimeException} ile patlar — fail-fast.

#### Etkilenen Bileşenler

- ✅ Tüm XAdES seviyeleri (B, T, C, XL, A) — SigningTime tek noktada üretilir
- ✅ e-Fatura, e-Arşiv Raporu, e-İrsaliye vb. tüm XAdES belgeleri
- ✅ Sertifika doğrulamasını **etkilemez** (notBefore/notAfter UTC Date üzerinden karşılaştırılır)

---

### 7. CRL Number Ekleme

**📁 Dosya:** `XAdESLevelC.java` (satır 414-433)

#### Problem

DSS, CRL referanslarına `<xades:Number>` elemanını **eklememektedir**:

```xml
<xades:CRLRef>
    <xades:DigestAlgAndValue>...</xades:DigestAlgAndValue>
    <xades:CRLIdentifier>
        <xades:Issuer>CN=...</xades:Issuer>
        <xades:IssueTime>2024-01-01T00:00:00Z</xades:IssueTime>
        <!-- EKSIK: Number elementi -->
    </xades:CRLIdentifier>
</xades:CRLRef>
```

**DSS Kaynak Kodu:**

```java
// DSS orijinalinde yorumlanmış:
// DSSXMLUtils.addTextElement(documentDom, crlRefDom, XAdESNamespaces.XAdES, "xades:Number", ???);
```

#### İMZAGER Gereksinimi

İMZAGER gibi bazı doğrulayıcılar, CRL Number içermeyen referansları **geçersiz** sayar:

```xml
<xades:CRLRef>
    <xades:DigestAlgAndValue>...</xades:DigestAlgAndValue>
    <xades:CRLIdentifier>
        <xades:Issuer>CN=...</xades:Issuer>
        <xades:IssueTime>2024-01-01T00:00:00Z</xades:IssueTime>
        <xades:Number>12345</xades:Number>  <!-- GEREKLİ -->
    </xades:CRLIdentifier>
</xades:CRLRef>
```

#### Çözüm

CRL Number, X509CRL extension'ından çıkarılarak eklenmiştir:

```java
// ########################OVERRIDE_DSS#########################
try {
    X509CRL x509CRL = (X509CRL) CertificateFactory.getInstance("X.509")
            .generateCRL(crlToken.getCRLStream());
    String crlNumber = XadesUtil.extractCrlNumber(x509CRL);
    DomUtils.addTextElement(documentDom, crlIdentifierDom, getXadesNamespace(),
            getCurrentXAdESElements().getElementNumber(), crlNumber);
} catch (Exception ignored) {
    // CRL Number bulunamazsa sessizce devam et
}
// #############################################################
```

**XadesUtil.extractCrlNumber():**

```java
public static String extractCrlNumber(X509CRL crl) {
    byte[] extensionValue = crl.getExtensionValue("2.5.29.20"); // CRLNumber OID
    if (extensionValue != null) {
        ASN1Primitive obj = ASN1Primitive.fromByteArray(
            ASN1OctetString.getInstance(extensionValue).getOctets()
        );
        return ASN1Integer.getInstance(obj).getValue().toString();
    }
    return "0"; // Fallback
}
```

#### Etkilenen Bileşenler

- ✅ XAdES-C seviyesi (`<xades:CRLRefs>`)
- ✅ İMZAGER doğrulaması
- ✅ Tüm CRL içeren imzalar

#### Upstream Katkı

Bu düzeltme için DSS projesine **Pull Request** gönderilmiştir:

- 🔗 [https://github.com/esig/dss/pull/187](https://github.com/esig/dss/pull/187)

> **Not:** DSS upstream'e merge edilene kadar bu override kalıcıdır.

---

## Etkilenen Bileşenler

### 🎯 İmza Seviyeleri


| Seviye                   | Etkilenen Override'lar                       |
| ------------------------ | -------------------------------------------- |
| XAdES-B (Basic)          | Reference Sıralaması, KeyInfo, KeyValue      |
| XAdES-T (Timestamp)      | Base64 Satır Sonları, CanonicalizationMethod |
| XAdES-C (Complete)       | OCSP Cache, CRL Number                       |
| XAdES-XL (eXtended Long) | Base64 Satır Sonları, OCSP Cache             |
| XAdES-A (Archival)       | OCSP Cache, Base64 Satır Sonları             |


### 📄 Belge Tipleri


| Belge Tipi     | Kritik Override'lar                           |
| -------------- | --------------------------------------------- |
| e-Fatura (UBL) | Reference Sıralaması, KeyInfo, KeyValue       |
| e-Arşiv Raporu | **Tüm override'lar** (XAdES-A'ya yükseltilir) |
| e-İrsaliye     | Reference Sıralaması, KeyInfo, KeyValue       |
| HrXml          | Reference Sıralaması, KeyValue                |
| Genel XML      | Reference Sıralaması, KeyValue                |


### 🔧 Servisler


| Servis                          | Bağımlı Olduğu Override                             |
| ------------------------------- | --------------------------------------------------- |
| `XAdESSignatureService`         | Reference Sıralaması, KeyInfo, KeyValue, OCSP Cache |
| `XAdESLevelUpgradeService`      | OCSP Cache, Base64, CRL Number                      |
| `XAdESDocumentPlacementService` | Yok (doğrudan etkilenmez)                           |


---

## Özet Tablo


| Override               | Dosya                      | Satır   | Kritiklik | TÜBİTAK Uyumu   |
| ---------------------- | -------------------------- | ------- | --------- | --------------- |
| Reference Sıralaması   | XAdESSignatureBuilder.java | 231-266 | 🔴 Kritik | Zorunlu         |
| KeyInfo Sertifikası    | XAdESSignatureBuilder.java | 556-577 | 🟡 Önemli | Zorunlu         |
| KeyValue (RSAKeyValue) | XAdESSignatureBuilder.java | 598-717 | 🟡 Önemli | Zorunlu         |
| Base64 Satır Sonları   | XAdESLevelBaselineT.java   | Çoklu   | 🟡 Önemli | Zorunlu         |
| CanonicalizationMethod | XAdESLevelBaselineT.java   | 669-698 | 🟢 Düşük  | Opsiyonel       |
| OCSP Cache             | XAdESLevelC.java           | 61-650  | 🔴 Kritik | Kritik (Digest) |
| CRL Number             | XAdESLevelC.java           | 414-433 | 🟡 Önemli | İMZAGER için    |


**Kritiklik Seviyeleri:**

- 🔴 **Kritik:** İmza doğrulaması başarısız olur
- 🟡 **Önemli:** Format uyumsuzluğu, bazı doğrulayıcılar sorun çıkarır
- 🟢 **Düşük:** Estetik/standart uyumu, doğrulama etkilenmez

---

## Katkıda Bulunanlar

Bu override'ların geliştirilmesinde katkıda bulunanlar:

- 🔬 **Araştırma:** TÜBİTAK BES format analizi
- 💻 **Geliştirme:** OCSP cache mekanizması, XadesUtil helper sınıfı
- 🧪 **Test:** İMZAGER, TÜBİTAK doğrulayıcı entegrasyonu
- 📚 **Dokümantasyon:** Bu doküman ve kod içi açıklamalar

---

## Lisans ve Atıf

Bu override'lar, orijinal DSS kodunun **LGPL v2.1** lisansına tabidir. Her override edilmiş dosyanın başında orijinal DSS lisans başlığı korunmuştur.

**DSS Framework:**

- 🔗 [https://github.com/esig/dss](https://github.com/esig/dss)
- 📄 Lisans: LGPL v2.1
- 🏢 Copyright: European Commission (CEF Programme)

**Bu Proje:**

- Override'lar açıkça işaretlenmiştir
- LGPL v2.1 koşullarına uygun şekilde türetilmiştir
- Kaynak kod değişiklikleri bu dokümanda belgelenmiştir

---

**Son Güncelleme:** Kasım 2025  
**DSS Versiyonu:** 6.3  
**Doküman Versiyonu:** 1.0