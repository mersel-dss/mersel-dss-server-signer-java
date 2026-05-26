# MERSEL.Services.DssSigner.Client

[mersel-dss-server-signer-java](https://github.com/mersel-dss/mersel-dss-server-signer-java) mikroservisini HTTP üzerinden çağıran **istemci SDK'sı**.

**.NET Framework 4.6.1'den .NET 10 LTS'e kadar tek paket** olarak çalışır (multi-targeting: `netstandard2.0` + `net8.0`). Tek satır DI kaydıyla tüm imzalama (XAdES, WS-Security, PAdES, CAdES), zaman damgası (RFC 3161 + TÜBİTAK ESYA) ve sertifika operasyonlarını uygulamanıza entegre edin. Servis stateless'tir; istemcide herhangi bir özel state tutulmaz, paket güvenle çoklu instance ile kullanılabilir.

## Kurulum

```bash
dotnet add package MERSEL.Services.DssSigner.Client
```

## DI Kaydı

```csharp
// Seçenek 1: appsettings.json'dan oku (varsayılan section: "Services:DssSigner")
builder.Services.AddDssSignerClient(builder.Configuration);

// Seçenek 2: Kod ile yapılandır
builder.Services.AddDssSignerClient(o =>
{
    o.BaseUrl = "http://dss-signer:8088";
    o.Timeout = TimeSpan.FromMinutes(5);
});

// Seçenek 3: Sadece URL belirt
builder.Services.AddDssSignerClient("http://dss-signer:8088");
```

**appsettings.json:**

```json
{
  "Services": {
    "DssSigner": {
      "BaseUrl": "http://dss-signer:8088",
      "Timeout": "00:02:00"
    }
  }
}
```

> **Not — Authentication:** Sunucu kendisi authentication uygulamaz (bkz. [SECURITY.md](https://github.com/mersel-dss/mersel-dss-server-signer-java/blob/main/SECURITY.md) — "internal kullanım / API Gateway arkasında çalıştırın"). API Gateway, reverse proxy veya başka bir auth katmanı arkasında çalıştırıyorsanız ekstra header'ları (örn. `X-API-Key`, `Authorization`) standart `IHttpClientFactory` zincirinden ekleyin:
>
> ```csharp
> builder.Services.AddHttpClient(DssSignerClientOptions.HttpClientName)
>     .ConfigureHttpClient(http =>
>     {
>         http.DefaultRequestHeaders.Add("X-API-Key", "gateway-secret");
>     });
> // veya: .AddHttpMessageHandler<MyAuthDelegatingHandler>();
> ```

DI kaydı sonrası tüketicide:

- `IDssSignerClient` — tüm domain'lere erişen birleşik cephe
- `IXadesSigner`, `ICadesSigner`, `IPadesSigner` — imzalama
- `ITimestampClient` — RFC 3161 timestamp
- `ITubitakClient` — TÜBİTAK ESYA kontör sorgu
- `ICertificateInfoClient` — sertifika listeleme/keystore meta

inject edilebilir.

## Kullanım

### XAdES (e-Fatura, e-Arşiv, HrXml vs.)

```csharp
public class FaturaImzalama(IDssSignerClient signer)
{
    public async Task<byte[]> EFaturaImzala(byte[] ublXml, CancellationToken ct = default)
    {
        // Varsayılan profil XADES_BES — TSA çağrılmaz, kontör harcanmaz.
        var result = await signer.Xades.SignAsync(ublXml, DocumentType.UblDocument, ct);
        // result.SignedDocument → imzalı XML
        // result.SignatureValue → x-signature-value header'ı (Base64)
        return result.SignedDocument;
    }
}
```

#### XAdES İmza Profilini (BES / A) Seçme

İmza profili artık tamamen request alanı ile belirlenir; `DocumentType` seviye kararına dahil değildir.
e-Arşiv Raporu / e-Bilet Raporu gibi arşivsel akışlarda XAdES-A istemek isterseniz `SignatureLevel`'ı
explicit set edin:

```csharp
// 1) Default (BES) — alan set edilmediğinde otomatik XADES_BES uygulanır.
var bes = await signer.Xades.SignAsync(new SignXadesRequest
{
    Document = ublXml,
    DocumentType = DocumentType.UblDocument
    // SignatureLevel = XadesSignatureLevel.XADES_BES (default)
});

// 2) e-Arşiv Raporu için XAdES-A (archive timestamp eklenir).
//    Sunucu tarafında TSA yapılandırılmamışsa 503 + TIMESTAMP_ERROR alırsınız.
var rapor = await signer.Xades.SignAsync(new SignXadesRequest
{
    Document = earsivRaporXml,
    DocumentType = DocumentType.EArchiveReport,
    SignatureLevel = XadesSignatureLevel.XADES_A
});
```

> **Mali sorumluluk**: e-Arşiv Raporu / e-Bilet Raporu gibi 10 yıllık saklama gerektiren akışlarda
> `XADES_A` talebi çağıran tarafın sorumluluğundadır. Sistem belge tipine bakarak otomatik upgrade
> yapmaz.

### WS-Security (SOAP zarfı)

```csharp
var imzaliEnvelope = await signer.Xades.SignWsSecurityAsync(soapBytes);
```

### PAdES (PDF)

```csharp
var imzaliPdf = await signer.Pades.SignAsync(new SignPadesRequest
{
    Document = pdfBytes,
    AppendMode = true,                  // mevcut imzalar korunur
    Attachment = ekDosyaBytes,          // opsiyonel
    AttachmentFileName = "rapor.csv"    // opsiyonel
});
```

### CAdES (her türlü dosya)

```csharp
// Detached imza — orijinal dosya zarfa konmaz, sadece imza döner
var detached = await signer.Cades.SignAsync(byteIcerigi, detached: true);

// Attached imza — CMS zarfı orijinal içeriği de gömer
var attached = await signer.Cades.SignAsync(byteIcerigi);
```

### RFC 3161 Zaman Damgası

```csharp
var ts = await signer.Timestamp.GetAsync(belge);
// ts.Token         → binary .tst içeriği
// ts.TokenBase64   → CAdES/XAdES gömme için kolay format
// ts.Time, ts.TsaName, ts.SerialNumber, ts.HashAlgorithm

var report = await signer.Timestamp.ValidateAsync(new ValidateTimestampRequest
{
    TimestampToken    = ts.Token,
    OriginalDocument  = belge   // hash doğrulaması için (opsiyonel)
});

if (!report.Valid)
{
    foreach (var hata in report.Errors ?? new()) Console.WriteLine(hata);
}
```

### TÜBİTAK ESYA Kontör

```csharp
var kontor = await signer.Tubitak.GetCreditAsync();
Console.WriteLine($"Kalan kontör: {kontor.RemainingCredit}");
```

### Sertifika / Keystore Bilgisi

```csharp
var liste = await signer.Certificates.ListAsync();
foreach (var sert in liste.Certificates)
{
    Console.WriteLine($"{sert.Alias} — {sert.Subject} (geçerli: {sert.ValidTo:d})");
}

var info = await signer.Certificates.GetInfoAsync();
Console.WriteLine(info.KeystoreType);   // PKCS11 / PFX
```

#### İmzacı Sertifikayı Tek-Shot Alma (Manuel XAdES İçin)

Manuel `<ds:X509Certificate>` doldurmak (örn. UBL-TR 2.1 namespace prefix gereksinimi olan
özel akışlar) için aktif imzacı sertifikayı base64 encoded biçimde tek bir çağrıyla alabilirsiniz.
Sunucu `Cache-Control: private, max-age=3600, immutable` döndürür; reverse-proxy / in-memory
cache'ler tekrarlı çağrılarda 0-RTT lookup yapar.

```csharp
var imzaciSertifika = await signer.Certificates.GetSigningCertificateAsync();

Console.WriteLine($"Alias: {imzaciSertifika.Alias}");
Console.WriteLine($"Algoritma: {imzaciSertifika.PublicKeyAlgorithm}");     // RSA / EC
string base64Der = imzaciSertifika.Base64EncodedCertificate!;
// ds:X509Certificate elementine doğrudan basılabilir.
```

> **Not**: `Base64EncodedCertificate` alanı yalnızca bu endpoint'te doludur; `ListAsync()`
> yanıtında `null` kalır (50+ sertifika içeren HSM'lerde payload'un patlamaması için kasıtlı).

## Hata Yönetimi

Sunucu 4xx/5xx döndürürse istemci `DssSignerApiException` fırlatır. Sunucunun yapılandırılmış hata gövdesi (`code` + `message`) varsa `ApiError` üzerinden erişilir:

```csharp
try
{
    await signer.Xades.SignAsync(xml, DocumentType.UblDocument);
}
catch (DssSignerApiException ex)
{
    Console.Error.WriteLine($"[{(int)ex.StatusCode}] {ex.ApiError?.Code}: {ex.ApiError?.Message}");
}
```

## Polly / Retry / Logging

Paket altta `Microsoft.Extensions.Http` ve `IHttpClientFactory` üzerinde çalışır; standart retry/policy/logging genişletmeleri için kayıt sonrası `IHttpClientBuilder`'a kolayca eklenir:

```csharp
builder.Services.AddDssSignerClient(builder.Configuration);

builder.Services.AddHttpClient(DssSignerClientOptions.HttpClientName)
    .AddPolicyHandler(Policy<HttpResponseMessage>
        .Handle<HttpRequestException>()
        .OrResult(r => (int)r.StatusCode >= 500)
        .WaitAndRetryAsync(3, attempt => TimeSpan.FromSeconds(Math.Pow(2, attempt))));
```

## Desteklenen Platformlar

| Runtime | Durum | Çekilen `lib/` | Notlar |
|---|---|---|---|
| **.NET 8 LTS** | ✅ Birinci sınıf | `lib/net8.0/` | Inbox `HttpClient.ReadAs*Async(ct)`, `IAsyncDisposable`, `SocketsHttpHandler` (HTTP/2, TLS 1.3) |
| **.NET 9 (STS)** | ✅ Çalışır (roll-forward) | `lib/net8.0/` | net8 binary'si net9 runtime'da sorunsuz koşar |
| **.NET 10 LTS** | ✅ Çalışır (roll-forward) | `lib/net8.0/` | net8 binary'si net10 runtime'da sorunsuz koşar |
| **.NET 6 / 7 (EOL)** | ✅ Çalışır (fallback) | `lib/netstandard2.0/` | Polyfill DLL'leri (`System.Text.Json`, `Microsoft.Bcl.AsyncInterfaces`) sürüklenir; stream-read fazında `CancellationToken` honor edilmez (marjinal) |
| **.NET Framework 4.6.1 – 4.8.1** | ✅ Çalışır | `lib/netstandard2.0/` | TLS notunu aşağıda okuyun |
| **Mono 5.4+, Xamarin, Unity** | ✅ Çalışır | `lib/netstandard2.0/` | — |

> `Microsoft.Extensions.Http 8.0.x` tüm bu runtime'larda inbox `IHttpClientFactory` ile çalışır; ASP.NET Core bağımlılığı **yoktur**.

### .NET Framework için TLS 1.2 / 1.3 Notu

.NET Framework 4.6.1 – 4.8.x üzerinde TLS 1.2 default **değildir**. DSS Signer mikroservisi HTTPS bir reverse-proxy / API Gateway arkasındaysa, uygulama başlangıcında **bir kez** aşağıdaki ayarı yapın:

```csharp
// Program.cs / Application_Start / Main
ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12
                                     | SecurityProtocolType.Tls13;
```

> HTTP üzerinden (örn. internal Kubernetes service) çalışıyorsanız bu ayar gereksizdir.

## Gereksinimler

- Yukarıdaki tabloda listelenen runtime'lardan biri
- Çalışan bir [mersel-dss-server-signer-java](https://github.com/mersel-dss/mersel-dss-server-signer-java) mikroservisi

## Bağlantılar

- [Sunucu projesi](https://github.com/mersel-dss/mersel-dss-server-signer-java)
- [OpenAPI spesifikasyonu](https://github.com/mersel-dss/mersel-dss-server-signer-java/blob/main/openapi-snapshot/openapi.json)
