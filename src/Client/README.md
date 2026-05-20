# MERSEL.Services.DssSigner.Client

[mersel-dss-server-signer-java](https://github.com/mersel-dss/mersel-dss-server-signer-java) mikroservisini HTTP üzerinden çağıran **istemci SDK'sı**.

`net6.0`, `net7.0`, `net8.0` ve `net9.0` hedeflerini destekler. Tek satır DI kaydıyla tüm imzalama (XAdES, WS-Security, PAdES, CAdES), zaman damgası (RFC 3161 + TÜBİTAK ESYA) ve sertifika operasyonlarını uygulamanıza entegre edin. Servis stateless'tir; istemcide herhangi bir özel state tutulmaz, paket güvenle çoklu instance ile kullanılabilir.

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
    o.ApiKey  = "secret-key";   // opsiyonel; X-API-Key header'ı olarak gider
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
      "Timeout": "00:02:00",
      "ApiKey": "...",
      "BasicAuthUsername": null,
      "BasicAuthPassword": null
    }
  }
}
```

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
        var result = await signer.Xades.SignAsync(ublXml, DocumentType.UblDocument, ct);
        // result.SignedDocument → imzalı XML
        // result.SignatureValue → x-signature-value header'ı (Base64)
        return result.SignedDocument;
    }
}
```

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

## Gereksinimler

- .NET 6.0, 7.0, 8.0 veya 9.0
- Çalışan bir [mersel-dss-server-signer-java](https://github.com/mersel-dss/mersel-dss-server-signer-java) mikroservisi

## Bağlantılar

- [Sunucu projesi](https://github.com/mersel-dss/mersel-dss-server-signer-java)
- [OpenAPI spesifikasyonu](https://github.com/mersel-dss/mersel-dss-server-signer-java/blob/main/openapi-snapshot/openapi.json)
