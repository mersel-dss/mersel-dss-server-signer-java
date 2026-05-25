using System.Text.Json.Serialization;

namespace MERSEL.Services.DssSigner.Client.Models;

/// <summary>
/// Keystore içerisindeki bir sertifikanın detay bilgileri.
/// API'nin <c>CertificateInfoDto</c> tipine birebir karşılık gelir.
/// </summary>
public sealed class CertificateInfo
{
    /// <summary>Sertifika alias'ı (keystore içindeki benzersiz adı).</summary>
    [JsonPropertyName("alias")]
    public string? Alias { get; set; }

    /// <summary>Seri numarası (hex).</summary>
    [JsonPropertyName("serialNumberHex")]
    public string? SerialNumberHex { get; set; }

    /// <summary>Seri numarası (decimal).</summary>
    [JsonPropertyName("serialNumberDec")]
    public string? SerialNumberDec { get; set; }

    /// <summary>Sertifika konusu (subject DN).</summary>
    [JsonPropertyName("subject")]
    public string? Subject { get; set; }

    /// <summary>Sertifika düzenleyicisi (issuer DN).</summary>
    [JsonPropertyName("issuer")]
    public string? Issuer { get; set; }

    /// <summary>Geçerlilik başlangıç tarihi.</summary>
    [JsonPropertyName("validFrom")]
    public DateTimeOffset? ValidFrom { get; set; }

    /// <summary>Geçerlilik bitiş tarihi.</summary>
    [JsonPropertyName("validTo")]
    public DateTimeOffset? ValidTo { get; set; }

    /// <summary>Bu alias için private key keystore'da mevcut mu?</summary>
    [JsonPropertyName("hasPrivateKey")]
    public bool? HasPrivateKey { get; set; }

    /// <summary>Sertifika tipi (örn. <c>X.509</c>).</summary>
    [JsonPropertyName("type")]
    public string? Type { get; set; }

    /// <summary>İmza algoritması.</summary>
    [JsonPropertyName("signatureAlgorithm")]
    public string? SignatureAlgorithm { get; set; }

    /// <summary>Sertifika kullanım alanları.</summary>
    [JsonPropertyName("keyUsage")]
    public string? KeyUsage { get; set; }

    /// <summary>Genişletilmiş kullanım alanları.</summary>
    [JsonPropertyName("extendedKeyUsage")]
    public string? ExtendedKeyUsage { get; set; }

    /// <summary>Sertifika politikaları (Certificate Policies OIDs).</summary>
    [JsonPropertyName("certificatePolicies")]
    public string? CertificatePolicies { get; set; }

    /// <summary>
    /// Public key algoritması (örn. <c>RSA</c>, <c>EC</c>).
    /// PR #20 ile eklendi.
    /// </summary>
    [JsonPropertyName("publicKeyAlgorithm")]
    public string? PublicKeyAlgorithm { get; set; }

    /// <summary>
    /// Base64 encoded X.509 sertifika (DER kodlamanın base64'lenmiş hali).
    /// </summary>
    /// <remarks>
    /// Yalnızca <c>/api/certificates/signingCertificate</c> endpoint'i bu alanı
    /// doldurur; <c>/api/certificates/list</c> yanıtında <c>null</c> kalır
    /// (50+ sertifika içeren HSM'lerde payload'un patlamaması için kasıtlı).
    /// Manuel XAdES <c>&lt;ds:X509Certificate&gt;</c> elementi doldurmak için kullanılır.
    /// </remarks>
    [JsonPropertyName("base64EncodedCertificate")]
    public string? Base64EncodedCertificate { get; set; }
}
