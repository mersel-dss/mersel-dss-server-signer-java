using System.Text.Json.Serialization;

namespace MERSEL.Services.DssSigner.Client.Models;

/// <summary>
/// Sunucudan dönen zaman damgası doğrulama raporu.
/// API'nin <c>TimestampValidationResponseDto</c> tipine birebir karşılık gelir.
/// </summary>
public sealed class TimestampValidationResult
{
    /// <summary>Token kriptografik olarak geçerli mi?</summary>
    [JsonPropertyName("valid")]
    public bool Valid { get; set; }

    /// <summary>Token'ın damgaladığı zaman (ISO 8601 string).</summary>
    [JsonPropertyName("timestamp")]
    public string? Timestamp { get; set; }

    /// <summary>TSA tanımlayıcısı.</summary>
    [JsonPropertyName("tsaName")]
    public string? TsaName { get; set; }

    /// <summary>Hash algoritması (insan okur formatta).</summary>
    [JsonPropertyName("hashAlgorithm")]
    public string? HashAlgorithm { get; set; }

    /// <summary>Hash algoritması OID.</summary>
    [JsonPropertyName("hashAlgorithmOid")]
    public string? HashAlgorithmOid { get; set; }

    /// <summary>Token seri numarası.</summary>
    [JsonPropertyName("serialNumber")]
    public string? SerialNumber { get; set; }

    /// <summary>Nonce.</summary>
    [JsonPropertyName("nonce")]
    public string? Nonce { get; set; }

    /// <summary>İmza algoritması (insan okur formatta).</summary>
    [JsonPropertyName("signatureAlgorithm")]
    public string? SignatureAlgorithm { get; set; }

    /// <summary>İmza algoritması OID.</summary>
    [JsonPropertyName("signatureAlgorithmOid")]
    public string? SignatureAlgorithmOid { get; set; }

    /// <summary>TSA sertifikası (Base64 PEM formatında).</summary>
    [JsonPropertyName("tsaCertificate")]
    public string? TsaCertificate { get; set; }

    /// <summary>TSA sertifikası geçerli mi?</summary>
    [JsonPropertyName("certificateValid")]
    public bool? CertificateValid { get; set; }

    /// <summary>Sertifika başlangıç tarihi (ISO 8601 string).</summary>
    [JsonPropertyName("certificateNotBefore")]
    public string? CertificateNotBefore { get; set; }

    /// <summary>Sertifika bitiş tarihi (ISO 8601 string).</summary>
    [JsonPropertyName("certificateNotAfter")]
    public string? CertificateNotAfter { get; set; }

    /// <summary>
    /// Hash doğrulaması başarılı mı? Sadece <c>OriginalDocument</c> sağlandığında değer alır.
    /// </summary>
    [JsonPropertyName("hashVerified")]
    public bool? HashVerified { get; set; }

    /// <summary>Doğrulama hataları/uyarıları.</summary>
    [JsonPropertyName("errors")]
    public List<string>? Errors { get; set; }

    /// <summary>Genel durum mesajı.</summary>
    [JsonPropertyName("message")]
    public string? Message { get; set; }
}
