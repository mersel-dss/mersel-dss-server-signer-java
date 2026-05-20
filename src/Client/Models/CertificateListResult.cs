using System.Text.Json.Serialization;

namespace MERSEL.Services.DssSigner.Client.Models;

/// <summary>
/// <c>GET /api/certificates/list</c> yanıtı.
/// </summary>
public sealed class CertificateListResult
{
    /// <summary>Çağrı başarılı mı?</summary>
    [JsonPropertyName("success")]
    public bool Success { get; set; }

    /// <summary>Keystore tipi (örn. <c>PKCS11</c>, <c>PFX</c>).</summary>
    [JsonPropertyName("keystoreType")]
    public string? KeystoreType { get; set; }

    /// <summary>Listelenen sertifika sayısı.</summary>
    [JsonPropertyName("certificateCount")]
    public int CertificateCount { get; set; }

    /// <summary>Sertifika listesi.</summary>
    [JsonPropertyName("certificates")]
    public List<CertificateInfo> Certificates { get; set; } = new();

    /// <summary>Hata mesajı (success=false ise).</summary>
    [JsonPropertyName("error")]
    public string? Error { get; set; }
}
