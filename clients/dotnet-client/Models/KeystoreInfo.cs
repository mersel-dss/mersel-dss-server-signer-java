using System.Text.Json.Serialization;

namespace MERSEL.Services.DssSigner.Client.Models;

/// <summary>
/// <c>GET /api/certificates/info</c> yanıtı.
/// Sunucu, keystore türüne göre farklı alanları doldurur.
/// </summary>
public sealed class KeystoreInfo
{
    /// <summary>Çağrı başarılı mı?</summary>
    [JsonPropertyName("success")]
    public bool Success { get; set; }

    /// <summary>Keystore tipi (örn. <c>PKCS11</c>, <c>PFX</c>).</summary>
    [JsonPropertyName("keystoreType")]
    public string? KeystoreType { get; set; }

    /// <summary>PKCS#11 kütüphanesi yolu (yalnızca PKCS#11 keystore'larda).</summary>
    [JsonPropertyName("library")]
    public string? Library { get; set; }

    /// <summary>PKCS#11 slot numarası (yalnızca PKCS#11 keystore'larda).</summary>
    [JsonPropertyName("slot")]
    public string? Slot { get; set; }

    /// <summary>PFX dosya yolu (yalnızca PFX keystore'larda).</summary>
    [JsonPropertyName("pfxPath")]
    public string? PfxPath { get; set; }

    /// <summary>İmzalama için kullanılan sertifika alias'ı.</summary>
    [JsonPropertyName("certificateAlias")]
    public string? CertificateAlias { get; set; }

    /// <summary>İmzalama sertifikasının seri numarası.</summary>
    [JsonPropertyName("certificateSerialNumber")]
    public string? CertificateSerialNumber { get; set; }

    /// <summary>Hata mesajı (success=false ise).</summary>
    [JsonPropertyName("error")]
    public string? Error { get; set; }
}
