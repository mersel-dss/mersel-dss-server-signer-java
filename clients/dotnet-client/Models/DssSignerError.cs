using System.Text.Json.Serialization;

namespace MERSEL.Services.DssSigner.Client.Models;

/// <summary>
/// Sunucudan dönen yapılandırılmış hata yanıtı.
/// API'nin <c>ErrorModel</c> tipine birebir karşılık gelir.
/// </summary>
public sealed class DssSignerError
{
    /// <summary>Hata kodu (örn. <c>INVALID_INPUT</c>, <c>SIGNATURE_FAILED</c>, <c>TIMESTAMP_NOT_CONFIGURED</c>).</summary>
    [JsonPropertyName("code")]
    public string? Code { get; set; }

    /// <summary>İnsan-okur formatında hata açıklaması.</summary>
    [JsonPropertyName("message")]
    public string? Message { get; set; }
}
