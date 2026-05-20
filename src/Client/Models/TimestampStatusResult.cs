using System.Text.Json.Serialization;

namespace MERSEL.Services.DssSigner.Client.Models;

/// <summary>
/// Timestamp servisinin yapılandırma/uygunluk durumu.
/// </summary>
public sealed class TimestampStatusResult
{
    /// <summary>Servis yapılandırılmış ve kullanıma hazır mı?</summary>
    [JsonPropertyName("configured")]
    public bool Configured { get; set; }

    /// <summary>Açıklayıcı durum mesajı.</summary>
    [JsonPropertyName("message")]
    public string? Message { get; set; }
}
