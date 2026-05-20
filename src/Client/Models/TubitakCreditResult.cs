using System.Text.Json.Serialization;

namespace MERSEL.Services.DssSigner.Client.Models;

/// <summary>
/// TÜBİTAK ESYA zaman damgası servisi kontör (kredi) sorgu yanıtı.
/// </summary>
public sealed class TubitakCreditResult
{
    /// <summary>Kalan kontör miktarı.</summary>
    [JsonPropertyName("remainingCredit")]
    public long? RemainingCredit { get; set; }

    /// <summary>TÜBİTAK müşteri kimliği.</summary>
    [JsonPropertyName("customerId")]
    public int? CustomerId { get; set; }

    /// <summary>Servis tarafından dönen mesaj.</summary>
    [JsonPropertyName("message")]
    public string? Message { get; set; }
}
