namespace MERSEL.Services.DssSigner.Client.Models;

/// <summary>
/// Zaman damgası doğrulama isteği.
/// </summary>
public sealed class ValidateTimestampRequest
{
    /// <summary>Doğrulanacak timestamp token (.tst).</summary>
    public byte[] TimestampToken { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// Orijinal belge. Sağlandığında sunucu hash doğrulaması da yapar
    /// (token'ın gerçekten bu belgeye ait olduğunu kanıtlar).
    /// </summary>
    public byte[]? OriginalDocument { get; set; }

    /// <summary>Token için multipart dosya adı.</summary>
    public string TokenFileName { get; set; } = "timestamp.tst";

    /// <summary>Orijinal belge için multipart dosya adı.</summary>
    public string OriginalDocumentFileName { get; set; } = "document.bin";

    /// <summary>
    /// Bu çağrıya özel HTTP header'ları
    /// (<see cref="DssSignerClientOptions.DefaultHeaders"/> override'ı için).
    /// </summary>
    public IDictionary<string, string>? Headers { get; set; }
}
