namespace MERSEL.Services.DssSigner.Client.Models;

/// <summary>
/// Sunucudan dönen RFC 3161 zaman damgası yanıtı.
/// Token binary gövdede; metadata <c>X-Timestamp-*</c> header'larından okunur.
/// </summary>
public sealed class TimestampResult
{
    /// <summary>Binary timestamp token (.tst dosyasının ham içeriği, RFC 3161 TSR).</summary>
    public byte[] Token { get; init; } = Array.Empty<byte>();

    /// <summary>
    /// Token'ı Base64 olarak verir. CMS/CAdES gömme operasyonlarında bu format kullanışlıdır.
    /// </summary>
    public string TokenBase64 => Convert.ToBase64String(Token);

    /// <summary>Sunucu Content-Disposition'da önerdiği dosya adı (örn. <c>timestamp.tst</c>).</summary>
    public string? SuggestedFileName { get; init; }

    /// <summary>TSA'nın damgaladığı zaman (ISO 8601). <c>X-Timestamp-Time</c> header'ından okunur.</summary>
    public string? Time { get; init; }

    /// <summary>TSA tanımlayıcı bilgisi (örn. <c>CN=TÜBİTAK ESYA TSS, O=TÜBİTAK, C=TR</c>).</summary>
    public string? TsaName { get; init; }

    /// <summary>Token seri numarası.</summary>
    public string? SerialNumber { get; init; }

    /// <summary>Kullanılan hash algoritması (sunucudan dönen).</summary>
    public string? HashAlgorithm { get; init; }

    /// <summary>Token nonce değeri (varsa).</summary>
    public string? Nonce { get; init; }
}
