namespace MERSEL.Services.DssSigner.Client.Models;

/// <summary>
/// Zaman damgası alma isteği parametreleri.
/// Sunucu, belgenin hash'ini hesaplayıp TSA'ya RFC 3161 TSQ olarak iletir
/// ve dönen TSR token'ını binary olarak istemciye geri gönderir.
/// </summary>
public sealed class GetTimestampRequest
{
    /// <summary>Zaman damgası alınacak dosyanın ham içeriği.</summary>
    public byte[] Document { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// Hash algoritması. Yaygın değerler için <see cref="TimestampHashAlgorithm"/>
    /// sabitlerini kullanın. Varsayılan: <c>SHA256</c>.
    /// </summary>
    public string HashAlgorithm { get; set; } = TimestampHashAlgorithm.Sha256;

    /// <summary>İsteğe konacak multipart dosya adı.</summary>
    public string FileName { get; set; } = "document.bin";
}
