namespace MERSEL.Services.DssSigner.Client.Models;

/// <summary>
/// İmzalama sonucunu temsil eden ortak yanıt tipi.
/// XAdES, WS-Security ve detached CAdES için <see cref="SignatureValue"/> set edilir;
/// PAdES ve attached CAdES için sadece <see cref="SignedDocument"/> dolar.
/// </summary>
public sealed class SignResult
{
    /// <summary>
    /// Sunucudan dönen imzalı belgenin ham içeriği:
    /// <list type="bullet">
    ///   <item>XAdES → imzalı XML</item>
    ///   <item>WS-Security → imzalı SOAP zarfı</item>
    ///   <item>PAdES → imzalı PDF</item>
    ///   <item>CAdES (attached) → CMS zarfı (.p7s, içerik gömülü)</item>
    ///   <item>CAdES (detached) → yalnızca imza verisi (.p7s)</item>
    /// </list>
    /// </summary>
    public byte[] SignedDocument { get; init; } = Array.Empty<byte>();

    /// <summary>
    /// <c>x-signature-value</c> response header'ından okunan Base64 imza değeri.
    /// XAdES, WS-Security ve detached CAdES için doludur; PAdES ve attached CAdES'te <c>null</c>.
    /// </summary>
    public string? SignatureValue { get; init; }

    /// <summary>
    /// <c>Content-Disposition</c> header'ından çıkarılan önerilen dosya adı.
    /// Sunucu her istekte UUID tabanlı bir ad üretir (örn. <c>signed-{guid}.xml</c>).
    /// </summary>
    public string? SuggestedFileName { get; init; }

    /// <summary>Yanıtın Content-Type değeri (örn. <c>application/octet-stream</c>).</summary>
    public string? ContentType { get; init; }
}
