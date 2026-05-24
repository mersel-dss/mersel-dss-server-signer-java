namespace MERSEL.Services.DssSigner.Client.Models;

/// <summary>
/// CAdES-BES imzalama isteği.
/// </summary>
public sealed class SignCadesRequest
{
    /// <summary>İmzalanacak ham veri (her türlü dosya formatı).</summary>
    public byte[] Document { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// <c>true</c> ise ayrık (detached) imza üretilir; orijinal belge zarfa konmaz,
    /// yalnızca imza verisi döner. <c>false</c> ise gömülü (attached) imza üretilir.
    /// Varsayılan: <c>false</c>.
    /// </summary>
    public bool Detached { get; set; }

    /// <summary>İsteğe konacak multipart dosya adı.</summary>
    public string FileName { get; set; } = "document.bin";
}
