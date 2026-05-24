namespace MERSEL.Services.DssSigner.Client.Models;

/// <summary>
/// XAdES imza isteği parametreleri.
/// </summary>
public sealed class SignXadesRequest
{
    /// <summary>İmzalanacak XML içeriği (binary).</summary>
    public byte[] Document { get; set; } = Array.Empty<byte>();

    /// <summary>Belge tipi. Sunucu tarafında imzalama profilini belirler.</summary>
    public DocumentType DocumentType { get; set; } = DocumentType.OtherXmlDocument;

    /// <summary>
    /// İmza içerisine yazılacak <c>SignatureId</c> XML attribute değeri.
    /// Boş bırakılırsa sunucu rastgele üretir.
    /// </summary>
    public string? SignatureId { get; set; }

    /// <summary>
    /// <c>true</c> ise belge ZIP içinde gönderilmiş olarak işaretlenir
    /// (sunucu çıkarır ve içeriği imzalar). Varsayılan: <c>false</c>.
    /// </summary>
    public bool ZipFile { get; set; }

    /// <summary>
    /// İsteğe konacak dosya adı (multipart filename). Sadece sunucu loglarına yansır,
    /// imzalama mantığını etkilemez.
    /// </summary>
    public string FileName { get; set; } = "document.xml";
}
