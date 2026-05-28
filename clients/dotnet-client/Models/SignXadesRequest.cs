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

    /// <summary>
    /// XAdES imza profili. API kontratı gereği <em>asla null değildir</em>;
    /// varsayılan <see cref="XadesSignatureLevel.XADES_BES"/>'tir
    /// (timestamp eklenmez, TSA çağrılmaz, kontör harcanmaz).
    /// </summary>
    /// <remarks>
    /// <see cref="XadesSignatureLevel.XADES_A"/> istenirse arşiv timestamp eklenir;
    /// sunucu tarafında TSA yapılandırılmamışsa istek 503 / <c>TIMESTAMP_ERROR</c>
    /// ile reddedilir.
    /// <para>
    /// <b>Önemli</b>: <see cref="DocumentType"/> artık seviye kararına dahil
    /// <em>değildir</em>. Rapor akışında XADES_A istenecekse bu alanın explicit
    /// olarak set edilmesi gerekir.
    /// </para>
    /// </remarks>
    public XadesSignatureLevel SignatureLevel { get; set; } = XadesSignatureLevel.XADES_BES;

    /// <summary>
    /// Bu çağrıya özel HTTP header'ları. Yaygın kullanım:
    /// <see cref="DssSignerClientOptions.DefaultHeaders"/> üzerine yazma,
    /// <c>x-log-correlation-id</c>, <c>x-log-tenant</c> gibi observability
    /// header'larıyla istek bazında MDC zenginleştirme veya gateway authorization
    /// header'ı override etme.
    /// </summary>
    /// <remarks>
    /// Bu sözlükteki anahtarlar <see cref="DssSignerClientOptions.DefaultHeaders"/>
    /// ile aynı isimli alanları override eder. Karşılaştırma büyük/küçük harf
    /// duyarsız tutulmalıdır (HTTP header semantiği). <c>null</c> ise hiçbir ek
    /// header eklenmez.
    /// </remarks>
    public IDictionary<string, string>? Headers { get; set; }
}
