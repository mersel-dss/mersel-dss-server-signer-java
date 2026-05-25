using MERSEL.Services.DssSigner.Client.Models;

namespace MERSEL.Services.DssSigner.Client.Interfaces;

/// <summary>
/// XAdES (XML Advanced Electronic Signature) ve WS-Security operasyonları.
/// Sunucu tarafında <c>POST /v1/xadessign</c> ve <c>POST /v1/wssecuritysign</c>
/// endpoint'lerine karşılık gelir.
/// </summary>
public interface IXadesSigner
{
    /// <summary>
    /// Bir XML belgesini XAdES profili ile imzalar. İmza profili
    /// (<see cref="XadesSignatureLevel.XADES_BES"/> /
    /// <see cref="XadesSignatureLevel.XADES_A"/>) tamamen
    /// <see cref="SignXadesRequest.SignatureLevel"/> alanı ile belirlenir;
    /// <see cref="SignXadesRequest.DocumentType"/> seviye kararına <em>dahil değildir</em>.
    /// e-Fatura, e-Arşiv Raporu, e-İrsaliye, Uygulama Yanıtı, HrXml ve serbest
    /// XML belgeleri desteklenir.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Varsayılan davranış</b>: <see cref="SignXadesRequest.SignatureLevel"/>
    /// alanı set edilmediğinde <see cref="XadesSignatureLevel.XADES_BES"/> uygulanır
    /// — TSA çağrılmaz, kontör harcanmaz. e-Arşiv Raporu / e-Bilet Raporu gibi
    /// arşivsel akışlarda <see cref="XadesSignatureLevel.XADES_A"/>'nın talep
    /// edilmesi <em>çağıran tarafın sorumluluğundadır</em>.
    /// </para>
    /// <para>
    /// <see cref="XadesSignatureLevel.XADES_A"/> istenir ve sunucu tarafında TSA
    /// yapılandırılmamışsa istek HTTP 503 + <c>TIMESTAMP_ERROR</c> ile reddedilir.
    /// </para>
    /// </remarks>
    /// <param name="request">İmza isteği parametreleri.</param>
    /// <param name="ct">İptal belirteci.</param>
    /// <returns>İmzalı XML, ham imza değeri ve yanıt metadata'sı.</returns>
    Task<SignResult> SignAsync(SignXadesRequest request, CancellationToken ct = default);

    /// <summary>
    /// Bir XML belgesini varsayılan ayarlarla (ZipFile=false, SignatureId=null,
    /// SignatureLevel=<see cref="XadesSignatureLevel.XADES_BES"/>) XAdES ile
    /// imzalamak için kısa yol overload'ı.
    /// </summary>
    Task<SignResult> SignAsync(byte[] document, DocumentType documentType, CancellationToken ct = default);

    /// <summary>
    /// Bir SOAP zarfını WS-Security imzasıyla imzalar.
    /// SOAP 1.1/1.2 namespace'leri <see cref="SignWsSecurityRequest.Soap1Dot2"/>
    /// ile seçilir.
    /// </summary>
    Task<SignResult> SignWsSecurityAsync(SignWsSecurityRequest request, CancellationToken ct = default);

    /// <summary>
    /// Bir SOAP zarfını varsayılan ayarlarla (SOAP 1.1) imzalamak için kısa yol overload'ı.
    /// </summary>
    Task<SignResult> SignWsSecurityAsync(byte[] soapEnvelope, CancellationToken ct = default);
}
