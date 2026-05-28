using MERSEL.Services.DssSigner.Client.Models;

namespace MERSEL.Services.DssSigner.Client.Interfaces;

/// <summary>
/// Sunucu tarafında yapılandırılmış keystore'dan sertifika listeleme ve
/// keystore meta bilgisini sorgulama operasyonları.
/// </summary>
public interface ICertificateInfoClient
{
    /// <summary>
    /// Yapılandırılmış keystore (PKCS#11 / PFX) içerisindeki tüm sertifikaları listeler.
    /// Alias ve serial number değerlerini öğrenmek için bu uçtan başlayın.
    /// </summary>
    Task<CertificateListResult> ListAsync(CancellationToken ct = default);

    /// <summary>
    /// Per-request HTTP header'ları ile sertifika listeleme.
    /// </summary>
    Task<CertificateListResult> ListAsync(IDictionary<string, string> headers, CancellationToken ct = default);

    /// <summary>
    /// Yapılandırılmış keystore'un genel bilgisini (tip, yol, slot vb.) döner.
    /// </summary>
    Task<KeystoreInfo> GetInfoAsync(CancellationToken ct = default);

    /// <summary>
    /// Per-request HTTP header'ları ile keystore meta bilgisini sorgular.
    /// </summary>
    Task<KeystoreInfo> GetInfoAsync(IDictionary<string, string> headers, CancellationToken ct = default);

    /// <summary>
    /// Aktif imza yapılandırmasındaki imzacı sertifikayı, base64 encoded biçimde de
    /// içerecek şekilde tek-shot olarak döner.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Listing endpoint'inin aksine alias/serial filtrelemesi yapılmaz; sunucu,
    /// başlangıçta resolve ettiği <c>SigningMaterial</c> singleton'ından doğrudan
    /// beslenir. Yanıt, manuel XAdES <c>&lt;ds:X509Certificate&gt;</c> elementi için
    /// kullanılabilen <see cref="CertificateInfo.Base64EncodedCertificate"/> alanını
    /// içerir; <see cref="CertificateInfo.HasPrivateKey"/> her zaman <c>true</c>'dur
    /// (HSM yolunda dahi, çünkü key handle token'da yaşar).
    /// </para>
    /// <para>
    /// Server tarafı <c>Cache-Control: private, max-age=3600, immutable</c> header'ı
    /// döndürür; reverse-proxy / in-memory cache'ler bu çağrıyı 0-RTT lookup ile
    /// karşılayabilir.
    /// </para>
    /// </remarks>
    Task<CertificateInfo> GetSigningCertificateAsync(CancellationToken ct = default);

    /// <summary>
    /// Per-request HTTP header'ları ile imzacı sertifika sorgusu.
    /// </summary>
    Task<CertificateInfo> GetSigningCertificateAsync(IDictionary<string, string> headers, CancellationToken ct = default);
}
