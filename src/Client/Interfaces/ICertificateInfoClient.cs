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
    /// Yapılandırılmış keystore'un genel bilgisini (tip, yol, slot vb.) döner.
    /// </summary>
    Task<KeystoreInfo> GetInfoAsync(CancellationToken ct = default);
}
