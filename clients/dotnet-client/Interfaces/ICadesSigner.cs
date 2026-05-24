using MERSEL.Services.DssSigner.Client.Models;

namespace MERSEL.Services.DssSigner.Client.Interfaces;

/// <summary>
/// CAdES-BES (CMS Advanced Electronic Signature) operasyonları.
/// <c>POST /v1/cadessign</c> endpoint'ine karşılık gelir.
/// </summary>
public interface ICadesSigner
{
    /// <summary>
    /// Bir dosyayı CAdES-BES profili ile imzalar.
    /// </summary>
    /// <param name="request">İmza isteği. <see cref="SignCadesRequest.Detached"/>
    /// false ise CMS zarfı içeriği gömerek döner; true ise yalnızca imza verisi döner ve
    /// sunucu <c>x-signature-value</c> header'ını da set eder.</param>
    /// <param name="ct">İptal belirteci.</param>
    /// <returns>.p7s içeriği ve metadata.</returns>
    Task<SignResult> SignAsync(SignCadesRequest request, CancellationToken ct = default);

    /// <summary>
    /// Varsayılan ayarlarla (attached imza) CAdES imzası oluşturmak için kısa yol overload'ı.
    /// </summary>
    Task<SignResult> SignAsync(byte[] document, bool detached = false, CancellationToken ct = default);
}
