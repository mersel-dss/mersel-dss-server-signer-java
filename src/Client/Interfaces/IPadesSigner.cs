using MERSEL.Services.DssSigner.Client.Models;

namespace MERSEL.Services.DssSigner.Client.Interfaces;

/// <summary>
/// PAdES (PDF Advanced Electronic Signature) operasyonları.
/// <c>POST /v1/padessign</c> endpoint'ine karşılık gelir.
/// </summary>
public interface IPadesSigner
{
    /// <summary>
    /// Bir PDF belgesini PAdES (CAdES-tabanlı) imza ile imzalar.
    /// </summary>
    /// <param name="request">İmza isteği. <see cref="SignPadesRequest.AppendMode"/>
    /// true verildiğinde mevcut imzalar geçerli kalacak şekilde incremental update yapılır.</param>
    /// <param name="ct">İptal belirteci.</param>
    /// <returns>İmzalı PDF içeriği.</returns>
    Task<SignResult> SignAsync(SignPadesRequest request, CancellationToken ct = default);

    /// <summary>
    /// Tek satırlık imzalama için kısa yol overload'ı (varsayılan ayarlar, attachment yok).
    /// </summary>
    Task<SignResult> SignAsync(byte[] pdfDocument, CancellationToken ct = default);
}
