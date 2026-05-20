using MERSEL.Services.DssSigner.Client.Models;

namespace MERSEL.Services.DssSigner.Client.Interfaces;

/// <summary>
/// RFC 3161 zaman damgası operasyonları.
/// <c>/api/timestamp/*</c> endpoint'lerine karşılık gelir.
/// </summary>
public interface ITimestampClient
{
    /// <summary>
    /// Belirtilen belge için TSA'dan zaman damgası alır. Sunucu hash hesaplamasını,
    /// TSQ üretimini ve TSA çağrısını yönetir; istemciye binary TSR token döner.
    /// </summary>
    /// <param name="request">Belge ve hash algoritması.</param>
    /// <param name="ct">İptal belirteci.</param>
    /// <returns>Token içeriği ve metadata.</returns>
    Task<TimestampResult> GetAsync(GetTimestampRequest request, CancellationToken ct = default);

    /// <summary>
    /// Varsayılan SHA-256 hash ile zaman damgası almak için kısa yol overload'ı.
    /// </summary>
    Task<TimestampResult> GetAsync(byte[] document, CancellationToken ct = default);

    /// <summary>
    /// Bir zaman damgası token'ını doğrular. <see cref="ValidateTimestampRequest.OriginalDocument"/>
    /// sağlanırsa hash doğrulaması da yapılır.
    /// </summary>
    Task<TimestampValidationResult> ValidateAsync(ValidateTimestampRequest request, CancellationToken ct = default);

    /// <summary>
    /// Sadece token doğrulamak için kısa yol overload'ı (orijinal belge yok).
    /// </summary>
    Task<TimestampValidationResult> ValidateAsync(byte[] timestampToken, CancellationToken ct = default);

    /// <summary>
    /// Sunucu tarafında timestamp servisinin yapılandırılmış olup olmadığını kontrol eder.
    /// </summary>
    Task<TimestampStatusResult> GetStatusAsync(CancellationToken ct = default);
}
