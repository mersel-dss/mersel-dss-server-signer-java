using MERSEL.Services.DssSigner.Client.Models;

namespace MERSEL.Services.DssSigner.Client.Interfaces;

/// <summary>
/// TÜBİTAK ESYA zaman damgası servisine özel operasyonlar.
/// <c>/api/tubitak/*</c> endpoint'lerine karşılık gelir.
/// </summary>
public interface ITubitakClient
{
    /// <summary>
    /// TÜBİTAK ESYA zaman damgası servisi için kalan kontör (kredi) bilgisini sorgular.
    /// Sadece sunucu <c>IS_TUBITAK_TSP=true</c> olarak yapılandırıldıysa çalışır.
    /// </summary>
    Task<TubitakCreditResult> GetCreditAsync(CancellationToken ct = default);

    /// <summary>
    /// Per-request HTTP header'ları ile TÜBİTAK kontör sorgusu (örn. observability
    /// için <c>x-log-correlation-id</c>). Header'lar
    /// <see cref="DssSignerClientOptions.DefaultHeaders"/> üzerine binder.
    /// </summary>
    Task<TubitakCreditResult> GetCreditAsync(IDictionary<string, string> headers, CancellationToken ct = default);
}
