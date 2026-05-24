using MERSEL.Services.DssSigner.Client.Interfaces;
using MERSEL.Services.DssSigner.Client.Internal;
using MERSEL.Services.DssSigner.Client.Models;
using Microsoft.Extensions.Logging;

namespace MERSEL.Services.DssSigner.Client.Clients;

/// <summary>
/// TÜBİTAK ESYA zaman damgası servisine özel operasyonlar.
/// </summary>
internal sealed class TubitakClient : DssSignerHttpBase, ITubitakClient
{
    public TubitakClient(HttpClient httpClient, ILogger<TubitakClient> logger)
        : base(httpClient, logger)
    {
    }

    /// <inheritdoc />
    public Task<TubitakCreditResult> GetCreditAsync(CancellationToken ct = default)
        => GetJsonAsync<TubitakCreditResult>("/api/tubitak/credit", ct);
}
