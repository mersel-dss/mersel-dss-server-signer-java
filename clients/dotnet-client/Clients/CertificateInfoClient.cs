using MERSEL.Services.DssSigner.Client.Interfaces;
using MERSEL.Services.DssSigner.Client.Internal;
using MERSEL.Services.DssSigner.Client.Models;
using Microsoft.Extensions.Logging;

namespace MERSEL.Services.DssSigner.Client.Clients;

/// <summary>
/// Sunucudaki keystore üzerinde sertifika listesi ve meta bilgi sorgulama operasyonları.
/// </summary>
internal sealed class CertificateInfoClient : DssSignerHttpBase, ICertificateInfoClient
{
    public CertificateInfoClient(HttpClient httpClient, ILogger<CertificateInfoClient> logger)
        : base(httpClient, logger)
    {
    }

    /// <inheritdoc />
    public Task<CertificateListResult> ListAsync(CancellationToken ct = default)
        => GetJsonAsync<CertificateListResult>("/api/certificates/list", ct);

    /// <inheritdoc />
    public Task<KeystoreInfo> GetInfoAsync(CancellationToken ct = default)
        => GetJsonAsync<KeystoreInfo>("/api/certificates/info", ct);

    /// <inheritdoc />
    public Task<CertificateInfo> GetSigningCertificateAsync(CancellationToken ct = default)
        => GetJsonAsync<CertificateInfo>("/api/certificates/signingCertificate", ct);
}
