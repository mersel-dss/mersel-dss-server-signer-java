using MERSEL.Services.DssSigner.Client.Interfaces;
using MERSEL.Services.DssSigner.Client.Internal;
using MERSEL.Services.DssSigner.Client.Models;
using Microsoft.Extensions.Logging;

namespace MERSEL.Services.DssSigner.Client.Clients;

/// <summary>
/// Pre-hashed digest imzalama operasyonlarını DSS Signer mikroservisinin
/// <c>POST /v1/hashsign</c> endpoint'i üzerinden gerçekleştirir.
/// </summary>
/// <remarks>
/// <para>
/// JSON gövdeli bir endpoint olduğu için multipart akışından farklıdır;
/// base sınıftaki <c>PostJsonAsync</c> helper'ı kullanılır.
/// </para>
/// </remarks>
internal sealed class HashSigner : DssSignerHttpBase, IHashSigner
{
    public HashSigner(HttpClient httpClient, ILogger<HashSigner> logger)
        : base(httpClient, logger)
    {
    }

    /// <inheritdoc />
    public Task<SignHashResult> SignAsync(
        byte[] digest,
        HashDigestAlgorithm digestAlgorithm = HashDigestAlgorithm.SHA256,
        CancellationToken ct = default)
    {
        if (digest is null || digest.Length == 0)
            throw new ArgumentException("Digest baytları boş olamaz.", nameof(digest));

        return SignAsync(new SignHashRequest
        {
            Base64EncodedDigest = Convert.ToBase64String(digest),
            DigestAlgorithm = digestAlgorithm
        }, ct);
    }

    /// <inheritdoc />
    public Task<SignHashResult> SignAsync(SignHashRequest request, CancellationToken ct = default)
    {
        if (request is null) throw new ArgumentNullException(nameof(request));
        if (string.IsNullOrWhiteSpace(request.Base64EncodedDigest))
            throw new ArgumentException(
                "SignHashRequest.Base64EncodedDigest zorunludur.",
                nameof(request));

        Logger.LogDebug(
            "DSS Signer hash imzalama isteği — algoritma: {Algoritma}, base64-uzunluk: {Uzunluk}",
            request.DigestAlgorithm,
            request.Base64EncodedDigest!.Length);

        return PostJsonAsync<SignHashRequest, SignHashResult>(
            "/v1/hashsign", request, ct, request.Headers);
    }
}
