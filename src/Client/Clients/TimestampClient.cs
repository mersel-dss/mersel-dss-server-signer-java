using MERSEL.Services.DssSigner.Client.Interfaces;
using MERSEL.Services.DssSigner.Client.Internal;
using MERSEL.Services.DssSigner.Client.Models;
using Microsoft.Extensions.Logging;

namespace MERSEL.Services.DssSigner.Client.Clients;

/// <summary>
/// RFC 3161 zaman damgası operasyonlarını DSS Signer mikroservisi üzerinden gerçekleştirir.
/// </summary>
internal sealed class TimestampClient : DssSignerHttpBase, ITimestampClient
{
    public TimestampClient(HttpClient httpClient, ILogger<TimestampClient> logger)
        : base(httpClient, logger)
    {
    }

    /// <inheritdoc />
    public Task<TimestampResult> GetAsync(byte[] document, CancellationToken ct = default)
        => GetAsync(new GetTimestampRequest { Document = document }, ct);

    /// <inheritdoc />
    public async Task<TimestampResult> GetAsync(GetTimestampRequest request, CancellationToken ct = default)
    {
        if (request is null) throw new ArgumentNullException(nameof(request));
        if (request.Document is null || request.Document.Length == 0)
            throw new ArgumentException("Belge içeriği boş olamaz.", nameof(request));
        if (string.IsNullOrWhiteSpace(request.HashAlgorithm))
            throw new ArgumentException("HashAlgorithm boş olamaz.", nameof(request));

        Logger.LogDebug(
            "DSS Signer timestamp isteği — boyut: {Boyut} bayt, hash: {Hash}",
            request.Document.Length, request.HashAlgorithm);

        using var form = new MultipartFormDataContent();
        AddFilePart(form, "document", request.Document, request.FileName);

        var path = $"/api/timestamp/get?hashAlgorithm={Uri.EscapeDataString(request.HashAlgorithm)}";

        using var response = await PostMultipartBinaryAsync(path, form, ct).ConfigureAwait(false);
        var bytes = await ReadResponseBytesAsync(response, ct).ConfigureAwait(false);

        return new TimestampResult
        {
            Token = bytes,
            SuggestedFileName = ExtractFileName(response),
            Time = FirstHeaderOrDefault(response, "X-Timestamp-Time"),
            TsaName = FirstHeaderOrDefault(response, "X-Timestamp-TSA"),
            SerialNumber = FirstHeaderOrDefault(response, "X-Timestamp-Serial"),
            HashAlgorithm = FirstHeaderOrDefault(response, "X-Timestamp-Hash-Algorithm"),
            Nonce = FirstHeaderOrDefault(response, "X-Timestamp-Nonce")
        };
    }

    /// <inheritdoc />
    public Task<TimestampValidationResult> ValidateAsync(byte[] timestampToken, CancellationToken ct = default)
        => ValidateAsync(new ValidateTimestampRequest { TimestampToken = timestampToken }, ct);

    /// <inheritdoc />
    public async Task<TimestampValidationResult> ValidateAsync(ValidateTimestampRequest request, CancellationToken ct = default)
    {
        if (request is null) throw new ArgumentNullException(nameof(request));
        if (request.TimestampToken is null || request.TimestampToken.Length == 0)
            throw new ArgumentException("TimestampToken içeriği boş olamaz.", nameof(request));

        Logger.LogDebug(
            "DSS Signer timestamp doğrulama — token: {Token} bayt, originalDoc: {HasDoc}",
            request.TimestampToken.Length, request.OriginalDocument is not null);

        using var form = new MultipartFormDataContent();
        AddFilePart(form, "timestampToken", request.TimestampToken, request.TokenFileName);
        if (request.OriginalDocument is { Length: > 0 })
        {
            AddFilePart(form, "originalDocument", request.OriginalDocument, request.OriginalDocumentFileName);
        }

        return await PostMultipartJsonAsync<TimestampValidationResult>(
            "/api/timestamp/validate", form, ct).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public Task<TimestampStatusResult> GetStatusAsync(CancellationToken ct = default)
        => GetJsonAsync<TimestampStatusResult>("/api/timestamp/status", ct);
}
