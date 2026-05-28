using MERSEL.Services.DssSigner.Client.Interfaces;
using MERSEL.Services.DssSigner.Client.Internal;
using MERSEL.Services.DssSigner.Client.Models;
using Microsoft.Extensions.Logging;

namespace MERSEL.Services.DssSigner.Client.Clients;

/// <summary>
/// PAdES (PDF) imzalama operasyonlarını DSS Signer mikroservisi üzerinden gerçekleştirir.
/// </summary>
internal sealed class PadesSigner : DssSignerHttpBase, IPadesSigner
{
    public PadesSigner(HttpClient httpClient, ILogger<PadesSigner> logger)
        : base(httpClient, logger)
    {
    }

    /// <inheritdoc />
    public Task<SignResult> SignAsync(byte[] pdfDocument, CancellationToken ct = default)
        => SignAsync(new SignPadesRequest { Document = pdfDocument }, ct);

    /// <inheritdoc />
    public async Task<SignResult> SignAsync(SignPadesRequest request, CancellationToken ct = default)
    {
        if (request is null) throw new ArgumentNullException(nameof(request));
        if (request.Document is null || request.Document.Length == 0)
            throw new ArgumentException("PDF içeriği boş olamaz.", nameof(request));

        Logger.LogDebug(
            "DSS Signer PAdES isteği — boyut: {Boyut} bayt, append: {Append}, attachment: {Att}",
            request.Document.Length, request.AppendMode, request.Attachment is not null);

        using var form = new MultipartFormDataContent();
        AddFilePart(form, "document", request.Document, request.FileName, "application/pdf");
        AddStringPart(form, "appendMode", request.AppendMode ? "true" : "false");

        if (request.Attachment is { Length: > 0 })
        {
            var attachmentName = string.IsNullOrEmpty(request.AttachmentFileName)
                ? "attachment.bin"
                : request.AttachmentFileName!;
            AddFilePart(form, "attachment", request.Attachment, attachmentName);
            AddStringPart(form, "attachmentFileName", attachmentName);
        }

        using var response = await PostMultipartBinaryAsync(
            "/v1/padessign", form, ct, request.Headers).ConfigureAwait(false);
        var bytes = await ReadResponseBytesAsync(response, ct).ConfigureAwait(false);

        return new SignResult
        {
            SignedDocument = bytes,
            SuggestedFileName = ExtractFileName(response),
            ContentType = response.Content.Headers.ContentType?.MediaType
        };
    }
}
