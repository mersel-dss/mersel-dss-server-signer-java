using MERSEL.Services.DssSigner.Client.Interfaces;
using MERSEL.Services.DssSigner.Client.Internal;
using MERSEL.Services.DssSigner.Client.Models;
using Microsoft.Extensions.Logging;

namespace MERSEL.Services.DssSigner.Client.Clients;

/// <summary>
/// XAdES (XML Advanced Electronic Signature) ve WS-Security imzalama operasyonlarını
/// DSS Signer mikroservisi üzerinden gerçekleştiren HTTP istemcisi.
/// </summary>
internal sealed class XadesSigner : DssSignerHttpBase, IXadesSigner
{
    public XadesSigner(HttpClient httpClient, ILogger<XadesSigner> logger)
        : base(httpClient, logger)
    {
    }

    /// <inheritdoc />
    public Task<SignResult> SignAsync(byte[] document, DocumentType documentType, CancellationToken ct = default)
        => SignAsync(new SignXadesRequest { Document = document, DocumentType = documentType }, ct);

    /// <inheritdoc />
    public async Task<SignResult> SignAsync(SignXadesRequest request, CancellationToken ct = default)
    {
        if (request is null) throw new ArgumentNullException(nameof(request));
        if (request.Document is null || request.Document.Length == 0)
            throw new ArgumentException("Belge içeriği boş olamaz.", nameof(request));
        if (request.DocumentType == DocumentType.None)
            throw new ArgumentException("DocumentType.None gönderilemez; geçerli bir XML belge tipi seçin.", nameof(request));

        Logger.LogDebug(
            "DSS Signer XAdES isteği — boyut: {Boyut} bayt, tip: {Tip}, zip: {Zip}, seviye: {Seviye}",
            request.Document.Length, request.DocumentType, request.ZipFile, request.SignatureLevel);

        using var form = new MultipartFormDataContent();
        AddFilePart(form, "document", request.Document, request.FileName, "application/xml");
        AddStringPart(form, "documentType", request.DocumentType.ToString());
        AddStringPart(form, "zipFile", request.ZipFile ? "true" : "false");
        AddStringPart(form, "signatureId", request.SignatureId);
        // signatureLevel asla null değildir (default XADES_BES); enum sabit ismi
        // sunucu Java enum'u ile birebir eşleşir (XADES_BES / XADES_A).
        AddStringPart(form, "signatureLevel", request.SignatureLevel.ToString());

        using var response = await PostMultipartBinaryAsync(
            "/v1/xadessign", form, ct, request.Headers).ConfigureAwait(false);
        return await BuildSignResultAsync(response, ct).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public Task<SignResult> SignWsSecurityAsync(byte[] soapEnvelope, CancellationToken ct = default)
        => SignWsSecurityAsync(new SignWsSecurityRequest { Document = soapEnvelope }, ct);

    /// <inheritdoc />
    public async Task<SignResult> SignWsSecurityAsync(SignWsSecurityRequest request, CancellationToken ct = default)
    {
        if (request is null) throw new ArgumentNullException(nameof(request));
        if (request.Document is null || request.Document.Length == 0)
            throw new ArgumentException("SOAP zarfı boş olamaz.", nameof(request));

        Logger.LogDebug(
            "DSS Signer WS-Security isteği — boyut: {Boyut} bayt, soap1.2: {Soap12}",
            request.Document.Length, request.Soap1Dot2);

        using var form = new MultipartFormDataContent();
        AddFilePart(form, "document", request.Document, request.FileName, "application/xml");
        AddStringPart(form, "soap1Dot2", request.Soap1Dot2 ? "true" : "false");

        using var response = await PostMultipartBinaryAsync(
            "/v1/wssecuritysign", form, ct, request.Headers).ConfigureAwait(false);
        return await BuildSignResultAsync(response, ct).ConfigureAwait(false);
    }

    private static async Task<SignResult> BuildSignResultAsync(HttpResponseMessage response, CancellationToken ct)
    {
        var bytes = await ReadResponseBytesAsync(response, ct).ConfigureAwait(false);
        return new SignResult
        {
            SignedDocument = bytes,
            SignatureValue = FirstHeaderOrDefault(response, "x-signature-value"),
            SuggestedFileName = ExtractFileName(response),
            ContentType = response.Content.Headers.ContentType?.MediaType
        };
    }
}
