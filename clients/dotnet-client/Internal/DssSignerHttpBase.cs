using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using MERSEL.Services.DssSigner.Client.Exceptions;
using MERSEL.Services.DssSigner.Client.Models;
using Microsoft.Extensions.Logging;

namespace MERSEL.Services.DssSigner.Client.Internal;

/// <summary>
/// Tüm sub-client'ların paylaştığı HTTP/multipart yardımcı tabanı.
/// Hata gövdesi parse, multipart inşa, JSON deserialize ve per-request
/// custom header injection işlemleri burada toplandı.
/// </summary>
internal abstract class DssSignerHttpBase
{
    /// <summary>Tüm yanıtlarda kullanılan ortak JSON ayarları.</summary>
    protected static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    protected readonly HttpClient HttpClient;
    protected readonly ILogger Logger;

    protected DssSignerHttpBase(HttpClient httpClient, ILogger logger)
    {
        HttpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        Logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    // ── Multipart yardımcıları ──────────────────────────────────────

    /// <summary>
    /// Verilen byte içeriği için form alanı (file part) inşa eder.
    /// API tarafında <c>MultipartFile</c> olarak okunan alanlarda kullanılır.
    /// </summary>
    protected static void AddFilePart(
        MultipartFormDataContent form,
        string name,
        byte[] content,
        string fileName,
        string mediaType = "application/octet-stream")
    {
        var part = new ByteArrayContent(content);
        part.Headers.ContentType = new MediaTypeHeaderValue(mediaType);
        form.Add(part, name, fileName);
    }

    /// <summary>
    /// Verilen string için düz form alanı ekler.
    /// API tarafında <c>@RequestParam</c> ya da <c>@ModelAttribute</c> tek değer alanlarına bağlanır.
    /// </summary>
    protected static void AddStringPart(
        MultipartFormDataContent form,
        string name,
        string? value)
    {
        if (value is null) return;
        form.Add(new StringContent(value), name);
    }

    // ── İstek/yanıt çağrıları ───────────────────────────────────────

    /// <summary>
    /// JSON yanıtı bekleyen GET istekleri için yardımcı.
    /// </summary>
    protected async Task<T> GetJsonAsync<T>(
        string path,
        CancellationToken ct,
        IDictionary<string, string>? extraHeaders = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        ApplyHeaders(request, extraHeaders);

        using var response = await HttpClient.SendAsync(
            request, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);

        await EnsureSuccessAsync(response, path, ct).ConfigureAwait(false);
        return await ReadJsonAsync<T>(response, path, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// JSON gövdeli POST → JSON yanıt.
    /// </summary>
    protected async Task<TResponse> PostJsonAsync<TRequest, TResponse>(
        string path,
        TRequest body,
        CancellationToken ct,
        IDictionary<string, string>? extraHeaders = null)
    {
        // System.Text.Json ile content inşa ediyoruz; null değerli alanlar
        // JsonOptions.DefaultIgnoreCondition gereği serialize'a girmez.
        var json = JsonSerializer.Serialize(body, JsonOptions);

        using var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };
        ApplyHeaders(request, extraHeaders);

        using var response = await HttpClient.SendAsync(
            request, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);

        await EnsureSuccessAsync(response, path, ct).ConfigureAwait(false);
        return await ReadJsonAsync<TResponse>(response, path, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// JSON yanıtı bekleyen POST(multipart) istekleri için yardımcı.
    /// </summary>
    protected async Task<T> PostMultipartJsonAsync<T>(
        string path,
        MultipartFormDataContent content,
        CancellationToken ct,
        IDictionary<string, string>? extraHeaders = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = content
        };
        ApplyHeaders(request, extraHeaders);

        using var response = await HttpClient.SendAsync(
            request, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);

        await EnsureSuccessAsync(response, path, ct).ConfigureAwait(false);
        return await ReadJsonAsync<T>(response, path, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Binary yanıt bekleyen POST(multipart) istekleri için yardımcı.
    /// Yanıt header'ları call-site'da işlenebilsin diye <see cref="HttpResponseMessage"/> döner.
    /// </summary>
    protected async Task<HttpResponseMessage> PostMultipartBinaryAsync(
        string path,
        MultipartFormDataContent content,
        CancellationToken ct,
        IDictionary<string, string>? extraHeaders = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = content
        };
        ApplyHeaders(request, extraHeaders);

        // SendAsync'in içine atılan request, response döndüğünde dispose edilmemeli;
        // çünkü çağıran kod yanıtı hâlâ stream olarak okuyacak. Request mesajını
        // ResponseHeadersRead aşamasından sonra disposable çubuğun dışında tutmuyoruz —
        // .NET HttpClient tüm request lifecycle'ı kendisi yönetir.
        var response = await HttpClient.SendAsync(
            request, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);

        try
        {
            await EnsureSuccessAsync(response, path, ct).ConfigureAwait(false);
            return response;
        }
        catch
        {
            response.Dispose();
            throw;
        }
        finally
        {
            // HttpRequestMessage'i burada dispose etmek güvenli — content stream'i
            // SendAsync sonrası HttpClient referansı altında tutuluyor; request body
            // multipart ise zaten transmit edildi.
            request.Dispose();
        }
    }

    // ── Header inject ───────────────────────────────────────────────

    /// <summary>
    /// İsteğe per-request custom header'ları ekler. Aynı isimli mevcut
    /// (default) header varsa kaldırılıp yenisi ile değiştirilir; bu sayede
    /// <see cref="DssSignerClientOptions.DefaultHeaders"/> üzerine yazılabilir.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="HttpHeaders.TryAddWithoutValidation(string,string?)"/> kullanılır;
    /// böylece <c>x-log-*</c> gibi non-standard header'lar BCL'in restricted-set
    /// kontrolüne takılmaz.
    /// </para>
    /// <para>
    /// <c>Content-Type</c> ve <c>Content-Length</c> gibi entity-header'lar
    /// burada <c>request.Headers</c>'a değil <c>request.Content.Headers</c>'a
    /// gider; HttpClient bunu otomatik route eder.
    /// </para>
    /// </remarks>
    protected static void ApplyHeaders(
        HttpRequestMessage request,
        IDictionary<string, string>? extraHeaders)
    {
        if (extraHeaders is null || extraHeaders.Count == 0) return;

        foreach (var kv in extraHeaders)
        {
            if (string.IsNullOrEmpty(kv.Key)) continue;

            // Override semantiği: aynı isimli default header set edilmişse temizle.
            request.Headers.Remove(kv.Key);
            if (request.Content is not null)
            {
                request.Content.Headers.Remove(kv.Key);
            }

            // Önce request-level header'a koymayı dener; entity header'sa BCL
            // burayı reddeder ve content header'a düşeriz.
            if (!request.Headers.TryAddWithoutValidation(kv.Key, kv.Value))
            {
                if (request.Content is not null)
                {
                    request.Content.Headers.TryAddWithoutValidation(kv.Key, kv.Value);
                }
            }
        }
    }

    // ── Hata/Yanıt parse ────────────────────────────────────────────

    /// <summary>
    /// Başarısız HTTP yanıtlarında, eğer mümkünse <see cref="DssSignerError"/>
    /// gövdesini parse edip <see cref="DssSignerApiException"/> fırlatır.
    /// </summary>
    protected async Task EnsureSuccessAsync(HttpResponseMessage response, string path, CancellationToken ct)
    {
        if (response.IsSuccessStatusCode) return;

        string? rawBody = null;
        DssSignerError? structuredError = null;

        try
        {
            rawBody = await ReadStringAsync(response.Content, ct).ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(rawBody) &&
                (BodyLooksLikeJson(rawBody) ||
                 MediaTypeIsJson(response.Content.Headers.ContentType?.MediaType)))
            {
                structuredError = JsonSerializer.Deserialize<DssSignerError>(rawBody, JsonOptions);
            }
        }
        catch (Exception ex)
        {
            Logger.LogDebug(ex, "DssSigner hata gövdesi parse edilemedi (path: {Path})", path);
        }

        var msg = structuredError?.Message
                  ?? rawBody
                  ?? response.ReasonPhrase
                  ?? $"DSS Signer API HTTP {(int)response.StatusCode}";

        throw new DssSignerApiException(
            response.StatusCode,
            $"DSS Signer API '{path}' başarısız (HTTP {(int)response.StatusCode}): {msg}",
            structuredError,
            rawBody,
            path);
    }

    private static bool MediaTypeIsJson(string? mediaType)
    {
        if (string.IsNullOrEmpty(mediaType)) return false;
        return mediaType!.IndexOf("json", StringComparison.OrdinalIgnoreCase) >= 0;
    }

    private static bool BodyLooksLikeJson(string body)
    {
        // Cheap heuristic — used as fallback when Content-Type missing/wildcard.
        var trimmed = body.TrimStart();
        return trimmed.StartsWith("{", StringComparison.Ordinal)
               || trimmed.StartsWith("[", StringComparison.Ordinal);
    }

    // Not: HttpContent.ReadAs*Async(CancellationToken) overload'ları .NET 5+
    // ile geldi. netstandard2.0 surface'ında yalnızca parametresiz overload var,
    // bu yolda token sadece request fazında onurlandırılır; stream-read fazında
    // ignored olur (kabul edilebilir bir trade-off — bkz. README "Desteklenen
    // Platformlar" bölümü).
    private static async Task<string> ReadStringAsync(HttpContent content, CancellationToken ct)
    {
#if !NETSTANDARD2_0
        return await content.ReadAsStringAsync(ct).ConfigureAwait(false);
#else
        return await content.ReadAsStringAsync().ConfigureAwait(false);
#endif
    }

    private static async Task<byte[]> ReadByteArrayAsync(HttpContent content, CancellationToken ct)
    {
#if !NETSTANDARD2_0
        return await content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
#else
        return await content.ReadAsByteArrayAsync().ConfigureAwait(false);
#endif
    }

    /// <summary>
    /// Başarılı yanıtın gövdesini binary olarak okur.
    /// </summary>
    protected static Task<byte[]> ReadResponseBytesAsync(HttpResponseMessage response, CancellationToken ct)
        => ReadByteArrayAsync(response.Content, ct);

    /// <summary>
    /// JSON yanıtı verilen tipe deserialize eder. Boş gövde durumunda
    /// <see cref="DssSignerApiException"/> fırlatır.
    /// </summary>
    private async Task<T> ReadJsonAsync<T>(HttpResponseMessage response, string path, CancellationToken ct)
    {
        // netstandard2.0'da Stream IAsyncDisposable'ı implemente etmez;
        // 'await using' compile etmez. Senkron 'using' yeterli — DisposeAsync
        // overhead'i zaten in-memory MemoryStream'lerde no-op.
#if !NETSTANDARD2_0
        await using var stream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
#else
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#endif
        try
        {
            var result = await JsonSerializer.DeserializeAsync<T>(stream, JsonOptions, ct).ConfigureAwait(false);
            if (result is null)
            {
                throw new DssSignerApiException(
                    response.StatusCode,
                    $"DSS Signer API '{path}' boş JSON yanıtı döndürdü.",
                    requestPath: path);
            }
            return result;
        }
        catch (JsonException ex)
        {
            throw new DssSignerApiException(
                response.StatusCode,
                $"DSS Signer API '{path}' yanıtı deserialize edilemedi: {ex.Message}",
                requestPath: path,
                innerException: ex);
        }
    }

    // ── Header yardımcıları ─────────────────────────────────────────

    /// <summary>
    /// Yanıt header'ından (HttpResponseMessage.Headers veya Content.Headers) tek değer döner.
    /// Bulunamazsa <c>null</c>.
    /// </summary>
    protected static string? FirstHeaderOrDefault(HttpResponseMessage response, string headerName)
    {
        if (response.Headers.TryGetValues(headerName, out var values))
        {
            foreach (var v in values) return v;
        }
        if (response.Content.Headers.TryGetValues(headerName, out var contentValues))
        {
            foreach (var v in contentValues) return v;
        }
        return null;
    }

    /// <summary>
    /// <c>Content-Disposition</c> header'ından dosya adını çıkarır
    /// (RFC 6266; <c>filename</c> parametresi).
    /// </summary>
    protected static string? ExtractFileName(HttpResponseMessage response)
    {
        var disposition = response.Content.Headers.ContentDisposition;
        if (disposition is null) return null;

        var name = disposition.FileNameStar ?? disposition.FileName;
        return string.IsNullOrEmpty(name) ? null : name?.Trim('"');
    }
}
