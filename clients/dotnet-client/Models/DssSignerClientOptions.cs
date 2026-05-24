namespace MERSEL.Services.DssSigner.Client.Models;

/// <summary>
/// İstemci yapılandırma seçenekleri. <c>appsettings.json</c> ya da kod ile bağlanır.
/// </summary>
public sealed class DssSignerClientOptions
{
    /// <summary>Yapılandırma kök bölümü (default <c>Services:DssSigner</c>).</summary>
    public const string DefaultConfigurationSection = "Services:DssSigner";

    /// <summary>HTTP istemcisinin kullanacağı isimli client adı.</summary>
    public const string HttpClientName = "MERSEL.Services.DssSigner";

    /// <summary>
    /// DSS Signer mikroservisinin temel URL'i. Sonunda <c>/</c> olmasına gerek yok.
    /// Örn. <c>http://dss-signer:8088</c>.
    /// </summary>
    public string BaseUrl { get; set; } = "http://localhost:8088";

    /// <summary>
    /// İstek zaman aşımı. Büyük PDF imzalama veya HSM gecikmesi olan ortamlarda
    /// 2-5 dakikaya çekilmesi önerilir. Varsayılan: 2 dakika.
    /// </summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromMinutes(2);

    /// <summary>
    /// İsteğe bağlı API anahtarı. Set edildiğinde her isteğe
    /// <c>X-API-Key</c> header'ı olarak eklenir.
    /// </summary>
    public string? ApiKey { get; set; }

    /// <summary>API key header adı (gereken durumlar için özelleştirilebilir).</summary>
    public string ApiKeyHeaderName { get; set; } = "X-API-Key";

    /// <summary>
    /// İsteğe bağlı temel kimlik doğrulama (basic auth) kullanıcı adı.
    /// <see cref="BasicAuthPassword"/> ile birlikte set edilirse
    /// <c>Authorization: Basic ...</c> header'ı eklenir.
    /// </summary>
    public string? BasicAuthUsername { get; set; }

    /// <summary>İsteğe bağlı basic auth parolası.</summary>
    public string? BasicAuthPassword { get; set; }

    /// <summary>
    /// Custom <c>User-Agent</c> başlığı. Varsayılan paket adı + sürümünden üretilir.
    /// </summary>
    public string? UserAgent { get; set; }
}
