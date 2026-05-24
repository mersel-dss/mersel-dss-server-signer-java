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
    /// Custom <c>User-Agent</c> başlığı. Varsayılan paket adı + sürümünden üretilir.
    /// </summary>
    /// <remarks>
    /// Sunucu authentication uygulamaz (bkz. <c>SECURITY.md</c>); herhangi bir ek
    /// header (API gateway anahtarı, korelasyon kimliği vb.) eklemek için
    /// <c>AddDssSignerClient(...)</c> sonrası <see cref="Microsoft.Extensions.DependencyInjection.IHttpClientBuilder"/>
    /// üzerinden <c>ConfigureHttpClient</c> ya da <c>AddHttpMessageHandler</c> kullanın.
    /// </remarks>
    public string? UserAgent { get; set; }
}
