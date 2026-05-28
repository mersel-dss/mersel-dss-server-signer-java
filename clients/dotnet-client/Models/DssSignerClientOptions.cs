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
    /// <see cref="DefaultHeaders"/>'ı kullanın ya da
    /// <c>AddDssSignerClient(...)</c> sonrası <see cref="Microsoft.Extensions.DependencyInjection.IHttpClientBuilder"/>
    /// üzerinden <c>ConfigureHttpClient</c> ya da <c>AddHttpMessageHandler</c> kullanın.
    /// </remarks>
    public string? UserAgent { get; set; }

    /// <summary>
    /// Her HTTP isteğine eklenecek varsayılan header'lar. <c>appsettings.json</c>
    /// üzerinden veya kod ile doldurulabilir.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Tipik kullanım</b>:
    /// </para>
    /// <list type="bullet">
    ///   <item>
    ///     API Gateway / reverse-proxy kimlik header'ları
    ///     (<c>X-API-Key</c>, <c>Authorization</c>, <c>X-Tenant-Id</c>).
    ///   </item>
    ///   <item>
    ///     Sunucu observability özelliği <c>x-log-*</c> header'ları —
    ///     bu prefix ile gönderilen tüm header'lar sunucu tarafında log
    ///     satırlarına JSON olarak yansır (örn. <c>x-log-correlation-id</c>,
    ///     <c>x-log-tenant</c>, <c>x-log-user</c>).
    ///   </item>
    /// </list>
    /// <para>
    /// İstek başına dinamik header (örn. her çağrıda değişen correlation id)
    /// eklemek için ilgili request DTO'sunun <c>Headers</c> property'sini
    /// kullanın; bu sözlük <see cref="DefaultHeaders"/> üzerine binder ve
    /// aynı isimli alanı override eder.
    /// </para>
    /// <para>
    /// Karşılaştırma anahtarları büyük/küçük harf duyarsız tutulur
    /// (HTTP header semantiği gereği).
    /// </para>
    /// </remarks>
    public IDictionary<string, string> DefaultHeaders { get; set; }
        = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
}
