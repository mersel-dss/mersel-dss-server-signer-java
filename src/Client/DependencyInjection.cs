using System.Net.Http.Headers;
using System.Reflection;
using System.Text;
using MERSEL.Services.DssSigner.Client.Clients;
using MERSEL.Services.DssSigner.Client.Interfaces;
using MERSEL.Services.DssSigner.Client.Models;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace MERSEL.Services.DssSigner.Client;

/// <summary>
/// MERSEL DSS Server Signer istemci SDK'sı için DI uzantı metotları.
/// Tek satırlık <c>AddDssSignerClient</c> çağrısıyla tüm sub-client'lar
/// (<see cref="IXadesSigner"/>, <see cref="ICadesSigner"/>, <see cref="IPadesSigner"/>,
/// <see cref="ITimestampClient"/>, <see cref="ITubitakClient"/>, <see cref="ICertificateInfoClient"/>)
/// ve aggregator <see cref="IDssSignerClient"/> servis koleksiyonuna kaydedilir.
/// </summary>
public static class DependencyInjection
{
    /// <summary>
    /// İstemci SDK'sını <c>IConfiguration</c> üzerinden okuyarak DI'ye kaydeder.
    /// </summary>
    /// <param name="services">Servis koleksiyonu.</param>
    /// <param name="configuration">Konfigürasyon kaynağı.</param>
    /// <param name="sectionName">
    /// Bağlanılacak konfigürasyon bölümü.
    /// Varsayılan: <see cref="DssSignerClientOptions.DefaultConfigurationSection"/> (<c>Services:DssSigner</c>).
    /// </param>
    /// <example>
    /// <code>
    /// // appsettings.json
    /// {
    ///   "Services": {
    ///     "DssSigner": {
    ///       "BaseUrl": "http://dss-signer:8088",
    ///       "Timeout": "00:02:00",
    ///       "ApiKey": "..."
    ///     }
    ///   }
    /// }
    ///
    /// // Program.cs
    /// builder.Services.AddDssSignerClient(builder.Configuration);
    /// </code>
    /// </example>
    public static IServiceCollection AddDssSignerClient(
        this IServiceCollection services,
        IConfiguration configuration,
        string sectionName = DssSignerClientOptions.DefaultConfigurationSection)
    {
        if (services is null) throw new ArgumentNullException(nameof(services));
        if (configuration is null) throw new ArgumentNullException(nameof(configuration));

        services.AddOptions<DssSignerClientOptions>()
            .Bind(configuration.GetSection(sectionName))
            .Validate(o => !string.IsNullOrWhiteSpace(o.BaseUrl),
                $"DssSignerClientOptions.BaseUrl '{sectionName}:BaseUrl' anahtarı zorunludur.");

        return AddDssSignerClientCore(services);
    }

    /// <summary>
    /// İstemci SDK'sını doğrudan kod ile yapılandırarak DI'ye kaydeder.
    /// </summary>
    /// <param name="services">Servis koleksiyonu.</param>
    /// <param name="configure">Seçenekleri yapılandıran delegate.</param>
    /// <example>
    /// <code>
    /// builder.Services.AddDssSignerClient(o =>
    /// {
    ///     o.BaseUrl = "http://dss-signer:8088";
    ///     o.Timeout = TimeSpan.FromMinutes(5);
    ///     o.ApiKey  = "secret-key";
    /// });
    /// </code>
    /// </example>
    public static IServiceCollection AddDssSignerClient(
        this IServiceCollection services,
        Action<DssSignerClientOptions> configure)
    {
        if (services is null) throw new ArgumentNullException(nameof(services));
        if (configure is null) throw new ArgumentNullException(nameof(configure));

        services.AddOptions<DssSignerClientOptions>()
            .Configure(configure)
            .Validate(o => !string.IsNullOrWhiteSpace(o.BaseUrl),
                "DssSignerClientOptions.BaseUrl zorunludur.");

        return AddDssSignerClientCore(services);
    }

    /// <summary>
    /// Sadece taban URL belirterek hızlıca DI'ye kayıt yapan kısa yol overload'ı.
    /// </summary>
    public static IServiceCollection AddDssSignerClient(
        this IServiceCollection services,
        string baseUrl)
    {
        if (string.IsNullOrWhiteSpace(baseUrl))
            throw new ArgumentException("BaseUrl boş olamaz.", nameof(baseUrl));

        return services.AddDssSignerClient(o => o.BaseUrl = baseUrl);
    }

    // ── Çekirdek kayıt: tüm typed-client'ların ortak HTTP client'ı paylaşmasını sağlar ──

    private static IServiceCollection AddDssSignerClientCore(IServiceCollection services)
    {
        services.AddHttpClient(DssSignerClientOptions.HttpClientName, ConfigureHttpClient);

        // Sub-client'lar; hepsi aynı HttpClient'ı (HttpClientFactory üzerinden) kullanır.
        services.TryAddTransient<IXadesSigner>(sp => CreateClient<XadesSigner>(sp));
        services.TryAddTransient<ICadesSigner>(sp => CreateClient<CadesSigner>(sp));
        services.TryAddTransient<IPadesSigner>(sp => CreateClient<PadesSigner>(sp));
        services.TryAddTransient<ITimestampClient>(sp => CreateClient<TimestampClient>(sp));
        services.TryAddTransient<ITubitakClient>(sp => CreateClient<TubitakClient>(sp));
        services.TryAddTransient<ICertificateInfoClient>(sp => CreateClient<CertificateInfoClient>(sp));

        services.TryAddTransient<IDssSignerClient, DssSignerClient>();

        return services;
    }

    private static T CreateClient<T>(IServiceProvider sp) where T : class
    {
        var factory = sp.GetRequiredService<IHttpClientFactory>();
        var http = factory.CreateClient(DssSignerClientOptions.HttpClientName);
        var loggerFactory = sp.GetRequiredService<ILoggerFactory>();
        var logger = loggerFactory.CreateLogger<T>();

        // İki argüman alan ctor'ı (HttpClient, ILogger<T>) bul ve çağır.
        return (T)Activator.CreateInstance(typeof(T), http, logger)!;
    }

    private static void ConfigureHttpClient(IServiceProvider sp, HttpClient http)
    {
        var options = sp.GetRequiredService<IOptions<DssSignerClientOptions>>().Value;

        var baseUrl = options.BaseUrl?.TrimEnd('/') ?? string.Empty;
        if (string.IsNullOrEmpty(baseUrl))
        {
            throw new InvalidOperationException(
                "DssSignerClientOptions.BaseUrl yapılandırılmamış. " +
                $"'{DssSignerClientOptions.DefaultConfigurationSection}:BaseUrl' anahtarını ayarlayın " +
                "veya AddDssSignerClient(...) çağrısında belirtin.");
        }

        http.BaseAddress = new Uri(baseUrl + "/");
        http.Timeout = options.Timeout > TimeSpan.Zero
            ? options.Timeout
            : TimeSpan.FromMinutes(2);

        // Authentication header'ları (kullanıcı seçimine bağlı).
        if (!string.IsNullOrEmpty(options.ApiKey) && !string.IsNullOrEmpty(options.ApiKeyHeaderName))
        {
            http.DefaultRequestHeaders.Remove(options.ApiKeyHeaderName);
            http.DefaultRequestHeaders.Add(options.ApiKeyHeaderName, options.ApiKey);
        }

        if (!string.IsNullOrEmpty(options.BasicAuthUsername))
        {
            var raw = $"{options.BasicAuthUsername}:{options.BasicAuthPassword ?? string.Empty}";
            var token = Convert.ToBase64String(Encoding.UTF8.GetBytes(raw));
            http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", token);
        }

        // User-Agent: paket adı + sürüm.
        var userAgent = options.UserAgent ?? BuildDefaultUserAgent();
        if (!string.IsNullOrEmpty(userAgent))
        {
            http.DefaultRequestHeaders.UserAgent.Clear();
            // Tek parça olarak ekleriz; karmaşık formatlama gerekmez.
            http.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", userAgent);
        }

        // application/json tercihen okunsun (sunucu */* dönse de hata gövdeleri JSON olur).
        http.DefaultRequestHeaders.Accept.Clear();
        http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json", 0.9));
        http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/octet-stream", 0.8));
        http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("*/*", 0.1));
    }

    private static string BuildDefaultUserAgent()
    {
        var asm = typeof(DependencyInjection).Assembly;
        var name = asm.GetName().Name ?? "MERSEL.Services.DssSigner.Client";
        var version = asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
                      ?? asm.GetName().Version?.ToString()
                      ?? "0.0.0";
        // SourceLink commit suffix'lerini temizle.
        var plus = version.IndexOf('+');
        if (plus > 0) version = version.Substring(0, plus);
        return $"{name}/{version}";
    }
}
