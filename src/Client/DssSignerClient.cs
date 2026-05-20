using MERSEL.Services.DssSigner.Client.Interfaces;

namespace MERSEL.Services.DssSigner.Client;

/// <summary>
/// MERSEL DSS Server Signer mikroservisinin tüm domain'lerini tek bir cephe arkasından
/// erişilebilir kılan birleşik istemci. <see cref="IDssSignerClient"/>'ı uygular.
/// <para>
/// Genellikle <see cref="DependencyInjection.AddDssSignerClient(Microsoft.Extensions.DependencyInjection.IServiceCollection, Microsoft.Extensions.Configuration.IConfiguration, string)"/>
/// ile DI'ye kaydedilir; tüketici kodda doğrudan <see cref="IDssSignerClient"/> olarak inject edilir.
/// </para>
/// </summary>
public sealed class DssSignerClient : IDssSignerClient
{
    /// <inheritdoc />
    public IXadesSigner Xades { get; }

    /// <inheritdoc />
    public ICadesSigner Cades { get; }

    /// <inheritdoc />
    public IPadesSigner Pades { get; }

    /// <inheritdoc />
    public ITimestampClient Timestamp { get; }

    /// <inheritdoc />
    public ITubitakClient Tubitak { get; }

    /// <inheritdoc />
    public ICertificateInfoClient Certificates { get; }

    public DssSignerClient(
        IXadesSigner xades,
        ICadesSigner cades,
        IPadesSigner pades,
        ITimestampClient timestamp,
        ITubitakClient tubitak,
        ICertificateInfoClient certificates)
    {
        Xades = xades ?? throw new ArgumentNullException(nameof(xades));
        Cades = cades ?? throw new ArgumentNullException(nameof(cades));
        Pades = pades ?? throw new ArgumentNullException(nameof(pades));
        Timestamp = timestamp ?? throw new ArgumentNullException(nameof(timestamp));
        Tubitak = tubitak ?? throw new ArgumentNullException(nameof(tubitak));
        Certificates = certificates ?? throw new ArgumentNullException(nameof(certificates));
    }
}
