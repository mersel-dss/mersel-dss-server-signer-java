namespace MERSEL.Services.DssSigner.Client.Models;

/// <summary>
/// WS-Security SOAP zarfı imzalama isteği.
/// </summary>
public sealed class SignWsSecurityRequest
{
    /// <summary>İmzalanacak SOAP zarfı (XML, binary).</summary>
    public byte[] Document { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// <c>true</c> ise SOAP 1.2 namespace'leri ile imzalanır,
    /// <c>false</c> ise SOAP 1.1. Varsayılan: <c>false</c>.
    /// </summary>
    public bool Soap1Dot2 { get; set; }

    /// <summary>İsteğe konacak multipart dosya adı (yalnızca log/metadata).</summary>
    public string FileName { get; set; } = "envelope.xml";

    /// <summary>
    /// Bu çağrıya özel HTTP header'ları
    /// (<see cref="DssSignerClientOptions.DefaultHeaders"/> override'ı için).
    /// Tipik kullanım: <c>x-log-correlation-id</c>, gateway auth header'ı.
    /// </summary>
    public IDictionary<string, string>? Headers { get; set; }
}
