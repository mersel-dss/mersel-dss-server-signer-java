using System.Text.Json.Serialization;

namespace MERSEL.Services.DssSigner.Client.Models;

/// <summary>
/// <c>POST /v1/hashsign</c> request body kontratı. API'nin
/// <c>SignHashDto</c> tipine birebir karşılık gelir.
/// </summary>
/// <remarks>
/// <para>
/// <b>Anlamlama</b> — Caller, sunucuya <em>zaten hesaplanmış</em> bir digest
/// gönderir. Sunucu bu digest'i <em>tekrar hash'lemez</em>; doğrudan
/// PKCS#1 v1.5 padding (RSA) veya raw ECDSA imzalama uygular. Tipik kullanım
/// e-Defter mali mührü ve manuel XAdES <c>SignedInfo</c> digest imzalama akışlarıdır.
/// </para>
/// <para>
/// <b>Validation</b> — <see cref="Base64EncodedDigest"/> zorunludur, decoded
/// uzunluğu <see cref="DigestAlgorithm"/> ile uyumlu olmalıdır:
/// SHA-1 → 20, SHA-224 → 28, SHA-256 → 32, SHA-384 → 48, SHA-512 → 64 byte.
/// Uyumsuzluk veya geçersiz base64 → HTTP 400 + <c>INVALID_INPUT</c>.
/// </para>
/// </remarks>
public sealed class SignHashRequest
{
    /// <summary>
    /// İmzalanacak hash'in base64 encoded değeri. Caller hash'i kendisi
    /// hesaplamalıdır. Decoded uzunluk <see cref="DigestAlgorithm"/> ile
    /// uyumlu olmalıdır.
    /// </summary>
    [JsonPropertyName("base64EncodedDigest")]
    public string? Base64EncodedDigest { get; set; }

    /// <summary>
    /// Hash algoritması. RSA path'inde DigestInfo prefix seçimi için, ECDSA
    /// path'inde uzunluk doğrulaması için kullanılır. Varsayılan
    /// <see cref="HashDigestAlgorithm.SHA256"/>.
    /// </summary>
    [JsonPropertyName("digestAlgorithm")]
    public HashDigestAlgorithm DigestAlgorithm { get; set; } = HashDigestAlgorithm.SHA256;

    /// <summary>
    /// Bu çağrıya özel HTTP header'ları
    /// (<see cref="DssSignerClientOptions.DefaultHeaders"/> override'ı için).
    /// JSON gövdesine serialize edilmez; yalnızca HTTP request header'ı olarak gider.
    /// </summary>
    [JsonIgnore]
    public IDictionary<string, string>? Headers { get; set; }
}
