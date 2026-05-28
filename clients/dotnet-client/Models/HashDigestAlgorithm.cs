using System.Text.Json.Serialization;

namespace MERSEL.Services.DssSigner.Client.Models;

/// <summary>
/// <c>POST /v1/hashsign</c> isteğinde kullanılabilecek hash algoritmaları.
/// Sunucu, <c>eu.europa.esig.dss.enumerations.DigestAlgorithm</c> Java enum'unu
/// JSON'dan parse eder; bu yüzden enum sabit isimleri sunucu tarafıyla
/// <em>birebir</em> eşleşir.
/// </summary>
/// <remarks>
/// <para>
/// <b>Validation</b>: Sunucu service katmanı, request'teki digest baytlarının
/// uzunluğunu seçilen algoritmanın hash uzunluğuyla doğrular (ör. SHA-256 → 32 byte).
/// Uyumsuzluk durumunda HTTP 400 + <c>INVALID_INPUT</c> döner.
/// </para>
/// <para>
/// <b>Algoritma vs. byte uzunluğu</b>:
/// <list type="bullet">
///   <item><see cref="SHA1"/> → 20 byte</item>
///   <item><see cref="SHA224"/> → 28 byte</item>
///   <item><see cref="SHA256"/> → 32 byte (varsayılan)</item>
///   <item><see cref="SHA384"/> → 48 byte</item>
///   <item><see cref="SHA512"/> → 64 byte</item>
/// </list>
/// </para>
/// <para>
/// SHA-1 modern kullanımda önerilmez; yalnızca legacy entegrasyonlar
/// (e-Defter mali mührü gibi mevzuat sabitlemeleri) için bırakılmıştır.
/// </para>
/// </remarks>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum HashDigestAlgorithm
{
    /// <summary>SHA-1 (20 byte). Legacy.</summary>
    SHA1,

    /// <summary>SHA-224 (28 byte).</summary>
    SHA224,

    /// <summary>SHA-256 (32 byte). Varsayılan.</summary>
    SHA256,

    /// <summary>SHA-384 (48 byte).</summary>
    SHA384,

    /// <summary>SHA-512 (64 byte).</summary>
    SHA512
}
