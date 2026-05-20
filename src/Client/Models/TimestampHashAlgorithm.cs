namespace MERSEL.Services.DssSigner.Client.Models;

/// <summary>
/// RFC 3161 zaman damgası talebi için kullanılacak hash algoritması.
/// Sunucu serbest string kabul eder; bu enum yaygın değerleri tip-güvenli sunmak içindir.
/// Özel bir değer göndermek isterseniz <see cref="GetTimestampRequest.HashAlgorithm"/>
/// alanına doğrudan string verin.
/// </summary>
public static class TimestampHashAlgorithm
{
    /// <summary>SHA-256 (varsayılan).</summary>
    public const string Sha256 = "SHA256";

    /// <summary>SHA-384.</summary>
    public const string Sha384 = "SHA384";

    /// <summary>SHA-512.</summary>
    public const string Sha512 = "SHA512";

    /// <summary>SHA-1 (modern kullanımda önerilmez, yalnızca legacy entegrasyonlar için).</summary>
    public const string Sha1 = "SHA1";
}
