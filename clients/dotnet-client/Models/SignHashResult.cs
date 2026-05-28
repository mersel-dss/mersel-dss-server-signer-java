using System.Text.Json.Serialization;

namespace MERSEL.Services.DssSigner.Client.Models;

/// <summary>
/// <c>POST /v1/hashsign</c> başarılı yanıtı. API'nin <c>SignHashResponseDto</c>
/// tipine birebir karşılık gelir.
/// </summary>
/// <remarks>
/// <para>
/// İmza baytları base64 encoded biçimde döner:
/// <list type="bullet">
///   <item><b>RSA</b>: PKCS#1 v1.5 padded RSA cipher çıktısı (modül büyüklüğüyle aynı uzunlukta).</item>
///   <item><b>ECDSA</b>: DER SEQUENCE <c>{ r, s }</c> formatında imza (P-256 için ~70-72 byte).</item>
/// </list>
/// </para>
/// <para>
/// e-Defter akışında bu değer doğrudan <c>&lt;ds:SignatureValue&gt;</c> elementine yazılabilir.
/// </para>
/// </remarks>
public sealed class SignHashResult
{
    /// <summary>
    /// İmza baytlarının base64 encoded değeri. RSA: PKCS#1 v1.5 padded;
    /// ECDSA: DER SEQUENCE { r, s }.
    /// </summary>
    [JsonPropertyName("base64EncodedSignature")]
    public string? Base64EncodedSignature { get; set; }

    /// <summary>
    /// Yanıttaki base64 imza değerini decode edip ham byte dizisi olarak döndürür.
    /// </summary>
    /// <returns>İmzanın ham baytları.</returns>
    /// <exception cref="InvalidOperationException">
    /// <see cref="Base64EncodedSignature"/> null/boş ise.
    /// </exception>
    /// <exception cref="FormatException">Base64 değeri geçersizse.</exception>
    public byte[] ToSignatureBytes()
    {
        if (string.IsNullOrEmpty(Base64EncodedSignature))
        {
            throw new InvalidOperationException(
                "Base64EncodedSignature boş; sunucu yanıtı tamamlanmamış olabilir.");
        }
        return Convert.FromBase64String(Base64EncodedSignature);
    }
}
