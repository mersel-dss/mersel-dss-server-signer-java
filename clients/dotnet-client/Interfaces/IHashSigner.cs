using MERSEL.Services.DssSigner.Client.Models;

namespace MERSEL.Services.DssSigner.Client.Interfaces;

/// <summary>
/// Pre-hashed digest imzalama operasyonları.
/// <c>POST /v1/hashsign</c> endpoint'ine karşılık gelir.
/// </summary>
/// <remarks>
/// <para>
/// <b>Use case</b> — e-Defter mali mührü, manuel XAdES <c>&lt;ds:SignedInfo&gt;</c>
/// digest imzalama veya buna benzer akışlar. Caller hash'i kendisi hesaplar;
/// sunucu bu digest'i <em>tekrar hash'lemez</em>.
/// </para>
/// <para>
/// <b>Akış</b>:
/// <list type="bullet">
///   <item><b>RSA</b>: Sunucu PKCS#1 v1.5 DigestInfo prefix ekler ve raw RSA cipher
///     uygular (JCA: <c>RSA/ECB/PKCS1Padding</c>; PKCS#11: <c>CKM_RSA_PKCS</c>).</item>
///   <item><b>ECDSA</b>: Hash doğrudan eğri üzerinde imzalanır (JCA: <c>NONEwithECDSA</c>;
///     PKCS#11: <c>CKM_ECDSA</c>). Çıktı her iki path'te de DER SEQUENCE
///     <c>{ r, s }</c> olarak normalize edilir.</item>
/// </list>
/// </para>
/// <para>
/// <b>Güvenlik</b> — Endpoint bir <em>signing oracle</em>'dir; private network
/// içinde tüketilmek üzere tasarlanmıştır. Public exposure senaryosunda API key
/// authentication, audit log ve rate limiting eklenmesi önerilir
/// (bkz. <c>SECURITY.md</c>).
/// </para>
/// </remarks>
public interface IHashSigner
{
    /// <summary>
    /// Pre-hashed bir digest'i sunucuda yapılandırılmış imzacı sertifika ile imzalar.
    /// </summary>
    /// <param name="request">
    /// İmza isteği. <see cref="SignHashRequest.Base64EncodedDigest"/> zorunludur;
    /// decoded uzunluk <see cref="SignHashRequest.DigestAlgorithm"/> ile uyumlu olmalıdır.
    /// </param>
    /// <param name="ct">İptal belirteci.</param>
    /// <returns>Base64 imza değerini içeren sonuç.</returns>
    Task<SignHashResult> SignAsync(SignHashRequest request, CancellationToken ct = default);

    /// <summary>
    /// Ham digest baytlarından kısa yol overload'ı. Base64 encoding istemci
    /// tarafında otomatik yapılır.
    /// </summary>
    /// <param name="digest">Pre-computed hash baytları (örn. SHA-256 → 32 byte).</param>
    /// <param name="digestAlgorithm">
    /// Hash algoritması; varsayılan <see cref="HashDigestAlgorithm.SHA256"/>.
    /// </param>
    /// <param name="ct">İptal belirteci.</param>
    Task<SignHashResult> SignAsync(
        byte[] digest,
        HashDigestAlgorithm digestAlgorithm = HashDigestAlgorithm.SHA256,
        CancellationToken ct = default);
}
