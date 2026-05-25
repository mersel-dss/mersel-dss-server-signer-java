using System.Text.Json.Serialization;

namespace MERSEL.Services.DssSigner.Client.Models;

/// <summary>
/// XAdES imza profili (seviyesi).
/// </summary>
/// <remarks>
/// <para>
/// <b>Karar Verici Sözleşmesi</b> — İmza seviyesinin tek karar vericisi
/// request'tir. <see cref="DocumentType"/> (örn. <see cref="DocumentType.EArchiveReport"/>)
/// seviyenin seçimine artık dahil değildir; sistem belge tipine bakarak
/// otomatik olarak <see cref="XADES_A"/>'ya yükseltme yapmaz.
/// </para>
/// <para>
/// <b>Varsayılan</b> — API kontratı gereği <see cref="SignXadesRequest.SignatureLevel"/>
/// alanı <em>null olamaz</em>. Talep oluşturulurken bu alan set edilmezse
/// <see cref="XADES_BES"/> uygulanır — yani upgrade akışına girilmez ve TSA'ya
/// tek bir round-trip bile gitmez.
/// </para>
/// <para>
/// <b>Mali Sorumluluk</b> — e-Arşiv Raporu / e-Bilet Raporu gibi 10 yıllık
/// saklama gerektiren akışlarda <see cref="XADES_A"/>'nın istenmesi
/// <em>çağıran tarafın sorumluluğundadır</em>. Sistem belge tipine göre
/// proaktif yükseltme yapmaz; "implicit upgrade" davranışı v0.x serisinde
/// kaldırılmıştır.
/// </para>
/// <para>
/// <b>DSS Eşlemesi</b>:
/// <list type="bullet">
///   <item><c>XADES_BES</c> → <c>SignatureLevel.XAdES_BASELINE_B</c></item>
///   <item><c>XADES_A</c>   → <c>SignatureLevel.XAdES_BASELINE_LTA</c>
///         (legacy ETSI TS 101 903 terminolojisindeki XAdES-A profili)</item>
/// </list>
/// </para>
/// </remarks>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum XadesSignatureLevel
{
    /// <summary>
    /// Baseline-B profili: yalnızca <c>ds:Signature</c> ve <c>xades:SignedProperties</c>.
    /// Hiçbir TSA çağrısı yapılmaz; kontör harcanmaz. e-Fatura, e-Arşiv faturası,
    /// irsaliye, uygulama yanıtı, HrXml, e-Adisyon raporu, e-Döviz raporu (iptal hariç)
    /// vb. timestamp gerektirmeyen tüm akışlar için. <b>API'nin varsayılan değeri.</b>
    /// </summary>
    XADES_BES,

    /// <summary>
    /// Baseline-LTA profili (legacy adıyla XAdES-A): imza + signature timestamp +
    /// archive timestamp. e-Arşiv Raporu / e-Bilet Raporu gibi arşivsel akışlar için
    /// uygundur.
    /// <para>
    /// <b>Zorunlu önkoşul</b>: Sunucu tarafında TSA host'u yapılandırılmış olmalı
    /// (örn. <c>TS_SERVER_HOST</c> property). Aksi halde imza akışı fail-fast olarak
    /// <c>TIMESTAMP_ERROR</c> ile reddedilir — <see cref="XADES_BES"/> seviyesinde
    /// sessiz fallback yapılmaz (silent data corruption pattern'inden kasıtlı kaçınma).
    /// </para>
    /// </summary>
    XADES_A
}
