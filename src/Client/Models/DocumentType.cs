using System.Text.Json.Serialization;

namespace MERSEL.Services.DssSigner.Client.Models;

/// <summary>
/// XAdES imzalanacak XML belge tipi.
/// Sunucu tarafında belge tipine göre özel imzalama profili seçilir
/// (örn. UBL-TR 2.1 e-Fatura için <see cref="UblDocument"/>, GİB e-Arşiv raporu için <see cref="EArchiveReport"/>).
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum DocumentType
{
    /// <summary>Belirtilmedi. Sunucu reddeder.</summary>
    None = 0,

    /// <summary>UBL-TR 2.1 belgesi (e-Fatura, e-Arşiv, e-İrsaliye, Uygulama Yanıtı vb.).</summary>
    UblDocument,

    /// <summary>İK / İnsan Kaynakları XML şeması (HrXml).</summary>
    HrXml,

    /// <summary>e-Arşiv raporu XML belgesi.</summary>
    EArchiveReport,

    /// <summary>e-Bilet raporu XML belgesi.</summary>
    EBiletReport,

    /// <summary>Yukarıdakilerin hiçbirine uymayan ancak XAdES ile imzalanacak XML belgesi.</summary>
    OtherXmlDocument
}
