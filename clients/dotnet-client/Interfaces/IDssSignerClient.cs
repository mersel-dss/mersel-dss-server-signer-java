namespace MERSEL.Services.DssSigner.Client.Interfaces;

/// <summary>
/// MERSEL DSS Server Signer mikroservisinin tüm domain'lerini tek bir cephe (facade)
/// arkasından erişilebilir kılan birleşik istemci sözleşmesi.
/// <para>
/// Tek bir bağımlılık enjeksiyonu ile tüm imzalama (XAdES, WS-Security, PAdES, CAdES,
/// pre-hashed digest), zaman damgası ve sertifika operasyonlarına erişebilirsiniz.
/// İhtiyacınız tek bir alan ise ilgili sub-interface'i (<see cref="IXadesSigner"/>,
/// <see cref="ICadesSigner"/> vb.) doğrudan da inject edebilirsiniz.
/// </para>
/// </summary>
public interface IDssSignerClient
{
    /// <summary>XAdES ve WS-Security operasyonları.</summary>
    IXadesSigner Xades { get; }

    /// <summary>CAdES-BES operasyonları.</summary>
    ICadesSigner Cades { get; }

    /// <summary>PAdES operasyonları.</summary>
    IPadesSigner Pades { get; }

    /// <summary>
    /// Pre-hashed digest imzalama operasyonları (e-Defter / manuel SignedInfo akışları).
    /// </summary>
    IHashSigner Hash { get; }

    /// <summary>RFC 3161 zaman damgası operasyonları.</summary>
    ITimestampClient Timestamp { get; }

    /// <summary>TÜBİTAK ESYA özel operasyonları (kontör vb.).</summary>
    ITubitakClient Tubitak { get; }

    /// <summary>Sertifika ve keystore meta bilgisi operasyonları.</summary>
    ICertificateInfoClient Certificates { get; }
}
