package io.mersel.dss.signer.api.models.enums;

/**
 * İmzalanabilir belge tipleri.
 * e-Fatura, e-Arşiv, İrsaliye ve diğer XML belge formatları.
 */
public enum DocumentType {
    None,
    UblDocument,
    HrXml,
    EArchiveReport,
    EBiletReport,  
    OtherXmlDocument
}
