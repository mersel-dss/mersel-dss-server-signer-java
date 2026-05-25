package io.mersel.dss.signer.api.dtos;

import javax.validation.constraints.NotBlank;

import org.springframework.web.multipart.MultipartFile;

import io.swagger.v3.oas.annotations.media.Schema;
import io.mersel.dss.signer.api.models.enums.DocumentType;
import io.mersel.dss.signer.api.models.enums.XadesSignatureLevel;

public class SignXadesDto {
    private MultipartFile Document;
    private String SignatureId;
    private DocumentType DocumentType;
    private Boolean ZipFile;

    /**
     * XAdES imza profili (seviyesi). API kontratı gereği bu alan
     * <strong>asla null değildir</strong>; gönderilmediği takdirde varsayılan
     * {@link XadesSignatureLevel#XADES_BES} uygulanır. Bu durumda archive timestamp
     * eklenmez, TSA çağrılmaz, kontör harcanmaz.
     *
     * <p>{@link XadesSignatureLevel#XADES_A} istenirse arşiv timestamp eklenir;
     * TSA yapılandırılmamışsa istek 503 / {@code TIMESTAMP_ERROR} ile reddedilir.</p>
     *
     * <p><strong>Önemli</strong>: {@code documentType} (örn. EArchiveReport) artık
     * seviye kararına dahil <em>değildir</em>. Rapor akışında XADES_A istenecekse
     * bu alanın explicit olarak gönderilmesi gerekir.</p>
     */
    private XadesSignatureLevel SignatureLevel = XadesSignatureLevel.XADES_BES;

    public String getSignatureId() {
        return SignatureId;
    }

    public void setSignatureId(String signatureId) {
        SignatureId = signatureId;
    }

    public MultipartFile getDocument() {
        return Document;
    }

    @NotBlank
    public void setDocument(MultipartFile document) {
        Document = document;
    }

    public io.mersel.dss.signer.api.models.enums.DocumentType getDocumentType() {
        return DocumentType;
    }

    @NotBlank
    @Schema(enumAsRef = true)
    public void setDocumentType(io.mersel.dss.signer.api.models.enums.DocumentType documentType) {
        DocumentType = documentType;
    }

    public Boolean getZipFile() {
        return ZipFile;
    }

    public void setZipFile(Boolean zipFile) {
        ZipFile = zipFile;
    }

    /**
     * Daima non-null bir {@link XadesSignatureLevel} döner. Non-null kontratı
     * iki katmanda korunur: (a) field initializer ctor sonrası başlangıç
     * değerini garantiler, (b) setter null gelirse {@link XadesSignatureLevel#XADES_BES}
     * fallback uygular. Dolayısıyla getter savunmacı bir null check yapmak
     * zorunda değildir.
     */
    public XadesSignatureLevel getSignatureLevel() {
        return SignatureLevel;
    }

    /**
     * Setter; {@code null} geçirildiğinde alan {@link XadesSignatureLevel#XADES_BES}'e
     * düşürülür. Bu, multipart form binding senaryolarında alan boş gelse bile
     * "asla null" kontratının korunmasını garanti eder.
     */
    @Schema(
        enumAsRef = true,
        description = "XAdES imza profili. Boş bırakılırsa XADES_BES davranışı uygulanır "
                + "(timestamp eklenmez, TSA çağrılmaz). XADES_A istenirse arşiv timestamp "
                + "eklenir; TSA yapılandırılmamışsa istek TIMESTAMP_ERROR ile reddedilir. "
                + "documentType seviye kararına dahil değildir — karar tamamen bu alana bağlıdır.",
        example = "XADES_BES",
        defaultValue = "XADES_BES"
    )
    public void setSignatureLevel(XadesSignatureLevel signatureLevel) {
        SignatureLevel = signatureLevel != null ? signatureLevel : XadesSignatureLevel.XADES_BES;
    }
}
