package io.mersel.dss.signer.api.dtos;

import javax.validation.constraints.NotBlank;

import org.springframework.web.multipart.MultipartFile;

import io.swagger.v3.oas.annotations.media.Schema;
import io.mersel.dss.signer.api.models.enums.DocumentType;

public class SignXadesDto {
    private MultipartFile Document;
    private String SignatureId;
    private DocumentType DocumentType;
    private Boolean ZipFile;
    private boolean DisableTimeStamp;

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

    public boolean isDisableTimeStamp() {
        return DisableTimeStamp;
    }

    public void setDisableTimeStamp(boolean disableTimeStamp) {
        this.DisableTimeStamp = disableTimeStamp;
    }
}
