package io.mersel.dss.signer.api.dtos;

import com.fasterxml.jackson.annotation.JsonFormat;
import io.swagger.v3.oas.annotations.media.Schema;

import java.util.Date;

/**
 * Keystore içerisindeki sertifika bilgilerini taşıyan DTO.
 */
@Schema(description = "Keystore içerisindeki sertifika detay bilgileri")
public class CertificateInfoDto {

    @Schema(description = "Sertifika alias'ı (keystore içindeki benzersiz adı)", example = "signing-cert-2024")
    private String alias;

    @Schema(description = "Sertifika seri numarası (hexadecimal)", example = "1A2B3C4D5E6F7890")
    private String serialNumberHex;

    @Schema(description = "Sertifika seri numarası (decimal)", example = "1886477714079739024")
    private String serialNumberDec;

    @Schema(description = "Sertifika subject (kime verildiği)", 
            example = "SERIALNUMBER=12345678901,C=TR,CN=JOHN DOE")
    private String subject;

    @Schema(description = "Sertifika issuer (kim tarafından verildiği)",
            example = "C=TR,O=Example CA,CN=Example E-Signature Certificate Authority")
    private String issuer;

    @Schema(description = "Geçerlilik başlangıç tarihi")
    @JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss'Z'", timezone = "UTC")
    private Date validFrom;

    @Schema(description = "Geçerlilik bitiş tarihi")
    @JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss'Z'", timezone = "UTC")
    private Date validTo;

    @Schema(description = "Private key mevcut mu?", example = "true")
    private boolean hasPrivateKey;

    @Schema(description = "Sertifika tipi", example = "X.509")
    private String type;

    @Schema(description = "İmza algoritması", example = "SHA512withECDSA")
    private String signatureAlgorithm;

    @Schema(description = "Sertifika kullanım alanları (Key Usage)", 
            example = "Digital Signature, Non Repudiation")
    private String keyUsage;

    @Schema(description = "Genişletilmiş kullanım alanları (Extended Key Usage)", 
            example = "Code Signing, Email Protection")
    private String extendedKeyUsage;

    @Schema(description = "Sertifika politikaları (Certificate Policies OIDs)", 
            example = "2.16.792.3.0.4.1.1.4")
    private String certificatePolicies;

    private String publicKeyAlgorithm;
    private String base64EncodedCertificate;

    public CertificateInfoDto() {
    }

    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }

    public String getSerialNumberHex() {
        return serialNumberHex;
    }

    public void setSerialNumberHex(String serialNumberHex) {
        this.serialNumberHex = serialNumberHex;
    }

    public String getSerialNumberDec() {
        return serialNumberDec;
    }

    public void setSerialNumberDec(String serialNumberDec) {
        this.serialNumberDec = serialNumberDec;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public Date getValidFrom() {
        return validFrom;
    }

    public void setValidFrom(Date validFrom) {
        this.validFrom = validFrom;
    }

    public Date getValidTo() {
        return validTo;
    }

    public void setValidTo(Date validTo) {
        this.validTo = validTo;
    }

    public boolean isHasPrivateKey() {
        return hasPrivateKey;
    }

    public void setHasPrivateKey(boolean hasPrivateKey) {
        this.hasPrivateKey = hasPrivateKey;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public String getKeyUsage() {
        return keyUsage;
    }

    public void setKeyUsage(String keyUsage) {
        this.keyUsage = keyUsage;
    }

    public String getExtendedKeyUsage() {
        return extendedKeyUsage;
    }

    public void setExtendedKeyUsage(String extendedKeyUsage) {
        this.extendedKeyUsage = extendedKeyUsage;
    }

    public String getCertificatePolicies() {
        return certificatePolicies;
    }

    public void setCertificatePolicies(String certificatePolicies) {
        this.certificatePolicies = certificatePolicies;
    }

    public String getPublicKeyAlgorithm() {
        return publicKeyAlgorithm;
    }

    public void setPublicKeyAlgorithm(String publicKeyAlgorithm) {
        this.publicKeyAlgorithm = publicKeyAlgorithm;
    }

    public String getBase64EncodedCertificate() {
        return base64EncodedCertificate;
    }

    public void setBase64EncodedCertificate(String base64EncodedCertificate) {
        this.base64EncodedCertificate = base64EncodedCertificate;
    }

    @Override
    public String toString() {
        return "CertificateInfoDto{" +
                "alias='" + alias + '\'' +
                ", serialNumberHex='" + serialNumberHex + '\'' +
                ", serialNumberDec='" + serialNumberDec + '\'' +
                ", subject='" + subject + '\'' +
                ", issuer='" + issuer + '\'' +
                ", validFrom=" + validFrom +
                ", validTo=" + validTo +
                ", hasPrivateKey=" + hasPrivateKey +
                ", type='" + type + '\'' +
                ", signatureAlgorithm='" + signatureAlgorithm + '\'' +
                ", keyUsage='" + keyUsage + '\'' +
                ", extendedKeyUsage='" + extendedKeyUsage + '\'' +
                ", certificatePolicies='" + certificatePolicies + '\'' +
                ", publicKeyAlgorithm='" + publicKeyAlgorithm + '\'' +
                ", base64EncodedCertificate='" + base64EncodedCertificate + '\'' +
                '}';
    }
}

