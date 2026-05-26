package io.mersel.dss.signer.api.dtos;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * {@code POST /v1/hashsign} endpoint'inin başarılı yanıtı.
 *
 * <p>İmza baytları base64 encoded biçimde döner:</p>
 * <ul>
 *   <li><b>RSA</b>: PKCS#1 v1.5 padded RSA cipher çıktısı (modül büyüklüğüyle aynı uzunlukta).</li>
 *   <li><b>ECDSA</b>: DER SEQUENCE { r, s } formatında imza (P-256 için ~70-72 byte).</li>
 * </ul>
 *
 * <p>e-Defter akışında bu değer doğrudan {@code <ds:SignatureValue>} elementine
 * yazılabilir.</p>
 */
@Schema(description = "Pre-hashed digest imzalama yanıtı")
public class SignHashResponseDto {

    @Schema(
        description = "İmza baytlarının base64 encoded değeri. RSA: PKCS#1 v1.5 padded; "
                + "ECDSA: DER SEQUENCE { r, s }.",
        example = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A..."
    )
    private String base64EncodedSignature;

    public SignHashResponseDto() {
    }

    public SignHashResponseDto(String base64EncodedSignature) {
        this.base64EncodedSignature = base64EncodedSignature;
    }

    public String getBase64EncodedSignature() {
        return base64EncodedSignature;
    }

    public void setBase64EncodedSignature(String base64EncodedSignature) {
        this.base64EncodedSignature = base64EncodedSignature;
    }
}
