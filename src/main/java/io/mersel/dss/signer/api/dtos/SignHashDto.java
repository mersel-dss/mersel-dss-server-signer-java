package io.mersel.dss.signer.api.dtos;

import javax.validation.constraints.NotBlank;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import io.swagger.v3.oas.annotations.media.Schema;

/**
 * {@code POST /v1/hashsign} endpoint'i için request body kontratı.
 *
 * <h3>Anlamlama</h3>
 * <p>Caller, server'a <b>zaten hesaplanmış</b> bir digest gönderir. Server bu
 * digest'i <em>tekrar hash'lemez</em>; doğrudan PKCS#1 v1.5 padding (RSA) veya
 * raw ECDSA imzalama uygular. Tipik kullanım e-Defter mali mührü ve manuel
 * XAdES SignedInfo digest imzalama akışlarıdır.</p>
 *
 * <h3>Validation</h3>
 * <ul>
 *   <li>{@link #base64EncodedDigest} zorunludur ({@code @NotBlank}); boş gelirse
 *       400 INVALID_INPUT döner.</li>
 *   <li>Decoded digest uzunluğu {@link #digestAlgorithm} ile uyumlu olmalıdır
 *       (örn. SHA-256 için 32 byte). Service katmanı uzunluk kontrolünü yapar
 *       ve uyumsuz girdiyi 400 ile reddeder.</li>
 * </ul>
 *
 * <h3>Geriye uyumluluk notu</h3>
 * <p>İlk PR taslağında alan adı {@code base64EncodedDataToSign} idi (yanıltıcı —
 * "data" terimi raw veri çağrışımı yapıyordu); merge öncesi netlik için
 * {@code base64EncodedDigest}'a yeniden adlandırıldı. Endpoint henüz release
 * edilmediği için breaking change değil.</p>
 */
@Schema(description = "Pre-hashed digest imzalama isteği")
public class SignHashDto {

    @Schema(
        description = "İmzalanacak hash'in base64 encoded değeri. Caller hash'i kendisi hesaplamalıdır. "
                + "Decoded uzunluk digestAlgorithm ile uyumlu olmalıdır (SHA-256 için 32 byte). "
                + "Server bu digest'i tekrar hash'lemez.",
        example = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
        requiredMode = Schema.RequiredMode.REQUIRED
    )
    @NotBlank
    private String base64EncodedDigest;

    @Schema(
        description = "Hash algoritması. RSA path'inde DigestInfo prefix seçimi için, ECDSA path'inde "
                + "uzunluk doğrulaması için kullanılır. Boş bırakılırsa SHA256 default uygulanır.",
        example = "SHA256",
        defaultValue = "SHA256",
        enumAsRef = true
    )
    private DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA256;

    public String getBase64EncodedDigest() {
        return base64EncodedDigest;
    }

    public void setBase64EncodedDigest(String base64EncodedDigest) {
        this.base64EncodedDigest = base64EncodedDigest;
    }

    public DigestAlgorithm getDigestAlgorithm() {
        return digestAlgorithm;
    }

    /**
     * Setter; {@code null} geçirildiğinde alan {@link DigestAlgorithm#SHA256}'ya düşer.
     * Bu, JSON binding sırasında alanın eksik gelmesi durumunda non-null kontratını korur.
     */
    public void setDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
        this.digestAlgorithm = (digestAlgorithm != null) ? digestAlgorithm : DigestAlgorithm.SHA256;
    }
}
