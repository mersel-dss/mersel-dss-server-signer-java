package io.mersel.dss.signer.api.dtos;

import io.swagger.v3.oas.annotations.media.Schema;
import org.springframework.web.multipart.MultipartFile;

import javax.validation.constraints.NotNull;

/**
 * Entegratör tarafından imzalanmış XAdES belgesine, <strong>entegratörün
 * kendi ana imza sertifikasıyla</strong> (ana {@code SigningMaterial} —
 * PFX veya HSM) <em>counter signature</em> (seri imza) ekleme isteğinin
 * DTO'su.
 *
 * <p>Kullanım senaryosu: GİB'in özel entegratörlerden, müşterileri adına
 * belge/rapor göndermeden önce <em>kendilerini</em> ilgili hizmette (ör.
 * e-MM) aktif etmelerini istediği akış. HrXml (Kullanıcı Açma/Kapama)
 * zarfı entegratör mali mührüyle imzalandıktan sonra, açılan kullanıcı
 * entegratörün kendisi olduğundan GİB'in "seri imza" (counter signature)
 * kontrolü de entegratörün kendi sertifikasıyla sağlanır.</p>
 *
 * <p>Farklı sertifika seçeneği gerektiren GİB <em>test ortamı</em> akışı
 * için (Kamu SM TestKurum sertifikaları)
 * {@link io.mersel.dss.signer.api.controllers.TestUserCounterSignatureController}
 * endpoint'ine bakın.</p>
 */
public class UserCounterSignatureDto {

    /**
     * Counter signature eklenecek, daha önce entegratör mali mührüyle
     * imzalanmış XAdES belgesi. Tipik kullanım: HrXml (Kullanıcı
     * Açma/Kapama) zarfı.
     */
    private MultipartFile document;

    public MultipartFile getDocument() {
        return document;
    }

    @NotNull
    public void setDocument(MultipartFile document) {
        this.document = document;
    }
}
