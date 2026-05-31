package io.mersel.dss.signer.api.dtos;

import io.mersel.dss.signer.api.models.enums.TestCompany;
import io.swagger.v3.oas.annotations.media.Schema;
import org.springframework.web.multipart.MultipartFile;

import javax.validation.constraints.NotNull;

/**
 * <strong>GİB test ortamı</strong> için entegratör tarafından imzalanmış
 * XAdES belgesine, seçilen test kurum mali mühür sertifikasıyla
 * <em>counter signature</em> ekleme isteğinin DTO'su.
 *
 * <p><strong>Production'da KULLANILMAZ.</strong> Detay için
 * {@link io.mersel.dss.signer.api.controllers.TestUserCounterSignatureController}
 * Javadoc'una bakın.</p>
 *
 * <h3>Counter-sign edilecek imza nasıl seçilir?</h3>
 * <p>Daima belgedeki <em>ilk</em> {@code <ds:Signature>} elementi
 * counter-sign edilir — bu, {@code mersel-dss-agent-signer-java}'daki
 * production-doğrulanmış davranışla birebir aynıdır. HrXml akışında zaten
 * tek bir entegratör imzası olduğu için ek bir parent ID parametresine
 * ihtiyaç yoktur.</p>
 */
public class TestUserCounterSignatureDto {

    /**
     * Counter signature eklenecek, daha önce entegratör mali mührüyle
     * imzalanmış XAdES belgesi. Tipik kullanım: HrXml (Kullanıcı
     * Açma/Kapama) zarfı.
     */
    private MultipartFile document;

    /**
     * Counter signature için kullanılacak Kamu SM RSA test sertifikası
     * (TestKurum1 / TestKurum2 / TestKurum3). PFX
     * {@code resources/test-certs/} altından yüklenir; private key ile
     * imza atılır.
     */
    private TestCompany testCompany;

    public MultipartFile getDocument() {
        return document;
    }

    @NotNull
    public void setDocument(MultipartFile document) {
        this.document = document;
    }

    public TestCompany getTestCompany() {
        return testCompany;
    }

    @NotNull
    @Schema(
        enumAsRef = true,
        description = "Counter signature için kullanılacak Kamu SM RSA test kurum sertifikası. "
                + "Sadece test ortamında geçerlidir; production akışlarında kullanılmaz."
    )
    public void setTestCompany(TestCompany testCompany) {
        this.testCompany = testCompany;
    }
}
