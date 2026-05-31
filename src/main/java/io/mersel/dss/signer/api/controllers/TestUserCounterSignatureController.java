package io.mersel.dss.signer.api.controllers;

import io.mersel.dss.signer.api.dtos.TestUserCounterSignatureDto;
import io.mersel.dss.signer.api.exceptions.SignatureException;
import io.mersel.dss.signer.api.models.ErrorModel;
import io.mersel.dss.signer.api.models.SignResponse;
import io.mersel.dss.signer.api.services.signature.xades.TestUserCounterSignatureService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

/**
 * <strong>GİB test ortamı</strong> için entegratör tarafından imzalanmış
 * XAdES belgesine (tipik: HrXml — Kullanıcı Açma/Kapama zarfı), Kamu SM'nin
 * publicly-published mali mühür <em>RSA-2048 test sertifikalarından</em>
 * birini kullanarak <em>counter signature</em> ekleyen endpoint.
 *
 * <h3>Neden ayrı bir endpoint?</h3>
 * <p>HrXml akışında GİB iki imza ister: (1) entegratör mali mührü
 * (ana imza), (2) kullanıcının/kurumun mali mührü (counter signature).
 * Üretimde (2) gerçek kurumun PFX'i ile atılır; test ortamında ise GİB'in
 * sertifika onayı olmadığı için Kamu SM'in test ortamına özel olarak
 * yayımladığı <em>TestKurum1 / TestKurum2 / TestKurum3</em> RSA-2048
 * test PFX'leri kullanılır.</p>
 *
 * <h3>Tasarım garantisi — production akışlarına etki yok</h3>
 * <p>Bu controller ve arkasındaki
 * {@link TestUserCounterSignatureService} <strong>tamamen izoledir</strong>:
 * ne ortak {@code SigningMaterial} / {@code SigningMaterialFactory} /
 * {@code CryptoSignerService} / {@code Semaphore} / {@code CertificateVerifier}
 * bean'ine, ne de ortak {@code SignerNotifier}'a bağlıdır. Standart imza
 * süreçlerinde yapılan herhangi bir değişiklik bu endpoint'i etkilemez ve
 * tersi. Tek paylaşılan kaynak repo'daki {@code resources/test-certs/}
 * dizinidir (test PFX'leri).</p>
 *
 * <h3>Production'da KULLANILMAZ</h3>
 * <ul>
 *   <li>PFX'ler Kamu SM'in <em>publicly-published</em> mali mühür yetkisiz
 *       test sertifikalarıdır; gerçek e-Belge gönderiminde GİB reddeder.</li>
 *   <li>Üretim ortamlarında reverse-proxy / web ACL seviyesinde kapatılması
 *       önerilir.</li>
 * </ul>
 *
 * <h3>Tipik akış</h3>
 * <ol>
 *   <li>Entegratör (DSS imzalayıcı) HrXml zarfını mali mührüyle imzalar
 *       ({@code POST /v1/xadessign} + {@code documentType=HrXml}).</li>
 *   <li>İmzalı XML, bu endpoint'e {@code TestKurum1|2|3} enum'u ile
 *       gönderilir.</li>
 *   <li>Dönüş: aynı XML, parent {@code <ds:Signature>} altına
 *       {@code <xades:CounterSignature>} eklenmiş hali.</li>
 *   <li>GİB test ortamına gönderim, bu çıktı üzerinden yapılır.</li>
 * </ol>
 *
 * @see io.mersel.dss.signer.api.models.enums.TestCompany
 * @see TestUserCounterSignatureService
 */
@RestController
@Tag(name = "TestUserCounterSignature",
        description = "GİB test ortamı için Kamu SM RSA test kurum sertifikası ile "
                + "entegratör tarafından imzalanmış XAdES belgesine counter signature ekler. "
                + "Production akışlarında KULLANILMAZ.")
@CrossOrigin(origins = "*", allowedHeaders = "*",
        methods = {RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT,
                RequestMethod.DELETE, RequestMethod.OPTIONS})
public class TestUserCounterSignatureController {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(TestUserCounterSignatureController.class);

    private static final String ENDPOINT_PATH = "/v1/testusercountersign";

    private final TestUserCounterSignatureService counterSignatureService;

    public TestUserCounterSignatureController(
            TestUserCounterSignatureService counterSignatureService) {
        this.counterSignatureService = counterSignatureService;
    }

    @Operation(
            summary = "Entegratör imzalı XAdES belgesine TestKurum counter signature ekler",
            description = "GİB TEST ORTAMI içindir; PRODUCTION akışlarında kullanılmaz. "
                    + "İstek, daha önce entegratör mali mührüyle imzalanmış bir XAdES belgesi "
                    + "(tipik olarak HrXml — Kullanıcı Açma/Kapama zarfı) ile birlikte bir "
                    + "'testCompany' enum değeri gönderir; karşılığında belgedeki ilk "
                    + "<ds:Signature> altına seçilen TestKurum PFX'iyle (Kamu SM publicly-"
                    + "published RSA-2048 test sertifikası) <xades:CounterSignature> eklenmiş "
                    + "XML döner. İmzalama yöntemi mersel-dss-agent-signer-java'daki "
                    + "production-doğrulanmış XadesService.doCounterSignature ile birebir parite: "
                    + "javax.xml.crypto.dsig DOM backend, XAdES-BES, RSA-SHA256, c14n WithComments. "
                    + "Bu endpoint production imzalama pipeline'ından TAMAMEN İZOLEDİR — "
                    + "paylaşılan SigningMaterial / Factory / CertificateVerifier / XAdESService "
                    + "bean'lerine değmez; PFX her istekte runtime'da açılır."
    )
    @RequestMapping(value = ENDPOINT_PATH, method = RequestMethod.POST,
            consumes = {MediaType.MULTIPART_FORM_DATA_VALUE})
    @ApiResponses({
            @ApiResponse(responseCode = "200",
                    description = "Counter-sign edilmiş XAdES belgesi (application/xml). "
                            + "Yanıt header'ı 'x-signature-value' counter signature'ın "
                            + "Base64 değerini içerir.",
                    content = @Content(schema = @Schema(type = "string", format = "binary"))),
            @ApiResponse(responseCode = "400",
                    description = "Geçersiz istek: belge eksik, testCompany eksik, "
                            + "PFX bulunamadı veya belgede counter-sign edilebilecek "
                            + "XAdES imza yok.",
                    content = @Content(schema = @Schema(implementation = ErrorModel.class))),
            @ApiResponse(responseCode = "500",
                    description = "Beklenmedik sunucu hatası (PFX yüklenemedi, DSS counter-sign "
                            + "başarısız vs.)",
                    content = @Content(schema = @Schema(implementation = ErrorModel.class)))
    })
    public ResponseEntity<?> signCounter(@ModelAttribute TestUserCounterSignatureDto dto) {
        if (dto.getDocument() == null || dto.getDocument().isEmpty()) {
            LOGGER.warn("TestKurum counter-signature: belge eksik");
            return ResponseEntity.badRequest()
                    .body(new ErrorModel("INVALID_INPUT",
                            "Counter-sign için 'document' alanı zorunludur"));
        }
        if (dto.getTestCompany() == null) {
            LOGGER.warn("TestKurum counter-signature: testCompany eksik");
            return ResponseEntity.badRequest()
                    .body(new ErrorModel("INVALID_INPUT",
                            "Counter-sign için 'testCompany' alanı zorunludur "
                                    + "(TestKurum1 / TestKurum2 / TestKurum3)"));
        }

        try {
            // try-with-resources: MultipartFile.getInputStream() Tomcat'in
            // disk-tabanlı temp dosyasına bir FileInputStream açar; XadesController
            // ile aynı handle-leak kontratı.
            SignResponse result;
            try (java.io.InputStream is = dto.getDocument().getInputStream()) {
                result = counterSignatureService.counterSign(is, dto.getTestCompany());
            }

            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_XML)
                    .header("x-signature-value", result.getSignatureValue())
                    .header("Content-Disposition",
                            "attachment; filename=\"countersigned-" + UUID.randomUUID() + ".xml\"")
                    .body(result.getSignedDocument());

        } catch (SignatureException e) {
            String code = e.getErrorCode();
            if ("INVALID_INPUT".equals(code)
                    || "NO_PARENT_SIGNATURE".equals(code)
                    || "TEST_CERT_NOT_FOUND".equals(code)) {
                LOGGER.warn("TestKurum counter-signature reddedildi: code={}, msg={}",
                        code, e.getMessage());
                return ResponseEntity.badRequest()
                        .body(new ErrorModel(code, e.getMessage()));
            }
            LOGGER.error("TestKurum counter-signature oluşturulurken hata", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorModel("SIGNATURE_FAILED", e.getMessage()));

        } catch (Exception e) {
            LOGGER.error("TestKurum counter-signature oluşturulurken beklenmedik hata", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorModel("SIGNATURE_FAILED", e.getMessage()));
        }
    }
}
