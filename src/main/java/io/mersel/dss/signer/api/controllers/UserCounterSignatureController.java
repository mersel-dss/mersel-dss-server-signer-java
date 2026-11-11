package io.mersel.dss.signer.api.controllers;

import io.mersel.dss.signer.api.dtos.UserCounterSignatureDto;
import io.mersel.dss.signer.api.exceptions.SignatureException;
import io.mersel.dss.signer.api.models.ErrorModel;
import io.mersel.dss.signer.api.models.SignResponse;
import io.mersel.dss.signer.api.models.SigningMaterial;
import io.mersel.dss.signer.api.services.metrics.SignatureMetrics;
import io.mersel.dss.signer.api.services.signature.xades.SigningMaterialCounterSignatureService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
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
 * Entegratör tarafından imzalanmış XAdES belgesine (tipik: HrXml — Kullanıcı
 * Açma/Kapama zarfı), entegratörün <b>kendi ana imza sertifikasıyla</b>
 * (ana {@link SigningMaterial} — PFX veya HSM) <em>counter signature</em>
 * (GİB terminolojisiyle <b>seri imza</b>) ekleyen endpoint.
 *
 * <h3>Neden bu endpoint gerekli?</h3>
 * <p>GİB, özel entegratörün müşterileri adına belge/rapor göndermesi için
 * önce kendisini ilgili hizmette (ör. e-MM) aktif etmesini ister. Bu
 * self-activation HrXml zarfında <b>iki imza</b> gerektirir:</p>
 * <ol>
 *   <li><b>Entegratör imzası</b> — ana imza; {@code POST /v1/xadessign}
 *       ({@code documentType=HrXml}) ile atılır.</li>
 *   <li><b>Seri imza</b> — counter signature; açılan kullanıcı entegratörün
 *       kendisi olduğundan bu imza da entegratörün kendi sertifikasıyla
 *       atılmalıdır (GİB aksi halde 1182 "eşleşmeyen seri imza bilgisi"
 *       hatası verir). Bu endpoint tam bu imzayı atar.</li>
 * </ol>
 *
 * <h3>{@code /v1/testusercountersign} ile farkı</h3>
 * <p>O endpoint GİB <em>test ortamında</em>, açılan kullanıcı üçüncü bir
 * kurum olduğunda kullanılan Kamu SM TestKurum PFX'leriyle imzalar ve
 * production'da kullanılmaz. Bu endpoint ise ana imza materyalini (PFX veya
 * HSM) kullanır — hem test hem production self-activation akışında
 * geçerlidir.</p>
 *
 * <h3>Tipik akış</h3>
 * <ol>
 *   <li>Entegratör (bu servis) HrXml zarfını mali mührüyle imzalar
 *       ({@code POST /v1/xadessign} + {@code documentType=HrXml}).</li>
 *   <li>İmzalı XML bu endpoint'e gönderilir.</li>
 *   <li>Dönüş: aynı XML, parent {@code <ds:Signature>} altına
 *       {@code <xades:CounterSignature>} eklenmiş hali.</li>
 *   <li>GİB'e gönderim, bu çıktı üzerinden yapılır.</li>
 * </ol>
 *
 * <h3>Feature flag — varsayılan KAPALI</h3>
 * <p>Bu endpoint, entegratörün <b>kendi aktif sertifikasını</b> alt kullanıcı
 * gibi kullanarak CounterSignature (seri imza) atabilmesi için — yani
 * entegratörün kendi kullanıcısını açma (self-activation) akışı için —
 * geliştirilmiştir. Servisin ana mali mührüyle, gönderilen herhangi bir
 * imzalı XAdES belgesine seri imza atabildiğinden <b>bilinçli olarak
 * açılmalıdır</b>:</p>
 * <ul>
 *   <li>Property: {@code mersel.signer.integrator-countersign.enabled}</li>
 *   <li>ENV: {@code INTEGRATOR_COUNTERSIGN_ENABLED=true}</li>
 * </ul>
 * <p>Değer verilmezse (veya {@code true} dışında bir değerse) controller
 * bean'i hiç oluşturulmaz ve endpoint 404 döner. Self-activation işlemi
 * tamamlandıktan sonra tekrar kapatılması önerilir.</p>
 *
 * @see SigningMaterialCounterSignatureService
 * @see io.mersel.dss.signer.api.controllers.TestUserCounterSignatureController
 */
@RestController
@ConditionalOnProperty(
        name = "mersel.signer.integrator-countersign.enabled",
        havingValue = "true",
        matchIfMissing = false)
@Tag(name = "UserCounterSignature",
        description = "Entegratör imzalı XAdES belgesine entegratörün kendi sertifikasıyla "
                + "counter signature (seri imza) ekler. Entegratörün kendi aktif sertifikasını "
                + "alt kullanıcı gibi kullanarak CounterSignature atabilmesi (self-activation) "
                + "için geliştirilmiştir. PFX ve HSM backend'lerinin ikisini de destekler. "
                + "Varsayılan KAPALI — INTEGRATOR_COUNTERSIGN_ENABLED=true ile açılır.")
@CrossOrigin(origins = "*", allowedHeaders = "*",
        methods = {RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT,
                RequestMethod.DELETE, RequestMethod.OPTIONS})
public class UserCounterSignatureController {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(UserCounterSignatureController.class);

    private static final String ENDPOINT_PATH = "/v1/usercountersign";

    private final SigningMaterialCounterSignatureService counterSignatureService;
    private final SigningMaterial signingMaterial;
    private final SignatureMetrics signatureMetrics;

    public UserCounterSignatureController(
            SigningMaterialCounterSignatureService counterSignatureService,
            SigningMaterial signingMaterial,
            SignatureMetrics signatureMetrics) {
        this.counterSignatureService = counterSignatureService;
        this.signingMaterial = signingMaterial;
        this.signatureMetrics = signatureMetrics;
    }

    @Operation(
            summary = "Entegratör imzalı XAdES belgesine entegratörün kendi sertifikasıyla counter signature ekler",
            description = "İstek, daha önce entegratör mali mührüyle imzalanmış bir XAdES belgesi "
                    + "(tipik olarak HrXml — Kullanıcı Açma/Kapama zarfı) ile birlikte gönderilir; "
                    + "karşılığında belgedeki ilk <ds:Signature> altına, ana imza materyaliyle "
                    + "(PFX veya HSM) imzalanmış <xades:CounterSignature> eklenmiş XML döner. "
                    + "Üretilen counter signature eksiksiz bir XAdES-BES imzasıdır: iki Reference "
                    + "(kendi SignedProperties + karşı imzalanan SignatureValue), KeyInfo'da "
                    + "yalnız imzacı sertifikası, SigningTime + SigningCertificate (CertDigest + "
                    + "IssuerSerial). Algoritma seçimi sertifikaya göredir: EC → ECDSA-SHA384/SHA-384, "
                    + "RSA → RSA-SHA256/SHA-256. "
                    + "NOT: Entegratörün kendi aktif sertifikasını alt kullanıcı gibi kullanarak "
                    + "CounterSignature atabilmesi (kendi kullanıcısını açma) için geliştirilmiştir. "
                    + "Feature flag ile varsayılan KAPALIDIR; "
                    + "INTEGRATOR_COUNTERSIGN_ENABLED=true verilmeden endpoint 404 döner."
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
                    description = "Geçersiz istek: belge eksik veya belgede counter-sign "
                            + "edilebilecek XAdES imza yok.",
                    content = @Content(schema = @Schema(implementation = ErrorModel.class))),
            @ApiResponse(responseCode = "500",
                    description = "Beklenmedik sunucu hatası (imza başarısız vs.)",
                    content = @Content(schema = @Schema(implementation = ErrorModel.class)))
    })
    public ResponseEntity<?> signCounter(@ModelAttribute UserCounterSignatureDto dto) {
        if (dto.getDocument() == null || dto.getDocument().isEmpty()) {
            LOGGER.warn("Entegratör seri imzası: belge eksik");
            return ResponseEntity.badRequest()
                    .body(new ErrorModel("INVALID_INPUT",
                            "Counter-sign için 'document' alanı zorunludur"));
        }

        long inputSize = dto.getDocument().getSize();
        SignatureMetrics.Sample sample = signatureMetrics.start(
                "CounterSignature", "xades", "integrator");
        try {
            // try-with-resources: MultipartFile.getInputStream() Tomcat'in
            // disk-tabanlı temp dosyasına bir FileInputStream açar; XadesController
            // ile aynı handle-leak kontratı.
            SignResponse result;
            try (java.io.InputStream is = dto.getDocument().getInputStream()) {
                result = counterSignatureService.counterSign(is, signingMaterial);
            }

            sample.success(inputSize,
                    result.getSignedDocument() != null ? result.getSignedDocument().length : -1);
            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_XML)
                    .header("x-signature-value", result.getSignatureValue())
                    .header("Content-Disposition",
                            "attachment; filename=\"countersigned-" + UUID.randomUUID() + ".xml\"")
                    .body(result.getSignedDocument());

        } catch (SignatureException e) {
            sample.failure(inputSize);
            String code = e.getErrorCode();
            if ("INVALID_INPUT".equals(code) || "NO_PARENT_SIGNATURE".equals(code)) {
                LOGGER.warn("Entegratör seri imzası reddedildi: code={}, msg={}",
                        code, e.getMessage());
                return ResponseEntity.badRequest()
                        .body(new ErrorModel(code, e.getMessage()));
            }
            LOGGER.error("Entegratör seri imzası oluşturulurken hata", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorModel("SIGNATURE_FAILED", e.getMessage()));

        } catch (Exception e) {
            sample.failure(inputSize);
            LOGGER.error("Entegratör seri imzası oluşturulurken beklenmedik hata", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorModel("SIGNATURE_FAILED", e.getMessage()));
        }
    }
}
