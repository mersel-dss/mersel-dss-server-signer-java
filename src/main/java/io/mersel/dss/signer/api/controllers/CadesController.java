package io.mersel.dss.signer.api.controllers;

import java.util.UUID;

import io.mersel.dss.signer.api.models.SigningMaterial;
import io.mersel.dss.signer.api.services.signature.cades.CAdESSignatureService;
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

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.mersel.dss.signer.api.dtos.SignCadesDto;
import io.mersel.dss.signer.api.models.ErrorModel;
import io.mersel.dss.signer.api.models.SignResponse;

/**
 * CAdES-BES seviyesinde elektronik imza operasyonlarını yöneten REST controller.
 *
 * <p>CAdES (CMS Advanced Electronic Signatures), ETSI TS 101 733 standardına uygun
 * olarak her türlü dosya formatı üzerinde dijital imza oluşturmayı sağlar.
 * Bu controller multipart/form-data üzerinden gelen dosyaları alıp imzalar ve
 * sonucu PKCS#7 (.p7s) formatında döndürür.</p>
 *
 * <p>Desteklenen imza modları:</p>
 * <ul>
 *   <li><b>Attached (gömülü):</b> İmzalanan içerik, CMS zarfının içine gömülür.
 *       Tek bir .p7s dosyası hem imzayı hem orijinal belgeyi barındırır.</li>
 *   <li><b>Detached (ayrık):</b> Yalnızca imza verisi üretilir; orijinal belge
 *       ayrı saklanır. Doğrulama sırasında her ikisi de gereklidir.</li>
 * </ul>
 *
 * <p>Detached modda imza değeri ayrıca {@code x-signature-value} response header'ında
 * Base64 olarak da gönderilir. Attached modda bu header eklenmez çünkü CMS zarfı
 * büyük dosyalarda HTTP header boyut limitini aşabilir.</p>
 *
 * @see CAdESSignatureService
 * @see SigningMaterial
 */
@RestController
@CrossOrigin(origins = "*", allowedHeaders = "*", methods = {RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT, RequestMethod.DELETE, RequestMethod.OPTIONS})
public class CadesController {

    private static final Logger LOGGER = LoggerFactory.getLogger(CadesController.class);

    private final CAdESSignatureService cadesSignatureService;
    private final SigningMaterial signingMaterial;

    /**
     * @param cadesSignatureService CAdES imza oluşturma işlemlerini gerçekleştiren servis
     * @param signingMaterial       Uygulama genelinde kullanılan sertifika ve private key çifti.
     *                              Genellikle PKCS#11 (HSM) veya PKCS#12 (.pfx) kaynağından yüklenir.
     */
    public CadesController(CAdESSignatureService cadesSignatureService,
                           SigningMaterial signingMaterial) {
        this.cadesSignatureService = cadesSignatureService;
        this.signingMaterial = signingMaterial;
    }

    /**
     * Gelen dosyayı CAdES-BES seviyesinde imzalar ve .p7s olarak döndürür.
     *
     * <p>İstek multipart/form-data olarak gönderilmelidir. {@code document} alanı zorunlu,
     * {@code detached} alanı opsiyoneldir (varsayılan: false → attached imza).</p>
     *
     * <p>Başarılı yanıt her zaman {@code application/octet-stream} olarak döner.
     * Detached modda ek olarak {@code x-signature-value} header'ı Base64 imza değerini içerir.</p>
     *
     * @param dto Belge ve imza parametrelerini taşıyan DTO
     * @return İmzalı .p7s dosyası veya hata durumunda {@link ErrorModel}
     */
    @Operation(
            summary = "Dosyaları CAdES-BES imzası ile imzalar",
            description = "Her türlü dosya için CAdES-BES seviyesinde elektronik imza oluşturur. " +
                    "Attached (gömülü) veya detached (ayrık) imza desteklenir."
    )
    @RequestMapping(value = "/v1/cadessign", method = RequestMethod.POST,
            consumes = {MediaType.MULTIPART_FORM_DATA_VALUE})
    @ApiResponses({
            @ApiResponse(responseCode = "200",
                    description = "CAdES imzası başarıyla oluşturuldu",
                    content = @Content(schema = @Schema(type = "string", format = "binary"))),
            @ApiResponse(responseCode = "400",
                    content = @Content(schema = @Schema(implementation = ErrorModel.class))),
            @ApiResponse(responseCode = "500")
    })
    public ResponseEntity<?> signCades(@ModelAttribute SignCadesDto dto) {
        try {
            if (dto.getDocument() == null || dto.getDocument().isEmpty()) {
                LOGGER.warn("Geçersiz istek: belge eksik");
                return ResponseEntity.badRequest()
                        .body(new ErrorModel("INVALID_INPUT", "Belge zorunludur"));
            }

            boolean detached = Boolean.TRUE.equals(dto.getDetached());

            SignResponse result;
            try (java.io.InputStream is = dto.getDocument().getInputStream()) {
                result = cadesSignatureService.signData(is, detached, signingMaterial);
            }

            LOGGER.info("CAdES imzası başarıyla oluşturuldu (detached: {})", detached);

            // Attached imzada CMS zarfı orijinal belgeyi de içerdiğinden Base64 hali
            // çok büyük olabilir; bu yüzden header yalnızca detached modda eklenir.
            ResponseEntity.BodyBuilder builder = ResponseEntity.ok()
                    .header("Content-Disposition",
                            "attachment; filename=\"signed-" + UUID.randomUUID() + ".p7s\"")
                    .contentType(MediaType.APPLICATION_OCTET_STREAM);
            if (detached) {
                builder = builder.header("x-signature-value", result.getSignatureValue());
            }
            return builder.body(result.getSignedDocument());

        } catch (Exception e) {
            LOGGER.error("CAdES imzası oluşturulurken hata", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorModel("SIGNATURE_FAILED", e.getMessage()));
        }
    }
}