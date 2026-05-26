package io.mersel.dss.signer.api.controllers;

import java.util.UUID;

import io.mersel.dss.signer.api.models.SigningMaterial;
import io.mersel.dss.signer.api.services.notification.SignerNotifier;
import io.mersel.dss.signer.api.services.signature.pades.PAdESSignatureService;
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
import io.mersel.dss.signer.api.dtos.SignPadesDto;
import io.mersel.dss.signer.api.models.ErrorModel;
import io.mersel.dss.signer.api.models.SignResponse;

/**
 * PAdES (PDF İleri Seviye Elektronik İmza) işlemleri için REST controller.
 * CAdES tabanlı PDF belge imzalama işlemlerini yönetir.
 */
@RestController
@CrossOrigin(origins = "*", allowedHeaders = "*", methods = {RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT, RequestMethod.DELETE, RequestMethod.OPTIONS})
public class PadesController {

    private static final Logger LOGGER = LoggerFactory.getLogger(PadesController.class);

    private final PAdESSignatureService padesSignatureService;
    private final SigningMaterial signingMaterial;
    private final SignerNotifier signerNotifier;

    public PadesController(PAdESSignatureService padesSignatureService,
                          SigningMaterial signingMaterial,
                          SignerNotifier signerNotifier) {
        this.padesSignatureService = padesSignatureService;
        this.signingMaterial = signingMaterial;
        this.signerNotifier = signerNotifier;
    }

    @Operation(
        summary = "PDF belgelerini PAdES imzası ile imzalar",
        description = "PDF belgelerine gömülü CAdES imzası oluşturur"
    )
    @RequestMapping(value = "/v1/padessign", method = RequestMethod.POST,
        consumes = {MediaType.MULTIPART_FORM_DATA_VALUE})
    @ApiResponses({
        @ApiResponse(responseCode = "200", 
            content = @Content(schema = @Schema(type = "string", format = "binary"))),
        @ApiResponse(responseCode = "400", 
            content = @Content(schema = @Schema(implementation = ErrorModel.class))),
        @ApiResponse(responseCode = "500")
    })
    public ResponseEntity<?> signPades(@ModelAttribute SignPadesDto dto) {
        try {
            if (dto.getDocument() == null) {
                LOGGER.warn("Geçersiz istek: PDF belgesi eksik");
                return ResponseEntity.badRequest()
                    .body(new ErrorModel("INVALID_INPUT", "PDF belgesi zorunludur"));
            }

            boolean appendMode = Boolean.TRUE.equals(dto.getAppendMode());
            byte[] attachment = dto.getAttachment() != null && !dto.getAttachment().isEmpty() 
                ? dto.getAttachment().getBytes() 
                : null;

            // try-with-resources: MultipartFile.getInputStream() Tomcat'in
            // disk-tabanlı temp dosyasına bir FileInputStream açar. Bu stream
            // explicit kapatılmazsa Windows'ta cleanupMultipart "Cannot delete
            // upload_*.tmp" UncheckedIOException'a düşer (Linux'ta belirti
            // vermez ama handle yine sızar). CADES endpoint'iyle tutarlı pattern.
            SignResponse result;
            try (java.io.InputStream is = dto.getDocument().getInputStream()) {
                result = padesSignatureService.signPdf(
                    is,
                    attachment,
                    dto.getAttachmentFileName(),
                    appendMode,
                    signingMaterial
                );
            }

            LOGGER.info("PAdES imzası başarıyla oluşturuldu (ekleme modu: {})", appendMode);

            // Content-Type açıkça set ediliyor — Spring default'ta byte[] body için
            // application/octet-stream üretir; bu PDF'i browser'ın inline gösterememesine
            // ve client tarafında "binary blob" sanılmasına yol açıyor.
            return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_PDF)
                .header("Content-Disposition",
                    "attachment; filename=\"signed-" + UUID.randomUUID() + ".pdf\"")
                .body(result.getSignedDocument());

        } catch (Exception e) {
            LOGGER.error("PAdES imzası oluşturulurken hata", e);
            byte[] documentBytes = null;
            String fileName = null;
            String contentType = null;
            try {
                if (dto.getDocument() != null && !dto.getDocument().isEmpty()) {
                    fileName = dto.getDocument().getOriginalFilename();
                    contentType = dto.getDocument().getContentType();
                    documentBytes = dto.getDocument().getBytes();
                }
            } catch (Exception readEx) {
                LOGGER.debug("Notifier için dosya bytes okunamadı: {}", readEx.getMessage());
            }
            signerNotifier.notifyOnSignatureFailure(
                    "/v1/padessign", "PAdES", e, documentBytes, fileName, contentType);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ErrorModel("SIGNATURE_FAILED", e.getMessage()));
        }
    }
}
