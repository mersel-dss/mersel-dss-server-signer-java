package io.mersel.dss.signer.api.controllers;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import io.mersel.dss.signer.api.dtos.SignHashDto;
import io.mersel.dss.signer.api.dtos.SignHashResponseDto;
import io.mersel.dss.signer.api.dtos.SignWsSecurityDto;
import io.mersel.dss.signer.api.dtos.SignXadesDto;
import io.mersel.dss.signer.api.models.ErrorModel;
import io.mersel.dss.signer.api.models.SignResponse;
import io.mersel.dss.signer.api.models.SigningMaterial;
import io.mersel.dss.signer.api.models.enums.DocumentType;
import io.mersel.dss.signer.api.services.crypto.DigestAlgorithmResolverService;
import io.mersel.dss.signer.api.services.signature.wssecurity.WsSecuritySignatureService;
import io.mersel.dss.signer.api.services.signature.xades.XAdESSignatureService;
import io.mersel.dss.signer.api.util.Utilities;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.w3c.dom.Document;

import java.util.Base64;
import java.util.UUID;

/**
 * XAdES (XML İleri Seviye Elektronik İmza) işlemleri için REST controller.
 * XML belge imzalama ve WS-Security SOAP zarf imzalama işlemlerini yönetir.
 */
@RestController
@CrossOrigin(origins = "*", allowedHeaders = "*", methods = {RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT, RequestMethod.DELETE, RequestMethod.OPTIONS})
public class XadesController {

    private static final Logger LOGGER = LoggerFactory.getLogger(XadesController.class);

    private final XAdESSignatureService xadesSignatureService;
    private final WsSecuritySignatureService wsSecuritySignatureService;
    private final SigningMaterial signingMaterial;
    private final String signingAlias;
    private final char[] signingPin;
    private final DigestAlgorithmResolverService digestAlgorithmResolverService;

    public XadesController(XAdESSignatureService xadesSignatureService,
                           WsSecuritySignatureService wsSecuritySignatureService,
                           SigningMaterial signingMaterial,
                           String signingAlias,
                           char[] signingPin, DigestAlgorithmResolverService digestAlgorithmResolverService) {
        this.xadesSignatureService = xadesSignatureService;
        this.wsSecuritySignatureService = wsSecuritySignatureService;
        this.signingMaterial = signingMaterial;
        this.signingAlias = signingAlias;
        this.signingPin = signingPin;
        this.digestAlgorithmResolverService = digestAlgorithmResolverService;
    }

    @Operation(
        summary = "XML belgelerini XAdES imzası ile imzalar",
        description = "e-Fatura, e-Arşiv Raporu, Uygulama Yanıtı, İrsaliye, HrXml ve diğer XML belgelerini destekler. "
                + "İmza profili (XADES_BES / XADES_A) tamamen 'signatureLevel' alanı ile belirlenir; "
                + "documentType seviye kararına dahil değildir. Alan gönderilmezse XADES_BES uygulanır "
                + "(TSA çağrılmaz, kontör harcanmaz). XADES_A istenirse TSA yapılandırılmamışsa "
                + "istek TIMESTAMP_ERROR ile reddedilir."
    )
    @RequestMapping(value = "/v1/xadessign", method = RequestMethod.POST, 
        consumes = {MediaType.MULTIPART_FORM_DATA_VALUE})
    @ApiResponses({
        @ApiResponse(responseCode = "200", 
            content = @Content(schema = @Schema(type = "string", format = "binary"))),
        @ApiResponse(responseCode = "400", 
            content = @Content(schema = @Schema(implementation = ErrorModel.class))),
        @ApiResponse(responseCode = "500")
    })
    public ResponseEntity<?> signXades(@ModelAttribute SignXadesDto dto) {
        try {
            if (dto.getDocument() == null || dto.getDocumentType() == DocumentType.None) {
                LOGGER.warn("Geçersiz istek: belge veya belge tipi eksik");
                return ResponseEntity.badRequest()
                    .body(new ErrorModel("INVALID_INPUT", "Belge ve belge tipi zorunludur"));
            }

            boolean zipped = Boolean.TRUE.equals(dto.getZipFile());

            // try-with-resources: MultipartFile.getInputStream() Tomcat'in
            // disk-tabanlı temp dosyasına bir FileInputStream açar. Bu stream
            // explicit kapatılmazsa Windows'ta dosya silinmesi (cleanupMultipart)
            // "Cannot delete upload_*.tmp" UncheckedIOException'a düşer
            // (Linux POSIX semantics'inde belirti vermez ama handle yine sızar).
            // CADES endpoint'iyle tutarlı pattern.
            SignResponse result;
            try (java.io.InputStream is = dto.getDocument().getInputStream()) {
                result = xadesSignatureService.signXml(
                    is,
                    dto.getDocumentType(),
                    dto.getSignatureId(),
                    zipped,
                    signingMaterial,
                    dto.getSignatureLevel()
                );
            }

            LOGGER.info("XAdES imzası başarıyla oluşturuldu. Belge tipi: {}", 
                dto.getDocumentType());

            // Content-Type açıkça application/xml — Spring default'ta byte[] body için
            // application/octet-stream üretir; client tarafında XML parser tetiklenmez.
            return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_XML)
                .header("x-signature-value", result.getSignatureValue())
                .header("Content-Disposition", 
                    "attachment; filename=\"signed-" + UUID.randomUUID() + ".xml\"")
                .body(result.getSignedDocument());

        } catch (Exception e) {
            LOGGER.error("XAdES imzası oluşturulurken hata", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ErrorModel("SIGNATURE_FAILED", e.getMessage()));
        }
    }

    @Operation(
        summary = "SOAP zarfını WS-Security ile imzalar",
        description = "SOAP 1.1/1.2 mesajları için WS-Security imzası oluşturur"
    )
    @RequestMapping(value = "/v1/wssecuritysign", method = RequestMethod.POST,
        consumes = {MediaType.MULTIPART_FORM_DATA_VALUE})
    @ApiResponses({
        @ApiResponse(responseCode = "200", 
            content = @Content(schema = @Schema(type = "string", format = "binary"))),
        @ApiResponse(responseCode = "400", 
            content = @Content(schema = @Schema(implementation = ErrorModel.class))),
        @ApiResponse(responseCode = "500")
    })
    public ResponseEntity<?> signWsSecurity(@ModelAttribute SignWsSecurityDto dto) {
        try {
            if (dto.getDocument() == null || dto.getDocument().isEmpty()) {
                LOGGER.warn("Geçersiz istek: SOAP belgesi eksik");
                return ResponseEntity.badRequest()
                    .body(new ErrorModel("INVALID_INPUT", "SOAP belgesi zorunludur"));
            }

            // try-with-resources: aynı handle-leak kontratı signXades ile;
            // SOAP parse'i InputStream'i tek-geçişte tükettiği için scope
            // sonunda stream güvenle kapatılabilir.
            Document soapDocument;
            try (java.io.InputStream is = dto.getDocument().getInputStream()) {
                soapDocument = Utilities.LoadXMLFromInputStream(is);
            }

            boolean useSoap12 = Boolean.TRUE.equals(dto.getSoap1Dot2());
            
            LOGGER.info("WS-Security imzalama isteği - soap1Dot2 parametresi: {}, useSoap12: {}", 
                dto.getSoap1Dot2(), useSoap12);

            SignResponse result = wsSecuritySignatureService.signSoapEnvelope(
                soapDocument,
                useSoap12,
                signingMaterial,
                signingAlias,
                signingPin
            );

            LOGGER.info("WS-Security imzası başarıyla oluşturuldu (SOAP {})", useSoap12 ? "1.2" : "1.1");

            // SOAP envelope → text/xml (SOAP 1.1 standardı) / application/soap+xml (1.2).
            // Çoğu SOAP client ikisini de kabul eder; en yaygın uyumluluk için text/xml.
            return ResponseEntity.ok()
                .contentType(MediaType.TEXT_XML)
                .header("x-signature-value", result.getSignatureValue())
                .header("Content-Disposition", 
                    "attachment; filename=\"signed-soap-" + UUID.randomUUID() + ".xml\"")
                .body(result.getSignedDocument());

        } catch (Exception e) {
            LOGGER.error("WS-Security imzası oluşturulurken hata", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ErrorModel("SIGNATURE_FAILED", e.getMessage()));
        }
    }

    @Operation(
            summary = "Hash değerini imzalar",
            description = "Hash imzalar(özellikle e-defter digest value için kullanılabilir)"
    )
    @RequestMapping(
            value = "/v1/hashsign",
            method = RequestMethod.POST,
            consumes = {MediaType.APPLICATION_JSON_VALUE},
            produces = {MediaType.APPLICATION_JSON_VALUE})
    @ApiResponses({
            @ApiResponse(responseCode = "200",
                    content = @Content(schema = @Schema(type = "string", format = "binary"))),
            @ApiResponse(responseCode = "400",
                    content = @Content(schema = @Schema(implementation = ErrorModel.class))),
            @ApiResponse(responseCode = "500")
    })
    public ResponseEntity<?> signHash(@RequestBody SignHashDto dto) {
        try {
            byte[] decoded = Base64.getDecoder().decode(dto.getBase64EncodedDataToSign());
            DigestAlgorithm digestAlg = digestAlgorithmResolverService.resolveDigestAlgorithm(signingMaterial.getSigningCertificate());
            EncryptionAlgorithm encAlg = EncryptionAlgorithm.forKey(signingMaterial.getSigningCertificate().getPublicKey());
            SignatureAlgorithm sigAlg = SignatureAlgorithm.getAlgorithm(encAlg, digestAlg);
            byte[] signed = signingMaterial.getSigningBackend().sign(decoded, sigAlg);
            SignHashResponseDto result = new SignHashResponseDto(Base64.getEncoder().encodeToString(signed));
            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(result);
        } catch (Exception e) {
            LOGGER.error("XAdES imzası oluşturulurken hata", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorModel("SIGNATURE_FAILED", e.getMessage()));
        }
    }
}
