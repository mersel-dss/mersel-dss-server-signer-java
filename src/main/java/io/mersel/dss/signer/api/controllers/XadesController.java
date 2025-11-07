package io.mersel.dss.signer.api.controllers;

import java.util.UUID;

import io.mersel.dss.signer.api.dtos.SignTestUserEnvelopeDto;
import io.mersel.dss.signer.api.models.SigningMaterial;
import io.mersel.dss.signer.api.services.signature.wssecurity.WsSecuritySignatureService;
import io.mersel.dss.signer.api.services.signature.xades.XAdESSignatureService;
import io.mersel.dss.signer.api.util.Utilities;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.w3c.dom.Document;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.mersel.dss.signer.api.dtos.SignWsSecurityDto;
import io.mersel.dss.signer.api.dtos.SignXadesDto;
import io.mersel.dss.signer.api.models.ErrorModel;
import io.mersel.dss.signer.api.models.SignResponse;
import io.mersel.dss.signer.api.models.enums.DocumentType;

/**
 * XAdES (XML İleri Seviye Elektronik İmza) işlemleri için REST controller.
 * XML belge imzalama ve WS-Security SOAP zarf imzalama işlemlerini yönetir.
 */
@RestController
public class XadesController {

    private static final Logger LOGGER = LoggerFactory.getLogger(XadesController.class);

    private final XAdESSignatureService xadesSignatureService;
    private final WsSecuritySignatureService wsSecuritySignatureService;
    private final SigningMaterial signingMaterial;
    private final String signingAlias;
    private final char[] signingPin;

    public XadesController(XAdESSignatureService xadesSignatureService,
                          WsSecuritySignatureService wsSecuritySignatureService,
                          SigningMaterial signingMaterial,
                          String signingAlias,
                          char[] signingPin) {
        this.xadesSignatureService = xadesSignatureService;
        this.wsSecuritySignatureService = wsSecuritySignatureService;
        this.signingMaterial = signingMaterial;
        this.signingAlias = signingAlias;
        this.signingPin = signingPin;
    }

    @Operation(
        summary = "XML belgelerini XAdES imzası ile imzalar",
        description = "e-Fatura, e-Arşiv Raporu, Uygulama Yanıtı, İrsaliye, HrXml ve diğer XML belgelerini destekler"
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
            
            SignResponse result = xadesSignatureService.signXml(
                dto.getDocument().getInputStream(),
                dto.getDocumentType(),
                dto.getSignatureId(),
                zipped,
                signingMaterial
            );

            LOGGER.info("XAdES imzası başarıyla oluşturuldu. Belge tipi: {}", 
                dto.getDocumentType());

            return ResponseEntity.ok()
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
        summary = "Test kullanıcı zarf belgelerini imzalar",
        description = "Önceden yapılandırılmış test şirketi kullanıcı kayıt belgelerini imzalar"
    )
    @RequestMapping(value = "/v1/signuserenvelopetestcompany", method = RequestMethod.POST,
        consumes = {MediaType.MULTIPART_FORM_DATA_VALUE})
    @ApiResponses({
        @ApiResponse(responseCode = "200", 
            content = @Content(schema = @Schema(type = "string", format = "binary"))),
        @ApiResponse(responseCode = "400", 
            content = @Content(schema = @Schema(implementation = ErrorModel.class))),
        @ApiResponse(responseCode = "500")
    })
    public ResponseEntity<?> signTestUserEnvelope(@ModelAttribute SignTestUserEnvelopeDto dto) {
        try {
            if (dto.getDocument() == null) {
                LOGGER.warn("Geçersiz istek: belge eksik");
                return ResponseEntity.badRequest()
                    .body(new ErrorModel("INVALID_INPUT", "Belge zorunludur"));
            }

            // TODO: Test kullanıcı imzalama mantığı implementasyonu
            LOGGER.warn("Test kullanıcı imzalama henüz refactor edilmiş versiyonda implement edilmedi");
            
            return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED)
                .body(new ErrorModel("NOT_IMPLEMENTED", 
                    "Test kullanıcı imzalama sonraki aşamada implement edilecek"));

        } catch (Exception e) {
            LOGGER.error("Test kullanıcı zarfı imzalanırken hata", e);
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

            Document soapDocument = Utilities.LoadXMLFromInputStream(
                dto.getDocument().getInputStream());
            
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

            return ResponseEntity.ok()
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
}
