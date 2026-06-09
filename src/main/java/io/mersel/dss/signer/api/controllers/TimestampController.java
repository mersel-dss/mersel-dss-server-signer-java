package io.mersel.dss.signer.api.controllers;

import io.mersel.dss.signer.api.dtos.TimestampResponseDto;
import io.mersel.dss.signer.api.dtos.TimestampStatusDto;
import io.mersel.dss.signer.api.dtos.TimestampValidationResponseDto;
import io.mersel.dss.signer.api.exceptions.TimestampException;
import io.mersel.dss.signer.api.models.ErrorModel;
import io.mersel.dss.signer.api.services.metrics.SignatureMetrics;
import io.mersel.dss.signer.api.services.notification.SignerNotifier;
import io.mersel.dss.signer.api.services.timestamp.TimestampConfigurationService;
import io.mersel.dss.signer.api.services.timestamp.TimestampService;
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
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

/**
 * Zaman damgası (timestamp) işlemleri için REST controller.
 * RFC 3161 standardına uygun TSQ, TSR ve validasyon endpoint'leri sağlar.
 */
@RestController
@CrossOrigin(origins = "*", allowedHeaders = "*", methods = {RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT, RequestMethod.DELETE, RequestMethod.OPTIONS})
@RequestMapping("/api/timestamp")
@Tag(name = "Timestamp", description = "Zaman damgası (RFC 3161) işlemleri - TSQ, TSR ve doğrulama")
public class TimestampController {

    private static final Logger LOGGER = LoggerFactory.getLogger(TimestampController.class);

    private final TimestampService timestampService;
    private final TimestampConfigurationService timestampConfigurationService;
    private final SignerNotifier signerNotifier;
    private final SignatureMetrics signatureMetrics;

    public TimestampController(
            TimestampService timestampService,
            TimestampConfigurationService timestampConfigurationService,
            SignerNotifier signerNotifier,
            SignatureMetrics signatureMetrics) {
        this.timestampService = timestampService;
        this.timestampConfigurationService = timestampConfigurationService;
        this.signerNotifier = signerNotifier;
        this.signatureMetrics = signatureMetrics;
    }

    @Operation(
        summary = "Binary belge için zaman damgası al",
        description = "Herhangi bir binary belge için RFC 3161 standardına uygun zaman damgası alır. " +
                     "Timestamp token'ı binary (application/octet-stream) olarak döner. " +
                     "Metadata bilgileri HTTP response header'larında gelir: " +
                     "X-Timestamp-Time, X-Timestamp-TSA, X-Timestamp-Serial, X-Timestamp-Hash-Algorithm"
    )
    @ApiResponses({
        @ApiResponse(
            responseCode = "200",
            description = "Zaman damgası başarıyla alındı (binary .tst dosyası)",
            content = @Content(mediaType = "application/octet-stream")
        ),
        @ApiResponse(
            responseCode = "400",
            description = "Geçersiz istek veya timestamp servisi yapılandırılmamış",
            content = @Content(schema = @Schema(implementation = ErrorModel.class))
        ),
        @ApiResponse(
            responseCode = "500",
            description = "Zaman damgası alınamadı",
            content = @Content(schema = @Schema(implementation = ErrorModel.class))
        )
    })
    @PostMapping(
        value = "/get",
        consumes = MediaType.MULTIPART_FORM_DATA_VALUE,
        produces = {MediaType.APPLICATION_OCTET_STREAM_VALUE, MediaType.APPLICATION_JSON_VALUE}
    )
    public ResponseEntity<?> getTimestamp(
            @RequestParam("document") 
            @io.swagger.v3.oas.annotations.Parameter(
                description = "Zaman damgası alınacak dosya",
                required = true
            )
            MultipartFile document,
            
            @RequestParam(value = "hashAlgorithm", defaultValue = "SHA256")
            @io.swagger.v3.oas.annotations.Parameter(
                description = "Hash algoritması",
                example = "SHA256"
            )
            String hashAlgorithm) {

        SignatureMetrics.Sample sample = null;
        long inputSize = document != null ? document.getSize() : -1;
        try {
            LOGGER.info("Zaman damgası alma isteği alındı. Dosya: {}, Hash: {}", 
                    document.getOriginalFilename(), hashAlgorithm);

            // Timestamp servisinin yapılandırılmış olup olmadığını kontrol et
            if (!timestampConfigurationService.isAvailable()) {
                LOGGER.warn("Timestamp servisi yapılandırılmamış");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(new ErrorModel(
                        "TIMESTAMP_NOT_CONFIGURED",
                        "Zaman damgası servisi yapılandırılmamış. TS_SERVER_HOST property'sini ayarlayın."
                    ));
            }

            sample = signatureMetrics.start("Timestamp", "binary", hashAlgorithm);

            // Dosyayı byte array'e çevir
            byte[] documentBytes = document.getBytes();
            
            TimestampResponseDto response = timestampService.getTimestamp(documentBytes, hashAlgorithm);

            LOGGER.info("Zaman damgası başarıyla alındı. Tarih: {}", response.getTimestamp());
            
            // Timestamp token'ı binary olarak dön, metadata header'larda
            byte[] timestampToken = java.util.Base64.getDecoder().decode(response.getTimestampToken());

            sample.success(inputSize, timestampToken != null ? timestampToken.length : -1);

            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .header("Content-Disposition", "attachment; filename=timestamp.tst")
                    .header("X-Timestamp-Time", response.getTimestamp())
                    .header("X-Timestamp-TSA", response.getTsaName() != null ? response.getTsaName() : "")
                    .header("X-Timestamp-Serial", response.getSerialNumber())
                    .header("X-Timestamp-Hash-Algorithm", response.getHashAlgorithm())
                    .header("X-Timestamp-Nonce", response.getNonce() != null ? response.getNonce() : "")
                    .body(timestampToken);

        } catch (TimestampException e) {
            LOGGER.error("Zaman damgası alma hatası: {}", e.getMessage());
            if (sample != null) {
                sample.failure(inputSize);
            }
            notifyTimestampFailure(document, e);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .contentType(MediaType.APPLICATION_JSON)
                .body(new ErrorModel("TIMESTAMP_ERROR", e.getMessage()));

        } catch (Exception e) {
            LOGGER.error("Beklenmeyen hata", e);
            if (sample != null) {
                sample.failure(inputSize);
            }
            notifyTimestampFailure(document, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .contentType(MediaType.APPLICATION_JSON)
                .body(new ErrorModel("INTERNAL_ERROR", "Zaman damgası alınamadı: " + e.getMessage()));
        }
    }

    /**
     * Timestamp ALMA hatalarını (TSA bağlantı problemi, kontör tükenmesi,
     * yanlış konfigürasyon) Slack/webhook'a fire-and-forget bildirir.
     * {@code /validate} ve {@code /status} bildirimi yapmaz — bunlar sırf
     * okuma operasyonu, alarm gürültüsü olur.
     */
    private void notifyTimestampFailure(MultipartFile document, Throwable error) {
        byte[] documentBytes = null;
        String fileName = null;
        String contentType = null;
        try {
            if (document != null && !document.isEmpty()) {
                fileName = document.getOriginalFilename();
                contentType = document.getContentType();
                // OOM koruması: getBytes() ile ikinci kopya oluşturmadan önce
                // boyut/eşik kontrolü.
                if (signerNotifier.shouldReadContentForFailure(document.getSize())) {
                    documentBytes = document.getBytes();
                }
            }
        } catch (Exception readEx) {
            LOGGER.debug("Notifier için dosya bytes okunamadı: {}", readEx.getMessage());
        }
        signerNotifier.notifyOnSignatureFailure(
                "/api/timestamp/get", "Timestamp", error,
                documentBytes, fileName, contentType);
    }

    @Operation(
        summary = "Zaman damgasını doğrula",
        description = "RFC 3161 zaman damgasını doğrular. Timestamp token'ın imzasını, " +
                     "TSA sertifikasını ve isteğe bağlı olarak orijinal belgenin hash'ini doğrular. " +
                     "Detaylı doğrulama raporu döner."
    )
    @ApiResponses({
        @ApiResponse(
            responseCode = "200",
            description = "Doğrulama tamamlandı (başarılı veya başarısız olabilir)",
            content = @Content(
                mediaType = "application/json",
                schema = @Schema(implementation = TimestampValidationResponseDto.class)
            )
        ),
        @ApiResponse(
            responseCode = "400",
            description = "Geçersiz istek",
            content = @Content(schema = @Schema(implementation = ErrorModel.class))
        ),
        @ApiResponse(
            responseCode = "500",
            description = "Doğrulama yapılamadı",
            content = @Content(schema = @Schema(implementation = ErrorModel.class))
        )
    })
    @PostMapping(
        value = "/validate",
        consumes = MediaType.MULTIPART_FORM_DATA_VALUE,
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<?> validateTimestamp(
            @RequestParam("timestampToken") 
            @io.swagger.v3.oas.annotations.Parameter(
                description = "Doğrulanacak timestamp token dosyası (.tst veya binary)",
                required = true
            )
            MultipartFile timestampToken,
            
            @RequestParam(value = "originalDocument", required = false)
            @io.swagger.v3.oas.annotations.Parameter(
                description = "Orijinal belge (hash doğrulaması için - opsiyonel)"
            )
            MultipartFile originalDocument) {
        
        try {
            LOGGER.info("Zaman damgası doğrulama isteği alındı. Token dosyası: {}", 
                    timestampToken.getOriginalFilename());

            // Timestamp token'ı byte array'e çevir
            byte[] tokenBytes = timestampToken.getBytes();
            LOGGER.debug("Timestamp token okundu - boyut: {} bytes", tokenBytes.length);
            
            // Orijinal belge varsa byte array'e çevir
            byte[] originalBytes = null;
            if (originalDocument != null && !originalDocument.isEmpty()) {
                originalBytes = originalDocument.getBytes();
                LOGGER.info("Orijinal belge sağlandı, hash doğrulaması yapılacak: {}", 
                        originalDocument.getOriginalFilename());
            }

            TimestampValidationResponseDto response = timestampService.validateTimestamp(
                    tokenBytes, originalBytes);

            if (response.isValid()) {
                LOGGER.info("Zaman damgası doğrulandı. Seri no: {}", response.getSerialNumber());
            } else {
                LOGGER.warn("Zaman damgası doğrulaması başarısız. Hatalar: {}", response.getErrors());
            }

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            LOGGER.error("Zaman damgası doğrulama hatası", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ErrorModel("VALIDATION_ERROR", "Doğrulama yapılamadı: " + e.getMessage()));
        }
    }

    @Operation(
        summary = "Timestamp servisi durumunu kontrol et",
        description = "Timestamp servisinin yapılandırılmış ve kullanıma hazır olup olmadığını kontrol eder."
    )
    @ApiResponses({
        @ApiResponse(
            responseCode = "200",
            description = "Servis durumu",
            content = @Content(
                mediaType = "application/json",
                schema = @Schema(implementation = TimestampStatusDto.class)
            )
        )
    })
    @GetMapping("/status")
    public ResponseEntity<TimestampStatusDto> getStatus() {
        boolean isAvailable = timestampConfigurationService.isAvailable();
        TimestampStatusDto status = new TimestampStatusDto(
            isAvailable,
            isAvailable ? "Timestamp servisi aktif" : "Timestamp servisi yapılandırılmamış"
        );
        
        return ResponseEntity.ok(status);
    }
}

