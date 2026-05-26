package io.mersel.dss.signer.api.controllers;

import io.mersel.dss.signer.api.dtos.SignHashDto;
import io.mersel.dss.signer.api.dtos.SignHashResponseDto;
import io.mersel.dss.signer.api.exceptions.SignatureException;
import io.mersel.dss.signer.api.models.ErrorModel;
import io.mersel.dss.signer.api.services.notification.SignerNotifier;
import io.mersel.dss.signer.api.services.signature.raw.RawHashSignatureService;
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
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.Base64;

/**
 * Pre-hashed digest imzalama endpoint'i.
 *
 * <p>{@code POST /v1/hashsign} — caller'ın kendisi hesaplayıp gönderdiği bir
 * digest'i, server tarafındaki PFX/HSM imzalama materyali ile imzalar. Server
 * digest'i <em>tekrar hash'lemez</em>. RSA için PKCS#1 v1.5 DigestInfo wrap'i
 * uygulanır; ECDSA için raw eğri imzalama yapılır. Tipik kullanım e-Defter
 * mali mührü ve manuel XAdES SignedInfo digest imzalama akışlarıdır.</p>
 *
 * <h3>Mimari notu</h3>
 * <p>Bu controller, XAdES belge imzalama akışlarından (bkz. {@link XadesController})
 * ayrı bir sorumluluk taşır: belge formatı, namespace, canonicalization gibi
 * yüksek seviye sözleşmelerden bağımsız bir cryptographic primitive sunar.
 * SRP gereği ayrı controller'da yaşar.</p>
 *
 * <h3>Güvenlik notu</h3>
 * <p>Endpoint bir <em>signing oracle</em> olduğu için private network içinde
 * kullanılması beklenir. Public exposure düşünülürse: API key authentication,
 * audit log, rate limiting eklenmesi şart. Mevcut deployment private ağ
 * varsayımına dayanır.</p>
 */
@RestController
@CrossOrigin(origins = "*", allowedHeaders = "*", methods = {RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT, RequestMethod.DELETE, RequestMethod.OPTIONS})
public class HashSignatureController {

    private static final Logger LOGGER = LoggerFactory.getLogger(HashSignatureController.class);

    private final RawHashSignatureService rawHashSignatureService;
    private final SignerNotifier signerNotifier;

    public HashSignatureController(RawHashSignatureService rawHashSignatureService,
                                   SignerNotifier signerNotifier) {
        this.rawHashSignatureService = rawHashSignatureService;
        this.signerNotifier = signerNotifier;
    }

    @Operation(
        summary = "Pre-hashed digest'i imzalar (e-Defter / manuel SignedInfo akışları için)",
        description = "Caller'ın kendisi hesaplayıp gönderdiği hash'i imzalar. Server hash'i tekrar "
                + "hash'lemez. RSA için PKCS#1 v1.5 DigestInfo wrap; ECDSA için raw eğri imzalama. "
                + "Decoded digest uzunluğu digestAlgorithm ile uyumlu olmalıdır."
    )
    @RequestMapping(
        value = "/v1/hashsign",
        method = RequestMethod.POST,
        consumes = {MediaType.APPLICATION_JSON_VALUE},
        produces = {MediaType.APPLICATION_JSON_VALUE}
    )
    @ApiResponses({
        @ApiResponse(responseCode = "200",
            content = @Content(schema = @Schema(implementation = SignHashResponseDto.class))),
        @ApiResponse(responseCode = "400",
            content = @Content(schema = @Schema(implementation = ErrorModel.class))),
        @ApiResponse(responseCode = "500",
            content = @Content(schema = @Schema(implementation = ErrorModel.class)))
    })
    public ResponseEntity<?> signHash(@RequestBody(required = false) SignHashDto dto) {
        if (dto == null || dto.getBase64EncodedDigest() == null
                || dto.getBase64EncodedDigest().trim().isEmpty()) {
            LOGGER.warn("Geçersiz hash imzalama isteği: digest eksik");
            return ResponseEntity.badRequest()
                .body(new ErrorModel("INVALID_INPUT", "base64EncodedDigest zorunludur"));
        }

        byte[] digest;
        try {
            digest = Base64.getDecoder().decode(dto.getBase64EncodedDigest().trim());
        } catch (IllegalArgumentException e) {
            LOGGER.warn("Geçersiz hash imzalama isteği: base64 decode başarısız: {}", e.getMessage());
            return ResponseEntity.badRequest()
                .body(new ErrorModel("INVALID_INPUT", "base64EncodedDigest geçerli bir base64 değil: " + e.getMessage()));
        }

        try {
            byte[] signed = rawHashSignatureService.signDigest(digest, dto.getDigestAlgorithm());
            String base64 = Base64.getEncoder().encodeToString(signed);
            return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_JSON)
                .body(new SignHashResponseDto(base64));
        } catch (IllegalArgumentException e) {
            LOGGER.warn("Hash imzalama validasyon hatası: {}", e.getMessage());
            // IllegalArgumentException kullanıcı hatası (4xx) — bildirim göndermiyoruz,
            // operasyonel alarm gürültüsü olmasın. SIGNATURE_FAILED kontratı 5xx için.
            return ResponseEntity.badRequest()
                .body(new ErrorModel("INVALID_INPUT", e.getMessage()));
        } catch (SignatureException e) {
            LOGGER.error("Hash imzası oluşturulamadı (errorCode={}): {}",
                e.getErrorCode(), e.getMessage(), e);
            // Hash imzasında "dosya" digest'in kendisi — operatör forensik için bytes'ı
            // gönderiyoruz (digest 32-64 byte civarı; payload boyutu sorun değil).
            signerNotifier.notifyOnSignatureFailure(
                    "/v1/hashsign", "Hash", e, digest, "digest.bin", "application/octet-stream");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ErrorModel("SIGNATURE_FAILED", e.getMessage()));
        } catch (Exception e) {
            LOGGER.error("Hash imzası oluşturulurken beklenmedik hata", e);
            signerNotifier.notifyOnSignatureFailure(
                    "/v1/hashsign", "Hash", e, digest, "digest.bin", "application/octet-stream");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ErrorModel("SIGNATURE_FAILED", e.getMessage()));
        }
    }
}
