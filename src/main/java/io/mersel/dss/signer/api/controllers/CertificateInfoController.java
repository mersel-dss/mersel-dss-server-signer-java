package io.mersel.dss.signer.api.controllers;

import io.mersel.dss.signer.api.dtos.CertificateInfoDto;
import io.mersel.dss.signer.api.models.configurations.SignatureServiceConfiguration;
import io.mersel.dss.signer.api.services.CertificateInfoService;
import io.mersel.dss.signer.api.services.keystore.KeyStoreProvider;
import io.mersel.dss.signer.api.services.keystore.PKCS11KeyStoreProvider;
import io.mersel.dss.signer.api.services.keystore.PfxKeyStoreProvider;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.cert.CertificateEncodingException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Keystore içerisindeki sertifika bilgilerini listeleme endpoint'i.
 * PKCS#11 veya PFX keystore'dan sertifika alias ve serial number bilgilerini almak için kullanılır.
 */
@RestController
@CrossOrigin(origins = "*", allowedHeaders = "*", methods = {RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT, RequestMethod.DELETE, RequestMethod.OPTIONS})
@RequestMapping("/api/certificates")
@Tag(name = "Certificate Info", description = "Keystore sertifika bilgileri API'si")
public class CertificateInfoController {

    private static final Logger LOGGER = LoggerFactory.getLogger(CertificateInfoController.class);

    @Autowired
    private CertificateInfoService certificateInfoService;

    @Autowired
    private SignatureServiceConfiguration config;

    /**
     * Singleton {@link KeyStoreProvider} bean'i — HSM yolunda da PFX yolunda
     * da {@link io.mersel.dss.signer.api.config.SignatureConfiguration}
     * tarafından sağlanır. Burada her istekte yeni provider üretmiyoruz;
     * yapılandırma yaşam döngüsü Spring container'a teslim edilir.
     */
    @Autowired
    private KeyStoreProvider keyStoreProvider;

    /**
     * Yapılandırılmış keystore'dan tüm sertifikaları listeler.
     * 
     * GET /api/certificates/list
     */
    @GetMapping(value = "/list", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(
        summary = "Keystore sertifikalarını listele",
        description = "Yapılandırılmış keystore (PKCS#11 veya PFX) içerisindeki tüm sertifikaları listeler. " +
                     "Bu endpoint ile alias ve serial number bilgilerini öğrenebilirsiniz.",
        responses = {
            @ApiResponse(
                responseCode = "200",
                description = "Sertifika listesi başarıyla döndürüldü",
                content = @Content(schema = @Schema(implementation = CertificateInfoDto.class))
            ),
            @ApiResponse(responseCode = "500", description = "Keystore yüklenemedi veya sertifikalar okunamadı")
        }
    )
    public ResponseEntity<?> listCertificates() {
        try {
            LOGGER.info("Sertifika listesi istendi");

            char[] pin = config.getCertificatePin().toCharArray();
            List<CertificateInfoDto> certificates =
                certificateInfoService.listCertificates(keyStoreProvider, pin);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("keystoreType", keyStoreProvider.getType());
            response.put("certificateCount", certificates.size());
            response.put("certificates", certificates);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            LOGGER.error("Sertifika listesi alınamadı", e);

            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("success", false);
            errorResponse.put("error", e.getMessage());

            return ResponseEntity.status(500).body(errorResponse);
        }
    }

    /**
     * Keystore bilgilerini döndürür (hangi tip kullanılıyor, vs.)
     * 
     * GET /api/certificates/info
     */
    @GetMapping(value = "/info", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(
        summary = "Keystore bilgilerini getir",
        description = "Yapılandırılmış keystore hakkında genel bilgi döndürür (tip, yol, slot, vb.)",
        responses = {
            @ApiResponse(responseCode = "200", description = "Keystore bilgileri başarıyla döndürüldü")
        }
    )
    public ResponseEntity<Map<String, Object>> getKeystoreInfo() {
        Map<String, Object> info = new HashMap<>();

        try {
            info.put("success", true);
            info.put("keystoreType", keyStoreProvider.getType());

            if (keyStoreProvider instanceof PKCS11KeyStoreProvider) {
                info.put("library", config.getPkcs11LibraryPath());
                info.put("slot", config.getPkcs11Slot());
            } else if (keyStoreProvider instanceof PfxKeyStoreProvider) {
                info.put("pfxPath", config.getPfxPath());
            }

            info.put("certificateAlias", config.getCertificateAlias());
            info.put("certificateSerialNumber", config.getCertificateSerialNumber());

        } catch (Exception e) {
            info.put("success", false);
            info.put("error", e.getMessage());
        }

        return ResponseEntity.ok(info);
    }

    /**
     * Keystore bilgilerini döndürür (hangi tip kullanılıyor, vs.)
     *
     * GET /api/certificates/info
     */
    @GetMapping(value = "/signingCertificate", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(
            summary = "İmzalama için kullanılan sertifika bilgilerini döner",
            description = "Yalnızca imza işleminde kullanılacak sertifika bilgilerini döner",
            responses = {
                    @ApiResponse(responseCode = "200", description = "İmzacı sertifika başarıyla döndürüldü")
            }
    )
    public ResponseEntity<?> getSigningCertificate() throws CertificateEncodingException {
        CertificateInfoDto dto = certificateInfoService.getSigningCertificateInfo();
        return ResponseEntity.ok(dto);
    }
}

