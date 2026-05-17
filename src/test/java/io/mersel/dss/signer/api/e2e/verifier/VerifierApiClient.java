package io.mersel.dss.signer.api.e2e.verifier;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * mersel-dss-verifier-api-java için minimum yüzeyli HTTP client.
 *
 * <p>E2E testleri sadece <code>POST /api/v1/verify/signature</code>
 * (birleşik endpoint) endpoint'ini kullanır — bu endpoint imza formatını
 * (XAdES/PAdES/CAdES) otomatik tespit eder, dolayısıyla format-spesifik
 * legacy endpoint'lere ({@code /verify/xades}, {@code /verify/pades},
 * {@code /verify/cades}) ihtiyacımız yok.</p>
 *
 * <p>JSON deserialization'da {@link JsonIgnoreProperties} ile ileride
 * eklenecek alanları sessizce yutuyoruz; verifier-api'nin sürüm yükselmesi
 * test'leri kırmasın.</p>
 */
public final class VerifierApiClient {

    private static final String VERIFY_ENDPOINT = "/api/v1/verify/signature";

    private final RestTemplate http;
    private final ObjectMapper json;
    private final String baseUrl;

    public VerifierApiClient(String baseUrl) {
        this.baseUrl = baseUrl;
        this.http = new RestTemplate();
        this.json = new ObjectMapper();
    }

    /**
     * Tek-imzalı bir belge için (PAdES, XAdES enveloped/enveloping) doğrulama.
     *
     * @param signedDocument imzalı belge bytes (.pdf, .xml, .p7s)
     * @param signedFileName multipart için dosya adı (ör. "signed.pdf")
     * @return verifier-api'nin döndürdüğü doğrulama sonucu
     */
    public VerificationResponse verify(byte[] signedDocument, String signedFileName) {
        return verify(signedDocument, signedFileName, null, null, ValidationLevel.COMPREHENSIVE);
    }

    /**
     * Detached imza (orijinal belge ayrı dosyada) için doğrulama. CAdES detached
     * veya XAdES detached senaryolarında kullanılır.
     *
     * @param signedDocument   imza dosyası (ör. .p7s veya .xml)
     * @param signedFileName   imza dosyasının adı
     * @param originalDocument orijinal (imzasız) belge bytes
     * @param originalFileName orijinal belgenin adı
     * @return verifier-api'nin döndürdüğü doğrulama sonucu
     */
    public VerificationResponse verifyDetached(byte[] signedDocument, String signedFileName,
                                               byte[] originalDocument, String originalFileName) {
        return verify(signedDocument, signedFileName,
                originalDocument, originalFileName, ValidationLevel.COMPREHENSIVE);
    }

    private VerificationResponse verify(byte[] signedDocument, String signedFileName,
                                        byte[] originalDocument, String originalFileName,
                                        ValidationLevel level) {
        MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
        body.add("signedDocument", asResource(signedDocument, signedFileName));
        if (originalDocument != null) {
            body.add("originalDocument", asResource(originalDocument, originalFileName));
        }
        body.add("level", level.name());

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.MULTIPART_FORM_DATA);
        // Verifier API default content negotiation'da XML döndürüyor; bizim
        // DTO'lar Jackson tabanlı, JSON'a kilitleyelim.
        headers.setAccept(java.util.Collections.singletonList(MediaType.APPLICATION_JSON));

        HttpEntity<MultiValueMap<String, Object>> request = new HttpEntity<>(body, headers);

        String responseBody;
        try {
            responseBody = http.postForObject(baseUrl + VERIFY_ENDPOINT, request, String.class);
        } catch (HttpServerErrorException ex) {
            // Verifier image'ın ilgili DSS modülü classpath'te değilse 500 fırlatır.
            // Bu, bu repo'nun sorumluluğunda olmayan bir verifier-side eksiklik:
            // testin "fail" olması yanıltıcı; bunun yerine VerifierBackendUnavailable
            // ile sarmalayıp çağıran sınıfa skip kararı bırakıyoruz.
            String bodyText = ex.getResponseBodyAsString();
            if (looksLikeMissingDssModule(bodyText)) {
                throw new VerifierBackendUnavailable(
                        "Verifier API bu imza formatını desteklemiyor (eksik DSS modülü). "
                                + "Body: " + bodyText, ex);
            }
            throw ex;
        }
        try {
            return json.readValue(responseBody, VerificationResponse.class);
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Verifier API yanıtı parse edilemedi (Accept=application/json ile bile JSON dönmedi): "
                            + responseBody, e);
        }
    }

    private static boolean looksLikeMissingDssModule(String body) {
        if (body == null) return false;
        // mersel-dss-verifier-api-java:main imajının gözlemlenen davranışları:
        //   CAdES: "No implementation found for ICMSUtils"
        //   PAdES: "No implementation found for IPdfObjFactory"
        // Bunlar verifier image build sırasında eksik bırakılmış DSS modülleri.
        return body.contains("No implementation found for ICMSUtils")
                || body.contains("No implementation found for IPdfObjFactory")
                || body.contains("Could not initialize class eu.europa.esig.dss.cms.CMSUtils")
                || body.contains("dss-pades-pdfbox")
                || body.contains("dss-pades-openpdf")
                || body.contains("dss-cms-object")
                || body.contains("dss-cms-stream");
    }

    /**
     * Verifier API'nin downstream DSS modülü eksikliği nedeniyle hizmet veremediği
     * durumlar için sinyal. Çağıran test kodu bunu yakalayıp
     * {@code Assumptions.abort()} ile testi <b>skip</b> etmelidir — çünkü hata
     * bu repo'nun değil, verifier projesinin sorumluluğundadır.
     */
    public static final class VerifierBackendUnavailable extends RuntimeException {
        private static final long serialVersionUID = 1L;
        public VerifierBackendUnavailable(String message, Throwable cause) {
            super(message, cause);
        }
    }

    private static ByteArrayResource asResource(byte[] data, String filename) {
        return new ByteArrayResource(data) {
            @Override
            public String getFilename() {
                return filename;
            }
            @Override
            public long contentLength() {
                return data.length;
            }
        };
    }

    /** {@code level=} parametre değerleri. */
    public enum ValidationLevel {
        SIMPLE, COMPREHENSIVE
    }

    // ===================================================================
    // Response DTO'ları — verifier-api'nin JSON şemasına minimum eşleme.
    // İleride yeni alan eklenirse @JsonIgnoreProperties(ignoreUnknown=true)
    // sayesinde sessizce yutulur; testler kırılmaz.
    // ===================================================================

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static final class VerificationResponse {
        private boolean valid;
        private String status;
        private String signatureType;
        private Integer signatureCount;
        private List<SignatureInfo> signatures;
        private List<String> errors;
        private List<String> warnings;

        public boolean isValid() { return valid; }
        public String getStatus() { return status; }
        public String getSignatureType() { return signatureType; }
        public Integer getSignatureCount() { return signatureCount; }
        public List<SignatureInfo> getSignatures() {
            return signatures != null ? signatures : Collections.emptyList();
        }
        public List<String> getErrors() {
            return errors != null ? errors : Collections.emptyList();
        }
        public List<String> getWarnings() {
            return warnings != null ? warnings : Collections.emptyList();
        }

        public void setValid(boolean valid) { this.valid = valid; }
        public void setStatus(String status) { this.status = status; }
        public void setSignatureType(String signatureType) { this.signatureType = signatureType; }
        public void setSignatureCount(Integer signatureCount) { this.signatureCount = signatureCount; }
        public void setSignatures(List<SignatureInfo> signatures) { this.signatures = signatures; }
        public void setErrors(List<String> errors) { this.errors = errors; }
        public void setWarnings(List<String> warnings) { this.warnings = warnings; }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static final class SignatureInfo {
        private String signatureId;
        private boolean valid;
        private String signatureFormat;
        private String signatureLevel;
        private String indication;
        private String subIndication;
        @JsonProperty("signerCertificate")
        private Map<String, Object> signerCertificate;
        private List<String> validationErrors;
        private List<String> validationWarnings;
        private ValidationDetails validationDetails;

        public String getSignatureId() { return signatureId; }
        public boolean isValid() { return valid; }
        public String getSignatureFormat() { return signatureFormat; }
        public String getSignatureLevel() { return signatureLevel; }
        public String getIndication() { return indication; }
        public String getSubIndication() { return subIndication; }
        public Map<String, Object> getSignerCertificate() { return signerCertificate; }
        public List<String> getValidationErrors() {
            return validationErrors != null ? validationErrors : Collections.emptyList();
        }
        public List<String> getValidationWarnings() {
            return validationWarnings != null ? validationWarnings : Collections.emptyList();
        }
        public ValidationDetails getValidationDetails() { return validationDetails; }

        public void setSignatureId(String signatureId) { this.signatureId = signatureId; }
        public void setValid(boolean valid) { this.valid = valid; }
        public void setSignatureFormat(String signatureFormat) { this.signatureFormat = signatureFormat; }
        public void setSignatureLevel(String signatureLevel) { this.signatureLevel = signatureLevel; }
        public void setIndication(String indication) { this.indication = indication; }
        public void setSubIndication(String subIndication) { this.subIndication = subIndication; }
        public void setSignerCertificate(Map<String, Object> signerCertificate) { this.signerCertificate = signerCertificate; }
        public void setValidationErrors(List<String> validationErrors) { this.validationErrors = validationErrors; }
        public void setValidationWarnings(List<String> validationWarnings) { this.validationWarnings = validationWarnings; }
        public void setValidationDetails(ValidationDetails validationDetails) { this.validationDetails = validationDetails; }
    }

    /**
     * Verifier'ın raporladığı düşük seviye doğrulama bayrakları. E2E assertion'ları
     * "valid=true" yerine bunlara dayanırsa, downstream verifier projesindeki trust
     * resolver bug'ları imzalama tarafının regression testini engellemez.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static final class ValidationDetails {
        private boolean signatureIntact;
        private boolean certificateChainValid;
        private boolean certificateNotExpired;
        private boolean certificateNotRevoked;
        private boolean trustAnchorReached;
        private boolean timestampValid;
        private boolean cryptographicVerificationSuccessful;
        private boolean revocationCheckPerformed;

        public boolean isSignatureIntact() { return signatureIntact; }
        public boolean isCertificateChainValid() { return certificateChainValid; }
        public boolean isCertificateNotExpired() { return certificateNotExpired; }
        public boolean isCertificateNotRevoked() { return certificateNotRevoked; }
        public boolean isTrustAnchorReached() { return trustAnchorReached; }
        public boolean isTimestampValid() { return timestampValid; }
        public boolean isCryptographicVerificationSuccessful() { return cryptographicVerificationSuccessful; }
        public boolean isRevocationCheckPerformed() { return revocationCheckPerformed; }

        public void setSignatureIntact(boolean v) { this.signatureIntact = v; }
        public void setCertificateChainValid(boolean v) { this.certificateChainValid = v; }
        public void setCertificateNotExpired(boolean v) { this.certificateNotExpired = v; }
        public void setCertificateNotRevoked(boolean v) { this.certificateNotRevoked = v; }
        public void setTrustAnchorReached(boolean v) { this.trustAnchorReached = v; }
        public void setTimestampValid(boolean v) { this.timestampValid = v; }
        public void setCryptographicVerificationSuccessful(boolean v) { this.cryptographicVerificationSuccessful = v; }
        public void setRevocationCheckPerformed(boolean v) { this.revocationCheckPerformed = v; }
    }
}
