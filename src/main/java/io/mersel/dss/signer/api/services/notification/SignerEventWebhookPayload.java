package io.mersel.dss.signer.api.services.notification;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.Date;
import java.util.Map;

/**
 * Signer API tarafından üretilen tüm bildirim olayları için ortak generic
 * webhook payload'ı.
 *
 * <p><b>Event tipleri</b>:</p>
 * <ul>
 *   <li>{@code signature-failure} — Herhangi bir imza endpoint'inde
 *       (XAdES/CAdES/PAdES/WS-Security/Hash/Timestamp) hata. Bu durumda
 *       {@link #signatureFailure} doludur; {@link #heartbeat} null.</li>
 *   <li>{@code heartbeat-failed} / {@code heartbeat-recovered} /
 *       {@code heartbeat-reinit-triggered} / {@code heartbeat-reinit-success} /
 *       {@code heartbeat-reinit-failed} — HSM heartbeat state transition'ları.
 *       Bu durumda {@link #heartbeat} doludur; {@link #signatureFailure}
 *       ve {@link #file} null.</li>
 * </ul>
 *
 * <p><b>Tasarım kararları</b>:</p>
 * <ul>
 *   <li>Tek payload schema'sı — receiver tek dispatcher kullanabilsin
 *       diye event ayrımı yalnızca {@link #event} alanı ve hangi
 *       sub-object'in dolu olduğuyla yapılır. Forward-compatible: yeni
 *       event tipleri eklendiğinde yeni sub-object alanı eklenir, eskiler
 *       kırılmaz.</li>
 *   <li>{@code @JsonInclude(NON_NULL)} — boş alanlar JSON'a düşmez,
 *       receiver gereksiz parse maliyeti çekmez.</li>
 *   <li>{@link #logHeaders} — request thread'inde toplanan {@code x-log-*}
 *       MDC snapshot'ı. Heartbeat eventlerinde {@code null}/boş; signature
 *       failure'da operatörün upstream akışıyla korelasyon kurması için
 *       kritik.</li>
 * </ul>
 *
 * <p><b>Şema kararlılığı</b>: alan adları kararlı API kontratıdır;
 * silinmez, yeniden adlandırılmaz. Yeni alanlar eklenebilir.</p>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class SignerEventWebhookPayload {

    /**
     * Kararlı event kodu. Signature failure için {@code "signature-failure"};
     * heartbeat için {@link HeartbeatEventType#getEventCode()} (örn.
     * {@code "heartbeat-failed"}). Receiver dispatch için ilk bakacağı alandır.
     */
    private String event;

    /**
     * Bildirim kaynağı — uygulama adı + versiyon. Örn:
     * {@code "mersel-dss-signer-api/0.9.2"}. {@link org.springframework.boot.info.BuildProperties}
     * bulunamazsa fallback string.
     */
    private String source;

    /**
     * Bildirim üretildiği an (server-time, ISO-8601 via Jackson default).
     * Receiver'ın saat sapma analizi için.
     */
    private Date notificationTime;

    /**
     * İmzalanmaya çalışılan dokümanın metadata + (opsiyonel) base64 içeriği.
     * Yalnız signature-failure event'lerinde set'tir; heartbeat'te null.
     */
    private FileEnvelope file;

    /**
     * Signature-failure event'i için yapısal hata bilgisi. Heartbeat
     * event'lerinde null.
     */
    private SignatureFailure signatureFailure;

    /**
     * Heartbeat event'i için state + sayaçlar. Signature-failure'da null.
     */
    private HeartbeatEvent heartbeat;

    /**
     * Request'e {@code x-log-*} prefix'iyle gelen korelasyon/audit
     * header'larının {@code Map<headerName, value>} kopyası. Anahtarlar
     * her zaman küçük harf ({@code x-log-id}, {@code x-log-tenant}, …);
     * değerler {@link io.mersel.dss.signer.api.config.LogHeadersFilter}
     * tarafından sanitize edilmiş hâli (CR/LF temizliği + uzunluk kırpma).
     *
     * <p>Receiver bu alanı imza olayını çağıran upstream akışla (API
     * gateway istek ID, tenant, trace ID) eşleştirmek için kullanır.
     * Hiç header yoksa veya request bağlamı yoksa (örn. heartbeat
     * scheduler thread'i) {@code null}.</p>
     */
    private Map<String, String> logHeaders;

    public SignerEventWebhookPayload() {}

    public String getEvent() {
        return event;
    }

    public void setEvent(String event) {
        this.event = event;
    }

    public String getSource() {
        return source;
    }

    public void setSource(String source) {
        this.source = source;
    }

    public Date getNotificationTime() {
        return notificationTime;
    }

    public void setNotificationTime(Date notificationTime) {
        this.notificationTime = notificationTime;
    }

    public FileEnvelope getFile() {
        return file;
    }

    public void setFile(FileEnvelope file) {
        this.file = file;
    }

    public SignatureFailure getSignatureFailure() {
        return signatureFailure;
    }

    public void setSignatureFailure(SignatureFailure signatureFailure) {
        this.signatureFailure = signatureFailure;
    }

    public HeartbeatEvent getHeartbeat() {
        return heartbeat;
    }

    public void setHeartbeat(HeartbeatEvent heartbeat) {
        this.heartbeat = heartbeat;
    }

    public Map<String, String> getLogHeaders() {
        return logHeaders;
    }

    public void setLogHeaders(Map<String, String> logHeaders) {
        this.logHeaders = logHeaders;
    }

    // =====================================================================
    // Nested DTOs — sub-events
    // =====================================================================

    /**
     * Tek bir dosya (imzalanmaya çalışılan doküman) için metadata + base64
     * içerik zarfı. {@code base64Content} alanı boyut sınırını aşan
     * dosyalarda veya operatör {@code includeContent=false} yaptığında null
     * gelir. Bu durumda {@code sha256Hex} alanı yine doludur (receiver
     * dosyayı kendi arşivinden eşleştirebilsin diye).
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class FileEnvelope {

        /** Dosya adı (multipart {@code originalFilename} veya synthetic). */
        private String name;

        /** Bayt cinsinden boyut. {@code base64Content} verilmese de set'tir. */
        private Long sizeBytes;

        /** MIME tipi; bilinmezse null. */
        private String contentType;

        /** Tüm dosyanın SHA-256 hash'i (lowercase hex). Forensik korelasyon. */
        private String sha256Hex;

        /**
         * Tüm dosyanın base64 encoding'i. Config'de
         * {@code includeContent=false} ise veya dosya
         * {@code maxContentSizeBytes}'ı aşıyorsa <code>null</code>.
         */
        private String base64Content;

        /**
         * {@code base64Content} alanı neden boş? — operatöre rehberlik
         * için kısa kod. Olası değerler: {@code "EXCLUDED_BY_CONFIG"},
         * {@code "EXCEEDED_MAX_SIZE"}. {@code base64Content} doluysa null.
         */
        private String contentOmittedReason;

        public FileEnvelope() {}

        public String getName() { return name; }
        public void setName(String name) { this.name = name; }

        public Long getSizeBytes() { return sizeBytes; }
        public void setSizeBytes(Long sizeBytes) { this.sizeBytes = sizeBytes; }

        public String getContentType() { return contentType; }
        public void setContentType(String contentType) { this.contentType = contentType; }

        public String getSha256Hex() { return sha256Hex; }
        public void setSha256Hex(String sha256Hex) { this.sha256Hex = sha256Hex; }

        public String getBase64Content() { return base64Content; }
        public void setBase64Content(String base64Content) { this.base64Content = base64Content; }

        public String getContentOmittedReason() { return contentOmittedReason; }
        public void setContentOmittedReason(String contentOmittedReason) {
            this.contentOmittedReason = contentOmittedReason;
        }
    }

    /**
     * Signature-failure olayının yapısal detayları. Stack trace yer
     * almaz (gizlilik + boyut); yalnız exception tipi ve mesajı.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class SignatureFailure {

        /**
         * İmza endpoint URL path'i (örn. {@code "/v1/xadessign"}). Operatör
         * hangi endpoint'in patladığını anında görsün.
         */
        private String endpoint;

        /**
         * İmza tipi insan-okunur etiket: {@code "XAdES"}, {@code "CAdES"},
         * {@code "PAdES"}, {@code "WS-Security"}, {@code "Hash"},
         * {@code "Timestamp"}.
         */
        private String signatureType;

        /** Exception class adı (örn. {@code "io.mersel.dss.signer.api.exceptions.SignatureException"}). */
        private String errorClass;

        /** Exception {@code getMessage()} dönüşü. {@code null} olabilir. */
        private String errorMessage;

        /**
         * {@link io.mersel.dss.signer.api.exceptions.SignatureException}
         * gibi domain exception'larda {@code getErrorCode()} dönüşü.
         * Generic exception'larda null.
         */
        private String errorCode;

        public SignatureFailure() {}

        public String getEndpoint() { return endpoint; }
        public void setEndpoint(String endpoint) { this.endpoint = endpoint; }

        public String getSignatureType() { return signatureType; }
        public void setSignatureType(String signatureType) { this.signatureType = signatureType; }

        public String getErrorClass() { return errorClass; }
        public void setErrorClass(String errorClass) { this.errorClass = errorClass; }

        public String getErrorMessage() { return errorMessage; }
        public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }

        public String getErrorCode() { return errorCode; }
        public void setErrorCode(String errorCode) { this.errorCode = errorCode; }
    }

    /**
     * Heartbeat state transition olayının detayları + cumulative sayaçlar.
     * Operatör tek bakışta HSM sağlık geçmişini görsün.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class HeartbeatEvent {

        /** Tetiklenen event tipi enum adı (örn. {@code "FAILED"}). */
        private String eventType;

        /** HSM private key alias'ı (heartbeat'in hangi anahtarla atıldığı). */
        private String alias;

        /** {@link eu.europa.esig.dss.enumerations.SignatureAlgorithm} enum adı. */
        private String signatureAlgorithm;

        /** Toplam başarılı heartbeat sayısı (cumulative). */
        private Long successCount;

        /** Toplam başarısız heartbeat sayısı (cumulative). */
        private Long failureCount;

        /** Şu ana kadar üst üste başarısızlık (event tetiklendiği andaki snapshot). */
        private Long consecutiveFailures;

        /** Şu ana kadar denenmiş Cryptoki-level reinit sayısı (cumulative). */
        private Long reinitAttempts;

        /** Başarılı reinit sayısı (cumulative). */
        private Long reinitSuccesses;

        /**
         * FAILED / REINIT_FAILED için exception mesajı (Throwable.getMessage()).
         * Diğer event'lerde null.
         */
        private String errorMessage;

        /** Exception class adı (FAILED / REINIT_FAILED'da). */
        private String errorClass;

        public HeartbeatEvent() {}

        public String getEventType() { return eventType; }
        public void setEventType(String eventType) { this.eventType = eventType; }

        public String getAlias() { return alias; }
        public void setAlias(String alias) { this.alias = alias; }

        public String getSignatureAlgorithm() { return signatureAlgorithm; }
        public void setSignatureAlgorithm(String signatureAlgorithm) {
            this.signatureAlgorithm = signatureAlgorithm;
        }

        public Long getSuccessCount() { return successCount; }
        public void setSuccessCount(Long successCount) { this.successCount = successCount; }

        public Long getFailureCount() { return failureCount; }
        public void setFailureCount(Long failureCount) { this.failureCount = failureCount; }

        public Long getConsecutiveFailures() { return consecutiveFailures; }
        public void setConsecutiveFailures(Long consecutiveFailures) {
            this.consecutiveFailures = consecutiveFailures;
        }

        public Long getReinitAttempts() { return reinitAttempts; }
        public void setReinitAttempts(Long reinitAttempts) { this.reinitAttempts = reinitAttempts; }

        public Long getReinitSuccesses() { return reinitSuccesses; }
        public void setReinitSuccesses(Long reinitSuccesses) { this.reinitSuccesses = reinitSuccesses; }

        public String getErrorMessage() { return errorMessage; }
        public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }

        public String getErrorClass() { return errorClass; }
        public void setErrorClass(String errorClass) { this.errorClass = errorClass; }
    }
}
