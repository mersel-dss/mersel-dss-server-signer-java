package io.mersel.dss.signer.api.services.notification;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import io.mersel.dss.signer.api.config.LogHeadersFilter;
import io.mersel.dss.signer.api.config.SignerNotificationConfiguration;
import io.mersel.dss.signer.api.exceptions.SignatureException;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.info.BuildProperties;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;

/**
 * Signer API üzerinde iki ayrı olayda fire-and-forget bildirim üreten
 * notifier servisi:
 *
 * <ul>
 *   <li><b>{@code signature-failure}</b> — Herhangi bir imza endpoint'inde
 *       (XAdES, CAdES, PAdES, WS-Security, Hash, Timestamp) bir exception
 *       yakalandığında. Controller {@link #notifyOnSignatureFailure} çağırır;
 *       MDC'de hazır bulunan {@code x-log-*} başlıkları payload'a + Slack
 *       mesajına eklenir. İmzalanmaya çalışılan doküman <em>opsiyonel</em>
 *       olarak generic webhook payload'una base64 ve/veya Slack bot
 *       upload'una dosya olarak gider.</li>
 *   <li><b>{@code heartbeat-*}</b> — HSM heartbeat state transition
 *       olayları ({@link HeartbeatEventType}). Heartbeat scheduler thread'i
 *       request bağlamına sahip olmadığı için {@code x-log-*} alanı boş;
 *       payload yalnız HSM/scheduler sayaçlarını taşır.</li>
 * </ul>
 *
 * <h3>Davranış sözleşmesi</h3>
 * <ul>
 *   <li><b>Aktivasyon</b> — Notifier {@code enabled} VE en az bir URL set
 *       edilmediği sürece hiçbir şey yapmaz. OkHttp client bile kurulmaz
 *       (heap maliyeti sıfır).</li>
 *   <li><b>Event-seviyesinde kapanış</b> — Operatör yalnız heartbeat'i
 *       açık tutup signature-failure'ı kapatabilir
 *       ({@code SIGNER_NOTIFICATION_SIGNATURE_FAILURE_ENABLED=false}) ya
 *       da tersi.</li>
 *   <li><b>Async</b> — OkHttp {@code enqueue()} kullanılır; çağıran thread
 *       (controller veya scheduler) HTTP'yi beklemez. Bildirim hataları
 *       imza/heartbeat akışını ASLA bozmaz; yalnız WARN/ERROR loglanır.</li>
 *   <li><b>İçerik</b> — Generic webhook payload'una imzalanmaya çalışılan
 *       dosya base64 olarak <em>opsiyonel</em> eklenir
 *       ({@code includeContent} + {@code maxContentSizeBytes}). Slack
 *       mesajına default'ta içerik gitmez; operatör
 *       {@code slackInlineBase64Enabled=true} yaparsa code-fenced chunk'lar
 *       eklenir.</li>
 * </ul>
 *
 * @see SignerNotificationConfiguration
 * @see SignerEventWebhookPayload
 * @see SlackFileUploader
 */
@Service
public class SignerNotifier {

    private static final Logger logger = LoggerFactory.getLogger(SignerNotifier.class);

    static final MediaType JSON_MEDIA_TYPE = MediaType.get("application/json; charset=utf-8");

    /** Webhook payload schema'sında sabit event tipi (signature-failure). */
    static final String EVENT_TYPE_SIGNATURE_FAILURE = "signature-failure";

    /** Operatöre rehberlik için contentOmittedReason kodları (kararlı API). */
    static final String OMITTED_BY_CONFIG = "EXCLUDED_BY_CONFIG";
    static final String OMITTED_EXCEEDED_MAX_SIZE = "EXCEEDED_MAX_SIZE";

    /** Slack mesajındaki korelasyon header sayısı üst sınırı (Block Kit 3000-char/section limiti). */
    static final int SLACK_MAX_LOG_HEADERS_LISTED = 10;

    /** Inline base64 chunk char tavanı — Block Kit per-section 3000 limiti içinde tampon. */
    static final int SLACK_INLINE_BASE64_CHUNK_CHARS = 2700;

    /** Signature-failure attachment color — danger/red yan şerit. */
    static final String SLACK_DANGER_COLOR = "#A30200";

    /** Heartbeat alarm event attachment color — uyarı/turuncu (FAILED, REINIT_TRIGGERED, REINIT_FAILED). */
    static final String SLACK_WARNING_COLOR = "#D97706";

    /** Heartbeat iyileşme event attachment color — yeşil (RECOVERED, REINIT_SUCCESS). */
    static final String SLACK_GOOD_COLOR = "#2EB67D";

    /** Generic webhook HMAC + replay-protection header isimleri (kararlı API). */
    static final String HEADER_WEBHOOK_ID = "X-Mersel-Webhook-Id";
    static final String HEADER_WEBHOOK_TIMESTAMP = "X-Mersel-Webhook-Timestamp";
    static final String HEADER_WEBHOOK_EVENT = "X-Mersel-Event";
    static final String HEADER_WEBHOOK_SIGNATURE = "X-Mersel-Signature";

    static final String HMAC_ALGORITHM = "HmacSHA256";

    @Autowired
    private SignerNotificationConfiguration config;

    /**
     * Spring Boot {@code build-info} goal'unun ürettiği
     * {@code META-INF/build-info.properties}'ten gelir. Test sırasında
     * yoksa {@code null} olabilir — {@code source} alanı fallback'e düşer.
     */
    @Autowired(required = false)
    private BuildProperties buildProperties;

    private final ObjectMapper objectMapper;

    private OkHttpClient httpClient;
    private SlackFileUploader slackFileUploader;

    /** Test hook'u — sabit zamanlı payload üretmek için. */
    private java.util.function.Supplier<Date> clock = Date::new;

    /** Test hook'u — webhook timestamp header'ını deterministik kılmak için. */
    private LongSupplier unixSecondsClock = () -> System.currentTimeMillis() / 1000L;

    /** Test hook'u — webhook delivery-id'sini sabitlemek için. */
    private java.util.function.Supplier<String> idGenerator = () -> UUID.randomUUID().toString();

    public SignerNotifier() {
        this.objectMapper = new ObjectMapper();
        this.objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        this.objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
    }

    @PostConstruct
    void initialize() {
        // Verifier paraleli LAZY HTTP CLIENT INIT — feature kapalı veya
        // hiç destination yoksa OkHttpClient KURULMAZ; heap maliyeti sıfır.
        if (!config.isEnabled()) {
            logger.info("SignerNotifier: feature kapalı "
                    + "(notification.signer.enabled=false). Hiçbir bildirim "
                    + "gönderilmeyecek. OkHttpClient kurulmadı (zero-overhead).");
            return;
        }
        if (!config.hasAnyDestination()) {
            logger.info("SignerNotifier: hiçbir bildirim hedefi set edilmedi "
                    + "(SIGNER_WEBHOOK_URL / SIGNER_SLACK_WEBHOOK_URL / "
                    + "SIGNER_SLACK_BOT_TOKEN+CHANNEL hepsi boş). "
                    + "Feature aktif ama bildirim hedefi yok — OkHttpClient kurulmadı (zero-overhead).");
            return;
        }

        this.httpClient = new OkHttpClient.Builder()
                .connectTimeout(config.getConnectTimeoutMs(), TimeUnit.MILLISECONDS)
                .readTimeout(config.getReadTimeoutMs(), TimeUnit.MILLISECONDS)
                .writeTimeout(config.getReadTimeoutMs(), TimeUnit.MILLISECONDS)
                .build();
        this.slackFileUploader = new SlackFileUploader(this.httpClient, this.objectMapper);

        logger.info("SignerNotifier: aktif. signatureFailure={}, heartbeat={}, "
                        + "webhook={}, webhookSecret={}, slackMessage={}, slackFileUpload={}, "
                        + "includeContent={}, maxContentSize={} bytes",
                config.isSignatureFailureEnabled(),
                config.isHeartbeatEnabled(),
                config.hasWebhookDestination() ? "configured" : "<unset>",
                config.hasWebhookSecret() ? "configured" : "<unset>",
                config.hasSlackDestination() ? "configured" : "<unset>",
                config.hasSlackBotUploadDestination() ? "configured" : "<unset>",
                config.isIncludeContent(),
                config.getMaxContentSizeBytes());
    }

    @PreDestroy
    void shutdown() {
        if (httpClient == null) {
            return;
        }
        try {
            httpClient.dispatcher().executorService().shutdown();
            httpClient.connectionPool().evictAll();
        } catch (Exception e) {
            logger.debug("SignerNotifier shutdown sırasında küçük hata (yok sayıldı): {}",
                    e.getMessage());
        }
    }

    // =====================================================================
    // PUBLIC API — Signature failure dispatch
    // =====================================================================

    /**
     * İmza endpoint'inde yakalanan exception için fire-and-forget bildirim.
     * <strong>Best-effort</strong>: bildirim başarısız olsa bile çağıran
     * controller akışı etkilenmez.
     *
     * @param endpoint        İmza endpoint URL path'i (örn. {@code "/v1/xadessign"})
     * @param signatureType   Hangi imza tipi ({@code "XAdES"}, {@code "CAdES"}, ...)
     * @param error           Yakalanan exception. {@code null} olabilir.
     * @param documentBytes   İmzalanmaya çalışılan dokümanın bytes (opsiyonel).
     * @param fileName        Multipart {@code originalFilename}. {@code null} olabilir.
     * @param contentType     MIME tipi. {@code null} olabilir.
     */
    public void notifyOnSignatureFailure(
            String endpoint,
            String signatureType,
            Throwable error,
            byte[] documentBytes,
            String fileName,
            String contentType) {

        try {
            doNotifyOnSignatureFailure(endpoint, signatureType, error,
                    documentBytes, fileName, contentType);
        } catch (Throwable t) {
            // Throwable: NoClassDefFoundError, OOM dahil hiçbir şey imza akışını bozmasın.
            logger.warn("SignerNotifier signature-failure: beklenmedik hata, "
                    + "bildirim atlandı (imza akışı etkilenmedi): {}", t.toString());
        }
    }

    private void doNotifyOnSignatureFailure(
            String endpoint,
            String signatureType,
            Throwable error,
            byte[] documentBytes,
            String fileName,
            String contentType) {

        if (!config.isEnabled() || !config.isSignatureFailureEnabled()
                || !config.hasAnyDestination()) {
            return;
        }

        Map<String, String> logHeaders = collectXlogHeadersFromMdc();

        SignerEventWebhookPayload payload;
        String slackBody;
        try {
            payload = buildSignatureFailurePayload(endpoint, signatureType, error,
                    documentBytes, fileName, contentType, logHeaders);
            slackBody = buildSlackBodyForSignatureFailure(
                    endpoint, signatureType, error, fileName, documentBytes, logHeaders);
        } catch (Exception buildEx) {
            logger.warn("SignerNotifier signature-failure payload build failed; "
                    + "bildirim atlanıyor: {}", buildEx.getMessage());
            return;
        }

        // Her kanal kendi try/catch'inde izole; biri patlasa diğeri yine gider.
        if (config.hasWebhookDestination()) {
            try {
                fireWebhookPost(config.getWebhookUrl(), serializeOrEmpty(payload),
                        EVENT_TYPE_SIGNATURE_FAILURE, logHeaders);
            } catch (Exception e) {
                logger.warn("SignerNotifier signature-failure webhook dispatch failed: {}",
                        e.getMessage());
            }
        }
        if (config.hasSlackDestination()) {
            try {
                fireSimplePost(config.getSlackWebhookUrl(), slackBody, "slack");
            } catch (Exception e) {
                logger.warn("SignerNotifier signature-failure slack message dispatch failed: {}",
                        e.getMessage());
            }
        }
        if (config.hasSlackBotUploadDestination()
                && documentBytes != null
                && documentBytes.length > 0
                && (long) documentBytes.length <= config.getMaxContentSizeBytes()
                && slackFileUploader != null) {
            try {
                slackFileUploader.uploadAsync(
                        config.getSlackBotToken(),
                        config.getSlackBotChannel(),
                        documentBytes,
                        safeFileName(fileName),
                        buildSlackFileTitle(signatureType, fileName),
                        buildSlackFileInitialComment(endpoint, signatureType, error,
                                fileName, logHeaders));
            } catch (Exception e) {
                logger.warn("SignerNotifier signature-failure slack file upload dispatch failed: {}",
                        e.getMessage());
            }
        } else if (config.hasSlackBotUploadDestination()
                && documentBytes != null
                && (long) documentBytes.length > config.getMaxContentSizeBytes()) {
            logger.info("Slack bot file upload skipped: dosya boyutu {} bytes > "
                            + "max-content-size {} bytes. Webhook payload zaten "
                            + "metadata + omittedReason taşıyor.",
                    documentBytes.length, config.getMaxContentSizeBytes());
        }
    }

    // =====================================================================
    // PUBLIC API — Heartbeat dispatch
    // =====================================================================

    /**
     * HSM heartbeat state transition'ı için fire-and-forget bildirim.
     * <strong>Best-effort</strong>: bildirim başarısız olsa bile scheduler
     * akışı etkilenmez. Scheduler thread'inde request bağlamı olmadığı için
     * {@code x-log-*} header'ları toplanmaz (payload {@code logHeaders}
     * null kalır).
     *
     * @param eventType            State transition tipi.
     * @param alias                HSM private key alias'ı.
     * @param signatureAlgorithm   Heartbeat'in algoritması (örn. {@code "RSA_SHA256"}).
     * @param stats                Cumulative sayaçlar (success, failure, consecutive, reinit*).
     *                             Anahtarlar: {@code "successCount"}, {@code "failureCount"},
     *                             {@code "consecutiveFailures"}, {@code "reinitAttempts"},
     *                             {@code "reinitSuccesses"}. {@code null} olabilir.
     * @param error                FAILED/REINIT_FAILED için exception. Diğerlerinde null.
     */
    public void notifyOnHeartbeatEvent(
            HeartbeatEventType eventType,
            String alias,
            String signatureAlgorithm,
            Map<String, Long> stats,
            Throwable error) {

        try {
            doNotifyOnHeartbeatEvent(eventType, alias, signatureAlgorithm, stats, error);
        } catch (Throwable t) {
            logger.warn("SignerNotifier heartbeat: beklenmedik hata, "
                    + "bildirim atlandı (scheduler akışı etkilenmedi): {}", t.toString());
        }
    }

    private void doNotifyOnHeartbeatEvent(
            HeartbeatEventType eventType,
            String alias,
            String signatureAlgorithm,
            Map<String, Long> stats,
            Throwable error) {

        if (eventType == null) {
            return;
        }
        if (!config.isEnabled() || !config.isHeartbeatEnabled()
                || !config.hasAnyDestination()) {
            return;
        }

        // Heartbeat scheduler thread'inde MDC tipik olarak boştur. Yine de
        // MDC.getCopyOfContextMap() güvenle dener; boşsa null/empty döner.
        Map<String, String> logHeaders = collectXlogHeadersFromMdc();

        SignerEventWebhookPayload payload;
        String slackBody;
        try {
            payload = buildHeartbeatPayload(eventType, alias, signatureAlgorithm,
                    stats, error, logHeaders);
            slackBody = buildSlackBodyForHeartbeat(eventType, alias, signatureAlgorithm,
                    stats, error);
        } catch (Exception buildEx) {
            logger.warn("SignerNotifier heartbeat payload build failed; "
                    + "bildirim atlanıyor: {}", buildEx.getMessage());
            return;
        }

        if (config.hasWebhookDestination()) {
            try {
                fireWebhookPost(config.getWebhookUrl(), serializeOrEmpty(payload),
                        eventType.getEventCode(), logHeaders);
            } catch (Exception e) {
                logger.warn("SignerNotifier heartbeat webhook dispatch failed: {}",
                        e.getMessage());
            }
        }
        if (config.hasSlackDestination()) {
            try {
                fireSimplePost(config.getSlackWebhookUrl(), slackBody, "slack");
            } catch (Exception e) {
                logger.warn("SignerNotifier heartbeat slack message dispatch failed: {}",
                        e.getMessage());
            }
        }
        // Bot file upload heartbeat için ATLANIR — dosya yok.
    }

    // =====================================================================
    // x-log-* MDC capture
    // =====================================================================

    /**
     * Request thread'inin MDC'sinden {@link LogHeadersFilter} tarafından
     * konulmuş {@code xlog.*} entry'lerini toplar ve orijinal
     * {@code x-log-*} header adına geri haritalar.
     *
     * <p>Sıralama deterministik (TreeMap) — snapshot eşitliği, test
     * stabilitesi, Slack mesaj okunabilirlik için. Hiç header yoksa
     * {@link Collections#emptyMap()} döner.</p>
     *
     * <p><b>Async sınırlama</b>: Bu metod yalnız notifier'ın SYNC kısmında
     * (controller request thread'i veya scheduler thread'i) çağrılır. OkHttp
     * dispatcher thread'ine geçtikten sonra MDC kaybolur; snapshot mantığı
     * doğru async-safe değer aktarımı sağlar.</p>
     */
    Map<String, String> collectXlogHeadersFromMdc() {
        Map<String, String> mdc;
        try {
            mdc = MDC.getCopyOfContextMap();
        } catch (Exception e) {
            return Collections.emptyMap();
        }
        if (mdc == null || mdc.isEmpty()) {
            return Collections.emptyMap();
        }
        TreeMap<String, String> out = new TreeMap<>();
        String prefix = LogHeadersFilter.MDC_KEY_PREFIX;
        for (Map.Entry<String, String> e : mdc.entrySet()) {
            String key = e.getKey();
            String value = e.getValue();
            if (key == null || value == null || value.isEmpty()) {
                continue;
            }
            if (!key.startsWith(prefix)) {
                continue;
            }
            String headerName = key.substring(prefix.length());
            if (headerName.isEmpty()) {
                continue;
            }
            out.put(headerName, value);
        }
        return out.isEmpty() ? Collections.emptyMap() : Collections.unmodifiableMap(out);
    }

    // =====================================================================
    // Payload builders — signature failure
    // =====================================================================

    /**
     * Package-private — birim testleri serializasyon-öncesi yapıyı
     * doğrulayabilsin (HTTP firing'i mock'lamaya gerek yok).
     */
    SignerEventWebhookPayload buildSignatureFailurePayload(
            String endpoint,
            String signatureType,
            Throwable error,
            byte[] documentBytes,
            String fileName,
            String contentType,
            Map<String, String> logHeaders) {

        SignerEventWebhookPayload payload = new SignerEventWebhookPayload();
        payload.setEvent(EVENT_TYPE_SIGNATURE_FAILURE);
        payload.setSource(resolveSource());
        payload.setNotificationTime(clock.get());

        payload.setFile(buildFileEnvelope(documentBytes, fileName, contentType));

        SignerEventWebhookPayload.SignatureFailure sf =
                new SignerEventWebhookPayload.SignatureFailure();
        sf.setEndpoint(endpoint);
        sf.setSignatureType(signatureType);
        if (error != null) {
            sf.setErrorClass(error.getClass().getName());
            sf.setErrorMessage(error.getMessage());
            if (error instanceof SignatureException) {
                sf.setErrorCode(((SignatureException) error).getErrorCode());
            }
        }
        payload.setSignatureFailure(sf);

        if (logHeaders != null && !logHeaders.isEmpty()) {
            payload.setLogHeaders(new TreeMap<>(logHeaders));
        }

        return payload;
    }

    // =====================================================================
    // Payload builders — heartbeat
    // =====================================================================

    SignerEventWebhookPayload buildHeartbeatPayload(
            HeartbeatEventType eventType,
            String alias,
            String signatureAlgorithm,
            Map<String, Long> stats,
            Throwable error,
            Map<String, String> logHeaders) {

        SignerEventWebhookPayload payload = new SignerEventWebhookPayload();
        payload.setEvent(eventType.getEventCode());
        payload.setSource(resolveSource());
        payload.setNotificationTime(clock.get());

        SignerEventWebhookPayload.HeartbeatEvent he =
                new SignerEventWebhookPayload.HeartbeatEvent();
        he.setEventType(eventType.name());
        he.setAlias(alias);
        he.setSignatureAlgorithm(signatureAlgorithm);
        if (stats != null) {
            he.setSuccessCount(stats.get("successCount"));
            he.setFailureCount(stats.get("failureCount"));
            he.setConsecutiveFailures(stats.get("consecutiveFailures"));
            he.setReinitAttempts(stats.get("reinitAttempts"));
            he.setReinitSuccesses(stats.get("reinitSuccesses"));
        }
        if (error != null) {
            he.setErrorClass(error.getClass().getName());
            he.setErrorMessage(error.getMessage());
        }
        payload.setHeartbeat(he);

        if (logHeaders != null && !logHeaders.isEmpty()) {
            payload.setLogHeaders(new TreeMap<>(logHeaders));
        }

        return payload;
    }

    // =====================================================================
    // Slack body — signature failure
    // =====================================================================

    String buildSlackBodyForSignatureFailure(
            String endpoint,
            String signatureType,
            Throwable error,
            String fileName,
            byte[] documentBytes,
            Map<String, String> logHeaders) {

        Map<String, Object> root = new LinkedHashMap<>();

        String title = "Mersel DSS Signer - SIGNATURE FAILURE";
        String fallbackText = title + ": " + safeFileName(fileName)
                + " (" + safeSignatureType(signatureType) + ")";
        root.put("text", fallbackText);

        List<Map<String, Object>> blocks = new ArrayList<>();

        // 1) Header
        blocks.add(slackHeader("\uD83D\uDEA8 " + title));

        // 2) Özet field'ları
        List<Map<String, Object>> summaryFields = new ArrayList<>();
        summaryFields.add(slackField("*Endpoint:*\n`" + safeStr(endpoint, "<unknown>") + "`"));
        summaryFields.add(slackField("*İmza Tipi:*\n" + safeSignatureType(signatureType)));
        summaryFields.add(slackField("*Dosya:*\n" + safeFileName(fileName)));
        if (documentBytes != null) {
            summaryFields.add(slackField("*Boyut:*\n" + documentBytes.length + " bytes"));
        }
        if (error != null) {
            summaryFields.add(slackField("*Hata Sınıfı:*\n`"
                    + error.getClass().getSimpleName() + "`"));
            if (error instanceof SignatureException) {
                summaryFields.add(slackField("*Hata Kodu:*\n`"
                        + ((SignatureException) error).getErrorCode() + "`"));
            }
        }
        blocks.add(slackSectionWithFields(summaryFields));

        // 2.5) Korelasyon header'ları
        if (logHeaders != null && !logHeaders.isEmpty()) {
            blocks.add(buildLogHeadersBlock(logHeaders));
        }

        // 3) Hata mesajı
        if (error != null && error.getMessage() != null && !error.getMessage().isEmpty()) {
            blocks.add(slackSectionMarkdown("*Hata Mesajı:*\n```"
                    + truncate(error.getMessage(), 1500) + "```"));
        }

        // 4) Inline base64 fallback — operatör bilinçli olarak açtıysa
        appendInlineBase64Sections(blocks, documentBytes);

        Map<String, Object> attachment = new LinkedHashMap<>();
        attachment.put("color", SLACK_DANGER_COLOR);
        attachment.put("blocks", blocks);
        attachment.put("fallback", fallbackText);
        root.put("attachments", Collections.singletonList(attachment));

        return serializeOrEmpty(root);
    }

    // =====================================================================
    // Slack body — heartbeat
    // =====================================================================

    String buildSlackBodyForHeartbeat(
            HeartbeatEventType eventType,
            String alias,
            String signatureAlgorithm,
            Map<String, Long> stats,
            Throwable error) {

        Map<String, Object> root = new LinkedHashMap<>();

        String emoji = eventType.isPositiveSignal() ? "\u2705" : "\u26A0\uFE0F";
        String title = "Mersel DSS Signer - " + eventType.getHumanLabel();
        String fallbackText = title + " (alias=" + safeStr(alias, "<unknown>") + ")";
        root.put("text", fallbackText);

        List<Map<String, Object>> blocks = new ArrayList<>();

        blocks.add(slackHeader(emoji + " " + title));

        List<Map<String, Object>> summaryFields = new ArrayList<>();
        summaryFields.add(slackField("*Event:*\n`" + eventType.getEventCode() + "`"));
        summaryFields.add(slackField("*Alias:*\n`" + safeStr(alias, "<unknown>") + "`"));
        if (signatureAlgorithm != null) {
            summaryFields.add(slackField("*Algoritma:*\n" + signatureAlgorithm));
        }
        if (stats != null) {
            Long successCount = stats.get("successCount");
            Long failureCount = stats.get("failureCount");
            Long consecutiveFailures = stats.get("consecutiveFailures");
            Long reinitAttempts = stats.get("reinitAttempts");
            Long reinitSuccesses = stats.get("reinitSuccesses");
            if (successCount != null) {
                summaryFields.add(slackField("*Toplam Başarı:*\n" + successCount));
            }
            if (failureCount != null) {
                summaryFields.add(slackField("*Toplam Başarısızlık:*\n" + failureCount));
            }
            if (consecutiveFailures != null) {
                summaryFields.add(slackField("*Ardışık Başarısızlık:*\n" + consecutiveFailures));
            }
            if (reinitAttempts != null) {
                summaryFields.add(slackField("*Reinit Denemesi:*\n" + reinitAttempts));
            }
            if (reinitSuccesses != null) {
                summaryFields.add(slackField("*Reinit Başarısı:*\n" + reinitSuccesses));
            }
        }
        blocks.add(slackSectionWithFields(summaryFields));

        if (error != null && error.getMessage() != null && !error.getMessage().isEmpty()) {
            blocks.add(slackSectionMarkdown("*Hata Mesajı:*\n```"
                    + truncate(error.getMessage(), 1500) + "```"));
        }

        // Heartbeat event'inde correlation header'ları teorik olarak yok
        // (scheduler thread); ama defensive: varsa yine ekle.
        Map<String, String> logHeaders = collectXlogHeadersFromMdc();
        if (logHeaders != null && !logHeaders.isEmpty()) {
            blocks.add(buildLogHeadersBlock(logHeaders));
        }

        Map<String, Object> attachment = new LinkedHashMap<>();
        attachment.put("color", eventType.isPositiveSignal()
                ? SLACK_GOOD_COLOR : SLACK_WARNING_COLOR);
        attachment.put("blocks", blocks);
        attachment.put("fallback", fallbackText);
        root.put("attachments", Collections.singletonList(attachment));

        return serializeOrEmpty(root);
    }

    // =====================================================================
    // Slack helpers
    // =====================================================================

    /** Korelasyon header'larını listeleyen Block Kit section block'u. */
    private Map<String, Object> buildLogHeadersBlock(Map<String, String> logHeaders) {
        StringBuilder hsb = new StringBuilder("*Korelasyon (x-log-*):*\n");
        int listed = 0;
        for (Map.Entry<String, String> e : logHeaders.entrySet()) {
            if (listed >= SLACK_MAX_LOG_HEADERS_LISTED) {
                hsb.append("• … (").append(logHeaders.size() - SLACK_MAX_LOG_HEADERS_LISTED)
                        .append(" header daha)\n");
                break;
            }
            hsb.append("• `").append(e.getKey()).append("`: ")
                    .append(truncate(e.getValue(), 200)).append('\n');
            listed++;
        }
        return slackSectionMarkdown(hsb.toString());
    }

    private void appendInlineBase64Sections(
            List<Map<String, Object>> blocks, byte[] documentBytes) {

        if (!config.isSlackInlineBase64Enabled()) {
            return;
        }
        if (documentBytes == null || documentBytes.length == 0) {
            return;
        }

        long limit = config.getSlackInlineBase64MaxBytes();
        if ((long) documentBytes.length > limit) {
            blocks.add(slackSectionMarkdown(
                    "*İçerik:* Dosya boyutu (" + documentBytes.length
                            + " bytes) Slack mesajı inline limiti (" + limit
                            + " bytes) aşıyor.\n"
                            + "_Operatör için en doğru yol *Slack bot file upload*"
                            + " (`SIGNER_SLACK_BOT_TOKEN` + `SIGNER_SLACK_CHANNEL` set"
                            + " edin → dosya `files.slack.com`'a yüklenir). Tam"
                            + " base64 içerik webhook payload'unda da mevcut._"));
            logger.info("Slack inline base64 skipped (oversized): {} bytes > {} bytes limit",
                    documentBytes.length, limit);
            return;
        }

        String base64;
        try {
            base64 = Base64.getEncoder().encodeToString(documentBytes);
        } catch (Exception e) {
            logger.warn("Slack inline base64 encode failed; inline blok atlandı: {}",
                    e.getMessage());
            return;
        }

        List<String> chunks = chunkForSlackSection(base64, SLACK_INLINE_BASE64_CHUNK_CHARS);
        if (chunks.isEmpty()) {
            return;
        }

        String prefix = "*İçerik (base64, " + documentBytes.length + " bytes):*\n";
        String decodeHint = "\n_Decode: `pbpaste | base64 -d > document.bin` (macOS)"
                + " / `xclip -o | base64 -d > document.bin` (Linux)_";

        int total = chunks.size();
        for (int i = 0; i < total; i++) {
            StringBuilder sb = new StringBuilder(SLACK_INLINE_BASE64_CHUNK_CHARS + 200);
            if (i == 0) {
                sb.append(prefix);
            }
            sb.append("```\n").append(chunks.get(i)).append("\n```");
            if (i == total - 1) {
                sb.append(decodeHint);
            }
            blocks.add(slackSectionMarkdown(sb.toString()));
        }
    }

    /**
     * Char-pencere chunk'lama — Slack Block Kit 3000-char/section limitine
     * sığdırmak için. Base64 string'leri için kritik: tek char drift
     * decode'u bozar; bu yüzden truncate ASLA uygulanmaz.
     *
     * <p>Round-trip garantisi: {@code String.join("", chunkForSlackSection(text, n)).equals(text)}.</p>
     */
    static List<String> chunkForSlackSection(String text, int chunkSize) {
        if (chunkSize <= 0) {
            throw new IllegalArgumentException(
                    "chunkSize must be > 0; got " + chunkSize);
        }
        if (text == null || text.isEmpty()) {
            return Collections.emptyList();
        }
        int len = text.length();
        if (len <= chunkSize) {
            return Collections.singletonList(text);
        }
        int expected = (len + chunkSize - 1) / chunkSize;
        List<String> out = new ArrayList<>(expected);
        int i = 0;
        while (i < len) {
            int end = Math.min(i + chunkSize, len);
            out.add(text.substring(i, end));
            i = end;
        }
        return out;
    }

    /** Slack file upload title — Slack dosya başlığında görünür. */
    String buildSlackFileTitle(String signatureType, String fileName) {
        return "[FAILED " + safeSignatureType(signatureType) + "] " + safeFileName(fileName);
    }

    /**
     * Slack file upload initial_comment — dosyanın altında kanal mesajı.
     * Block Kit kullanmıyoruz çünkü {@code completeUploadExternal}
     * initial_comment için zengin format desteği sınırlı; mrkdwn-flavored
     * plain text en güvenli yol.
     */
    String buildSlackFileInitialComment(String endpoint, String signatureType,
                                        Throwable error, String fileName,
                                        Map<String, String> logHeaders) {
        StringBuilder sb = new StringBuilder();
        sb.append(":rotating_light: *Mersel DSS Signer – SIGNATURE FAILURE*\n");
        sb.append("• Endpoint: `").append(safeStr(endpoint, "<unknown>")).append("`\n");
        sb.append("• İmza Tipi: `").append(safeSignatureType(signatureType)).append("`\n");
        sb.append("• Dosya: `").append(safeFileName(fileName)).append("`\n");
        if (error != null) {
            sb.append("• Hata Sınıfı: `").append(error.getClass().getSimpleName()).append("`\n");
            if (error.getMessage() != null) {
                sb.append("• Hata Mesajı: ").append(truncate(error.getMessage(), 300)).append('\n');
            }
            if (error instanceof SignatureException) {
                sb.append("• Hata Kodu: `")
                        .append(((SignatureException) error).getErrorCode()).append("`\n");
            }
        }
        if (logHeaders != null && !logHeaders.isEmpty()) {
            sb.append("• Korelasyon (x-log-*):");
            int listed = 0;
            for (Map.Entry<String, String> e : logHeaders.entrySet()) {
                if (listed >= SLACK_MAX_LOG_HEADERS_LISTED) {
                    sb.append(" … (+")
                            .append(logHeaders.size() - SLACK_MAX_LOG_HEADERS_LISTED)
                            .append(")");
                    break;
                }
                sb.append(" `").append(e.getKey()).append("`=")
                        .append(truncate(e.getValue(), 120));
                listed++;
            }
            sb.append('\n');
        }
        return truncate(sb.toString(), 1500);
    }

    // =====================================================================
    // File envelope
    // =====================================================================

    private SignerEventWebhookPayload.FileEnvelope buildFileEnvelope(
            byte[] bytes, String fileName, String contentType) {
        SignerEventWebhookPayload.FileEnvelope envelope =
                new SignerEventWebhookPayload.FileEnvelope();
        envelope.setName(fileName);
        envelope.setContentType(contentType);

        if (bytes == null) {
            return envelope;
        }
        envelope.setSizeBytes((long) bytes.length);
        envelope.setSha256Hex(sha256Hex(bytes));

        if (!config.isIncludeContent()) {
            envelope.setContentOmittedReason(OMITTED_BY_CONFIG);
        } else if ((long) bytes.length > config.getMaxContentSizeBytes()) {
            envelope.setContentOmittedReason(OMITTED_EXCEEDED_MAX_SIZE);
            logger.debug("Webhook payload'una içerik dahil edilmedi: dosya boyutu {} > sınır {}",
                    bytes.length, config.getMaxContentSizeBytes());
        } else {
            envelope.setBase64Content(Base64.getEncoder().encodeToString(bytes));
        }
        return envelope;
    }

    // =====================================================================
    // HTTP firing
    // =====================================================================

    /**
     * Generic webhook POST'u — HMAC imzası + delivery-id + timestamp
     * header'larını ekler. Receiver bu header'lardan üç şey doğrular:
     * authenticity (HMAC), replay protection (timestamp window),
     * idempotency (delivery-id).
     *
     * <p>Secret set değilse {@code X-Mersel-Signature} header'ı ATILMAZ —
     * receiver URL gizliliğine güvenir (Slack incoming webhook modeli
     * paraleli).</p>
     */
    private void fireWebhookPost(String url, String jsonBody, String eventCode,
                                 Map<String, String> logHeaders) {
        if (httpClient == null) {
            logger.warn("SignerNotifier webhook: HTTP client başlatılmamış "
                    + "(başlangıçta destination yoktu); bildirim atlanıyor.");
            return;
        }
        if (jsonBody == null || jsonBody.isEmpty()) {
            logger.warn("SignerNotifier webhook: serialized body boş, gönderim atlandı.");
            return;
        }

        String deliveryId = idGenerator.get();
        long timestampSeconds = unixSecondsClock.getAsLong();

        Request.Builder builder;
        try {
            builder = new Request.Builder()
                    .url(url)
                    .header("User-Agent", resolveSource())
                    .header("Accept", "application/json")
                    .header(HEADER_WEBHOOK_EVENT, eventCode != null ? eventCode : "unknown")
                    .header(HEADER_WEBHOOK_ID, deliveryId)
                    .header(HEADER_WEBHOOK_TIMESTAMP, String.valueOf(timestampSeconds))
                    .post(RequestBody.create(jsonBody, JSON_MEDIA_TYPE));
        } catch (IllegalArgumentException badUrl) {
            logger.warn("SignerNotifier webhook: URL geçersiz, gönderim atlandı: {}",
                    badUrl.getMessage());
            return;
        }

        // Korelasyon header'larını PASS-THROUGH — receiver upstream'e
        // zincirleme bağlandığında aynı x-log-* başlıklarıyla kendi
        // log'larını işaretleyebilsin.
        if (logHeaders != null && !logHeaders.isEmpty()) {
            for (Map.Entry<String, String> e : logHeaders.entrySet()) {
                try {
                    builder.header(e.getKey(), e.getValue());
                } catch (Exception headerEx) {
                    logger.debug("SignerNotifier webhook: log header eklenemedi "
                                    + "(name={}): {}",
                            e.getKey(), headerEx.getMessage());
                }
            }
        }

        if (config.hasWebhookSecret()) {
            // signingString = "<timestamp>.<rawBody>" — Stripe-style.
            String signingString = timestampSeconds + "." + jsonBody;
            String signatureHex = computeHmacSha256Hex(signingString, config.getWebhookSecret());
            if (signatureHex != null) {
                builder.header(HEADER_WEBHOOK_SIGNATURE, "sha256=" + signatureHex);
            }
        }

        Call call = httpClient.newCall(builder.build());
        call.enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                logger.warn("SignerNotifier webhook POST başarısız ({}): {} [delivery-id={}]",
                        url, e.getMessage(), deliveryId);
            }

            @Override
            public void onResponse(Call call, Response response) {
                try {
                    int code = response.code();
                    if (code >= 200 && code < 300) {
                        logger.debug("SignerNotifier webhook POST OK ({} {}) [delivery-id={}]",
                                code, url, deliveryId);
                    } else {
                        logger.warn("SignerNotifier webhook POST non-2xx: "
                                        + "{} {} (receiver={}, delivery-id={})",
                                code, response.message(), url, deliveryId);
                    }
                } catch (Throwable t) {
                    logger.warn("SignerNotifier webhook callback beklenmedik hata: {}",
                            t.toString());
                } finally {
                    try { response.close(); } catch (Exception ignore) { }
                }
            }
        });
    }

    /**
     * Slack incoming webhook gibi <em>auth'u URL gizliliğine</em> dayanan
     * kanallar için sade POST. HMAC eklemek Slack tarafında parse
     * edilemez; receiver doğrulaması zaten URL'in kendisi.
     */
    private void fireSimplePost(String url, String jsonBody, String channelLabel) {
        if (httpClient == null) {
            logger.warn("SignerNotifier {}: HTTP client başlatılmamış "
                    + "(başlangıçta destination yoktu); bildirim atlanıyor.",
                    channelLabel);
            return;
        }
        if (jsonBody == null || jsonBody.isEmpty()) {
            logger.warn("SignerNotifier {}: serialized body boş, gönderim atlandı.",
                    channelLabel);
            return;
        }
        Request request;
        try {
            request = new Request.Builder()
                    .url(url)
                    .header("User-Agent", resolveSource())
                    .header("Accept", "application/json")
                    .post(RequestBody.create(jsonBody, JSON_MEDIA_TYPE))
                    .build();
        } catch (IllegalArgumentException badUrl) {
            logger.warn("SignerNotifier {}: URL geçersiz, gönderim atlandı: {}",
                    channelLabel, badUrl.getMessage());
            return;
        }
        httpClient.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                logger.warn("SignerNotifier {} POST başarısız ({}): {}",
                        channelLabel, url, e.getMessage());
            }

            @Override
            public void onResponse(Call call, Response response) {
                try {
                    int code = response.code();
                    if (code >= 200 && code < 300) {
                        logger.debug("SignerNotifier {} POST OK ({} {})",
                                channelLabel, code, url);
                    } else {
                        logger.warn("SignerNotifier {} POST non-2xx: {} {} (receiver={})",
                                channelLabel, code, response.message(), url);
                    }
                } catch (Throwable t) {
                    logger.warn("SignerNotifier {} callback beklenmedik hata: {}",
                            channelLabel, t.toString());
                } finally {
                    try { response.close(); } catch (Exception ignore) { }
                }
            }
        });
    }

    // =====================================================================
    // Crypto + utility
    // =====================================================================

    /**
     * HMAC-SHA256 hesaplayıp lowercase hex döner. UTF-8 byte'ları kullanılır
     * (endüstri standardı — Stripe/GitHub/Slack hepsi UTF-8). Algoritma
     * platform'da yoksa (pratikte imkânsız) {@code null} döner.
     */
    static String computeHmacSha256Hex(String message, String secret) {
        if (message == null || secret == null || secret.isEmpty()) {
            return null;
        }
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), HMAC_ALGORITHM));
            byte[] raw = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(raw.length * 2);
            for (byte b : raw) {
                hex.append(String.format("%02x", b & 0xff));
            }
            return hex.toString();
        } catch (Exception e) {
            logger.warn("HMAC-SHA256 hesaplanamadı: {}", e.getMessage());
            return null;
        }
    }

    private String serializeOrEmpty(Object obj) {
        try {
            return objectMapper.writeValueAsString(obj);
        } catch (Exception e) {
            logger.warn("SignerNotifier serializasyon hatası ({}): {}",
                    obj.getClass().getSimpleName(), e.getMessage());
            return "";
        }
    }

    private String resolveSource() {
        if (buildProperties != null) {
            String name = buildProperties.getName() != null
                    ? buildProperties.getName() : "mersel-dss-signer-api";
            String version = buildProperties.getVersion() != null
                    ? buildProperties.getVersion() : "unknown";
            return name + "/" + version;
        }
        return "mersel-dss-signer-api/unknown";
    }

    private static String sha256Hex(byte[] bytes) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(bytes);
            StringBuilder sb = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                sb.append(String.format("%02x", b & 0xff));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 her JRE'de zorunlu — pratikte buraya düşmez.
            return null;
        }
    }

    private static String safeFileName(String fileName) {
        if (fileName == null || fileName.trim().isEmpty()) {
            return "<unknown>";
        }
        return fileName;
    }

    private static String safeSignatureType(String type) {
        if (type == null || type.trim().isEmpty()) {
            return "Signature";
        }
        return type;
    }

    private static String safeStr(String s, String fallback) {
        if (s == null || s.trim().isEmpty()) {
            return fallback;
        }
        return s;
    }

    private static String truncate(String s, int max) {
        if (s == null) {
            return "";
        }
        if (s.length() <= max) {
            return s;
        }
        return s.substring(0, max - 1) + "…";
    }

    // =====================================================================
    // Slack Block Kit primitives
    // =====================================================================

    private static Map<String, Object> slackHeader(String text) {
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("type", "header");
        Map<String, Object> t = new LinkedHashMap<>();
        t.put("type", "plain_text");
        t.put("text", truncate(text, 150));
        t.put("emoji", true);
        b.put("text", t);
        return b;
    }

    private static Map<String, Object> slackSectionMarkdown(String text) {
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("type", "section");
        Map<String, Object> t = new LinkedHashMap<>();
        t.put("type", "mrkdwn");
        t.put("text", truncate(text, 2900));
        b.put("text", t);
        return b;
    }

    private static Map<String, Object> slackSectionWithFields(List<Map<String, Object>> fields) {
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("type", "section");
        b.put("fields", fields);
        return b;
    }

    private static Map<String, Object> slackField(String mrkdwn) {
        Map<String, Object> f = new LinkedHashMap<>();
        f.put("type", "mrkdwn");
        f.put("text", truncate(mrkdwn, 2000));
        return f;
    }

    // =====================================================================
    // Test hooks (package-private)
    // =====================================================================

    void setClock(java.util.function.Supplier<Date> clock) {
        if (clock != null) {
            this.clock = clock;
        }
    }

    void setUnixSecondsClock(LongSupplier unixSecondsClock) {
        if (unixSecondsClock != null) {
            this.unixSecondsClock = unixSecondsClock;
        }
    }

    void setIdGenerator(java.util.function.Supplier<String> idGenerator) {
        if (idGenerator != null) {
            this.idGenerator = idGenerator;
        }
    }

    void setHttpClient(OkHttpClient httpClient) {
        if (httpClient != null) {
            this.httpClient = httpClient;
        }
    }

    void setSlackFileUploader(SlackFileUploader slackFileUploader) {
        this.slackFileUploader = slackFileUploader;
    }

    void setConfig(SignerNotificationConfiguration config) {
        this.config = config;
    }
}
