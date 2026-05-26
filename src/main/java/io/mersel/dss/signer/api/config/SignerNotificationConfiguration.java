package io.mersel.dss.signer.api.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

/**
 * Signer API üzerinde tetiklenen olaylar için generic webhook + Slack
 * bildirim konfigürasyonu.
 *
 * <h3>Tetiklenen olaylar</h3>
 * <ul>
 *   <li><b>{@code signature-failure}</b> — Herhangi bir imza endpoint'inde
 *       (XAdES, CAdES, PAdES, WS-Security, Hash, Timestamp) çağrı bir
 *       exception ile sonuçlanırsa. İstek thread'inde tetiklendiği için
 *       <code>x-log-*</code> header'ları MDC'den toplanıp payload'a + Slack
 *       mesajına eklenir.</li>
 *   <li><b>{@code heartbeat-*}</b> — HSM heartbeat scheduler'ın state
 *       transition'ları:
 *       <ul>
 *         <li>{@code heartbeat-failed} — heartbeat sign hatası</li>
 *         <li>{@code heartbeat-recovered} — failure sonrası ilk başarı</li>
 *         <li>{@code heartbeat-reinit-triggered} — Cryptoki reinit denendi</li>
 *         <li>{@code heartbeat-reinit-success} — reinit başarılı oldu</li>
 *         <li>{@code heartbeat-reinit-failed} — reinit başarısız oldu</li>
 *       </ul>
 *       Heartbeat scheduler thread'inde tetiklenir; istek bağlamı yoktur,
 *       <code>x-log-*</code> alanı boş gelir.</li>
 * </ul>
 *
 * <h3>Aktivasyon kuralı</h3>
 * <p>Verifier paralelinde: feature default <i>açık</i>tır
 * ({@link #enabled} = {@code true}). Ancak gerçek dispatch yalnızca en az
 * bir destination URL ({@link #webhookUrl} / {@link #slackWebhookUrl} /
 * {@link #slackBotToken}+{@link #slackBotChannel}) set edildiğinde
 * gerçekleşir. Hiçbir destination yoksa OkHttp client bile kurulmaz —
 * heap maliyeti sıfır.</p>
 *
 * <h3>Generic webhook ile Slack farkı</h3>
 * <ul>
 *   <li><b>Generic webhook</b> — operatörün kendi sistemi (alert manager,
 *       SIEM, ticket). JSON body içine
 *       {@link io.mersel.dss.signer.api.services.notification.SignerEventWebhookPayload}
 *       basılır. {@link #includeContent} açıksa imzalanmaya çalışılan
 *       dokümanın base64 içeriği {@link #maxContentSizeBytes} sınırına
 *       kadar eklenir. HMAC için {@link #webhookSecret}.</li>
 *   <li><b>Slack incoming webhook</b> — chat kanalı, Block Kit özet mesajı.
 *       Heartbeat olayları için renk turuncu/kırmızı; signature failure için
 *       kırmızı şerit. {@link #slackInlineBase64Enabled} ile küçük
 *       dosyalar inline base64 olarak da eklenebilir.</li>
 *   <li><b>Slack bot file upload</b> — signature-failure olayları için
 *       imzalanmaya çalışılan dosyayı kanala indirilebilir bir Slack file
 *       objesi olarak yükler. Heartbeat olaylarında dosya yoktur, bu
 *       kanal devreye girmez.</li>
 * </ul>
 *
 * <p><b>İletişim modeli</b>: Tüm dispatch'ler <em>best-effort + async</em>.
 * Bildirim hataları imza akışını ASLA bozmaz; yalnız WARN loglanır.</p>
 *
 * <p><b>Olay seviyesinde kapatma</b>: Operatör yalnız heartbeat alarmı
 * isteyip signature-failure'ı kapatmak (veya tersi) isterse iki bayrağı
 * da kullanabilir: {@link #signatureFailureEnabled},
 * {@link #heartbeatEnabled}.</p>
 *
 * @see io.mersel.dss.signer.api.services.notification.SignerNotifier
 * @see io.mersel.dss.signer.api.services.notification.SignerEventWebhookPayload
 */
@Configuration
public class SignerNotificationConfiguration {

    /**
     * Master switch. Operatör URL'leri set bıraktığı halde geçici olarak
     * bildirimleri susturmak istediğinde {@code false} yapılır. Hem
     * signature-failure hem heartbeat olaylarını topyekun kapatır.
     */
    @Value("${notification.signer.enabled:${SIGNER_NOTIFICATION_ENABLED:true}}")
    private boolean enabled;

    /**
     * Olay seviyesi anahtar — {@code signature-failure} olaylarını gönder.
     * Default {@code true}; operatör sadece heartbeat istiyorsa {@code false}
     * yapar. {@link #enabled} kapalıysa zaten devre dışıdır.
     */
    @Value("${notification.signer.events.signature-failure.enabled:${SIGNER_NOTIFICATION_SIGNATURE_FAILURE_ENABLED:true}}")
    private boolean signatureFailureEnabled;

    /**
     * Olay seviyesi anahtar — {@code heartbeat-*} olaylarını gönder.
     * Default {@code true}; HSM kullanılmıyorsa heartbeat scheduler zaten
     * yüklenmez ve flag etkisizdir.
     */
    @Value("${notification.signer.events.heartbeat.enabled:${SIGNER_NOTIFICATION_HEARTBEAT_ENABLED:true}}")
    private boolean heartbeatEnabled;

    /**
     * Generic webhook URL — operatörün kendi alert/ticket/audit sistemi.
     * Boş ise generic webhook tetiklenmez (Slack hâlâ tetiklenebilir).
     */
    @Value("${notification.signer.webhook.url:${SIGNER_WEBHOOK_URL:}}")
    private String webhookUrl;

    /**
     * Slack incoming webhook URL'i (tipik:
     * {@code https://hooks.slack.com/services/T.../B.../...}).
     * Boş ise Slack mesaj kanalı tetiklenmez.
     */
    @Value("${notification.signer.slack.webhook.url:${SIGNER_SLACK_WEBHOOK_URL:}}")
    private String slackWebhookUrl;

    /**
     * Slack <em>Bot User OAuth Token</em> ({@code xoxb-…}). Set edildiğinde
     * signature-failure olayında imzalanmaya çalışılan dosya, alarm mesajına
     * ek olarak Slack kanalına <strong>indirilebilir bir dosya</strong>
     * olarak yüklenir (3-adımlı yeni Slack files API'si).
     *
     * <p><b>Heartbeat olaylarında etkisizdir</b> — heartbeat'in dosyası yok.</p>
     *
     * <p>Boş veya {@link #slackBotChannel} boşsa dosya upload yapılmaz —
     * yalnız incoming webhook mesajı gider.</p>
     */
    @Value("${notification.signer.slack.bot.token:${SIGNER_SLACK_BOT_TOKEN:}}")
    private String slackBotToken;

    /**
     * Dosyanın yükleneceği Slack kanal ID'si (genelde {@code C…} formatında).
     * Kanal ADI değil ID gereklidir — Slack
     * {@code files.completeUploadExternal} channel-name kabul etmez.
     */
    @Value("${notification.signer.slack.bot.channel:${SIGNER_SLACK_CHANNEL:}}")
    private String slackBotChannel;

    /**
     * Slack-only / tek-URL dağıtım modu için inline base64 master switch'i.
     * Bot upload yolu yerine imzalanmaya çalışılan dosyayı Slack chat
     * mesajının içine base64 kodlu code block olarak gömmek için.
     *
     * <p>Heartbeat olaylarında dosya yoktur; flag yalnız signature-failure
     * için anlamlıdır.</p>
     */
    @Value("${notification.signer.slack.inline-base64-enabled:${SIGNER_SLACK_INLINE_BASE64_ENABLED:false}}")
    private boolean slackInlineBase64Enabled;

    /**
     * Slack inline base64 üst boyut sınırı (byte). Default 8192 (8KB) —
     * Slack mesaj toplam 40KB sınırı + Block Kit 3000-char/section limiti
     * ile uyumlu seçilmiş eşik.
     */
    @Value("${notification.signer.slack.inline-base64-max-bytes:${SIGNER_SLACK_INLINE_BASE64_MAX_BYTES:8192}}")
    private long slackInlineBase64MaxBytes;

    /**
     * Generic webhook HMAC paylaşılan secret'i. Set edilirse her POST'a
     * Stripe-style {@code X-Mersel-Signature: sha256=<hex>} header'ı eklenir.
     */
    @Value("${notification.signer.webhook.secret:${SIGNER_WEBHOOK_SECRET:}}")
    private String webhookSecret;

    /**
     * İmzalanmaya çalışılan dokümanın base64 içeriği signature-failure
     * payload'una dahil edilsin mi? Default açık. Mali mühür / e-Fatura
     * gibi PII taşıyan akışlarda kapatılabilir; o zaman yalnız hash +
     * metadata gider.
     */
    @Value("${notification.signer.include-content:${SIGNER_NOTIFICATION_INCLUDE_CONTENT:true}}")
    private boolean includeContent;

    /**
     * Bayt cinsinden üst sınır. Bu eşikten büyük dokümanlar için
     * {@code base64Content} eklenmez — yalnız hash + metadata gider.
     * Default 10MB.
     */
    @Value("${notification.signer.max-content-size-bytes:${SIGNER_NOTIFICATION_MAX_CONTENT_SIZE_BYTES:10485760}}")
    private long maxContentSizeBytes;

    /**
     * HTTP connect timeout (ms). Default 5s — bildirim asla imza
     * latency'sini yutmamalı.
     */
    @Value("${notification.signer.connect-timeout-ms:${SIGNER_NOTIFICATION_CONNECT_TIMEOUT_MS:5000}}")
    private int connectTimeoutMs;

    /**
     * HTTP read timeout (ms). Default 10s.
     */
    @Value("${notification.signer.read-timeout-ms:${SIGNER_NOTIFICATION_READ_TIMEOUT_MS:10000}}")
    private int readTimeoutMs;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isSignatureFailureEnabled() {
        return signatureFailureEnabled;
    }

    public void setSignatureFailureEnabled(boolean signatureFailureEnabled) {
        this.signatureFailureEnabled = signatureFailureEnabled;
    }

    public boolean isHeartbeatEnabled() {
        return heartbeatEnabled;
    }

    public void setHeartbeatEnabled(boolean heartbeatEnabled) {
        this.heartbeatEnabled = heartbeatEnabled;
    }

    public String getWebhookUrl() {
        return webhookUrl;
    }

    public void setWebhookUrl(String webhookUrl) {
        this.webhookUrl = webhookUrl;
    }

    public String getSlackWebhookUrl() {
        return slackWebhookUrl;
    }

    public void setSlackWebhookUrl(String slackWebhookUrl) {
        this.slackWebhookUrl = slackWebhookUrl;
    }

    public String getSlackBotToken() {
        return slackBotToken;
    }

    public void setSlackBotToken(String slackBotToken) {
        this.slackBotToken = slackBotToken;
    }

    public String getSlackBotChannel() {
        return slackBotChannel;
    }

    public void setSlackBotChannel(String slackBotChannel) {
        this.slackBotChannel = slackBotChannel;
    }

    public boolean isSlackInlineBase64Enabled() {
        return slackInlineBase64Enabled;
    }

    public void setSlackInlineBase64Enabled(boolean slackInlineBase64Enabled) {
        this.slackInlineBase64Enabled = slackInlineBase64Enabled;
    }

    public long getSlackInlineBase64MaxBytes() {
        return slackInlineBase64MaxBytes;
    }

    public void setSlackInlineBase64MaxBytes(long slackInlineBase64MaxBytes) {
        this.slackInlineBase64MaxBytes = slackInlineBase64MaxBytes;
    }

    public String getWebhookSecret() {
        return webhookSecret;
    }

    public void setWebhookSecret(String webhookSecret) {
        this.webhookSecret = webhookSecret;
    }

    public boolean isIncludeContent() {
        return includeContent;
    }

    public void setIncludeContent(boolean includeContent) {
        this.includeContent = includeContent;
    }

    public long getMaxContentSizeBytes() {
        return maxContentSizeBytes;
    }

    public void setMaxContentSizeBytes(long maxContentSizeBytes) {
        this.maxContentSizeBytes = maxContentSizeBytes;
    }

    public int getConnectTimeoutMs() {
        return connectTimeoutMs;
    }

    public void setConnectTimeoutMs(int connectTimeoutMs) {
        this.connectTimeoutMs = connectTimeoutMs;
    }

    public int getReadTimeoutMs() {
        return readTimeoutMs;
    }

    public void setReadTimeoutMs(int readTimeoutMs) {
        this.readTimeoutMs = readTimeoutMs;
    }

    /**
     * En az bir hedef (generic webhook / Slack incoming webhook / Slack bot
     * file upload) set edilmiş mi? Hızlı runtime check — notifier her
     * tetiklemede bu metoda bakarak gereksiz iş yapmamayı seçer.
     */
    public boolean hasAnyDestination() {
        return hasWebhookDestination() || hasSlackDestination() || hasSlackBotUploadDestination();
    }

    public boolean hasWebhookDestination() {
        return isNonBlank(webhookUrl);
    }

    public boolean hasSlackDestination() {
        return isNonBlank(slackWebhookUrl);
    }

    public boolean hasSlackBotUploadDestination() {
        return isNonBlank(slackBotToken) && isNonBlank(slackBotChannel);
    }

    public boolean hasWebhookSecret() {
        return isNonBlank(webhookSecret);
    }

    private static boolean isNonBlank(String s) {
        return s != null && !s.trim().isEmpty();
    }
}
