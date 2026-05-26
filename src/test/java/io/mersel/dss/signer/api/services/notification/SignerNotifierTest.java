package io.mersel.dss.signer.api.services.notification;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mersel.dss.signer.api.config.LogHeadersFilter;
import io.mersel.dss.signer.api.config.SignerNotificationConfiguration;
import io.mersel.dss.signer.api.exceptions.SignatureException;
import okhttp3.OkHttpClient;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link SignerNotifier}'ın signature-failure ve heartbeat dispatch'lerini,
 * x-log-* propagation'ını, HMAC imzasını ve gate'lerini doğrulayan
 * birim testleri.
 *
 * <p>HTTP tarafı için OkHttp {@link MockWebServer} kullanılır — gerçek
 * bir TCP server ayağa kalkar, in-process; SocketException'lara karşı
 * dirençli, deterministik. Async dispatch'lerden sonra
 * {@code takeRequest(timeout)} ile recorded request'i bekleriz.</p>
 */
class SignerNotifierTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private MockWebServer mockServer;
    private SignerNotificationConfiguration config;
    private SignerNotifier notifier;

    @BeforeEach
    void setUp() throws Exception {
        mockServer = new MockWebServer();
        mockServer.start();

        config = new SignerNotificationConfiguration();
        config.setEnabled(true);
        config.setSignatureFailureEnabled(true);
        config.setHeartbeatEnabled(true);
        config.setIncludeContent(true);
        config.setMaxContentSizeBytes(10L * 1024 * 1024);
        config.setConnectTimeoutMs(2000);
        config.setReadTimeoutMs(2000);
        config.setSlackInlineBase64Enabled(false);
        config.setSlackInlineBase64MaxBytes(8192);

        notifier = new SignerNotifier();
        notifier.setConfig(config);
        // Deterministik clock/id — payload assertion'ları kararlı olsun.
        notifier.setClock(() -> new Date(1_700_000_000_000L));
        notifier.setUnixSecondsClock(() -> 1_700_000_000L);
        notifier.setIdGenerator(() -> "00000000-0000-0000-0000-000000000001");
    }

    @AfterEach
    void tearDown() throws Exception {
        try {
            // MDC'yi her testten sonra temizle — bir sonraki test
            // x-log-* leak'i görmesin.
            MDC.clear();
        } finally {
            mockServer.shutdown();
        }
    }

    /**
     * Notifier kurulumunu MockWebServer URL'lerini config'e yazdıktan
     * sonra explicit init eder. Webhook secret null bırakılırsa HMAC
     * header'ı gönderilmez; testler buna göre assert eder.
     */
    private void initNotifier() {
        // initialize() PostConstruct ekvivalenti — testte kendimiz çağırıyoruz.
        // OkHttpClient'ı manuel kurmak yerine notifier'ın kendi init'ine bırak;
        // sonra timeout'ları kısaltmak için yeniden kurar.
        notifier.initialize();
    }

    // =====================================================================
    // Signature-failure dispatch
    // =====================================================================

    @Test
    void signatureFailure_webhookOnly_sendsJsonWithMetadataAndContent() throws Exception {
        config.setWebhookUrl(mockServer.url("/webhook").toString());
        mockServer.enqueue(new MockResponse().setResponseCode(200));
        initNotifier();

        byte[] doc = "hello world".getBytes(StandardCharsets.UTF_8);
        SignatureException ex = new SignatureException("TEST_ERROR", "boom");

        notifier.notifyOnSignatureFailure(
            "/v1/xadessign", "XAdES", ex, doc, "test.xml", "application/xml");

        RecordedRequest req = mockServer.takeRequest(2, TimeUnit.SECONDS);
        assertNotNull(req, "webhook isteği bekleniyordu");
        assertEquals("POST", req.getMethod());
        assertEquals("/webhook", req.getPath());
        assertEquals("signature-failure", req.getHeader("X-Mersel-Event"));
        assertNotNull(req.getHeader("X-Mersel-Webhook-Id"));
        assertNotNull(req.getHeader("X-Mersel-Webhook-Timestamp"));
        // Secret set edilmedi → HMAC signature header'ı GÖNDERİLMEMELİ.
        assertNull(req.getHeader("X-Mersel-Signature"),
            "Secret yokken HMAC header'ı gönderilmemeli");

        JsonNode body = OBJECT_MAPPER.readTree(req.getBody().readUtf8());
        assertEquals("signature-failure", body.path("event").asText());
        assertEquals("/v1/xadessign", body.path("signatureFailure").path("endpoint").asText());
        assertEquals("XAdES", body.path("signatureFailure").path("signatureType").asText());
        assertEquals("TEST_ERROR", body.path("signatureFailure").path("errorCode").asText());
        assertEquals("test.xml", body.path("file").path("name").asText());
        assertEquals("application/xml", body.path("file").path("contentType").asText());
        assertEquals((long) doc.length, body.path("file").path("sizeBytes").asLong());
        assertTrue(body.path("file").has("sha256Hex"),
            "sha256Hex her zaman set'tir");
        assertTrue(body.path("file").has("base64Content"),
            "includeContent=true ve dosya küçükken base64Content set'tir");
    }

    @Test
    void signatureFailure_withWebhookSecret_addsHmacSha256Signature() throws Exception {
        config.setWebhookUrl(mockServer.url("/webhook").toString());
        config.setWebhookSecret("super-secret");
        mockServer.enqueue(new MockResponse().setResponseCode(204));
        initNotifier();

        notifier.notifyOnSignatureFailure(
            "/v1/cadessign", "CAdES",
            new SignatureException("KEYSTORE_INIT_FAIL", "hsm down"),
            null, null, null);

        RecordedRequest req = mockServer.takeRequest(2, TimeUnit.SECONDS);
        assertNotNull(req);
        String sigHeader = req.getHeader("X-Mersel-Signature");
        assertNotNull(sigHeader, "Secret set edilince HMAC header'ı eklenmeli");
        assertTrue(sigHeader.startsWith("sha256="),
            "HMAC header sha256= prefix'iyle başlamalı; gerçek: " + sigHeader);

        // Receiver'ın doğrulayacağı algoritmayı burada da yeniden hesaplayıp eşleştir.
        String tsHeader = req.getHeader("X-Mersel-Webhook-Timestamp");
        assertNotNull(tsHeader);
        String body = req.getBody().readUtf8();
        String signingString = tsHeader + "." + body;
        String expectedHex = SignerNotifier.computeHmacSha256Hex(signingString, "super-secret");
        assertEquals("sha256=" + expectedHex, sigHeader,
            "HMAC değeri Stripe-style signing string ile uyumlu olmalı");
    }

    @Test
    void signatureFailure_includeContentFalse_omitsBase64WithReasonCode() throws Exception {
        config.setWebhookUrl(mockServer.url("/webhook").toString());
        config.setIncludeContent(false);
        mockServer.enqueue(new MockResponse().setResponseCode(200));
        initNotifier();

        byte[] doc = "secret-content".getBytes(StandardCharsets.UTF_8);
        notifier.notifyOnSignatureFailure(
            "/v1/padessign", "PAdES", new RuntimeException("x"),
            doc, "file.pdf", "application/pdf");

        RecordedRequest req = mockServer.takeRequest(2, TimeUnit.SECONDS);
        JsonNode body = OBJECT_MAPPER.readTree(req.getBody().readUtf8());
        assertFalse(body.path("file").has("base64Content"),
            "includeContent=false iken base64Content JSON'a düşmemeli");
        assertEquals("EXCLUDED_BY_CONFIG",
            body.path("file").path("contentOmittedReason").asText());
    }

    @Test
    void signatureFailure_oversizedContent_omitsBase64WithSizeReason() throws Exception {
        config.setWebhookUrl(mockServer.url("/webhook").toString());
        config.setMaxContentSizeBytes(16L); // küçük eşik
        mockServer.enqueue(new MockResponse().setResponseCode(200));
        initNotifier();

        byte[] doc = new byte[64]; // eşiğin üstünde
        notifier.notifyOnSignatureFailure(
            "/v1/cadessign", "CAdES", new RuntimeException("x"),
            doc, "big.bin", "application/octet-stream");

        RecordedRequest req = mockServer.takeRequest(2, TimeUnit.SECONDS);
        JsonNode body = OBJECT_MAPPER.readTree(req.getBody().readUtf8());
        assertFalse(body.path("file").has("base64Content"));
        assertEquals("EXCEEDED_MAX_SIZE",
            body.path("file").path("contentOmittedReason").asText());
        assertEquals(64L, body.path("file").path("sizeBytes").asLong(),
            "Boyut sınırını aşan dosyada bile size + hash bilgisi gönderilmeli");
    }

    @Test
    void signatureFailure_propagatesXLogHeadersToWebhookHeadersAndBody() throws Exception {
        config.setWebhookUrl(mockServer.url("/webhook").toString());
        mockServer.enqueue(new MockResponse().setResponseCode(200));
        initNotifier();

        // LogHeadersFilter'ın yaptığı gibi MDC'ye xlog.* anahtarları koy.
        MDC.put(LogHeadersFilter.MDC_KEY_PREFIX + "x-log-id", "req-123");
        MDC.put(LogHeadersFilter.MDC_KEY_PREFIX + "x-log-tenant", "finsel");

        notifier.notifyOnSignatureFailure(
            "/v1/xadessign", "XAdES", new RuntimeException("kaput"),
            null, "x.xml", "application/xml");

        RecordedRequest req = mockServer.takeRequest(2, TimeUnit.SECONDS);
        // x-log-* header'ları webhook isteğine de PASS-THROUGH eklenmeli.
        assertEquals("req-123", req.getHeader("x-log-id"));
        assertEquals("finsel", req.getHeader("x-log-tenant"));

        // Payload body'sinde logHeaders alanı da set olmalı.
        JsonNode body = OBJECT_MAPPER.readTree(req.getBody().readUtf8());
        assertEquals("req-123", body.path("logHeaders").path("x-log-id").asText());
        assertEquals("finsel", body.path("logHeaders").path("x-log-tenant").asText());
    }

    @Test
    void signatureFailure_disabledFlag_skipsDispatchEntirely() throws Exception {
        config.setWebhookUrl(mockServer.url("/webhook").toString());
        config.setSignatureFailureEnabled(false); // event seviyesinde kapalı
        initNotifier();

        notifier.notifyOnSignatureFailure(
            "/v1/xadessign", "XAdES", new RuntimeException("x"),
            null, null, null);

        // Hiç istek gelmemeli.
        RecordedRequest req = mockServer.takeRequest(500, TimeUnit.MILLISECONDS);
        assertNull(req, "signatureFailureEnabled=false iken dispatch olmamalı");
    }

    @Test
    void signatureFailure_masterDisabled_skipsDispatchEntirely() throws Exception {
        config.setWebhookUrl(mockServer.url("/webhook").toString());
        config.setEnabled(false);
        initNotifier();

        notifier.notifyOnSignatureFailure(
            "/v1/xadessign", "XAdES", new RuntimeException("x"),
            null, null, null);

        RecordedRequest req = mockServer.takeRequest(500, TimeUnit.MILLISECONDS);
        assertNull(req, "Master enabled=false iken hiçbir dispatch olmamalı");
    }

    // =====================================================================
    // Heartbeat dispatch
    // =====================================================================

    @Test
    void heartbeat_failedEvent_postsJsonPayloadWithStatsAndError() throws Exception {
        config.setWebhookUrl(mockServer.url("/webhook").toString());
        mockServer.enqueue(new MockResponse().setResponseCode(200));
        initNotifier();

        Map<String, Long> stats = new LinkedHashMap<>();
        stats.put("successCount", 100L);
        stats.put("failureCount", 1L);
        stats.put("consecutiveFailures", 1L);
        stats.put("reinitAttempts", 0L);
        stats.put("reinitSuccesses", 0L);
        notifier.notifyOnHeartbeatEvent(
            HeartbeatEventType.FAILED, "alias-1", "RSA_SHA256", stats,
            new RuntimeException("CKR_SMS_ERROR"));

        RecordedRequest req = mockServer.takeRequest(2, TimeUnit.SECONDS);
        assertNotNull(req);
        assertEquals("heartbeat-failed", req.getHeader("X-Mersel-Event"));
        JsonNode body = OBJECT_MAPPER.readTree(req.getBody().readUtf8());
        assertEquals("heartbeat-failed", body.path("event").asText());
        assertEquals("FAILED", body.path("heartbeat").path("eventType").asText());
        assertEquals("alias-1", body.path("heartbeat").path("alias").asText());
        assertEquals("RSA_SHA256", body.path("heartbeat").path("signatureAlgorithm").asText());
        assertEquals(100L, body.path("heartbeat").path("successCount").asLong());
        assertEquals(1L, body.path("heartbeat").path("consecutiveFailures").asLong());
        assertEquals("CKR_SMS_ERROR",
            body.path("heartbeat").path("errorMessage").asText());
        assertFalse(body.has("file"),
            "Heartbeat event'inde file alanı OLMAMALI");
        assertFalse(body.has("signatureFailure"),
            "Heartbeat event'inde signatureFailure alanı OLMAMALI");
    }

    @Test
    void heartbeat_recoveredEvent_usesPositiveSignalColorInSlack() {
        // Slack body builder'ı doğrudan çağırıp RECOVERED color = good
        // olduğunu görsel sinyalleme için doğruluyoruz.
        String slackBody = notifier.buildSlackBodyForHeartbeat(
            HeartbeatEventType.RECOVERED, "alias-1", "RSA_SHA256",
            Collections.singletonMap("successCount", 50L), null);

        assertTrue(slackBody.contains(SignerNotifier.SLACK_GOOD_COLOR),
            "RECOVERED rengi yeşil (#2EB67D) olmalı; body: " + slackBody);
        assertFalse(slackBody.contains(SignerNotifier.SLACK_WARNING_COLOR),
            "RECOVERED rengi turuncu (#D97706) OLMAMALI");
    }

    @Test
    void heartbeat_failedEvent_usesWarningColorInSlack() {
        String slackBody = notifier.buildSlackBodyForHeartbeat(
            HeartbeatEventType.FAILED, "alias-1", "RSA_SHA256",
            null, new RuntimeException("boom"));

        assertTrue(slackBody.contains(SignerNotifier.SLACK_WARNING_COLOR),
            "FAILED rengi turuncu/warning olmalı");
    }

    @Test
    void heartbeat_disabledFlag_skipsDispatchButSignatureFailureStillWorks() throws Exception {
        config.setWebhookUrl(mockServer.url("/webhook").toString());
        config.setHeartbeatEnabled(false);
        mockServer.enqueue(new MockResponse().setResponseCode(200));
        initNotifier();

        // Heartbeat: dispatch olmamalı.
        notifier.notifyOnHeartbeatEvent(
            HeartbeatEventType.FAILED, "x", "RSA_SHA256",
            Collections.emptyMap(), new RuntimeException("y"));
        RecordedRequest none = mockServer.takeRequest(500, TimeUnit.MILLISECONDS);
        assertNull(none, "heartbeatEnabled=false iken heartbeat dispatch'i olmamalı");

        // Signature failure: yine de gitmeli (event-seviye bağımsız).
        notifier.notifyOnSignatureFailure(
            "/v1/xadessign", "XAdES", new RuntimeException("err"),
            null, null, null);
        RecordedRequest req = mockServer.takeRequest(2, TimeUnit.SECONDS);
        assertNotNull(req,
            "heartbeatEnabled kapalı iken bile signature-failure dispatch olmalı");
        assertEquals("signature-failure", req.getHeader("X-Mersel-Event"));
    }

    // =====================================================================
    // Slack incoming webhook
    // =====================================================================

    @Test
    void slackIncomingWebhook_receivesBlockKitJson() throws Exception {
        config.setSlackWebhookUrl(mockServer.url("/slack").toString());
        mockServer.enqueue(new MockResponse().setResponseCode(200));
        initNotifier();

        notifier.notifyOnSignatureFailure(
            "/v1/cadessign", "CAdES",
            new SignatureException("INTERNAL", "stack overflow"),
            null, "doc.bin", "application/octet-stream");

        RecordedRequest req = mockServer.takeRequest(2, TimeUnit.SECONDS);
        assertNotNull(req);
        assertEquals("/slack", req.getPath());
        // Slack için HMAC header'ı eklenmez — URL gizliliği yeterli.
        assertNull(req.getHeader("X-Mersel-Signature"));

        String body = req.getBody().readUtf8();
        JsonNode json = OBJECT_MAPPER.readTree(body);
        assertTrue(json.has("text"), "Slack mesajı için top-level 'text' zorunlu");
        assertTrue(json.has("attachments"), "Block Kit + color attachment wrapper kullanılır");
        JsonNode firstAttachment = json.path("attachments").path(0);
        assertEquals(SignerNotifier.SLACK_DANGER_COLOR,
            firstAttachment.path("color").asText(),
            "Signature failure mesajı kırmızı bantlı olmalı");
        assertTrue(firstAttachment.path("blocks").isArray(),
            "Block Kit blocks dizisi attachment içinde");
    }

    // =====================================================================
    // x-log-* MDC capture util
    // =====================================================================

    @Test
    void collectXlogHeadersFromMdc_skipsNonPrefixedAndEmptyValues() {
        MDC.clear();
        MDC.put(LogHeadersFilter.MDC_KEY_PREFIX + "x-log-id", "abc");
        MDC.put(LogHeadersFilter.MDC_KEY_PREFIX + "x-log-empty", "");
        MDC.put("other.key", "ignored");

        Map<String, String> result = notifier.collectXlogHeadersFromMdc();
        assertEquals(1, result.size(),
            "Yalnız non-empty xlog.* entry'leri toplanmalı");
        assertEquals("abc", result.get("x-log-id"));
        assertFalse(result.containsKey("other.key"),
            "Prefix dışı MDC entry'leri ASLA toplanmamalı");
    }

    @Test
    void collectXlogHeadersFromMdc_emptyMdc_returnsEmptyMap() {
        MDC.clear();
        Map<String, String> result = notifier.collectXlogHeadersFromMdc();
        assertNotNull(result);
        assertTrue(result.isEmpty(), "Boş MDC'de boş map dönmeli (NPE yok)");
    }

    // =====================================================================
    // Resilience
    // =====================================================================

    @Test
    void dispatch_serverReturns500_doesNotThrow() throws Exception {
        config.setWebhookUrl(mockServer.url("/webhook").toString());
        mockServer.enqueue(new MockResponse().setResponseCode(500));
        initNotifier();

        // Server 500 dönerse callback'te WARN loglanır — caller'a exception sızmaz.
        notifier.notifyOnSignatureFailure(
            "/v1/xadessign", "XAdES", new RuntimeException("x"),
            null, null, null);

        RecordedRequest req = mockServer.takeRequest(2, TimeUnit.SECONDS);
        assertNotNull(req,
            "İstek server'a gitmiş olmalı; 500 yanıtı callback tarafından tüketildi");
    }

    @Test
    void dispatch_invalidUrl_doesNotThrow() {
        config.setWebhookUrl("not-a-valid-url");
        initNotifier();

        // İllegal URL — Request.Builder.url() IllegalArgumentException atar; notifier
        // bunu yutmalı, çağıran akışı bozmamalı.
        notifier.notifyOnSignatureFailure(
            "/v1/xadessign", "XAdES", new RuntimeException("x"),
            null, null, null);
        // assertion yok — exception fırlamadığı için bu nokta zaten yeşil.
    }

    // =====================================================================
    // Chunk algorithm (base64 round-trip)
    // =====================================================================

    @Test
    void chunkForSlackSection_roundTripsExactly() {
        // Java 8 baseline → String.repeat() yok; StringBuilder ile manuel.
        StringBuilder sb = new StringBuilder(5000);
        for (int i = 0; i < 500; i++) {
            sb.append("abcdefghij");
        }
        String input = sb.toString(); // 5000 char
        java.util.List<String> chunks =
            SignerNotifier.chunkForSlackSection(input, 2700);
        StringBuilder joined = new StringBuilder();
        for (String c : chunks) {
            joined.append(c);
        }
        assertEquals(input, joined.toString(),
            "Round-trip property: join(chunks) == input. Base64 için kritik.");
        assertTrue(chunks.size() >= 2,
            "5000 char / 2700 chunkSize >= 2 chunk üretmeli");
        // Hiçbir chunk chunkSize'ı aşmamalı (Block Kit 3000 char limiti).
        for (String c : chunks) {
            assertTrue(c.length() <= 2700,
                "Hiçbir chunk chunkSize'ı aşmamalı: " + c.length());
        }
    }
}
