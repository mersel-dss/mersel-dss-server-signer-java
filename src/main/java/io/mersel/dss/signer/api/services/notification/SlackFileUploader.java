package io.mersel.dss.signer.api.services.notification;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.HttpUrl;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Slack'in <strong>yeni 3-adımlı</strong> dosya yükleme API'sini kullanarak
 * imzalanmaya çalışılan dokümanı bot kanal yorumuyla birlikte yükler.
 *
 * <p><b>NEDEN BU SINIF VAR?</b> Slack {@code files.upload} metodu 12 Kasım
 * 2025 itibariyle <em>sunset</em> edildi ve artık tüm uygulamalar için
 * {@code method_deprecated} hatası dönüyor. Yerine zorunlu olan yeni flow:</p>
 *
 * <ol>
 *   <li>{@code POST https://slack.com/api/files.getUploadURLExternal} —
 *       form-encoded ({@code filename}, {@code length}). Authorization:
 *       Bearer xoxb-... → cevapta {@code upload_url} ve {@code file_id}.</li>
 *   <li>{@code POST <upload_url>} — raw octet-stream olarak dosya
 *       byte'larını gönder. Bu istekte token yok (URL kendi içinde
 *       time-bound auth taşır).</li>
 *   <li>{@code POST https://slack.com/api/files.completeUploadExternal} —
 *       JSON body ({@code files:[{id,title}], channel_id, initial_comment}).
 *       Bu çağrı paylaşımı kanala düşürür; çağrılmazsa upload sessizce
 *       kaybolur.</li>
 * </ol>
 *
 * <p><b>Best-effort</b>: Tüm aşamalar async OkHttp callback zinciri olarak
 * çalışır. Bot token yanlış ise step 1 {@code invalid_auth} döner; her
 * aşamada hata olursa WARN log + zinciri kes — imza akışına asla
 * exception sızdırmaz.</p>
 *
 * <p><b>Boyut güvenliği</b>: Çağıran (yani {@link SignerNotifier})
 * {@code maxContentSizeBytes} sınırını uygulamış olur; uploader sadece
 * kendisine verilen byte dizisini yükler. Slack'in resmi single-file upload
 * limiti 1GB; pratikte 50MB üstünde gecikme yaşanabilir.</p>
 */
public class SlackFileUploader {

    private static final Logger logger = LoggerFactory.getLogger(SlackFileUploader.class);

    static final String API_BASE = "https://slack.com/api";
    static final String GET_UPLOAD_URL_PATH = "/files.getUploadURLExternal";
    static final String COMPLETE_UPLOAD_PATH = "/files.completeUploadExternal";

    private static final MediaType OCTET_STREAM = MediaType.get("application/octet-stream");
    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");
    private static final MediaType FORM = MediaType.get(
            "application/x-www-form-urlencoded; charset=utf-8");

    private final OkHttpClient httpClient;
    private final ObjectMapper objectMapper;

    /**
     * Test hook'u — Slack production endpoint'i yerine MockWebServer'a
     * yönlendirilmek için override edilir. Default {@link #API_BASE}.
     */
    private String apiBaseUrl = API_BASE;

    public SlackFileUploader(OkHttpClient httpClient, ObjectMapper objectMapper) {
        this.httpClient = httpClient;
        this.objectMapper = objectMapper;
    }

    /**
     * Dosyayı bot kanalına async yükler. <strong>Best-effort</strong>:
     * herhangi bir aşama başarısız olursa WARN loglanır ama exception
     * fırlatılmaz.
     *
     * @param botToken     {@code xoxb-…} formatında Slack bot token. Boşsa no-op.
     * @param channelId    Hedef kanalın Slack ID'si (örn. {@code C0123456789}). Boşsa no-op.
     * @param fileBytes    Yüklenecek byte içeriği. {@code null} veya boş ise no-op.
     * @param filename     Slack'te görünecek dosya adı.
     * @param title        Dosyaya başlık (Slack mesajının üstünde görünür).
     * @param initialComment Kanal mesajı olarak görünecek özet metni.
     */
    public void uploadAsync(
            String botToken,
            String channelId,
            byte[] fileBytes,
            String filename,
            String title,
            String initialComment) {

        try {
            doUploadAsync(botToken, channelId, fileBytes, filename, title, initialComment);
        } catch (Throwable t) {
            logger.warn("SlackFileUploader: beklenmedik hata, dosya yükleme atlandı: {}",
                    t.toString());
        }
    }

    private void doUploadAsync(
            String botToken,
            String channelId,
            byte[] fileBytes,
            String filename,
            String title,
            String initialComment) {

        if (isBlank(botToken) || isBlank(channelId)) {
            return;
        }
        if (fileBytes == null || fileBytes.length == 0) {
            logger.debug("SlackFileUploader: byte içeriği boş, upload atlandı (filename={})",
                    filename);
            return;
        }

        String safeFilename = (filename == null || filename.isEmpty()) ? "signed-document" : filename;
        String safeTitle = (title == null || title.isEmpty()) ? safeFilename : title;
        String safeComment = (initialComment == null) ? "" : initialComment;

        Request step1;
        try {
            step1 = buildGetUploadUrlRequest(botToken, safeFilename, fileBytes.length);
        } catch (IllegalArgumentException badUrl) {
            logger.warn("SlackFileUploader step1: URL geçersiz, upload atlandı: {}",
                    badUrl.getMessage());
            return;
        }

        httpClient.newCall(step1).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                logger.warn("SlackFileUploader step1 (getUploadURLExternal) HTTP başarısız: {}",
                        e.getMessage());
            }

            @Override
            public void onResponse(Call call, Response response) {
                try {
                    String body = readBody(response);
                    if (!response.isSuccessful()) {
                        logger.warn("SlackFileUploader step1 non-2xx: {} {}",
                                response.code(), abbreviate(body, 200));
                        return;
                    }
                    JsonNode root;
                    try {
                        root = objectMapper.readTree(body);
                    } catch (Exception parseEx) {
                        logger.warn("SlackFileUploader step1: JSON parse hatası: {}; body={}",
                                parseEx.getMessage(), abbreviate(body, 200));
                        return;
                    }
                    if (!root.path("ok").asBoolean(false)) {
                        logger.warn("SlackFileUploader step1 reddedildi: {}",
                                abbreviate(body, 300));
                        return;
                    }
                    String uploadUrl = root.path("upload_url").asText(null);
                    String fileId = root.path("file_id").asText(null);
                    if (uploadUrl == null || fileId == null) {
                        logger.warn("SlackFileUploader step1: upload_url veya file_id eksik: {}",
                                abbreviate(body, 300));
                        return;
                    }
                    uploadBytesStep2(uploadUrl, fileId, fileBytes, safeFilename,
                            botToken, channelId, safeTitle, safeComment);
                } catch (Throwable t) {
                    logger.warn("SlackFileUploader step1 callback beklenmedik hata: {}",
                            t.toString());
                } finally {
                    try { response.close(); } catch (Exception ignore) { }
                }
            }
        });
    }

    private void uploadBytesStep2(
            String uploadUrl,
            String fileId,
            byte[] bytes,
            String filename,
            String botToken,
            String channelId,
            String title,
            String initialComment) {

        Request step2;
        try {
            step2 = new Request.Builder()
                    .url(uploadUrl)
                    .post(RequestBody.create(bytes, OCTET_STREAM))
                    .build();
        } catch (IllegalArgumentException badUrl) {
            logger.warn("SlackFileUploader step2: Slack'ten dönen upload_url geçersiz: {}",
                    badUrl.getMessage());
            return;
        }

        httpClient.newCall(step2).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                logger.warn("SlackFileUploader step2 (binary POST) başarısız: {}", e.getMessage());
            }

            @Override
            public void onResponse(Call call, Response response) {
                try {
                    if (!response.isSuccessful()) {
                        logger.warn("SlackFileUploader step2 non-2xx: {} (fileId={}, filename={})",
                                response.code(), fileId, filename);
                        return;
                    }
                    completeUploadStep3(botToken, channelId, fileId, title, initialComment);
                } catch (Throwable t) {
                    logger.warn("SlackFileUploader step2 callback beklenmedik hata: {}",
                            t.toString());
                } finally {
                    try { response.close(); } catch (Exception ignore) { }
                }
            }
        });
    }

    private void completeUploadStep3(
            String botToken,
            String channelId,
            String fileId,
            String title,
            String initialComment) {

        Map<String, Object> fileEntry = new LinkedHashMap<>();
        fileEntry.put("id", fileId);
        fileEntry.put("title", title);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("files", Collections.singletonList(fileEntry));
        body.put("channel_id", channelId);
        if (initialComment != null && !initialComment.isEmpty()) {
            body.put("initial_comment", initialComment);
        }

        String jsonBody;
        try {
            jsonBody = objectMapper.writeValueAsString(body);
        } catch (Exception e) {
            logger.warn("SlackFileUploader step3 serializasyon hatası: {}", e.getMessage());
            return;
        }

        Request step3;
        try {
            step3 = new Request.Builder()
                    .url(apiBaseUrl + COMPLETE_UPLOAD_PATH)
                    .header("Authorization", "Bearer " + botToken)
                    .header("Accept", "application/json")
                    .post(RequestBody.create(jsonBody, JSON))
                    .build();
        } catch (IllegalArgumentException badUrl) {
            logger.warn("SlackFileUploader step3: URL geçersiz, finalize atlandı: {}",
                    badUrl.getMessage());
            return;
        }

        httpClient.newCall(step3).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                logger.warn("SlackFileUploader step3 (completeUploadExternal) başarısız: {}",
                        e.getMessage());
            }

            @Override
            public void onResponse(Call call, Response response) {
                try {
                    String respBody = readBody(response);
                    if (!response.isSuccessful()) {
                        logger.warn("SlackFileUploader step3 non-2xx: {} {}",
                                response.code(), abbreviate(respBody, 200));
                        return;
                    }
                    JsonNode root;
                    try {
                        root = objectMapper.readTree(respBody);
                    } catch (Exception parseEx) {
                        logger.warn("SlackFileUploader step3: JSON parse hatası: {}; body={}",
                                parseEx.getMessage(), abbreviate(respBody, 200));
                        return;
                    }
                    if (!root.path("ok").asBoolean(false)) {
                        logger.warn("SlackFileUploader step3 reddedildi: {}",
                                abbreviate(respBody, 300));
                        return;
                    }
                    logger.debug("SlackFileUploader: dosya kanala basariyla yuklendi "
                            + "(fileId={}, channel={})", fileId, channelId);
                } catch (Throwable t) {
                    logger.warn("SlackFileUploader step3 callback beklenmedik hata: {}",
                            t.toString());
                } finally {
                    try { response.close(); } catch (Exception ignore) { }
                }
            }
        });
    }

    private Request buildGetUploadUrlRequest(String botToken, String filename, long sizeBytes) {
        // Query encoding'i OkHttp HttpUrl.Builder ile güvenli yapıyoruz —
        // Türkçe karakterli dosya adlarında manuel encoding bug'ları olmasın.
        String form = HttpUrl.parse("https://x/")
                .newBuilder()
                .addQueryParameter("filename", filename)
                .addQueryParameter("length", String.valueOf(sizeBytes))
                .build()
                .encodedQuery();

        return new Request.Builder()
                .url(apiBaseUrl + GET_UPLOAD_URL_PATH)
                .header("Authorization", "Bearer " + botToken)
                .header("Accept", "application/json")
                .post(RequestBody.create(form != null ? form : "", FORM))
                .build();
    }

    /** Test hook — Slack API base URL'sini MockWebServer'a yönlendir. */
    void setApiBaseUrl(String apiBaseUrl) {
        if (apiBaseUrl != null && !apiBaseUrl.isEmpty()) {
            this.apiBaseUrl = apiBaseUrl;
        }
    }

    private static String readBody(Response response) {
        ResponseBody rb = response.body();
        if (rb == null) {
            return "";
        }
        try {
            return rb.string();
        } catch (IOException e) {
            return "";
        }
    }

    private static String abbreviate(String s, int max) {
        if (s == null) {
            return "";
        }
        if (s.length() <= max) {
            return s;
        }
        return s.substring(0, max) + "…";
    }

    private static boolean isBlank(String s) {
        return s == null || s.trim().isEmpty();
    }
}
