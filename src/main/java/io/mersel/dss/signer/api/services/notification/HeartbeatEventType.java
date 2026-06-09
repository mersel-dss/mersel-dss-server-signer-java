package io.mersel.dss.signer.api.services.notification;

/**
 * HSM heartbeat scheduler tarafından üretilen state transition olayları.
 *
 * <p>Her bir enum sabiti hem JSON webhook payload'una hem Slack mesajına
 * (event etiketi olarak) basılır. {@link #getEventCode()} dönüşü kararlı
 * API kontratıdır — receiver tarafında string eşleştirme yapan kodlar
 * bu değere bağlandığı için <strong>asla yeniden adlandırılmaz</strong>;
 * yeni event tipleri yalnız enum'a eklenir (forward-compatible).</p>
 *
 * <h3>State machine</h3>
 * <pre>
 *   (success)  --(C_Sign fails)-->  FAILED
 *   FAILED     --(eşik aşıldı)-->   REINIT_TRIGGERED
 *   REINIT_TRIGGERED --(success)--> REINIT_SUCCESS
 *   REINIT_TRIGGERED --(fail)----->  REINIT_FAILED
 *   FAILED|REINIT_*  --(C_Sign ok)-> RECOVERED
 * </pre>
 *
 * <p>Event üreticileri: in-process modda
 * {@link io.mersel.dss.signer.api.services.keystore.iaik.HsmHeartbeatScheduler};
 * remote (köprü) modunda
 * {@code io.mersel.dss.signer.api.services.keystore.iaik.bridge.RemoteHsmHeartbeatMonitor}
 * (helper içindeki heartbeat'in durumunu IPC ile gözleyip aynı event tiplerini
 * yayar). Her iki modda da operatör bildirim akışı (Slack/webhook) aynıdır.</p>
 */
public enum HeartbeatEventType {

    /**
     * Heartbeat {@code C_Sign} round-trip'i hata atttı. İlk başarısızlıkta
     * WARN, {@code consecutive >= 5}'te ERROR seviyesinde tetiklenir.
     * Slack/webhook'a her başarısızlıkta gönderilmez — yalnız ilk
     * başarısızlıkta (transitive 0→1) ve eşik aşımında — gürültüyü
     * sınırlamak için.
     */
    FAILED("heartbeat-failed", "HSM heartbeat sign FAILED"),

    /**
     * Önceki ardışık başarısızlık sayacı &gt; 0 iken sign başarılı oldu —
     * yani HSM kendi başına veya reinit sonrası iyileşti. Operatöre
     * pozitif sinyal (alarm temizliği) için tek seferlik bildirim.
     */
    RECOVERED("heartbeat-recovered", "HSM heartbeat RECOVERED"),

    /**
     * Ardışık başarısızlık {@code REINIT_THRESHOLD}'u aştı; scheduler
     * Cryptoki-level {@code C_Finalize + C_Initialize} denemek üzere.
     * Reinit'in sonucu ayrı bir event'le bildirilir.
     */
    REINIT_TRIGGERED("heartbeat-reinit-triggered", "HSM Cryptoki REINIT triggered"),

    /**
     * Cryptoki reinit başarılı; private key handle yenilendi. Sonraki
     * heartbeat tick'i yeni kanal üstünden sign deneyecek (başarılı
     * olursa ayrıca {@link #RECOVERED} bildirilir).
     */
    REINIT_SUCCESS("heartbeat-reinit-success", "HSM Cryptoki REINIT successful"),

    /**
     * Reinit başarısız — backoff penceresine girildi. Operatöre kritik
     * sinyal; HSM dışında elle müdahale (network/firmware/partition)
     * gerekebilir.
     */
    REINIT_FAILED("heartbeat-reinit-failed", "HSM Cryptoki REINIT failed");

    private final String eventCode;
    private final String humanLabel;

    HeartbeatEventType(String eventCode, String humanLabel) {
        this.eventCode = eventCode;
        this.humanLabel = humanLabel;
    }

    /**
     * Webhook payload {@code event} alanına basılan kararlı string
     * (kebab-case). Receiver string eşleştirmesi yapar.
     */
    public String getEventCode() {
        return eventCode;
    }

    /**
     * Slack header'ında ve initial_comment'ta görünecek insan-okunur
     * etiket (operatör chat'te göreceği başlık).
     */
    public String getHumanLabel() {
        return humanLabel;
    }

    /**
     * Pozitif/iyileşme sinyali mi? Slack mesaj renk kararını yönetir
     * (yeşil/iyi-haber vs kırmızı/alarm).
     */
    public boolean isPositiveSignal() {
        return this == RECOVERED || this == REINIT_SUCCESS;
    }
}
