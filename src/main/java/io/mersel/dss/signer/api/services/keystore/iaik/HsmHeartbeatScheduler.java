package io.mersel.dss.signer.api.services.keystore.iaik;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import io.mersel.dss.signer.api.models.SigningMaterial;
import io.mersel.dss.signer.api.services.notification.HeartbeatEventType;
import io.mersel.dss.signer.api.services.notification.SignerNotifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/**
 * SafeNet / Thales HSM ailesinde gözlenen idle-time secure messaging
 * teardown davranışını önleyen periyodik gerçek-imza heartbeat'i +
 * Cryptoki-level <b>self-healing</b> kontrolörü.
 *
 * <h2>Neden var?</h2>
 * <p>SafeNet Luna / ProtectServer / Thales PTK-C HSM ailesinde client
 * ile HSM arasındaki secure messaging session-key'leri belirli bir
 * idle süresinden sonra HSM tarafında reap edilir veya network/TLS
 * tarafından düşürülür. İlk müşteri imza isteği bu sırada gelirse
 * vendor hata kodlarını alırsınız:</p>
 * <ul>
 *   <li>{@code CKR_NO_SESSION_KEYS = 0x80000387} — Luna NTLS idle teardown</li>
 *   <li>{@code CKR_SMS_ERROR = 0x80000384} — PTK-C Secure Messaging System
 *       genel çöküşü (HSM veya network kaynaklı; üretimde gözlendi)</li>
 * </ul>
 *
 * <h2>İki katmanlı koruma</h2>
 * <ol>
 *   <li><b>Heartbeat (L1, bu sınıf)</b>: periyodik gerçek {@code C_Sign}
 *       round-trip'i secure messaging katmanını sıcak tutar. Başarısız
 *       olursa exponential backoff ile Cryptoki-level reinit tetikler.</li>
 *   <li><b>Caller-path recovery (L2,
 *       {@link IaikPkcs11Module#signOnSession(IaikPkcs11Module.ResolvedKey,
 *       byte[], SignatureAlgorithm)})</b>: müşteri sign isteği SMS-aile
 *       hata alırsa, tek-shot Cryptoki reset + retry yapar. Heartbeat
 *       geç kalsa bile müşteri kısa pencerede recovered olur.</li>
 * </ol>
 *
 * <h2>Aktivasyon koşulu</h2>
 * <ol>
 *   <li>{@code PKCS11_LIBRARY} dolu — yani HSM yolu kullanılıyor</li>
 *   <li>{@code HSM_HEARTBEAT_ENABLED=true} — operatör explicit olarak açtı</li>
 * </ol>
 *
 * <h2>Self-healing state machine (Mayıs 2026 incident öğrenimleri)</h2>
 * <p>Üretimde gözlenen vaka: 22 May 14:41 boot → 71 başarılı heartbeat
 * → 15:53'te bir {@code C_Sign} ~99 dk asılı kaldı → secure channel
 * çöktü → <b>3297x ardışık başarısız heartbeat</b>, hiç self-recovery
 * yok, müşteri ilk isteği {@code CKR_SMS_ERROR} alıyordu. Sebep:
 * xipki wrapper'ın token-level recovery'si ({@code C_GetSessionInfo}
 * + relogin) PTK-C tarafında secure messaging katmanı komple ölünce
 * çalışmaz — login bile secure channel üzerinden gider.</p>
 *
 * <p><b>Çözüm</b>: ardışık başarısızlık eşiği ({@link #REINIT_THRESHOLD})
 * aşıldığında {@link IaikPkcs11Module#reinitializeForSmsRecovery} ile
 * Cryptoki global state'ini {@code C_Finalize + C_Initialize} ile
 * sıfırdan kurmak. Reinit başarısızsa exponential backoff:</p>
 *
 * <table border="1" summary="Reinit backoff schedule">
 *   <tr><th>Deneme #</th><th>Bekleme</th></tr>
 *   <tr><td>1 (eşik aşılınca)</td><td>hemen</td></tr>
 *   <tr><td>2</td><td>60 s</td></tr>
 *   <tr><td>3</td><td>300 s (5 dk)</td></tr>
 *   <tr><td>4</td><td>900 s (15 dk)</td></tr>
 *   <tr><td>≥ 5</td><td>1800 s (30 dk) cap</td></tr>
 * </table>
 *
 * <p>Backoff penceresinde heartbeat normal şekilde tetiklenir (sign
 * dener — HSM dış müdahaleyle iyileşirse hemen fark ederiz) ama yeniden
 * reinit denemez. Başarılı sign sonrası tüm state sıfır + RECOVERED log.</p>
 *
 * <h2>Concurrency</h2>
 * <p>{@code @Scheduled} fixedDelay kullanır: önceki heartbeat tamamlanmadan
 * yeni iteration başlamaz. Heartbeat üst seviye {@code signatureSemaphore}
 * permit tüketmez. Reinit'in {@link IaikPkcs11Module} tarafındaki
 * {@code reinitLock} üstünde sign çağrılarıyla yarış senaryosu için
 * bkz. {@link IaikPkcs11Module#reinitializeForSmsRecovery}.</p>
 */
@Component
@ConditionalOnExpression(
    "#{T(org.springframework.util.StringUtils).hasText('${PKCS11_LIBRARY:}')"
    + " && '${HSM_HEARTBEAT_ENABLED:false}' == 'true'}")
public class HsmHeartbeatScheduler {

    private static final Logger LOGGER = LoggerFactory.getLogger(HsmHeartbeatScheduler.class);

    /**
     * Üst üste başarısız heartbeat sayısı bu eşiği geçtiğinde ERROR
     * seviyesine yükseltilir (alerting hook).
     */
    private static final int CONSECUTIVE_FAILURE_ERROR_THRESHOLD = 5;

    /**
     * Üst üste başarısız heartbeat sayısı bu eşiği geçtiğinde Cryptoki-level
     * reinit tetiklenir. 3 dakika (3 × 60s interval default) pencere —
     * transient glitch ile kalıcı çöküşü ayırt etmeye yeter; çok küçük
     * olursa benign network jitter'ında gereksiz reinit yapar.
     */
    private static final int REINIT_THRESHOLD = 3;

    /** Reinit exponential backoff schedule (ms). Index = reinitAttempts (1-based). */
    private static final long[] REINIT_BACKOFF_MS = {
        0L,            // attempts=1: hemen
        60_000L,       // attempts=2: +60 s
        300_000L,      // attempts=3: +5 dk
        900_000L,      // attempts=4: +15 dk
        1_800_000L     // attempts≥5: +30 dk cap
    };

    private final IaikPkcs11Module module;
    private final IaikPkcs11Signer signer;
    private final IaikPkcs11Module.ResolvedKey resolvedKey;
    private final SignatureAlgorithm signatureAlgorithm;
    private final String alias;
    /**
     * State transition'larda Slack/webhook bildirimi atan servis. Feature
     * flag kapalıysa veya destination yoksa no-op. Heartbeat thread'inde
     * MDC olmadığı için {@code x-log-*} alanı boş gider — bu tasarım gereği.
     */
    private final SignerNotifier signerNotifier;

    private final AtomicLong successCount = new AtomicLong();
    private final AtomicLong failureCount = new AtomicLong();
    private final AtomicLong consecutiveFailures = new AtomicLong();
    private final AtomicLong reinitAttempts = new AtomicLong();
    private final AtomicLong reinitSuccesses = new AtomicLong();
    /** {@code System.currentTimeMillis()} biçiminde — bu zamandan önce yeni reinit denemesi yapılmaz. */
    private final AtomicLong nextReinitAllowedAtMillis = new AtomicLong(0L);
    private volatile long lastSuccessAtMillis = 0L;

    public HsmHeartbeatScheduler(IaikPkcs11Module module,
                                 SigningMaterial signingMaterial,
                                 SignerNotifier signerNotifier,
                                 @Value("${HSM_HEARTBEAT_INTERVAL_SECONDS:60}")
                                 int intervalSeconds) {
        this.module = module;
        this.signerNotifier = signerNotifier;
        if (!signingMaterial.isPkcs11()) {
            // Defensive: @ConditionalOnExpression PKCS11_LIBRARY varlığına
            // bakar ama signingMaterial nihai backend kararını verir. PFX'e
            // düşmüşsek (örn. PKCS11 init başarısız ve fallback yoksa) bu
            // scheduler hiç çalışmamalı — bu durum konfigürasyon hatasıdır.
            throw new IllegalStateException(
                "HsmHeartbeatScheduler aktive edildi ama SigningMaterial PKCS#11 değil; "
                + "konfigürasyon tutarsız. HSM_HEARTBEAT_ENABLED yalnızca PKCS#11 yolu "
                + "etkin olduğunda aktive edilmelidir.");
        }
        Pkcs11Signer rawSigner = signingMaterial.getPkcs11Signer();
        if (!(rawSigner instanceof IaikPkcs11Signer)) {
            // ipkcs11wrapper dışında bir signer implementasyonu pratik
            // olarak yok (Pkcs11Signer tek implementasyonu IaikPkcs11Signer);
            // ileride değişirse explicit hata mesajı görsün.
            throw new IllegalStateException(
                "Beklenmeyen Pkcs11Signer implementasyonu: "
                + rawSigner.getClass().getName() + ". HsmHeartbeatScheduler yalnızca "
                + "IaikPkcs11Signer ile uyumludur.");
        }
        this.signer = (IaikPkcs11Signer) rawSigner;
        this.resolvedKey = signer.getResolvedKey();
        this.alias = rawSigner.getAlias();
        this.signatureAlgorithm = deriveAlgorithm(rawSigner);
        LOGGER.info("HSM heartbeat scheduler aktive edildi: alias='{}', alg={}, "
            + "intervalSeconds={}, reinitThreshold={} (Cryptoki-level self-healing aktif)",
            alias, signatureAlgorithm, intervalSeconds, REINIT_THRESHOLD);
    }

    /**
     * Sertifikanın public key tipinden + SHA-256 digest'inden DSS
     * {@link SignatureAlgorithm} türetir. RSA ve ECDSA'nın her ikisi de
     * tüm modern HSM'lerde universal destekli — heartbeat için ek mekanizma
     * uyumluluk problemi yaratmaz.
     */
    private static SignatureAlgorithm deriveAlgorithm(Pkcs11Signer signer) {
        EncryptionAlgorithm enc = EncryptionAlgorithm.forKey(signer.getCertificate().getPublicKey());
        SignatureAlgorithm sa = SignatureAlgorithm.getAlgorithm(enc, DigestAlgorithm.SHA256);
        if (sa == null) {
            throw new IllegalStateException(
                "Heartbeat için SignatureAlgorithm türetilemedi: enc=" + enc
                + ". HSM sertifikasının public key tipi desteklenmiyor olabilir.");
        }
        return sa;
    }

    /**
     * Periyodik heartbeat tetikleyici.
     *
     * <p>{@code fixedDelayString} ile saniye → ms dönüşümü yapılır;
     * {@code initialDelayString} startup race'i önler (token init/login
     * tamamlanmadan heartbeat tetiklenirse {@code CKR_USER_NOT_LOGGED_IN}
     * gibi gürültülü hatalar üretir).</p>
     */
    @Scheduled(
        fixedDelayString = "#{${HSM_HEARTBEAT_INTERVAL_SECONDS:60} * 1000}",
        initialDelayString = "15000")
    public void heartbeat() {
        long t0 = System.currentTimeMillis();
        try {
            // Handle her tick'te resolvedKey'den fresh okunur — reinit
            // sonrası (L1 veya L2) in-place refresh'lenmiş volatile değer.
            int sigLen = module.heartbeatSign(resolvedKey.privateKeyHandle, signatureAlgorithm);
            long elapsed = System.currentTimeMillis() - t0;
            long s = successCount.incrementAndGet();
            long priorConsecutiveFailures = consecutiveFailures.getAndSet(0);
            lastSuccessAtMillis = System.currentTimeMillis();
            // Başarılı sign sonrası reinit state'ini de sıfırla — bir
            // sonraki çöküşte tekrar baştan exponential başlasın.
            long priorReinitAttempts = reinitAttempts.getAndSet(0);
            nextReinitAllowedAtMillis.set(0L);
            if (priorConsecutiveFailures > 0) {
                // Failure -> success state change: operatör için kritik bir
                // sinyaller (HSM secure channel kendini iyileştirdi).
                LOGGER.info("HSM heartbeat imzası RECOVERED: alias='{}', alg={}, "
                    + "sigLen={}, elapsed={}ms, öncesindeki ardışık başarısızlık={}, "
                    + "reinitDenemesi={}, totalSuccess={}, totalFail={}, totalReinit={}",
                    alias, signatureAlgorithm, sigLen, elapsed,
                    priorConsecutiveFailures, priorReinitAttempts, s, failureCount.get(),
                    reinitSuccesses.get());
                // Alarm temizliği: yalnız transition'da (failure→success)
                // bildirim — her başarılı tick'te göndermek operatörü boğar.
                notifySafely(HeartbeatEventType.RECOVERED, null);
            } else {
                LOGGER.info("HSM heartbeat imzası atıldı: alias='{}', alg={}, "
                    + "sigLen={}, elapsed={}ms, totalSuccess={}",
                    alias, signatureAlgorithm, sigLen, elapsed, s);
            }
        } catch (Exception e) {
            long f = failureCount.incrementAndGet();
            long c = consecutiveFailures.incrementAndGet();
            logHeartbeatFailure(c, f, e);
            // Bildirim gürültü kontrolü: ilk başarısızlıkta (transition 0→1)
            // ve ERROR seviyesine yükselen eşik aşımının ilk seferinde
            // bildir. Aradaki her tick'te göndermek operatörü boğar; eşik
            // sonrası tekrar geçişi RECOVERED event'i kapatır.
            if (c == 1L || c == CONSECUTIVE_FAILURE_ERROR_THRESHOLD) {
                notifySafely(HeartbeatEventType.FAILED, e);
            }
            maybeTriggerReinit(c);
            // ASLA throw etme — Spring scheduler exception fırlatan task'ı
            // pool'dan düşürmez ama log spam'i yaratır.
        }
    }

    /**
     * Notifier'ı best-effort çağırır. Notifier veya bağımlı bir bean
     * patlasa bile scheduler tick'i etkilenmemeli — burada outer try/catch
     * uyguluyoruz (notifier zaten kendi içinde try/catch ile çalışıyor;
     * defense-in-depth için ikinci katman).
     */
    private void notifySafely(HeartbeatEventType eventType, Throwable error) {
        if (signerNotifier == null) {
            return;
        }
        try {
            signerNotifier.notifyOnHeartbeatEvent(
                eventType, alias,
                signatureAlgorithm != null ? signatureAlgorithm.name() : null,
                snapshotStats(), error);
        } catch (Throwable t) {
            LOGGER.warn("Heartbeat notifier çağrısı beklenmedik hata "
                + "(scheduler etkilenmedi): {}", t.toString());
        }
    }

    /**
     * Cumulative sayaçların anlık snapshot'ını döner — notifier'ın payload
     * builder'ı bu Map'i okur. Atomik okumalar ardışık (atomik snapshot
     * gerekmiyor: bildirim audit kanalı, mikro tutarsızlık önemsiz).
     */
    private Map<String, Long> snapshotStats() {
        Map<String, Long> stats = new LinkedHashMap<>();
        stats.put("successCount", successCount.get());
        stats.put("failureCount", failureCount.get());
        stats.put("consecutiveFailures", consecutiveFailures.get());
        stats.put("reinitAttempts", reinitAttempts.get());
        stats.put("reinitSuccesses", reinitSuccesses.get());
        return stats;
    }

    private void logHeartbeatFailure(long consecutive, long total, Exception e) {
        if (consecutive >= CONSECUTIVE_FAILURE_ERROR_THRESHOLD) {
            LOGGER.error("HSM heartbeat ÜST ÜSTE BAŞARISIZ ({}x): alias='{}', alg={}, "
                + "totalFail={}, son hata='{}'. HSM durumu kontrol edilmeli "
                + "(secure channel / partition / firmware).",
                consecutive, alias, signatureAlgorithm, total, e.getMessage());
        } else {
            LOGGER.warn("HSM heartbeat başarısız (denenenecek): alias='{}', alg={}, "
                + "totalFail={}, hata='{}'",
                alias, signatureAlgorithm, total, e.getMessage());
        }
    }

    /**
     * Self-healing tetik kararı. {@link #REINIT_THRESHOLD} aşıldığında VE
     * exponential backoff penceresi dolmuşsa Cryptoki-level reinit dener.
     * Reinit başarılı olursa local handle refresh; başarısız olursa
     * backoff timestamp'i ileri sarılır.
     */
    private void maybeTriggerReinit(long consecutive) {
        if (consecutive < REINIT_THRESHOLD) {
            return;
        }
        long now = System.currentTimeMillis();
        long nextAllowed = nextReinitAllowedAtMillis.get();
        if (now < nextAllowed) {
            LOGGER.debug("Reinit backoff window aktif: alias='{}', kalan={}ms",
                alias, nextAllowed - now);
            return;
        }
        long attempt = reinitAttempts.incrementAndGet();
        long backoffMs = REINIT_BACKOFF_MS[
            (int) Math.min(attempt, REINIT_BACKOFF_MS.length - 1)];
        nextReinitAllowedAtMillis.set(now + backoffMs);

        LOGGER.warn("L1 Cryptoki-level REINIT tetiklendi: alias='{}', consecutiveFail={}, "
            + "reinitDenemesi={}, sonrakiDenemeicinBekleme={}s",
            alias, consecutive, attempt, backoffMs / 1000);
        // Operatöre cryptoki-level müdahale başladığını duyur — bu noktada
        // HSM secure channel'ında ciddi bir problem olduğunu biliyoruz.
        notifySafely(HeartbeatEventType.REINIT_TRIGGERED, null);

        try {
            IaikPkcs11Module.ResolvedKey refreshed =
                module.reinitializeForSmsRecovery(alias, null);
            // In-place refresh — aynı ResolvedKey instance'ını paylaşan
            // signer (müşteri istekleri) ve heartbeat aynı handle'ı görür.
            resolvedKey.privateKeyHandle = refreshed.privateKeyHandle;
            resolvedKey.certificate = refreshed.certificate;
            resolvedKey.certificateChain = refreshed.certificateChain;
            reinitSuccesses.incrementAndGet();
            LOGGER.info("L1 reinit başarılı: alias='{}', yeni handle=0x{}. "
                + "Sonraki heartbeat tick'inde sign yeni kanal üstünden denenecek.",
                alias, Long.toHexString(resolvedKey.privateKeyHandle));
            notifySafely(HeartbeatEventType.REINIT_SUCCESS, null);
        } catch (Exception reinitEx) {
            LOGGER.error("L1 reinit BAŞARISIZ (deneme={}): alias='{}', hata='{}'. "
                + "Sonraki reinit denemesine {}s sonra izin verilecek.",
                attempt, alias, reinitEx.getMessage(), backoffMs / 1000);
            // Reinit başarısızlığı kritik sinyal — operatör elle müdahale
            // gerekebileceğini bilmelidir (firmware/network/partition).
            notifySafely(HeartbeatEventType.REINIT_FAILED, reinitEx);
        }
    }

    // ----------------------------------------------------------------
    // Observability (test + future Micrometer hook)
    // ----------------------------------------------------------------

    public long getSuccessCount() {
        return successCount.get();
    }

    public long getFailureCount() {
        return failureCount.get();
    }

    public long getConsecutiveFailureCount() {
        return consecutiveFailures.get();
    }

    public long getLastSuccessAtMillis() {
        return lastSuccessAtMillis;
    }

    public long getReinitAttempts() {
        return reinitAttempts.get();
    }

    public long getReinitSuccesses() {
        return reinitSuccesses.get();
    }

    public long getNextReinitAllowedAtMillis() {
        return nextReinitAllowedAtMillis.get();
    }
}
