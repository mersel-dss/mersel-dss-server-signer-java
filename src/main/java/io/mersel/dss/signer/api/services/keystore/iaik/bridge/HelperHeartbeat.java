package io.mersel.dss.signer.api.services.keystore.iaik.bridge;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import io.mersel.dss.signer.api.services.keystore.iaik.IaikPkcs11Module;
import io.mersel.dss.signer.api.services.keystore.iaik.Pkcs11Signer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Remote modda heartbeat'in çalıştığı yer: <b>helper process'in içi</b> — yani
 * DLL'e ve secure-messaging kanalına bitişik. Ana process tarafındaki
 * {@code HsmHeartbeatScheduler} yalnızca in-process modda devrededir; remote
 * modda kanalı sıcak tutmak ve Cryptoki reinit'i tetiklemek DLL'i tutan tarafın
 * görevidir (native handle ve {@code C_Finalize/C_Initialize} bu process'e ait).
 *
 * <p>Periyodik gerçek {@code C_Sign}; ardışık {@link #REINIT_THRESHOLD}
 * başarısızlıkta {@link IaikPkcs11Module#reinitializeForSmsRecovery} ile
 * Cryptoki reset + signer re-resolve — in-process scheduler ile <b>aynı
 * exponential backoff</b> çizelgesinde (benign jitter'da gereksiz reinit'i
 * önler). Gerçek müşteri imzalarındaki L2 SMS-recovery zaten
 * {@link IaikPkcs11Module#signOnSession} içinde aktiftir.</p>
 *
 * <p><b>Gözlemlenebilirlik:</b> tuttuğu sayaçlar {@link #currentStatus()} ile
 * dışarı açılır; helper IPC sunucusu bunları {@code OP_HEARTBEAT_STATUS} ile
 * ana process'e raporlar. Ana process'teki {@code RemoteHsmHeartbeatMonitor}
 * bu durumu periyodik sorup geçişlerde Slack/webhook alarmı atar — böylece
 * operatör bildirimleri remote modda da (in-process ile parite) çalışır.</p>
 */
final class HelperHeartbeat {

    private static final Logger LOGGER = LoggerFactory.getLogger(HelperHeartbeat.class);
    private static final byte[] PAYLOAD =
        "mersel-hsm-heartbeat-helper-v1".getBytes(StandardCharsets.US_ASCII);
    private static final int REINIT_THRESHOLD = 3;

    /** In-process {@code HsmHeartbeatScheduler} ile aynı backoff çizelgesi (ms). */
    private static final long[] REINIT_BACKOFF_MS = {
        0L, 60_000L, 300_000L, 900_000L, 1_800_000L
    };

    private final IaikPkcs11Module module;
    private final String alias;
    private final String serial;
    private final int intervalSeconds;

    private volatile Pkcs11Signer signer;
    private volatile SignatureAlgorithm algorithm;
    private ScheduledExecutorService scheduler;

    // Sayaçlar: heartbeat thread'i yazar, IPC server-conn thread'i okur → atomik.
    private final AtomicLong successCount = new AtomicLong();
    private final AtomicLong failureCount = new AtomicLong();
    private final AtomicLong consecutiveFailures = new AtomicLong();
    private final AtomicLong reinitAttempts = new AtomicLong();
    private final AtomicLong reinitSuccesses = new AtomicLong();
    private final AtomicLong reinitFailures = new AtomicLong();
    private volatile long lastSuccessAtMillis = 0L;
    private volatile String lastErrorMessage = null;

    // Yalnız heartbeat thread'i erişir (tick tek thread'de seri) — backoff state.
    private long backoffIndex = 0L;
    private long nextReinitAllowedAtMillis = 0L;

    HelperHeartbeat(IaikPkcs11Module module, String alias, String serial, int intervalSeconds) {
        this.module = module;
        this.alias = alias;
        this.serial = serial;
        this.intervalSeconds = intervalSeconds;
    }

    void start() {
        this.signer = module.findSigner(alias, serial);
        EncryptionAlgorithm enc = EncryptionAlgorithm.forKey(signer.getCertificate().getPublicKey());
        this.algorithm = SignatureAlgorithm.getAlgorithm(enc, DigestAlgorithm.SHA256);
        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "pkcs11-helper-heartbeat");
            t.setDaemon(true);
            return t;
        });
        scheduler.scheduleWithFixedDelay(this::tick, 15, intervalSeconds, TimeUnit.SECONDS);
        LOGGER.info("Helper heartbeat aktif: alias='{}', alg={}, interval={}s, reinitThreshold={}",
            signer.getAlias(), algorithm, intervalSeconds, REINIT_THRESHOLD);
    }

    private void tick() {
        try {
            byte[] sig = signer.sign(PAYLOAD, algorithm);
            long s = successCount.incrementAndGet();
            long prior = consecutiveFailures.getAndSet(0);
            lastSuccessAtMillis = System.currentTimeMillis();
            // Başarılı sign → backoff state sıfır (sonraki çöküşte baştan başlasın).
            backoffIndex = 0L;
            nextReinitAllowedAtMillis = 0L;
            if (prior > 0) {
                LOGGER.info("Helper heartbeat RECOVERED: alias='{}', sigLen={}, "
                    + "öncesindeki ardışık başarısızlık={}, totalSuccess={}.",
                    signer.getAlias(), sig.length, prior, s);
            } else {
                LOGGER.info("Helper heartbeat imzası atıldı: alias='{}', sigLen={}, totalSuccess={}.",
                    signer.getAlias(), sig.length, s);
            }
        } catch (Exception e) {
            long f = failureCount.incrementAndGet();
            long c = consecutiveFailures.incrementAndGet();
            lastErrorMessage = e.getMessage();
            LOGGER.warn("Helper heartbeat başarısız (ardışık={}, totalFail={}): {}",
                c, f, e.getMessage());
            maybeReinit(c);
        }
    }

    private void maybeReinit(long consecutive) {
        if (consecutive < REINIT_THRESHOLD) {
            return;
        }
        long now = System.currentTimeMillis();
        if (now < nextReinitAllowedAtMillis) {
            LOGGER.debug("Helper reinit backoff penceresi aktif: kalan={}ms",
                nextReinitAllowedAtMillis - now);
            return;
        }
        backoffIndex++;
        long backoffMs = REINIT_BACKOFF_MS[(int) Math.min(backoffIndex, REINIT_BACKOFF_MS.length - 1)];
        nextReinitAllowedAtMillis = now + backoffMs;
        long attempt = reinitAttempts.incrementAndGet();

        LOGGER.warn("Helper Cryptoki-level REINIT tetiklendi: alias='{}', ardışıkBaşarısız={}, "
            + "reinitDenemesi={}, sonrakiDenemeIcinBekleme={}s",
            alias, consecutive, attempt, backoffMs / 1000);
        try {
            module.reinitializeForSmsRecovery(alias, serial);
            signer = module.findSigner(alias, serial);
            reinitSuccesses.incrementAndGet();
            LOGGER.info("Helper reinit başarılı: alias='{}'. Sonraki tick yeni kanal üstünden denenecek.",
                alias);
        } catch (Exception reinitEx) {
            reinitFailures.incrementAndGet();
            lastErrorMessage = reinitEx.getMessage();
            LOGGER.error("Helper reinit BAŞARISIZ (deneme={}): alias='{}', hata='{}'. "
                + "Sonraki denemeye {}s sonra izin verilecek.",
                attempt, alias, reinitEx.getMessage(), backoffMs / 1000);
        }
    }

    /** Ana process'in IPC ile sorabilmesi için anlık sayaç snapshot'ı. */
    Status currentStatus() {
        return new Status(true,
            successCount.get(), failureCount.get(), consecutiveFailures.get(),
            reinitAttempts.get(), reinitSuccesses.get(), reinitFailures.get(),
            lastSuccessAtMillis, lastErrorMessage);
    }

    void stop() {
        if (scheduler != null) {
            scheduler.shutdownNow();
        }
    }

    /** Heartbeat sayaçlarının değişmez (immutable) anlık görüntüsü. */
    static final class Status {
        final boolean enabled;
        final long successCount;
        final long failureCount;
        final long consecutiveFailures;
        final long reinitAttempts;
        final long reinitSuccesses;
        final long reinitFailures;
        final long lastSuccessAtMillis;
        final String lastErrorMessage;

        Status(boolean enabled, long successCount, long failureCount, long consecutiveFailures,
               long reinitAttempts, long reinitSuccesses, long reinitFailures,
               long lastSuccessAtMillis, String lastErrorMessage) {
            this.enabled = enabled;
            this.successCount = successCount;
            this.failureCount = failureCount;
            this.consecutiveFailures = consecutiveFailures;
            this.reinitAttempts = reinitAttempts;
            this.reinitSuccesses = reinitSuccesses;
            this.reinitFailures = reinitFailures;
            this.lastSuccessAtMillis = lastSuccessAtMillis;
            this.lastErrorMessage = lastErrorMessage;
        }

        /** Heartbeat helper'da kapalıyken dönen durum. */
        static Status disabled() {
            return new Status(false, 0, 0, 0, 0, 0, 0, 0, null);
        }
    }
}
