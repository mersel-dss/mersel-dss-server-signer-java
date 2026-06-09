package io.mersel.dss.signer.api.services.keystore.iaik.bridge;

import io.mersel.dss.signer.api.services.notification.HeartbeatEventType;
import io.mersel.dss.signer.api.services.notification.SignerNotifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Conditional;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * <b>Remote modun heartbeat gözlemlenebilirlik katmanı.</b> Asıl keep-alive
 * {@code C_Sign} ve Cryptoki reinit, DLL'i tutan helper process'inde
 * ({@link HelperHeartbeat}) çalışır — mimari gereği orada olmak zorunda. Ama
 * operatör bildirimleri (Slack/webhook) ana process'teki {@link SignerNotifier}
 * üzerinden gider. Bu monitör aradaki köprüdür: helper'ın heartbeat sayaçlarını
 * IPC ile ({@code OP_HEARTBEAT_STATUS}) periyodik sorar, <b>durum geçişlerini</b>
 * tespit eder ve in-process {@code HsmHeartbeatScheduler} ile aynı event
 * tiplerini ({@link HeartbeatEventType}) yayar.
 *
 * <p>Böylece in-process ↔ remote arasında operatör-alarm <b>paritesi</b> sağlanır:
 * her iki modda da FAILED / RECOVERED / REINIT_* bildirimleri akar.</p>
 *
 * <h2>Aktivasyon</h2>
 * <ul>
 *   <li>{@code PKCS11_LIBRARY} dolu + {@code HSM_HEARTBEAT_ENABLED=true}</li>
 *   <li>köprü <b>remote</b> modda ({@link Pkcs11BridgeConditions.Remote})</li>
 * </ul>
 *
 * <h2>Polling vs event-driven</h2>
 * <p>In-process scheduler event-driven (tam) iken bu monitör polling tabanlıdır;
 * çok hızlı fail→recover salınımı tek poll aralığında kaçabilir. Alarm kanalı
 * için bu kabul edilebilir (best-effort). Helper restart'ında sayaçlar sıfırlanır;
 * monitör bunu (sayaç düşüşü) algılayıp baseline'ı sessizce sıfırlar — sahte
 * RECOVERED üretmez.</p>
 */
@Component
@ConditionalOnExpression(
    "#{T(org.springframework.util.StringUtils).hasText('${PKCS11_LIBRARY:}')"
    + " && '${HSM_HEARTBEAT_ENABLED:false}' == 'true'}")
@Conditional(Pkcs11BridgeConditions.Remote.class)
public class RemoteHsmHeartbeatMonitor {

    private static final Logger LOGGER = LoggerFactory.getLogger(RemoteHsmHeartbeatMonitor.class);

    /** Ardışık başarısızlık bu eşiği geçtiğinde FAILED bildirimini yükselt. */
    private static final int CONSECUTIVE_FAILURE_ERROR_THRESHOLD = 5;

    private final RemotePkcs11Module module;
    private final SignerNotifier signerNotifier;
    private final String alias;

    // Geçiş tespiti için önceki snapshot (yalnız scheduler thread'i erişir).
    private boolean baselineReady = false;
    private long prevSuccess;
    private long prevFailure;
    private long prevConsecutive;
    private long prevReinitAttempts;
    private long prevReinitSuccesses;
    private long prevReinitFailures;

    public RemoteHsmHeartbeatMonitor(RemotePkcs11Module module,
                                     SignerNotifier signerNotifier,
                                     @Value("${CERTIFICATE_ALIAS:}") String alias) {
        this.module = module;
        this.signerNotifier = signerNotifier;
        this.alias = StringUtils.hasText(alias) ? alias : "(default)";
        LOGGER.info("Remote HSM heartbeat monitörü aktive edildi: helper içi heartbeat IPC ile "
            + "gözlenecek, durum geçişlerinde operatör bildirimi atılacak (in-process ile parite).");
    }

    @Scheduled(
        fixedDelayString = "#{${HSM_HEARTBEAT_INTERVAL_SECONDS:60} * 1000}",
        initialDelayString = "20000")
    public void poll() {
        RemotePkcs11Module.HeartbeatStatus st;
        try {
            st = module.heartbeatStatus();
        } catch (Exception e) {
            LOGGER.warn("Remote heartbeat durumu alınamadı (helper restart/asılı olabilir): {}",
                e.getMessage());
            return;
        }
        if (!st.enabled) {
            return; // helper'da heartbeat kapalı — izlenecek bir şey yok.
        }

        // İlk poll: yalnızca baseline al, geçmiş sayaçları event olarak yayma.
        if (!baselineReady) {
            snapshot(st);
            baselineReady = true;
            return;
        }

        // Helper restart algılama: kümülatif sayaçlar düştüyse process yenilenmiştir.
        if (st.successCount < prevSuccess || st.failureCount < prevFailure
            || st.reinitAttempts < prevReinitAttempts) {
            LOGGER.info("Helper restart algılandı (heartbeat sayaçları sıfırlandı); "
                + "monitör baseline'ı sıfırlanıyor.");
            snapshot(st);
            return;
        }

        // FAILED: ardışık başarısızlık arttı; ilk hata (0→1) veya ERROR eşiği aşımı.
        if (st.consecutiveFailures > prevConsecutive
            && (prevConsecutive == 0
                || (prevConsecutive < CONSECUTIVE_FAILURE_ERROR_THRESHOLD
                    && st.consecutiveFailures >= CONSECUTIVE_FAILURE_ERROR_THRESHOLD))) {
            LOGGER.warn("Remote HSM heartbeat başarısız: alias='{}', ardışık={}, son hata='{}'.",
                alias, st.consecutiveFailures, st.lastErrorMessage);
            notify(HeartbeatEventType.FAILED, st, st.lastErrorMessage);
        }

        // RECOVERED: ardışık başarısızlık >0 iken 0'a döndü.
        if (prevConsecutive > 0 && st.consecutiveFailures == 0 && st.successCount > prevSuccess) {
            LOGGER.info("Remote HSM heartbeat RECOVERED: alias='{}', totalSuccess={}.",
                alias, st.successCount);
            notify(HeartbeatEventType.RECOVERED, st, null);
        }

        // REINIT geçişleri.
        if (st.reinitAttempts > prevReinitAttempts) {
            LOGGER.warn("Remote HSM Cryptoki REINIT tetiklendi (helper): alias='{}', toplamDeneme={}.",
                alias, st.reinitAttempts);
            notify(HeartbeatEventType.REINIT_TRIGGERED, st, null);
        }
        if (st.reinitSuccesses > prevReinitSuccesses) {
            LOGGER.info("Remote HSM Cryptoki REINIT başarılı (helper): alias='{}'.", alias);
            notify(HeartbeatEventType.REINIT_SUCCESS, st, null);
        }
        if (st.reinitFailures > prevReinitFailures) {
            LOGGER.error("Remote HSM Cryptoki REINIT BAŞARISIZ (helper): alias='{}', son hata='{}'. "
                + "Elle müdahale gerekebilir (network/firmware/partition).",
                alias, st.lastErrorMessage);
            notify(HeartbeatEventType.REINIT_FAILED, st, st.lastErrorMessage);
        }

        snapshot(st);
    }

    private void snapshot(RemotePkcs11Module.HeartbeatStatus st) {
        prevSuccess = st.successCount;
        prevFailure = st.failureCount;
        prevConsecutive = st.consecutiveFailures;
        prevReinitAttempts = st.reinitAttempts;
        prevReinitSuccesses = st.reinitSuccesses;
        prevReinitFailures = st.reinitFailures;
    }

    private void notify(HeartbeatEventType eventType,
                        RemotePkcs11Module.HeartbeatStatus st,
                        String errorMessage) {
        if (signerNotifier == null) {
            return;
        }
        Map<String, Long> stats = new LinkedHashMap<>();
        stats.put("successCount", st.successCount);
        stats.put("failureCount", st.failureCount);
        stats.put("consecutiveFailures", st.consecutiveFailures);
        stats.put("reinitAttempts", st.reinitAttempts);
        stats.put("reinitSuccesses", st.reinitSuccesses);
        // Hata mesajını alarm taşısın diye sentetik exception'a sarıyoruz
        // (notifier imzası Throwable bekliyor; remote tarafta gerçek stack yok).
        Throwable error = errorMessage != null ? new RuntimeException(errorMessage) : null;
        try {
            signerNotifier.notifyOnHeartbeatEvent(eventType, alias, null, stats, error);
        } catch (Throwable t) {
            LOGGER.warn("Remote heartbeat bildirim çağrısı beklenmedik hata "
                + "(monitör etkilenmedi): {}", t.toString());
        }
    }
}
