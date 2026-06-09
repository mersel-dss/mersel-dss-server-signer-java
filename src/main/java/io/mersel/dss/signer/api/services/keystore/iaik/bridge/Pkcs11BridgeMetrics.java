package io.mersel.dss.signer.api.services.keystore.iaik.bridge;

import io.micrometer.core.instrument.FunctionCounter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Conditional;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.function.ToLongFunction;

/**
 * PKCS#11 <b>out-of-process köprüsü</b> için Micrometer/Prometheus metrikleri.
 * {@code /actuator/prometheus} üzerinden scrape edilir ve Grafana'da panel +
 * alert kurulabilir.
 *
 * <h2>Yayınlanan metrikler</h2>
 * <ul>
 *   <li>{@code pkcs11_bridge_helper_alive} — helper process ayakta mı (1/0)</li>
 *   <li>{@code pkcs11_bridge_ipc_healthy} — son IPC round-trip sağlıklı mıydı (1/0)</li>
 *   <li>{@code pkcs11_bridge_successful_operations_total} — kümülatif başarılı IPC sayısı</li>
 *   <li>{@code pkcs11_bridge_heartbeat_enabled} — helper içi keep-alive açık mı (1/0)</li>
 *   <li>{@code pkcs11_bridge_heartbeat_success} / {@code _failure} — heartbeat sayaçları</li>
 *   <li>{@code pkcs11_bridge_heartbeat_consecutive_failures} — ardışık başarısızlık</li>
 *   <li>{@code pkcs11_bridge_heartbeat_reinit_attempts} / {@code _successes} / {@code _failures}
 *       — Cryptoki reinit istatistikleri</li>
 * </ul>
 *
 * <h2>Tasarım</h2>
 * <p>{@code helperAlive} / {@code ipcHealthy} / {@code successfulOperations}
 * ana process'te yerel alanlardan okunur (IPC yok) → her scrape'te güvenle
 * değerlenir. Heartbeat sayaçları ise helper'dan IPC ile ({@code OP_HEARTBEAT_STATUS})
 * gelir; her scrape'te tekrar IPC atmamak için <b>30 sn'de bir</b> tek bir poll
 * ile önbelleğe alınır ve gauge'lar bu snapshot'tan okur.</p>
 *
 * <p><b>Yalnızca remote modda</b> ({@link Pkcs11BridgeConditions.Remote})
 * oluşur; in-process / PFX kurulumlarında bean yoktur, hiçbir köprü metriği
 * yayınlanmaz ve sıfır ek yük olur. Salt-okuma — native DLL'e veya imza yoluna
 * dokunmaz.</p>
 */
@Component
@Conditional(Pkcs11BridgeConditions.Remote.class)
public class Pkcs11BridgeMetrics {

    private static final Logger LOGGER = LoggerFactory.getLogger(Pkcs11BridgeMetrics.class);

    private static final String COMPONENT_TAG_KEY = "component";
    private static final String COMPONENT_TAG_VAL = "pkcs11-bridge";

    private final RemotePkcs11Module module;

    /** Heartbeat sayaçlarının periyodik tazelenen, scrape'ten bağımsız snapshot'ı. */
    private volatile RemotePkcs11Module.HeartbeatStatus cachedHeartbeat;

    public Pkcs11BridgeMetrics(RemotePkcs11Module module, MeterRegistry registry) {
        this.module = module;
        registerMeters(registry);
        LOGGER.info("PKCS#11 köprü metrikleri kaydedildi (Prometheus): "
            + "helper_alive, ipc_healthy, successful_operations + heartbeat sayaçları.");
    }

    private void registerMeters(MeterRegistry registry) {
        Gauge.builder("pkcs11.bridge.helper.alive", module,
                m -> m.isHelperAlive() ? 1.0 : 0.0)
            .description("PKCS#11 helper process ayakta mı (1=evet, 0=hayır)")
            .tag(COMPONENT_TAG_KEY, COMPONENT_TAG_VAL)
            .register(registry);

        Gauge.builder("pkcs11.bridge.ipc.healthy", module,
                m -> m.isIpcHealthy() ? 1.0 : 0.0)
            .description("Son IPC round-trip sağlıklı mıydı (1=evet, 0=hayır)")
            .tag(COMPONENT_TAG_KEY, COMPONENT_TAG_VAL)
            .register(registry);

        FunctionCounter.builder("pkcs11.bridge.successful.operations", module,
                m -> (double) m.getSuccessfulOperationCount())
            .description("Köprü üzerinden tamamlanan kümülatif başarılı IPC işlemi sayısı")
            .tag(COMPONENT_TAG_KEY, COMPONENT_TAG_VAL)
            .register(registry);

        Gauge.builder("pkcs11.bridge.heartbeat.enabled", this,
                m -> {
                    RemotePkcs11Module.HeartbeatStatus s = m.cachedHeartbeat;
                    return s != null && s.enabled ? 1.0 : 0.0;
                })
            .description("Helper içi HSM heartbeat (keep-alive) açık mı (1=evet, 0=hayır)")
            .tag(COMPONENT_TAG_KEY, COMPONENT_TAG_VAL)
            .register(registry);

        registerHeartbeatGauge(registry, "pkcs11.bridge.heartbeat.success",
            "Heartbeat başarılı keep-alive sayısı (helper restart'ta sıfırlanır)",
            s -> s.successCount);
        registerHeartbeatGauge(registry, "pkcs11.bridge.heartbeat.failure",
            "Heartbeat başarısız keep-alive sayısı (helper restart'ta sıfırlanır)",
            s -> s.failureCount);
        registerHeartbeatGauge(registry, "pkcs11.bridge.heartbeat.consecutive.failures",
            "Ardışık heartbeat başarısızlığı (0 = sağlıklı)",
            s -> s.consecutiveFailures);
        registerHeartbeatGauge(registry, "pkcs11.bridge.heartbeat.reinit.attempts",
            "Cryptoki reinit deneme sayısı (helper restart'ta sıfırlanır)",
            s -> s.reinitAttempts);
        registerHeartbeatGauge(registry, "pkcs11.bridge.heartbeat.reinit.successes",
            "Cryptoki reinit başarı sayısı (helper restart'ta sıfırlanır)",
            s -> s.reinitSuccesses);
        registerHeartbeatGauge(registry, "pkcs11.bridge.heartbeat.reinit.failures",
            "Cryptoki reinit başarısızlık sayısı (helper restart'ta sıfırlanır)",
            s -> s.reinitFailures);
    }

    private void registerHeartbeatGauge(MeterRegistry registry, String name, String description,
                                        ToLongFunction<RemotePkcs11Module.HeartbeatStatus> accessor) {
        Gauge.builder(name, this, m -> {
                RemotePkcs11Module.HeartbeatStatus s = m.cachedHeartbeat;
                return s == null ? 0.0 : (double) accessor.applyAsLong(s);
            })
            .description(description)
            .tag(COMPONENT_TAG_KEY, COMPONENT_TAG_VAL)
            .register(registry);
    }

    /**
     * Heartbeat sayaçlarını helper'dan tek IPC ile periyodik tazeler. Scrape'ten
     * bağımsız çalışır; gauge'lar bu snapshot'tan okur. Helper ayakta değilse
     * önceki snapshot korunur (gauge 0'a değil, son bilinen değere yaslanır;
     * helper_alive gauge'u zaten ayrı sinyal verir).
     */
    @Scheduled(fixedDelayString = "30000", initialDelayString = "15000")
    public void refreshHeartbeat() {
        try {
            if (module.isHelperAlive()) {
                cachedHeartbeat = module.heartbeatStatus();
            }
        } catch (Exception e) {
            LOGGER.debug("Köprü heartbeat metrik tazeleme başarısız (helper restart/asılı olabilir): {}",
                e.toString());
        }
    }
}
