package io.mersel.dss.signer.api.services.keystore.iaik.bridge;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.actuate.endpoint.annotation.Endpoint;
import org.springframework.boot.actuate.endpoint.annotation.ReadOperation;
import org.springframework.context.annotation.Conditional;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * PKCS#11 <b>out-of-process köprüsü</b> için salt-okunur teşhis (diagnostic)
 * Actuator endpoint'i: {@code GET /actuator/pkcs11bridge}.
 *
 * <p>{@code /actuator/health} köprünün yalnızca <em>UP/DOWN</em> + temel
 * bilgisini taşır; bu endpoint ek olarak <b>helper heartbeat</b> sayaçlarını
 * (success/failure, ardışık başarısızlık, Cryptoki reinit istatistikleri,
 * son hata mesajı, son başarı zamanı) on-demand görünür kılar. Operatör,
 * Slack/webhook alarmlarını beklemeden köprü + HSM keep-alive sağlığını
 * anlık sorgulayabilir.</p>
 *
 * <p><b>Yalnızca remote modda</b> ({@link Pkcs11BridgeConditions.Remote})
 * container'a girer; in-process / PFX kurulumlarında hiç oluşmaz ve endpoint
 * 404 döner. Salt-okunur ve native DLL'e dokunmaz (probe yalnız hafif
 * {@code OP_PING} + {@code OP_HEARTBEAT_STATUS} IPC'leri yapar), bu yüzden
 * eşzamanlı imzaları etkilemez.</p>
 *
 * <p><b>Maruz bırakma:</b> {@code management.endpoints.web.exposure.include}
 * listesinde {@code pkcs11bridge} bulunmalıdır (bkz. {@code application.properties}).
 * Endpoint diğer actuator uçlarıyla aynı güvenlik/ağ kısıtına tabidir.</p>
 */
@Component
@Endpoint(id = "pkcs11bridge")
@Conditional(Pkcs11BridgeConditions.Remote.class)
public class Pkcs11BridgeEndpoint {

    private static final Logger LOGGER = LoggerFactory.getLogger(Pkcs11BridgeEndpoint.class);

    private final RemotePkcs11Module module;

    public Pkcs11BridgeEndpoint(RemotePkcs11Module module) {
        this.module = module;
    }

    @ReadOperation
    public Map<String, Object> bridge() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("mode", "remote (out-of-process PKCS#11 bridge)");

        boolean helperAlive = module.isHelperAlive();
        out.put("helperAlive", helperAlive);
        out.put("helperPort", module.getHelperPort());
        out.put("successfulOperations", module.getSuccessfulOperationCount());
        out.put("ipcHealthyFlag", module.isIpcHealthy());

        // Aktif IPC probe (helper sadece ayakta değil, yanıt veriyor mu).
        Map<String, Object> ipc = new LinkedHashMap<>();
        if (!helperAlive) {
            ipc.put("status", "helper-down");
            ipc.put("hint", "Helper process ayakta değil; supervisor restart deniyor olabilir.");
        } else {
            try {
                module.ping();
                ipc.put("status", "ok");
            } catch (Exception e) {
                ipc.put("status", "ping-failed");
                ipc.put("error", e.getMessage());
                ipc.put("hint", "Helper yanıt vermiyor (asılı veya restart'ta).");
            }
        }
        out.put("ipcProbe", ipc);

        // Helper içindeki HSM heartbeat sayaçları (keep-alive + reinit).
        out.put("heartbeat", heartbeatDetails(helperAlive));

        return out;
    }

    private Map<String, Object> heartbeatDetails(boolean helperAlive) {
        Map<String, Object> hb = new LinkedHashMap<>();
        if (!helperAlive) {
            hb.put("available", false);
            hb.put("reason", "helper-down");
            return hb;
        }
        try {
            RemotePkcs11Module.HeartbeatStatus st = module.heartbeatStatus();
            hb.put("available", true);
            hb.put("enabled", st.enabled);
            hb.put("successCount", st.successCount);
            hb.put("failureCount", st.failureCount);
            hb.put("consecutiveFailures", st.consecutiveFailures);
            hb.put("reinitAttempts", st.reinitAttempts);
            hb.put("reinitSuccesses", st.reinitSuccesses);
            hb.put("reinitFailures", st.reinitFailures);
            hb.put("lastErrorMessage",
                st.lastErrorMessage == null || st.lastErrorMessage.isEmpty()
                    ? null : st.lastErrorMessage);
            if (st.lastSuccessAtMillis > 0) {
                hb.put("lastSuccessAt", DateTimeFormatter.ISO_INSTANT.format(
                    Instant.ofEpochMilli(st.lastSuccessAtMillis).atZone(ZoneOffset.UTC).toInstant()));
                hb.put("lastSuccessAgeMs",
                    Math.max(0L, System.currentTimeMillis() - st.lastSuccessAtMillis));
            } else {
                hb.put("lastSuccessAt", null);
            }
        } catch (Exception e) {
            LOGGER.debug("Köprü heartbeat durumu okunamadı: {}", e.toString());
            hb.put("available", false);
            hb.put("reason", "status-query-failed");
            hb.put("error", e.getMessage());
        }
        return hb;
    }
}
