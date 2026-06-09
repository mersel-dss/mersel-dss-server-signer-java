package io.mersel.dss.signer.api.services.keystore.iaik.bridge;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.context.annotation.Conditional;
import org.springframework.stereotype.Component;

/**
 * PKCS#11 <b>out-of-process köprüsü</b> için Spring Boot Actuator sağlık
 * göstergesi. Yalnızca remote modda ({@link Pkcs11BridgeConditions.Remote})
 * container'a girer; in-process veya PFX kurulumlarında hiç oluşturulmaz, bu
 * yüzden o dağıtımlardaki {@code /actuator/health} çıktısı değişmez.
 *
 * <p>{@code components.pkcs11Bridge} altında raporlanır. Sağlık kontrolü
 * <b>aktif</b>tir: helper'a hafif bir {@code OP_PING} round-trip'i yapar — yani
 * helper sadece "ayakta" değil, gerçekten <b>yanıt veriyor</b> mu onu doğrular
 * (asılı kalmış/yarı-ölü helper'ı da yakalar). PING native DLL'e dokunmadığı
 * için eşzamanlı imzaları etkilemez.</p>
 *
 * <p>Köprü {@code DOWN} olduğunda genel health {@code DOWN} olur; load
 * balancer / orchestrator bu instance'ı rotasyon dışına alabilir. Helper
 * supervisor restart'ı tamamlayıp PING yeniden başarılı olunca {@code UP}'a
 * döner.</p>
 */
@Component("pkcs11Bridge")
@Conditional(Pkcs11BridgeConditions.Remote.class)
public class Pkcs11BridgeHealthIndicator implements HealthIndicator {

    private static final Logger LOGGER = LoggerFactory.getLogger(Pkcs11BridgeHealthIndicator.class);

    private final RemotePkcs11Module module;

    public Pkcs11BridgeHealthIndicator(RemotePkcs11Module module) {
        this.module = module;
    }

    @Override
    public Health health() {
        Health.Builder builder = new Health.Builder()
            .withDetail("mode", "remote (out-of-process PKCS#11 bridge)")
            .withDetail("helperAlive", module.isHelperAlive())
            .withDetail("helperPort", module.getHelperPort());

        if (!module.isHelperAlive()) {
            return builder.down()
                .withDetail("ipc", "helper-down")
                .withDetail("hint", "Helper process ayakta değil; supervisor yeniden "
                    + "başlatmayı deniyor olabilir.")
                .build();
        }

        try {
            module.ping();
            return builder.up()
                .withDetail("ipc", "ok")
                .withDetail("successfulOperations", module.getSuccessfulOperationCount())
                .build();
        } catch (Exception e) {
            LOGGER.debug("PKCS#11 köprü health probe'u başarısız: {}", e.toString());
            return builder.down(e)
                .withDetail("ipc", "ping-failed")
                .withDetail("hint", "Helper yanıt vermiyor (asılı veya restart'ta). "
                    + "Bir sonraki başarılı probe'da UP'a dönecek.")
                .build();
        }
    }
}
