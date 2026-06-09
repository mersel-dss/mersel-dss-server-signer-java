package io.mersel.dss.signer.api.wiring;

import io.mersel.dss.signer.api.controllers.HashSignatureController;
import io.mersel.dss.signer.api.services.metrics.SignatureMetrics;
import io.mersel.dss.signer.api.services.notification.SignerNotifier;
import io.mersel.dss.signer.api.services.signature.raw.RawHashSignatureService;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Severity;
import io.qameta.allure.SeverityLevel;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.ApplicationContext;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code /v1/hashsign} endpoint'inin Spring context'te <b>doğru wire</b>
 * olduğunu doğrulayan bütünleyici (smoke) test.
 *
 * <h2>Niye gerekli?</h2>
 * <p>Mevcut {@code HashSignatureControllerTest} kontrolör'ü {@code new}
 * ile inşa ediyor — bağımlılık enjeksiyonunun gerçekten çalıştığını
 * doğrulamıyor. Bu test:</p>
 * <ul>
 *   <li>{@link HashSignatureController} bean'i Spring component scan ile
 *       <em>bulunabilir mi</em>?</li>
 *   <li>Controller constructor injection ({@link RawHashSignatureService})
 *       gerçek bir Spring lifecycle altında çözülebiliyor mu?</li>
 *   <li>{@code POST /v1/hashsign} mapping'i {@link RequestMappingHandlerMapping}
 *       tarafından kayıt ediliyor mu?</li>
 * </ul>
 *
 * <h2>Strateji</h2>
 * <p>{@code @WebMvcTest} Spring MVC slice'ı yüklenir; bu
 * {@code RequestMappingHandlerMapping} ve handler resolver gibi web
 * infrastructure bean'lerini otomatik kurar ama keystore/HSM/timestamp
 * gibi domain bean'lerine dokunmaz. Service katmanı {@code @MockBean} ile
 * değiştirilir; bu sayede HSM/PFX gibi production infra'sına bağımlı
 * kalmaz, sadece controller↔service <em>wiring</em>'i ve URL mapping'i
 * test edilir. Controller'ın HTTP davranışı ve service'in iç davranışı
 * zaten {@code HashSignatureControllerTest} ve
 * {@code RawHashSignatureServiceTest}'te kapsamlı test edildi.</p>
 *
 * <h2>Bu test ne yakalar?</h2>
 * <ul>
 *   <li>Yanlışlıkla controller'dan {@code @RestController} silinmesi</li>
 *   <li>Controller paketinin component scan dışına taşınması</li>
 *   <li>Endpoint URL'inin değiştirilmesi (örn. {@code /v1/hashsign} → {@code /api/hashsign})</li>
 *   <li>Constructor injection bağımlılık zincirinin kırılması (örn.
 *       {@link RawHashSignatureService}'in {@code @Service} annotation'ının
 *       kaldırılması veya yanlış alana enjekte edilmesi)</li>
 * </ul>
 */
@WebMvcTest(controllers = HashSignatureController.class,
        excludeAutoConfiguration = {
            org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration.class
        })
@Epic("HTTP API Contract")
@Feature("HashSignatureController Wiring")
@Severity(SeverityLevel.NORMAL)
class HashSignatureWiringTest {

    @Autowired
    private ApplicationContext context;

    @Autowired
    private HashSignatureController controller;

    @MockBean
    private RawHashSignatureService rawHashSignatureService;

    /**
     * SignerNotifier bağımlılığı — controller artık signature-failure
     * bildirimlerini buraya yönlendiriyor. WebMvcTest slice'ı
     * {@code @Service}'leri scan etmez (sadece web layer); bu yüzden
     * notifier bean'ini test için mock olarak sağlıyoruz.
     */
    @MockBean
    private SignerNotifier signerNotifier;

    /**
     * SignatureMetrics bağımlılığı — controller artık imza iş metriklerini
     * (signer_signatures_total / boyut / süre) buraya kaydediyor. WebMvcTest
     * slice'ı {@code @Component}'leri scan etmediğinden mock olarak sağlanır;
     * bu wiring testi endpoint'i çağırmaz (yalnız bean + mapping doğrular).
     */
    @MockBean
    private SignatureMetrics signatureMetrics;

    /**
     * Controller bean'i context'te kayıtlı mı?
     */
    @Test
    void controllerBean_isRegistered() {
        HashSignatureController bean = context.getBean(HashSignatureController.class);
        assertNotNull(bean,
                "HashSignatureController bean'i Spring context'te bulunmalı");
        assertSame(controller, bean,
                "Controller bean'i singleton olmalı (autowired ile aynı instance)");
    }

    /**
     * Controller'ın service field'ı, context'teki @MockBean ile aynı instance
     * olmalı. Constructor injection gerçekten çalışıyor mu kanıtı.
     */
    @Test
    void rawHashSignatureService_isInjectedIntoController() throws Exception {
        java.lang.reflect.Field f = HashSignatureController.class
                .getDeclaredField("rawHashSignatureService");
        f.setAccessible(true);
        Object injected = f.get(controller);

        assertSame(rawHashSignatureService, injected,
                "Controller içindeki service field'ı, @MockBean ile aynı instance olmalı "
                + "(constructor injection bütünlüğü)");
    }

    /**
     * Endpoint URL'inin doğru kayıt edildiğini doğrular. Yanlışlıkla
     * {@code @RequestMapping("/v1/hashsign")} URL'i değiştirilirse bu test
     * derhal fail eder.
     */
    @Test
    void postV1HashSignMapping_isRegistered() {
        RequestMappingHandlerMapping mappings = context
                .getBean(RequestMappingHandlerMapping.class);
        Map<RequestMappingInfo, ?> handlers = mappings.getHandlerMethods();

        boolean foundUrl = false;
        boolean foundPostMethod = false;
        for (RequestMappingInfo info : handlers.keySet()) {
            String s = info.toString();
            if (s.contains("/v1/hashsign")) {
                foundUrl = true;
                if (s.contains("POST")) {
                    foundPostMethod = true;
                }
            }
        }
        assertTrue(foundUrl,
                "/v1/hashsign URL'i RequestMappingHandlerMapping'de bulunmalı; "
                + "kayıtlı mapping'ler: " + handlers.keySet());
        assertTrue(foundPostMethod,
                "/v1/hashsign POST metodu kayıt edilmeli (yanlışlıkla GET/PUT'a "
                + "değiştirilmiş olmamalı)");
    }

    /**
     * Endpoint'in JSON content-type ürettiğini ve aldığını mapping seviyesinde
     * doğrular. {@code consumes}/{@code produces} attribute'larının yanlışlıkla
     * silinmesi e-Defter / GİB istemcilerini kıracaktır.
     */
    @Test
    void postV1HashSignMapping_isJsonOnly() {
        RequestMappingHandlerMapping mappings = context
                .getBean(RequestMappingHandlerMapping.class);
        Map<RequestMappingInfo, ?> handlers = mappings.getHandlerMethods();

        RequestMappingInfo hashSignInfo = handlers.keySet().stream()
                .filter(info -> info.toString().contains("/v1/hashsign"))
                .findFirst()
                .orElseThrow(() -> new AssertionError(
                        "/v1/hashsign mapping bulunamadı: " + handlers.keySet()));

        String repr = hashSignInfo.toString();
        assertTrue(repr.contains("application/json"),
                "Mapping JSON content-type konfigürasyonu içermeli; aktif: " + repr);
    }
}
