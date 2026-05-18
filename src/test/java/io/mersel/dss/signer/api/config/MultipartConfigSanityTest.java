package io.mersel.dss.signer.api.config;

import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Severity;
import io.qameta.allure.SeverityLevel;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Multipart upload limit konfigürasyon kontratı.
 *
 * <p>G grubu (HTTP/API kontratı): production'da hortum etkisini önlemek için
 * Spring'in multipart upload limit'i <b>200MB</b>'ye sabitlenmiş olmalı.
 * Bu değerin yanlışlıkla düşürülmesi (DoS yüzeyini büyütür) ya da
 * yükseltilmesi (memory blow-up) bir regression sayılır.</p>
 *
 * <p>Test prod {@code application.properties}'i direkt classpath'ten okur;
 * Spring lifecycle'a (PFX gerektirir) ihtiyaç duymaz, hızlı çalışır.</p>
 */
@Epic("HTTP API Contract")
@Feature("Multipart Limits")
@Severity(SeverityLevel.MINOR)
class MultipartConfigSanityTest {

    private static final String EXPECTED_LIMIT = "200MB";

    /**
     * Spring Boot multipart resolver'ı için izin verilen tek-dosya boyutu.
     * {@code spring.servlet.multipart.max-file-size} property'sinin
     * tam değeri {@code 200MB} olmalı (suffix dahil).
     */
    @Test
    void maxFileSize_isPinnedTo200Mb() throws IOException {
        Properties props = loadApplicationProperties();
        assertEquals(EXPECTED_LIMIT,
            props.getProperty("spring.servlet.multipart.max-file-size"),
            "max-file-size production limit'i 200MB olmalı (G grubu kontratı)");
    }

    /**
     * Aynı şekilde toplam istek (multi-part toplamı) limiti.
     * Tek dosya == toplam istek senaryosunda iki değerin eşit kalması
     * tutarlı bir 413 davranışı sağlar.
     */
    @Test
    void maxRequestSize_isPinnedTo200Mb() throws IOException {
        Properties props = loadApplicationProperties();
        assertEquals(EXPECTED_LIMIT,
            props.getProperty("spring.servlet.multipart.max-request-size"),
            "max-request-size production limit'i 200MB olmalı (G grubu kontratı)");
    }

    /**
     * Multipart resolver'ı kapatmak prod davranışını sessizce bozar
     * (controller'lar {@code @ModelAttribute} multipart'a sarılı DTO'lar
     * bekliyor). Property'nin {@code true} kalması zorunlu.
     */
    @Test
    void multipartResolver_isEnabled() throws IOException {
        Properties props = loadApplicationProperties();
        assertEquals("true",
            props.getProperty("spring.servlet.multipart.enabled"),
            "multipart resolver kapanırsa tüm /v1/*sign endpoint'leri bozulur");
    }

    private Properties loadApplicationProperties() throws IOException {
        Properties props = new Properties();
        try (InputStream in = getClass().getClassLoader()
                .getResourceAsStream("application.properties")) {
            assertNotNull(in, "application.properties classpath'te bulunamadı");
            props.load(in);
        }
        return props;
    }
}
