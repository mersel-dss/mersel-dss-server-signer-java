package io.mersel.dss.signer.api.e2e.verifier;

import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Severity;
import io.qameta.allure.SeverityLevel;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.web.client.RestTemplate;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifier container'ın kendi ayağa kalktığını doğrulayan minimum smoke test.
 *
 * <p>Bu test geçmeden CAdES/PAdES/XAdES E2E testlerini koşmanın anlamı yok;
 * suite'in ilk adımı olarak sınıf adı alfabetik düzende erken çıksın diye
 * "Verifier..." prefix'i ile isimlendirildi (gerçi JUnit 5 tabii ki garanti
 * order vermiyor — yine de hızlı feedback için iyi bir habit).</p>
 */
@Epic("Infrastructure")
@Feature("Verifier API Container")
@Severity(SeverityLevel.BLOCKER)
class VerifierContainerSmokeTest extends AbstractVerifierE2ETest {

    @Test
    @DisplayName("Verifier container ayağa kalkıyor ve /actuator/health UP döner")
    void containerIsHealthy() {
        String baseUrl = VerifierApiContainer.baseUrl();
        assertNotNull(baseUrl, "baseUrl boş olmamalı");
        assertTrue(baseUrl.startsWith("http://"), "baseUrl http:// ile başlamalı: " + baseUrl);

        String health = new RestTemplate()
                .getForObject(baseUrl + "/actuator/health", String.class);
        assertNotNull(health, "/actuator/health yanıtı null olmamalı");
        assertTrue(health.contains("\"UP\""),
                "Beklenen 'UP' status yok, gelen: " + health);
    }
}
