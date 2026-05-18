package io.mersel.dss.signer.api.config;

import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Severity;
import io.qameta.allure.SeverityLevel;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Security yapılandırması test'leri.
 * CORS yapılandırmasının düzgün yüklendiğini doğrular.
 */
@SpringBootTest(classes = {
    io.mersel.dss.signer.api.config.SecurityConfiguration.class
})
@TestPropertySource(properties = {
    "cors.allowed-origins=https://example.com,https://test.com",
    "cors.allowed-methods=GET,POST",
    "cors.max-age=7200"
})
@Epic("HTTP API Contract")
@Feature("Security Filters")
@Severity(SeverityLevel.NORMAL)
class SecurityConfigurationTest {

    @Autowired
    private SecurityConfiguration securityConfiguration;

    @Test
    void testSecurityConfigurationLoaded() {
        // Then
        assertNotNull(securityConfiguration);
    }

    @Test
    void testConfigurationIsWebMvcConfigurer() {
        // Then
        assertTrue(securityConfiguration instanceof org.springframework.web.servlet.config.annotation.WebMvcConfigurer);
    }
}

