package io.mersel.dss.signer.api.services.signature.xades;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import io.mersel.dss.signer.api.exceptions.TimestampException;
import io.mersel.dss.signer.api.models.enums.DocumentType;
import io.mersel.dss.signer.api.services.timestamp.TimestampConfigurationService;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Severity;
import io.qameta.allure.SeverityLevel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@Epic("Service Layer")
@Feature("XAdES Level Upgrade (T/LT/LTA)")
@Severity(SeverityLevel.NORMAL)
class XAdESLevelUpgradeServiceTest {

    @Mock
    private CertificateVerifier certificateVerifier;

    @Mock
    private TimestampConfigurationService timestampService;

    private XAdESLevelUpgradeService service;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        service = new XAdESLevelUpgradeService(certificateVerifier, timestampService);
    }

    private DSSDocument createTestDocument() {
        return new InMemoryDocument("<test/>".getBytes(), "test.xml");
    }

    private XAdESSignatureParameters createTestParameters() {
        return new XAdESSignatureParameters();
    }

    @Nested
    class SkipUpgrade {

        @Test
        void shouldSkipUpgradeForUblDocument() {
            DSSDocument original = createTestDocument();

            DSSDocument result = service.upgradeIfNeeded(original, DocumentType.UblDocument, createTestParameters());

            assertSame(original, result);
            verifyNoInteractions(timestampService);
        }

        @Test
        void shouldSkipUpgradeForHrXml() {
            DSSDocument original = createTestDocument();

            DSSDocument result = service.upgradeIfNeeded(original, DocumentType.HrXml, createTestParameters());

            assertSame(original, result);
            verifyNoInteractions(timestampService);
        }

        @Test
        void shouldSkipUpgradeForOtherXmlDocument() {
            DSSDocument original = createTestDocument();

            DSSDocument result = service.upgradeIfNeeded(original, DocumentType.OtherXmlDocument, createTestParameters());

            assertSame(original, result);
            verifyNoInteractions(timestampService);
        }

        @Test
        void shouldSkipUpgradeForNone() {
            DSSDocument original = createTestDocument();

            DSSDocument result = service.upgradeIfNeeded(original, DocumentType.None, createTestParameters());

            assertSame(original, result);
            verifyNoInteractions(timestampService);
        }
    }

    /**
     * EArchiveReport için XAdES-A yükseltmesi GİB tarafına gönderilen raporun
     * uygunluğu için zorunludur. TSP yapılandırılmamışsa veya upgrade hata
     * alırsa servis sessizce XAdES-B döndürmemeli — fail-fast olmalı ki
     * client {@link TimestampException} → HTTP 503 / {@code TIMESTAMP_ERROR}
     * görür ve işlemi tekrar denemeye / config'i düzeltmeye yönlenir.
     */
    @Nested
    class EArchiveReportUpgrade {

        @Test
        void shouldThrowTimestampExceptionWhenTimestampServiceUnavailable() {
            when(timestampService.isAvailable()).thenReturn(false);
            DSSDocument original = createTestDocument();
            XAdESSignatureParameters parameters = createTestParameters();

            TimestampException ex = assertThrows(TimestampException.class,
                    () -> service.upgradeIfNeeded(original, DocumentType.EArchiveReport, parameters));

            assertEquals("TIMESTAMP_ERROR", ex.getErrorCode());
            assertTrue(ex.getMessage().contains("EArchiveReport"),
                    "Hata mesajı belge tipini içermeli ki client hangi rapor için TSP gerektiğini bilsin");
            assertTrue(ex.getMessage().contains("TS_SERVER_HOST"),
                    "Hata mesajı yapılandırılması gereken property'yi söylemeli");
            verify(timestampService).isAvailable();
            verify(timestampService, never()).getTspSource();
        }

        @Test
        void shouldThrowTimestampExceptionWhenUpgradeFails() {
            when(timestampService.isAvailable()).thenReturn(true);
            when(timestampService.getTspSource())
                    .thenThrow(new TimestampException("TSP unavailable"));
            DSSDocument original = createTestDocument();
            XAdESSignatureParameters parameters = createTestParameters();

            TimestampException ex = assertThrows(TimestampException.class,
                    () -> service.upgradeIfNeeded(original, DocumentType.EArchiveReport, parameters));

            assertEquals("TIMESTAMP_ERROR", ex.getErrorCode(),
                    "Orijinal TimestampException sarmalanmadan bubble etmeli ki error envelope korunabilsin");
            verify(timestampService).isAvailable();
            verify(timestampService).getTspSource();
        }

        @Test
        void shouldWrapGenericUpgradeFailureAsTimestampException() {
            when(timestampService.isAvailable()).thenReturn(true);
            when(timestampService.getTspSource())
                    .thenThrow(new RuntimeException("Beklenmedik DSS hatası"));
            DSSDocument original = createTestDocument();
            XAdESSignatureParameters parameters = createTestParameters();

            TimestampException ex = assertThrows(TimestampException.class,
                    () -> service.upgradeIfNeeded(original, DocumentType.EArchiveReport, parameters));

            assertEquals("TIMESTAMP_ERROR", ex.getErrorCode());
            assertTrue(ex.getMessage().contains("EArchiveReport"));
            assertTrue(ex.getMessage().contains("XAdES-A"),
                    "Hata mesajı XAdES-A bağlamını net etmeli (XAdES-B yarım imza üretilmediği belirtilmeli)");
        }
    }

    /**
     * EBiletReport için aynı XAdES-A garantisi: TSP yoksa fail-fast,
     * upgrade fail olursa fail-fast.
     */
    @Nested
    class EBiletReportUpgrade {

        @Test
        void shouldThrowTimestampExceptionWhenTimestampServiceUnavailable() {
            when(timestampService.isAvailable()).thenReturn(false);
            DSSDocument original = createTestDocument();
            XAdESSignatureParameters parameters = createTestParameters();

            TimestampException ex = assertThrows(TimestampException.class,
                    () -> service.upgradeIfNeeded(original, DocumentType.EBiletReport, parameters));

            assertEquals("TIMESTAMP_ERROR", ex.getErrorCode());
            assertTrue(ex.getMessage().contains("EBiletReport"));
            verify(timestampService).isAvailable();
            verify(timestampService, never()).getTspSource();
        }

        @Test
        void shouldThrowTimestampExceptionWhenUpgradeFails() {
            when(timestampService.isAvailable()).thenReturn(true);
            when(timestampService.getTspSource())
                    .thenThrow(new RuntimeException("TSP unreachable"));
            DSSDocument original = createTestDocument();
            XAdESSignatureParameters parameters = createTestParameters();

            TimestampException ex = assertThrows(TimestampException.class,
                    () -> service.upgradeIfNeeded(original, DocumentType.EBiletReport, parameters));

            assertEquals("TIMESTAMP_ERROR", ex.getErrorCode());
            verify(timestampService).isAvailable();
            verify(timestampService).getTspSource();
        }
    }
}
