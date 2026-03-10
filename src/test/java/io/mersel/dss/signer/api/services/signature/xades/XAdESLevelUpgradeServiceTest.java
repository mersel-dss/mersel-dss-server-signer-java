package io.mersel.dss.signer.api.services.signature.xades;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import io.mersel.dss.signer.api.models.enums.DocumentType;
import io.mersel.dss.signer.api.services.timestamp.TimestampConfigurationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

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

        @Test
        void shouldNotSkipUpgradeForEBiletReport() {
            when(timestampService.isAvailable()).thenReturn(false);
            DSSDocument original = createTestDocument();

            DSSDocument result = service.upgradeIfNeeded(original, DocumentType.EBiletReport, createTestParameters());

            assertSame(original, result);
            verify(timestampService).isAvailable();
        }
    }

    @Nested
    class EArchiveReportUpgrade {

        @Test
        void shouldReturnOriginalWhenTimestampServiceUnavailable() {
            when(timestampService.isAvailable()).thenReturn(false);
            DSSDocument original = createTestDocument();

            DSSDocument result = service.upgradeIfNeeded(original, DocumentType.EArchiveReport, createTestParameters());

            assertSame(original, result);
            verify(timestampService).isAvailable();
            verify(timestampService, never()).getTspSource();
        }

        @Test
        void shouldCheckTimestampAvailabilityForEArchiveReport() {
            when(timestampService.isAvailable()).thenReturn(true);
            when(timestampService.getTspSource()).thenThrow(new RuntimeException("TSP unavailable"));
            DSSDocument original = createTestDocument();

            DSSDocument result = service.upgradeIfNeeded(original, DocumentType.EArchiveReport, createTestParameters());

            verify(timestampService).isAvailable();
            verify(timestampService).getTspSource();
            assertSame(original, result);
        }
    }

    @Nested
    class EBiletReportUpgrade {

        @Test
        void shouldReturnOriginalWhenTimestampServiceUnavailable() {
            when(timestampService.isAvailable()).thenReturn(false);
            DSSDocument original = createTestDocument();

            DSSDocument result = service.upgradeIfNeeded(original, DocumentType.EBiletReport, createTestParameters());

            assertSame(original, result);
            verify(timestampService).isAvailable();
            verify(timestampService, never()).getTspSource();
        }

        @Test
        void shouldAttemptUpgradeWhenTimestampServiceAvailable() {
            when(timestampService.isAvailable()).thenReturn(true);
            when(timestampService.getTspSource()).thenThrow(new RuntimeException("TSP unavailable"));
            DSSDocument original = createTestDocument();

            DSSDocument result = service.upgradeIfNeeded(original, DocumentType.EBiletReport, createTestParameters());

            verify(timestampService).isAvailable();
            verify(timestampService).getTspSource();
            assertSame(original, result);
        }
    }
}
