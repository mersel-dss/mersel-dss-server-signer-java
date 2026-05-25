package io.mersel.dss.signer.api.services.signature.xades;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import io.mersel.dss.signer.api.exceptions.TimestampException;
import io.mersel.dss.signer.api.models.enums.XadesSignatureLevel;
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

/**
 * XAdESLevelUpgradeService kontrat testleri.
 *
 * <p>Karar verici sözleşmesi: imza seviyesi yalnızca {@link XadesSignatureLevel}
 * parametresine bağlıdır; documentType (UblDocument, EArchiveReport vb.) bu
 * servisin imzasına dahil değildir ve seviye kararına etki etmez. Parametre
 * <strong>asla null olamaz</strong>; null safety DTO katmanında garanti edilir.</p>
 */
@Epic("Service Layer")
@Feature("XAdES Level Upgrade (request-driven)")
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

    /**
     * level={@link XadesSignatureLevel#XADES_BES} geldiğinde upgrade akışına hiç
     * girilmemeli; {@code timestampService}'e tek bir çağrı bile yapılmamalıdır.
     * Bu, kontör tasarrufu kontratının özüdür.
     */
    @Nested
    class NoUpgrade {

        @Test
        void shouldReturnOriginalDocumentWhenLevelIsXADES_BES() {
            DSSDocument original = createTestDocument();

            DSSDocument result = service.upgradeIfNeeded(
                    original, createTestParameters(), XadesSignatureLevel.XADES_BES);

            assertSame(original, result, "XADES_BES iken orijinal belge dönmeli");
            verifyNoInteractions(timestampService);
        }

        /**
         * Kritik test: TSA host'u <em>hiç</em> yapılandırılmamış olsa bile
         * level=XADES_BES iken fail-fast tetiklenmemeli. Bu, e-Adisyon /
         * e-Döviz rapor akışlarında TSA olmadan rapor üretme senaryosunun
         * iş gerekçesidir.
         */
        @Test
        void shouldNotThrowEvenWhenTimestampServiceMisconfiguredAndLevelIsBes() {
            DSSDocument original = createTestDocument();

            DSSDocument result = service.upgradeIfNeeded(
                    original, createTestParameters(), XadesSignatureLevel.XADES_BES);

            assertSame(original, result);
            verifyNoInteractions(timestampService);
        }
    }

    /**
     * level={@link XadesSignatureLevel#XADES_A} açıkça istendiğinde fail-fast
     * davranışı korunur: TSA yapılandırılmamışsa veya yükseltme hata alırsa
     * {@link TimestampException} bubble eder; XADES_BES fallback üretilmez.
     */
    @Nested
    class XADES_A_UpgradeFailFast {

        @Test
        void shouldThrowTimestampExceptionWhenTimestampServiceUnavailable() {
            when(timestampService.isAvailable()).thenReturn(false);
            DSSDocument original = createTestDocument();
            XAdESSignatureParameters parameters = createTestParameters();

            TimestampException ex = assertThrows(TimestampException.class,
                    () -> service.upgradeIfNeeded(original, parameters, XadesSignatureLevel.XADES_A));

            assertEquals("TIMESTAMP_ERROR", ex.getErrorCode());
            assertTrue(ex.getMessage().contains("XADES_A"),
                    "Hata mesajı istenen profili içermeli ki client neyin başarısız olduğunu bilsin");
            assertTrue(ex.getMessage().contains("TS_SERVER_HOST"),
                    "Hata mesajı yapılandırılması gereken property'yi söylemeli");
            verify(timestampService).isAvailable();
            verify(timestampService, never()).getTspSource();
        }

        @Test
        void shouldBubbleOriginalTimestampExceptionWhenTspSourceFails() {
            when(timestampService.isAvailable()).thenReturn(true);
            when(timestampService.getTspSource())
                    .thenThrow(new TimestampException("TSP unavailable"));
            DSSDocument original = createTestDocument();
            XAdESSignatureParameters parameters = createTestParameters();

            TimestampException ex = assertThrows(TimestampException.class,
                    () -> service.upgradeIfNeeded(original, parameters, XadesSignatureLevel.XADES_A));

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
                    () -> service.upgradeIfNeeded(original, parameters, XadesSignatureLevel.XADES_A));

            assertEquals("TIMESTAMP_ERROR", ex.getErrorCode());
            assertTrue(ex.getMessage().contains("XADES_A"),
                    "Hata mesajı XADES_A bağlamını net etmeli (XADES_BES yarım imza üretilmediği belirtilmeli)");
        }
    }
}
