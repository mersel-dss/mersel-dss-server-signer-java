package io.mersel.dss.signer.api.e2e.verifier;

import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.xades.signature.XAdESService;
import io.mersel.dss.signer.api.exceptions.TimestampException;
import io.mersel.dss.signer.api.models.SignResponse;
import io.mersel.dss.signer.api.models.SigningMaterial;
import io.mersel.dss.signer.api.models.enums.DocumentType;
import io.mersel.dss.signer.api.services.crypto.CryptoSignerService;
import io.mersel.dss.signer.api.services.crypto.DigestAlgorithmResolverService;
import io.mersel.dss.signer.api.services.crypto.SignatureAlgorithmResolverService;
import io.mersel.dss.signer.api.services.signature.xades.XAdESDocumentPlacementService;
import io.mersel.dss.signer.api.services.signature.xades.XAdESLevelUpgradeService;
import io.mersel.dss.signer.api.services.signature.xades.XAdESParametersBuilderService;
import io.mersel.dss.signer.api.services.signature.xades.XAdESSignatureService;
import io.mersel.dss.signer.api.services.signature.xades.XmlProcessingService;
import io.mersel.dss.signer.api.services.timestamp.TimestampConfigurationService;
import io.mersel.dss.signer.api.services.util.CompressionService;
import io.mersel.dss.signer.api.testsupport.SignedArtifactExporter;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Severity;
import io.qameta.allure.SeverityLevel;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.Semaphore;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * XAdES için uçtan-uca sign → verify roundtrip testi.
 *
 * <h3>Senaryo matrisi</h3>
 * <p>Üç test method'u:</p>
 *
 * <ol>
 *   <li><b>TSA-bağımsız UBL/HR-XML fixture matrisi</b>:
 *       5 PFX × 2 backend × {@code XadesDocumentFixture} TSA-bağımsız değerleri
 *       (UBL e-Fatura/e-İrsaliye/e-Müstahsil, HR-XML, large UBL ~5 MB,
 *       BOM-encoded UBL, mixed-newlines, CDATA, comments,
 *       foreign-namespace-prefix, unicode-emoji). EARSIV_RAPORU
 *       {@link XadesDocumentFixture#requiresTsa()} olduğu için bu matrise
 *       <em>dahil değildir</em> (aşağıdaki dedike test'e bakın).</li>
 *   <li><b>Generic OtherXmlDocument matrisi</b>:
 *       5 PFX × 2 backend × 1 jenerik XML = <b>10 senaryo</b>
 *       ({@link DocumentType#OtherXmlDocument} placement yolunu test
 *       eder; bu yol enum'da değil çünkü "production fixture" değil).</li>
 *   <li><b>EArchiveReport fail-fast</b>: TSA yapılandırılmamış ortamda
 *       e-Arşiv Raporu imzalanmaya çalışıldığında {@code XAdES-A}
 *       yükseltmesinin sessizce atlanmadığını,
 *       {@link TimestampException} fırlattığını doğrular —
 *       silent XAdES-B fallback regresyonunu engeller.</li>
 * </ol>
 *
 * <p>Her TSA-bağımsız senaryo XAdES-BES (BASELINE_B) üretir;
 * verifier <code>signatureType=XADES</code>, <code>indication=TOTAL_PASSED</code>
 * dönmeli.</p>
 *
 * <h3>Fixture-bazlı ek davranışlar</h3>
 * <ul>
 *   <li>{@link XadesDocumentFixture#EFATURA_WITH_BOM}: imzalama öncesi
 *       fixture'ın gerçekten UTF-8 BOM ile başladığı sanity check'i; testi
 *       yanlış pozitiften korur.</li>
 *   <li>{@link XadesDocumentFixture#EFATURA_LARGE} (~5 MB, 4797 satır):
 *       sign ve verify süreleri INFO seviyesinde log'lanır (performans
 *       regresyonu PR diff'inde gözlenebilsin).</li>
 * </ul>
 *
 * <p><b>Hard performance threshold yok</b> — CI runner varyasyonu
 * (cold JIT, paylaşımlı hardware, verifier OCSP gecikmesi) flaky'lığa
 * yol açar. Job-level <code>timeout-minutes: 20</code> güvenlik ağıdır.</p>
 *
 * <h3>Kapsam dışı</h3>
 * <p>e-Arşiv Raporu için XAdES-A roundtrip (gerçek TSA ile) ayrı bir
 * suite'in işidir. Bu sınıf TSA-bağımsız fixture'larda BASELINE_B akışını
 * doğrular; e-Arşiv için <em>sadece fail-fast davranışını</em> sınar.</p>
 */
@ExtendWith(SignedArtifactExporter.class)
@Epic("Signature Roundtrip")
@Feature("XAdES Production Fixtures")
@Severity(SeverityLevel.BLOCKER)
class XAdESSignAndVerifyE2ETest extends AbstractVerifierE2ETest {

    private static final Logger LOGGER = LoggerFactory.getLogger(XAdESSignAndVerifyE2ETest.class);

    /** UTF-8 BOM: 0xEF 0xBB 0xBF — BOM fixture sanity check için. */
    private static final byte[] UTF8_BOM = new byte[] {
            (byte) 0xEF, (byte) 0xBB, (byte) 0xBF
    };

    private static XAdESSignatureService xadesSignatureService;

    @BeforeAll
    static void initSigningStack() {
        // DSS validation context — imza üretimi için minimum.
        // Test JVM'inde revocation alert'leri sustur (bkz. base class).
        CertificateVerifier verifier = newPermissiveVerifier();
        XAdESService xadesService = new XAdESService(verifier);

        DigestAlgorithmResolverService digestResolver = new DigestAlgorithmResolverService();
        SignatureAlgorithmResolverService sigAlgResolver = new SignatureAlgorithmResolverService();
        CryptoSignerService crypto = new CryptoSignerService(sigAlgResolver);

        XAdESParametersBuilderService paramsBuilder =
                new XAdESParametersBuilderService(digestResolver);
        XmlProcessingService xmlProcessor = new XmlProcessingService();
        XAdESDocumentPlacementService placement = new XAdESDocumentPlacementService();

        // TimestampConfigurationService boş TSP config'iyle — XAdES-A upgrade
        // tetiklenmediği sürece (UblDocument / OtherXmlDocument / HrXml) çağrılmaz.
        // EArchiveReport ile çağrılırsa fail-fast: TimestampException fırlar.
        TimestampConfigurationService tsConfig = new TimestampConfigurationService(
                /*tspServerUrl*/ "",
                /*tspUserId*/ "",
                /*tspUserPassword*/ "",
                /*isTubitakTsp*/ false);
        XAdESLevelUpgradeService upgrade = new XAdESLevelUpgradeService(verifier, tsConfig);

        CompressionService compression = new CompressionService();

        xadesSignatureService = new XAdESSignatureService(
                xadesService,
                paramsBuilder,
                xmlProcessor,
                placement,
                upgrade,
                crypto,
                verifier,
                compression,
                new Semaphore(2));
    }

    // ================================================================
    // Matrix 1: 5 PFX × 2 backend × tüm XadesDocumentFixture (= 70)
    // ================================================================

    static Stream<Arguments> pfxBackendFixtureMatrix() {
        Stream.Builder<Arguments> b = Stream.builder();
        // Pozitif matriks: yalnızca Status.VALID PFX'ler. Negative lifecycle
        // (revoked/expired/suspended) PFX'leri ayrı bir test sınıfında
        // ele alınır — bkz. CertificateLifecycleNegativeE2ETest.
        //
        // TSA-gerektiren fixture'lar (EArchiveReport / EBiletReport) kasıtlı
        // olarak filtrelenir — XAdESLevelUpgradeService TSA olmadan fail-fast
        // TimestampException fırlatır (silent XAdES-B fallback kaldırıldı).
        // Bu davranışı sınayan dedike test method'u aşağıda mevcut.
        for (PfxTestKey key : PfxTestKey.positiveValues()) {
            for (E2eSigningBackend backend : E2eSigningBackend.values()) {
                for (XadesDocumentFixture fixture : XadesDocumentFixture.values()) {
                    if (fixture.requiresTsa()) {
                        continue;
                    }
                    b.add(Arguments.of(key, backend, fixture));
                }
            }
        }
        return b.build();
    }

    @ParameterizedTest(name = "{index} → {0} / {1} / {2}")
    @MethodSource("pfxBackendFixtureMatrix")
    @DisplayName("XAdES fixture roundtrip: tüm UBL/EArchive/HR-XML fixture'ları × tüm PFX × tüm backend")
    void xadesFixtureRoundtripIsValid(PfxTestKey key,
                                      E2eSigningBackend backend,
                                      XadesDocumentFixture fixture) {
        byte[] xmlBytes = fixture.readBytes();
        assertTrue(xmlBytes.length > 0, "XML test fixture boş olmamalı: " + fixture);

        // BOM fixture'ı: testin yanlış pozitif geçmemesi için sanity check.
        if (fixture == XadesDocumentFixture.EFATURA_WITH_BOM) {
            assertBomFixtureStartsWithBom(xmlBytes, fixture);
        }

        SigningMaterial material = backend.load(key);
        String signatureId = "id-" + UUID.randomUUID().toString().replace("-", "");

        long signStart = System.nanoTime();
        SignResponse signed = xadesSignatureService.signXml(
                new ByteArrayInputStream(xmlBytes),
                fixture.getDocumentType(),
                signatureId,
                /*zipped*/ false,
                material,false);
        long signNanos = System.nanoTime() - signStart;

        assertNotNull(signed, "signResponse null olmamalı");
        byte[] signedBytes = signed.getSignedDocument();
        assertNotNull(signedBytes, "imzalı XML null olmamalı");
        assertTrue(signedBytes.length > 0, "imzalı XML boş olmamalı");

        // Large fixture: perf log (hard threshold yok, sadece gözlem).
        if (fixture == XadesDocumentFixture.EFATURA_LARGE) {
            LOGGER.info(
                    "XAdES large-doc sign: backend={}, pfx={}, "
                            + "input={} bytes, signed={} bytes, signDuration={}",
                    backend, key, xmlBytes.length, signedBytes.length,
                    Duration.ofNanos(signNanos));
        }

        long verifyStart = System.nanoTime();
        VerifierApiClient.VerificationResponse result = verifierClient()
                .verify(signedBytes, fixture.getFileName());
        long verifyNanos = System.nanoTime() - verifyStart;

        if (fixture == XadesDocumentFixture.EFATURA_LARGE) {
            LOGGER.info(
                    "XAdES large-doc verify: backend={}, pfx={}, verifyDuration={}",
                    backend, key, Duration.ofNanos(verifyNanos));
        }

        // Imzalı dosya + mersel-verifier-api response'unu Pages "Evidence Site"
        // için disk'e + Allure attachment olarak export et. Verify'dan SONRA
        // çağırıyoruz ki sidecar JSON gerçek verifier sonucu ile tutarlı olsun.
        SignedArtifactExporter.exportWithVerification(
                SignedArtifactExporter.Format.XADES, signedBytes,
                key.name() + "_" + backend.name() + "_" + fixture.name(),
                verificationReport(result));

        CAdESSignAndVerifyE2ETest.assertVerificationPassed(
                result, "XADES", key, backend + "/" + fixture.name());
    }

    // ================================================================
    // Matrix 2: 5 PFX × 2 backend × generic OtherXmlDocument (= 10)
    // ================================================================
    // Generic XML için fixture-enum'a yer yok (production senaryosu değil),
    // ama DocumentType.OtherXmlDocument yolunu da test ediyoruz.

    static Stream<Arguments> pfxBackendMatrix() {
        Stream.Builder<Arguments> b = Stream.builder();
        for (PfxTestKey key : PfxTestKey.positiveValues()) {
            for (E2eSigningBackend backend : E2eSigningBackend.values()) {
                b.add(Arguments.of(key, backend));
            }
        }
        return b.build();
    }

    @ParameterizedTest(name = "{index} → {0} / {1} / OtherXmlDocument(generic)")
    @MethodSource("pfxBackendMatrix")
    @DisplayName("XAdES generic OtherXmlDocument roundtrip: jenerik XML × tüm PFX × tüm backend")
    void xadesGenericXmlRoundtripIsValid(PfxTestKey key, E2eSigningBackend backend) {
        byte[] xmlBytes = E2eFixtures.genericXml();
        String fileName = E2eFixtures.genericXmlFileName();
        assertTrue(xmlBytes.length > 0, "generic XML fixture boş olmamalı");

        SigningMaterial material = backend.load(key);
        String signatureId = "id-" + UUID.randomUUID().toString().replace("-", "");

        SignResponse signed = xadesSignatureService.signXml(
                new ByteArrayInputStream(xmlBytes),
                DocumentType.OtherXmlDocument,
                signatureId,
                /*zipped*/ false,
                material,false);

        assertNotNull(signed, "signResponse null olmamalı");
        byte[] signedBytes = signed.getSignedDocument();
        assertNotNull(signedBytes, "imzalı XML null olmamalı");
        // Generic XML çok küçük (< 200 byte), enveloped signature ekleyince
        // çıktı orijinalden büyük olmalı — bu eski kontratın aynısı.
        assertTrue(signedBytes.length > xmlBytes.length,
                "imzalı XML orijinalden büyük olmalı (jenerik XML enveloped)");

        VerifierApiClient.VerificationResponse result =
                verifierClient().verify(signedBytes, fileName);

        SignedArtifactExporter.exportWithVerification(
                SignedArtifactExporter.Format.XADES, signedBytes,
                key.name() + "_" + backend.name() + "_generic-xml",
                verificationReport(result));

        CAdESSignAndVerifyE2ETest.assertVerificationPassed(
                result, "XADES", key, backend + "/OtherXmlDocument");
    }

    // ================================================================
    // Matrix 3: EArchiveReport fail-fast (TSA yapılandırılmamış)
    // ================================================================

    /**
     * <h3>e-Arşiv Raporu için silent XAdES-B fallback regresyonu</h3>
     *
     * <p>e-Arşiv Raporu GİB tarafına XAdES-A seviyesinde gönderilmek
     * <em>zorundadır</em>. {@code XAdESLevelUpgradeService} eskiden TSA
     * yapılandırılmamışken WARN log + XAdES-B döndürüyordu — bu sessizce
     * uyumsuz rapor üretiyordu (silent data corruption pattern). Yeni
     * sözleşmede TSA yoksa veya upgrade hata alırsa
     * {@link TimestampException} fırlatılır, HTTP katmanında 503
     * SERVICE_UNAVAILABLE + {@code TIMESTAMP_ERROR} envelope'una mapping'i
     * {@code GlobalExceptionHandlerTest} kapsar.</p>
     *
     * <p>Bu test: TSA yapılandırılmamış servis stack'inde
     * {@link XadesDocumentFixture#EARSIV_RAPORU} imzalanmaya
     * çalışıldığında {@code TimestampException} alındığını ve mesajın
     * client'a yönlendirme bilgisi (TS_SERVER_HOST property)
     * taşıdığını doğrular.</p>
     */
    @Test
    @DisplayName("EArchiveReport: TSA yapılandırılmamışken fail-fast TimestampException fırlatır")
    void earchiveReportFailsFastWhenTsaUnconfigured() {
        XadesDocumentFixture fixture = XadesDocumentFixture.EARSIV_RAPORU;
        byte[] xmlBytes = fixture.readBytes();
        assertTrue(xmlBytes.length > 0, "e-Arşiv Raporu fixture boş olmamalı");

        // Pozitif PFX'lerden ilki yeterli — backend ile fail-fast davranışı
        // arasında bir bağımlılık yok; TSA kontrolü imza üretiminden önce
        // (XAdESLevelUpgradeService.upgradeIfNeeded içinde) yapılır.
        PfxTestKey key = PfxTestKey.positiveValues()[0];
        SigningMaterial material = E2eSigningBackend.values()[0].load(key);

        TimestampException ex = assertThrows(TimestampException.class,
                () -> xadesSignatureService.signXml(
                        new ByteArrayInputStream(xmlBytes),
                        fixture.getDocumentType(),
                        "id-" + UUID.randomUUID().toString().replace("-", ""),
                        /*zipped*/ false,
                        material,false),
                "TSA yapılandırılmamışken EArchiveReport için TimestampException beklenir; "
                        + "silent XAdES-B fallback regresyon vakası");

        assertEquals("TIMESTAMP_ERROR", ex.getErrorCode(),
                "GlobalExceptionHandler 503 + TIMESTAMP_ERROR envelope için error code'u görmek zorunda");
        assertTrue(ex.getMessage().contains("EArchiveReport"),
                "Mesaj hangi belge tipinin upgrade gerektirdiğini söylemeli ki client doğru "
                        + "endpoint'i / config property'sini hedefleyebilsin: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("TS_SERVER_HOST"),
                "Mesaj operatöre yapılandırması gereken property adını söylemeli: " + ex.getMessage());
    }

    // ================================================================

    private static void assertBomFixtureStartsWithBom(byte[] xmlBytes,
                                                     XadesDocumentFixture fixture) {
        assertTrue(xmlBytes.length > UTF8_BOM.length,
                fixture + " fixture'ı UTF-8 BOM'dan büyük olmalı");
        for (int i = 0; i < UTF8_BOM.length; i++) {
            assertTrue(xmlBytes[i] == UTF8_BOM[i],
                    fixture + " UTF-8 BOM (EF BB BF) ile başlamalı; "
                            + "byte[" + i + "]=0x" + String.format("%02X", xmlBytes[i])
                            + " (regression: fixture yanlış üretilmiş olabilir)");
        }
    }
}
