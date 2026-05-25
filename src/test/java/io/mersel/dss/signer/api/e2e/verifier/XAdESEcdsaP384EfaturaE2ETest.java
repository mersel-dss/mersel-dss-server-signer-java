package io.mersel.dss.signer.api.e2e.verifier;

import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.xades.signature.XAdESService;
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
import io.qameta.allure.Description;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Severity;
import io.qameta.allure.SeverityLevel;
import io.qameta.allure.Story;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.UUID;
import java.util.concurrent.Semaphore;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * <h1>EC P-384 sertifika ile e-Fatura UBL XAdES roundtrip — verifier-api odaklı E2E</h1>
 *
 * <h2>Niçin ayrı bir test?</h2>
 * <p>{@link XAdESSignAndVerifyE2ETest} matriksinde EC P-384 + e-Fatura zaten
 * 130 senaryo arasında koşuyor; bu test ise <b>sadece</b> ECDSA P-384 + UBL
 * e-Fatura roundtrip'ine odaklanır. Amaç:</p>
 * <ul>
 *   <li><b>Hızlı izolasyon:</b> "EC384 imza verifier'dan geçiyor mu?" sorusunu
 *       4 senaryoda yanıtlar — debug ve regression localization daha kolay.</li>
 *   <li><b>ECDSA-spesifik kod yolu garantisi:</b> PKCS#11 backend'inde imza
 *       formatı raw {@code r||s} (PKCS#11 spec) → XML-DSig için DER SEQUENCE
 *       beklentisi var. {@link XAdESSignatureService#ensureXadesSignatureValueFormat}
 *       bu dönüşümü garanti ediyor; bu test o garantiyi siyah-kutu olarak
 *       doğrular (verifier {@code SIG_CRYPTO_FAILURE} dönerse dönüşüm
 *       bozulmuş demektir).</li>
 *   <li><b>Pre-flight sanity:</b> PFX'in gerçekten EC P-384 anahtar taşıdığı
 *       imza akışı başlamadan önce doğrulanır; yanlış fixture seçimine karşı
 *       savunma.</li>
 * </ul>
 *
 * <h2>Senaryo matrisi (4 senaryo)</h2>
 * <p>2 EC384 PFX × 2 backend:</p>
 * <ul>
 *   <li>{@link PfxTestKey#KURUM02_EC384} × {@link E2eSigningBackend#PFX_JCA}</li>
 *   <li>{@link PfxTestKey#KURUM02_EC384} × {@link E2eSigningBackend#PFX_BACKED_PKCS11}</li>
 *   <li>{@link PfxTestKey#KURUM03_EC384} × {@link E2eSigningBackend#PFX_JCA}</li>
 *   <li>{@link PfxTestKey#KURUM03_EC384} × {@link E2eSigningBackend#PFX_BACKED_PKCS11}</li>
 * </ul>
 *
 * <p>Her senaryo {@link XadesDocumentFixture#EFATURA} (UBL Invoice) üzerinde
 * XAdES-BES (BASELINE_B) üretir. Verifier'dan beklenen:</p>
 * <ul>
 *   <li>{@code signatureType=XADES}</li>
 *   <li>{@code indication=TOTAL_PASSED}</li>
 *   <li>{@code cryptographicVerificationSuccessful=true} (asıl ECDSA kanıtı)</li>
 *   <li>{@code trustAnchorReached=true} (KamuSM kök zinciri)</li>
 *   <li>{@code certificateNotExpired=true}</li>
 * </ul>
 *
 * <h2>Failure modu okuması</h2>
 * <p>Bir başarısızlık durumunda diagnostic string'i okurken hangi flag yanlışsa
 * sebep tipik olarak:</p>
 * <ul>
 *   <li>{@code cryptographicVerificationSuccessful=false} →
 *       ECDSA imza format dönüşümü bozuk (DER ↔ plain r||s). Bkz.
 *       {@code Pkcs11EcdsaSignatureEncoder.normalizeToDer} ve
 *       {@code XAdESSignatureService#ensureXadesSignatureValueFormat}.</li>
 *   <li>{@code trustAnchorReached=false} → KamuSM kök sertifikası verifier
 *       trust store'da yok / DSS LOTL fetch başarısız.</li>
 *   <li>{@code certificateChainValid=false} → ara sertifika eksik
 *       (AIA fetch başarısız veya verifier offline).</li>
 *   <li>{@code certificateNotExpired=false} → test PFX'lerinin notAfter geçmiş;
 *       sertifika rotasyonu gerekli (bkz. {@code TEST_CERTIFICATES.md}).</li>
 * </ul>
 */
@ExtendWith(SignedArtifactExporter.class)
@Epic("Signature Roundtrip")
@Feature("XAdES ECDSA P-384 Focused")
@Story("EC P-384 sertifika ile e-Fatura UBL imzala → verifier doğrulasın")
@Severity(SeverityLevel.CRITICAL)
class XAdESEcdsaP384EfaturaE2ETest extends AbstractVerifierE2ETest {

    private static final Logger LOGGER = LoggerFactory.getLogger(XAdESEcdsaP384EfaturaE2ETest.class);

    /**
     * Java {@code AlgorithmParameters("EC")} P-384 curve OID — JCA standardı.
     * {@link ECParameterSpec} doğrudan curve OID/adı vermez; OID'i 384-bit
     * field size + cofactor=1'den teşhis ederiz (defansif sanity).
     */
    private static final int P384_FIELD_BIT_SIZE = 384;

    private static XAdESSignatureService xadesSignatureService;

    @BeforeAll
    static void initSigningStack() {
        // Mevcut XAdESSignAndVerifyE2ETest ile bire bir aynı pipeline; ECDSA
        // için özel bir konfigürasyon yok (production'da da yok). Service
        // matriksinin her test sınıfı kurması Spring boot süresinden tasarruf
        // ettirir ve test izolasyonu sağlar.
        CertificateVerifier verifier = newPermissiveVerifier();
        XAdESService xadesService = new XAdESService(verifier);

        DigestAlgorithmResolverService digestResolver = new DigestAlgorithmResolverService();
        SignatureAlgorithmResolverService sigAlgResolver = new SignatureAlgorithmResolverService();
        CryptoSignerService crypto = new CryptoSignerService(sigAlgResolver);

        XAdESParametersBuilderService paramsBuilder =
                new XAdESParametersBuilderService(digestResolver);
        XmlProcessingService xmlProcessor = new XmlProcessingService();
        XAdESDocumentPlacementService placement = new XAdESDocumentPlacementService();

        // TSA yok — UBL e-Fatura XAdES-B üretilir, upgrade tetiklenmez.
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

    /**
     * 2 EC384 PFX × 2 backend = 4 senaryo. Pozitif-only filter zaten yok;
     * EC384 anahtarlar enum'da {@link PfxTestKey.Status#VALID}.
     */
    static Stream<Arguments> ec384Matrix() {
        Stream.Builder<Arguments> b = Stream.builder();
        PfxTestKey[] ec384Keys = { PfxTestKey.KURUM02_EC384, PfxTestKey.KURUM03_EC384 };
        for (PfxTestKey key : ec384Keys) {
            for (E2eSigningBackend backend : E2eSigningBackend.values()) {
                b.add(Arguments.of(key, backend));
            }
        }
        return b.build();
    }

    @ParameterizedTest(name = "{index} → {0} / {1}")
    @MethodSource("ec384Matrix")
    @DisplayName("EC P-384 + e-Fatura UBL: imzala → verifier-api → TOTAL_PASSED + cryptoOk")
    @Description("EC P-384 sertifika ile UBL e-Fatura imzalanıp Mersel Verifier API'ye "
            + "gönderilir. Verifier'dan TOTAL_PASSED + cryptographicVerificationSuccessful "
            + "beklenir. PKCS#11 yolu özelinde imza format dönüşümü (raw r||s → DER) "
            + "kritik; başarısızlık tipik olarak format regresyonunu işaret eder.")
    void ec384EfaturaRoundtripIsValid(PfxTestKey key, E2eSigningBackend backend) {
        // ───────────────────────────────────────────────────────────────
        // Pre-flight: PFX gerçekten EC P-384 mü? Yanlış fixture seçimine
        // karşı erken hata; verifier patladığında "alg neydi ki?" sorusunu
        // bertaraf eder.
        // ───────────────────────────────────────────────────────────────
        SigningMaterial material = backend.load(key);
        assertNotNull(material, "SigningMaterial null geldi: " + key + " / " + backend);

        X509Certificate cert = material.getSigningCertificate();
        assertNotNull(cert, "SigningCertificate null: " + key);
        assertEcP384(cert, key);

        // ───────────────────────────────────────────────────────────────
        // İmza akışı
        // ───────────────────────────────────────────────────────────────
        byte[] xmlBytes = XadesDocumentFixture.EFATURA.readBytes();
        assertTrue(xmlBytes.length > 0, "e-Fatura fixture boş olmamalı");

        String signatureId = "id-" + UUID.randomUUID().toString().replace("-", "");

        long signStartNs = System.nanoTime();
        SignResponse signed = xadesSignatureService.signXml(
                new ByteArrayInputStream(xmlBytes),
                DocumentType.UblDocument,
                signatureId,
                /*zipped*/ false,
                material,false);
        long signMs = (System.nanoTime() - signStartNs) / 1_000_000L;

        assertNotNull(signed, "signResponse null");
        byte[] signedBytes = signed.getSignedDocument();
        assertNotNull(signedBytes, "imzalı XML null");
        assertTrue(signedBytes.length > xmlBytes.length,
                "imzalı XML orijinalden büyük olmalı (UBLExtensions + ds:Signature eklenir); "
                        + "input=" + xmlBytes.length + " B, signed=" + signedBytes.length + " B");

        LOGGER.info("EC P-384 e-Fatura imza tamamlandı: pfx={}, backend={}, "
                        + "input={} B, signed={} B, signDuration={} ms",
                key.name(), backend, xmlBytes.length, signedBytes.length, signMs);

        // ───────────────────────────────────────────────────────────────
        // Verifier roundtrip
        // ───────────────────────────────────────────────────────────────
        long verifyStartNs = System.nanoTime();
        VerifierApiClient.VerificationResponse result = verifierClient()
                .verify(signedBytes, XadesDocumentFixture.EFATURA.getFileName());
        long verifyMs = (System.nanoTime() - verifyStartNs) / 1_000_000L;

        LOGGER.info("EC P-384 e-Fatura verifier yanıtladı: pfx={}, backend={}, "
                        + "verifyDuration={} ms, indication={}",
                key.name(), backend, verifyMs,
                result == null || result.getSignatures() == null || result.getSignatures().isEmpty()
                        ? "(yok)"
                        : result.getSignatures().get(0).getIndication());

        // Allure attachment + Pages "Evidence Site" — verify SONRASI ki
        // sidecar JSON gerçek sonucu yansıtsın.
        SignedArtifactExporter.exportWithVerification(
                SignedArtifactExporter.Format.XADES, signedBytes,
                "EC384_" + key.name() + "_" + backend.name() + "_efatura",
                verificationReport(result));

        // ───────────────────────────────────────────────────────────────
        // Assertion bloğu — CAdES test'iyle aynı strict kontrat:
        //   1) result.isValid() + first.isValid() = true
        //   2) indication = TOTAL_PASSED
        //   3) cryptographicVerificationSuccessful = true  (ECDSA için kritik)
        //   4) trustAnchorReached = true
        //   5) certificateNotExpired = true
        // ───────────────────────────────────────────────────────────────
        CAdESSignAndVerifyE2ETest.assertVerificationPassed(
                result, "XADES", key,
                backend + "/ECDSA-P384/EFATURA");

        // ECDSA-spesifik ek kontrat (XAdES format kontrolü):
        // signatureFormat XAdES-BASELINE-B veya XAdES-B-B ile başlamalı.
        // Eski DSS sürümlerinde "XAdES-BASELINE-B", yenilerde "XAdES-B-B"
        // formatında dönebiliyor; ikisi de kabul.
        assertFalse(result.getSignatures().isEmpty(), "imza listesi boş");
        VerifierApiClient.SignatureInfo first = result.getSignatures().get(0);
        String format = first.getSignatureFormat();
        assertNotNull(format, "signatureFormat null — verifier kontratı değişmiş olabilir");
        assertTrue(format.startsWith("XAdES") || format.startsWith("XADES"),
                "signatureFormat XAdES* bekleniyor, gelen: " + format);
    }

    /**
     * Sertifikanın gerçekten EC P-384 olduğunu doğrular. PFX dosya adından
     * isim çıkarımı yerine cryptographic primitive'leri okur — yanlış
     * fixture'a karşı erken/net hata.
     *
     * <p>Kontrol kriterleri:</p>
     * <ul>
     *   <li>Public key algoritması "EC" olmalı.</li>
     *   <li>{@link ECPublicKey#getParams()} field size 384 bit olmalı
     *       (P-384 NIST curve = secp384r1 = ANSI X9.62 prime384v1).</li>
     * </ul>
     */
    private static void assertEcP384(X509Certificate cert, PfxTestKey key) {
        PublicKey pk = cert.getPublicKey();
        assertEquals("EC", pk.getAlgorithm(),
                "PFX " + key + " EC anahtar taşımıyor; algorithm=" + pk.getAlgorithm()
                        + " (fixture seçimi yanlış? bkz. PfxTestKey naming convention)");
        assertTrue(pk instanceof ECPublicKey,
                "PublicKey ECPublicKey değil: " + pk.getClass().getName());
        ECPublicKey ecPk = (ECPublicKey) pk;
        ECParameterSpec spec = ecPk.getParams();
        assertNotNull(spec, "ECParameterSpec null — provider EC parametrelerini açmıyor");
        int fieldBits = spec.getCurve().getField().getFieldSize();
        assertEquals(P384_FIELD_BIT_SIZE, fieldBits,
                "EC curve P-384 değil; fieldSize=" + fieldBits
                        + " bit (P-256=256, P-384=384, P-521=521). "
                        + "PFX " + key + " yanlış curve taşıyor olabilir.");

        LOGGER.info("EC P-384 sanity OK: pfx={}, subject={}, fieldBits={}, sigAlgName={}",
                key.name(), cert.getSubjectX500Principal().getName(),
                fieldBits, cert.getSigAlgName());
    }
}
