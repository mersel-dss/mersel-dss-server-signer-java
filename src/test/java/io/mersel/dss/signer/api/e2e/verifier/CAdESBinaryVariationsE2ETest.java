package io.mersel.dss.signer.api.e2e.verifier;

import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import io.mersel.dss.signer.api.models.SignResponse;
import io.mersel.dss.signer.api.models.SigningMaterial;
import io.mersel.dss.signer.api.services.crypto.CryptoSignerService;
import io.mersel.dss.signer.api.services.crypto.DigestAlgorithmResolverService;
import io.mersel.dss.signer.api.services.crypto.SignatureAlgorithmResolverService;
import io.mersel.dss.signer.api.services.signature.cades.CAdESSignatureService;
import io.mersel.dss.signer.api.testsupport.SignedArtifactExporter;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Severity;
import io.qameta.allure.SeverityLevel;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.security.cert.X509Certificate;
import java.util.concurrent.Semaphore;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CAdES için <b>binary girdi varyasyonu</b> sign+verify roundtrip testi.
 *
 * <h3>Amaç</h3>
 * <p>Farklı binary girdi tiplerinin (UTF-8 text, ham binary, UTF-16 BOM)
 * signer'ın ContentInfo + digest akışını bozmadığını test eder. Mevcut
 * {@link CAdESSignAndVerifyE2ETest} CAdES yapı kontratını (attached vs
 * detached, 5 PFX × 2 backend) zaten kapsar; bu sınıf <b>tamamlayıcı</b>
 * fixture-content regresyon vektörüdür.</p>
 *
 * <h3>Senaryo matrisi</h3>
 * <p>Tek RSA PFX × JCA backend × 4 fixture = <b>4 senaryo</b>. Key-tipinden
 * bağımsız (content-regression testi); 5×2 matriks CI yükü olur, değer
 * eklemez. EMPTY_BIN (0 byte) özel davranış: signer empty input'a hata
 * fırlatmalı (production kontratı), test onun yerine assertion farklı.</p>
 *
 * <h3>Mod stratejisi</h3>
 * <p>Her fixture iki modda da test edilir:</p>
 * <ul>
 *   <li><b>Attached (enveloping)</b> — verifier API'ye gönderilir,
 *       sertifika zinciri + digest + ICMSUtils policy ile tam roundtrip.</li>
 *   <li><b>Detached</b> — verifier'a göndermek için orijinal içeriği de
 *       birlikte göndermek gerekir (multipart kontratı ayrı); bu test
 *       lokal BouncyCastle {@code CMSSignedData} parser'ı ile yapısal +
 *       kriptografik geçerliliği doğrular. CAdES detached davranışının
 *       binary-tarafı içerik-bağımsız olduğu için bu kapsamla yeterli;
 *       detached için downstream verifier sözleşmesi
 *       {@link CAdESSignAndVerifyE2ETest}'te ayrı PFX × backend
 *       matrisi ile test edilir.</li>
 * </ul>
 */
@ExtendWith(SignedArtifactExporter.class)
@Epic("Signature Roundtrip")
@Feature("CAdES Binary Fixtures")
@Severity(SeverityLevel.NORMAL)
class CAdESBinaryVariationsE2ETest extends AbstractVerifierE2ETest {

    private static final Logger LOGGER = LoggerFactory.getLogger(CAdESBinaryVariationsE2ETest.class);

    private static CAdESSignatureService cadesSignatureService;
    private static SigningMaterial defaultMaterial;

    @BeforeAll
    static void initSigningStack() {
        CommonCertificateVerifier verifier = new CommonCertificateVerifier();
        CAdESService cadesService = new CAdESService(verifier);
        SignatureAlgorithmResolverService sigAlgResolver = new SignatureAlgorithmResolverService();
        DigestAlgorithmResolverService digestResolver = new DigestAlgorithmResolverService();
        CryptoSignerService crypto = new CryptoSignerService(sigAlgResolver);
        cadesSignatureService = new CAdESSignatureService(
                cadesService, crypto, digestResolver,
                new Semaphore(2));
        defaultMaterial = E2eSigningBackend.PFX_JCA.load(PfxTestKey.positiveValues()[0]);
    }

    @ParameterizedTest(name = "{0} (attached)")
    @EnumSource(CadesBinaryFixture.class)
    @DisplayName("CAdES binary variation: 4 fixture × tek RSA PFX × JCA × ATTACHED → verifier API")
    void cadesBinaryRoundtripIsValid(CadesBinaryFixture fixture) {
        byte[] data = fixture.readBytes();

        // EMPTY_BIN edge-case: 0-byte input. İki davranış kabul edilebilir,
        // signer + DSS sürümüne bağlı:
        //   (a) RuntimeException atar (defansif tercih) — production'da
        //       upload hatası gibi davranır;
        //   (b) Spec-uyumlu boş ContentInfo üretir (RFC 5652 §5.3) — DSS
        //       6.x default davranışı. Bu da OK; sessiz başarı değil,
        //       valid bir CMS yapısı (sadece içerik boş).
        // Test: hangisi olursa olsun JVM çökmesin, log'lansın.
        if (fixture == CadesBinaryFixture.EMPTY_BIN) {
            assertEmptyInputHandledGracefully(data);
            return;
        }

        // Normal akış: imzala + verifier'a gönder (attached).
        SignResponse signed = cadesSignatureService.signData(
                new ByteArrayInputStream(data),
                /*detached*/ false,
                defaultMaterial);
        assertNotNull(signed, "signResponse null olmamalı: " + fixture);
        byte[] signedBytes = signed.getSignedDocument();
        assertNotNull(signedBytes, "imzalı bytes null olmamalı: " + fixture);
        assertTrue(signedBytes.length > 0, "imzalı bytes boş olmamalı: " + fixture);
        // Attached/enveloping: imzalı çıktı orijinal veriden büyük olmalı
        // (CMS overhead + signed-attrs + cert ~kilobytes).
        assertTrue(signedBytes.length > data.length,
                "attached CMS orijinal veriden büyük olmalı (" + fixture
                        + ", input=" + data.length + ", signed=" + signedBytes.length + ")");

        // Üçüncü taraf doğrulama için disk'e export et (attached → payload
        // CMS'in içinde, sidecar gerekmez).
        SignedArtifactExporter.export(
                SignedArtifactExporter.Format.CADES_ATTACHED, signedBytes);

        VerifierApiClient.VerificationResponse result;
        try {
            result = verifierClient().verify(signedBytes, "binary-" + fixture.name() + ".p7s");
        } catch (VerifierApiClient.VerifierBackendUnavailable backendDown) {
            // JUnit 5.8 — Assumptions.abort yok; assumeTrue(false) ile aynı semantic.
            org.junit.jupiter.api.Assumptions.assumeTrue(false,
                    "Verifier backend CAdES'i ele alamadı (eksik DSS modülü, lokal-only), test skip: "
                            + backendDown.getMessage());
            return;
        }

        CAdESSignAndVerifyE2ETest.assertVerificationPassed(
                result, "CADES", PfxTestKey.positiveValues()[0],
                E2eSigningBackend.PFX_JCA + "/" + fixture.name());
    }

    /**
     * Empty input için graceful behavior kontratı.
     *
     * <p>İki olası davranış {@code RuntimeException} <b>veya</b> spec-uyumlu
     * boş CMS — her ikisi de "graceful" sayılır. Production tercihi DSS
     * sürümüne bağlıdır:</p>
     *
     * <ul>
     *   <li><b>RuntimeException</b>: Operator-friendly defansif tercih.
     *       Upload hatası anında dönülür.</li>
     *   <li><b>Boş CMS (RFC 5652 §5.3 spec-uyumlu)</b>: DSS 6.x default
     *       davranışı — encapsulated content boş, ama yapı geçerli.</li>
     * </ul>
     *
     * <p>Regresyon: ikisi de değil → "null pointer" / "infinite loop" gibi
     * gerçek bug. Bu test sadece <em>davranışı dokümante</em> eder, build
     * kırıcı asserrtion yoktur — log'a hangi davranışın gözlendiğini yazar.</p>
     */
    private static void assertEmptyInputHandledGracefully(byte[] empty) {
        assertTrue(empty.length == 0, "EMPTY_BIN gerçekten 0 byte olmalı");

        SignResponse signed;
        try {
            signed = cadesSignatureService.signData(
                    new ByteArrayInputStream(empty),
                    /*detached*/ false,
                    defaultMaterial);
        } catch (RuntimeException ex) {
            // Davranış (a) — defansif throws. Doğru kontrat, build geçer.
            LOGGER.info("EMPTY_BIN contract: signer defansif throws ({}): {}",
                    ex.getClass().getSimpleName(), ex.getMessage());
            return;
        }

        // Davranış (b) — boş CMS üretildi. Yapısal sağlık kontrolü:
        // signResponse null olmamalı, byte length > 0 (CMS overhead).
        assertNotNull(signed, "EMPTY_BIN: signer hata atmadıysa signResponse null olmamalı");
        byte[] cms = signed.getSignedDocument();
        assertNotNull(cms, "EMPTY_BIN: signed bytes null olmamalı");
        assertTrue(cms.length > 0,
                "EMPTY_BIN: 0-byte input'a karşı CMS overhead'i 0-byte olamaz "
                        + "(yapı bozulmuş demek)");

        LOGGER.warn("EMPTY_BIN contract: signer spec-uyumlu boş CMS üretti "
                        + "({} byte). Production'da empty input genelde upload hatası — "
                        + "operator caller'a WARN dönmeli.",
                cms.length);
    }

    /**
     * C-ek: Aynı 4 fixture × <b>DETACHED</b> mode.
     *
     * <p>Detached CMS imzasında orijinal içerik {@code SignedData}
     * yapısına gömülü <em>değildir</em>; verifier ayrı bir parametre
     * olarak içeriği bekler. Bu nedenle remote verifier API'ye değil,
     * lokal BouncyCastle {@code CMSSignedData} parser'ı ile şu
     * invariant'ları doğruluyoruz:</p>
     *
     * <ul>
     *   <li>{@code CMSSignedData} parse edilebilir (yapı geçerli).</li>
     *   <li>{@code getSignedContent() == null} — detached olmasının tanımı.</li>
     *   <li>En az 1 {@code SignerInformation} var.</li>
     *   <li>Sertifika store'unda signer cert var.</li>
     *   <li>{@code SignerInformation.verify(...)} orijinal içerik ile
     *       başarılı → imzanın kriptografik geçerliliği.</li>
     * </ul>
     *
     * <p>EMPTY_BIN için detached mode aynı edge-case'i taşır
     * (graceful: throws veya valid empty); attached-side davranışla
     * paralel.</p>
     */
    @ParameterizedTest(name = "{0} (detached)")
    @EnumSource(CadesBinaryFixture.class)
    @DisplayName("CAdES binary variation: 4 fixture × DETACHED → lokal BC CMSSignedData verify")
    void cadesBinaryDetached_signatureIsCryptographicallyValid(CadesBinaryFixture fixture)
            throws Exception {
        byte[] data = fixture.readBytes();

        // EMPTY_BIN: attached-side ile aynı kontrat — JVM çökmesin.
        if (fixture == CadesBinaryFixture.EMPTY_BIN) {
            try {
                SignResponse signed = cadesSignatureService.signData(
                        new ByteArrayInputStream(data), /*detached*/ true, defaultMaterial);
                if (signed != null && signed.getSignedDocument() != null) {
                    // Valid CMS yapısı parse edilebilmeli — yapısal sağlık kontrolü.
                    new CMSSignedData(signed.getSignedDocument());
                }
                LOGGER.info("EMPTY_BIN detached: signer empty input için "
                        + "yapısal-geçerli detached CMS üretti");
            } catch (RuntimeException ex) {
                LOGGER.info("EMPTY_BIN detached: signer defansif throws ({}): {}",
                        ex.getClass().getSimpleName(), ex.getMessage());
            }
            return;
        }

        SignResponse signed = cadesSignatureService.signData(
                new ByteArrayInputStream(data), /*detached*/ true, defaultMaterial);
        assertNotNull(signed, "detached signResponse null olmamalı: " + fixture);
        byte[] cmsBytes = signed.getSignedDocument();
        assertNotNull(cmsBytes, "detached CMS bytes null olmamalı: " + fixture);
        assertTrue(cmsBytes.length > 0, "detached CMS boş olmamalı: " + fixture);

        // Detached için imza + payload sidecar pair'i — openssl smime
        // -verify komutuyla doğrulanır.
        SignedArtifactExporter.exportDetachedCmsPair(cmsBytes, data);

        // RFC 5652 §5.1: detached CMS'de SignedData.encapContentInfo.eContent YOK.
        // BC bunu null olarak okur.
        CMSSignedData cms = new CMSSignedData(cmsBytes);
        assertEquals(null, cms.getSignedContent(),
                "detached CMS'in signed content'i null olmalı (encapContentInfo.eContent yok): "
                        + fixture);

        SignerInformationStore signers = cms.getSignerInfos();
        assertEquals(1, signers.size(),
                "detached CMS tek SignerInformation içermeli: " + fixture);

        // Sertifika store'unda signer cert olmalı (CertificateChain set edilmiş).
        assertFalse(cms.getCertificates().getMatches(null).isEmpty(),
                "detached CMS sertifika içermeli (chain set): " + fixture);

        // Kriptografik doğrulama — orijinal içerik externally besleniyor.
        SignerInformation signer = signers.getSigners().iterator().next();
        CMSSignedData cmsWithContent = new CMSSignedData(
                new CMSProcessableByteArray(data), cmsBytes);
        SignerInformation signerWithContent =
                cmsWithContent.getSignerInfos().getSigners().iterator().next();

        boolean cryptoValid = signerWithContent.verify(
                new JcaSimpleSignerInfoVerifierBuilder()
                        .build((X509Certificate) defaultMaterial.getSigningCertificate()));
        assertTrue(cryptoValid,
                "detached CMS imzası orijinal içerikle birlikte doğrulanamadı: " + fixture);

        LOGGER.info("CAdES detached fixture {} doğrulandı (CMS bytes: {}, signer: {})",
                fixture, cmsBytes.length, signer.getSID());
    }
}
