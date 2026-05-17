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
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.util.concurrent.Semaphore;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * CAdES için <b>negatif</b> sign+verify roundtrip testi. Detached CMS
 * yapısında orijinal payload mutate edilirse verifier
 * <b>"signature integrity broken"</b> raporlamalı.
 *
 * <h3>Pattern (detached)</h3>
 * <ol>
 *   <li>Bir veri buffer'ını {@link CAdESSignatureService}'le <b>detached</b>
 *       imzala — sonuç bir <code>.p7s</code>, orijinal veri ayrı dosya.</li>
 *   <li>Sanity: <code>.p7s</code> + orijinal veri verifier'da VALID dön.</li>
 *   <li><b>Orijinal veriyi</b> mutate et (tek byte flip); imza ve sertifika
 *       hâlâ matematiksel olarak doğru, ama imza orijinal digest'i
 *       referans aldığı için mutasyon detect edilmeli.</li>
 *   <li>Verifier <code>.p7s</code> + tampered original ile çağrıldığında
 *       <code>signatureIntact=false</code> / <code>valid=false</code>
 *       dönmeli.</li>
 * </ol>
 *
 * <h3>Neden detached?</h3>
 * <p>Attached (enveloping) CAdES'te payload CMS yapısının içinde
 * gömülüdür; tamper denemek için CMS yapısını parse edip içeri girmek
 * gerekir → kompleks ve test patternini bulanıklaştırır. Detached mode
 * "imzalı içerik" ve "imza" iki ayrı bayt dizisi olduğu için tampering
 * trivially modellenebilir: original'i değiştir, signature'a dokunma.
 * Production CAdES detached kullanımı yaygın (sertifika authority workflows,
 * "imza zarflanmamış" PDF/dosya senaryoları).</p>
 *
 * <h3>Ek pattern (signature tampering — opsiyonel)</h3>
 * <p>Aynı detached p7s'in son byte'ını flip ettiğimizde CMS DER parser
 * structural exception fırlatabilir; bu testin ana akışı "veri tamper"
 * üzerinde — DSS verifier'ının deterministic davranışını daha temiz
 * gözlemlemek için.</p>
 *
 * <h3>Tag stratejisi</h3>
 * <p>{@code "verifier-e2e"} — Docker tabanlı verifier-api gerekli.
 * Tek RSA PFX × JCA backend.</p>
 */
@ExtendWith(SignedArtifactExporter.class)
@Epic("Negative — Tampering")
@Feature("CAdES Detached Payload Tamper")
@Severity(SeverityLevel.CRITICAL)
class CAdESTamperedE2ETest extends AbstractVerifierE2ETest {

    private static final Logger LOGGER = LoggerFactory.getLogger(CAdESTamperedE2ETest.class);

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

    @Test
    @DisplayName("Tampered-after-sign CMS (detached): orijinal payload byte flip → verifier reject")
    void cmsTamperedAfterSignRejected() {
        // Sabit bir payload — runtime üreteç değil, böylece tamper offset
        // belirleyebiliyoruz ve mesaj human-readable.
        byte[] originalData =
                "Mersel CAdES negative-test payload — tamper this and watch verifier scream.\n"
                        .getBytes(java.nio.charset.StandardCharsets.UTF_8);
        if (originalData.length < 32) {
            fail("Test payload çok kısa — tamper offset güvenli değil");
        }

        SignResponse signed = cadesSignatureService.signData(
                new ByteArrayInputStream(originalData),
                /*detached*/ true,
                defaultMaterial);

        assertNotNull(signed, "signResponse null olmamalı");
        byte[] p7s = signed.getSignedDocument();
        assertNotNull(p7s, ".p7s null olmamalı");
        assertTrue(p7s.length > 0, ".p7s boş olmamalı");

        // 1) Baseline: orijinal payload + .p7s VALID dönmeli.
        VerifierApiClient.VerificationResponse beforeResult = verifyOrAbort(
                p7s, originalData, "pre");
        assertTrue(beforeResult.isValid(),
                "Pre-tamper sanity: signer çıktısı VALID olmalı — "
                        + "negative test'in baseline'ı bozuk. response=" + beforeResult);

        SignedArtifactExporter.exportDetachedCmsPairWithVerification(
                p7s, originalData, "baseline", verificationReport(beforeResult));

        // 2) Tamper: orijinal payload'da bir byte'ı flip et. "tamper this"
        //    string'i içindeki 't' karakterini ASCII'de bir bit aşağı kaydır.
        byte[] tamperedData = originalData.clone();
        int tamperOffset = 25; // 'tamper this' kelimesinin yaklaşık başlangıcı
        byte before = tamperedData[tamperOffset];
        tamperedData[tamperOffset] ^= 0x01;
        LOGGER.info("CMS tamper: data[{}] 0x{} → 0x{}", tamperOffset,
                String.format("%02X", before),
                String.format("%02X", tamperedData[tamperOffset]));

        // 3) Verifier .p7s + tampered original ile çağrıldığında reddetmeli.
        VerifierApiClient.VerificationResponse afterResult = verifyOrAbort(
                p7s, tamperedData, "post");

        // Tampered payload'ı imza ile birlikte verify.json ile export —
        // negatif test kanıtı: openssl smime -verify FAIL döner; verifier
        // de aynı şekilde "expected failure" raporu verir.
        SignedArtifactExporter.exportWithVerification(
                SignedArtifactExporter.Format.CADES_NEGATIVE, p7s, "tampered-payload-p7s",
                verificationReportExpectingFailure(afterResult,
                        "CMS detached payload byte-flip (offset=" + tamperOffset
                                + "): SHA-256 digest mismatch beklenir"));

        assertFalse(afterResult.isValid(),
                "CMS data tamper sonrası verifier HÂLÂ VALID dönüyor — "
                        + "CAdES detached digest koruması çalışmıyor (REGRESYON). response="
                        + afterResult);

        if (afterResult.getSignatures().isEmpty()) {
            LOGGER.info("Tampered CMS: signature list boş — verifier imza bulamadı (acceptable)");
            return;
        }

        VerifierApiClient.SignatureInfo s = afterResult.getSignatures().get(0);
        VerifierApiClient.ValidationDetails d = s.getValidationDetails();
        assertNotNull(d, "validationDetails null — verifier şema bozulmuş olabilir");

        boolean intactFalse = !d.isSignatureIntact();
        boolean cryptoFalse = !d.isCryptographicVerificationSuccessful();
        boolean sigLevelInvalid = !s.isValid();

        if (!(intactFalse || cryptoFalse || sigLevelInvalid)) {
            fail("Tampered CMS: hiçbir flag 'invalid' demedi — "
                    + "signatureIntact=" + d.isSignatureIntact()
                    + ", cryptoOk=" + d.isCryptographicVerificationSuccessful()
                    + ", sigValid=" + s.isValid()
                    + ", indication=" + s.getIndication()
                    + ", sub=" + s.getSubIndication());
        }
        LOGGER.info("Tampered CMS reddedildi → intactFalse={}, cryptoFalse={}, "
                        + "sigLevelInvalid={}, indication={}/{}",
                intactFalse, cryptoFalse, sigLevelInvalid,
                s.getIndication(), s.getSubIndication());
    }

    private static VerifierApiClient.VerificationResponse verifyOrAbort(byte[] p7s,
                                                                       byte[] original,
                                                                       String label) {
        try {
            return verifierClient().verifyDetached(
                    p7s, "tampered-" + label + ".p7s",
                    original, "tampered-" + label + "-original.bin");
        } catch (VerifierApiClient.VerifierBackendUnavailable backendDown) {
            // JUnit 5.8 — Assumptions.abort yok; assumeTrue(false) ile aynı semantic.
            org.junit.jupiter.api.Assumptions.assumeTrue(false,
                    "Verifier backend CAdES'i ele alamadı (eksik DSS modülü), test skip: "
                            + backendDown.getMessage());
            return null; // unreachable
        }
    }
}
