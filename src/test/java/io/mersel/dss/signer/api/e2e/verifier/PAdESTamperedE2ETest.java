package io.mersel.dss.signer.api.e2e.verifier;

import io.mersel.dss.signer.api.models.SignResponse;
import io.mersel.dss.signer.api.models.SigningMaterial;
import io.mersel.dss.signer.api.services.crypto.DigestAlgorithmResolverService;
import io.mersel.dss.signer.api.services.signature.pades.PAdESSignatureService;
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
 * PAdES için <b>negatif</b> sign+verify roundtrip testi. İmzalı PDF'in
 * <code>ByteRange</code>'i içindeki bir byte mutate edilirse verifier
 * <b>"signature integrity broken"</b> raporlamalı.
 *
 * <h3>Pattern</h3>
 * <ol>
 *   <li>Boş bir PDF'i {@link PAdESSignatureService}'le imzala (PAdES-BASELINE-B).</li>
 *   <li>Sanity: imzalı PDF verifier'da VALID dön (baseline).</li>
 *   <li>PDF byte stream'inin başına yakın bir byte'ı flip et — bu bölge
 *       <code>ByteRange[0]–ByteRange[1]</code> kapsamındadır
 *       (signature dictionary'den önce). Flip imza kapsamındaki içeriği
 *       değiştirir → CMS detached SignedData digest mismatch.</li>
 *   <li>Verifier'a tekrar gönder; <code>signatureIntact=false</code> veya
 *       <code>valid=false</code> bekle.</li>
 * </ol>
 *
 * <h3>Neden ilk byte'a yakın?</h3>
 * <p>PAdES ByteRange iki segment kapsar: <code>[0, sigStart]</code> ve
 * <code>[sigEnd, eof]</code>. Signature dictionary PDF'in sonuna yakın
 * yer aldığı için ilk segment dosyanın büyük bölümünü kapsar; baştaki
 * herhangi bir mutasyon ByteRange dahilindedir. Tek byte flip (örn.
 * <code>byte[100] ^= 0x01</code>) görsel olarak invisible olsa da
 * cryptographically detected olur — bu yüzden PAdES vardır.</p>
 *
 * <h3>Tag stratejisi</h3>
 * <p>{@code "verifier-e2e"} — Docker tabanlı verifier-api gerekli.
 * Tek RSA PFX × JCA backend; tamper davranışı XML/PDF-level,
 * key-tipinden bağımsız.</p>
 */
@ExtendWith(SignedArtifactExporter.class)
@Epic("Negative — Tampering")
@Feature("PAdES ByteRange Tamper")
@Severity(SeverityLevel.CRITICAL)
class PAdESTamperedE2ETest extends AbstractVerifierE2ETest {

    private static final Logger LOGGER = LoggerFactory.getLogger(PAdESTamperedE2ETest.class);

    private static PAdESSignatureService padesSignatureService;
    private static SigningMaterial defaultMaterial;

    @BeforeAll
    static void initSigningStack() {
        padesSignatureService = new PAdESSignatureService(
                new Semaphore(2),
                new DigestAlgorithmResolverService());
        defaultMaterial = E2eSigningBackend.PFX_JCA.load(PfxTestKey.positiveValues()[0]);
    }

    @Test
    @DisplayName("Tampered-after-sign PDF: ByteRange içinde byte flip → verifier signatureIntact=false")
    void pdfTamperedAfterSignRejected() {
        byte[] pdfBytes = E2eFixtures.padesPdf();
        SignResponse signed = padesSignatureService.signPdf(
                new ByteArrayInputStream(pdfBytes),
                /*attachment*/ null,
                /*attachmentFileName*/ null,
                /*appendMode*/ false,
                defaultMaterial);

        assertNotNull(signed, "signResponse null olmamalı");
        byte[] signedPdf = signed.getSignedDocument();
        assertNotNull(signedPdf, "imzalı PDF null olmamalı");
        assertTrue(signedPdf.length > pdfBytes.length,
                "imzalı PDF orijinalden büyük olmalı");

        // 1) Baseline: tamper'sız PDF verifier'da VALID olmalı.
        VerifierApiClient.VerificationResponse beforeResult =
                verifyOrAbort(signedPdf, "pre");
        assertTrue(beforeResult.isValid(),
                "Pre-tamper sanity: signer çıktısı VALID olmalı — "
                        + "negative test'in baseline'ı bozuk. response=" + beforeResult);

        // Baseline imzalı PDF — Adobe Reader'da "valid" görmeli.
        SignedArtifactExporter.exportWithVerification(
                SignedArtifactExporter.Format.PADES, signedPdf, "baseline",
                verificationReport(beforeResult));

        // 2) Tamper: byte[100]'ün en alt bit'ini ters çevir.
        //    Bu offset PDF header + xref pre-content içinde (signature
        //    dictionary çok daha sonra başlar) — ByteRange dahilinde.
        if (signedPdf.length < 200) {
            fail("Test PDF'i beklenmedik şekilde küçük (" + signedPdf.length
                    + " byte) — byte[100] flip güvenli değil");
        }
        byte[] tampered = signedPdf.clone();
        byte original = tampered[100];
        tampered[100] ^= 0x01;
        LOGGER.info("PDF tamper: byte[100] 0x{} → 0x{}",
                String.format("%02X", original),
                String.format("%02X", tampered[100]));

        // 3) Verifier tampered PDF'i reddetmeli.
        VerifierApiClient.VerificationResponse afterResult =
                verifyOrAbort(tampered, "post");

        // Tampered PDF + verifier "expected failure" raporu — Adobe Reader'da
        // "signature is invalid / document has been altered" görmeli; Pages'te
        // verify.json'da expectedFailure=true, expectationMet=true.
        SignedArtifactExporter.exportWithVerification(
                SignedArtifactExporter.Format.PADES_NEGATIVE, tampered, "byte100-bitflip",
                verificationReportExpectingFailure(afterResult,
                        "PDF ByteRange içinde byte[100] bit-flip: signed range digest mismatch beklenir"));

        assertFalse(afterResult.isValid(),
                "PDF byte flip sonrası verifier HÂLÂ VALID dönüyor — "
                        + "PAdES ByteRange koruması çalışmıyor (REGRESYON). response="
                        + afterResult);

        if (afterResult.getSignatures().isEmpty()) {
            // PDF structure broken — imza listesi boş, valid=false yeterli signal.
            LOGGER.info("Tampered PDF: signature list boş — verifier imza bulamadı (acceptable)");
            return;
        }

        VerifierApiClient.SignatureInfo s = afterResult.getSignatures().get(0);
        VerifierApiClient.ValidationDetails d = s.getValidationDetails();
        assertNotNull(d, "validationDetails null — verifier şema bozulmuş olabilir");

        // Tipik PAdES tamper: signatureIntact veya cryptographicVerification
        // false olur. İkisinden birinin false olması yeterli.
        boolean intactFalse = !d.isSignatureIntact();
        boolean cryptoFalse = !d.isCryptographicVerificationSuccessful();
        boolean sigLevelInvalid = !s.isValid();

        if (!(intactFalse || cryptoFalse || sigLevelInvalid)) {
            fail("Tampered PDF: hiçbir flag 'invalid' demedi — "
                    + "signatureIntact=" + d.isSignatureIntact()
                    + ", cryptoOk=" + d.isCryptographicVerificationSuccessful()
                    + ", sigValid=" + s.isValid()
                    + ", indication=" + s.getIndication()
                    + ", sub=" + s.getSubIndication());
        }
        LOGGER.info("Tampered PDF reddedildi → intactFalse={}, cryptoFalse={}, "
                        + "sigLevelInvalid={}, indication={}/{}",
                intactFalse, cryptoFalse, sigLevelInvalid,
                s.getIndication(), s.getSubIndication());
    }

    private static VerifierApiClient.VerificationResponse verifyOrAbort(byte[] pdf, String label) {
        try {
            return verifierClient().verify(pdf, "tampered-" + label + ".pdf");
        } catch (VerifierApiClient.VerifierBackendUnavailable backendDown) {
            // JUnit 5.8 — Assumptions.abort yok; assumeTrue(false) ile aynı semantic.
            org.junit.jupiter.api.Assumptions.assumeTrue(false,
                    "Verifier backend PAdES'i ele alamadı (eksik DSS modülü), test skip: "
                            + backendDown.getMessage());
            return null; // unreachable
        }
    }
}
