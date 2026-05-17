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
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.ByteArrayInputStream;
import java.util.concurrent.Semaphore;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * PAdES için uçtan-uca sign → verify roundtrip testi.
 *
 * <h3>Senaryo matrisi</h3>
     * <p>5 test PFX × 2 backend (PFX/JCA, PFX-backed PKCS#11) × 1 mod
     * (PDF embedded) = 10 senaryo.</p>
 *
 * <h3>Önemli not — PAdES seviyesi</h3>
 * <p>Bizim PAdES implementasyonumuz şu an sadece <b>PAdES-BASELINE-B</b>
 * üretiyor (timestamp/LT/LTA upgrade yok). Verifier
 * <code>level=COMPREHENSIVE</code> ile çağrıldığında {@code timestampInfo}
 * alanı {@code null} dönecek; bu beklenen davranış, assertion'lar buna
 * göre yazıldı. PAdES-T üretmeye başladığımızda assertion'lar genişletilebilir.</p>
 */
@ExtendWith(SignedArtifactExporter.class)
@Epic("Signature Roundtrip")
@Feature("PAdES Embedded PDF")
@Severity(SeverityLevel.CRITICAL)
class PAdESSignAndVerifyE2ETest extends AbstractVerifierE2ETest {

    private static PAdESSignatureService padesSignatureService;

    @BeforeAll
    static void initSigningStack() {
        DigestAlgorithmResolverService digestResolver = new DigestAlgorithmResolverService();
        padesSignatureService = new PAdESSignatureService(
                new Semaphore(2), digestResolver);
    }

    static Stream<Arguments> pfxAndBackendMatrix() {
        Stream.Builder<Arguments> b = Stream.builder();
        // Pozitif matriks: yalnızca Status.VALID PFX'ler. Lifecycle negatif
        // sertifikaları CertificateLifecycleNegativeE2ETest ele alır.
        for (PfxTestKey key : PfxTestKey.positiveValues()) {
            for (E2eSigningBackend backend : E2eSigningBackend.values()) {
                b.add(Arguments.of(key, backend));
            }
        }
        return b.build();
    }

    @ParameterizedTest(name = "{index} → {0} / {1}")
    @MethodSource("pfxAndBackendMatrix")
    @DisplayName("PAdES roundtrip: PDF imzala → verifier'a gönder → VALID dönmesi gerekir")
    void padesRoundtripIsValid(PfxTestKey key, E2eSigningBackend backend) {
        SigningMaterial material = backend.load(key);
        byte[] pdfBytes = E2eFixtures.padesPdf();
        assertTrue(pdfBytes.length > 0, "test PDF boş olmamalı");

        SignResponse signed = padesSignatureService.signPdf(
                new ByteArrayInputStream(pdfBytes),
                /*attachment*/ null,
                /*attachmentFileName*/ null,
                /*appendMode*/ false,
                material);

        assertNotNull(signed, "signResponse null olmamalı");
        assertNotNull(signed.getSignedDocument(), "imzalı PDF null olmamalı");
        assertTrue(signed.getSignedDocument().length > pdfBytes.length,
                "imzalı PDF en az orijinalden büyük olmalı");

        VerifierApiClient.VerificationResponse result =
                verifierClient().verify(signed.getSignedDocument(), E2eFixtures.padesFileName());

        // Imzalı PDF + mersel-verifier-api response'unu Pages için disk'e
        // + Allure attachment olarak export et. Adobe Acrobat Reader ile manuel
        // cross-validation için (Signature panel → "Signature is valid").
        SignedArtifactExporter.exportWithVerification(
                SignedArtifactExporter.Format.PADES, signed.getSignedDocument(),
                key.name() + "_" + backend.name() + "_embedded",
                verificationReport(result));

        CAdESSignAndVerifyE2ETest.assertVerificationPassed(result, "PADES", key, backend + "/EMBEDDED");
    }
}
