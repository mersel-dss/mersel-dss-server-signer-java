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
import org.junit.jupiter.params.provider.EnumSource;

import java.io.ByteArrayInputStream;
import java.util.concurrent.Semaphore;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * PAdES için <b>PDF varyasyonu</b> sign+verify roundtrip testi.
 *
 * <h3>Amaç</h3>
 * <p>Farklı PDF yapılarının (multi-page, landscape, Türkçe karakter,
 * 50-sayfa) signer'ın ByteRange + signature dictionary yerleştirme
 * akışını bozmadığını test eder. Mevcut {@link PAdESSignAndVerifyE2ETest}
 * tek PDF (1-sayfa, programatik iText) × 5 PFX × 2 backend = 10 senaryo
 * PFX-key matriksini kapsar; bu sınıf <b>tamamlayıcı</b> PDF-content
 * regresyon vektörüdür.</p>
 *
 * <h3>Senaryo matrisi</h3>
 * <p>Tek RSA PFX × JCA backend × 4 fixture = <b>4 senaryo</b>. Key-tipinden
 * bağımsız (PDF-structure regression testi); 5×2 matriks CI yükü olur,
 * değer eklemez.</p>
 *
 * <h3>Fixture'lar</h3>
 * <p>Üretim detayı için {@link PadesDocumentFixture} Javadoc'una bakın —
 * 4 PDF iText 5.4.1 ile programatik üretildi, commit'lendi, generator
 * silindi.</p>
 */
@ExtendWith(SignedArtifactExporter.class)
@Epic("Signature Roundtrip")
@Feature("PAdES PDF Variations")
@Severity(SeverityLevel.NORMAL)
class PAdESDocumentVariationsE2ETest extends AbstractVerifierE2ETest {

    private static PAdESSignatureService padesSignatureService;
    private static SigningMaterial defaultMaterial;

    @BeforeAll
    static void initSigningStack() {
        padesSignatureService = new PAdESSignatureService(
                new Semaphore(2),
                new DigestAlgorithmResolverService());
        defaultMaterial = E2eSigningBackend.PFX_JCA.load(PfxTestKey.positiveValues()[0]);
    }

    @ParameterizedTest(name = "{0}")
    @EnumSource(PadesDocumentFixture.class)
    @DisplayName("PAdES PDF variation: 4 fixture × tek RSA PFX × JCA")
    void padesPdfRoundtripIsValid(PadesDocumentFixture fixture) {
        byte[] pdfBytes = fixture.readBytes();
        assertTrue(pdfBytes.length > 0, "PDF fixture boş olmamalı: " + fixture);

        // PDF magic byte sanity — yanlış dosya commit edilmişse erken fail.
        assertTrue(
                pdfBytes.length >= 4
                        && pdfBytes[0] == '%' && pdfBytes[1] == 'P'
                        && pdfBytes[2] == 'D' && pdfBytes[3] == 'F',
                "PDF magic byte (%PDF) bulunamadı: " + fixture
                        + " — fixture yanlış üretilmiş olabilir");

        SignResponse signed = padesSignatureService.signPdf(
                new ByteArrayInputStream(pdfBytes),
                /*attachment*/ null,
                /*attachmentFileName*/ null,
                /*appendMode*/ false,
                defaultMaterial);
        assertNotNull(signed, "signResponse null olmamalı: " + fixture);
        byte[] signedPdf = signed.getSignedDocument();
        assertNotNull(signedPdf, "imzalı PDF null olmamalı: " + fixture);
        // Signature dictionary + ByteRange + CMS pad: ~5-10 KB ek.
        assertTrue(signedPdf.length > pdfBytes.length,
                "imzalı PDF orijinalden büyük olmalı (" + fixture
                        + ", input=" + pdfBytes.length + ", signed=" + signedPdf.length + ")");

        // İmzalı PDF varyantını disk'e export et — Adobe Reader ile
        // landscape A3 / Türkçe karakter / 50-sayfa fixture'ların manuel
        // rendering + signature panel doğrulamasına imkân tanır.
        SignedArtifactExporter.export(SignedArtifactExporter.Format.PADES, signedPdf);

        VerifierApiClient.VerificationResponse result;
        try {
            result = verifierClient().verify(signedPdf, "variation-" + fixture.name() + ".pdf");
        } catch (VerifierApiClient.VerifierBackendUnavailable backendDown) {
            // JUnit 5.8 — Assumptions.abort yok; assumeTrue(false) ile aynı semantic.
            org.junit.jupiter.api.Assumptions.assumeTrue(false,
                    "Verifier backend PAdES'i ele alamadı (eksik DSS modülü, lokal-only), test skip: "
                            + backendDown.getMessage());
            return;
        }

        CAdESSignAndVerifyE2ETest.assertVerificationPassed(
                result, "PADES", PfxTestKey.positiveValues()[0],
                E2eSigningBackend.PFX_JCA + "/" + fixture.name());
    }
}
