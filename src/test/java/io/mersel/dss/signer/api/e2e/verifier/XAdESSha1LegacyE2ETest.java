package io.mersel.dss.signer.api.e2e.verifier;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import io.mersel.dss.signer.api.models.SigningMaterial;
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

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Legacy <b>SHA-1</b> ile imzalanmış bir XAdES belgenin verifier
 * tarafından <em>crypto policy gereği</em> kabul edildiğini test eder.
 *
 * <h3>Niye signer servisini bypass ediyoruz?</h3>
 * <p>Bu repo'nun ana <code>XAdESSignatureService</code>'i SHA-1 üretmez
 * (ürün davranışı zaten modern SHA-256+). Yani "signer SHA-1 üretirse..."
 * gibi bir senaryo <em>üretemeyiz</em>. Test ettiğimiz şey farklı:
 * <b>"Üçüncü taraf bir sistem SHA-1 imzalı bir XAdES gönderirse,
 * verifier-api'mizin crypto policy'si bunu kabul ediyor mu?"</b>
 * Türkiye'de hâlâ dolaşımda olan eski/legacy imzalarla geriye dönük
 * uyumluluk için verifier SHA-1'i kabul etmelidir.</p>
 *
 * <p>SHA-1 fixture'ını üretmek için DSS {@link XAdESService} API'sini
 * <em>doğrudan</em> ve <em>kasten</em> SHA-1 ile çağırıyoruz; bu sadece
 * test scope'unda yapılır, production kodunda bu çağrı yok.</p>
 *
 * <h3>Verifier davranış matrisi</h3>
 * <p>Verifier'ın crypto policy'si artık SHA-1'i kabul eder. Beklenen
 * sonuç:</p>
 * <ol>
 *   <li><code>valid=true</code> — SHA-1 legacy imza geriye dönük
 *       uyumluluk gereği kabul edilir. Uyarı eşlik etse de etmese de
 *       sorun yok.</li>
 * </ol>
 * <p><code>valid=false</code> (SHA-1 reddi) artık <b>kabul edilemez</b>;
 * çünkü kabul ettiğimiz politikaya göre bu bir regresyon. Test bu
 * durumda fail eder.</p>
 *
 * <h3>Tag stratejisi</h3>
 * <p>{@code "verifier-e2e"} — Docker tabanlı verifier-api gerekli;
 * single RSA PFX × JCA (SHA-1 zorlandığı için backend çeşitliliği değer
 * eklemez).</p>
 */
@ExtendWith(SignedArtifactExporter.class)
@Epic("Negative — Crypto Policy")
@Feature("XAdES Legacy SHA-1")
@Severity(SeverityLevel.NORMAL)
class XAdESSha1LegacyE2ETest extends AbstractVerifierE2ETest {

    private static final Logger LOGGER = LoggerFactory.getLogger(XAdESSha1LegacyE2ETest.class);

    private static XAdESService dssXadesService;
    private static SigningMaterial defaultMaterial;

    @BeforeAll
    static void initSigningStack() {
        dssXadesService = new XAdESService(newPermissiveVerifier());
        defaultMaterial = E2eSigningBackend.PFX_JCA.load(PfxTestKey.positiveValues()[0]);
    }

    @Test
    @DisplayName("SHA-1 ile imzalanmış XAdES verifier policy tarafından kabul edilir")
    void sha1XadesIsAcceptedByPolicy() {
        // 1) SHA-1 ile XAdES-BES üret. Bu code path SADECE bu test'te;
        //    production XAdESSignatureService'i SHA-1 üretmez.
        byte[] sha1Signed = signWithSha1();
        assertNotNull(sha1Signed, "SHA-1 imzalı XAdES üretilemedi");
        assertTrue(sha1Signed.length > 0, "SHA-1 imzalı çıktı boş");

        // Üçüncü taraf doğrulayıcılarla "modern policy SHA-1'i nasıl ele alır?"
        // sınamak için disk'e export et.
        SignedArtifactExporter.export(SignedArtifactExporter.Format.XADES_LEGACY, sha1Signed);

        // 2) Verifier'a gönder.
        VerifierApiClient.VerificationResponse result;
        try {
            result = verifierClient().verify(sha1Signed, "legacy-sha1.xml");
        } catch (VerifierApiClient.VerifierBackendUnavailable backendDown) {
            // JUnit 5.8 — Assumptions.abort yok; assumeTrue(false) ile aynı semantic.
            org.junit.jupiter.api.Assumptions.assumeTrue(false,
                    "Verifier backend XAdES'i ele alamadı (eksik modül), test skip: "
                            + backendDown.getMessage());
            return;
        }
        assertNotNull(result, "verifier yanıtı null");

        // 3) Beklenen davranış: SHA-1 legacy imza geriye dönük uyumluluk
        //    gereği KABUL edilir (valid=true). Uyarı eşlik etse de etmese
        //    de sorun yok; reddedilmesi ise regresyondur.
        if (result.isValid()) {
            boolean warnedAboutSha1 = mentionsSha1(result);
            if (warnedAboutSha1) {
                LOGGER.info("SHA-1 imzalı XAdES verifier tarafından KABUL edildi "
                                + "(valid=true), warning'de SHA-1 mention var. warnings={}",
                        extractWarnings(result));
            } else {
                LOGGER.info("SHA-1 imzalı XAdES verifier tarafından KABUL edildi "
                        + "(valid=true), uyarısız. Beklenen davranış.");
            }
            return;
        }

        fail("SHA-1 imzalı XAdES verifier tarafından REDDEDİLDİ — "
                + "ancak artık SHA-1 kabul ediyoruz, bu bir crypto policy "
                + "regresyonu. indication=" + (result.getSignatures().isEmpty() ? "—"
                : result.getSignatures().get(0).getIndication())
                + ", sub=" + (result.getSignatures().isEmpty() ? "—"
                : result.getSignatures().get(0).getSubIndication())
                + ", errors=" + extractErrors(result));
    }

    /**
     * DSS XAdESService'i SHA-1 + RSA_SHA1 ile çağırır. PFX/JCA yolu;
     * HSM ile aynı kontratı test etmek değil amaç (zaten DSS yolu ortak).
     */
    private static byte[] signWithSha1() {
        // Minimal UBL gibi bir XML payload; içerik önemli değil, sadece
        // verifier'ın algoritma tespiti çalışsın diye XAdES yapı korunsun.
        byte[] xml = (
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                        + "<doc xmlns=\"http://mersel.io/sha1-legacy-test\">"
                        + "<message>Bu belge SHA-1 ile imzalandı (test fixture).</message>"
                        + "</doc>"
        ).getBytes(java.nio.charset.StandardCharsets.UTF_8);

        DSSDocument original = new InMemoryDocument(xml, "legacy-sha1.xml");

        XAdESSignatureParameters params = new XAdESSignatureParameters();
        params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        params.setSignaturePackaging(SignaturePackaging.ENVELOPED);
        // ANA TWIST: SHA-1 hash + RSA-SHA1 imza algoritması zorla.
        params.setDigestAlgorithm(DigestAlgorithm.SHA1);
        params.setEncryptionAlgorithm(eu.europa.esig.dss.enumerations.EncryptionAlgorithm.RSA);

        params.setSigningCertificate(defaultMaterial.getPrimaryCertificateToken());
        List<eu.europa.esig.dss.model.x509.CertificateToken> chain =
                defaultMaterial.getCertificateTokens();
        params.setCertificateChain(chain);

        ToBeSigned tbs = dssXadesService.getDataToSign(original, params);
        // SignatureAlgorithm.RSA_SHA1 → SigningMaterial bunu PKCS#1 v1.5 RSA-SHA1
        // olarak imzalar; ECDSA / EdDSA olsaydı yine SHA-1 forced ama PFX'imiz RSA.
        byte[] rawSig = defaultMaterial.sign(tbs.getBytes(), SignatureAlgorithm.RSA_SHA1);
        SignatureValue sv = new SignatureValue(SignatureAlgorithm.RSA_SHA1, rawSig);

        DSSDocument signed = dssXadesService.signDocument(original, params, sv);
        // Java 8 — InputStream.readAllBytes() Java 9+; commons-io zaten classpath'te.
        try (java.io.InputStream in = signed.openStream()) {
            return org.apache.commons.io.IOUtils.toByteArray(in);
        } catch (java.io.IOException e) {
            throw new IllegalStateException("SHA-1 imzalı XAdES okunamadı", e);
        }
    }

    private static boolean mentionsSha1(VerifierApiClient.VerificationResponse r) {
        if (r.getWarnings().stream().anyMatch(XAdESSha1LegacyE2ETest::isSha1Mention)) {
            return true;
        }
        if (r.getErrors().stream().anyMatch(XAdESSha1LegacyE2ETest::isSha1Mention)) {
            return true;
        }
        for (VerifierApiClient.SignatureInfo s : r.getSignatures()) {
            if (s.getValidationWarnings().stream().anyMatch(XAdESSha1LegacyE2ETest::isSha1Mention)) {
                return true;
            }
            if (s.getValidationErrors().stream().anyMatch(XAdESSha1LegacyE2ETest::isSha1Mention)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isSha1Mention(String text) {
        if (text == null) return false;
        String upper = text.toUpperCase(java.util.Locale.ROOT);
        return upper.contains("SHA1") || upper.contains("SHA-1")
                || upper.contains("CRYPTO_CONSTRAINTS") || upper.contains("ALG_NOT_ALLOWED");
    }

    private static java.util.List<String> extractWarnings(VerifierApiClient.VerificationResponse r) {
        java.util.List<String> all = new java.util.ArrayList<>(r.getWarnings());
        for (VerifierApiClient.SignatureInfo s : r.getSignatures()) {
            all.addAll(s.getValidationWarnings());
        }
        return all;
    }

    private static java.util.List<String> extractErrors(VerifierApiClient.VerificationResponse r) {
        java.util.List<String> all = new java.util.ArrayList<>(r.getErrors());
        for (VerifierApiClient.SignatureInfo s : r.getSignatures()) {
            all.addAll(s.getValidationErrors());
        }
        return all;
    }
}
