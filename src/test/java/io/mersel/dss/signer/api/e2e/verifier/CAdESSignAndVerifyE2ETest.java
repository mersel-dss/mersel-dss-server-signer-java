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
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.ByteArrayInputStream;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CAdES için uçtan-uca sign → verify roundtrip testi.
 *
 * <h3>Senaryo matrisi</h3>
     * <p>5 test PFX × 2 backend (PFX/JCA, PFX-backed PKCS#11) × 2 mod
     * (attached/enveloping, detached) = 20 senaryo.</p>
 *
 * <p><b>Attached (enveloping)</b>: orijinal veri CMS zarfı içine gömülür.
 * Verifier'a sadece .p7s gönderilir; <code>originalDocument</code>
 * parametresi gerekmez.</p>
 *
 * <p><b>Detached</b>: yalnızca imza verisi üretilir; verifier'a hem .p7s
 * hem orijinal veri gönderilir.</p>
 *
 * <h3>Servis kurulumu</h3>
 * <p>Spring context yerine bağımlılıklar manuel kuruluyor — her test
 * minimum izolasyonla çalışır, Spring boot süresinden tasarruf edilir.
 * Production'da {@code SignatureConfiguration}'da kurulan bean grafının
 * birebir aynısı.</p>
 */
@ExtendWith(SignedArtifactExporter.class)
@Epic("Signature Roundtrip")
@Feature("CAdES Attached & Detached")
@Severity(SeverityLevel.CRITICAL)
class CAdESSignAndVerifyE2ETest extends AbstractVerifierE2ETest {

    private static CAdESSignatureService cadesSignatureService;

    @BeforeAll
    static void initSigningStack() {
        // DSS validation context — production'daki gibi minimum verifier;
        // imza üretimi için zaten zincir doğrulaması yapmaz.
        CommonCertificateVerifier verifier = new CommonCertificateVerifier();
        CAdESService cadesService = new CAdESService(verifier);

        SignatureAlgorithmResolverService sigAlgResolver = new SignatureAlgorithmResolverService();
        DigestAlgorithmResolverService digestResolver = new DigestAlgorithmResolverService();
        CryptoSignerService crypto = new CryptoSignerService(sigAlgResolver);

        cadesSignatureService = new CAdESSignatureService(
                cadesService, crypto, digestResolver,
                new java.util.concurrent.Semaphore(2));
    }

    static Stream<Arguments> pfxAndModeMatrix() {
        Stream.Builder<Arguments> b = Stream.builder();
        // Pozitif matriks: yalnızca Status.VALID PFX'ler. Lifecycle negatif
        // sertifikaları CertificateLifecycleNegativeE2ETest ele alır.
        for (PfxTestKey key : PfxTestKey.positiveValues()) {
            for (E2eSigningBackend backend : E2eSigningBackend.values()) {
                b.add(Arguments.of(key, backend, /*detached*/ false, "ATTACHED"));
                b.add(Arguments.of(key, backend, /*detached*/ true, "DETACHED"));
            }
        }
        return b.build();
    }

    @ParameterizedTest(name = "{index} → {0} / {1} / {3}")
    @MethodSource("pfxAndModeMatrix")
    @DisplayName("CAdES roundtrip: imzala → verifier-api'ye gönder → VALID dönmesi gerekir")
    void cadesRoundtripIsValid(PfxTestKey key,
                               E2eSigningBackend backend,
                               boolean detached,
                               String modeLabel) {
        SigningMaterial material = backend.load(key);
        byte[] data = E2eFixtures.cadesData();

        SignResponse signed = cadesSignatureService.signData(
                new ByteArrayInputStream(data), detached, material);

        assertNotNull(signed, "signResponse null olmamalı");
        assertNotNull(signed.getSignedDocument(), "signed bytes null olmamalı");
        assertTrue(signed.getSignedDocument().length > 0, "signed bytes boş olmamalı");

        VerifierApiClient.VerificationResponse result = detached
                ? verifierClient().verifyDetached(
                        signed.getSignedDocument(), "signed.p7s",
                        data, E2eFixtures.cadesFileName())
                : verifierClient().verify(signed.getSignedDocument(), "signed.p7s");

        // Imzalı dosya + payload (detached) + mersel-verifier-api response'unu
        // Pages "Evidence Site" için disk'e + Allure attachment olarak export et.
        // Verify'dan SONRA çağırıyoruz; sidecar JSON gerçek verifier sonucu.
        String exportLabel = key.name() + "_" + backend.name() + "_" + modeLabel;
        Map<String, Object> verifyReport = verificationReport(result);
        if (detached) {
            SignedArtifactExporter.exportDetachedCmsPairWithVerification(
                    signed.getSignedDocument(), data, exportLabel, verifyReport);
        } else {
            SignedArtifactExporter.exportWithVerification(
                    SignedArtifactExporter.Format.CADES_ATTACHED,
                    signed.getSignedDocument(), exportLabel, verifyReport);
        }

        assertVerificationPassed(result, "CADES", key, backend + "/" + modeLabel);
    }

    /**
     * Verifier yanıtı için ortak assertion'lar.
     *
     * <h3>Sıkı seviye: <code>valid=true</code> + <code>indication=TOTAL_PASSED</code></h3>
     * <p>Bu repo'nun sorumluluğu <b>imza üretimi</b>; ama "imzanın doğru
     * üretildiğinin" tek meşru ispatı verifier'ın <code>VALID</code> dönmesidir.
     * mersel-dss-verifier-api-java şu durumda artık:</p>
     * <ul>
     *   <li>KamuSM root'unu <code>trusted=true</code> olarak işaretliyor (29 root yükleniyor),</li>
     *   <li>Revocation eksikliğini fail değil <code>WARN</code> olarak ele alan
     *       <em>kamusm-permissive</em> validation policy kullanıyor,</li>
     *   <li>CAdES (dss-cms-object) ve PAdES (dss-pades-pdfbox) modüllerini içeriyor.</li>
     * </ul>
     * <p>Bu nedenle artık <code>isValid()</code>, <code>indication=TOTAL_PASSED</code>
     * ve granular flag'lerin tümünü birden talep ediyoruz. Bu, bir regresyon
     * tespitinin gerçek anlamı olmasını sağlar.</p>
     */
    static void assertVerificationPassed(VerifierApiClient.VerificationResponse result,
                                         String expectedType,
                                         PfxTestKey key,
                                         String modeLabel) {
        assertNotNull(result, "verifier yanıtı null");
        assertEquals(expectedType, result.getSignatureType(),
                "signatureType " + expectedType + " bekleniyor");
        assertFalse(result.getSignatures().isEmpty(),
                "imza listesi boş olmamalı");

        VerifierApiClient.SignatureInfo first = result.getSignatures().get(0);
        VerifierApiClient.ValidationDetails details = first.getValidationDetails();
        assertNotNull(details,
                "validationDetails dönmedi → verifier API kontrat değişmiş olabilir");

        String diag = String.format(
                "(%s / %s / %s) details=intact:%s,cryptoOk:%s,trustAnchor:%s,chainValid:%s,"
                        + "notExpired:%s,notRevoked:%s indication=%s sub=%s "
                        + "responseValid=%s sigValid=%s validationErrors=%s",
                expectedType, key, modeLabel,
                details.isSignatureIntact(),
                details.isCryptographicVerificationSuccessful(),
                details.isTrustAnchorReached(),
                details.isCertificateChainValid(),
                details.isCertificateNotExpired(),
                details.isCertificateNotRevoked(),
                first.getIndication(),
                first.getSubIndication(),
                result.isValid(),
                first.isValid(),
                first.getValidationErrors());

        // 1) Üst-seviye VALID — verifier'ın final kararı.
        assertTrue(result.isValid(),
                "verifier result.isValid()=true bekleniyor " + diag);
        assertTrue(first.isValid(),
                "imza-bazlı isValid()=true bekleniyor " + diag);

        // 2) DSS indication net olmalı.
        assertEquals("TOTAL_PASSED", first.getIndication(),
                "indication=TOTAL_PASSED bekleniyor " + diag);

        // 3) Bytes-level kripto doğrulaması.
        assertTrue(details.isCryptographicVerificationSuccessful(),
                "cryptographicVerificationSuccessful=true bekleniyor " + diag);

        // 4) Trust chain KamuSM kök'üne kadar build edilebilmeli.
        assertTrue(details.isTrustAnchorReached(),
                "trustAnchorReached=true bekleniyor " + diag);

        // 5) Sertifika süresi açısından sağlam (test PFX'leri 2026/2028'e kadar).
        assertTrue(details.isCertificateNotExpired(),
                "certificateNotExpired=true bekleniyor " + diag);
    }
}
