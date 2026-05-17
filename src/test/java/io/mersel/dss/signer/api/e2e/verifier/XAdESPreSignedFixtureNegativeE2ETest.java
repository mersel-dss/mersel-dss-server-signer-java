package io.mersel.dss.signer.api.e2e.verifier;

import io.mersel.dss.signer.api.testsupport.SignedArtifactExporter;
import io.qameta.allure.Allure;
import io.qameta.allure.Description;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Link;
import io.qameta.allure.Owner;
import io.qameta.allure.Severity;
import io.qameta.allure.SeverityLevel;
import io.qameta.allure.Story;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Önceden imzalanmış (ama imzalandıktan sonra içeriği değiştirilmiş) bir
 * <b>external</b> XAdES dosyasını verifier-api'ye gönderir ve verifier'ın
 * imzayı reddettiğini doğrular.
 *
 * <h3>Senaryo</h3>
 * <p>Diğer XAdES negatif testler ({@link XAdESNegativeE2ETest}) "biz imzala
 * → biz tamper et → verify et" akışını koşar. Bu test farklıdır: <b>biz
 * imzalama yapmıyoruz</b>. Production-like bir akışı simüle ediyoruz:
 * dışarıdan gelen şüpheli bir XAdES dokümanı (manipüle edilmiş e-Fatura,
 * e-Arşiv vs.) verifier'a düşüyor. Fixture statik olarak commit edilmiş
 * (<code>resources/test-fixtures/xades/already-signed-but-not-valid.xml</code>):
 * gerçek bir KamuSM TEST CA imzalı UBL Invoice'tur, ama imzadan sonra
 * içerikteki bir veri değiştirildiği için reference digest mismatch
 * yaratır.</p>
 *
 * <h3>Beklenen davranış</h3>
 * <p>Verifier kripto matematiğini kontrol etmeli ve şu sinyallerden en az
 * birini üretmeli:</p>
 * <ul>
 *   <li>top-level <code>valid=false</code> ({@code overallValid}),</li>
 *   <li>signature {@code indication != TOTAL_PASSED} — tipik {@code TOTAL_FAILED}
 *       (sub: {@code HASH_FAILURE}) ya da {@code INDETERMINATE},</li>
 *   <li>{@code validationDetails.signatureIntact=false} veya
 *       {@code cryptographicVerificationSuccessful=false}.</li>
 * </ul>
 *
 * <h3>Auditor değeri</h3>
 * <p>"Production'da bu kadar açık bir tampered doküman gelse bizim verifier
 * yakalıyor mu?" sorusunun direkt kanıtı. Pages Evidence Site'taki
 * <code>xades-negative/</code> dump'ı ile auditor verifier yanıtını
 * (<code>.verify.json</code>) ve fixture'ı (<code>.xml</code>) yan yana
 * inceleyebilir.</p>
 *
 * <h3>Verifier backend unavailable handling</h3>
 * <p>Verifier image'ın downstream DSS modülü eksikse (XAdES için
 * {@code dss-xades} sınıf yükleme hatası, vs.) test
 * {@code Assumptions.abort(...)} ile <em>skip</em> edilir — fail değil.
 * Bu, başka subagent'lar paralel test koştururken false-negative
 * üretmemek için bilinçli karar (regression bizim repomuzda değil,
 * verifier image'dadır).</p>
 */
@Tag("verifier-e2e")
@Epic("Negative — Tampering")
@Feature("XAdES Pre-Signed Fixture (External)")
@Story("Post-Sign Content Mutation")
@Owner("dss-signer-core")
@Link(name = "ETSI EN 319 132-1 §5 (XAdES reference integrity)",
        url = "https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/")
@Link(name = "Fixture: resources/test-fixtures/xades/already-signed-but-not-valid.xml",
        url = "../../../../resources/test-fixtures/xades/already-signed-but-not-valid.xml")
@ExtendWith(SignedArtifactExporter.class)
class XAdESPreSignedFixtureNegativeE2ETest extends AbstractVerifierE2ETest {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(XAdESPreSignedFixtureNegativeE2ETest.class);

    /**
     * Statik fixture yolu — repo köküne göre (Maven test cwd = user.dir = repo root).
     * Bu dosya bilinçli olarak imzalandıktan sonra içeriği değiştirilmiş gerçek
     * bir UBL Invoice'tur; XAdES reference digest mismatch üretir.
     */
    private static final String FIXTURE_PATH =
            "resources/test-fixtures/xades/already-signed-but-not-valid.xml";

    @Test
    @DisplayName("Pre-signed XAdES fixture içeriği değiştirilmişse verifier reddetmeli")
    @Severity(SeverityLevel.BLOCKER)
    @Description(
            "**Senaryo**: KamuSM TEST CA imzalı gerçek bir UBL Invoice " +
            "(<code>already-signed-but-not-valid.xml</code>) — imzadan sonra " +
            "içerikteki bir veri değiştirildiği için reference digest mismatch " +
            "yaratıyor.<br><br>" +
            "**Diğer XAdES negatif testlerden farkı**: Biz imzalama yapmıyoruz, " +
            "biz sadece tampered external fixture'ı verifier'a yolluyoruz — " +
            "production'da \"dışarıdan gelen şüpheli e-Fatura\" akışını simüle eder.<br><br>" +
            "**Beklenen verifier davranışı** (en az biri):<br>" +
            "<ul>" +
            "<li><code>overallValid == false</code></li>" +
            "<li><code>indication != TOTAL_PASSED</code> " +
            "(tipik: <code>TOTAL_FAILED</code> sub <code>HASH_FAILURE</code>, " +
            "veya <code>INDETERMINATE</code>)</li>" +
            "<li><code>signatureIntact == false</code> veya " +
            "<code>cryptographicVerificationSuccessful == false</code></li>" +
            "</ul>")
    void preSignedTamperedFixtureRejectedByVerifier() throws Exception {
        Allure.parameter("fixturePath", FIXTURE_PATH);
        Allure.parameter("fixtureType", "Pre-signed external XAdES (UBL Invoice)");
        Allure.parameter("expectedRejectionReason", "HASH_FAILURE / TOTAL_FAILED / INDETERMINATE");

        // 1) Fixture'ı diskten oku — yoksa erken fail (regression / yanlış commit).
        byte[] xmlBytes = Allure.step("1) Tampered XAdES fixture'ı diskten oku", () -> {
            Path path = Paths.get(FIXTURE_PATH);
            assertTrue(Files.exists(path),
                    "Fixture eksik: " + path.toAbsolutePath()
                            + " — testin koşulması için bu dosya repo'da bulunmalı. "
                            + "Check: resources/test-fixtures/xades/already-signed-but-not-valid.xml");
            byte[] bytes = Files.readAllBytes(path);
            assertTrue(bytes.length > 0,
                    "Fixture boş; tampered XAdES içeriği bekleniyordu");
            Allure.parameter("fixtureSizeBytes", bytes.length);
            return bytes;
        });

        // 2) Verifier'a gönder; verifier-side DSS modülü eksikse skip et.
        VerifierApiClient.VerificationResponse response;
        try {
            response = Allure.step("2) Fixture'ı mersel-verifier-api'ye yolla", () ->
                    verifierClient().verify(xmlBytes, "already-signed-but-not-valid.xml"));
        } catch (VerifierApiClient.VerifierBackendUnavailable backendDown) {
            // JUnit 5.8 (Spring Boot parent) Assumptions.abort yok; assumeTrue(false)
            // ile TestAbortedException → test "skipped" raporlanır, fail değil.
            // Sorun bizim repo'da değil, verifier image'da.
            Assumptions.assumeTrue(false,
                    "Verifier backend XAdES'i ele alamadı (eksik DSS modülü), test skip: "
                            + backendDown.getMessage());
            return; // unreachable — assumeTrue(false) zaten throw eder
        }
        assertNotNull(response, "Verifier yanıtı null olmamalı");

        // 3) Signed artifact + .verify.json sidecar'ı evidence dizinine + Allure'a yaz.
        final VerifierApiClient.VerificationResponse responseRef = response;
        Allure.step("3) Signed artifact + .verify.json sidecar'ı export et", () ->
                SignedArtifactExporter.exportWithVerification(
                        SignedArtifactExporter.Format.XADES_NEGATIVE,
                        xmlBytes,
                        "pre-signed-tampered-fixture",
                        verificationReportExpectingFailure(responseRef,
                                "Pre-signed XAdES (KamuSM TEST CA imzalı UBL Invoice); "
                                        + "içerik imzadan sonra değiştirildi → "
                                        + "verifier reference digest matematiği fail etmeli "
                                        + "(HASH_FAILURE / TOTAL_FAILED / INDETERMINATE).")));

        // 4) Çok-yönlü reject kanıtı: top-level + signature-level + validation flags.
        Allure.step("4) Verifier reject kontratını doğrula "
                + "(overallValid, indication, validationDetails)", () -> {
            // 4a) Top-level "overall valid" false olmalı — verifier'ın en açık sinyali.
            assertFalse(responseRef.isValid(),
                    "Pre-signed tampered fixture verifier'dan PASSED geçti → "
                            + "REGRESYON / SAHTE-POZİTİF GÜVENLİK AÇIĞI. "
                            + "Verifier response.isValid()=true; bu tampered bir XAdES, "
                            + "kabul edilmemeli. response=" + responseRef);

            // 4b) Signature listesi boş olabilir (verifier imzayı hiç tanıyamadıysa)
            //     → bu da bir reject sinyali. Doluysa indication detayını inceliyoruz.
            if (responseRef.getSignatures().isEmpty()) {
                Allure.parameter("verifierObservedIndication", "(signature list empty)");
                LOGGER.info("Verifier signature listesi boş — imza tanınmadı (acceptable reject)");
                return;
            }

            VerifierApiClient.SignatureInfo first = responseRef.getSignatures().get(0);
            String indication = first.getIndication();
            String subIndication = first.getSubIndication();
            Allure.parameter("verifierObservedIndication", indication + " / " + subIndication);

            // 4c) indication TOTAL_PASSED olmamalı — bu negatif test'in özü.
            if ("TOTAL_PASSED".equals(indication)) {
                fail("Pre-signed tampered fixture verifier'da TOTAL_PASSED indication aldı — "
                        + "REGRESYON. Beklenen: TOTAL_FAILED veya INDETERMINATE. "
                        + "sub=" + subIndication
                        + ", sigValid=" + first.isValid()
                        + ", sigFormat=" + first.getSignatureFormat());
            }

            // 4d) Validation details — DSS hash-mismatch'i en az birinde göstermeli:
            //     signatureIntact=false (reference digest mismatch) veya
            //     cryptographicVerificationSuccessful=false (kripto pipeline fail).
            //     Bazı durumlarda details null olabilir; bu da implicit reject sayılır.
            VerifierApiClient.ValidationDetails details = first.getValidationDetails();
            if (details != null) {
                boolean signatureBroken = !details.isSignatureIntact()
                        || !details.isCryptographicVerificationSuccessful();
                boolean signatureLevelInvalid = !first.isValid();

                if (!signatureBroken && !signatureLevelInvalid) {
                    fail("Pre-signed tampered fixture: hiçbir validation flag 'invalid' demedi — "
                            + "signatureIntact=" + details.isSignatureIntact()
                            + ", cryptoOk=" + details.isCryptographicVerificationSuccessful()
                            + ", sigValid=" + first.isValid()
                            + ", indication=" + indication + "/" + subIndication
                            + " — verifier reject sinyali üretmedi. REGRESYON.");
                }

                LOGGER.info("Pre-signed tampered fixture: verifier doğru reddetti → "
                                + "indication={}/{}, sigIntact={}, cryptoOk={}, sigValid={}",
                        indication, subIndication,
                        details.isSignatureIntact(),
                        details.isCryptographicVerificationSuccessful(),
                        first.isValid());
            } else {
                LOGGER.info("Pre-signed tampered fixture: validationDetails null — "
                        + "indication={}/{} (top-level invalid yeterli kanıt)",
                        indication, subIndication);
            }
        });
    }
}
