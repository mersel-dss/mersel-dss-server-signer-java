package io.mersel.dss.signer.api.e2e.verifier;

import eu.europa.esig.dss.alert.SilentOnStatusAlert;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.condition.DisabledIfSystemProperty;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Verifier API ile çalışan tüm E2E test sınıflarının ortak base'i.
 *
 * <h3>Ne sağlar?</h3>
 * <ul>
 *   <li>{@link Tag} ile {@code "verifier-e2e"} etiketi — Surefire default'ta
 *       atlatır; sadece <code>mvn test -Dgroups=verifier-e2e -DexcludedGroups=</code>
 *       komutuyla koşulur.</li>
 *   <li>{@link DisabledIfSystemProperty} ile geliştirici makinesinde
 *       {@code -Dskip.verifier.e2e=true} flag'i ile devre dışı
 *       bırakılabilir.</li>
 *   <li>{@link #ensureDockerAvailable()} → Docker daemon erişilebilir değilse
 *       test'i fail değil, <b>skip</b> eder. CI'da Docker açıkken çalışır,
 *       CI'da Docker yoksa pas geçer.</li>
 *   <li>{@link #verifierClient()} → tüm sınıflarda paylaşılan singleton
 *       verifier-api client'ını döner.</li>
 * </ul>
 */
@Tag("verifier-e2e")
@Testcontainers
@DisabledIfSystemProperty(named = "skip.verifier.e2e", matches = "true")
public abstract class AbstractVerifierE2ETest {

    private static volatile VerifierApiClient CLIENT;

    @BeforeAll
    static void ensureDockerAvailable() {
        // Lokal Docker daemon yoksa testi sessiz pas geç. CI'da Docker varsa
        // bu assume true olur; geliştiri makinesinde Docker Desktop kapalıysa
        // false ve JUnit testi 'skipped' olarak raporlar (failure değil).
        assumeTrue(
                DockerClientFactory.instance().isDockerAvailable(),
                "Docker daemon erişilemiyor → verifier-e2e testleri atlandı");
    }

    /** Singleton verifier client (container ilk talep edildiğinde başlar). */
    protected static VerifierApiClient verifierClient() {
        if (CLIENT == null) {
            synchronized (AbstractVerifierE2ETest.class) {
                if (CLIENT == null) {
                    CLIENT = new VerifierApiClient(VerifierApiContainer.baseUrl());
                }
            }
        }
        return CLIENT;
    }

    /**
     * DSS {@link CommonCertificateVerifier} default'unda eksik revocation
     * data (CRL/OCSP), uncovered POE veya invalid timestamp durumlarında
     * imzalama daha başlamadan {@code AlertException} fırlatır
     * ("Revocation data is missing for one or more certificate(s)"). Test
     * ortamında CRL/OCSP responder ve TSA bulunmadığından bu kontroller
     * sürekli patlardı. Production'da bu kontroller
     * {@code CertificateValidatorService} tarafından zaten yapıldığı için
     * test JVM'inde DSS'in dahili pre-flight'ını sessize alıyoruz; ürün
     * davranışı değişmez.
     */
    protected static CertificateVerifier newPermissiveVerifier() {
        CommonCertificateVerifier verifier = new CommonCertificateVerifier();
        verifier.setAlertOnMissingRevocationData(new SilentOnStatusAlert());
        verifier.setAlertOnNoRevocationAfterBestSignatureTime(new SilentOnStatusAlert());
        verifier.setAlertOnRevokedCertificate(new SilentOnStatusAlert());
        verifier.setAlertOnInvalidTimestamp(new SilentOnStatusAlert());
        verifier.setAlertOnExpiredCertificate(new SilentOnStatusAlert());
        verifier.setAlertOnNotYetValidCertificate(new SilentOnStatusAlert());
        return verifier;
    }

    // ════════════════════════════════════════════════════════════════════
    //  Verification → Map helpers
    //  -----------------------------------------------------------------
    //  Pages "Evidence Site" üzerinde her imzalı artifact'in yanına
    //  .verify.json sidecar yazıyoruz. JSON içeriği bu helper'ların ürettiği
    //  Map<String, Object>'tan oluşur. LinkedHashMap kullanıyoruz ki insertion
    //  order korunsun; auditor JSON'ı açtığında "verifierName" en üstte
    //  görsün, "expectationMet" en altta.
    // ════════════════════════════════════════════════════════════════════

    /**
     * Positive test için verifier-api response'unu flatten Map'e çevirir.
     * Indication "TOTAL_PASSED" beklenir; expectationMet otomatik hesaplanır.
     */
    protected static Map<String, Object> verificationReport(
            VerifierApiClient.VerificationResponse response) {
        return verificationReport(response, "TOTAL_PASSED");
    }

    /**
     * Genel-amaçlı verification report builder — positive ve negative
     * testlerde aynı helper kullanılır. {@code expectedIndication} null/empty
     * ise expectation kontrolü atlanır (sadece raw response gösterilir).
     */
    protected static Map<String, Object> verificationReport(
            VerifierApiClient.VerificationResponse response,
            String expectedIndication) {
        Map<String, Object> report = new LinkedHashMap<>();
        report.put("verifierName", "mersel-verifier-api");
        try {
            report.put("verifierEndpoint", VerifierApiContainer.baseUrl());
        } catch (Throwable t) {
            report.put("verifierEndpoint", "n/a (container not started)");
        }
        report.put("validationTime", Instant.now().toString());

        if (response == null) {
            report.put("verifierResponseMissing", true);
            report.put("expectedIndication", expectedIndication);
            report.put("expectationMet", false);
            return report;
        }

        report.put("overallValid", response.isValid());
        report.put("overallStatus", response.getStatus());
        report.put("signatureType", response.getSignatureType());
        report.put("signatureCount", response.getSignatureCount());

        List<VerifierApiClient.SignatureInfo> sigs = response.getSignatures();
        if (sigs != null && !sigs.isEmpty()) {
            VerifierApiClient.SignatureInfo first = sigs.get(0);
            report.put("indication", first.getIndication());
            report.put("subIndication", first.getSubIndication());
            report.put("signatureFormat", first.getSignatureFormat());
            report.put("signatureLevel", first.getSignatureLevel());
            if (first.getSignerCertificate() != null) {
                Object subjectDn = first.getSignerCertificate().get("subjectDN");
                if (subjectDn != null) {
                    report.put("signedBy", subjectDn);
                }
                Object issuerDn = first.getSignerCertificate().get("issuerDN");
                if (issuerDn != null) {
                    report.put("issuer", issuerDn);
                }
            }
            if (first.getValidationDetails() != null) {
                VerifierApiClient.ValidationDetails d = first.getValidationDetails();
                Map<String, Object> details = new LinkedHashMap<>();
                details.put("signatureIntact", d.isSignatureIntact());
                details.put("certificateChainValid", d.isCertificateChainValid());
                details.put("certificateNotExpired", d.isCertificateNotExpired());
                details.put("certificateNotRevoked", d.isCertificateNotRevoked());
                details.put("trustAnchorReached", d.isTrustAnchorReached());
                details.put("timestampValid", d.isTimestampValid());
                details.put("cryptographicVerificationSuccessful",
                        d.isCryptographicVerificationSuccessful());
                details.put("revocationCheckPerformed", d.isRevocationCheckPerformed());
                report.put("validationDetails", details);
            }
            if (!first.getValidationErrors().isEmpty()) {
                report.put("validationErrors", first.getValidationErrors());
            }
            if (!first.getValidationWarnings().isEmpty()) {
                report.put("validationWarnings", first.getValidationWarnings());
            }
        }
        if (response.getErrors() != null && !response.getErrors().isEmpty()) {
            report.put("topLevelErrors", response.getErrors());
        }
        if (response.getWarnings() != null && !response.getWarnings().isEmpty()) {
            report.put("topLevelWarnings", response.getWarnings());
        }

        if (expectedIndication != null && !expectedIndication.isEmpty()) {
            String actualIndication = (String) report.get("indication");
            report.put("expectedIndication", expectedIndication);
            report.put("expectationMet", expectedIndication.equals(actualIndication));
        }
        return report;
    }

    /**
     * Negatif testler için verification report — tampered/wrap-attack/
     * signature-value-flipped örnekleri verifier'ın INVALID/INDETERMINATE
     * dönmesini bekler. expectedFailure=true + expectedFailureReason
     * alanları Pages'te "bu test bilinçli olarak FAIL üretti, kanıt da burada"
     * mesajını verir.
     *
     * @param response verifier-api response (null olabilir — VerifierBackend
     *                 unavailable durumunda)
     * @param reason   insan-okunabilir tamper açıklaması, örn.
     *                 "wrap-attack injection (XSW pattern)"
     */
    protected static Map<String, Object> verificationReportExpectingFailure(
            VerifierApiClient.VerificationResponse response, String reason) {
        Map<String, Object> report = verificationReport(response, null);
        report.put("expectedFailure", true);
        report.put("expectedFailureReason", reason);
        String actualIndication = (String) report.get("indication");
        // PASSED dönmemesi expectation — TOTAL_FAILED, INDETERMINATE,
        // veya cevap hiç dönmemesi (REVOKED/EXPIRED dahil) tümü "expected".
        report.put("expectationMet",
                actualIndication != null && !"TOTAL_PASSED".equals(actualIndication));
        return report;
    }
}
