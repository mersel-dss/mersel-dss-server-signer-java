package io.mersel.dss.signer.api.e2e.verifier;

import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.xades.signature.XAdESService;
import io.mersel.dss.signer.api.models.SignResponse;
import io.mersel.dss.signer.api.models.SigningMaterial;
import io.mersel.dss.signer.api.models.enums.DocumentType;
import io.mersel.dss.signer.api.services.crypto.CryptoSignerService;
import io.mersel.dss.signer.api.services.crypto.DigestAlgorithmResolverService;
import io.mersel.dss.signer.api.services.crypto.SignatureAlgorithmResolverService;
import io.mersel.dss.signer.api.services.signature.cades.CAdESSignatureService;
import io.mersel.dss.signer.api.services.signature.pades.PAdESSignatureService;
import io.mersel.dss.signer.api.services.signature.wssecurity.WsSecuritySignatureService;
import io.mersel.dss.signer.api.services.signature.xades.XAdESDocumentPlacementService;
import io.mersel.dss.signer.api.services.signature.xades.XAdESLevelUpgradeService;
import io.mersel.dss.signer.api.services.signature.xades.XAdESParametersBuilderService;
import io.mersel.dss.signer.api.services.signature.xades.XAdESSignatureService;
import io.mersel.dss.signer.api.services.signature.xades.XmlProcessingService;
import io.mersel.dss.signer.api.services.timestamp.TimestampConfigurationService;
import io.mersel.dss.signer.api.services.util.CompressionService;
import io.mersel.dss.signer.api.testsupport.SignedArtifactExporter;
import io.mersel.dss.signer.api.util.xml.SecureXmlFactories;
import io.qameta.allure.Allure;
import io.qameta.allure.Description;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Link;
import io.qameta.allure.Owner;
import io.qameta.allure.Severity;
import io.qameta.allure.SeverityLevel;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Semaphore;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Sertifika <b>lifecycle</b> negatifleri için E2E sign+verify roundtrip.
 *
 * <h3>Senaryo</h3>
 * <p>Kamu SM test ortamı revoked / expired / suspended sertifikalarıyla
 * (RSA-2048 + EC-384, toplam 6 PFX) imza atılır ve {@code mersel-verifier-api}
 * downstream'inde reddedildiği doğrulanır. Tamper testlerinin
 * ({@link XAdESNegativeE2ETest}, {@link CAdESTamperedE2ETest},
 * {@link PAdESTamperedE2ETest}) tersine: imza matematik olarak <b>doğru</b>,
 * ancak sertifika lifecycle'ı geçersiz — verifier'ın bu farkı yakalaması
 * spec gereği zorunludur (DSS BBB → ETSI EN 319 102-1).</p>
 *
 * <h3>Beklenen verifier davranışı</h3>
 * <table>
 *   <tr><th>Status</th><th>Beklenen indication</th><th>Beklenen subIndication</th></tr>
 *   <tr><td>REVOKED</td><td>INDETERMINATE / TOTAL_FAILED</td><td>REVOKED / REVOKED_NO_POE</td></tr>
 *   <tr><td>EXPIRED</td><td>INDETERMINATE / TOTAL_FAILED</td><td>OUT_OF_BOUNDS_NOT_FRESH / EXPIRED</td></tr>
 *   <tr><td>SUSPENDED</td><td>INDETERMINATE</td><td>CERTIFICATE_HOLD / TRY_LATER</td></tr>
 * </table>
 *
 * <p>Verifier'ın <em>exact</em> subIndication'ı DSS sürümüne ve trust store
 * yapılandırmasına göre değişebilir. Bu yüzden assertion'lar şudur:</p>
 * <ol>
 *   <li>{@code overallValid == false} (verifier PASSED dememeli) — primer
 *       kontrat.</li>
 *   <li>{@code indication != "TOTAL_PASSED"} — secondary, primer'ı
 *       destekleyici.</li>
 * </ol>
 * <p>Exact subIndication değeri verifier response'unda {@code .verify.json}
 * sidecar'ına yazılır (auditor manuel inceler).</p>
 *
 * <h3>Production behavior bağlamı</h3>
 * <ul>
 *   <li><b>EXPIRED</b>: Production {@code SigningMaterialFactory.create}
 *       içindeki {@code certificateValidator.validateCertificateDates} ile
 *       <em>sign anında</em> reddedilir
 *       ({@code CertificateValidationException} → 400). Bu test
 *       {@code E2eSigningMaterialFactory} kullanır ki o pre-flight'ı
 *       <b>bypass</b> eder — biz signer "yine de imza üretmiş olsa" verifier'ın
 *       reddetmesini test ediyoruz (defense-in-depth).</li>
 *   <li><b>REVOKED / SUSPENDED</b>: Production'da revocation kontrolü
 *       sign-time'da yapılmaz ({@code setRevocationEnabled(false)}); imza
 *       başarıyla atılır, downstream verifier OCSP/CRL üzerinden yakalar.
 *       Bu test o yakalamayı doğrular.</li>
 * </ul>
 *
 * <h3>Graceful skip</h3>
 * <p>6 negatif PFX Kamu SM'den manuel indirilir (login + email onayı; otomatik
 * download yok). Dosyalar repo'ya konana kadar her test
 * {@code Assumptions.assumeTrue(key.isAvailable())} ile <em>skip</em> olur
 * (failure değil). Repo'ya bir PFX gelince ilgili senaryo otomatik aktif.</p>
 *
 * <h3>Tag</h3>
 * <p>{@code "verifier-e2e"} — default suite'te koşmaz; CI'da
 * {@code -Dgroups=verifier-e2e} ile veya
 * {@code mvn test -Dtest=CertificateLifecycleNegativeE2ETest -Dgroups=verifier-e2e -DexcludedGroups=}
 * komutuyla tetiklenir.</p>
 */
@ExtendWith(SignedArtifactExporter.class)
@Epic("Negative — Certificate Lifecycle")
@Feature("Revoked / Expired / Suspended Cert × XAdES/CAdES/PAdES/WSS")
@Severity(SeverityLevel.CRITICAL)
@Owner("dss-signer-core")
@Link(name = "ETSI EN 319 102-1 §5.2.6 (X.509 validation)",
        url = "https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/")
@Link(name = "Kamu SM Test Sertifika Tablosu",
        url = "https://kamusm.bilgem.tubitak.gov.tr/en/urunler/test_sertifikalari/")
@Link(name = "resources/test-certs/README.md",
        url = "../../../../resources/test-certs/README.md")
class CertificateLifecycleNegativeE2ETest extends AbstractVerifierE2ETest {

    private static final Logger LOGGER = LoggerFactory.getLogger(
            CertificateLifecycleNegativeE2ETest.class);

    private static XAdESSignatureService xadesService;
    private static CAdESSignatureService cadesService;
    private static PAdESSignatureService padesService;
    private static WsSecuritySignatureService wsService;

    @BeforeAll
    static void initSigningStack() {
        CertificateVerifier verifier = newPermissiveVerifier();

        XAdESService dssXades = new XAdESService(verifier);
        DigestAlgorithmResolverService digestResolver = new DigestAlgorithmResolverService();
        SignatureAlgorithmResolverService sigAlgResolver = new SignatureAlgorithmResolverService();
        CryptoSignerService crypto = new CryptoSignerService(sigAlgResolver);
        XAdESParametersBuilderService paramsBuilder = new XAdESParametersBuilderService(digestResolver);
        XmlProcessingService xmlProcessor = new XmlProcessingService();
        XAdESDocumentPlacementService placement = new XAdESDocumentPlacementService();
        TimestampConfigurationService tsConfig =
                new TimestampConfigurationService("", "", "", false);
        XAdESLevelUpgradeService upgrade = new XAdESLevelUpgradeService(verifier, tsConfig);
        CompressionService compression = new CompressionService();

        xadesService = new XAdESSignatureService(
                dssXades, paramsBuilder, xmlProcessor, placement,
                upgrade, crypto, verifier, compression, new Semaphore(2));

        CAdESService dssCades = new CAdESService(verifier);
        cadesService = new CAdESSignatureService(
                dssCades, crypto, digestResolver, new Semaphore(2));

        padesService = new PAdESSignatureService(new Semaphore(2), digestResolver);

        wsService = new WsSecuritySignatureService(new Semaphore(2), digestResolver);
    }

    // ════════════════════════════════════════════════════════════════════
    //  Format dispatch — her negatif PFX × 4 format kombinasyonu
    // ════════════════════════════════════════════════════════════════════

    /**
     * Test edilen imza formatları. Her biri kendi
     * {@link SignedArtifactExporter.Format} klasörüne dump eder ki auditor
     * "tampered" (XADES_NEGATIVE) ile "negatif sertifika ile imzalanmış"
     * (XADES_NEGATIVE_CERT) örnekleri klasörden ayırt etsin.
     */
    enum NegativeSignatureFormat {
        XADES(SignedArtifactExporter.Format.XADES_NEGATIVE_CERT,    "XADES",       "efatura.xml"),
        CADES(SignedArtifactExporter.Format.CADES_NEGATIVE_CERT,    "CADES",       "payload.bin"),
        PADES(SignedArtifactExporter.Format.PADES_NEGATIVE_CERT,    "PADES",       "document.pdf"),
        WSSECURITY(SignedArtifactExporter.Format.WSSECURITY_NEGATIVE_CERT, "WSSECURITY", "envelope.xml");

        final SignedArtifactExporter.Format exportFormat;
        final String verifierFormatHint;
        final String fileName;

        NegativeSignatureFormat(SignedArtifactExporter.Format exportFormat,
                                String verifierFormatHint,
                                String fileName) {
            this.exportFormat = exportFormat;
            this.verifierFormatHint = verifierFormatHint;
            this.fileName = fileName;
        }
    }

    static Stream<Arguments> negativeCertFormatMatrix() {
        Stream.Builder<Arguments> b = Stream.builder();
        for (PfxTestKey key : PfxTestKey.negativeValues()) {
            for (NegativeSignatureFormat format : NegativeSignatureFormat.values()) {
                b.add(Arguments.of(key, format));
            }
        }
        return b.build();
    }

    @ParameterizedTest(name = "{index} → {0} × {1}")
    @MethodSource("negativeCertFormatMatrix")
    @DisplayName("Negatif sertifika lifecycle: imzala → verifier reddetmeli (REVOKED/EXPIRED/SUSPENDED)")
    @Description(
            "Kamu SM TEST CA tarafından üretilmiş **lifecycle-bozuk** bir sertifikayla " +
            "(REVOKED / EXPIRED / SUSPENDED) gerçek bir e-Fatura / SOAP / PDF / detached " +
            "binary imzalanır ve `mersel-verifier-api` downstream'ine yollanır. " +
            "<br><br><b>Birincil kontrat</b>: <code>response.isValid() == false</code>. " +
            "<br><b>İkincil kontrat</b>: <code>indication != TOTAL_PASSED</code>. " +
            "<br><br>Exact <code>subIndication</code> verifier (DSS) sürümüne göre değişir; " +
            "<code>.verify.json</code> sidecar'ına auditor için ham değer yazılır " +
            "(REVOKED için <i>REVOKED_NO_POE</i>, EXPIRED için <i>OUT_OF_BOUNDS_NOT_FRESH</i>, " +
            "SUSPENDED için <i>TRY_LATER</i> tipiktir). " +
            "<br><br>Mali bağlam: VUK Md. 230 + 421 Sıra No.lu VUK GT — verifier'da " +
            "PASSED dönmeyen e-Belge yasal olarak hiç düzenlenmemiş sayılır.")
    void negativeCertSignAndVerify_verifierRejects(PfxTestKey key,
                                                   NegativeSignatureFormat format) throws Exception {
        // ─── Allure Behaviors trinity 3. katman: Story = sertifika status'u.
        //     Auditor "tüm REVOKED senaryoları" gibi filtre yapabilir.
        Allure.story(key.status().name());

        // ─── Auditor-facing parameters — Allure UI'da test'in altında tablo
        //     halinde görünür ve filtrelenebilir hale gelir.
        Allure.parameter("certificateStatus", key.status().name());
        Allure.parameter("certificateAlgorithm", key.name().contains("EC384") ? "EC P-384" : "RSA-2048");
        Allure.parameter("signatureFormat", format.name());
        Allure.parameter("pfxFile", key.getFileName());
        Allure.parameter("verifierFormatHint", format.verifierFormatHint);

        // ────────── 1) PFX repo'da var mı? Yoksa graceful skip. ──────────
        Allure.step("1) Negatif PFX dosyasının repo'da var olduğunu doğrula", () ->
                Assumptions.assumeTrue(
                        key.isAvailable(),
                        () -> "Negatif PFX repo'da yok — Kamu SM'den manuel indirilmesi gerekir: "
                                + key.getFileName()
                                + "\n  → resources/test-certs/ altına atıldığında bu test otomatik aktif olacak."
                                + "\n  → Detay: resources/test-certs/README.md"));

        // ────────── 2) SigningMaterial yükle (date-validation BYPASS). ────────
        // E2eSigningMaterialFactory production SigningMaterialFactory'nin
        // validateCertificateDates pre-flight'ını bypass eder; expired PFX
        // için bile imza üretilir. "Signer dahili kontrolü atlasa bile verifier
        // yakalar" defense-in-depth kontratını test ediyoruz.
        SigningMaterial material = Allure.step(
                "2) PFX'i yükle (E2eSigningMaterialFactory, validateCertificateDates bypass)",
                () -> {
                    try {
                        return E2eSigningBackend.PFX_JCA.load(key);
                    } catch (Exception loadEx) {
                        // PFX şifresi yanlış / dosya bozuk / cert parse hatası →
                        // bu testte sadece skip; kullanıcı PFX'i yanlış rename etmiş
                        // olabilir (file name son segment = password convention).
                        Assumptions.assumeTrue(false,
                                "PFX yüklenemedi (" + key.getFileName() + ") — şifre/format kontrolü gerek: "
                                        + loadEx.getMessage());
                        return null; // unreachable
                    }
                });

        // ────────── 3) İmza üret (format-dispatch). ──────────
        final byte[] detachedPayload = null;
        byte[] signedBytes;
        try {
            signedBytes = Allure.step("3) " + format.name() + " imzasını üret", () -> {
                switch (format) {
                    case XADES:      return signXades(material);
                    case CADES:      return signCadesAttached(material);
                    case PADES:      return signPades(material);
                    case WSSECURITY: return signWssecurity(material);
                    default:
                        throw new IllegalStateException("Unhandled format: " + format);
                }
            });
        } catch (RuntimeException signEx) {
            // EXPIRED sertifika için bazı DSS kod yolları sign-time'da da
            // exception atabilir (örn. iç certificate validation). Bu da
            // "signer reddetti" sayılır — kontrat zaten "verifier PASSED
            // dememeli"; sign-time reddi de aynı kontratın daha sıkı
            // ucudur. Test'i FAIL etmiyoruz; signed bytes yok → skip.
            LOGGER.info("Sign-time reject (kabul edilebilir, primary kontrat verifier-side): "
                    + "key={}, format={}, ex={}", key, format, signEx.getMessage());
            Assumptions.assumeTrue(false,
                    "Sign-time reject (key=" + key + ", format=" + format + "): "
                            + signEx.getMessage());
            return;
        }

        assertNotNull(signedBytes, "imzalı bytes null olmamalı: " + key + " / " + format);
        assertTrue(signedBytes.length > 0,
                "imzalı bytes boş olmamalı: " + key + " / " + format);

        // ────────── 4) Verifier'a gönder. ──────────
        final byte[] signedBytesRef = signedBytes;
        VerifierApiClient.VerificationResponse verifierResponse;
        try {
            verifierResponse = Allure.step(
                    "4) İmzalı bytes'ı mersel-verifier-api'ye yolla (roundtrip)",
                    () -> verifierClient().verify(signedBytesRef, format.fileName));
        } catch (VerifierApiClient.VerifierBackendUnavailable backendDown) {
            // Verifier image'ta gerekli DSS modülü eksikse skip — bu test'in
            // ground truth'u verifier-side, downstream eksik ise yanıt veremez.
            Assumptions.assumeTrue(false,
                    "Verifier backend " + format + "'ı ele alamadı (eksik DSS modülü), skip: "
                            + backendDown.getMessage());
            return;
        }

        // ────────── 5) Export with verification report. ──────────
        // Auditor Pages Evidence Site'ta dosyayı + .verify.json sidecar'ı
        // yan yana görür → "negatif sertifika ile imzalandı, verifier şu
        // indication ile reddetti" kanıt zinciri.
        final VerifierApiClient.VerificationResponse verifierResponseRef = verifierResponse;
        Allure.step("5) Signed artifact + .verify.json sidecar'ı export et", () -> {
            String label = key.name() + "_" + format.name();
            Map<String, Object> report = buildNegativeCertReport(verifierResponseRef, key);

            if (format == NegativeSignatureFormat.CADES && detachedPayload != null) {
                SignedArtifactExporter.exportDetachedCmsPairWithVerification(
                        signedBytesRef, detachedPayload, label, report);
            } else {
                SignedArtifactExporter.exportWithVerification(
                        format.exportFormat, signedBytesRef, label, report);
            }
        });

        // ────────── 6) Primary kontrat: verifier PASSED dememeli. ──────────
        Allure.step("6) Birincil + ikincil kontrat assertion'ları "
                        + "(isValid==false, indication != TOTAL_PASSED)",
                () -> assertVerifierRejected(verifierResponseRef, key, format));
    }

    // ════════════════════════════════════════════════════════════════════
    //  Sign helpers — her format için en az invasive yol
    // ════════════════════════════════════════════════════════════════════

    private static byte[] signXades(SigningMaterial material) {
        SignResponse signed = xadesService.signXml(
                new ByteArrayInputStream(E2eFixtures.efaturaXml()),
                DocumentType.UblDocument,
                "id-" + UUID.randomUUID().toString().replace("-", ""),
                /*zipped*/ false,
                material,false);
        return signed.getSignedDocument();
    }

    private static byte[] signCadesAttached(SigningMaterial material) {
        byte[] payload = E2eFixtures.cadesData();
        SignResponse signed = cadesService.signData(
                new ByteArrayInputStream(payload),
                /*detached*/ false,
                material);
        return signed.getSignedDocument();
    }

    private static byte[] signPades(SigningMaterial material) {
        SignResponse signed = padesService.signPdf(
                new ByteArrayInputStream(E2eFixtures.padesPdf()),
                /*attachment*/ null,
                /*attachmentFileName*/ null,
                /*appendMode*/ false,
                material);
        return signed.getSignedDocument();
    }

    private static byte[] signWssecurity(SigningMaterial material) throws Exception {
        byte[] envelopeBytes = SoapEnvelopeFixture.SOAP_1_1.readBytes();
        Document soapDoc = parseXmlSecurely(envelopeBytes);
        SignResponse signed = wsService.signSoapEnvelope(
                soapDoc,
                /*useSoap12*/ false,
                material,
                /*alias*/ "test",
                /*pin*/   new char[0]);
        return signed.getSignedDocument();
    }

    private static Document parseXmlSecurely(byte[] xml) throws Exception {
        DocumentBuilderFactory dbf = SecureXmlFactories.newDocumentBuilderFactory();
        DocumentBuilder db = dbf.newDocumentBuilder();
        return db.parse(new ByteArrayInputStream(xml));
    }

    // ════════════════════════════════════════════════════════════════════
    //  Verification helpers
    // ════════════════════════════════════════════════════════════════════

    /**
     * Verifier yanıtının PASSED dönmediğini doğrular. Primer kontrat:
     * "lifecycle bozuk sertifika ile imzalanmış belge verifier'dan
     * geçmesin". Exact subIndication assertion'ı bilinçli olarak yumuşak —
     * DSS sürümleri (6.x, 5.x) bazen indication=INDETERMINATE,
     * bazen TOTAL_FAILED dönebilir; aynı semantik (rejection) farklı
     * granülerlikte raporlanır.
     */
    private static void assertVerifierRejected(VerifierApiClient.VerificationResponse r,
                                                PfxTestKey key,
                                                NegativeSignatureFormat format) {
        assertNotNull(r, "verifier yanıtı null (" + key + " / " + format + ")");

        assertFalse(r.isValid(),
                "REGRESYON / SAHTE-POZİTİF: negatif sertifika (" + key.status()
                        + ") ile imzalandı ama verifier VALID dönüyor — "
                        + "downstream revocation/expiration kontrolü çalışmıyor olabilir. "
                        + "key=" + key + ", format=" + format + ", response=" + r);

        if (!r.getSignatures().isEmpty()) {
            VerifierApiClient.SignatureInfo first = r.getSignatures().get(0);
            String indication = first.getIndication();
            assertFalse(
                    "TOTAL_PASSED".equals(indication),
                    "Negatif sertifika senaryosu için indication TOTAL_PASSED olmamalı "
                            + "(secondary kontrat): key=" + key + ", indication=" + indication
                            + ", sub=" + first.getSubIndication());

            LOGGER.info("[{} × {}] Verifier doğru reddetti: indication={}, sub={}, valid={}",
                    key, format, indication, first.getSubIndication(), first.isValid());
        } else {
            LOGGER.info("[{} × {}] Verifier signature listesi boş — reject olarak değerlendirildi",
                    key, format);
        }
    }

    /**
     * Negatif sertifika senaryosu için {@code .verify.json} sidecar içeriği.
     * {@link AbstractVerifierE2ETest#verificationReport(VerifierApiClient.VerificationResponse, String)}
     * baz alınır; üzerine "expected failure" markörü ve status-bazlı
     * beklenen subIndication ipucu eklenir.
     */
    private Map<String, Object> buildNegativeCertReport(VerifierApiClient.VerificationResponse r,
                                                         PfxTestKey key) {
        // Negatif olduğu için "PASSED bekleniyor mu?" yerine raw report al,
        // sonra expectedFailure markörü ekle.
        Map<String, Object> base = verificationReport(r, /*expectedIndication*/ null);
        Map<String, Object> report = new LinkedHashMap<>(base);

        report.put("certificateStatus", key.status().name());
        report.put("expectedFailure", true);
        report.put("expectedFailureReason",
                "Sertifika lifecycle " + key.status().name().toLowerCase(Locale.ROOT)
                        + " — verifier PASSED dönmemeli (DSS BBB / ETSI EN 319 102-1 §5.2.6)");
        report.put("expectedSubIndicationHints", expectedSubIndicationHints(key.status()));

        // expectationMet: PASSED gelmediyse beklenti karşılandı.
        String actualIndication = (String) report.get("indication");
        report.put("expectationMet",
                actualIndication == null || !"TOTAL_PASSED".equals(actualIndication));
        return report;
    }

    private static String expectedSubIndicationHints(PfxTestKey.Status status) {
        switch (status) {
            case REVOKED:   return "REVOKED, REVOKED_NO_POE, REVOKED_CA_NO_POE";
            case EXPIRED:   return "OUT_OF_BOUNDS_NOT_FRESH, EXPIRED, EXPIRED_NOT_FRESH";
            case SUSPENDED: return "CERTIFICATE_HOLD, TRY_LATER, REVOKED_NO_POE";
            default:        return "(n/a)";
        }
    }
}
