package io.mersel.dss.signer.api.e2e.verifier;

import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.xades.signature.XAdESService;
import io.mersel.dss.signer.api.models.SignResponse;
import io.mersel.dss.signer.api.models.SigningMaterial;
import io.mersel.dss.signer.api.models.enums.DocumentType;
import io.mersel.dss.signer.api.services.crypto.CryptoSignerService;
import io.mersel.dss.signer.api.services.crypto.DigestAlgorithmResolverService;
import io.mersel.dss.signer.api.services.crypto.SignatureAlgorithmResolverService;
import io.mersel.dss.signer.api.services.signature.xades.XAdESDocumentPlacementService;
import io.mersel.dss.signer.api.services.signature.xades.XAdESLevelUpgradeService;
import io.mersel.dss.signer.api.services.signature.xades.XAdESParametersBuilderService;
import io.mersel.dss.signer.api.services.signature.xades.XAdESSignatureService;
import io.mersel.dss.signer.api.services.signature.xades.XmlProcessingService;
import io.mersel.dss.signer.api.services.timestamp.TimestampConfigurationService;
import io.mersel.dss.signer.api.services.util.CompressionService;
import io.mersel.dss.signer.api.testsupport.SignedArtifactExporter;
import io.mersel.dss.signer.api.util.xml.SecureXmlFactories;
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
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Base64;
import java.util.UUID;
import java.util.concurrent.Semaphore;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * XAdES için <b>negatif</b> sign+verify roundtrip testleri. Pozitif testlerin
 * ({@link XAdESSignAndVerifyE2ETest}) tersi: signer doğru bir imza üretsin,
 * sonra biz onu kasıtlı olarak boz, verifier <em>geçersiz</em> olduğunu
 * raporlamalı. "Verifier yanlış yere ses çıkarmıyor" diye kontrol etmenin
 * tek meşru yolu.
 *
 * <h3>Senaryolar</h3>
 * <ol>
 *   <li><b>wrap-attack</b> — imzalı XAdES'te body sub-tree'sine yeni bir
 *       element enjekte edilir (klasik XML signature wrap pattern'inin
 *       basit formu); verifier reference digest mismatch nedeniyle
 *       <code>HASH_FAILURE</code> (veya benzeri <code>INDETERMINATE</code>)
 *       dönmeli.</li>
 *   <li><b>tampered-after-sign</b> — imzalı XAdES'te bir text node değeri
 *       değiştirilir (UUID); verifier reference digest mismatch
 *       raporlamalı.</li>
 *   <li><b>signature-value-tampered</b> — <code>&lt;ds:SignatureValue&gt;</code>
 *       içinde bit-flip yapılır; verifier
 *       <code>cryptographicVerificationSuccessful=false</code> dönmeli.</li>
 * </ol>
 *
 * <h3>PFX/backend stratejisi</h3>
 * <p>Tüm negative testler tek RSA PFX × JCA backend ile koşar. Tamper
 * davranışı XML-level (key-tipinden bağımsız) olduğu için 5×2 matriks
 * gereksiz CI yükü olur — yine de ilk RSA PFX'in tüm sign akışını
 * çalıştırması "regresyon tespiti için yeterli signal" kontratını sağlar.</p>
 *
 * <h3>Neden runtime üretim?</h3>
 * <p>Statik commit yerine her testte fresh sign + tamper pattern:</p>
 * <ul>
 *   <li>Cert expire ettiğinde test kırılmaz — yeni test PFX'leri
 *       gelirse otomatik adapte olur.</li>
 *   <li>"Signer doğru imza üretti" sanity'sini aynı testte ölçer
 *       (pre-tamper assertion, ayrı pozitif test gerekmez).</li>
 *   <li>Verifier davranışını her zaman canlı sign akışıyla karşılaştırır.</li>
 * </ul>
 */
@ExtendWith(SignedArtifactExporter.class)
@Epic("Negative — Tampering")
@Feature("XAdES Wrap/Tamper/SigVal")
@Severity(SeverityLevel.CRITICAL)
class XAdESNegativeE2ETest extends AbstractVerifierE2ETest {

    private static final Logger LOGGER = LoggerFactory.getLogger(XAdESNegativeE2ETest.class);

    private static XAdESSignatureService xadesSignatureService;
    private static SigningMaterial defaultMaterial;

    @BeforeAll
    static void initSigningStack() {
        // Sign akışını XAdESSignAndVerifyE2ETest'tekiyle birebir kur — biz
        // signer behavior'unu test ediyoruz, oradaki stack ne ise burada da o.
        CertificateVerifier verifier = newPermissiveVerifier();
        XAdESService xadesService = new XAdESService(verifier);
        DigestAlgorithmResolverService digestResolver = new DigestAlgorithmResolverService();
        SignatureAlgorithmResolverService sigAlgResolver = new SignatureAlgorithmResolverService();
        CryptoSignerService crypto = new CryptoSignerService(sigAlgResolver);
        XAdESParametersBuilderService paramsBuilder = new XAdESParametersBuilderService(digestResolver);
        XmlProcessingService xmlProcessor = new XmlProcessingService();
        XAdESDocumentPlacementService placement = new XAdESDocumentPlacementService();
        TimestampConfigurationService tsConfig = new TimestampConfigurationService("", "", "", false);
        XAdESLevelUpgradeService upgrade = new XAdESLevelUpgradeService(verifier, tsConfig);
        CompressionService compression = new CompressionService();

        xadesSignatureService = new XAdESSignatureService(
                xadesService, paramsBuilder, xmlProcessor, placement,
                upgrade, crypto, verifier, compression,
                new Semaphore(2));

        defaultMaterial = E2eSigningBackend.PFX_JCA.load(PfxTestKey.positiveValues()[0]);
    }

    // ─────────────────────────────────────────────────────────────────
    // Senaryo 1: wrap-attack (XML signature wrap pattern, basit form)
    // ─────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("Wrap attack: signed UBL'e ekstra element enjekte edilirse verifier reddetmeli")
    void wrapAttackRejected() throws Exception {
        byte[] signedXml = signFixture(XadesDocumentFixture.EFATURA);

        // Pozitif sanity: ham imza önce VALID dönmeli — testin "tamper
        // gerçekten geçersiz yaptı" assertion'ı için baseline.
        VerifierApiClient.VerificationResponse beforeResult = verifyOrAbort(signedXml, "wrap-pre");
        assertValidBaseline(beforeResult, "wrap-attack pre-condition (signer çıktısı VALID olmalı)");

        SignedArtifactExporter.exportWithVerification(
                SignedArtifactExporter.Format.XADES, signedXml, "baseline",
                verificationReport(beforeResult));

        // Tamper: <ds:Signature>'nin signed scope'undaki bir element
        // (cbc:UUID) altına yabancı bir child element ekle. Reference URI=""
        // tüm dokümanı kapsadığı için bu enjeksiyon c14n + digest sırasında
        // farklı bayt akışı üretir → reference digest mismatch → INVALID.
        byte[] tamperedXml = injectWrapElement(signedXml,
                /*targetNs*/ "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
                /*targetLocal*/ "UUID",
                /*injectedXml*/ "<wrap:WrapAttackInjection xmlns:wrap=\"http://attacker.example.com\"/>");

        VerifierApiClient.VerificationResponse afterResult = verifyOrAbort(tamperedXml, "wrap-post");
        SignedArtifactExporter.exportWithVerification(
                SignedArtifactExporter.Format.XADES_NEGATIVE, tamperedXml, "wrap-attack",
                verificationReportExpectingFailure(afterResult,
                        "wrap-attack: cbc:UUID altına yabancı element enjekte; reference digest mismatch beklenir"));

        assertInvalidWithReason(afterResult,
                /*wantSignatureIntactFalse*/ true,
                /*wantCryptoFalseAllowed*/ true,
                "wrap-attack");
    }

    // ─────────────────────────────────────────────────────────────────
    // Senaryo 2: tampered-after-sign (body text mutation)
    // ─────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("Tampered-after-sign: signed UBL'de text content değiştirilirse verifier reddetmeli")
    void tamperedAfterSignRejected() throws Exception {
        byte[] signedXml = signFixture(XadesDocumentFixture.EFATURA);

        VerifierApiClient.VerificationResponse beforeResult = verifyOrAbort(signedXml, "tamper-pre");
        assertValidBaseline(beforeResult, "tampered-after-sign pre-condition (signer çıktısı VALID olmalı)");
        SignedArtifactExporter.exportWithVerification(
                SignedArtifactExporter.Format.XADES, signedXml, "baseline",
                verificationReport(beforeResult));

        // Tamper: UUID text content'ini mutate et — XAdES reference belge
        // tamamını içerdiği için bayt-bayt farklılaşır → digest mismatch.
        byte[] tamperedXml = mutateUuidText(signedXml,
                /*newValue*/ "ffffffff-ffff-ffff-ffff-ffffffffffff");

        VerifierApiClient.VerificationResponse afterResult = verifyOrAbort(tamperedXml, "tamper-post");
        SignedArtifactExporter.exportWithVerification(
                SignedArtifactExporter.Format.XADES_NEGATIVE, tamperedXml, "uuid-text-mutated",
                verificationReportExpectingFailure(afterResult,
                        "tampered-after-sign: imzalandıktan sonra UUID text content değiştirildi"));

        assertInvalidWithReason(afterResult,
                /*wantSignatureIntactFalse*/ true,
                /*wantCryptoFalseAllowed*/ true,
                "tampered-after-sign");
    }

    // ─────────────────────────────────────────────────────────────────
    // Senaryo 3: signature-value tampered (kripto bütünlüğü)
    // ─────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("SignatureValue bit-flip: kripto doğrulaması verifier'da BAŞARISIZ olmalı")
    void signatureValueTamperedRejected() throws Exception {
        byte[] signedXml = signFixture(XadesDocumentFixture.EFATURA);

        VerifierApiClient.VerificationResponse beforeResult = verifyOrAbort(signedXml, "sigval-pre");
        assertValidBaseline(beforeResult, "signature-value bit-flip pre-condition (signer VALID olmalı)");
        SignedArtifactExporter.exportWithVerification(
                SignedArtifactExporter.Format.XADES, signedXml, "baseline",
                verificationReport(beforeResult));

        // Tamper: SignatureValue base64'ünü decode et, ilk byte'ı flip et,
        // tekrar encode et. Hash matematiği değişmediği için reference
        // digest aynı; ama kripto verify FAİL eder
        // (cryptographicVerificationSuccessful=false).
        byte[] tamperedXml = flipSignatureValueFirstBit(signedXml);

        VerifierApiClient.VerificationResponse afterResult = verifyOrAbort(tamperedXml, "sigval-post");
        SignedArtifactExporter.exportWithVerification(
                SignedArtifactExporter.Format.XADES_NEGATIVE, tamperedXml, "signature-value-bitflip",
                verificationReportExpectingFailure(afterResult,
                        "signature-value bit-flip: SignatureValue base64'ünün ilk byte'ı flip; kripto verify FAIL beklenir"));

        assertInvalidWithReason(afterResult,
                /*wantSignatureIntactFalse*/ false, // reference digest hala doğru olabilir
                /*wantCryptoFalseAllowed*/ true,    // ama kripto verify mutlaka false
                "signature-value-tampered");
    }

    // ─────────────────────────────────────────────────────────────────
    // Sign + verify helper'ları
    // ─────────────────────────────────────────────────────────────────

    private static byte[] signFixture(XadesDocumentFixture fixture) {
        byte[] xmlBytes = fixture.readBytes();
        String signatureId = "id-" + UUID.randomUUID().toString().replace("-", "");
        SignResponse signed = xadesSignatureService.signXml(
                new ByteArrayInputStream(xmlBytes),
                fixture.getDocumentType(),
                signatureId,
                /*zipped*/ false,
                defaultMaterial,false);
        assertNotNull(signed, "signResponse null olmamalı");
        byte[] signedBytes = signed.getSignedDocument();
        assertNotNull(signedBytes, "imzalı XML null olmamalı");
        assertTrue(signedBytes.length > 0, "imzalı XML boş olmamalı");
        return signedBytes;
    }

    /**
     * Verifier'a gönder; lokal verifier image'da XAdES modülü eksikse
     * test'i skip et (CI'da GHCR image'da modül var; lokal-only durum).
     */
    private static VerifierApiClient.VerificationResponse verifyOrAbort(byte[] signed, String label) {
        try {
            return verifierClient().verify(signed, "negative-" + label + ".xml");
        } catch (VerifierApiClient.VerifierBackendUnavailable backendDown) {
            // JUnit 5.8 (Spring Boot parent) — Assumptions.abort yok; assumeTrue(false)
            // aynı semantic ile TestAbortedException fırlatır → skip.
            org.junit.jupiter.api.Assumptions.assumeTrue(false,
                    "Verifier backend XAdES'i ele alamadı (eksik DSS modülü), test skip: "
                            + backendDown.getMessage());
            return null; // unreachable
        }
    }

    private static void assertValidBaseline(VerifierApiClient.VerificationResponse r, String diag) {
        assertNotNull(r, "verifier yanıtı null (" + diag + ")");
        assertTrue(r.isValid(),
                "Tamper-öncesi sanity: signer çıktısı VALID dönmedi — "
                        + "negative test'in baseline'ı çalışmıyor. (" + diag + ")");
    }

    /**
     * Verifier'ın "geçersiz" raporladığını çoklu yoldan onayla. DSS hem
     * "hash mismatch" hem "crypto failure" varyantını farklı flag'lerle
     * raporlayabilir — biri yeterli, ama hiçbiri yoksa test FAIL.
     */
    private static void assertInvalidWithReason(VerifierApiClient.VerificationResponse r,
                                                boolean wantSignatureIntactFalse,
                                                boolean wantCryptoFalseAllowed,
                                                String scenario) {
        assertNotNull(r, "verifier yanıtı null (" + scenario + ")");
        assertFalse(r.isValid(),
                scenario + ": tamper sonrası verifier hâlâ VALID dönüyor — "
                        + "REGRESYON / SAHTE-POZİTİF GÜVENLİK AÇIĞI. response=" + r);

        if (r.getSignatures().isEmpty()) {
            // Bazı tamper'lar imzayı tanınmaz hale getirebilir; bu da geçerli
            // bir "reject" sinyalidir (signature listesi boş = "imza bulunamadı").
            LOGGER.info("{}: imza listesi boş — verifier imzayı reddetti (acceptable)",
                    scenario);
            return;
        }

        VerifierApiClient.SignatureInfo s = r.getSignatures().get(0);
        VerifierApiClient.ValidationDetails d = s.getValidationDetails();
        assertNotNull(d, scenario + ": validationDetails null — verifier şemasında "
                + "bozulma olabilir");

        boolean intactFalse = !d.isSignatureIntact();
        boolean cryptoFalse = !d.isCryptographicVerificationSuccessful();
        boolean signatureLevelInvalid = !s.isValid();

        boolean rejectedAtSomeLevel = signatureLevelInvalid
                || (wantSignatureIntactFalse && intactFalse)
                || (wantCryptoFalseAllowed && cryptoFalse);

        if (!rejectedAtSomeLevel) {
            fail(scenario + ": tamper sonrası hiçbir flag 'invalid' demedi — "
                    + "signatureIntact=" + d.isSignatureIntact()
                    + ", cryptoOk=" + d.isCryptographicVerificationSuccessful()
                    + ", sigValid=" + s.isValid()
                    + ", indication=" + s.getIndication()
                    + ", sub=" + s.getSubIndication());
        }

        LOGGER.info("{}: verifier doğru reddetti — intactFalse={}, cryptoFalse={}, "
                        + "sigLevelInvalid={}, indication={}/{}",
                scenario, intactFalse, cryptoFalse, signatureLevelInvalid,
                s.getIndication(), s.getSubIndication());
    }

    // ─────────────────────────────────────────────────────────────────
    // DOM mutation utilities (XXE-safe parser kullanır)
    // ─────────────────────────────────────────────────────────────────

    /**
     * UBL içine yabancı bir element enjekte eder (target element'in altına
     * yeni child olarak). Hedef element bulunamazsa testi başarısız bırakır.
     */
    private static byte[] injectWrapElement(byte[] signedXml,
                                            String targetNs,
                                            String targetLocal,
                                            String injectedXml) throws Exception {
        Document doc = parseSecurely(signedXml);
        NodeList nodes = doc.getElementsByTagNameNS(targetNs, targetLocal);
        if (nodes.getLength() == 0) {
            fail("Wrap target bulunamadı: {" + targetNs + "}" + targetLocal
                    + " — fixture beklenenden farklı yapıda");
        }
        Element target = (Element) nodes.item(0);

        // Inject string'i ayrı parse edip target altına node-import et.
        Document injected = parseSecurely(
                ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>" + injectedXml)
                        .getBytes(java.nio.charset.StandardCharsets.UTF_8));
        org.w3c.dom.Node imported = doc.importNode(injected.getDocumentElement(), true);
        target.appendChild(imported);

        return serialize(doc);
    }

    /**
     * UBL cbc:UUID text node'unu yeni bir değerle değiştirir. Reference
     * URI="" (tüm doc) kapsadığı için bu değişiklik byte akışını değiştirir.
     */
    private static byte[] mutateUuidText(byte[] signedXml, String newValue) throws Exception {
        Document doc = parseSecurely(signedXml);
        NodeList list = doc.getElementsByTagNameNS(
                "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
                "UUID");
        if (list.getLength() == 0) {
            fail("cbc:UUID element bulunamadı — fixture beklenenden farklı yapıda");
        }
        Element uuid = (Element) list.item(0);
        uuid.setTextContent(newValue);
        return serialize(doc);
    }

    /**
     * &lt;ds:SignatureValue&gt; base64'ünü decode eder, ilk byte'ı flip eder,
     * tekrar encode eder. Reference digest'leri sağlam kalır; sadece kripto
     * verify bozulur. Verifier <code>cryptographicVerificationSuccessful=false</code>
     * dönmeli.
     */
    private static byte[] flipSignatureValueFirstBit(byte[] signedXml) throws Exception {
        Document doc = parseSecurely(signedXml);
        NodeList list = doc.getElementsByTagNameNS(
                "http://www.w3.org/2000/09/xmldsig#", "SignatureValue");
        if (list.getLength() == 0) {
            fail("ds:SignatureValue bulunamadı — imzalı çıktı beklenmedik şekilde");
        }
        Element sigValue = (Element) list.item(0);
        String b64 = sigValue.getTextContent().replaceAll("\\s", "");
        byte[] rawSig = Base64.getDecoder().decode(b64);
        if (rawSig.length == 0) {
            fail("SignatureValue boş");
        }
        rawSig[0] ^= 0x01; // ilk byte'ın en alt bit'ini ters çevir
        sigValue.setTextContent(Base64.getEncoder().encodeToString(rawSig));
        return serialize(doc);
    }

    private static Document parseSecurely(byte[] xml) throws Exception {
        DocumentBuilderFactory dbf = SecureXmlFactories.newDocumentBuilderFactory();
        DocumentBuilder db = dbf.newDocumentBuilder();
        return db.parse(new ByteArrayInputStream(xml));
    }

    private static byte[] serialize(Document doc) throws Exception {
        TransformerFactory tf = SecureXmlFactories.newTransformerFactory();
        Transformer transformer = tf.newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
        transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(doc), new StreamResult(out));
        return out.toByteArray();
    }

    /**
     * XAdES BASELINE_B'nin {@link DocumentType#UblDocument} olarak imzalanması
     * için EFATURA fixture'ı kullanılır — sign akışı production paritesi.
     * Diğer fixture'ları kullanmak teste değer eklemez (tamper davranışı
     * fixture-agnostic).
     */
    @SuppressWarnings("unused")
    private static XadesDocumentFixture defaultFixture() {
        return XadesDocumentFixture.EFATURA;
    }
}
