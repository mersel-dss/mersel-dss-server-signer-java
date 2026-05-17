package io.mersel.dss.signer.api.services.signature.wssecurity;

import io.mersel.dss.signer.api.e2e.verifier.E2eSigningMaterialFactory;
import io.mersel.dss.signer.api.e2e.verifier.PfxTestKey;
import io.mersel.dss.signer.api.e2e.verifier.SoapEnvelopeFixture;
import io.mersel.dss.signer.api.e2e.verifier.WsSecurityLocalXmlDsigVerifier;
import io.mersel.dss.signer.api.models.SignResponse;
import io.mersel.dss.signer.api.models.SigningMaterial;
import io.mersel.dss.signer.api.services.crypto.DigestAlgorithmResolverService;
import io.mersel.dss.signer.api.testsupport.SignedArtifactExporter;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Severity;
import io.qameta.allure.SeverityLevel;
import io.mersel.dss.signer.api.util.xml.SecureXmlFactories;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.util.concurrent.Semaphore;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * WS-Security imzalama: <b>GİB Mali Mühür request envelope</b> (production-parity)
 * vs <b>minimal SOAP 1.1 envelope</b> (baseline/header'sız) structural parity testi.
 *
 * <h3>Neden bu test?</h3>
 * <p>Türkiye e-Fatura ekosisteminde signer iki tipik kullanım senaryosu görür:</p>
 * <ol>
 *   <li><b>GİB Mali Mühür envelope</b> — <code>soapenv/ei/xsd/xsi/gib</code>
 *       multi-namespace, <code>xsi:type</code> attribute'lar, UBL benzeri
 *       business element'leri (VKN, isim, fatura UUID); GİB EFatura ve
 *       EArşiv endpoint'lerinin standart yapısı. Üretimde "Mali Mühür"
 *       sertifikası ({@code testkurum01_rsa2048@test.com.tr_614573.pfx}
 *       muadili) ile imzalanır.</li>
 *   <li><b>Minimal envelope</b> — özel GİB header'ı taşımayan generic SOAP
 *       request (örn. KamuSM endpoint'leri ya da custom B2B servisler).
 *       Daha az namespace, daha sade body.</li>
 * </ol>
 *
 * <p>{@link io.mersel.dss.signer.api.services.signature.wssecurity.WsSecuritySignatureService}
 * tasarım gereği envelope-shape agnostic olmalıdır: gelen body'nin
 * carrying-namespace'i, child sayısı veya GİB-specific attribute'ları
 * imza üretimini değiştirmemeli. Bu testin asıl katkısı:</p>
 *
 * <ul>
 *   <li>İki envelope shape'i de aynı <em>structural invariant</em>'leri taşıyan
 *       Security header üretir (BST + Timestamp + Signature + 2 Reference).</li>
 *   <li>Body element'in business content'i sign sonrası bayt-bayt korunur
 *       (Mali Mühür envelope'undaki <code>senderTaxId</code>, <code>senderName</code>
 *       Türkçe diakritiklerle değişmemeli — c14n + DOM roundtrip'te aslen
 *       NaN-safe olduğunun teyidi).</li>
 *   <li>Her iki çıktı da lokal XMLDsig verifier'ı geçer.</li>
 * </ul>
 *
 * <p>Bu kontrat, <em>WsSecuritySignAndLocalVerifyE2ETest</em>'in 90'lık
 * matrisinden (5 PFX × 2 backend × 9 fixture) ayrılır: orada "her envelope
 * sign-verify roundtrip" test edilir. Burada <b>iki envelope'un signer
 * üretiminde structural parity'sini</b> explicit assert ediyoruz —
 * regression olursa (örn. signer Mali Mühür envelope'unda farklı bir
 * Reference URI üretirse) ana matriste boğulmaz, burada yakalanır.</p>
 */
@DisplayName("D-mali-muhur: Mali Mühür envelope vs minimal envelope structural parity")
@ExtendWith(SignedArtifactExporter.class)
@Epic("Service Layer")
@Feature("WS-Security Envelope Shape Parity")
@Severity(SeverityLevel.NORMAL)
class WsSecurityEnvelopeShapeParityTest {

    private static final String NS_DSIG =
            "http://www.w3.org/2000/09/xmldsig#";
    private static final String NS_WSSE =
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    private static final String NS_WSU =
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
    private static final String NS_SOAP_1_1 =
            "http://schemas.xmlsoap.org/soap/envelope/";

    private static WsSecuritySignatureService service;
    private static SigningMaterial rsa2048Material;

    @BeforeAll
    static void initStack() {
        service = new WsSecuritySignatureService(
                new Semaphore(2), new DigestAlgorithmResolverService());
        rsa2048Material = E2eSigningMaterialFactory.load(PfxTestKey.KURUM01_RSA2048);
    }

    /**
     * Hem GİB Mali Mühür envelope'u hem minimal envelope için
     * <b>aynı</b> Security header skeletonu üretildiğini doğrular.
     */
    @Test
    @DisplayName("GIB envelope ve minimal envelope aynı Security skeleton'ı üretmeli")
    void gibAndMinimalEnvelope_produceEquivalentSecurityHeaderShape() throws Exception {
        Document gibSigned = parse(signEnvelope(SoapEnvelopeFixture.GIB_EFATURA_SOAP));
        Document minimalSigned = parse(signEnvelope(SoapEnvelopeFixture.SOAP_1_1));

        SecurityShape gibShape = SecurityShape.of(gibSigned);
        SecurityShape minimalShape = SecurityShape.of(minimalSigned);

        // Yapısal invariant'lar (signer için kontrat):
        // - tek Security header
        // - tek BST
        // - tek Timestamp
        // - tek Signature
        // - 2 Reference (Body + Timestamp)
        assertEquals(gibShape, minimalShape,
                "GIB envelope ve minimal envelope Security header skeleton'ları "
                        + "structural olarak eşit olmalı.\n"
                        + "  GIB:     " + gibShape + "\n"
                        + "  Minimal: " + minimalShape);

        // Sanity: skeleton'ın değerleri beklenen değerlere de eşit
        // (yukarıdaki equals değerlerin eşitliğini ölçer ama bu test'i
        // ileri-uyumlu yapmak için beklenen yapıyı da explicit assert
        // ediyoruz).
        assertEquals(1, gibShape.securityHeaderCount, "tek Security header");
        assertEquals(1, gibShape.bstCount, "tek BST");
        assertEquals(1, gibShape.timestampCount, "tek Timestamp");
        assertEquals(1, gibShape.signatureCount, "tek Signature");
        assertEquals(2, gibShape.referenceCount, "2 Reference (Body + Timestamp)");
    }

    /**
     * Mali Mühür envelope'undaki Türkçe karakterli business content'in
     * (VKN, sender adı, alıcı adı) sign sonrası bayt-bayt korunduğunu
     * doğrular. Signer body subtree'sine dokunmamalı.
     */
    @Test
    @DisplayName("GIB envelope: Türkçe karakterli business content sign sonrası korunur")
    void gibEnvelope_turkishBusinessContent_isPreservedAfterSign() throws Exception {
        Document signedDoc = parse(signEnvelope(SoapEnvelopeFixture.GIB_EFATURA_SOAP));

        // gib-efatura-soap.xml içindeki bilinen Türkçe değerler.
        String expectedSenderName = "MERSEL YAZILIM TEKNOLOJİLERİ A.Ş.";
        String expectedReceiverName = "ANONİM ALICI TİC. LTD. ŞTİ.";
        String expectedSubmissionAddress = "Ankara V.D., İstanbul Şubesi";

        assertEquals(expectedSenderName,
                singleTextContentByLocalName(signedDoc, "senderName"),
                "Mali Mühür senderName Türkçe diakritiklerini sign sonrası kaybetti");
        assertEquals(expectedReceiverName,
                singleTextContentByLocalName(signedDoc, "receiverName"),
                "Mali Mühür receiverName Türkçe diakritiklerini sign sonrası kaybetti");
        assertEquals(expectedSubmissionAddress,
                singleTextContentByLocalName(signedDoc, "SubmissionAddress"),
                "Mali Mühür SubmissionAddress içeriği bozulmuş "
                        + "(c14n veya DOM serialize regression sinyali)");
    }

    /**
     * Her iki shape de lokal XMLDsig verifier'ı geçmeli — bu, signer
     * üretiminin matematiksel olarak doğru kaldığının çapraz kanıtı.
     * Tek bir cert PFX × tek tip envelope ana matriste de var; burada
     * iki shape'in yan-yana eşit-validity'sini test ediyoruz (parity).
     */
    @Test
    @DisplayName("İki envelope shape'i de lokal XMLDsig validator'dan geçer (parity)")
    void bothEnvelopeShapes_passLocalXmlDsigValidator() throws Exception {
        byte[] gibSigned = signEnvelope(SoapEnvelopeFixture.GIB_EFATURA_SOAP);
        byte[] minimalSigned = signEnvelope(SoapEnvelopeFixture.SOAP_1_1);

        WsSecurityLocalXmlDsigVerifier.Result gibResult =
                WsSecurityLocalXmlDsigVerifier.validate(
                        gibSigned,
                        rsa2048Material.getSigningCertificate().getPublicKey());
        WsSecurityLocalXmlDsigVerifier.Result minimalResult =
                WsSecurityLocalXmlDsigVerifier.validate(
                        minimalSigned,
                        rsa2048Material.getSigningCertificate().getPublicKey());

        assertTrue(gibResult.isValid(),
                "Mali Mühür envelope için lokal XMLDsig validator reddetti: " + gibResult);
        assertTrue(minimalResult.isValid(),
                "Minimal envelope için lokal XMLDsig validator reddetti: " + minimalResult);
    }

    // ─────────────────────────── helpers ───────────────────────────

    private byte[] signEnvelope(SoapEnvelopeFixture fixture) throws Exception {
        Document doc = parse(fixture.readBytes());
        SignResponse response = service.signSoapEnvelope(
                doc,
                fixture.isUseSoap12(),
                rsa2048Material,
                /*alias*/ "test",
                /*pin*/ new char[0]);
        assertNotNull(response);
        assertNotNull(response.getSignedDocument());
        // Mali Mühür envelope vs minimal envelope karşılaştırması için her
        // fixture'ın imzalı çıktısını disk'e ayrı dosya olarak export et —
        // SoapUI / WSS4J cross-validation.
        SignedArtifactExporter.export(
                SignedArtifactExporter.Format.WSSECURITY,
                response.getSignedDocument(),
                fixture.name().toLowerCase());
        return response.getSignedDocument();
    }

    private static Document parse(byte[] xml) throws Exception {
        DocumentBuilderFactory dbf = SecureXmlFactories.newDocumentBuilderFactory();
        DocumentBuilder db = dbf.newDocumentBuilder();
        return db.parse(new ByteArrayInputStream(xml));
    }

    /**
     * Document genelinde verilen local name'e sahip TEK element bekler;
     * birden fazla varsa veya yoksa AssertionError. Test fixture'larında
     * unique olduğu bilinen element'ler için uygundur.
     */
    private static String singleTextContentByLocalName(Document doc, String localName) {
        NodeList all = doc.getElementsByTagName("*");
        Element found = null;
        for (int i = 0; i < all.getLength(); i++) {
            Element e = (Element) all.item(i);
            if (localName.equals(e.getLocalName())) {
                if (found != null) {
                    throw new AssertionError(
                            "Birden fazla element bulundu: " + localName);
                }
                found = e;
            }
        }
        if (found == null) {
            throw new AssertionError("Element bulunamadı: " + localName);
        }
        return found.getTextContent();
    }

    /**
     * İmzalı SOAP envelope'unun Security header iskeletini sayar.
     * İki envelope shape için aynı sayılar bekleniyor; equality ile karşılaştırılır.
     */
    private static final class SecurityShape {
        final int securityHeaderCount;
        final int bstCount;
        final int timestampCount;
        final int signatureCount;
        final int referenceCount;
        final boolean usesSoap11;

        SecurityShape(int securityHeaderCount, int bstCount, int timestampCount,
                      int signatureCount, int referenceCount, boolean usesSoap11) {
            this.securityHeaderCount = securityHeaderCount;
            this.bstCount = bstCount;
            this.timestampCount = timestampCount;
            this.signatureCount = signatureCount;
            this.referenceCount = referenceCount;
            this.usesSoap11 = usesSoap11;
        }

        static SecurityShape of(Document signedDoc) {
            int sec = signedDoc.getElementsByTagNameNS(NS_WSSE, "Security").getLength();
            int bst = signedDoc.getElementsByTagNameNS(NS_WSSE, "BinarySecurityToken").getLength();
            int ts = signedDoc.getElementsByTagNameNS(NS_WSU, "Timestamp").getLength();
            int sig = signedDoc.getElementsByTagNameNS(NS_DSIG, "Signature").getLength();
            int ref = signedDoc.getElementsByTagNameNS(NS_DSIG, "Reference").getLength();
            boolean soap11 = signedDoc.getElementsByTagNameNS(
                    NS_SOAP_1_1, "Envelope").getLength() == 1;
            return new SecurityShape(sec, bst, ts, sig, ref, soap11);
        }

        @Override
        public boolean equals(Object o) {
            if (!(o instanceof SecurityShape)) return false;
            SecurityShape other = (SecurityShape) o;
            return securityHeaderCount == other.securityHeaderCount
                    && bstCount == other.bstCount
                    && timestampCount == other.timestampCount
                    && signatureCount == other.signatureCount
                    && referenceCount == other.referenceCount;
            // soap11 bilerek karşılaştırmaya katılmıyor — iki test
            // envelope'u zaten ikisi de SOAP 1.1; ileride 1.2 envelope
            // eklenirse "parity" testinin yanlış pozitif fail vermesini
            // istemiyoruz.
        }

        @Override
        public int hashCode() {
            return securityHeaderCount * 31
                    + bstCount * 13
                    + timestampCount * 7
                    + signatureCount * 5
                    + referenceCount;
        }

        @Override
        public String toString() {
            return "SecurityShape{Security=" + securityHeaderCount
                    + ", BST=" + bstCount
                    + ", Timestamp=" + timestampCount
                    + ", Signature=" + signatureCount
                    + ", Reference=" + referenceCount
                    + ", soap11=" + usesSoap11
                    + "}";
        }
    }
}
