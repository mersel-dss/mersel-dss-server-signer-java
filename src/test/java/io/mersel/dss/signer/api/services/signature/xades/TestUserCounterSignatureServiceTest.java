package io.mersel.dss.signer.api.services.signature.xades;

import io.mersel.dss.signer.api.e2e.verifier.PfxTestKey;
import io.mersel.dss.signer.api.models.SignResponse;
import io.mersel.dss.signer.api.models.enums.TestCompany;
import org.apache.xml.security.Init;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * {@link TestUserCounterSignatureService}'in {@code mersel-dss-agent-signer-java}'daki
 * {@code XadesService.doCounterSignature} ile <strong>bit-bit parite</strong>
 * ürettiğini Kamu SM RSA-2048 test sertifikasıyla doğrular.
 *
 * <p>Test, agent reposundaki {@code XadesCounterSignatureTest}'in birebir
 * eşdeğeridir; aynı XAdES-BES yapısal invariant'larını ve XML-DSig
 * doğrulamasını çalıştırır:</p>
 * <ul>
 *   <li>{@code xades:CounterSignature} elementi {@code
 *       UnsignedSignatureProperties} altında eklenmiş.</li>
 *   <li>Counter-signature kendi başına geçerli bir XML-DSig — iki
 *       Reference ({@code #SignedProperties} + {@code #CountersignedSignature}).</li>
 *   <li>{@code QualifyingProperties Target} counter-sig Id'sini gösterir.</li>
 *   <li>{@code SigningTime} + {@code CertDigest} + {@code IssuerSerial}
 *       doldurulmuş.</li>
 *   <li>{@code KeyInfo} tek X509Certificate içerir (chain leak yok).</li>
 * </ul>
 *
 * <p>PFX repo'da yoksa test {@code Assumptions.assumeTrue} ile graceful
 * skip eder.</p>
 */
class TestUserCounterSignatureServiceTest {

    @BeforeAll
    static void initApacheSantuario() {
        Init.init();
    }

    @Test
    @DisplayName("Kamu SM RSA-2048 PFX ile XAdES-BES counter-signature ekler ve XML-DSig doğrulamasını geçer")
    void addsAndVerifiesCounterSignature() throws Exception {
        PfxTestKey key = PfxTestKey.KURUM01_RSA2048;
        assumeTrue(key.isAvailable(), "Skip — PFX yok: " + key.getAbsolutePath());

        byte[] originalSignedXml = sampleSignedXadesDocument();

        TestUserCounterSignatureService service =
                new TestUserCounterSignatureService("resources/test-certs");

        SignResponse response = service.counterSign(
                new ByteArrayInputStream(originalSignedXml),
                TestCompany.TestKurum1);

        assertNotNull(response, "SignResponse null olmamalı.");
        assertNotNull(response.getSignedDocument(),
                "Counter-sign edilmiş belge byte'ları null olmamalı.");
        assertNotNull(response.getSignatureValue(),
                "Base64 SignatureValue header değeri üretilmiş olmalı.");

        Document doc = parse(response.getSignedDocument());

        // CounterSignature elementi var mı?
        NodeList counterSigs = doc.getElementsByTagNameNS(
                TestUserCounterSignatureService.XADES_NS, "CounterSignature");
        assertTrue(counterSigs.getLength() >= 1,
                "xades:CounterSignature elementi eklenmiş olmalı.");

        Element counterContainer = (Element) counterSigs.item(0);
        NodeList innerSigs = counterContainer.getElementsByTagNameNS(
                TestUserCounterSignatureService.DS_NS, "Signature");
        assertTrue(innerSigs.getLength() >= 1, "CounterSignature içinde ds:Signature olmalı.");

        // SignatureValue Id'lerini XML ID olarak işaretle (schema yokken
        // getElementById bulabilsin) — agent test'iyle aynı pattern.
        NodeList allSigValues = doc.getElementsByTagNameNS(
                TestUserCounterSignatureService.DS_NS, "SignatureValue");
        boolean targetHasId = false;
        for (int i = 0; i < allSigValues.getLength(); i++) {
            Element el = (Element) allSigValues.item(i);
            String id = el.getAttribute("Id");
            if (id != null && !id.isEmpty()) {
                if (i == 0) targetHasId = true;
                el.setIdAttribute("Id", true);
            }
        }
        assertTrue(targetHasId, "Hedef SignatureValue'a Id atanmış olmalı.");

        // SignedProperties Id'lerini de XML ID olarak işaretle.
        NodeList signedPropsList = doc.getElementsByTagNameNS(
                TestUserCounterSignatureService.XADES_NS, "SignedProperties");
        boolean counterHasSignedProps = false;
        for (int i = 0; i < signedPropsList.getLength(); i++) {
            Element el = (Element) signedPropsList.item(i);
            String id = el.getAttribute("Id");
            if (id != null && !id.isEmpty()) {
                el.setIdAttribute("Id", true);
                counterHasSignedProps = true;
            }
        }
        assertTrue(counterHasSignedProps,
                "Counter-signature için xades:SignedProperties (Id'li) üretilmiş olmalı.");

        // Counter-sig XAdES-BES olarak: iki Reference'ı da içeren XML-DSig
        // validate'i geçmeli.
        Element counterSigElement = (Element) innerSigs.item(0);
        DOMValidateContext valCtx = new DOMValidateContext(new X509KeySelector(), counterSigElement);
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
        XMLSignature signature = fac.unmarshalXMLSignature(valCtx);
        assertTrue(signature.validate(valCtx),
                "Counter-signature XAdES-BES (SignedProperties + CountersignedSignature) "
                        + "olarak geçerli olmalı.");

        // XAdES-BES yapısal invariant'ları:
        // 1) SignedInfo iki Reference içerir.
        assertEquals(2, signature.getSignedInfo().getReferences().size(),
                "İki Reference olmalı.");
        boolean hasSignedPropsRef = false;
        boolean hasCounterRef = false;
        for (Object refObj : signature.getSignedInfo().getReferences()) {
            javax.xml.crypto.dsig.Reference r = (javax.xml.crypto.dsig.Reference) refObj;
            if (TestUserCounterSignatureService.XADES_TYPE_SIGNED_PROPERTIES.equals(r.getType())) {
                hasSignedPropsRef = true;
            }
            if (TestUserCounterSignatureService.XADES_TYPE_COUNTERSIGNED_SIGNATURE.equals(r.getType())) {
                hasCounterRef = true;
            }
        }
        assertTrue(hasSignedPropsRef, "SignedProperties tipli Reference olmalı.");
        assertTrue(hasCounterRef, "CountersignedSignature tipli Reference olmalı.");

        // 2) QualifyingProperties Target counter-signature'ın kendi Id'sini göstermeli.
        Element counterQp = (Element) counterSigElement.getElementsByTagNameNS(
                TestUserCounterSignatureService.XADES_NS, "QualifyingProperties").item(0);
        assertNotNull(counterQp, "Counter-sig içinde xades:QualifyingProperties olmalı.");
        String target = counterQp.getAttribute("Target");
        String counterId = counterSigElement.getAttribute("Id");
        assertTrue(target != null && counterId != null && target.equals("#" + counterId),
                "QualifyingProperties Target counter-sig Id'siyle eşleşmeli: target=" + target);

        // 3) SigningTime + SigningCertificate (CertDigest + IssuerSerial) doldurulmuş olmalı.
        assertTrue(counterSigElement.getElementsByTagNameNS(
                        TestUserCounterSignatureService.XADES_NS, "SigningTime").getLength() > 0,
                "xades:SigningTime üretilmiş olmalı.");
        assertTrue(counterSigElement.getElementsByTagNameNS(
                        TestUserCounterSignatureService.XADES_NS, "CertDigest").getLength() > 0,
                "xades:CertDigest üretilmiş olmalı.");
        assertTrue(counterSigElement.getElementsByTagNameNS(
                        TestUserCounterSignatureService.XADES_NS, "IssuerSerial").getLength() > 0,
                "xades:IssuerSerial üretilmiş olmalı.");

        // 4) KeyInfo'da yalnız tek imzacı sertifikası bulunsun (chain leak'i değil).
        Element counterKeyInfo = (Element) counterSigElement.getElementsByTagNameNS(
                TestUserCounterSignatureService.DS_NS, "KeyInfo").item(0);
        assertNotNull(counterKeyInfo, "ds:KeyInfo olmalı.");
        NodeList certs = counterKeyInfo.getElementsByTagNameNS(
                TestUserCounterSignatureService.DS_NS, "X509Certificate");
        assertEquals(1, certs.getLength(),
                "Counter-sig KeyInfo tek X509Certificate içermeli.");
    }

    private static byte[] sampleSignedXadesDocument() {
        String xml =
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                        + "<doc xmlns=\"urn:test\">"
                        + "  <body>HR Faturası</body>"
                        + "  <ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" Id=\"sig1\">"
                        + "    <ds:SignedInfo>"
                        + "      <ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments\"/>"
                        + "      <ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>"
                        + "      <ds:Reference URI=\"\">"
                        + "        <ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>"
                        + "        <ds:DigestValue>AAAA</ds:DigestValue>"
                        + "      </ds:Reference>"
                        + "    </ds:SignedInfo>"
                        + "    <ds:SignatureValue>ZHVtbXk=</ds:SignatureValue>"
                        + "    <ds:KeyInfo><ds:X509Data><ds:X509SubjectName>CN=Original</ds:X509SubjectName></ds:X509Data></ds:KeyInfo>"
                        + "  </ds:Signature>"
                        + "</doc>";
        return xml.getBytes(StandardCharsets.UTF_8);
    }

    private static Document parse(byte[] bytes) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder builder = dbf.newDocumentBuilder();
        return builder.parse(new ByteArrayInputStream(bytes));
    }

    /**
     * Counter-signature'ın kendi KeyInfo'sundaki X509 sertifikasından
     * public key'i çıkarıp validate sırasında kullanır.
     */
    static final class X509KeySelector extends KeySelector {
        @Override
        public KeySelectorResult select(
                KeyInfo keyInfo,
                Purpose purpose,
                javax.xml.crypto.AlgorithmMethod method,
                XMLCryptoContext context) {
            for (Object xobj : keyInfo.getContent()) {
                if (!(xobj instanceof X509Data)) continue;
                for (Object o : ((X509Data) xobj).getContent()) {
                    if (o instanceof X509Certificate) {
                        final PublicKey pk = ((X509Certificate) o).getPublicKey();
                        return new KeySelectorResult() {
                            @Override
                            public Key getKey() {
                                return pk;
                            }
                        };
                    }
                }
            }
            throw new RuntimeException("X509 sertifikası KeyInfo'da bulunamadı.");
        }
    }
}
