package io.mersel.dss.signer.api.services.signature.xades;

import io.mersel.dss.signer.api.e2e.verifier.PfxTestKey;
import io.mersel.dss.signer.api.models.SignResponse;
import io.mersel.dss.signer.api.models.enums.TestCompany;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Counter-signature çıktı formatının standart XAdES görünümüne sahip
 * olduğunu doğrular:
 * <ul>
 *   <li>{@code &#13;} / {@code &#xD;} (CR entity) yok — Transformer hiçbir
 *       carriage return karakterini entity-encode etmez.</li>
 *   <li>{@code <ds:SignatureValue>} ve {@code <ds:X509Certificate>} text
 *       içerikleri 76 karakterde LF ile bölünmüş (RFC 2045 / MIME default;
 *       Apache Santuario, OpenSSL ve DSS aynı genişlikte üretir).</li>
 *   <li>Hiçbir satır 76 karakterden uzun değil.</li>
 * </ul>
 */
class TestUserCounterSignatureCleanOutputTest {

    private static final int EXPECTED_LINE_WIDTH = 76;

    @Test
    @DisplayName("Counter-sign çıktısı standart 76-char LF wrapping kullanır, &#13; içermez")
    void counterSignatureOutputHasStandardBase64Wrapping() throws Exception {
        PfxTestKey key = PfxTestKey.KURUM01_RSA2048;
        assumeTrue(key.isAvailable(), "Skip — PFX yok: " + key.getAbsolutePath());

        TestUserCounterSignatureService service =
                new TestUserCounterSignatureService("resources/test-certs");

        SignResponse response = service.counterSign(
                new ByteArrayInputStream(sampleSignedXadesDocument()),
                TestCompany.TestKurum1);

        String xml = new String(response.getSignedDocument(), StandardCharsets.UTF_8);

        // (1) Hiçbir CR entity'si yok.
        assertFalse(xml.contains("&#13;"),
                "Çıktıda '&#13;' (CR entity) bulunmamalı.");
        assertFalse(xml.contains("&#xD;"),
                "Çıktıda '&#xD;' (hex CR entity) bulunmamalı.");
        assertFalse(xml.contains("\r"),
                "Çıktıda ham '\\r' karakteri bulunmamalı.");

        // (2) Counter-signature subtree'sinde Base64 elemanları 64 karakterde
        //     LF ile bölünmüş — DOM düzeyinde inceleyelim.
        Document doc = parseDom(response.getSignedDocument());

        NodeList counterSigs = doc.getElementsByTagNameNS(
                TestUserCounterSignatureService.XADES_NS, "CounterSignature");
        assertTrue(counterSigs.getLength() >= 1,
                "<xades:CounterSignature> üretilmiş olmalı.");

        Element counterContainer = (Element) counterSigs.item(0);

        assertWrappedAt64(counterContainer,
                TestUserCounterSignatureService.DS_NS, "SignatureValue");
        assertWrappedAt64(counterContainer,
                TestUserCounterSignatureService.DS_NS, "X509Certificate");
    }

    private static void assertWrappedAt64(Element root, String ns, String localName) {
        NodeList list = root.getElementsByTagNameNS(ns, localName);
        assertTrue(list.getLength() >= 1,
                "<" + ns + ":" + localName + "> bulunmalı.");

        for (int i = 0; i < list.getLength(); i++) {
            Element el = (Element) list.item(i);
            String text = el.getTextContent();
            assertFalse(text.contains("\r"),
                    localName + " text içeriği '\\r' barındırmamalı.");

            String[] lines = text.split("\n", -1);
            // Tek satır da kabul (içerik 64 char altı olduğunda)
            if (lines.length == 1) {
                assertTrue(lines[0].length() <= EXPECTED_LINE_WIDTH,
                        localName + " tek-satır ise " + EXPECTED_LINE_WIDTH
                                + " karakteri aşmamalı, length=" + lines[0].length());
                continue;
            }

            // Çok satır: son satır hariç hepsi tam EXPECTED_LINE_WIDTH olmalı
            for (int li = 0; li < lines.length - 1; li++) {
                assertEquals(EXPECTED_LINE_WIDTH, lines[li].length(),
                        localName + " satır " + li + " " + EXPECTED_LINE_WIDTH
                                + " karakter olmalı, ama " + lines[li].length()
                                + " bulundu");
            }
            int last = lines.length - 1;
            assertTrue(lines[last].length() <= EXPECTED_LINE_WIDTH,
                    localName + " son satır " + EXPECTED_LINE_WIDTH
                            + " karakteri aşmamalı, length=" + lines[last].length());
        }
    }

    private static Document parseDom(byte[] xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder builder = dbf.newDocumentBuilder();
        return builder.parse(new ByteArrayInputStream(xml));
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
}
