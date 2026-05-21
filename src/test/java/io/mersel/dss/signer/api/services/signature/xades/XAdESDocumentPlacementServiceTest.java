package io.mersel.dss.signer.api.services.signature.xades;

import io.mersel.dss.signer.api.constants.XmlConstants;
import io.mersel.dss.signer.api.models.enums.DocumentType;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Severity;
import io.qameta.allure.SeverityLevel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

@Epic("Service Layer")
@Feature("XAdES Document Placement")
@Severity(SeverityLevel.NORMAL)
class XAdESDocumentPlacementServiceTest {

    private XAdESDocumentPlacementService service;

    @BeforeEach
    void setUp() {
        service = new XAdESDocumentPlacementService();
    }

    private Document parseXml(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
    }

    private Element createSignatureElement(Document ownerDocument) {
        return ownerDocument.createElementNS("http://www.w3.org/2000/09/xmldsig#", "ds:Signature");
    }

    @Nested
    class EBiletReportPlacement {

        @Test
        void shouldPlaceSignatureInBaslikElement() throws Exception {
            String xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
                    "<biletRapor xmlns:ebilet=\"" + XmlConstants.NS_BILET + "\">" +
                    "<ebilet:baslik>" +
                    "<ebilet:raporNo>RPR-001</ebilet:raporNo>" +
                    "</ebilet:baslik>" +
                    "<ebilet:detay>test</ebilet:detay>" +
                    "</biletRapor>";

            Document document = parseXml(xml);
            Element signatureElement = createSignatureElement(document);
            document.getDocumentElement().appendChild(signatureElement);

            service.placeSignatureElement(document, signatureElement, DocumentType.EBiletReport);

            NodeList baslikChildren = document.getElementsByTagNameNS(XmlConstants.NS_BILET, "baslik");
            assertEquals(1, baslikChildren.getLength());

            Element baslik = (Element) baslikChildren.item(0);
            NodeList signatures = baslik.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
            assertEquals(1, signatures.getLength());
        }

        @Test
        void shouldThrowWhenBaslikElementMissing() throws Exception {
            String xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
                    "<biletRapor xmlns:ebilet=\"" + XmlConstants.NS_BILET + "\">" +
                    "<ebilet:detay>test</ebilet:detay>" +
                    "</biletRapor>";

            Document document = parseXml(xml);
            Element signatureElement = createSignatureElement(document);
            document.getDocumentElement().appendChild(signatureElement);

            IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                    () -> service.placeSignatureElement(document, signatureElement, DocumentType.EBiletReport));

            assertTrue(ex.getMessage().contains("baslik"));
            assertTrue(ex.getMessage().contains(XmlConstants.NS_BILET));
        }

        @Test
        void shouldThrowWhenBaslikHasWrongNamespace() throws Exception {
            String wrongNamespace = "http://wrong.namespace.com";
            String xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
                    "<biletRapor xmlns:wrong=\"" + wrongNamespace + "\">" +
                    "<wrong:baslik>test</wrong:baslik>" +
                    "</biletRapor>";

            Document document = parseXml(xml);
            Element signatureElement = createSignatureElement(document);
            document.getDocumentElement().appendChild(signatureElement);

            assertThrows(IllegalArgumentException.class,
                    () -> service.placeSignatureElement(document, signatureElement, DocumentType.EBiletReport));
        }

        @Test
        void shouldRemoveSignatureFromPreviousParentBeforePlacing() throws Exception {
            String xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
                    "<biletRapor xmlns:ebilet=\"" + XmlConstants.NS_BILET + "\">" +
                    "<ebilet:baslik/>" +
                    "<detay/>" +
                    "</biletRapor>";

            Document document = parseXml(xml);
            Element signatureElement = createSignatureElement(document);

            Element detay = (Element) document.getElementsByTagName("detay").item(0);
            detay.appendChild(signatureElement);
            assertEquals(1, detay.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature").getLength());

            service.placeSignatureElement(document, signatureElement, DocumentType.EBiletReport);

            assertEquals(0, detay.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature").getLength());

            Element baslik = (Element) document.getElementsByTagNameNS(XmlConstants.NS_BILET, "baslik").item(0);
            assertEquals(1, baslik.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature").getLength());
        }
    }

    @Nested
    class EArchiveReportPlacement {

        @Test
        void shouldPlaceSignatureInEArchiveBaslikElement() throws Exception {
            String xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
                    "<arsivRapor xmlns:earsiv=\"" + XmlConstants.NS_EARSIV + "\">" +
                    "<earsiv:baslik>" +
                    "<earsiv:raporNo>RPR-001</earsiv:raporNo>" +
                    "</earsiv:baslik>" +
                    "</arsivRapor>";

            Document document = parseXml(xml);
            Element signatureElement = createSignatureElement(document);
            document.getDocumentElement().appendChild(signatureElement);

            service.placeSignatureElement(document, signatureElement, DocumentType.EArchiveReport);

            Element baslik = (Element) document.getElementsByTagNameNS(XmlConstants.NS_EARSIV, "baslik").item(0);
            NodeList signatures = baslik.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
            assertEquals(1, signatures.getLength());
        }

        @Test
        void shouldThrowWhenEArchiveBaslikMissing() throws Exception {
            String xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
                    "<arsivRapor><detay>test</detay></arsivRapor>";

            Document document = parseXml(xml);
            Element signatureElement = createSignatureElement(document);
            document.getDocumentElement().appendChild(signatureElement);

            assertThrows(IllegalArgumentException.class,
                    () -> service.placeSignatureElement(document, signatureElement, DocumentType.EArchiveReport));
        }
    }

    @Nested
    class DefaultPlacement {

        @Test
        void shouldPlaceSignatureInDocumentRootForOtherXmlDocument() throws Exception {
            String xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><root><data>test</data></root>";

            Document document = parseXml(xml);
            Element signatureElement = createSignatureElement(document);
            document.getDocumentElement().appendChild(signatureElement);

            service.placeSignatureElement(document, signatureElement, DocumentType.OtherXmlDocument);

            Element root = document.getDocumentElement();
            NodeList signatures = root.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
            assertEquals(1, signatures.getLength());
            assertSame(root, signatures.item(0).getParentNode());
        }
    }

    @Nested
    class UblDocumentPlacement {

        private static final String XMLNS_URI = "http://www.w3.org/2000/xmlns/";

        @Test
        void shouldEnsureUblExtensionContentExists() throws Exception {
            String xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
                    "<Invoice xmlns:ext=\"" + XmlConstants.NS_UBL_EXTENSION + "\">" +
                    "<ext:UBLExtensions>" +
                    "<ext:UBLExtension>" +
                    "<ext:ExtensionContent/>" +
                    "</ext:UBLExtension>" +
                    "</ext:UBLExtensions>" +
                    "</Invoice>";

            Document document = parseXml(xml);
            Element signatureElement = createSignatureElement(document);
            document.getDocumentElement().appendChild(signatureElement);

            service.placeSignatureElement(document, signatureElement, DocumentType.UblDocument);

            NodeList extContent = document.getElementsByTagNameNS(XmlConstants.NS_UBL_EXTENSION, "ExtensionContent");
            assertEquals(1, extContent.getLength());

            NodeList signatures = ((Element) extContent.item(0))
                    .getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
            assertEquals(1, signatures.getLength());
        }

        // Bu test ApplicationResponse-tipi minimal UBL XML'lerde yaşanan
        // "namespace asimetrisi -> SignedProperties digest mismatch" regresyonunu
        // kilitler. Kök elemanda xmlns:ext yokken UBLExtensions iskeletini eklemek
        // ext namespace'ini SADECE UBLExtensions üzerine bırakıyordu; DSS Signature
        // root altına basıp c14n hesabını orada yapınca xmlns:ext SignedProperties
        // subtree scope'unda yoktu; sonradan Signature ExtensionContent içine
        // taşınınca scope'a giriyordu -> c14n bytes değişiyor -> imza geçersiz.
        @Test
        void shouldDeclareExtNamespaceOnRootWhenExtensionsCreated() throws Exception {
            String xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
                    "<urn:ApplicationResponse" +
                    " xmlns:urn=\"urn:oasis:names:specification:ubl:schema:xsd:ApplicationResponse-2\">" +
                    "<urn:UBLVersionID>2.1</urn:UBLVersionID>" +
                    "</urn:ApplicationResponse>";

            Document document = parseXml(xml);

            boolean added = service.ensureUblExtensionContentExists(document);

            assertTrue(added, "UBLExtensions iskeleti eklenmeliydi");
            Element root = document.getDocumentElement();
            assertEquals(XmlConstants.NS_UBL_EXTENSION, root.getAttributeNS(XMLNS_URI, "ext"),
                    "xmlns:ext kök element üzerinde declare edilmiş olmalı");
        }

        @Test
        void shouldDeclareExtNamespaceOnRootEvenWhenExtensionContentAlreadyExists() throws Exception {
            // UBLExtensions zaten var (xmlns:ext UBLExtensions seviyesinde),
            // ama kök elemanda xmlns:ext declare edilmemiş. Bu, c14n asimetrisi
            // riski taşır; method yine de root'a xmlns:ext eklemeli.
            String xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
                    "<urn:ApplicationResponse" +
                    " xmlns:urn=\"urn:oasis:names:specification:ubl:schema:xsd:ApplicationResponse-2\">" +
                    "<ext:UBLExtensions xmlns:ext=\"" + XmlConstants.NS_UBL_EXTENSION + "\">" +
                    "<ext:UBLExtension><ext:ExtensionContent/></ext:UBLExtension>" +
                    "</ext:UBLExtensions>" +
                    "</urn:ApplicationResponse>";

            Document document = parseXml(xml);

            boolean added = service.ensureUblExtensionContentExists(document);

            assertFalse(added, "ExtensionContent zaten vardı, ekleme yapılmamalı");
            Element root = document.getDocumentElement();
            assertEquals(XmlConstants.NS_UBL_EXTENSION, root.getAttributeNS(XMLNS_URI, "ext"),
                    "xmlns:ext kök element üzerinde declare edilmiş olmalı");
        }

        @Test
        void shouldBeIdempotentWhenExtNamespaceAlreadyOnRoot() throws Exception {
            // Kök zaten xmlns:ext declare ediyor (e-Fatura tarzı). Method
            // duplicate eklememeli, davranış no-op olmalı.
            String xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
                    "<Invoice" +
                    " xmlns=\"urn:oasis:names:specification:ubl:schema:xsd:Invoice-2\"" +
                    " xmlns:ext=\"" + XmlConstants.NS_UBL_EXTENSION + "\">" +
                    "<ext:UBLExtensions>" +
                    "<ext:UBLExtension><ext:ExtensionContent/></ext:UBLExtension>" +
                    "</ext:UBLExtensions>" +
                    "</Invoice>";

            Document document = parseXml(xml);
            Element root = document.getDocumentElement();
            int attrsBefore = root.getAttributes().getLength();

            service.ensureUblExtensionContentExists(document);

            assertEquals(attrsBefore, root.getAttributes().getLength(),
                    "Root üzerine duplicate xmlns:ext eklenmemeli");
            assertEquals(XmlConstants.NS_UBL_EXTENSION, root.getAttributeNS(XMLNS_URI, "ext"));
        }
    }
}
