package io.mersel.dss.signer.api.services.signature.xades;

import io.mersel.dss.signer.api.constants.XmlConstants;
import io.qameta.allure.Description;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Severity;
import io.qameta.allure.SeverityLevel;
import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.Canonicalizer;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * <h2>Neden bu test sınıfı var?</h2>
 *
 * UBL/XAdES imzasının "bazı belgelerde geçerli, bazılarında geçersiz çıkıyor"
 * davranışının kök nedeni canonical XML (XML-C14N 1.0) namespace inheritance
 * kurallarıdır:
 *
 * <ul>
 * <li>DSS, ENVELOPED packaging'de Signature elementini varsayılan olarak
 *     kök elemanın altına yerleştirir ve SignedProperties referansının
 *     digest'ini bu konumda hesaplar.</li>
 * <li>Sonra bizim {@link XAdESDocumentPlacementService} Signature'ı
 *     UBLExtensions/UBLExtension/ExtensionContent içine taşır.</li>
 * <li>Doğrulayıcı imzayı kontrol ederken SignedProperties'in subtree'sini
 *     YENİ konumda c14n eder.</li>
 * </ul>
 *
 * Inclusive C14N, subtree tepe elementine "scope'taki tüm in-scope namespace
 * declaration'larını" yazar. {@code xmlns:ext} sadece UBLExtensions üzerinde
 * declare edilmişse, root altındayken SignedProperties scope'unda yoktur;
 * ExtensionContent altındayken vardır. Sonuç: c14n çıktıları farklı → digest
 * mismatch → imza geçersiz.
 *
 * Çözüm: {@code xmlns:ext}'i ROOT'A da declare etmek.
 * ({@link XAdESDocumentPlacementService#ensureUblExtensionContentExists(Document)}
 * artık bunu garantiliyor.)
 *
 * Bu test sınıfı şunu kanıtlar:
 * <ul>
 * <li><b>Negatif:</b> Fix yokken (xmlns:ext sadece UBLExtensions'da) iki
 *     konumdaki SignedProperties subtree c14n'i FARKLI bytes üretir.</li>
 * <li><b>Pozitif:</b> Fix uygulandığında (xmlns:ext aynı zamanda root'ta)
 *     iki konumdaki c14n çıktıları AYNI bytes üretir → digest match → imza
 *     valid.</li>
 * </ul>
 */
@Epic("Service Layer")
@Feature("XAdES Canonicalization Symmetry")
@Severity(SeverityLevel.CRITICAL)
class XAdESNamespaceCanonicalizationSymmetryTest {

    private static final String DS_NS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String XADES_NS = "http://uri.etsi.org/01903/v1.3.2#";
    private static final String APPLICATION_RESPONSE_NS =
            "urn:oasis:names:specification:ubl:schema:xsd:ApplicationResponse-2";
    private static final String C14N_INCLUSIVE_WITHOUT_COMMENTS =
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";

    private XAdESDocumentPlacementService placementService;

    @BeforeAll
    static void initSantuario() {
        Init.init();
    }

    @BeforeEach
    void setUp() {
        placementService = new XAdESDocumentPlacementService();
    }

    @Test
    @DisplayName("FIX YOKKEN: ApplicationResponse'ta SignedProperties c14n'i root-altı vs ExtensionContent-içi konumlarda FARKLIDIR (regresyonun kanıtı)")
    @Description("Bu test, fix uygulanmazsa namespace inheritance asimetrisinin gerçekten c14n bytes farkı yarattığını kanıtlar. " +
            "Eğer bu testin assertion'ı bir gün fail olursa, bug ortadan kalkmıştır demektir — o zaman bu test bekleneni de güncelleyebilir.")
    void canonicalizationDiffersAcrossPlacementsWithoutFix() throws Exception {
        // Senaryo: kök elemanda xmlns:ext yok. UBLExtensions üzerinde declare
        // edilmiş. Fix UYGULANMADAN bu durumu yapay olarak kuruyoruz.
        String xml = baseApplicationResponseWithExtensionsOnly();

        Document doc = parse(xml);
        // Önemli: ensureUblExtensionContentExists'i ÇAĞIRMIYORUZ. Yani root'a
        // xmlns:ext eklenmemiş hâliyle gidiyoruz.

        byte[] cAtRoot = canonicalizeSignedPropsAt(doc, /*placeInExtensionContent*/ false);
        byte[] cAtExtension = canonicalizeSignedPropsAt(doc, /*placeInExtensionContent*/ true);

        assertFalse(java.util.Arrays.equals(cAtRoot, cAtExtension),
                "Fix yokken c14n çıktıları AYNI olmamalı; eğer aynıysa namespace " +
                        "asimetrisi hipotezimiz hatalı demektir. Beklenen: farklı bytes.");
    }

    @Test
    @DisplayName("FIX VARKEN: ApplicationResponse'ta SignedProperties c14n'i root-altı vs ExtensionContent-içi konumlarda AYNIDIR (imza valid olur)")
    @Description("Bu test fix'in asıl kanıtıdır: ensureUblExtensionContentExists çağrıldıktan sonra, " +
            "Signature root altında hesaplansa da ExtensionContent içinde hesaplansa da " +
            "SignedProperties subtree'nin Inclusive C14N çıktısı aynı bytes üretir → digest match → imza geçerli.")
    void canonicalizationIsSymmetricAfterFix() throws Exception {
        String xml = baseApplicationResponseWithExtensionsOnly();

        Document doc = parse(xml);
        // Fix devreye sokulur: xmlns:ext kök elemana da declare edilir.
        placementService.ensureUblExtensionContentExists(doc);

        byte[] cAtRoot = canonicalizeSignedPropsAt(doc, /*placeInExtensionContent*/ false);
        byte[] cAtExtension = canonicalizeSignedPropsAt(doc, /*placeInExtensionContent*/ true);

        assertArrayEquals(cAtRoot, cAtExtension,
                "Fix uygulandıktan sonra iki konumdaki SignedProperties c14n çıktıları AYNI olmalı; " +
                        "değilse imzalama-doğrulama digest mismatch'i geri döner.");
    }

    @Test
    @DisplayName("E-FATURA TARZI: root'ta xmlns:ext zaten varsa fix'in eklediği davranış no-op'tur, c14n simetrisi yine korunur")
    void canonicalizationStaysSymmetricWhenRootAlreadyDeclaresExt() throws Exception {
        // e-Fatura/e-İrsaliye gibi UBL-TR şablonları kök elemanda xmlns:ext'i
        // zaten declare eder. Bu, fix uygulansa da uygulanmasa da c14n
        // simetrisinin korunduğu durumdur (regresyon güvencesi).
        String xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
                "<urn:ApplicationResponse" +
                " xmlns:urn=\"" + APPLICATION_RESPONSE_NS + "\"" +
                " xmlns:ext=\"" + XmlConstants.NS_UBL_EXTENSION + "\">" +
                "<ext:UBLExtensions>" +
                "<ext:UBLExtension><ext:ExtensionContent/></ext:UBLExtension>" +
                "</ext:UBLExtensions>" +
                "<urn:UBLVersionID>2.1</urn:UBLVersionID>" +
                "</urn:ApplicationResponse>";

        Document doc = parse(xml);
        placementService.ensureUblExtensionContentExists(doc);

        byte[] cAtRoot = canonicalizeSignedPropsAt(doc, false);
        byte[] cAtExtension = canonicalizeSignedPropsAt(doc, true);

        assertArrayEquals(cAtRoot, cAtExtension,
                "Kök zaten xmlns:ext declare ediyorken c14n simetrisi her zaman korunur");
    }

    // ---- helpers --------------------------------------------------------

    private String baseApplicationResponseWithExtensionsOnly() {
        // ApplicationResponse-tipi minimal XML: kök elemanda xmlns:ext YOK.
        // UBLExtensions iskeleti hazır ve xmlns:ext UBLExtensions üzerinde
        // declare edilmiş (bizim eski ensureUblExtensionContentExists davranışı).
        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
                "<urn:ApplicationResponse" +
                " xmlns:urn=\"" + APPLICATION_RESPONSE_NS + "\">" +
                "<ext:UBLExtensions xmlns:ext=\"" + XmlConstants.NS_UBL_EXTENSION + "\">" +
                "<ext:UBLExtension><ext:ExtensionContent/></ext:UBLExtension>" +
                "</ext:UBLExtensions>" +
                "<urn:UBLVersionID>2.1</urn:UBLVersionID>" +
                "</urn:ApplicationResponse>";
    }

    /**
     * Belgeye XAdES tipi minimal bir Signature elementi monte eder:
     * <pre>
     * &lt;ds:Signature&gt;
     *   &lt;ds:Object&gt;
     *     &lt;xades:QualifyingProperties&gt;
     *       &lt;xades:SignedProperties&gt;
     *         &lt;xades:SignedSignatureProperties/&gt;
     *       &lt;/xades:SignedProperties&gt;
     *     &lt;/xades:QualifyingProperties&gt;
     *   &lt;/ds:Object&gt;
     * &lt;/ds:Signature&gt;
     * </pre>
     * Yerleşim flag'ine göre ya kök altına ya da ExtensionContent içine eklenir
     * ve sonra SignedProperties subtree'sinin Inclusive C14N çıktısı dönülür.
     * <p>
     * Her çağrı önceki Signature'ı temizler ki testler birbirine sızıntı yapmasın.
     */
    private byte[] canonicalizeSignedPropsAt(Document doc, boolean placeInExtensionContent) throws Exception {
        removeAllSignatures(doc);

        Element signature = doc.createElementNS(DS_NS, "ds:Signature");
        Element object = doc.createElementNS(DS_NS, "ds:Object");
        Element qualifying = doc.createElementNS(XADES_NS, "xades:QualifyingProperties");
        Element signedProps = doc.createElementNS(XADES_NS, "xades:SignedProperties");
        signedProps.setAttribute("Id", "xades-Signature_Attach_1");
        Element ssp = doc.createElementNS(XADES_NS, "xades:SignedSignatureProperties");

        signedProps.appendChild(ssp);
        qualifying.appendChild(signedProps);
        object.appendChild(qualifying);
        signature.appendChild(object);

        if (placeInExtensionContent) {
            Element extensionContent = (Element) doc.getElementsByTagNameNS(
                    XmlConstants.NS_UBL_EXTENSION, "ExtensionContent").item(0);
            extensionContent.appendChild(signature);
        } else {
            doc.getDocumentElement().appendChild(signature);
        }

        Canonicalizer canonicalizer = Canonicalizer.getInstance(C14N_INCLUSIVE_WITHOUT_COMMENTS);
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            canonicalizer.canonicalizeSubtree(signedProps, out);
            return out.toByteArray();
        }
    }

    private void removeAllSignatures(Document doc) {
        org.w3c.dom.NodeList list = doc.getElementsByTagNameNS(DS_NS, "Signature");
        for (int i = list.getLength() - 1; i >= 0; i--) {
            org.w3c.dom.Node sig = list.item(i);
            sig.getParentNode().removeChild(sig);
        }
    }

    private Document parse(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
    }
}
