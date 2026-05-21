package io.mersel.dss.signer.api.services.signature.xades;

import java.io.IOException;
import java.io.StringReader;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import io.mersel.dss.signer.api.constants.XmlConstants;
import io.mersel.dss.signer.api.exceptions.SignatureException;
import io.mersel.dss.signer.api.models.enums.DocumentType;
import io.mersel.dss.signer.api.util.xml.SecureXmlFactories;

/**
 * XML belgelerinde imza elemanlarını yerleştiren servis.
 * Belge tipine özgü yerleştirme mantığını yönetir (UBL, e-Arşiv, HrXml vb.).
 */
@Service
public class XAdESDocumentPlacementService {

    /**
     * İmza elemanını belge tipine göre uygun konuma yerleştirir.
     *
     * @param document         Ana XML belgesi
     * @param signatureElement Yerleştirilecek imza elemanı
     * @param documentType     Belge tipi
     */
    public void placeSignatureElement(Document document,
            Element signatureElement,
            DocumentType documentType) {
        // İmzayı mevcut üst elemanından kaldır
        Node parent = signatureElement.getParentNode();
        if (parent != null) {
            parent.removeChild(signatureElement);
        }

        // Belge tipine göre hedef konumu belirle
        Node target = resolveTargetNode(document, documentType);

        // İmzayı import et ve ekle
        Node importedSignature = document.importNode(signatureElement, true);
        target.appendChild(importedSignature);
    }

    /**
     * İmzanın yerleştirileceği hedef node'u çözümler.
     */
    private Node resolveTargetNode(Document document, DocumentType documentType) {
        Node target = null;

        switch (documentType) {
            case UblDocument:
                target = findUblExtensionContent(document);
                break;

            case EArchiveReport:
                target = findEArchiveHeader(document);
                break;

            case EBiletReport:
                target = findEBiletHeader(document);
                break;

            case HrXml:
                target = findHrXmlSignatureContainer(document);
                break;

            default:
                // Diğer belge tipleri için kök elemana yerleştir
                break;
        }

        // Yedek olarak belge köküne yerleştir
        if (target == null) {
            target = document.getDocumentElement();
        }

        return target;
    }

    /**
     * UBL belgelerinde imzadan ÖNCE UBLExtensions yapısının mevcut olmasını sağlar.
     * Mevcut yapıyı katman katman kontrol eder ve sadece eksik olanı ekler:
     * <ul>
     * <li>UBLExtensions bile yoksa -> tüm yapıyı kök elemanın başına ekler</li>
     * <li>UBLExtensions var ama UBLExtension yoksa -> UBLExtension/ExtensionContent
     * ekler</li>
     * <li>UBLExtension var ama ExtensionContent yoksa -> sadece ExtensionContent
     * ekler</li>
     * </ul>
     * <p>
     * Ek olarak: çağrı her durumda kök elemana {@code xmlns:ext} declaration'unu
     * yansıtır. Bu, c14n digest'lerinin imzalama ve doğrulama arasında stabilite
     * kazanması için zorunludur (aşağıdaki not'a bakınız).
     * <p>
     * İmza, belgenin canonical formu üzerinden hesaplanır; bu yüzden yapı imzalama
     * öncesinde eklenmelidir.
     *
     * @param document UBL belgesi
     * @return ExtensionContent zaten varsa false, yeni eklendiyse true
     */
    public boolean ensureUblExtensionContentExists(Document document) {
        boolean addedStructure;
        if (getFirstElementByTagNameNS(document, XmlConstants.NS_UBL_EXTENSION, "ExtensionContent") != null) {
            addedStructure = false;
        } else {
            ensureUblExtensionStructure(document);
            addedStructure = true;
        }

        // UBL/XAdES imzasının "neden bazen geçersiz çıkıyor?" bilmecesinin
        // çözümü burada. Detaylı açıklama için ensureExtensionNamespaceOnRoot'a
        // bakınız.
        ensureExtensionNamespaceOnRoot(document);

        return addedStructure;
    }

    /**
     * {@code xmlns:ext} declaration'unu kök elemana garantiler (zaten varsa
     * dokunmaz). Bu method UBL/XAdES imzasının tutarlılığı için kritiktir.
     *
     * <h3>Neden bu adım var?</h3>
     * <p>DSS, ENVELOPED packaging'de Signature elementini varsayılan olarak
     * {@code documentDom}'un (kök elemanın) altına yerleştirir ve SignedProperties
     * referansının digest'ini bu konumda hesaplar. Bizim akışımız daha sonra
     * Signature'ı kök altından alıp UBLExtensions/UBLExtension/ExtensionContent
     * içine taşır. Doğrulayıcı imzayı kontrol ederken SignedProperties'in
     * subtree'sini bu YENİ konumda (ExtensionContent içinde) c14n eder.
     * <p>
     * Inclusive C14N (XML-C14N 1.0), subtree'nin tepe elementine "scope'ta olan
     * tüm namespace declaration'larını" yazar. Kök altındayken SignedProperties'in
     * ancestor zinciri root → Signature → Object → QualifyingProperties iken,
     * ExtensionContent altında zincire UBLExtensions ve UBLExtension da eklenir.
     * Eğer {@code xmlns:ext} sadece UBLExtensions üzerinde declare edilmişse,
     * doğrulayıcının gördüğü c14n çıktısına imzalama anında olmayan fazladan bir
     * {@code xmlns:ext} declaration'ı katılır → digest karşılaştırması FAIL eder.
     * <p>
     * Çözüm: {@code xmlns:ext}'i ROOT'A da declare etmek. Aynı namespace URI'sini
     * birden fazla yerde declare etmek XML semantiğini değiştirmez; sadece c14n
     * çıktısının deterministic ve imzalama/doğrulama arasında simetrik olmasını
     * sağlar.
     * <p>
     * Bu davranışın gerçek dünya kanıtı: e-Fatura/e-İrsaliye gibi UBL-TR
     * belgelerinin XML şablonları zaten kök elemanda {@code xmlns:ext}'i declare
     * eder (TÜBİTAK MA3 referans çıktıları da öyle); o yüzden o belgelerde
     * imzalama sorunsuz çalışır. ApplicationResponse gibi minimal şablonlarda
     * kök elemanda {@code xmlns:ext} yoktur — biz UBLExtensions'ı eklerken
     * sadece UBLExtensions üzerinde declare ederiz ve fix olmadan imza geçersiz
     * çıkar. Bu method o asimetriyi kapatır.
     *
     * @param document UBL belgesi
     */
    private void ensureExtensionNamespaceOnRoot(Document document) {
        Element root = document.getDocumentElement();
        if (root == null) {
            return;
        }
        // DOM Level 2: xmlns:* attribute'ları "http://www.w3.org/2000/xmlns/"
        // namespace'inde yaşar. getAttributeNS(xmlnsNS, "ext") root'taki
        // xmlns:ext'in value'sini döner; yoksa boş string.
        final String XMLNS_URI = "http://www.w3.org/2000/xmlns/";
        String existing = root.getAttributeNS(XMLNS_URI, "ext");
        if (XmlConstants.NS_UBL_EXTENSION.equals(existing)) {
            return;
        }
        root.setAttributeNS(XMLNS_URI, "xmlns:ext", XmlConstants.NS_UBL_EXTENSION);
    }

    /**
     * UBL ExtensionContent elemanını bulur. Yoksa eksik katmanları tamamlayarak
     * ExtensionContent döner.
     * <p>
     * DOM createElementNS ile oluşturma, imza canonicalization'da farklı çıktı
     * ürettiği için string parse kullanılıyor.
     */
    private Node findUblExtensionContent(Document document) {
        Node target = getFirstElementByTagNameNS(document, XmlConstants.NS_UBL_EXTENSION, "ExtensionContent");
        if (target != null) {
            return target;
        }
        ensureUblExtensionStructure(document);
        return getFirstElementByTagNameNS(document, XmlConstants.NS_UBL_EXTENSION, "ExtensionContent");
    }

    /**
     * UBLExtensions/UBLExtension/ExtensionContent hiyerarşisini katman katman
     * kontrol eder
     * ve sadece eksik olan kısmı ekler.
     */
    private void ensureUblExtensionStructure(Document document) {
        String ns = XmlConstants.NS_UBL_EXTENSION;

        Node ublExtensions = getFirstElementByTagNameNS(document, ns, "UBLExtensions");
        if (ublExtensions == null) {
            addFullUblExtensionsStructure(document);
            return;
        }

        Node ublExtension = getFirstElementByTagNameNS(document, ns, "UBLExtension");
        if (ublExtension == null) {
            Node fragment = parseFragment(
                    "<ext:UBLExtension xmlns:ext=\"" + ns + "\">" +
                            "<ext:ExtensionContent></ext:ExtensionContent>" +
                            "</ext:UBLExtension>");
            ublExtensions.insertBefore(
                    document.importNode(fragment, true),
                    ublExtensions.getFirstChild());
            return;
        }

        Node extensionContent = getFirstElementByTagNameNS(document, ns, "ExtensionContent");
        if (extensionContent == null) {
            Node fragment = parseFragment(
                    "<ext:ExtensionContent xmlns:ext=\"" + ns + "\"></ext:ExtensionContent>");
            ublExtension.insertBefore(
                    document.importNode(fragment, true),
                    ublExtension.getFirstChild());
        }
    }

    /**
     * Hiçbir UBLExtensions yapısı olmadığında tüm hiyerarşiyi kök elemanın başına
     * ekler.
     */
    private void addFullUblExtensionsStructure(Document document) {
        Node fragment = parseFragment(
                "<ext:UBLExtensions xmlns:ext=\"" + XmlConstants.NS_UBL_EXTENSION + "\">" +
                        "<ext:UBLExtension>" +
                        "<ext:ExtensionContent></ext:ExtensionContent>" +
                        "</ext:UBLExtension>" +
                        "</ext:UBLExtensions>");

        Element root = document.getDocumentElement();
        Node imported = document.importNode(fragment, true);

        Node firstChild = root.getFirstChild();
        if (firstChild != null) {
            root.insertBefore(imported, firstChild);
        } else {
            root.appendChild(imported);
        }
    }

    /**
     * XML string'ini parse edip kök elemanını döner.
     * DOM createElementNS yerine string parse kullanılır çünkü
     * canonicalization sırasında namespace declaration sıralaması farklılık
     * yaratabilir.
     */
    private Node parseFragment(String xml) {
        try {
            DocumentBuilderFactory dbf = SecureXmlFactories.newDocumentBuilderFactory();
            DocumentBuilder db = dbf.newDocumentBuilder();
            return db.parse(new InputSource(new StringReader(xml))).getDocumentElement();
        } catch (ParserConfigurationException | SAXException | IOException e) {
            throw new SignatureException("UBL_EXTENSION_ERROR",
                    "UBLExtensions yapısı eklenirken hata oluştu", e);
        }
    }

    /**
     * e-Arşiv Raporu başlık elemanını bulur.
     *
     * @throws IllegalArgumentException Başlık elemanı bulunamazsa
     */
    private Node findEArchiveHeader(Document document) {
        Node target = getFirstElementByTagNameNS(document, XmlConstants.NS_EARSIV, "baslik");

        if (target == null) {
            throw new IllegalArgumentException(
                    String.format("e-Arşiv rapor belgesi için 'baslik' elemanı bulunamadı. " +
                            "Beklenen namespace: %s", XmlConstants.NS_EARSIV));
        }

        return target;
    }

    /**
     * HrXml imza konteynırını bulur.
     *
     * @throws IllegalArgumentException ApplicationArea elemanı bulunamazsa
     */
    private Node findHrXmlSignatureContainer(Document document) {
        // ApplicationArea'yı namespace ile bul
        Node applicationArea = getFirstElementByTagNameNS(document, XmlConstants.NS_OAGIS, "ApplicationArea");

        // Namespace olmadan fallback
        if (applicationArea == null) {
            applicationArea = getFirstElementByTagName(document, "ApplicationArea");
        }

        if (applicationArea == null) {
            throw new IllegalArgumentException(
                    String.format("HrXml belgesi için 'ApplicationArea' elemanı bulunamadı. " +
                            "Beklenen namespace: %s", XmlConstants.NS_OAGIS));
        }

        // ApplicationArea içinde Signature node'unu bul (namespace ile)
        Node signatureNode = getFirstChildElementNS(applicationArea, XmlConstants.NS_OAGIS, "Signature");

        // Namespace olmadan fallback
        if (signatureNode == null) {
            signatureNode = getFirstChildElement(applicationArea, "Signature");
        }

        return signatureNode != null ? signatureNode : applicationArea;
    }

    /**
     * e-Bilet Raporu başlık elemanını bulur.
     * 
     * @throws IllegalArgumentException Başlık elemanı bulunamazsa
     */
    private Node findEBiletHeader(Document document) {
        Node target = getFirstElementByTagNameNS(document, XmlConstants.NS_BILET, "baslik");

        if (target == null) {
            throw new IllegalArgumentException(
                    String.format("e-Bilet rapor belgesi için 'baslik' elemanı bulunamadı. " +
                            "Beklenen namespace: %s", XmlConstants.NS_BILET));
        }

        return target;
    }

    private Node getFirstElementByTagName(Document document, String tagName) {
        NodeList nodeList = document.getElementsByTagName(tagName);
        return (nodeList != null && nodeList.getLength() > 0) ? nodeList.item(0) : null;
    }

    private Node getFirstElementByTagNameNS(Document document, String namespace, String localName) {
        NodeList nodeList = document.getElementsByTagNameNS(namespace, localName);
        return (nodeList != null && nodeList.getLength() > 0) ? nodeList.item(0) : null;
    }

    private Node getFirstChildElement(Node parent, String tagName) {
        NodeList nodeList = ((Element) parent).getElementsByTagName(tagName);
        return (nodeList != null && nodeList.getLength() > 0) ? nodeList.item(0) : null;
    }

    private Node getFirstChildElementNS(Node parent, String namespace, String localName) {
        NodeList nodeList = ((Element) parent).getElementsByTagNameNS(namespace, localName);
        return (nodeList != null && nodeList.getLength() > 0) ? nodeList.item(0) : null;
    }
}
