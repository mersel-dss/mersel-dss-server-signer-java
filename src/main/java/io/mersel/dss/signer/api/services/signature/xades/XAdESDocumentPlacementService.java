package io.mersel.dss.signer.api.services.signature.xades;

import io.mersel.dss.signer.api.constants.XmlConstants;
import io.mersel.dss.signer.api.models.enums.DocumentType;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.io.StringReader;

/**
 * XML belgelerinde imza elemanlarını yerleştiren servis.
 * Belge tipine özgü yerleştirme mantığını yönetir (UBL, e-Arşiv, HrXml vb.).
 */
@Service
public class XAdESDocumentPlacementService {

    /**
     * İmza elemanını belge tipine göre uygun konuma yerleştirir.
     *
     * @param document Ana XML belgesi
     * @param signatureElement Yerleştirilecek imza elemanı
     * @param documentType Belge tipi
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
     * İmza, imzalama sırasında belgenin canonical formu üzerinden hesaplanır.
     * @param document UBL belgesi
     * @return ExtensionContent zaten varsa false, yeni eklendiyse true
     */
    public boolean ensureUblExtensionContentExists(Document document) {
        if (getFirstElementByTagNameNS(document, XmlConstants.NS_UBL_EXTENSION, "ExtensionContent") != null) {
            return false;
        }
        addUblExtensionsStructure(document);
        return true;
    }

    /**
     * UBL ExtensionContent elemanını bulur. Yoksa UBLExtensions/UBLExtension/ExtensionContent
     * XML ile aynı formatta (string parse) kök elemanın başına ekleyip
     * ExtensionContent döner. DOM createElementNS ile oluşturma imza canonicalization'da
     * farklı çıktı ürettiği için string parse kullanılıyor.
     */
    private Node findUblExtensionContent(Document document) {
        Node target = getFirstElementByTagNameNS(document, XmlConstants.NS_UBL_EXTENSION, "ExtensionContent");
        if (target != null) {
            return target;
        }
        addUblExtensionsStructure(document);
        return getFirstElementByTagNameNS(document, XmlConstants.NS_UBL_EXTENSION, "ExtensionContent");
    }

    private void addUblExtensionsStructure(Document document) {
        try {
            String fragment = "<ext:UBLExtensions xmlns:ext=\"" + XmlConstants.NS_UBL_EXTENSION + "\">" +
                    "<ext:UBLExtension>" +
                    "<ext:ExtensionContent></ext:ExtensionContent>" +
                    "</ext:UBLExtension>" +
                    "</ext:UBLExtensions>";

            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document fragDoc = db.parse(new InputSource(new StringReader(fragment)));
            Element ublExtensions = fragDoc.getDocumentElement();

            Element root = document.getDocumentElement();
            Node imported = document.importNode(ublExtensions, true);

            Node firstChild = root.getFirstChild();
            if (firstChild != null) {
                root.insertBefore(imported, firstChild);
            } else {
                root.appendChild(imported);
            }
        } catch (ParserConfigurationException | SAXException | IOException e) {
            throw new RuntimeException("UBLExtensions yapısı eklenirken hata oluştu", e);
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

