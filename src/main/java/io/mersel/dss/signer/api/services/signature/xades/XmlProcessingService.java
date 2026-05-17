package io.mersel.dss.signer.api.services.signature.xades;

import eu.europa.esig.dss.model.DSSDocument;
import io.mersel.dss.signer.api.exceptions.SignatureException;
import io.mersel.dss.signer.api.util.xml.SecureXmlFactories;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * XML ayrıştırma ve dönüştürme işlemleri için servis.
 * Tüm XML işleme mantığını merkezileştirir.
 */
@Service
public class XmlProcessingService {

    private final DocumentBuilderFactory documentBuilderFactory;

    public XmlProcessingService() {
        // XXE-güvenli (hardened) factory; SecureXmlFactories merkezi olarak
        // DOCTYPE/external entity/DTD/XInclude vektörlerini kapatır.
        this.documentBuilderFactory = SecureXmlFactories.newDocumentBuilderFactory();
    }

    /**
     * XML byte'larını DOM Document'e ayrıştırır.
     */
    public Document parseDocument(byte[] xmlBytes) {
        try {
            DocumentBuilder builder = documentBuilderFactory.newDocumentBuilder();
            try (ByteArrayInputStream inputStream = new ByteArrayInputStream(xmlBytes)) {
                return builder.parse(inputStream);
            }
        } catch (ParserConfigurationException | SAXException | IOException e) {
            throw new SignatureException("XML belgesi ayrıştırılamadı", e);
        }
    }

    /**
     * DOM Document'i byte dizisine dönüştürür.
     */
    public byte[] documentToBytes(Document document) {
        try {
            TransformerFactory transformerFactory = SecureXmlFactories.newTransformerFactory();
            Transformer transformer = transformerFactory.newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
            transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
            
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            transformer.transform(new DOMSource(document), new StreamResult(outputStream));
            return outputStream.toByteArray();
            
        } catch (TransformerException e) {
            throw new SignatureException("Belge byte dizisine dönüştürülemedi", e);
        }
    }

    /**
     * DSS document'ten byte dizisi çıkarır.
     */
    public byte[] dssDocumentToBytes(DSSDocument document) {
        try {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            document.writeTo(outputStream);
            return outputStream.toByteArray();
        } catch (IOException e) {
            throw new SignatureException("DSS document'ten byte'lar çıkarılamadı", e);
        }
    }

    /**
     * XML belgesinde Signature elemanını bulur.
     */
    public Element findSignatureElement(Document document) {
        // Önce namespace ile dene
        NodeList nodeList = document.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        
        // Yerel isim ile yedekleme
        if (nodeList == null || nodeList.getLength() == 0) {
            nodeList = document.getElementsByTagName("ds:Signature");
        }
        
        if (nodeList != null && nodeList.getLength() > 0) {
            return (Element) nodeList.item(0);
        }
        
        return null;
    }
}

