package io.mersel.dss.signer.api.services.signature.wssecurity;

import io.mersel.dss.signer.api.constants.XmlConstants;
import io.mersel.dss.signer.api.exceptions.SignatureException;
import io.mersel.dss.signer.api.models.SignResponse;
import io.mersel.dss.signer.api.models.SigningMaterial;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.Semaphore;

/**
 * SOAP mesajları için WS-Security imzaları oluşturan servis.
 * Hem SOAP 1.1 hem de SOAP 1.2'yi destekler.
 */
@Service
public class WsSecuritySignatureService {

    private static final Logger LOGGER = LoggerFactory.getLogger(WsSecuritySignatureService.class);

    private final Semaphore semaphore;

    public WsSecuritySignatureService(Semaphore signatureSemaphore) {
        this.semaphore = signatureSemaphore;
    }

    /**
     * SOAP zarfını WS-Security imzası ile imzalar.
     * 
     * @param soapDocument SOAP zarf belgesi
     * @param useSoap12 SOAP 1.2 (true) veya SOAP 1.1 (false) kullanılıp kullanılmayacağı
     * @param material Sertifika ve private key içeren imzalama materyali
     * @param alias İmzalama için anahtar alias'ı
     * @param pin Private key erişimi için PIN/şifre
     * @return İmzalanmış SOAP belgesi içeren yanıt
     */
    public SignResponse signSoapEnvelope(Document soapDocument,
                                        boolean useSoap12,
                                        SigningMaterial material,
                                        String alias,
                                        char[] pin) {
        try {
            String soapNamespace = useSoap12 
                ? XmlConstants.NS_SOAP_1_DOT_2_ENVELOPE 
                : XmlConstants.NS_SOAP_ENVELOPE;

            // SOAP Header'ı bul veya oluştur
            Element soapHeaderElement = ensureSoapHeader(soapDocument, soapNamespace);

            // Security header'ı doğru SOAP namespace ile oluştur (mevcut değilse)
            Element securityElement = createSecurityHeader(soapDocument, soapHeaderElement);

            // Zaman damgası ekle
            addTimestamp(soapDocument, securityElement);

            // Body elemanını hazırla
            Element bodyElement = (Element) soapDocument
                .getElementsByTagNameNS(soapNamespace, "Body").item(0);
            
            if (bodyElement != null) {
                bodyElement.setAttribute("Id", "SignedSoapBodyContent");
                // ID attribute'unu XML parser'a bildir
                bodyElement.setIdAttribute("Id", true);
                bodyElement.removeAttribute("wsu:Id");
                bodyElement.removeAttribute("xmlns:xsi");
                bodyElement.removeAttribute("xmlns:xsd");
            }

            // BinarySecurityToken ekle
            String bstReference = addBinarySecurityToken(
                soapDocument, soapNamespace, material);

            // DEBUG: ID'lerin eklendiğini doğrula
            Element testTimestamp = findElementById(soapDocument, "SignedSoapTimestampContent");
            Element testBody = findElementById(soapDocument, "SignedSoapBodyContent");
            LOGGER.debug("Pre-signature validation - Timestamp found: {}, Body found: {}", 
                testTimestamp != null, testBody != null);
            if (testTimestamp == null) {
                LOGGER.error("SignedSoapTimestampContent elementi bulunamadı!");
            }
            if (testBody == null) {
                LOGGER.error("SignedSoapBodyContent elementi bulunamadı!");
            }

            // İmzayı oluştur
            signDocument(soapDocument, securityElement, material, alias, pin, bstReference);

            // Byte'lara dönüştür
            byte[] signedBytes = documentToBytes(soapDocument);

            LOGGER.info("WS-Security imzası başarıyla oluşturuldu (SOAP {})", useSoap12 ? "1.2" : "1.1");
            return new SignResponse(signedBytes, null);

        } catch (Exception e) {
            LOGGER.error("WS-Security imzası oluşturulurken hata", e);
            throw new SignatureException("WS-Security imzası oluşturulamadı", e);
        }
    }

    /**
     * SOAP Header'ın doğru namespace ile var olduğundan emin olur.
     * Eğer yoksa oluşturur.
     */
    private Element ensureSoapHeader(Document document, String soapNamespace) {
        Element envelopeElement = document.getDocumentElement();
        Element headerElement = (Element) document
            .getElementsByTagNameNS(soapNamespace, "Header").item(0);
        
        if (headerElement == null) {
            LOGGER.debug("SOAP Header bulunamadı, oluşturuluyor (namespace: {})", soapNamespace);
            
            // Doğru namespace ile Header oluştur
            String prefix = soapNamespace.equals(XmlConstants.NS_SOAP_1_DOT_2_ENVELOPE) ? "env" : "soapenv";
            headerElement = document.createElementNS(soapNamespace, prefix + ":Header");
            
            // Body'den önce ekle
            Element bodyElement = (Element) document
                .getElementsByTagNameNS(soapNamespace, "Body").item(0);
            
            if (bodyElement != null) {
                envelopeElement.insertBefore(headerElement, bodyElement);
            } else {
                envelopeElement.appendChild(headerElement);
            }
        }
        
        return headerElement;
    }

    /**
     * Security header'ı oluşturur ve SOAP Header'a ekler.
     * SOAP 1.1 ve 1.2 namespace'leri için uyumlu çalışır.
     */
    private Element createSecurityHeader(Document document, Element soapHeaderElement) {
        // Mevcut Security elemanını kontrol et
        Element securityElement = (Element) soapHeaderElement
            .getElementsByTagNameNS(XmlConstants.NS_WSSE, "Security").item(0);
        
        if (securityElement == null) {
            // Security header'ı oluştur
            securityElement = document.createElementNS(XmlConstants.NS_WSSE, "wsse:Security");
            securityElement.setAttributeNS(
                "http://www.w3.org/2000/xmlns/", 
                "xmlns:wsse", 
                XmlConstants.NS_WSSE);
            securityElement.setAttributeNS(
                "http://www.w3.org/2000/xmlns/", 
                "xmlns:wsu", 
                XmlConstants.NS_WSU);
            
            // SOAP Header'ın ilk child'ı olarak ekle
            if (soapHeaderElement.hasChildNodes()) {
                soapHeaderElement.insertBefore(securityElement, soapHeaderElement.getFirstChild());
            } else {
                soapHeaderElement.appendChild(securityElement);
            }
            
            LOGGER.debug("Security header oluşturuldu");
        }
        
        return securityElement;
    }

    /**
     * SOAP security header'ına zaman damgası ekler.
     */
    private void addTimestamp(Document document, Element securityElement) throws Exception {
        // Timestamp elemanını manuel oluştur
        Element timestampElement = document.createElementNS(XmlConstants.NS_WSU, "wsu:Timestamp");
        timestampElement.setAttribute("Id", "SignedSoapTimestampContent");
        // ID attribute'unu XML parser'a bildir
        timestampElement.setIdAttribute("Id", true);
        
        // Created zamanı
        Element createdElement = document.createElementNS(XmlConstants.NS_WSU, "wsu:Created");
        java.time.Instant now = java.time.Instant.now();
        createdElement.setTextContent(now.toString());
        timestampElement.appendChild(createdElement);
        
        // Expires zamanı (30 saniye sonra)
        Element expiresElement = document.createElementNS(XmlConstants.NS_WSU, "wsu:Expires");
        java.time.Instant expires = now.plusSeconds(30);
        expiresElement.setTextContent(expires.toString());
        timestampElement.appendChild(expiresElement);
        
        // Security header'ın ilk child'ı olarak ekle (BST'den önce)
        if (securityElement.hasChildNodes()) {
            securityElement.insertBefore(timestampElement, securityElement.getFirstChild());
        } else {
            securityElement.appendChild(timestampElement);
        }
    }

    /**
     * Security header'a BinarySecurityToken ekler.
     */
    private String addBinarySecurityToken(Document document,
                                         String soapNamespace,
                                         SigningMaterial material) throws Exception {
        String bstReference = "X509-" + material.getSigningCertificate().getSerialNumber();

        Element headerElement = (Element) document
            .getElementsByTagNameNS(soapNamespace, "Header").item(0);
        
        if (headerElement == null) {
            throw new SignatureException("SOAP Header bulunamadı");
        }

        Element securityElement = (Element) headerElement
            .getElementsByTagNameNS(XmlConstants.NS_WSSE, "Security").item(0);
        
        if (securityElement == null) {
            securityElement = document.createElementNS(XmlConstants.NS_WSSE, "wsse:Security");
            headerElement.appendChild(securityElement);
        }

        Element binarySecurityToken = document.createElementNS(
            XmlConstants.NS_WSSE, "wsse:BinarySecurityToken");
        binarySecurityToken.setAttribute("EncodingType", XmlConstants.ATTR_EncodingType);
        binarySecurityToken.setAttribute("ValueType", XmlConstants.ATTR_ValueType);
        binarySecurityToken.setAttributeNS(XmlConstants.NS_WSU, "wsu:Id", bstReference);
        // ID attribute'unu XML parser'a bildir
        binarySecurityToken.setIdAttributeNS(XmlConstants.NS_WSU, "Id", true);
        binarySecurityToken.setTextContent(
            Base64.getEncoder().encodeToString(
                material.getSigningCertificate().getEncoded()));

        securityElement.insertBefore(binarySecurityToken, securityElement.getFirstChild());

        return bstReference;
    }

    /**
     * WS-Security imzasını oluşturur ve uygular.
     * Manuel XML Signature oluşturur (WSS4J namespace sorunlarını bypass eder).
     */
    private void signDocument(Document document,
                             Element securityElement,
                             SigningMaterial material,
                             String alias,
                             char[] pin,
                             String bstReference) throws Exception {
        
        semaphore.acquire();
        try {
            // XML Signature factory oluştur
            javax.xml.crypto.dsig.XMLSignatureFactory sigFactory = 
                javax.xml.crypto.dsig.XMLSignatureFactory.getInstance("DOM");
            
            // DigestMethod
            javax.xml.crypto.dsig.DigestMethod digestMethod = 
                sigFactory.newDigestMethod(javax.xml.crypto.dsig.DigestMethod.SHA256, null);
            
            // Transform'lar (Exclusive C14N)
            List<javax.xml.crypto.dsig.Transform> transforms = new ArrayList<>();
            transforms.add(sigFactory.newTransform(
                javax.xml.crypto.dsig.CanonicalizationMethod.EXCLUSIVE,
                (javax.xml.crypto.dsig.spec.TransformParameterSpec) null));
            
            // İmzalanacak referanslar
            List<javax.xml.crypto.dsig.Reference> references = new ArrayList<>();
            
            // Timestamp referansı
            references.add(sigFactory.newReference(
                "#SignedSoapTimestampContent",
                digestMethod,
                transforms,
                null,
                null));
            
            // Body referansı
            references.add(sigFactory.newReference(
                "#SignedSoapBodyContent",
                digestMethod,
                transforms,
                null,
                null));
            
            // SignedInfo
            javax.xml.crypto.dsig.SignedInfo signedInfo = sigFactory.newSignedInfo(
                sigFactory.newCanonicalizationMethod(
                    javax.xml.crypto.dsig.CanonicalizationMethod.EXCLUSIVE,
                    (javax.xml.crypto.dsig.spec.C14NMethodParameterSpec) null),
                sigFactory.newSignatureMethod(
                    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", null),
                references);
            
            // KeyInfo - SecurityTokenReference kullan
            Element securityTokenRefElement = createSecurityTokenReference(
                document, bstReference);
            List<javax.xml.crypto.XMLStructure> keyInfoContent = new ArrayList<>();
            keyInfoContent.add(new javax.xml.crypto.dom.DOMStructure(securityTokenRefElement));
            javax.xml.crypto.dsig.keyinfo.KeyInfo keyInfo = 
                sigFactory.getKeyInfoFactory().newKeyInfo(keyInfoContent);
            
            // Private key
            java.security.PrivateKey privateKey = material.getPrivateKey();
            
            // XMLSignature oluştur
            javax.xml.crypto.dsig.XMLSignature signature = 
                sigFactory.newXMLSignature(signedInfo, keyInfo);
            
            // DOMSignContext oluştur ve imzala
            javax.xml.crypto.dsig.dom.DOMSignContext signContext = 
                new javax.xml.crypto.dsig.dom.DOMSignContext(privateKey, securityElement);
            
            // Namespace prefix mapping
            signContext.putNamespacePrefix(
                javax.xml.crypto.dsig.XMLSignature.XMLNS, "ds");
            
            // Custom URIDereferencer - ID attribute'larını manuel olarak çöz
            signContext.setURIDereferencer(new javax.xml.crypto.URIDereferencer() {
                @Override
                public javax.xml.crypto.Data dereference(javax.xml.crypto.URIReference uriReference, 
                                                         javax.xml.crypto.XMLCryptoContext context) 
                        throws javax.xml.crypto.URIReferenceException {
                    String uri = uriReference.getURI();
                    LOGGER.debug("URIDereferencer çağrıldı: URI={}", uri);
                    
                    if (uri != null && uri.startsWith("#")) {
                        String id = uri.substring(1);
                        LOGGER.debug("ID arıyor: {}", id);
                        
                        // ID ile elementi bul
                        org.w3c.dom.Element element = findElementById(document, id);
                        if (element != null) {
                            LOGGER.debug("Element başarıyla bulundu ve döndürülüyor: {}", id);
                            // NodeSetData olarak dön
                            java.util.Set<org.w3c.dom.Node> nodeSet = 
                                new java.util.HashSet<org.w3c.dom.Node>();
                            nodeSet.add(element);
                            return new javax.xml.crypto.NodeSetData() {
                                @Override
                                public java.util.Iterator<org.w3c.dom.Node> iterator() {
                                    return nodeSet.iterator();
                                }
                            };
                        } else {
                            LOGGER.error("Element bulunamadı! ID: {}", id);
                        }
                    }
                    throw new javax.xml.crypto.URIReferenceException(
                        "Element bulunamadı: " + uri);
                }
            });
            
            // İmzala
            signature.sign(signContext);
            
        } finally {
            semaphore.release();
        }
    }
    
    /**
     * SecurityTokenReference elemanı oluşturur.
     */
    private Element createSecurityTokenReference(Document document, String bstReference) {
        Element secTokenRef = document.createElementNS(XmlConstants.NS_WSSE, "wsse:SecurityTokenReference");
        Element reference = document.createElementNS(XmlConstants.NS_WSSE, "wsse:Reference");
        reference.setAttribute("URI", "#" + bstReference);
        reference.setAttribute("ValueType", XmlConstants.ATTR_ValueType);
        secTokenRef.appendChild(reference);
        return secTokenRef;
    }
    
    /**
     * Dokümanda belirli ID attribute'u ile elementi bulur.
     * Tüm dokümanda recursive olarak arar.
     */
    private Element findElementById(Document document, String id) {
        return findElementByIdRecursive(document.getDocumentElement(), id);
    }
    
    /**
     * Recursive olarak ID attribute'u ile elementi arar.
     */
    private Element findElementByIdRecursive(Element element, String id) {
        if (id == null || id.isEmpty()) {
            return null;
        }
        
        // Bu elementin Id attribute'unu kontrol et
        String elementId = element.getAttribute("Id");
        if (elementId != null && !elementId.isEmpty() && id.equals(elementId)) {
            LOGGER.debug("Element bulundu: {} -> {}", id, element.getLocalName());
            return element;
        }
        
        // wsu:Id attribute'unu da kontrol et
        String wsuId = element.getAttributeNS(XmlConstants.NS_WSU, "Id");
        if (wsuId != null && !wsuId.isEmpty() && id.equals(wsuId)) {
            LOGGER.debug("Element bulundu (wsu:Id): {} -> {}", id, element.getLocalName());
            return element;
        }
        
        // Child elementlerde ara
        org.w3c.dom.NodeList children = element.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            org.w3c.dom.Node node = children.item(i);
            if (node instanceof Element) {
                Element found = findElementByIdRecursive((Element) node, id);
                if (found != null) {
                    return found;
                }
            }
        }
        
        return null;
    }

    /**
     * Document'i byte dizisine dönüştürür.
     */
    private byte[] documentToBytes(Document document) throws Exception {
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
        transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
        
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(outputStream));
        return outputStream.toByteArray();
    }
}

