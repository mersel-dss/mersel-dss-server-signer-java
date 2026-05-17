package io.mersel.dss.signer.api.services.signature.wssecurity;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import io.mersel.dss.signer.api.constants.XmlConstants;
import io.mersel.dss.signer.api.exceptions.SignatureException;
import io.mersel.dss.signer.api.models.SignResponse;
import io.mersel.dss.signer.api.models.SigningMaterial;
import io.mersel.dss.signer.api.services.crypto.DigestAlgorithmResolverService;
import io.mersel.dss.signer.api.services.keystore.iaik.Pkcs11EcdsaSignatureEncoder;
import io.mersel.dss.signer.api.services.keystore.iaik.Pkcs11Signer;
import io.mersel.dss.signer.api.util.xml.SecureXmlFactories;
import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.Canonicalizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.util.concurrent.Semaphore;

/**
 * SOAP mesajları için WS-Security XML imzaları oluşturan servis.
 * SOAP 1.1 ve SOAP 1.2'yi destekler; <b>hem PFX hem HSM (PKCS#11)</b>
 * imzalama yolunu aynı kod akışıyla çözer.
 *
 * <h2>Tasarım</h2>
 * <p>Bu servis JCA {@link javax.xml.crypto.dsig.XMLSignatureFactory}
 * kullanmaz çünkü o API yalnızca {@link java.security.PrivateKey} ile imza
 * atabilir — HSM yolunda elimizde sadece bir <em>key handle</em> var,
 * JCA-uyumlu PrivateKey değil. Bunun yerine:</p>
 *
 * <ol>
 *   <li><b>SignedInfo</b> + <b>Reference</b> elementlerini doğrudan DOM ile
 *       inşa ederiz.</li>
 *   <li>Her referans için hedef elementi <b>Apache Santuario</b>'nun
 *       {@link Canonicalizer}'ı ile EXC-C14N'leyip {@link MessageDigest}
 *       ile hash'leriz.</li>
 *   <li>SignedInfo'yu yine EXC-C14N'leyip {@link CryptoSigner} aracılığıyla
 *       imzalarız — PFX yolunda JCA, HSM yolunda
 *       {@link Pkcs11Signer#sign(byte[], SignatureAlgorithm)}.</li>
 *   <li>ECDSA imzaları XMLDsig spec'inde (RFC 4051 §3.4.1)
 *       <b>raw {@code r||s}</b> formatında olmalıdır. CMS/CAdES'in
 *       beklediği DER SEQUENCE'tan farklı; bu yüzden imzayı
 *       {@link Pkcs11EcdsaSignatureEncoder#derToRaw} ile dönüştürürüz.</li>
 * </ol>
 *
 * <h2>Thread-safety</h2>
 * <p>{@code signatureSemaphore} aynı anda imza atan thread sayısını sınırlar
 * (HSM session pool boyutuyla eşleşmeli). Servis state'siz; her çağrı izole.</p>
 */
@Service
public class WsSecuritySignatureService {

    private static final Logger LOGGER = LoggerFactory.getLogger(WsSecuritySignatureService.class);

    private static final String BODY_ID = "SignedSoapBodyContent";
    private static final String TS_ID = "SignedSoapTimestampContent";
    private static final String NS_WSSE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    private static final String NS_DSIG = "http://www.w3.org/2000/09/xmldsig#";
    private static final String NS_DSIG_MORE = "http://www.w3.org/2001/04/xmldsig-more#";
    private static final String NS_XMLENC = "http://www.w3.org/2001/04/xmlenc#";
    private static final String C14N_EXCL = Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS;

    static {
        // Apache Santuario'nun bir kez initialize edilmesi gerekiyor (Canonicalizer
        // ve diğer algoritmaların registry'sini kurar). Idempotent.
        if (!Init.isInitialized()) {
            Init.init();
        }
    }

    private final Semaphore semaphore;
    private final DigestAlgorithmResolverService digestAlgorithmResolver;

    public WsSecuritySignatureService(Semaphore signatureSemaphore,
                                      DigestAlgorithmResolverService digestAlgorithmResolver) {
        this.semaphore = signatureSemaphore;
        this.digestAlgorithmResolver = digestAlgorithmResolver;
    }

    /**
     * SOAP zarfını WS-Security imzası ile imzalar. PFX ve HSM yapılandırmaları
     * her ikisi de desteklenir.
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

            Element soapHeaderElement = ensureSoapHeader(soapDocument, soapNamespace);
            Element securityElement = createSecurityHeader(soapDocument, soapHeaderElement);

            addTimestamp(soapDocument, securityElement);

            Element bodyElement = (Element) soapDocument
                .getElementsByTagNameNS(soapNamespace, "Body").item(0);
            if (bodyElement != null) {
                bodyElement.setAttribute("Id", BODY_ID);
                bodyElement.setIdAttribute("Id", true);
                bodyElement.removeAttribute("wsu:Id");
                bodyElement.removeAttribute("xmlns:xsi");
                bodyElement.removeAttribute("xmlns:xsd");
            }

            String bstReference = addBinarySecurityToken(
                soapDocument, soapNamespace, material);

            Element testTimestamp = findElementById(soapDocument, TS_ID);
            Element testBody = findElementById(soapDocument, BODY_ID);
            LOGGER.debug("Pre-signature validation - Timestamp found: {}, Body found: {}",
                testTimestamp != null, testBody != null);
            if (testTimestamp == null) {
                LOGGER.error("{} elementi bulunamadı!", TS_ID);
            }
            if (testBody == null) {
                LOGGER.error("{} elementi bulunamadı!", BODY_ID);
            }

            signDocument(soapDocument, securityElement, material, bstReference);

            byte[] signedBytes = documentToBytes(soapDocument);

            LOGGER.info("WS-Security imzası başarıyla oluşturuldu (SOAP {}, backend={})",
                useSoap12 ? "1.2" : "1.1",
                material.isPkcs11() ? "HSM/PKCS#11" : "PFX/JCA");
            return new SignResponse(signedBytes, null);

        } catch (Exception e) {
            LOGGER.error("WS-Security imzası oluşturulurken hata", e);
            throw new SignatureException("WS-Security imzası oluşturulamadı", e);
        }
    }

    /**
     * SOAP Header'ın doğru namespace ile var olduğundan emin olur. Yoksa oluşturur.
     */
    private Element ensureSoapHeader(Document document, String soapNamespace) {
        Element envelopeElement = document.getDocumentElement();
        Element headerElement = (Element) document
            .getElementsByTagNameNS(soapNamespace, "Header").item(0);

        if (headerElement == null) {
            LOGGER.debug("SOAP Header bulunamadı, oluşturuluyor (namespace: {})", soapNamespace);
            String prefix = soapNamespace.equals(XmlConstants.NS_SOAP_1_DOT_2_ENVELOPE) ? "env" : "soapenv";
            headerElement = document.createElementNS(soapNamespace, prefix + ":Header");

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

    private Element createSecurityHeader(Document document, Element soapHeaderElement) {
        Element securityElement = (Element) soapHeaderElement
            .getElementsByTagNameNS(XmlConstants.NS_WSSE, "Security").item(0);

        if (securityElement == null) {
            securityElement = document.createElementNS(XmlConstants.NS_WSSE, "wsse:Security");
            securityElement.setAttributeNS(
                "http://www.w3.org/2000/xmlns/",
                "xmlns:wsse",
                XmlConstants.NS_WSSE);
            securityElement.setAttributeNS(
                "http://www.w3.org/2000/xmlns/",
                "xmlns:wsu",
                XmlConstants.NS_WSU);

            if (soapHeaderElement.hasChildNodes()) {
                soapHeaderElement.insertBefore(securityElement, soapHeaderElement.getFirstChild());
            } else {
                soapHeaderElement.appendChild(securityElement);
            }

            LOGGER.debug("Security header oluşturuldu");
        }

        return securityElement;
    }

    private void addTimestamp(Document document, Element securityElement) {
        Element timestampElement = document.createElementNS(XmlConstants.NS_WSU, "wsu:Timestamp");
        timestampElement.setAttribute("Id", TS_ID);
        timestampElement.setIdAttribute("Id", true);

        Element createdElement = document.createElementNS(XmlConstants.NS_WSU, "wsu:Created");
        java.time.Instant now = java.time.Instant.now();
        createdElement.setTextContent(now.toString());
        timestampElement.appendChild(createdElement);

        Element expiresElement = document.createElementNS(XmlConstants.NS_WSU, "wsu:Expires");
        java.time.Instant expires = now.plusSeconds(30);
        expiresElement.setTextContent(expires.toString());
        timestampElement.appendChild(expiresElement);

        if (securityElement.hasChildNodes()) {
            securityElement.insertBefore(timestampElement, securityElement.getFirstChild());
        } else {
            securityElement.appendChild(timestampElement);
        }
    }

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
        binarySecurityToken.setIdAttributeNS(XmlConstants.NS_WSU, "Id", true);
        binarySecurityToken.setTextContent(
            Base64.getEncoder().encodeToString(
                material.getSigningCertificate().getEncoded()));

        securityElement.insertBefore(binarySecurityToken, securityElement.getFirstChild());

        return bstReference;
    }

    /**
     * Manuel XMLDsig akışı: SignedInfo + Reference oluştur, digest'leri hesapla,
     * SignedInfo'yu canonicalize edip imzala, sonucu DOM'a inject et.
     *
     * <p>Bu yol PFX (JCA) ve HSM (PKCS#11) için tamamen ortaktır; tek fark
     * {@link #signRaw} içindeki backend seçimi.</p>
     */
    private void signDocument(Document document,
                             Element securityElement,
                             SigningMaterial material,
                             String bstReference) throws Exception {
        semaphore.acquire();
        try {
            X509Certificate cert = material.getSigningCertificate();
            DigestAlgorithm digestAlg = digestAlgorithmResolver.resolveDigestAlgorithm(cert);
            EncryptionAlgorithm encAlg = EncryptionAlgorithm.forKey(cert.getPublicKey());
            SignatureAlgorithm sigAlg = SignatureAlgorithm.getAlgorithm(encAlg, digestAlg);
            if (sigAlg == null) {
                throw new SignatureException(
                    "Desteklenmeyen kombinasyon: enc=" + encAlg + ", digest=" + digestAlg);
            }
            String signatureMethodUri = signatureMethodUri(sigAlg);
            String digestMethodUri = digestMethodUri(digestAlg);

            // 1) <ds:Signature> skeleton'u
            Element signatureElem = document.createElementNS(NS_DSIG, "ds:Signature");
            signatureElem.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:ds", NS_DSIG);

            Element signedInfo = document.createElementNS(NS_DSIG, "ds:SignedInfo");
            Element cm = document.createElementNS(NS_DSIG, "ds:CanonicalizationMethod");
            cm.setAttribute("Algorithm", C14N_EXCL);
            signedInfo.appendChild(cm);

            Element sm = document.createElementNS(NS_DSIG, "ds:SignatureMethod");
            sm.setAttribute("Algorithm", signatureMethodUri);
            signedInfo.appendChild(sm);

            // Referanslar: Timestamp + Body
            signedInfo.appendChild(buildReference(document, TS_ID, digestMethodUri));
            signedInfo.appendChild(buildReference(document, BODY_ID, digestMethodUri));

            signatureElem.appendChild(signedInfo);

            Element sigValueElem = document.createElementNS(NS_DSIG, "ds:SignatureValue");
            signatureElem.appendChild(sigValueElem);

            // KeyInfo → SecurityTokenReference → BST reference
            signatureElem.appendChild(buildKeyInfo(document, bstReference));

            // Security header'ın altına Signature ekle.
            securityElement.appendChild(signatureElem);

            // 2) Referansların DigestValue'larını hesapla.
            NodeList refs = signedInfo.getElementsByTagNameNS(NS_DSIG, "Reference");
            for (int i = 0; i < refs.getLength(); i++) {
                Element refElem = (Element) refs.item(i);
                String uri = refElem.getAttribute("URI");
                String id = uri.startsWith("#") ? uri.substring(1) : uri;
                Element target = findElementById(document, id);
                if (target == null) {
                    throw new SignatureException("Reference URI=" + uri + " hedefi DOM'da bulunamadı");
                }
                byte[] c14nBytes = canonicalize(target);
                byte[] digest = MessageDigest.getInstance(digestAlg.getJavaName()).digest(c14nBytes);
                Element digestValueElem = (Element) refElem
                    .getElementsByTagNameNS(NS_DSIG, "DigestValue").item(0);
                digestValueElem.setTextContent(Base64.getEncoder().encodeToString(digest));
            }

            // 3) SignedInfo'yu canonicalize edip imzala.
            byte[] signedInfoBytes = canonicalize(signedInfo);
            byte[] signatureBytes = signRaw(signedInfoBytes, material, sigAlg);

            // 4) ECDSA/DSA imzaları XMLDsig spec'ine göre raw r||s'a indirgenir
            //    (RFC 4051 §3.4.1, DSA için xmldsig dsa-sha1/256).
            //    PFX yolunda JCA Signature.sign() DER üretir;
            //    HSM yolunda IaikPkcs11Module DER'e normalize ediyor — her iki
            //    durumda da DER'den raw'a çevirmek gerek. DSA için aynı encoder
            //    çalışır çünkü hem ECDSA hem DSA imzası ASN.1
            //    {@code SEQUENCE { INTEGER r, INTEGER s }} formatındadır;
            //    aradaki tek fark "field size" — ECDSA için curve P-XXX bit,
            //    DSA için subprime Q'nun bit uzunluğu.
            if (isEcdsa(encAlg)) {
                int fieldSize = ecFieldSizeBytes(cert);
                signatureBytes = Pkcs11EcdsaSignatureEncoder.derToRaw(signatureBytes, fieldSize);
            } else if (encAlg == EncryptionAlgorithm.DSA) {
                int fieldSize = dsaFieldSizeBytes(cert);
                signatureBytes = Pkcs11EcdsaSignatureEncoder.derToRaw(signatureBytes, fieldSize);
            }

            sigValueElem.setTextContent(Base64.getEncoder().encodeToString(signatureBytes));
        } finally {
            semaphore.release();
        }
    }

    private Element buildReference(Document document, String elementId, String digestMethodUri) {
        Element ref = document.createElementNS(NS_DSIG, "ds:Reference");
        ref.setAttribute("URI", "#" + elementId);

        Element transforms = document.createElementNS(NS_DSIG, "ds:Transforms");
        Element t = document.createElementNS(NS_DSIG, "ds:Transform");
        t.setAttribute("Algorithm", C14N_EXCL);
        transforms.appendChild(t);
        ref.appendChild(transforms);

        Element dm = document.createElementNS(NS_DSIG, "ds:DigestMethod");
        dm.setAttribute("Algorithm", digestMethodUri);
        ref.appendChild(dm);

        // DigestValue içeriği signDocument içinde set edilir.
        Element dv = document.createElementNS(NS_DSIG, "ds:DigestValue");
        ref.appendChild(dv);

        return ref;
    }

    private Element buildKeyInfo(Document document, String bstReference) {
        Element keyInfo = document.createElementNS(NS_DSIG, "ds:KeyInfo");
        Element str = document.createElementNS(NS_WSSE, "wsse:SecurityTokenReference");
        Element ref = document.createElementNS(NS_WSSE, "wsse:Reference");
        ref.setAttribute("URI", "#" + bstReference);
        ref.setAttribute(
            "ValueType",
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
        str.appendChild(ref);
        keyInfo.appendChild(str);
        return keyInfo;
    }

    /**
     * Backend-agnostic imzalama: PFX yolunda JCA, HSM yolunda PKCS#11.
     * Çıktı ECDSA için <b>DER SEQUENCE</b>, RSA için RSASSA-PKCS1-v1_5 encoded
     * (her ikisi de {@link SigningMaterial} kontratının standart çıktısı).
     */
    private byte[] signRaw(byte[] data, SigningMaterial material, SignatureAlgorithm sigAlg) throws Exception {
        return material.sign(data, sigAlg);
    }

    private byte[] canonicalize(Element element) throws Exception {
        Canonicalizer canonicalizer = Canonicalizer.getInstance(C14N_EXCL);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        canonicalizer.canonicalizeSubtree(element, out);
        return out.toByteArray();
    }

    private static boolean isEcdsa(EncryptionAlgorithm enc) {
        return enc == EncryptionAlgorithm.ECDSA || enc == EncryptionAlgorithm.PLAIN_ECDSA;
    }

    /**
     * EC eğri parametre boyutunu (P-256/384/521) byte cinsinden döndürür.
     * XMLDsig {@code SignatureValue} = {@code padZ(r, n) || padZ(s, n)} olur.
     */
    private static int ecFieldSizeBytes(X509Certificate cert) {
        if (!(cert.getPublicKey() instanceof ECPublicKey)) {
            throw new SignatureException(
                "ECDSA imzalama isteniyor ama sertifika public key EC değil: "
                + cert.getPublicKey().getAlgorithm());
        }
        ECPublicKey ec = (ECPublicKey) cert.getPublicKey();
        int bits = ec.getParams().getCurve().getField().getFieldSize();
        return (bits + 7) / 8;
    }

    /**
     * DSA subprime Q'nun bit uzunluğunu byte cinsinden döndürür. XMLDsig
     * {@code SignatureValue} = {@code padZ(r, |q|) || padZ(s, |q|)}.
     *
     * <p><b>Pratik notu:</b> Türkiye Mali Mühür sertifikaları DSA değildir
     * (RSA veya ECDSA). DSA desteği tamlık ve XMLDsig spec uyumu için
     * eklenmiştir; üretim ortamında DSA imzalama doğrulanmamıştır. Eğer
     * gerçekten kullanılacaksa entegrasyon testi yazılması gerekir.</p>
     */
    private static int dsaFieldSizeBytes(X509Certificate cert) {
        if (!(cert.getPublicKey() instanceof DSAPublicKey)) {
            throw new SignatureException(
                "DSA imzalama isteniyor ama sertifika public key DSA değil: "
                + cert.getPublicKey().getAlgorithm());
        }
        DSAPublicKey dsa = (DSAPublicKey) cert.getPublicKey();
        // DSA L (P bit length) ile N (Q bit length) farklı parametrelerdir;
        // imza komponentleri (r, s) ∈ [1, q-1] olduğu için N'i kullanırız.
        // Tipik: DSA-1024 → N=160 (20 byte), DSA-2048/3072 → N=256 (32 byte).
        int qBits = dsa.getParams().getQ().bitLength();
        return (qBits + 7) / 8;
    }

    private static String digestMethodUri(DigestAlgorithm digest) {
        switch (digest) {
            case SHA1:   return NS_DSIG + "sha1";
            case SHA224: return NS_DSIG_MORE + "sha224";
            case SHA256: return NS_XMLENC + "sha256";
            case SHA384: return NS_DSIG_MORE + "sha384";
            case SHA512: return NS_XMLENC + "sha512";
            default:
                throw new SignatureException("XMLDsig için desteklenmeyen digest: " + digest);
        }
    }

    /**
     * XMLDsig / xmldsig-more URI'lerine map eder. RSA-PSS şu an WS-Security
     * tarafında kapsam dışı (mvcd RFC 6931 var ama kullanım çok dar).
     */
    private static String signatureMethodUri(SignatureAlgorithm sigAlg) {
        EncryptionAlgorithm enc = sigAlg.getEncryptionAlgorithm();
        DigestAlgorithm digest = sigAlg.getDigestAlgorithm();
        if (enc == EncryptionAlgorithm.ECDSA || enc == EncryptionAlgorithm.PLAIN_ECDSA) {
            switch (digest) {
                case SHA1:   return NS_DSIG_MORE + "ecdsa-sha1";
                case SHA224: return NS_DSIG_MORE + "ecdsa-sha224";
                case SHA256: return NS_DSIG_MORE + "ecdsa-sha256";
                case SHA384: return NS_DSIG_MORE + "ecdsa-sha384";
                case SHA512: return NS_DSIG_MORE + "ecdsa-sha512";
                default:
                    throw new SignatureException("ECDSA için desteklenmeyen digest: " + digest);
            }
        }
        if (enc == EncryptionAlgorithm.DSA) {
            // DSA Türkiye e-imzasında pratik olarak ölü, ama legacy desteği:
            return digest == DigestAlgorithm.SHA1
                ? NS_DSIG + "dsa-sha1"
                : NS_DSIG_MORE + "dsa-sha256";
        }
        // RSA (PKCS#1 v1.5)
        switch (digest) {
            case SHA1:   return NS_DSIG + "rsa-sha1";
            case SHA224: return NS_DSIG_MORE + "rsa-sha224";
            case SHA256: return NS_DSIG_MORE + "rsa-sha256";
            case SHA384: return NS_DSIG_MORE + "rsa-sha384";
            case SHA512: return NS_DSIG_MORE + "rsa-sha512";
            default:
                throw new SignatureException("RSA için desteklenmeyen digest: " + digest);
        }
    }

    /**
     * Tüm dokümanda recursive olarak verilen ID değerini taşıyan elementi arar.
     * "Id" (WS-Security tarzı) ve "wsu:Id" attribute'larını kontrol eder.
     */
    private Element findElementById(Document document, String id) {
        return findElementByIdRecursive(document.getDocumentElement(), id);
    }

    private Element findElementByIdRecursive(Element element, String id) {
        if (id == null || id.isEmpty()) {
            return null;
        }
        String elementId = element.getAttribute("Id");
        if (elementId != null && !elementId.isEmpty() && id.equals(elementId)) {
            return element;
        }
        String wsuId = element.getAttributeNS(XmlConstants.NS_WSU, "Id");
        if (wsuId != null && !wsuId.isEmpty() && id.equals(wsuId)) {
            return element;
        }
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

    private byte[] documentToBytes(Document document) throws Exception {
        TransformerFactory transformerFactory = SecureXmlFactories.newTransformerFactory();
        Transformer transformer = transformerFactory.newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
        transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(outputStream));
        return outputStream.toByteArray();
    }
}
