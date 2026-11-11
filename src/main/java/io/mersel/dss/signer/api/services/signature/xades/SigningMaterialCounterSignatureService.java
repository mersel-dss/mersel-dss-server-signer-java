package io.mersel.dss.signer.api.services.signature.xades;

import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import io.mersel.dss.signer.api.exceptions.SignatureException;
import io.mersel.dss.signer.api.models.SignResponse;
import io.mersel.dss.signer.api.models.SigningMaterial;
import io.mersel.dss.signer.api.services.keystore.iaik.Pkcs11EcdsaSignatureEncoder;
import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.Canonicalizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.security.auth.x500.X500Principal;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.time.temporal.ChronoField;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.Semaphore;

/**
 * Entegratör tarafından imzalanmış XAdES belgesine, entegratörün <b>kendi
 * ana imza sertifikasıyla</b> ({@link SigningMaterial} — PFX <em>veya</em>
 * HSM/PKCS#11) ETSI XAdES-BES uyumlu <em>counter signature</em> (GİB
 * terminolojisiyle <b>seri imza</b>) ekleyen servis.
 *
 * <h3>Neden ayrı bir servis?</h3>
 * <p>{@link TestUserCounterSignatureService} imzayı
 * {@code javax.xml.crypto.dsig} {@code DOMSignContext(PrivateKey, ...)}
 * ile atar; bu API yalnızca JCA {@link java.security.PrivateKey} ile
 * çalışır. Ana imza materyali HSM'de olduğunda elimizde sadece bir
 * <em>key handle</em> vardır — JCA-uyumlu PrivateKey değil (bkz.
 * {@code WsSecuritySignatureService} tasarım notu). Bu servis bu yüzden
 * imzayı manuel akışla atar:</p>
 * <ol>
 *   <li>Counter-signature DOM iskeleti doğrudan kurulur (SignedInfo +
 *       iki Reference + SignatureValue + KeyInfo + QualifyingProperties).</li>
 *   <li>Her Reference hedefi Apache Santuario {@link Canonicalizer} ile
 *       canonicalize edilip {@link MessageDigest} ile hash'lenir.</li>
 *   <li>SignedInfo, belirtilen c14n (INCLUSIVE_WITH_COMMENTS) ile
 *       canonicalize edilip {@link SigningMaterial#sign(byte[], SignatureAlgorithm)}
 *       ile imzalanır — PFX yolunda JCA, HSM yolunda C_Sign.</li>
 *   <li>ECDSA imzaları XML-DSig spec'i gereği raw {@code r||s} formatına
 *       çevrilir ({@link Pkcs11EcdsaSignatureEncoder#derToRaw}).</li>
 * </ol>
 *
 * <h3>Üretilen yapı — GİB ile doğrulanmış akışla parite</h3>
 * <p>Reference set'i, Id şablonları, algoritma seçimi (EC → ECDSA-SHA384 /
 * SHA-384, RSA → RSA-SHA256 / SHA-256), c14n seçimleri ve XAdES-BES
 * SignedProperties içeriği {@link TestUserCounterSignatureService}
 * (mersel-dss-agent-signer-java'daki production-doğrulanmış
 * {@code XadesService.doCounterSignature} paritesi) ile birebir aynıdır.
 * Digest hesaplama kuralları XML-DSig standardıdır: transformsuz node-set
 * Reference'ları inclusive c14n <em>comments'siz</em>, transform'lular
 * transform'un kendisiyle (burada WithComments) digest'lenir.</p>
 *
 * <h3>Kullanım senaryosu</h3>
 * <p>GİB, özel entegratörün müşterileri adına belge/rapor göndermesi için
 * önce kendisini ilgili hizmette (ör. e-MM) aktif etmesini ister. HrXml
 * (Kullanıcı Açma/Kapama) belgesi: (1) entegratör mali mührüyle imzalanır
 * ({@code POST /v1/xadessign}, {@code documentType=HrXml}), (2) seri imza
 * (counter signature) entegratörün kendi sertifikasıyla bu servis üzerinden
 * atılır — açılan kullanıcı entegratörün kendisi olduğundan GİB'in 1182
 * "eşleşmeyen seri imza bilgisi" kontrolü böylece sağlanır.</p>
 */
@Service
public class SigningMaterialCounterSignatureService {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(SigningMaterialCounterSignatureService.class);

    public static final String DS_NS = "http://www.w3.org/2000/09/xmldsig#";
    public static final String XADES_NS = "http://uri.etsi.org/01903/v1.3.2#";
    private static final String XMLNS_NS = "http://www.w3.org/2000/xmlns/";

    /** SHA-384 digest URL (xmldsig-more). */
    static final String DIGEST_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384";
    /** SHA-256 digest URL (xmlenc — JSR-105 DigestMethod.SHA256 ile aynı). */
    static final String DIGEST_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";
    /** ECDSA-SHA384 signature URL. */
    static final String SIG_ECDSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";
    /** RSA-SHA256 signature URL. */
    static final String SIG_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

    /** XAdES 1.3.2 — counter-signature Reference Type URI (parent {@code SignatureValue} hedefi). */
    public static final String XADES_TYPE_COUNTERSIGNED_SIGNATURE =
            "http://uri.etsi.org/01903#CountersignedSignature";

    /** XAdES 1.3.2 — SignedProperties Reference Type URI. */
    public static final String XADES_TYPE_SIGNED_PROPERTIES =
            "http://uri.etsi.org/01903#SignedProperties";

    /**
     * XAdES {@code SigningTime} formatı: {@code 2026-05-20T16:43:15.486+03:00}.
     * Millisaniye 3 hane sabit; saniyenin altı yuvarlanmıyor sadece kırpılıyor.
     */
    private static final DateTimeFormatter XADES_SIGNING_TIME_FORMAT =
            new DateTimeFormatterBuilder()
                    .append(DateTimeFormatter.ISO_LOCAL_DATE)
                    .appendLiteral('T')
                    .appendPattern("HH:mm:ss")
                    .appendFraction(ChronoField.MILLI_OF_SECOND, 3, 3, true)
                    .appendOffset("+HH:MM", "Z")
                    .toFormatter(Locale.ROOT);

    /** Standart XAdES Base64 line width (RFC 2045 / MIME default). */
    private static final int BASE64_LINE_WIDTH = 76;

    private final Semaphore semaphore;

    public SigningMaterialCounterSignatureService(Semaphore signatureSemaphore) {
        this.semaphore = signatureSemaphore;

        // Apache Santuario init — Canonicalizer registry'si için. Idempotent.
        Init.init();

        LOGGER.info("SigningMaterial counter-signature (entegratör seri imzası) servisi hazır.");
    }

    /* ================================================================== */
    /* Public API                                                          */
    /* ================================================================== */

    /**
     * Daha önce entegratör tarafından imzalanmış XAdES belgesine, entegratörün
     * ana imza materyaliyle (PFX veya HSM) counter signature ekler.
     *
     * @param signedXmlInputStream Entegratör tarafından imzalanmış XAdES belgesi
     * @param material             Ana imza materyali (PFX veya HSM backend)
     * @return Counter-sign edilmiş belge + Base64 counter-signature SignatureValue
     */
    public SignResponse counterSign(InputStream signedXmlInputStream, SigningMaterial material) {
        if (signedXmlInputStream == null) {
            throw new SignatureException("INVALID_INPUT",
                    "Counter signature için document alanı zorunludur");
        }
        if (material == null) {
            throw new SignatureException("INVALID_INPUT",
                    "Counter signature için SigningMaterial zorunludur");
        }

        try {
            byte[] xmlBytes = readAll(signedXmlInputStream);
            X509Certificate certificate = material.getSigningCertificate();

            LOGGER.info("Entegratör seri imzası (counter-signature) istemi: backend={}, subject={}",
                    material.getBackendName(), certificate.getSubjectX500Principal());

            CounterSignResult result = doCounterSignature(xmlBytes, material, certificate);

            LOGGER.info("Entegratör seri imzası başarıyla eklendi. backend={}",
                    material.getBackendName());

            return new SignResponse(
                    result.signedDocument,
                    Base64.getEncoder().encodeToString(result.signatureValue));

        } catch (SignatureException e) {
            throw e;
        } catch (Exception e) {
            LOGGER.error("Entegratör seri imzası oluşturulurken hata", e);
            throw new SignatureException(
                    "Entegratör seri imzası oluşturulamadı: " + e.getMessage(), e);
        }
    }

    /* ================================================================== */
    /* XAdES Counter-signature implementation                              */
    /* ================================================================== */

    /**
     * Var olan ilk {@code <ds:Signature>}'ın {@code <ds:SignatureValue>}'su
     * üzerine, verilen materyal ile ETSI XAdES-BES uyumlu
     * {@code <xades:CounterSignature>} ekler.
     *
     * <p>Üretilen counter-signature kendi başına eksiksiz bir XAdES-BES
     * imzasıdır: SignedInfo iki Reference (kendi SignedProperties + karşı
     * imzalanan SignatureValue) içerir, KeyInfo yalnız imzacı sertifikasıdır,
     * QualifyingProperties altında SigningTime + SigningCertificate (CertDigest
     * + IssuerSerial) bulunur.</p>
     */
    CounterSignResult doCounterSignature(byte[] xmlBytes,
                                         SigningMaterial material,
                                         X509Certificate signingCert) throws Exception {
        Document doc = parseXml(xmlBytes);

        NodeList sigs = doc.getElementsByTagNameNS(DS_NS, "Signature");
        if (sigs.getLength() == 0) {
            throw new SignatureException("NO_PARENT_SIGNATURE",
                    "XML'de imzalanacak <ds:Signature> bulunamadı (counter-sig için zorunlu).");
        }
        Element existingSig = (Element) sigs.item(0);

        Element parentSigValueEl = findChildSignatureValue(existingSig);
        if (parentSigValueEl == null) {
            throw new SignatureException("NO_PARENT_SIGNATURE",
                    "Mevcut <ds:Signature> içinde <ds:SignatureValue> yok.");
        }

        // Karşı imzalanacak SignatureValue'a XML ID garantisi (URI fragment
        // dereferencing için). Bu attribute parent SignedInfo digest'ine
        // dahil değildir; parent imza geçerli kalır.
        String parentSigValueId = parentSigValueEl.getAttribute("Id");
        if (parentSigValueId == null || parentSigValueId.isEmpty()) {
            parentSigValueId = "Signature-Value-Id-" + UUID.randomUUID();
            parentSigValueEl.setAttribute("Id", parentSigValueId);
        }
        parentSigValueEl.setIdAttribute("Id", true);

        Element ussp = findOrCreateUnsignedSignatureProperties(existingSig, doc);

        Element counterSig = doc.createElementNS(XADES_NS, "xades:CounterSignature");
        ensureNamespaceInScope(counterSig, "xades", XADES_NS);
        ussp.appendChild(counterSig);

        // Counter-signature'a ait Id'ler — agent/TestUser servisiyle aynı şablon.
        String counterSigId = "Signature-Id-" + UUID.randomUUID();
        String counterSigValueId = "Signature-Value-Id-" + UUID.randomUUID();
        String signedPropsId = "Signed-Properties-Id-" + UUID.randomUUID();
        String objectId = "Object-Id-" + UUID.randomUUID();
        String signedPropsRefId = "Reference-Id-" + UUID.randomUUID();
        String counterRefId = "Reference-Id-" + UUID.randomUUID();

        // Algoritma seçimi: EC = ECDSA-SHA384 / SHA-384, RSA = RSA-SHA256 / SHA-256
        // (TestUserCounterSignatureService ile aynı kural; mali mühür RSA veya EC olur).
        boolean ecdsa = isEcdsa(signingCert);
        String digestUrl = ecdsa ? DIGEST_SHA384 : DIGEST_SHA256;
        String digestJavaName = ecdsa ? "SHA-384" : "SHA-256";
        String sigUrl = ecdsa ? SIG_ECDSA_SHA384 : SIG_RSA_SHA256;
        SignatureAlgorithm signatureAlgorithm = ecdsa
                ? SignatureAlgorithm.ECDSA_SHA384
                : SignatureAlgorithm.RSA_SHA256;

        /* 1) ds:Signature iskeleti — namespace'ler explicit bağlanır ki hem
         *    final serileştirme hem de inclusive c14n deterministik olsun. */
        Element signatureEl = doc.createElementNS(DS_NS, "ds:Signature");
        signatureEl.setAttribute("Id", counterSigId);
        signatureEl.setIdAttribute("Id", true);
        signatureEl.setAttributeNS(XMLNS_NS, "xmlns:ds", DS_NS);
        signatureEl.setAttributeNS(XMLNS_NS, "xmlns:xades", XADES_NS);
        counterSig.appendChild(signatureEl);

        /* 2) SignedInfo — c14n INCLUSIVE_WITH_COMMENTS; Reference sırası
         *    verified akışla aynı: önce SignedProperties, sonra
         *    CountersignedSignature. */
        Element signedInfo = doc.createElementNS(DS_NS, "ds:SignedInfo");
        signatureEl.appendChild(signedInfo);

        Element c14nMethod = doc.createElementNS(DS_NS, "ds:CanonicalizationMethod");
        c14nMethod.setAttribute("Algorithm", Canonicalizer.ALGO_ID_C14N_WITH_COMMENTS);
        signedInfo.appendChild(c14nMethod);

        Element signatureMethod = doc.createElementNS(DS_NS, "ds:SignatureMethod");
        signatureMethod.setAttribute("Algorithm", sigUrl);
        signedInfo.appendChild(signatureMethod);

        // Reference #1 — kendi SignedProperties (transformsuz; node-set digest
        // XML-DSig standardı gereği inclusive c14n omit-comments ile hesaplanır).
        Element signedPropsRef = doc.createElementNS(DS_NS, "ds:Reference");
        signedPropsRef.setAttribute("Id", signedPropsRefId);
        signedPropsRef.setAttribute("Type", XADES_TYPE_SIGNED_PROPERTIES);
        signedPropsRef.setAttribute("URI", "#" + signedPropsId);
        signedInfo.appendChild(signedPropsRef);
        appendDigestMethodAndValue(doc, signedPropsRef, digestUrl);

        // Reference #2 — karşı imzalanan SignatureValue (transform c14n WithComments).
        Element counterRef = doc.createElementNS(DS_NS, "ds:Reference");
        counterRef.setAttribute("Id", counterRefId);
        counterRef.setAttribute("Type", XADES_TYPE_COUNTERSIGNED_SIGNATURE);
        counterRef.setAttribute("URI", "#" + parentSigValueId);
        signedInfo.appendChild(counterRef);

        Element transforms = doc.createElementNS(DS_NS, "ds:Transforms");
        Element transform = doc.createElementNS(DS_NS, "ds:Transform");
        transform.setAttribute("Algorithm", Canonicalizer.ALGO_ID_C14N_WITH_COMMENTS);
        transforms.appendChild(transform);
        counterRef.appendChild(transforms);
        appendDigestMethodAndValue(doc, counterRef, digestUrl);

        /* 3) SignatureValue (boş — imzadan sonra doldurulur). */
        Element sigValueEl = doc.createElementNS(DS_NS, "ds:SignatureValue");
        sigValueEl.setAttribute("Id", counterSigValueId);
        sigValueEl.setIdAttribute("Id", true);
        signatureEl.appendChild(sigValueEl);

        /* 4) KeyInfo — yalnız imzacı sertifikası (xades:Cert ile zaten
         *    chain'e bağlanıyor). */
        Element keyInfo = doc.createElementNS(DS_NS, "ds:KeyInfo");
        Element x509Data = doc.createElementNS(DS_NS, "ds:X509Data");
        Element x509Certificate = doc.createElementNS(DS_NS, "ds:X509Certificate");
        x509Certificate.setTextContent(
                Base64.getEncoder().encodeToString(signingCert.getEncoded()));
        x509Data.appendChild(x509Certificate);
        keyInfo.appendChild(x509Data);
        signatureEl.appendChild(keyInfo);

        /* 5) Object / QualifyingProperties / SignedProperties
         *    (SigningTime + SigningCertificate: CertDigest + IssuerSerial). */
        Element objectEl = doc.createElementNS(DS_NS, "ds:Object");
        objectEl.setAttribute("Id", objectId);
        objectEl.setIdAttribute("Id", true);
        signatureEl.appendChild(objectEl);

        Element qualifyingProps = doc.createElementNS(XADES_NS, "xades:QualifyingProperties");
        qualifyingProps.setAttribute("Target", "#" + counterSigId);
        objectEl.appendChild(qualifyingProps);

        Element signedPropsEl = doc.createElementNS(XADES_NS, "xades:SignedProperties");
        signedPropsEl.setAttribute("Id", signedPropsId);
        signedPropsEl.setIdAttribute("Id", true);
        qualifyingProps.appendChild(signedPropsEl);

        populateSignedProperties(doc, signedPropsEl, signingCert, digestUrl, digestJavaName);

        /* 6) Digest'leri hesapla ve doldur. */
        byte[] signedPropsC14n = canonicalizeSubtree(
                signedPropsEl, Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
        digestValueElementOf(signedPropsRef).setTextContent(
                digestBase64(signedPropsC14n, digestJavaName));

        byte[] parentSigValueC14n = canonicalizeSubtree(
                parentSigValueEl, Canonicalizer.ALGO_ID_C14N_WITH_COMMENTS);
        digestValueElementOf(counterRef).setTextContent(
                digestBase64(parentSigValueC14n, digestJavaName));

        /* 7) SignedInfo'yu c14n ile imzala — backend-agnostic
         *    (PFX → JCA, HSM → C_Sign). */
        byte[] signedInfoC14n = canonicalizeSubtree(
                signedInfo, Canonicalizer.ALGO_ID_C14N_WITH_COMMENTS);

        byte[] signatureBytes;
        semaphore.acquire();
        try {
            signatureBytes = material.sign(signedInfoC14n, signatureAlgorithm);
        } finally {
            semaphore.release();
        }

        // XML-DSig spec'i ECDSA SignatureValue'nun r||s (plain) formatında
        // olmasını şart koşar; PFX (JCA) ve HSM (IAIK) yollarının ikisi de
        // DER SEQUENCE üretir. RSA için bu adım atlanır.
        if (ecdsa) {
            signatureBytes = Pkcs11EcdsaSignatureEncoder.derToRaw(
                    signatureBytes, ecFieldSizeBytes(signingCert));
        }

        sigValueEl.setTextContent(Base64.getEncoder().encodeToString(signatureBytes));

        // Base64 kozmetiği — Santuario/Transformer &#13; entity'si üretmesin
        // diye counter-signature subtree'sindeki Base64 text'leri standart
        // 76-char LF ile yeniden wrap'le (digest/c14n girişi değildirler).
        rewrapBase64InSubtree(signatureEl);

        byte[] serialized = serialise(doc);
        return new CounterSignResult(serialized, signatureBytes);
    }

    /* ================================================================== */
    /* SignedProperties                                                    */
    /* ================================================================== */

    /**
     * {@code SignedProperties} altına {@code SignedSignatureProperties}
     * kurarak {@code SigningTime} + {@code SigningCertificate} (CertDigest
     * + IssuerSerial) yerleştirir.
     */
    private static void populateSignedProperties(
            Document doc, Element signedProps, X509Certificate signingCert,
            String digestUrl, String digestJavaName) throws Exception {
        Element ssp = doc.createElementNS(XADES_NS, "xades:SignedSignatureProperties");
        signedProps.appendChild(ssp);

        Element signingTime = doc.createElementNS(XADES_NS, "xades:SigningTime");
        signingTime.setTextContent(currentXadesSigningTime());
        ssp.appendChild(signingTime);

        Element signingCertificate = doc.createElementNS(XADES_NS, "xades:SigningCertificate");
        ssp.appendChild(signingCertificate);

        Element certEl = doc.createElementNS(XADES_NS, "xades:Cert");
        signingCertificate.appendChild(certEl);

        Element certDigest = doc.createElementNS(XADES_NS, "xades:CertDigest");
        certEl.appendChild(certDigest);
        Element certDigestMethod = doc.createElementNS(DS_NS, "ds:DigestMethod");
        certDigestMethod.setAttribute("Algorithm", digestUrl);
        certDigest.appendChild(certDigestMethod);
        Element certDigestValue = doc.createElementNS(DS_NS, "ds:DigestValue");
        certDigestValue.setTextContent(certificateDigestBase64(signingCert, digestJavaName));
        certDigest.appendChild(certDigestValue);

        Element issuerSerial = doc.createElementNS(XADES_NS, "xades:IssuerSerial");
        certEl.appendChild(issuerSerial);
        Element x509IssuerName = doc.createElementNS(DS_NS, "ds:X509IssuerName");
        x509IssuerName.setTextContent(
                signingCert.getIssuerX500Principal().getName(X500Principal.RFC2253));
        issuerSerial.appendChild(x509IssuerName);
        Element x509SerialNumber = doc.createElementNS(DS_NS, "ds:X509SerialNumber");
        x509SerialNumber.setTextContent(signingCert.getSerialNumber().toString());
        issuerSerial.appendChild(x509SerialNumber);
    }

    /* ================================================================== */
    /* Digest / c14n helpers                                               */
    /* ================================================================== */

    private static void appendDigestMethodAndValue(Document doc, Element reference, String digestUrl) {
        Element dm = doc.createElementNS(DS_NS, "ds:DigestMethod");
        dm.setAttribute("Algorithm", digestUrl);
        reference.appendChild(dm);
        Element dv = doc.createElementNS(DS_NS, "ds:DigestValue");
        reference.appendChild(dv);
    }

    private static Element digestValueElementOf(Element reference) {
        return (Element) reference.getElementsByTagNameNS(DS_NS, "DigestValue").item(0);
    }

    private static byte[] canonicalizeSubtree(Element element, String c14nAlgorithm) throws Exception {
        Canonicalizer canonicalizer = Canonicalizer.getInstance(c14nAlgorithm);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        canonicalizer.canonicalizeSubtree(element, out);
        return out.toByteArray();
    }

    private static String digestBase64(byte[] data, String javaDigestName) throws Exception {
        MessageDigest md = MessageDigest.getInstance(javaDigestName);
        return Base64.getEncoder().encodeToString(md.digest(data));
    }

    /** Sertifikanın DER kodlamasını hash'leyip Base64 döner. */
    private static String certificateDigestBase64(X509Certificate cert, String javaDigestName)
            throws Exception {
        MessageDigest md = MessageDigest.getInstance(javaDigestName);
        byte[] digest = md.digest(cert.getEncoded());
        return Base64.getEncoder().encodeToString(digest);
    }

    /** Sistem saatinden XAdES uyumlu (millis hassasiyetinde, offset'li) SigningTime üretir. */
    private static String currentXadesSigningTime() {
        OffsetDateTime now = OffsetDateTime.now(ZoneId.systemDefault())
                .truncatedTo(ChronoUnit.MILLIS);
        return XADES_SIGNING_TIME_FORMAT.format(now);
    }

    /* ================================================================== */
    /* Base64 kozmetiği (TestUserCounterSignatureService ile aynı)          */
    /* ================================================================== */

    private static void rewrapBase64InSubtree(Element counterSignatureRoot) {
        rewrapBase64ForAll(counterSignatureRoot, DS_NS, "SignatureValue");
        rewrapBase64ForAll(counterSignatureRoot, DS_NS, "X509Certificate");
    }

    private static void rewrapBase64ForAll(Element root, String ns, String localName) {
        NodeList list = root.getElementsByTagNameNS(ns, localName);
        for (int i = 0; i < list.getLength(); i++) {
            Element el = (Element) list.item(i);
            String text = el.getTextContent();
            if (text == null || text.isEmpty()) continue;
            String raw = text.replaceAll("[\\r\\n\\t ]+", "");
            if (raw.isEmpty()) continue;
            String wrapped = wrapBase64(raw);
            if (!wrapped.equals(text)) {
                el.setTextContent(wrapped);
            }
        }
    }

    private static String wrapBase64(String base64) {
        int len = base64.length();
        if (len <= BASE64_LINE_WIDTH) {
            return base64;
        }
        StringBuilder sb = new StringBuilder(len + len / BASE64_LINE_WIDTH + 1);
        int offset = 0;
        while (offset < len) {
            int end = Math.min(offset + BASE64_LINE_WIDTH, len);
            sb.append(base64, offset, end);
            if (end < len) sb.append('\n');
            offset = end;
        }
        return sb.toString();
    }

    /* ================================================================== */
    /* DOM helpers                                                         */
    /* ================================================================== */

    /**
     * {@code <ds:Signature>} ALTINDA (descendant) ilk
     * {@code <ds:SignatureValue>}'u döner.
     */
    private static Element findChildSignatureValue(Element signatureEl) {
        NodeList all = signatureEl.getElementsByTagNameNS(DS_NS, "SignatureValue");
        if (all.getLength() == 0) return null;
        return (Element) all.item(0);
    }

    /**
     * {@code Signature/Object/QualifyingProperties/UnsignedProperties/UnsignedSignatureProperties}
     * yolunda eksik node'ları sırayla oluşturup en alttakini döner.
     */
    private static Element findOrCreateUnsignedSignatureProperties(
            Element signatureEl, Document doc) {
        Element qualifyingProps =
                (Element) singleDescendantNs(signatureEl, XADES_NS, "QualifyingProperties");
        if (qualifyingProps == null) {
            Element obj = (Element) firstChildLocal(signatureEl, DS_NS, "Object");
            if (obj == null) {
                obj = doc.createElementNS(DS_NS, "ds:Object");
                signatureEl.appendChild(obj);
            }
            qualifyingProps = doc.createElementNS(XADES_NS, "xades:QualifyingProperties");
            String sigId = signatureEl.getAttribute("Id");
            if (sigId == null || sigId.isEmpty()) {
                sigId = "MerselSig-" + UUID.randomUUID().toString().replaceAll("-", "").substring(0, 12);
                signatureEl.setAttribute("Id", sigId);
                signatureEl.setIdAttribute("Id", true);
            }
            qualifyingProps.setAttribute("Target", "#" + sigId);
            obj.appendChild(qualifyingProps);
        }

        Element unsignedProps =
                (Element) firstChildLocal(qualifyingProps, XADES_NS, "UnsignedProperties");
        if (unsignedProps == null) {
            unsignedProps = doc.createElementNS(XADES_NS, "xades:UnsignedProperties");
            qualifyingProps.appendChild(unsignedProps);
        }

        Element ussp =
                (Element) firstChildLocal(unsignedProps, XADES_NS, "UnsignedSignatureProperties");
        if (ussp == null) {
            ussp = doc.createElementNS(XADES_NS, "xades:UnsignedSignatureProperties");
            unsignedProps.appendChild(ussp);
        }
        return ussp;
    }

    /**
     * Verilen prefix elementin ancestor zincirinde <em>aynı namespace URI'sine</em>
     * bağlanmış mı kontrol eder; bağlı değilse (veya başka bir URI'ye bağlıysa)
     * element üzerinde explicit xmlns bildirimi ekler. Final serileştirmede
     * bağlanmamış/çakışan prefix Transformer hatasına düşmesin diye.
     */
    private static void ensureNamespaceInScope(Element element, String prefix, String namespaceUri) {
        Node current = element;
        while (current != null && current.getNodeType() == Node.ELEMENT_NODE) {
            String bound = ((Element) current).getAttributeNS(XMLNS_NS, prefix);
            if (namespaceUri.equals(bound)) {
                return;
            }
            current = current.getParentNode();
        }
        element.setAttributeNS(XMLNS_NS, "xmlns:" + prefix, namespaceUri);
    }

    private static Node singleDescendantNs(Element parent, String ns, String localName) {
        NodeList list = parent.getElementsByTagNameNS(ns, localName);
        if (list.getLength() == 0) return null;
        return list.item(0);
    }

    private static Node firstChildLocal(Element parent, String ns, String localName) {
        NodeList children = parent.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node n = children.item(i);
            if (n.getNodeType() != Node.ELEMENT_NODE) continue;
            String nNs = n.getNamespaceURI();
            String nLocal = n.getLocalName();
            if (nLocal == null) nLocal = n.getNodeName();
            if (ns.equals(nNs) && localName.equals(nLocal)) return n;
        }
        return null;
    }

    static boolean isEcdsa(X509Certificate cert) {
        String algo = cert.getPublicKey().getAlgorithm();
        if (algo == null) return false;
        String upper = algo.toUpperCase(Locale.ROOT);
        if (upper.contains("EC")) return true;
        // Defensive: DSA mali mühürlerde karşımıza çıkmaz; unsupported kalsın.
        if (upper.contains("RSA")) return false;
        throw new SignatureException(
                "Counter-signature için desteklenmeyen anahtar algoritması: " + algo
                        + " (beklenen: RSA veya EC)");
    }

    /** EC eğri parametre boyutunu (P-256/384/521) byte cinsinden döndürür. */
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

    private static Document parseXml(byte[] xmlBytes) {
        try {
            javax.xml.parsers.DocumentBuilderFactory dbf =
                    javax.xml.parsers.DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            javax.xml.parsers.DocumentBuilder builder = dbf.newDocumentBuilder();
            return builder.parse(new ByteArrayInputStream(xmlBytes));
        } catch (Exception e) {
            throw new SignatureException("XML parse edilemedi: " + e.getMessage(), e);
        }
    }

    private static byte[] serialise(Document doc) {
        try {
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
            transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            transformer.transform(new DOMSource(doc), new StreamResult(out));
            return out.toByteArray();
        } catch (Exception e) {
            throw new SignatureException("XML serileştirilemedi: " + e.getMessage(), e);
        }
    }

    private static byte[] readAll(InputStream in) throws java.io.IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) {
            baos.write(buf, 0, n);
        }
        return baos.toByteArray();
    }

    /** {@link #doCounterSignature} dönüş tipi: serileştirilmiş XML + ham SignatureValue. */
    static final class CounterSignResult {
        final byte[] signedDocument;
        final byte[] signatureValue;

        CounterSignResult(byte[] signedDocument, byte[] signatureValue) {
            this.signedDocument = signedDocument;
            this.signatureValue = signatureValue;
        }
    }
}
