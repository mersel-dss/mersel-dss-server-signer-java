package io.mersel.dss.signer.api.services.signature.xades;

import io.mersel.dss.signer.api.exceptions.SignatureException;
import io.mersel.dss.signer.api.models.SignResponse;
import io.mersel.dss.signer.api.models.enums.TestCompany;
import org.apache.xml.security.Init;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.security.auth.x500.X500Principal;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.time.temporal.ChronoField;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Locale;
import java.util.UUID;

/**
 * <strong>GİB test ortamı</strong> için entegratör tarafından imzalanmış
 * XAdES belgesine, Kamu SM'nin publicly-published <em>RSA-2048</em> mali
 * mühür test sertifikalarından birini kullanarak ETSI XAdES-BES uyumlu
 * <em>counter signature</em> ekleyen, <b>tamamen kendi kendine yeten</b>
 * servis.
 *
 * <h3>İmza üretim yöntemi</h3>
 * <p>{@code mersel-dss-agent-signer-java}'daki üretim ortamında çalıştığı
 * doğrulanmış {@code XadesService#doCounterSignature} implementasyonuyla
 * <strong>bit-bit parite</strong>:
 * <ul>
 *   <li>Saf {@link javax.xml.crypto.dsig javax.xml.crypto.dsig} (DOM
 *       backend, Santuario xmlsec) — DSS ve xades4j bağımlılığı yok.</li>
 *   <li>Counter-signature kendi başına eksiksiz bir XAdES-BES imzasıdır:
 *       SignedInfo iki {@code Reference} (kendi SignedProperties +
 *       parent SignatureValue), KeyInfo yalnız imzacı sertifikası,
 *       QualifyingProperties altında SigningTime + SigningCertificate
 *       (CertDigest + IssuerSerial).</li>
 *   <li>Algoritma seçimi: RSA → RSA-SHA256/SHA-256, ECDSA →
 *       ECDSA-SHA384/SHA-384 (agent ile aynı kural; tüm TestKurum
 *       PFX'leri RSA-2048 olduğu için fiilen RSA-SHA256 çalışır).</li>
 *   <li>Canonicalization: SignedInfo c14n = INCLUSIVE_WITH_COMMENTS,
 *       parent SignatureValue reference transform = INCLUSIVE_WITH_COMMENTS
 *       — İmzager Kurumsal ve GİB doğrulayıcısıyla parite.</li>
 * </ul>
 *
 * <h3>Anahtar kaynağı — PFX runtime</h3>
 * <p>Agent PKCS#11 token kullanırken, bu servis runtime'da
 * {@code KeyStore.getInstance("PKCS12")} ile {@code resources/test-certs/}
 * altındaki PFX'i açar, alias enum'da sabit ({@link TestCompany#getAlias()},
 * Kamu SM convention {@code "1"}), şifre enum'da sabit. Caching yok —
 * endpoint test akışları için, birkaç çağrıdan ibaret.</p>
 *
 * <h3>Production'da KULLANILMAZ</h3>
 * <p>Bu servis production imzalama pipeline'ından <strong>tamamen
 * izoledir</strong>: ne {@code SigningMaterial}, ne {@code SigningMaterialFactory},
 * ne ortak {@code CertificateVerifier}, ne {@code Semaphore}, ne
 * {@code XAdESService} bean'ine bağlıdır. Üretim akışında yapılan herhangi
 * bir değişiklik bu endpoint'i etkilemez ve tersi.</p>
 */
@Service
public class TestUserCounterSignatureService {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(TestUserCounterSignatureService.class);

    public static final String DS_NS = "http://www.w3.org/2000/09/xmldsig#";
    public static final String XADES_NS = "http://uri.etsi.org/01903/v1.3.2#";

    /** SHA-384 digest URL (xmldsig-more). */
    static final String DIGEST_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384";
    /** ECDSA-SHA384 signature URL. */
    static final String SIG_ECDSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";
    /**
     * RSA-SHA256 signature URL. JDK 1.8 javax.xml.crypto.dsig.SignatureMethod'da
     * constant olarak yok.
     */
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

    private static final String DEFAULT_TEST_CERTS_DIR = "resources/test-certs";

    private final Path testCertsDirectory;

    public TestUserCounterSignatureService(
            @Value("${signing.test-certs.directory:" + DEFAULT_TEST_CERTS_DIR + "}")
            String testCertsDirectory) {
        this.testCertsDirectory = Paths.get(
                StringUtils.hasText(testCertsDirectory)
                        ? testCertsDirectory : DEFAULT_TEST_CERTS_DIR
        ).toAbsolutePath();

        // Apache Santuario init — XMLSignatureFactory("DOM") arka ucu için
        // gerekli olabilen statik kayıtlar. Idempotent (kendi içinde guard'lı).
        Init.init();

        LOGGER.info("TestKurum counter-signature servisi hazır. PFX dizini: {}",
                this.testCertsDirectory);
    }

    /* ================================================================== */
    /* Public API                                                          */
    /* ================================================================== */

    /**
     * Daha önce imzalanmış bir XAdES belgesine, seçili Kamu SM test
     * kurumunun RSA PFX'i ile counter signature ekler.
     *
     * @param signedXmlInputStream Entegratör tarafından imzalanmış XAdES belgesi
     * @param testCompany          Kullanılacak Kamu SM RSA test kurum sertifikası
     * @return Counter-sign edilmiş belge + Base64 counter-signature SignatureValue
     */
    public SignResponse counterSign(InputStream signedXmlInputStream,
                                    TestCompany testCompany) {
        if (testCompany == null) {
            throw new SignatureException("INVALID_INPUT",
                    "Counter signature için testCompany alanı zorunludur");
        }
        if (signedXmlInputStream == null) {
            throw new SignatureException("INVALID_INPUT",
                    "Counter signature için document alanı zorunludur");
        }

        try {
            byte[] xmlBytes = readAll(signedXmlInputStream);

            KeyStore.PrivateKeyEntry entry = loadKeyEntry(testCompany);
            PrivateKey privateKey = entry.getPrivateKey();
            X509Certificate certificate = (X509Certificate) entry.getCertificate();

            LOGGER.info("TestKurum counter-signature istemi: testCompany={}, subject={}",
                    testCompany, certificate.getSubjectX500Principal());

            CounterSignResult result = doCounterSignature(xmlBytes, privateKey, certificate);

            LOGGER.info("TestKurum counter-signature başarıyla eklendi. testCompany={}",
                    testCompany);

            return new SignResponse(
                    result.signedDocument,
                    Base64.getEncoder().encodeToString(result.signatureValue));

        } catch (SignatureException e) {
            throw e;
        } catch (Exception e) {
            LOGGER.error("TestKurum counter-signature oluşturulurken hata", e);
            throw new SignatureException(
                    "TestKurum counter-signature oluşturulamadı: " + e.getMessage(), e);
        }
    }

    /* ================================================================== */
    /* PFX runtime loading                                                 */
    /* ================================================================== */

    /**
     * Seçili test kurumun PFX'ini runtime'da açıp PrivateKeyEntry'yi döndürür.
     * Hiçbir cache, hiçbir provider chain — saf JCA PKCS12.
     */
    private KeyStore.PrivateKeyEntry loadKeyEntry(TestCompany testCompany) throws Exception {
        Path pfxPath = testCertsDirectory.resolve(testCompany.getPfxFileName());
        if (!Files.isRegularFile(pfxPath)) {
            throw new SignatureException("TEST_CERT_NOT_FOUND",
                    "Test kurum PFX dosyası bulunamadı: " + pfxPath
                            + ". 'resources/test-certs/README.md' içindeki kurulum adımlarını izleyin.");
        }

        char[] pin = testCompany.getPfxPassword().toCharArray();
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(pfxPath)) {
            keyStore.load(in, pin);
        }

        String alias = testCompany.getAlias();
        if (!keyStore.isKeyEntry(alias)) {
            throw new SignatureException("TEST_CERT_NOT_FOUND",
                    "Alias '" + alias + "' PFX içinde key entry değil: " + pfxPath);
        }
        KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry)
                keyStore.getEntry(alias, new KeyStore.PasswordProtection(pin));
        if (entry == null) {
            throw new SignatureException("TEST_CERT_NOT_FOUND",
                    "Alias '" + alias + "' için PrivateKeyEntry alınamadı: " + pfxPath);
        }
        return entry;
    }

    /* ================================================================== */
    /* XAdES Counter-signature implementation                              */
    /* (mersel-dss-agent-signer-java XadesService.doCounterSignature ile  */
    /*  birebir parite — production'da çalıştığı doğrulanmış kod)         */
    /* ================================================================== */

    /**
     * Var olan {@code <ds:Signature>}'ın {@code <ds:SignatureValue>}'su
     * üzerine ETSI XAdES-BES uyumlu bir {@code <xades:CounterSignature>}
     * ekler.
     *
     * <p>Üretilen counter-signature, kendi başına eksiksiz bir XAdES-BES
     * imzasıdır:</p>
     * <ul>
     *   <li>{@code SignedInfo} iki {@code Reference} içerir:
     *     <ul>
     *       <li>Kendi {@code SignedProperties}'i hedefler — Type =
     *           {@code http://uri.etsi.org/01903#SignedProperties}.</li>
     *       <li>Karşı imzalanan {@code SignatureValue}'u hedefler — Type =
     *           {@code http://uri.etsi.org/01903#CountersignedSignature},
     *           c14n WithComments transform.</li>
     *     </ul>
     *   </li>
     *   <li>{@code KeyInfo} sadece imzacı sertifikasını içerir.</li>
     *   <li>{@code Object/QualifyingProperties} altında
     *       {@code SignedProperties} ({@code SigningTime} +
     *       {@code SigningCertificate}: CertDigest + IssuerSerial) bulunur.</li>
     * </ul>
     *
     * <p>İmzacı sertifikası RSA ise {@code RSA-SHA256 / SHA-256}, ECDSA ise
     * {@code ECDSA-SHA384 / SHA-384} kullanılır. {@code DOMSignContext}'e
     * {@code ds} ve {@code xades} prefix'leri sabitlenir; böylece üretilen
     * XML İmzager Kurumsal gibi araçlarda XAdES profilinde doğrulanabilir
     * hale gelir.</p>
     */
    CounterSignResult doCounterSignature(byte[] xmlBytes, PrivateKey privateKey,
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
        ussp.appendChild(counterSig);

        // Counter-signature'a ait Id'ler — agent ile aynı isim şablonu.
        String counterSigId = "Signature-Id-" + UUID.randomUUID();
        String counterSigValueId = "Signature-Value-Id-" + UUID.randomUUID();
        String signedPropsId = "Signed-Properties-Id-" + UUID.randomUUID();
        String objectId = "Object-Id-" + UUID.randomUUID();
        String signedPropsRefId = "Reference-Id-" + UUID.randomUUID();
        String counterRefId = "Reference-Id-" + UUID.randomUUID();

        // Algoritma seçimi: RSA-2048 NES = RSA-SHA256 / SHA-256,
        // ECDSA = ECDSA-SHA384 / SHA-384. TestCompany enum'unda yalnızca
        // RSA PFX'leri var; ECDSA dalı defansif olarak korundu.
        boolean ecdsa = isEcdsa(signingCert);
        String digestUrl = ecdsa ? DIGEST_SHA384 : DigestMethod.SHA256;
        String sigUrl = ecdsa ? SIG_ECDSA_SHA384 : SIG_RSA_SHA256;

        // 1) QualifyingProperties / SignedProperties DOM ağacını kur — JSR
        //    105 XMLObject içine DOMStructure olarak konacak.
        //    SignedProperties'in Id attribute'unu XML ID olarak işaretle ki
        //    Reference URI="#signedPropsId" digest hesaplanırken
        //    dereferencing düşmesin.
        Element qualifyingProps = buildQualifyingProperties(doc, counterSigId, signedPropsId);
        Element signedPropsEl = (Element) qualifyingProps.getFirstChild();
        populateSignedProperties(doc, signedPropsEl, signingCert, digestUrl);

        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

        DOMStructure qpStruct = new DOMStructure(qualifyingProps);
        XMLObject xmlObject =
                fac.newXMLObject(Collections.singletonList(qpStruct), objectId, null, null);

        // 2) İki Reference (XAdES-BES: kendi SignedProperties + karşı
        //    imzalanan SignatureValue)
        Reference signedPropsRef =
                fac.newReference(
                        "#" + signedPropsId,
                        fac.newDigestMethod(digestUrl, null),
                        null,
                        XADES_TYPE_SIGNED_PROPERTIES,
                        signedPropsRefId);

        Reference counterRef =
                fac.newReference(
                        "#" + parentSigValueId,
                        fac.newDigestMethod(digestUrl, null),
                        Collections.singletonList(
                                fac.newTransform(
                                        CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS,
                                        (TransformParameterSpec) null)),
                        XADES_TYPE_COUNTERSIGNED_SIGNATURE,
                        counterRefId);

        SignedInfo si =
                fac.newSignedInfo(
                        fac.newCanonicalizationMethod(
                                CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS,
                                (C14NMethodParameterSpec) null),
                        fac.newSignatureMethod(sigUrl, null),
                        Arrays.asList(signedPropsRef, counterRef));

        // 3) KeyInfo — yalnız imzacı sertifikası (xades:Cert ile zaten
        //    chain'e bağlanıyor)
        KeyInfoFactory kif = fac.getKeyInfoFactory();
        X509Data x509Data = kif.newX509Data(Collections.<Object>singletonList(signingCert));
        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(x509Data));

        // 4) XMLSignature — Id ve SignatureValue Id explicit, Object
        //    listesi içeride QP taşıyor
        XMLSignature xmlSig =
                fac.newXMLSignature(
                        si, ki, Collections.singletonList(xmlObject),
                        counterSigId, counterSigValueId);

        DOMSignContext sc = new DOMSignContext(privateKey, counterSig);
        sc.putNamespacePrefix(DS_NS, "ds");
        sc.putNamespacePrefix(XADES_NS, "xades");

        xmlSig.sign(sc);

        // Apache Santuario Base64'ü 76 karakterde CRLF ile böler (RFC
        // 2045/MIME geleneği). XML Transformer '\r' karakterini '&#13;'
        // olarak entity-encode ettiği için çıktıda görsel kirlilik oluşur.
        //
        // Global olarak kapatmak (org.apache.xml.security.ignoreLineBreaks=true)
        // Santuario class yüklenmeden ÖNCE set edilmesi gerektiği için
        // bu yola gidemeyiz — DSS XAdESService zaten startup'ta Santuario'yu
        // yüklemiştir ve property global yan etki yaratıp production XAdES
        // davranışını değiştirir.
        //
        // Çözüm: sadece <xades:CounterSignature> subtree'sindeki Base64
        // text node'larını <strong>standart 76-char</strong> genişlikte
        // (RFC 2045 / MIME — Apache Santuario, OpenSSL, DSS hepsi aynı
        // genişlikte üretir) <strong>LF</strong> ile yeniden wrap'liyoruz.
        // Sonuç: 1) klasik XAdES görüntüsü, 2) '&#13;' entity'si üretilmez
        // (Transformer LF'i olduğu gibi basar), 3) imza geçerliliği
        // etkilenmez — Base64 decoder zaten whitespace'i yok sayar ve bu
        // iki node digest/canonicalization girişi değildir.
        rewrapBase64InSubtree(counterSig);

        byte[] sigValue = xmlSig.getSignatureValue().getValue();
        byte[] serialized = serialise(doc);
        return new CounterSignResult(serialized, sigValue);
    }

    /**
     * Standart XAdES Base64 line width: her satır 76 karakter
     * (RFC 2045 / MIME default; Apache Santuario, OpenSSL ve DSS aynı
     * genişlikte üretir).
     */
    private static final int BASE64_LINE_WIDTH = 76;

    /**
     * Verilen subtree içindeki {@code <ds:SignatureValue>} ve
     * {@code <ds:X509Certificate>} elementlerinin Base64 text'ini
     * normalize edip {@value #BASE64_LINE_WIDTH} karakter genişliğinde
     * LF ile yeniden wrap'ler.
     *
     * <p><strong>Niye sadece bu iki element?</strong> XML-DSig referansları
     * {@code SignedInfo > Reference > DigestValue} ve karşı-imzalanan
     * SignatureValue üzerine kuruluyor. Bu iki node'un text içeriği
     * canonicalize/digest girişi <em>değil</em> — sadece Base64 decode
     * edilip ham bytes elde edilir; whitespace zaten yutulur. Bu yüzden
     * imza geçerliliğini bozmadan kozmetik olarak normalize edilebilirler.</p>
     *
     * <p><strong>Niye sadece counter-signature subtree?</strong> Parent
     * imzanın text content'lerine dokunmuyoruz — parent c14n parity'sini
     * riske atmamak ve caller'ın gönderdiği byte'ları gereksiz mutasyona
     * uğratmamak için.</p>
     */
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
            // 1) Önce tüm whitespace'i sıyırarak ham Base64'ü elde et
            //    (Santuario'nun eklediği CRLF + Transformer'ın koruduğu
            //    indentation hepsi gider).
            String raw = text.replaceAll("[\\r\\n\\t ]+", "");
            if (raw.isEmpty()) continue;
            // 2) Standart genişlikte LF ile yeniden wrap'le.
            String wrapped = wrapBase64(raw);
            if (!wrapped.equals(text)) {
                el.setTextContent(wrapped);
            }
        }
    }

    /**
     * Base64 string'ini {@value #BASE64_LINE_WIDTH} karakter genişliğinde
     * {@code '\n'} ile böler. Standalone, kütüphane bağımlılığı yok.
     */
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

    /**
     * {@code <xades:QualifyingProperties Target="#sigId">
     * <xades:SignedProperties Id="...">} iskeletini üretir.
     * {@code SignedProperties}'in {@code Id} attribute'u XML ID olarak işaretlenir.
     */
    private static Element buildQualifyingProperties(
            Document doc, String counterSigId, String signedPropsId) {
        Element qp = doc.createElementNS(XADES_NS, "xades:QualifyingProperties");
        qp.setAttribute("Target", "#" + counterSigId);
        Element sp = doc.createElementNS(XADES_NS, "xades:SignedProperties");
        sp.setAttribute("Id", signedPropsId);
        sp.setIdAttribute("Id", true);
        qp.appendChild(sp);
        return qp;
    }

    /**
     * {@code SignedProperties} altına {@code SignedSignatureProperties}
     * kurarak {@code SigningTime} + {@code SigningCertificate} (CertDigest
     * + IssuerSerial) yerleştirir.
     */
    private static void populateSignedProperties(
            Document doc, Element signedProps, X509Certificate signingCert, String digestUrl)
            throws Exception {
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
        certDigestValue.setTextContent(certificateDigestBase64(signingCert, digestUrl));
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

    /** Sertifikanın DER kodlamasını verilen XAdES digest algoritmasıyla hash'leyip Base64 döner. */
    private static String certificateDigestBase64(X509Certificate cert, String digestUrl)
            throws Exception {
        String javaAlg = digestUrl.endsWith("sha384") ? "SHA-384" : "SHA-256";
        MessageDigest md = MessageDigest.getInstance(javaAlg);
        byte[] digest = md.digest(cert.getEncoded());
        return Base64.getEncoder().encodeToString(digest);
    }

    /** Sistem saatinden XAdES uyumlu (millis hassasiyetinde, offset'li) SigningTime üretir. */
    private static String currentXadesSigningTime() {
        OffsetDateTime now = OffsetDateTime.now(ZoneId.systemDefault())
                .truncatedTo(ChronoUnit.MILLIS);
        return XADES_SIGNING_TIME_FORMAT.format(now);
    }

    /**
     * {@code <ds:Signature>} ALTINDA (descendant) ilk
     * {@code <ds:SignatureValue>}'u döner. Standart XAdES'te her signature'ın
     * tam olarak bir tane vardır.
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
            // Object/QualifyingProperties yoksa, mevcut bir Object'in altına koy
            // veya yeni bir Object oluştur.
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
        return upper.contains("EC");
    }

    /* ================================================================== */
    /* DOM helpers                                                         */
    /* ================================================================== */

    private static Document parseXml(byte[] xmlBytes) {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            DocumentBuilder builder = dbf.newDocumentBuilder();
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
