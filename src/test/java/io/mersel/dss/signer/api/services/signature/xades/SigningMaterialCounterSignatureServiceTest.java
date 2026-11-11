package io.mersel.dss.signer.api.services.signature.xades;

import io.mersel.dss.signer.api.e2e.verifier.PfxTestKey;
import io.mersel.dss.signer.api.models.SignResponse;
import io.mersel.dss.signer.api.models.SigningMaterial;
import io.mersel.dss.signer.api.testsupport.PfxBackedPkcs11Signer;
import org.apache.xml.security.Init;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Semaphore;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * {@link SigningMaterialCounterSignatureService}'in (entegratör seri imzası —
 * ana {@link SigningMaterial} ile counter signature) ürettiği yapının
 * geçerliliğini doğrular.
 *
 * <p>{@link TestUserCounterSignatureServiceTest} ile aynı XAdES-BES yapısal
 * invariant'larını ve XML-DSig doğrulamasını çalıştırır; ek olarak aynı testi
 * <b>HSM kod yolu simülasyonunda</b> ({@code PfxBackedPkcs11Signer} sarmalı
 * materyal — {@code material.getPrivateKey() == null}) da koşar: digest'ler
 * iki yolda da aynı hesaplanmalı, yalnızca imza backend'i değişmelidir.</p>
 *
 * <p>PFX repo'da yoksa test {@code Assumptions.assumeTrue} ile graceful
 * skip eder.</p>
 */
class SigningMaterialCounterSignatureServiceTest {

    private static SigningMaterialCounterSignatureService service;

    @BeforeAll
    static void initApacheSantuario() {
        Init.init();
        service = new SigningMaterialCounterSignatureService(new Semaphore(1));
    }

    @Test
    @DisplayName("Ana imza materyali (PFX/JCA) ile XAdES-BES counter signature ekler ve XML-DSig doğrulamasını geçer")
    void addsAndVerifiesCounterSignatureWithJcaMaterial() throws Exception {
        PfxTestKey key = PfxTestKey.KURUM17_EC384;
        assumeTrue(key.isAvailable(), "Skip — PFX yok: " + key.getAbsolutePath());

        SigningMaterial material = loadJcaMaterial(key);

        SignResponse response = service.counterSign(
                new ByteArrayInputStream(sampleSignedXadesDocument()), material);

        assertValidCounterSignature(response, material);
    }

    @Test
    @DisplayName("HSM kod yolu (PfxBackedPkcs11Signer — PrivateKey yok) ile aynı doğrulamayı geçer")
    void addsAndVerifiesCounterSignatureWithPkcs11SimulatedMaterial() throws Exception {
        PfxTestKey key = PfxTestKey.KURUM02_EC384;
        assumeTrue(key.isAvailable(), "Skip — PFX yok: " + key.getAbsolutePath());

        SigningMaterial material = loadPkcs11SimulatedMaterial(key);
        // HSM simülasyonu: JCA PrivateKey erişimi YOK — imza SigningBackend
        // üzerinden atılmalı.
        org.junit.jupiter.api.Assertions.assertNull(material.getPrivateKey(),
                "HSM simülasyonunda getPrivateKey() null olmalı.");

        SignResponse response = service.counterSign(
                new ByteArrayInputStream(sampleSignedXadesDocument()), material);

        assertValidCounterSignature(response, material);
    }

    /* ================================================================== */
    /* Material loading (provider-izole — KeyStoreLoaderService KULLANMAZ)  */
    /* ================================================================== */

    /**
     * PFX'i düz JCA ile yükler. Bilinçli olarak
     * {@code E2eSigningMaterialFactory} kullanılmaz: o factory
     * {@code KeyStoreLoaderService} üzerinden BouncyCastle'ı JVM-wide
     * priority 1 yapar ve sonraki düz PKCS12 yüklemelerinde (ör.
     * {@code TestUserCounterSignatureService}) alias "1" çözümlenemez.
     * Bu test provider düzenine hiç dokunmaz; ayrıca JVM'de BC kurulmuş
     * olsa bile (batch'te başka testler kurabilir) alias friendlyName yerine
     * localKeyId olabileceğinden key entry <em>iterasyonla</em> bulunur —
     * test PFX'lerinde tek key entry vardır (E2eSigningMaterialFactory ile
     * aynı savunma).
     */
    private static KeyStore.PrivateKeyEntry loadKeyEntry(PfxTestKey key) throws Exception {
        char[] pin = key.getPassword();
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(Paths.get(key.getAbsolutePath()))) {
            keyStore.load(in, pin);
        }

        KeyStore.PasswordProtection protection = new KeyStore.PasswordProtection(pin);
        if (keyStore.isKeyEntry(key.getAlias())) {
            return (KeyStore.PrivateKeyEntry) keyStore.getEntry(key.getAlias(), protection);
        }

        java.util.Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (keyStore.isKeyEntry(alias)) {
                KeyStore.Entry entry = keyStore.getEntry(alias, protection);
                if (entry instanceof KeyStore.PrivateKeyEntry) {
                    return (KeyStore.PrivateKeyEntry) entry;
                }
            }
        }

        throw new IllegalStateException("PFX içinde key entry bulunamadı: " + key.getFileName());
    }

    private static SigningMaterial loadJcaMaterial(PfxTestKey key) throws Exception {
        KeyStore.PrivateKeyEntry entry = loadKeyEntry(key);
        return new SigningMaterial(
                entry.getPrivateKey(),
                (X509Certificate) entry.getCertificate(),
                toCertificateChain(entry.getCertificateChain()));
    }

    private static SigningMaterial loadPkcs11SimulatedMaterial(PfxTestKey key) throws Exception {
        KeyStore.PrivateKeyEntry entry = loadKeyEntry(key);
        X509Certificate certificate = (X509Certificate) entry.getCertificate();
        List<X509Certificate> chain = toCertificateChain(entry.getCertificateChain());
        return new SigningMaterial(
                new PfxBackedPkcs11Signer(key.getAlias(), entry.getPrivateKey(), certificate, chain),
                certificate,
                chain);
    }

    private static List<X509Certificate> toCertificateChain(Certificate[] certificates) {
        if (certificates == null || certificates.length == 0) {
            return null;
        }
        List<X509Certificate> chain = new ArrayList<>(certificates.length);
        boolean any = false;
        for (Certificate c : certificates) {
            if (c instanceof X509Certificate) {
                chain.add((X509Certificate) c);
                any = true;
            }
        }
        return any ? chain : Collections.<X509Certificate>emptyList();
    }

    /* ================================================================== */
    /* Assertions                                                          */
    /* ================================================================== */

    private static void assertValidCounterSignature(SignResponse response,
                                                    SigningMaterial material) throws Exception {
        assertNotNull(response, "SignResponse null olmamalı.");
        assertNotNull(response.getSignedDocument(),
                "Counter-sign edilmiş belge byte'ları null olmamalı.");
        assertNotNull(response.getSignatureValue(),
                "Base64 SignatureValue header değeri üretilmiş olmalı.");

        Document doc = parse(response.getSignedDocument());

        // CounterSignature elementi var mı?
        NodeList counterSigs = doc.getElementsByTagNameNS(
                SigningMaterialCounterSignatureService.XADES_NS, "CounterSignature");
        assertTrue(counterSigs.getLength() >= 1,
                "xades:CounterSignature elementi eklenmiş olmalı.");

        Element counterContainer = (Element) counterSigs.item(0);
        NodeList innerSigs = counterContainer.getElementsByTagNameNS(
                SigningMaterialCounterSignatureService.DS_NS, "Signature");
        assertTrue(innerSigs.getLength() >= 1, "CounterSignature içinde ds:Signature olmalı.");

        // SignatureValue Id'lerini XML ID olarak işaretle (schema yokken
        // dereferencing bulabilsin).
        NodeList allSigValues = doc.getElementsByTagNameNS(
                SigningMaterialCounterSignatureService.DS_NS, "SignatureValue");
        boolean targetHasId = false;
        for (int i = 0; i < allSigValues.getLength(); i++) {
            Element el = (Element) allSigValues.item(i);
            String id = el.getAttribute("Id");
            if (id != null && !id.isEmpty()) {
                if (i == 0) targetHasId = true;
                el.setIdAttribute("Id", true);
            }
        }
        assertTrue(targetHasId, "Hedef SignatureValue'a Id atanmış olmalı.");

        // SignedProperties Id'lerini de XML ID olarak işaretle.
        NodeList signedPropsList = doc.getElementsByTagNameNS(
                SigningMaterialCounterSignatureService.XADES_NS, "SignedProperties");
        boolean counterHasSignedProps = false;
        for (int i = 0; i < signedPropsList.getLength(); i++) {
            Element el = (Element) signedPropsList.item(i);
            String id = el.getAttribute("Id");
            if (id != null && !id.isEmpty()) {
                el.setIdAttribute("Id", true);
                counterHasSignedProps = true;
            }
        }
        assertTrue(counterHasSignedProps,
                "Counter-signature için xades:SignedProperties (Id'li) üretilmiş olmalı.");

        // Counter-sig XAdES-BES olarak: iki Reference'ı da içeren XML-DSig
        // validate'i geçmeli.
        Element counterSigElement = (Element) innerSigs.item(0);
        DOMValidateContext valCtx = new DOMValidateContext(
                new TestUserCounterSignatureServiceTest.X509KeySelector(), counterSigElement);
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
        XMLSignature signature = fac.unmarshalXMLSignature(valCtx);
        assertTrue(signature.validate(valCtx),
                "Counter-signature XAdES-BES (SignedProperties + CountersignedSignature) "
                        + "olarak geçerli olmalı.");

        // XAdES-BES yapısal invariant'ları:
        // 1) SignedInfo iki Reference içerir.
        assertEquals(2, signature.getSignedInfo().getReferences().size(),
                "İki Reference olmalı.");
        boolean hasSignedPropsRef = false;
        boolean hasCounterRef = false;
        for (Object refObj : signature.getSignedInfo().getReferences()) {
            javax.xml.crypto.dsig.Reference r = (javax.xml.crypto.dsig.Reference) refObj;
            if (SigningMaterialCounterSignatureService.XADES_TYPE_SIGNED_PROPERTIES.equals(r.getType())) {
                hasSignedPropsRef = true;
            }
            if (SigningMaterialCounterSignatureService.XADES_TYPE_COUNTERSIGNED_SIGNATURE.equals(r.getType())) {
                hasCounterRef = true;
            }
        }
        assertTrue(hasSignedPropsRef, "SignedProperties tipli Reference olmalı.");
        assertTrue(hasCounterRef, "CountersignedSignature tipli Reference olmalı.");

        // 2) QualifyingProperties Target counter-signature'ın kendi Id'sini göstermeli.
        Element counterQp = (Element) counterSigElement.getElementsByTagNameNS(
                SigningMaterialCounterSignatureService.XADES_NS, "QualifyingProperties").item(0);
        assertNotNull(counterQp, "Counter-sig içinde xades:QualifyingProperties olmalı.");
        String target = counterQp.getAttribute("Target");
        String counterId = counterSigElement.getAttribute("Id");
        assertTrue(target != null && counterId != null && target.equals("#" + counterId),
                "QualifyingProperties Target counter-sig Id'siyle eşleşmeli: target=" + target);

        // 3) SigningTime + SigningCertificate (CertDigest + IssuerSerial) doldurulmuş olmalı.
        assertTrue(counterSigElement.getElementsByTagNameNS(
                        SigningMaterialCounterSignatureService.XADES_NS, "SigningTime").getLength() > 0,
                "xades:SigningTime üretilmiş olmalı.");
        assertTrue(counterSigElement.getElementsByTagNameNS(
                        SigningMaterialCounterSignatureService.XADES_NS, "CertDigest").getLength() > 0,
                "xades:CertDigest üretilmiş olmalı.");
        assertTrue(counterSigElement.getElementsByTagNameNS(
                        SigningMaterialCounterSignatureService.XADES_NS, "IssuerSerial").getLength() > 0,
                "xades:IssuerSerial üretilmiş olmalı.");

        // 4) KeyInfo'da yalnız tek imzacı sertifikası bulunsun (chain leak değil)
        //    ve bu sertifika materyalin imza sertifikasıyla aynı olmalı.
        Element counterKeyInfo = (Element) counterSigElement.getElementsByTagNameNS(
                SigningMaterialCounterSignatureService.DS_NS, "KeyInfo").item(0);
        assertNotNull(counterKeyInfo, "ds:KeyInfo olmalı.");
        NodeList certs = counterKeyInfo.getElementsByTagNameNS(
                SigningMaterialCounterSignatureService.DS_NS, "X509Certificate");
        assertEquals(1, certs.getLength(),
                "Counter-sig KeyInfo tek X509Certificate içermeli.");
        byte[] embeddedCertBytes = java.util.Base64.getDecoder()
                .decode(certs.item(0).getTextContent().replaceAll("[\\r\\n\\t ]+", ""));
        assertTrue(java.util.Arrays.equals(embeddedCertBytes, material.getSigningCertificate().getEncoded()),
                "KeyInfo'daki sertifika ana imza materyalinin sertifikası olmalı.");
    }

    /* ================================================================== */
    /* Fixtures                                                            */
    /* ================================================================== */

    private static byte[] sampleSignedXadesDocument() {
        String xml =
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                        + "<doc xmlns=\"urn:test\">"
                        + "  <body>HR Faturası</body>"
                        + "  <ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" Id=\"sig1\">"
                        + "    <ds:SignedInfo>"
                        + "      <ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments\"/>"
                        + "      <ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384\"/>"
                        + "      <ds:Reference URI=\"\">"
                        + "        <ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>"
                        + "        <ds:DigestValue>AAAA</ds:DigestValue>"
                        + "      </ds:Reference>"
                        + "    </ds:SignedInfo>"
                        + "    <ds:SignatureValue>ZHVtbXk=</ds:SignatureValue>"
                        + "    <ds:KeyInfo><ds:X509Data><ds:X509SubjectName>CN=Original</ds:X509SubjectName></ds:X509Data></ds:KeyInfo>"
                        + "  </ds:Signature>"
                        + "</doc>";
        return xml.getBytes(StandardCharsets.UTF_8);
    }

    private static Document parse(byte[] bytes) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder builder = dbf.newDocumentBuilder();
        return builder.parse(new ByteArrayInputStream(bytes));
    }
}
