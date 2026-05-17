package io.mersel.dss.signer.api.services.signature.wssecurity;

import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import io.mersel.dss.signer.api.exceptions.SignatureException;
import io.mersel.dss.signer.api.models.SignResponse;
import io.mersel.dss.signer.api.models.SigningMaterial;
import io.mersel.dss.signer.api.services.crypto.DigestAlgorithmResolverService;
import io.mersel.dss.signer.api.services.keystore.iaik.Pkcs11EcdsaSignatureEncoder;
import io.mersel.dss.signer.api.services.keystore.iaik.Pkcs11Signer;
import io.mersel.dss.signer.api.testsupport.SignedArtifactExporter;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Severity;
import io.qameta.allure.SeverityLevel;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link WsSecuritySignatureService} regression testleri.
 *
 * <p>Kritik kontrat: bu servis <b>hem PFX hem HSM (PKCS#11)</b> yapılandırmasında
 * geçerli WS-Security XML imzası üretmeli. HSM yolunda elimizde JCA
 * {@code PrivateKey} yok; servis bunu doğrudan {@link Pkcs11Signer#sign} ile
 * yapmalı.</p>
 *
 * <p>HSM davranışı in-test bir {@code FakePkcs11Signer} ile simüle edilir —
 * gerçek HSM'in {@code IaikPkcs11Module} sonrası DER-normalize edilmiş çıktı
 * davranışını birebir taklit eder.</p>
 */
@ExtendWith(SignedArtifactExporter.class)
@Epic("Service Layer")
@Feature("WsSecuritySignatureService")
@Severity(SeverityLevel.NORMAL)
class WsSecuritySignatureServiceTest {

    private static KeyPair rsaPair;
    private static KeyPair ecPair;
    private static X509Certificate rsaCert;
    private static X509Certificate ecCert;

    private final WsSecuritySignatureService service = new WsSecuritySignatureService(
        new Semaphore(4),
        new DigestAlgorithmResolverService());

    @BeforeAll
    static void initFixtures() throws Exception {
        rsaPair = generateKeyPair("RSA", 2048);
        ecPair = generateKeyPair("EC", 256);
        rsaCert = generateSelfSignedCertificate(rsaPair, "SHA256withRSA",
            "CN=WS-Security RSA Test");
        ecCert = generateSelfSignedCertificate(ecPair, "SHA256withECDSA",
            "CN=WS-Security EC Test");
    }

    // -------------------------------------------------------------------
    // PFX yolu (eski davranış — regression olmadığından emin ol)
    // -------------------------------------------------------------------

    @Nested
    @DisplayName("PFX/JCA yolu (mevcut müşterilerin breaking olmaması)")
    class PfxPath {

        @Test
        @DisplayName("RSA-SHA256: geçerli WS-Security imzası üretilmeli ve doğrulanmalı")
        void pfxRsa_shouldProduceValidSignature() throws Exception {
            Document soap = loadSoapEnvelope();
            SigningMaterial material = pfxMaterial(rsaPair, rsaCert);

            SignResponse response = service.signSoapEnvelope(soap, false, material, "test", new char[0]);
            SignedArtifactExporter.export(
                    SignedArtifactExporter.Format.WSSECURITY, response.getSignedDocument());

            Document signed = parseXml(response.getSignedDocument());
            assertSignatureValid(signed, rsaCert.getPublicKey());
        }

        @Test
        @DisplayName("ECDSA-SHA256: DER çıktısı raw r||s'a dönüştürülüp XML'e gömülmeli")
        void pfxEc_shouldProduceValidSignature_withRawRsConversion() throws Exception {
            Document soap = loadSoapEnvelope();
            SigningMaterial material = pfxMaterial(ecPair, ecCert);

            SignResponse response = service.signSoapEnvelope(soap, false, material, "test", new char[0]);
            SignedArtifactExporter.export(
                    SignedArtifactExporter.Format.WSSECURITY, response.getSignedDocument());

            Document signed = parseXml(response.getSignedDocument());
            assertSignatureValid(signed, ecCert.getPublicKey());

            // P-256 → raw imza 64 byte; XMLDsig spec gereği.
            String signatureValueB64 = readSignatureValue(signed);
            byte[] sigBytes = java.util.Base64.getDecoder().decode(signatureValueB64);
            assertEquals(64, sigBytes.length,
                "P-256 ECDSA için XMLDsig SignatureValue r(32) || s(32) = 64 byte olmalı "
                + "(RFC 4051 §3.4.1).");
            assertFalse(Pkcs11EcdsaSignatureEncoder.looksLikeDer(sigBytes),
                "WS-Security'de SignatureValue DER olmamalı; servis derToRaw uygulamış olmalı.");
        }
    }

    // -------------------------------------------------------------------
    // HSM yolu (yeni davranış — codex bulgusu fix)
    // -------------------------------------------------------------------

    @Nested
    @DisplayName("HSM/PKCS#11 yolu (codex bulgusu: 500 dönmemeli)")
    class Pkcs11Path {

        @Test
        @DisplayName("isPkcs11() true ise SignatureException atmamalı (regression)")
        void hsmMode_shouldNotRejectAsBefore() throws Exception {
            Document soap = loadSoapEnvelope();
            FakePkcs11Signer fakeSigner = new FakePkcs11Signer(rsaPair, rsaCert);
            SigningMaterial material = new SigningMaterial(fakeSigner, rsaCert,
                Collections.singletonList(rsaCert));

            // Önceki davranış: hemen SignatureException ile bail-out.
            // Yeni davranış: imzayı tamamla ve geçerli SignResponse dön.
            SignResponse response = service.signSoapEnvelope(soap, false, material, "test", new char[0]);

            assertNotNull(response, "HSM yapılandırmasında servis 500 atmamalı.");
            assertNotNull(response.getSignedDocument(), "Signed bytes null olmamalı.");
            SignedArtifactExporter.export(
                    SignedArtifactExporter.Format.WSSECURITY, response.getSignedDocument());
        }

        @Test
        @DisplayName("RSA HSM: imza XML doğrulamasından geçmeli")
        void hsmRsa_shouldProduceVerifiableSignature() throws Exception {
            Document soap = loadSoapEnvelope();
            FakePkcs11Signer fakeSigner = new FakePkcs11Signer(rsaPair, rsaCert);
            SigningMaterial material = new SigningMaterial(fakeSigner, rsaCert,
                Collections.singletonList(rsaCert));

            SignResponse response = service.signSoapEnvelope(soap, false, material, "test", new char[0]);
            SignedArtifactExporter.export(
                    SignedArtifactExporter.Format.WSSECURITY, response.getSignedDocument());

            assertEquals(1, fakeSigner.callCount.get(),
                "WS-Security tek SignedInfo imzaladığı için Pkcs11Signer.sign tam 1 kez çağrılmalı.");
            Document signed = parseXml(response.getSignedDocument());
            assertSignatureValid(signed, rsaCert.getPublicKey());
        }

        @Test
        @DisplayName("EC HSM: DER imzayı raw r||s'a dönüştürüp doğrulanabilir XML üretmeli")
        void hsmEc_shouldHandleDerToRawConversion() throws Exception {
            Document soap = loadSoapEnvelope();
            FakePkcs11Signer fakeSigner = new FakePkcs11Signer(ecPair, ecCert);
            SigningMaterial material = new SigningMaterial(fakeSigner, ecCert,
                Collections.singletonList(ecCert));

            SignResponse response = service.signSoapEnvelope(soap, false, material, "test", new char[0]);
            SignedArtifactExporter.export(
                    SignedArtifactExporter.Format.WSSECURITY, response.getSignedDocument());

            Document signed = parseXml(response.getSignedDocument());
            String signatureValueB64 = readSignatureValue(signed);
            byte[] sigBytes = java.util.Base64.getDecoder().decode(signatureValueB64);
            assertEquals(64, sigBytes.length, "P-256 EC için XMLDsig raw r||s = 64 byte.");
            assertSignatureValid(signed, ecCert.getPublicKey());
        }

        @Test
        @DisplayName("Pkcs11Signer.sign exception fırlatırsa SignatureException sarmalanmalı")
        void hsmSignFailure_shouldWrapInSignatureException() throws Exception {
            Document soap = loadSoapEnvelope();
            Pkcs11Signer failing = new Pkcs11Signer() {
                @Override
                public String getAlias() { return "test"; }
                @Override
                public X509Certificate getCertificate() { return rsaCert; }
                @Override
                public List<X509Certificate> getCertificateChain() {
                    return Collections.singletonList(rsaCert);
                }
                @Override
                public byte[] sign(byte[] dataToSign, SignatureAlgorithm signatureAlgorithm) {
                    throw new RuntimeException("Simulated HSM session timeout");
                }
            };
            SigningMaterial material = new SigningMaterial(failing, rsaCert,
                Collections.singletonList(rsaCert));

            SignatureException ex = assertThrows(SignatureException.class,
                () -> service.signSoapEnvelope(soap, false, material, "test", new char[0]));
            assertTrue(ex.getMessage().contains("WS-Security imzası oluşturulamadı"),
                "Top-level wrapper devreye girmeli.");
        }
    }

    // -------------------------------------------------------------------
    // Yardımcılar
    // -------------------------------------------------------------------

    private static Document loadSoapEnvelope() throws Exception {
        String xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            + "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\">"
            + "<soapenv:Header/>"
            + "<soapenv:Body><test:Request xmlns:test=\"urn:test\">"
            + "<test:Data>WS-Security test payload</test:Data>"
            + "</test:Request></soapenv:Body></soapenv:Envelope>";
        return parseXml(xml.getBytes("UTF-8"));
    }

    private static Document parseXml(byte[] xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        return db.parse(new InputSource(new ByteArrayInputStream(xml)));
    }

    /**
     * XMLDsig validate: JCA XMLSignatureFactory ile <ds:Signature>'ı bul,
     * KeyInfo'dan public key seç (yerine biz veriyoruz), referans + signature
     * core validate.
     */
    private static void assertSignatureValid(Document signedDoc, PublicKey publicKey) throws Exception {
        // Manuel ID set'i — DOMValidateContext getElementById ile ID resolve eder.
        NodeList allElements = signedDoc.getElementsByTagName("*");
        for (int i = 0; i < allElements.getLength(); i++) {
            Element e = (Element) allElements.item(i);
            String idAttr = e.getAttribute("Id");
            if (idAttr != null && !idAttr.isEmpty()) {
                e.setIdAttribute("Id", true);
            }
            String wsuId = e.getAttributeNS(
                "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
                "Id");
            if (wsuId != null && !wsuId.isEmpty()) {
                e.setIdAttributeNS(
                    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
                    "Id", true);
            }
        }

        NodeList signatures = signedDoc.getElementsByTagNameNS(
            "http://www.w3.org/2000/09/xmldsig#", "Signature");
        assertEquals(1, signatures.getLength(), "Tek <ds:Signature> bekleniyor.");

        KeySelector keySelector = new KeySelector() {
            @Override
            public KeySelectorResult select(KeyInfo keyInfo, KeySelector.Purpose purpose,
                                            AlgorithmMethod method, XMLCryptoContext context)
                    throws KeySelectorException {
                return new KeySelectorResult() {
                    @Override
                    public Key getKey() {
                        return publicKey;
                    }
                };
            }
        };
        DOMValidateContext valCtx = new DOMValidateContext(keySelector, signatures.item(0));
        XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
        XMLSignature signature = factory.unmarshalXMLSignature(valCtx);
        boolean valid = signature.validate(valCtx);
        if (!valid) {
            // Hangi referans/signature value bozuk diye log
            boolean sv = signature.getSignatureValue().validate(valCtx);
            StringBuilder refStatus = new StringBuilder();
            for (Object refObj : signature.getSignedInfo().getReferences()) {
                javax.xml.crypto.dsig.Reference ref = (javax.xml.crypto.dsig.Reference) refObj;
                refStatus.append("\n  URI=").append(ref.getURI())
                    .append(" valid=").append(ref.validate(valCtx));
            }
            throw new AssertionError("WS-Security imzası doğrulanamadı. "
                + "SignatureValue valid=" + sv + ", referenceStatus=" + refStatus);
        }
    }

    private static String readSignatureValue(Document signedDoc) {
        NodeList list = signedDoc.getElementsByTagNameNS(
            "http://www.w3.org/2000/09/xmldsig#", "SignatureValue");
        assertEquals(1, list.getLength());
        return list.item(0).getTextContent().replaceAll("\\s", "");
    }

    private static SigningMaterial pfxMaterial(KeyPair pair, X509Certificate cert) {
        return new SigningMaterial(pair.getPrivate(), cert, Collections.singletonList(cert));
    }

    private static KeyPair generateKeyPair(String alg, int size) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(alg);
        kpg.initialize(size);
        return kpg.generateKeyPair();
    }

    private static X509Certificate generateSelfSignedCertificate(
            KeyPair pair, String sigAlg, String dn) throws Exception {
        X500Name subject = new X500Name(dn);
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 365L * 24 * 60 * 60 * 1000);
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(
            pair.getPublic().getEncoded());

        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
            subject, BigInteger.valueOf(System.nanoTime()),
            notBefore, notAfter, subject, spki);

        return new JcaX509CertificateConverter().getCertificate(
            builder.build(new JcaContentSignerBuilder(sigAlg).build(pair.getPrivate())));
    }

    /**
     * Gerçek HSM yerine in-process {@link Pkcs11Signer} — JCA Signature ile
     * imzalar. ECDSA için DER üretir (IaikPkcs11Module'ün normalize sonrası
     * çıktı kontratını birebir taklit eder). Çağrı sayısını {@link #callCount}
     * üzerinden açar.
     */
    private static final class FakePkcs11Signer implements Pkcs11Signer {

        private final KeyPair keyPair;
        private final X509Certificate cert;
        private final AtomicInteger callCount = new AtomicInteger(0);

        FakePkcs11Signer(KeyPair keyPair, X509Certificate cert) {
            this.keyPair = keyPair;
            this.cert = cert;
        }

        @Override
        public String getAlias() {
            return "test-alias";
        }

        @Override
        public X509Certificate getCertificate() {
            return cert;
        }

        @Override
        public List<X509Certificate> getCertificateChain() {
            List<X509Certificate> chain = new ArrayList<>();
            chain.add(cert);
            return chain;
        }

        @Override
        public byte[] sign(byte[] dataToSign, SignatureAlgorithm signatureAlgorithm) {
            callCount.incrementAndGet();
            try {
                Signature sig = Signature.getInstance(signatureAlgorithm.getJCEId());
                sig.initSign(keyPair.getPrivate());
                sig.update(dataToSign);
                return sig.sign();
            } catch (Exception e) {
                throw new RuntimeException("FakePkcs11Signer failure", e);
            }
        }
    }
}
