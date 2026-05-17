package io.mersel.dss.signer.api.services.signature.wssecurity;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import io.mersel.dss.signer.api.e2e.verifier.E2eSigningMaterialFactory;
import io.mersel.dss.signer.api.e2e.verifier.PfxTestKey;
import io.mersel.dss.signer.api.e2e.verifier.SoapEnvelopeFixture;
import io.mersel.dss.signer.api.e2e.verifier.WsSecurityLocalXmlDsigVerifier;
import io.mersel.dss.signer.api.models.SignResponse;
import io.mersel.dss.signer.api.models.SigningMaterial;
import io.mersel.dss.signer.api.services.crypto.DigestAlgorithmResolverService;
import io.mersel.dss.signer.api.testsupport.SignedArtifactExporter;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Severity;
import io.qameta.allure.SeverityLevel;
import io.mersel.dss.signer.api.util.xml.SecureXmlFactories;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.security.cert.X509Certificate;
import java.util.concurrent.Semaphore;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * WS-Security için <b>hash algoritma parametrizasyonu</b> kontrat testi.
 *
 * <h3>Neden bu test?</h3>
 * <p>Üretim {@link DigestAlgorithmResolverService} sertifikanın signature
 * algorithm name'inden ({@code SHA256withRSA}, {@code SHA384withECDSA} vb.)
 * SHA-1/224/256/384/512 değerinden birini çözer. SHA varyasyonları
 * {@link WsSecuritySignatureService} tarafından üç ayrı XMLDsig URI'sine
 * map edilir:</p>
 *
 * <ul>
 *   <li><b>SignedInfo &gt; SignatureMethod/@Algorithm</b> → enc+digest kombosu</li>
 *   <li><b>Reference &gt; DigestMethod/@Algorithm</b> → digest'ın URI'si</li>
 *   <li><b>Reference &gt; DigestValue</b> → c14n bytes üzerine MessageDigest çıktısı</li>
 * </ul>
 *
 * <p>Bu üç URI'nin birbirleriyle <b>tutarlı</b> kalması (örn. SHA-384
 * çözüldüyse DigestMethod {@code xmldsig-more#sha384} olur, MessageDigest
 * {@code SHA-384} kullanılır, SignatureMethod {@code rsa-sha384} olur)
 * critical bir kontrat. Yanlışlıkla DigestMethod URI ↔ MessageDigest
 * uyumsuzluğu silent regression olur: imza üretilir, verifier digest
 * mismatch'ten fail eder ama hata mesajı "neden?"i göstermez.</p>
 *
 * <h3>Strateji</h3>
 * <p>Cert'in sigAlg adına bakılan resolver yerine <b>mock resolver</b>
 * inject ederiz; her test SHA-256/384/512 değerini zorla döndürür. Output
 * SOAP'tan DigestMethod + SignatureMethod URI'leri parse edilip mock'ın
 * verdiği SHA ile birebir eşleşmeli; ayrıca lokal
 * {@link WsSecurityLocalXmlDsigVerifier} ile imza geçerli kalmalı
 * (digest URI ↔ algorithm tutarlılığı).</p>
 *
 * <p>Test PFX RSA-2048 ile sınırlandırılmıştır — RSA cert'ler her SHA
 * varyasyonu ile imzalanabilir (PKCS#1 v1.5 enc + herhangi SHA digest).
 * ECDSA için SHA seçimi NIST SP 800-57 önerilerine bağlıdır (P-256 ile
 * SHA-512 mismatch olur); EC parametrizasyonu daha dar bir kontrat.</p>
 */
@DisplayName("D-hash-param: WS-Security DigestMethod/SignatureMethod URI tutarlılığı (SHA-256/384/512)")
@ExtendWith(SignedArtifactExporter.class)
@Epic("Service Layer")
@Feature("WS-Security Hash Algorithm Matrix")
@Severity(SeverityLevel.NORMAL)
class WsSecurityHashAlgorithmParametrizedTest {

    private static final String NS_DSIG = "http://www.w3.org/2000/09/xmldsig#";
    private static final String NS_DSIG_MORE = "http://www.w3.org/2001/04/xmldsig-more#";
    private static final String NS_XMLENC = "http://www.w3.org/2001/04/xmlenc#";

    private static SigningMaterial rsa2048Material;
    private static byte[] baselineSoap;

    @BeforeAll
    static void initStack() {
        // RSA-2048 (KURUM01) — PFX/JCA backend; her SHA varyasyonu ile
        // PKCS#1 v1.5 imzalanabilir (cert public key constraint yok).
        rsa2048Material = E2eSigningMaterialFactory.load(PfxTestKey.KURUM01_RSA2048);
        // Baseline minimal envelope — SHA çeşitliliğine duyarlı değil
        // (sadece c14n bytes farklılaşır). Her test bunu re-parse eder
        // (her thread için fresh DOM zorunlu; JCA DocumentBuilder
        // thread-safe değil).
        baselineSoap = SoapEnvelopeFixture.SOAP_1_1.readBytes();
    }

    /**
     * SHA-256 / 384 / 512 — her biri için:
     * <ol>
     *   <li>Mock resolver verilen SHA'yı döner;</li>
     *   <li>{@link WsSecuritySignatureService} imzalar;</li>
     *   <li>Output SOAP'ta DigestMethod URI = beklenen XMLDsig URI'si;</li>
     *   <li>SignatureMethod URI = RSA + beklenen SHA;</li>
     *   <li>Local XMLDsig verifier imzayı kabul eder (URI ↔ algo tutarlı).</li>
     * </ol>
     */
    @ParameterizedTest(name = "{0}")
    @EnumSource(value = DigestAlgorithm.class, names = {"SHA256", "SHA384", "SHA512"})
    @DisplayName("RSA-2048 × SHA-{256,384,512} → DigestMethod + SignatureMethod URI tutarlı + verifier valid")
    void rsaHashAlgorithmVariations_emitConsistentXmlDsigUris(DigestAlgorithm hashAlgo) throws Exception {
        DigestAlgorithmResolverService mockResolver = mock(DigestAlgorithmResolverService.class);
        when(mockResolver.resolveDigestAlgorithm(any(X509Certificate.class))).thenReturn(hashAlgo);

        WsSecuritySignatureService service = new WsSecuritySignatureService(
                new Semaphore(2), mockResolver);

        Document soapDoc = parseXmlSecurely(baselineSoap);
        SignResponse signed = service.signSoapEnvelope(
                soapDoc,
                /*useSoap12*/ false,
                rsa2048Material,
                /*alias*/ "test",
                /*pin*/ new char[0]);

        assertNotNull(signed);
        byte[] signedBytes = signed.getSignedDocument();
        assertNotNull(signedBytes);
        assertTrue(signedBytes.length > 0);

        // Her SHA varyasyonu için imzalı SOAP'ı disk'e export et —
        // xmlsec1 / WSS4J ile DigestMethod URI tutarlılığını üçüncü
        // taraf araç üzerinden de teyit etmek için.
        SignedArtifactExporter.export(SignedArtifactExporter.Format.WSSECURITY, signedBytes);

        Document signedDoc = parseXmlSecurely(signedBytes);

        String expectedDigestUri = expectedDigestMethodUri(hashAlgo);
        String expectedSignatureUri = expectedRsaSignatureMethodUri(hashAlgo);

        NodeList digestMethods = signedDoc.getElementsByTagNameNS(NS_DSIG, "DigestMethod");
        assertTrue(digestMethods.getLength() >= 1,
                "En az 1 DigestMethod beklenir (Timestamp + Body), bulunan: "
                        + digestMethods.getLength());
        for (int i = 0; i < digestMethods.getLength(); i++) {
            Element dm = (Element) digestMethods.item(i);
            assertEquals(expectedDigestUri, dm.getAttribute("Algorithm"),
                    "DigestMethod[" + i + "]/@Algorithm beklenen SHA URI'sine eşit değil: "
                            + hashAlgo);
        }

        NodeList signatureMethods = signedDoc.getElementsByTagNameNS(NS_DSIG, "SignatureMethod");
        assertEquals(1, signatureMethods.getLength(),
                "Tek bir SignatureMethod beklenir");
        Element sm = (Element) signatureMethods.item(0);
        assertEquals(expectedSignatureUri, sm.getAttribute("Algorithm"),
                "SignatureMethod/@Algorithm RSA + " + hashAlgo + " kombosuyla eşleşmeli");

        // Asıl tutarlılık testi: lokal XMLDsig verifier'ı geçer mi?
        // Verifier DigestMethod URI'sine bakıp aynı SHA ile c14n bytes'ı
        // re-digest eder ve emitted DigestValue ile karşılaştırır.
        // Eğer signer URI ↔ MessageDigest mismatch yapıyorsa burası FAIL.
        WsSecurityLocalXmlDsigVerifier.Result result =
                WsSecurityLocalXmlDsigVerifier.validate(
                        signedBytes,
                        rsa2048Material.getSigningCertificate().getPublicKey());
        assertTrue(result.isValid(),
                "Lokal XMLDsig verifier SHA=" + hashAlgo + " ile reddetti: " + result);
    }

    private static String expectedDigestMethodUri(DigestAlgorithm digest) {
        switch (digest) {
            case SHA256: return NS_XMLENC + "sha256";
            case SHA384: return NS_DSIG_MORE + "sha384";
            case SHA512: return NS_XMLENC + "sha512";
            default:
                throw new IllegalArgumentException("Test için desteklenmeyen SHA: " + digest);
        }
    }

    private static String expectedRsaSignatureMethodUri(DigestAlgorithm digest) {
        // WsSecuritySignatureService#signatureMethodUri (RSA dalı):
        //   SHA-256/384/512 hepsi xmldsig-more namespace'inde.
        switch (digest) {
            case SHA256: return NS_DSIG_MORE + "rsa-sha256";
            case SHA384: return NS_DSIG_MORE + "rsa-sha384";
            case SHA512: return NS_DSIG_MORE + "rsa-sha512";
            default:
                throw new IllegalArgumentException("Test için desteklenmeyen SHA: " + digest);
        }
    }

    private static Document parseXmlSecurely(byte[] xml) throws Exception {
        DocumentBuilderFactory dbf = SecureXmlFactories.newDocumentBuilderFactory();
        DocumentBuilder db = dbf.newDocumentBuilder();
        return db.parse(new ByteArrayInputStream(xml));
    }
}
