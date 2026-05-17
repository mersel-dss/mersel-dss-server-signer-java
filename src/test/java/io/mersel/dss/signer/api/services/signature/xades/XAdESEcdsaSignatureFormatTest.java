package io.mersel.dss.signer.api.services.signature.xades;

import eu.europa.esig.dss.alert.SilentOnStatusAlert;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.signature.XAdESService;
import io.mersel.dss.signer.api.e2e.verifier.E2eFixtures;
import io.mersel.dss.signer.api.e2e.verifier.E2eSigningMaterialFactory;
import io.mersel.dss.signer.api.e2e.verifier.PfxTestKey;
import io.mersel.dss.signer.api.models.SignResponse;
import io.mersel.dss.signer.api.models.SigningMaterial;
import io.mersel.dss.signer.api.models.enums.DocumentType;
import io.mersel.dss.signer.api.services.crypto.CryptoSignerService;
import io.mersel.dss.signer.api.services.crypto.DigestAlgorithmResolverService;
import io.mersel.dss.signer.api.services.crypto.SignatureAlgorithmResolverService;
import io.mersel.dss.signer.api.services.timestamp.TimestampConfigurationService;
import io.mersel.dss.signer.api.services.util.CompressionService;
import io.mersel.dss.signer.api.testsupport.SignedArtifactExporter;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Severity;
import io.qameta.allure.SeverityLevel;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.EnumSource.Mode;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.util.Base64;
import java.util.UUID;
import java.util.concurrent.Semaphore;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Regression: XAdES ECDSA imzaları XML-DSig spec'ine uygun şekilde plain
 * (r||s) formatında üretilmelidir, ASN.1 DER SEQUENCE değil.
 *
 * <p>Bu test çift PFX (RSA + EC) kullanarak hem RSA imzalarının uzunluğunun
 * değişmediğini hem de ECDSA imzalarının doğru P-curve uzunluğuna (P-384 için
 * 96 byte) sıkıştığını doğrular. Eğer
 * {@link io.mersel.dss.signer.api.services.signature.xades.XAdESSignatureService#ensureXadesSignatureValueFormat
 * ensureXadesSignatureValueFormat} silinir veya bozulursa, EC iterasyonlarda
 * sigValueBinLen 102/103 byte (DER) olarak ölçülür ve assert patlar.</p>
 *
 * <p>Bu test verifier API container'ı GEREKTİRMEZ — sadece imzalama akışını
 * çalıştırır ve XML'i kendi parse eder. {@link E2eFixtures} altyapısını
 * yeniden kullanır ve repo kökündeki test PFX'lerini okur. Hızlı çalışır,
 * default Surefire suite'inde koşar.</p>
 */
@ExtendWith(SignedArtifactExporter.class)
@Epic("Crypto Conformance")
@Feature("ECDSA Signature Format (XAdES vs WSS)")
@Severity(SeverityLevel.CRITICAL)
class XAdESEcdsaSignatureFormatTest {

    private XAdESSignatureService service;

    private XAdESSignatureService buildService() {
        // CRL/OCSP yokluğunda DSS'in pre-flight alert'lerini sustur.
        CommonCertificateVerifier verifier = new CommonCertificateVerifier();
        verifier.setAlertOnMissingRevocationData(new SilentOnStatusAlert());
        verifier.setAlertOnNoRevocationAfterBestSignatureTime(new SilentOnStatusAlert());
        verifier.setAlertOnRevokedCertificate(new SilentOnStatusAlert());
        verifier.setAlertOnInvalidTimestamp(new SilentOnStatusAlert());
        verifier.setAlertOnExpiredCertificate(new SilentOnStatusAlert());
        verifier.setAlertOnNotYetValidCertificate(new SilentOnStatusAlert());

        XAdESService dssService = new XAdESService(verifier);
        DigestAlgorithmResolverService digestResolver = new DigestAlgorithmResolverService();
        SignatureAlgorithmResolverService sigAlgResolver = new SignatureAlgorithmResolverService();
        CryptoSignerService crypto = new CryptoSignerService(sigAlgResolver);
        XAdESParametersBuilderService paramsBuilder =
                new XAdESParametersBuilderService(digestResolver);
        XmlProcessingService xmlProcessor = new XmlProcessingService();
        XAdESDocumentPlacementService placement = new XAdESDocumentPlacementService();
        TimestampConfigurationService tsConfig = new TimestampConfigurationService(
                "", "", "", false);
        XAdESLevelUpgradeService upgrade = new XAdESLevelUpgradeService(verifier, tsConfig);
        CompressionService compression = new CompressionService();
        return new XAdESSignatureService(
                dssService, paramsBuilder, xmlProcessor, placement, upgrade,
                crypto, verifier, compression, new Semaphore(2));
    }

    @ParameterizedTest(name = "[{index}] {0}")
    // Yalnızca pozitif (Status.VALID) PFX'leri kapsa — negatif lifecycle
    // (revoked/expired/suspended) PFX'leri PfxTestKey enum'unda mevcut ama
    // ana ECDSA format matriksine ait değil. JUnit 5.8 (Spring Boot 2.7
    // parent) MATCH_NONE desteklemiyor, EXCLUDE + explicit names kullanıyoruz.
    @EnumSource(value = PfxTestKey.class, mode = Mode.EXCLUDE,
            names = {"KAMUSM_REVOKED_RSA2048", "KAMUSM_REVOKED_EC384",
                     "KAMUSM_EXPIRED_RSA2048", "KAMUSM_EXPIRED_EC384",
                     "KAMUSM_SUSPENDED_RSA2048", "KAMUSM_SUSPENDED_EC384"})
    @DisplayName("XAdES SignatureValue formatı XML-DSig spec'ine uygun (RSA → uzunluk korunur, ECDSA → r||s plain)")
    void signatureValueRespectsXmldsigPlainFormat(PfxTestKey key) throws Exception {
        if (service == null) {
            service = buildService();
        }
        SigningMaterial material = E2eSigningMaterialFactory.load(key);

        SignResponse signed = service.signXml(
                new ByteArrayInputStream(E2eFixtures.efaturaXml()),
                DocumentType.UblDocument,
                "id-" + UUID.randomUUID().toString().replace("-", ""),
                /*zipped*/ false,
                material);

        assertNotNull(signed.getSignedDocument(), "signedDocument null olmamalı");

        // RSA/EC karışık matrislerinde her PFX için bir XAdES örneği export et —
        // xmlsec1 veya EU DSS Demo ile cross-validate edilebilir.
        SignedArtifactExporter.export(
                SignedArtifactExporter.Format.XADES, signed.getSignedDocument());

        byte[] sigValue = extractSignatureValueBinary(signed.getSignedDocument());

        // Regression: x-signature-value header'ı (= SignResponse.signatureValue)
        // XML içindeki <ds:SignatureValue> ile birebir AYNI Base64 değer olmalı.
        // Aksi halde tüketici XML ↔ header diff'iyle imzayı yanlış reddeder.
        // ECDSA'da DSS'in ensurePlainSignatureValue() çağrısından önce capture
        // edilen değer DER kalıp uyuşmazlığa yol açıyordu; bu test o regression'ı
        // kalıcı olarak yakalar.
        assertNotNull(signed.getSignatureValue(),
                "SignResponse.signatureValue null olmamalı");
        assertEquals(Base64.getEncoder().encodeToString(sigValue),
                signed.getSignatureValue(),
                "x-signature-value header XML içindeki <ds:SignatureValue> ile "
                        + "birebir aynı olmalı (Base64-eşit). ECDSA için DER↔r||s "
                        + "uyumsuzluğu burada yakalanır.");

        String keyAlg = material.getSigningCertificate().getPublicKey().getAlgorithm();
        if ("RSA".equalsIgnoreCase(keyAlg)) {
            // 2048-bit RSA imzası ham 256 byte; PSS ise farklı uzunlukta olabilir
            // ama buradaki sözleşme klasik PKCS#1.5 SHA384.
            assertEquals(256, sigValue.length,
                    "RSA-2048 PKCS#1 v1.5 imza uzunluğu 256 byte olmalı, gözlenen: " + sigValue.length);
            return;
        }
        if ("EC".equalsIgnoreCase(keyAlg) || "ECDSA".equalsIgnoreCase(keyAlg)) {
            // P-384 için r||s plain = 48 + 48 = 96 byte (TAM)
            assertEquals(96, sigValue.length,
                    "P-384 ECDSA SignatureValue plain (r||s) 96 byte olmalı (XML-DSig spec), "
                            + "gözlenen: " + sigValue.length + " byte. "
                            + "Eğer 100-104 byte aralığında ise muhtemelen ASN.1 DER SEQUENCE "
                            + "olarak yazılmış demektir — bu XML-DSig spec ihlalidir ve verifier "
                            + "SIG_CRYPTO_FAILURE döner.");
            // İlk byte 0x30 (SEQUENCE) olmamalı — eğer öyleyse DER kalmış.
            assertTrue((sigValue[0] & 0xFF) != 0x30,
                    "SignatureValue ilk byte 0x30 (ASN.1 SEQUENCE tag). Plain r||s "
                            + "formatında olmadığı için bu bir regression.");
            return;
        }
        throw new IllegalStateException("Test bilinmeyen public-key algoritması için yazılmamış: " + keyAlg);
    }

    private static byte[] extractSignatureValueBinary(byte[] signedXml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document dom = db.parse(new InputSource(new StringReader(new String(signedXml))));
        NodeList nodes = dom.getElementsByTagNameNS(
                "http://www.w3.org/2000/09/xmldsig#", "SignatureValue");
        if (nodes.getLength() == 0) {
            throw new IllegalStateException("İmzalı XML'de SignatureValue elementi bulunamadı");
        }
        String b64 = ((Element) nodes.item(0)).getTextContent().replaceAll("\\s", "");
        return Base64.getDecoder().decode(b64);
    }
}
