package io.mersel.dss.signer.api.services.signature.pades;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import io.mersel.dss.signer.api.models.SigningMaterial;
import io.mersel.dss.signer.api.services.crypto.DigestAlgorithmResolverService;
import io.mersel.dss.signer.api.services.crypto.SigningMaterialContentSigner;
import io.mersel.dss.signer.api.services.keystore.iaik.Pkcs11Signer;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Severity;
import io.qameta.allure.SeverityLevel;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.concurrent.Semaphore;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * PAdES imzalama akışı için <b>digest seçim tutarlılığı</b> regression
 * testleri (K2).
 *
 * <p>Önceki davranış: PAdES, sertifikanın {@code sigAlgName}'ine bakıyordu —
 * yani CA'nın bizi imzalarken kullandığı algoritmaya. Bu yanlış sinyaldi.
 * Şimdi PAdES de CAdES/XAdES gibi {@link DigestAlgorithmResolverService}
 * kullanır; aynı sertifika ile aynı digest tüm formatlarda kullanılır.</p>
 */
@Epic("Service Layer")
@Feature("PAdESSignatureService")
@Severity(SeverityLevel.NORMAL)
class PAdESSignatureServiceTest {

    private static X509Certificate rsaCert;
    private static KeyPair rsaPair;

    @BeforeAll
    static void initCert() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        rsaPair = kpg.generateKeyPair();

        X500Name dn = new X500Name("CN=PAdES Digest Test, O=Mersel, C=TR");
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 365L * 24 * 60 * 60 * 1000);
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(
            rsaPair.getPublic().getEncoded());

        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
            dn, BigInteger.ONE, notBefore, notAfter, dn, spki);

        rsaCert = new JcaX509CertificateConverter().getCertificate(
            builder.build(new JcaContentSignerBuilder("SHA256withRSA")
                .build(rsaPair.getPrivate())));
    }

    @Test
    @DisplayName("PAdES constructor DigestAlgorithmResolverService bağımlılığını ister")
    void constructorRequiresDigestAlgorithmResolverService() throws Exception {
        Constructor<?>[] ctors = PAdESSignatureService.class.getConstructors();
        boolean found = false;
        for (Constructor<?> c : ctors) {
            for (Class<?> p : c.getParameterTypes()) {
                if (p == DigestAlgorithmResolverService.class) {
                    found = true;
                    break;
                }
            }
        }
        assertTrue(found,
            "PAdESSignatureService DigestAlgorithmResolverService inject etmeli; "
            + "aksi halde CAdES/XAdES ile farklı digest seçer ve aynı sertifika ile "
            + "tutarsız imzalar üretir.");
    }

    @Test
    @DisplayName("HSM yolunda unified ContentSigner resolver'ın döndürdüğü digest'i kullanır")
    void hsmPath_contentSignerUsesResolverDigest_sha384() throws Exception {
        DigestAlgorithmResolverService resolver = mock(DigestAlgorithmResolverService.class);
        when(resolver.resolveDigestAlgorithm(any(X509Certificate.class)))
            .thenReturn(DigestAlgorithm.SHA384);

        Pkcs11Signer signer = mock(Pkcs11Signer.class);
        when(signer.getCertificate()).thenReturn(rsaCert);

        SigningMaterial material = new SigningMaterial(signer, rsaCert,
            Collections.singletonList(rsaCert));

        PAdESSignatureService service = new PAdESSignatureService(
            new Semaphore(1), resolver);

        // buildContentSigner private; reflektif olarak çağırıp dönen ContentSigner'ın
        // algorithmIdentifier'ını kontrol et. Bu, PAdES'in HSM yolunda doğru
        // digest'i bağladığını davranışsal olarak kanıtlar.
        Method buildMethod = PAdESSignatureService.class.getDeclaredMethod(
            "buildContentSigner", SigningMaterial.class, DigestAlgorithm.class);
        buildMethod.setAccessible(true);

        ContentSigner cs = (ContentSigner) buildMethod.invoke(service, material,
            resolver.resolveDigestAlgorithm(rsaCert));

        assertNotNull(cs);
        assertTrue(cs instanceof SigningMaterialContentSigner,
            "PAdES yolunda PFX/HSM ayrımı olmadan SigningMaterialContentSigner kullanılmalı");

        // SHA384withRSA OID
        assertEquals("1.2.840.113549.1.1.12",
            cs.getAlgorithmIdentifier().getAlgorithm().getId(),
            "Resolver SHA384 dediğinde ContentSigner SHA384withRSA OID kullanmalı");
    }

    @Test
    @DisplayName("HSM yolunda farklı digest'lerin doğru OID'ye eşlenmesi")
    void hsmPath_resolverDigest_mapsToCorrectSignatureOid() throws Exception {
        // SHA-256
        verifyHsmDigestMapping(DigestAlgorithm.SHA256, "1.2.840.113549.1.1.11");
        // SHA-512
        verifyHsmDigestMapping(DigestAlgorithm.SHA512, "1.2.840.113549.1.1.13");
        // SHA-224
        verifyHsmDigestMapping(DigestAlgorithm.SHA224, "1.2.840.113549.1.1.14");
    }

    private void verifyHsmDigestMapping(DigestAlgorithm digest, String expectedOid) throws Exception {
        DigestAlgorithmResolverService resolver = mock(DigestAlgorithmResolverService.class);
        when(resolver.resolveDigestAlgorithm(any(X509Certificate.class))).thenReturn(digest);

        Pkcs11Signer signer = mock(Pkcs11Signer.class);
        when(signer.getCertificate()).thenReturn(rsaCert);
        when(signer.sign(any(byte[].class), any(SignatureAlgorithm.class)))
            .thenReturn(new byte[]{0x00});

        SigningMaterial material = new SigningMaterial(signer, rsaCert,
            Collections.singletonList(rsaCert));

        PAdESSignatureService service = new PAdESSignatureService(new Semaphore(1), resolver);
        Method buildMethod = PAdESSignatureService.class.getDeclaredMethod(
            "buildContentSigner", SigningMaterial.class, DigestAlgorithm.class);
        buildMethod.setAccessible(true);

        ContentSigner cs = (ContentSigner) buildMethod.invoke(service, material, digest);
        assertEquals(expectedOid,
            cs.getAlgorithmIdentifier().getAlgorithm().getId(),
            "Digest " + digest + " için imza algoritması OID'si yanlış");

        // İmza zinciri sağlam mı (HSM çağrılıyor + sinyal doğru DSS alg ile)
        cs.getOutputStream().write(new byte[]{0x01, 0x02});
        cs.getSignature();
        SignatureAlgorithm expected = SignatureAlgorithm.getAlgorithm(
            eu.europa.esig.dss.enumerations.EncryptionAlgorithm.RSA, digest);
        verify(signer).sign(any(byte[].class), org.mockito.ArgumentMatchers.eq(expected));
    }

    @Test
    @DisplayName("PFX yolunda da aynı ContentSigner kontratı kullanılır")
    void pfxPath_usesSameContentSignerContract() throws Exception {
        SigningMaterial material = new SigningMaterial(rsaPair.getPrivate(), rsaCert,
            Collections.singletonList(rsaCert));
        PAdESSignatureService service = new PAdESSignatureService(
            new Semaphore(1), new DigestAlgorithmResolverService());

        Method buildMethod = PAdESSignatureService.class.getDeclaredMethod(
            "buildContentSigner", SigningMaterial.class, DigestAlgorithm.class);
        buildMethod.setAccessible(true);

        ContentSigner cs = (ContentSigner) buildMethod.invoke(service, material, DigestAlgorithm.SHA256);

        assertTrue(cs instanceof SigningMaterialContentSigner,
            "PFX yolu da HSM yolu da aynı ContentSigner adapter'ından geçmeli");
        cs.getOutputStream().write(new byte[]{0x01, 0x02});
        assertTrue(cs.getSignature().length > 0);
    }
}
