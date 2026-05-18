package io.mersel.dss.signer.api.models;

import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.x509.CertificateToken;
import io.mersel.dss.signer.api.services.keystore.iaik.Pkcs11Signer;
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

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * {@link SigningMaterial} immutable nesnesini iki backend ayrımı (PFX/PKCS#11)
 * ve kontratları açısından doğrular. Bu nesne tüm imza akışlarının (CAdES,
 * XAdES, PAdES, WS-Security) ortak girdisidir; davranışı yanlış olursa
 * downstream branching tüm sektörde patlar.
 */
@Epic("Service Layer")
@Feature("SigningMaterial Backend Abstraction")
@Severity(SeverityLevel.CRITICAL)
class SigningMaterialTest {

    private static KeyPair rsaKeyPair;
    private static X509Certificate selfSignedCert;

    @BeforeAll
    static void initCryptoFixtures() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        rsaKeyPair = kpg.generateKeyPair();

        X500Name subject = new X500Name("CN=SigningMaterial Test, O=Mersel, C=TR");
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 365L * 24 * 60 * 60 * 1000);

        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(
            rsaKeyPair.getPublic().getEncoded());
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
            subject, BigInteger.ONE, notBefore, notAfter, subject, spki);

        selfSignedCert = new JcaX509CertificateConverter().getCertificate(
            builder.build(new JcaContentSignerBuilder("SHA256withRSA")
                .build(rsaKeyPair.getPrivate())));
    }

    // ----------------------------------------------------------------
    // PFX / JCA constructor
    // ----------------------------------------------------------------

    @Nested
    @DisplayName("PFX (JCA PrivateKey) backend")
    class PfxBackend {

        @Test
        void shouldExposePrivateKeyAndMarkNotPkcs11() {
            SigningMaterial material = new SigningMaterial(
                rsaKeyPair.getPrivate(), selfSignedCert,
                Collections.singletonList(selfSignedCert));

            assertSame(rsaKeyPair.getPrivate(), material.getPrivateKey());
            assertNull(material.getPkcs11Signer(),
                "PFX yolunda pkcs11Signer null olmalı");
            assertFalse(material.isPkcs11(),
                "isPkcs11() false dönmeli — CryptoSignerService JCA yolunu seçer");
            assertEquals("PFX/JCA", material.getBackendName());
        }

        @Test
        void shouldExposeCertificateAndChain() {
            List<X509Certificate> chain = Arrays.asList(selfSignedCert, selfSignedCert);
            SigningMaterial material = new SigningMaterial(
                rsaKeyPair.getPrivate(), selfSignedCert, chain);

            assertSame(selfSignedCert, material.getSigningCertificate());
            assertEquals(2, material.getCertificateChain().size());
            assertSame(selfSignedCert, material.getCertificateChain().get(0));
            assertSame(selfSignedCert, material.getCertificateChain().get(1));
        }

        @Test
        void materialSign_shouldProduceVerifiableJcaSignature() throws Exception {
            byte[] payload = "contract payload".getBytes("UTF-8");
            SigningMaterial material = new SigningMaterial(rsaKeyPair.getPrivate(),
                selfSignedCert, Collections.singletonList(selfSignedCert));

            byte[] signatureBytes = material.sign(payload, SignatureAlgorithm.RSA_SHA256);

            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(selfSignedCert.getPublicKey());
            verifier.update(payload);
            assertTrue(verifier.verify(signatureBytes),
                "SigningMaterial.sign PFX yolunda doğrulanabilir JCA imzası üretmeli");
        }
    }

    // ----------------------------------------------------------------
    // PKCS#11 / HSM constructor
    // ----------------------------------------------------------------

    @Nested
    @DisplayName("PKCS#11 (HSM Pkcs11Signer) backend")
    class Pkcs11Backend {

        @Test
        void shouldExposePkcs11SignerAndMarkAsPkcs11() {
            Pkcs11Signer mockSigner = mock(Pkcs11Signer.class);

            SigningMaterial material = new SigningMaterial(
                mockSigner, selfSignedCert,
                Collections.singletonList(selfSignedCert));

            assertSame(mockSigner, material.getPkcs11Signer());
            assertNull(material.getPrivateKey(),
                "HSM yolunda privateKey null olmalı — key handle HSM içinde kalır");
            assertTrue(material.isPkcs11());
            assertEquals("HSM/PKCS#11", material.getBackendName());
        }

        @Test
        void isPkcs11_shouldDriveCryptoSignerBranching() {
            // CryptoSignerService.sign() bu flag'e bakıp ya JCA ya da
            // PKCS#11 yoluna sapar. Yanlış flag = yanlış imza yolu.
            Pkcs11Signer hsm = mock(Pkcs11Signer.class);

            SigningMaterial pfx = new SigningMaterial(rsaKeyPair.getPrivate(),
                selfSignedCert, Collections.singletonList(selfSignedCert));
            SigningMaterial hsmMaterial = new SigningMaterial(hsm,
                selfSignedCert, Collections.singletonList(selfSignedCert));

            assertFalse(pfx.isPkcs11());
            assertTrue(hsmMaterial.isPkcs11());
        }

        @Test
        void pkcs11SignerSign_shouldBeDelegatedTo() {
            // Davranışsal: SigningMaterial Pkcs11Signer'a doğrudan referans
            // tutmalı; downstream CryptoSignerService bu referansı kullanmalı.
            Pkcs11Signer hsm = mock(Pkcs11Signer.class);
            byte[] expected = new byte[]{0x01, 0x02};
            when(hsm.sign(any(byte[].class), any(SignatureAlgorithm.class))).thenReturn(expected);

            SigningMaterial material = new SigningMaterial(hsm, selfSignedCert,
                Collections.singletonList(selfSignedCert));

            byte[] result = material.sign(
                new byte[]{0x10}, SignatureAlgorithm.RSA_SHA256);
            assertSame(expected, result);
        }

    }

    // ----------------------------------------------------------------
    // CertificateToken dönüşümü
    // ----------------------------------------------------------------

    @Nested
    @DisplayName("DSS CertificateToken dönüşümü")
    class CertificateTokenConversion {

        @Test
        void shouldConvertChainToCertificateTokens() {
            SigningMaterial material = new SigningMaterial(
                rsaKeyPair.getPrivate(), selfSignedCert,
                Collections.singletonList(selfSignedCert));

            List<CertificateToken> tokens = material.getCertificateTokens();
            assertNotNull(tokens);
            assertEquals(1, tokens.size());
            assertEquals(selfSignedCert, tokens.get(0).getCertificate());
        }

        @Test
        void primaryCertificateToken_shouldBeFirstInChain() {
            SigningMaterial material = new SigningMaterial(
                rsaKeyPair.getPrivate(), selfSignedCert,
                Collections.singletonList(selfSignedCert));

            assertEquals(selfSignedCert, material.getPrimaryCertificateToken().getCertificate());
        }
    }

    // ----------------------------------------------------------------
    // Immutability garantileri
    // ----------------------------------------------------------------

    @Nested
    @DisplayName("Immutability kontratı")
    class ImmutabilityContract {

        @Test
        void returnedChain_shouldBeUnmodifiable() {
            SigningMaterial material = new SigningMaterial(
                rsaKeyPair.getPrivate(), selfSignedCert,
                Collections.singletonList(selfSignedCert));

            List<X509Certificate> chain = material.getCertificateChain();
            assertThrows(UnsupportedOperationException.class,
                () -> chain.add(selfSignedCert),
                "getCertificateChain() unmodifiableList dönmeli");
        }

        @Test
        void mutatingOriginalChain_shouldNotAffectMaterial() {
            // Ctor'a verilen liste sonradan değişirse SigningMaterial içeriği
            // değişmemeli (defensive copy).
            java.util.ArrayList<X509Certificate> originalChain = new java.util.ArrayList<>();
            originalChain.add(selfSignedCert);

            SigningMaterial material = new SigningMaterial(
                rsaKeyPair.getPrivate(), selfSignedCert, originalChain);

            originalChain.clear();

            assertEquals(1, material.getCertificateChain().size(),
                "Ctor defensive copy yapmalı; dışarıdaki list mutasyonu material'ı etkilememeli");
        }
    }

    // ----------------------------------------------------------------
    // Negative paths
    // ----------------------------------------------------------------

    @Nested
    @DisplayName("Hatalı kullanım senaryoları")
    class ErrorCases {

        @Test
        void bothBackendsNull_shouldThrow() {
            assertThrows(IllegalArgumentException.class,
                () -> invokePrivateCtorWithBothNull(),
                "Ne PrivateKey ne Pkcs11Signer verilmediği durum reddedilmeli");
        }

        /**
         * Public constructor'lar bir tarafı her zaman doluyor; ama
         * SigningMaterial(null, signingCert, chain) — public PFX ctor —
         * private key null verilirse private ctor'a "ikisi de null"
         * gelir ve guard tetiklenir.
         */
        private void invokePrivateCtorWithBothNull() {
            new SigningMaterial((PrivateKey) null, selfSignedCert,
                Collections.singletonList(selfSignedCert));
        }
    }
}
