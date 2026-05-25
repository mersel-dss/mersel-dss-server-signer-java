package io.mersel.dss.signer.api.services.keystore.iaik;

import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * {@link IaikPkcs11Signer} ince delegasyon kontratını test eder. Asıl HSM
 * çağrısı {@link IaikPkcs11Module#signOnSession} içindedir (gerçek token
 * gerektirir); burada signer'ın doğru handle/algoritma/byte'ı modüle
 * forward'ladığını verifiye ediyoruz.
 *
 * <p>Bu testler aynı paket içindedir çünkü
 * {@link IaikPkcs11Module.ResolvedKey} ve {@link IaikPkcs11Signer} ctor'u
 * package-private — wrapper'ın "internal" sözleşmesini test eder.</p>
 */
@Epic("PKCS#11 Integration")
@Feature("IAIK Signer Delegation")
@Severity(SeverityLevel.CRITICAL)
class IaikPkcs11SignerTest {

    private static X509Certificate cert;
    private static X509Certificate intermediateCert;

    private IaikPkcs11Module moduleMock;

    @BeforeAll
    static void initFixtures() throws Exception {
        cert = newCert("CN=HSM End Entity");
        intermediateCert = newCert("CN=HSM Intermediate CA");
    }

    @BeforeEach
    void setUp() {
        moduleMock = mock(IaikPkcs11Module.class);
    }

    private IaikPkcs11Module.ResolvedKey resolvedKey(long handle, String alias,
                                                    List<X509Certificate> chain) {
        IaikPkcs11Module.ResolvedKey rk = new IaikPkcs11Module.ResolvedKey();
        rk.alias = alias;
        rk.certificate = chain.get(0);
        rk.certificateChain = chain;
        rk.privateKeyHandle = handle;
        return rk;
    }

    @Nested
    @DisplayName("Cert / alias / chain getter'ları")
    class Getters {

        @Test
        void shouldExposeAliasFromResolvedKey() {
            IaikPkcs11Module.ResolvedKey rk =
                resolvedKey(0xABCD, "e-imza-2026", Collections.singletonList(cert));

            IaikPkcs11Signer signer = new IaikPkcs11Signer(moduleMock, rk);
            assertEquals("e-imza-2026", signer.getAlias());
        }

        @Test
        void shouldExposeCertificateFromResolvedKey() {
            IaikPkcs11Module.ResolvedKey rk =
                resolvedKey(0xABCD, "x", Collections.singletonList(cert));

            IaikPkcs11Signer signer = new IaikPkcs11Signer(moduleMock, rk);
            assertSame(cert, signer.getCertificate());
        }

        @Test
        void shouldExposeFullChain() {
            List<X509Certificate> chain = Arrays.asList(cert, intermediateCert);
            IaikPkcs11Module.ResolvedKey rk = resolvedKey(0xABCD, "x", chain);

            IaikPkcs11Signer signer = new IaikPkcs11Signer(moduleMock, rk);
            List<X509Certificate> exposed = signer.getCertificateChain();
            assertEquals(2, exposed.size());
            assertSame(cert, exposed.get(0));
            assertSame(intermediateCert, exposed.get(1));
        }
    }

    @Nested
    @DisplayName("sign() delegasyonu")
    class SignDelegation {

        @Test
        void shouldForwardHandleDataAndAlgorithm_toModule() {
            byte[] data = "payload".getBytes();
            byte[] hsmSignature = new byte[]{0x70, 0x71};
            long handle = 0xDEADBEEFL;

            // L2 SMS-aile recovery branch'i ResolvedKey overload'unu kullanır.
            when(moduleMock.signOnSession(any(IaikPkcs11Module.ResolvedKey.class),
                any(byte[].class), any(SignatureAlgorithm.class)))
                .thenReturn(hsmSignature);

            IaikPkcs11Module.ResolvedKey rk =
                resolvedKey(handle, "x", Collections.singletonList(cert));
            IaikPkcs11Signer signer = new IaikPkcs11Signer(moduleMock, rk);

            byte[] result = signer.sign(data, SignatureAlgorithm.RSA_SHA256);
            assertArrayEquals(hsmSignature, result,
                "Signer modülün dönen byte'larını mutate etmemeli");

            ArgumentCaptor<IaikPkcs11Module.ResolvedKey> rkCaptor =
                ArgumentCaptor.forClass(IaikPkcs11Module.ResolvedKey.class);
            ArgumentCaptor<byte[]> dataCaptor = ArgumentCaptor.forClass(byte[].class);
            ArgumentCaptor<SignatureAlgorithm> algCaptor =
                ArgumentCaptor.forClass(SignatureAlgorithm.class);
            verify(moduleMock, times(1)).signOnSession(rkCaptor.capture(),
                dataCaptor.capture(), algCaptor.capture());
            assertSame(rk, rkCaptor.getValue(),
                "Signer kendi ResolvedKey referansını modüle geçirmeli — "
                + "in-place handle refresh için aynı instance paylaşılmalı");
            assertEquals(handle, rkCaptor.getValue().privateKeyHandle,
                "ResolvedKey üzerindeki handle modüle aktarılmalı");
            assertSame(data, dataCaptor.getValue(),
                "Veri direkt referans olarak modüle geçirilmeli — gereksiz kopya yok");
            assertEquals(SignatureAlgorithm.RSA_SHA256, algCaptor.getValue());
        }

        @Test
        void multipleSignCalls_shouldEachInvokeModule() {
            when(moduleMock.signOnSession(any(IaikPkcs11Module.ResolvedKey.class),
                any(byte[].class), any(SignatureAlgorithm.class)))
                .thenReturn(new byte[]{0x01});

            IaikPkcs11Module.ResolvedKey rk =
                resolvedKey(1L, "x", Collections.singletonList(cert));
            IaikPkcs11Signer signer = new IaikPkcs11Signer(moduleMock, rk);

            signer.sign(new byte[]{1}, SignatureAlgorithm.RSA_SHA256);
            signer.sign(new byte[]{2}, SignatureAlgorithm.RSA_SHA384);
            signer.sign(new byte[]{3}, SignatureAlgorithm.RSA_SHA512);

            verify(moduleMock, times(3)).signOnSession(
                any(IaikPkcs11Module.ResolvedKey.class),
                any(byte[].class),
                any(SignatureAlgorithm.class));
            verify(moduleMock).signOnSession(eq(rk), any(byte[].class),
                eq(SignatureAlgorithm.RSA_SHA384));
        }

        @Test
        void differentSignaturesAlgorithms_areForwarded() {
            when(moduleMock.signOnSession(any(IaikPkcs11Module.ResolvedKey.class),
                any(byte[].class), any(SignatureAlgorithm.class)))
                .thenReturn(new byte[]{0x01});

            IaikPkcs11Module.ResolvedKey rk =
                resolvedKey(42L, "ecdsa-key", Collections.singletonList(cert));
            IaikPkcs11Signer signer = new IaikPkcs11Signer(moduleMock, rk);

            for (SignatureAlgorithm alg : new SignatureAlgorithm[]{
                SignatureAlgorithm.RSA_SHA256,
                SignatureAlgorithm.RSA_SHA512,
                SignatureAlgorithm.ECDSA_SHA256,
                SignatureAlgorithm.ECDSA_SHA512,
                SignatureAlgorithm.RSA_SSA_PSS_SHA256_MGF1
            }) {
                signer.sign(new byte[]{1}, alg);
                verify(moduleMock).signOnSession(eq(rk), any(byte[].class), eq(alg));
            }
        }

        @Test
        void resolvedKey_volatileHandleRefresh_isPickedUpByNextSign() {
            // L1/L2 reinit sonrası ResolvedKey.privateKeyHandle in-place
            // güncellenir; signer aynı ResolvedKey referansını paylaştığı
            // için bir sonraki sign çağrısı yeni handle ile gitmeli.
            when(moduleMock.signOnSession(any(IaikPkcs11Module.ResolvedKey.class),
                any(byte[].class), any(SignatureAlgorithm.class)))
                .thenReturn(new byte[]{0x01});

            IaikPkcs11Module.ResolvedKey rk =
                resolvedKey(0xAAA, "x", Collections.singletonList(cert));
            IaikPkcs11Signer signer = new IaikPkcs11Signer(moduleMock, rk);

            signer.sign(new byte[]{1}, SignatureAlgorithm.RSA_SHA256);

            // Reinit simülasyonu: handle yenilendi.
            rk.privateKeyHandle = 0xBBBL;
            signer.sign(new byte[]{2}, SignatureAlgorithm.RSA_SHA256);

            ArgumentCaptor<IaikPkcs11Module.ResolvedKey> rkCaptor =
                ArgumentCaptor.forClass(IaikPkcs11Module.ResolvedKey.class);
            verify(moduleMock, times(2)).signOnSession(rkCaptor.capture(),
                any(byte[].class), any(SignatureAlgorithm.class));
            // Aynı reference paylaşılır; her iki çağrıda da current handle okunur.
            assertSame(rk, rkCaptor.getAllValues().get(0));
            assertSame(rk, rkCaptor.getAllValues().get(1));
            assertEquals(0xBBBL, rk.privateKeyHandle,
                "Reinit sonrası handle in-place güncellendi.");
        }
    }

    @Nested
    @DisplayName("Pkcs11Signer interface uyumu")
    class InterfaceConformance {

        @Test
        void shouldBeAssignableToPkcs11SignerInterface() {
            IaikPkcs11Module.ResolvedKey rk =
                resolvedKey(1L, "x", Collections.singletonList(cert));
            Pkcs11Signer asInterface = new IaikPkcs11Signer(moduleMock, rk);
            assertTrue(asInterface instanceof Pkcs11Signer);
        }
    }

    // ----------------------------------------------------------------
    // helpers
    // ----------------------------------------------------------------

    private static X509Certificate newCert(String dn) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair pair = kpg.generateKeyPair();

        X500Name subject = new X500Name(dn);
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 365L * 24 * 60 * 60 * 1000);
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(
            pair.getPublic().getEncoded());
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
            subject, BigInteger.valueOf(System.nanoTime()),
            notBefore, notAfter, subject, spki);

        return new JcaX509CertificateConverter().getCertificate(
            builder.build(new JcaContentSignerBuilder("SHA256withRSA")
                .build(pair.getPrivate())));
    }
}
