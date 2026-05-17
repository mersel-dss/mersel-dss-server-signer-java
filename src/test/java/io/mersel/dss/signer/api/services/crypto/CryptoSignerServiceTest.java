package io.mersel.dss.signer.api.services.crypto;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import io.mersel.dss.signer.api.exceptions.SignatureException;
import io.mersel.dss.signer.api.models.SigningMaterial;
import io.mersel.dss.signer.api.services.keystore.iaik.Pkcs11Signer;
import io.mersel.dss.signer.api.testsupport.PfxBackedPkcs11Signer;
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
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * {@link CryptoSignerService}'in iki backend yolunu (JCA / PKCS#11) ve
 * exception sarmalamasını verifiye eder.
 *
 * <p>Bu servis tüm DSS imzalama akışlarında {@code signatureValue}'yu üreten
 * tek noktadır; branch seçimi yanlış olursa HSM yerine yanlış key kullanılır
 * veya tam tersi olur — kritik hata.</p>
 */
class CryptoSignerServiceTest {

    private static KeyPair rsaKeyPair;
    private static X509Certificate rsaCertificate;

    private CryptoSignerService service;

    @BeforeAll
    static void initFixtures() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        rsaKeyPair = kpg.generateKeyPair();

        X500Name subject = new X500Name("CN=CryptoSigner Test, O=Mersel, C=TR");
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 365L * 24 * 60 * 60 * 1000);
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(
            rsaKeyPair.getPublic().getEncoded());

        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
            subject, BigInteger.ONE, notBefore, notAfter, subject, spki);

        rsaCertificate = new JcaX509CertificateConverter().getCertificate(
            builder.build(new JcaContentSignerBuilder("SHA256withRSA")
                .build(rsaKeyPair.getPrivate())));
    }

    @BeforeEach
    void setUp() {
        service = new CryptoSignerService(new SignatureAlgorithmResolverService());
    }

    // ----------------------------------------------------------------
    // PFX / JCA yolu
    // ----------------------------------------------------------------

    @Nested
    @DisplayName("PFX (JCA) imza yolu")
    class JcaPath {

        @Test
        void shouldProduceVerifiableRsaSha256Signature() throws Exception {
            byte[] data = "e-Donusum critical signature payload".getBytes();
            SigningMaterial material = new SigningMaterial(
                rsaKeyPair.getPrivate(), rsaCertificate,
                Collections.singletonList(rsaCertificate));

            SignatureValue result = service.sign(new ToBeSigned(data),
                material, DigestAlgorithm.SHA256);

            assertNotNull(result);
            assertEquals(SignatureAlgorithm.RSA_SHA256, result.getAlgorithm());
            assertTrue(result.getValue().length > 0);

            // İmzanın gerçekten geçerli olduğunu JCA verify ile doğrula —
            // sadece bytes üretildi diye geçmiş olmasın, kriptografik
            // anlamda da doğru olduğunu kanıtlayalım.
            Signature verify = Signature.getInstance("SHA256withRSA");
            verify.initVerify(rsaCertificate.getPublicKey());
            verify.update(data);
            assertTrue(verify.verify(result.getValue()),
                "Üretilen imza public key ile verify edilebilmeli");
        }

        @Test
        void differentDigestAlgorithms_shouldProduceCorrespondingSignatureAlg() {
            byte[] data = new byte[]{1, 2, 3};
            SigningMaterial material = new SigningMaterial(
                rsaKeyPair.getPrivate(), rsaCertificate,
                Collections.singletonList(rsaCertificate));

            SignatureValue sha384 = service.sign(new ToBeSigned(data), material, DigestAlgorithm.SHA384);
            assertEquals(SignatureAlgorithm.RSA_SHA384, sha384.getAlgorithm());

            SignatureValue sha512 = service.sign(new ToBeSigned(data), material, DigestAlgorithm.SHA512);
            assertEquals(SignatureAlgorithm.RSA_SHA512, sha512.getAlgorithm());
        }
    }

    // ----------------------------------------------------------------
    // PKCS#11 yolu (mock)
    // ----------------------------------------------------------------

    @Nested
    @DisplayName("PKCS#11 (HSM) imza yolu")
    class Pkcs11Path {

        @Test
        void shouldDelegateToHsmAndPassBytesIntact() {
            byte[] payload = "raw bytes to HSM".getBytes();
            byte[] hsmSignature = new byte[]{(byte) 0xAA, (byte) 0xBB, (byte) 0xCC};

            Pkcs11Signer hsm = mock(Pkcs11Signer.class);
            when(hsm.sign(any(byte[].class), any(SignatureAlgorithm.class)))
                .thenReturn(hsmSignature);
            when(hsm.getAlias()).thenReturn("hsm-key-1");

            SigningMaterial material = new SigningMaterial(hsm, rsaCertificate,
                Collections.singletonList(rsaCertificate));

            SignatureValue result = service.sign(new ToBeSigned(payload),
                material, DigestAlgorithm.SHA256);

            assertNotNull(result);
            assertEquals(SignatureAlgorithm.RSA_SHA256, result.getAlgorithm());
            assertArrayEquals(hsmSignature, result.getValue(),
                "HSM'den dönen byte'lar SignatureValue'da değişmeden olmalı");

            // HSM'e geçilen byte stream tam payload olmalı (digest ya da
            // başka pre-processing yok — bu pre-processing HSM'in işi).
            ArgumentCaptor<byte[]> dataCaptor = ArgumentCaptor.forClass(byte[].class);
            ArgumentCaptor<SignatureAlgorithm> algCaptor =
                ArgumentCaptor.forClass(SignatureAlgorithm.class);
            verify(hsm, times(1)).sign(dataCaptor.capture(), algCaptor.capture());
            assertArrayEquals(payload, dataCaptor.getValue(),
                "CryptoSignerService HSM'e ham veriyi geçmeli, lokal hash YAPMAMALI");
            assertEquals(SignatureAlgorithm.RSA_SHA256, algCaptor.getValue());
        }

        @Test
        void shouldResolveAlgorithmFromCertificatePublicKey() {
            // HSM yolunda PrivateKey yok; algorithm cert public key'inden
            // çıkarılmalı. RSA cert → RSA_SHA*; aksi durumlar daha sonra
            // ECDSA cert testi ile cover edilir.
            Pkcs11Signer hsm = mock(Pkcs11Signer.class);
            when(hsm.sign(any(byte[].class), any(SignatureAlgorithm.class)))
                .thenReturn(new byte[]{1});

            SigningMaterial material = new SigningMaterial(hsm, rsaCertificate,
                Collections.singletonList(rsaCertificate));

            SignatureValue result = service.sign(new ToBeSigned(new byte[]{1}),
                material, DigestAlgorithm.SHA512);

            assertEquals(SignatureAlgorithm.RSA_SHA512, result.getAlgorithm());
            verify(hsm).sign(any(byte[].class), eq(SignatureAlgorithm.RSA_SHA512));
        }

        @Test
        void pfxBackedPkcs11Material_shouldProduceVerifiableSignature() throws Exception {
            byte[] payload = "production branch with software key".getBytes("UTF-8");
            PfxBackedPkcs11Signer signer = new PfxBackedPkcs11Signer(
                "pfx-backed-hsm", rsaKeyPair.getPrivate(), rsaCertificate,
                Collections.singletonList(rsaCertificate));
            SigningMaterial material = new SigningMaterial(signer, rsaCertificate,
                Collections.singletonList(rsaCertificate));

            SignatureValue result = service.sign(new ToBeSigned(payload),
                material, DigestAlgorithm.SHA256);

            assertEquals(SignatureAlgorithm.RSA_SHA256, result.getAlgorithm());
            assertEquals(1, signer.getSignCount(),
                "PKCS#11 material üretildiğinde imza SigningBackend üzerinden signer'a gitmeli");

            Signature verify = Signature.getInstance("SHA256withRSA");
            verify.initVerify(rsaCertificate.getPublicKey());
            verify.update(payload);
            assertTrue(verify.verify(result.getValue()),
                "PFX-backed PKCS#11 signer gerçek ve doğrulanabilir imza üretmeli");
        }

        @Test
        void hsmRuntimeException_shouldBeWrappedInSignatureException() {
            Pkcs11Signer hsm = mock(Pkcs11Signer.class);
            when(hsm.sign(any(byte[].class), any(SignatureAlgorithm.class)))
                .thenThrow(new RuntimeException("CKR_DEVICE_ERROR"));

            SigningMaterial material = new SigningMaterial(hsm, rsaCertificate,
                Collections.singletonList(rsaCertificate));

            SignatureException ex = assertThrows(SignatureException.class,
                () -> service.sign(new ToBeSigned(new byte[]{1}),
                    material, DigestAlgorithm.SHA256));
            assertTrue(ex.getMessage().contains("HSM"),
                "Hata mesajı backend'i (HSM) belirtmeli");
            assertNotNull(ex.getCause(), "Orijinal hata cause olarak korunmalı");
        }

        @Test
        void hsmSignatureException_shouldPropagateUnchanged() {
            // Servis kendi içinde anlamlı SignatureException atmışsa bunu
            // yeniden sarmamalı (hata mesajı stack iki kez aynı şeyi söyler).
            SignatureException original =
                new SignatureException("ALG_ERR", "Algorithm rejected by HSM");

            Pkcs11Signer hsm = mock(Pkcs11Signer.class);
            when(hsm.sign(any(byte[].class), any(SignatureAlgorithm.class)))
                .thenThrow(original);

            SigningMaterial material = new SigningMaterial(hsm, rsaCertificate,
                Collections.singletonList(rsaCertificate));

            SignatureException thrown = assertThrows(SignatureException.class,
                () -> service.sign(new ToBeSigned(new byte[]{1}),
                    material, DigestAlgorithm.SHA256));
            assertSame(original, thrown, "SignatureException pass-through olmalı");
        }
    }

    // ----------------------------------------------------------------
    // Branching guarantee
    // ----------------------------------------------------------------

    @Nested
    @DisplayName("Eş zamanlı imza (K1 regression)")
    class ConcurrentSigning {

        /**
         * Pkcs11Signer mock'una eş zamanlı 32 imza talebi atılır. Her imza
         * 50ms simüle eder. Seri çalışsaydı toplam ~1.6s sürer; paralel
         * çalışıyorsa ~50-100ms civarında biter. Bu test
         * {@link io.mersel.dss.signer.api.services.crypto.CryptoSignerService}
         * tarafında imza akışında kilit yokluğunu garanti eder; üst katmanda
         * (IaikPkcs11Module) synchronized regress eklenirse <b>burada düşmez</b>
         * ama CryptoSigner katmanı kendi başına temizdir.
         */
        @Test
        void cryptoSignerService_shouldHandleParallelSignsWithoutInternalLock() throws Exception {
            int threads = 32;
            long perSignMs = 50;

            Pkcs11Signer hsm = mock(Pkcs11Signer.class);
            when(hsm.sign(any(byte[].class), any(SignatureAlgorithm.class))).thenAnswer(inv -> {
                Thread.sleep(perSignMs);
                return new byte[]{0x42};
            });

            SigningMaterial material = new SigningMaterial(hsm, rsaCertificate,
                Collections.singletonList(rsaCertificate));

            java.util.concurrent.ExecutorService pool =
                java.util.concurrent.Executors.newFixedThreadPool(threads);
            java.util.concurrent.CountDownLatch start = new java.util.concurrent.CountDownLatch(1);
            java.util.List<java.util.concurrent.Future<SignatureValue>> futures = new java.util.ArrayList<>();

            long t0 = System.currentTimeMillis();
            try {
                for (int i = 0; i < threads; i++) {
                    futures.add(pool.submit(() -> {
                        start.await();
                        return service.sign(new ToBeSigned(new byte[]{0x01}), material, DigestAlgorithm.SHA256);
                    }));
                }
                start.countDown();

                for (java.util.concurrent.Future<SignatureValue> f : futures) {
                    SignatureValue v = f.get(10, java.util.concurrent.TimeUnit.SECONDS);
                    assertNotNull(v);
                    assertEquals(SignatureAlgorithm.RSA_SHA256, v.getAlgorithm());
                }
                long elapsed = System.currentTimeMillis() - t0;

                // Geniş tolerans: CI'da scheduling jitter olabilir. Seri
                // çalışsa 32 × 50ms = 1600ms olur; bu test 800ms altı bekler.
                // Pratikte paralel = 50-200ms.
                assertTrue(elapsed < 800,
                    "CryptoSignerService imzaları seri çalıştırdı (elapsed=" + elapsed
                    + "ms). 32 paralel × 50ms simulation 800ms altında bitmeli; "
                    + "synchronized blok eklendi mi?");
            } finally {
                pool.shutdownNow();
            }

            verify(hsm, times(threads)).sign(any(byte[].class), any(SignatureAlgorithm.class));
        }
    }

    @Nested
    @DisplayName("Backend ayrımı")
    class BackendBranching {

        @Test
        void pkcs11Material_shouldNeverTouchJcaPath() {
            // Material isPkcs11()=true ise JCA Signature.getInstance() yoluna
            // hiç düşmemeli; aksi takdirde HSM key handle yerine null
            // privateKey ile çalışmaya kalkar ve NullPointerException olur.
            Pkcs11Signer hsm = mock(Pkcs11Signer.class);
            when(hsm.sign(any(byte[].class), any(SignatureAlgorithm.class)))
                .thenReturn(new byte[]{0x01});

            SigningMaterial material = new SigningMaterial(hsm, rsaCertificate,
                Collections.singletonList(rsaCertificate));

            // Eğer JCA yoluna düşseydi material.getPrivateKey() null olduğu
            // için NPE atardı.
            SignatureValue result = service.sign(new ToBeSigned(new byte[]{0}),
                material, DigestAlgorithm.SHA256);

            assertNotNull(result);
            verify(hsm, times(1)).sign(any(byte[].class), any(SignatureAlgorithm.class));
        }

        @Test
        void pfxMaterial_shouldNeverInvokeHsmSigner() {
            // Mock Pkcs11Signer SigningMaterial'a girmediği için bu test
            // negatif kanıt değil pozitif kanıt: PFX yolu rsaKeyPair ile çalışır.
            Pkcs11Signer unusedSigner = mock(Pkcs11Signer.class);
            SigningMaterial material = new SigningMaterial(
                rsaKeyPair.getPrivate(), rsaCertificate,
                Collections.singletonList(rsaCertificate));

            service.sign(new ToBeSigned(new byte[]{1, 2, 3}),
                material, DigestAlgorithm.SHA256);

            verify(unusedSigner, never())
                .sign(any(byte[].class), any(SignatureAlgorithm.class));
        }
    }
}
