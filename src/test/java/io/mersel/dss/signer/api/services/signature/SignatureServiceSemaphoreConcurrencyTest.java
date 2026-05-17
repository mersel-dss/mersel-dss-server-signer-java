package io.mersel.dss.signer.api.services.signature;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import io.mersel.dss.signer.api.models.SignResponse;
import io.mersel.dss.signer.api.models.SigningMaterial;
import io.mersel.dss.signer.api.services.crypto.CryptoSignerService;
import io.mersel.dss.signer.api.services.crypto.DigestAlgorithmResolverService;
import io.mersel.dss.signer.api.services.signature.cades.CAdESSignatureService;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Semaphore tabanlı eşzamanlılık kontratı.
 *
 * <p>G grubu (HTTP/API concurrent 50 istek) ve H grubu (PKCS#11 2 paralel)
 * için <b>shared infrastructure</b>: tüm imza servisleri aynı
 * {@code signatureSemaphore} bean'ini paylaşır ve kritik bölgeyi
 * {@code semaphore.acquire() … release()} bloğu ile sarar. Bu test, gerçekten
 * paralel yükle servisin <b>asla</b> permits sayısını aşmadığını doğrular —
 * HSM session pool kullanımının sessizce kırılmasına karşı regression guard.</p>
 *
 * <p>Mock'lar gerçek DSS imzasını taklit eder; semaphore acquire/release
 * sırası, kritik bölgede sleep + atomic counter ile <em>highWaterMark</em>
 * gözlemlenir. {@code Semaphore(2)} altında 50 paralel istek başlasa bile
 * highWaterMark ≤ 2 olmalı.</p>
 */
class SignatureServiceSemaphoreConcurrencyTest {

    private static final int PERMITS = 2;
    private static final int PARALLEL_REQUESTS = 50;
    private static final long WORK_DELAY_MS = 20;

    private static KeyPair testKeyPair;
    private static X509Certificate testCertificate;

    @BeforeAll
    static void initCrypto() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        testKeyPair = kpg.generateKeyPair();

        X500Name subject = new X500Name("CN=Concurrency Test, O=Mersel, C=TR");
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 365L * 24 * 60 * 60 * 1000);
        SubjectPublicKeyInfo spki =
            SubjectPublicKeyInfo.getInstance(testKeyPair.getPublic().getEncoded());

        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
            subject, BigInteger.valueOf(System.currentTimeMillis()),
            notBefore, notAfter, subject, spki);

        testCertificate = new JcaX509CertificateConverter().getCertificate(
            certBuilder.build(new JcaContentSignerBuilder("SHA256withRSA")
                .build(testKeyPair.getPrivate())));
    }

    /**
     * G+H ana kontrat: 50 paralel istek, Semaphore(2). Hiçbir an
     * eşzamanlı icra sayısı 2'yi geçmemeli. Tüm istekler başarıyla
     * tamamlanmalı; permits sızıntısı olmamalı.
     */
    @Test
    void parallel50Requests_neverExceedSemaphorePermits() throws Exception {
        AtomicInteger concurrentActive = new AtomicInteger(0);
        AtomicInteger highWaterMark = new AtomicInteger(0);
        AtomicInteger totalCompleted = new AtomicInteger(0);

        // Mock DSS service — kritik bölgenin (acquire-release arası) içinde
        // çalışır. Sleep + atomic counter ile yüksek su seviyesi izlenir.
        CAdESService dssService = mock(CAdESService.class);
        when(dssService.getDataToSign(any(DSSDocument.class), any(CAdESSignatureParameters.class)))
            .thenAnswer(invocation -> {
                int active = concurrentActive.incrementAndGet();
                highWaterMark.updateAndGet(prev -> Math.max(prev, active));
                Thread.sleep(WORK_DELAY_MS);
                concurrentActive.decrementAndGet();
                return new ToBeSigned(new byte[]{1, 2, 3});
            });

        CryptoSignerService cryptoSigner = mock(CryptoSignerService.class);
        when(cryptoSigner.sign(any(ToBeSigned.class), any(SigningMaterial.class),
            any(DigestAlgorithm.class)))
            .thenReturn(new SignatureValue(SignatureAlgorithm.RSA_SHA256, new byte[]{9, 9, 9}));

        when(dssService.signDocument(any(DSSDocument.class),
            any(CAdESSignatureParameters.class), any(SignatureValue.class)))
            .thenReturn(new InMemoryDocument("signed".getBytes(), "out.p7s"));

        DigestAlgorithmResolverService digestResolver = mock(DigestAlgorithmResolverService.class);
        when(digestResolver.resolveDigestAlgorithm(any(X509Certificate.class)))
            .thenReturn(DigestAlgorithm.SHA256);

        Semaphore semaphore = new Semaphore(PERMITS);
        CAdESSignatureService service = new CAdESSignatureService(
            dssService, cryptoSigner, digestResolver, semaphore);

        SigningMaterial material = new SigningMaterial(
            testKeyPair.getPrivate(),
            testCertificate,
            Collections.singletonList(testCertificate));

        ExecutorService pool = Executors.newFixedThreadPool(PARALLEL_REQUESTS);
        CountDownLatch startGate = new CountDownLatch(1);
        List<Future<?>> futures = new ArrayList<>(PARALLEL_REQUESTS);

        try {
            for (int i = 0; i < PARALLEL_REQUESTS; i++) {
                futures.add(pool.submit(() -> {
                    startGate.await();
                    SignResponse response = service.signData(
                        new ByteArrayInputStream("payload".getBytes()), false, material);
                    if (response != null) {
                        totalCompleted.incrementAndGet();
                    }
                    return null;
                }));
            }
            startGate.countDown();

            for (Future<?> future : futures) {
                future.get(30, TimeUnit.SECONDS);
            }
        } finally {
            pool.shutdownNow();
        }

        assertEquals(PARALLEL_REQUESTS, totalCompleted.get(),
            "Tüm istekler başarıyla tamamlanmalı");
        assertTrue(highWaterMark.get() <= PERMITS,
            "Eşzamanlı active sayısı asla permits limitini geçmemeli. "
                + "Gözlemlenen tepe: " + highWaterMark.get()
                + ", limit: " + PERMITS);
        assertEquals(PERMITS, semaphore.availablePermits(),
            "Permits sızıntısı olmamalı — tüm acquire'lar release ile dengelenmiş olmalı");
    }

    /**
     * Sentinel: highWaterMark gerçekten ≥1 olarak gözlemlenmeli — paralel
     * koşumun gerçekleştiğini doğrular. Aksi takdirde bir önceki test'in
     * "≤2" assertion'ı pasif geçer.
     */
    @Test
    void parallelExecution_actuallyOccurs_highWaterMarkGreaterThanOne() throws Exception {
        AtomicInteger concurrentActive = new AtomicInteger(0);
        AtomicInteger highWaterMark = new AtomicInteger(0);

        CAdESService dssService = mock(CAdESService.class);
        when(dssService.getDataToSign(any(DSSDocument.class), any(CAdESSignatureParameters.class)))
            .thenAnswer(invocation -> {
                int active = concurrentActive.incrementAndGet();
                highWaterMark.updateAndGet(prev -> Math.max(prev, active));
                Thread.sleep(WORK_DELAY_MS * 2);
                concurrentActive.decrementAndGet();
                return new ToBeSigned(new byte[]{1});
            });

        CryptoSignerService cryptoSigner = mock(CryptoSignerService.class);
        when(cryptoSigner.sign(any(ToBeSigned.class), any(SigningMaterial.class),
            any(DigestAlgorithm.class)))
            .thenReturn(new SignatureValue(SignatureAlgorithm.RSA_SHA256, new byte[]{1}));
        when(dssService.signDocument(any(), any(), any()))
            .thenReturn(new InMemoryDocument(new byte[]{1}, "s.p7s"));

        DigestAlgorithmResolverService digestResolver = mock(DigestAlgorithmResolverService.class);
        when(digestResolver.resolveDigestAlgorithm(any(X509Certificate.class)))
            .thenReturn(DigestAlgorithm.SHA256);

        Semaphore semaphore = new Semaphore(PERMITS);
        CAdESSignatureService service = new CAdESSignatureService(
            dssService, cryptoSigner, digestResolver, semaphore);

        SigningMaterial material = new SigningMaterial(
            testKeyPair.getPrivate(), testCertificate,
            Collections.singletonList(testCertificate));

        ExecutorService pool = Executors.newFixedThreadPool(4);
        CountDownLatch startGate = new CountDownLatch(1);
        List<Future<?>> futures = new ArrayList<>(4);

        try {
            for (int i = 0; i < 4; i++) {
                futures.add(pool.submit(() -> {
                    startGate.await();
                    service.signData(
                        new ByteArrayInputStream("payload".getBytes()), false, material);
                    return null;
                }));
            }
            startGate.countDown();
            for (Future<?> future : futures) {
                future.get(30, TimeUnit.SECONDS);
            }
        } finally {
            pool.shutdownNow();
        }

        assertTrue(highWaterMark.get() >= 2,
            "Paralel koşum gerçekleşmedi — sentinel başarısız. Gözlemlenen: " + highWaterMark.get());
    }

    /**
     * Birden fazla servis aynı semaphore bean'ini paylaşırsa permits'ler
     * <b>cross-service</b> kısıtlamalı. Bu, prod'da PAdES + CAdES + XAdES
     * + WSS servislerinin signatureSemaphore bean'i ile aynı HSM session
     * havuzunu paylaşması demek. Test: tek bir semaphore'u iki ayrı service
     * instance'ına inject et, paralel başlat → toplam active hâlâ ≤ permits.
     *
     * <p>NOTE: Bu davranış cross-service bean sharing kontratının özüdür;
     * sessizce ayrı semaphore'a dönüş regression olur.</p>
     */
    @Test
    void semaphoreSharedAcrossServices_globallyLimitsConcurrency() throws Exception {
        AtomicInteger concurrentActive = new AtomicInteger(0);
        AtomicInteger highWaterMark = new AtomicInteger(0);
        Semaphore shared = new Semaphore(PERMITS);

        CAdESSignatureService serviceA = buildServiceWithSharedSemaphore(
            shared, concurrentActive, highWaterMark);
        CAdESSignatureService serviceB = buildServiceWithSharedSemaphore(
            shared, concurrentActive, highWaterMark);

        SigningMaterial material = new SigningMaterial(
            testKeyPair.getPrivate(), testCertificate,
            Collections.singletonList(testCertificate));

        ExecutorService pool = Executors.newFixedThreadPool(10);
        CountDownLatch startGate = new CountDownLatch(1);
        List<Future<?>> futures = new ArrayList<>(10);

        try {
            for (int i = 0; i < 10; i++) {
                final CAdESSignatureService target = (i % 2 == 0) ? serviceA : serviceB;
                futures.add(pool.submit(() -> {
                    startGate.await();
                    target.signData(
                        new ByteArrayInputStream("payload".getBytes()), false, material);
                    return null;
                }));
            }
            startGate.countDown();
            for (Future<?> future : futures) {
                future.get(30, TimeUnit.SECONDS);
            }
        } finally {
            pool.shutdownNow();
        }

        assertTrue(highWaterMark.get() <= PERMITS,
            "Cross-service semaphore sharing bozuk — observed peak: " + highWaterMark.get());
    }

    private CAdESSignatureService buildServiceWithSharedSemaphore(
            Semaphore shared, AtomicInteger active, AtomicInteger highWaterMark) {
        CAdESService dssService = mock(CAdESService.class);
        when(dssService.getDataToSign(any(DSSDocument.class), any(CAdESSignatureParameters.class)))
            .thenAnswer(invocation -> {
                int curr = active.incrementAndGet();
                highWaterMark.updateAndGet(prev -> Math.max(prev, curr));
                Thread.sleep(WORK_DELAY_MS);
                active.decrementAndGet();
                return new ToBeSigned(new byte[]{1});
            });
        CryptoSignerService cryptoSigner = mock(CryptoSignerService.class);
        try {
            when(cryptoSigner.sign(any(ToBeSigned.class), any(SigningMaterial.class),
                any(DigestAlgorithm.class)))
                .thenReturn(new SignatureValue(SignatureAlgorithm.RSA_SHA256, new byte[]{1}));
        } catch (Exception ignored) {
            // Mockito.when ile thenReturn — Exception fırlatmıyor
        }
        when(dssService.signDocument(any(), any(), any()))
            .thenReturn(new InMemoryDocument(new byte[]{1}, "s.p7s"));
        DigestAlgorithmResolverService digestResolver = mock(DigestAlgorithmResolverService.class);
        when(digestResolver.resolveDigestAlgorithm(any(X509Certificate.class)))
            .thenReturn(DigestAlgorithm.SHA256);

        return new CAdESSignatureService(dssService, cryptoSigner, digestResolver, shared);
    }
}
