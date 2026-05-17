package io.mersel.dss.signer.api.services.keystore.iaik;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import io.mersel.dss.signer.api.e2e.verifier.E2eSigningMaterialFactory;
import io.mersel.dss.signer.api.e2e.verifier.PfxTestKey;
import io.mersel.dss.signer.api.models.SigningContext;
import io.mersel.dss.signer.api.models.SigningMaterial;
import io.mersel.dss.signer.api.services.SigningMaterialFactory;
import io.mersel.dss.signer.api.services.certificate.CertificateChainBuilderService;
import io.mersel.dss.signer.api.services.certificate.CertificateValidatorService;
import io.mersel.dss.signer.api.services.crypto.CryptoSignerService;
import io.mersel.dss.signer.api.services.crypto.SignatureAlgorithmResolverService;
import io.mersel.dss.signer.api.services.keystore.KeyStoreLoaderService;
import io.mersel.dss.signer.api.testsupport.SoftHsm2TestSupport;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.EnumSource.Mode;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * SoftHSM2 ile gerçek PKCS#11 entegrasyon testi (tüm {@link PfxTestKey} anahtarlar).
 *
 * <p>Test, her PFX test anahtarını {@link SoftHsm2TestSupport} aracılığıyla
 * SoftHSM2 token'ına import eder ve canlı ortam HSM yolunda olduğu gibi
 * {@link IaikPkcs11Module} + {@link SigningMaterialFactory#createPkcs11SigningContext}
 * kullanarak imzalama yapar.</p>
 *
 * <h2>Algoritmik kapsam</h2>
 * <ul>
 *   <li>RSA-2048 → {@code CKM_SHA256_RSA_PKCS} → DSS {@code RSA_SHA256}</li>
 *   <li>EC P-384 → {@code CKM_ECDSA + dış SHA-256} → DSS {@code ECDSA_SHA256}.
 *       <b>Bu kol özellikle değerlidir</b>: gerçek HSM raw {@code r||s} çıktısını
 *       {@link Pkcs11EcdsaSignatureEncoder#toDer} aracılığıyla DER SEQUENCE'a
 *       çevirir; JCA verifier (DER SEQUENCE bekliyor) sonucu kabul etmelidir.</li>
 * </ul>
 *
 * <h2>Çalıştırma</h2>
 * <pre>
 *   mvn test -B -Dgroups=pkcs11-integration -DexcludedGroups=
 * </pre>
 *
 * <p>Yerel native araçlar gerektirir: {@code softhsm2-util}, {@code pkcs11-tool},
 * libsofthsm2. Bunlar yoksa testler {@code assumeTrue(false)} ile sessizce
 * atlanır. CI runner'larında {@code apt-get install -y softhsm2 opensc} ile
 * sağlanır.</p>
 *
 * <h2>İzolasyon</h2>
 * <p>Surefire {@code <environmentVariables>} ile JVM seviyesinde
 * {@code SOFTHSM2_CONF} set edilir; subprocess ve JVM JNI aynı config'i
 * paylaşır. Her iterasyon kendi token'ı için {@code --free} ile yeni slot
 * alır; token label parametre değerine göre unique olduğundan koleksiyonel
 * sızıntı olmaz.</p>
 */
@Tag("pkcs11-integration")
class SoftHsm2Pkcs11IntegrationTest {

    private static final String TOKEN_LABEL_PREFIX = "mersel-test-";
    private static final String KEY_LABEL_PREFIX = "mersel-test-key-";
    private static final String SO_PIN = "12345678";
    private static final String USER_PIN = "123456";

    @TempDir
    Path tempDir;

    @ParameterizedTest(name = "[{index}] {0}")
    // Yalnızca pozitif (Status.VALID) PFX'leri SoftHSM'e import et — negatif
    // lifecycle PFX'leri (revoked/expired/suspended) HSM kontratıyla ilgisiz.
    // JUnit 5.8 (Spring Boot 2.7 parent) MATCH_NONE desteklemiyor; EXCLUDE +
    // explicit names ile filtreliyoruz.
    @EnumSource(value = PfxTestKey.class, mode = Mode.EXCLUDE,
            names = {"KAMUSM_REVOKED_RSA2048", "KAMUSM_REVOKED_EC384",
                     "KAMUSM_EXPIRED_RSA2048", "KAMUSM_EXPIRED_EC384",
                     "KAMUSM_SUSPENDED_RSA2048", "KAMUSM_SUSPENDED_EC384"})
    void pfxImportedIntoSoftHsm_shouldSignThroughIaikPkcs11Module(PfxTestKey key) throws Exception {
        try (SoftHsm2TestSupport hsm = SoftHsm2TestSupport.requireOrSkip(tempDir)) {
            String tokenLabel = TOKEN_LABEL_PREFIX + key.name().toLowerCase();
            String keyLabel = KEY_LABEL_PREFIX + key.name().toLowerCase();

            hsm.initToken(tokenLabel, SO_PIN, USER_PIN);
            hsm.importPfx(key, keyLabel);

            IaikPkcs11Module module = hsm.openModule(USER_PIN);
            SigningMaterial pfxMaterial = E2eSigningMaterialFactory.load(key);
            PrivateKey privateKey = pfxMaterial.getPrivateKey();
            String keyAlgorithm = privateKey.getAlgorithm();

            SigningMaterialFactory factory = new SigningMaterialFactory(
                    new KeyStoreLoaderService(),
                    new CertificateChainBuilderService(Collections.emptyList()),
                    new CertificateValidatorService());

            SigningContext context = factory.createPkcs11SigningContext(module, keyLabel, null);
            SigningMaterial material = context.getMaterial();

            assertTrue(material.isPkcs11(),
                    "SoftHSM materyali PKCS#11 arka ucu olarak işaretlenmeli (" + key + ")");
            assertEquals(keyLabel, context.getAlias());
            assertSameCertificate(pfxMaterial.getSigningCertificate(), material.getSigningCertificate());

            byte[] payload = ("SoftHSM2 PKCS#11 integration payload [" + key.name() + "]")
                    .getBytes(StandardCharsets.UTF_8);
            CryptoSignerService crypto = new CryptoSignerService(new SignatureAlgorithmResolverService());
            SignatureValue signatureValue = crypto.sign(
                    new ToBeSigned(payload), material, DigestAlgorithm.SHA256);

            SignatureAlgorithm expectedAlg = expectedSignatureAlgorithm(keyAlgorithm);
            assertEquals(expectedAlg, signatureValue.getAlgorithm(),
                    "Beklenen DSS imza algoritması " + expectedAlg + " olmalı (anahtar tipi: "
                            + keyAlgorithm + ", PFX: " + key + ")");
            assertNotNull(signatureValue.getValue());
            assertTrue(signatureValue.getValue().length > 0);

            String jcaAlg = jcaVerificationAlgorithm(keyAlgorithm);
            Signature verifier = Signature.getInstance(jcaAlg);
            verifier.initVerify(material.getSigningCertificate().getPublicKey());
            verifier.update(payload);
            assertTrue(verifier.verify(signatureValue.getValue()),
                    "SoftHSM2 üzerinden gelen C_Sign çıktısı public key ile doğrulanmalı "
                            + "(alg=" + jcaAlg + ", PFX=" + key + ")");
        }
    }

    /**
     * PFX'teki JCA private key algoritmasına göre, {@link DigestAlgorithm#SHA256}
     * ile birleşince DSS'in üreteceği imza algoritmasını döner.
     *
     * <p>RSA-2048 → {@code RSA_SHA256}, EC P-384 → {@code ECDSA_SHA256}.
     * EC kolu özellikle önemlidir çünkü gerçek HSM'in döndüğü {@code r||s}
     * raw imzanın {@link Pkcs11EcdsaSignatureEncoder#toDer DER SEQUENCE}'a
     * çevrilmesini sınar.</p>
     */
    private static SignatureAlgorithm expectedSignatureAlgorithm(String keyAlgorithm) {
        if ("RSA".equals(keyAlgorithm)) {
            return SignatureAlgorithm.RSA_SHA256;
        }
        if ("EC".equals(keyAlgorithm) || "ECDSA".equals(keyAlgorithm)) {
            return SignatureAlgorithm.ECDSA_SHA256;
        }
        throw new IllegalStateException("Beklenmeyen private key algoritması: " + keyAlgorithm);
    }

    /** JCA {@link Signature#getInstance(String)} için doğrulayıcı algoritma adı. */
    private static String jcaVerificationAlgorithm(String keyAlgorithm) {
        if ("RSA".equals(keyAlgorithm)) {
            return "SHA256withRSA";
        }
        if ("EC".equals(keyAlgorithm) || "ECDSA".equals(keyAlgorithm)) {
            return "SHA256withECDSA";
        }
        throw new IllegalStateException("Beklenmeyen private key algoritması: " + keyAlgorithm);
    }

    private static void assertSameCertificate(X509Certificate expected, X509Certificate actual) {
        assertEquals(expected.getSerialNumber(), actual.getSerialNumber());
        assertEquals(expected.getSubjectX500Principal(), actual.getSubjectX500Principal());
    }

    /**
     * H1: SoftHSM token üzerinde 2 thread paralel sign çağrısı. IAIK
     * PKCS#11 wrapper'ı kendi içinde session pool'u kontrol ediyor;
     * dış servis katmanı {@code signatureSemaphore} ile sınırlandırıyor.
     *
     * <p>Bu test direkt {@link CryptoSignerService} çağırır (semaphore
     * yok). Amaç: alt katman IAIK + SoftHSM2 stack'i {@code C_Login} +
     * {@code C_Sign} çağrılarını eşzamanlı koşulda race condition'sız
     * tamamlıyor mu? İki imza da public key ile doğrulanmalı.</p>
     *
     * <p>RSA-2048 anahtarı seçildi — EC kolu C_Sign'dan sonra ek
     * encoder (raw r||s → DER) gerektirir, bu da paralel test'te ek
     * shared state riski yaratır; izole tutmak için ayrı bir test
     * kapsamı (mevcut parametrize coverage).</p>
     */
    @Test
    void h1_parallelSign_onSameHsmToken_bothSucceed() throws Exception {
        PfxTestKey key = PfxTestKey.KURUM01_RSA2048;

        try (SoftHsm2TestSupport hsm = SoftHsm2TestSupport.requireOrSkip(tempDir)) {
            String tokenLabel = TOKEN_LABEL_PREFIX + "concurrency";
            String keyLabel = KEY_LABEL_PREFIX + "concurrency";

            hsm.initToken(tokenLabel, SO_PIN, USER_PIN);
            hsm.importPfx(key, keyLabel);
            IaikPkcs11Module module = hsm.openModule(USER_PIN);

            SigningMaterialFactory factory = new SigningMaterialFactory(
                    new KeyStoreLoaderService(),
                    new CertificateChainBuilderService(Collections.emptyList()),
                    new CertificateValidatorService());

            SigningContext context = factory.createPkcs11SigningContext(module, keyLabel, null);
            SigningMaterial material = context.getMaterial();

            CryptoSignerService crypto = new CryptoSignerService(
                    new SignatureAlgorithmResolverService());

            int parallel = 2;
            int iterationsPerThread = 3;
            ExecutorService pool = Executors.newFixedThreadPool(parallel);
            CountDownLatch startGate = new CountDownLatch(1);
            AtomicInteger successes = new AtomicInteger(0);
            List<Future<byte[]>> futures = new ArrayList<>();

            try {
                for (int t = 0; t < parallel; t++) {
                    final int threadId = t;
                    futures.add(pool.submit(() -> {
                        startGate.await();
                        byte[] lastSig = null;
                        for (int it = 0; it < iterationsPerThread; it++) {
                            byte[] payload = ("HSM-parallel-thread-" + threadId
                                    + "-iter-" + it).getBytes(StandardCharsets.UTF_8);
                            SignatureValue sig = crypto.sign(
                                    new ToBeSigned(payload), material,
                                    DigestAlgorithm.SHA256);
                            assertNotNull(sig.getValue(),
                                    "Paralel sign sonucu null olmamalı");

                            Signature verifier = Signature.getInstance("SHA256withRSA");
                            verifier.initVerify(material.getSigningCertificate().getPublicKey());
                            verifier.update(payload);
                            assertTrue(verifier.verify(sig.getValue()),
                                    "Paralel HSM sign çıktısı public key ile doğrulanmalı"
                                            + " (thread=" + threadId + ", iter=" + it + ")");
                            successes.incrementAndGet();
                            lastSig = sig.getValue();
                        }
                        return lastSig;
                    }));
                }
                startGate.countDown();
                for (Future<byte[]> future : futures) {
                    future.get(60, TimeUnit.SECONDS);
                }
            } finally {
                pool.shutdownNow();
            }

            assertEquals(parallel * iterationsPerThread, successes.get(),
                    "Tüm paralel HSM imzaları başarıyla tamamlanmalı");
        }
    }
}
