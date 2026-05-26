package io.mersel.dss.signer.api.services.keystore.iaik;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import io.mersel.dss.signer.api.e2e.verifier.E2eSigningMaterialFactory;
import io.mersel.dss.signer.api.e2e.verifier.PfxTestKey;
import io.mersel.dss.signer.api.models.SigningContext;
import io.mersel.dss.signer.api.models.SigningMaterial;
import io.mersel.dss.signer.api.services.SigningMaterialFactory;
import io.mersel.dss.signer.api.services.certificate.CertificateChainBuilderService;
import io.mersel.dss.signer.api.services.certificate.CertificateValidatorService;
import io.mersel.dss.signer.api.services.keystore.KeyStoreLoaderService;
import io.mersel.dss.signer.api.services.signature.raw.RawHashSignatureService;
import io.mersel.dss.signer.api.testsupport.SoftHsm2TestSupport;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Severity;
import io.qameta.allure.SeverityLevel;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.EnumSource.Mode;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Gerçek SoftHSM2 token üzerinde {@code v1/hashsign} kod yolunun (pre-hashed
 * digest imzalama) entegrasyon testi.
 *
 * <h2>Kapsanan production kod yolu</h2>
 * <ul>
 *   <li>{@link RawHashSignatureService#signDigest} → service katmanı validation
 *       + audit log</li>
 *   <li>{@link io.mersel.dss.signer.api.models.Pkcs11SigningBackend#signDigest}
 *       → backend dispatch</li>
 *   <li>{@link IaikPkcs11Signer#signDigest} → cert'ten {@code EncryptionAlgorithm}
 *       resolution</li>
 *   <li>{@link IaikPkcs11Module#signOnSessionRawDigest} → raw mekanizma yolu:
 *       <ul>
 *         <li><b>RSA</b>: {@link Pkcs1DigestInfo#wrap} ile DigestInfo prefix +
 *             {@code CKM_RSA_PKCS} mekanizması</li>
 *         <li><b>ECDSA</b>: raw digest + {@code CKM_ECDSA} mekanizması +
 *             {@code Pkcs11EcdsaSignatureEncoder.normalizeToDer}</li>
 *       </ul>
 *   </li>
 * </ul>
 *
 * <p>Bu kod yolu {@code RawHashSignatureServiceTest}'in PFX-backed
 * {@code Pkcs11Signer} fixture'ında <em>kapsanmıyordu</em>; test fixture
 * interface'i implement ediyor ama gerçek IAIK + libsofthsm2 stack'ini
 * çalıştırmıyor. Bu test gerçek HSM driver'ında doğrulamayı garantiliyor.</p>
 *
 * <h2>Double-hash regression guard</h2>
 * <p>Her iterasyon iki yönlü kontrol yapar:</p>
 * <ol>
 *   <li><b>Pozitif</b>: Service çıktısı, içerikten bir kez hash uygulanan
 *       {@code Signature.verify(content)} ile doğrulanmalı (geçer).</li>
 *   <li><b>Negatif</b>: Service çıktısı, içerikten iki kez hash uygulanan
 *       senaryoya UYMAMALI. Eğer uyarsa service double-hash yapıyor
 *       (regresyon).</li>
 * </ol>
 *
 * <h2>Çalıştırma</h2>
 * <pre>
 *   mvn test -B -Dgroups=pkcs11-integration -DexcludedGroups=
 * </pre>
 *
 * <p>Native bağımlılıklar yoksa testler {@code assumeTrue(false)} ile sessizce
 * atlanır; CI runner'larında {@code apt-get install -y softhsm2 opensc} ile
 * sağlanır. Mevcut {@code pkcs11-integration-tests.yml} workflow'una bu sınıfın
 * eklenmesi otomatiktir (workflow surefire pattern bazlı çalışır).</p>
 */
@Tag("pkcs11-integration")
@Epic("PKCS#11 Integration")
@Feature("SoftHSM2 — Pre-hashed Digest Signing")
@Severity(SeverityLevel.CRITICAL)
class HashSignSoftHsm2IntegrationTest {

    // SoftHSM2 token label MAX 32 karakter; key label limiti yok ama tutarlılık
    // için aynı kısaltma mantığını uyguluyoruz.
    private static final String TOKEN_LABEL_PREFIX = "hs-";
    private static final String KEY_LABEL_PREFIX = "hs-key-";
    private static final String VALIDATION_TOKEN_LABEL_PREFIX = "hs-val-";
    private static final String VALIDATION_KEY_LABEL_PREFIX = "hs-val-key-";
    private static final String SO_PIN = "12345678";
    private static final String USER_PIN = "123456";

    @TempDir
    Path tempDir;

    /**
     * RSA-2048 ve EC P-384 PFX anahtarlarının hepsi için: SoftHSM'e import
     * et, RawHashSignatureService üzerinden gerçek HSM kod yolunda imzala,
     * çıktıyı public key ile doğrula, double-hash regression guard'ı çalıştır.
     */
    @ParameterizedTest(name = "[{index}] {0} — pre-hashed digest sign + verify")
    @EnumSource(value = PfxTestKey.class, mode = Mode.EXCLUDE,
            names = {"KAMUSM_REVOKED_RSA2048", "KAMUSM_REVOKED_EC384",
                     "KAMUSM_EXPIRED_RSA2048", "KAMUSM_EXPIRED_EC384",
                     "KAMUSM_SUSPENDED_RSA2048", "KAMUSM_SUSPENDED_EC384"})
    void hashSign_throughRealSoftHsmStack_roundtrip(PfxTestKey key) throws Exception {
        try (SoftHsm2TestSupport hsm = SoftHsm2TestSupport.requireOrSkip(tempDir)) {
            String tokenLabel = TOKEN_LABEL_PREFIX + key.name().toLowerCase();
            String keyLabel = KEY_LABEL_PREFIX + key.name().toLowerCase();

            hsm.initToken(tokenLabel, SO_PIN, USER_PIN);
            hsm.importPfx(key, keyLabel);

            IaikPkcs11Module module = hsm.openModule(USER_PIN);
            SigningMaterialFactory factory = new SigningMaterialFactory(
                    new KeyStoreLoaderService(),
                    new CertificateChainBuilderService(Collections.emptyList()),
                    new CertificateValidatorService());
            SigningContext context = factory.createPkcs11SigningContext(module, keyLabel, null);
            SigningMaterial material = context.getMaterial();

            assertTrue(material.isPkcs11(),
                    "SoftHSM materyali PKCS#11 backend olarak işaretlenmeli (key=" + key + ")");

            // Service tam production yolunu çalıştırır:
            // RawHashSignatureService → SigningMaterial → Pkcs11SigningBackend
            //   → IaikPkcs11Signer → IaikPkcs11Module.signOnSessionRawDigest
            //   → token.sign(CKM_RSA_PKCS / CKM_ECDSA) → libsofthsm2
            RawHashSignatureService service = new RawHashSignatureService(material);

            byte[] payload = ("Mersel hashsign HSM integration [" + key.name() + "]")
                    .getBytes(StandardCharsets.UTF_8);
            DigestAlgorithm digestAlg = preferredDigestForKey(key);
            byte[] digest = MessageDigest.getInstance(digestAlg.getJavaName()).digest(payload);

            byte[] signature = service.signDigest(digest, digestAlg);

            assertNotNull(signature);
            assertTrue(signature.length > 0);
            assertSignatureFormat(material.getSigningCertificate().getPublicKey(),
                    signature, key);

            // Pozitif: içerikten bir kez hash uygulanan verify YOLU geçmeli.
            String jcaAlg = jcaVerifyAlgorithm(material.getSigningCertificate().getPublicKey(),
                    digestAlg);
            assertTrue(verifyContent(material.getSigningCertificate(), payload, signature, jcaAlg),
                    "Gerçek HSM hashsign çıktısı public key ile doğrulanmalı "
                            + "(alg=" + jcaAlg + ", key=" + key + ")");

            // Negatif (double-hash regression guard): RSA için yalnızca anlamlı.
            // Eğer service double-hash yapsaydı, ürettiği imza
            // SHA-256(SHA-256(payload)) = SHA-256(digest) ile verify(digest)
            // edildiğinde geçerdi. Geçmemesi gerek.
            if ("RSA".equalsIgnoreCase(material.getSigningCertificate().getPublicKey().getAlgorithm())
                    && digestAlg == DigestAlgorithm.SHA256) {
                assertFalse(verifyContent(material.getSigningCertificate(), digest, signature,
                                "SHA256withRSA"),
                        "Service çıktısı SHA-256(SHA-256(payload)) imzasıyla eşleşmemeli "
                                + "(double-hash regresyonu — gerçek HSM yolunda); key=" + key);
            }
        }
    }

    /**
     * Validation katmanının HSM yolunda da çalıştığını doğrular: yanlış uzunluk
     * digest, kod controller'a kadar dönmeden service'te erkenden reddedilmeli;
     * HSM'e fakir bir C_Sign çağrısı atılmamalı (boşa kaynak).
     */
    @ParameterizedTest(name = "[{index}] {0} — validation HSM yoluna sızmamalı")
    @EnumSource(value = PfxTestKey.class, mode = Mode.INCLUDE,
            names = {"KURUM01_RSA2048", "KURUM02_EC384"})
    void wrongLengthDigest_rejectedAtServiceLayer_beforeHsmCall(PfxTestKey key) throws Exception {
        try (SoftHsm2TestSupport hsm = SoftHsm2TestSupport.requireOrSkip(tempDir)) {
            String tokenLabel = VALIDATION_TOKEN_LABEL_PREFIX + key.name().toLowerCase();
            String keyLabel = VALIDATION_KEY_LABEL_PREFIX + key.name().toLowerCase();

            hsm.initToken(tokenLabel, SO_PIN, USER_PIN);
            hsm.importPfx(key, keyLabel);

            IaikPkcs11Module module = hsm.openModule(USER_PIN);
            SigningMaterialFactory factory = new SigningMaterialFactory(
                    new KeyStoreLoaderService(),
                    new CertificateChainBuilderService(Collections.emptyList()),
                    new CertificateValidatorService());
            SigningContext context = factory.createPkcs11SigningContext(module, keyLabel, null);
            SigningMaterial material = context.getMaterial();
            RawHashSignatureService service = new RawHashSignatureService(material);

            // SHA-256 32 byte ister; 27 byte gönder → service reddetmeli.
            byte[] suspiciousRaw = "this is not a valid hash...".getBytes(StandardCharsets.UTF_8);
            assertEquals(27, suspiciousRaw.length);

            IllegalArgumentException ex = org.junit.jupiter.api.Assertions.assertThrows(
                    IllegalArgumentException.class,
                    () -> service.signDigest(suspiciousRaw, DigestAlgorithm.SHA256),
                    "Service yanlış uzunluk digest'i HSM çağrısı YAPMADAN reddetmeli");
            assertTrue(ex.getMessage().contains("32 byte"),
                    "Hata mesajı beklenen uzunluğu açıklamalı: " + ex.getMessage());
        }
    }

    // ──────────────── Yardımcılar ────────────────

    /**
     * RSA için SHA-256 (e-Defter konvansiyonu, KamuSM RSA-2048 ekosistem
     * default'u). EC P-384 için SHA-384 (NIST SP 800-57 eğri-digest eşlemesi).
     */
    private static DigestAlgorithm preferredDigestForKey(PfxTestKey key) {
        if (key.name().contains("EC384")) {
            return DigestAlgorithm.SHA384;
        }
        return DigestAlgorithm.SHA256;
    }

    private static String jcaVerifyAlgorithm(PublicKey publicKey, DigestAlgorithm digestAlg) {
        String prefix = digestAlg.getJavaName().replace("-", "");
        if ("EC".equalsIgnoreCase(publicKey.getAlgorithm())) {
            return prefix + "withECDSA";
        }
        return prefix + "withRSA";
    }

    /**
     * Format kontratı: RSA imzası modül uzunluğunda; ECDSA imzası DER SEQUENCE
     * (0x30 ile başlamalı). HSM raw r||s döndürürse normalize katmanı çalışmamış
     * demektir → test fail eder.
     */
    private static void assertSignatureFormat(PublicKey publicKey, byte[] signature, PfxTestKey key) {
        if ("RSA".equalsIgnoreCase(publicKey.getAlgorithm())) {
            assertEquals(256, signature.length,
                    "RSA-2048 PKCS#1 v1.5 imzası 256 byte olmalı (key=" + key + ")");
        } else {
            assertEquals((byte) 0x30, signature[0],
                    "ECDSA imzası DER SEQUENCE (0x30) ile başlamalı — raw r||s normalize "
                            + "edilmemiş olabilir (key=" + key + ")");
        }
    }

    private static boolean verifyContent(X509Certificate cert, byte[] content,
                                          byte[] signature, String jcaAlg) throws Exception {
        Signature s = Signature.getInstance(jcaAlg);
        s.initVerify(cert.getPublicKey());
        s.update(content);
        return s.verify(signature);
    }
}
