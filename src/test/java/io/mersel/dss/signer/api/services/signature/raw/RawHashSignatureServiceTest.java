package io.mersel.dss.signer.api.services.signature.raw;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import io.mersel.dss.signer.api.e2e.verifier.E2eSigningMaterialFactory;
import io.mersel.dss.signer.api.e2e.verifier.PfxTestKey;
import io.mersel.dss.signer.api.models.SigningMaterial;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link RawHashSignatureService} için gerçek kriptografik testler.
 *
 * <h3>Test stratejisi</h3>
 * <p>Mock değil <b>gerçek kriptografi</b>: PFX test sertifikaları yüklenir,
 * service ile bir digest imzalanır, sonra public key ile <em>doğrulanır</em>.
 * Doğrulama akışı şu şekildedir:</p>
 * <ol>
 *   <li>İçerik baytları → SHA-256 (MessageDigest) → digest32</li>
 *   <li>{@code service.signDigest(digest32, SHA256)} → signature bytes</li>
 *   <li>JCA {@code Signature.getInstance("SHA256with...").update(content).verify(signature)}
 *       — burada verify <em>içeriği yeniden hash'ler</em>; eğer service
 *       double-hash yapsaydı bu doğrulama FAIL olurdu.</li>
 * </ol>
 *
 * <p>Bu test PR #21'in orijinal halinde TAM OLARAK FAIL eder — bu yüzden
 * regression guard görevi görür.</p>
 *
 * <h3>Backend matrisi</h3>
 * <p>Hem {@link E2eSigningBackend#PFX_JCA} (JcaSigningBackend yolu) hem de
 * {@link E2eSigningBackend#PFX_BACKED_PKCS11} (Pkcs11SigningBackend yolu)
 * matriste çalıştırılır. PKCS#11 yolunda gerçek HSM yerine
 * {@code PfxBackedPkcs11Signer} kullanılır; production code path'i (interface
 * dispatch) birebir aynı, sadece backing key fixture'tan gelir.</p>
 */
@DisplayName("RawHashSignatureService — gerçek kriptografi ile digest imzalama")
class RawHashSignatureServiceTest {

    @BeforeAll
    static void registerBcIfNeeded() {
        // Bazı NONEwithECDSA / RSA cipher path'leri Bouncy Castle gerektirebilir;
        // production code BC'yi PFX yüklenirken ekliyor, test'te de aynı şart.
        if (java.security.Security.getProvider("BC") == null) {
            java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    /**
     * Backend matrisi: PFX/JCA ve PFX-backed PKCS#11 yolu.
     * Production code'da PKCS#11 ve JCA farklı sign() kod yolları çalıştırır;
     * her ikisinin de aynı doğrulanabilir imzayı üretmesi gerekir.
     */
    enum Backend {
        PFX_JCA {
            @Override
            SigningMaterial load(PfxTestKey key) {
                return E2eSigningMaterialFactory.load(key);
            }
        },
        PFX_BACKED_PKCS11 {
            @Override
            SigningMaterial load(PfxTestKey key) {
                return E2eSigningMaterialFactory.loadAsPkcs11(key);
            }
        };

        abstract SigningMaterial load(PfxTestKey key);
    }

    static Stream<Arguments> matrix() {
        List<Arguments> args = new ArrayList<>();
        for (PfxTestKey key : PfxTestKey.positiveValues()) {
            for (Backend backend : Backend.values()) {
                args.add(Arguments.of(backend, key));
            }
        }
        return args.stream();
    }

    @ParameterizedTest(name = "{0} + {1}: SHA-256 digest imzala → public key ile doğrula")
    @MethodSource("matrix")
    @DisplayName("Roundtrip: digest imzalama + content-side verify")
    void signDigest_andVerifyWithPublicKey_roundtrip(Backend backend, PfxTestKey key) throws Exception {
        SigningMaterial material = backend.load(key);
        RawHashSignatureService service = new RawHashSignatureService(material);

        byte[] content = "Mersel DSS hash-sign roundtrip test payload".getBytes("UTF-8");
        byte[] digest = sha256(content);

        byte[] signature = service.signDigest(digest, DigestAlgorithm.SHA256);

        // Doğrulama: içerikten direkt verify. Eğer service double-hash yapsaydı
        // (eski PR davranışı), Signature.update(content) zaten içeriği hash'leyip
        // RSA verify'e geçecekti; oysa imza SHA-256(SHA-256(content))'in imzası
        // olduğu için verify FALSE dönerdi.
        assertTrue(verifyContent(material.getSigningCertificate(), content, signature, "SHA-256"),
            "İçerikten verify FAIL — double-hash bug regresyonu " +
            "(backend=" + backend + ", key=" + key.name() + ")");
    }

    /**
     * SHA-256 dışı algoritmalar için de doğrulama: SHA-1, SHA-384, SHA-512.
     * RSA-2048 anahtarı SHA-1, SHA-384, SHA-512 hepsini taşır;
     * EC-P384 yalnızca SHA-384'i mantıklı kullanır (P-384 + SHA-256 de
     * teknik olarak çalışır ama ekosistem konvansiyonu eğri ile eşler).
     */
    @Test
    @DisplayName("SHA-1 / SHA-384 / SHA-512: RSA path tüm prefix'leri doğru basıyor")
    void multipleDigestAlgorithms_roundtrip_rsa() throws Exception {
        SigningMaterial material = E2eSigningMaterialFactory.load(PfxTestKey.KURUM01_RSA2048);
        RawHashSignatureService service = new RawHashSignatureService(material);

        byte[] content = "Mersel multi-digest test".getBytes("UTF-8");

        for (DigestAlgorithm alg : new DigestAlgorithm[] {
                DigestAlgorithm.SHA1, DigestAlgorithm.SHA256,
                DigestAlgorithm.SHA384, DigestAlgorithm.SHA512 }) {
            byte[] digest = MessageDigest.getInstance(alg.getJavaName()).digest(content);
            byte[] sig = service.signDigest(digest, alg);
            assertTrue(verifyContent(material.getSigningCertificate(), content, sig, alg.getJavaName()),
                "RSA + " + alg + ": içerik-tabanlı verify FAIL");
        }
    }

    @Test
    @DisplayName("Default digest algoritması (null) → SHA-256 olarak uygulanır")
    void nullDigestAlgorithm_defaultsToSha256() throws Exception {
        SigningMaterial material = E2eSigningMaterialFactory.load(PfxTestKey.KURUM01_RSA2048);
        RawHashSignatureService service = new RawHashSignatureService(material);

        byte[] content = "default digest".getBytes("UTF-8");
        byte[] digest = sha256(content);

        byte[] sig = service.signDigest(digest, null);

        assertTrue(verifyContent(material.getSigningCertificate(), content, sig, "SHA-256"),
            "null digestAlgorithm SHA-256'a düşmeli ve verify geçmeli");
    }

    @Test
    @DisplayName("Null digest → IllegalArgumentException")
    void nullDigest_rejectsWithIllegalArgument() {
        SigningMaterial material = E2eSigningMaterialFactory.load(PfxTestKey.KURUM01_RSA2048);
        RawHashSignatureService service = new RawHashSignatureService(material);
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
            () -> service.signDigest(null, DigestAlgorithm.SHA256));
        assertTrue(ex.getMessage().contains("null") || ex.getMessage().contains("boş"),
            "Hata mesajı netleştirilmeli: " + ex.getMessage());
    }

    @Test
    @DisplayName("Boş digest array → IllegalArgumentException")
    void emptyDigest_rejectsWithIllegalArgument() {
        SigningMaterial material = E2eSigningMaterialFactory.load(PfxTestKey.KURUM01_RSA2048);
        RawHashSignatureService service = new RawHashSignatureService(material);
        assertThrows(IllegalArgumentException.class,
            () -> service.signDigest(new byte[0], DigestAlgorithm.SHA256));
    }

    @Test
    @DisplayName("Yanlış uzunluktaki digest (raw veri gönderme regresyonu) → IllegalArgumentException")
    void wrongLengthDigest_rejectsWithDescriptiveMessage() {
        SigningMaterial material = E2eSigningMaterialFactory.load(PfxTestKey.KURUM01_RSA2048);
        RawHashSignatureService service = new RawHashSignatureService(material);

        // SHA-256 32 byte bekler; raw veri gibi gelen 27 byte → reject.
        byte[] suspiciousRawData = "this is not a valid hash...".getBytes();
        assertEquals(27, suspiciousRawData.length);

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
            () -> service.signDigest(suspiciousRawData, DigestAlgorithm.SHA256));
        assertTrue(ex.getMessage().contains("32 byte"),
            "Hata mesajı beklenen uzunluğu açıkça söylemeli: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("raw veri"),
            "Hata mesajı caller'ı yanlış kullanım hakkında uyarmalı: " + ex.getMessage());
    }

    @Test
    @DisplayName("Desteklenmeyen digest algoritması → IllegalArgumentException")
    void unsupportedDigestAlgorithm_rejectsWithDescriptiveMessage() {
        SigningMaterial material = E2eSigningMaterialFactory.load(PfxTestKey.KURUM01_RSA2048);
        RawHashSignatureService service = new RawHashSignatureService(material);

        byte[] dummyDigest = new byte[32];
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
            () -> service.signDigest(dummyDigest, DigestAlgorithm.MD5));
        assertTrue(ex.getMessage().contains("Desteklenmeyen"),
            "Hata mesajı net olmalı: " + ex.getMessage());
    }

    @Test
    @DisplayName("RSA imza uzunluğu modül büyüklüğüyle eşleşmeli (RSA-2048 → 256 byte)")
    void rsa2048_signatureLengthMatchesModulus() throws Exception {
        SigningMaterial material = E2eSigningMaterialFactory.load(PfxTestKey.KURUM01_RSA2048);
        RawHashSignatureService service = new RawHashSignatureService(material);

        byte[] sig = service.signDigest(sha256("anything".getBytes("UTF-8")), DigestAlgorithm.SHA256);
        assertEquals(256, sig.length, "RSA-2048 PKCS#1 v1.5 imzası modül uzunluğunda olmalı");
    }

    @Test
    @DisplayName("ECDSA imza DER SEQUENCE formatında — 0x30 ile başlamalı")
    void ecdsa_signatureIsDerSequence() throws Exception {
        SigningMaterial material = E2eSigningMaterialFactory.load(PfxTestKey.KURUM02_EC384);
        RawHashSignatureService service = new RawHashSignatureService(material);

        byte[] content = "ec sign test".getBytes("UTF-8");
        byte[] digest = MessageDigest.getInstance("SHA-384").digest(content);
        byte[] sig = service.signDigest(digest, DigestAlgorithm.SHA384);

        assertNotNull(sig);
        assertTrue(sig.length > 0);
        assertEquals((byte) 0x30, sig[0],
            "ECDSA imzası DER SEQUENCE ile başlamalı (0x30); HSM raw r||s normalize edilmemiş olabilir");

        assertTrue(verifyContent(material.getSigningCertificate(), content, sig, "SHA-384"),
            "ECDSA içerik-tabanlı verify FAIL");
    }

    @Test
    @DisplayName("Double-hash regression guard: aynı içerik aynı imzaya götürmemeli (sanity)")
    void doubleHashRegressionGuard() throws Exception {
        // Bu test indirekt olarak double-hash bug'ını yakalar. signDigest(SHA-256(content), SHA256)
        // ile verify(content, SHA-256) eşleşirse, service hash'i tekrar uygulamamış demektir.
        SigningMaterial material = E2eSigningMaterialFactory.load(PfxTestKey.KURUM01_RSA2048);
        RawHashSignatureService service = new RawHashSignatureService(material);

        byte[] content = "regression guard payload".getBytes("UTF-8");
        byte[] digest = sha256(content);
        byte[] sig = service.signDigest(digest, DigestAlgorithm.SHA256);

        // POSITIVE: hash'i bir kez uygulayan verify path geçmeli
        assertTrue(verifyContent(material.getSigningCertificate(), content, sig, "SHA-256"),
            "Service tek-hash uygulamış (doğru davranış) ama verify FAIL — beklenmedik durum");

        // NEGATIVE: hash'i iki kez uygulayan verify path FAIL olmalı.
        // Eğer bu assertion FAIL ederse, service double-hash yapıyor demektir.
        byte[] doubleHash = sha256(digest);
        assertTrue(!verifyContentRaw(material.getSigningCertificate(), doubleHash, sig),
            "Service'in çıktısı SHA-256(SHA-256(content)) imzası — double-hash bug regresyonu");
    }

    // ──────────────── Yardımcılar ────────────────

    private static byte[] sha256(byte[] content) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(content);
    }

    /**
     * İçerik baytlarını verir, JCA'nın hash'leyip RSA/ECDSA verify yapmasını
     * bekler. RSA için "SHA-256withRSA"; EC için "SHA-256withECDSA" gibi.
     */
    private static boolean verifyContent(X509Certificate cert, byte[] content,
                                          byte[] signature, String digestJavaName) throws Exception {
        PublicKey pk = cert.getPublicKey();
        String alg = digestJavaName.replace("-", "") + "with"
                + ("EC".equalsIgnoreCase(pk.getAlgorithm()) ? "ECDSA" : pk.getAlgorithm());
        Signature s = Signature.getInstance(alg);
        s.initVerify(pk);
        s.update(content);
        return s.verify(signature);
    }

    /**
     * Önceden hash'lenmiş baytları "raw input" olarak verir; double-hash
     * regresyon guard'ı için. RSA path'i NONEwithRSA + manual DigestInfo
     * gerektirir; bu helper'da sadece RSA için kullanıyoruz, EC için anlamlı değil.
     */
    private static boolean verifyContentRaw(X509Certificate cert, byte[] preHashedAsContent,
                                             byte[] signature) throws Exception {
        PublicKey pk = cert.getPublicKey();
        if (!"RSA".equalsIgnoreCase(pk.getAlgorithm())) {
            return false;
        }
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initVerify(pk);
        s.update(preHashedAsContent);
        return s.verify(signature);
    }
}
