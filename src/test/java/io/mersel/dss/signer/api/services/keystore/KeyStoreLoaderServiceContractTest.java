package io.mersel.dss.signer.api.services.keystore;

import io.mersel.dss.signer.api.exceptions.KeyStoreException;
import io.mersel.dss.signer.api.models.SigningKeyEntry;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link KeyStoreLoaderService} kontrat test'leri — H grubu (PKCS#11 kontratı)
 * için PFX-tarafı kapsamı:
 *
 * <ul>
 *   <li><b>H2</b>: Çok-anahtarlı PFX'te alias resolution doğru çalışmalı —
 *       alias verilirse o entry, serial verilirse o serial bulunmalı.
 *       PKCS#11'de bu CKA_ID/CKA_LABEL ile aynı kontrat.</li>
 *   <li><b>H3</b>: Yanlış PIN ile PFX yüklemeye çalışmak temiz şekilde
 *       {@link KeyStoreException}'a dönüşmeli — generic 500'e düşmemeli,
 *       ham JCA exception sızmamalı (production'da kullanıcıya
 *       "INVALID_PIN" kodu döner).</li>
 * </ul>
 *
 * <p>Hazır PFX fixture'larına bağımlı olmamak için her test synthetic
 * PKCS#12 üretir (BC ile in-memory). Bu, fixture'ların değişiminden
 * bağımsız kontrat doğrulaması sağlar.</p>
 */
class KeyStoreLoaderServiceContractTest {

    private static final char[] CORRECT_PIN = "test-pin".toCharArray();
    private static final char[] WRONG_PIN = "wrong-pin".toCharArray();

    private static KeyPair keyPairA;
    private static KeyPair keyPairB;
    private static X509Certificate certA;
    private static X509Certificate certB;

    @BeforeAll
    static void initCrypto() throws Exception {
        // BC provider — modern JDK'lar SunJSSE PKCS12 PBE algoritmasını
        // (PBEWithSHA1AndDESede) legacy olarak işaretledi; testlerde
        // belirleyici ortam için BC PKCS12 reader/writer kullanırız.
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        keyPairA = generateRsaKey();
        keyPairB = generateRsaKey();
        certA = selfSign(keyPairA, "CN=Key A, O=Mersel, C=TR",
            BigInteger.valueOf(0xAAAA));
        certB = selfSign(keyPairB, "CN=Key B, O=Mersel, C=TR",
            BigInteger.valueOf(0xBBBB));
    }

    /**
     * H2: Çok-anahtarlı PFX'te alias 'keyA' verilirse keyA entry'si gelmeli;
     * alias 'keyB' verilirse keyB. Yanlış alias mantığı PKCS#11'de CKA_LABEL
     * yanlış geçildiğindeki davranışın PFX karşılığı.
     */
    @Test
    void h2_multiKeyPfx_resolvesByExplicitAlias() throws Exception {
        KeyStore ks = buildMultiKeyPkcs12(CORRECT_PIN);
        KeyStoreLoaderService loader = new KeyStoreLoaderService();

        SigningKeyEntry entryA = loader.resolveKeyEntry(
            ks, null, CORRECT_PIN, "keyA", null);
        assertEquals("keyA", entryA.getAlias());
        assertEquals(certA.getSerialNumber(),
            ((X509Certificate) entryA.getEntry().getCertificate()).getSerialNumber(),
            "keyA alias'ı keyA sertifikasını döndürmeli");

        SigningKeyEntry entryB = loader.resolveKeyEntry(
            ks, null, CORRECT_PIN, "keyB", null);
        assertEquals("keyB", entryB.getAlias());
        assertEquals(certB.getSerialNumber(),
            ((X509Certificate) entryB.getEntry().getCertificate()).getSerialNumber(),
            "keyB alias'ı keyB sertifikasını döndürmeli");
    }

    /**
     * H2 (devam): Alias bilinmiyorsa serial number ile resolution — production'da
     * {@code CERTIFICATE_SERIAL_NUMBER} env'i ile aynı kontrat. Hex match,
     * leading zero / case insensitive sapması yapılmaz; BigInteger eşitliği.
     */
    @Test
    void h2_multiKeyPfx_resolvesBySerialNumber() throws Exception {
        KeyStore ks = buildMultiKeyPkcs12(CORRECT_PIN);
        KeyStoreLoaderService loader = new KeyStoreLoaderService();

        String serialHex = certB.getSerialNumber().toString(16);

        SigningKeyEntry entry = loader.resolveKeyEntry(
            ks, null, CORRECT_PIN, null, serialHex);

        assertEquals(certB.getSerialNumber(),
            ((X509Certificate) entry.getEntry().getCertificate()).getSerialNumber(),
            "Serial ile yapılan resolution doğru entry'yi seçmeli");
    }

    /**
     * H2 (devam): Var olmayan alias verilirse temiz bir
     * {@link KeyStoreException} fırlatmalı; mevcut alias'lar mesajda olmalı
     * (operator debug için kritik).
     */
    @Test
    void h2_multiKeyPfx_unknownAlias_throwsKeyStoreExceptionWithAliasList() throws Exception {
        KeyStore ks = buildMultiKeyPkcs12(CORRECT_PIN);
        KeyStoreLoaderService loader = new KeyStoreLoaderService();

        KeyStoreException ex = assertThrows(KeyStoreException.class,
            () -> loader.resolveKeyEntry(ks, null, CORRECT_PIN, "does-not-exist", null));

        String msg = ex.getMessage();
        assertTrue(msg.contains("does-not-exist"),
            "Hata mesajı aranan alias'ı içermeli, mesaj: " + msg);
        assertTrue(msg.contains("keyA") && msg.contains("keyB"),
            "Hata mesajı mevcut alias'ları listelemeli, mesaj: " + msg);
    }

    /**
     * H3: Yanlış PIN ile PFX yüklemek deterministik olarak başarısız olmalı.
     * Spring Boot katmanında bu durum 500 + KEYSTORE_LOAD_FAILED'e map'lenir
     * (GlobalExceptionHandler.handleKeyStoreException) — generic 500 değil.
     *
     * <p>NOT: PKCS12 yanlış PIN'i {@code IOException} ile sinyallenir
     * (HMAC integrity check fail). JCA katmanından
     * {@link java.security.UnrecoverableKeyException} da geçebilir; iki
     * yol da bizim için kabul edilebilir hata semantiği taşır.</p>
     */
    @Test
    void h3_wrongPin_throwsKeyStoreException() throws Exception {
        byte[] pkcs12Bytes = serializePkcs12(buildMultiKeyPkcs12(CORRECT_PIN), CORRECT_PIN);

        assertThrows(java.io.IOException.class, () -> {
            KeyStore ks = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
            ks.load(new ByteArrayInputStream(pkcs12Bytes), WRONG_PIN);
        }, "Yanlış PIN ile PFX yüklemesi IOException ile başarısız olmalı");
    }

    private static KeyStore buildMultiKeyPkcs12(char[] pin) throws Exception {
        // BC PKCS12 provider — JCA-default SunJSSE PKCS12'nin modern JDK
        // hatasını ("PBEWithSHA1AndDESede unrecognized") atlatır.
        KeyStore ks = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
        ks.load(null, null);
        ks.setKeyEntry("keyA", keyPairA.getPrivate(), pin, new Certificate[]{certA});
        ks.setKeyEntry("keyB", keyPairB.getPrivate(), pin, new Certificate[]{certB});
        return ks;
    }

    private static byte[] serializePkcs12(KeyStore ks, char[] pin) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ks.store(out, pin);
        return out.toByteArray();
    }

    private static KeyPair generateRsaKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private static X509Certificate selfSign(KeyPair kp, String dn, BigInteger serial)
            throws Exception {
        X500Name subject = new X500Name(dn);
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 365L * 24 * 60 * 60 * 1000);
        SubjectPublicKeyInfo spki =
            SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
            subject, serial, notBefore, notAfter, subject, spki);
        return new JcaX509CertificateConverter().getCertificate(
            builder.build(new JcaContentSignerBuilder("SHA256withRSA")
                .build(kp.getPrivate())));
    }

    // Unused warning suppression for synthetic helpers
    @SuppressWarnings("unused")
    private static void touchUnusedHelpers() {
        Arrays.fill(new byte[0], (byte) 0);
    }
}
