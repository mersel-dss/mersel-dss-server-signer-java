package io.mersel.dss.signer.api.services.keystore.iaik;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link Pkcs11EcdsaSignatureEncoder} testleri.
 *
 * <p>Kritik kontrat: PKCS#11 HSM'den dönen raw r||s byte dizisi
 * <b>DER SEQUENCE { r, s }</b> formatına dönüştürülmeli. Bu olmadan
 * EC sertifikalı HSM imzaları (e-Fatura, PAdES, CAdES, XAdES)
 * doğrulayıcılar tarafından reddedilir.</p>
 */
class Pkcs11EcdsaSignatureEncoderTest {

    @Nested
    @DisplayName("toDer: raw r||s → DER SEQUENCE")
    class ToDerHappyPath {

        @Test
        @DisplayName("P-256 sabit uzunluk (64 byte) raw → DER round-trip")
        void p256_rawToDer_roundTrip() throws Exception {
            // r ve s, P-256 için 32 byte. High-bit set olan kasıtlı: ASN.1
            // INTEGER negatif olmasın diye encoder leading 0x00 ekler.
            byte[] r = Hex.decode("FF" + repeatHex("11", 31));
            byte[] s = Hex.decode("80" + repeatHex("22", 31));
            byte[] raw = concat(r, s);

            byte[] der = Pkcs11EcdsaSignatureEncoder.toDer(raw);

            try (ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(der))) {
                ASN1Sequence seq = (ASN1Sequence) in.readObject();
                assertEquals(2, seq.size(), "SEQUENCE iki INTEGER içermeli");

                BigInteger decodedR = ((ASN1Integer) seq.getObjectAt(0)).getValue();
                BigInteger decodedS = ((ASN1Integer) seq.getObjectAt(1)).getValue();

                assertEquals(new BigInteger(1, r), decodedR,
                    "r unsigned olarak geri okunmalı (high-bit set olsa bile pozitif)");
                assertEquals(new BigInteger(1, s), decodedS, "s unsigned olarak geri okunmalı");
            }
        }

        @Test
        @DisplayName("P-384 (96 byte raw → DER)")
        void p384_rawToDer() throws Exception {
            byte[] raw = new byte[96];
            // r: 0x01, 0x02, ... 0x30 (48 byte)
            // s: 0x10, 0x11, ... 0x3F (48 byte)
            for (int i = 0; i < 48; i++) raw[i] = (byte) (0x01 + i);
            for (int i = 0; i < 48; i++) raw[48 + i] = (byte) (0x10 + i);

            byte[] der = Pkcs11EcdsaSignatureEncoder.toDer(raw);

            try (ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(der))) {
                ASN1Sequence seq = (ASN1Sequence) in.readObject();
                BigInteger decodedR = ((ASN1Integer) seq.getObjectAt(0)).getValue();
                BigInteger decodedS = ((ASN1Integer) seq.getObjectAt(1)).getValue();
                assertEquals(new BigInteger(1, Arrays.copyOfRange(raw, 0, 48)), decodedR);
                assertEquals(new BigInteger(1, Arrays.copyOfRange(raw, 48, 96)), decodedS);
            }
        }

        @Test
        @DisplayName("Leading zero r (sıfırla başlayan): unsigned interpretation korunmalı")
        void leadingZeroR_preserved() throws Exception {
            // r'nin ilk byte'ı 0x00 — bu P-256'da pratikte rare ama valid.
            // BigInteger doğru parse etmeli, eklenmiş zero byte yutulmamalı.
            byte[] r = new byte[32];
            r[1] = (byte) 0xAA;
            byte[] s = new byte[32];
            Arrays.fill(s, (byte) 0x55);
            byte[] raw = concat(r, s);

            byte[] der = Pkcs11EcdsaSignatureEncoder.toDer(raw);

            try (ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(der))) {
                ASN1Sequence seq = (ASN1Sequence) in.readObject();
                BigInteger decodedR = ((ASN1Integer) seq.getObjectAt(0)).getValue();
                assertEquals(new BigInteger(1, r), decodedR);
            }
        }

        @Test
        @DisplayName("P-521 (132 byte raw → DER)")
        void p521_rawToDer() throws Exception {
            byte[] raw = new byte[132];
            for (int i = 0; i < 132; i++) raw[i] = (byte) ((i * 7) & 0xFF);

            byte[] der = Pkcs11EcdsaSignatureEncoder.toDer(raw);

            try (ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(der))) {
                ASN1Sequence seq = (ASN1Sequence) in.readObject();
                assertEquals(2, seq.size());
            }
        }
    }

    @Nested
    @DisplayName("toDer: invalid input")
    class ToDerEdge {

        @Test
        @DisplayName("null → IllegalArgumentException")
        void nullInput_rejected() {
            assertThrows(IllegalArgumentException.class,
                () -> Pkcs11EcdsaSignatureEncoder.toDer(null));
        }

        @Test
        @DisplayName("boş array → reddedilir (r||s en az 2 byte)")
        void emptyInput_rejected() {
            assertThrows(IllegalArgumentException.class,
                () -> Pkcs11EcdsaSignatureEncoder.toDer(new byte[0]));
        }

        @Test
        @DisplayName("tek-sayılı uzunluk → reddedilir (r ve s eşit olmalı)")
        void oddLength_rejected() {
            assertThrows(IllegalArgumentException.class,
                () -> Pkcs11EcdsaSignatureEncoder.toDer(new byte[33]));
        }
    }

    @Nested
    @DisplayName("looksLikeDer / normalizeToDer (idempotent)")
    class IdempotentBehavior {

        @Test
        @DisplayName("Zaten DER ise toDer tekrar çağrılmaz (idempotent normalize)")
        void alreadyDer_isPassthrough() throws Exception {
            // Önce raw'dan gerçek bir DER üret, sonra normalize'ı çağır;
            // çıktı aynı olmalı.
            byte[] raw = new byte[64];
            new SecureRandom().nextBytes(raw);
            byte[] der = Pkcs11EcdsaSignatureEncoder.toDer(raw);

            assertTrue(Pkcs11EcdsaSignatureEncoder.looksLikeDer(der),
                "Encoder kendi çıktısı DER olarak algılanmalı");

            byte[] normalized = Pkcs11EcdsaSignatureEncoder.normalizeToDer(der);
            assertArrayEquals(der, normalized,
                "Idempotent: DER input olduğu gibi dönmeli, yeniden sarılmamalı");
        }

        @Test
        @DisplayName("Raw r||s DER gibi görünmez (tag 0x30 değil)")
        void rawDoesNotLookLikeDer() {
            byte[] raw = new byte[64];
            raw[0] = (byte) 0xAB; // 0x30 değil
            assertFalse(Pkcs11EcdsaSignatureEncoder.looksLikeDer(raw));
        }

        @Test
        @DisplayName("normalize: raw input → DER")
        void normalize_rawInput_producesDer() {
            byte[] raw = new byte[64];
            Arrays.fill(raw, (byte) 0x42);
            byte[] der = Pkcs11EcdsaSignatureEncoder.normalizeToDer(raw);
            assertTrue(Pkcs11EcdsaSignatureEncoder.looksLikeDer(der));
        }
    }

    @Nested
    @DisplayName("looksLikeDer: yanlış-pozitif koruması (strict ASN.1 + roundtrip)")
    class FalsePositiveProtection {

        @Test
        @DisplayName("Raw r||s tesadüfen 0x30 ile başlasa bile DER kabul edilmemeli")
        void rawStartingWith0x30_mustNotBeAcceptedAsDer() {
            // Bu test eski (yüzeysel) heuristic'in patladığı vakayı koruyor.
            // İlk byte 0x30 (SEQUENCE tag), ikinci byte uzunluk (64-2=62=0x3E),
            // üçüncü byte 0x02 (INTEGER tag) — yüzeysel kontrol "DER" der.
            // Ama gerçek ASN.1 trial-parse + roundtrip burayı eler.
            byte[] raw = new byte[64];
            raw[0] = 0x30; // SEQUENCE tag
            raw[1] = 0x3E; // length = 62
            raw[2] = 0x02; // INTEGER tag
            raw[3] = 0x20; // length = 32
            // r body 32 byte
            for (int i = 4; i < 36; i++) raw[i] = (byte) (i & 0xFF);
            raw[36] = 0x02; // INTEGER tag
            raw[37] = 0x1C; // length = 28 (ama 36+2+28=66 ≠ 64; veya 0x1A=26 olsun)
            for (int i = 38; i < 64; i++) raw[i] = (byte) (i & 0xFF);

            // Strict heuristic: ya ASN.1 olarak tam tüketmemeli, ya iki
            // INTEGER bulamamalı, ya da roundtrip aynı çıkmamalı.
            assertFalse(Pkcs11EcdsaSignatureEncoder.looksLikeDer(raw),
                "Yüzeysel DER-benzeri prefix yetmemeli; strict trial-parse + DER "
                + "roundtrip kontrolü raw r||s'i DER kabul etmemeli.");
        }

        @Test
        @DisplayName("Rastgele 1000 raw r||s deseni — hiçbiri DER olarak algılanmamalı")
        void manyRandomRawSignatures_neverLookLikeDer() {
            // Fuzz: rastgele raw imzalar üretip strict heuristic'in
            // tutarlı raw değerleri DER olarak algılamadığını doğrula.
            // Eski yüzeysel heuristic burada 1-2 yanlış-pozitif verirdi.
            SecureRandom rnd = new SecureRandom();
            int falsePositives = 0;
            for (int i = 0; i < 1000; i++) {
                byte[] raw = new byte[64]; // P-256
                rnd.nextBytes(raw);
                if (Pkcs11EcdsaSignatureEncoder.looksLikeDer(raw)) {
                    falsePositives++;
                }
            }
            assertEquals(0, falsePositives,
                "Strict heuristic 1000 rastgele raw imza üzerinde "
                + falsePositives + " yanlış-pozitif verdi; trial-parse + "
                + "roundtrip kontrolünü gözden geçirin.");
        }

        @Test
        @DisplayName("Sequence içinde fazla öğe varsa DER olarak kabul edilmemeli")
        void sequenceWithThreeIntegers_rejected() throws Exception {
            // Geçerli ASN.1 SEQUENCE ama 3 INTEGER içeriyor; ECDSA değil.
            // Strict heuristic boyut kontrolü yapmalı.
            org.bouncycastle.asn1.ASN1EncodableVector vec =
                new org.bouncycastle.asn1.ASN1EncodableVector();
            vec.add(new org.bouncycastle.asn1.ASN1Integer(BigInteger.ONE));
            vec.add(new org.bouncycastle.asn1.ASN1Integer(BigInteger.TEN));
            vec.add(new org.bouncycastle.asn1.ASN1Integer(BigInteger.valueOf(42)));
            byte[] threeIntSeq = new org.bouncycastle.asn1.DERSequence(vec).getEncoded("DER");

            assertFalse(Pkcs11EcdsaSignatureEncoder.looksLikeDer(threeIntSeq),
                "ECDSA-Sig-Value tam 2 INTEGER bekler; 3 INTEGER'lı SEQUENCE reddedilmeli.");
        }
    }

    @Nested
    @DisplayName("derToRaw: DER → raw r||s (XMLDsig / RFC 4051 yönü)")
    class DerToRaw {

        @Test
        @DisplayName("toDer + derToRaw round-trip: orijinal raw byte'a dönmeli")
        void roundTrip_p256() {
            byte[] originalRaw = new byte[64];
            new SecureRandom().nextBytes(originalRaw);
            byte[] der = Pkcs11EcdsaSignatureEncoder.toDer(originalRaw);

            byte[] roundTripped = Pkcs11EcdsaSignatureEncoder.derToRaw(der, 32);

            assertArrayEquals(originalRaw, roundTripped,
                "toDer → derToRaw birebir orijinal raw'ı geri vermeli (deterministik dönüşüm).");
        }

        @Test
        @DisplayName("P-384: roundtrip 96 byte")
        void roundTrip_p384() {
            byte[] originalRaw = new byte[96];
            new SecureRandom().nextBytes(originalRaw);
            byte[] der = Pkcs11EcdsaSignatureEncoder.toDer(originalRaw);

            byte[] roundTripped = Pkcs11EcdsaSignatureEncoder.derToRaw(der, 48);

            assertArrayEquals(originalRaw, roundTripped);
        }

        @Test
        @DisplayName("P-521: roundtrip 132 byte (133-bit field → 66 byte coordinate)")
        void roundTrip_p521() {
            byte[] originalRaw = new byte[132];
            new SecureRandom().nextBytes(originalRaw);
            byte[] der = Pkcs11EcdsaSignatureEncoder.toDer(originalRaw);

            byte[] roundTripped = Pkcs11EcdsaSignatureEncoder.derToRaw(der, 66);

            assertArrayEquals(originalRaw, roundTripped);
        }

        @Test
        @DisplayName("Leading zero r/s: BigInteger high-bit handling pad'i doğru yapmalı")
        void leadingZeroHandling() {
            // r = 0x00112233...; s = 0x80AABBCC... (high-bit set)
            byte[] originalRaw = new byte[64];
            originalRaw[1] = 0x11;
            originalRaw[32] = (byte) 0x80;
            originalRaw[33] = (byte) 0xAA;

            byte[] der = Pkcs11EcdsaSignatureEncoder.toDer(originalRaw);
            byte[] roundTripped = Pkcs11EcdsaSignatureEncoder.derToRaw(der, 32);

            assertArrayEquals(originalRaw, roundTripped,
                "BigInteger high-bit için eklenen 0x00 byte derToRaw'da temizlenmeli "
                + "ve sabit uzunluk korunmalı.");
        }

        @Test
        @DisplayName("Real JCA ECDSA imzası derToRaw'a verilebilir")
        void jcaEcdsa_canBeConvertedToRaw() throws Exception {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair kp = kpg.generateKeyPair();

            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initSign(kp.getPrivate());
            sig.update("xmldsig data".getBytes());
            byte[] derSig = sig.sign();

            byte[] rawSig = Pkcs11EcdsaSignatureEncoder.derToRaw(derSig, 32);

            assertEquals(64, rawSig.length,
                "P-256 raw imza tam 64 byte olmalı (r:32 + s:32). XMLDsig SignatureValue formatı.");
            assertTrue(Pkcs11EcdsaSignatureEncoder.looksLikeDer(derSig),
                "Orijinal JCA çıktısı DER'di — sanity check.");
        }

        @Test
        @DisplayName("Raw input (non-DER) reddedilir")
        void rawInputRejected() {
            byte[] notDer = new byte[64];
            new SecureRandom().nextBytes(notDer);
            // Çok düşük olasılıkla DER görünebilir; emin olmak için 0x30 başlangıcını bozalım.
            notDer[0] = (byte) 0xAA;

            assertThrows(IllegalArgumentException.class,
                () -> Pkcs11EcdsaSignatureEncoder.derToRaw(notDer, 32));
        }

        @Test
        @DisplayName("fieldSizeBytes negative/zero → reddedilir")
        void invalidFieldSize() {
            byte[] dummy = Pkcs11EcdsaSignatureEncoder.toDer(new byte[64]);
            assertThrows(IllegalArgumentException.class,
                () -> Pkcs11EcdsaSignatureEncoder.derToRaw(dummy, 0));
            assertThrows(IllegalArgumentException.class,
                () -> Pkcs11EcdsaSignatureEncoder.derToRaw(dummy, -1));
        }

        /**
         * Regresyon: r veya s, curve field size'tan büyükse encoder sessizce
         * yüksek byte'ları atıyordu (writeUnsignedFixedLength içinde önce
         * kırpıp sonra unreachable length kontrolü yapıyordu). Artık önce
         * "kırpılacak ön byte'lar tamamen sıfır mı?" diye bakıp aksi halde
         * fail-fast atıyor — anlamlı veri kaybı engelleniyor.
         */
        @Test
        @DisplayName("Oversized r/s (fieldSize'tan büyük anlamlı veri) → IllegalArgumentException")
        void oversizedComponentRejected() {
            // r ve s, P-256 için normalde 32 byte. Burada her birini 33 byte
            // anlamlı veriyle (sign-padding 0x00 değil) inşa ediyoruz —
            // BigInteger sign byte eklemese bile leading byte 0xCC.
            byte[] oversizedR = new byte[33];
            byte[] oversizedS = new byte[33];
            Arrays.fill(oversizedR, (byte) 0xCC);
            Arrays.fill(oversizedS, (byte) 0xDD);

            // BigInteger.toByteArray() bu 33 byte'ı pozitif kabul edebilmek için
            // bir 0x00 daha ekleyecek → 34 byte. Yine de fieldSize=32 ile
            // kullanmaya çalışınca anlamlı üst byte 0xCC kırpılır → fail-fast.
            BigInteger r = new BigInteger(1, oversizedR);
            BigInteger s = new BigInteger(1, oversizedS);
            byte[] der = derEncodeSequence(r, s);

            IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> Pkcs11EcdsaSignatureEncoder.derToRaw(der, 32),
                "Curve fieldSize'tan büyük r/s sessizce kırpılmamalı.");
            assertTrue(ex.getMessage().contains("fieldSize'tan büyük")
                    || ex.getMessage().contains("anlamlı"),
                "Hata mesajı kullanıcıya anlamlı veri kaybı sebebini açıklamalı: "
                    + ex.getMessage());
        }

        /**
         * Pozitif kontrol: BigInteger'in sign-padding amacıyla eklediği
         * 0x00 byte fieldSize'ı bir aşsa bile geçerli; encoder onu atıp
         * fail-fast atmamalı.
         */
        @Test
        @DisplayName("BigInteger sign-padding (0x00 + high-bit set 32 byte) → kabul edilir")
        void signPaddingTolerated() throws Exception {
            // Tam fieldSize (32 byte) ama high-bit set: BigInteger.toByteArray()
            // 33 byte üretir, ilki 0x00. Bu meşru pozitif değer; encoder bunu
            // atıp 32 byte'ı yazmalı.
            byte[] thirtyTwoHighBit = new byte[32];
            Arrays.fill(thirtyTwoHighBit, (byte) 0xFF);
            BigInteger r = new BigInteger(1, thirtyTwoHighBit);
            BigInteger s = BigInteger.ONE;
            byte[] der = derEncodeSequence(r, s);

            byte[] raw = Pkcs11EcdsaSignatureEncoder.derToRaw(der, 32);

            assertEquals(64, raw.length, "P-256 raw çıktı 64 byte olmalı");
            // İlk 32 byte: r — tamamı 0xFF olmalı
            byte[] firstHalf = Arrays.copyOfRange(raw, 0, 32);
            assertArrayEquals(thirtyTwoHighBit, firstHalf,
                "r alanı sign-padding'siz orijinal 32 byte değeri içermeli");
        }
    }

    @Nested
    @DisplayName("Cross-verification: real JCA EC signature uyumluluğu")
    class CrossVerification {

        @Test
        @DisplayName("JCA Signature.sign() çıktısı looksLikeDer == true olmalı")
        void jcaEcSignatureIsDer() throws Exception {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair kp = kpg.generateKeyPair();

            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initSign(kp.getPrivate());
            sig.update("test message".getBytes());
            byte[] jcaSignature = sig.sign();

            // JCA EC imzası daima DER formatında — bizim heuristik bunu
            // doğru algılamalı, idempotent davranış için kritik.
            assertTrue(Pkcs11EcdsaSignatureEncoder.looksLikeDer(jcaSignature),
                "JCA Signature.sign() ECDSA çıktısı DER SEQUENCE — looksLikeDer true dönmeli "
                + "(bazı HSM driver'ları aynı formatta üretirse double-wrap olmasın).");

            byte[] normalized = Pkcs11EcdsaSignatureEncoder.normalizeToDer(jcaSignature);
            assertSame(jcaSignature, normalized,
                "JCA çıktısı normalize sonrası birebir aynı referans dönmeli; "
                + "ekstra allocation veya re-wrap yapılmamalı.");
        }
    }

    // ---- helpers ----

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static String repeatHex(String hex, int times) {
        StringBuilder sb = new StringBuilder(hex.length() * times);
        for (int i = 0; i < times; i++) sb.append(hex);
        return sb.toString();
    }

    /**
     * Test-only: BigInteger r, s'yi minimal DER ECDSA-Sig-Value SEQUENCE
     * olarak encode eder. Üretim kodu BouncyCastle ASN1 API'sini başka
     * yerde kullanıyor; bu helper test'lerin tek satırda asıl niyeti
     * (oversize r/s) ifade etmesi içindir.
     */
    private static byte[] derEncodeSequence(BigInteger r, BigInteger s) {
        try {
            org.bouncycastle.asn1.ASN1EncodableVector vec =
                new org.bouncycastle.asn1.ASN1EncodableVector();
            vec.add(new ASN1Integer(r));
            vec.add(new ASN1Integer(s));
            return new org.bouncycastle.asn1.DERSequence(vec).getEncoded("DER");
        } catch (Exception e) {
            throw new IllegalStateException("DER encode failed", e);
        }
    }
}
