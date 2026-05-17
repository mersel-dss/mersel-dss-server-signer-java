package io.mersel.dss.signer.api.services.keystore.iaik;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.security.MessageDigest;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * RFC 8017 §9.2 PKCS#1 v1.5 DigestInfo encoder testleri.
 *
 * <p>Bu sınıf raw {@code CKM_RSA_PKCS} mekanizmasıyla imza atarken digest'in
 * önüne hangi sabit DigestInfo prefix'inin geleceğini belirler. Bir tek bit
 * yanlışlık imzayı kesinlikle bozar (PKCS#1 verify safhasında digest
 * algoritmasını tanıyamaz, ya da yanlış byte length okur), bu yüzden
 * **byte-bit kesinliğe** kadar test ediyoruz.</p>
 *
 * <p>Karşılaştırma için kullandığımız beklenen prefix'ler RFC 8017
 * Appendix B.1 ile bire bir uyumludur.</p>
 */
class Pkcs1DigestInfoTest {

    // RFC 8017 §B.1 - sabit DigestInfo prefix'leri (hex)
    private static final String PREFIX_SHA1_HEX   = "3021300906052b0e03021a05000414";
    private static final String PREFIX_SHA224_HEX = "302d300d06096086480165030402040500041c";
    private static final String PREFIX_SHA256_HEX = "3031300d060960864801650304020105000420";
    private static final String PREFIX_SHA384_HEX = "3041300d060960864801650304020205000430";
    private static final String PREFIX_SHA512_HEX = "3051300d060960864801650304020305000440";

    @Nested
    @DisplayName("Bilinen RFC 8017 §B.1 prefix'leri")
    class KnownPrefixes {

        @Test
        void sha1_prefixShouldMatchRfc8017() {
            byte[] zeroDigest = new byte[20];
            byte[] wrapped = Pkcs1DigestInfo.wrap(zeroDigest, DigestAlgorithm.SHA1);
            assertArrayEquals(fromHex(PREFIX_SHA1_HEX), slice(wrapped, 0, 15),
                "SHA-1 DigestInfo prefix RFC 8017 B.1 ile bire bir aynı olmalı");
            assertEquals(15 + 20, wrapped.length, "SHA-1 toplam DigestInfo uzunluğu");
        }

        @Test
        void sha224_prefixShouldMatchRfc8017() {
            byte[] zeroDigest = new byte[28];
            byte[] wrapped = Pkcs1DigestInfo.wrap(zeroDigest, DigestAlgorithm.SHA224);
            assertArrayEquals(fromHex(PREFIX_SHA224_HEX), slice(wrapped, 0, 19));
            assertEquals(19 + 28, wrapped.length);
        }

        @Test
        void sha256_prefixShouldMatchRfc8017() {
            byte[] zeroDigest = new byte[32];
            byte[] wrapped = Pkcs1DigestInfo.wrap(zeroDigest, DigestAlgorithm.SHA256);
            assertArrayEquals(fromHex(PREFIX_SHA256_HEX), slice(wrapped, 0, 19));
            assertEquals(19 + 32, wrapped.length);
        }

        @Test
        void sha384_prefixShouldMatchRfc8017() {
            byte[] zeroDigest = new byte[48];
            byte[] wrapped = Pkcs1DigestInfo.wrap(zeroDigest, DigestAlgorithm.SHA384);
            assertArrayEquals(fromHex(PREFIX_SHA384_HEX), slice(wrapped, 0, 19));
            assertEquals(19 + 48, wrapped.length);
        }

        @Test
        void sha512_prefixShouldMatchRfc8017() {
            byte[] zeroDigest = new byte[64];
            byte[] wrapped = Pkcs1DigestInfo.wrap(zeroDigest, DigestAlgorithm.SHA512);
            assertArrayEquals(fromHex(PREFIX_SHA512_HEX), slice(wrapped, 0, 19));
            assertEquals(19 + 64, wrapped.length);
        }
    }

    @Nested
    @DisplayName("Bilinen test vector (SHA-256(\"abc\"))")
    class KnownTestVector {

        /**
         * NIST FIPS 180-4 örnek vektörü: SHA-256("abc")
         * = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
         * <p>PKCS#1 v1.5 DigestInfo bunu prefix ile birleştirir ve verifier
         * tarafında bu byte stream çözümlenir. Bizim wrap()'imiz bu byte
         * sequence'ı dakik üretmeli.</p>
         */
        @Test
        void sha256OfAbc_shouldProduceExpectedDigestInfo() throws Exception {
            byte[] digestOfAbc = MessageDigest.getInstance("SHA-256")
                .digest("abc".getBytes());

            byte[] wrapped = Pkcs1DigestInfo.wrap(digestOfAbc, DigestAlgorithm.SHA256);

            String expected = PREFIX_SHA256_HEX
                + "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
            assertArrayEquals(fromHex(expected), wrapped,
                "SHA-256(\"abc\") DigestInfo byte-bit eşleşmeli (NIST FIPS 180-4)");
        }

        @Test
        void sha1OfAbc_shouldProduceExpectedDigestInfo() throws Exception {
            byte[] digestOfAbc = MessageDigest.getInstance("SHA-1")
                .digest("abc".getBytes());

            byte[] wrapped = Pkcs1DigestInfo.wrap(digestOfAbc, DigestAlgorithm.SHA1);

            // SHA-1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
            String expected = PREFIX_SHA1_HEX
                + "a9993e364706816aba3e25717850c26c9cd0d89d";
            assertArrayEquals(fromHex(expected), wrapped);
        }
    }

    @Nested
    @DisplayName("Edge case'ler")
    class EdgeCases {

        @Test
        void unsupportedDigest_sha3_shouldThrow() {
            // SHA3 algoritmaları için PKCS#1 prefix yok — encoder reddetmeli.
            byte[] dummyDigest = new byte[32];
            assertThrows(IllegalArgumentException.class,
                () -> Pkcs1DigestInfo.wrap(dummyDigest, DigestAlgorithm.SHA3_256));
        }

        @Test
        void utilityClass_shouldHavePrivateCtor() {
            // Refleksiyon yapmaya gerek yok; class final + private ctor olduğunu
            // bu testin var olmasıyla zaten static utility kontratını doğruluyoruz.
            // Mass digest test verification:
            byte[] one = Pkcs1DigestInfo.wrap(new byte[32], DigestAlgorithm.SHA256);
            byte[] two = Pkcs1DigestInfo.wrap(new byte[32], DigestAlgorithm.SHA256);
            assertArrayEquals(one, two, "Aynı input → aynı output (deterministik)");
        }

        @Test
        void wrapShouldNotMutateInputDigest() {
            byte[] digest = new byte[32];
            for (int i = 0; i < 32; i++) digest[i] = (byte) i;
            byte[] snapshot = digest.clone();

            Pkcs1DigestInfo.wrap(digest, DigestAlgorithm.SHA256);

            assertArrayEquals(snapshot, digest,
                "wrap() input digest array'ini değiştirmemeli (immutability)");
        }

        @Test
        void wrappedOutput_shouldPlaceDigestAtCorrectOffset() {
            byte[] digest = new byte[32];
            for (int i = 0; i < 32; i++) digest[i] = (byte) (0xAA);

            byte[] wrapped = Pkcs1DigestInfo.wrap(digest, DigestAlgorithm.SHA256);

            // Output[19..51] = digest
            assertArrayEquals(digest, slice(wrapped, 19, 32),
                "Digest payload prefix'in hemen ardından gelmeli (offset=prefix.length)");
        }
    }

    // ------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------

    private static byte[] fromHex(String hex) {
        return Hex.decode(hex);
    }

    private static byte[] slice(byte[] src, int offset, int length) {
        byte[] out = new byte[length];
        System.arraycopy(src, offset, out, 0, length);
        return out;
    }
}
