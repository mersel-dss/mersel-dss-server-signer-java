package io.mersel.dss.signer.api.services.keystore.iaik;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;

/**
 * Raw {@code CKM_RSA_PKCS} mekanizmasıyla imza atarken gerekli PKCS#1 v1.5
 * DigestInfo encoder'ı.
 *
 * <p>{@code CKM_<HASH>_RSA_PKCS} (örn. {@code CKM_SHA256_RSA_PKCS}) mekanizması
 * HSM içinde digest + DigestInfo wrapping + PKCS#1 v1.5 padding hepsini
 * yapar; bizim ham veriyi geçirmemiz yeterlidir. Eğer token bu mekanizmayı
 * desteklemiyorsa raw {@code CKM_RSA_PKCS} mekanizmasına düşeriz: digest'i
 * dışarıda hesaplar, DigestInfo ASN.1 yapısını dışarıda inşa eder ve sonra
 * imzalatırız.</p>
 *
 * <p>DigestInfo ASN.1 yapısı (RFC 8017 §9.2 step 2):</p>
 * <pre>
 *   DigestInfo ::= SEQUENCE {
 *       digestAlgorithm AlgorithmIdentifier,
 *       digest          OCTET STRING
 *   }
 * </pre>
 *
 * <p>Her digest algoritması için DigestInfo prefix'i (algorithm identifier +
 * OCTET STRING tag + length) sabittir; sadece digest payload'u değişir.</p>
 */
final class Pkcs1DigestInfo {

    /** SHA-1   OID = 1.3.14.3.2.26 */
    private static final byte[] PREFIX_SHA1 = {
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a,
        0x05, 0x00, 0x04, 0x14
    };
    /** SHA-224 OID = 2.16.840.1.101.3.4.2.4 */
    private static final byte[] PREFIX_SHA224 = {
        0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01,
        0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c
    };
    /** SHA-256 OID = 2.16.840.1.101.3.4.2.1 */
    private static final byte[] PREFIX_SHA256 = {
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01,
        0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
    };
    /** SHA-384 OID = 2.16.840.1.101.3.4.2.2 */
    private static final byte[] PREFIX_SHA384 = {
        0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01,
        0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30
    };
    /** SHA-512 OID = 2.16.840.1.101.3.4.2.3 */
    private static final byte[] PREFIX_SHA512 = {
        0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01,
        0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40
    };

    private Pkcs1DigestInfo() {
        throw new UnsupportedOperationException("static utility");
    }

    /**
     * Verilen ham digest'in başına DSS digest algoritmasına karşılık gelen
     * DigestInfo prefix'ini ekler. Sonuç {@code session.sign()}'a raw
     * {@code CKM_RSA_PKCS} mekanizmasıyla geçirilebilir.
     */
    static byte[] wrap(byte[] digest, DigestAlgorithm digestAlgorithm) {
        byte[] prefix;
        switch (digestAlgorithm) {
            case SHA1:   prefix = PREFIX_SHA1;   break;
            case SHA224: prefix = PREFIX_SHA224; break;
            case SHA256: prefix = PREFIX_SHA256; break;
            case SHA384: prefix = PREFIX_SHA384; break;
            case SHA512: prefix = PREFIX_SHA512; break;
            default:
                throw new IllegalArgumentException(
                    "PKCS#1 DigestInfo prefix bilinmiyor: " + digestAlgorithm);
        }
        byte[] result = new byte[prefix.length + digest.length];
        System.arraycopy(prefix, 0, result, 0, prefix.length);
        System.arraycopy(digest, 0, result, prefix.length, digest.length);
        return result;
    }
}
