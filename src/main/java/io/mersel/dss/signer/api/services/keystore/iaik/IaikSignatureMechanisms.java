package io.mersel.dss.signer.api.services.keystore.iaik;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import org.xipki.pkcs11.wrapper.Mechanism;
import org.xipki.pkcs11.wrapper.PKCS11Constants;
import org.xipki.pkcs11.wrapper.params.RSA_PKCS_PSS_PARAMS;

/**
 * DSS {@link SignatureAlgorithm} -&gt; PKCS#11 {@link Mechanism} donusumu.
 *
 * <h2>RSA: combined mod (tek round-trip)</h2>
 * <p>RSA icin token'in {@code CKM_<HASH>_RSA_PKCS} (orn.
 * {@code CKM_SHA256_RSA_PKCS}) mekanizmasini kullanarak digest hesaplamasini
 * HSM'e yaptiririz. Bu yol:</p>
 * <ul>
 *   <li>JCE-uyumlu davranir (DSS'in bekledigi {@code Signature.sign()}
 *       ciktisiyla bit-bit ayni imzayi uretir).</li>
 *   <li>Tek round-trip - basarili performans.</li>
 *   <li>HSM PKCS#1 v1.5 padding'i kendi saglar; DigestInfo yapisini disarida
 *       insa etmek zorunda kalmayiz.</li>
 * </ul>
 *
 * <h2>ECDSA: her zaman raw {@code CKM_ECDSA} + dis digest</h2>
 * <p>ECDSA icin combined mekanizmalari ({@code CKM_ECDSA_SHA256} vb.)
 * <b>kullanmiyoruz</b>. Sebep: SoftHSM2 ve bazi production HSM driver'lari
 * (SafeNet ProtectServer K7, eski Luna firmware) bu mekanizmalari
 * mechanism-list'te bildirir ama {@code C_SignInit}'te
 * {@code CKR_MECHANISM_INVALID} / {@code CKR_FUNCTION_NOT_SUPPORTED} doner.
 * Ayrica xipki ipkcs11wrapper 1.0.9'da {@code PKCS11Token.opInit()}
 * <em>swallow-bug</em>'i bu hatayi {@code CKR_OPERATION_NOT_INITIALIZED}'a
 * cevirip <b>gercek hata kodunu yutuyor</b> — bu yuzden combined-mode
 * basarisizliklarini guvenilir bicimde tespit edemiyoruz.</p>
 *
 * <p>Coz&uuml;m: ECDSA icin her zaman raw {@code CKM_ECDSA} kullanip digest'i
 * Java tarafinda hesapliyoruz. Bu, tum production HSM'lerinde universal
 * destek goren tek ECDSA imza yolu. JCA verifier'i raw r||s ciktisi yerine
 * ASN.1 DER SEQUENCE bekledigi icin
 * {@link Pkcs11EcdsaSignatureEncoder#normalizeToDer} ile cevirim yapilir.</p>
 *
 * <h2>RSA-PSS ve DSA</h2>
 * <p>PSS combined modu kalir (raw fallback PSS imzayi sessizce v1.5'e
 * cevirir — yanlistir, reddetmek dogru davranis). DSA combined modu da
 * kalir (Turkiye'de pratik olarak olu, raw fallback yolu mevcut degil).</p>
 */
final class IaikSignatureMechanisms {

    private IaikSignatureMechanisms() {
        throw new UnsupportedOperationException("static utility");
    }

    static Mechanism resolveMechanism(SignatureAlgorithm signatureAlgorithm) {
        EncryptionAlgorithm encryption = signatureAlgorithm.getEncryptionAlgorithm();
        DigestAlgorithm digest = signatureAlgorithm.getDigestAlgorithm();
        if (encryption == EncryptionAlgorithm.RSASSA_PSS) {
            return rsaPssMechanism(digest);
        }
        switch (encryption) {
            case RSA:
                return new Mechanism(rsaPkcsCkm(digest));
            case ECDSA:
            case PLAIN_ECDSA:
                // Kasitli olarak combined CKM_ECDSA_<HASH> kullanmiyoruz —
                // class javadoc'undaki "ECDSA: her zaman raw" politikasi.
                return new Mechanism(PKCS11Constants.CKM_ECDSA);
            case DSA:
                return new Mechanism(dsaCkm(digest));
            default:
                throw new IllegalArgumentException(
                    "Desteklenmeyen sifreleme algoritmasi: " + encryption);
        }
    }

    static boolean requiresExternalDigest(Mechanism mechanism) {
        long m = mechanism.getMechanismCode();
        // CKM_ECDSA ve raw CKM_RSA_PKCS digest'i disarida bekler.
        // Combined hash+sign mekanizmalari (CKM_<HASH>_RSA_PKCS,
        // CKM_<HASH>_RSA_PKCS_PSS) HSM icinde digest hesaplar.
        return m == PKCS11Constants.CKM_ECDSA
            || m == PKCS11Constants.CKM_RSA_PKCS;
    }

    static Mechanism fallbackToRawEcdsa() {
        return new Mechanism(PKCS11Constants.CKM_ECDSA);
    }

    static Mechanism fallbackToRawRsaPkcs() {
        return new Mechanism(PKCS11Constants.CKM_RSA_PKCS);
    }

    private static long rsaPkcsCkm(DigestAlgorithm digest) {
        switch (digest) {
            case SHA1:   return PKCS11Constants.CKM_SHA1_RSA_PKCS;
            case SHA224: return PKCS11Constants.CKM_SHA224_RSA_PKCS;
            case SHA256: return PKCS11Constants.CKM_SHA256_RSA_PKCS;
            case SHA384: return PKCS11Constants.CKM_SHA384_RSA_PKCS;
            case SHA512: return PKCS11Constants.CKM_SHA512_RSA_PKCS;
            default:
                throw new IllegalArgumentException(
                    "RSA-PKCS icin desteklenmeyen digest: " + digest);
        }
    }

    private static long dsaCkm(DigestAlgorithm digest) {
        switch (digest) {
            case SHA1:   return PKCS11Constants.CKM_DSA_SHA1;
            case SHA224: return PKCS11Constants.CKM_DSA_SHA224;
            case SHA256: return PKCS11Constants.CKM_DSA_SHA256;
            case SHA384: return PKCS11Constants.CKM_DSA_SHA384;
            case SHA512: return PKCS11Constants.CKM_DSA_SHA512;
            default:
                throw new IllegalArgumentException(
                    "DSA icin desteklenmeyen digest: " + digest);
        }
    }

    private static Mechanism rsaPssMechanism(DigestAlgorithm digest) {
        long ckm;
        long hashCkm;
        int saltLen;
        switch (digest) {
            case SHA1:
                ckm = PKCS11Constants.CKM_SHA1_RSA_PKCS_PSS;
                hashCkm = PKCS11Constants.CKM_SHA_1;
                saltLen = 20;
                break;
            case SHA224:
                ckm = PKCS11Constants.CKM_SHA224_RSA_PKCS_PSS;
                hashCkm = PKCS11Constants.CKM_SHA224;
                saltLen = 28;
                break;
            case SHA256:
                ckm = PKCS11Constants.CKM_SHA256_RSA_PKCS_PSS;
                hashCkm = PKCS11Constants.CKM_SHA256;
                saltLen = 32;
                break;
            case SHA384:
                ckm = PKCS11Constants.CKM_SHA384_RSA_PKCS_PSS;
                hashCkm = PKCS11Constants.CKM_SHA384;
                saltLen = 48;
                break;
            case SHA512:
                ckm = PKCS11Constants.CKM_SHA512_RSA_PKCS_PSS;
                hashCkm = PKCS11Constants.CKM_SHA512;
                saltLen = 64;
                break;
            default:
                throw new IllegalArgumentException("RSA-PSS icin desteklenmeyen digest: " + digest);
        }

        long mgf = mgfPkcs11Source(hashCkm);
        RSA_PKCS_PSS_PARAMS pssParams = new RSA_PKCS_PSS_PARAMS(hashCkm, mgf, saltLen);
        return new Mechanism(ckm, pssParams);
    }

    private static long mgfPkcs11Source(long hashCkm) {
        if (hashCkm == PKCS11Constants.CKM_SHA_1)  return PKCS11Constants.CKG_MGF1_SHA1;
        if (hashCkm == PKCS11Constants.CKM_SHA224) return PKCS11Constants.CKG_MGF1_SHA224;
        if (hashCkm == PKCS11Constants.CKM_SHA256) return PKCS11Constants.CKG_MGF1_SHA256;
        if (hashCkm == PKCS11Constants.CKM_SHA384) return PKCS11Constants.CKG_MGF1_SHA384;
        if (hashCkm == PKCS11Constants.CKM_SHA512) return PKCS11Constants.CKG_MGF1_SHA512;
        throw new IllegalArgumentException(
            "MGF1 source icin bilinmeyen hash mekanizmasi: 0x" + Long.toHexString(hashCkm));
    }
}
