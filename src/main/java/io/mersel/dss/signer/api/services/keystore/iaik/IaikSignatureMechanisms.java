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
 * <p>Stratejimiz "tek-shot hashing": mumkun oldugunda token'in
 * {@code CKM_<HASH>_RSA_PKCS} (orn. {@code CKM_SHA256_RSA_PKCS}) mekanizmasini
 * kullanarak digest hesaplamasini HSM'e yaptiririz. Bu yol:</p>
 * <ul>
 *   <li>JCE-uyumlu davranir (DSS'in bekledigi {@code Signature.sign()}
 *       ciktisiyla bit-bit ayni imzayi uretir).</li>
 *   <li>Tek round-trip - basarili performans.</li>
 *   <li>HSM PKCS#1 v1.5 padding'i kendi saglar; DigestInfo yapisini disarida
 *       insa etmek zorunda kalmayiz.</li>
 * </ul>
 *
 * <p>EC icin durum farkli: bazi tokenler (SafeNet ProtectServer K7 dahil)
 * yalnizca {@code CKM_ECDSA_SHA1} saglar; SHA-256/384/512 icin ham
 * {@code CKM_ECDSA} mekanizmasini kullanir ve digest'i disaridan veririz.
 * {@link #requiresExternalDigest(Mechanism)} bu farki isaret eder.</p>
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
                return new Mechanism(ecdsaCkm(digest));
            case DSA:
                return new Mechanism(dsaCkm(digest));
            default:
                throw new IllegalArgumentException(
                    "Desteklenmeyen sifreleme algoritmasi: " + encryption);
        }
    }

    static boolean requiresExternalDigest(Mechanism mechanism) {
        long m = mechanism.getMechanismCode();
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

    private static long ecdsaCkm(DigestAlgorithm digest) {
        switch (digest) {
            case SHA1:   return PKCS11Constants.CKM_ECDSA_SHA1;
            case SHA224: return PKCS11Constants.CKM_ECDSA_SHA224;
            case SHA256: return PKCS11Constants.CKM_ECDSA_SHA256;
            case SHA384: return PKCS11Constants.CKM_ECDSA_SHA384;
            case SHA512: return PKCS11Constants.CKM_ECDSA_SHA512;
            default:
                throw new IllegalArgumentException(
                    "ECDSA icin desteklenmeyen digest: " + digest);
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
