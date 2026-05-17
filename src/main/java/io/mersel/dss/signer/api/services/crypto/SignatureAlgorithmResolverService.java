package io.mersel.dss.signer.api.services.crypto;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import io.mersel.dss.signer.api.exceptions.SignatureException;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

/**
 * Anahtar tipi ve digest algoritmasına göre imza algoritmalarını çözümleme servisi.
 */
@Service
public class SignatureAlgorithmResolverService {

    /**
     * Private key tipi ve istenen digest algoritmasına göre uygun imza algoritmasını belirler.
     *
     * @param privateKey İmzalama için kullanılacak private key
     * @param digestAlgorithm Kullanılacak digest algoritması
     * @return Eşleşen imza algoritması
     * @throws SignatureException Kombinasyon desteklenmiyorsa
     */
    public SignatureAlgorithm determineSignatureAlgorithm(PrivateKey privateKey,
                                                          DigestAlgorithm digestAlgorithm) {
        return resolveByKeyAlgorithm(privateKey.getAlgorithm(), digestAlgorithm);
    }

    /**
     * HSM yolunda private key handle'a doğrudan erişimimiz yok; sertifikanın
     * public key'inden algoritma adını çıkarırız (RSA / EC / DSA aynıdır).
     */
    public SignatureAlgorithm determineSignatureAlgorithm(X509Certificate certificate,
                                                          DigestAlgorithm digestAlgorithm) {
        PublicKey publicKey = certificate.getPublicKey();
        return resolveByKeyAlgorithm(publicKey.getAlgorithm(), digestAlgorithm);
    }

    /**
     * {@link Key#getAlgorithm()} string'i üzerinden algoritma çözümleme.
     * Public ve private key aynı string'i döndürür ("RSA", "EC", "DSA"),
     * bu yüzden tek yardımcı metod yeterli.
     */
    private SignatureAlgorithm resolveByKeyAlgorithm(String keyAlgorithm,
                                                     DigestAlgorithm digestAlgorithm) {
        if ("RSA".equalsIgnoreCase(keyAlgorithm)) {
            return resolveRSAAlgorithm(digestAlgorithm);
        }

        if ("EC".equalsIgnoreCase(keyAlgorithm) || "ECDSA".equalsIgnoreCase(keyAlgorithm)) {
            return resolveECDSAAlgorithm(digestAlgorithm);
        }

        if ("DSA".equalsIgnoreCase(keyAlgorithm)) {
            return resolveDSAAlgorithm(digestAlgorithm);
        }

        throw new SignatureException(
            "Desteklenmeyen anahtar algoritması: " + keyAlgorithm +
            " (Digest: " + digestAlgorithm + ")");
    }

    private SignatureAlgorithm resolveRSAAlgorithm(DigestAlgorithm digest) {
        switch (digest) {
            case SHA1:
                return SignatureAlgorithm.RSA_SHA1;
            case SHA224:
                return SignatureAlgorithm.RSA_SHA224;
            case SHA256:
                return SignatureAlgorithm.RSA_SHA256;
            case SHA384:
                return SignatureAlgorithm.RSA_SHA384;
            case SHA512:
                return SignatureAlgorithm.RSA_SHA512;
            case SHA3_224:
                return SignatureAlgorithm.RSA_SHA3_224;
            case SHA3_256:
                return SignatureAlgorithm.RSA_SHA3_256;
            case SHA3_384:
                return SignatureAlgorithm.RSA_SHA3_384;
            case SHA3_512:
                return SignatureAlgorithm.RSA_SHA3_512;
            default:
                throw new SignatureException(
                    "Unsupported RSA digest algorithm: " + digest);
        }
    }

    private SignatureAlgorithm resolveECDSAAlgorithm(DigestAlgorithm digest) {
        switch (digest) {
            case SHA1:
                return SignatureAlgorithm.ECDSA_SHA1;
            case SHA224:
                return SignatureAlgorithm.ECDSA_SHA224;
            case SHA256:
                return SignatureAlgorithm.ECDSA_SHA256;
            case SHA384:
                return SignatureAlgorithm.ECDSA_SHA384;
            case SHA512:
                return SignatureAlgorithm.ECDSA_SHA512;
            case SHA3_224:
                return SignatureAlgorithm.ECDSA_SHA3_224;
            case SHA3_256:
                return SignatureAlgorithm.ECDSA_SHA3_256;
            case SHA3_384:
                return SignatureAlgorithm.ECDSA_SHA3_384;
            case SHA3_512:
                return SignatureAlgorithm.ECDSA_SHA3_512;
            default:
                throw new SignatureException(
                    "Unsupported ECDSA digest algorithm: " + digest);
        }
    }

    private SignatureAlgorithm resolveDSAAlgorithm(DigestAlgorithm digest) {
        switch (digest) {
            case SHA1:
                return SignatureAlgorithm.DSA_SHA1;
            case SHA224:
                return SignatureAlgorithm.DSA_SHA224;
            case SHA256:
                return SignatureAlgorithm.DSA_SHA256;
            case SHA384:
                return SignatureAlgorithm.DSA_SHA384;
            case SHA512:
                return SignatureAlgorithm.DSA_SHA512;
            default:
                throw new SignatureException(
                    "Unsupported DSA digest algorithm: " + digest);
        }
    }
}

