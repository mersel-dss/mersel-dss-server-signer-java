package io.mersel.dss.signer.api.services.signature.raw;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import io.mersel.dss.signer.api.exceptions.SignatureException;
import io.mersel.dss.signer.api.models.SigningMaterial;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.cert.X509Certificate;
import java.util.Locale;

/**
 * Pre-hashed digest imzalama servisi.
 *
 * <p>Bu servis, e-Defter mali mührü ve manuel XAdES SignedInfo digest imzalama
 * gibi <b>caller'ın hash'i zaten hesapladığı</b> akışlar için bir
 * cryptographic primitive sunar. Doğrudan {@link SigningMaterial#signDigest}
 * yolunu kullanır, böylece backend digest'i <em>tekrar hash'lemez</em>:</p>
 *
 * <ul>
 *   <li><b>RSA</b>: Backend PKCS#1 v1.5 DigestInfo wrap'i ekler ve raw RSA
 *       cipher (JCA path: {@code Cipher("RSA/ECB/PKCS1Padding")}; PKCS#11
 *       path: {@code CKM_RSA_PKCS} mekanizması) ile imzalar.</li>
 *   <li><b>ECDSA</b>: Hash doğrudan eğri üzerinde imzalanır
 *       (JCA: {@code NONEwithECDSA}; PKCS#11: {@code CKM_ECDSA}). Çıktı her
 *       iki path'te de DER SEQUENCE { r, s } olarak normalize edilir.</li>
 * </ul>
 *
 * <h3>Validation kontratı</h3>
 * <p>Service seviyesinde digest uzunluğu ve algoritma uyumu doğrulanır.
 * Geçersiz girdi {@link IllegalArgumentException} ile reddedilir; controller
 * bu exception'ı 400 Bad Request'e çevirir.</p>
 *
 * <h3>Kullanım örneği (e-Defter)</h3>
 * <pre>{@code
 *   byte[] digest = sha256(canonicalSignedInfoBytes);
 *   byte[] signature = rawHashSignatureService.signDigest(digest, DigestAlgorithm.SHA256);
 *   String base64 = Base64.getEncoder().encodeToString(signature);
 *   // base64 -> <ds:SignatureValue>
 * }</pre>
 */
@Service
public class RawHashSignatureService {

    private static final Logger LOGGER = LoggerFactory.getLogger(RawHashSignatureService.class);

    private final SigningMaterial signingMaterial;

    @Autowired
    public RawHashSignatureService(SigningMaterial signingMaterial) {
        this.signingMaterial = signingMaterial;
    }

    /**
     * Pre-hashed digest'i imzalar.
     *
     * @param digest          pre-computed hash baytları (örn. SHA-256 → 32 byte)
     * @param digestAlgorithm hash algoritması; null ise default {@link DigestAlgorithm#SHA256}
     * @return JCA uyumlu imza byte'ları (RSA: PKCS#1 v1.5; ECDSA: DER SEQUENCE)
     * @throws IllegalArgumentException digest null/boş, uzunluk uyumsuz veya
     *                                  algoritma desteklenmiyor
     * @throws SignatureException       backend (JCA / HSM) imzalama başarısız olursa
     */
    public byte[] signDigest(byte[] digest, DigestAlgorithm digestAlgorithm) {
        DigestAlgorithm effectiveAlg = (digestAlgorithm != null) ? digestAlgorithm : DigestAlgorithm.SHA256;
        validateDigest(digest, effectiveAlg);

        X509Certificate signingCert = signingMaterial.getSigningCertificate();
        if (signingCert == null) {
            throw new SignatureException("İmzalama sertifikası yüklenmemiş");
        }

        long startNanos = System.nanoTime();
        byte[] signature = signingMaterial.signDigest(digest, effectiveAlg);
        long elapsedMs = (System.nanoTime() - startNanos) / 1_000_000L;

        // Audit-friendly log: backend, digest algoritması, digest fingerprint
        // (ilk 8 byte hex). Tam digest LOGLANMAZ — forensic amaçla yeterli ama
        // signing oracle bilgisini ifşa etmez.
        if (LOGGER.isInfoEnabled()) {
            LOGGER.info("Hash imzası tamamlandı: backend={}, digestAlg={}, digestLen={}, "
                    + "digestFp={}, sigLen={}, elapsedMs={}",
                signingMaterial.getBackendName(),
                effectiveAlg,
                digest.length,
                digestFingerprintHex(digest),
                signature.length,
                elapsedMs);
        }
        return signature;
    }

    /**
     * Digest girdi doğrulaması:
     * <ul>
     *   <li>Null veya boş array → reddedilir</li>
     *   <li>Uzunluk DSS digest algoritmasının beklediği byte sayısıyla eşleşmiyor → reddedilir</li>
     * </ul>
     *
     * <p>Bu kontrol caller'ın yanlışlıkla raw data göndermesini ya da
     * truncated/concatenated digest göndermesini erkenden yakalar.</p>
     */
    private static void validateDigest(byte[] digest, DigestAlgorithm digestAlgorithm) {
        if (digest == null || digest.length == 0) {
            throw new IllegalArgumentException("digest null veya boş olamaz");
        }
        int expectedLen = expectedDigestLength(digestAlgorithm);
        if (digest.length != expectedLen) {
            throw new IllegalArgumentException(String.format(
                Locale.ROOT,
                "Digest uzunluğu algoritma ile uyumsuz: %s için %d byte bekleniyor, %d byte alındı. "
                + "Caller pre-computed digest yerine raw veri göndermiş olabilir.",
                digestAlgorithm, expectedLen, digest.length));
        }
    }

    /**
     * DSS digest algoritmasının ürettiği hash uzunluğu (byte). DigestAlgorithm
     * enum'unda saltLength alanı bit cinsinden saklanır; 8'e bölerek byte değerine
     * çeviriyoruz.
     */
    private static int expectedDigestLength(DigestAlgorithm digestAlgorithm) {
        switch (digestAlgorithm) {
            case SHA1:   return 20;
            case SHA224: return 28;
            case SHA256: return 32;
            case SHA384: return 48;
            case SHA512: return 64;
            default:
                throw new IllegalArgumentException(
                    "Desteklenmeyen digest algoritması: " + digestAlgorithm
                    + " (yalnızca SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 destekleniyor)");
        }
    }

    /**
     * Digest'in ilk 8 byte'ını hex olarak döndürür — log'da forensic amaçlı
     * fingerprint. Tam digest'i loglamak signing-oracle abuse'unu kolaylaştırabilir;
     * 64-bit prefix collision olasılığı pratik olarak yok ama tam digest'i ifşa etmez.
     */
    private static String digestFingerprintHex(byte[] digest) {
        int n = Math.min(8, digest.length);
        StringBuilder sb = new StringBuilder(n * 2);
        for (int i = 0; i < n; i++) {
            sb.append(String.format("%02x", digest[i] & 0xff));
        }
        return sb.toString();
    }
}
