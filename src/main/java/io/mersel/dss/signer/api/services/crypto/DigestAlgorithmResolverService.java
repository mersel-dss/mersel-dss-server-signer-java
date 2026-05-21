package io.mersel.dss.signer.api.services.crypto;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.util.Locale;

/**
 * Bir sertifikanın <b>public key</b> parametresine göre uygun digest
 * algoritmasını belirleyen servis.
 *
 * <h3>Neden public key, neden sertifikanın imza algoritması değil?</h3>
 *
 * Bir X.509 sertifikasındaki <code>Signature Algorithm</code> alanı, <b>bu
 * sertifikayı imzalayan makamın (CA)</b> hangi algoritmayı kullandığını
 * söyler. Yani <code>cert.getSigAlgName()</code> = "<i>KamuSM bu sertifikayı
 * üretirken SHA-384 ile imzaladı</i>" demektir; <b>son kullanıcının imza
 * atarken hangi algoritmayı kullanması gerektiğini söylemez</b>.
 *
 * <p>Sertifika sahibinin (yani bizim) imzalama algoritması, <b>public key
 * parametresinden</b> türetilmelidir:</p>
 * <ul>
 *   <li><b>EC anahtarlar</b> &mdash; curve büyüklüğü (NIST SP 800-57):
 *       P-256 → SHA-256, P-384 → SHA-384, P-521 → SHA-512.</li>
 *   <li><b>RSA / DSA</b> &mdash; public key parametresi digest belirtmediği
 *       için, e-Fatura / KamuSM ekosisteminin yerleşik konvansiyonu olan
 *       <b>SHA-256</b> kullanılır.</li>
 * </ul>
 *
 * <h3>Geçmiş hata (regression)</h3>
 *
 * Eski sürüm <code>cert.getSigAlgName()</code> üzerinden digest çıkarıyordu.
 * KamuSM ara-CA'sının SHA-384'e geçmesinin ardından, RSA-2048 son-kullanıcı
 * sertifikaları aynı kalmasına rağmen üretilen imzalar
 * <code>rsa-sha256</code> yerine <code>rsa-sha384</code> dönmeye başlamıştı.
 *
 * <h3>Override</h3>
 *
 * Operatör belirli bir digest'i zorlamak isterse
 * <code>SIGNING_DIGEST_ALGORITHM</code> environment değişkeni (veya
 * <code>signing.digest.algorithm</code> property'si) ile global olarak
 * dayatabilir. Kabul edilen değerler:
 * <code>SHA256, SHA384, SHA512, SHA224, SHA1</code>. Boş bırakıldığında
 * (default) public key tabanlı otomatik çözümleme devreye girer.
 */
@Service
public class DigestAlgorithmResolverService {

    private static final Logger LOGGER = LoggerFactory.getLogger(DigestAlgorithmResolverService.class);

    /**
     * E-Fatura / KamuSM ekosisteminin yerleşik default'u. RSA-2048 anahtarlar
     * için referans çıktılarla (TÜBİTAK MA3, İMZAGER) birebir eşleşen değer.
     */
    private static final DigestAlgorithm DEFAULT_ALGORITHM = DigestAlgorithm.SHA256;

    private final DigestAlgorithm forcedDigestAlgorithm;

    /**
     * Otomatik çözümleme modu — testler ve manual instantiate için kullanışlı.
     * Production'da Spring, property-aware overload'ı tercih eder.
     */
    public DigestAlgorithmResolverService() {
        this("");
    }

    @Autowired
    public DigestAlgorithmResolverService(
            @Value("${signing.digest.algorithm:}") String forcedDigestAlgorithm) {
        this.forcedDigestAlgorithm = parseForcedAlgorithm(forcedDigestAlgorithm);
        if (this.forcedDigestAlgorithm != null) {
            LOGGER.info("İmza digest algoritması global olarak '{}' değerine sabitlendi " +
                            "(signing.digest.algorithm).",
                    this.forcedDigestAlgorithm);
        }
    }

    /**
     * Bir sertifika için uygun digest algoritmasını çözümler.
     *
     * <p>Sıra:</p>
     * <ol>
     *   <li>Operatör <code>signing.digest.algorithm</code> ile bir değer
     *       dayattıysa, onu döndür.</li>
     *   <li>Sertifika <code>null</code> ise default'a düş.</li>
     *   <li>Public key <b>EC</b> ise curve büyüklüğüne göre çöz.</li>
     *   <li>Aksi halde (RSA / DSA / bilinmeyen) default ({@link #DEFAULT_ALGORITHM}).</li>
     * </ol>
     *
     * <p><b>Önemli:</b> <code>certificate.getSigAlgName()</code> &mdash; yani
     * CA'nın bu sertifikayı imzalarken kullandığı algoritma &mdash;
     * <b>kasıtlı olarak dikkate alınmaz</b>. Detay için sınıf javadoc'una
     * bakın.</p>
     *
     * @param certificate Analiz edilecek sertifika (null güvenli)
     * @return Önerilen digest algoritması; asla null döndürmez
     */
    public DigestAlgorithm resolveDigestAlgorithm(X509Certificate certificate) {
        if (forcedDigestAlgorithm != null) {
            return forcedDigestAlgorithm;
        }

        if (certificate == null) {
            return DEFAULT_ALGORITHM;
        }

        PublicKey publicKey = certificate.getPublicKey();
        if (publicKey == null) {
            return DEFAULT_ALGORITHM;
        }

        if (publicKey instanceof ECKey) {
            return resolveForECKey((ECKey) publicKey);
        }

        if (publicKey instanceof RSAKey || "RSA".equalsIgnoreCase(publicKey.getAlgorithm())) {
            return DEFAULT_ALGORITHM;
        }

        return DEFAULT_ALGORITHM;
    }

    /**
     * EC anahtarlar için curve büyüklüğüne göre digest seçimi
     * (NIST SP 800-57 önerileri).
     */
    private DigestAlgorithm resolveForECKey(ECKey ecKey) {
        if (ecKey.getParams() == null || ecKey.getParams().getOrder() == null) {
            return DEFAULT_ALGORITHM;
        }
        int keySize = ecKey.getParams().getOrder().bitLength();

        if (keySize > 384) {
            return DigestAlgorithm.SHA512;
        }
        if (keySize > 256) {
            return DigestAlgorithm.SHA384;
        }
        if (keySize > 224) {
            return DigestAlgorithm.SHA256;
        }
        return DigestAlgorithm.SHA224;
    }

    /**
     * <code>signing.digest.algorithm</code> property değerini DSS digest
     * enum'una çevirir. Geçersiz değerlerde {@code null} döner ve uyarı
     * loglar &mdash; uygulama yine de boot eder, default davranış devreye
     * girer.
     */
    private DigestAlgorithm parseForcedAlgorithm(String raw) {
        if (!StringUtils.hasText(raw)) {
            return null;
        }
        String normalized = raw.trim().toUpperCase(Locale.ROOT).replace("-", "").replace("_", "");
        try {
            switch (normalized) {
                case "SHA1":
                    return DigestAlgorithm.SHA1;
                case "SHA224":
                    return DigestAlgorithm.SHA224;
                case "SHA256":
                    return DigestAlgorithm.SHA256;
                case "SHA384":
                    return DigestAlgorithm.SHA384;
                case "SHA512":
                    return DigestAlgorithm.SHA512;
                default:
                    LOGGER.warn("signing.digest.algorithm değeri tanınmadı: '{}'. " +
                                    "Otomatik çözümlemeye geri dönülüyor (default: SHA-256).",
                            raw);
                    return null;
            }
        } catch (RuntimeException e) {
            LOGGER.warn("signing.digest.algorithm parse edilemedi: '{}'. Otomatik çözümleme kullanılacak.",
                    raw, e);
            return null;
        }
    }
}
