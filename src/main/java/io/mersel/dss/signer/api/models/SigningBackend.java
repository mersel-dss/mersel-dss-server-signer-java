package io.mersel.dss.signer.api.models;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;

/**
 * Düşük seviye imzalama arka uç kontratı.
 *
 * <p>Uygulama imzalama materyalini farklı kaynaklardan alabilir
 * (PKCS#12/PFX veya PKCS#11/HSM). Belge imzalama katmanı ise sadece bu
 * kontrata bağlı kalır: verilen byte dizisini, çözülmüş DSS imza algoritmasıyla
 * imzala.</p>
 *
 * <h2>İki imzalama modu</h2>
 * <ul>
 *   <li>{@link #sign(byte[], SignatureAlgorithm)} &mdash; <b>raw veri imzalama</b>:
 *       Çağıran orijinal (digest hesaplanmamış) bayt dizisini verir; backend
 *       (JCA combined alg veya PKCS#11 {@code CKM_<HASH>_RSA_PKCS}) digest'i
 *       kendi içinde alıp imzalar. XAdES / WS-Security / belge imzalama
 *       akışlarının kullandığı yol.</li>
 *   <li>{@link #signDigest(byte[], DigestAlgorithm)} &mdash; <b>pre-hashed digest
 *       imzalama</b>: Çağıran zaten hesaplanmış digest'i verir; backend digest'i
 *       <em>tekrar hash'lemez</em>. RSA için PKCS#1 v1.5 DigestInfo wrap'ini
 *       backend yapar; ECDSA için raw digest doğrudan {@code CKM_ECDSA} /
 *       {@code NONEwithECDSA}'ya beslenir. e-Defter mali mührü ve manuel
 *       XAdES SignedInfo digest imzalama akışları bu yolu kullanır.</li>
 * </ul>
 *
 * <p><b>Önemli</b>: Yanlış metodu çağırmak <em>sessiz double-hash</em>
 * üretir (caller'ın hash'ini backend tekrar hash'ler) ve imza doğrulamada
 * GEÇERSİZ olarak görünür. Endpoint sözleşmesini DTO seviyesinde belirleyin.</p>
 */
public interface SigningBackend {

    /** Log ve tanılama için okunabilir arka uç adı. */
    String getName();

    /** Özel anahtar PKCS#11 token sınırının arkasında kalıyorsa {@code true}. */
    boolean isPkcs11();

    /**
     * Raw veriyi sağlanan imza algoritmasıyla imzalar; digest hesaplaması
     * backend'in <em>içinde</em> gerçekleşir.
     *
     * @param dataToSign üst imza formatı katmanının ürettiği birebir imzalanacak byte'lar
     * @param signatureAlgorithm digest ve anahtar tipini içeren DSS imza algoritması
     * @return JCA uyumlu imza byte'ları. ECDSA/DSA imzaları bu sınırda DER
     *         SEQUENCE formatındadır; XMLDsig'in beklediği raw {@code r||s}
     *         dönüşümü XML imza katmanında yapılır.
     */
    byte[] sign(byte[] dataToSign, SignatureAlgorithm signatureAlgorithm);

    /**
     * Pre-hashed digest'i imzalar; backend digest'i <em>tekrar hash'lemez</em>.
     *
     * <p>RSA yolunda PKCS#1 v1.5 DigestInfo encoding ({@code SEQUENCE {
     * AlgorithmIdentifier, OCTET STRING }}) backend tarafından eklenir; çağıran
     * yalnızca ham digest baytlarını verir. ECDSA yolunda hash doğrudan eğri
     * üzerinde imzalanır (DigestInfo gerekmez); çıktı DER SEQUENCE { r, s }.</p>
     *
     * @param digest pre-computed hash baytları (örn. SHA-256 için 32 byte).
     *               {@code null} veya boş kabul edilmez.
     * @param digestAlgorithm hash algoritması; RSA path'inde DigestInfo prefix
     *                        seçimi için kullanılır, ECDSA path'inde digest
     *                        uzunluk doğrulaması için kullanılır
     * @return JCA uyumlu imza byte'ları (RSA: PKCS#1 v1.5 padded RSA cipher
     *         output; ECDSA: DER SEQUENCE { r, s })
     * @throws IllegalArgumentException digest null/boş ise ya da uzunluk
     *         {@code digestAlgorithm} ile uyumsuzsa
     */
    byte[] signDigest(byte[] digest, DigestAlgorithm digestAlgorithm);
}
