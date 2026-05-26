package io.mersel.dss.signer.api.services.keystore.iaik;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * HSM üzerinde imza atan abstraction. {@link IaikPkcs11Module} tarafından
 * üretilen {@link IaikPkcs11Signer} bu interface'i implement eder ve
 * imzalama akışına SunPKCS11'in JCA katmanından bağımsız bir yol sağlar.
 *
 * <p>{@link CryptoSignerService} bu interface'i tek imzalama sözleşmesi
 * olarak görür; PFX (JCA {@code PrivateKey}) yolundan ayırt etmek için
 * {@link io.mersel.dss.signer.api.models.SigningMaterial#getPkcs11Signer()}
 * çağrısı yapar.</p>
 */
public interface Pkcs11Signer {

    /** Token üzerindeki sertifika için human-readable alias. */
    String getAlias();

    /** İmzalama sertifikası (kök veya ara değil — imzayı atan). */
    X509Certificate getCertificate();

    /**
     * İmzalama sertifikası dahil tam zincir. İlk eleman daima
     * {@link #getCertificate()} ile aynıdır.
     */
    List<X509Certificate> getCertificateChain();

    /**
     * Verilen ham veriyi DSS {@link SignatureAlgorithm}'a karşılık gelen
     * PKCS#11 mekanizmasıyla HSM üzerinde imzalar. Digest hesaplaması
     * (CKM_SHA*_RSA_PKCS gibi mekanizmalarda) HSM tarafında yapılır;
     * çağıran tarafın dışarıdan digest hesaplaması gerekmez.
     *
     * @param dataToSign ham veri (digest uygulanmamış)
     * @param signatureAlgorithm DSS SignatureAlgorithm; digest ve key algoritması dahil
     * @return imza byte'ları JCA uyumlu formda. RSA-PKCS#1 v1.5/PSS encoded;
     *         ECDSA/DSA için DER SEQUENCE. XMLDsig gibi raw {@code r||s}
     *         bekleyen formatlar dönüşümü kendi katmanında yapar.
     */
    byte[] sign(byte[] dataToSign, SignatureAlgorithm signatureAlgorithm);

    /**
     * Pre-hashed digest'i HSM'de imzalar; HSM digest'i <em>tekrar hash'lemez</em>.
     *
     * <p>RSA için raw {@code CKM_RSA_PKCS} mekanizması kullanılır: {@link Pkcs1DigestInfo}
     * ile DigestInfo wrap'i bu sınır içinde yapılır. ECDSA için raw {@code CKM_ECDSA}
     * kullanılır; çıktı DER SEQUENCE { r, s }'e {@link Pkcs11EcdsaSignatureEncoder}
     * tarafından normalize edilir.</p>
     *
     * <p>Combined mekanizmalar ({@code CKM_<HASH>_RSA_PKCS}) HSM içinde digest
     * alacağı için <b>kullanılmaz</b> — caller zaten hashlenmiş veriyi gönderiyor.</p>
     *
     * @param digest pre-computed hash baytları
     * @param digestAlgorithm RSA path'inde DigestInfo prefix seçimi için DSS
     *                        digest algoritması
     * @return JCA uyumlu imza byte'ları
     */
    byte[] signDigest(byte[] digest, DigestAlgorithm digestAlgorithm);
}
