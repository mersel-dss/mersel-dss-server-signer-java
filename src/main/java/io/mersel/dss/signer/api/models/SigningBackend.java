package io.mersel.dss.signer.api.models;

import eu.europa.esig.dss.enumerations.SignatureAlgorithm;

/**
 * Düşük seviye imzalama arka uç kontratı.
 *
 * <p>Uygulama imzalama materyalini farklı kaynaklardan alabilir
 * (PKCS#12/PFX veya PKCS#11/HSM). Belge imzalama katmanı ise sadece bu
 * kontrata bağlı kalır: verilen byte dizisini, çözülmüş DSS imza algoritmasıyla
 * imzala.</p>
 */
public interface SigningBackend {

    /** Log ve tanılama için okunabilir arka uç adı. */
    String getName();

    /** Özel anahtar PKCS#11 token sınırının arkasında kalıyorsa {@code true}. */
    boolean isPkcs11();

    /**
     * Verilen byte dizisini sağlanan imza algoritmasıyla imzalar.
     *
     * @param dataToSign üst imza formatı katmanının ürettiği birebir imzalanacak byte'lar
     * @param signatureAlgorithm digest ve anahtar tipini içeren DSS imza algoritması
     * @return JCA uyumlu imza byte'ları. ECDSA/DSA imzaları bu sınırda DER
     *         SEQUENCE formatındadır; XMLDsig'in beklediği raw {@code r||s}
     *         dönüşümü XML imza katmanında yapılır.
     */
    byte[] sign(byte[] dataToSign, SignatureAlgorithm signatureAlgorithm);
}
