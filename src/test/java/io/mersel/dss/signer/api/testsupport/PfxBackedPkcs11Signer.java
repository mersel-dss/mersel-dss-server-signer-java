package io.mersel.dss.signer.api.testsupport;

import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import io.mersel.dss.signer.api.services.keystore.iaik.Pkcs11Signer;

import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Dışa aktarılabilir PFX özel anahtarı ile çalışan test amaçlı PKCS#11 signer.
 *
 * <p>Gerçek token olmadan production PKCS#11 kod yolunu bilinçli olarak
 * çalıştırır. Mock'tan daha güçlüdür, çünkü kriptografik olarak doğrulanabilir
 * imzalar üretir; yine de SoftHSM2 / gerçek PKCS#11 entegrasyon testinin
 * yerine geçmez.</p>
 */
public final class PfxBackedPkcs11Signer implements Pkcs11Signer {

    private final String alias;
    private final PrivateKey privateKey;
    private final X509Certificate certificate;
    private final List<X509Certificate> certificateChain;
    private final AtomicInteger signCount = new AtomicInteger();

    public PfxBackedPkcs11Signer(String alias,
                                 PrivateKey privateKey,
                                 X509Certificate certificate,
                                 List<X509Certificate> certificateChain) {
        this.alias = alias;
        this.privateKey = privateKey;
        this.certificate = certificate;
        this.certificateChain = Collections.unmodifiableList(new ArrayList<>(certificateChain));
    }

    @Override
    public String getAlias() {
        return alias;
    }

    @Override
    public X509Certificate getCertificate() {
        return certificate;
    }

    @Override
    public List<X509Certificate> getCertificateChain() {
        return certificateChain;
    }

    @Override
    public byte[] sign(byte[] dataToSign, SignatureAlgorithm signatureAlgorithm) {
        signCount.incrementAndGet();
        try {
            Signature signature = Signature.getInstance(signatureAlgorithm.getJCEId());
            signature.initSign(privateKey);
            signature.update(dataToSign);
            return signature.sign();
        } catch (Exception e) {
            throw new IllegalStateException("PFX destekli PKCS#11 test signer imza atamadı", e);
        }
    }

    public int getSignCount() {
        return signCount.get();
    }
}
