package io.mersel.dss.signer.api.models;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import io.mersel.dss.signer.api.services.keystore.iaik.Pkcs11Signer;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * İmzalama için gereken kriptografik materyali kapsayan immutable nesne.
 *
 * <p>İki ayrı arka uç desteklenir:</p>
 * <ul>
 *   <li><b>PFX / PKCS#12</b> → {@link #getPrivateKey()} dolu, JCA
 *       {@code Signature.initSign(privateKey)} ile imzalanır.</li>
 *   <li><b>HSM / PKCS#11 (IAIK üzerinden)</b> → {@link #getPkcs11Signer()}
 *       dolu, özel anahtar handle'ı HSM'de kalır;
 *       {@link Pkcs11Signer#sign(byte[], eu.europa.esig.dss.enumerations.SignatureAlgorithm)}
 *       çağrısı C_Sign'e delege eder.</li>
 * </ul>
 *
 * <p>Belge seviyesi servislerin ortak kontratı {@link #sign(byte[], SignatureAlgorithm)}
 * metodudur. Böylece XAdES/CAdES/PAdES/WS-Security katmanları PFX mi HSM mi
 * kullanıldığını bilmek zorunda kalmaz.</p>
 */
public final class SigningMaterial {

    private final SigningBackend signingBackend;
    private final X509Certificate signingCertificate;
    private final List<X509Certificate> certificateChain;
    private final List<CertificateToken> certificateTokens;

    /** PFX yolu için kurucu. */
    public SigningMaterial(PrivateKey privateKey,
                          X509Certificate signingCertificate,
                          List<X509Certificate> certificateChain) {
        this(new JcaSigningBackend(privateKey), signingCertificate, certificateChain);
    }

    /** HSM yolu için kurucu. */
    public SigningMaterial(Pkcs11Signer pkcs11Signer,
                          X509Certificate signingCertificate,
                          List<X509Certificate> certificateChain) {
        this(new Pkcs11SigningBackend(pkcs11Signer), signingCertificate, certificateChain);
    }

    private SigningMaterial(SigningBackend signingBackend,
                            X509Certificate signingCertificate,
                            List<X509Certificate> certificateChain) {
        if (signingBackend == null) {
            throw new IllegalArgumentException("SigningMaterial: signingBackend null olamaz");
        }
        if (signingCertificate == null) {
            throw new IllegalArgumentException("SigningMaterial: signingCertificate null olamaz");
        }
        if (certificateChain == null || certificateChain.isEmpty()) {
            throw new IllegalArgumentException("SigningMaterial: certificateChain boş olamaz");
        }
        this.signingBackend = signingBackend;
        this.signingCertificate = signingCertificate;
        this.certificateChain = Collections.unmodifiableList(new ArrayList<>(certificateChain));
        this.certificateTokens = this.certificateChain.stream()
                .map(CertificateToken::new)
                .collect(Collectors.toList());
    }

    /**
     * JCA özel anahtarı. PFX yolunda dolu, HSM yolunda {@code null}.
     * HSM yolunda imza için {@link #getPkcs11Signer()} kullanılmalıdır.
     */
    public PrivateKey getPrivateKey() {
        if (signingBackend instanceof JcaSigningBackend) {
            return ((JcaSigningBackend) signingBackend).getPrivateKey();
        }
        return null;
    }

    /**
     * HSM (PKCS#11) yolunda imza atan token. PFX yolunda {@code null}.
     */
    public Pkcs11Signer getPkcs11Signer() {
        if (signingBackend instanceof Pkcs11SigningBackend) {
            return ((Pkcs11SigningBackend) signingBackend).getSigner();
        }
        return null;
    }

    /** PKCS#11 yolundayız mi? */
    public boolean isPkcs11() {
        return signingBackend.isPkcs11();
    }

    public String getBackendName() {
        return signingBackend.getName();
    }

    public SigningBackend getSigningBackend() {
        return signingBackend;
    }

    public byte[] sign(byte[] dataToSign, SignatureAlgorithm signatureAlgorithm) {
        return signingBackend.sign(dataToSign, signatureAlgorithm);
    }

    public X509Certificate getSigningCertificate() {
        return signingCertificate;
    }

    public List<X509Certificate> getCertificateChain() {
        return certificateChain;
    }

    public List<CertificateToken> getCertificateTokens() {
        return certificateTokens;
    }

    public CertificateToken getPrimaryCertificateToken() {
        return certificateTokens.get(0);
    }
}
