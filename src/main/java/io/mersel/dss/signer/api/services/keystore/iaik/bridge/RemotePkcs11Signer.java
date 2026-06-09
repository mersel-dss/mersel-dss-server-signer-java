package io.mersel.dss.signer.api.services.keystore.iaik.bridge;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import io.mersel.dss.signer.api.services.keystore.iaik.Pkcs11Signer;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * {@link Pkcs11Signer}'ın remote (köprü) implementasyonu. Native handle
 * tutmaz; helper process'teki gerçek signer'a opak bir {@code signerId} ile
 * yönlenir. Sertifika + zincir bilgisi helper'dan bir kez çekilip burada
 * tutulur (DSS belge katmanının imzalama-sertifikasına senkron erişebilmesi
 * için).
 *
 * <p>Helper restart olduğunda {@code signerId} kaybolur; {@link
 * RemotePkcs11Module#sign} bunu yakalayıp signer'ı re-resolve eder ve
 * {@link #refreshFrom} ile bu instance'ı in-place günceller — çağıranın
 * referansı korunur.</p>
 */
public final class RemotePkcs11Signer implements Pkcs11Signer {

    private final RemotePkcs11Module module;
    private final String requestedAlias;
    private final String requestedSerial;

    private volatile int signerId;
    private volatile String alias;
    private volatile X509Certificate certificate;
    private volatile List<X509Certificate> certificateChain;

    RemotePkcs11Signer(RemotePkcs11Module module,
                       int signerId,
                       String alias,
                       String requestedAlias,
                       String requestedSerial,
                       X509Certificate certificate,
                       List<X509Certificate> certificateChain) {
        this.module = module;
        this.signerId = signerId;
        this.alias = alias;
        this.requestedAlias = requestedAlias;
        this.requestedSerial = requestedSerial;
        this.certificate = certificate;
        this.certificateChain = certificateChain;
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
        return module.sign(this, dataToSign, signatureAlgorithm.name(), false);
    }

    @Override
    public byte[] signDigest(byte[] digest, DigestAlgorithm digestAlgorithm) {
        if (digest == null || digest.length == 0) {
            throw new IllegalArgumentException("signDigest: digest null veya boş olamaz");
        }
        if (digestAlgorithm == null) {
            throw new IllegalArgumentException("signDigest: digestAlgorithm null olamaz");
        }
        return module.sign(this, digest, digestAlgorithm.name(), true);
    }

    int getSignerId() {
        return signerId;
    }

    String getRequestedAlias() {
        return requestedAlias;
    }

    String getRequestedSerial() {
        return requestedSerial;
    }

    /** Re-resolve sonrası in-place güncelleme (helper restart kurtarması). */
    void refreshFrom(RemotePkcs11Signer fresh) {
        this.signerId = fresh.signerId;
        this.alias = fresh.alias;
        this.certificate = fresh.certificate;
        this.certificateChain = fresh.certificateChain;
    }
}
