package io.mersel.dss.signer.api.services.keystore.iaik;

import eu.europa.esig.dss.enumerations.SignatureAlgorithm;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * IAIK PKCS#11 destekli {@link Pkcs11Signer} implementasyonu. Cert + chain +
 * key handle bilgilerini taşır, asıl C_Sign çağrısını
 * {@link IaikPkcs11Module#signOnSession} metoduna delege eder.
 *
 * <p>Bu sınıf {@link IaikPkcs11Module#findSigner} tarafından üretilir;
 * uygulama yaşamı boyunca cert'i değişmediği için thread-safe (immutable
 * field'lar + module thread-safe sign).</p>
 */
final class IaikPkcs11Signer implements Pkcs11Signer {

    private final IaikPkcs11Module module;
    private final IaikPkcs11Module.ResolvedKey resolvedKey;

    IaikPkcs11Signer(IaikPkcs11Module module, IaikPkcs11Module.ResolvedKey resolvedKey) {
        this.module = module;
        this.resolvedKey = resolvedKey;
    }

    @Override
    public String getAlias() {
        return resolvedKey.alias;
    }

    @Override
    public X509Certificate getCertificate() {
        return resolvedKey.certificate;
    }

    @Override
    public List<X509Certificate> getCertificateChain() {
        return resolvedKey.certificateChain;
    }

    @Override
    public byte[] sign(byte[] dataToSign, SignatureAlgorithm signatureAlgorithm) {
        return module.signOnSession(resolvedKey.privateKeyHandle, dataToSign, signatureAlgorithm);
    }

    /**
     * HSM heartbeat scheduler için package-private erişim. Aynı paketteki
     * {@link HsmHeartbeatScheduler} sabit interval'de {@link IaikPkcs11Module#heartbeatSign}
     * çağırırken bu handle'a ihtiyaç duyar; public {@link Pkcs11Signer}
     * sözleşmesini handle ile kirletmemek için package-private bırakıldı.
     */
    long getPrivateKeyHandle() {
        return resolvedKey.privateKeyHandle;
    }
}
