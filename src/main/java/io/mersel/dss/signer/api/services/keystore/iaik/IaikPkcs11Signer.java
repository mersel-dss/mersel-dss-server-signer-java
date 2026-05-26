package io.mersel.dss.signer.api.services.keystore.iaik;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
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
        // Alias-aware overload (L2 SMS-aile recovery branch) — handle her
        // sign çağrısında {@code resolvedKey.privateKeyHandle} (volatile)
        // üzerinden fresh okunur. Reinit sonrası in-place refresh edilen
        // handle'ı bir sonraki sign otomatik kullanır; cascade transparent.
        return module.signOnSession(resolvedKey, dataToSign, signatureAlgorithm);
    }

    @Override
    public byte[] signDigest(byte[] digest, DigestAlgorithm digestAlgorithm) {
        if (digest == null || digest.length == 0) {
            throw new IllegalArgumentException("signDigest: digest null veya boş olamaz");
        }
        if (digestAlgorithm == null) {
            throw new IllegalArgumentException("signDigest: digestAlgorithm null olamaz");
        }
        // EncryptionAlgorithm sertifikanın public key'inden çözülür; mevcut
        // sertifika imzalama için kullanılan key ile birebir bağlı (HSM-resident
        // key handle bu cert'in private partner'ı).
        EncryptionAlgorithm enc = EncryptionAlgorithm.forKey(resolvedKey.certificate.getPublicKey());
        return module.signOnSessionRawDigest(resolvedKey, digest, digestAlgorithm, enc);
    }

    /**
     * HSM heartbeat scheduler için package-private erişim. Heartbeat L1
     * yolu üzerinden Cryptoki reinit'i bağımsız tetikler ve reinit sonrası
     * bu {@link ResolvedKey} instance'ı in-place refresh edilir — scheduler
     * her heartbeat tick'inde fresh handle okur.
     *
     * <p>Public {@link Pkcs11Signer} sözleşmesini handle ile kirletmemek
     * için package-private bırakıldı.</p>
     */
    IaikPkcs11Module.ResolvedKey getResolvedKey() {
        return resolvedKey;
    }

    /** @deprecated {@link #getResolvedKey()} kullanın — handle volatile
     *  field'dan okunur, reinit sonrası fresh.
     */
    @Deprecated
    long getPrivateKeyHandle() {
        return resolvedKey.privateKeyHandle;
    }
}
