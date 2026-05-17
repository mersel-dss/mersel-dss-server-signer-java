package io.mersel.dss.signer.api.models;

import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import io.mersel.dss.signer.api.exceptions.SignatureException;
import io.mersel.dss.signer.api.services.keystore.iaik.Pkcs11Signer;

/**
 * PKCS#11 tabanlı imzalama arka ucu.
 *
 * <p>Özel anahtar token dışına çıkmaz; gerçek imzalama işlemi
 * {@link Pkcs11Signer} üzerinden HSM'e delege edilir.</p>
 */
public final class Pkcs11SigningBackend implements SigningBackend {

    private final Pkcs11Signer signer;

    public Pkcs11SigningBackend(Pkcs11Signer signer) {
        if (signer == null) {
            throw new IllegalArgumentException("PKCS#11 imzalama arka ucunda signer null olamaz");
        }
        this.signer = signer;
    }

    @Override
    public String getName() {
        return "HSM/PKCS#11";
    }

    @Override
    public boolean isPkcs11() {
        return true;
    }

    @Override
    public byte[] sign(byte[] dataToSign, SignatureAlgorithm signatureAlgorithm) {
        try {
            return signer.sign(dataToSign, signatureAlgorithm);
        } catch (SignatureException e) {
            throw e;
        } catch (Exception e) {
            throw new SignatureException("HSM imzası oluşturulamadı", e);
        }
    }

    public Pkcs11Signer getSigner() {
        return signer;
    }
}
