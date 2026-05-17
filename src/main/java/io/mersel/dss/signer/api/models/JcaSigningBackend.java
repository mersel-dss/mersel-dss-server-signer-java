package io.mersel.dss.signer.api.models;

import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import io.mersel.dss.signer.api.exceptions.SignatureException;

import java.security.PrivateKey;
import java.security.Signature;

/**
 * PKCS#12/PFX materyali için JCA tabanlı yazılım imzalama arka ucu.
 */
public final class JcaSigningBackend implements SigningBackend {

    private final PrivateKey privateKey;

    public JcaSigningBackend(PrivateKey privateKey) {
        if (privateKey == null) {
            throw new IllegalArgumentException("JCA imzalama arka ucunda privateKey null olamaz");
        }
        this.privateKey = privateKey;
    }

    @Override
    public String getName() {
        return "PFX/JCA";
    }

    @Override
    public boolean isPkcs11() {
        return false;
    }

    @Override
    public byte[] sign(byte[] dataToSign, SignatureAlgorithm signatureAlgorithm) {
        try {
            Signature signature = Signature.getInstance(signatureAlgorithm.getJCEId());
            signature.initSign(privateKey);
            signature.update(dataToSign);
            return signature.sign();
        } catch (SignatureException e) {
            throw e;
        } catch (Exception e) {
            throw new SignatureException("JCA imzası oluşturulamadı", e);
        }
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }
}
