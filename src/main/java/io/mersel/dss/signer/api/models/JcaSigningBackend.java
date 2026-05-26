package io.mersel.dss.signer.api.models;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import io.mersel.dss.signer.api.exceptions.SignatureException;
import io.mersel.dss.signer.api.services.keystore.iaik.Pkcs1DigestInfo;

import javax.crypto.Cipher;
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

    /**
     * Pre-hashed digest yolu. RSA için PKCS#1 v1.5 DigestInfo wrap'ı +
     * raw RSA encrypt; ECDSA için raw digest'i {@code NONEwithECDSA} ile
     * imzalama. Backend digest'i <em>tekrar hash'lemez</em>.
     *
     * <p>RSA path'inde {@code Cipher("RSA/ECB/PKCS1Padding").doFinal(digestInfo)}
     * tercih edildi: {@code Signature("NONEwithRSA")} bazı SunRsaSign sürümlerinde
     * input'un PKCS#1 padding boyutuna sığmadığında sessizce truncation yapabiliyor;
     * {@code Cipher} yolu DigestInfo'yu literal olarak alıp PKCS#1 v1.5 ile padler
     * ve modülar üst alır — daha öngörülebilir.</p>
     *
     * <p>ECDSA path'inde {@code NONEwithECDSA} digest'in eğri büyüklüğüne kırpılması
     * (FIPS 186-4 §6.4) JCA tarafından otomatik yapılır; çağıran SHA-256
     * (32 byte) → P-256 (32 byte) gibi eşlenmiş kombinasyonu garanti eder.</p>
     */
    @Override
    public byte[] signDigest(byte[] digest, DigestAlgorithm digestAlgorithm) {
        if (digest == null || digest.length == 0) {
            throw new IllegalArgumentException("signDigest: digest null veya boş olamaz");
        }
        if (digestAlgorithm == null) {
            throw new IllegalArgumentException("signDigest: digestAlgorithm null olamaz");
        }
        String keyAlg = privateKey.getAlgorithm();
        try {
            if ("RSA".equalsIgnoreCase(keyAlg)) {
                byte[] digestInfo = Pkcs1DigestInfo.wrap(digest, digestAlgorithm);
                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.ENCRYPT_MODE, privateKey);
                return cipher.doFinal(digestInfo);
            }
            if ("EC".equalsIgnoreCase(keyAlg) || "ECDSA".equalsIgnoreCase(keyAlg)) {
                Signature signature = Signature.getInstance("NONEwithECDSA");
                signature.initSign(privateKey);
                signature.update(digest);
                return signature.sign();
            }
            throw new SignatureException(
                "signDigest desteklenmeyen anahtar algoritması: " + keyAlg
                    + " (yalnızca RSA ve ECDSA destekleniyor)");
        } catch (SignatureException e) {
            throw e;
        } catch (Exception e) {
            throw new SignatureException("JCA digest imzası oluşturulamadı", e);
        }
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }
}
