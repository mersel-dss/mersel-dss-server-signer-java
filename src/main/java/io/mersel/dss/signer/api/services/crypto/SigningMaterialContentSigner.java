package io.mersel.dss.signer.api.services.crypto;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import io.mersel.dss.signer.api.models.SigningMaterial;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;

/**
 * {@link SigningMaterial} ile çalışan BouncyCastle {@link ContentSigner}
 * adaptörü.
 *
 * <p>PAdES gibi CMS tabanlı akışlar BC {@code ContentSigner} ister. Bu adaptör,
 * PFX ve PKCS#11 ayrımını belge formatı servisinin içine taşımadan
 * {@link SigningMaterial} üzerindeki ortak imzalama kontratına bağlar.</p>
 */
public final class SigningMaterialContentSigner implements ContentSigner {

    private static final DefaultSignatureAlgorithmIdentifierFinder SIG_ALG_FINDER =
        new DefaultSignatureAlgorithmIdentifierFinder();

    private final SigningMaterial material;
    private final SignatureAlgorithm signatureAlgorithm;
    private final AlgorithmIdentifier algorithmIdentifier;
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream(4096);

    public SigningMaterialContentSigner(SigningMaterial material, DigestAlgorithm digestAlgorithm) {
        if (material == null) {
            throw new IllegalArgumentException("SigningMaterial null olamaz");
        }
        this.material = material;
        EncryptionAlgorithm encryption = EncryptionAlgorithm.forKey(
            material.getSigningCertificate().getPublicKey());
        this.signatureAlgorithm = SignatureAlgorithm.getAlgorithm(encryption, digestAlgorithm);
        if (this.signatureAlgorithm == null) {
            throw new IllegalArgumentException(
                "DSS SignatureAlgorithm bulunamadı: enc=" + encryption + ", digest=" + digestAlgorithm);
        }
        this.algorithmIdentifier = SIG_ALG_FINDER.find(signatureAlgorithm.getJCEId());
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return algorithmIdentifier;
    }

    @Override
    public OutputStream getOutputStream() {
        return buffer;
    }

    @Override
    public byte[] getSignature() {
        return material.sign(buffer.toByteArray(), signatureAlgorithm);
    }
}
