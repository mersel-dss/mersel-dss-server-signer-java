package io.mersel.dss.signer.api.services.keystore.iaik;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;

/**
 * BouncyCastle {@link ContentSigner} adaptörü — CMS / PKCS#7 imzalama
 * akışlarında JCA {@code PrivateKey} yerine HSM'i kullanır.
 *
 * <p>BC, {@code CMSSignedDataGenerator}, {@code JcaSignerInfoGeneratorBuilder}
 * gibi yapıların imza atan tarafa "ContentSigner" üzerinden bağlandığı
 * pattern'i izler. Pure-software akış {@code JcaContentSignerBuilder} ile
 * {@link java.security.PrivateKey} üretirken bu sınıf aynı interface'i
 * implement eder ama {@link Pkcs11Signer#sign} ile HSM C_Sign'a delege eder.</p>
 *
 * <p>Kullanım: PAdES gibi BC CMS akışlarında
 * {@code generator.addSignerInfoGenerator(builder.build(new IaikContentSigner(...)))}.</p>
 *
 * <p>Thread-safety: bu sınıf state'li ({@code ByteArrayOutputStream} biriktirir);
 * her imzalama için yeni instance oluşturulmalıdır.</p>
 */
public final class IaikContentSigner implements ContentSigner {

    private static final DefaultSignatureAlgorithmIdentifierFinder SIG_ALG_FINDER =
        new DefaultSignatureAlgorithmIdentifierFinder();

    private final Pkcs11Signer signer;
    private final SignatureAlgorithm signatureAlgorithm;
    private final AlgorithmIdentifier algorithmIdentifier;
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream(4096);

    public IaikContentSigner(Pkcs11Signer signer, DigestAlgorithm digestAlgorithm) {
        this.signer = signer;
        EncryptionAlgorithm encryption = EncryptionAlgorithm.forKey(
            signer.getCertificate().getPublicKey());
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
        return signer.sign(buffer.toByteArray(), signatureAlgorithm);
    }
}
