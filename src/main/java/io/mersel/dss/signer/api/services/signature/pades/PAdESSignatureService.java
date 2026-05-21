package io.mersel.dss.signer.api.services.signature.pades;

import com.itextpdf.text.pdf.*;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import io.mersel.dss.signer.api.exceptions.SignatureException;
import io.mersel.dss.signer.api.models.SignResponse;
import io.mersel.dss.signer.api.models.SigningMaterial;
import io.mersel.dss.signer.api.services.crypto.DigestAlgorithmResolverService;
import io.mersel.dss.signer.api.services.crypto.SigningMaterialContentSigner;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Calendar;
import java.util.HashMap;
import java.util.concurrent.Semaphore;

/**
 * PAdES (PDF İleri Seviye Elektronik İmza) imzaları oluşturan servis.
 * iText ve BouncyCastle kullanarak CAdES tabanlı PDF imzalama yapar.
 * 
 * <p>Özellikler:
 * <ul>
 *   <li>Gömülü CAdES imzası</li>
 *   <li>Dosya eki desteği</li>
 *   <li>Çoklu imza için ekleme modu</li>
 *   <li>SigningCertificateV2 özniteliği</li>
 * </ul>
 */
@Service
public class PAdESSignatureService {

    private static final Logger LOGGER = LoggerFactory.getLogger(PAdESSignatureService.class);
    private static final int SIGNATURE_SIZE_ESTIMATE = 8192;

    private final Semaphore semaphore;
    private final DigestAlgorithmResolverService digestAlgorithmResolver;

    public PAdESSignatureService(Semaphore signatureSemaphore,
                                 DigestAlgorithmResolverService digestAlgorithmResolver) {
        this.semaphore = signatureSemaphore;
        this.digestAlgorithmResolver = digestAlgorithmResolver;
    }

    /**
     * PDF belgesini PAdES imzası ile imzalar.
     * 
     * @param pdfInputStream PDF belgesi içeren input stream
     * @param attachment İsteğe bağlı dosya eki içeriği
     * @param attachmentFileName İsteğe bağlı ek dosya adı
     * @param appendMode İmzanın eklenmesi (true) veya yeni revizyon (false)
     * @param material İmzalama sertifikası ve private key içeren materyal
     * @return İmzalanmış PDF içeren yanıt
     */
    public SignResponse signPdf(InputStream pdfInputStream,
                               byte[] attachment,
                               String attachmentFileName,
                               boolean appendMode,
                               SigningMaterial material) {
        try {
            PdfReader reader = new PdfReader(pdfInputStream);
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            PdfStamper stamper = PdfStamper.createSignature(
                reader, outputStream, '\0', null, appendMode);

            // Dosya eki varsa ekle
            if (attachment != null && attachment.length > 0 && attachmentFileName != null) {
                stamper.addFileAttachment(null, attachment, null, attachmentFileName);
            }

            // İmza görünümünü yapılandır
            PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
            appearance.setLocation("Turkey");
            appearance.setSignDate(Calendar.getInstance());

            // İmza sözlüğünü oluştur
            PdfSignature pdfSignature = new PdfSignature(
                PdfName.ADOBE_PPKLITE, PdfName.ETSI_CADES_DETACHED);
            pdfSignature.setReason(appearance.getReason());
            pdfSignature.setLocation(appearance.getLocation());
            pdfSignature.setContact(appearance.getContact());
            pdfSignature.setDate(new PdfDate(appearance.getSignDate()));
            appearance.setCryptoDictionary(pdfSignature);

            // İmza için yer ayır
            HashMap<PdfName, Integer> exclusionSizes = new HashMap<>();
            exclusionSizes.put(PdfName.CONTENTS, SIGNATURE_SIZE_ESTIMATE * 2 + 2);
            appearance.preClose(exclusionSizes);

            // CMS imzasını oluştur
            byte[] signatureBytes = createCMSSignature(
                appearance, material);

            // İmzayı göm
            PdfDictionary dictionary = new PdfDictionary();
            dictionary.put(PdfName.CONTENTS, 
                new PdfString(signatureBytes).setHexWriting(true));
            appearance.close(dictionary);

            LOGGER.info("PAdES imzası başarıyla oluşturuldu");
            return new SignResponse(outputStream.toByteArray(), null);

        } catch (Exception e) {
            LOGGER.error("PAdES imzası oluşturulurken hata", e);
            throw new SignatureException("PAdES imzası oluşturulamadı", e);
        }
    }

    /**
     * PDF içeriği için CMS imzası oluşturur.
     * SigningCertificateV2 özniteliği ile sertifikaya uygun hash algoritması kullanır.
     *
     * <p>Digest algoritması seçimi {@link DigestAlgorithmResolverService}'e
     * delege edilir — CAdES/XAdES ile <b>aynı</b> mantık: yalnızca sertifikanın
     * <b>public key</b> parametresine bakılır (EC için curve büyüklüğü
     * NIST SP 800-57, RSA için SHA-256 default). CA'nın sertifikayı imzalarken
     * kullandığı algoritma (<code>cert.getSigAlgName()</code>) <b>kasıtlı
     * olarak yok sayılır</b>. Bu sayede aynı sertifikayla farklı imza
     * formatlarında tutarlı digest kullanılır.</p>
     */
    private byte[] createCMSSignature(PdfSignatureAppearance appearance,
                                     SigningMaterial material) throws Exception {
        DigestAlgorithm digest = digestAlgorithmResolver.resolveDigestAlgorithm(
            material.getSigningCertificate());
        String digestAlgName = digest.getJavaName();
        org.bouncycastle.asn1.ASN1ObjectIdentifier digestOid =
            new org.bouncycastle.asn1.ASN1ObjectIdentifier(digest.getOid());

        // SigningCertificateV2 için sertifika hash'i hesapla
        MessageDigest messageDigest = MessageDigest.getInstance(digestAlgName);
        byte[] certificateHash = messageDigest.digest(
            material.getSigningCertificate().getEncoded());

        // Issuer serial oluştur
        GeneralName generalName = new GeneralName(
            X500Name.getInstance(material.getSigningCertificate()
                .getIssuerX500Principal().getEncoded()));
        GeneralNames generalNames = new GeneralNames(generalName);
        IssuerSerial issuerSerial = new IssuerSerial(
            generalNames, material.getSigningCertificate().getSerialNumber());

        // Create SigningCertificateV2 attribute
        ESSCertIDv2 essCert = new ESSCertIDv2(
            new AlgorithmIdentifier(digestOid),
            certificateHash, issuerSerial);
        SigningCertificateV2 signingCertificateV2 = new SigningCertificateV2(
            new ESSCertIDv2[]{essCert});
        Attribute signingCertAttr = new Attribute(
            PKCSObjectIdentifiers.id_aa_signingCertificateV2,
            new DERSet(signingCertificateV2));

        // Build signed attributes
        ASN1EncodableVector signedAttributes = new ASN1EncodableVector();
        signedAttributes.add(signingCertAttr);
        AttributeTable attributeTable = new AttributeTable(signedAttributes);

        // Create signer
        JcaSignerInfoGeneratorBuilder signerInfoGeneratorBuilder = 
            new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().build())
                .setSignedAttributeGenerator(
                    new DefaultSignedAttributeTableGenerator(attributeTable));

        // BC CMS imzasını SigningMaterial'ın tek sign kontratı üzerinden ata.
        // PFX ve HSM ayrımı document-format katmanına sızmaz.
        ContentSigner contentSigner = buildContentSigner(material, digest);

        // Generate CMS signed data
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        generator.addSignerInfoGenerator(
            signerInfoGeneratorBuilder.build(contentSigner, 
                material.getSigningCertificate()));
        generator.addCertificates(new JcaCertStore(material.getCertificateChain()));

        // Sign PDF content
        InputStream rangeStream = appearance.getRangeStream();
        byte[] rangeBytes = IOUtils.toByteArray(rangeStream);

        semaphore.acquire();
        try {
            CMSSignedData signedData = generator.generate(
                new CMSProcessableByteArray(rangeBytes), false);
            byte[] encodedSignature = signedData.getEncoded();

            if (encodedSignature.length > SIGNATURE_SIZE_ESTIMATE) {
                throw new SignatureException(
                    "Signature size exceeds reserved space: " + 
                    encodedSignature.length + " > " + SIGNATURE_SIZE_ESTIMATE);
            }

            // Pad signature to reserved size
            byte[] paddedSignature = new byte[SIGNATURE_SIZE_ESTIMATE];
            System.arraycopy(encodedSignature, 0, paddedSignature, 0, 
                encodedSignature.length);

            return paddedSignature;

        } finally {
            semaphore.release();
        }
    }

    /**
     * Material'in arka ucundan bağımsız tek {@link ContentSigner} üretir.
     */
    private ContentSigner buildContentSigner(SigningMaterial material, DigestAlgorithm digest) throws Exception {
        return new SigningMaterialContentSigner(material, digest);
    }
}
