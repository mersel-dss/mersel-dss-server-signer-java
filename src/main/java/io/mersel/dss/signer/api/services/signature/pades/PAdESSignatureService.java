package io.mersel.dss.signer.api.services.signature.pades;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Semaphore;

import org.apache.commons.io.IOUtils;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentCatalog;
import org.apache.pdfbox.pdmodel.PDDocumentNameDictionary;
import org.apache.pdfbox.pdmodel.PDEmbeddedFilesNameTreeNode;
import org.apache.pdfbox.pdmodel.common.filespecification.PDComplexFileSpecification;
import org.apache.pdfbox.pdmodel.common.filespecification.PDEmbeddedFile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import io.mersel.dss.signer.api.exceptions.SignatureException;
import io.mersel.dss.signer.api.exceptions.TimestampException;
import io.mersel.dss.signer.api.models.SignResponse;
import io.mersel.dss.signer.api.models.SigningMaterial;
import io.mersel.dss.signer.api.models.enums.PadesSignatureLevel;
import io.mersel.dss.signer.api.services.crypto.CryptoSignerService;
import io.mersel.dss.signer.api.services.crypto.DigestAlgorithmResolverService;
import io.mersel.dss.signer.api.services.timestamp.TimestampConfigurationService;

/**
 * PAdES (PDF İleri Seviye Elektronik İmza) imzaları oluşturan servis.
 *
 * <p>EU DSS {@link PAdESService} (PDFBox 3 implementasyonu) üzerinden ETSI EN 319 142
 * PAdES Baseline imzaları üretir. CAdES/XAdES ile aynı mimari kullanılır:</p>
 *
 * <ul>
 *   <li>{@link PAdESService} — PDF imza sözlüğü, incremental update yönetimi</li>
 *   <li>{@link CryptoSignerService} — HSM-aware kriptografik imzalama</li>
 *   <li>{@link DigestAlgorithmResolverService} — sertifikaya göre digest çözümleme</li>
 *   <li>{@link TimestampConfigurationService} — T/LT/A seviyelerinde TSP source</li>
 * </ul>
 *
 * <h3>Seviyeler</h3>
 * <p>{@link PadesSignatureLevel} ile B/T/LT/LTA seçilebilir. TSA gerektiren
 * seviyeler (T/LT/A) için TSA yapılandırılmamışsa fail-fast
 * ({@link TimestampException}).</p>
 *
 * <h3>Dosya eki</h3>
 * <p>İsteğe bağlı dosya eki, imzadan <em>önce</em> PDFBox ile belgeye gömülür;
 * böylece ek de imza kapsamına girer.</p>
 *
 * <h3>appendMode</h3>
 * <p>DSS PAdES her zaman incremental update ile imzalar ve var olan imzaları
 * korur. {@code appendMode} parametresi geriye dönük API uyumluluğu için kabul
 * edilir; DSS akışında davranışsal bir farkı yoktur.</p>
 */
@Service
public class PAdESSignatureService {

    private static final Logger LOGGER = LoggerFactory.getLogger(PAdESSignatureService.class);
    private static final String DEFAULT_PDF_NAME = "document.pdf";

    private final PAdESService padesService;
    private final CryptoSignerService cryptoSigner;
    private final DigestAlgorithmResolverService digestAlgorithmResolver;
    private final TimestampConfigurationService timestampService;
    private final Semaphore semaphore;

    public PAdESSignatureService(PAdESService padesService,
                                 CryptoSignerService cryptoSigner,
                                 DigestAlgorithmResolverService digestAlgorithmResolver,
                                 TimestampConfigurationService timestampService,
                                 Semaphore signatureSemaphore) {
        this.padesService = padesService;
        this.cryptoSigner = cryptoSigner;
        this.digestAlgorithmResolver = digestAlgorithmResolver;
        this.timestampService = timestampService;
        this.semaphore = signatureSemaphore;
    }

    /**
     * PDF belgesini PAdES-BES seviyesinde imzalar (geriye dönük uyumlu overload).
     */
    public SignResponse signPdf(InputStream pdfInputStream,
                               byte[] attachment,
                               String attachmentFileName,
                               boolean appendMode,
                               SigningMaterial material) {
        return signPdf(pdfInputStream, attachment, attachmentFileName, appendMode, material,
                PadesSignatureLevel.PADES_BES);
    }

    /**
     * PDF belgesini istenen PAdES seviyesinde imzalar.
     *
     * @param pdfInputStream     PDF belgesi içeren input stream
     * @param attachment         İsteğe bağlı dosya eki içeriği (imzadan önce gömülür)
     * @param attachmentFileName İsteğe bağlı ek dosya adı
     * @param appendMode         API uyumluluğu için kabul edilir (DSS davranışını değiştirmez)
     * @param material           İmzalama sertifikası ve private key içeren materyal
     * @param signatureLevel     İstenen PAdES profili. B dışı seviyeler TSA gerektirir;
     *                           yapılandırılmamışsa fail-fast. <strong>null geçilemez.</strong>
     * @return İmzalanmış PDF içeren yanıt
     */
    public SignResponse signPdf(InputStream pdfInputStream,
                               byte[] attachment,
                               String attachmentFileName,
                               boolean appendMode,
                               SigningMaterial material) {
        PdfReader reader = null;
        try {
            reader = new PdfReader(pdfInputStream);
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            PdfStamper stamper = PdfStamper.createSignature(
                reader, outputStream, '\0', null, appendMode);

            byte[] pdfBytes = IOUtils.toByteArray(pdfInputStream);

            // Dosya eki imzadan ÖNCE gömülür ki imza kapsamına dahil olsun.
            if (attachment != null && attachment.length > 0 && attachmentFileName != null) {
                pdfBytes = embedAttachment(pdfBytes, attachment, attachmentFileName);
            }

            DSSDocument document = new InMemoryDocument(pdfBytes, DEFAULT_PDF_NAME, MimeTypeEnum.PDF);

            DigestAlgorithm digestAlgorithm =
                    digestAlgorithmResolver.resolveDigestAlgorithm(material.getSigningCertificate());

            PAdESSignatureParameters parameters =
                    buildParameters(digestAlgorithm, material, signatureLevel);

            semaphore.acquire();
            try {
                ToBeSigned dataToSign = padesService.getDataToSign(document, parameters);

                SignatureValue signatureValue = cryptoSigner.sign(
                        dataToSign, material, digestAlgorithm);

                DSSDocument signedDocument = padesService.signDocument(document, parameters, signatureValue);

                byte[] signedBytes = IOUtils.toByteArray(signedDocument.openStream());
                String encodedSignature = Base64.getEncoder().encodeToString(signatureValue.getValue());

                LOGGER.info("PAdES imzası başarıyla oluşturuldu (seviye: {})", signatureLevel);
                return new SignResponse(signedBytes, encodedSignature);

            } finally {
                semaphore.release();
            }

        } catch (SignatureException e) {
            // TimestampException de SignatureException alt sınıfıdır; olduğu gibi bubble eder.
            throw e;
        } catch (Exception e) {
            LOGGER.error("PAdES imzası oluşturulurken hata", e);
            throw new SignatureException("PAdES imzası oluşturulamadı", e);
        } finally {
            // PdfReader alttaki multipart temp-file handle'ını tutar; başarı ve
            // hata yolunun her ikisinde de kapatılmalı (aksi halde özellikle
            // Windows'ta temp dosya silinemez / handle sızar).
            if (reader != null) {
                reader.close();
            }
        }
    }

    /**
     * DSS {@link PAdESSignatureParameters} nesnesini oluşturur.
     */
    private PAdESSignatureParameters buildParameters(DigestAlgorithm digestAlgorithm,
                                                     SigningMaterial material,
                                                     PadesSignatureLevel signatureLevel) {
        PAdESSignatureParameters parameters = new PAdESSignatureParameters();
        parameters.setSignatureLevel(toDssLevel(signatureLevel));
        parameters.setDigestAlgorithm(digestAlgorithm);
        parameters.setSigningCertificate(material.getPrimaryCertificateToken());
        parameters.setCertificateChain(material.getCertificateTokens());
        parameters.setLocation("Turkey");
        return parameters;
    }

    /**
     * Uygulama seviyesi enum'unu DSS {@link SignatureLevel}'a eşler.
     */
    private static SignatureLevel toDssLevel(PadesSignatureLevel level) {
        switch (level) {
            case PADES_BES:
                return SignatureLevel.PAdES_BASELINE_B;
            case PADES_T:
                return SignatureLevel.PAdES_BASELINE_T;
            case PADES_LT:
                return SignatureLevel.PAdES_BASELINE_LT;
            case PADES_A:
                return SignatureLevel.PAdES_BASELINE_LTA;
            default:
                throw new IllegalStateException("Beklenmeyen PAdES seviyesi: " + level);
        }
    }

    /**
     * PDF'e dosya ekini (embedded file) PDFBox ile gömer ve yeni PDF byte'larını döner.
     * İmza işleminden önce çağrılır; ek böylece imza kapsamına dahil olur.
     */
    private byte[] embedAttachment(byte[] pdfBytes, byte[] attachment, String fileName) {
        try (PDDocument document = Loader.loadPDF(pdfBytes)) {
            PDEmbeddedFile embeddedFile = new PDEmbeddedFile(document, new ByteArrayInputStream(attachment));
            embeddedFile.setSize(attachment.length);

            PDComplexFileSpecification fileSpecification = new PDComplexFileSpecification();
            fileSpecification.setFile(fileName);
            fileSpecification.setEmbeddedFile(embeddedFile);

            Map<String, PDComplexFileSpecification> embeddedFileMap = new HashMap<>();
            embeddedFileMap.put(fileName, fileSpecification);

            PDEmbeddedFilesNameTreeNode efTree = new PDEmbeddedFilesNameTreeNode();
            efTree.setNames(embeddedFileMap);

            PDDocumentCatalog catalog = document.getDocumentCatalog();
            PDDocumentNameDictionary names = new PDDocumentNameDictionary(catalog);
            names.setEmbeddedFiles(efTree);
            catalog.setNames(names);

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            document.save(outputStream);
            return outputStream.toByteArray();

        } catch (Exception e) {
            throw new SignatureException("PDF dosya eki gömülemedi", e);
        }
    }
}
