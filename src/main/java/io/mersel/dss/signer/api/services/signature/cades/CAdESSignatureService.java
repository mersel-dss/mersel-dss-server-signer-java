package io.mersel.dss.signer.api.services.signature.cades;

import java.io.InputStream;
import java.util.Base64;
import java.util.concurrent.Semaphore;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import io.mersel.dss.signer.api.exceptions.SignatureException;
import io.mersel.dss.signer.api.models.SignResponse;
import io.mersel.dss.signer.api.models.SigningMaterial;
import io.mersel.dss.signer.api.services.crypto.CryptoSignerService;
import io.mersel.dss.signer.api.services.crypto.DigestAlgorithmResolverService;

/**
 * CAdES-BES seviyesinde elektronik imza üreten servis.
 *
 * <p>EU DSS (Digital Signature Services) kütüphanesinin {@link CAdESService} altyapısı
 * üzerinden RFC 5652 (CMS) ve ETSI EN 319 122-1 (CAdES Baseline) gereksinimlerine
 * uygun imzalar oluşturur. XAdES imzalama ile aynı mimari kullanılır:</p>
 *
 * <ul>
 *   <li>{@link CAdESService} — CMS zarfı oluşturma, SigningCertificateV2 attribute yönetimi</li>
 *   <li>{@link CryptoSignerService} — HSM-aware kriptografik imzalama</li>
 *   <li>{@link DigestAlgorithmResolverService} — sertifikaya göre digest algoritma çözümleme</li>
 * </ul>
 *
 * <h3>Eşzamanlılık</h3>
 * <p>PKCS#11 (HSM) session havuzlarının tükenmesini engellemek için eş zamanlı imza
 * sayısı bir {@link Semaphore} ile sınırlandırılır.</p>
 *
 * @see CAdESService
 * @see CryptoSignerService
 * @see DigestAlgorithmResolverService
 */
@Service
public class CAdESSignatureService {

    private static final Logger LOGGER = LoggerFactory.getLogger(CAdESSignatureService.class);

    private final CAdESService cadesService;
    private final CryptoSignerService cryptoSigner;
    private final DigestAlgorithmResolverService digestAlgorithmResolver;
    private final Semaphore semaphore;

    /**
     * @param cadesService            DSS CAdES imza servisi
     * @param cryptoSigner            HSM-aware kriptografik imzalama servisi
     * @param digestAlgorithmResolver sertifikaya göre digest algoritma çözümleme servisi
     * @param signatureSemaphore      eş zamanlı imza işlemi sayısını kısıtlayan semaphore
     */
    public CAdESSignatureService(CAdESService cadesService,
                                 CryptoSignerService cryptoSigner,
                                 DigestAlgorithmResolverService digestAlgorithmResolver,
                                 Semaphore signatureSemaphore) {
        this.cadesService = cadesService;
        this.cryptoSigner = cryptoSigner;
        this.digestAlgorithmResolver = digestAlgorithmResolver;
        this.semaphore = signatureSemaphore;
    }

    /**
     * Verilen stream'deki veriyi okuyarak CAdES-BES imzası üretir.
     *
     * @param dataInputStream imzalanacak dosyanın stream'i — metot içinde tüketilir, kapatılmaz
     * @param detached        {@code true} → ayrık imza, {@code false} → gömülü imza
     * @param material        sertifika zinciri ve private key'i barındıran imzalama materyali
     * @return imzalanmış byte dizisi ve Base64 kodlanmış imza değerini içeren {@link SignResponse}
     * @throws SignatureException imza oluşturma sırasında herhangi bir hata meydana gelirse
     */
    public SignResponse signData(InputStream dataInputStream,
                                 boolean detached,
                                 SigningMaterial material) {
        try {
            byte[] contentBytes = IOUtils.toByteArray(dataInputStream);
            DSSDocument document = new InMemoryDocument(contentBytes, "document.bin");

            DigestAlgorithm digestAlgorithm =
                    digestAlgorithmResolver.resolveDigestAlgorithm(material.getSigningCertificate());

            CAdESSignatureParameters parameters = buildParameters(detached, digestAlgorithm, material);

            semaphore.acquire();
            try {
                ToBeSigned dataToSign = cadesService.getDataToSign(document, parameters);

                SignatureValue signatureValue = cryptoSigner.sign(
                        dataToSign,
                        material.getPrivateKey(),
                        digestAlgorithm);

                DSSDocument signedDocument = cadesService.signDocument(document, parameters, signatureValue);

                byte[] signedBytes = IOUtils.toByteArray(signedDocument.openStream());
                String encodedSignature = Base64.getEncoder().encodeToString(signatureValue.getValue());

                LOGGER.info("CAdES imzası başarıyla oluşturuldu (detached: {})", detached);
                return new SignResponse(signedBytes, encodedSignature);

            } finally {
                semaphore.release();
            }

        } catch (SignatureException e) {
            throw e;
        } catch (Exception e) {
            LOGGER.error("CAdES imzası oluşturulurken hata", e);
            throw new SignatureException("CADES_SIGN_ERROR", "CAdES imzası oluşturulamadı", e);
        }
    }

    /**
     * DSS {@link CAdESSignatureParameters} nesnesini oluşturur.
     *
     * <p>Signature level {@code CAdES_BASELINE_B} olarak ayarlanır; bu seviye
     * CAdES-BES'e karşılık gelir ve {@code SigningCertificateV2} attribute'ünü
     * otomatik olarak ekler.</p>
     *
     * @param detached        ayrık imza mı
     * @param digestAlgorithm kullanılacak digest algoritması
     * @param material        imzalama materyali
     * @return yapılandırılmış CAdES parametreleri
     */
    private CAdESSignatureParameters buildParameters(boolean detached,
                                                     DigestAlgorithm digestAlgorithm,
                                                     SigningMaterial material) {
        CAdESSignatureParameters parameters = new CAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        parameters.setSignaturePackaging(
                detached ? SignaturePackaging.DETACHED : SignaturePackaging.ENVELOPING);
        parameters.setDigestAlgorithm(digestAlgorithm);
        parameters.setSigningCertificate(material.getPrimaryCertificateToken());
        parameters.setCertificateChain(material.getCertificateTokens());
        return parameters;
    }
}
