package io.mersel.dss.signer.api.services.signature.xades;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.signature.XAdESLevelA;
import io.mersel.dss.signer.api.exceptions.TimestampException;
import io.mersel.dss.signer.api.models.enums.DocumentType;
import io.mersel.dss.signer.api.services.timestamp.TimestampConfigurationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.xml.crypto.dsig.CanonicalizationMethod;

/**
 * XAdES imza seviyelerini yükselten servis.
 * e-Arşiv Raporları ve e-Bilet Raporları için XAdES-B'den XAdES-A'ya yükseltme yapar.
 *
 * <h3>Fail-fast sözleşmesi</h3>
 * <p>e-Arşiv ve e-Bilet raporları GİB tarafına XAdES-A (archival) seviyesinde
 * gönderilmek <em>zorundadır</em> — TSA imzası ve archive timestamp olmadan
 * üretilen rapor 10 yıllık saklama gereğine uymaz ve karşı tarafça reddedilir.
 * Bu yüzden:</p>
 * <ul>
 *   <li>Timestamp sunucusu yapılandırılmamışsa (TS_SERVER_HOST boş)
 *       sessiz fallback yerine {@link TimestampException} fırlatılır
 *       — caller HTTP 503 + {@code TIMESTAMP_ERROR} alır.</li>
 *   <li>XAdES-A yükseltmesi sırasında oluşan herhangi bir hata da
 *       {@link TimestampException} olarak yukarı bubble edilir; XAdES-B
 *       seviyesinde "yarım imzalı" rapor üretilmez.</li>
 * </ul>
 * <p>Önceki davranışta hata durumlarında WARN loglayıp orijinal XAdES-B belgesi
 * döndürülüyordu; bu sessizce uyumsuz rapor üretiyordu (silent data corruption
 * pattern). Bu sınıf artık fail-fast garantisi verir.</p>
 */
@Service
public class XAdESLevelUpgradeService {

    private static final Logger LOGGER = LoggerFactory.getLogger(XAdESLevelUpgradeService.class);

    private final CertificateVerifier certificateVerifier;
    private final TimestampConfigurationService timestampService;

    public XAdESLevelUpgradeService(CertificateVerifier certificateVerifier,
                                   TimestampConfigurationService timestampService) {
        this.certificateVerifier = certificateVerifier;
        this.timestampService = timestampService;
    }

    /**
     * Belge tipine göre imza seviyesini yükseltir.
     * e-Arşiv Raporları ve e-Bilet Raporları için XAdES-A yükseltmesi yapılır.
     *
     * @param signedDocument İmzalanmış belge
     * @param documentType Belge tipi
     * @param baseParameters Temel imza parametreleri
     * @return Seviyesi yükseltilmiş belge (XAdES-A); upgrade gerekmeyen belge tipleri için orijinal
     * @throws TimestampException XAdES-A gerektiren belge tipi için timestamp sunucusu
     *         yapılandırılmamışsa veya yükseltme işlemi başarısız olursa
     */
    public DSSDocument upgradeIfNeeded(DSSDocument signedDocument,
                                      DocumentType documentType,
                                      XAdESSignatureParameters baseParameters) {
        if (documentType != DocumentType.EArchiveReport && documentType != DocumentType.EBiletReport) {
            return signedDocument;
        }

        if (!timestampService.isAvailable()) {
            String message = String.format(
                    "%s için XAdES-A yükseltmesi zorunludur ancak timestamp sunucusu yapılandırılmamış. "
                            + "TS_SERVER_HOST property'sini ayarlayın.",
                    documentType);
            LOGGER.error(message);
            throw new TimestampException(message);
        }

        try {
            LOGGER.info("{} için XAdES-A seviyesine yükseltiliyor...", documentType);

            XAdESTimestampParameters tsParams = new XAdESTimestampParameters();
            tsParams.setCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS);
            tsParams.setDigestAlgorithm(DigestAlgorithm.SHA256);

            baseParameters.setArchiveTimestampParameters(tsParams);
            baseParameters.setSignatureTimestampParameters(tsParams);
            baseParameters.setContentTimestampParameters(tsParams);
            baseParameters.setEn319132(false);

            XAdESLevelA levelA = new XAdESLevelA(certificateVerifier);
            levelA.setTspSource(timestampService.getTspSource());

            DSSDocument upgradedDocument = levelA.extendSignatures(signedDocument, baseParameters);

            LOGGER.info("{} başarıyla XAdES-A seviyesine yükseltildi", documentType);
            return upgradedDocument;

        } catch (TimestampException ex) {
            // TimestampConfigurationService.getTspSource() zaten doğru exception'ı fırlatır;
            // tekrar sarmalamadan bubble et ki orijinal hata kodu/mesajı korunsun.
            throw ex;
        } catch (Exception ex) {
            String message = String.format(
                    "%s için XAdES-A yükseltmesi başarısız. Belge XAdES-B seviyesinde bırakılamaz; "
                            + "imza işlemi reddediliyor.",
                    documentType);
            LOGGER.error(message, ex);
            throw new TimestampException(message, ex);
        }
    }
}

