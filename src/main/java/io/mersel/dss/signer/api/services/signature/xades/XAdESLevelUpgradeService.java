package io.mersel.dss.signer.api.services.signature.xades;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.signature.XAdESLevelA;
import io.mersel.dss.signer.api.models.enums.DocumentType;
import io.mersel.dss.signer.api.services.timestamp.TimestampConfigurationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.xml.crypto.dsig.CanonicalizationMethod;

/**
 * XAdES imza seviyelerini yükselten servis.
 * e-Arşiv Raporları ve e-Bilet Raporları için XAdES-B'den XAdES-A'ya yükseltme yapar.
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
     * @return Seviyesi yükseltilmiş belge (veya değişiklik yapılmamışsa orijinal)
     */
    public DSSDocument upgradeIfNeeded(DSSDocument signedDocument,
                                      DocumentType documentType,
                                      XAdESSignatureParameters baseParameters) {
        if (documentType != DocumentType.EArchiveReport && documentType != DocumentType.EBiletReport) {
            return signedDocument;
        }

        if (!timestampService.isAvailable()) {
            LOGGER.warn("Timestamp servisi yapılandırılmamış. {} için XAdES-A yükseltmesi atlanıyor.", documentType);
            return signedDocument;
        }

        try {
            LOGGER.info("{} için XAdES-A seviyesine yükseltiliyor...", documentType);

            // Timestamp parametrelerini yapılandır
            XAdESTimestampParameters tsParams = new XAdESTimestampParameters();
            tsParams.setCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS);
            tsParams.setDigestAlgorithm(DigestAlgorithm.SHA256);

            baseParameters.setArchiveTimestampParameters(tsParams);
            baseParameters.setSignatureTimestampParameters(tsParams);
            baseParameters.setContentTimestampParameters(tsParams);
            baseParameters.setEn319132(false);

            // XAdES-A seviyesine yükselt
            XAdESLevelA levelA = new XAdESLevelA(certificateVerifier);
            levelA.setTspSource(timestampService.getTspSource());
            
            DSSDocument upgradedDocument = levelA.extendSignatures(signedDocument, baseParameters);

            LOGGER.info("{} başarıyla XAdES-A seviyesine yükseltildi", documentType);
            return upgradedDocument;

        } catch (Exception ex) {
            LOGGER.error("XAdES seviye yükseltme başarısız. XAdES-B seviyesi korunuyor.", ex);
            // Hata durumunda orijinal belgeyi döndür (XAdES-B)
            return signedDocument;
        }
    }
}

