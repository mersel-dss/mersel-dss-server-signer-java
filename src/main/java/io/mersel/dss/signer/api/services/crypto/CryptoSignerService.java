package io.mersel.dss.signer.api.services.crypto;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import io.mersel.dss.signer.api.exceptions.SignatureException;
import io.mersel.dss.signer.api.models.SigningBackend;
import io.mersel.dss.signer.api.models.SigningMaterial;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.security.Signature;

/**
 * DSS'in 2-aşamalı imza akışında {@code SignatureValue} üreten düşük seviye
 * servis. İki arka ucu da tek tip API'nin arkasına alır:
 *
 * <ul>
 *   <li><b>PFX (JCA)</b> → {@link Signature#getInstance(String)} üzerinden
 *       yazılım imza, mevcut davranış.</li>
 *   <li><b>HSM (PKCS#11 / IAIK)</b> →
 *       {@link SigningBackend#sign(byte[], SignatureAlgorithm)} ile token'da
 *       C_Sign çağrısı. SunPKCS11'in P11Key alias-mapping katmanına
 *       bağımlı değildir.</li>
 * </ul>
 *
 * <p>Çağıran taraflar (XAdES / CAdES / WS-Security servisleri) sadece
 * {@link #sign(ToBeSigned, SigningMaterial, DigestAlgorithm)} metodunu çağırır;
 * arka uç seçimi {@link SigningMaterial} içindeki {@link SigningBackend}
 * kontratına delege edilir.</p>
 */
@Service
public class CryptoSignerService {

    private static final Logger LOGGER = LoggerFactory.getLogger(CryptoSignerService.class);

    private final SignatureAlgorithmResolverService algorithmResolver;

    public CryptoSignerService(SignatureAlgorithmResolverService algorithmResolver) {
        this.algorithmResolver = algorithmResolver;
    }

    /**
     * Birleşik imzalama girişi: imzalanacak algoritmayı sertifikadan çözer,
     * sonra gerçek imza operasyonunu material içindeki arka uç kontratına
     * delege eder.
     *
     * @param dataToSign DSS'in {@code getDataToSign()} çıktısı
     * @param material   imzalama materyali (PFX veya HSM)
     * @param digestAlgorithm sertifikaya göre çözümlenmiş digest algoritması
     * @return DSS {@code signDocument(signatureValue)}'a verilecek imza değeri
     */
    public SignatureValue sign(ToBeSigned dataToSign,
                               SigningMaterial material,
                               DigestAlgorithm digestAlgorithm) {
        try {
            SignatureAlgorithm signatureAlgorithm =
                algorithmResolver.determineSignatureAlgorithm(
                    material.getSigningCertificate(), digestAlgorithm);

            byte[] signatureBytes = material.sign(dataToSign.getBytes(), signatureAlgorithm);

            LOGGER.debug("İmza başarıyla oluşturuldu. Backend: {}, Algoritma: {}",
                material.getBackendName(), signatureAlgorithm);
            return new SignatureValue(signatureAlgorithm, signatureBytes);
        } catch (SignatureException e) {
            throw e;
        } catch (Exception e) {
            throw new SignatureException("İmza oluşturulamadı", e);
        }
    }
}
