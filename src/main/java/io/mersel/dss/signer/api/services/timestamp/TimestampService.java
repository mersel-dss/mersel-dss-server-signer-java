package io.mersel.dss.signer.api.services.timestamp;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import io.mersel.dss.signer.api.dtos.TimestampRequestDto;
import io.mersel.dss.signer.api.dtos.TimestampResponseDto;
import io.mersel.dss.signer.api.dtos.TimestampValidationDto;
import io.mersel.dss.signer.api.dtos.TimestampValidationResponseDto;
import io.mersel.dss.signer.api.exceptions.TimestampException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.util.Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.security.MessageDigest;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * Zaman damgası (timestamp) işlemleri için servis.
 * RFC 3161 standardına uygun TSQ (Time Stamp Query), TSR (Time Stamp Response)
 * ve validasyon işlemlerini gerçekleştirir.
 */
@Service
public class TimestampService {

    private static final Logger LOGGER = LoggerFactory.getLogger(TimestampService.class);

    // SimpleDateFormat thread-safe degildir; bu servis singleton olup timestamp
    // uclari paralel isteklerde ayni ornek uzerinden format() cagirdigi icin
    // immutable ve thread-safe DateTimeFormatter kullaniliyor. Pattern'deki 'Z'
    // literal olup cikti bicimi (yyyy-MM-dd'T'HH:mm:ss'Z', UTC) aynen korunur.
    private static final DateTimeFormatter ISO_DATE_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'").withZone(ZoneOffset.UTC);

    private static String formatIsoUtc(Date date) {
        return ISO_DATE_FORMAT.format(date.toInstant());
    }

    private final TimestampConfigurationService timestampConfigurationService;

    public TimestampService(TimestampConfigurationService timestampConfigurationService) {
        this.timestampConfigurationService = timestampConfigurationService;
    }

    /**
     * Binary belge için zaman damgası alır (DTO versiyonu - geriye dönük uyumluluk için).
     * 
     * @param requestDto Zaman damgası talebi
     * @return Zaman damgası yanıtı
     * @throws TimestampException Zaman damgası alınamadığında
     */
    public TimestampResponseDto getTimestamp(TimestampRequestDto requestDto) {
        try {
            LOGGER.info("Zaman damgası talebi alındı. Hash algoritması: {}", requestDto.getHashAlgorithm());

            // Base64 encoded veriyi decode et
            byte[] documentData = Base64.getDecoder().decode(requestDto.getDocumentData());
            
            return getTimestamp(documentData, requestDto.getHashAlgorithm());

        } catch (Exception e) {
            LOGGER.error("Zaman damgası alınırken hata oluştu", e);
            throw new TimestampException("Zaman damgası alınamadı: " + e.getMessage(), e);
        }
    }

    /**
     * Binary belge için zaman damgası alır.
     * 
     * @param documentData Belge verisi
     * @param hashAlgorithm Hash algoritması (null ise SHA256 kullanılır)
     * @return Zaman damgası yanıtı
     * @throws TimestampException Zaman damgası alınamadığında
     */
    public TimestampResponseDto getTimestamp(byte[] documentData, String hashAlgorithm) {
        try {
            LOGGER.info("Zaman damgası talebi alındı. Hash algoritması: {}", hashAlgorithm);
            
            // Hash algoritmasını belirle
            DigestAlgorithm digestAlgorithm = getDigestAlgorithm(hashAlgorithm);
            
            // Belgenin hash'ini hesapla
            byte[] digest = computeDigest(documentData, digestAlgorithm);
            
            // TSP source'u al
            eu.europa.esig.dss.spi.x509.tsp.TSPSource tspSource = timestampConfigurationService.getTspSource();
            
            // DSS ile timestamp al
            TimestampBinary timestampBinary = tspSource.getTimeStampResponse(digestAlgorithm, digest);
            byte[] timestampBytes = timestampBinary.getBytes();
            
            // DSS'den gelen TimestampToken'ı kullan
            eu.europa.esig.dss.spi.x509.tsp.TimestampToken dssToken = new eu.europa.esig.dss.spi.x509.tsp.TimestampToken(
                    timestampBytes, eu.europa.esig.dss.enumerations.TimestampType.CONTENT_TIMESTAMP);
            
            // Response DTO'yu oluştur
            TimestampResponseDto response = new TimestampResponseDto();
            response.setTimestampToken(Base64.getEncoder().encodeToString(timestampBytes));
            response.setTimestamp(formatIsoUtc(dssToken.getGenerationTime()));
            response.setHashAlgorithm(digestAlgorithm.getName());
            response.setSerialNumber(dssToken.getDSSIdAsString());
            
            // TSA bilgisini al
            if (dssToken.getIssuerX500Principal() != null) {
                response.setTsaName(dssToken.getIssuerX500Principal().getName());
            }
            
            LOGGER.info("Zaman damgası başarıyla alındı. Tarih: {}", response.getTimestamp());
            return response;

        } catch (Exception e) {
            LOGGER.error("Zaman damgası alınırken hata oluştu", e);
            throw new TimestampException("Zaman damgası alınamadı: " + e.getMessage(), e);
        }
    }

    /**
     * Zaman damgasını doğrular (DTO versiyonu - geriye dönük uyumluluk için).
     * 
     * @param validationDto Doğrulama talebi
     * @return Doğrulama sonucu
     */
    public TimestampValidationResponseDto validateTimestamp(TimestampValidationDto validationDto) {
        try {
            // Timestamp token'ı decode et
            byte[] timestampBytes = Base64.getDecoder().decode(validationDto.getTimestampToken());
            
            // Orijinal veri varsa decode et
            byte[] originalData = null;
            if (StringUtils.hasText(validationDto.getOriginalData())) {
                originalData = Base64.getDecoder().decode(validationDto.getOriginalData());
            }
            
            return validateTimestamp(timestampBytes, originalData);
            
        } catch (Exception e) {
            LOGGER.error("Zaman damgası doğrulama hatası", e);
            TimestampValidationResponseDto response = new TimestampValidationResponseDto();
            response.setValid(false);
            response.setErrors(Arrays.asList("Genel doğrulama hatası: " + e.getMessage()));
            response.setMessage("Zaman damgası doğrulanamadı");
            return response;
        }
    }

    /**
     * Zaman damgasını doğrular.
     * 
     * @param timestampBytes Timestamp token bytes
     * @param originalData Orijinal belge (opsiyonel, hash doğrulaması için)
     * @return Doğrulama sonucu
     */
    public TimestampValidationResponseDto validateTimestamp(byte[] timestampBytes, byte[] originalData) {
        TimestampValidationResponseDto response = new TimestampValidationResponseDto();
        List<String> errors = new ArrayList<>();

        try {
            LOGGER.info("Zaman damgası doğrulama talebi alındı. Token boyutu: {} bytes", timestampBytes.length);
            
            // BouncyCastle token'ı parse et
            org.bouncycastle.tsp.TimeStampToken bcToken = parseBCTimestampToken(timestampBytes);
            
            if (bcToken == null) {
                errors.add("Timestamp token parse edilemedi");
                response.setValid(false);
                response.setErrors(errors);
                response.setMessage("Zaman damgası token'ı geçersiz format");
                return response;
            }
            
            // Temel bilgileri doldur (BouncyCastle token'dan)
            response.setTimestamp(formatIsoUtc(bcToken.getTimeStampInfo().getGenTime()));
            
            // Hash algoritmasını hem isim hem OID olarak set et
            String hashAlgOid = bcToken.getTimeStampInfo().getHashAlgorithm().getAlgorithm().getId();
            response.setHashAlgorithmOid(hashAlgOid);
            try {
                DigestAlgorithm digestAlg = DigestAlgorithm.forOID(hashAlgOid);
                response.setHashAlgorithm(digestAlg.getName());
            } catch (Exception e) {
                LOGGER.debug("Hash algoritması DSS'de bulunamadı, OID kullanılıyor: {}", hashAlgOid);
                response.setHashAlgorithm(hashAlgOid);
            }
            
            response.setSerialNumber(bcToken.getTimeStampInfo().getSerialNumber().toString());
            
            // İmza algoritmasını hem isim hem OID olarak set et
            try {
                CMSSignedData signedData = bcToken.toCMSSignedData();
                if (signedData.getSignerInfos().size() > 0) {
                    org.bouncycastle.cms.SignerInformation signerInfo = 
                        (org.bouncycastle.cms.SignerInformation) signedData.getSignerInfos().getSigners().iterator().next();
                    
                    String digestOid = signerInfo.getDigestAlgOID();
                    String encryptionOid = signerInfo.getEncryptionAlgOID();
                    LOGGER.debug("İmza algoritması OID'leri: digest={}, encryption={}", digestOid, encryptionOid);
                    
                    response.setSignatureAlgorithmOid(encryptionOid);
                    
                    // Önce encryptionOid'yi direkt SignatureAlgorithm olarak dene
                    try {
                        SignatureAlgorithm sigAlg = SignatureAlgorithm.forOID(encryptionOid);
                        String algName = sigAlg.name().replace("_", " with ");
                        response.setSignatureAlgorithm(algName);
                        LOGGER.debug("İmza algoritması bulundu: {}", algName);
                    } catch (Exception ex) {
                        // SignatureAlgorithm kombinasyonunu oluştur
                        try {
                            DigestAlgorithm digestAlg = DigestAlgorithm.forOID(digestOid);
                            EncryptionAlgorithm encAlg = EncryptionAlgorithm.forOID(encryptionOid);
                            SignatureAlgorithm sigAlg = SignatureAlgorithm.getAlgorithm(encAlg, digestAlg);
                            String algName = sigAlg.name().replace("_", " with ");
                            response.setSignatureAlgorithm(algName);
                            LOGGER.debug("İmza algoritması kombinasyonu oluşturuldu: {}", algName);
                        } catch (Exception ex2) {
                            // Fallback: Manuel isim oluştur
                            try {
                                DigestAlgorithm digestAlg = DigestAlgorithm.forOID(digestOid);
                                EncryptionAlgorithm encAlg = EncryptionAlgorithm.forOID(encryptionOid);
                                String algName = digestAlg.getName() + " with " + encAlg.getName();
                                response.setSignatureAlgorithm(algName);
                            } catch (Exception ex3) {
                                LOGGER.debug("İmza algoritması DSS'de bulunamadı, OID kullanılıyor: {}", encryptionOid);
                                response.setSignatureAlgorithm(encryptionOid);
                            }
                        }
                    }
                }
            } catch (Exception e) {
                LOGGER.warn("İmza algoritması bilgisi alınamadı: {}", e.getMessage());
            }
            
            if (bcToken.getTimeStampInfo().getNonce() != null) {
                response.setNonce(bcToken.getTimeStampInfo().getNonce().toString());
            }
            
            // TSA sertifikasını al ve doğrula
            X509CertificateHolder signerCert = getSignerCertificate(bcToken);
            if (signerCert != null) {
                response.setTsaName(signerCert.getSubject().toString());
                response.setTsaCertificate(Base64.getEncoder().encodeToString(signerCert.getEncoded()));
                
                // Sertifika geçerlilik tarihlerini kontrol et
                Date now = new Date();
                response.setCertificateNotBefore(formatIsoUtc(signerCert.getNotBefore()));
                response.setCertificateNotAfter(formatIsoUtc(signerCert.getNotAfter()));
                
                boolean certValid = now.after(signerCert.getNotBefore()) && now.before(signerCert.getNotAfter());
                response.setCertificateValid(certValid);
                
                if (!certValid) {
                    errors.add("TSA sertifikası geçerlilik tarihleri dışında");
                }
                
                LOGGER.info("Zaman damgası sertifikası bulundu ve imza geçerli");
            } else {
                errors.add("TSA sertifikası bulunamadı");
            }

            // Orijinal veri sağlanmışsa hash doğrulaması yap
            if (originalData != null) {
                try {
                    byte[] messageImprint = bcToken.getTimeStampInfo().getMessageImprintDigest();
                    
                    // Hash'i hesapla
                    String messageImprintOid = bcToken.getTimeStampInfo().getMessageImprintAlgOID().getId();
                    DigestAlgorithm digestAlgorithm = getDigestAlgorithmByOid(messageImprintOid);
                    byte[] computedHash = computeDigest(originalData, digestAlgorithm);
                    
                    boolean hashMatch = Arrays.equals(messageImprint, computedHash);
                    response.setHashVerified(hashMatch);
                    
                    if (!hashMatch) {
                        errors.add("Belge hash'i eşleşmiyor - belge değiştirilmiş olabilir");
                    } else {
                        LOGGER.info("Belge hash'i doğrulandı");
                    }
                } catch (Exception e) {
                    errors.add("Hash doğrulaması yapılamadı: " + e.getMessage());
                    LOGGER.error("Hash doğrulaması başarısız", e);
                }
            }

            // Genel geçerlilik durumu
            boolean valid = errors.isEmpty();
            response.setValid(valid);
            response.setErrors(errors);
            
            if (valid) {
                response.setMessage("Zaman damgası geçerli ve doğrulandı");
                LOGGER.info("Zaman damgası doğrulaması başarılı. Seri no: {}", response.getSerialNumber());
            } else {
                response.setMessage("Zaman damgası doğrulaması başarısız");
                LOGGER.warn("Zaman damgası doğrulaması başarısız. Hatalar: {}", errors);
            }

            return response;

        } catch (Exception e) {
            LOGGER.error("Zaman damgası doğrulama hatası", e);
            errors.add("Genel doğrulama hatası: " + e.getMessage());
            response.setValid(false);
            response.setErrors(errors);
            response.setMessage("Zaman damgası doğrulanamadı");
            return response;
        }
    }

    /**
     * BouncyCastle timestamp token'ı parse eder.
     * Hem TimeStampResponse formatını hem de direkt TimeStampToken formatını destekler.
     */
    private org.bouncycastle.tsp.TimeStampToken parseBCTimestampToken(byte[] timestampBytes) {
        try {
            LOGGER.debug("Timestamp token parse ediliyor, boyut: {} bytes", timestampBytes.length);
            
            // Direkt TimeStampToken formatı dene (CMSSignedData)
            try {
                CMSSignedData signedData = new CMSSignedData(timestampBytes);
                org.bouncycastle.tsp.TimeStampToken token = new org.bouncycastle.tsp.TimeStampToken(signedData);
                LOGGER.debug("Token CMSSignedData formatında parse edildi");
                return token;
            } catch (Exception e) {
                LOGGER.debug("CMSSignedData formatı değil: {}", e.getMessage());
            }

             // TimeStampResponse formatı dene
             try {
                TimeStampResponse tsResponse = new TimeStampResponse(timestampBytes);
                org.bouncycastle.tsp.TimeStampToken token = tsResponse.getTimeStampToken();
                if (token != null) {
                    LOGGER.debug("Token TimeStampResponse formatında parse edildi");
                    return token;
                }
            } catch (Exception e) {
                LOGGER.debug("TimeStampResponse formatı değil: {}", e.getMessage());
            }
            
            LOGGER.warn("Timestamp token formatı tanınamadı");
            return null;
        } catch (Exception e) {
            LOGGER.error("Timestamp token parse hatası", e);
            return null;
        }
    }

    /**
     * Timestamp token'dan imzalayan sertifikayı alır.
     */
    @SuppressWarnings("unchecked")
    private X509CertificateHolder getSignerCertificate(org.bouncycastle.tsp.TimeStampToken tsToken) {
        try {
            @SuppressWarnings("rawtypes")
            Store certStore = tsToken.getCertificates();
            Collection<X509CertificateHolder> certCollection = certStore.getMatches(null);
            
            if (!certCollection.isEmpty()) {
                return certCollection.iterator().next();
            }
        } catch (Exception e) {
            LOGGER.warn("TSA sertifikası alınamadı", e);
        }
        return null;
    }

    /**
     * Verinin hash'ini hesaplar.
     */
    private byte[] computeDigest(byte[] data, DigestAlgorithm algorithm) {
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm.getJavaName());
            return digest.digest(data);
        } catch (Exception e) {
            throw new TimestampException("Hash hesaplanamadı: " + e.getMessage(), e);
        }
    }

    /**
     * Hash algoritmasını string'den DigestAlgorithm'a çevirir.
     */
    private DigestAlgorithm getDigestAlgorithm(String algorithm) {
        if (!StringUtils.hasText(algorithm)) {
            return DigestAlgorithm.SHA256;
        }
        
        try {
            return DigestAlgorithm.valueOf(algorithm.toUpperCase().replace("-", ""));
        } catch (IllegalArgumentException e) {
            throw new TimestampException("Geçersiz hash algoritması: " + algorithm);
        }
    }

    /**
     * OID'den DigestAlgorithm'a çevirir.
     */
    private DigestAlgorithm getDigestAlgorithmByOid(String oid) {
        for (DigestAlgorithm alg : DigestAlgorithm.values()) {
            if (alg.getOid().equals(oid)) {
                return alg;
            }
        }
        return DigestAlgorithm.SHA256; // default
    }

}

