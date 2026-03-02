package io.mersel.dss.signer.api.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Locale;

/**
 * Kriptografik ve encoding işlemleri için yardımcı metodlar.
 */
public final class CryptoUtils {

    private static final Logger LOGGER = LoggerFactory.getLogger(CryptoUtils.class);

    private CryptoUtils() {
        // Utility class - instantiation engellendi
    }

    /**
     * Byte array'i hexadecimal string'e çevirir.
     *
     * @param bytes Çevrilecek byte array
     * @return Hexadecimal string
     */
    public static String bytesToHex(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * Hexadecimal string'i byte array'e çevirir.
     *
     * @param hex Hexadecimal string
     * @return Byte array
     * @throws IllegalArgumentException Geçersiz hex string için
     */
    public static byte[] hexToBytes(String hex) {
        if (hex == null || hex.isEmpty()) {
            return new byte[0];
        }
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException("Hex string uzunluğu çift sayı olmalı");
        }
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            int digit1 = Character.digit(hex.charAt(i), 16);
            int digit2 = Character.digit(hex.charAt(i + 1), 16);
            if (digit1 == -1 || digit2 == -1) {
                throw new IllegalArgumentException("Geçersiz hexadecimal karakter: " + hex.substring(i, i + 2));
            }
            data[i / 2] = (byte) ((digit1 << 4) + digit2);
        }
        return data;
    }

    /**
     * Private key tipine göre uygun signature algoritmasını döndürür.
     * RSA ve EC (Elliptic Curve) key'leri destekler.
     * EC key boyutuna göre SHA256/SHA384/SHA512 otomatik seçilir.
     * 
     * @param privateKey İmzalama için kullanılacak private key
     * @return Signature algoritması (örn: "SHA256withRSA", "SHA384withECDSA")
     */
    public static String getSignatureAlgorithm(PrivateKey privateKey) {
        if (privateKey instanceof RSAPrivateKey) {
            LOGGER.debug("RSA private key algılandı, SHA256withRSA kullanılacak");
            return "SHA256withRSA";
        } else if (privateKey instanceof ECPrivateKey) {
            String ecAlgorithm = resolveECSignatureAlgorithm((ECPrivateKey) privateKey);
            LOGGER.debug("EC private key algılandı, {} kullanılacak", ecAlgorithm);
            return ecAlgorithm;
        } else {
            String algorithm = privateKey.getAlgorithm();
            LOGGER.warn("Bilinmeyen private key tipi: {}, algorithm: {}", 
                privateKey.getClass().getName(), algorithm);
            
            if ("EC".equalsIgnoreCase(algorithm) || "ECDSA".equalsIgnoreCase(algorithm)) {
                return "SHA256withECDSA";
            } else if ("RSA".equalsIgnoreCase(algorithm)) {
                return "SHA256withRSA";
            }
            
            LOGGER.warn("Desteklenmeyen key tipi, SHA256withRSA kullanılacak");
            return "SHA256withRSA";
        }
    }

    /**
     * Sertifika ve key tipine göre uygun signature algoritmasını döndürür.
     * Sertifikanın kendi sigAlgName bilgisini kullanarak doğru hash boyutunu belirler.
     */
    public static String getSignatureAlgorithm(PrivateKey privateKey, 
                                                java.security.cert.X509Certificate certificate) {
        if (certificate != null) {
            java.security.PublicKey publicKey = certificate.getPublicKey();
            String certSigAlg = certificate.getSigAlgName();
            
            if (publicKey instanceof RSAPublicKey) {
                // Açık anahtar RSA ise, sertifika algoritmasından SHA kısmını al ve RSA ile birleştir
                if (certSigAlg != null && !certSigAlg.isEmpty()) {
                    String shaPrefix = extractShaPrefix(certSigAlg);
                    String result = shaPrefix + "withRSA";
                    LOGGER.debug("Sertifika RSA açık anahtara sahip, algoritma düzeltildi: {} -> {}", certSigAlg, result);
                    return result;
                }
                return "SHA256withRSA";
            } else if (publicKey instanceof ECPublicKey) {
                if (certSigAlg != null && !certSigAlg.isEmpty()) {
                    LOGGER.debug("Sertifika EC açık anahtara sahip, sertifika algoritması kullanılacak: {}", certSigAlg);
                    return certSigAlg;
                }
            }
        }
        return getSignatureAlgorithm(privateKey);
    }

    private static String extractShaPrefix(String sigAlgorithm) {
        String upper = sigAlgorithm.toUpperCase(Locale.ENGLISH);
        if (upper.startsWith("SHA")) {
            int idx = upper.indexOf("WITH");
            if (idx > 0) {
                return upper.substring(0, idx);
            }
        }
        return "SHA256";
    }
    /**
     * EC key boyutuna göre uygun hash algoritmasını seçer.
     * P-256 -> SHA256, P-384 -> SHA384, P-521 -> SHA512
     */
    private static String resolveECSignatureAlgorithm(ECPrivateKey ecKey) {
        try {
            java.security.spec.ECParameterSpec params = ecKey.getParams();
            if (params != null) {
                int fieldSize = params.getOrder().bitLength();
                if (fieldSize <= 256) {
                    return "SHA256withECDSA";
                } else if (fieldSize <= 384) {
                    return "SHA384withECDSA";
                } else {
                    return "SHA512withECDSA";
                }
            }
        } catch (Exception e) {
            LOGGER.debug("EC parametre okunamadı, SHA256withECDSA kullanılacak", e);
        }
        return "SHA256withECDSA";
    }
}

