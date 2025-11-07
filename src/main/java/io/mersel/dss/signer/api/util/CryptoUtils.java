package io.mersel.dss.signer.api.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;

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
     * 
     * @param privateKey İmzalama için kullanılacak private key
     * @return Signature algoritması (örn: "SHA256withRSA", "SHA256withECDSA")
     */
    public static String getSignatureAlgorithm(PrivateKey privateKey) {
        if (privateKey instanceof RSAPrivateKey) {
            LOGGER.debug("RSA private key algılandı, SHA256withRSA kullanılacak");
            return "SHA256withRSA";
        } else if (privateKey instanceof ECPrivateKey) {
            LOGGER.debug("EC private key algılandı, SHA256withECDSA kullanılacak");
            return "SHA256withECDSA";
        } else {
            // Fallback: Algorithm adından çıkarsama yap
            String algorithm = privateKey.getAlgorithm();
            LOGGER.warn("Bilinmeyen private key tipi: {}, algorithm: {}", 
                privateKey.getClass().getName(), algorithm);
            
            if ("EC".equalsIgnoreCase(algorithm) || "ECDSA".equalsIgnoreCase(algorithm)) {
                return "SHA256withECDSA";
            } else if ("RSA".equalsIgnoreCase(algorithm)) {
                return "SHA256withRSA";
            }
            
            // Son çare: Default RSA
            LOGGER.warn("Desteklenmeyen key tipi, SHA256withRSA kullanılacak");
            return "SHA256withRSA";
        }
    }
}

