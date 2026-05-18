package io.mersel.dss.signer.api.util;

import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Severity;
import io.qameta.allure.SeverityLevel;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * CryptoUtils yardımcı sınıfı test'leri.
 */
@Epic("Crypto Conformance")
@Feature("CryptoUtils — Hex/Base64 Helpers")
@Severity(SeverityLevel.MINOR)
class CryptoUtilsTest {

    @Test
    void testHexEncodeDecode() {
        // Given
        byte[] originalData = "Test Data 123".getBytes();

        // When
        String hexString = CryptoUtils.bytesToHex(originalData);
        byte[] decodedData = CryptoUtils.hexToBytes(hexString);

        // Then
        assertNotNull(hexString);
        assertNotNull(decodedData);
        assertArrayEquals(originalData, decodedData);
    }

    @Test
    void testEmptyByteArray() {
        // Given
        byte[] emptyData = new byte[0];

        // When
        String hexString = CryptoUtils.bytesToHex(emptyData);
        byte[] decodedData = CryptoUtils.hexToBytes(hexString);

        // Then
        assertEquals("", hexString);
        assertNotNull(decodedData);
        assertEquals(0, decodedData.length);
    }

    @Test
    void testNullByteArray() {
        // Given
        byte[] nullData = null;

        // When
        String result = CryptoUtils.bytesToHex(nullData);

        // Then
        assertEquals("", result);
    }

    @Test
    void testInvalidHexString() {
        // When/Then
        assertThrows(IllegalArgumentException.class, () -> {
            CryptoUtils.hexToBytes("GHIJKL");  // Geçersiz hex karakterler
        });
    }

    @Test
    void testHexStringWithSpecialChars() {
        // Given
        byte[] data = new byte[]{0x00, 0x0F, (byte) 0xFF, (byte) 0xAB};

        // When
        String hex = CryptoUtils.bytesToHex(data);
        byte[] decoded = CryptoUtils.hexToBytes(hex);

        // Then
        assertEquals("000FFFAB", hex.toUpperCase());
        assertArrayEquals(data, decoded);
    }
}

