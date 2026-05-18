package io.mersel.dss.signer.api.models;

import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Severity;
import io.qameta.allure.SeverityLevel;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ErrorModel test'leri.
 */
@Epic("HTTP API Contract")
@Feature("Error Model")
@Severity(SeverityLevel.MINOR)
class ErrorModelTest {

    @Test
    void testErrorModelCreation() {
        // Given
        String errorCode = "TEST_ERROR";
        String message = "Test error message";

        // When
        ErrorModel errorModel = new ErrorModel(errorCode, message);

        // Then
        assertNotNull(errorModel);
        assertEquals(errorCode, errorModel.getCode());
        assertEquals(message, errorModel.getMessage());
    }

    @Test
    void testErrorModelWithNullValues() {
        // When
        ErrorModel errorModel = new ErrorModel(null, null);

        // Then
        assertNotNull(errorModel);
        assertNull(errorModel.getCode());
        assertNull(errorModel.getMessage());
    }

    @Test
    void testErrorModelSetters() {
        // Given
        ErrorModel errorModel = new ErrorModel("CODE1", "Message1");

        // When
        errorModel.setCode("CODE2");
        errorModel.setMessage("Message2");

        // Then
        assertEquals("CODE2", errorModel.getCode());
        assertEquals("Message2", errorModel.getMessage());
    }

    @Test
    void testErrorModelToString() {
        // Given
        ErrorModel errorModel = new ErrorModel("ERR_001", "Test error");

        // When
        String toString = errorModel.toString();

        // Then
        assertNotNull(toString);
        // toString varsayılan Object.toString() kullanıyor, class adı içermeli
        assertTrue(toString.contains("ErrorModel"));
    }
}

