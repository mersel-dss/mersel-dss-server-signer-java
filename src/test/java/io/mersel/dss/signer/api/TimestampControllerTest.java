package io.mersel.dss.signer.api;

import io.mersel.dss.signer.api.controllers.TimestampController;
import io.mersel.dss.signer.api.dtos.TimestampResponseDto;
import io.mersel.dss.signer.api.dtos.TimestampStatusDto;
import io.mersel.dss.signer.api.dtos.TimestampValidationResponseDto;
import io.mersel.dss.signer.api.exceptions.TimestampException;
import io.mersel.dss.signer.api.services.notification.SignerNotifier;
import io.mersel.dss.signer.api.services.timestamp.TimestampConfigurationService;
import io.mersel.dss.signer.api.services.timestamp.TimestampService;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Severity;
import io.qameta.allure.SeverityLevel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockMultipartFile;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * TimestampController için unit testler.
 */
@ExtendWith(MockitoExtension.class)
@Epic("HTTP API Contract")
@Feature("Timestamp Endpoint")
@Severity(SeverityLevel.NORMAL)
public class TimestampControllerTest {

    @Mock
    private TimestampService timestampService;

    @Mock
    private TimestampConfigurationService timestampConfigurationService;

    @Mock
    private SignerNotifier signerNotifier;

    private TimestampController timestampController;

    @BeforeEach
    void setUp() {
        timestampController = new TimestampController(
            timestampService, timestampConfigurationService, signerNotifier,
            new io.mersel.dss.signer.api.services.metrics.SignatureMetrics(
                new io.micrometer.core.instrument.simple.SimpleMeterRegistry()));
    }

    @Test
    void testGetTimestamp_whenServiceNotConfigured_shouldReturnBadRequest() throws Exception {
        when(timestampConfigurationService.isAvailable()).thenReturn(false);

        MockMultipartFile file = new MockMultipartFile(
                "document",
                "test.txt",
                "text/plain",
                "test content".getBytes()
        );

        ResponseEntity<?> response = timestampController.getTimestamp(file, "SHA256");

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        verify(timestampConfigurationService, times(1)).isAvailable();
        verify(timestampService, never()).getTimestamp(any(byte[].class), anyString());
    }

    @Test
    void testGetTimestamp_whenServiceConfigured_shouldCallService() throws Exception {
        when(timestampConfigurationService.isAvailable()).thenReturn(true);

        TimestampResponseDto mockResponse = new TimestampResponseDto();
        mockResponse.setTimestampToken(java.util.Base64.getEncoder().encodeToString("mock-token".getBytes()));
        mockResponse.setTimestamp("2025-11-07T14:30:00Z");
        mockResponse.setSerialNumber("123456");
        mockResponse.setTsaName("CN=TSA");
        mockResponse.setHashAlgorithm("SHA256");

        when(timestampService.getTimestamp(any(byte[].class), anyString()))
            .thenReturn(mockResponse);

        MockMultipartFile file = new MockMultipartFile(
                "document",
                "test.txt",
                "text/plain",
                "test content".getBytes()
        );

        ResponseEntity<?> response = timestampController.getTimestamp(file, "SHA256");

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertTrue(response.getBody() instanceof byte[]);
        
        // Header'ları kontrol et
        assertEquals("2025-11-07T14:30:00Z", response.getHeaders().getFirst("X-Timestamp-Time"));
        assertEquals("CN=TSA", response.getHeaders().getFirst("X-Timestamp-TSA"));
        assertEquals("123456", response.getHeaders().getFirst("X-Timestamp-Serial"));
        
        verify(timestampService, times(1)).getTimestamp(any(byte[].class), anyString());
    }

    @Test
    void testGetTimestamp_whenServiceThrowsException_shouldReturnError() throws Exception {
        when(timestampConfigurationService.isAvailable()).thenReturn(true);
        when(timestampService.getTimestamp(any(byte[].class), anyString()))
            .thenThrow(new TimestampException("Test exception"));

        MockMultipartFile file = new MockMultipartFile(
                "document",
                "test.txt",
                "text/plain",
                "test content".getBytes()
        );

        ResponseEntity<?> response = timestampController.getTimestamp(file, "SHA256");

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        verify(timestampService, times(1)).getTimestamp(any(byte[].class), anyString());
    }

    @Test
    void testValidateTimestamp_shouldCallService() throws Exception {
        TimestampValidationResponseDto mockResponse = new TimestampValidationResponseDto();
        mockResponse.setValid(true);
        mockResponse.setMessage("Timestamp geçerli");

        when(timestampService.validateTimestamp(any(byte[].class), any()))
            .thenReturn(mockResponse);

        MockMultipartFile tokenFile = new MockMultipartFile(
                "timestampToken",
                "timestamp.tst",
                "application/octet-stream",
                "mock-token".getBytes()
        );

        ResponseEntity<?> response = timestampController.validateTimestamp(tokenFile, null);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        verify(timestampService, times(1)).validateTimestamp(any(byte[].class), any());
    }

    @Test
    void testValidateTimestamp_whenValidationFails_shouldReturnValidResponse() throws Exception {
        TimestampValidationResponseDto mockResponse = new TimestampValidationResponseDto();
        mockResponse.setValid(false);
        mockResponse.setMessage("Timestamp geçersiz");

        when(timestampService.validateTimestamp(any(byte[].class), any()))
            .thenReturn(mockResponse);

        MockMultipartFile tokenFile = new MockMultipartFile(
                "timestampToken",
                "timestamp.tst",
                "application/octet-stream",
                "invalid-token".getBytes()
        );

        ResponseEntity<?> response = timestampController.validateTimestamp(tokenFile, null);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        TimestampValidationResponseDto body = (TimestampValidationResponseDto) response.getBody();
        assertNotNull(body);
        assertFalse(body.isValid());
    }

    @Test
    void testValidateTimestamp_whenServiceThrowsException_shouldReturnError() throws Exception {
        when(timestampService.validateTimestamp(any(byte[].class), any()))
            .thenThrow(new RuntimeException("Validation error"));

        MockMultipartFile tokenFile = new MockMultipartFile(
                "timestampToken",
                "timestamp.tst",
                "application/octet-stream",
                "mock-token".getBytes()
        );

        ResponseEntity<?> response = timestampController.validateTimestamp(tokenFile, null);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        verify(timestampService, times(1)).validateTimestamp(any(byte[].class), any());
    }

    @Test
    void testGetStatus_whenConfigured_shouldReturnTrue() {
        when(timestampConfigurationService.isAvailable()).thenReturn(true);

        ResponseEntity<TimestampStatusDto> response = timestampController.getStatus();

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        
        TimestampStatusDto body = response.getBody();
        assertTrue(body.isConfigured());
        assertNotNull(body.getMessage());
        verify(timestampConfigurationService, times(1)).isAvailable();
    }

    @Test
    void testGetStatus_whenNotConfigured_shouldReturnFalse() {
        when(timestampConfigurationService.isAvailable()).thenReturn(false);

        ResponseEntity<TimestampStatusDto> response = timestampController.getStatus();

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        
        TimestampStatusDto body = response.getBody();
        assertFalse(body.isConfigured());
        assertNotNull(body.getMessage());
        verify(timestampConfigurationService, times(1)).isAvailable();
    }

    @Test
    void testGetTimestamp_withValidResponse_shouldReturnAllFields() throws Exception {
        when(timestampConfigurationService.isAvailable()).thenReturn(true);

        TimestampResponseDto mockResponse = new TimestampResponseDto();
        mockResponse.setTimestampToken(java.util.Base64.getEncoder().encodeToString("token123".getBytes()));
        mockResponse.setTimestamp("2025-11-07T14:30:00Z");
        mockResponse.setTsaName("CN=TSA");
        mockResponse.setHashAlgorithm("SHA256");
        mockResponse.setSerialNumber("123456");
        mockResponse.setNonce("nonce123");

        when(timestampService.getTimestamp(any(byte[].class), anyString()))
            .thenReturn(mockResponse);

        MockMultipartFile file = new MockMultipartFile(
                "document",
                "test.txt",
                "text/plain",
                "test content".getBytes()
        );

        ResponseEntity<?> response = timestampController.getTimestamp(file, "SHA256");

        assertEquals(HttpStatus.OK, response.getStatusCode());
        
        // Response binary olmalı
        assertNotNull(response.getBody());
        assertTrue(response.getBody() instanceof byte[]);
        
        // Header'larda metadata olmalı
        assertEquals("2025-11-07T14:30:00Z", response.getHeaders().getFirst("X-Timestamp-Time"));
        assertEquals("CN=TSA", response.getHeaders().getFirst("X-Timestamp-TSA"));
        assertEquals("123456", response.getHeaders().getFirst("X-Timestamp-Serial"));
        assertEquals("SHA256", response.getHeaders().getFirst("X-Timestamp-Hash-Algorithm"));
        assertEquals("nonce123", response.getHeaders().getFirst("X-Timestamp-Nonce"));
        
        // Content-Type binary olmalı
        assertEquals(MediaType.APPLICATION_OCTET_STREAM, response.getHeaders().getContentType());
    }

    @Test
    void testValidateTimestamp_withOriginalData_shouldIncludeHashVerification() throws Exception {
        TimestampValidationResponseDto mockResponse = new TimestampValidationResponseDto();
        mockResponse.setValid(true);
        mockResponse.setHashVerified(true);
        mockResponse.setMessage("Timestamp ve hash doğrulandı");

        when(timestampService.validateTimestamp(any(byte[].class), any(byte[].class)))
            .thenReturn(mockResponse);

        MockMultipartFile tokenFile = new MockMultipartFile(
                "timestampToken",
                "timestamp.tst",
                "application/octet-stream",
                "mock-token".getBytes()
        );

        MockMultipartFile originalFile = new MockMultipartFile(
                "originalDocument",
                "test.txt",
                "text/plain",
                "test content".getBytes()
        );

        ResponseEntity<?> response = timestampController.validateTimestamp(tokenFile, originalFile);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        TimestampValidationResponseDto body = (TimestampValidationResponseDto) response.getBody();
        assertNotNull(body);
        assertTrue(body.isValid());
        assertTrue(body.getHashVerified());
    }

    @Test
    void testGetTimestamp_withIOException_shouldReturnError() throws Exception {
        when(timestampConfigurationService.isAvailable()).thenReturn(true);

        // Mock MultipartFile that throws exception
        MockMultipartFile file = new MockMultipartFile(
                "document",
                "test.txt",
                "text/plain",
                "test content".getBytes()
        );

        when(timestampService.getTimestamp(any(byte[].class), anyString()))
            .thenThrow(new RuntimeException("IO error"));

        ResponseEntity<?> response = timestampController.getTimestamp(file, "SHA256");

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
    }
}
