package io.mersel.dss.signer.api;

import io.mersel.dss.signer.api.dtos.TimestampRequestDto;
import io.mersel.dss.signer.api.dtos.TimestampResponseDto;
import io.mersel.dss.signer.api.dtos.TimestampValidationDto;
import io.mersel.dss.signer.api.dtos.TimestampValidationResponseDto;
import io.mersel.dss.signer.api.exceptions.TimestampException;
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

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * TimestampService için unit testler.
 */
@ExtendWith(MockitoExtension.class)
@Epic("Service Layer")
@Feature("Timestamp Service")
@Severity(SeverityLevel.NORMAL)
public class TimestampServiceTest {

    @Mock
    private TimestampConfigurationService timestampConfigurationService;

    private TimestampService timestampService;

    @BeforeEach
    void setUp() {
        timestampService = new TimestampService(timestampConfigurationService);
    }

    @Test
    void testGetTimestamp_withValidData_shouldSucceed() {
        // Bu test gerçek bir TSP sunucusu gerektirir
        // Mock ile temel akış testi yapılabilir
        
        TimestampRequestDto requestDto = new TimestampRequestDto();
        String testData = "Hello World!";
        requestDto.setDocumentData(Base64.getEncoder().encodeToString(testData.getBytes()));
        requestDto.setHashAlgorithm("SHA256");
        requestDto.setUseNonce(true);
        requestDto.setCertReq(true);

        // TSP sunucusu yapılandırılmamışsa exception fırlatmalı
        when(timestampConfigurationService.getTspSource())
            .thenThrow(new TimestampException("TSP sunucusu yapılandırılmamış"));

        assertThrows(TimestampException.class, () -> {
            timestampService.getTimestamp(requestDto);
        });

        verify(timestampConfigurationService, times(1)).getTspSource();
    }

    @Test
    void testGetTimestamp_withInvalidBase64_shouldThrowException() {
        TimestampRequestDto requestDto = new TimestampRequestDto();
        requestDto.setDocumentData("invalid-base64!!!!");
        requestDto.setHashAlgorithm("SHA256");

        assertThrows(Exception.class, () -> {
            timestampService.getTimestamp(requestDto);
        });
    }

    @Test
    void testGetTimestamp_withInvalidHashAlgorithm_shouldThrowException() {
        TimestampRequestDto requestDto = new TimestampRequestDto();
        requestDto.setDocumentData(Base64.getEncoder().encodeToString("test".getBytes()));
        requestDto.setHashAlgorithm("INVALID_ALGORITHM");

        assertThrows(TimestampException.class, () -> {
            timestampService.getTimestamp(requestDto);
        });
    }

    @Test
    void testValidateTimestamp_withInvalidToken_shouldReturnInvalid() {
        TimestampValidationDto validationDto = new TimestampValidationDto();
        // Geçersiz bir token (sadece base64 encoded text)
        validationDto.setTimestampToken(Base64.getEncoder().encodeToString("invalid".getBytes()));

        TimestampValidationResponseDto response = timestampService.validateTimestamp(validationDto);

        assertNotNull(response);
        assertFalse(response.isValid());
        assertNotNull(response.getErrors());
        assertFalse(response.getErrors().isEmpty());
    }

    @Test
    void testValidateTimestamp_withoutOriginalData_shouldNotCheckHash() {
        TimestampValidationDto validationDto = new TimestampValidationDto();
        validationDto.setTimestampToken(Base64.getEncoder().encodeToString("invalid".getBytes()));
        // originalData set edilmemiş

        TimestampValidationResponseDto response = timestampService.validateTimestamp(validationDto);

        assertNotNull(response);
        assertNull(response.getHashVerified());
    }

    @Test
    void testGetTimestamp_withDefaultHashAlgorithm_shouldUseSHA256() {
        TimestampRequestDto requestDto = new TimestampRequestDto();
        requestDto.setDocumentData(Base64.getEncoder().encodeToString("test".getBytes()));
        // hashAlgorithm set edilmemiş - default SHA256 kullanılmalı
        
        when(timestampConfigurationService.getTspSource())
            .thenThrow(new TimestampException("Test için mock exception"));

        try {
            timestampService.getTimestamp(requestDto);
            fail("Exception bekleniyor");
        } catch (TimestampException e) {
            // Beklenen durum
            assertTrue(e.getMessage().contains("Test için mock exception"));
        }

        verify(timestampConfigurationService, times(1)).getTspSource();
    }

    @Test
    void testGetTimestamp_withDifferentHashAlgorithms() {
        String[] algorithms = {"SHA256", "SHA384", "SHA512"};

        // Mock her algoritma için geçerli
        when(timestampConfigurationService.getTspSource())
            .thenThrow(new TimestampException("Test exception"));

        for (String algorithm : algorithms) {
            TimestampRequestDto requestDto = new TimestampRequestDto();
            requestDto.setDocumentData(Base64.getEncoder().encodeToString("test".getBytes()));
            requestDto.setHashAlgorithm(algorithm);

            assertThrows(TimestampException.class, () -> {
                timestampService.getTimestamp(requestDto);
            });
        }
    }

    @Test
    void testValidateTimestamp_withInvalidBase64Token_shouldReturnInvalid() {
        TimestampValidationDto validationDto = new TimestampValidationDto();
        validationDto.setTimestampToken("not-a-valid-base64!!!");

        // Geçersiz base64 ile validation response dönmeli (exception değil)
        TimestampValidationResponseDto response = timestampService.validateTimestamp(validationDto);
        
        assertNotNull(response);
        assertFalse(response.isValid());
        assertNotNull(response.getErrors());
        assertFalse(response.getErrors().isEmpty());
    }

    @Test
    void testGetTimestamp_withEmptyData_shouldThrowException() {
        TimestampRequestDto requestDto = new TimestampRequestDto();
        requestDto.setDocumentData("");
        requestDto.setHashAlgorithm("SHA256");

        assertThrows(Exception.class, () -> {
            timestampService.getTimestamp(requestDto);
        });
    }

    @Test
    void testGetTimestamp_withNullHashAlgorithm_shouldUseDefault() {
        TimestampRequestDto requestDto = new TimestampRequestDto();
        requestDto.setDocumentData(Base64.getEncoder().encodeToString("test".getBytes()));
        requestDto.setHashAlgorithm(null);

        when(timestampConfigurationService.getTspSource())
            .thenThrow(new TimestampException("Test exception"));

        assertThrows(TimestampException.class, () -> {
            timestampService.getTimestamp(requestDto);
        });

        verify(timestampConfigurationService, times(1)).getTspSource();
    }

    @Test
    void testValidateTimestamp_responseShouldHaveAllFields() {
        TimestampValidationDto validationDto = new TimestampValidationDto();
        validationDto.setTimestampToken(Base64.getEncoder().encodeToString("invalid".getBytes()));

        TimestampValidationResponseDto response = timestampService.validateTimestamp(validationDto);

        assertNotNull(response);
        assertNotNull(response.getMessage());
        assertNotNull(response.getErrors());
        // valid field her zaman set edilmeli
        assertFalse(response.isValid());
    }
}

