package io.mersel.dss.signer.api.controllers;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import io.mersel.dss.signer.api.dtos.SignHashDto;
import io.mersel.dss.signer.api.dtos.SignHashResponseDto;
import io.mersel.dss.signer.api.exceptions.SignatureException;
import io.mersel.dss.signer.api.models.ErrorModel;
import io.mersel.dss.signer.api.services.notification.SignerNotifier;
import io.mersel.dss.signer.api.services.signature.raw.RawHashSignatureService;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Severity;
import io.qameta.allure.SeverityLevel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * {@link HashSignatureController} HTTP kontrat testleri. Service mock'lanır;
 * controller'ın validation, error handling, response shape ve content-type
 * davranışları izole edilir.
 *
 * <p>Cryptographic doğruluk testi (gerçek imza + verify) servis seviyesinde
 * {@code RawHashSignatureServiceTest}'tedir; burada controller'ın HTTP
 * layer'da yanlış davranışlar olmadığını doğruluyoruz.</p>
 */
@Epic("HTTP API Contract")
@Feature("Hash-Sign Endpoint")
@Severity(SeverityLevel.CRITICAL)
class HashSignatureControllerTest {

    private RawHashSignatureService service;
    private SignerNotifier signerNotifier;
    private HashSignatureController controller;

    @BeforeEach
    void setUp() {
        service = mock(RawHashSignatureService.class);
        signerNotifier = mock(SignerNotifier.class);
        controller = new HashSignatureController(service, signerNotifier,
            new io.mersel.dss.signer.api.services.metrics.SignatureMetrics(
                new io.micrometer.core.instrument.simple.SimpleMeterRegistry()));
    }

    @Test
    void signHash_success_returnsBase64SignatureInJson() {
        byte[] mockSignature = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        when(service.signDigest(any(byte[].class), eq(DigestAlgorithm.SHA256)))
            .thenReturn(mockSignature);

        SignHashDto dto = new SignHashDto();
        dto.setBase64EncodedDigest(Base64.getEncoder().encodeToString(new byte[32]));
        dto.setDigestAlgorithm(DigestAlgorithm.SHA256);

        ResponseEntity<?> response = controller.signHash(dto);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertInstanceOf(SignHashResponseDto.class, response.getBody());
        SignHashResponseDto body = (SignHashResponseDto) response.getBody();
        assertEquals(Base64.getEncoder().encodeToString(mockSignature),
            body.getBase64EncodedSignature());
    }

    @Test
    void signHash_nullBody_returns400() {
        ResponseEntity<?> response = controller.signHash(null);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        ErrorModel err = (ErrorModel) response.getBody();
        assertNotNull(err);
        assertEquals("INVALID_INPUT", err.getCode());
        verify(service, never()).signDigest(any(), any());
    }

    @Test
    void signHash_nullDigestField_returns400() {
        SignHashDto dto = new SignHashDto();
        dto.setBase64EncodedDigest(null);

        ResponseEntity<?> response = controller.signHash(dto);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        verify(service, never()).signDigest(any(), any());
    }

    @Test
    void signHash_emptyDigestField_returns400() {
        SignHashDto dto = new SignHashDto();
        dto.setBase64EncodedDigest("");

        ResponseEntity<?> response = controller.signHash(dto);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        verify(service, never()).signDigest(any(), any());
    }

    @Test
    void signHash_blankDigestField_returns400() {
        SignHashDto dto = new SignHashDto();
        dto.setBase64EncodedDigest("   \n\t  ");

        ResponseEntity<?> response = controller.signHash(dto);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        verify(service, never()).signDigest(any(), any());
    }

    @Test
    void signHash_invalidBase64_returns400() {
        SignHashDto dto = new SignHashDto();
        dto.setBase64EncodedDigest("!!! not valid base64 !!!");

        ResponseEntity<?> response = controller.signHash(dto);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        ErrorModel err = (ErrorModel) response.getBody();
        assertNotNull(err);
        assertEquals("INVALID_INPUT", err.getCode());
        assertTrue(err.getMessage().toLowerCase().contains("base64"),
            "Hata mesajı base64 problemini açıklamalı: " + err.getMessage());
        verify(service, never()).signDigest(any(), any());
    }

    @Test
    void signHash_serviceValidationFailure_returns400() {
        when(service.signDigest(any(), any()))
            .thenThrow(new IllegalArgumentException(
                "Digest uzunluğu algoritma ile uyumsuz: SHA256 için 32 byte bekleniyor, 27 byte alındı."));

        SignHashDto dto = new SignHashDto();
        dto.setBase64EncodedDigest(Base64.getEncoder().encodeToString(new byte[27]));

        ResponseEntity<?> response = controller.signHash(dto);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        ErrorModel err = (ErrorModel) response.getBody();
        assertNotNull(err);
        assertEquals("INVALID_INPUT", err.getCode());
        assertTrue(err.getMessage().contains("32 byte"),
            "Hata mesajı service'den propagate edilmeli");
    }

    @Test
    void signHash_signatureFailure_returns500() {
        when(service.signDigest(any(), any()))
            .thenThrow(new SignatureException("HSM unreachable"));

        SignHashDto dto = new SignHashDto();
        dto.setBase64EncodedDigest(Base64.getEncoder().encodeToString(new byte[32]));

        ResponseEntity<?> response = controller.signHash(dto);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        ErrorModel err = (ErrorModel) response.getBody();
        assertNotNull(err);
        assertEquals("SIGNATURE_FAILED", err.getCode());
    }

    @Test
    void signHash_unexpectedException_returns500() {
        when(service.signDigest(any(), any()))
            .thenThrow(new RuntimeException("Beklenmedik durum"));

        SignHashDto dto = new SignHashDto();
        dto.setBase64EncodedDigest(Base64.getEncoder().encodeToString(new byte[32]));

        ResponseEntity<?> response = controller.signHash(dto);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        ErrorModel err = (ErrorModel) response.getBody();
        assertNotNull(err);
        assertEquals("SIGNATURE_FAILED", err.getCode());
    }

    @Test
    void signHash_omittedDigestAlgorithm_defaultsToSha256() {
        when(service.signDigest(any(), eq(DigestAlgorithm.SHA256)))
            .thenReturn(new byte[] { 0x42 });

        SignHashDto dto = new SignHashDto();
        // digestAlgorithm set edilmedi → default
        dto.setBase64EncodedDigest(Base64.getEncoder().encodeToString(new byte[32]));

        ResponseEntity<?> response = controller.signHash(dto);
        assertEquals(HttpStatus.OK, response.getStatusCode());

        verify(service).signDigest(any(byte[].class), eq(DigestAlgorithm.SHA256));
    }

    @Test
    void signHash_explicitSha384_forwardedToService() {
        when(service.signDigest(any(), eq(DigestAlgorithm.SHA384)))
            .thenReturn(new byte[] { 0x42 });

        SignHashDto dto = new SignHashDto();
        dto.setBase64EncodedDigest(Base64.getEncoder().encodeToString(new byte[48]));
        dto.setDigestAlgorithm(DigestAlgorithm.SHA384);

        ResponseEntity<?> response = controller.signHash(dto);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        verify(service).signDigest(any(byte[].class), eq(DigestAlgorithm.SHA384));
    }

    @Test
    void signHash_paddingTrimmedFromDigestField() {
        when(service.signDigest(any(), any())).thenReturn(new byte[] { 0x01 });

        SignHashDto dto = new SignHashDto();
        // başında/sonunda whitespace var (curl ile JSON quoting bazen takıyor)
        dto.setBase64EncodedDigest("  " + Base64.getEncoder().encodeToString(new byte[32]) + "\n");

        ResponseEntity<?> response = controller.signHash(dto);
        assertEquals(HttpStatus.OK, response.getStatusCode(),
            "Whitespace trim edilmeli, geçerli base64 olarak işlenmeli");
    }
}
