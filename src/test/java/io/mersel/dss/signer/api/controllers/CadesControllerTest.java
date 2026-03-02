package io.mersel.dss.signer.api.controllers;

import io.mersel.dss.signer.api.dtos.SignCadesDto;
import io.mersel.dss.signer.api.exceptions.SignatureException;
import io.mersel.dss.signer.api.models.ErrorModel;
import io.mersel.dss.signer.api.models.SignResponse;
import io.mersel.dss.signer.api.models.SigningMaterial;
import io.mersel.dss.signer.api.services.signature.cades.CAdESSignatureService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockMultipartFile;

import java.io.InputStream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class CadesControllerTest {

    @Mock private CAdESSignatureService cadesSignatureService;

    private SigningMaterial signingMaterial = null;
    private CadesController controller;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        controller = new CadesController(cadesSignatureService, signingMaterial);
    }

    @Nested
    class SuccessfulRequests {

        @Test
        void attachedMode_shouldReturnOkWithOctetStream() throws Exception {
            byte[] signedBytes = "signed-data".getBytes();
            SignResponse mockResponse = new SignResponse(signedBytes, "base64sig");
            when(cadesSignatureService.signData(any(InputStream.class), eq(false), eq(signingMaterial)))
                    .thenReturn(mockResponse);

            SignCadesDto dto = new SignCadesDto();
            dto.setDocument(new MockMultipartFile("document", "file.pdf", "application/pdf", "pdf-content".getBytes()));
            dto.setDetached(false);

            ResponseEntity<?> response = controller.signCades(dto);

            assertEquals(HttpStatus.OK, response.getStatusCode());
            assertEquals("application/octet-stream", response.getHeaders().getContentType().toString());
            assertArrayEquals(signedBytes, (byte[]) response.getBody());
        }

        @Test
        void detachedMode_shouldIncludeSignatureValueHeader() throws Exception {
            SignResponse mockResponse = new SignResponse("detached-sig".getBytes(), "detached-base64");
            when(cadesSignatureService.signData(any(InputStream.class), eq(true), eq(signingMaterial)))
                    .thenReturn(mockResponse);

            SignCadesDto dto = new SignCadesDto();
            dto.setDocument(new MockMultipartFile("document", "file.pdf", "application/pdf", "content".getBytes()));
            dto.setDetached(true);

            ResponseEntity<?> response = controller.signCades(dto);

            assertEquals(HttpStatus.OK, response.getStatusCode());
            assertNotNull(response.getHeaders().get("x-signature-value"));
            assertEquals("detached-base64", response.getHeaders().getFirst("x-signature-value"));
        }

        @Test
        void attachedMode_shouldNotIncludeSignatureValueHeader() throws Exception {
            SignResponse mockResponse = new SignResponse("attached-data".getBytes(), "big-base64");
            when(cadesSignatureService.signData(any(InputStream.class), eq(false), eq(signingMaterial)))
                    .thenReturn(mockResponse);

            SignCadesDto dto = new SignCadesDto();
            dto.setDocument(new MockMultipartFile("document", "file.pdf", "application/pdf", "content".getBytes()));
            dto.setDetached(false);

            ResponseEntity<?> response = controller.signCades(dto);

            assertNull(response.getHeaders().get("x-signature-value"));
        }

        @Test
        void shouldReturnContentDispositionWithP7sExtension() throws Exception {
            SignResponse mockResponse = new SignResponse("data".getBytes(), "sig");
            when(cadesSignatureService.signData(any(), anyBoolean(), any())).thenReturn(mockResponse);

            SignCadesDto dto = new SignCadesDto();
            dto.setDocument(new MockMultipartFile("document", "file.pdf", "application/pdf", "content".getBytes()));

            ResponseEntity<?> response = controller.signCades(dto);

            String disposition = response.getHeaders().getFirst("Content-Disposition");
            assertNotNull(disposition);
            assertTrue(disposition.contains(".p7s"));
        }

        @Test
        void nullDetachedFlag_shouldDefaultToAttached() throws Exception {
            SignResponse mockResponse = new SignResponse("data".getBytes(), "sig");
            when(cadesSignatureService.signData(any(InputStream.class), eq(false), eq(signingMaterial)))
                    .thenReturn(mockResponse);

            SignCadesDto dto = new SignCadesDto();
            dto.setDocument(new MockMultipartFile("document", "file.pdf", "application/pdf", "content".getBytes()));
            dto.setDetached(null);

            ResponseEntity<?> response = controller.signCades(dto);

            assertEquals(HttpStatus.OK, response.getStatusCode());
            verify(cadesSignatureService).signData(any(InputStream.class), eq(false), any());
        }
    }

    @Nested
    class ValidationErrors {

        @Test
        void nullDocument_shouldReturnBadRequest() {
            SignCadesDto dto = new SignCadesDto();
            dto.setDocument(null);

            ResponseEntity<?> response = controller.signCades(dto);

            assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
            assertTrue(response.getBody() instanceof ErrorModel);
            assertEquals("INVALID_INPUT", ((ErrorModel) response.getBody()).getCode());
        }

        @Test
        void emptyDocument_shouldReturnBadRequest() {
            SignCadesDto dto = new SignCadesDto();
            dto.setDocument(new MockMultipartFile("document", "empty.pdf", "application/pdf", new byte[0]));

            ResponseEntity<?> response = controller.signCades(dto);

            assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        }
    }

    @Nested
    class ErrorHandling {

        @Test
        void serviceException_shouldReturnInternalServerError() throws Exception {
            when(cadesSignatureService.signData(any(), anyBoolean(), any()))
                    .thenThrow(new SignatureException("CADES_SIGN_ERROR", "CAdES failed"));

            SignCadesDto dto = new SignCadesDto();
            dto.setDocument(new MockMultipartFile("document", "file.pdf", "application/pdf", "content".getBytes()));

            ResponseEntity<?> response = controller.signCades(dto);

            assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
            assertTrue(response.getBody() instanceof ErrorModel);
        }

        @Test
        void unexpectedException_shouldReturnInternalServerError() throws Exception {
            when(cadesSignatureService.signData(any(), anyBoolean(), any()))
                    .thenThrow(new RuntimeException("Unexpected"));

            SignCadesDto dto = new SignCadesDto();
            dto.setDocument(new MockMultipartFile("document", "file.pdf", "application/pdf", "content".getBytes()));

            ResponseEntity<?> response = controller.signCades(dto);

            assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        }
    }
}
