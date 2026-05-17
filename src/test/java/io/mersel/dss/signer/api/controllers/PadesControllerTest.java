package io.mersel.dss.signer.api.controllers;

import io.mersel.dss.signer.api.dtos.SignPadesDto;
import io.mersel.dss.signer.api.exceptions.SignatureException;
import io.mersel.dss.signer.api.models.ErrorModel;
import io.mersel.dss.signer.api.models.SignResponse;
import io.mersel.dss.signer.api.models.SigningMaterial;
import io.mersel.dss.signer.api.services.signature.pades.PAdESSignatureService;
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
import static org.mockito.AdditionalMatchers.aryEq;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * {@link PadesController} kontrat test'leri.
 *
 * <p>G grubu (HTTP/API kontratı) kapsamı:
 * <ul>
 *   <li><b>G3</b>: Empty / null document → 400 INVALID_INPUT</li>
 *   <li><b>G6</b>: Response gövdesi {@code byte[]} olarak döner
 *       (Spring tarafından chunked değil, Content-Length set edilen
 *       formatta serialize edilir). Cosmetic — bağlantıyı uzun süreli
 *       açık tutmaz, proxy/load balancer ile uyumlu.</li>
 *   <li>Cades/Xades controller'larıyla parite (Content-Disposition,
 *       service exception → 500, attachment davranışı).</li>
 * </ul>
 * </p>
 *
 * <p>NOTE: Wrong content-type → 415 ve malformed multipart → 400/500
 * davranışları Spring framework'ün default'udur (signer kodu adına
 * <em>signer-side</em> bir kontrat değil; framework upgrade'inde
 * implicit olarak korunur). Bu davranışlar burada test edilmez —
 * out-of-scope, framework-level garantidir.</p>
 */
class PadesControllerTest {

    @Mock private PAdESSignatureService padesSignatureService;

    private SigningMaterial signingMaterial = null;
    private PadesController controller;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        controller = new PadesController(padesSignatureService, signingMaterial);
    }

    @Nested
    class SuccessfulRequests {

        @Test
        void shouldReturnOkWithPdfBytes() throws Exception {
            byte[] signedPdf = "%PDF-1.4 signed".getBytes();
            when(padesSignatureService.signPdf(
                    any(InputStream.class), isNull(), isNull(), eq(false), eq(signingMaterial)))
                .thenReturn(new SignResponse(signedPdf, null));

            SignPadesDto dto = new SignPadesDto();
            dto.setDocument(new MockMultipartFile(
                "document", "in.pdf", "application/pdf", "original".getBytes()));
            dto.setAppendMode(false);

            ResponseEntity<?> response = controller.signPades(dto);

            assertEquals(HttpStatus.OK, response.getStatusCode());
            assertArrayEquals(signedPdf, (byte[]) response.getBody());
        }

        @Test
        void shouldIncludeContentDispositionWithPdfExtension() throws Exception {
            when(padesSignatureService.signPdf(any(), any(), any(), anyBoolean(), any()))
                .thenReturn(new SignResponse("pdf".getBytes(), null));

            SignPadesDto dto = new SignPadesDto();
            dto.setDocument(new MockMultipartFile(
                "document", "in.pdf", "application/pdf", "x".getBytes()));

            ResponseEntity<?> response = controller.signPades(dto);

            String disposition = response.getHeaders().getFirst("Content-Disposition");
            assertNotNull(disposition);
            assertTrue(disposition.contains(".pdf"),
                "PAdES çıktısının uzantısı .pdf olmalı (Content-Disposition)");
            assertTrue(disposition.contains("signed-"),
                "Content-Disposition imzalı dosyayı 'signed-' prefix'i ile işaretlemeli");
        }

        @Test
        void appendMode_truePassedToService() throws Exception {
            when(padesSignatureService.signPdf(any(), any(), any(), anyBoolean(), any()))
                .thenReturn(new SignResponse("x".getBytes(), null));

            SignPadesDto dto = new SignPadesDto();
            dto.setDocument(new MockMultipartFile(
                "document", "in.pdf", "application/pdf", "x".getBytes()));
            dto.setAppendMode(true);

            controller.signPades(dto);

            verify(padesSignatureService).signPdf(
                any(InputStream.class), isNull(), isNull(), eq(true), eq(signingMaterial));
        }

        @Test
        void appendMode_nullDefaultsToFalse() throws Exception {
            when(padesSignatureService.signPdf(any(), any(), any(), anyBoolean(), any()))
                .thenReturn(new SignResponse("x".getBytes(), null));

            SignPadesDto dto = new SignPadesDto();
            dto.setDocument(new MockMultipartFile(
                "document", "in.pdf", "application/pdf", "x".getBytes()));
            dto.setAppendMode(null);

            controller.signPades(dto);

            verify(padesSignatureService).signPdf(
                any(InputStream.class), isNull(), isNull(), eq(false), eq(signingMaterial));
        }

        @Test
        void attachmentBytes_passedThroughToService() throws Exception {
            byte[] attachmentBytes = "xml-payload".getBytes();
            when(padesSignatureService.signPdf(
                    any(InputStream.class), aryEq(attachmentBytes), eq("invoice.xml"),
                    anyBoolean(), any()))
                .thenReturn(new SignResponse("pdf".getBytes(), null));

            SignPadesDto dto = new SignPadesDto();
            dto.setDocument(new MockMultipartFile(
                "document", "in.pdf", "application/pdf", "x".getBytes()));
            dto.setAttachment(new MockMultipartFile(
                "attachment", "invoice.xml", "application/xml", attachmentBytes));
            dto.setAttachmentFileName("invoice.xml");

            ResponseEntity<?> response = controller.signPades(dto);

            assertEquals(HttpStatus.OK, response.getStatusCode());
            verify(padesSignatureService).signPdf(
                any(InputStream.class), aryEq(attachmentBytes), eq("invoice.xml"),
                anyBoolean(), any());
        }

        /**
         * G6 (chunked streaming kontratı): Response gövdesi gerçek bir
         * {@code byte[]} olmalı; Spring tarafından otomatik Content-Length
         * ile serialize edilir (chunked encoding değil). Bu, proxy/LB
         * uyumluluğu için kritik — chunked yanıtlar bazı katmanlarda
         * cache miss veya buffer'lanma yapabilir.
         */
        @Test
        void g6_chunkedStreamingContract_bodyIsByteArrayNotStream() throws Exception {
            when(padesSignatureService.signPdf(any(), any(), any(), anyBoolean(), any()))
                .thenReturn(new SignResponse("pdf-body".getBytes(), null));

            SignPadesDto dto = new SignPadesDto();
            dto.setDocument(new MockMultipartFile(
                "document", "in.pdf", "application/pdf", "x".getBytes()));

            ResponseEntity<?> response = controller.signPades(dto);

            assertNotNull(response.getBody());
            assertTrue(response.getBody() instanceof byte[],
                "Response gövdesi byte[] olmalı — InputStream yanıtı chunked encoding tetikler");
        }
    }

    @Nested
    class ValidationErrors {

        /**
         * G3: PDF belgesi gönderilmediğinde controller 400 INVALID_INPUT
         * dönmeli — generic 500'e düşmek prod log'larını kirletir ve
         * kullanıcıya yanlış (server-side) error semantiği iletir.
         */
        @Test
        void g3_nullDocument_shouldReturnBadRequest() {
            SignPadesDto dto = new SignPadesDto();
            dto.setDocument(null);

            ResponseEntity<?> response = controller.signPades(dto);

            assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
            assertTrue(response.getBody() instanceof ErrorModel);
            assertEquals("INVALID_INPUT", ((ErrorModel) response.getBody()).getCode());
        }
    }

    @Nested
    class ErrorHandling {

        @Test
        void serviceException_shouldReturnInternalServerError() {
            when(padesSignatureService.signPdf(any(), any(), any(), anyBoolean(), any()))
                .thenThrow(new SignatureException("PADES_SIGN_ERROR", "iText failed"));

            SignPadesDto dto = new SignPadesDto();
            dto.setDocument(new MockMultipartFile(
                "document", "in.pdf", "application/pdf", "x".getBytes()));

            ResponseEntity<?> response = controller.signPades(dto);

            assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
            assertTrue(response.getBody() instanceof ErrorModel);
            assertEquals("SIGNATURE_FAILED", ((ErrorModel) response.getBody()).getCode());
        }

        @Test
        void unexpectedException_shouldReturnInternalServerError() {
            when(padesSignatureService.signPdf(any(), any(), any(), anyBoolean(), any()))
                .thenThrow(new RuntimeException("Unexpected"));

            SignPadesDto dto = new SignPadesDto();
            dto.setDocument(new MockMultipartFile(
                "document", "in.pdf", "application/pdf", "x".getBytes()));

            ResponseEntity<?> response = controller.signPades(dto);

            assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        }
    }
}
