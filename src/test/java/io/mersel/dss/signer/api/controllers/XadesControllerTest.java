package io.mersel.dss.signer.api.controllers;

import io.mersel.dss.signer.api.models.SignResponse;
import io.mersel.dss.signer.api.models.SigningMaterial;
import io.mersel.dss.signer.api.models.enums.DocumentType;
import io.mersel.dss.signer.api.services.signature.wssecurity.WsSecuritySignatureService;
import io.mersel.dss.signer.api.services.signature.xades.XAdESSignatureService;
import org.junit.jupiter.api.BeforeEach;
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

/**
 * XadesController test'leri.
 */
class XadesControllerTest {

    @Mock
    private XAdESSignatureService xadesSignatureService;

    @Mock
    private WsSecuritySignatureService wsSecuritySignatureService;

    private SigningMaterial signingMaterial = null; // SigningMaterial final class - mock edilemiyor

    private XadesController controller;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        controller = new XadesController(
            xadesSignatureService,
            wsSecuritySignatureService,
            signingMaterial,
            "testAlias",
            "testPin".toCharArray()
        );
    }

    @Test
    void testSignXadesSuccess() throws Exception {
        // Given
        String xmlContent = "<?xml version=\"1.0\"?><test>data</test>";
        MockMultipartFile file = new MockMultipartFile(
            "document",
            "test.xml",
            "text/xml",
            xmlContent.getBytes()
        );

        SignResponse mockResponse = new SignResponse(
            xmlContent.getBytes(),
            "test-signature-value"
        );

        when(xadesSignatureService.signXml(
            any(InputStream.class),
            eq(DocumentType.UblDocument),
            isNull(),
            eq(false),
            eq(signingMaterial)
        )).thenReturn(mockResponse);

        // When
        io.mersel.dss.signer.api.dtos.SignXadesDto dto = 
            new io.mersel.dss.signer.api.dtos.SignXadesDto();
        dto.setDocument(file);
        dto.setDocumentType(DocumentType.UblDocument);
        dto.setZipFile(false);

        ResponseEntity<?> response = controller.signXades(dto);

        // Then
        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getHeaders().get("x-signature-value"));
    }

    @Test
    void testSignXadesWithNullDocument() {
        // Given
        io.mersel.dss.signer.api.dtos.SignXadesDto dto = 
            new io.mersel.dss.signer.api.dtos.SignXadesDto();
        dto.setDocument(null);
        dto.setDocumentType(DocumentType.UblDocument);

        // When
        ResponseEntity<?> response = controller.signXades(dto);

        // Then
        assertNotNull(response);
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
    }

    @Test
    void testSignXadesWithNoneDocumentType() {
        // Given
        String xmlContent = "<?xml version=\"1.0\"?><test>data</test>";
        MockMultipartFile file = new MockMultipartFile(
            "document",
            "test.xml",
            "text/xml",
            xmlContent.getBytes()
        );

        io.mersel.dss.signer.api.dtos.SignXadesDto dto = 
            new io.mersel.dss.signer.api.dtos.SignXadesDto();
        dto.setDocument(file);
        dto.setDocumentType(DocumentType.None);

        // When
        ResponseEntity<?> response = controller.signXades(dto);

        // Then
        assertNotNull(response);
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
    }

    @Test
    void testSignXadesWithEBiletReportSuccess() throws Exception {
        // Given
        String xmlContent = "<?xml version=\"1.0\"?><biletRapor><baslik/></biletRapor>";
        MockMultipartFile file = new MockMultipartFile(
            "document",
            "ebilet-rapor.xml",
            "text/xml",
            xmlContent.getBytes()
        );

        SignResponse mockResponse = new SignResponse(
            xmlContent.getBytes(),
            "test-ebilet-signature-value"
        );

        when(xadesSignatureService.signXml(
            any(InputStream.class),
            eq(DocumentType.EBiletReport),
            isNull(),
            eq(false),
            eq(signingMaterial)
        )).thenReturn(mockResponse);

        // When
        io.mersel.dss.signer.api.dtos.SignXadesDto dto =
            new io.mersel.dss.signer.api.dtos.SignXadesDto();
        dto.setDocument(file);
        dto.setDocumentType(DocumentType.EBiletReport);
        dto.setZipFile(false);

        ResponseEntity<?> response = controller.signXades(dto);

        // Then
        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getHeaders().get("x-signature-value"));
        assertEquals("test-ebilet-signature-value",
            response.getHeaders().getFirst("x-signature-value"));
    }

    @Test
    void testSignXadesWithEBiletReportPassesCorrectDocumentType() throws Exception {
        // Given
        String xmlContent = "<?xml version=\"1.0\"?><biletRapor/>";
        MockMultipartFile file = new MockMultipartFile(
            "document",
            "ebilet-rapor.xml",
            "text/xml",
            xmlContent.getBytes()
        );

        SignResponse mockResponse = new SignResponse(
            xmlContent.getBytes(),
            "sig-value"
        );

        when(xadesSignatureService.signXml(
            any(InputStream.class),
            any(DocumentType.class),
            any(),
            anyBoolean(),
            any()
        )).thenReturn(mockResponse);

        // When
        io.mersel.dss.signer.api.dtos.SignXadesDto dto =
            new io.mersel.dss.signer.api.dtos.SignXadesDto();
        dto.setDocument(file);
        dto.setDocumentType(DocumentType.EBiletReport);
        dto.setZipFile(false);

        controller.signXades(dto);

        // Then
        verify(xadesSignatureService).signXml(
            any(InputStream.class),
            eq(DocumentType.EBiletReport),
            isNull(),
            eq(false),
            eq(signingMaterial)
        );
    }
}

