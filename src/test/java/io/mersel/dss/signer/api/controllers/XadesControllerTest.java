package io.mersel.dss.signer.api.controllers;

import io.mersel.dss.signer.api.models.SignResponse;
import io.mersel.dss.signer.api.models.SigningMaterial;
import io.mersel.dss.signer.api.models.enums.DocumentType;
import io.mersel.dss.signer.api.models.enums.XadesSignatureLevel;
import io.mersel.dss.signer.api.services.crypto.DigestAlgorithmResolverService;
import io.mersel.dss.signer.api.services.signature.wssecurity.WsSecuritySignatureService;
import io.mersel.dss.signer.api.services.signature.xades.XAdESSignatureService;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Severity;
import io.qameta.allure.SeverityLevel;
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
@Epic("HTTP API Contract")
@Feature("XAdES Endpoint")
@Severity(SeverityLevel.CRITICAL)
class XadesControllerTest {

    @Mock
    private XAdESSignatureService xadesSignatureService;

    @Mock
    private WsSecuritySignatureService wsSecuritySignatureService;

    @Mock
    private DigestAlgorithmResolverService digestAlgorithmResolverService;

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
            "testPin".toCharArray(),
                digestAlgorithmResolverService
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
            eq(signingMaterial),
            eq(XadesSignatureLevel.XADES_BES)
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
        // Given: rapor tipi gönderilse bile signatureLevel set edilmediği için
        // DTO kontratı XADES_BES default uygular. documentType artık seviye
        // kararına dahil değildir.
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
            eq(signingMaterial),
            eq(XadesSignatureLevel.XADES_BES)
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
            any(),
            any(XadesSignatureLevel.class)
        )).thenReturn(mockResponse);

        // When
        io.mersel.dss.signer.api.dtos.SignXadesDto dto =
            new io.mersel.dss.signer.api.dtos.SignXadesDto();
        dto.setDocument(file);
        dto.setDocumentType(DocumentType.EBiletReport);
        dto.setZipFile(false);

        controller.signXades(dto);

        // Then: signatureLevel set edilmediği için DTO default XADES_BES forward eder.
        verify(xadesSignatureService).signXml(
            any(InputStream.class),
            eq(DocumentType.EBiletReport),
            isNull(),
            eq(false),
            eq(signingMaterial),
            eq(XadesSignatureLevel.XADES_BES)
        );
    }

    @Test
    void testSignXadesForwardsXADES_AWhenExplicitlyRequested() throws Exception {
        // Given: rapor tipi + signatureLevel=XADES_A; service'e enum doğru forward edilmeli.
        String xmlContent = "<?xml version=\"1.0\"?><earsivRapor/>";
        MockMultipartFile file = new MockMultipartFile(
            "document",
            "earsiv-rapor.xml",
            "text/xml",
            xmlContent.getBytes()
        );

        SignResponse mockResponse = new SignResponse(
            xmlContent.getBytes(),
            "sig-xades-a"
        );

        when(xadesSignatureService.signXml(
            any(InputStream.class),
            any(DocumentType.class),
            any(),
            anyBoolean(),
            any(),
            any(XadesSignatureLevel.class)
        )).thenReturn(mockResponse);

        io.mersel.dss.signer.api.dtos.SignXadesDto dto =
            new io.mersel.dss.signer.api.dtos.SignXadesDto();
        dto.setDocument(file);
        dto.setDocumentType(DocumentType.EArchiveReport);
        dto.setZipFile(false);
        dto.setSignatureLevel(XadesSignatureLevel.XADES_A);

        // When
        ResponseEntity<?> response = controller.signXades(dto);

        // Then
        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        verify(xadesSignatureService).signXml(
            any(InputStream.class),
            eq(DocumentType.EArchiveReport),
            isNull(),
            eq(false),
            eq(signingMaterial),
            eq(XadesSignatureLevel.XADES_A)
        );
    }

    @Test
    void testSignXadesForwardsXADES_BESWhenExplicitlyRequested() throws Exception {
        // Given: rapor tipinde explicit XADES_BES; documentType artık karar verici değildir.
        String xmlContent = "<?xml version=\"1.0\"?><dovizRapor/>";
        MockMultipartFile file = new MockMultipartFile(
            "document",
            "edoviz-rapor.xml",
            "text/xml",
            xmlContent.getBytes()
        );

        SignResponse mockResponse = new SignResponse(
            xmlContent.getBytes(),
            "sig-bes-rapor"
        );

        when(xadesSignatureService.signXml(
            any(InputStream.class),
            any(DocumentType.class),
            any(),
            anyBoolean(),
            any(),
            any(XadesSignatureLevel.class)
        )).thenReturn(mockResponse);

        io.mersel.dss.signer.api.dtos.SignXadesDto dto =
            new io.mersel.dss.signer.api.dtos.SignXadesDto();
        dto.setDocument(file);
        dto.setDocumentType(DocumentType.EBiletReport);
        dto.setZipFile(false);
        dto.setSignatureLevel(XadesSignatureLevel.XADES_BES);

        // When
        controller.signXades(dto);

        // Then: rapor tipi olsa bile BES tercih edildiği için enum BES olarak iletilir.
        verify(xadesSignatureService).signXml(
            any(InputStream.class),
            eq(DocumentType.EBiletReport),
            isNull(),
            eq(false),
            eq(signingMaterial),
            eq(XadesSignatureLevel.XADES_BES)
        );
    }

    @Test
    void testSignXadesSignatureLevelDefaultsToXADES_BESWhenOmitted() throws Exception {
        // Given: signatureLevel set edilmedi → DTO non-null kontratı gereği XADES_BES forward edilmeli.
        String xmlContent = "<?xml version=\"1.0\"?><invoice/>";
        MockMultipartFile file = new MockMultipartFile(
            "document",
            "invoice.xml",
            "text/xml",
            xmlContent.getBytes()
        );

        SignResponse mockResponse = new SignResponse(
            xmlContent.getBytes(),
            "sig-default"
        );

        when(xadesSignatureService.signXml(
            any(InputStream.class),
            any(DocumentType.class),
            any(),
            anyBoolean(),
            any(),
            any(XadesSignatureLevel.class)
        )).thenReturn(mockResponse);

        io.mersel.dss.signer.api.dtos.SignXadesDto dto =
            new io.mersel.dss.signer.api.dtos.SignXadesDto();
        dto.setDocument(file);
        dto.setDocumentType(DocumentType.UblDocument);
        dto.setZipFile(false);
        // signatureLevel set edilmedi.

        // When
        controller.signXades(dto);

        // Then
        verify(xadesSignatureService).signXml(
            any(InputStream.class),
            eq(DocumentType.UblDocument),
            isNull(),
            eq(false),
            eq(signingMaterial),
            eq(XadesSignatureLevel.XADES_BES)
        );
    }

}
