package io.mersel.dss.signer.api;

import io.mersel.dss.signer.api.exceptions.CertificateValidationException;
import io.mersel.dss.signer.api.exceptions.SignatureException;
import io.mersel.dss.signer.api.exceptions.TimestampException;
import io.mersel.dss.signer.api.models.ErrorModel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.multipart.MaxUploadSizeExceededException;

import java.util.Collections;

import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Global exception handler test'leri.
 *
 * <p>Her HTTP error mapping'ini direkt invocation ile kapsar.
 * G grubu (HTTP/API kontratı) içindeki status code garantileri buradan
 * yürütülür; production-grade error envelope (kod + mesaj) regression'larını
 * yakalar.</p>
 */
class GlobalExceptionHandlerTest {

    private GlobalExceptionHandler exceptionHandler;

    @BeforeEach
    void setUp() {
        exceptionHandler = new GlobalExceptionHandler();
    }

    @Test
    void testHandleSignatureException() {
        // Given
        SignatureException exception = new SignatureException(
            "SIGNATURE_FAILED", 
            "İmza oluşturulamadı"
        );

        // When
        ResponseEntity<ErrorModel> response = exceptionHandler.handleSignatureException(exception);

        // Then
        assertNotNull(response);
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("SIGNATURE_FAILED", response.getBody().getCode());
        assertEquals("İmza oluşturulamadı", response.getBody().getMessage());
    }

    @Test
    void testHandleCertificateValidationException() {
        // Given
        CertificateValidationException exception = new CertificateValidationException(
            "Sertifika geçersiz"
        );

        // When
        ResponseEntity<ErrorModel> response = 
            exceptionHandler.handleCertificateValidationException(exception);

        // Then
        assertNotNull(response);
        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("CERTIFICATE_VALIDATION_ERROR", response.getBody().getCode());
    }

    @Test
    void testHandleTimestampException() {
        // Given
        TimestampException exception = new TimestampException(
            "Zaman damgası sunucusuna erişilemiyor"
        );

        // When
        ResponseEntity<ErrorModel> response = exceptionHandler.handleTimestampException(exception);

        // Then
        assertNotNull(response);
        assertEquals(HttpStatus.SERVICE_UNAVAILABLE, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("TIMESTAMP_ERROR", response.getBody().getCode());
    }

    @Test
    void testHandleGenericException() {
        // Given
        Exception exception = new RuntimeException("Beklenmeyen hata");

        // When
        ResponseEntity<ErrorModel> response = exceptionHandler.handleGenericException(exception);

        // Then
        assertNotNull(response);
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("INTERNAL_ERROR", response.getBody().getCode());
        assertTrue(response.getBody().getMessage().contains("Beklenmeyen bir hata"));
    }

    /**
     * G-1: Upload boyutu limiti aşılırsa Spring'in
     * {@link MaxUploadSizeExceededException}'ı 413 Payload Too Large'a
     * map'lenmeli (200MB limit aşımı).
     */
    @Test
    void testHandleMaxUploadSizeExceeded_returns413() {
        MaxUploadSizeExceededException exception =
            new MaxUploadSizeExceededException(200L * 1024 * 1024);

        ResponseEntity<ErrorModel> response =
            exceptionHandler.handleMaxUploadSizeExceeded(exception);

        assertNotNull(response);
        assertEquals(HttpStatus.PAYLOAD_TOO_LARGE, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("FILE_TOO_LARGE", response.getBody().getCode());
    }

    /**
     * G-2: Uygulamaya özgü {@link io.mersel.dss.signer.api.exceptions.KeyStoreException}
     * 500 INTERNAL_SERVER_ERROR + uygulama-tarafı error kodu döner.
     */
    @Test
    void testHandleKeyStoreException_returns500WithErrorCode() {
        io.mersel.dss.signer.api.exceptions.KeyStoreException exception =
            new io.mersel.dss.signer.api.exceptions.KeyStoreException(
                "Keystore yüklenemedi");

        ResponseEntity<ErrorModel> response =
            exceptionHandler.handleKeyStoreException(exception);

        assertNotNull(response);
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("KEYSTORE_ERROR", response.getBody().getCode(),
            "io.mersel KeyStoreException kendi sabit error kodunu (\"KEYSTORE_ERROR\") taşır");
    }

    /**
     * G-3: JCA exception ailesi (KeyStore/Certificate/NoSuchAlgorithm/UnrecoverableKey)
     * tek bir handler ile 500 + SECURITY_ERROR koduna toplanır.
     * Sertifika/anahtar hatalarının HTTP envelope tarafında ifşa edilmemesi
     * için cosmetic mesaj sabitleştirilmiştir.
     */
    @Test
    void testHandleSecurityException_javaKeyStore_returns500() {
        Exception exception = new KeyStoreException("Yanlış PIN");

        ResponseEntity<ErrorModel> response =
            exceptionHandler.handleSecurityException(exception);

        assertNotNull(response);
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("SECURITY_ERROR", response.getBody().getCode());
        assertTrue(response.getBody().getMessage().contains("güvenlik hatası"));
    }

    @Test
    void testHandleSecurityException_certificate_returns500() {
        Exception exception = new CertificateException("Sertifika parse edilemedi");

        ResponseEntity<ErrorModel> response =
            exceptionHandler.handleSecurityException(exception);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals("SECURITY_ERROR", response.getBody().getCode());
    }

    @Test
    void testHandleSecurityException_noSuchAlgorithm_returns500() {
        Exception exception = new NoSuchAlgorithmException("SHA-2048 yok");

        ResponseEntity<ErrorModel> response =
            exceptionHandler.handleSecurityException(exception);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals("SECURITY_ERROR", response.getBody().getCode());
    }

    @Test
    void testHandleSecurityException_unrecoverableKey_returns500() {
        Exception exception = new UnrecoverableKeyException("Yanlış alias");

        ResponseEntity<ErrorModel> response =
            exceptionHandler.handleSecurityException(exception);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals("SECURITY_ERROR", response.getBody().getCode());
    }

    /**
     * G-5: Yanlış {@code Content-Type} ile gelen istekler 415 dönmeli.
     *
     * <p>Spring {@link HttpMediaTypeNotSupportedException} fırlattığında
     * generic {@code Exception.class} handler'a düşmemeli; explicit handler
     * 415 + sabit {@code WRONG_CONTENT_TYPE} error koduyla yanıtlar.
     * Mesaj client'a desteklenen Content-Type'ı söyler.</p>
     */
    @Test
    void testHandleHttpMediaTypeNotSupported_returns415WithWrongContentTypeCode() {
        HttpMediaTypeNotSupportedException exception =
            new HttpMediaTypeNotSupportedException(
                MediaType.APPLICATION_JSON,
                Collections.singletonList(MediaType.MULTIPART_FORM_DATA));

        ResponseEntity<ErrorModel> response =
            exceptionHandler.handleHttpMediaTypeNotSupported(exception);

        assertNotNull(response);
        assertEquals(HttpStatus.UNSUPPORTED_MEDIA_TYPE, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("WRONG_CONTENT_TYPE", response.getBody().getCode());
        assertTrue(response.getBody().getMessage().contains("multipart/form-data"),
            "Client'a doğru Content-Type'ı işaret eden mesaj olmalı");
    }
}

