package io.mersel.dss.signer.api;

import io.mersel.dss.signer.api.exceptions.CertificateValidationException;
import io.mersel.dss.signer.api.exceptions.SignatureException;
import io.mersel.dss.signer.api.exceptions.TimestampException;
import io.mersel.dss.signer.api.models.ErrorModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.MaxUploadSizeExceededException;

import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

/**
 * Uygulama için global exception handler.
 * Tutarlı hata yanıtları ve loglama sağlar.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    /**
     * İmza ile ilgili exception'ları yönetir.
     */
    @ExceptionHandler(SignatureException.class)
    public ResponseEntity<ErrorModel> handleSignatureException(SignatureException ex) {
        LOGGER.error("İmza işlemi başarısız: {} - {}", ex.getErrorCode(), ex.getMessage(), ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
            .body(new ErrorModel(ex.getErrorCode(), ex.getMessage()));
    }

    /**
     * Sertifika doğrulama exception'larını yönetir.
     */
    @ExceptionHandler(CertificateValidationException.class)
    public ResponseEntity<ErrorModel> handleCertificateValidationException(
            CertificateValidationException ex) {
        LOGGER.error("Sertifika doğrulama başarısız: {}", ex.getMessage(), ex);
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
            .body(new ErrorModel(ex.getErrorCode(), ex.getMessage()));
    }

    /**
     * Keystore exception'larını yönetir.
     */
    @ExceptionHandler(io.mersel.dss.signer.api.exceptions.KeyStoreException.class)
    public ResponseEntity<ErrorModel> handleKeyStoreException(
            io.mersel.dss.signer.api.exceptions.KeyStoreException ex) {
        LOGGER.error("KeyStore işlemi başarısız: {}", ex.getMessage(), ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
            .body(new ErrorModel(ex.getErrorCode(), ex.getMessage()));
    }

    /**
     * Zaman damgası exception'larını yönetir.
     */
    @ExceptionHandler(TimestampException.class)
    public ResponseEntity<ErrorModel> handleTimestampException(TimestampException ex) {
        LOGGER.error("Zaman damgası işlemi başarısız: {}", ex.getMessage(), ex);
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
            .body(new ErrorModel(ex.getErrorCode(), ex.getMessage()));
    }

    /**
     * Dosya yükleme boyut aşımı exception'larını yönetir.
     */
    @ExceptionHandler(MaxUploadSizeExceededException.class)
    public ResponseEntity<ErrorModel> handleMaxUploadSizeExceeded(
            MaxUploadSizeExceededException ex) {
        LOGGER.warn("Dosya yükleme boyutu aşıldı: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.PAYLOAD_TOO_LARGE)
            .body(new ErrorModel("FILE_TOO_LARGE", 
                "Yüklenen dosya maksimum izin verilen boyutu aşıyor"));
    }

    /**
     * Yanlış {@code Content-Type} ile gelen istekler için 415 mapping.
     *
     * <p>Sign endpoint'leri {@code consumes=multipart/form-data} sözleşmesi
     * ile çalışır; client {@code application/json}, {@code text/plain} ya da
     * benzeri media type ile POST attığında Spring
     * {@link HttpMediaTypeNotSupportedException} fırlatır. Bu exception
     * generic {@code Exception} handler'a düşmemeli — operasyonel UX için
     * 415 UNSUPPORTED_MEDIA_TYPE + açık bir {@code WRONG_CONTENT_TYPE}
     * error kodu daha doğru ki client doğru header'ı ayarlasın.</p>
     */
    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    public ResponseEntity<ErrorModel> handleHttpMediaTypeNotSupported(
            HttpMediaTypeNotSupportedException ex) {
        LOGGER.warn("Desteklenmeyen content-type: {}", ex.getContentType());
        return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE)
            .body(new ErrorModel("WRONG_CONTENT_TYPE",
                "İstek 'multipart/form-data' Content-Type'ı ile gönderilmeli"));
    }

    /**
     * Java güvenlik exception'larını yönetir.
     */
    @ExceptionHandler({
        KeyStoreException.class,
        CertificateException.class,
        NoSuchAlgorithmException.class,
        UnrecoverableKeyException.class
    })
    public ResponseEntity<ErrorModel> handleSecurityException(Exception ex) {
        LOGGER.error("Güvenlik işlemi başarısız: {}", ex.getMessage(), ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
            .body(new ErrorModel("SECURITY_ERROR", 
                "Bir güvenlik hatası oluştu: " + ex.getMessage()));
    }

    /**
     * Diğer tüm beklenmeyen exception'ları yönetir.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorModel> handleGenericException(Exception ex) {
        LOGGER.error("Beklenmeyen hata oluştu", ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
            .body(new ErrorModel("INTERNAL_ERROR", 
                "Beklenmeyen bir hata oluştu. Sorun devam ederse lütfen destek ile iletişime geçin."));
    }
}