package io.mersel.dss.signer.api.util;

import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Severity;
import io.qameta.allure.SeverityLevel;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@Epic("Crypto Conformance")
@Feature("CryptoUtils — Algorithm/OID Resolution")
@Severity(SeverityLevel.CRITICAL)
class CryptoUtilsSignatureAlgorithmTest {

    @Nested
    @DisplayName("getSignatureAlgorithm(PrivateKey) — key-only overload")
    class KeyOnlyTests {

        @Test
        void rsaKey_shouldReturnSha256WithRsa() {
            RSAPrivateKey key = mock(RSAPrivateKey.class);
            assertEquals("SHA256withRSA", CryptoUtils.getSignatureAlgorithm(key));
        }

        @Test
        void ecKeyP256_shouldReturnSha256WithEcdsa() {
            ECPrivateKey key = mockECPrivateKey(256);
            assertEquals("SHA256withECDSA", CryptoUtils.getSignatureAlgorithm(key));
        }

        @Test
        void ecKeyP384_shouldReturnSha384WithEcdsa() {
            ECPrivateKey key = mockECPrivateKey(384);
            assertEquals("SHA384withECDSA", CryptoUtils.getSignatureAlgorithm(key));
        }

        @Test
        void ecKeyP521_shouldReturnSha512WithEcdsa() {
            ECPrivateKey key = mockECPrivateKey(521);
            assertEquals("SHA512withECDSA", CryptoUtils.getSignatureAlgorithm(key));
        }

        @Test
        void unknownKeyWithEcAlgorithm_shouldReturnEcdsa() {
            java.security.PrivateKey key = mock(java.security.PrivateKey.class);
            when(key.getAlgorithm()).thenReturn("EC");
            assertEquals("SHA256withECDSA", CryptoUtils.getSignatureAlgorithm(key));
        }

        @Test
        void unknownKeyWithRsaAlgorithm_shouldReturnRsa() {
            java.security.PrivateKey key = mock(java.security.PrivateKey.class);
            when(key.getAlgorithm()).thenReturn("RSA");
            assertEquals("SHA256withRSA", CryptoUtils.getSignatureAlgorithm(key));
        }
    }

    @Nested
    @DisplayName("getSignatureAlgorithm(PrivateKey, X509Certificate) — cert-aware overload (CA'nın getSigAlgName'i kasıtlı yok sayılır; yalnızca public key parametresinden türetilir)")
    class CertificateAwareTests {

        /**
         * Regression: İZİBİZ test ortamı (Hasan Yıldız, 20.05.2026). KamuSM
         * ara-CA'sı SHA-384'e geçtiğinde, RSA-2048 son-kullanıcı sertifikalarının
         * imzaları yanlışlıkla rsa-sha384 olmuştu. Düzeltme: CA imza
         * algoritması ne olursa olsun, RSA public key her zaman SHA256withRSA.
         */
        @Test
        @DisplayName("Regression: CA cert'i SHA384withRSA ile imzalamış olsa bile, RSA public key → SHA256withRSA")
        void rsaCert_caSignedWithSha384_shouldStillReturnSha256WithRsa() {
            RSAPrivateKey key = mock(RSAPrivateKey.class);
            X509Certificate cert = certWithPublicKey(mock(RSAPublicKey.class), "SHA384withRSA");

            assertEquals("SHA256withRSA", CryptoUtils.getSignatureAlgorithm(key, cert));
        }

        @Test
        @DisplayName("RSA cert + CA sigAlg=SHA512withRSA → SHA256withRSA")
        void rsaCert_caSignedWithSha512_shouldStillReturnSha256WithRsa() {
            RSAPrivateKey key = mock(RSAPrivateKey.class);
            X509Certificate cert = certWithPublicKey(mock(RSAPublicKey.class), "SHA512withRSA");

            assertEquals("SHA256withRSA", CryptoUtils.getSignatureAlgorithm(key, cert));
        }

        @Test
        @DisplayName("RSA cert + CA sigAlg=SHA256withRSA → SHA256withRSA")
        void rsaCert_caSignedWithSha256_returnsSha256WithRsa() {
            RSAPrivateKey key = mock(RSAPrivateKey.class);
            X509Certificate cert = certWithPublicKey(mock(RSAPublicKey.class), "SHA256withRSA");

            assertEquals("SHA256withRSA", CryptoUtils.getSignatureAlgorithm(key, cert));
        }

        @Test
        @DisplayName("RSA cert + cross-algo CA (SHA384withECDSA) → SHA256withRSA")
        void rsaCert_crossAlgoCaSig_returnsSha256WithRsa() {
            RSAPrivateKey key = mock(RSAPrivateKey.class);
            X509Certificate cert = certWithPublicKey(mock(RSAPublicKey.class), "SHA384withECDSA");

            assertEquals("SHA256withRSA", CryptoUtils.getSignatureAlgorithm(key, cert));
        }

        @Test
        @DisplayName("EC cert P-256 → SHA256withECDSA (CA imzasından bağımsız)")
        void ecCertP256_returnsSha256WithEcdsa() {
            ECPrivateKey key = mockECPrivateKey(256);
            X509Certificate cert = certWithPublicKey(mockECPublicKey(256), "SHA384withRSA");

            assertEquals("SHA256withECDSA", CryptoUtils.getSignatureAlgorithm(key, cert));
        }

        @Test
        @DisplayName("EC cert P-384 → SHA384withECDSA")
        void ecCertP384_returnsSha384WithEcdsa() {
            ECPrivateKey key = mockECPrivateKey(384);
            X509Certificate cert = certWithPublicKey(mockECPublicKey(384), "SHA256withRSA");

            assertEquals("SHA384withECDSA", CryptoUtils.getSignatureAlgorithm(key, cert));
        }

        @Test
        @DisplayName("EC cert P-521 → SHA512withECDSA")
        void ecCertP521_returnsSha512WithEcdsa() {
            ECPrivateKey key = mockECPrivateKey(521);
            X509Certificate cert = certWithPublicKey(mockECPublicKey(521), "SHA384withECDSA");

            assertEquals("SHA512withECDSA", CryptoUtils.getSignatureAlgorithm(key, cert));
        }

        @Test
        @DisplayName("null certificate → key-based fallback")
        void nullCertificate_shouldFallbackToKeyBased() {
            RSAPrivateKey key = mock(RSAPrivateKey.class);
            assertEquals("SHA256withRSA", CryptoUtils.getSignatureAlgorithm(key, null));
        }

        @Test
        @DisplayName("cert without sigAlgName + RSA public key → SHA256withRSA")
        void certWithNullSigAlg_rsaPublicKey_shouldReturnDefaultRsa() {
            RSAPrivateKey key = mock(RSAPrivateKey.class);
            X509Certificate cert = certWithPublicKey(mock(RSAPublicKey.class), null);

            assertEquals("SHA256withRSA", CryptoUtils.getSignatureAlgorithm(key, cert));
        }

        @Test
        @DisplayName("cert with null public key → key-based fallback")
        void certWithNullPublicKey_shouldFallbackToKeyBased() {
            RSAPrivateKey key = mock(RSAPrivateKey.class);
            X509Certificate cert = mock(X509Certificate.class);
            lenient().when(cert.getSigAlgName()).thenReturn("SHA384withECDSA");
            when(cert.getPublicKey()).thenReturn(null);

            assertEquals("SHA256withRSA", CryptoUtils.getSignatureAlgorithm(key, cert));
        }
    }

    private ECPrivateKey mockECPrivateKey(int bitLength) {
        ECPrivateKey key = mock(ECPrivateKey.class);
        ECParameterSpec params = mock(ECParameterSpec.class);
        BigInteger order = BigInteger.ONE.shiftLeft(bitLength - 1);
        lenient().when(params.getOrder()).thenReturn(order);
        lenient().when(key.getParams()).thenReturn(params);
        return key;
    }

    private ECPublicKey mockECPublicKey(int bitLength) {
        ECPublicKey key = mock(ECPublicKey.class);
        ECParameterSpec params = mock(ECParameterSpec.class);
        BigInteger order = BigInteger.ONE.shiftLeft(bitLength - 1);
        lenient().when(params.getOrder()).thenReturn(order);
        lenient().when(key.getParams()).thenReturn(params);
        return key;
    }

    private X509Certificate certWithPublicKey(PublicKey publicKey, String sigAlgName) {
        X509Certificate cert = mock(X509Certificate.class);
        when(cert.getPublicKey()).thenReturn(publicKey);
        lenient().when(cert.getSigAlgName()).thenReturn(sigAlgName);
        return cert;
    }
}
