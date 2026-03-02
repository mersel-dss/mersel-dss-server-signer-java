package io.mersel.dss.signer.api.util;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class CryptoUtilsSignatureAlgorithmTest {

    @Nested
    @DisplayName("getSignatureAlgorithm(PrivateKey) - key-only overload")
    class KeyOnlyTests {

        @Test
        void rsaKey_shouldReturnSha256WithRsa() {
            RSAPrivateKey key = mock(RSAPrivateKey.class);
            assertEquals("SHA256withRSA", CryptoUtils.getSignatureAlgorithm(key));
        }

        @Test
        void ecKeyP256_shouldReturnSha256WithEcdsa() {
            ECPrivateKey key = mockECKey(256);
            assertEquals("SHA256withECDSA", CryptoUtils.getSignatureAlgorithm(key));
        }

        @Test
        void ecKeyP384_shouldReturnSha384WithEcdsa() {
            ECPrivateKey key = mockECKey(384);
            assertEquals("SHA384withECDSA", CryptoUtils.getSignatureAlgorithm(key));
        }

        @Test
        void ecKeyP521_shouldReturnSha512WithEcdsa() {
            ECPrivateKey key = mockECKey(521);
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
    @DisplayName("getSignatureAlgorithm(PrivateKey, X509Certificate) - cert-aware overload")
    class CertificateAwareTests {

        @Test
        void rsaCert_sha384_shouldReturnSha384WithRsa() {
            RSAPrivateKey key = mock(RSAPrivateKey.class);
            X509Certificate cert = mockCertWithPublicKey(mock(RSAPublicKey.class), "SHA384withECDSA");

            assertEquals("SHA384withRSA", CryptoUtils.getSignatureAlgorithm(key, cert));
        }

        @Test
        void rsaCert_sha256_shouldReturnSha256WithRsa() {
            RSAPrivateKey key = mock(RSAPrivateKey.class);
            X509Certificate cert = mockCertWithPublicKey(mock(RSAPublicKey.class), "SHA256withRSA");

            assertEquals("SHA256withRSA", CryptoUtils.getSignatureAlgorithm(key, cert));
        }

        @Test
        void rsaCert_sha512_shouldReturnSha512WithRsa() {
            RSAPrivateKey key = mock(RSAPrivateKey.class);
            X509Certificate cert = mockCertWithPublicKey(mock(RSAPublicKey.class), "SHA512withRSA");

            assertEquals("SHA512withRSA", CryptoUtils.getSignatureAlgorithm(key, cert));
        }

        @Test
        void ecCert_shouldUseCertSigAlgDirectly() {
            ECPrivateKey key = mockECKey(384);
            X509Certificate cert = mockCertWithPublicKey(mock(ECPublicKey.class), "SHA384withECDSA");

            assertEquals("SHA384withECDSA", CryptoUtils.getSignatureAlgorithm(key, cert));
        }

        @Test
        void nullCertificate_shouldFallbackToKeyBased() {
            RSAPrivateKey key = mock(RSAPrivateKey.class);
            assertEquals("SHA256withRSA", CryptoUtils.getSignatureAlgorithm(key, null));
        }

        @Test
        void certWithNullSigAlg_rsaPublicKey_shouldReturnDefaultRsa() {
            RSAPrivateKey key = mock(RSAPrivateKey.class);
            X509Certificate cert = mockCertWithPublicKey(mock(RSAPublicKey.class), null);

            assertEquals("SHA256withRSA", CryptoUtils.getSignatureAlgorithm(key, cert));
        }

        @Test
        void certWithNullPublicKey_shouldFallbackToKeyBased() {
            RSAPrivateKey key = mock(RSAPrivateKey.class);
            X509Certificate cert = mock(X509Certificate.class);
            when(cert.getSigAlgName()).thenReturn("SHA384withECDSA");
            when(cert.getPublicKey()).thenReturn(null);

            assertEquals("SHA256withRSA", CryptoUtils.getSignatureAlgorithm(key, cert));
        }
    }

    private ECPrivateKey mockECKey(int bitLength) {
        ECPrivateKey key = mock(ECPrivateKey.class);
        ECParameterSpec params = mock(ECParameterSpec.class);
        BigInteger order = BigInteger.valueOf(2).pow(bitLength).subtract(BigInteger.ONE);
        when(params.getOrder()).thenReturn(order);
        when(key.getParams()).thenReturn(params);
        return key;
    }

    private X509Certificate mockCertWithPublicKey(PublicKey publicKey, String sigAlgName) {
        X509Certificate cert = mock(X509Certificate.class);
        when(cert.getPublicKey()).thenReturn(publicKey);
        when(cert.getSigAlgName()).thenReturn(sigAlgName);
        return cert;
    }
}

