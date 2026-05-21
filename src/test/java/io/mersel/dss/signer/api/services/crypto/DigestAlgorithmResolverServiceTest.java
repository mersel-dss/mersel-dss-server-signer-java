package io.mersel.dss.signer.api.services.crypto;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import io.qameta.allure.Description;
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
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@Epic("Crypto Conformance")
@Feature("Digest Algorithm Resolver")
@Severity(SeverityLevel.CRITICAL)
class DigestAlgorithmResolverServiceTest {

    private DigestAlgorithmResolverService resolverWithoutOverride() {
        return new DigestAlgorithmResolverService("");
    }

    private DigestAlgorithmResolverService resolverWithOverride(String forced) {
        return new DigestAlgorithmResolverService(forced);
    }

    @Test
    @DisplayName("null certificate → SHA-256 default")
    void nullCertificate_shouldReturnSha256Default() {
        assertEquals(DigestAlgorithm.SHA256, resolverWithoutOverride().resolveDigestAlgorithm(null));
    }

    @Nested
    @DisplayName("RSA public key — daima SHA-256 (e-Fatura/KamuSM konvansiyonu)")
    class RsaPublicKeyTests {

        @Test
        @DisplayName("RSA cert + CA sigAlg=SHA256withRSA → SHA-256")
        void rsaCertSignedWithSha256_returnsSha256() {
            X509Certificate cert = rsaCertWithSigAlg("SHA256withRSA");
            assertEquals(DigestAlgorithm.SHA256, resolverWithoutOverride().resolveDigestAlgorithm(cert));
        }

        /**
         * Regression: İZİBİZ test ortamında (20.05.2026) yakalanan asıl
         * vaka. KamuSM ara-CA'sı SHA-384'e geçtiğinde, RSA-2048 son-kullanıcı
         * sertifikasıyla üretilen imzalar yanlışlıkla rsa-sha384'e fırlamıştı.
         * Düzeltmeden sonra: public key parametresi RSA olduğu için
         * her durumda SHA-256 döner.
         */
        @Test
        @DisplayName("Regression (İzibiz 20.05.2026): RSA cert + CA sigAlg=SHA384withRSA → SHA-256 (CA imzası dikkate alınmaz)")
        void rsaCertSignedBySha384Ca_stillReturnsSha256() {
            X509Certificate cert = rsaCertWithSigAlg("SHA384withRSA");
            assertEquals(DigestAlgorithm.SHA256, resolverWithoutOverride().resolveDigestAlgorithm(cert));
        }

        @Test
        @DisplayName("RSA cert + CA sigAlg=SHA512withRSA → SHA-256")
        void rsaCertSignedBySha512Ca_stillReturnsSha256() {
            X509Certificate cert = rsaCertWithSigAlg("SHA512withRSA");
            assertEquals(DigestAlgorithm.SHA256, resolverWithoutOverride().resolveDigestAlgorithm(cert));
        }

        @Test
        @DisplayName("RSA cert + CA sigAlg=SHA384withECDSA → SHA-256 (cross-algo CA)")
        void rsaCertSignedByEcdsaCa_returnsSha256() {
            X509Certificate cert = rsaCertWithSigAlg("SHA384withECDSA");
            assertEquals(DigestAlgorithm.SHA256, resolverWithoutOverride().resolveDigestAlgorithm(cert));
        }

        @Test
        @DisplayName("RSA cert + boş sigAlg → SHA-256")
        void rsaCertWithEmptySigAlg_returnsSha256() {
            X509Certificate cert = rsaCertWithSigAlg("");
            assertEquals(DigestAlgorithm.SHA256, resolverWithoutOverride().resolveDigestAlgorithm(cert));
        }
    }

    @Nested
    @DisplayName("EC public key — curve büyüklüğüne göre (NIST SP 800-57)")
    class EcPublicKeyTests {

        @Test
        @DisplayName("P-256 → SHA-256")
        void ecP256_returnsSha256() {
            X509Certificate cert = ecCert(256, "SHA256withECDSA");
            assertEquals(DigestAlgorithm.SHA256, resolverWithoutOverride().resolveDigestAlgorithm(cert));
        }

        @Test
        @DisplayName("P-384 → SHA-384")
        void ecP384_returnsSha384() {
            X509Certificate cert = ecCert(384, "SHA384withECDSA");
            assertEquals(DigestAlgorithm.SHA384, resolverWithoutOverride().resolveDigestAlgorithm(cert));
        }

        @Test
        @DisplayName("P-521 → SHA-512")
        void ecP521_returnsSha512() {
            X509Certificate cert = ecCert(521, "SHA512withECDSA");
            assertEquals(DigestAlgorithm.SHA512, resolverWithoutOverride().resolveDigestAlgorithm(cert));
        }

        @Test
        @DisplayName("EC P-384 cert + CA sigAlg=SHA256withRSA → SHA-384 (curve büyüklüğü)")
        void ecP384CertSignedBySha256Ca_returnsSha384() {
            // CA'nın imza algoritması ne olursa olsun, EC curve P-384 ise SHA-384.
            X509Certificate cert = ecCert(384, "SHA256withRSA");
            assertEquals(DigestAlgorithm.SHA384, resolverWithoutOverride().resolveDigestAlgorithm(cert));
        }
    }

    @Nested
    @DisplayName("Override (signing.digest.algorithm property)")
    class OverrideTests {

        @Test
        @DisplayName("Override SHA384 + RSA cert → SHA-384")
        void overrideSha384_appliesGlobally() {
            X509Certificate cert = rsaCertWithSigAlg("SHA256withRSA");
            assertEquals(DigestAlgorithm.SHA384, resolverWithOverride("SHA384").resolveDigestAlgorithm(cert));
        }

        @Test
        @DisplayName("Override SHA-256 (hyphen variant) → SHA-256")
        void overrideAcceptsHyphenAndUnderscoreVariants() {
            X509Certificate cert = rsaCertWithSigAlg("SHA384withRSA");
            assertEquals(DigestAlgorithm.SHA256, resolverWithOverride("SHA-256").resolveDigestAlgorithm(cert));
        }

        @Test
        @DisplayName("Override + null cert → override değeri")
        void overrideAppliesEvenWhenCertIsNull() {
            assertEquals(DigestAlgorithm.SHA512, resolverWithOverride("sha512").resolveDigestAlgorithm(null));
        }

        @Test
        @DisplayName("Geçersiz override → otomatik çözümlemeye düşer (SHA-256)")
        void invalidOverrideValue_fallsBackToAuto() {
            X509Certificate cert = rsaCertWithSigAlg("SHA256withRSA");
            assertEquals(DigestAlgorithm.SHA256, resolverWithOverride("FOOBAR").resolveDigestAlgorithm(cert));
        }

        @Test
        @DisplayName("Boş override → otomatik çözümleme")
        void blankOverride_fallsBackToAuto() {
            X509Certificate cert = rsaCertWithSigAlg("SHA256withRSA");
            assertEquals(DigestAlgorithm.SHA256, resolverWithOverride("   ").resolveDigestAlgorithm(cert));
        }
    }

    @Nested
    @DisplayName("Edge cases")
    class EdgeCases {

        @Test
        @DisplayName("public key null → SHA-256 default")
        @Description("Bazı edge senaryolarda (mock cert, kısmen parse edilmiş cert) public key null olabilir.")
        void nullPublicKey_returnsDefault() {
            X509Certificate cert = mock(X509Certificate.class);
            when(cert.getPublicKey()).thenReturn(null);
            assertEquals(DigestAlgorithm.SHA256, resolverWithoutOverride().resolveDigestAlgorithm(cert));
        }

        @Test
        @DisplayName("Bilinmeyen public key tipi → SHA-256 default")
        void unknownPublicKeyType_returnsDefault() {
            X509Certificate cert = mock(X509Certificate.class);
            PublicKey unknownKey = mock(PublicKey.class);
            when(unknownKey.getAlgorithm()).thenReturn("DSA");
            when(cert.getPublicKey()).thenReturn(unknownKey);
            assertEquals(DigestAlgorithm.SHA256, resolverWithoutOverride().resolveDigestAlgorithm(cert));
        }
    }

    // --- Test fixture helpers -------------------------------------------------

    private X509Certificate rsaCertWithSigAlg(String sigAlgName) {
        X509Certificate cert = mock(X509Certificate.class);
        RSAPublicKey rsaKey = mock(RSAPublicKey.class);
        lenient().when(rsaKey.getAlgorithm()).thenReturn("RSA");
        when(cert.getPublicKey()).thenReturn(rsaKey);
        lenient().when(cert.getSigAlgName()).thenReturn(sigAlgName);
        return cert;
    }

    private X509Certificate ecCert(int curveBits, String sigAlgName) {
        X509Certificate cert = mock(X509Certificate.class);
        ECPublicKey ecKey = mock(ECPublicKey.class);
        ECParameterSpec params = mock(ECParameterSpec.class);
        // Sadece bit length değerini gözetiyoruz; order bizzat o bit sayısında.
        BigInteger order = BigInteger.ONE.shiftLeft(curveBits - 1);
        lenient().when(params.getOrder()).thenReturn(order);
        lenient().when(ecKey.getParams()).thenReturn(params);
        lenient().when(ecKey.getAlgorithm()).thenReturn("EC");
        when(cert.getPublicKey()).thenReturn(ecKey);
        lenient().when(cert.getSigAlgName()).thenReturn(sigAlgName);
        return cert;
    }
}
