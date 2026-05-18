package io.mersel.dss.signer.api.services.crypto;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Severity;
import io.qameta.allure.SeverityLevel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@Epic("Crypto Conformance")
@Feature("Digest Algorithm Resolver")
@Severity(SeverityLevel.NORMAL)
class DigestAlgorithmResolverServiceTest {

    private DigestAlgorithmResolverService resolver;

    @BeforeEach
    void setUp() {
        resolver = new DigestAlgorithmResolverService();
    }

    @Test
    void nullCertificate_shouldReturnSha256Default() {
        assertEquals(DigestAlgorithm.SHA256, resolver.resolveDigestAlgorithm(null));
    }

    @Test
    void sha256WithRsa_shouldReturnSha256() {
        X509Certificate cert = mock(X509Certificate.class);
        when(cert.getSigAlgName()).thenReturn("SHA256withRSA");
        assertEquals(DigestAlgorithm.SHA256, resolver.resolveDigestAlgorithm(cert));
    }

    @Test
    void sha384WithEcdsa_shouldReturnSha384() {
        X509Certificate cert = mock(X509Certificate.class);
        when(cert.getSigAlgName()).thenReturn("SHA384withECDSA");
        assertEquals(DigestAlgorithm.SHA384, resolver.resolveDigestAlgorithm(cert));
    }

    @Test
    void sha512WithEcdsa_shouldReturnSha512() {
        X509Certificate cert = mock(X509Certificate.class);
        when(cert.getSigAlgName()).thenReturn("SHA512withECDSA");
        assertEquals(DigestAlgorithm.SHA512, resolver.resolveDigestAlgorithm(cert));
    }

    @Test
    void sha1WithRsa_shouldReturnSha1() {
        X509Certificate cert = mock(X509Certificate.class);
        when(cert.getSigAlgName()).thenReturn("SHA1withRSA");
        assertEquals(DigestAlgorithm.SHA1, resolver.resolveDigestAlgorithm(cert));
    }

    @Test
    void emptySigAlgName_shouldFallbackToDefault() {
        X509Certificate cert = mock(X509Certificate.class);
        when(cert.getSigAlgName()).thenReturn("");
        when(cert.getPublicKey()).thenReturn(null);
        assertEquals(DigestAlgorithm.SHA256, resolver.resolveDigestAlgorithm(cert));
    }
}
