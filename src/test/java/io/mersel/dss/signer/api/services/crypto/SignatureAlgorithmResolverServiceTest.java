package io.mersel.dss.signer.api.services.crypto;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Severity;
import io.qameta.allure.SeverityLevel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.PrivateKey;

import static org.junit.jupiter.api.Assertions.*;

@Epic("Crypto Conformance")
@Feature("Signature Algorithm Resolver")
@Severity(SeverityLevel.NORMAL)
class SignatureAlgorithmResolverServiceTest {

    private SignatureAlgorithmResolverService resolver;

    @BeforeEach
    void setUp() {
        resolver = new SignatureAlgorithmResolverService();
    }

    @Test
    void rsaWithSha256_shouldReturnRsaSha256() {
        PrivateKey key = new StubPrivateKey("RSA");
        assertEquals(SignatureAlgorithm.RSA_SHA256,
                resolver.determineSignatureAlgorithm(key, DigestAlgorithm.SHA256));
    }

    @Test
    void rsaWithSha384_shouldReturnRsaSha384() {
        PrivateKey key = new StubPrivateKey("RSA");
        assertEquals(SignatureAlgorithm.RSA_SHA384,
                resolver.determineSignatureAlgorithm(key, DigestAlgorithm.SHA384));
    }

    @Test
    void rsaWithSha512_shouldReturnRsaSha512() {
        PrivateKey key = new StubPrivateKey("RSA");
        assertEquals(SignatureAlgorithm.RSA_SHA512,
                resolver.determineSignatureAlgorithm(key, DigestAlgorithm.SHA512));
    }

    @Test
    void ecWithSha256_shouldReturnEcdsaSha256() {
        PrivateKey key = new StubPrivateKey("EC");
        assertEquals(SignatureAlgorithm.ECDSA_SHA256,
                resolver.determineSignatureAlgorithm(key, DigestAlgorithm.SHA256));
    }

    @Test
    void ecWithSha384_shouldReturnEcdsaSha384() {
        PrivateKey key = new StubPrivateKey("EC");
        assertEquals(SignatureAlgorithm.ECDSA_SHA384,
                resolver.determineSignatureAlgorithm(key, DigestAlgorithm.SHA384));
    }

    @Test
    void ecWithSha512_shouldReturnEcdsaSha512() {
        PrivateKey key = new StubPrivateKey("EC");
        assertEquals(SignatureAlgorithm.ECDSA_SHA512,
                resolver.determineSignatureAlgorithm(key, DigestAlgorithm.SHA512));
    }

    @Test
    void ecdsaAlgorithmName_shouldResolveAsEcdsa() {
        PrivateKey key = new StubPrivateKey("ECDSA");
        assertEquals(SignatureAlgorithm.ECDSA_SHA384,
                resolver.determineSignatureAlgorithm(key, DigestAlgorithm.SHA384));
    }

    @Test
    void unsupportedKeyAlgorithm_shouldThrow() {
        PrivateKey key = new StubPrivateKey("UNKNOWN");
        assertThrows(Exception.class, () ->
                resolver.determineSignatureAlgorithm(key, DigestAlgorithm.SHA256));
    }

    private static class StubPrivateKey implements PrivateKey {
        private final String algorithm;

        StubPrivateKey(String algorithm) {
            this.algorithm = algorithm;
        }

        @Override public String getAlgorithm() { return algorithm; }
        @Override public String getFormat() { return "PKCS#8"; }
        @Override public byte[] getEncoded() { return new byte[0]; }
    }
}
