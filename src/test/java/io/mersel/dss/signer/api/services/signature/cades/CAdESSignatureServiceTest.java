package io.mersel.dss.signer.api.services.signature.cades;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import io.mersel.dss.signer.api.exceptions.SignatureException;
import io.mersel.dss.signer.api.models.SignResponse;
import io.mersel.dss.signer.api.models.SigningMaterial;
import io.mersel.dss.signer.api.services.crypto.CryptoSignerService;
import io.mersel.dss.signer.api.services.crypto.DigestAlgorithmResolverService;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.concurrent.Semaphore;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class CAdESSignatureServiceTest {

    @Mock private CAdESService cadesService;
    @Mock private CryptoSignerService cryptoSigner;
    @Mock private DigestAlgorithmResolverService digestAlgorithmResolver;

    private static KeyPair testKeyPair;
    private static X509Certificate testCertificate;

    private Semaphore semaphore;
    private CAdESSignatureService service;

    @BeforeAll
    static void initCrypto() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        testKeyPair = kpg.generateKeyPair();

        X500Name subject = new X500Name("CN=CAdES Test, O=Mersel, C=TR");
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 365L * 24 * 60 * 60 * 1000);

        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(
                testKeyPair.getPublic().getEncoded());
        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                subject, serial, notBefore, notAfter, subject, spki);

        testCertificate = new JcaX509CertificateConverter().getCertificate(
                certBuilder.build(
                        new JcaContentSignerBuilder("SHA256withRSA")
                                .build(testKeyPair.getPrivate())));
    }

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        semaphore = new Semaphore(2);
        service = new CAdESSignatureService(cadesService, cryptoSigner, digestAlgorithmResolver, semaphore);
    }

    private SigningMaterial createTestMaterial() {
        return new SigningMaterial(
                testKeyPair.getPrivate(),
                testCertificate,
                Collections.singletonList(testCertificate));
    }

    private void setupDefaultMocks() throws Exception {
        when(digestAlgorithmResolver.resolveDigestAlgorithm(any(X509Certificate.class)))
                .thenReturn(DigestAlgorithm.SHA256);

        ToBeSigned toBeSigned = new ToBeSigned(new byte[]{1, 2, 3});
        when(cadesService.getDataToSign(any(DSSDocument.class), any(CAdESSignatureParameters.class)))
                .thenReturn(toBeSigned);

        SignatureValue signatureValue = new SignatureValue(
                SignatureAlgorithm.RSA_SHA256, new byte[]{10, 20, 30});
        when(cryptoSigner.sign(any(ToBeSigned.class), any(PrivateKey.class),
                any(DigestAlgorithm.class)))
                .thenReturn(signatureValue);

        DSSDocument signedDoc = new InMemoryDocument("signed-cms-envelope".getBytes(), "signed.p7s");
        when(cadesService.signDocument(any(DSSDocument.class), any(CAdESSignatureParameters.class),
                any(SignatureValue.class)))
                .thenReturn(signedDoc);
    }

    @Nested
    class SuccessfulSigning {

        @Test
        void attachedMode_shouldReturnSignedCmsEnvelope() throws Exception {
            setupDefaultMocks();
            SigningMaterial material = createTestMaterial();
            InputStream input = new ByteArrayInputStream("test-content".getBytes());

            SignResponse response = service.signData(input, false, material);

            assertNotNull(response);
            assertNotNull(response.getSignedDocument());
            assertNotNull(response.getSignatureValue());
            assertTrue(response.getSignedDocument().length > 0);
        }

        @Test
        void detachedMode_shouldReturnSignedCmsEnvelope() throws Exception {
            setupDefaultMocks();
            SigningMaterial material = createTestMaterial();
            InputStream input = new ByteArrayInputStream("test-content".getBytes());

            SignResponse response = service.signData(input, true, material);

            assertNotNull(response);
            assertNotNull(response.getSignedDocument());
            assertNotNull(response.getSignatureValue());
        }

        @Test
        void shouldReturnBase64EncodedSignatureValue() throws Exception {
            byte[] rawSigBytes = new byte[]{10, 20, 30};
            setupDefaultMocks();
            SigningMaterial material = createTestMaterial();
            InputStream input = new ByteArrayInputStream("test".getBytes());

            SignResponse response = service.signData(input, false, material);

            String expectedBase64 = Base64.getEncoder().encodeToString(rawSigBytes);
            assertEquals(expectedBase64, response.getSignatureValue());
        }

        @Test
        void shouldReturnSignedDocumentBytes() throws Exception {
            setupDefaultMocks();
            SigningMaterial material = createTestMaterial();
            InputStream input = new ByteArrayInputStream("content".getBytes());

            SignResponse response = service.signData(input, false, material);

            assertArrayEquals("signed-cms-envelope".getBytes(), response.getSignedDocument());
        }
    }

    @Nested
    class ParameterConfiguration {

        @Test
        void attachedMode_shouldUseEnvelopingPackaging() throws Exception {
            setupDefaultMocks();
            SigningMaterial material = createTestMaterial();
            ArgumentCaptor<CAdESSignatureParameters> paramsCaptor =
                    ArgumentCaptor.forClass(CAdESSignatureParameters.class);

            service.signData(new ByteArrayInputStream("test".getBytes()), false, material);

            verify(cadesService).getDataToSign(any(DSSDocument.class), paramsCaptor.capture());
            assertEquals(SignaturePackaging.ENVELOPING, paramsCaptor.getValue().getSignaturePackaging());
        }

        @Test
        void detachedMode_shouldUseDetachedPackaging() throws Exception {
            setupDefaultMocks();
            SigningMaterial material = createTestMaterial();
            ArgumentCaptor<CAdESSignatureParameters> paramsCaptor =
                    ArgumentCaptor.forClass(CAdESSignatureParameters.class);

            service.signData(new ByteArrayInputStream("test".getBytes()), true, material);

            verify(cadesService).getDataToSign(any(DSSDocument.class), paramsCaptor.capture());
            assertEquals(SignaturePackaging.DETACHED, paramsCaptor.getValue().getSignaturePackaging());
        }

        @Test
        void shouldSetBaselineBLevel() throws Exception {
            setupDefaultMocks();
            SigningMaterial material = createTestMaterial();
            ArgumentCaptor<CAdESSignatureParameters> paramsCaptor =
                    ArgumentCaptor.forClass(CAdESSignatureParameters.class);

            service.signData(new ByteArrayInputStream("test".getBytes()), false, material);

            verify(cadesService).getDataToSign(any(DSSDocument.class), paramsCaptor.capture());
            assertEquals(SignatureLevel.CAdES_BASELINE_B, paramsCaptor.getValue().getSignatureLevel());
        }

        @Test
        void shouldUseDigestFromResolver() throws Exception {
            when(digestAlgorithmResolver.resolveDigestAlgorithm(any(X509Certificate.class)))
                    .thenReturn(DigestAlgorithm.SHA384);

            ToBeSigned toBeSigned = new ToBeSigned(new byte[]{1});
            when(cadesService.getDataToSign(any(DSSDocument.class), any(CAdESSignatureParameters.class)))
                    .thenReturn(toBeSigned);
            when(cryptoSigner.sign(any(), any(), any()))
                    .thenReturn(new SignatureValue(SignatureAlgorithm.RSA_SHA384, new byte[]{1}));
            when(cadesService.signDocument(any(), any(), any()))
                    .thenReturn(new InMemoryDocument(new byte[]{1}, "s.p7s"));

            SigningMaterial material = createTestMaterial();
            ArgumentCaptor<CAdESSignatureParameters> paramsCaptor =
                    ArgumentCaptor.forClass(CAdESSignatureParameters.class);

            service.signData(new ByteArrayInputStream("test".getBytes()), false, material);

            verify(cadesService).getDataToSign(any(DSSDocument.class), paramsCaptor.capture());
            assertEquals(DigestAlgorithm.SHA384, paramsCaptor.getValue().getDigestAlgorithm());
        }

        @Test
        void shouldSetSigningCertificateAndChain() throws Exception {
            setupDefaultMocks();
            SigningMaterial material = createTestMaterial();
            ArgumentCaptor<CAdESSignatureParameters> paramsCaptor =
                    ArgumentCaptor.forClass(CAdESSignatureParameters.class);

            service.signData(new ByteArrayInputStream("test".getBytes()), false, material);

            verify(cadesService).getDataToSign(any(DSSDocument.class), paramsCaptor.capture());
            CAdESSignatureParameters params = paramsCaptor.getValue();
            assertNotNull(params.getSigningCertificate());
            assertNotNull(params.getCertificateChain());
            assertFalse(params.getCertificateChain().isEmpty());
        }
    }

    @Nested
    class DssServiceInteraction {

        @Test
        void shouldCallGetDataToSign_thenSign_thenSignDocument() throws Exception {
            setupDefaultMocks();
            SigningMaterial material = createTestMaterial();

            service.signData(new ByteArrayInputStream("test".getBytes()), false, material);

            org.mockito.InOrder inOrder = inOrder(cadesService, cryptoSigner);
            inOrder.verify(cadesService).getDataToSign(
                    any(DSSDocument.class), any(CAdESSignatureParameters.class));
            inOrder.verify(cryptoSigner).sign(
                    any(ToBeSigned.class), any(PrivateKey.class),
                    any(DigestAlgorithm.class));
            inOrder.verify(cadesService).signDocument(
                    any(DSSDocument.class), any(CAdESSignatureParameters.class),
                    any(SignatureValue.class));
        }

        @Test
        void shouldPassPrivateKeyAndCertificateToCryptoSigner() throws Exception {
            setupDefaultMocks();
            SigningMaterial material = createTestMaterial();

            service.signData(new ByteArrayInputStream("test".getBytes()), false, material);

            verify(cryptoSigner).sign(
                    any(ToBeSigned.class),
                    eq(testKeyPair.getPrivate()),
                    eq(DigestAlgorithm.SHA256));
        }

        @Test
        void shouldPassDigestAlgorithmToCryptoSigner() throws Exception {
            when(digestAlgorithmResolver.resolveDigestAlgorithm(any(X509Certificate.class)))
                    .thenReturn(DigestAlgorithm.SHA512);
            ToBeSigned toBeSigned = new ToBeSigned(new byte[]{1});
            when(cadesService.getDataToSign(any(), any())).thenReturn(toBeSigned);
            when(cryptoSigner.sign(any(), any(), any()))
                    .thenReturn(new SignatureValue(SignatureAlgorithm.RSA_SHA512, new byte[]{1}));
            when(cadesService.signDocument(any(), any(), any()))
                    .thenReturn(new InMemoryDocument(new byte[]{1}, "s.p7s"));

            SigningMaterial material = createTestMaterial();

            service.signData(new ByteArrayInputStream("test".getBytes()), false, material);

            verify(cryptoSigner).sign(
                    any(ToBeSigned.class), any(PrivateKey.class),
                    eq(DigestAlgorithm.SHA512));
        }
    }

    @Nested
    class SemaphoreManagement {

        @Test
        void shouldReleaseSemaphoreAfterSuccess() throws Exception {
            setupDefaultMocks();
            SigningMaterial material = createTestMaterial();
            int permitsBefore = semaphore.availablePermits();

            service.signData(new ByteArrayInputStream("test".getBytes()), false, material);

            assertEquals(permitsBefore, semaphore.availablePermits());
        }

        @Test
        void shouldReleaseSemaphoreAfterFailure() throws Exception {
            when(digestAlgorithmResolver.resolveDigestAlgorithm(any(X509Certificate.class)))
                    .thenReturn(DigestAlgorithm.SHA256);
            when(cadesService.getDataToSign(any(DSSDocument.class), any(CAdESSignatureParameters.class)))
                    .thenThrow(new RuntimeException("DSS error"));

            SigningMaterial material = createTestMaterial();
            int permitsBefore = semaphore.availablePermits();

            assertThrows(SignatureException.class,
                    () -> service.signData(new ByteArrayInputStream("test".getBytes()), false, material));

            assertEquals(permitsBefore, semaphore.availablePermits());
        }
    }

    @Nested
    class ErrorHandling {

        @Test
        void dssGetDataToSignFailure_shouldThrowSignatureException() throws Exception {
            when(digestAlgorithmResolver.resolveDigestAlgorithm(any(X509Certificate.class)))
                    .thenReturn(DigestAlgorithm.SHA256);
            when(cadesService.getDataToSign(any(DSSDocument.class), any(CAdESSignatureParameters.class)))
                    .thenThrow(new RuntimeException("DSS internal error"));

            SigningMaterial material = createTestMaterial();

            SignatureException ex = assertThrows(SignatureException.class,
                    () -> service.signData(new ByteArrayInputStream("test".getBytes()), false, material));
            assertEquals("CADES_SIGN_ERROR", ex.getErrorCode());
        }

        @Test
        void cryptoSignerFailure_shouldThrowSignatureException() throws Exception {
            when(digestAlgorithmResolver.resolveDigestAlgorithm(any(X509Certificate.class)))
                    .thenReturn(DigestAlgorithm.SHA256);
            when(cadesService.getDataToSign(any(DSSDocument.class), any(CAdESSignatureParameters.class)))
                    .thenReturn(new ToBeSigned(new byte[]{1}));
            when(cryptoSigner.sign(any(ToBeSigned.class), any(PrivateKey.class),
                    any(DigestAlgorithm.class)))
                    .thenThrow(new RuntimeException("HSM error"));

            SigningMaterial material = createTestMaterial();

            SignatureException ex = assertThrows(SignatureException.class,
                    () -> service.signData(new ByteArrayInputStream("test".getBytes()), false, material));
            assertEquals("CADES_SIGN_ERROR", ex.getErrorCode());
        }

        @Test
        void signDocumentFailure_shouldThrowSignatureException() throws Exception {
            when(digestAlgorithmResolver.resolveDigestAlgorithm(any(X509Certificate.class)))
                    .thenReturn(DigestAlgorithm.SHA256);
            when(cadesService.getDataToSign(any(DSSDocument.class), any(CAdESSignatureParameters.class)))
                    .thenReturn(new ToBeSigned(new byte[]{1}));
            when(cryptoSigner.sign(any(), any(), any()))
                    .thenReturn(new SignatureValue(SignatureAlgorithm.RSA_SHA256, new byte[]{1}));
            when(cadesService.signDocument(any(DSSDocument.class), any(CAdESSignatureParameters.class),
                    any(SignatureValue.class)))
                    .thenThrow(new RuntimeException("CMS generation failed"));

            SigningMaterial material = createTestMaterial();

            SignatureException ex = assertThrows(SignatureException.class,
                    () -> service.signData(new ByteArrayInputStream("test".getBytes()), false, material));
            assertEquals("CADES_SIGN_ERROR", ex.getErrorCode());
        }

        @Test
        void signatureExceptionFromCryptoSigner_shouldPropagateDirectly() throws Exception {
            when(digestAlgorithmResolver.resolveDigestAlgorithm(any(X509Certificate.class)))
                    .thenReturn(DigestAlgorithm.SHA256);
            when(cadesService.getDataToSign(any(), any()))
                    .thenReturn(new ToBeSigned(new byte[]{1}));
            SignatureException original = new SignatureException("HSM_ERROR", "HSM connection lost");
            when(cryptoSigner.sign(any(), any(), any())).thenThrow(original);

            SigningMaterial material = createTestMaterial();

            SignatureException ex = assertThrows(SignatureException.class,
                    () -> service.signData(new ByteArrayInputStream("test".getBytes()), false, material));
            assertSame(original, ex);
            assertEquals("HSM_ERROR", ex.getErrorCode());
        }
    }
}
