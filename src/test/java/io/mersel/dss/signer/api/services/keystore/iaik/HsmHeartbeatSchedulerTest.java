package io.mersel.dss.signer.api.services.keystore.iaik;

import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import io.mersel.dss.signer.api.exceptions.SignatureException;
import io.mersel.dss.signer.api.models.SigningMaterial;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Severity;
import io.qameta.allure.SeverityLevel;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * {@link HsmHeartbeatScheduler} davranış kontratını test eder.
 *
 * <p>Test stratejisi: {@link IaikPkcs11Module} mock, gerçek
 * {@link IaikPkcs11Signer} + {@link SigningMaterial} (final sınıf, Mockito
 * inline yok). Scheduler interval'i unit test'te {@code @Scheduled}
 * tarafından değil; doğrudan {@code heartbeat()} manuel tetikleme ile
 * test edilir — flaky timing'den kaçınılır.</p>
 */
@Epic("PKCS#11 Integration")
@Feature("HSM Heartbeat Scheduler")
@Severity(SeverityLevel.CRITICAL)
class HsmHeartbeatSchedulerTest {

    private static X509Certificate rsaCert;
    private static final long HANDLE = 0xDEADBEEFL;

    @BeforeAll
    static void initFixture() throws Exception {
        rsaCert = newRsaCert("CN=HSM Heartbeat Test");
    }

    private HsmHeartbeatScheduler newScheduler(IaikPkcs11Module module) {
        IaikPkcs11Module.ResolvedKey rk = new IaikPkcs11Module.ResolvedKey();
        rk.alias = "heartbeat-key";
        rk.certificate = rsaCert;
        rk.certificateChain = Collections.singletonList(rsaCert);
        rk.privateKeyHandle = HANDLE;
        IaikPkcs11Signer signer = new IaikPkcs11Signer(module, rk);
        SigningMaterial material = new SigningMaterial(signer, rsaCert,
            Collections.singletonList(rsaCert));
        return new HsmHeartbeatScheduler(module, material, 60);
    }

    @Nested
    @DisplayName("Happy path")
    class HappyPath {

        @Test
        @DisplayName("heartbeat() module.heartbeatSign'\u0131 do\u011fru handle + algoritma ile \u00e7a\u011f\u0131r\u0131r")
        void heartbeat_invokesModule_withResolvedHandleAndAlgorithm() {
            IaikPkcs11Module module = mock(IaikPkcs11Module.class);
            doNothing().when(module).heartbeatSign(anyLong(), any(SignatureAlgorithm.class));

            HsmHeartbeatScheduler scheduler = newScheduler(module);
            scheduler.heartbeat();

            verify(module, times(1)).heartbeatSign(eq(HANDLE), eq(SignatureAlgorithm.RSA_SHA256));
            assertEquals(1L, scheduler.getSuccessCount());
            assertEquals(0L, scheduler.getFailureCount());
            assertEquals(0L, scheduler.getConsecutiveFailureCount());
            assertTrue(scheduler.getLastSuccessAtMillis() > 0L);
        }

        @Test
        @DisplayName("Birden fazla heartbeat() ba\u015far\u0131l\u0131 say\u0131lar\u0131 artt\u0131r\u0131r")
        void multipleHeartbeats_incrementSuccessCount() {
            IaikPkcs11Module module = mock(IaikPkcs11Module.class);
            doNothing().when(module).heartbeatSign(anyLong(), any(SignatureAlgorithm.class));

            HsmHeartbeatScheduler scheduler = newScheduler(module);
            scheduler.heartbeat();
            scheduler.heartbeat();
            scheduler.heartbeat();

            verify(module, times(3)).heartbeatSign(eq(HANDLE), eq(SignatureAlgorithm.RSA_SHA256));
            assertEquals(3L, scheduler.getSuccessCount());
        }
    }

    @Nested
    @DisplayName("Hata davran\u0131\u015f\u0131")
    class FailureHandling {

        @Test
        @DisplayName("Module exception f\u0131rlat\u0131rsa scheduler crash etmez")
        void moduleException_doesNotPropagate() {
            IaikPkcs11Module module = mock(IaikPkcs11Module.class);
            doThrow(new SignatureException("simulated CKR_NO_SESSION_KEYS"))
                .when(module).heartbeatSign(anyLong(), any(SignatureAlgorithm.class));

            HsmHeartbeatScheduler scheduler = newScheduler(module);

            assertDoesNotThrow(scheduler::heartbeat,
                "Scheduler exception'\u0131 swallow etmeli; aksi halde @Scheduled "
                + "loop'u sa\u011fl\u0131k kontrol\u00fc i\u00e7in g\u00fcvenilmez olur.");
            assertEquals(0L, scheduler.getSuccessCount());
            assertEquals(1L, scheduler.getFailureCount());
            assertEquals(1L, scheduler.getConsecutiveFailureCount());
        }

        @Test
        @DisplayName("\u00dcst \u00fcste ba\u015far\u0131s\u0131z heartbeat consecutiveFailureCount artt\u0131r\u0131r")
        void consecutiveFailures_incrementCounter() {
            IaikPkcs11Module module = mock(IaikPkcs11Module.class);
            doThrow(new SignatureException("simulated HSM down"))
                .when(module).heartbeatSign(anyLong(), any(SignatureAlgorithm.class));

            HsmHeartbeatScheduler scheduler = newScheduler(module);
            for (int i = 0; i < 7; i++) {
                scheduler.heartbeat();
            }

            assertEquals(7L, scheduler.getFailureCount());
            assertEquals(7L, scheduler.getConsecutiveFailureCount(),
                "Hi\u00e7 ba\u015far\u0131l\u0131 \u00e7a\u011fr\u0131 yokken consecutive counter t\u00fcm "
                + "ba\u015far\u0131s\u0131zl\u0131klar\u0131 sayar.");
        }

        @Test
        @DisplayName("Ba\u015far\u0131l\u0131 heartbeat consecutiveFailureCount'u s\u0131f\u0131rlar")
        void successResetsConsecutiveFailureCount() {
            IaikPkcs11Module module = mock(IaikPkcs11Module.class);

            HsmHeartbeatScheduler scheduler = newScheduler(module);

            doThrow(new SignatureException("transient failure"))
                .when(module).heartbeatSign(anyLong(), any(SignatureAlgorithm.class));
            scheduler.heartbeat();
            scheduler.heartbeat();
            scheduler.heartbeat();
            assertEquals(3L, scheduler.getConsecutiveFailureCount());

            Mockito.reset(module);
            doNothing().when(module).heartbeatSign(anyLong(), any(SignatureAlgorithm.class));
            scheduler.heartbeat();

            assertEquals(0L, scheduler.getConsecutiveFailureCount(),
                "Ba\u015far\u0131l\u0131 heartbeat consecutive counter'\u0131 s\u0131f\u0131rlamal\u0131; "
                + "aksi halde ge\u00e7ici hatalar kal\u0131c\u0131 ERROR \u015fi\u015firir.");
            assertEquals(1L, scheduler.getSuccessCount());
            assertEquals(3L, scheduler.getFailureCount(),
                "Total failure counter ge\u00e7mi\u015fi tutmaya devam etmeli.");
        }

        @Test
        @DisplayName("RuntimeException de yakalan\u0131r")
        void anyRuntimeException_isSwallowed() {
            IaikPkcs11Module module = mock(IaikPkcs11Module.class);
            doThrow(new RuntimeException("unexpected"))
                .when(module).heartbeatSign(anyLong(), any(SignatureAlgorithm.class));

            HsmHeartbeatScheduler scheduler = newScheduler(module);

            assertDoesNotThrow(scheduler::heartbeat);
            assertEquals(1L, scheduler.getFailureCount());
        }
    }

    @Nested
    @DisplayName("Konstrukt\u00f6r kontrat\u0131")
    class ConstructorContract {

        @Test
        @DisplayName("PFX yolundaki SigningMaterial ile aktive edilirse IllegalStateException")
        void pfxMaterial_throwsIllegalState() {
            IaikPkcs11Module module = mock(IaikPkcs11Module.class);
            SigningMaterial pfxMaterial = new SigningMaterial(
                (java.security.PrivateKey) mock(java.security.PrivateKey.class),
                rsaCert, Collections.singletonList(rsaCert));

            assertThrows(IllegalStateException.class,
                () -> new HsmHeartbeatScheduler(module, pfxMaterial, 60),
                "PFX SigningMaterial ile HsmHeartbeatScheduler instantiate edilmemeli "
                + "(@ConditionalOnExpression normalde engeller; defensive guard).");
        }
    }

    // ----------------------------------------------------------------
    // helpers
    // ----------------------------------------------------------------

    private static X509Certificate newRsaCert(String dn) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair pair = kpg.generateKeyPair();

        X500Name subject = new X500Name(dn);
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 365L * 24 * 60 * 60 * 1000);
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(
            pair.getPublic().getEncoded());
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
            subject, BigInteger.valueOf(System.nanoTime()),
            notBefore, notAfter, subject, spki);

        return new JcaX509CertificateConverter().getCertificate(
            builder.build(new JcaContentSignerBuilder("SHA256withRSA")
                .build(pair.getPrivate())));
    }
}
