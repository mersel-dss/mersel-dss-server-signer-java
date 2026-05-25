package io.mersel.dss.signer.api.services.keystore.iaik;

import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import io.mersel.dss.signer.api.exceptions.SignatureException;
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
import org.xipki.pkcs11.wrapper.PKCS11Exception;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * {@link IaikPkcs11Module#signOnSession(IaikPkcs11Module.ResolvedKey, byte[],
 * SignatureAlgorithm)} alias-aware overload'unun L2 SMS-aile recovery
 * branch'ini doğrular.
 *
 * <h2>Senaryolar</h2>
 * <ul>
 *   <li>CKR_SMS_ERROR (0x80000384) → reinit + retry; tek-shot başarılı.</li>
 *   <li>CKR_NO_SESSION_KEYS (0x80000387) → reinit + retry; tek-shot başarılı.</li>
 *   <li>Non-SMS PKCS11Exception → reinit denenmez, orijinal hata propagate.</li>
 *   <li>Reinit kendi başarısız → orijinal SMS hatası propagate (sonsuz döngü
 *       koruması).</li>
 *   <li>Retry de SMS hatası alırsa → orijinal hata propagate (tek-shot).</li>
 *   <li>Recovery sonrası {@code rk.privateKeyHandle} in-place refresh edilmiş
 *       olmalı (heartbeat scheduler ve diğer holderlar yeni handle'ı görür).</li>
 * </ul>
 *
 * <p>Test stratejisi: {@link IaikPkcs11Module} {@link Mockito#spy} — gerçek
 * ResolvedKey overload'ı çalışır, alttaki {@code signOnSession(long, ...)}
 * ve {@code reinitializeForSmsRecovery} stub'lanır.</p>
 */
@Epic("PKCS#11 Integration")
@Feature("L2 SMS-Family Recovery Branch")
@Severity(SeverityLevel.CRITICAL)
class IaikPkcs11ModuleSmsRecoveryTest {

    private static final long CKR_SMS_ERROR        = 0x80000384L;
    private static final long CKR_NO_SESSION_KEYS  = 0x80000387L;
    private static final long CKR_DEVICE_ERROR     = 0x00000030L; // standart, SMS değil

    private static X509Certificate rsaCert;

    @BeforeAll
    static void initFixture() throws Exception {
        rsaCert = newRsaCert("CN=L2 SMS Recovery Test");
    }

    private IaikPkcs11Module spyModule() {
        // Ctor yalnızca field set; afterPropertiesSet çağrılmıyor — token/module
        // null kalır. signOnSession(long,...) ve reinitializeForSmsRecovery
        // tamamen stub'landığı için real path'e girmiyoruz.
        return Mockito.spy(new IaikPkcs11Module(
            "non-existent-library", null, null, null));
    }

    private IaikPkcs11Module.ResolvedKey newResolvedKey(long handle, String alias) {
        IaikPkcs11Module.ResolvedKey rk = new IaikPkcs11Module.ResolvedKey();
        rk.alias = alias;
        rk.certificate = rsaCert;
        rk.certificateChain = Collections.singletonList(rsaCert);
        rk.privateKeyHandle = handle;
        return rk;
    }

    private IaikPkcs11Module.ResolvedKey refreshedKey(long newHandle, String alias) {
        IaikPkcs11Module.ResolvedKey rk = new IaikPkcs11Module.ResolvedKey();
        rk.alias = alias;
        rk.certificate = rsaCert;
        rk.certificateChain = Collections.singletonList(rsaCert);
        rk.privateKeyHandle = newHandle;
        return rk;
    }

    private SignatureException wrapPkcs11Error(long ckrCode) {
        // signOnSession(long,...) varolan catch zinciri: PKCS11Exception →
        // SignatureException("HSM imza başarısız: " + msg, ckEx). extractor
        // getCause() ile PKCS11Exception'ı bulup error code'unu okur.
        PKCS11Exception ckEx = new PKCS11Exception(ckrCode);
        return new SignatureException("HSM imza başarısız: " + ckEx.getMessage(), ckEx);
    }

    @Nested
    @DisplayName("SMS-aile hata → reinit + retry başarılı")
    class SmsRecoveryHappyPath {

        @Test
        @DisplayName("CKR_SMS_ERROR (0x80000384) → reinit + retry → success")
        void ckrSmsError_triggersReinitAndRetry() {
            IaikPkcs11Module spy = spyModule();
            byte[] data = "payload".getBytes();
            byte[] success = new byte[]{0x42, 0x42};
            long oldHandle = 0xAAAL;
            long newHandle = 0xBBBL;
            IaikPkcs11Module.ResolvedKey rk = newResolvedKey(oldHandle, "alias-1");

            doThrow(wrapPkcs11Error(CKR_SMS_ERROR))
                .doReturn(success)
                .when(spy).signOnSession(anyLong(), any(byte[].class),
                    any(SignatureAlgorithm.class));
            doReturn(refreshedKey(newHandle, "alias-1"))
                .when(spy).reinitializeForSmsRecovery(anyString(),
                    Mockito.<String>any());

            byte[] result = spy.signOnSession(rk, data, SignatureAlgorithm.RSA_SHA256);

            assertArrayEquals(success, result, "Retry başarılı dönmeli");
            assertEquals(newHandle, rk.privateKeyHandle,
                "ResolvedKey.privateKeyHandle in-place refresh edilmeli — "
                + "scheduler ve diğer holderlar yeni handle'ı görür");
            verify(spy, times(2)).signOnSession(anyLong(), any(byte[].class),
                any(SignatureAlgorithm.class));
            verify(spy, times(1)).reinitializeForSmsRecovery("alias-1", null);
        }

        @Test
        @DisplayName("CKR_NO_SESSION_KEYS (0x80000387) → reinit + retry → success")
        void ckrNoSessionKeys_triggersReinitAndRetry() {
            IaikPkcs11Module spy = spyModule();
            byte[] data = "payload".getBytes();
            byte[] success = new byte[]{(byte) 0x99};
            IaikPkcs11Module.ResolvedKey rk = newResolvedKey(0x111L, "alias-2");

            doThrow(wrapPkcs11Error(CKR_NO_SESSION_KEYS))
                .doReturn(success)
                .when(spy).signOnSession(anyLong(), any(byte[].class),
                    any(SignatureAlgorithm.class));
            doReturn(refreshedKey(0x222L, "alias-2"))
                .when(spy).reinitializeForSmsRecovery(anyString(),
                    Mockito.<String>any());

            byte[] result = spy.signOnSession(rk, data, SignatureAlgorithm.RSA_SHA256);

            assertArrayEquals(success, result);
            assertEquals(0x222L, rk.privateKeyHandle);
            verify(spy, times(1)).reinitializeForSmsRecovery("alias-2", null);
        }
    }

    @Nested
    @DisplayName("Non-recoverable hata davranışları")
    class NonRecoverableErrors {

        @Test
        @DisplayName("Non-SMS PKCS11Exception (CKR_DEVICE_ERROR) → reinit YOK, orijinal hata propagate")
        void nonSmsError_doesNotTriggerReinit() {
            IaikPkcs11Module spy = spyModule();
            IaikPkcs11Module.ResolvedKey rk = newResolvedKey(0x111L, "x");

            SignatureException originalEx = wrapPkcs11Error(CKR_DEVICE_ERROR);
            doThrow(originalEx).when(spy).signOnSession(anyLong(),
                any(byte[].class), any(SignatureAlgorithm.class));

            SignatureException thrown = assertThrows(SignatureException.class,
                () -> spy.signOnSession(rk, "data".getBytes(), SignatureAlgorithm.RSA_SHA256));
            assertSame(originalEx, thrown,
                "SMS-aile dışı hatalar orijinal exception ile aynen propagate etmeli");

            verify(spy, never()).reinitializeForSmsRecovery(anyString(),
                Mockito.<String>any());
            verify(spy, times(1)).signOnSession(anyLong(), any(byte[].class),
                any(SignatureAlgorithm.class));
        }

        @Test
        @DisplayName("Reinit kendi başarısız → orijinal SMS hatası propagate (handle güncellenmemiş)")
        void reinitItselfFails_propagatesOriginalSmsError() {
            IaikPkcs11Module spy = spyModule();
            IaikPkcs11Module.ResolvedKey rk = newResolvedKey(0x111L, "x");

            SignatureException smsEx = wrapPkcs11Error(CKR_SMS_ERROR);
            doThrow(smsEx).when(spy).signOnSession(anyLong(),
                any(byte[].class), any(SignatureAlgorithm.class));
            doThrow(new io.mersel.dss.signer.api.exceptions.KeyStoreException(
                "simulated reinit failure", new RuntimeException()))
                .when(spy).reinitializeForSmsRecovery(anyString(),
                    Mockito.<String>any());

            SignatureException thrown = assertThrows(SignatureException.class,
                () -> spy.signOnSession(rk, "data".getBytes(), SignatureAlgorithm.RSA_SHA256));
            assertSame(smsEx, thrown,
                "Reinit başarısızsa müşteri orijinal SMS hatasını görmeli "
                + "(reinit failure ile shadow olmamalı)");

            assertEquals(0x111L, rk.privateKeyHandle,
                "Reinit başarısızsa handle değişmemeli");
            verify(spy, times(1)).reinitializeForSmsRecovery(anyString(),
                Mockito.<String>any());
            // İlk sign call yapıldı, retry edilmedi.
            verify(spy, times(1)).signOnSession(anyLong(), any(byte[].class),
                any(SignatureAlgorithm.class));
        }

        @Test
        @DisplayName("Tek-shot kontratı: retry de SMS alırsa tekrar reinit denenmez")
        void retryAlsoFailsWithSms_doesNotRecurse() {
            IaikPkcs11Module spy = spyModule();
            IaikPkcs11Module.ResolvedKey rk = newResolvedKey(0x111L, "x");

            // İlk çağrı CKR_SMS_ERROR, retry CKR_NO_SESSION_KEYS — iki SMS-aile
            // arka arkaya. Tek-shot kontratı: ikincide reinit ETMEZ.
            doThrow(wrapPkcs11Error(CKR_SMS_ERROR))
                .doThrow(wrapPkcs11Error(CKR_NO_SESSION_KEYS))
                .when(spy).signOnSession(anyLong(),
                    any(byte[].class), any(SignatureAlgorithm.class));
            doReturn(refreshedKey(0x222L, "x"))
                .when(spy).reinitializeForSmsRecovery(anyString(),
                    Mockito.<String>any());

            assertThrows(SignatureException.class,
                () -> spy.signOnSession(rk, "data".getBytes(), SignatureAlgorithm.RSA_SHA256));

            verify(spy, times(1)).reinitializeForSmsRecovery(anyString(),
                Mockito.<String>any());
            verify(spy, times(2)).signOnSession(anyLong(), any(byte[].class),
                any(SignatureAlgorithm.class));
        }
    }

    @Nested
    @DisplayName("Wrap zinciri davranışı")
    class WrapChainBehavior {

        @Test
        @DisplayName("Çok katmanlı SignatureException sarması altında PKCS11Exception bulunmalı")
        void nestedSignatureExceptionWraps_areUnwrappedCorrectly() {
            IaikPkcs11Module spy = spyModule();
            IaikPkcs11Module.ResolvedKey rk = newResolvedKey(0x111L, "x");

            // SignatureException("outer", SignatureException("inner", PKCS11Exception(CKR_SMS_ERROR)))
            PKCS11Exception ckEx = new PKCS11Exception(CKR_SMS_ERROR);
            SignatureException inner = new SignatureException("inner wrap", ckEx);
            SignatureException outer = new SignatureException("outer wrap", inner);

            doThrow(outer).doReturn(new byte[]{0x01})
                .when(spy).signOnSession(anyLong(), any(byte[].class),
                    any(SignatureAlgorithm.class));
            doReturn(refreshedKey(0x222L, "x"))
                .when(spy).reinitializeForSmsRecovery(anyString(),
                    Mockito.<String>any());

            // Recovery branch çok-katmanlı sarmayı da unwrap edebilmeli.
            byte[] result = spy.signOnSession(rk, "data".getBytes(),
                SignatureAlgorithm.RSA_SHA256);
            assertArrayEquals(new byte[]{0x01}, result);
            verify(spy, times(1)).reinitializeForSmsRecovery(anyString(),
                Mockito.<String>any());
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
