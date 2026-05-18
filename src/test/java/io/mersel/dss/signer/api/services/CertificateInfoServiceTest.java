package io.mersel.dss.signer.api.services;

import io.mersel.dss.signer.api.dtos.CertificateInfoDto;
import io.mersel.dss.signer.api.exceptions.KeyStoreException;
import io.mersel.dss.signer.api.services.keystore.KeyStoreProvider;
import io.mersel.dss.signer.api.services.keystore.PKCS11KeyStoreProvider;
import io.mersel.dss.signer.api.services.keystore.iaik.IaikPkcs11Module;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Severity;
import io.qameta.allure.SeverityLevel;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * {@link CertificateInfoService} davranış kontratı testleri.
 *
 * <p>Kritik vaka: PKCS#11 yapılandırmasında IAIK module bir nedenle
 * exception fırlatırsa <b>asla</b> PFX/JCA fallback'ine düşülmemeli —
 * çünkü {@link PKCS11KeyStoreProvider#loadKeyStore} her zaman
 * {@link UnsupportedOperationException} fırlatır ve bu sessiz ölü yolda
 * orijinal HSM hatası kaybolur. Bunun yerine {@link KeyStoreException}
 * sarmalanmalı ve orijinal hata cause olarak korunmalıdır.</p>
 */
@Epic("Service Layer")
@Feature("Certificate Info")
@Severity(SeverityLevel.NORMAL)
class CertificateInfoServiceTest {

    @Nested
    @DisplayName("PKCS#11 yolu — IAIK fail durumunda davranış")
    class Pkcs11FailureBehavior {

        @Test
        @DisplayName("IAIK fail + PKCS11Provider → KeyStoreException atmalı, fallback'e düşmemeli")
        void iaikFailure_onPkcs11Provider_shouldThrowKeyStoreException() {
            IaikPkcs11Module module = mock(IaikPkcs11Module.class);
            RuntimeException hsmFailure = new RuntimeException("CKR_DEVICE_ERROR");
            when(module.listCertificates()).thenThrow(hsmFailure);

            PKCS11KeyStoreProvider provider =
                new PKCS11KeyStoreProvider("/dev/null/lib.so", 0L, 0L);

            CertificateInfoService service = new CertificateInfoService(module);

            KeyStoreException ex = assertThrows(KeyStoreException.class,
                () -> service.listCertificates(provider, new char[]{'p', 'i', 'n'}));

            // Orijinal HSM hatası cause olarak korunmalı.
            assertNotNull(ex.getCause(), "Cause attach edilmeli");
            assertSame(hsmFailure, ex.getCause(),
                "Orijinal IAIK hatası cause olarak korunmalı; debugging için kritik");
            assertTrue(ex.getMessage().contains("PKCS#11"),
                "Mesaj PKCS#11 yapılandırması olduğunu belirtmeli");
            assertTrue(ex.getMessage().contains("CKR_DEVICE_ERROR"),
                "Orijinal HSM hata mesajı kullanıcıya aktarılmalı");
        }

        @Test
        @DisplayName("IAIK fail + non-PKCS11 provider → fallback denenir (regression koruma)")
        void iaikFailure_onNonPkcs11Provider_shouldFallbackQuietly() {
            // PKCS11 olmayan provider için fallback davranışı korunmalı.
            // (Pratikte bu vaka çok yaygın değil çünkü IAIK module sadece
            // PKCS11 yapılandırmasında inject edilir; ama defensive contract
            // için non-PKCS11 yolunun açık kalması doğrudur.)
            IaikPkcs11Module module = mock(IaikPkcs11Module.class);
            when(module.listCertificates()).thenThrow(new RuntimeException("transient"));

            KeyStoreProvider fakeProvider = new KeyStoreProvider() {
                @Override
                public java.security.KeyStore loadKeyStore(char[] pin) {
                    throw new RuntimeException("simulated PFX load failure");
                }

                @Override
                public String getType() {
                    return "PKCS12";
                }
            };

            CertificateInfoService service = new CertificateInfoService(module);

            // Fallback denenecek, o da fail edecek — ama mesaj "PKCS#11" geçmemeli;
            // fallback'in açık yol olduğunu doğruluyoruz.
            KeyStoreException ex = assertThrows(KeyStoreException.class,
                () -> service.listCertificates(fakeProvider, new char[]{}));

            assertTrue(!ex.getMessage().contains("PKCS#11 yapılandırmasında"),
                "Non-PKCS11 yolda PKCS#11-spesifik hata mesajı verilmemeli");
        }
    }

    @Nested
    @DisplayName("Mutlu yol")
    class HappyPath {

        @Test
        @DisplayName("IAIK başarılı listing → doğrudan döner")
        void iaikSuccess_shouldReturnList() {
            IaikPkcs11Module module = mock(IaikPkcs11Module.class);
            CertificateInfoDto dto = new CertificateInfoDto();
            dto.setAlias("hsm-key-1");
            dto.setSerialNumberHex("DEADBEEF");
            List<CertificateInfoDto> expected = Collections.singletonList(dto);
            when(module.listCertificates()).thenReturn(expected);

            PKCS11KeyStoreProvider provider =
                new PKCS11KeyStoreProvider("/dev/null", 0L, 0L);
            CertificateInfoService service = new CertificateInfoService(module);

            List<CertificateInfoDto> actual = service.listCertificates(provider, new char[]{});

            assertEquals(1, actual.size());
            assertEquals("hsm-key-1", actual.get(0).getAlias());
            assertSame(expected, actual,
                "IAIK başarılı yolda dönüş listesi olduğu gibi geçmeli — kopya/wrapping yapılmamalı");
        }

        @Test
        @DisplayName("IAIK module null (PFX yapılandırması) → fallback yolu çalışır")
        void noIaikModule_shouldUseFallback() {
            CertificateInfoService service = new CertificateInfoService((IaikPkcs11Module) null);

            // PFX provider mock; gerçek bir keystore yüklenmeyecek ama fallback
            // yolunun denendiğini doğrulamak için exception sızması yeterli.
            KeyStoreProvider fakeProvider = new KeyStoreProvider() {
                @Override
                public java.security.KeyStore loadKeyStore(char[] pin) {
                    throw new RuntimeException("expected: this path is exercised");
                }

                @Override
                public String getType() {
                    return "PKCS12";
                }
            };

            KeyStoreException ex = assertThrows(KeyStoreException.class,
                () -> service.listCertificates(fakeProvider, new char[]{}));
            assertTrue(ex.getMessage().contains("expected"),
                "Fallback gerçekten çağrılmalı; iaikModule==null koşulunda PKCS#11 mesajı çıkmamalı");
        }
    }
}
