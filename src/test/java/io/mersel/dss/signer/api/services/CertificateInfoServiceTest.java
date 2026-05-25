package io.mersel.dss.signer.api.services;

import io.mersel.dss.signer.api.dtos.CertificateInfoDto;
import io.mersel.dss.signer.api.exceptions.KeyStoreException;
import io.mersel.dss.signer.api.models.SigningMaterial;
import io.mersel.dss.signer.api.services.keystore.KeyStoreProvider;
import io.mersel.dss.signer.api.services.keystore.PKCS11KeyStoreProvider;
import io.mersel.dss.signer.api.services.keystore.iaik.IaikPkcs11Module;
import io.mersel.dss.signer.api.services.keystore.iaik.Pkcs11Signer;
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

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
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
 *
 * <p>İkinci kritik vaka: {@code /signingCertificate} endpoint'i HSM
 * modunda da {@code hasPrivateKey=true} dönmeli — JCA katmanı HSM
 * yolunda {@code null} private key yansıtsa da imza materyali fiilen
 * vardır (key handle token'da yaşar).</p>
 */
@Epic("Service Layer")
@Feature("Certificate Info")
@Severity(SeverityLevel.NORMAL)
class CertificateInfoServiceTest {

    private static KeyPair rsaKeyPair;
    private static X509Certificate selfSignedCert;

    @BeforeAll
    static void initCryptoFixtures() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        rsaKeyPair = kpg.generateKeyPair();

        X500Name subject = new X500Name("CN=CertificateInfoService Test, O=Mersel, C=TR");
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 365L * 24 * 60 * 60 * 1000);

        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(
            rsaKeyPair.getPublic().getEncoded());
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
            subject, BigInteger.ONE, notBefore, notAfter, subject, spki);

        selfSignedCert = new JcaX509CertificateConverter().getCertificate(
            builder.build(new JcaContentSignerBuilder("SHA256withRSA")
                .build(rsaKeyPair.getPrivate())));
    }

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

    @Nested
    @DisplayName("getSigningCertificateInfo — /signingCertificate endpoint sözleşmesi")
    class SigningCertificateInfoContract {

        @Test
        @DisplayName("PFX yolu → tüm alanlar doğru mapping + base64 + hasPrivateKey=true")
        void pfxPath_returnsFullDtoWithBase64() throws Exception {
            SigningMaterial material = new SigningMaterial(
                rsaKeyPair.getPrivate(),
                selfSignedCert,
                Collections.singletonList(selfSignedCert));

            CertificateInfoService service = new CertificateInfoService(null, material);

            CertificateInfoDto dto = service.getSigningCertificateInfo();

            assertNotNull(dto, "PFX yolunda dto null dönmemeli");
            assertEquals("X.509", dto.getType(),
                "Sertifika tipi X.509 olmalı");
            assertEquals("RSA", dto.getPublicKeyAlgorithm(),
                "RSA key pair için public key algoritması RSA");
            assertEquals(selfSignedCert.getSerialNumber().toString(16).toUpperCase(),
                dto.getSerialNumberHex(),
                "Serial hex BigInteger.toString(16) ile upper-case formatlanmalı");
            assertEquals(selfSignedCert.getSerialNumber().toString(),
                dto.getSerialNumberDec(), "Serial dec ham BigInteger formatında");
            assertEquals(selfSignedCert.getSubjectX500Principal().toString(), dto.getSubject());
            assertEquals(selfSignedCert.getIssuerX500Principal().toString(), dto.getIssuer());
            assertTrue(dto.isHasPrivateKey(),
                "PFX yolunda hasPrivateKey true olmalı — JCA private key mevcut");
            assertNotNull(dto.getBase64EncodedCertificate(),
                "/signingCertificate endpoint'i base64 encoded sertifikayı doldurmalı");
            assertEquals(Base64.getEncoder().encodeToString(selfSignedCert.getEncoded()),
                dto.getBase64EncodedCertificate(),
                "Base64 encoded sertifika ham X.509 DER encoding'in base64 hali olmalı");
        }

        @Test
        @DisplayName("HSM yolu → hasPrivateKey=true (regresyon koruma: JCA katmanı null verse de)")
        void pkcs11Path_hasPrivateKeyIsTrue_evenThoughJcaPrivateKeyIsNull() throws Exception {
            Pkcs11Signer pkcs11Signer = mock(Pkcs11Signer.class);
            SigningMaterial material = new SigningMaterial(
                pkcs11Signer,
                selfSignedCert,
                Collections.singletonList(selfSignedCert));

            // Davranış sözleşmesini ön-doğrula: SigningMaterial HSM yolunda
            // JCA private key olarak null döner — bu beklenen davranış,
            // bizim regresyon korumamızın gerekçesi.
            assertNull(material.getPrivateKey(),
                "HSM yolunda SigningMaterial.getPrivateKey() null döner; testin önkoşulu");
            assertNotNull(material.getPkcs11Signer(),
                "HSM yolunda Pkcs11Signer dolu olmalı");

            CertificateInfoService service = new CertificateInfoService(null, material);

            CertificateInfoDto dto = service.getSigningCertificateInfo();

            assertTrue(dto.isHasPrivateKey(),
                "HSM yolunda hasPrivateKey TRUE olmalı — key handle token'da yaşar, "
                + "imzacı materyal fiilen vardır. JCA katmanının null vermesi ≠ private key yok.");
            assertNotNull(dto.getBase64EncodedCertificate(),
                "HSM yolunda da base64 encoded sertifika doldurulmalı");
            assertEquals("RSA", dto.getPublicKeyAlgorithm());
        }

        @Test
        @DisplayName("SigningMaterial null → IllegalStateException (CLI/bootstrap hatası)")
        void noSigningMaterial_shouldThrowIllegalState() {
            CertificateInfoService service = new CertificateInfoService(null, null);

            IllegalStateException ex = assertThrows(IllegalStateException.class,
                service::getSigningCertificateInfo);

            assertTrue(ex.getMessage().contains("SigningMaterial"),
                "Hata mesajı yapılandırma sorununu net belirtmeli");
            assertTrue(ex.getMessage().contains("/signingCertificate"),
                "Mesaj endpoint adını içermeli — operasyonel teşhis kolaylaşsın");
        }
    }
}
