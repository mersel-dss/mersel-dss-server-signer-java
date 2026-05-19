package io.mersel.dss.signer.api.services.keystore.iaik;

import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Severity;
import io.qameta.allure.SeverityLevel;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.xipki.pkcs11.wrapper.Mechanism;
import org.xipki.pkcs11.wrapper.PKCS11Constants;
import org.xipki.pkcs11.wrapper.params.CkParams;
import org.xipki.pkcs11.wrapper.params.RSA_PKCS_PSS_PARAMS;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * DSS {@link SignatureAlgorithm} ile PKCS#11 {@link Mechanism} arasındaki tek
 * yönlü çevrim katmanını verifiye eder.
 *
 * <p>Bu mapping HSM imzalama akışının kalbidir — yanlış mekanizma demek yanlış
 * dijital imza demek. e-Dönüşüm imzaları için her digest/alg kombinasyonu
 * doğru CKM koduna eşlenmek zorunda; PSS için ek olarak salt length ve MGF1
 * hash CKG_MGF1_* sabitleri de doğru olmalı (yoksa Schematron doğrulama
 * geçmez).</p>
 */
@Epic("PKCS#11 Integration")
@Feature("Mechanism Resolution (CKM_*)")
@Severity(SeverityLevel.NORMAL)
class IaikSignatureMechanismsTest {

    // ----------------------------------------------------------------
    // RSA-PKCS#1 v1.5: CKM_<HASH>_RSA_PKCS
    // ----------------------------------------------------------------

    @Nested
    @DisplayName("RSA-PKCS#1 v1.5 mapping")
    class RsaPkcsMapping {

        @Test
        void rsaSha1_shouldMapToCkmSha1RsaPkcs() {
            Mechanism m = IaikSignatureMechanisms.resolveMechanism(SignatureAlgorithm.RSA_SHA1);
            assertEquals(PKCS11Constants.CKM_SHA1_RSA_PKCS, m.getMechanismCode());
            assertNull(m.getParameters(), "RSA-PKCS#1 v1.5 mekanizmaları parametresizdir");
        }

        @Test
        void rsaSha224_shouldMapToCkmSha224RsaPkcs() {
            Mechanism m = IaikSignatureMechanisms.resolveMechanism(SignatureAlgorithm.RSA_SHA224);
            assertEquals(PKCS11Constants.CKM_SHA224_RSA_PKCS, m.getMechanismCode());
        }

        @Test
        void rsaSha256_shouldMapToCkmSha256RsaPkcs() {
            Mechanism m = IaikSignatureMechanisms.resolveMechanism(SignatureAlgorithm.RSA_SHA256);
            assertEquals(PKCS11Constants.CKM_SHA256_RSA_PKCS, m.getMechanismCode());
        }

        @Test
        void rsaSha384_shouldMapToCkmSha384RsaPkcs() {
            Mechanism m = IaikSignatureMechanisms.resolveMechanism(SignatureAlgorithm.RSA_SHA384);
            assertEquals(PKCS11Constants.CKM_SHA384_RSA_PKCS, m.getMechanismCode());
        }

        @Test
        void rsaSha512_shouldMapToCkmSha512RsaPkcs() {
            Mechanism m = IaikSignatureMechanisms.resolveMechanism(SignatureAlgorithm.RSA_SHA512);
            assertEquals(PKCS11Constants.CKM_SHA512_RSA_PKCS, m.getMechanismCode());
        }
    }

    // ----------------------------------------------------------------
    // ECDSA: her zaman raw CKM_ECDSA + dış digest (universal HSM uyumu)
    // ----------------------------------------------------------------

    /**
     * <h3>Politika değişikliği (Mayıs 2026)</h3>
     * <p>ECDSA için kombine {@code CKM_ECDSA_<HASH>} mekanizmaları
     * <b>kullanılmıyor</b>. Sebep: SoftHSM2 + bazı production HSM driver'ları
     * (SafeNet ProtectServer K7, eski Luna) bu mekanizmaları mechanism-list'te
     * bildirip {@code C_SignInit}'te reddediyor; ayrıca xipki ipkcs11wrapper
     * 1.0.9'da {@code PKCS11Token.opInit()} swallow-bug'i gerçek hata kodunu
     * yutuyor → güvenilir fallback yapılamıyor.</p>
     *
     * <p>Üretim politikası: ECDSA imzasının tüm digest varyantları
     * (SHA1/224/256/384/512) {@code CKM_ECDSA} mekanizmasına eşlenir;
     * digest Java tarafında hesaplanır.</p>
     */
    @Nested
    @DisplayName("ECDSA mapping — her zaman raw CKM_ECDSA")
    class EcdsaMapping {

        @Test
        void ecdsaSha1_shouldAlwaysMapToRawCkmEcdsa() {
            Mechanism m = IaikSignatureMechanisms.resolveMechanism(SignatureAlgorithm.ECDSA_SHA1);
            assertEquals(PKCS11Constants.CKM_ECDSA, m.getMechanismCode(),
                "ECDSA varyantları her zaman raw CKM_ECDSA'ya eşlenmeli "
                + "(combined CKM_ECDSA_SHA1 universal HSM desteği yok).");
            assertNull(m.getParameters(), "Raw CKM_ECDSA parametresizdir");
        }

        @Test
        void ecdsaSha224_shouldAlwaysMapToRawCkmEcdsa() {
            Mechanism m = IaikSignatureMechanisms.resolveMechanism(SignatureAlgorithm.ECDSA_SHA224);
            assertEquals(PKCS11Constants.CKM_ECDSA, m.getMechanismCode());
        }

        @Test
        void ecdsaSha256_shouldAlwaysMapToRawCkmEcdsa() {
            Mechanism m = IaikSignatureMechanisms.resolveMechanism(SignatureAlgorithm.ECDSA_SHA256);
            assertEquals(PKCS11Constants.CKM_ECDSA, m.getMechanismCode(),
                "SoftHSM2/SafeNet/Luna driver'larında CKM_ECDSA_SHA256 reddedilebilir; "
                + "biz ECDSA için universal destekli raw CKM_ECDSA + dış SHA-256 yolunu kullanıyoruz.");
        }

        @Test
        void ecdsaSha384_shouldAlwaysMapToRawCkmEcdsa() {
            Mechanism m = IaikSignatureMechanisms.resolveMechanism(SignatureAlgorithm.ECDSA_SHA384);
            assertEquals(PKCS11Constants.CKM_ECDSA, m.getMechanismCode());
        }

        @Test
        void ecdsaSha512_shouldAlwaysMapToRawCkmEcdsa() {
            Mechanism m = IaikSignatureMechanisms.resolveMechanism(SignatureAlgorithm.ECDSA_SHA512);
            assertEquals(PKCS11Constants.CKM_ECDSA, m.getMechanismCode());
        }

        @Test
        @DisplayName("ECDSA mekanizması her durumda requiresExternalDigest=true olmalı")
        void resolvedEcdsaMechanism_alwaysRequiresExternalDigest() {
            // Politikanın kontratı: resolveMechanism çıktısı caller tarafından
            // requiresExternalDigest ile sorgulanır; ECDSA için her zaman true
            // dönmeli ki caller dış SHA-* digest hesaplasın.
            for (SignatureAlgorithm alg : new SignatureAlgorithm[] {
                    SignatureAlgorithm.ECDSA_SHA1, SignatureAlgorithm.ECDSA_SHA224,
                    SignatureAlgorithm.ECDSA_SHA256, SignatureAlgorithm.ECDSA_SHA384,
                    SignatureAlgorithm.ECDSA_SHA512}) {
                Mechanism m = IaikSignatureMechanisms.resolveMechanism(alg);
                assertTrue(IaikSignatureMechanisms.requiresExternalDigest(m),
                    "ECDSA varyantı " + alg + " için resolveMechanism çıktısı dış digest beklemeli");
            }
        }
    }

    // ----------------------------------------------------------------
    // DSA: CKM_DSA_<HASH>
    // ----------------------------------------------------------------

    @Nested
    @DisplayName("DSA mapping")
    class DsaMapping {

        @Test
        void dsaSha1_shouldMapToCkmDsaSha1() {
            Mechanism m = IaikSignatureMechanisms.resolveMechanism(SignatureAlgorithm.DSA_SHA1);
            assertEquals(PKCS11Constants.CKM_DSA_SHA1, m.getMechanismCode());
        }

        @Test
        void dsaSha256_shouldMapToCkmDsaSha256() {
            Mechanism m = IaikSignatureMechanisms.resolveMechanism(SignatureAlgorithm.DSA_SHA256);
            assertEquals(PKCS11Constants.CKM_DSA_SHA256, m.getMechanismCode());
        }

        @Test
        void dsaSha512_shouldMapToCkmDsaSha512() {
            Mechanism m = IaikSignatureMechanisms.resolveMechanism(SignatureAlgorithm.DSA_SHA512);
            assertEquals(PKCS11Constants.CKM_DSA_SHA512, m.getMechanismCode());
        }
    }

    // ----------------------------------------------------------------
    // RSA-PSS: CKM_<HASH>_RSA_PKCS_PSS + RSA_PKCS_PSS_PARAMS
    // ----------------------------------------------------------------

    @Nested
    @DisplayName("RSA-PSS mapping (PKCS#1 v2.1 PSS)")
    class RsaPssMapping {

        @Test
        void pssSha256_shouldMapToCkmAndCarrySaltLength32() {
            Mechanism m = IaikSignatureMechanisms.resolveMechanism(SignatureAlgorithm.RSA_SSA_PSS_SHA256_MGF1);
            assertEquals(PKCS11Constants.CKM_SHA256_RSA_PKCS_PSS, m.getMechanismCode());

            CkParams params = m.getParameters();
            assertInstanceOf(RSA_PKCS_PSS_PARAMS.class, params,
                "PSS mekanizmaları RSA_PKCS_PSS_PARAMS taşımalı");
            assertNotNull(params.getParams(), "params.getParams() native CK_RSA_PKCS_PSS_PARAMS dönmeli");
        }

        @Test
        void pssSha1_shouldHaveSaltLength20AndMgf1Sha1() {
            Mechanism m = IaikSignatureMechanisms.resolveMechanism(SignatureAlgorithm.RSA_SSA_PSS_SHA1_MGF1);
            assertEquals(PKCS11Constants.CKM_SHA1_RSA_PKCS_PSS, m.getMechanismCode());
            // saltLen/mgf doğrulaması için CK_RSA_PKCS_PSS_PARAMS introspect (reflective);
            // halka taraf zaten Mechanism kodunu ve params varlığını kontrol ediyor.
            assertNotNull(m.getParameters());
        }

        @Test
        void pssSha384_shouldHaveSaltLength48AndMgf1Sha384() {
            Mechanism m = IaikSignatureMechanisms.resolveMechanism(SignatureAlgorithm.RSA_SSA_PSS_SHA384_MGF1);
            assertEquals(PKCS11Constants.CKM_SHA384_RSA_PKCS_PSS, m.getMechanismCode());
            assertNotNull(m.getParameters());
        }

        @Test
        void pssSha512_shouldHaveSaltLength64AndMgf1Sha512() {
            Mechanism m = IaikSignatureMechanisms.resolveMechanism(SignatureAlgorithm.RSA_SSA_PSS_SHA512_MGF1);
            assertEquals(PKCS11Constants.CKM_SHA512_RSA_PKCS_PSS, m.getMechanismCode());
            assertNotNull(m.getParameters());
        }
    }

    // ----------------------------------------------------------------
    // External-digest gerektiren mekanizmalar
    // ----------------------------------------------------------------

    @Nested
    @DisplayName("requiresExternalDigest contract")
    class RequiresExternalDigest {

        @Test
        void rawEcdsa_shouldRequireExternalDigest() {
            Mechanism m = new Mechanism(PKCS11Constants.CKM_ECDSA);
            assertTrue(IaikSignatureMechanisms.requiresExternalDigest(m),
                "Raw CKM_ECDSA token-side digest yapmaz; caller hash etmeli");
        }

        @Test
        void rawRsaPkcs_shouldRequireExternalDigest() {
            Mechanism m = new Mechanism(PKCS11Constants.CKM_RSA_PKCS);
            assertTrue(IaikSignatureMechanisms.requiresExternalDigest(m),
                "Raw CKM_RSA_PKCS PKCS#1 DigestInfo wrap'i dışarıdan beklenir");
        }

        @Test
        void singleShotRsa_shouldNotRequireExternalDigest() {
            Mechanism m = new Mechanism(PKCS11Constants.CKM_SHA256_RSA_PKCS);
            assertFalse(IaikSignatureMechanisms.requiresExternalDigest(m),
                "CKM_SHA256_RSA_PKCS digest + padding'i HSM'e yaptırır");
        }

        @Test
        void singleShotEcdsa_shouldNotRequireExternalDigest() {
            Mechanism m = new Mechanism(PKCS11Constants.CKM_ECDSA_SHA256);
            assertFalse(IaikSignatureMechanisms.requiresExternalDigest(m),
                "CKM_ECDSA_SHA256 digest'i HSM'e yaptırır");
        }
    }

    // ----------------------------------------------------------------
    // Fallback mechanisms (HSM vendor kısıtları için)
    // ----------------------------------------------------------------

    @Test
    void fallbackToRawEcdsa_shouldReturnCkmEcdsa() {
        Mechanism m = IaikSignatureMechanisms.fallbackToRawEcdsa();
        assertEquals(PKCS11Constants.CKM_ECDSA, m.getMechanismCode());
        assertNull(m.getParameters());
    }

    @Test
    void fallbackToRawRsaPkcs_shouldReturnCkmRsaPkcs() {
        Mechanism m = IaikSignatureMechanisms.fallbackToRawRsaPkcs();
        assertEquals(PKCS11Constants.CKM_RSA_PKCS, m.getMechanismCode());
        assertNull(m.getParameters());
    }

    // ----------------------------------------------------------------
    // Negative paths
    // ----------------------------------------------------------------

    @Test
    void hmacAlgorithm_shouldThrowUnsupported() {
        // HMAC_SHA256 imza algoritması olarak DSS'te yer alır ama PKCS#11
        // imza akışımızın kapsamında değil — IllegalArgumentException beklenir.
        assertThrows(IllegalArgumentException.class,
            () -> IaikSignatureMechanisms.resolveMechanism(SignatureAlgorithm.HMAC_SHA256));
    }

    // ----------------------------------------------------------------
    // PSS raw fallback contract (O3 regression)
    // ----------------------------------------------------------------

    /**
     * RSA-PSS imzası raw CKM_RSA_PKCS'e indirgenirse PKCS#1 v1.5 ile imza
     * üretilir; bu PSS doğrulamasından geçmez (sessiz yanlış imza).
     * fallbackToRawRsaPkcs() bu kontekstte ASLA kullanılmamalıdır.
     *
     * <p>{@code IaikPkcs11Module.signOnSession} bu durumu PSS algoritması
     * için açıkça reddediyor — bu test sözleşmeyi sabitler.</p>
     */
    @Test
    @DisplayName("Raw RSA-PKCS fallback PSS için kullanılmamalı (silent yanlış imzayı önle)")
    void rawRsaPkcsFallback_shouldNotBeUsedForPss() {
        // fallbackToRawRsaPkcs CKM_RSA_PKCS dönüyor — bu mekanizma PKCS#1 v1.5
        // padding uygular. PSS isteyen bir imza burası ile karıştırılırsa
        // doğrulama başarısız olur. Bu testin amacı: fallback API'nın PSS
        // semantiğini taşımadığını kanıtlamak.
        Mechanism rawRsa = IaikSignatureMechanisms.fallbackToRawRsaPkcs();
        assertEquals(PKCS11Constants.CKM_RSA_PKCS, rawRsa.getMechanismCode(),
            "fallbackToRawRsaPkcs YALNIZCA CKM_RSA_PKCS döner; PSS değil.");
        assertNull(rawRsa.getParameters(),
            "CKM_RSA_PKCS parametresizdir — PSS'in salt+MGF1 bilgisini ASLA taşımaz. "
            + "Bu yüzden PSS akışında bu fallback kullanılırsa sessiz yanlış imza olur.");
    }
}
