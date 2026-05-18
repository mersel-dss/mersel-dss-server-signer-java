package io.mersel.dss.signer.api.services.keystore.iaik;

import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import io.mersel.dss.signer.api.exceptions.SignatureException;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Severity;
import io.qameta.allure.SeverityLevel;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.xipki.pkcs11.wrapper.PKCS11Constants;
import org.xipki.pkcs11.wrapper.PKCS11Exception;
import org.xipki.pkcs11.wrapper.PKCS11Module;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentMap;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link IaikPkcs11Module} kontrat regression testleri.
 *
 * <p>Bu testler kodun <em>davranışını</em> değil <em>API kontratını</em>
 * doğrular: imzalama ve listing metodları üzerinde {@code synchronized}
 * kilidi BULUNMAMALIDIR. Aksi halde {@code PKCS11Token}'ın yerleşik session
 * havuzu sıkışır ve eş zamanlı imzalar seri çalışmaya başlar.</p>
 *
 * <p>HSM throughput'u doğrudan e-Fatura/e-İrsaliye batch hızını belirlediği
 * için bu kontrat ileride biri yanlışlıkla {@code synchronized} eklerse
 * "production'da SLA bozuldu" hatası yerine burada düşsün.</p>
 */
@Epic("PKCS#11 Integration")
@Feature("IAIK Module — Thread-Safety Contract")
@Severity(SeverityLevel.CRITICAL)
class IaikPkcs11ModuleContractTest {

    @Test
    @DisplayName("signOnSession synchronized OLMAMALI (PKCS11Token paralel destekler)")
    void signOnSession_mustNotBeSynchronized() throws Exception {
        Method m = IaikPkcs11Module.class.getDeclaredMethod("signOnSession",
            long.class, byte[].class,
            eu.europa.esig.dss.enumerations.SignatureAlgorithm.class);

        assertFalse(Modifier.isSynchronized(m.getModifiers()),
            "signOnSession synchronized olamaz; PKCS11Token kendi içinde session-pool "
            + "tabanlı thread-safety sağlar. Synchronized = production darboğazı.");
    }

    @Test
    @DisplayName("findSigner synchronized OLMAMALI (ConcurrentHashMap kullanılıyor)")
    void findSigner_mustNotBeSynchronized() throws Exception {
        Method m = IaikPkcs11Module.class.getDeclaredMethod("findSigner", String.class, String.class);
        assertFalse(Modifier.isSynchronized(m.getModifiers()),
            "findSigner synchronized olmamalı; cache concurrent.");
    }

    @Test
    @DisplayName("listCertificates synchronized OLMAMALI")
    void listCertificates_mustNotBeSynchronized() throws Exception {
        Method m = IaikPkcs11Module.class.getDeclaredMethod("listCertificates");
        assertFalse(Modifier.isSynchronized(m.getModifiers()),
            "Listing token roundtrip; paralel adminler engellenmemeli.");
    }

    @Test
    @DisplayName("resolvedKeyCache ConcurrentMap implementasyonu olmalı")
    void resolvedKeyCache_mustBeConcurrent() throws Exception {
        Field f = IaikPkcs11Module.class.getDeclaredField("resolvedKeyCache");
        f.setAccessible(true);

        // Field tipi Map<...> olabilir ama instance ConcurrentMap olmalı.
        // Static initialization olmadığı için reflective instantiation
        // yerine doğrudan instance kontrolü için bir IaikPkcs11Module kurmak
        // gerekir — ama ctor PIN/library ister; basit: type kontrolü.
        assertTrue(Map.class.isAssignableFrom(f.getType()),
            "Field bir Map olmalı");

        // Kanıt: kaynak kodda new ConcurrentHashMap<>() var. Bunun değişip
        // değişmediğini regression olarak yakalamak için cache initializer'ı
        // çalıştırıp tipini kontrol edelim — minimal heap ctor yeterli.
        IaikPkcs11Module instance = new IaikPkcs11Module(
            "non-existent-library", null, null, null);
        Object cacheInstance = f.get(instance);
        assertTrue(cacheInstance instanceof ConcurrentMap,
            "resolvedKeyCache ConcurrentMap olmalı; HashMap kullanmak "
            + "computeIfAbsent altında race condition yaratır.");
    }

    @Test
    @DisplayName("module ve token field'ları volatile olmalı (happens-before yayını)")
    void moduleAndTokenFields_mustBeVolatile() throws Exception {
        Field moduleField = IaikPkcs11Module.class.getDeclaredField("module");
        Field tokenField = IaikPkcs11Module.class.getDeclaredField("token");

        assertTrue(Modifier.isVolatile(moduleField.getModifiers()),
            "module field volatile olmalı; aksi halde init sonrası diğer thread'ler "
            + "stale null görebilir ve ensureTokenOpen sırasında yanlış reddedebilir.");
        assertTrue(Modifier.isVolatile(tokenField.getModifiers()),
            "token field volatile olmalı; lifecycle reentrance senaryolarında kritik.");
    }

    @Test
    @DisplayName("invalidateKeyCache() public API olmalı ve cache'i temizlemeli")
    void invalidateKeyCache_mustBePublicAndClearCache() throws Exception {
        // Public API regression: stale cache durumunda admin/health endpoint
        // bu metodu çağırarak yeni HSM sertifikasını re-resolve edebilmeli.
        Method method = IaikPkcs11Module.class.getMethod("invalidateKeyCache");
        assertTrue(Modifier.isPublic(method.getModifiers()),
            "invalidateKeyCache public olmalı");
        assertFalse(Modifier.isStatic(method.getModifiers()),
            "invalidateKeyCache instance metodu olmalı (state cache temizler)");

        // Davranış: cache fiilen temizleniyor mu?
        IaikPkcs11Module instance = new IaikPkcs11Module(
            "non-existent-library", null, null, null);

        Field cacheField = IaikPkcs11Module.class.getDeclaredField("resolvedKeyCache");
        cacheField.setAccessible(true);
        @SuppressWarnings("unchecked")
        Map<String, Object> cache = (Map<String, Object>) cacheField.get(instance);

        cache.put("dummy-alias|deadbeef", new Object());
        assertTrue(cache.size() == 1, "Cache fixture set edilmeli");

        method.invoke(instance);

        assertTrue(cache.isEmpty(),
            "invalidateKeyCache() çağrısından sonra cache boş olmalı; "
            + "stale HSM entry sorununu manuel sıfırlayamazsak listing/imza tutarsızlığı kalır.");
    }

    /**
     * Bu test, PKCS#11 EC/DSA raw r||s → DER SEQUENCE dönüşümünün
     * {@code signOnSession} ve {@code signWithRawFallback} yollarında
     * yapıldığını <em>kontrat olarak</em> doğrular. Gerçek HSM gerekmeden
     * normalizasyon mantığını izole çağırırız.
     */
    @Test
    @DisplayName("normalizeIfEcOrDsa: ECDSA raw r||s → DER, RSA olduğu gibi geçer")
    void normalizeIfEcOrDsa_mustNormalizeEcButPassRsa() throws Exception {
        Method m = IaikPkcs11Module.class.getDeclaredMethod(
            "normalizeIfEcOrDsa", byte[].class, SignatureAlgorithm.class);
        m.setAccessible(true);

        // (1) ECDSA raw r||s (P-256, 64 byte): DER'e dönüşmeli
        byte[] rawEcdsa = new byte[64];
        Arrays.fill(rawEcdsa, 0, 32, (byte) 0x11);
        Arrays.fill(rawEcdsa, 32, 64, (byte) 0x22);
        byte[] ecdsaOut = (byte[]) m.invoke(null, rawEcdsa, SignatureAlgorithm.ECDSA_SHA256);

        assertNotEquals(rawEcdsa.length, ecdsaOut.length,
            "ECDSA raw 64B'tan DER'e dönüşünce uzunluk değişmeli (tag/length overhead)");
        assertTrue(Pkcs11EcdsaSignatureEncoder.looksLikeDer(ecdsaOut),
            "ECDSA çıktısı DER SEQUENCE olmalı — yoksa CAdES/PAdES/XAdES imzayı reddeder");

        // (2) PLAIN_ECDSA da normalize edilmeli
        byte[] plainEcdsaOut = (byte[]) m.invoke(null, rawEcdsa, SignatureAlgorithm.ECDSA_SHA384);
        assertTrue(Pkcs11EcdsaSignatureEncoder.looksLikeDer(plainEcdsaOut),
            "ECDSA_SHA384 çıktısı da DER olmalı");

        // (3) RSA imzası olduğu gibi geçmeli (PKCS#11 zaten encoded verir)
        byte[] rsaRawSignature = new byte[256];
        Arrays.fill(rsaRawSignature, (byte) 0xAB);
        byte[] rsaOut = (byte[]) m.invoke(null, rsaRawSignature, SignatureAlgorithm.RSA_SHA256);
        assertArrayEquals(rsaRawSignature, rsaOut,
            "RSA imzası dönüştürülmemeli — PKCS#11 zaten RSASSA-PKCS1-v1_5 encoded verir");

        // (4) RSA-PSS imzası olduğu gibi geçmeli
        byte[] pssOut = (byte[]) m.invoke(null, rsaRawSignature, SignatureAlgorithm.RSA_SSA_PSS_SHA256_MGF1);
        assertArrayEquals(rsaRawSignature, pssOut,
            "RSA-PSS imzası dönüştürülmemeli — RSASSA-PSS encoded zaten standart");
    }

    @Test
    @DisplayName("signWithRawFallback: DSA için SignatureException atmalı, RSA mekanizmasına düşmemeli")
    void signWithRawFallback_dsaMustBeRejectedExplicitly() throws Exception {
        // Codex regresyonu: DSA private key'le HSM CKM_DSA_<HASH> reddederse,
        // önceki kod yanlışlıkla CKM_RSA_PKCS fallback'ine düşüyordu. DSA key
        // ile RSA mekanizma çağırmak token tarafından anlamsız hatalar üretir.
        // Bu yol explicit reddedilmeli, fallback yapılmamalı.
        IaikPkcs11Module instance = new IaikPkcs11Module(
            "non-existent-library", null, null, null);

        Method fallback = IaikPkcs11Module.class.getDeclaredMethod(
            "signWithRawFallback", long.class, byte[].class, SignatureAlgorithm.class);
        fallback.setAccessible(true);

        InvocationTargetException invocation = assertThrows(InvocationTargetException.class,
            () -> fallback.invoke(instance, 0L, new byte[]{1, 2, 3}, SignatureAlgorithm.DSA_SHA256));

        assertTrue(invocation.getCause() instanceof SignatureException,
            "DSA fallback SignatureException atmalı, fakat şu hata çıktı: " + invocation.getCause());
        String msg = invocation.getCause().getMessage();
        assertTrue(msg.contains("DSA") || msg.contains("dsa") || msg.contains("CKM_DSA"),
            "Hata mesajı DSA olduğunu net belirtmeli: " + msg);
    }

    @Test
    @DisplayName("CertificateFactory ThreadLocal olmalı (JDK thread-safe garanti vermez)")
    void certFactory_mustBeThreadLocal() throws Exception {
        Field f = IaikPkcs11Module.class.getDeclaredField("CERT_FACTORY");
        assertTrue(Modifier.isStatic(f.getModifiers()), "CERT_FACTORY static olmalı");
        assertTrue(ThreadLocal.class.isAssignableFrom(f.getType()),
            "CERT_FACTORY ThreadLocal olmalı; CertificateFactory JDK spec'inde "
            + "thread-safe garanti edilmiyor, paralel listing parse hatalarına "
            + "açık kalmamalı.");
    }

    // ------------------------------------------------------------------
    // Lifecycle: paylaşımlı Cryptoki state ownership
    // ------------------------------------------------------------------

    @Test
    @DisplayName("ownsInitialization field volatile olmalı (lifecycle reentrance)")
    void ownsInitializationField_mustBeVolatile() throws Exception {
        Field f = IaikPkcs11Module.class.getDeclaredField("ownsInitialization");
        assertTrue(Modifier.isVolatile(f.getModifiers()),
            "ownsInitialization volatile olmalı; afterPropertiesSet ve destroy "
            + "farklı thread'lerden çağrılabilir (Spring lifecycle), happens-before "
            + "garantisi olmadan stale değer okunabilir.");
    }

    @Test
    @DisplayName("initializeIdempotent: başarılı init → owned=true, singleThreaded=false")
    void initializeIdempotent_returnsTrueOnFreshInit() throws Exception {
        Method m = IaikPkcs11Module.class.getDeclaredMethod(
            "initializeIdempotent", PKCS11Module.class, boolean.class);
        m.setAccessible(true);

        PKCS11Module mockModule = Mockito.mock(PKCS11Module.class);

        Object outcome = m.invoke(null, mockModule, Boolean.FALSE);

        assertTrue(readOutcomeOwned(outcome),
            "initialize() exception atmadıysa owned=true olmalı (init sahibi biziz).");
        assertFalse(readOutcomeSingleThreaded(outcome),
            "Standart init başarılı; singleThreaded modu sadece NULL-args fallback'inde "
            + "(AKİS uyumluluk) aktif olur.");
        Mockito.verify(mockModule).initialize();
    }

    @Test
    @DisplayName("initializeIdempotent: CKR_CRYPTOKI_ALREADY_INITIALIZED → owned=false (paylaşımlı)")
    void initializeIdempotent_returnsFalseOnAlreadyInitialized() throws Exception {
        Method m = IaikPkcs11Module.class.getDeclaredMethod(
            "initializeIdempotent", PKCS11Module.class, boolean.class);
        m.setAccessible(true);

        PKCS11Module mockModule = Mockito.mock(PKCS11Module.class);
        PKCS11Exception alreadyInit = new PKCS11Exception(
            PKCS11Constants.CKR_CRYPTOKI_ALREADY_INITIALIZED);
        Mockito.doThrow(alreadyInit).when(mockModule).initialize();

        Object outcome = m.invoke(null, mockModule, Boolean.FALSE);

        assertFalse(readOutcomeOwned(outcome),
            "Başka bileşen Cryptoki'yi init etmiş; owned=false olmalı ki "
            + "destroy() finalize çağırmasın (codex bulgusu: paylaşımlı state "
            + "korunmalı).");
    }

    @Test
    @DisplayName("initializeIdempotent: CKR_CRYPTOKI_ALREADY_INITIALIZED dışındaki hatayı yutmamalı")
    void initializeIdempotent_propagatesUnrelatedErrors() throws Exception {
        Method m = IaikPkcs11Module.class.getDeclaredMethod(
            "initializeIdempotent", PKCS11Module.class, boolean.class);
        m.setAccessible(true);

        PKCS11Module mockModule = Mockito.mock(PKCS11Module.class);
        // CKR_DEVICE_ERROR: pass-through olmalı, swallow değil.
        PKCS11Exception deviceError = new PKCS11Exception(
            PKCS11Constants.CKR_DEVICE_ERROR);
        Mockito.doThrow(deviceError).when(mockModule).initialize();

        InvocationTargetException ex = assertThrows(InvocationTargetException.class,
            () -> m.invoke(null, mockModule, Boolean.FALSE));

        assertTrue(ex.getCause() instanceof PKCS11Exception,
            "Diğer PKCS11Exception'lar swallow edilmemeli; ne "
            + "CKR_CRYPTOKI_ALREADY_INITIALIZED ne de CKR_ARGUMENTS_BAD için "
            + "özel davranış geçerli — bu kod ortada hiçbiri değil.");
    }

    @Test
    @DisplayName("initializeIdempotent: CKR_ARGUMENTS_BAD → standart initialize() yeniden denenmez (AKİS fallback)")
    void initializeIdempotent_argumentsBad_triesNullArgsFallbackWithoutRetryingStandard() throws Exception {
        // Mock PKCS11Module'da pkcs11 alanı null olduğu için NULL-args fallback'i
        // reflection sırasında IllegalStateException atar — biz burada şunu
        // doğruluyoruz: standart module.initialize() YALNIZCA BİR KERE çağrıldı
        // ve CKR_ARGUMENTS_BAD sonrası tekrar denenmedi. Fallback yolunun
        // alındığını kanıtlamak için kontrolun reflection katmanına geçtiğini
        // (InvocationTargetException → cause IllegalStateException) gözlüyoruz.
        Method m = IaikPkcs11Module.class.getDeclaredMethod(
            "initializeIdempotent", PKCS11Module.class, boolean.class);
        m.setAccessible(true);

        PKCS11Module mockModule = Mockito.mock(PKCS11Module.class);
        PKCS11Exception argsBad = new PKCS11Exception(PKCS11Constants.CKR_ARGUMENTS_BAD);
        Mockito.doThrow(argsBad).when(mockModule).initialize();

        InvocationTargetException ex = assertThrows(InvocationTargetException.class,
            () -> m.invoke(null, mockModule, Boolean.FALSE));

        // Standart initialize() tam bir kez denendi; AKİS fallback'i de
        // denendi ama mock'ta gerçek native pkcs11 olmadığı için reflection
        // katmanı patladı → IllegalStateException görmeliyiz.
        Mockito.verify(mockModule, Mockito.times(1)).initialize();
        assertTrue(ex.getCause() instanceof IllegalStateException,
            "CKR_ARGUMENTS_BAD sonrası NULL-args fallback yolu denenmeli; mock üstünde "
            + "reflection IllegalStateException atar — bu fallback'in alındığının kanıtıdır. "
            + "Gerçek cause: " + ex.getCause());
    }

    @Test
    @DisplayName("initializeIdempotent: forceNullInitArgs=true → standart initialize() ASLA çağrılmaz")
    void initializeIdempotent_forceNullSkipsStandardInit() throws Exception {
        // Operatör PKCS11_NULL_INIT_ARGS=true verdiyse trial-and-error
        // beklemiyoruz. Mock üstünde NULL-args fallback reflection'a girer
        // ve patlar — biz module.initialize()'ın hiç çağrılmadığını
        // doğruluyoruz (operatöre verilen kontratın gereği).
        Method m = IaikPkcs11Module.class.getDeclaredMethod(
            "initializeIdempotent", PKCS11Module.class, boolean.class);
        m.setAccessible(true);

        PKCS11Module mockModule = Mockito.mock(PKCS11Module.class);

        assertThrows(InvocationTargetException.class,
            () -> m.invoke(null, mockModule, Boolean.TRUE));

        Mockito.verify(mockModule, Mockito.never()).initialize();
    }

    /** {@code InitOutcome.owned} alanını reflection ile okur. */
    private static boolean readOutcomeOwned(Object outcome) throws Exception {
        Field f = outcome.getClass().getDeclaredField("owned");
        f.setAccessible(true);
        return f.getBoolean(outcome);
    }

    /** {@code InitOutcome.singleThreaded} alanını reflection ile okur. */
    private static boolean readOutcomeSingleThreaded(Object outcome) throws Exception {
        Field f = outcome.getClass().getDeclaredField("singleThreaded");
        f.setAccessible(true);
        return f.getBoolean(outcome);
    }

    @Test
    @DisplayName("destroy(): ownsInitialization=false ise module.finalize() ÇAĞRILMAMALI")
    void destroy_mustNotFinalizeWhenInitWasShared() throws Exception {
        // Codex regresyonu: agresif finalize. Bu test paylaşımlı Cryptoki
        // senaryosunda finalize'ın atlandığını DOĞRUDAN gözlemler.
        IaikPkcs11Module instance = new IaikPkcs11Module(
            "non-existent-library", null, null, null);

        PKCS11Module mockModule = Mockito.mock(PKCS11Module.class);

        Field moduleField = IaikPkcs11Module.class.getDeclaredField("module");
        moduleField.setAccessible(true);
        moduleField.set(instance, mockModule);

        Field ownsField = IaikPkcs11Module.class.getDeclaredField("ownsInitialization");
        ownsField.setAccessible(true);
        ownsField.setBoolean(instance, false); // paylaşımlı senaryo

        instance.destroy();

        Mockito.verify(mockModule, Mockito.never())
            .finalize(ArgumentMatchers.any());
    }

    @Test
    @DisplayName("destroy(): ownsInitialization=true ise module.finalize() ÇAĞRILMALI")
    void destroy_mustFinalizeWhenWeOwnTheInit() throws Exception {
        IaikPkcs11Module instance = new IaikPkcs11Module(
            "non-existent-library", null, null, null);

        PKCS11Module mockModule = Mockito.mock(PKCS11Module.class);

        Field moduleField = IaikPkcs11Module.class.getDeclaredField("module");
        moduleField.setAccessible(true);
        moduleField.set(instance, mockModule);

        Field ownsField = IaikPkcs11Module.class.getDeclaredField("ownsInitialization");
        ownsField.setAccessible(true);
        ownsField.setBoolean(instance, true); // bizim init ettiğimiz senaryo

        instance.destroy();

        Mockito.verify(mockModule).finalize(ArgumentMatchers.any());
    }

    @Test
    @DisplayName("destroy() ownership state'i reset etmeli (yeniden init için)")
    void destroy_mustResetOwnershipFlag() throws Exception {
        IaikPkcs11Module instance = new IaikPkcs11Module(
            "non-existent-library", null, null, null);

        Field moduleField = IaikPkcs11Module.class.getDeclaredField("module");
        moduleField.setAccessible(true);
        moduleField.set(instance, Mockito.mock(PKCS11Module.class));

        Field ownsField = IaikPkcs11Module.class.getDeclaredField("ownsInitialization");
        ownsField.setAccessible(true);
        ownsField.setBoolean(instance, true);

        instance.destroy();

        assertFalse(ownsField.getBoolean(instance),
            "destroy() sonrası ownsInitialization false'a sıfırlanmalı; "
            + "aksi halde re-init senaryosunda stale state ile dönülür.");
    }
}
