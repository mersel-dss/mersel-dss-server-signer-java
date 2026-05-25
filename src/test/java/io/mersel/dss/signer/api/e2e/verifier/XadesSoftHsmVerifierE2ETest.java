package io.mersel.dss.signer.api.e2e.verifier;

import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.signature.XAdESService;
import io.mersel.dss.signer.api.models.SignResponse;
import io.mersel.dss.signer.api.models.SigningContext;
import io.mersel.dss.signer.api.models.SigningMaterial;
import io.mersel.dss.signer.api.models.enums.XadesSignatureLevel;
import io.mersel.dss.signer.api.services.SigningMaterialFactory;
import io.mersel.dss.signer.api.services.certificate.CertificateChainBuilderService;
import io.mersel.dss.signer.api.services.certificate.CertificateValidatorService;
import io.mersel.dss.signer.api.services.crypto.CryptoSignerService;
import io.mersel.dss.signer.api.services.crypto.DigestAlgorithmResolverService;
import io.mersel.dss.signer.api.services.crypto.SignatureAlgorithmResolverService;
import io.mersel.dss.signer.api.services.keystore.KeyStoreLoaderService;
import io.mersel.dss.signer.api.services.keystore.iaik.IaikPkcs11Module;
import io.mersel.dss.signer.api.services.signature.xades.XAdESDocumentPlacementService;
import io.mersel.dss.signer.api.services.signature.xades.XAdESLevelUpgradeService;
import io.mersel.dss.signer.api.services.signature.xades.XAdESParametersBuilderService;
import io.mersel.dss.signer.api.services.signature.xades.XAdESSignatureService;
import io.mersel.dss.signer.api.services.signature.xades.XmlProcessingService;
import io.mersel.dss.signer.api.services.timestamp.TimestampConfigurationService;
import io.mersel.dss.signer.api.services.util.CompressionService;
import io.mersel.dss.signer.api.testsupport.SignedArtifactExporter;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Severity;
import io.qameta.allure.SeverityLevel;
import io.mersel.dss.signer.api.testsupport.SoftHsm2TestSupport;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.ByteArrayInputStream;
import java.nio.file.Path;
import java.util.Collections;
import java.util.EnumMap;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Semaphore;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * <h1>Gerçek SoftHSM2 + DSS Verifier API üzerinden uçtan-uca XAdES E2E testi</h1>
 *
 * <p>Her PFX test sertifikası ({@link PfxTestKey}, 5 adet) gerçek bir SoftHSM2
 * token'a import edilir; üretim koduyla <b>aynı</b> {@link IaikPkcs11Module}
 * üzerinden ({@link SigningMaterialFactory#createPkcs11SigningContext}) imza
 * akışı çalıştırılır. Üretilen XAdES belgesi Testcontainers ile ayağa kalkan
 * DSS verifier API'sine gönderilir ve {@code TOTAL_PASSED} dönmesi beklenir.</p>
 *
 * <h2>Senaryo matrisi</h2>
 * <p>{@code 5 PFX × 4 belge tipi = 20 parametrize iterasyon}
 * — {@link XadesDocumentFixture#standardFixtures()} TSA-bağımsız fixture
 * setini döndürür:</p>
 * <ul>
 *   <li>{@link XadesDocumentFixture#EFATURA} (UBL Invoice)</li>
 *   <li>{@link XadesDocumentFixture#EIRSALIYE} (UBL DespatchAdvice)</li>
 *   <li>{@link XadesDocumentFixture#EMUSTAHSIL} (UBL CreditNote)</li>
 *   <li>{@link XadesDocumentFixture#HRXML} (HR-XML ProcessUserAccount)</li>
 * </ul>
 *
 * <p>{@link XadesDocumentFixture#EARSIV_RAPORU} bu matrise <em>dahil
 * değildir</em>: e-Arşiv Raporu için XAdES-A yükseltmesi zorunludur ve
 * {@code XAdESLevelUpgradeService} TSA tanımlı değilse fail-fast davranır
 * ({@link io.mersel.dss.signer.api.exceptions.TimestampException}
 * fırlatır). EArchiveReport-spesifik fail-fast regresyonu
 * {@code XAdESSignAndVerifyE2ETest#earchiveReportFailsFastWhenTsaUnconfigured()}
 * tarafından kapsanır; pozitif XAdES-A roundtrip'i için TSA-mock'lı dedike
 * suite gerekir.</p>
 *
 * <h2>Production kod yolunun kapsadığı kritik noktalar</h2>
 * <ul>
 *   <li>{@code IaikPkcs11Module.findByIdOrLabel} ile label-bazlı key resolution.</li>
 *   <li>{@code SigningMaterialFactory.createPkcs11SigningContext} üzerinden
 *       SigningMaterial üretimi (HSM backend).</li>
 *   <li>{@code SigningMaterial.sign} → {@code Pkcs11SigningBackend} →
 *       gerçek {@code C_Sign} çağrısı.</li>
 *   <li>EC anahtarlar için {@code Pkcs11EcdsaSignatureEncoder.toDer} (raw r||s
 *       → DER SEQUENCE) gerçek HSM çıktısı üzerinde sınanır.</li>
 *   <li>{@code XAdESDocumentPlacementService} her belge tipi için doğru
 *       yerleştirme stratejisi kullanır (UBLExtensions vs. enveloped).</li>
 * </ul>
 *
 * <h2>İki bağımlılık birden gerekir</h2>
 * <ul>
 *   <li><b>Native</b>: {@code softhsm2-util}, {@code pkcs11-tool}, libsofthsm2 —
 *       yoksa testler {@code assumeTrue(false)} ile sessizce atlanır.</li>
 *   <li><b>Docker</b>: verifier-api container'ı için Docker daemon —
 *       {@link AbstractVerifierE2ETest#ensureDockerAvailable()} kontrol eder.</li>
 * </ul>
 *
 * <h2>Tag stratejisi</h2>
 * <p>Bu sınıf <b>iki tag'i</b> birden taşır:</p>
 * <ul>
 *   <li>{@code verifier-e2e} — {@link AbstractVerifierE2ETest}'ten inherit edilir.</li>
 *   <li>{@code pkcs11-integration} — bu sınıfta açıkça belirtilir.</li>
 * </ul>
 * <p>Default {@code mvn test} ikisini de exclude eder. Koşturma:</p>
 * <pre>
 *   mvn test -B -Dgroups=pkcs11-integration -DexcludedGroups=
 *   # veya
 *   mvn test -B -Dgroups=verifier-e2e -DexcludedGroups=
 * </pre>
 *
 * <h2>Performans</h2>
 * <p>SoftHSM init + 5 PFX import + verifier container startup ≈ 30-60 saniye
 * (per-class, bir kez). Sonraki 20 test her biri ≈ 1-2 saniye → toplam
 * yaklaşık 1-2 dakika.</p>
 */
@Tag("pkcs11-integration")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ExtendWith(SignedArtifactExporter.class)
@DisplayName("XAdES E2E: gerçek SoftHSM ile imzala → DSS verifier ile doğrula")
@Epic("Signature Roundtrip")
@Feature("XAdES / PKCS#11 SoftHSM")
@Severity(SeverityLevel.CRITICAL)
class XadesSoftHsmVerifierE2ETest extends AbstractVerifierE2ETest {

    private static final String TOKEN_LABEL = "mersel-xades-e2e";
    private static final String SO_PIN = "12345678";
    private static final String USER_PIN = "123456";

    /**
     * Tüm parametrize iterasyonlar aynı SoftHSM state'ini paylaşır.
     *
     * <p><b>NEDEN STATIC?</b> JUnit Jupiter {@code 5.8.2}'de
     * {@code @TestInstance(PER_CLASS)} + <em>non-static</em> {@code @TempDir}
     * instance field + non-static {@code @BeforeAll} method kombinasyonunda
     * field, {@code @BeforeAll} çalışırken henüz inject <b>edilmez</b> ve
     * {@code NullPointerException} atılır. Sorun
     * <a href="https://github.com/junit-team/junit5/pull/2811">junit5#2811</a>
     * ile 5.9.0'da düzeltildi; biz Spring Boot parent'tan 5.8.2 aldığımız için
     * field'ı {@code static} yapmak en güvenli geçici çözüm. Static
     * {@code @TempDir} her Jupiter sürümünde ilk {@code @BeforeAll}'dan ÖNCE
     * garanti inject edilir.</p>
     */
    @TempDir
    static Path softHsmDir;

    private SoftHsm2TestSupport hsm;
    private XAdESSignatureService xadesSignatureService;
    private Map<PfxTestKey, SigningMaterial> materialsByKey;

    @BeforeAll
    void setUpHsmAndSigningStack() throws Exception {
        // 1) Native araç kontrolü; yoksa tüm class skip olur.
        hsm = SoftHsm2TestSupport.requireOrSkip(softHsmDir);

        // 2) Tek bir token + 5 PFX (her biri unique label ile).
        // Yalnızca pozitif (Status.VALID) PFX'ler import edilir; negative
        // lifecycle PFX'leri CertificateLifecycleNegativeE2ETest'in scope'unda.
        hsm.initToken(TOKEN_LABEL, SO_PIN, USER_PIN);
        for (PfxTestKey key : PfxTestKey.positiveValues()) {
            hsm.importPfx(key, labelFor(key));
        }

        // 3) IaikPkcs11Module — production kodunda kullanılan SINIFIN AYNISI.
        IaikPkcs11Module module = hsm.openModule(USER_PIN);

        // 4) Her PFX için SigningMaterial pre-resolve et (test başına resolve
        //    pahalı ve hep aynı sonuç). EnumMap → O(1) lookup.
        SigningMaterialFactory factory = new SigningMaterialFactory(
                new KeyStoreLoaderService(),
                new CertificateChainBuilderService(Collections.emptyList()),
                new CertificateValidatorService());
        materialsByKey = new EnumMap<>(PfxTestKey.class);
        for (PfxTestKey key : PfxTestKey.positiveValues()) {
            SigningContext ctx = factory.createPkcs11SigningContext(
                    module, hsm.labelFor(key), /*serialNumberHex*/ null);
            materialsByKey.put(key, ctx.getMaterial());
        }

        // 5) XAdES servis stack'i (mevcut XAdESSignAndVerifyE2ETest ile aynı
        //    pattern; production Spring DI'sini manuel kuruyoruz).
        xadesSignatureService = buildXadesSignatureService();
    }

    @AfterAll
    void tearDown() {
        if (hsm != null) {
            hsm.close();
        }
    }

    static Stream<Arguments> matrix() {
        Stream.Builder<Arguments> b = Stream.builder();
        for (PfxTestKey key : PfxTestKey.positiveValues()) {
            // Standart küçük fixture'lar; EFATURA_LARGE (~5 MB) ayrı
            // XAdESLargeDocumentE2ETest tarafından SoftHSM-bağımsız koşturulur.
            for (XadesDocumentFixture fixture : XadesDocumentFixture.standardFixtures()) {
                b.add(Arguments.of(key, fixture));
            }
        }
        return b.build();
    }

    @ParameterizedTest(name = "[{index}] {0} × {1}")
    @MethodSource("matrix")
    void signXadesViaSoftHsm_andVerifyValid(PfxTestKey key, XadesDocumentFixture fixture) {
        SigningMaterial material = materialsByKey.get(key);
        assertNotNull(material, "SigningMaterial pre-resolve edilmiş olmalı: " + key);
        assertTrue(material.isPkcs11(),
                "Materyal PKCS#11 backend olarak işaretlenmeli (" + key + ")");

        byte[] xmlBytes = fixture.readBytes();
        assertTrue(xmlBytes.length > 0, "Fixture XML boş olmamalı: " + fixture);

        String signatureId = "id-" + UUID.randomUUID().toString().replace("-", "");

        SignResponse signed = xadesSignatureService.signXml(
                new ByteArrayInputStream(xmlBytes),
                fixture.getDocumentType(),
                signatureId,
                /*zipped*/ false,
                material, XadesSignatureLevel.XADES_BES);

        assertNotNull(signed, "signResponse null olmamalı (" + key + " / " + fixture + ")");
        assertNotNull(signed.getSignedDocument(),
                "imzalı XML byte dizisi null olmamalı (" + key + " / " + fixture + ")");
        assertTrue(signed.getSignedDocument().length > xmlBytes.length,
                "İmzalı XML orijinalden en az büyük olmalı (XAdES Signature eklenir); "
                        + "orijinal=" + xmlBytes.length
                        + ", imzalı=" + signed.getSignedDocument().length);

        // SoftHSM-backed imzayı disk'e export et — production HSM ile aynı
        // kod yolundan üretildiği için downstream araçlarla cross-validation
        // yapmaya değer.
        SignedArtifactExporter.export(
                SignedArtifactExporter.Format.XADES_HSM, signed.getSignedDocument());

        // Verifier API roundtrip
        VerifierApiClient.VerificationResponse result =
                verifierClient().verify(signed.getSignedDocument(), fixture.getFileName());

        CAdESSignAndVerifyE2ETest.assertVerificationPassed(
                result, "XADES", key, "SoftHSM/" + fixture.name());
    }

    // ---------------------------------------------------------------- helpers

    private static String labelFor(PfxTestKey key) {
        return "xades-e2e-" + key.name().toLowerCase(Locale.ROOT);
    }

    /**
     * Production'da Spring tarafından DI ile kurulan {@link XAdESSignatureService}'i
     * test koşumunda manuel olarak wire eder.
     *
     * <p>Mevcut {@link XAdESSignAndVerifyE2ETest#initSigningStack()} ile birebir
     * aynı bağımlılık ağacı; tek fark <em>SigningMaterial</em>'in HSM-backed
     * olması.</p>
     */
    private static XAdESSignatureService buildXadesSignatureService() {
        // Revocation alert'leri sustur (bkz. AbstractVerifierE2ETest).
        CertificateVerifier verifier = newPermissiveVerifier();
        XAdESService xadesService = new XAdESService(verifier);

        DigestAlgorithmResolverService digestResolver = new DigestAlgorithmResolverService();
        SignatureAlgorithmResolverService sigAlgResolver = new SignatureAlgorithmResolverService();
        CryptoSignerService crypto = new CryptoSignerService(sigAlgResolver);

        XAdESParametersBuilderService paramsBuilder =
                new XAdESParametersBuilderService(digestResolver);
        XmlProcessingService xmlProcessor = new XmlProcessingService();
        XAdESDocumentPlacementService placement = new XAdESDocumentPlacementService();

        // TSA yapılandırılmamış → e-Arşiv/e-Bilet için XAdES-A upgrade
        // çağrılırsa fail-fast TimestampException fırlar. Bu matrisde EArchive/
        // EBilet fixture'ları kullanılmadığı için (standardFixtures() onları
        // hariç tutar) sorun çıkmaz.
        TimestampConfigurationService tsConfig = new TimestampConfigurationService(
                /*tspServerUrl*/ "",
                /*tspUserId*/ "",
                /*tspUserPassword*/ "",
                /*isTubitakTsp*/ false);
        XAdESLevelUpgradeService upgrade = new XAdESLevelUpgradeService(verifier, tsConfig);

        CompressionService compression = new CompressionService();

        return new XAdESSignatureService(
                xadesService,
                paramsBuilder,
                xmlProcessor,
                placement,
                upgrade,
                crypto,
                verifier,
                compression,
                new Semaphore(2));
    }
}
