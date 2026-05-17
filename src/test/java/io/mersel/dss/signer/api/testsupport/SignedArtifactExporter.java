package io.mersel.dss.signer.api.testsupport;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import io.qameta.allure.Allure;
import org.junit.jupiter.api.extension.AfterTestExecutionCallback;
import org.junit.jupiter.api.extension.BeforeTestExecutionCallback;
import org.junit.jupiter.api.extension.Extension;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Test sırasında üretilen <b>gerçek imzalı içerikleri</b> diske export eden
 * yardımcı + JUnit 5 extension.
 *
 * <h2>Amaç</h2>
 * <p>Default suite + verifier-e2e suite çalıştırıldığında, her gerçek-imza
 * testi (XAdES / CAdES / PAdES / WS-Security) imzaladığı bytes'ı
 * <code>${project}/target/signed-artifacts/&lt;format&gt;/</code> altına
 * descriptive bir dosya adıyla yazar. Bu dosyalar:</p>
 *
 * <ul>
 *   <li>Production signer'ın gerçek çıktısıdır (test mock'ı değil).</li>
 *   <li>Adobe Acrobat Reader / EU DSS Demo Webapp / xmlsec1 / openssl smime /
 *       Apache WSS4J gibi <b>üçüncü taraf doğrulayıcılarla</b> manuel olarak
 *       sınanabilir — "kendi verifier'ımız dışında" cross-validation.</li>
 *   <li>{@code target/} altında olduğu için git'e karışmaz
 *       ({@code .gitignore}'da {@code target/} zaten exclude). Her
 *       {@code mvn clean} sonrası sıfırdan üretilir.</li>
 * </ul>
 *
 * <h2>Kullanım</h2>
 *
 * <p><b>1) Test sınıfına extension ekle:</b></p>
 * <pre>{@code
 * @ExtendWith(SignedArtifactExporter.class)
 * class MyXadesTest { ... }
 * }</pre>
 *
 * <p><b>2) İmzalı bytes'ı üret ve export et:</b></p>
 * <pre>{@code
 * SignResponse signed = service.signXml(...);
 * SignedArtifactExporter.export(Format.XADES, signed.getSignedDocument());
 * }</pre>
 *
 * <p>Extension test başında {@link ExtensionContext}'i thread-local'a koyar
 * → {@link #export(Format, byte[])} dosya adını otomatik test
 * class + method + display name'den türetir. Aynı test birden fazla bytes
 * üretiyorsa {@link #export(Format, byte[], String)} ile label verilir
 * (örn. {@code "baseline"}, {@code "tampered"}, {@code "sample-0"}).</p>
 *
 * <h2>Dosya adı formatı</h2>
 *
 * <p><b>Tercih edilen — label dolu:</b> Çağıran taraf PFX × backend ×
 * fixture × scenario detayını {@code label} parametresinde verirse
 * dosya adı kısa ve semantic olur:</p>
 * <pre>
 *   target/signed-artifacts/&lt;format&gt;/&lt;methodName&gt;__&lt;sanitize(label)&gt;.&lt;ext&gt;
 *
 *   xades/xadesFixtureRoundtripIsValid__KURUM01_RSA2048_PFX_JCA_EFATURA.xml
 *   cades-attached/cadesRoundtripIsValid__KURUM01_RSA2048_PFX_JCA_attached.p7s
 *   cades-detached/cadesRoundtripIsValid__KURUM01_RSA2048_PFX_JCA_detached.p7s
 *   pades/padesRoundtripIsValid__KURUM01_RSA2048_PFX_JCA_embedded.pdf
 *   pades-negative/byteRangeBitFlipFailsVerification__byte100-bitflip.pdf
 *   xades-negative/wrapAttackRejected__wrap-attack.xml
 * </pre>
 *
 * <p><b>Fallback — label boş:</b> Eski stil çağrılar için class +
 * method + parametre/hash birleşimi:</p>
 * <pre>
 *   target/signed-artifacts/&lt;format&gt;/&lt;className&gt;__&lt;methodName&gt;[__&lt;displayOrIter&gt;].&lt;ext&gt;
 * </pre>
 *
 * <h2>System property toggle'ları</h2>
 * <ul>
 *   <li>{@code -Dsigned.artifacts.export=false} → export'u tamamen kapatır
 *       (no-op). CI'da disk space tasarrufu istenirse.</li>
 *   <li>{@code -Dsigned.artifacts.dir=/abs/path} → hedef klasörü değiştirir.
 *       Default {@code target/signed-artifacts}. Mutlak veya cwd-göreli yol.</li>
 *   <li>{@code -Dsigned.artifacts.purge=false} → JVM başlangıcında otomatik
 *       root purge'unu kapatır (incremental debug veya paralel
 *       {@code forkCount>1} koşumu için).</li>
 * </ul>
 *
 * <h2>Determinism + temiz snapshot garantisi</h2>
 * <p>Her {@code mvn test} koşumunun başında (ilk export çağrısında)
 * {@code target/signed-artifacts/} root klasörü tamamen silinir →
 * klasörde <em>yalnızca</em> bu run'da koşan testlerin çıktıları
 * kalır. Aynı testin tekrar tekrar koşumu aynı dosya yoluna üzerine
 * yazar (timestamp suffix'i yok); eski runlardan kalan hayalet
 * dosyalar birikmez. Tarih bilgisine ihtiyaç varsa dosyanın
 * {@code mtime}'ına bakılabilir.</p>
 *
 * <h2>Thread-safety</h2>
 * <p>Surefire {@code forkCount > 1} ile koşuldukta her fork ayrı JVM —
 * thread-local context tekildir. Aynı JVM içinde paralel test koşumu
 * için ({@code junit.jupiter.execution.parallel.enabled=true}) static
 * {@link InheritableThreadLocal} kullanılır; her test method'unun
 * {@code beforeTestExecution} hook'u kendi thread'inde set eder.</p>
 */
public final class SignedArtifactExporter
        implements BeforeTestExecutionCallback, AfterTestExecutionCallback, Extension {

    private static final Logger LOGGER = LoggerFactory.getLogger(SignedArtifactExporter.class);

    /** System property: {@code true} (default) → export aktif. */
    private static final String PROP_EXPORT_ENABLED = "signed.artifacts.export";

    /** System property: hedef root klasör. Default {@code target/signed-artifacts}. */
    private static final String PROP_EXPORT_DIR = "signed.artifacts.dir";

    /**
     * System property: {@code true} (default) → her JVM açılışında
     * (yani her {@code mvn test} koşumunun başında) root klasör
     * tamamen silinir → sadece bu run'da koşan testlerin çıktıları
     * kalır. {@code false} verilirse eski runlardan kalan dosyalar
     * korunur (incremental debug için).
     */
    private static final String PROP_PURGE_ROOT = "signed.artifacts.purge";

    /** Cwd-göreli default klasör. {@code mvn clean} bunu siler. */
    private static final String DEFAULT_DIR = "target/signed-artifacts";

    /** README.md'yi yalnızca tek bir kez yaz. */
    private static final AtomicBoolean README_WRITTEN = new AtomicBoolean(false);

    /** Root klasör temizliği yalnızca JVM başına bir kez yapılır. */
    private static final AtomicBoolean ROOT_PURGED = new AtomicBoolean(false);

    /**
     * Test başına ExtensionContext — her test method'u kendi thread'inde
     * set eder. {@link InheritableThreadLocal} sayesinde test'in spawn
     * ettiği worker thread'lerden (paralel imza testleri) de erişilebilir.
     */
    private static final InheritableThreadLocal<ExtensionContext> CTX =
            new InheritableThreadLocal<>();

    /**
     * İmza formatları — her birinin alt klasörü + uzantısı sabittir.
     * Yeni format eklemek için enum'a entry eklemek + dispatcher
     * helper'larla {@link #export(Format, byte[])} çağırmak yeter.
     */
    public enum Format {
        /** XAdES-BES enveloped imzalar (UBL e-Fatura, e-Arşiv vs.). */
        XADES("xades", "xml", "application/xml"),
        /** XAdES tampered/negative testler için ayrı klasör. */
        XADES_NEGATIVE("xades-negative", "xml", "application/xml"),
        /**
         * XAdES — <b>negatif sertifika</b> ile imzalanmış (revoked / expired /
         * suspended). Tamper'dan (XADES_NEGATIVE) farklı: imza matematik
         * olarak doğru, ama sertifikanın lifecycle'ı geçersiz; verifier
         * REVOKED / OUT_OF_BOUNDS_NOT_FRESH / CERTIFICATE_HOLD dönmeli.
         */
        XADES_NEGATIVE_CERT("xades-negative-cert", "xml", "application/xml"),
        /** XAdES SHA-1 legacy fixture'lar. */
        XADES_LEGACY("xades-legacy", "xml", "application/xml"),
        /** XAdES HSM/SoftHSM-backed signing. */
        XADES_HSM("xades-hsm", "xml", "application/xml"),
        /** CAdES attached/enveloping CMS (.p7s içinde payload da var). */
        CADES_ATTACHED("cades-attached", "p7s", "application/pkcs7-signature"),
        /** CAdES detached imza (.p7s'te payload yok, ayrı bir orijinal var). */
        CADES_DETACHED("cades-detached", "p7s", "application/pkcs7-signature"),
        /** CAdES tampered/negative örnekler. */
        CADES_NEGATIVE("cades-negative", "p7s", "application/pkcs7-signature"),
        /** CAdES — negatif sertifika lifecycle (revoked/expired/suspended). */
        CADES_NEGATIVE_CERT("cades-negative-cert", "p7s", "application/pkcs7-signature"),
        /** PAdES embedded PDF imzalar. */
        PADES("pades", "pdf", "application/pdf"),
        /** PAdES tampered/cosign/encrypted varyantlar. */
        PADES_NEGATIVE("pades-negative", "pdf", "application/pdf"),
        /** PAdES — negatif sertifika lifecycle (revoked/expired/suspended). */
        PADES_NEGATIVE_CERT("pades-negative-cert", "pdf", "application/pdf"),
        /** WS-Security imzalı SOAP envelope. */
        WSSECURITY("wssecurity", "xml", "application/xml"),
        /** WS-Security — negatif sertifika lifecycle (revoked/expired/suspended). */
        WSSECURITY_NEGATIVE_CERT("wssecurity-negative-cert", "xml", "application/xml");

        private final String dirName;
        private final String extension;
        private final String mimeType;

        Format(String dirName, String extension, String mimeType) {
            this.dirName = dirName;
            this.extension = extension;
            this.mimeType = mimeType;
        }

        public String dirName() { return dirName; }
        public String extension() { return extension; }
        /** Allure attachment için MIME type — preview rendering ipucu. */
        public String mimeType() { return mimeType; }
    }

    // ════════════════════════ JUnit Extension API ════════════════════════

    @Override
    public void beforeTestExecution(ExtensionContext context) {
        CTX.set(context);
    }

    @Override
    public void afterTestExecution(ExtensionContext context) {
        CTX.remove();
    }

    // ════════════════════════ Public Export API ════════════════════════

    /**
     * Verilen formattaki imzalı bytes'ı export eder. Dosya adı çalışan
     * test'in class + method + display name'den otomatik türetilir.
     * Aynı test birden fazla bytes üretiyorsa
     * {@link #export(Format, byte[], String)} ile label vermek gerekir
     * (aksi halde dosya overwrite olur).
     *
     * @return yazılan dosyanın path'i (test assertions'da debug için
     *         loglanabilir); export devre dışıysa {@code null}.
     */
    public static Path export(Format format, byte[] signedBytes) {
        return export(format, signedBytes, null);
    }

    /**
     * Detached CAdES için imza ({@code .p7s}) + orijinal payload'u
     * ({@code .bin}) yan-yana export eder. Üçüncü taraf doğrulayıcı
     * komut: {@code openssl smime -verify -in X.p7s -inform DER
     * -content X.bin -noverify}.
     *
     * <p>Tek başına {@code .p7s} eksik bilgi taşır — orijinal payload
     * olmadan downstream verifier (BouncyCastle CMSSignedData, openssl,
     * EU DSS Demo) imza matematiğini doğrulayamaz. Bu method ikisini
     * birden aynı base-name + farklı uzantı ile yazar.</p>
     *
     * @return yazılan {@code .p7s} dosyasının path'i (sidecar yan tarafta);
     *         export disabled ise {@code null}.
     */
    public static Path exportDetachedCmsPair(byte[] cmsBytes, byte[] payloadBytes) {
        return exportDetachedCmsPair(cmsBytes, payloadBytes, null);
    }

    /**
     * Detached CAdES için imza + payload export'u; aynı test birden
     * fazla pair üretirse {@code label} ile ayrıştırılır.
     */
    public static Path exportDetachedCmsPair(byte[] cmsBytes, byte[] payloadBytes, String label) {
        Path cmsPath = export(Format.CADES_DETACHED, cmsBytes, label);
        if (cmsPath == null) {
            return null;
        }
        if (payloadBytes == null || payloadBytes.length == 0) {
            LOGGER.warn("Detached CMS payload null/empty — sidecar yazılmadı (label={})", label);
            return cmsPath;
        }
        try {
            String p7sName = cmsPath.getFileName().toString();
            // ".p7s" → ".bin" — uzunluğunun ".p7s" kadarını çıkar.
            String stem = p7sName.endsWith("." + Format.CADES_DETACHED.extension())
                    ? p7sName.substring(0, p7sName.length() - (Format.CADES_DETACHED.extension().length() + 1))
                    : p7sName;
            Path binPath = cmsPath.resolveSibling(stem + ".bin");
            Files.write(binPath, payloadBytes,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING,
                    StandardOpenOption.WRITE);
            LOGGER.debug("Detached CMS payload sidecar yazıldı: {} ({} byte)",
                    binPath, payloadBytes.length);
        } catch (IOException e) {
            LOGGER.warn("Detached CMS payload sidecar yazılamadı (label={}): {}",
                    label, e.getMessage());
        }
        return cmsPath;
    }

    /**
     * Verilen formattaki imzalı bytes'ı export eder; aynı test method'u
     * içinde birden fazla bytes üretildiğinde {@code label} ile
     * (örn. {@code "baseline"}, {@code "tampered"}) ayrıştırılır.
     *
     * <p><b>Allure side-effect:</b> Disk'e yazmanın yanı sıra imzalı bytes
     * koşan test case'e Allure attachment olarak da bağlanır → GitHub
     * Pages Evidence Site'taki test detay sayfasında doğrudan
     * görüntülenebilir/indirilebilir.</p>
     *
     * @param format imza tipi (dosya uzantısı + alt klasör belirler)
     * @param signedBytes imzalı içerik — null/empty ise no-op + WARN log
     * @param label opsiyonel ek tanımlayıcı; null/empty ise eklenmez
     * @return yazılan dosya path'i; export disabled ise {@code null}
     */
    public static Path export(Format format, byte[] signedBytes, String label) {
        if (!isEnabled()) {
            return null;
        }
        if (signedBytes == null || signedBytes.length == 0) {
            LOGGER.warn("SignedArtifactExporter.export: bytes null/empty, atlandı (format={})", format);
            return null;
        }
        try {
            Path root = exportRoot();
            Files.createDirectories(root);
            ensureReadmeWritten(root);

            Path formatDir = root.resolve(format.dirName());
            Files.createDirectories(formatDir);

            String fileName = deriveFileName(format, label);
            Path target = formatDir.resolve(fileName);

            Files.write(target, signedBytes,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING,
                    StandardOpenOption.WRITE);

            LOGGER.debug("Signed artifact yazıldı: {} ({} byte)", target, signedBytes.length);

            // Allure attachment — Pages/test-report/ altında test case detayında
            // signed binary'yi doğrudan açma/indirme imkanı sunar. Allure
            // classpath'te değilse veya call test contextinde değilse silently
            // pas geçilir (TestNG/JUnit 5 dışındaki bir akıştan çağrılırsa).
            tryAddAllureAttachment(fileName, format.mimeType(), signedBytes);

            return target;
        } catch (IOException e) {
            // Test akışını kesmeyelim — export bir side-effect, asıl test
            // assertion'larını engellemesin. WARN ve devam.
            LOGGER.warn("Signed artifact yazılamadı (format={}, label={}): {}",
                    format, label, e.getMessage());
            return null;
        }
    }

    // ════════════════════════ Public Export API (v2 — verification) ════════════════════════

    /**
     * Imzalı bytes'ı export eder VE yanına {@code .verify.json} sidecar
     * dosyası yazar; ayrıca her ikisini Allure attachment olarak test
     * case'e bağlar. GitHub Pages Evidence Site'ta test detay sayfasında
     * "signed dosya + mersel-verifier-api PASSED/INDETERMINATE response'u"
     * yan-yana görünür.
     *
     * <p><b>Tipik kullanım (positive test):</b></p>
     * <pre>{@code
     * VerificationResponse r = verifierClient().verify(signedBytes, "doc.xml");
     * Map<String, Object> report = new LinkedHashMap<>();
     * report.put("verifierName", "mersel-verifier-api");
     * report.put("verifierEndpoint", verifierContainer().baseUrl());
     * report.put("indication", r.getSignatures().get(0).getIndication());
     * report.put("subIndication", r.getSignatures().get(0).getSubIndication());
     * report.put("signedBy", r.getSignatures().get(0).getSignerCertificate().get("subjectDN"));
     * report.put("signatureFormat", r.getSignatures().get(0).getSignatureFormat());
     * report.put("trustAnchorReached", r.getSignatures().get(0).getValidationDetails().isTrustAnchorReached());
     * report.put("validationTime", Instant.now().toString());
     * report.put("expectedIndication", "TOTAL_PASSED");
     * report.put("expectationMet", "TOTAL_PASSED".equals(report.get("indication")));
     * SignedArtifactExporter.exportWithVerification(
     *         Format.XADES, signedBytes, "kurum01-rsa-efatura", report);
     * }</pre>
     *
     * <p>{@code verificationReport} {@link LinkedHashMap} ile order-preserve
     * verilirse JSON çıktısı deterministic okunabilir sırada olur. Auditor
     * Pages'te dosyayı açtığında "verifierName" en üstte, "expectationMet"
     * en altta gibi bir display sağlar.</p>
     *
     * @param verificationReport jackson-serializable map; null ise
     *                           {@link #export(Format, byte[], String)}
     *                           davranışına düşer (sidecar yazılmaz)
     * @return signed bytes dosyasının path'i; verify.json yan tarafa yazılır
     */
    public static Path exportWithVerification(Format format,
                                              byte[] signedBytes,
                                              String label,
                                              Map<String, Object> verificationReport) {
        Path signedPath = export(format, signedBytes, label);
        if (signedPath == null || verificationReport == null || verificationReport.isEmpty()) {
            return signedPath;
        }
        writeVerifyJsonSidecar(signedPath, format, verificationReport);
        return signedPath;
    }

    /**
     * Detached CAdES için imza + payload + verify.json üçlüsünü
     * export eder. {@link #exportDetachedCmsPair(byte[], byte[], String)}
     * üzerine verify.json sidecar ekler.
     */
    public static Path exportDetachedCmsPairWithVerification(byte[] cmsBytes,
                                                              byte[] payloadBytes,
                                                              String label,
                                                              Map<String, Object> verificationReport) {
        Path cmsPath = exportDetachedCmsPair(cmsBytes, payloadBytes, label);
        if (cmsPath == null || verificationReport == null || verificationReport.isEmpty()) {
            return cmsPath;
        }
        writeVerifyJsonSidecar(cmsPath, Format.CADES_DETACHED, verificationReport);
        return cmsPath;
    }

    // ════════════════════════ Internal helpers ════════════════════════

    /**
     * Lazy-init Jackson ObjectMapper — pretty-print + insertion-order key
     * preserve. SerializationFeature.WRITE_DATES_AS_TIMESTAMPS=false default
     * (Instant'lar ISO-8601 string olarak çıkar).
     */
    private static final class JsonHolder {
        static final ObjectMapper INSTANCE = new ObjectMapper()
                .enable(SerializationFeature.INDENT_OUTPUT)
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    }

    /**
     * Signed artifact'in yanına {@code .verify.json} sidecar yazar.
     * Örnek: {@code kurum01-rsa-efatura.xml} → {@code kurum01-rsa-efatura.verify.json}.
     * <p>Aynı sidecar'ı Allure attachment olarak da test case'e bağlar.</p>
     */
    private static void writeVerifyJsonSidecar(Path signedPath,
                                               Format format,
                                               Map<String, Object> report) {
        try {
            String name = signedPath.getFileName().toString();
            String stem = name.endsWith("." + format.extension())
                    ? name.substring(0, name.length() - (format.extension().length() + 1))
                    : name;
            Path verifyPath = signedPath.resolveSibling(stem + ".verify.json");

            // Generation context'i raporun "envelope"una koy ki Pages'te
            // dosya açıldığında okuyan kişi hangi test, hangi commit, ne
            // zaman olduğunu görsün.
            Map<String, Object> envelope = new LinkedHashMap<>();
            envelope.put("artifact", name);
            envelope.put("format", format.name());
            envelope.put("generatedAt", Instant.now().toString());
            envelope.put("generatedBy", testContextDescriptor());
            envelope.putAll(report);

            byte[] json = JsonHolder.INSTANCE.writerWithDefaultPrettyPrinter()
                    .writeValueAsBytes(envelope);
            Files.write(verifyPath, json,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING,
                    StandardOpenOption.WRITE);
            LOGGER.debug("Verify sidecar yazıldı: {} ({} byte)", verifyPath, json.length);

            tryAddAllureAttachment(stem + ".verify.json", "application/json", json);
        } catch (IOException e) {
            LOGGER.warn("Verify sidecar yazılamadı (artifact={}): {}",
                    signedPath.getFileName(), e.getMessage());
        }
    }

    /**
     * Allure'a attachment ekleme — JUnit context yoksa veya Allure classpath
     * dışındaysa (production akışı, tooling test'i) silently no-op.
     */
    private static void tryAddAllureAttachment(String name, String mimeType, byte[] content) {
        // Test contextinde değilsek Allure runtime "no allure-results dir" warn'i
        // basar — bunu engellemek için CTX kontrolü yeter (CTX null ise main
        // thread'de değil, adhoc çağrı; attachment'ın anlamı yok).
        if (CTX.get() == null) {
            return;
        }
        try {
            Allure.addAttachment(name, mimeType, new ByteArrayInputStream(content),
                    fileExtensionForMime(mimeType));
        } catch (Throwable t) {
            // NoClassDefFoundError + her türlü Allure runtime exception silently
            // yutulur — test akışı bozulmasın. WARN olarak loglayalım, debug için.
            LOGGER.warn("Allure attachment eklenemedi (name={}, mime={}): {}",
                    name, mimeType, t.getMessage());
        }
    }

    /**
     * Allure'un dosya uzantısı kararı için MIME'a karşılık gelen extension.
     * Allure UI bu uzantıyı dosya download adında ve preview seçiminde kullanır.
     */
    private static String fileExtensionForMime(String mimeType) {
        if (mimeType == null) return ".bin";
        switch (mimeType) {
            case "application/xml": return ".xml";
            case "application/json": return ".json";
            case "application/pdf": return ".pdf";
            case "application/pkcs7-signature": return ".p7s";
            case "application/octet-stream": return ".bin";
            default: return ".bin";
        }
    }

    /**
     * Test context'in kısa, okunabilir tanıtıcısı — verify.json envelope'una
     * "generatedBy" alanı olarak gömülür. Örn: {@code "XAdESSignAndVerifyE2ETest#xadesFixtureRoundtripIsValid"}.
     */
    private static String testContextDescriptor() {
        ExtensionContext ctx = CTX.get();
        if (ctx == null) {
            return "adhoc";
        }
        try {
            return ctx.getRequiredTestClass().getSimpleName()
                    + "#" + ctx.getRequiredTestMethod().getName();
        } catch (Exception e) {
            return ctx.getDisplayName();
        }
    }

    private static boolean isEnabled() {
        String prop = System.getProperty(PROP_EXPORT_ENABLED, "true");
        return !"false".equalsIgnoreCase(prop.trim());
    }

    private static boolean isPurgeEnabled() {
        String prop = System.getProperty(PROP_PURGE_ROOT, "true");
        return !"false".equalsIgnoreCase(prop.trim());
    }

    /**
     * Resolve eder ve <b>ilk çağrıda</b> (JVM başına) root'u temizler.
     *
     * <p><b>Neden purge?</b> {@code mvn test} {@code mvn clean} olmadan
     * koşulduğunda {@code target/signed-artifacts/} altındaki eski
     * dosyalar birikiyor: önceki run'da bir test koştu, yeni run'da
     * o test silindi ya da label'ı değişti → eski dosya hayalet
     * olarak kalıyor ve auditor "bu çıktı son run'a mı ait?" diye
     * tereddüt ediyor. Her JVM başlangıcında root sıfırlanarak
     * klasörün "son test koşumunun snapshot'ı" olması garanti
     * edilir.</p>
     *
     * <p><b>Race condition notu:</b> Surefire varsayılan
     * ({@code forkCount=1, reuseForks=true}) tek JVM kullandığı için
     * {@code AtomicBoolean} yeterli. Eğer {@code forkCount > 1} ile
     * paralel JVM açılırsa her fork kendi root'unu purge eder ve
     * birbirinin yazdıklarını silebilir → bu durumda
     * {@code -Dsigned.artifacts.purge=false} verilmesi tavsiye edilir.</p>
     */
    private static Path exportRoot() {
        String configured = System.getProperty(PROP_EXPORT_DIR, DEFAULT_DIR);
        Path root = Paths.get(configured).toAbsolutePath().normalize();
        if (ROOT_PURGED.compareAndSet(false, true) && isPurgeEnabled()) {
            purgeRoot(root);
        }
        return root;
    }

    /**
     * Root klasörü recursive olarak siler. Dosya yoksa no-op.
     * Yazma hataları (örn. dosya başka süreç tarafından kilitli)
     * silently swallow edilir — test akışını kesmeyiz.
     */
    private static void purgeRoot(Path root) {
        if (!Files.exists(root)) {
            return;
        }
        try {
            // Recursive delete: deepest-first sort ki klasörden önce içerik silinsin.
            try (java.util.stream.Stream<Path> walk = Files.walk(root)) {
                walk.sorted(java.util.Comparator.reverseOrder())
                        .forEach(p -> {
                            try {
                                Files.delete(p);
                            } catch (IOException ignored) {
                                // Silinemeyen tek dosya tüm purge'u bozmasın.
                            }
                        });
            }
            LOGGER.info("SignedArtifactExporter: önceki koşumdan kalan dosyalar temizlendi → {}", root);
        } catch (IOException e) {
            LOGGER.warn("SignedArtifactExporter: root klasör temizlenemedi ({}): {}",
                    root, e.getMessage());
        }
    }

    /**
     * Dosya adı üretimi — iki stratejiden birini seçer:
     *
     * <h3>1) Label dolu → semantic mod (tercih edilen)</h3>
     * <p>Çağıran taraf {@code label} parametresinde dosyayı tanımlayan
     * tüm bilgiyi (PFX × backend × fixture × tampering türü vs.)
     * geçtiyse, dosya adı kısa ve okunabilir tutulur:</p>
     * <pre>
     *   &lt;methodName&gt;__&lt;sanitize(label)&gt;.&lt;ext&gt;
     *
     *   örnek:
     *   xades/xadesFixtureRoundtripIsValid__KURUM01_RSA2048_PFX_JCA_EFATURA.xml
     *   cades-attached/cadesRoundtripIsValid__KURUM01_RSA2048_PFX_JCA_attached.p7s
     *   pades-negative/byteRangeBitFlipFailsVerification__byte100-bitflip.pdf
     *   xades-negative/wrapAttackRejected__wrap-attack.xml
     * </pre>
     * <p>Class adı dahil edilmez çünkü {@code Format} alt klasörü
     * ({@code xades/}, {@code cades-attached/} vs.) zaten format
     * context'i veriyor; class adının da prefix olarak eklenmesi
     * dosya adlarını gereksiz uzatır. Method adı sadece aynı
     * "label" değerinin farklı method'lardan üretilebilmesi
     * için tutulur (örn. negative E2E'de 3 farklı tampering
     * method'unun "baseline" label'ı çakışmasın).</p>
     *
     * <h3>2) Label boş → otomatik mod (fallback)</h3>
     * <p>Çağıran label vermediyse class + method + parametre/hash
     * birleşimi üretilir (eski davranış). Bu yol parametrize
     * testlerde anlamlı kalır:</p>
     * <pre>
     *   &lt;className&gt;__&lt;methodName&gt;[__&lt;displayOrIter&gt;].&lt;ext&gt;
     * </pre>
     * <p>Yeni testler her zaman label vermeli; legacy çağrılar
     * (henüz migrate edilmemiş) için 2. yol geri uyumluluk
     * sağlar.</p>
     */
    private static String deriveFileName(Format format, String label) {
        ExtensionContext ctx = CTX.get();
        String className;
        String methodName;
        String displayName;
        if (ctx != null) {
            className = ctx.getRequiredTestClass().getSimpleName();
            methodName = ctx.getRequiredTestMethod().getName();
            displayName = ctx.getDisplayName();
        } else {
            className = "adhoc";
            methodName = "noTestContext";
            displayName = "ts" + Instant.now().toEpochMilli();
        }

        String sanitizedMethod = sanitize(methodName);

        // ───────── 1) SEMANTIC MOD: label dolu ─────────
        if (label != null && !label.trim().isEmpty()) {
            String sanitizedLabel = sanitize(label);
            // Method adı + label birleşimi — method aynı label'ın
            // farklı testlerde çakışmasını engeller.
            String name = sanitizedMethod + "__" + sanitizedLabel + "." + format.extension();
            return trimToFsLimit(name, format);
        }

        // ───────── 2) FALLBACK MOD: label boş ─────────
        String sanitizedDisplay = sanitize(displayName);

        // Display name semantic kararı:
        // 1) Parametrize: display "{methodName} / {paramValues}" → method
        //    prefix'i çıkar, parametre kısmını koru.
        // 2) @DisplayName uzun açıklama → drop (≤ 40 char değilse).
        // 3) Kısa display (parametre tek değer): tut.
        String displayComponent;
        if (sanitizedDisplay.startsWith(sanitizedMethod)) {
            String trimmed = sanitizedDisplay.substring(sanitizedMethod.length());
            while (!trimmed.isEmpty()
                    && (trimmed.charAt(0) == '_' || trimmed.charAt(0) == '-')) {
                trimmed = trimmed.substring(1);
            }
            displayComponent = trimmed;
        } else if (sanitizedDisplay.length() <= 40
                && !sanitizedDisplay.equalsIgnoreCase(sanitize(className))) {
            displayComponent = sanitizedDisplay;
        } else {
            displayComponent = "";
        }

        if (displayComponent.length() > 80) {
            int hash = displayComponent.hashCode();
            displayComponent = displayComponent.substring(0, 72) + "_"
                    + Integer.toHexString(hash);
        }

        // Parametrize collision koruması — displayComponent boş kalırsa
        // uniqueId hash'ini suffix yap.
        if (displayComponent.isEmpty() && ctx != null) {
            String uniqueIdSuffix = uniqueInvocationHash(ctx);
            if (uniqueIdSuffix != null) {
                displayComponent = uniqueIdSuffix;
            }
        }

        StringBuilder fileName = new StringBuilder()
                .append(sanitize(className))
                .append("__")
                .append(sanitizedMethod);

        if (!displayComponent.isEmpty()) {
            fileName.append("__").append(displayComponent);
        }
        fileName.append('.').append(format.extension());

        return trimToFsLimit(fileName.toString(), format);
    }

    /**
     * Dosya adını filesystem limitlerine (ext4: 255 byte, Windows: 248)
     * göre 200 char'da keser; gerekirse sona hash ekler ki collide
     * olmasın. Tüm {@link #deriveFileName(Format, String)} branch'leri
     * çıkışta bu helper'dan geçer.
     */
    private static String trimToFsLimit(String name, Format format) {
        if (name.length() <= 200) {
            return name;
        }
        String ext = "." + format.extension();
        String head = name.endsWith(ext)
                ? name.substring(0, name.length() - ext.length())
                : name;
        int keep = 200 - ext.length();
        int hash = head.hashCode();
        return head.substring(0, Math.min(keep - 9, head.length())) + "_"
                + Integer.toHexString(hash) + ext;
    }

    /**
     * Parametrize test'in invocation segment'inden kısa bir hash döner.
     * Display name JUnit tarafından @DisplayName'le ezildiğinde parametre
     * iterasyonlarının dosya adı çakışmasını engeller.
     *
     * <p>Format: 8-haneli hex hash + opsiyonel "iter{N}" suffix
     * (uniqueId'de "test-template-invocation:#N" varsa).</p>
     *
     * @return null eğer parametrize test değilse veya unique-id ayrıştırılamazsa
     */
    private static String uniqueInvocationHash(ExtensionContext ctx) {
        String uniqueId = ctx.getUniqueId();
        if (uniqueId == null || uniqueId.isEmpty()) {
            return null;
        }
        // Parametrize değilse hash zaten gereksiz — collision olmaz.
        if (!uniqueId.contains("test-template-invocation")) {
            return null;
        }
        // "#N" suffix'ini çek (insan-okunabilir indeks).
        String iterPart = "";
        int idx = uniqueId.lastIndexOf("#");
        if (idx >= 0) {
            // "#42]" → "42"
            int endIdx = uniqueId.indexOf(']', idx);
            if (endIdx > idx) {
                iterPart = "iter" + uniqueId.substring(idx + 1, endIdx);
            }
        }
        // Argument hash'i ile birleştir (aynı index farklı method'larda
        // collide etmesin diye).
        String argHash = Integer.toHexString(uniqueId.hashCode() & 0x7FFFFFFF);
        if (argHash.length() > 6) {
            argHash = argHash.substring(0, 6);
        }
        return iterPart.isEmpty() ? argHash : iterPart + "_" + argHash;
    }

    /**
     * Dosya-sistemi-güvenli karakter dönüşümü. Türkçe diakritikler,
     * boşluk, slash, kontrol karakterleri vb. underscore'a çevrilir.
     *
     * <p><b>Casing korunur</b> — bilinçli karar: enum adları
     * ({@code KURUM01_RSA2048}, {@code PFX_JCA}, {@code EFATURA}) ve
     * camelCase method adları ({@code xadesFixtureRoundtripIsValid})
     * lowercase'e çevrilirse okunabilirlik kaybolur. macOS varsayılan
     * filesystem'i case-insensitive olduğu için dosya çakışması
     * riski yok; aynı semantic adı üreten iki test üst-üste yazar
     * ve bu zaten istenen davranış.</p>
     */
    private static String sanitize(String raw) {
        if (raw == null || raw.isEmpty()) {
            return "";
        }
        StringBuilder out = new StringBuilder(raw.length());
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9') || c == '-' || c == '.') {
                out.append(c);
            } else if (c == '_') {
                out.append('_');
            } else {
                out.append('_');
            }
        }
        // Birden fazla _ ardı ardına gelirse tek _ yap.
        String collapsed = out.toString().replaceAll("_+", "_");
        // Baş/son _ temizle.
        while (collapsed.startsWith("_")) collapsed = collapsed.substring(1);
        while (collapsed.endsWith("_")) collapsed = collapsed.substring(0, collapsed.length() - 1);
        return collapsed;
    }

    /**
     * İlk export çağrısında {@code README.md} dosyasını yazar.
     * Atomic flag ile race-condition güvenli (worst case 2 thread yazar,
     * sonuç deterministic — aynı içerik).
     */
    private static void ensureReadmeWritten(Path root) {
        if (!README_WRITTEN.compareAndSet(false, true)) {
            return;
        }
        Path readme = root.resolve("README.md");
        if (Files.exists(readme)) {
            return;
        }
        String content = ""
                + "# Signed Artifacts — Üçüncü taraf doğrulama için imza çıktıları\n"
                + "\n"
                + "Bu klasörü `target/` altında olduğu için git **izlemez**\n"
                + "(`.gitignore` → `target/`).\n"
                + "\n"
                + "> **Otomatik temizlik:** Her `mvn test` koşumunun başında bu\n"
                + "> klasör (`target/signed-artifacts/`) tamamen silinir →\n"
                + "> içerikte **sadece son test koşumunun çıktıları** kalır.\n"
                + "> Önceki run'larda koşan ama bu run'da koşmayan test'lerin\n"
                + "> dosyaları hayalet olarak takılmaz. Bu davranış\n"
                + "> `-Dsigned.artifacts.purge=false` ile kapatılabilir.\n"
                + "\n"
                + "## Klasör yapısı\n"
                + "\n"
                + "| Klasör | İçerik | Uzantı | Önerilen doğrulayıcı |\n"
                + "|---|---|---|---|\n"
                + "| `xades/` | XAdES-BES imzalı XML (UBL, e-Arşiv, HR-XML) | `.xml` | EU DSS Demo Webapp, xmlsec1, Akıs İmzala/Doğrula |\n"
                + "| `xades-negative/` | XAdES tampered/wrap-attack — verifier reddetmeli | `.xml` | Aynı araçlar (\"INVALID\" beklenir) |\n"
                + "| `xades-legacy/` | XAdES SHA-1 — modern verifier reject veya WARN dönmeli | `.xml` | EU DSS Demo (\"crypto constraint\" uyarısı) |\n"
                + "| `xades-hsm/` | SoftHSM/PKCS#11 üzerinden imzalanmış XAdES | `.xml` | EU DSS Demo Webapp |\n"
                + "| `cades-attached/` | CMS enveloping (içerik p7s'te) | `.p7s` | `openssl smime -verify -in *.p7s -inform DER`, EU DSS Demo |\n"
                + "| `cades-detached/` | CMS detached (p7s + orijinal ayrı) | `.p7s` | `openssl smime -verify -in *.p7s -content original -inform DER` |\n"
                + "| `cades-negative/` | CAdES tampered örnekler | `.p7s` | Yukarıdaki araçlar (reject beklenir) |\n"
                + "| `pades/` | PAdES-B embedded PDF imza | `.pdf` | **Adobe Acrobat Reader** (\"Signed and all signatures are valid\"), EU DSS Demo |\n"
                + "| `pades-negative/` | PAdES cosign/tampered/encrypted | `.pdf` | Adobe Reader (\"changes since signing\" uyarısı) |\n"
                + "| `wssecurity/` | WS-Security imzalı SOAP envelope | `.xml` | SoapUI WSS validation, Apache WSS4J, xmlsec1 |\n"
                + "\n"
                + "## Dosya isimlendirmesi\n"
                + "\n"
                + "**Tercih edilen — label dolu** (modern E2E testleri):\n"
                + "\n"
                + "```\n"
                + "<testMethodName>__<sanitize(label)>.<ext>\n"
                + "```\n"
                + "\n"
                + "Örnekler:\n"
                + "\n"
                + "- `xades/xadesFixtureRoundtripIsValid__KURUM01_RSA2048_PFX_JCA_EFATURA.xml`\n"
                + "- `cades-attached/cadesRoundtripIsValid__KURUM01_RSA2048_PFX_JCA_attached.p7s`\n"
                + "- `cades-detached/cadesRoundtripIsValid__KURUM01_RSA2048_PFX_JCA_detached.p7s`\n"
                + "- `pades/padesRoundtripIsValid__KURUM01_RSA2048_PFX_JCA_embedded.pdf`\n"
                + "- `pades-negative/byteRangeBitFlipFailsVerification__byte100-bitflip.pdf`\n"
                + "- `xades-negative/wrapAttackRejected__wrap-attack.xml`\n"
                + "\n"
                + "**Fallback — label yok** (eski stil çağrılar):\n"
                + "\n"
                + "```\n"
                + "<TestClassName>__<testMethodName>[__<displayOrIter>].<ext>\n"
                + "```\n"
                + "\n"
                + "Label içeriği genellikle `<PFX>_<backend>_<scenario>` biçiminde\n"
                + "ve **case korunur** (lowercase düşürülmez) → enum adları\n"
                + "(`KURUM01_RSA2048`, `PFX_JCA`, `EFATURA`) okunabilir kalır.\n"
                + "\n"
                + "## System property toggle'ları\n"
                + "\n"
                + "- `-Dsigned.artifacts.export=false` → export'u kapatır (CI disk tasarrufu).\n"
                + "- `-Dsigned.artifacts.dir=/abs/path` → hedef klasörü değiştirir.\n"
                + "  Default `target/signed-artifacts`.\n"
                + "- `-Dsigned.artifacts.purge=false` → JVM başlangıcında root temizliğini\n"
                + "  kapatır. Incremental debug (önceki run'ın çıktısını saklamak istiyorsanız)\n"
                + "  veya `forkCount>1` ile paralel JVM koşumlarında race önlemek için.\n"
                + "\n"
                + "## Hızlı sanity check'ler (üçüncü taraf araçlarla)\n"
                + "\n"
                + "### CAdES attached → openssl\n"
                + "```bash\n"
                + "for f in cades-attached/*.p7s; do\n"
                + "  echo \"=== $f ===\"\n"
                + "  openssl smime -verify -in \"$f\" -inform DER -noverify 2>&1 | head -5\n"
                + "done\n"
                + "```\n"
                + "\n"
                + "### XAdES → xmlsec1\n"
                + "```bash\n"
                + "for f in xades/*.xml; do\n"
                + "  echo \"=== $f ===\"\n"
                + "  xmlsec1 verify --pubkey-cert-pem signer-cert.pem \"$f\" 2>&1\n"
                + "done\n"
                + "```\n"
                + "\n"
                + "### PAdES → Adobe Acrobat Reader\n"
                + "1. `pades/*.pdf` dosyasını Acrobat ile aç.\n"
                + "2. Signature panel → \"Signature is valid\" mesajını gör.\n"
                + "3. Sertifika detayları → KamuSM test kök CA'sı görünmeli.\n"
                + "\n"
                + "### WS-Security → SoapUI\n"
                + "1. `wssecurity/*.xml` dosyalarını manuel olarak SoapUI'a\n"
                + "   request olarak yapıştır.\n"
                + "2. WS-Security panel → \"Signature\" entry → \"Verify\".\n"
                + "3. KamuSM kök sertifikası import edilmiş olmalı.\n"
                + "\n"
                + "---\n"
                + "_Üretildi: " + Instant.now() + " · `io.mersel.dss.signer.api.testsupport.SignedArtifactExporter`_\n";
        try {
            Files.write(readme, content.getBytes(StandardCharsets.UTF_8),
                    StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING,
                    StandardOpenOption.WRITE);
        } catch (IOException e) {
            // README zaten en kötü ihtimal eksik kalır — test akışını kesmeyiz.
            throw new UncheckedIOException("Signed-artifacts README yazılamadı", e);
        }
    }
}
