package io.mersel.dss.signer.api.testsupport;

import io.mersel.dss.signer.api.e2e.verifier.E2eSigningMaterialFactory;
import io.mersel.dss.signer.api.e2e.verifier.PfxTestKey;
import io.mersel.dss.signer.api.models.SigningMaterial;
import io.mersel.dss.signer.api.services.keystore.iaik.IaikPkcs11Module;
import org.apache.commons.io.IOUtils;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * SoftHSM2 entegrasyon testleri için ortak yardımcı.
 *
 * <p>Tipik kullanım:</p>
 * <pre>
 *   SoftHsm2TestSupport hsm = SoftHsm2TestSupport.requireOrSkip(tempDir);
 *   hsm.initToken("my-token", "12345678", "123456");
 *   for (PfxTestKey key : PfxTestKey.positiveValues()) {
 *       hsm.importPfx(key, "label-" + key.name());
 *   }
 *   IaikPkcs11Module module = hsm.openModule("123456");
 *   // ... test
 *   hsm.close();   // module.destroy() çağrılır
 * </pre>
 *
 * <p>Native araçlar (softhsm2-util / pkcs11-tool / libsofthsm2) bulunamazsa
 * {@link #requireOrSkip(Path)} testi sessizce ATLAR — yani testin başında bu
 * metodu çağırmak yeterli; ek "skip if missing" mantığı yazmaya gerek yok.</p>
 *
 * <p>Thread-safe değildir; bir test yaşam döngüsünde tek instance kullanılır.</p>
 */
public final class SoftHsm2TestSupport implements AutoCloseable {

    private static final Pattern SLOT_PATTERN =
            Pattern.compile("slot\\s+(\\d+)", Pattern.CASE_INSENSITIVE);

    private final Path tempDir;
    private final Path softhsm2Util;
    private final Path pkcs11Tool;
    private final Path modulePath;
    private final Path configFile;
    private final Path tokenDir;
    private final Map<String, String> env;
    private final Map<PfxTestKey, String> importedLabels = new LinkedHashMap<>();

    private Long slot;
    private String userPin;
    private IaikPkcs11Module module;
    private int nextKeyIdSeq = 1;

    private SoftHsm2TestSupport(Path tempDir,
                                Path softhsm2Util,
                                Path pkcs11Tool,
                                Path modulePath) throws Exception {
        this.softhsm2Util = softhsm2Util;
        this.pkcs11Tool = pkcs11Tool;
        this.modulePath = modulePath;

        // SOFTHSM2_CONF: JVM seviyesinde (Surefire <environmentVariables>'dan)
        // set edildiyse onu kullan; subprocess + JVM JNI aynı config'i okumalı,
        // aksi halde token init subprocess'te yaratılır ama JVM default sistem
        // config'ine bakar ve token'ı bulamaz. Fallback: yerel tempDir
        // (geliştirici manuel mvn test koşumunda kalite-of-life).
        String envConf = System.getenv("SOFTHSM2_CONF");
        if (envConf != null && !envConf.trim().isEmpty()) {
            this.configFile = new File(envConf).toPath().toAbsolutePath();
            this.tempDir = configFile.getParent();
        } else {
            this.tempDir = tempDir;
            this.configFile = tempDir.resolve("softhsm2.conf").toAbsolutePath();
        }
        this.tokenDir = this.tempDir.resolve("tokens").toAbsolutePath();

        // Token dizinini her test class koşumunda taze tut — eski token state
        // sızıntısı (örn. önceki class'tan kalan slot'lar) izolasyonu bozar.
        Files.createDirectories(this.tempDir);
        deleteRecursivelyIfExists(this.tokenDir);
        Files.createDirectories(this.tokenDir);

        Files.write(this.configFile, (
                "directories.tokendir = " + tokenDir + "\n"
                        + "objectstore.backend = file\n"
                        + "log.level = ERROR\n").getBytes(StandardCharsets.UTF_8));

        this.env = new HashMap<>();
        this.env.put("SOFTHSM2_CONF", configFile.toString());
    }

    /**
     * Native araçların hepsi mevcutsa support instance döner; aksi takdirde
     * {@code assumeTrue(false)} ile testi sessizce ATLAR.
     *
     * @param tempDir JUnit'in test başına verdiği geçici dizin. Sadece
     *                {@code SOFTHSM2_CONF} env'i SET DEĞİLSE kullanılır
     *                (geliştirici manual mvn koşumu için fallback). CI ve
     *                Surefire akışında env her zaman set olduğundan bu
     *                parametre o zaman görmezden gelinir.
     */
    public static SoftHsm2TestSupport requireOrSkip(Path tempDir) throws Exception {
        Path softhsm2Util = requireExecutable("SOFTHSM2_UTIL", "softhsm2-util");
        Path pkcs11Tool = requireExecutable("PKCS11_TOOL", "pkcs11-tool");
        Path modulePath = requireSoftHsmModule();
        return new SoftHsm2TestSupport(tempDir, softhsm2Util, pkcs11Tool, modulePath);
    }

    private static void deleteRecursivelyIfExists(Path root) throws Exception {
        if (!Files.exists(root)) {
            return;
        }
        Files.walk(root)
                .sorted(java.util.Comparator.reverseOrder())
                .forEach(p -> {
                    try {
                        Files.deleteIfExists(p);
                    } catch (Exception ignore) {
                        // best-effort; aşağıda createDirectories yine deneyecek
                    }
                });
    }

    /**
     * Yeni bir SoftHSM2 token başlatır. Bir support instance için yalnızca bir
     * kez çağrılmalıdır.
     */
    public void initToken(String tokenLabel, String soPin, String userPin) throws Exception {
        if (slot != null) {
            throw new IllegalStateException(
                    "initToken() ikinci kez çağrıldı; SoftHsm2TestSupport bir token destekler");
        }
        this.userPin = userPin;
        String output = run(softhsm2Util.toString(),
                "--init-token",
                "--free",
                "--label", tokenLabel,
                "--so-pin", soPin,
                "--pin", userPin);
        this.slot = parseInitializedSlot(output);
        if (slot == null) {
            throw new AssertionError(
                    "Yeni SoftHSM slot numarası softhsm2-util çıktısından parse edilemedi:\n"
                            + output);
        }
    }

    /**
     * Verilen PFX'in private key + leaf sertifikasını HSM'e import eder.
     * Her import için otomatik artan {@code CKA_ID} (01, 02, ...) atanır;
     * {@code CKA_LABEL} parametre ile verilir.
     *
     * @return token'da kayıt için kullanılan label (geri verilir ki test
     *         {@code findSigner(label)} ile resolve edebilsin)
     */
    public String importPfx(PfxTestKey key, String label) throws Exception {
        if (slot == null) {
            throw new IllegalStateException("Önce initToken() çağrılmalı");
        }
        if (importedLabels.containsKey(key)) {
            throw new IllegalStateException(
                    "Aynı PfxTestKey iki kez import edildi: " + key);
        }

        SigningMaterial pfxMaterial = E2eSigningMaterialFactory.load(key);
        PrivateKey privateKey = pfxMaterial.getPrivateKey();
        X509Certificate certificate = pfxMaterial.getSigningCertificate();

        Path privateKeyDer = tempDir.resolve("import-" + key.name() + ".pk8");
        Path certificateDer = tempDir.resolve("import-" + key.name() + ".der");
        Files.write(privateKeyDer, privateKey.getEncoded());
        Files.write(certificateDer, certificate.getEncoded());

        String hexId = String.format(Locale.ROOT, "%02x", nextKeyIdSeq++);

        run(pkcs11Tool.toString(),
                "--module", modulePath.toString(),
                "--slot", Long.toString(slot),
                "--login",
                "--pin", userPin,
                "--write-object", privateKeyDer.toString(),
                "--type", "privkey",
                "--id", hexId,
                "--label", label,
                "--usage-sign");

        run(pkcs11Tool.toString(),
                "--module", modulePath.toString(),
                "--slot", Long.toString(slot),
                "--login",
                "--pin", userPin,
                "--write-object", certificateDer.toString(),
                "--type", "cert",
                "--id", hexId,
                "--label", label);

        importedLabels.put(key, label);
        return label;
    }

    /**
     * {@link IaikPkcs11Module}'ü açar ve initialize eder. Cache'lenir; ikinci
     * çağrılarda aynı module döner.
     */
    public IaikPkcs11Module openModule(String userPin) throws Exception {
        if (module != null) {
            return module;
        }
        if (slot == null) {
            throw new IllegalStateException("Önce initToken() + importPfx() çağrılmalı");
        }
        IaikPkcs11Module created = new IaikPkcs11Module(
                modulePath.toString(), slot, 0L, userPin.toCharArray());
        created.afterPropertiesSet();
        this.module = created;
        return module;
    }

    public String labelFor(PfxTestKey key) {
        String label = importedLabels.get(key);
        if (label == null) {
            throw new IllegalStateException("Bu key import edilmedi: " + key);
        }
        return label;
    }

    public Long getSlot() {
        return slot;
    }

    public Path getModulePath() {
        return modulePath;
    }

    @Override
    public void close() {
        if (module != null) {
            try {
                module.destroy();
            } catch (Exception ignore) {
                // Best-effort cleanup; testin yıkılışını sabote etmesin
            }
            module = null;
        }
    }

    // ---------------------------------------------------------------- helpers

    private String run(String... command) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.environment().putAll(env);
        pb.redirectErrorStream(true);
        Process process = pb.start();
        String output = IOUtils.toString(process.getInputStream(), StandardCharsets.UTF_8);
        int exit = process.waitFor();
        if (exit != 0) {
            throw new AssertionError("SoftHSM komutu başarısız (exit=" + exit + "): "
                    + String.join(" ", command) + "\n" + output);
        }
        return output;
    }

    private static Long parseInitializedSlot(String output) {
        if (output == null) {
            return null;
        }
        Matcher m = SLOT_PATTERN.matcher(output);
        Long last = null;
        while (m.find()) {
            last = Long.valueOf(m.group(1));
        }
        return last;
    }

    private static Path requireExecutable(String envName, String executableName) {
        String override = System.getenv(envName);
        if (override != null && !override.trim().isEmpty()) {
            Path path = new File(override).toPath();
            assumeTrue(Files.isRegularFile(path) && Files.isExecutable(path),
                    envName + " executable bulunamadı veya çalıştırılabilir değil: " + override);
            return path;
        }

        String pathEnv = System.getenv("PATH");
        if (pathEnv != null) {
            for (String entry : pathEnv.split(File.pathSeparator)) {
                Path candidate = new File(entry, executableName).toPath();
                if (Files.isRegularFile(candidate) && Files.isExecutable(candidate)) {
                    return candidate;
                }
            }
        }
        assumeTrue(false, executableName + " bulunamadı; SoftHSM2 entegrasyon testi atlandı");
        return null;
    }

    private static Path requireSoftHsmModule() {
        String override = System.getenv("SOFTHSM2_MODULE");
        if (override != null && !override.trim().isEmpty()) {
            Path path = new File(override).toPath();
            assumeTrue(Files.isRegularFile(path),
                    "SOFTHSM2_MODULE bulunamadı: " + override);
            return path;
        }

        String[] candidates = {
                "/usr/lib/softhsm/libsofthsm2.so",
                "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
                "/usr/local/lib/softhsm/libsofthsm2.so",
                "/usr/local/lib/softhsm/libsofthsm2.dylib",
                "/opt/homebrew/lib/softhsm/libsofthsm2.so",
                "/opt/homebrew/lib/softhsm/libsofthsm2.dylib"
        };
        for (String candidate : candidates) {
            Path path = new File(candidate).toPath();
            if (Files.isRegularFile(path)) {
                return path;
            }
        }
        assumeTrue(false, "libsofthsm2 bulunamadı; SOFTHSM2_MODULE ile belirtilebilir");
        return null;
    }
}
