package io.mersel.dss.signer.api.services.keystore.iaik.bridge;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Farklı bit'likteki PKCS#11 helper JVM'ini başlatan, gözeten (crash → restart)
 * ve kapatan supervisor. Helper, ana process ile aynı fat-jar'ı çalıştırır ama
 * giriş noktası {@link Pkcs11HelperMain}'dir ve DLL'in bit'liğine uygun bir
 * {@code java} ile koşar.
 *
 * <h2>Yaşam döngüsü</h2>
 * <ol>
 *   <li>{@link #start()} → process'i fork et, stdout'tan {@link HelperEnv#READY_PREFIX}
 *       satırını bekle, dinlenen portu öğren.</li>
 *   <li>Çalışırken stdout/stderr satırları logger'a forward edilir.</li>
 *   <li>Process beklenmedik şekilde ölürse exponential backoff ile restart;
 *       yeni port {@link #getPort()} üzerinden okunur (client her istekte
 *       güncel portu sorar).</li>
 *   <li>{@link #close()} → temiz kapatma; restart yapılmaz.</li>
 * </ol>
 */
public final class Pkcs11HelperProcess {

    private static final Logger LOGGER = LoggerFactory.getLogger(Pkcs11HelperProcess.class);

    private static final String HELPER_MAIN =
        "io.mersel.dss.signer.api.services.keystore.iaik.bridge.Pkcs11HelperMain";
    private static final String BOOT_LAUNCHER =
        "org.springframework.boot.loader.PropertiesLauncher";

    private final String helperJava;
    private final List<String> jvmOpts;
    private final String classpath;
    private final String launcherMode; // auto | propertieslauncher | direct
    private final String bindHost;
    private final Map<String, String> envOverrides;
    private final int readyTimeoutMs;
    private final String token;

    private final AtomicBoolean shuttingDown = new AtomicBoolean(false);
    private volatile Process process;
    private volatile int port = -1;
    private volatile CountDownLatch readyLatch;
    private long restartBackoffMs = 1000L;

    public Pkcs11HelperProcess(String helperJava,
                               List<String> jvmOpts,
                               String classpath,
                               String launcherMode,
                               String bindHost,
                               int readyTimeoutMs,
                               Map<String, String> envOverrides) {
        this.helperJava = helperJava;
        this.jvmOpts = jvmOpts;
        this.classpath = classpath;
        this.launcherMode = launcherMode == null ? "auto" : launcherMode.toLowerCase();
        this.bindHost = bindHost;
        this.readyTimeoutMs = readyTimeoutMs;
        this.envOverrides = envOverrides;
        this.token = generateToken();
    }

    public String getToken() {
        return token;
    }

    public String getBindHost() {
        return bindHost;
    }

    public int getPort() {
        return port;
    }

    public boolean isAlive() {
        Process p = process;
        return p != null && p.isAlive();
    }

    /** Helper'ı başlatır ve READY satırı gelene (veya timeout/ölüm) dek bloklar. */
    public synchronized void start() throws IOException {
        spawnAndAwaitReady();
    }

    private void spawnAndAwaitReady() throws IOException {
        readyLatch = new CountDownLatch(1);
        port = -1;

        List<String> command = buildCommand();
        LOGGER.info("PKCS#11 helper başlatılıyor: {}", String.join(" ", command));

        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);
        Map<String, String> env = pb.environment();
        env.put(HelperEnv.ENV_TOKEN, token);
        env.put(HelperEnv.ENV_BIND_HOST, bindHost);
        env.put(HelperEnv.ENV_PORT, "0"); // ephemeral; gerçek port READY satırında
        if (envOverrides != null) {
            env.putAll(envOverrides);
        }

        process = pb.start();
        Thread reader = new Thread(this::pumpOutput, "pkcs11-helper-stdout");
        reader.setDaemon(true);
        reader.start();

        boolean ready;
        try {
            ready = readyLatch.await(readyTimeoutMs, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Helper başlatma beklemesi kesildi", e);
        }
        if (!ready || port < 0) {
            int exit = process.isAlive() ? -1 : safeExitValue();
            destroyProcess();
            throw new IOException("PKCS#11 helper " + readyTimeoutMs
                + "ms içinde READY vermedi (process "
                + (exit == -1 ? "hâlâ ayakta ama port bildirmedi" : "exit code=" + exit) + "). "
                + "Helper JVM yolu / DLL bit'liği / classpath ayarlarını kontrol edin.");
        }
        LOGGER.info("PKCS#11 helper hazır: {}:{}", bindHost, port);
        restartBackoffMs = 1000L; // başarılı başlatma → backoff sıfırla
    }

    private void pumpOutput() {
        Process p = process;
        try (BufferedReader br = new BufferedReader(
                new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = br.readLine()) != null) {
                if (line.startsWith(HelperEnv.READY_PREFIX)) {
                    try {
                        port = Integer.parseInt(line.substring(HelperEnv.READY_PREFIX.length()).trim());
                    } catch (NumberFormatException nfe) {
                        LOGGER.warn("READY satırı parse edilemedi: {}", line);
                    }
                    CountDownLatch latch = readyLatch;
                    if (latch != null) {
                        latch.countDown();
                    }
                } else {
                    LOGGER.info("[helper] {}", line);
                }
            }
        } catch (IOException e) {
            LOGGER.debug("Helper stdout okuma sonlandı: {}", e.getMessage());
        }
        // Stream bitti → process öldü. Restart gerekir mi?
        onProcessExit();
    }

    private void onProcessExit() {
        if (shuttingDown.get()) {
            return;
        }
        int exit = safeExitValue();
        LOGGER.warn("PKCS#11 helper beklenmedik şekilde sonlandı (exit={}); {}ms sonra restart denenecek.",
            exit, restartBackoffMs);
        // READY bekleyen başlatma varsa serbest bırak (hata olarak görülür).
        CountDownLatch latch = readyLatch;
        if (latch != null) {
            latch.countDown();
        }
        try {
            Thread.sleep(restartBackoffMs);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return;
        }
        restartBackoffMs = Math.min(restartBackoffMs * 2, 60_000L);
        if (shuttingDown.get()) {
            return;
        }
        try {
            synchronized (this) {
                if (!shuttingDown.get()) {
                    spawnAndAwaitReady();
                }
            }
        } catch (IOException e) {
            LOGGER.error("PKCS#11 helper restart başarısız: {}", e.getMessage());
        }
    }

    private List<String> buildCommand() {
        List<String> cmd = new ArrayList<>();
        cmd.add(helperJava);
        if (jvmOpts != null) {
            cmd.addAll(jvmOpts);
        }
        cmd.add("-cp");
        cmd.add(classpath);
        if (usePropertiesLauncher()) {
            cmd.add("-Dloader.main=" + HELPER_MAIN);
            cmd.add(BOOT_LAUNCHER);
        } else {
            cmd.add(HELPER_MAIN);
        }
        return cmd;
    }

    private boolean usePropertiesLauncher() {
        if ("propertieslauncher".equals(launcherMode)) {
            return true;
        }
        if ("direct".equals(launcherMode)) {
            return false;
        }
        // auto: tek bir .jar classpath'i → Spring Boot fat jar varsay.
        String cp = classpath == null ? "" : classpath.trim();
        return !cp.contains(java.io.File.pathSeparator) && cp.toLowerCase().endsWith(".jar");
    }

    public void close() {
        shuttingDown.set(true);
        destroyProcess();
    }

    private void destroyProcess() {
        Process p = process;
        if (p == null) {
            return;
        }
        p.destroy();
        try {
            if (!p.waitFor(5, TimeUnit.SECONDS)) {
                p.destroyForcibly();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            p.destroyForcibly();
        }
    }

    private int safeExitValue() {
        try {
            return process.exitValue();
        } catch (IllegalThreadStateException e) {
            return -1;
        }
    }

    private static String generateToken() {
        byte[] b = new byte[32];
        new SecureRandom().nextBytes(b);
        StringBuilder sb = new StringBuilder();
        for (byte x : b) {
            sb.append(String.format("%02x", x & 0xFF));
        }
        return sb.toString();
    }
}
