package io.mersel.dss.signer.api.services.keystore.iaik.bridge;

import io.mersel.dss.signer.api.services.keystore.iaik.IaikPkcs11Module;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Out-of-process PKCS#11 helper'ının giriş noktası. Ana process ile <b>aynı
 * fat-jar</b> içinde paketlenir; tek farkı, vendor DLL'in bit'liğine uygun
 * (örn. 32-bit) bir {@code java} ile başlatılmasıdır:
 *
 * <pre>
 *   &lt;helperJava&gt; -Xmx256m -cp app.jar \
 *       -Dloader.main=io.mersel.dss.signer.api.services.keystore.iaik.bridge.Pkcs11HelperMain \
 *       org.springframework.boot.loader.PropertiesLauncher
 * </pre>
 *
 * <p>Yapılandırmayı ana process ile <b>aynı env var adlarından</b> okur
 * ({@code PKCS11_LIBRARY}, {@code PKCS11_SLOT}, {@code CERTIFICATE_PIN}, ...);
 * köprüye özgü alanlar için bkz. {@link HelperEnv}. Hazır olunca stdout'a
 * {@link HelperEnv#READY_PREFIX} satırını basar — parent bunu bekler.</p>
 *
 * <p>Spring container kurmaz: dar adres alanlı 32-bit JVM'de mümkün olan en
 * küçük ayak izini hedefler. Sadece {@link IaikPkcs11Module} + soket sunucusu.</p>
 */
public final class Pkcs11HelperMain {

    private static final Logger LOGGER = LoggerFactory.getLogger(Pkcs11HelperMain.class);

    private Pkcs11HelperMain() {
    }

    public static void main(String[] args) {
        try {
            run();
        } catch (Throwable t) {
            // Parent stderr'ı yakalar; net bir hata mesajıyla çık.
            System.err.println("PKCS11_HELPER_FATAL: " + t.getMessage());
            LOGGER.error("Helper başlatılamadı", t);
            System.exit(2);
        }
    }

    private static void run() throws Exception {
        String libraryPath = required("PKCS11_LIBRARY");
        String pin = required("CERTIFICATE_PIN");
        Long slot = sanitizeSlot(HelperEnv.read("PKCS11_SLOT", "-1"));
        Long slotIndex = sanitizeSlot(HelperEnv.read("PKCS11_SLOT_LIST_INDEX", "-1"));
        boolean nullInitArgs = Boolean.parseBoolean(HelperEnv.read("PKCS11_NULL_INIT_ARGS", "false"));
        int maxSessions = parseInt(HelperEnv.read("MAX_SESSION_COUNT", "5"), 5);

        String token = HelperEnv.read(HelperEnv.ENV_TOKEN, "");
        String bindHost = HelperEnv.read(HelperEnv.ENV_BIND_HOST, HelperEnv.DEFAULT_BIND_HOST);
        int port = parseInt(HelperEnv.read(HelperEnv.ENV_PORT, "0"), 0);

        LOGGER.info("PKCS#11 helper başlıyor: library={}, JVM bit'liği={}, nullInitArgs={}, maxSessions={}",
            libraryPath, NativeArchitecture.jvmBitness(), nullInitArgs, maxSessions);

        IaikPkcs11Module module = new IaikPkcs11Module(
            libraryPath, slot, slotIndex, pin.toCharArray(), nullInitArgs, maxSessions);
        module.afterPropertiesSet();

        Pkcs11HelperServer server = new Pkcs11HelperServer(module, token, bindHost, port);
        int actualPort = server.start();

        // Remote modda heartbeat helper'ın içinde (DLL'e bitişik) çalışır.
        final HelperHeartbeat heartbeat;
        if (Boolean.parseBoolean(HelperEnv.read("HSM_HEARTBEAT_ENABLED", "false"))) {
            int interval = parseInt(HelperEnv.read("HSM_HEARTBEAT_INTERVAL_SECONDS", "60"), 60);
            heartbeat = new HelperHeartbeat(module,
                HelperEnv.read("CERTIFICATE_ALIAS", null),
                HelperEnv.read("CERTIFICATE_SERIAL_NUMBER", null),
                interval);
            heartbeat.start();
        } else {
            heartbeat = null;
        }
        // Ana process'in OP_HEARTBEAT_STATUS ile durumu sorabilmesi için bağla.
        server.setHeartbeat(heartbeat);

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            LOGGER.info("Helper kapanıyor; modül teardown.");
            if (heartbeat != null) {
                heartbeat.stop();
            }
            server.stop();
            try { module.destroy(); } catch (Exception ignored) { }
        }, "pkcs11-helper-shutdown"));

        // Parent bu satırı bekliyor — stdout'a bas ve flush et.
        System.out.println(HelperEnv.READY_PREFIX + actualPort);
        System.out.flush();

        server.serve();
        LOGGER.info("Helper accept loop sona erdi.");
    }

    private static String required(String name) {
        String v = HelperEnv.read(name, null);
        if (v == null) {
            throw new IllegalStateException("Zorunlu env var eksik: " + name);
        }
        return v;
    }

    private static Long sanitizeSlot(String raw) {
        try {
            long v = Long.parseLong(raw.trim());
            return v >= 0 ? v : null;
        } catch (Exception e) {
            return null;
        }
    }

    private static int parseInt(String raw, int def) {
        try {
            return Integer.parseInt(raw.trim());
        } catch (Exception e) {
            return def;
        }
    }
}
