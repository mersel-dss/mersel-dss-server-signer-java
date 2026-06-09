package io.mersel.dss.signer.api.services.keystore.iaik.bridge;

/**
 * Ana process ile PKCS#11 helper process arasında paylaşılan bootstrap
 * sabitleri (env var adları, READY satırı işareti).
 *
 * <p>İmza/PKCS#11 yapılandırması (kütüphane yolu, slot, PIN, NULL-init,
 * session sayısı) helper'a <b>ana process ile aynı env var adlarıyla</b>
 * geçer ({@code PKCS11_LIBRARY}, {@code CERTIFICATE_PIN}, ...). Yalnızca
 * köprüye özgü alanlar burada tanımlıdır.</p>
 */
public final class HelperEnv {

    private HelperEnv() {
    }

    /** Tek-seferlik paylaşılan auth token (loopback bağlantı doğrulaması). */
    public static final String ENV_TOKEN = "PKCS11_HELPER_TOKEN";

    /** Helper'ın dinleyeceği host. Default {@code 127.0.0.1}. */
    public static final String ENV_BIND_HOST = "PKCS11_HELPER_BIND_HOST";

    /** Helper'ın dinleyeceği port. {@code 0} (default) → ephemeral; gerçek port READY satırında bildirilir. */
    public static final String ENV_PORT = "PKCS11_HELPER_PORT";

    /** Helper hazır olduğunda stdout'a bastığı satırın öneki; parent bunu parse edip portu öğrenir. */
    public static final String READY_PREFIX = "MERSEL_PKCS11_HELPER_READY port=";

    /** Bind host default'u. */
    public static final String DEFAULT_BIND_HOST = "127.0.0.1";

    /** Env veya system property (env önce) okur; ikisi de yoksa default. */
    public static String read(String name, String defaultValue) {
        String v = System.getenv(name);
        if (v == null || v.trim().isEmpty()) {
            v = System.getProperty(name);
        }
        return (v == null || v.trim().isEmpty()) ? defaultValue : v.trim();
    }
}
