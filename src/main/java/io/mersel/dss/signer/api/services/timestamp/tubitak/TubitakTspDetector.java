package io.mersel.dss.signer.api.services.timestamp.tubitak;

import java.net.URI;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * KamuSM zaman damgası endpoint'lerini host bazlı tespit eden yardımcı.
 * <p>
 * KamuSM yalnızca iki sabit zaman damgası endpoint'i yayınlar:
 * <ul>
 *   <li>{@code zd.kamusm.gov.tr}  — production</li>
 *   <li>{@code tzd.kamusm.gov.tr} — test</li>
 * </ul>
 * Bu host'lara giden trafik TÜBİTAK ESYA protokolü (custom {@code identity}
 * header, AES-şifrelenmiş kimlik) ile gönderilmek zorundadır; standart
 * RFC 3161 HTTP Basic Auth ile istek atılırsa 403 alınır. Dolayısıyla
 * host pattern'ından {@code IS_TUBITAK_TSP=true} çıkarımı deterministik
 * olarak güvenlidir.
 * <p>
 * Operasyonel motivasyon: kullanıcılar {@code TS_SERVER_HOST}'u doğru
 * verip {@code IS_TUBITAK_TSP} bayrağını set etmeyi unuttuğunda servis
 * sessizce yanlış protokole düşüyordu. Bu sınıf bayrağı host'tan
 * türeterek bu sınıf hatasını fail-safe biçimde kapatır.
 */
public final class TubitakTspDetector {

    private static final Set<String> TUBITAK_TSP_HOSTS = Collections.unmodifiableSet(
            new HashSet<>(Arrays.asList(
                    "zd.kamusm.gov.tr",
                    "tzd.kamusm.gov.tr"
            )));

    private TubitakTspDetector() {
    }

    /**
     * Verilen URL'in host'unun KamuSM TÜBİTAK zaman damgası endpoint'i
     * olup olmadığını döndürür.
     *
     * @param tspServerUrl Zaman damgası sunucu URL'i (boş/null olabilir)
     * @return Host KamuSM zaman damgası ise {@code true}
     */
    public static boolean isTubitakTspHost(String tspServerUrl) {
        if (tspServerUrl == null) {
            return false;
        }
        String trimmed = tspServerUrl.trim();
        if (trimmed.isEmpty()) {
            return false;
        }
        try {
            String host = URI.create(trimmed).getHost();
            if (host == null) {
                return false;
            }
            return TUBITAK_TSP_HOSTS.contains(host.toLowerCase(Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }

    /**
     * Etkin TÜBİTAK modunu döndürür. Explicit bayrak {@code true} ise
     * her zaman {@code true}; aksi halde host'a göre otomatik tespit
     * yapılır.
     *
     * @param explicitFlag  {@code IS_TUBITAK_TSP} property'sinden gelen değer
     * @param tspServerUrl  {@code TS_SERVER_HOST} property'sinden gelen URL
     * @return Etkin {@code isTubitakTsp} değeri
     */
    public static boolean resolveTubitakTspMode(boolean explicitFlag, String tspServerUrl) {
        return explicitFlag || isTubitakTspHost(tspServerUrl);
    }
}
