// @formatter:off

package eu.europa.esig.dss.xades.signature;

import java.time.DateTimeException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.Objects;

// ########################OVERRIDE_DSS#########################
// #####  DİKKAT: OVERRIDE DEĞİLDİR!                        ####
// #####  XAdES <SigningTime> elementinin hangi timezone    ####
// #####  ile yazılacağını taşıyan statik tutucu sınıf.     ####
// #####  DSS upstream her zaman UTC ('Z') yazar; bu sınıf  ####
// #####  TÜBİTAK MA3 çıktısı ile uyumlu '+03:00' default'u ####
// #####  sağlar. Operatör env üzerinden değiştirebilir.    ####
// #############################################################

/**
 * XAdES {@code <SigningTime>} elemanının XML serileştirmesinde kullanılacak
 * zaman dilimini tutan singleton.
 *
 * <p>Default değer {@code +03:00} (Türkiye saati). Bu seçim, TÜBİTAK MA3
 * kütüphanesinin ürettiği XAdES çıktılarıyla birebir uyumlu olmasını sağlar
 * (bkz. issue #7). Default'u değiştirmek için {@code XADES_SIGNING_TIME_ZONE}
 * ortam değişkeni kullanılır — örn. UTC için {@code Z}, sabit ofset için
 * {@code +03:00} veya named zone için {@code Europe/Istanbul}.</p>
 *
 * <p>DSS {@link XAdESSignatureBuilder#incorporateSigningTime()} override'ı
 * çalışma anında bu sınıftan {@link #formatSigningTime(Date)} okuyarak
 * çıktıyı oluşturur. Bu, builder'ın Spring container'a bağlı olmamasını ve
 * DSS upstream paket yapısının (eu.europa.esig.dss.xades.signature) korunmasını
 * sağlar. Spring tarafı uygulamanın açılışında bir kez {@link #setZone(ZoneId)}
 * çağırarak konfigürasyonu yansıtır.</p>
 *
 * <p>Thread-safety: tek bir {@code volatile} alan üzerinden okuma/yazma yapılır.
 * Çağrı sıklığı düşük (her imza başına bir defa) olduğundan kilit gerekmez.</p>
 */
public final class XAdESSigningTimeZoneHolder {

    /**
     * Default değer: {@code +03:00}. TÜBİTAK uyumluluğu için (issue #7).
     * Operatör isterse Spring config üzerinden değiştirir.
     */
    public static final ZoneId DEFAULT_ZONE = ZoneOffset.of("+03:00");

    /**
     * XML çıktı formatı. {@code XXX} ofseti {@code +03:00} olarak, UTC'yi ise
     * {@code Z} olarak basar — her ikisi de {@code xsd:dateTime} grameri
     * altında geçerlidir.
     */
    private static final DateTimeFormatter FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssXXX");

    private static volatile ZoneId zone = DEFAULT_ZONE;

    private XAdESSigningTimeZoneHolder() {
        // utility class
    }

    /**
     * Aktif imza zaman dilimini döner. Default {@link #DEFAULT_ZONE}.
     */
    public static ZoneId getZone() {
        return zone;
    }

    /**
     * İmza zaman dilimini günceller. Genellikle uygulama açılışında bir kez
     * {@code XADES_SIGNING_TIME_ZONE} ortam değişkeninden çağrılır.
     *
     * @param newZone yeni zaman dilimi; null verilirse {@link #DEFAULT_ZONE}'a döner
     */
    public static void setZone(ZoneId newZone) {
        zone = (newZone != null) ? newZone : DEFAULT_ZONE;
    }

    /**
     * String değerden zaman dilimini parse eder. Desteklenen formatlar:
     * <ul>
     *   <li>{@code +03:00}, {@code -05:30} — sabit ofset</li>
     *   <li>{@code Z}, {@code UTC}, {@code GMT} — UTC</li>
     *   <li>{@code Europe/Istanbul} — IANA zone (DST destekli)</li>
     * </ul>
     *
     * <p>{@code null}/boş input default'a düşer. Geçersiz string için
     * {@link DateTimeException} fırlatılır; bu hata, fail-fast davranışını
     * tercih eden Spring bootstrap akışında bilinçli olarak yakalanmaz.</p>
     *
     * @param raw kullanıcı/env tarafından verilen zaman dilimi metni
     * @return parse edilmiş {@link ZoneId}
     */
    public static ZoneId parseZone(String raw) {
        if (raw == null) {
            return DEFAULT_ZONE;
        }
        String trimmed = raw.trim();
        if (trimmed.isEmpty()) {
            return DEFAULT_ZONE;
        }
        return ZoneId.of(trimmed);
    }

    /**
     * Verilen tarihi aktif zaman dilimi ile XML {@code dateTime} formatına
     * dönüştürür. Örnek çıktılar:
     * <ul>
     *   <li>{@code +03:00} zone: {@code 2025-11-19T14:12:39+03:00}</li>
     *   <li>UTC zone: {@code 2025-11-19T11:12:39Z}</li>
     * </ul>
     *
     * @param signingDate imza anı; null değilse {@link Date#toInstant()} kullanılır
     * @return XAdES {@code <SigningTime>} text node'una konulacak metin
     */
    public static String formatSigningTime(Date signingDate) {
        Objects.requireNonNull(signingDate, "signingDate null olamaz");
        Instant instant = signingDate.toInstant();
        ZonedDateTime zdt = instant.atZone(zone);
        return FORMATTER.format(zdt);
    }
}
