package eu.europa.esig.dss.xades.signature;

import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Severity;
import io.qameta.allure.SeverityLevel;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.DateTimeException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * {@link XAdESSigningTimeZoneHolder} davranışını doğrular. Bu sınıf XAdES
 * imza zaman dilimini global statik bir alanda taşıdığı için, her test
 * çalışmadan önce ve sonra default değere geri çekilir; aksi halde test
 * sıralaması birbirini etkileyebilir.
 */
@Epic("XAdES Conformance")
@Feature("SigningTime Timezone Configuration")
@Severity(SeverityLevel.CRITICAL)
class XAdESSigningTimeZoneHolderTest {

    /**
     * Sabit imza anı. Türkiye 2016'dan beri kalıcı {@code +03:00}
     * (DST yok) olduğu için {@code Europe/Istanbul} ve {@code +03:00}
     * çıktıları aynıdır. 1970 epoch'u seçilseydi tarihsel DST
     * ({@code +02:00} kış) çıkardı; bu test fixture'ını DST-bağımsız
     * tutmak için bilinçli olarak güncel tarih kullanıyoruz.
     *
     * <p>UTC: {@code 2025-11-19T12:22:52Z}. {@code +03:00}: {@code 15:22:52}.</p>
     */
    private static final Date FIXED_INSTANT =
            Date.from(Instant.parse("2025-11-19T12:22:52Z"));

    @BeforeEach
    @AfterEach
    void resetToDefault() {
        XAdESSigningTimeZoneHolder.setZone(XAdESSigningTimeZoneHolder.DEFAULT_ZONE);
    }

    @Test
    @DisplayName("Default zone TÜBİTAK uyumlu +03:00 (issue #7)")
    void defaultZoneIsPlusThree() {
        assertEquals(ZoneOffset.of("+03:00"), XAdESSigningTimeZoneHolder.DEFAULT_ZONE);
        assertEquals(ZoneOffset.of("+03:00"), XAdESSigningTimeZoneHolder.getZone());
    }

    @Test
    @DisplayName("Default ile formatlanan tarih +03:00 son ekiyle yazılır")
    void formatsDefaultWithPlusThreeOffset() {
        String formatted = XAdESSigningTimeZoneHolder.formatSigningTime(FIXED_INSTANT);
        assertEquals("2025-11-19T15:22:52+03:00", formatted);
    }

    @Test
    @DisplayName("UTC seçilirse Z son eki üretilir (ETSI saf yorum)")
    void formatsUtcAsZSuffix() {
        XAdESSigningTimeZoneHolder.setZone(ZoneOffset.UTC);
        String formatted = XAdESSigningTimeZoneHolder.formatSigningTime(FIXED_INSTANT);
        assertEquals("2025-11-19T12:22:52Z", formatted);
    }

    @ParameterizedTest(name = "[{index}] zone='{0}' beklenen='{1}'")
    @CsvSource({
            "+03:00,          2025-11-19T15:22:52+03:00",
            "Z,               2025-11-19T12:22:52Z",
            "UTC,             2025-11-19T12:22:52Z",
            "+05:30,          2025-11-19T17:52:52+05:30",
            "-05:00,          2025-11-19T07:22:52-05:00",
            "Europe/Istanbul, 2025-11-19T15:22:52+03:00"
    })
    @DisplayName("parseZone() + format() farklı offset ve named zone'ları doğru basar")
    void parsesAndFormatsAcrossZones(String raw, String expected) {
        ZoneId parsed = XAdESSigningTimeZoneHolder.parseZone(raw);
        XAdESSigningTimeZoneHolder.setZone(parsed);
        assertEquals(expected, XAdESSigningTimeZoneHolder.formatSigningTime(FIXED_INSTANT));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t"})
    @DisplayName("Boş/null parseZone() default'a düşer (silent fallback)")
    void parseZoneBlankFallsBackToDefault(String raw) {
        ZoneId parsed = XAdESSigningTimeZoneHolder.parseZone(raw);
        assertSame(XAdESSigningTimeZoneHolder.DEFAULT_ZONE, parsed);
    }

    @Test
    @DisplayName("setZone(null) verilirse default'a döner")
    void setZoneNullResetsToDefault() {
        XAdESSigningTimeZoneHolder.setZone(ZoneOffset.UTC);
        XAdESSigningTimeZoneHolder.setZone(null);
        assertEquals(XAdESSigningTimeZoneHolder.DEFAULT_ZONE,
                XAdESSigningTimeZoneHolder.getZone());
    }

    @Test
    @DisplayName("Geçersiz zone string parse'i fail-fast (bilinmeyen named zone)")
    void invalidZoneStringFailsFast() {
        // Not: {@code "+3"} ya da {@code "+03"} aslında geçerli — Java
        // ZoneOffset.of() bunları kabul eder ({@code +03:00}'a normalize edilir).
        // Bu yüzden burada açıkça anlamsız bir IANA bölge ismi kullanıyoruz.
        assertThrows(DateTimeException.class,
                () -> XAdESSigningTimeZoneHolder.parseZone("Bogus/Mars"));
        assertThrows(DateTimeException.class,
                () -> XAdESSigningTimeZoneHolder.parseZone("not-a-zone"));
    }

    @Test
    @DisplayName("formatSigningTime(null) NPE atar")
    void formatSigningTimeNullThrows() {
        assertThrows(NullPointerException.class,
                () -> XAdESSigningTimeZoneHolder.formatSigningTime(null));
    }

    @Test
    @DisplayName("Aynı Date farklı zone'larda farklı (ama tutarlı) çıktı üretir")
    void sameInstantDifferentZonesYieldDifferentText() {
        XAdESSigningTimeZoneHolder.setZone(ZoneOffset.UTC);
        String utc = XAdESSigningTimeZoneHolder.formatSigningTime(FIXED_INSTANT);

        XAdESSigningTimeZoneHolder.setZone(ZoneOffset.of("+03:00"));
        String trkey = XAdESSigningTimeZoneHolder.formatSigningTime(FIXED_INSTANT);

        assertNotNull(utc);
        assertNotNull(trkey);
        // Z son eki ile +03:00 son eki birbirini aynalamaz; farklı string'ler
        // beklenir, ama aynı Instant'ı temsil ettiklerini Java üzerinden teyit edebiliriz.
        assertEquals(Instant.parse("2025-11-19T12:22:52Z"),
                Instant.parse(utc));
        assertEquals(Instant.parse("2025-11-19T12:22:52Z"),
                java.time.OffsetDateTime.parse(trkey).toInstant());
    }
}
