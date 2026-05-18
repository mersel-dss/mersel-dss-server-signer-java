package io.mersel.dss.signer.api.services.timestamp.tubitak;

import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Severity;
import io.qameta.allure.SeverityLevel;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Epic("Timestamp Provider")
@Feature("TÜBİTAK TSP Host Detection")
@Severity(SeverityLevel.CRITICAL)
class TubitakTspDetectorTest {

    @ParameterizedTest(name = "KamuSM zaman damgası host'u tespit edilir: {0}")
    @ValueSource(strings = {
            "http://zd.kamusm.gov.tr",
            "https://zd.kamusm.gov.tr",
            "http://zd.kamusm.gov.tr:80",
            "https://zd.kamusm.gov.tr:443/tsa",
            "http://tzd.kamusm.gov.tr",
            "https://tzd.kamusm.gov.tr/",
            "http://ZD.KamuSM.gov.TR",
            "https://TZD.KAMUSM.GOV.TR"
    })
    @DisplayName("KamuSM zaman damgası endpoint'leri TÜBİTAK olarak tespit edilir")
    void detectsTubitakTspHosts(String url) {
        assertTrue(TubitakTspDetector.isTubitakTspHost(url));
    }

    @ParameterizedTest(name = "KamuSM olmayan host TÜBİTAK olarak tespit edilmez: {0}")
    @ValueSource(strings = {
            "http://example.com",
            "http://depo.kamusm.gov.tr/depo/SertifikaDeposu.xml",
            "http://tsa.example.com",
            "http://kamusm.gov.tr",
            "http://malicious-zd.kamusm.gov.tr.attacker.com",
            "http://zd.kamusm.gov.tr.attacker.com",
            "not-a-url",
            "http://"
    })
    @DisplayName("Diğer host'lar TÜBİTAK olarak tespit edilmez")
    void rejectsNonTubitakHosts(String url) {
        assertFalse(TubitakTspDetector.isTubitakTspHost(url));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t"})
    @DisplayName("Boş/null URL TÜBİTAK olarak tespit edilmez")
    void rejectsBlankInputs(String url) {
        assertFalse(TubitakTspDetector.isTubitakTspHost(url));
    }

    @ParameterizedTest(name = "explicit={0}, url={1} -> {2}")
    @CsvSource(emptyValue = "", value = {
            "true,  ,                                true",
            "true,  http://example.com,              true",
            "true,  http://zd.kamusm.gov.tr,         true",
            "false, ,                                false",
            "false, http://example.com,              false",
            "false, http://depo.kamusm.gov.tr,       false",
            "false, http://zd.kamusm.gov.tr,         true",
            "false, http://tzd.kamusm.gov.tr,        true",
            "false, https://ZD.KAMUSM.GOV.TR:443,    true"
    })
    @DisplayName("Explicit bayrak veya host pattern'i ile etkin mod doğru çözülür")
    void resolvesEffectiveMode(boolean explicit, String url, boolean expected) {
        boolean actual = TubitakTspDetector.resolveTubitakTspMode(explicit, url);
        assertTrue(actual == expected,
                () -> "resolveTubitakTspMode(" + explicit + ", \"" + url + "\") = " + actual
                        + ", beklenen " + expected);
    }
}
