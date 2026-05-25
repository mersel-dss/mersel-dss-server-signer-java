package io.mersel.dss.signer.api.config;

import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Severity;
import io.qameta.allure.SeverityLevel;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link LogHeadersFilter} davranış test'leri.
 *
 * <p>Filtre HTTP request başına gelen {@code x-log-*} header'larını MDC'ye
 * taşır ve request bitince temizler. Test'ler MDC'nin doğru anlık görüntüsünü
 * downstream {@code FilterChain} adımında yakalayarak doğrular — bu, asıl
 * log emission anına eşdeğer noktadır.</p>
 */
@Epic("Observability")
@Feature("X-Log Header Propagation")
@Severity(SeverityLevel.NORMAL)
class LogHeadersFilterTest {

    private LogHeadersFilter filter;

    @BeforeEach
    void setUp() {
        filter = new LogHeadersFilter();
        MDC.clear();
    }

    @AfterEach
    void tearDown() {
        MDC.clear();
    }

    @Test
    void copiesXLogHeadersIntoMdcDuringRequest() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-Log-Id", "abc");
        request.addHeader("x-log-kimlik", "kajsdh");
        request.addHeader("Authorization", "Bearer should-not-leak");

        Map<String, String> snapshot = invokeAndCaptureMdc(request);

        assertEquals("abc", snapshot.get("xlog.x-log-id"));
        assertEquals("kajsdh", snapshot.get("xlog.x-log-kimlik"));
        assertFalse(snapshot.containsKey("xlog.authorization"),
            "İlgisiz header'lar MDC'ye sızmamalı");
    }

    @Test
    void removesAddedKeysAfterRequest() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-Log-Id", "trace-1");

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        assertNull(MDC.get("xlog.x-log-id"),
            "Request sonrası MDC sızıntısı olmamalı");
    }

    @Test
    void preservesPreExistingMdcEntries() throws ServletException, IOException {
        MDC.put("tenant.id", "preserved");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-Log-Id", "abc");

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        assertEquals("preserved", MDC.get("tenant.id"),
            "Filtre sadece kendi koyduğu anahtarları temizlemeli");
    }

    @Test
    void cleansUpEvenWhenDownstreamThrows() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-Log-Id", "abc");
        FilterChain throwing = (req, res) -> {
            throw new ServletException("boom");
        };

        ServletException thrown = assertThrows(ServletException.class,
            () -> filter.doFilter(request, new MockHttpServletResponse(), throwing));

        assertEquals("boom", thrown.getMessage());
        assertNull(MDC.get("xlog.x-log-id"),
            "Exception path'inde de MDC temizlenmeli");
    }

    @Test
    void sanitizesCrlfToPreventLogInjection() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-Log-Note", "good\r\nFAKE 12:00:00 ERROR injected");

        Map<String, String> snapshot = invokeAndCaptureMdc(request);

        String value = snapshot.get("xlog.x-log-note");
        assertNotNull(value);
        assertFalse(value.contains("\n"), "Newline temizlenmeli");
        assertFalse(value.contains("\r"), "CR temizlenmeli");
    }

    @Test
    void trimsValuesExceedingMaxLength() throws ServletException, IOException {
        StringBuilder big = new StringBuilder(LogHeadersFilter.MAX_VALUE_LENGTH + 100);
        for (int i = 0; i < LogHeadersFilter.MAX_VALUE_LENGTH + 100; i++) {
            big.append('a');
        }
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-Log-Blob", big.toString());

        Map<String, String> snapshot = invokeAndCaptureMdc(request);

        String value = snapshot.get("xlog.x-log-blob");
        assertNotNull(value);
        assertEquals(LogHeadersFilter.MAX_VALUE_LENGTH, value.length(),
            "Değer uzunluk üst sınırına kırpılmalı");
    }

    @Test
    void capsNumberOfHeadersPerRequest() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        for (int i = 0; i < LogHeadersFilter.MAX_HEADERS + 5; i++) {
            request.addHeader("X-Log-K" + i, "v" + i);
        }

        Map<String, String> snapshot = invokeAndCaptureMdc(request);

        long count = snapshot.keySet().stream()
            .filter(k -> k.startsWith(LogHeadersFilter.MDC_KEY_PREFIX))
            .count();
        assertEquals(LogHeadersFilter.MAX_HEADERS, count,
            "MAX_HEADERS üzeri entry kabul edilmemeli");
    }

    @Test
    void skipsEmptyValues() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-Log-Empty", "");
        request.addHeader("X-Log-Spaces", "   ");
        request.addHeader("X-Log-Real", "ok");

        Map<String, String> snapshot = invokeAndCaptureMdc(request);

        assertFalse(snapshot.containsKey("xlog.x-log-empty"));
        assertFalse(snapshot.containsKey("xlog.x-log-spaces"));
        assertEquals("ok", snapshot.get("xlog.x-log-real"));
    }

    /**
     * Filtre çağrılır ve {@link FilterChain} adımında MDC'nin tam anlık
     * görüntüsü kopyalanır — log emission tam bu noktada gerçekleşir.
     */
    private Map<String, String> invokeAndCaptureMdc(HttpServletRequest request)
            throws ServletException, IOException {
        AtomicReference<Map<String, String>> capture = new AtomicReference<>();
        FilterChain capturing = (req, res) -> {
            Map<String, String> copy = MDC.getCopyOfContextMap();
            capture.set(copy != null ? copy : new HashMap<>());
        };
        filter.doFilter(request, new MockHttpServletResponse(), capturing);
        return capture.get();
    }
}
