package io.mersel.dss.signer.api.config;

import ch.qos.logback.classic.spi.ILoggingEvent;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Severity;
import io.qameta.allure.SeverityLevel;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * {@link LogHeadersConverter} JSON emission test'leri.
 *
 * <p>Converter MDC'deki {@code xlog.*} anahtarlarını alfabetik sırada JSON
 * nesnesine çevirir. Test'ler format kontratını (anahtar sıralaması,
 * kaçışlar, boş durum) sabitler.</p>
 */
@Epic("Observability")
@Feature("X-Log Header Propagation")
@Severity(SeverityLevel.NORMAL)
class LogHeadersConverterTest {

    private final LogHeadersConverter converter = new LogHeadersConverter();

    @Test
    void emitsEmptyStringWhenNoXLogEntries() {
        Map<String, String> mdc = new HashMap<>();
        mdc.put("tenant.id", "irrelevant");

        assertEquals("", converter.convert(eventWith(mdc)));
    }

    @Test
    void emitsEmptyStringWhenMdcIsNull() {
        ILoggingEvent event = mock(ILoggingEvent.class);
        when(event.getMDCPropertyMap()).thenReturn(null);

        assertEquals("", converter.convert(event));
    }

    @Test
    void emitsSortedJsonObjectForXLogEntries() {
        Map<String, String> mdc = new LinkedHashMap<>();
        mdc.put("xlog.x-log-kimlik", "kajsdh");
        mdc.put("xlog.x-log-id", "abc");
        mdc.put("tenant.id", "ignored");

        String result = converter.convert(eventWith(mdc));

        assertEquals("xlog={\"x-log-id\":\"abc\",\"x-log-kimlik\":\"kajsdh\"}", result);
    }

    @Test
    void escapesQuoteAndBackslashInValues() {
        Map<String, String> mdc = new HashMap<>();
        mdc.put("xlog.x-log-payload", "a\"b\\c");

        String result = converter.convert(eventWith(mdc));

        assertEquals("xlog={\"x-log-payload\":\"a\\\"b\\\\c\"}", result);
    }

    @Test
    void escapesControlCharactersInValues() {
        Map<String, String> mdc = new HashMap<>();
        mdc.put("xlog.x-log-ctl", "a\nb\tc");

        String result = converter.convert(eventWith(mdc));

        assertEquals("xlog={\"x-log-ctl\":\"a\\nb\\tc\"}", result);
    }

    @Test
    void skipsBlankValues() {
        Map<String, String> mdc = new HashMap<>();
        mdc.put("xlog.x-log-empty", "");
        mdc.put("xlog.x-log-real", "ok");

        String result = converter.convert(eventWith(mdc));

        assertEquals("xlog={\"x-log-real\":\"ok\"}", result);
    }

    private ILoggingEvent eventWith(Map<String, String> mdc) {
        ILoggingEvent event = mock(ILoggingEvent.class);
        when(event.getMDCPropertyMap()).thenReturn(mdc);
        return event;
    }
}
