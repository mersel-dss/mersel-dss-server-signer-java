package io.mersel.dss.signer.api.config;

import ch.qos.logback.classic.pattern.ClassicConverter;
import ch.qos.logback.classic.spi.ILoggingEvent;

import java.util.Map;
import java.util.TreeMap;

/**
 * Logback pattern converter — MDC'deki {@code xlog.*} entry'lerini JSON
 * nesnesi olarak log satırına gömer.
 *
 * <p>{@link LogHeadersFilter} request başına gelen {@code x-log-*}
 * header'larını {@code xlog.<lower-case-name>} formunda MDC'ye koyar.
 * Bu converter her log event'i için MDC'yi tarar, prefix'i çıkartıp
 * JSON anahtar/değer çiftleri üretir. Hiç header yoksa boş string
 * döner — log gürültüsü olmaz.</p>
 *
 * <h3>Çıktı formatı</h3>
 * <pre>xlog={"x-log-id":"abc","x-log-kimlik":"kajsdh"}</pre>
 *
 * <p>{@code xlog=} prefix'i çıktıyı greppable kılar; içerik standart
 * JSON olduğu için log aggregator'lar (ELK, Loki, Splunk) field
 * extraction yapabilir. Anahtarlar deterministik olsun diye
 * alfabetik sıraya alınır.</p>
 *
 * <h3>JSON kaçışları</h3>
 * RFC 8259'a uygun minimal kaçış: çift tırnak, ters slash ve {@code <0x20}
 * kontrol karakterleri. {@link LogHeadersFilter} zaten kontrol
 * karakterlerini boşlukla değiştirir; bu konverter ikinci savunma hattıdır
 * (başka bir kod yolu MDC'ye {@code xlog.*} koyarsa diye).
 */
public class LogHeadersConverter extends ClassicConverter {

    @Override
    public String convert(ILoggingEvent event) {
        Map<String, String> mdc = event.getMDCPropertyMap();
        if (mdc == null || mdc.isEmpty()) {
            return "";
        }

        TreeMap<String, String> selected = new TreeMap<>();
        for (Map.Entry<String, String> e : mdc.entrySet()) {
            String key = e.getKey();
            if (key == null || !key.startsWith(LogHeadersFilter.MDC_KEY_PREFIX)) {
                continue;
            }
            String value = e.getValue();
            if (value == null || value.isEmpty()) {
                continue;
            }
            selected.put(key.substring(LogHeadersFilter.MDC_KEY_PREFIX.length()), value);
        }

        if (selected.isEmpty()) {
            return "";
        }

        StringBuilder sb = new StringBuilder(64 + selected.size() * 32);
        sb.append("xlog={");
        boolean first = true;
        for (Map.Entry<String, String> e : selected.entrySet()) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            sb.append('"');
            appendJsonEscaped(sb, e.getKey());
            sb.append("\":\"");
            appendJsonEscaped(sb, e.getValue());
            sb.append('"');
        }
        sb.append('}');
        return sb.toString();
    }

    /**
     * RFC 8259 minimal JSON kaçışı — sadece güvenli ve gerekli karakterler.
     */
    static void appendJsonEscaped(StringBuilder sb, String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':
                    sb.append("\\\"");
                    break;
                case '\\':
                    sb.append("\\\\");
                    break;
                case '\b':
                    sb.append("\\b");
                    break;
                case '\f':
                    sb.append("\\f");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
    }
}
