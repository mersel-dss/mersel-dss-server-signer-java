package io.mersel.dss.signer.api.config;

import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;

/**
 * Request boyunca tüm {@code x-log-*} HTTP header'larını yakalayıp MDC'ye taşıyan filtre.
 *
 * <p>Bu filtre çalıştıktan sonra request thread'i üzerinde atılan her log
 * satırı (info / warn / error fark etmez) {@link LogHeadersConverter}
 * tarafından yakalanan MDC entry'leriyle JSON formatında zenginleştirilir.
 * Controller, service ve {@code GlobalExceptionHandler} kodunun bu
 * davranıştan haberdar olmasına gerek yok — header'lar log pattern'ine
 * otomatik gömülür.</p>
 *
 * <h3>Güvenlik kontrolleri</h3>
 * <ul>
 *   <li>Header adı normalleştirme — JSON anahtarı her zaman küçük harf
 *       ({@code X-Log-Id} → {@code x-log-id}).</li>
 *   <li>Header sayısı tavanı ({@link #MAX_HEADERS}) — DoS / şişirilmiş
 *       MDC'ye karşı sınır.</li>
 *   <li>Değer uzunluğu kırpma ({@link #MAX_VALUE_LENGTH}) — büyük
 *       payload header'ı log satırını patlatmasın.</li>
 *   <li>CR/LF ve diğer kontrol karakterleri temizlenir — log injection
 *       (CRLF) ataklarına karşı sertleştirme.</li>
 * </ul>
 *
 * <h3>MDC sözleşmesi</h3>
 * Anahtar formatı: {@code xlog.<lower-case-header-name>}. Prefix sayesinde
 * uygulamanın başka bir yerinde MDC'ye konmuş anahtarlarla çakışma olmaz;
 * {@link LogHeadersConverter} JSON'ı sadece bu prefix'li entry'lerden üretir.
 *
 * <h3>Thread güvenliği</h3>
 * Filter request thread'inde sadece kendi koyduğu MDC anahtarlarını
 * {@code finally} bloğunda temizler — başka kodun MDC'sine dokunmaz.
 *
 * <h3>Async sınırlama</h3>
 * SLF4J MDC thread-local'dir; {@code @Async} ya da explicit executor
 * dispatch'lerinde context otomatik propagate olmaz. Bu uygulamada
 * imza pipeline'ları request thread'i üzerinde sync çalıştığı için
 * pratik bir sorun değil; yeni bir async kullanım eklenirse
 * {@code MDC.getCopyOfContextMap()} ile manuel taşıma gerekir.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 50)
public class LogHeadersFilter extends OncePerRequestFilter {

    /** Bu prefix ile başlayan tüm request header'ları yakalanır (case-insensitive). */
    public static final String HEADER_PREFIX = "x-log-";

    /** MDC anahtarlarına eklenen iç prefix — {@link LogHeadersConverter} filtreleme için kullanır. */
    public static final String MDC_KEY_PREFIX = "xlog.";

    /** Header başına izin verilen maksimum değer uzunluğu. */
    static final int MAX_VALUE_LENGTH = 512;

    /** Request başına işlenecek maksimum {@code x-log-*} header sayısı. */
    static final int MAX_HEADERS = 20;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        List<String> mdcKeysToCleanup = applyHeadersToMdc(request);
        try {
            filterChain.doFilter(request, response);
        } finally {
            for (String key : mdcKeysToCleanup) {
                MDC.remove(key);
            }
        }
    }

    /**
     * {@code x-log-*} header'larını MDC'ye yazar ve yazılan anahtar listesini döner.
     *
     * <p>Liste sırası tahmin edilebilir olsun diye request'teki sıraya
     * göre toplanır; ancak bunun pratik bir önemi yok — temizlik
     * idempotent.</p>
     */
    private List<String> applyHeadersToMdc(HttpServletRequest request) {
        Enumeration<String> headerNames = request.getHeaderNames();
        if (headerNames == null) {
            return Collections.emptyList();
        }
        List<String> addedKeys = new ArrayList<>();
        while (headerNames.hasMoreElements()) {
            String rawName = headerNames.nextElement();
            if (rawName == null) {
                continue;
            }
            String normalizedName = rawName.toLowerCase(Locale.ROOT);
            if (!normalizedName.startsWith(HEADER_PREFIX)) {
                continue;
            }
            if (addedKeys.size() >= MAX_HEADERS) {
                break;
            }
            String value = request.getHeader(rawName);
            if (value == null || value.isEmpty()) {
                continue;
            }
            String sanitized = sanitizeValue(value);
            if (sanitized.isEmpty()) {
                continue;
            }
            String mdcKey = MDC_KEY_PREFIX + normalizedName;
            MDC.put(mdcKey, sanitized);
            addedKeys.add(mdcKey);
        }
        return addedKeys;
    }

    /**
     * Header değerini kırpar ve kontrol karakterlerini temizler.
     *
     * <p>CR/LF (log injection riski), TAB ve diğer ASCII control
     * karakterleri tek boşlukla değiştirilir; ardışık boşluklar
     * kalır — operatör orijinal payload'ı yine de görsel olarak
     * gözleyebilir, ama log satırı bütünlüğü bozulmaz.</p>
     */
    static String sanitizeValue(String raw) {
        String trimmed = raw.length() > MAX_VALUE_LENGTH
            ? raw.substring(0, MAX_VALUE_LENGTH)
            : raw;
        StringBuilder out = new StringBuilder(trimmed.length());
        for (int i = 0; i < trimmed.length(); i++) {
            char c = trimmed.charAt(i);
            if (c < 0x20 || c == 0x7F) {
                out.append(' ');
            } else {
                out.append(c);
            }
        }
        return out.toString().trim();
    }
}
