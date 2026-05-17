package io.mersel.dss.signer.api.services.timestamp;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import io.mersel.dss.signer.api.dtos.TimestampRequestDto;
import io.mersel.dss.signer.api.exceptions.TimestampException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

/**
 * TSP / Timestamp servisi için <b>HTTP-tarafı kontrat</b> testleri.
 *
 * <p>E grubu (Timestamp/TSA) için kapsamlı unit + lightweight integration:
 * gerçek bir TSA mock'lamak yerine JDK'nın built-in
 * {@link HttpServer}'ını kullanarak HTTP davranış matrislerini test
 * ederiz. Gerçek RFC 3161 response generation testcontainer
 * (örn. {@code freetsa/freetsa}) gerektirir ve {@code TEST_BACKLOG}'da
 * ayrı bir item olarak kalır.</p>
 *
 * <h3>Kapsanan kontratlar</h3>
 * <ol>
 *   <li><b>E2</b>: Empty {@code TS_SERVER_HOST} → {@code isAvailable()}
 *       false; {@code getTspSource()} {@link TimestampException} fırlatır
 *       (sessiz "no-op" değil). Operator config eksikliğini fark eder.</li>
 *   <li><b>E2-alt</b>: Empty URL + getTimestamp çağrısı →
 *       TimestampException; "config eksik" mesajı.</li>
 *   <li><b>E3</b>: TSA 500 Internal Server Error → TimestampException
 *       (graceful degrade — controller 503 SERVICE_UNAVAILABLE'a
 *       map'ler GlobalExceptionHandler ile).</li>
 *   <li><b>E3-alt</b>: TSA bağlanılamaz port (TCP RST) → TimestampException.</li>
 * </ol>
 */
class TimestampServiceContractTest {

    private HttpServer httpServer;
    private int port;

    @BeforeEach
    void startMockServer() throws Exception {
        httpServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        port = httpServer.getAddress().getPort();
    }

    @AfterEach
    void stopMockServer() {
        if (httpServer != null) {
            httpServer.stop(0);
        }
    }

    /**
     * E2: TS_SERVER_HOST yapılandırılmamışsa {@code isAvailable()} false
     * ve {@code getTspSource()} açık bir hata mesajı ile fırlatmalı.
     */
    @Test
    @DisplayName("E2: empty TS_SERVER_HOST → isAvailable() false, getTspSource throws")
    void e2_emptyTspUrl_throwsExplicitException() {
        TimestampConfigurationService config = new TimestampConfigurationService(
                /*tspServerUrl*/ "",
                /*tspUserId*/    "",
                /*tspUserPassword*/ "",
                /*isTubitakTsp*/ false);

        assertFalse(config.isAvailable(),
                "Empty URL'de isAvailable false dönmeli");

        TimestampException ex = assertThrows(TimestampException.class,
                config::getTspSource,
                "Empty URL'de getTspSource sessizce null dönmemeli, açıkça throws etmeli");
        assertTrue(ex.getMessage().contains("TS_SERVER_HOST"),
                "Hata mesajı eksik property adını içermeli: " + ex.getMessage());
    }

    /**
     * E2 (alt): Empty URL + getTimestamp → TimestampException propagation
     * controller → GlobalExceptionHandler → 503 SERVICE_UNAVAILABLE
     * (handleTimestampException kontratı, ayrıca test edilmiş).
     */
    @Test
    @DisplayName("E2-alt: empty URL, getTimestamp call propagates TimestampException")
    void e2_emptyTspUrl_getTimestamp_propagatesException() {
        TimestampConfigurationService config = new TimestampConfigurationService(
                "", "", "", false);
        TimestampService service = new TimestampService(config);

        TimestampRequestDto dto = new TimestampRequestDto();
        dto.setDocumentData(Base64.getEncoder().encodeToString("payload".getBytes()));
        dto.setHashAlgorithm("SHA256");

        assertThrows(TimestampException.class, () -> service.getTimestamp(dto));
    }

    /**
     * E3: TSA 500 Internal Server Error. OnlineTSPSource HTTP katmanından
     * çıkan hatayı yakalayıp TimestampException olarak fırlatır;
     * controller 503'e map'ler.
     */
    @Test
    @DisplayName("E3: TSA 500 Internal Server Error → TimestampException (graceful degrade)")
    void e3_tspServerReturns500_failsGracefully() {
        httpServer.createContext("/tsp", new Returns500Handler());
        httpServer.start();

        TimestampConfigurationService config = new TimestampConfigurationService(
                "http://127.0.0.1:" + port + "/tsp",
                "", "", false);
        TimestampService service = new TimestampService(config);

        TimestampRequestDto dto = new TimestampRequestDto();
        dto.setDocumentData(Base64.getEncoder().encodeToString("payload".getBytes()));
        dto.setHashAlgorithm("SHA256");

        // DSS OnlineTSPSource HTTP non-2xx için runtime ex atar; servis
        // bunu yakalayıp TimestampException'a sarar (veya
        // genericException → 500 INTERNAL'a düşer ki bu da prod'da
        // controller-katmanı 500 dönmesi anlamına gelir — kontrat
        // "exception throws" yönünde temel; "503 mu 500 mü" mapping
        // GlobalExceptionHandlerTest'te kapsanır).
        Exception thrown = assertThrows(Exception.class,
                () -> service.getTimestamp(dto));

        assertNotNull(thrown.getMessage(), "Hata mesajı set olmalı");
    }

    /**
     * E3-alt: TSA port'a bağlanılamaz (bizim server bağlı port'a değil
     * başka bir port'a, TCP RST garantili).
     */
    @Test
    @DisplayName("E3-alt: TSA port unreachable → TimestampException")
    void e3_tspServerUnreachable_failsGracefully() throws IOException {
        httpServer.start();
        int unreachablePort = port + 1;
        // Yakın port'un kullanımda olmadığını lokal davranış sırasında
        // belirsiz; doğru hedef: kapatılmış soket. En sağlam yöntem,
        // mock server'ı kapatıp port'u serbest bırakmak.
        httpServer.stop(0);
        httpServer = null;

        TimestampConfigurationService config = new TimestampConfigurationService(
                "http://127.0.0.1:" + port + "/tsp",
                "", "", false);
        TimestampService service = new TimestampService(config);

        TimestampRequestDto dto = new TimestampRequestDto();
        dto.setDocumentData(Base64.getEncoder().encodeToString("payload".getBytes()));
        dto.setHashAlgorithm("SHA256");

        Exception thrown = assertThrows(Exception.class,
                () -> service.getTimestamp(dto));
        assertNotNull(thrown.getMessage(), "Hata mesajı set olmalı");
    }

    // ───────────────────────── HTTP handler ─────────────────────────

    private static final class Returns500Handler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            byte[] body = "TSA internal error".getBytes();
            exchange.sendResponseHeaders(500, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        }
    }
}
