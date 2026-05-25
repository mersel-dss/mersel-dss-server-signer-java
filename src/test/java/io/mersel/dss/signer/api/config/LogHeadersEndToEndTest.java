package io.mersel.dss.signer.api.config;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.encoder.PatternLayoutEncoder;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.OutputStreamAppender;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Severity;
import io.qameta.allure.SeverityLevel;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Uçtan uca davranış doğrulaması — {@link LogHeadersFilter} +
 * {@link LogHeadersConverter} + Logback pattern entegrasyonunun gerçek
 * çıktısını ölçer.
 *
 * <p>Her hedef seviyede (INFO / WARN / ERROR) bir log satırı atılır ve
 * çıktının {@code xlog={...}} JSON ek bloğunu içerdiği byte-byte
 * doğrulanır. Birim test'leri filter ve converter'ı izole eder; bu
 * test ise iki bileşenin Logback pattern içinden gerçek emisyonda
 * birleşmesini garanti eder.</p>
 */
@Epic("Observability")
@Feature("X-Log Header Propagation")
@Severity(SeverityLevel.CRITICAL)
class LogHeadersEndToEndTest {

    private static final String LOGGER_NAME = "io.mersel.dss.signer.api.config.LogHeadersEndToEndTest";

    private LogHeadersFilter filter;
    private Logger logger;
    private OutputStreamAppender<ILoggingEvent> appender;
    private ByteArrayOutputStream captured;

    @BeforeEach
    void setUp() {
        filter = new LogHeadersFilter();

        LoggerContext context = (LoggerContext) LoggerFactory.getILoggerFactory();

        PatternLayoutEncoder encoder = new PatternLayoutEncoder();
        encoder.setContext(context);
        encoder.setPattern("%-5level %msg %xLogHeaders%n");
        encoder.start();

        captured = new ByteArrayOutputStream();
        appender = new OutputStreamAppender<>();
        appender.setContext(context);
        appender.setEncoder(encoder);
        appender.setOutputStream(captured);
        appender.start();

        logger = context.getLogger(LOGGER_NAME);
        logger.addAppender(appender);
        logger.setLevel(ch.qos.logback.classic.Level.DEBUG);
        logger.setAdditive(false);
    }

    @AfterEach
    void tearDown() {
        if (appender != null) {
            appender.stop();
        }
        if (logger != null) {
            logger.detachAppender(appender);
        }
    }

    @Test
    void infoWarnAndErrorAllReceiveJsonHeaderBlock() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-Log-Id", "abc");
        request.addHeader("x-log-kimlik", "kajsdh");

        FilterChain logEachLevel = (req, res) -> {
            logger.info("info message");
            logger.warn("warn message");
            logger.error("error message");
        };

        filter.doFilter(request, new MockHttpServletResponse(), logEachLevel);

        String output = captured.toString(StandardCharsets.UTF_8.name());
        String[] lines = output.split("\\r?\\n");
        assertEquals(3, lines.length, "Üç log satırı bekleniyor; çıktı: " + output);

        String expectedJsonBlock = "xlog={\"x-log-id\":\"abc\",\"x-log-kimlik\":\"kajsdh\"}";
        assertTrue(lines[0].startsWith("INFO  info message ") && lines[0].endsWith(expectedJsonBlock),
            "INFO satırı format dışı: " + lines[0]);
        assertTrue(lines[1].startsWith("WARN  warn message ") && lines[1].endsWith(expectedJsonBlock),
            "WARN satırı format dışı: " + lines[1]);
        assertTrue(lines[2].startsWith("ERROR error message ") && lines[2].endsWith(expectedJsonBlock),
            "ERROR satırı format dışı: " + lines[2]);
    }

    @Test
    void logEmittedOutsideRequestThreadHasNoJsonBlock() {
        logger.info("standalone");

        String output = captured.toString();
        assertFalse(output.contains("xlog="),
            "Request context dışında atılan log'da xlog bloğu olmamalı: " + output);
    }

    @Test
    void logEmittedAfterRequestFinishesHasNoJsonBlock() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-Log-Id", "abc");

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
        captured.reset();

        logger.info("post-request");

        String output = captured.toString();
        assertFalse(output.contains("xlog="),
            "Request bitince MDC temizlenmeli; sonraki log'da xlog bloğu olmamalı: " + output);
    }
}
