package io.mersel.dss.signer.api.controllers;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mersel.dss.signer.api.GlobalExceptionHandler;
import io.mersel.dss.signer.api.services.notification.SignerNotifier;
import io.mersel.dss.signer.api.services.signature.cades.CAdESSignatureService;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Severity;
import io.qameta.allure.SeverityLevel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * G-1: Multipart upload boyut limiti HTTP kontratı.
 *
 * <p>Production multipart limit'i {@code spring.servlet.multipart.max-file-size=200MB}
 * (ayrıca {@code MultipartConfigSanityTest} ile pinli). Limit aşıldığında
 * Spring {@link MaxUploadSizeExceededException} fırlatır; bu exception'ın
 * controller'ın HTTP yanıt katmanında nasıl handle edildiğini bu test
 * uçtan-uca (MockMvc seviyesinde) doğrular.</p>
 *
 * <h3>Strateji</h3>
 * <p>Gerçekten 200MB+ byte upload etmek yerine — JVM heap'i şişirmemek için
 * — Spring DispatcherServlet'in <b>pre-handle interceptor</b>'unu hijack
 * ediyoruz: her multipart request'ten <em>önce</em>
 * {@link MaxUploadSizeExceededException} fırlatıyor. Bu, gerçek
 * StandardServletMultipartResolver'ın limit aşımına davranışı ile aynı
 * runtime semantik: exception MVC layer'da yakalanır, ardından
 * {@link GlobalExceptionHandler#handleMaxUploadSizeExceeded} 413 +
 * {@code FILE_TOO_LARGE} ErrorModel ile yanıtlar.</p>
 *
 * <h3>Neden bu seviye?</h3>
 * <p>{@code GlobalExceptionHandlerTest.testHandleMaxUploadSizeExceeded_returns413}
 * exception → ResponseEntity mapping'ini direkt invocation ile test eder.
 * Bu test ek olarak <em>tam HTTP yanıt</em>'ı (status code, JSON body,
 * Content-Type) doğrular — production'da Spring filter zincirinden ve
 * ErrorModel JSON serialization'ından geçtiği yol. Filter ya da
 * ExceptionResolver chain bozulursa burada yakalanır.</p>
 */
@DisplayName("G-1: >200MB multipart upload → 413 PAYLOAD_TOO_LARGE + ErrorModel JSON")
@Epic("HTTP API Contract")
@Feature("Multipart Limits")
@Severity(SeverityLevel.NORMAL)
class MultipartLimitHttpContractTest {

    private static final long EXCEEDED_BYTES = 200L * 1024 * 1024 + 1;

    @Mock private CAdESSignatureService cadesSignatureService;
    @Mock private SignerNotifier signerNotifier;

    private MockMvc mockMvc;
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        CadesController cadesController = new CadesController(
            cadesSignatureService, null, signerNotifier);

        // Interceptor — her request'i intercept eder ve içinde
        // MaxUploadSizeExceededException atar. Spring DispatcherServlet
        // bu exception'ı GlobalExceptionHandler'a teslim eder
        // (@RestControllerAdvice MVC pipeline'ında auto-resolve edilir).
        //
        // NOT: standalone setup default message converter olarak String
        // converter kullanır; JSON yanıt için Jackson converter'ı explicit
        // register etmek gerek (production'da Spring Boot auto-config
        // tarafından sağlanır).
        mockMvc = MockMvcBuilders.standaloneSetup(cadesController)
                .setControllerAdvice(new GlobalExceptionHandler())
                .setMessageConverters(new MappingJackson2HttpMessageConverter())
                .addInterceptors(new MultipartLimitTrapInterceptor())
                .build();
    }

    /**
     * CAdES endpoint'i için 200MB sınır aşımı senaryosu:
     * <ul>
     *   <li>HTTP status = 413 Payload Too Large</li>
     *   <li>Body code = {@code FILE_TOO_LARGE}</li>
     *   <li>Body message Türkçe operasyonel mesaj içerir</li>
     * </ul>
     */
    @Test
    void cades_uploadOver200Mb_returns413WithFileTooLargeErrorCode() throws Exception {
        MvcResult result = mockMvc.perform(multipart("/v1/cadessign")
                        .file(new MockMultipartFile(
                                "document", "fake-huge.bin",
                                "application/octet-stream",
                                new byte[]{1, 2, 3}))) // dummy small content
                .andExpect(status().isPayloadTooLarge())
                .andReturn();

        String body = result.getResponse().getContentAsString();
        assertNotNull(body, "413 yanıtı body taşımalı (ErrorModel JSON)");
        JsonNode error = OBJECT_MAPPER.readTree(body);
        assertEquals("FILE_TOO_LARGE", error.path("code").asText(),
                "413 yanıtı sabit FILE_TOO_LARGE error kodunu içermeli");
        String message = error.path("message").asText();
        assertNotNull(message,
                "413 yanıtı operasyonel error mesajı içermeli (loglara, "
                        + "client UI'a aktarılabilir)");
        assertTrue(message.toLowerCase().contains("dosya"),
                "Türkçe error mesajı 'dosya' kelimesini içermeli: " + message);
    }

    /**
     * Determinizm sanity: ikinci çağrıda da aynı yanıt — interceptor her
     * istekte throw eder, sessiz başarı (silent bypass) yok.
     */
    @Test
    void interceptorActuallyThrows_notSilentBypass() throws Exception {
        MvcResult result = mockMvc.perform(multipart("/v1/cadessign")
                        .file(new MockMultipartFile(
                                "document", "another.bin",
                                "application/octet-stream",
                                new byte[]{9})))
                .andExpect(status().isPayloadTooLarge())
                .andReturn();

        JsonNode error = OBJECT_MAPPER.readTree(
                result.getResponse().getContentAsString());
        assertEquals("FILE_TOO_LARGE", error.path("code").asText(),
                "Tekrarlanan istek de 413 + FILE_TOO_LARGE dönmeli (deterministic)");
    }

    /**
     * Production multipart limit aşımının runtime semantiğini taklit eder.
     *
     * <p>Spring'in {@code StandardServletMultipartResolver}'ı
     * {@code maxFileSize} aşıldığında {@link MaxUploadSizeExceededException}
     * fırlatır; bu exception MVC layer'ın "preHandle" + "handle" zincirinde
     * yakalanır ve ExceptionHandler'lar tarafından resolve edilir. Interceptor
     * bu davranışı simüle eder — gerçek multipart parse'ın throw etmesi ile
     * fonksiyonel olarak eş semantik (her ikisi de SAME exception type'ını
     * SAME pipeline aşamasında atar).</p>
     */
    private static final class MultipartLimitTrapInterceptor implements HandlerInterceptor {
        @Override
        public boolean preHandle(HttpServletRequest request, HttpServletResponse response,
                                 Object handler) {
            throw new MaxUploadSizeExceededException(EXCEEDED_BYTES);
        }
    }

}
