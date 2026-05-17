package io.mersel.dss.signer.api.controllers;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mersel.dss.signer.api.GlobalExceptionHandler;
import io.mersel.dss.signer.api.services.signature.cades.CAdESSignatureService;
import io.mersel.dss.signer.api.services.signature.pades.PAdESSignatureService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * G-2, G-3, G-5: İmza endpoint'lerinin HTTP-envelope kontratı.
 *
 * <h3>Kapsanan kontratlar</h3>
 * <ol>
 *   <li><b>G-3 — empty body / missing document</b> → 400 INVALID_INPUT.
 *       Controller-side validation; PadesControllerTest ve CadesControllerTest
 *       direct-invoke seviyesinde bunu zaten test eder. Bu test ek olarak
 *       <em>tam HTTP yanıt formatı</em>nı (status + ErrorModel JSON gövdesi)
 *       MockMvc seviyesinde doğrular — Spring MessageConverter zincirindeki
 *       regresyonu yakalar.</li>
 *   <li><b>G-2 — malformed multipart</b>: Content-Type {@code multipart/form-data}
 *       declare edilmiş ama body boş/parse edilebilir form-part içermiyor.
 *       Spring {@code StandardServletMultipartResolver} davranışı: form'u
 *       parse eder, {@code dto.getDocument()} null kalır, controller
 *       400 INVALID_INPUT döner. Bu davranış controller'ın <b>graceful
 *       degradation</b> sözleşmesidir — 500 generic'e düşmez.</li>
 *   <li><b>G-5 — wrong Content-Type</b>: {@code application/json} POST.
 *       Spring framework default davranışı: 415 UNSUPPORTED_MEDIA_TYPE.
 *       Controller {@code consumes=multipart/form-data} kısıtlaması var;
 *       bu davranış framework-level kontrat ama implicit regression
 *       koruması için açıkça assert edilir.</li>
 * </ol>
 *
 * <p>{@link MultipartLimitHttpContractTest} 200MB+ upload (413) kontratını
 * ayrı tutar — orada interceptor trap kullanılıyor, burada gerçek HTTP
 * davranışı.</p>
 */
@DisplayName("G-2/3/5: Sign endpoint HTTP envelope (empty body 400, malformed 400, wrong CT 415)")
class SignEndpointHttpEnvelopeContractTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Mock private CAdESSignatureService cadesSignatureService;
    @Mock private PAdESSignatureService padesSignatureService;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        CadesController cadesController = new CadesController(cadesSignatureService, null);
        PadesController padesController = new PadesController(padesSignatureService, null);

        mockMvc = MockMvcBuilders
                .standaloneSetup(cadesController, padesController)
                .setControllerAdvice(new GlobalExceptionHandler())
                .setMessageConverters(new MappingJackson2HttpMessageConverter())
                .build();
    }

    // ─────────────────────────── G-3: empty body / missing document ───────────────────────────

    /**
     * G-3 (CAdES): multipart body'de "document" part hiç yoksa controller
     * 400 + INVALID_INPUT döner. 500 generic'e düşmez (operator UX kontratı).
     */
    @Test
    @DisplayName("CAdES: multipart'ta document yoksa 400 INVALID_INPUT")
    void cades_multipartWithoutDocument_returns400InvalidInput() throws Exception {
        MvcResult result = mockMvc.perform(multipart("/v1/cadessign"))
                .andExpect(status().isBadRequest())
                .andReturn();

        assertErrorEnvelope(result, "INVALID_INPUT");
    }

    /**
     * G-3 (PAdES) — aynı kontrat, parite.
     */
    @Test
    @DisplayName("PAdES: multipart'ta document yoksa 400 INVALID_INPUT")
    void pades_multipartWithoutDocument_returns400InvalidInput() throws Exception {
        MvcResult result = mockMvc.perform(multipart("/v1/padessign"))
                .andExpect(status().isBadRequest())
                .andReturn();

        assertErrorEnvelope(result, "INVALID_INPUT");
    }

    // ─────────────────────────── G-2: malformed multipart ───────────────────────────

    /**
     * G-2 (CAdES): document part adı yanlış ("file" yerine doğrusu "document").
     * Controller {@code dto.getDocument()} null olur → 400 INVALID_INPUT.
     *
     * <p>Bu, "Spring form parse'ı tamamlanır ama beklenen field eksik" =
     * <em>malformed</em> request senaryosu. 500'e düşmesi prod UX regression.</p>
     */
    @Test
    @DisplayName("CAdES: yanlış field name'li multipart → 400 INVALID_INPUT")
    void cades_multipartWithUnknownFieldName_returns400InvalidInput() throws Exception {
        MvcResult result = mockMvc.perform(multipart("/v1/cadessign")
                        .file(new MockMultipartFile(
                                "wrongFieldName", "file.pdf",
                                "application/pdf", "content".getBytes())))
                .andExpect(status().isBadRequest())
                .andReturn();

        assertErrorEnvelope(result, "INVALID_INPUT");
    }

    /**
     * G-2 (CAdES, 0-byte part): document part var ama boş — controller
     * {@code dto.getDocument().isEmpty()} branch'ini test eder.
     */
    @Test
    @DisplayName("CAdES: 0-byte document part → 400 (empty multipart entry)")
    void cades_multipartWithZeroBytePart_returns400() throws Exception {
        mockMvc.perform(multipart("/v1/cadessign")
                        .file(new MockMultipartFile(
                                "document", "empty.bin",
                                "application/octet-stream", new byte[0])))
                .andExpect(status().isBadRequest());
    }

    // ─────────────────────────── G-5: wrong content-type ───────────────────────────

    /**
     * G-5 (CAdES): application/json POST → 415 UNSUPPORTED_MEDIA_TYPE.
     *
     * <p>Controller {@code consumes=multipart/form-data} sözleşmesi var;
     * Spring {@link org.springframework.web.HttpMediaTypeNotSupportedException}
     * fırlatır. {@code GlobalExceptionHandler.handleHttpMediaTypeNotSupported}
     * bu exception'ı 415 + {@code WRONG_CONTENT_TYPE} ErrorModel'e map'ler;
     * generic {@code Exception.class} handler'a düşmemeli (operasyonel UX
     * için 500 değil 415 daha doğru).</p>
     */
    @Test
    @DisplayName("CAdES: application/json POST → 415 + WRONG_CONTENT_TYPE")
    void cades_wrongContentTypeJson_returns415() throws Exception {
        MvcResult result = mockMvc.perform(post("/v1/cadessign")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"document\":\"base64data\"}"))
                .andExpect(status().isUnsupportedMediaType())
                .andReturn();
        assertErrorEnvelope(result, "WRONG_CONTENT_TYPE");
    }

    /**
     * G-5 (PAdES): aynı parite.
     */
    @Test
    @DisplayName("PAdES: application/json POST → 415 + WRONG_CONTENT_TYPE")
    void pades_wrongContentTypeJson_returns415() throws Exception {
        MvcResult result = mockMvc.perform(post("/v1/padessign")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"document\":\"base64data\"}"))
                .andExpect(status().isUnsupportedMediaType())
                .andReturn();
        assertErrorEnvelope(result, "WRONG_CONTENT_TYPE");
    }

    /**
     * G-5 (CAdES, text/plain): text/plain'in de reddedilmesi — neredeyse her
     * tip text/plain ile POST eden client'ı kapsar.
     */
    @Test
    @DisplayName("CAdES: text/plain POST → 415 + WRONG_CONTENT_TYPE")
    void cades_wrongContentTypeText_returns415() throws Exception {
        MvcResult result = mockMvc.perform(post("/v1/cadessign")
                        .contentType(MediaType.TEXT_PLAIN)
                        .content("plain text body"))
                .andExpect(status().isUnsupportedMediaType())
                .andReturn();
        assertErrorEnvelope(result, "WRONG_CONTENT_TYPE");
    }

    private static void assertErrorEnvelope(MvcResult result, String expectedCode) throws Exception {
        String body = result.getResponse().getContentAsString();
        assertNotNull(body, "ErrorModel JSON body olmalı, boş yanıt yok");
        assertTrue(body.length() > 0, "ErrorModel JSON body boş olmamalı");

        JsonNode error = OBJECT_MAPPER.readTree(body);
        assertEquals(expectedCode, error.path("code").asText(),
                "ErrorModel.code beklenen değere eşit olmalı");
        assertNotNull(error.path("message").asText(),
                "ErrorModel.message dolu olmalı (operasyonel UX)");
    }
}
