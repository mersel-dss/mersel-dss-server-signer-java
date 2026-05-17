package io.mersel.dss.signer.api.util.xml;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.xml.sax.SAXParseException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.nio.file.Files;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * {@link SecureXmlFactories}'in gerçek saldırı vektörlerine karşı
 * dayanıklılığını teyit eden negatif testler.
 *
 * <h3>Neden gerçek payload?</h3>
 * <p>Unit test'lerde "feature true mı?" kontrolü kolay (config introspect)
 * ama yanıltıcı — feature flag'i set etmek tek başına saldırının başarısız
 * olacağını garantilemez (parser implementasyonu farklı interpret edebilir).
 * Bu test gerçek saldırı XML'lerini commit'lenmiş fixture olarak yükler ve
 * parser'ın gerçekten exception fırlattığını uçtan uca doğrular.</p>
 *
 * <h3>Tag stratejisi</h3>
 * <p>Bu test'ler verifier-api veya Docker gerektirmez (saf parser-level
 * regression). Default Surefire suite'inde koşar; her CI run'da çalışır.</p>
 *
 * <h3>Kapsanan saldırılar</h3>
 * <ol>
 *   <li><b>XXE (XML eXternal Entity)</b> — <code>file:///etc/passwd</code>
 *       gibi dış kaynak okuma ({@link #xxeAttackIsRejected()}).</li>
 *   <li><b>Billion Laughs / entity expansion DoS</b> — nested entity
 *       referansları ile memory bomb ({@link #billionLaughsIsRejected()}).</li>
 * </ol>
 *
 * @see <a href="https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html">OWASP XXE Prevention Cheat Sheet</a>
 */
@DisplayName("SecureXmlFactories — gerçek XXE / DoS saldırılarına karşı dayanıklılık")
class XmlSecurityTest {

    private static final String FIXTURE_DIR = "resources/test-fixtures/negative";

    @Test
    @DisplayName("XXE saldırısı (DOCTYPE + ENTITY SYSTEM file:///) parser tarafından reddedilir")
    void xxeAttackIsRejected() throws Exception {
        byte[] xxeBytes = readFixture("xxe-attack.xml");

        // Sanity: fixture gerçekten saldırı payload'ı içermeli (regression
        // koruması; dosya yanlışlıkla sanitize edilirse test anlamsız olur).
        String xml = new String(xxeBytes, java.nio.charset.StandardCharsets.UTF_8);
        assertTrue(xml.contains("<!DOCTYPE foo"),
                "fixture DOCTYPE içermiyor — saldırı payload'ı eksik");
        assertTrue(xml.contains("<!ENTITY xxe SYSTEM \"file:///etc/passwd\">"),
                "fixture external entity declaration içermiyor — saldırı payload'ı eksik");

        DocumentBuilderFactory dbf = SecureXmlFactories.newDocumentBuilderFactory();
        DocumentBuilder db = dbf.newDocumentBuilder();

        // Parser DOCTYPE'ı görür görmez SAXParseException atmalı.
        // Hangi exception class hierarchy'sinden geldiğinin tek doğrusu yok
        // (Xerces, JDK built-in, IBM J9 küçük farklarla atar); ortak ata
        // SAXParseException'dır.
        SAXParseException ex = assertThrows(SAXParseException.class,
                () -> db.parse(new ByteArrayInputStream(xxeBytes)),
                "XXE fixture parse edildi → SecureXmlFactories XXE'ye AÇIK! "
                        + "Bu kritik güvenlik regresyonu, derhal düzeltilmelidir.");

        // Hata mesajı disallow-doctype kontrolünü açıkça belirtmeli;
        // başka sebepten patlamış olsa (örn. malformed XML), test yanıltıcı
        // şekilde geçerdi.
        String msg = ex.getMessage() == null ? "" : ex.getMessage();
        assertTrue(
                msg.contains("DOCTYPE") || msg.contains("disallow-doctype-decl"),
                "Exception sebebi DOCTYPE-reject olmalı; başka bir parse hatası "
                        + "geldi — koruma açık ama yanlış noktada tetiklendi. msg=" + msg);
    }

    @Test
    @DisplayName("Billion Laughs (entity expansion DoS) parser tarafından reddedilir")
    void billionLaughsIsRejected() throws Exception {
        byte[] blBytes = readFixture("billion-laughs.xml");

        // Sanity: gerçek nested entity bombası olduğunu doğrula
        // (en azından lol9 entity'si tanımlanmış olmalı, expansion derinliği).
        String xml = new String(blBytes, java.nio.charset.StandardCharsets.UTF_8);
        assertTrue(xml.contains("<!DOCTYPE lolz"),
                "fixture DOCTYPE içermiyor");
        assertTrue(xml.contains("<!ENTITY lol9"),
                "fixture nested entity definition'larını içermiyor");

        DocumentBuilderFactory dbf = SecureXmlFactories.newDocumentBuilderFactory();
        DocumentBuilder db = dbf.newDocumentBuilder();

        long t0 = System.currentTimeMillis();
        SAXParseException ex = null;
        try {
            db.parse(new ByteArrayInputStream(blBytes));
            fail("Billion Laughs fixture parse edildi → SecureXmlFactories "
                    + "entity expansion'a AÇIK! Heap'i tüketmeden önce DOCTYPE "
                    + "veya secure-processing reddetmeliydi.");
        } catch (SAXParseException e) {
            ex = e;
        }
        long elapsed = System.currentTimeMillis() - t0;

        // Saldırı reddedilse de hızlı reddedilmeli; uzun süre sonra exception
        // gelirse parser bir miktar expansion yapmış demektir (defense weak).
        // 5 saniye eşiği güvenli üst sınır; gerçek reject genelde <100ms.
        assertTrue(elapsed < 5_000,
                "Billion Laughs reject edildi ancak " + elapsed + "ms sürdü — "
                        + "parser bir miktar expansion yapmış olabilir; "
                        + "entity expansion limit'i düzgün set olmamış olabilir.");

        String msg = ex.getMessage() == null ? "" : ex.getMessage();
        assertTrue(
                msg.contains("DOCTYPE") || msg.contains("disallow-doctype-decl"),
                "Exception sebebi DOCTYPE-reject olmalı (defense-in-depth: "
                        + "DOCTYPE zaten reddedildiği için expansion'a gerek "
                        + "kalmadan kesilmeli). msg=" + msg);
    }

    private static byte[] readFixture(String name) throws Exception {
        File f = new File(FIXTURE_DIR, name).getAbsoluteFile();
        assertNotNull(f, "fixture dosya yolu null");
        if (!f.isFile()) {
            throw new IllegalStateException(
                    "Negative fixture bulunamadı: " + f.getAbsolutePath());
        }
        return Files.readAllBytes(f.toPath());
    }
}
