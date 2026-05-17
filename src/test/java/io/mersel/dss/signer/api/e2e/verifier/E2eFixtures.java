package io.mersel.dss.signer.api.e2e.verifier;

import com.itextpdf.text.Document;
import com.itextpdf.text.Paragraph;
import com.itextpdf.text.pdf.PdfWriter;
import org.apache.commons.io.IOUtils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;

/**
 * E2E testleri için fixture (örnek belge) yükleme/üretme helper'ı.
 *
 * <h3>Strateji</h3>
 * <p>Her belge tipi için iki yol vardır:</p>
 * <ol>
 *   <li><b>Resources'tan oku</b> — eğer
 *       <code>src/test/resources/e2e-fixtures/{tip}/sample.{ext}</code>
 *       mevcutsa onu kullan. Bu, kullanıcının kendi gerçek örneklerini
 *       ekleyebilmesi için tercih edilen yoldur.</li>
 *   <li><b>Programatik üret</b> — yoksa, minimum geçerli bir belge
 *       üret. Bu sayede testler "henüz fixture eklemedik" demeden
 *       default'ta da çalışır.</li>
 * </ol>
 *
 * <p>XAdES için {@code resources/test-documents/EFATURA.xml} (repo köküne
 * göre) hazır — UBL e-Fatura örneği.</p>
 */
public final class E2eFixtures {

    private static final String CADES_CLASSPATH = "/e2e-fixtures/cades/sample.bin";
    private static final String PADES_CLASSPATH = "/e2e-fixtures/pades/sample.pdf";
    private static final String XADES_OTHER_CLASSPATH = "/e2e-fixtures/xades/sample.xml";

    /**
     * Repo köküne göre default UBL XML. {@link XadesDocumentFixture#EFATURA} ile
     * <b>tek bir kaynaktan</b> okumak için bilinçli olarak aynı path'i kullanır;
     * iki ayrı XAdES test sınıfının fixture drift'i olmasın diye.
     */
    private static final Path EFATURA_DEFAULT_PATH = Paths.get("resources/test-fixtures/xades/efatura.xml");

    private E2eFixtures() {
        // utility class
    }

    // ====================== CAdES (binary data) ======================

    /**
     * CAdES için imzalanacak ham veri. Sırasıyla:
     * 1) classpath: <code>/e2e-fixtures/cades/sample.bin</code>
     * 2) yoksa zamana bağlı kısa bir UTF-8 string
     */
    public static byte[] cadesData() {
        byte[] fromCp = readClasspath(CADES_CLASSPATH);
        if (fromCp != null) {
            return fromCp;
        }
        String content = "Mersel DSS E2E test payload — " + Instant.now();
        return content.getBytes(StandardCharsets.UTF_8);
    }

    public static String cadesFileName() {
        return "sample.bin";
    }

    // ============================ PAdES (PDF) =========================

    /**
     * PAdES için minimum geçerli PDF. Sırasıyla:
     * 1) classpath: <code>/e2e-fixtures/pades/sample.pdf</code>
     * 2) yoksa iText ile programatik küçük bir PDF
     */
    public static byte[] padesPdf() {
        byte[] fromCp = readClasspath(PADES_CLASSPATH);
        if (fromCp != null) {
            return fromCp;
        }
        return generateMinimalPdf();
    }

    public static String padesFileName() {
        return "sample.pdf";
    }

    private static byte[] generateMinimalPdf() {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            Document document = new Document();
            PdfWriter.getInstance(document, baos);
            document.open();
            document.add(new Paragraph("Mersel DSS E2E Test PDF"));
            document.add(new Paragraph("Generated at: " + Instant.now()));
            document.close();
            return baos.toByteArray();
        } catch (Exception e) {
            throw new IllegalStateException("Test PDF üretilemedi", e);
        }
    }

    // ============================ XAdES (XML) =========================

    /**
     * UBL e-Fatura XML'i (DocumentType.UblDocument senaryosu için).
     * Repo'da hazır olan {@code resources/test-fixtures/xades/efatura.xml} kullanılır.
     */
    public static byte[] efaturaXml() {
        try {
            if (!Files.exists(EFATURA_DEFAULT_PATH)) {
                throw new IllegalStateException(
                        "efatura.xml bulunamadı: " + EFATURA_DEFAULT_PATH.toAbsolutePath()
                                + ". Test repo kök dizininden çalıştırılmalı.");
            }
            return Files.readAllBytes(EFATURA_DEFAULT_PATH);
        } catch (IOException e) {
            throw new IllegalStateException("EFATURA.xml okunamadı", e);
        }
    }

    public static String efaturaFileName() {
        return "EFATURA.xml";
    }

    /**
     * Generic XAdES (DocumentType.OtherXmlDocument) senaryosu için XML.
     * Sırasıyla:
     * 1) classpath: <code>/e2e-fixtures/xades/sample.xml</code>
     * 2) yoksa minimum geçerli bir XML literal
     */
    public static byte[] genericXml() {
        byte[] fromCp = readClasspath(XADES_OTHER_CLASSPATH);
        if (fromCp != null) {
            return fromCp;
        }
        String xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                + "<root xmlns=\"http://mersel.io/e2e\">"
                + "<message>E2E test payload</message>"
                + "<timestamp>" + Instant.now() + "</timestamp>"
                + "</root>";
        return xml.getBytes(StandardCharsets.UTF_8);
    }

    public static String genericXmlFileName() {
        return "sample.xml";
    }

    // ============================ Helpers ============================

    private static byte[] readClasspath(String path) {
        try (InputStream in = E2eFixtures.class.getResourceAsStream(path)) {
            if (in == null) {
                return null;
            }
            return IOUtils.toByteArray(in);
        } catch (IOException e) {
            throw new IllegalStateException("Classpath fixture okunamadı: " + path, e);
        }
    }
}
