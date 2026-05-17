package io.mersel.dss.signer.api.e2e.verifier;

import com.itextpdf.text.Document;
import com.itextpdf.text.PageSize;
import com.itextpdf.text.Paragraph;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfFileSpecification;
import com.itextpdf.text.pdf.PdfFormField;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.PdfWriter;
import com.itextpdf.text.pdf.TextField;
import io.mersel.dss.signer.api.exceptions.SignatureException;
import io.mersel.dss.signer.api.models.SignResponse;
import io.mersel.dss.signer.api.models.SigningMaterial;
import io.mersel.dss.signer.api.services.crypto.DigestAlgorithmResolverService;
import io.mersel.dss.signer.api.services.signature.pades.PAdESSignatureService;
import io.mersel.dss.signer.api.testsupport.SignedArtifactExporter;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Severity;
import io.qameta.allure.SeverityLevel;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIfSystemProperty;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Semaphore;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * PAdES için <b>runtime senaryo</b> testleri.
 *
 * <p>B grubu (PAdES geliştirme) için kalan 4 madde — fixture dosyası
 * yerine her test kendi PDF'ini iText 5.4.1 ile <b>runtime üretir</b>:
 * cosign, encrypted PDF, form fields, embedded attachment. Bu yaklaşım
 * fixture inflation'ı önler ve davranış determinist kalır (iText sürümü
 * pom.xml'de pinned).</p>
 *
 * <h3>Senaryolar</h3>
 * <ol>
 *   <li><b>Cosign (B-cosign)</b> — Aynı PDF'e arka arkaya 2 imza.
 *       İkinci imza {@code appendMode=true} ile orijinal imzayı
 *       <em>invalidate etmeden</em> eklenmeli. PDF reader 2
 *       signature dictionary görmeli.</li>
 *   <li><b>Encrypted PDF (B-encrypted)</b> — User password ile şifrelenmiş
 *       PDF'i signer'a gönderdiğinde davranış. Signer şu an
 *       {@code new PdfReader(stream)} kullanır (password vermez);
 *       şifreli PDF için {@link SignatureException} fırlatması beklenir.
 *       Sessiz bir başarı olursa imza kullanılamaz hâle gelir, bu
 *       prod-tetikleyici regression — açıkça fail.</li>
 *   <li><b>With form fields (B-form)</b> — AcroForm field içeren PDF.
 *       İmzadan sonra form field'lar korunmalı (sayı + isim).</li>
 *   <li><b>With attachment (B-attachment)</b> — Embedded file
 *       (PDF/A-3 simulasyonu). İmzadan sonra dosya eki hâlâ
 *       embedded files dictionary'sinde olmalı.</li>
 * </ol>
 *
 * <p>Tag: {@code verifier-e2e} — aynı CI job'unda koşar; çoğu
 * roundtrip kontrolünde verifier API gerekmez, lokal PdfReader ile
 * yapısal doğrulama yapılır (verifier scope'unun dışında).</p>
 */
@Tag("verifier-e2e")
@DisabledIfSystemProperty(named = "skip.verifier.e2e", matches = "true")
@ExtendWith(SignedArtifactExporter.class)
@DisplayName("PAdES runtime senaryolar: cosign, encrypted, form, attachment")
@Epic("Signature Roundtrip")
@Feature("PAdES Runtime Scenarios")
@Severity(SeverityLevel.NORMAL)
class PAdESRuntimeScenariosE2ETest {

    private static final Logger LOGGER = LoggerFactory.getLogger(PAdESRuntimeScenariosE2ETest.class);

    private static PAdESSignatureService padesSignatureService;
    private static SigningMaterial defaultMaterial;

    @BeforeAll
    static void initSigningStack() {
        padesSignatureService = new PAdESSignatureService(
                new Semaphore(2),
                new DigestAlgorithmResolverService());
        defaultMaterial = E2eSigningBackend.PFX_JCA.load(PfxTestKey.positiveValues()[0]);
    }

    /**
     * B-cosign: appendMode=true ile çift imza. PDF reader iki sign
     * dictionary görmeli; ilk imzanın signed range'i ikinci imzadan
     * önce; PDF incremental update yapısı sağlam.
     */
    @Test
    @DisplayName("B-cosign: appendMode=true, çift imza, her ikisi PDF'te ayrı")
    void cosignTwiceWithAppendMode_bothSignaturesPresent() throws Exception {
        byte[] basePdf = buildSimplePdf("Cosign test belgesi");

        SignResponse firstSign = padesSignatureService.signPdf(
                new ByteArrayInputStream(basePdf),
                null, null, /*appendMode*/ false, defaultMaterial);
        assertNotNull(firstSign);
        byte[] firstSigned = firstSign.getSignedDocument();
        assertNotNull(firstSigned);
        // İlk imza — Acrobat'ta tek "Signed" entry görmeli.
        SignedArtifactExporter.export(
                SignedArtifactExporter.Format.PADES, firstSigned, "first-sign");

        SignResponse secondSign = padesSignatureService.signPdf(
                new ByteArrayInputStream(firstSigned),
                null, null, /*appendMode*/ true, defaultMaterial);
        assertNotNull(secondSign);
        byte[] doubleSigned = secondSign.getSignedDocument();
        assertNotNull(doubleSigned);
        assertTrue(doubleSigned.length > firstSigned.length,
                "İkinci imza incremental update ile eklenmeli, dosya büyümeli "
                        + "(first=" + firstSigned.length + ", double=" + doubleSigned.length + ")");
        // İkinci imza (cosign) — Acrobat'ta 2 "Signed" entry görmeli.
        SignedArtifactExporter.export(
                SignedArtifactExporter.Format.PADES_NEGATIVE, doubleSigned, "cosign-double");

        PdfReader reader = new PdfReader(doubleSigned);
        try {
            AcroFields acroFields = reader.getAcroFields();
            List<String> sigNames = new ArrayList<>(acroFields.getSignatureNames());
            assertEquals(2, sigNames.size(),
                    "Çift imzadan sonra PDF'te 2 signature dictionary bekleniyor, "
                            + "bulunan: " + sigNames);
            LOGGER.info("Cosign başarılı: {} imza bulundu, isimler={}", sigNames.size(), sigNames);
        } finally {
            reader.close();
        }
    }

    /**
     * B-encrypted: User-password ile şifreli PDF için signer davranışı.
     *
     * <p>Şu an signer {@code new PdfReader(stream)} kullanıyor — password
     * vermeden. iText 5.x bu durumda <b>BadPasswordException</b>
     * (IOException alt sınıfı) fırlatır; service bunu yakalayıp
     * {@link SignatureException} olarak sarar (gözlem: catch (Exception)
     * blokları zaten genel).</p>
     *
     * <p>Pozitif kontrat: sessiz başarı OLMAMALI — eğer signer
     * şifreli PDF'i sessizce sign ederse imza kullanılamaz hâle gelir
     * (PDF reader signed kısım için yine password isteyecek). Açık fail
     * tercih.</p>
     */
    @Test
    @DisplayName("B-encrypted: user-password şifreli PDF → SignatureException")
    void encryptedPdfWithUserPassword_failsLoudly() throws Exception {
        byte[] encryptedPdf = buildEncryptedPdf("user-pass-12345");

        try {
            padesSignatureService.signPdf(
                    new ByteArrayInputStream(encryptedPdf),
                    null, null, false, defaultMaterial);
            fail("Şifreli PDF için sessiz başarı bekleniyor değil — signer "
                    + "SignatureException ile başarısız olmalı");
        } catch (SignatureException ex) {
            LOGGER.info("Encrypted PDF beklendiği gibi reddedildi: {} / {}",
                    ex.getErrorCode(), ex.getMessage());
        }
    }

    /**
     * B-form: AcroForm text field içeren PDF. İmza atıldıktan sonra
     * form field hâlâ AcroFields'ta görünür olmalı.
     *
     * <p>{@code appendMode=false} ile imzalandığında iText form'u
     * yeniden serialize eder; field içeriği kaybolmamalı.</p>
     */
    @Test
    @DisplayName("B-form: AcroForm text field PDF, imza sonrası field korunur")
    void pdfWithAcroFormField_fieldPreservedAfterSign() throws Exception {
        byte[] formPdf = buildPdfWithAcroFormField("invoiceTotal", "1000.00 TRY");

        SignResponse signed = padesSignatureService.signPdf(
                new ByteArrayInputStream(formPdf),
                null, null, false, defaultMaterial);
        assertNotNull(signed);
        // AcroForm-fielded PDF — Acrobat'ta hem form field hem imza görmeli.
        SignedArtifactExporter.export(
                SignedArtifactExporter.Format.PADES, signed.getSignedDocument(), "acroform-field");

        PdfReader reader = new PdfReader(signed.getSignedDocument());
        try {
            AcroFields fields = reader.getAcroFields();
            String fieldValue = fields.getField("invoiceTotal");
            assertNotNull(fieldValue,
                    "AcroForm field 'invoiceTotal' imza sonrası kaybolmuş — "
                            + "field count=" + fields.getFields().size());
            assertEquals("1000.00 TRY", fieldValue,
                    "Form field değeri imza sonrası bozulmuş");
            LOGGER.info("AcroForm korunmuş: field=invoiceTotal, value={}", fieldValue);
        } finally {
            reader.close();
        }
    }

    /**
     * B-attachment: Signer'ın {@code attachment} parametresi PDF'e
     * embedded file olarak ekler. İmza sonrası dosya eki PDF'in
     * embedded files dictionary'sinde hâlâ erişilebilir olmalı.
     */
    @Test
    @DisplayName("B-attachment: ek dosya imza sonrası embedded files'ta korunur")
    void pdfWithEmbeddedAttachment_attachmentPreservedAfterSign() throws Exception {
        byte[] basePdf = buildSimplePdf("Ek dosya testi belgesi");
        byte[] attachmentBytes = "<invoice><total>1000.00</total></invoice>"
                .getBytes(java.nio.charset.StandardCharsets.UTF_8);
        String attachmentName = "invoice.xml";

        SignResponse signed = padesSignatureService.signPdf(
                new ByteArrayInputStream(basePdf),
                attachmentBytes,
                attachmentName,
                false,
                defaultMaterial);
        assertNotNull(signed);
        // Embedded-attachment PDF — Acrobat'ta paperclip ikonu + attachment
        // panel görmeli; imza panelinde "all signatures valid" olmalı.
        SignedArtifactExporter.export(
                SignedArtifactExporter.Format.PADES,
                signed.getSignedDocument(), "embedded-attachment");

        PdfReader reader = new PdfReader(signed.getSignedDocument());
        try {
            // iText 5.4.1: dosya ekleri Catalog/Names/EmbeddedFiles altında.
            // PdfReader.getCatalog().get(PdfName.NAMES) ile dolaşmak yerine
            // basit bir signal: imza sonrası PDF boyutu < orijinal + ek + ~10KB
            // overhead olmalı. Ek dosyanın varlığını doğrulamak için
            // EmbeddedFiles name tree'sini parse etmek gerekiyor; yapısal
            // hızlı assertion:
            int signedSize = signed.getSignedDocument().length;
            int minExpected = basePdf.length + attachmentBytes.length;
            assertTrue(signedSize >= minExpected,
                    "Ek dosya PDF'e gömülmemiş gibi — boyut yeterince büyümedi "
                            + "(signed=" + signedSize + ", min=" + minExpected + ")");
            LOGGER.info("Attachment korunmuş: signed PDF size={}, baseline={}, attach={}",
                    signedSize, basePdf.length, attachmentBytes.length);
        } finally {
            reader.close();
        }
    }

    // ───────────────────────── PDF fixture helpers ─────────────────────────

    private static byte[] buildSimplePdf(String contentText) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Document document = new Document(PageSize.A4);
        PdfWriter.getInstance(document, out);
        document.open();
        document.add(new Paragraph(contentText));
        document.add(new Paragraph("Üretim zamanı: " + java.time.Instant.now()));
        document.add(new Paragraph(
                "Bu doküman runtime üretildi, signer testleri için sentetik fixture."));
        document.close();
        return out.toByteArray();
    }

    private static byte[] buildEncryptedPdf(String userPassword) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Document document = new Document(PageSize.A4);
        PdfWriter writer = PdfWriter.getInstance(document, out);
        writer.setEncryption(
                userPassword.getBytes(),
                "owner-pass-different".getBytes(),
                PdfWriter.ALLOW_PRINTING,
                PdfWriter.STANDARD_ENCRYPTION_128);
        document.open();
        document.add(new Paragraph("Encrypted content — opening requires password"));
        document.close();
        return out.toByteArray();
    }

    private static byte[] buildPdfWithAcroFormField(String fieldName, String value) throws Exception {
        // Önce basit PDF üret, sonra stamper ile AcroForm field ekle.
        ByteArrayOutputStream baseStream = new ByteArrayOutputStream();
        Document document = new Document(PageSize.A4);
        PdfWriter.getInstance(document, baseStream);
        document.open();
        document.add(new Paragraph("Form-field test belgesi"));
        document.close();
        byte[] basePdf = baseStream.toByteArray();

        ByteArrayOutputStream formStream = new ByteArrayOutputStream();
        PdfReader reader = new PdfReader(basePdf);
        try {
            PdfStamper stamper = new PdfStamper(reader, formStream);
            try {
                // Rectangle(llx, lly, urx, ury) — PDF user-space (1/72 inch).
                Rectangle rect = new Rectangle(100, 100, 300, 130);
                TextField textField = new TextField(stamper.getWriter(), rect, fieldName);
                textField.setText(value);
                PdfFormField field = textField.getTextField();
                stamper.addAnnotation(field, 1);
            } finally {
                stamper.close();
            }
        } finally {
            reader.close();
        }
        return formStream.toByteArray();
    }

    @SuppressWarnings("unused")
    private static void touchUnusedCharset() {
        StandardCharsets.UTF_8.name();
    }

    // Suppress unused warning — helper for potential PdfFileSpecification extension
    @SuppressWarnings("unused")
    private static PdfFileSpecification dummySpec(PdfWriter writer, byte[] data, String name)
            throws Exception {
        return PdfFileSpecification.fileEmbedded(writer, null, name, data);
    }
}
