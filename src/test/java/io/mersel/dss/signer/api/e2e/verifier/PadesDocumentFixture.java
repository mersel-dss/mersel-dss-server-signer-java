package io.mersel.dss.signer.api.e2e.verifier;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

/**
 * <code>resources/test-fixtures/pades/</code> altındaki PAdES için
 * imzalanabilir <b>PDF varyasyon</b> örneklerini tipli olarak ifade eder.
 *
 * <p>PAdES, PDF spec'inin "imza dictionary + ByteRange" yapısı üzerine
 * kuruludur; signer'ın farklı PDF yapılarında (multi-page, landscape,
 * Türkçe karakter, page-count) doğru ByteRange hesapladığını ve
 * signature dictionary'i bozmadan yerleştirdiğini test ediyoruz.</p>
 *
 * <h3>Neden bu fixture'lar?</h3>
 * <ul>
 *   <li><b>EFATURA_PDF (3 sayfa)</b>: UBL-benzeri görsel fatura
 *       (Türkçe başlık + tablo + tutar özeti). Multi-page byte range
 *       coverage ve KDV/tutar sembollerinin (₺) düzgün korunması.</li>
 *   <li><b>TURKISH_CHARS (1 sayfa)</b>: Türkçe karakter-yoğun gövde
 *       (ç, ş, ı, ğ, ü, ö, İ). Cp1254 encoded — signer cross-encoding
 *       PDF'lerde ByteRange digest hesaplarken bozulmamalı.</li>
 *   <li><b>LANDSCAPE_A3 (1 sayfa)</b>: A3 landscape orientation
 *       (297 × 420 mm rotated). MediaBox sınırlarının landscape için
 *       doğru hesaplandığını test eder; ileride "visible signature"
 *       özelliği eklenirse bu fixture geri-uyumluluk regresyon
 *       vektörü olur.</li>
 *   <li><b>LARGE_50_PAGES (50 sayfa)</b>: Çok-sayfa byte range
 *       coverage + PdfBox memory pressure test. Sayfa başına ~15
 *       paragraf, ~22 KB toplam (PDF compression sayesinde).</li>
 * </ul>
 *
 * <h3>Tek source-of-truth</h3>
 * <p>Yeni PDF fixture eklemek için: bu enum'a entry + dosyayı
 * {@code resources/test-fixtures/pades/} altına commit (manuel ya da
 * iText/PDFBox ile programatik üretip dump). Test sınıfları
 * ({@link PAdESDocumentVariationsE2ETest}) {@code .values()} üzerinde
 * iterate eder, yeni fixture otomatik matrise dahil olur.</p>
 *
 * <h3>Fixture üretimi (referans, içerik commit'in özeti)</h3>
 * <p>4 PDF iText 5.4.1 ile programatik üretildi (Helvetica + Cp1254
 * Türkçe encoding). Üretici geçici bir bootstrap test class'tı; çıktı
 * commit edildi ve generator silindi (kullanıcı tercihi). Yeniden
 * üretmek gerekirse content özeti bu enum Javadoc'unda + boyut
 * sanity'leri test'in kendisinde.</p>
 */
public enum PadesDocumentFixture {

    EFATURA_PDF("efatura-pdf.pdf", "Test e-Fatura (3 sayfa, Türkçe görsel UBL)"),
    TURKISH_CHARS("turkish-chars.pdf", "Türkçe karakter-yoğun gövde (Cp1254)"),
    LANDSCAPE_A3("landscape-a3.pdf", "A3 landscape (297×420 mm rotated)"),
    LARGE_50_PAGES("large-50pages.pdf", "50 sayfa (multi-page ByteRange + memory pressure)");

    private static final String FIXTURE_DIR = "resources/test-fixtures/pades";

    private final String fileName;
    private final String displayName;

    PadesDocumentFixture(String fileName, String displayName) {
        this.fileName = fileName;
        this.displayName = displayName;
    }

    public String getFileName() {
        return fileName;
    }

    public File getFile() {
        return new File(FIXTURE_DIR, fileName).getAbsoluteFile();
    }

    public byte[] readBytes() {
        File file = getFile();
        if (!file.isFile()) {
            throw new IllegalStateException(
                    "PAdES PDF fixture bulunamadı: " + file.getAbsolutePath()
                            + " (resources/test-fixtures/pades/ klasörünü kontrol edin)");
        }
        try {
            return Files.readAllBytes(file.toPath());
        } catch (IOException e) {
            throw new IllegalStateException(
                    "PAdES PDF fixture okunamadı: " + file.getAbsolutePath(), e);
        }
    }

    @Override
    public String toString() {
        return name() + " (" + displayName + ")";
    }
}
