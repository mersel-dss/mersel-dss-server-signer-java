package io.mersel.dss.signer.api.e2e.verifier;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

/**
 * <code>resources/test-fixtures/cades/</code> altındaki CAdES için
 * imzalanabilir <b>binary varyasyon</b> örneklerini tipli olarak ifade eder.
 *
 * <p>CAdES, XAdES/PAdES gibi belge-formatı tanımıyan generic CMS imza;
 * payload herhangi bir bayt akışı olabilir. Production'da farklı binary
 * girdi tiplerinin (UTF-8 text, ham binary, sıfır-byte, UTF-16 with BOM)
 * imzalayıcının hash + ContentInfo akışını bozmadığını test ediyoruz.</p>
 *
 * <h3>Neden bu fixture'lar?</h3>
 * <ul>
 *   <li><b>SAMPLE_TXT (UTF-8)</b>: Türkçe diakritik içeren UTF-8 multibyte
 *       text — signer "byte[]" olarak alır, encoding-agnostic davranmalı.
 *       Production'da PDF/XML dışında düz metin imzalama yaygındır
 *       (ör. bilgi güvenliği rapor txt'leri).</li>
 *   <li><b>SAMPLE_BIN (10KB random)</b>: SHA-256 seed'li deterministic
 *       binary — ham binary akışında attached/detached digest farkını
 *       test eder. Reproducible: git'e commit edilen bayt-dizisi tahmin
 *       edilebilir (regression için tek source-of-truth).</li>
 *   <li><b>EMPTY_BIN (0 byte)</b>: Boş input edge-case. Signer hata
 *       fırlatmadan boş ContentInfo üretebilmeli; veya production
 *       davranışına göre net hata. Yine de "verifier ne diyor" diye
 *       roundtrip lay-of-the-land sağlar.</li>
 *   <li><b>UTF16_TEXT (UTF-16 BE with BOM)</b>: Çift-bayt encoding +
 *       BOM ile başlayan text — signer'ın "binary olarak handle eder"
 *       kontratını test eder (encoding tahmin etmemeli).</li>
 * </ul>
 *
 * <h3>Tek source-of-truth</h3>
 * <p>Yeni binary fixture eklemek için: bu enum'a entry + dosyayı
 * {@code resources/test-fixtures/cades/} altına commit. Test sınıfları
 * ({@link CAdESBinaryVariationsE2ETest}) {@code .values()} üzerinde
 * iterate ettiği için yeni fixture otomatik matrise dahil olur.</p>
 */
public enum CadesBinaryFixture {

    SAMPLE_TXT("sample.txt", "UTF-8 Türkçe metin (~2 KB)"),
    SAMPLE_BIN("sample.bin", "Deterministic random binary (10 KB)"),
    EMPTY_BIN("empty.bin", "0 byte (boş input edge-case)"),
    UTF16_TEXT("utf16-text.txt", "UTF-16 BE BOM + Türkçe text (~1.4 KB)");

    private static final String FIXTURE_DIR = "resources/test-fixtures/cades";

    private final String fileName;
    private final String displayName;

    CadesBinaryFixture(String fileName, String displayName) {
        this.fileName = fileName;
        this.displayName = displayName;
    }

    public String getFileName() {
        return fileName;
    }

    /** Mutlak dosya yolu — Maven testlerde user.dir repo köküdür. */
    public File getFile() {
        return new File(FIXTURE_DIR, fileName).getAbsoluteFile();
    }

    /**
     * Dosya içeriğini byte dizisi olarak okur. EMPTY_BIN için 0-byte
     * döner; dosya yoksa {@link IllegalStateException}.
     */
    public byte[] readBytes() {
        File file = getFile();
        if (!file.isFile()) {
            throw new IllegalStateException(
                    "CAdES binary fixture bulunamadı: " + file.getAbsolutePath()
                            + " (resources/test-fixtures/cades/ klasörünü kontrol edin)");
        }
        try {
            return Files.readAllBytes(file.toPath());
        } catch (IOException e) {
            throw new IllegalStateException(
                    "CAdES binary fixture okunamadı: " + file.getAbsolutePath(), e);
        }
    }

    @Override
    public String toString() {
        return name() + " (" + displayName + ")";
    }
}
