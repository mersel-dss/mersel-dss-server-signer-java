package io.mersel.dss.signer.api.services.util;

import io.mersel.dss.signer.api.exceptions.SignatureException;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/**
 * Sıkıştırma işlemleri (ZIP) için servis.
 */
@Service
public class CompressionService {

    /**
     * Bir ZIP girdisinin açılırken ulaşabileceği azami boyut (decompression bomb
     * korumasi). Meşru e-fatura/e-arşiv içerikleri bunun çok altındadır; bu sınır
     * yalnızca kötü niyetli, aşırı sıkıştırılmış ("zip bomb") girdileri engeller.
     */
    private static final long MAX_DECOMPRESSED_BYTES = 100L * 1024 * 1024; // 100 MB
    private static final int COPY_BUFFER_SIZE = 8192;

    /**
     * Byte dizisini belirtilen girdi adıyla ZIP formatında sıkıştırır.
     *
     * @param filename ZIP dosyasındaki girdi adı
     * @param content Sıkıştırılacak içerik
     * @return Sıkıştırılmış ZIP byte'ları
     */
    public byte[] zipBytes(String filename, byte[] content) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(baos)) {
            ZipEntry entry = new ZipEntry(filename);
            entry.setSize(content.length);
            zos.putNextEntry(entry);
            zos.write(content);
            zos.closeEntry();
        } catch (IOException e) {
            throw new SignatureException("İçerik sıkıştırılamadı", e);
        }
        return baos.toByteArray();
    }

    /**
     * ZIP input stream'den ilk girdiyi çıkarır. Açılan içerik
     * {@link #MAX_DECOMPRESSED_BYTES} sınırını aşarsa hata verir (zip bomb koruması).
     *
     * @param inputStream ZIP input stream
     * @return Sıkıştırılmamış içerik
     */
    public byte[] unzipFirstEntry(InputStream inputStream) {
        try (ZipInputStream zipInputStream = new ZipInputStream(
                inputStream,
                StandardCharsets.ISO_8859_1
        )) {
            ZipEntry entry = zipInputStream.getNextEntry();
            if (entry == null) {
                throw new SignatureException("ZIP arşivi girdi içermiyor");
            }
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[COPY_BUFFER_SIZE];
            long total = 0;
            int read;
            while ((read = zipInputStream.read(buffer)) != -1) {
                total += read;
                if (total > MAX_DECOMPRESSED_BYTES) {
                    throw new SignatureException(
                            "ZIP içeriği izin verilen azami boyutu aşıyor (olası zip bomb)");
                }
                out.write(buffer, 0, read);
            }
            return out.toByteArray();
        } catch (IOException e) {
            throw new SignatureException("ZIP içeriği çıkarılamadı", e);
        }
    }
}

