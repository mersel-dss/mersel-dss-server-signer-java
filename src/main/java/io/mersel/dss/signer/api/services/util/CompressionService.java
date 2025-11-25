package io.mersel.dss.signer.api.services.util;

import io.mersel.dss.signer.api.exceptions.SignatureException;
import org.apache.commons.io.IOUtils;
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
     * Byte dizisini belirtilen girdi adıyla ZIP formatında sıkıştırır.
     * 
     * @param filename ZIP dosyasındaki girdi adı
     * @param content Sıkıştırılacak içerik
     * @return Sıkıştırılmış ZIP byte'ları
     */
    public byte[] zipBytes(String filename, byte[] content) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ZipOutputStream zos = new ZipOutputStream(baos);
            ZipEntry entry = new ZipEntry(filename);
            entry.setSize(content.length);
            zos.putNextEntry(entry);
            zos.write(content);
            zos.closeEntry();
            zos.close();
            return baos.toByteArray();
        } catch (IOException e) {
            throw new SignatureException("İçerik sıkıştırılamadı", e);
        }
    }

    /**
     * ZIP input stream'den ilk girdiyi çıkarır.
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
            if (entry != null) {
                return IOUtils.toByteArray(zipInputStream);
            }
            throw new SignatureException("ZIP arşivi girdi içermiyor");
        } catch (IOException e) {
            throw new SignatureException("ZIP içeriği çıkarılamadı", e);
        }
    }
}

