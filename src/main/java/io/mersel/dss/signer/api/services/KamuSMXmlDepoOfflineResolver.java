package io.mersel.dss.signer.api.services;

import org.apache.commons.io.IOUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import eu.europa.esig.dss.model.x509.CertificateToken;

/**
 * KamuSM XML Deposu Offline Resolver
 * Yerel dosya sisteminden KamuSM sertifika deposunu okur ve yönetir.
 * Offline ortamlarda kullanım için tasarlanmıştır.
 */
@Service("kamuSMXmlDepoOfflineResolver")
public class KamuSMXmlDepoOfflineResolver extends AbstractKamuSMXmlDepoResolver {

    private final ResourceLoader resourceLoader;
    private final String xmlFilePath;

    public KamuSMXmlDepoOfflineResolver(ResourceLoader resourceLoader,
                                          @Value("${kamusm.root.offline.path:}") String xmlFilePath) {
        this.resourceLoader = resourceLoader;
        // Path'teki baştaki ve sondaki tırnakları temizle (Spring properties'te çift tırnak kullanımı için)
        if (xmlFilePath != null) {
            xmlFilePath = xmlFilePath.trim();
            // Çift tırnak veya tek tırnak ile başlayıp bitiyorsa kaldır
            if ((xmlFilePath.startsWith("\"") && xmlFilePath.endsWith("\"")) ||
                (xmlFilePath.startsWith("'") && xmlFilePath.endsWith("'"))) {
                xmlFilePath = xmlFilePath.substring(1, xmlFilePath.length() - 1);
            }
            // Encoding sorununu çöz: Eğer path ISO-8859-1 olarak yanlış okunduysa UTF-8'e çevir
            try {
                // ISO-8859-1 olarak yanlış okunmuş gibi görünen karakterleri UTF-8'e çevir
                // Örnek: "Ãn" -> "Ön", "HazÄ±rlÄ±k" -> "Hazırlık"
                if (xmlFilePath.contains("Ã") || xmlFilePath.contains("Ä")) {
                    byte[] bytes = xmlFilePath.getBytes("ISO-8859-1");
                    String correctedPath = new String(bytes, "UTF-8");
                    // Eğer düzeltilmiş path Türkçe karakterler içeriyorsa kullan
                    if (correctedPath.contains("Ö") || correctedPath.contains("ö") || 
                        correctedPath.contains("ı") || correctedPath.contains("İ") ||
                        correctedPath.contains("ş") || correctedPath.contains("Ş") ||
                        correctedPath.contains("ğ") || correctedPath.contains("Ğ") ||
                        correctedPath.contains("ü") || correctedPath.contains("Ü") ||
                        correctedPath.contains("ç") || correctedPath.contains("Ç")) {
                        xmlFilePath = correctedPath;
                        logger.debug("Path encoding düzeltildi: {}", xmlFilePath);
                    }
                }
            } catch (Exception e) {
                logger.debug("Path encoding düzeltme hatası: {}", e.getMessage());
            }
        }
        this.xmlFilePath = xmlFilePath;
    }

    @Override
    public void refreshTrustedRoots() {
        // Mevcut sertifikaları sakla (başarısız olursa geri yüklemek için)
        List<X509Certificate> previousRoots = new ArrayList<>(trustedRoots.get());
        List<CertificateToken> previousTokens = new ArrayList<>(trustedRootTokens.get());
        
        try {
            if (xmlFilePath == null || xmlFilePath.trim().isEmpty()) {
                logger.warn("Offline KamuSM XML dosya yolu belirtilmemiş. Sertifika yüklenemiyor.");
                return;
            }
            
            logger.info("KamuSM XML deposu offline olarak yukleniyor: {}", xmlFilePath);
            String xmlBody = loadRepositoryXml();
            if (xmlBody == null || xmlBody.trim().isEmpty()) {
                logger.warn("KamuSM kok sertifika verisi bos - mevcut liste korunuyor");
                return;
            }
            List<X509Certificate> certificates = parseCertificates(xmlBody);
            if (certificates.isEmpty()) {
                logger.warn("KamuSM kok sertifika listesi bos - mevcut liste korunuyor");
                return;
            }
            List<CertificateToken> tokens = new ArrayList<CertificateToken>(certificates.size());
            for (X509Certificate certificate : certificates) {
                tokens.add(new CertificateToken(certificate));
            }
            trustedRoots.set(Collections.unmodifiableList(certificates));
            trustedRootTokens.set(Collections.unmodifiableList(tokens));
            logger.info("KamuSM kok sertifikalari basariyla yuklendi ({} adet)", certificates.size());
            
            // Trusted certificate source'u da guncelle
            updateTrustedCertificateSource();
            
        } catch (Exception ex) {
            logger.error("KamuSM kok sertifikalarini yukleme basarisiz: {} - mevcut liste korunuyor", ex.getMessage(), ex);
            
            // Başarısız olursa önceki sertifikaları geri yükle
            if (!previousRoots.isEmpty()) {
                trustedRoots.set(Collections.unmodifiableList(previousRoots));
                trustedRootTokens.set(Collections.unmodifiableList(previousTokens));
                logger.info("Onceki sertifikalar geri yuklendi ({} adet)", previousRoots.size());
            }
        }
    }

    @Override
    protected String loadRepositoryXml() throws Exception {
        // Direkt dosya sistemi yolu kontrolü
        // Desteklenen formatlar:
        // - file:/path/to/file.xml (Unix/Linux/Mac)
        // - file:/C:/path/to/file.xml (Windows)
        // - /absolute/path/to/file.xml (Unix/Linux/Mac absolute path)
        // - C:\path\to\file.xml (Windows absolute path)
        // - C:/path/to/file.xml (Windows absolute path with forward slash)
        boolean isDirectFileSystemPath = xmlFilePath.startsWith("file:") || 
                                         xmlFilePath.startsWith("/") || 
                                         (xmlFilePath.length() >= 2 && xmlFilePath.charAt(1) == ':' && 
                                          (xmlFilePath.charAt(2) == '\\' || xmlFilePath.charAt(2) == '/')) ||
                                         (!xmlFilePath.startsWith("classpath:") && !xmlFilePath.startsWith("http"));
        
        if (isDirectFileSystemPath) {
            String filePath = xmlFilePath.startsWith("file:") ? xmlFilePath.substring(5) : xmlFilePath;
            // Windows path'lerinde file: prefix'i sonrası /C:/ gibi olabilir, bunu düzelt
            if (filePath.startsWith("/") && filePath.length() > 3 && filePath.charAt(2) == ':') {
                filePath = filePath.substring(1); // Baştaki /'yi kaldır (file:/C:/ -> C:/)
            }
            File file = new File(filePath);
            if (!file.exists()) {
                throw new IllegalStateException("KamuSM XML dosyasi bulunamadi: " + filePath);
            }
            if (!file.isFile()) {
                throw new IllegalStateException("Belirtilen yol bir dosya degil: " + filePath);
            }
            try (FileInputStream fis = new FileInputStream(file)) {
                byte[] bytes = IOUtils.toByteArray(fis);
                return new String(bytes, StandardCharsets.UTF_8);
            }
        }
        
        // Classpath veya diğer Spring Resource formatları için
        Resource resource = resourceLoader.getResource(xmlFilePath);
        if (!resource.exists()) {
            throw new IllegalStateException("KamuSM XML dosyasi bulunamadi: " + xmlFilePath);
        }
        try (InputStream inputStream = resource.getInputStream()) {
            byte[] bytes = IOUtils.toByteArray(inputStream);
            return new String(bytes, StandardCharsets.UTF_8);
        }
    }
}
