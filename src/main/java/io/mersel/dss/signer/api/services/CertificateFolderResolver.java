package io.mersel.dss.signer.api.services;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Certificate Folder Resolver
 * Belirtilen klasördeki tüm .crt ve .cer dosyalarını güvenilir kök sertifika olarak yükler.
 * Klasördeki tüm sertifika dosyalarını tarar ve yükler.
 */
@Service("certificateFolderResolver")
public class CertificateFolderResolver implements TrustedRootCertificateResolver {

    private static final Logger logger = LoggerFactory.getLogger(CertificateFolderResolver.class);
    
    private final ResourceLoader resourceLoader;
    private final String folderPath;
    private final AtomicReference<List<X509Certificate>> trustedRoots = new AtomicReference<>(Collections.emptyList());
    private final AtomicReference<List<CertificateToken>> trustedRootTokens = new AtomicReference<>(Collections.emptyList());
    
    private CommonTrustedCertificateSource trustedCertificateSource;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public CertificateFolderResolver(ResourceLoader resourceLoader,
                                     @Value("${trusted.root.cert.folder.path:}") String folderPath) {
        this.resourceLoader = resourceLoader;
        // Path'teki baştaki ve sondaki tırnakları temizle (Spring properties'te çift tırnak kullanımı için)
        if (folderPath != null) {
            folderPath = folderPath.trim();
            // Çift tırnak veya tek tırnak ile başlayıp bitiyorsa kaldır
            if ((folderPath.startsWith("\"") && folderPath.endsWith("\"")) ||
                (folderPath.startsWith("'") && folderPath.endsWith("'"))) {
                folderPath = folderPath.substring(1, folderPath.length() - 1);
            }
            // Encoding sorununu çöz: Eğer path ISO-8859-1 olarak yanlış okunduysa UTF-8'e çevir
            try {
                // ISO-8859-1 olarak yanlış okunmuş gibi görünen karakterleri UTF-8'e çevir
                // Örnek: "Ãn" -> "Ön", "HazÄ±rlÄ±k" -> "Hazırlık"
                if (folderPath.contains("Ã") || folderPath.contains("Ä")) {
                    byte[] bytes = folderPath.getBytes("ISO-8859-1");
                    String correctedPath = new String(bytes, "UTF-8");
                    // Eğer düzeltilmiş path Türkçe karakterler içeriyorsa kullan
                    if (correctedPath.contains("Ö") || correctedPath.contains("ö") || 
                        correctedPath.contains("ı") || correctedPath.contains("İ") ||
                        correctedPath.contains("ş") || correctedPath.contains("Ş") ||
                        correctedPath.contains("ğ") || correctedPath.contains("Ğ") ||
                        correctedPath.contains("ü") || correctedPath.contains("Ü") ||
                        correctedPath.contains("ç") || correctedPath.contains("Ç")) {
                        folderPath = correctedPath;
                        logger.debug("Path encoding düzeltildi: {}", folderPath);
                    }
                }
            } catch (Exception e) {
                logger.debug("Path encoding düzeltme hatası: {}", e.getMessage());
            }
        }
        this.folderPath = folderPath;
    }

    @Override
    public void refreshTrustedRoots() {
        // Mevcut sertifikaları sakla (başarısız olursa geri yüklemek için)
        List<X509Certificate> previousRoots = new ArrayList<>(trustedRoots.get());
        List<CertificateToken> previousTokens = new ArrayList<>(trustedRootTokens.get());
        
        try {
            if (folderPath == null || folderPath.trim().isEmpty()) {
                logger.warn("Sertifika klasoru yolu belirtilmemiş. Sertifika yüklenemiyor.");
                return;
            }
            
            logger.info("Sertifika klasorunden güvenilir kök sertifikalar yükleniyor: {}", folderPath);
            
            // Klasör yolunu çöz
            File certFolder = resolveFolderPath(folderPath);
            if (certFolder == null || !certFolder.exists() || !certFolder.isDirectory()) {
                logger.warn("Sertifika klasoru bulunamadi veya bir dizin degil: {}", folderPath);
                return;
            }
            
            List<X509Certificate> certificates = loadCertificatesFromFolder(certFolder);
            if (certificates.isEmpty()) {
                logger.warn("Klasorde sertifika bulunamadi: {}", folderPath);
                return;
            }
            
            List<CertificateToken> tokens = new ArrayList<CertificateToken>(certificates.size());
            for (X509Certificate certificate : certificates) {
                tokens.add(new CertificateToken(certificate));
            }
            trustedRoots.set(Collections.unmodifiableList(certificates));
            trustedRootTokens.set(Collections.unmodifiableList(tokens));
            logger.info("Klasorden {} adet güvenilir kök sertifika yuklendi", certificates.size());
            
            // Trusted certificate source'u da guncelle
            updateTrustedCertificateSource();
            
        } catch (Exception ex) {
            logger.error("Sertifika klasorunden yukleme basarisiz: {} - mevcut liste korunuyor", ex.getMessage(), ex);
            
            // Başarısız olursa önceki sertifikaları geri yükle
            if (!previousRoots.isEmpty()) {
                trustedRoots.set(Collections.unmodifiableList(previousRoots));
                trustedRootTokens.set(Collections.unmodifiableList(previousTokens));
                logger.info("Onceki sertifikalar geri yuklendi ({} adet)", previousRoots.size());
            }
        }
    }

    /**
     * Klasör yolunu çözer (file:, classpath: veya direkt path)
     * Desteklenen formatlar:
     * - file:/path/to/folder (Unix/Linux/Mac)
     * - file:/C:/path/to/folder (Windows)
     * - /absolute/path/to/folder (Unix/Linux/Mac absolute path)
     * - C:\path\to\folder (Windows absolute path)
     * - C:/path/to/folder (Windows absolute path with forward slash)
     */
    private File resolveFolderPath(String path) {
        try {
            if (path.startsWith("file:")) {
                String filePath = path.substring(5);
                // Windows path'lerinde file: prefix'i sonrası /C:/ gibi olabilir, bunu düzelt
                if (filePath.startsWith("/") && filePath.length() > 3 && filePath.charAt(2) == ':') {
                    filePath = filePath.substring(1); // Baştaki /'yi kaldır (file:/C:/ -> C:/)
                }
                return new File(filePath);
            } else if (path.startsWith("classpath:")) {
                Resource resource = resourceLoader.getResource(path);
                if (resource.exists()) {
                    return resource.getFile();
                }
            } else {
                // Direkt dosya yolu (absolute path - Unix/Linux/Mac veya Windows)
                return new File(path);
            }
        } catch (Exception e) {
            logger.warn("Klasor yolu cozulemedi: {}", e.getMessage());
        }
        return null;
    }

    /**
     * Klasördeki tüm .crt ve .cer dosyalarını yükler
     */
    private List<X509Certificate> loadCertificatesFromFolder(File folder) {
        List<X509Certificate> certificates = new ArrayList<X509Certificate>();
        CertificateFactory cf;
        
        try {
            cf = CertificateFactory.getInstance("X.509");
        } catch (Exception e) {
            logger.error("CertificateFactory olusturulamadi: {}", e.getMessage());
            return certificates;
        }
        
        File[] files = folder.listFiles();
        if (files == null) {
            logger.warn("Klasor okunamadi veya bos: {}", folder.getAbsolutePath());
            return certificates;
        }
        
        for (File file : files) {
            if (file.isFile() && (file.getName().toLowerCase().endsWith(".crt") || 
                                  file.getName().toLowerCase().endsWith(".cer") ||
                                  file.getName().toLowerCase().endsWith(".pem"))) {
                try {
                    try (InputStream is = new FileInputStream(file)) {
                        X509Certificate cert = (X509Certificate) cf.generateCertificate(is);
                        certificates.add(cert);
                        logger.debug("Sertifika yuklendi: {} - Subject: {}", 
                            file.getName(), cert.getSubjectDN());
                    }
                } catch (Exception e) {
                    logger.warn("Sertifika dosyasi yuklenemedi: {} - {}", file.getName(), e.getMessage());
                }
            }
        }
        
        return certificates;
    }

    /**
     * Trusted certificate source'u gunceller
     */
    private void updateTrustedCertificateSource() {
        if (trustedCertificateSource == null) {
            trustedCertificateSource = new CommonTrustedCertificateSource();
        }
        
        // Klasörden yüklenen sertifikaları ekle
        for (CertificateToken token : trustedRootTokens.get()) {
            trustedCertificateSource.addCertificate(token);
        }
        
        logger.info("Trusted certificate source updated with {} certificates", 
            trustedCertificateSource.getCertificates().size());
    }

    @Override
    public List<X509Certificate> getTrustedRoots() {
        return trustedRoots.get();
    }

    @Override
    public List<CertificateToken> getTrustedRootTokens() {
        return trustedRootTokens.get();
    }

    @Override
    public CommonTrustedCertificateSource getTrustedCertificateSource() {
        if (trustedCertificateSource == null) {
            updateTrustedCertificateSource();
        }
        return trustedCertificateSource;
    }

    @Override
    public void addTrustedCertificate(CertificateToken certificate) {
        if (trustedCertificateSource == null) {
            trustedCertificateSource = new CommonTrustedCertificateSource();
        }
        trustedCertificateSource.addCertificate(certificate);
        logger.info("Added trusted certificate: {}", certificate.getSubject());
    }

    @Override
    public void addTrustedCertificate(X509Certificate certificate) {
        addTrustedCertificate(new CertificateToken(certificate));
    }

    @Override
    public boolean isTrusted(CertificateToken certificate) {
        if (trustedCertificateSource == null) {
            return false;
        }
        return trustedCertificateSource.getCertificates().contains(certificate);
    }
}

