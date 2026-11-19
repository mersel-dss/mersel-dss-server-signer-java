package io.mersel.dss.signer.api.util;

import io.mersel.dss.signer.api.util.xml.SecureXmlFactories;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

public class Utilities {
    private static final Logger LOGGER = LoggerFactory.getLogger(Utilities.class);

    public static Document LoadXMLFromInputStream(InputStream inputStream) throws ParserConfigurationException, SAXException, IOException {
        DocumentBuilderFactory factory = SecureXmlFactories.newDocumentBuilderFactory();
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(inputStream);
    }

    public static X509Certificate LoadX509Certificate(String filePath) throws Exception {
        try (InputStream in = Files.newInputStream(Paths.get(filePath))) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(in);
        }
    }

    public static void CheckIsDateValid(X509Certificate cert) {
        Date certStartTime = cert.getNotBefore();
        Date certEndTime = cert.getNotAfter();
        Date now = Calendar.getInstance().getTime();

        if (!(now.after(certStartTime) && now.before(certEndTime))) {
            throw new RuntimeException("Certificate is not valid");
        }
    }

    /**
     * Spring {@code @Value} ile gelen bir dosya/klasör yolunu normalize eder:
     * <ul>
     *   <li>baştaki/sondaki eşleşen tek veya çift tırnakları temizler,</li>
     *   <li>yol ISO-8859-1 olarak yanlış decode edilmişse (mojibake) UTF-8'e onarır.</li>
     * </ul>
     * {@code CertificateFolderResolver} ve {@code KamuSMXmlDepoOfflineResolver}
     * aynı mantığı paylaştığı için burada tek noktada toplanmıştır.
     *
     * @param path ham yapılandırma değeri (null olabilir)
     * @return normalize edilmiş yol (girdi null ise null)
     */
    public static String sanitizeConfiguredPath(String path) {
        if (path == null) {
            return null;
        }
        path = path.trim();
        // Çift tırnak veya tek tırnak ile başlayıp bitiyorsa kaldır
        if (path.length() >= 2 &&
                ((path.startsWith("\"") && path.endsWith("\"")) ||
                 (path.startsWith("'") && path.endsWith("'")))) {
            path = path.substring(1, path.length() - 1);
        }
        // Encoding sorununu çöz: path ISO-8859-1 olarak yanlış okunduysa UTF-8'e çevir
        // Örnek: "Ã–n" -> "Ön", "HazÄ±rlÄ±k" -> "Hazırlık"
        try {
            if (path.contains("Ã") || path.contains("Ä")) {
                byte[] bytes = path.getBytes(StandardCharsets.ISO_8859_1);
                String correctedPath = new String(bytes, StandardCharsets.UTF_8);
                if (correctedPath.contains("Ö") || correctedPath.contains("ö") ||
                    correctedPath.contains("ı") || correctedPath.contains("İ") ||
                    correctedPath.contains("ş") || correctedPath.contains("Ş") ||
                    correctedPath.contains("ğ") || correctedPath.contains("Ğ") ||
                    correctedPath.contains("ü") || correctedPath.contains("Ü") ||
                    correctedPath.contains("ç") || correctedPath.contains("Ç")) {
                    path = correctedPath;
                    LOGGER.debug("Yapılandırılan yol encoding düzeltildi: {}", path);
                }
            }
        } catch (Exception e) {
            LOGGER.debug("Yol encoding düzeltme hatası: {}", e.getMessage());
        }
        return path;
    }
}
