package io.mersel.dss.signer.api.services;

import org.apache.commons.io.IOUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import eu.europa.esig.dss.model.x509.CertificateToken;

/**
 * KamuSM XML Deposu Online Resolver
 * İnternet üzerinden KamuSM sertifika deposunu indirir ve yönetir.
 * http://depo.kamusm.gov.tr/depo/SertifikaDeposu.xml
 */
@Service("kamuSMXmlDepoOnlineResolver")
public class KamuSMXmlDepoOnlineResolver extends AbstractKamuSMXmlDepoResolver {

    private static final String DEFAULT_URL = "http://depo.kamusm.gov.tr/depo/SertifikaDeposu.xml";
    
    private final RestTemplate restTemplate;
    private final ResourceLoader resourceLoader;
    private final String rootUrl;

    public KamuSMXmlDepoOnlineResolver(RestTemplateBuilder restTemplateBuilder,
                                        ResourceLoader resourceLoader,
                                        @Value("${kamusm.root.url:" + DEFAULT_URL + "}") String rootUrl) {
        this.restTemplate = restTemplateBuilder
                .setReadTimeout(Duration.ofSeconds(10))
                .setConnectTimeout(Duration.ofSeconds(5))
                .build();
        this.resourceLoader = resourceLoader;
        this.rootUrl = rootUrl;
    }

    @Override
    public void refreshTrustedRoots() {
        // Mevcut sertifikaları sakla (başarısız olursa geri yüklemek için)
        List<X509Certificate> previousRoots = new ArrayList<>(trustedRoots.get());
        List<CertificateToken> previousTokens = new ArrayList<>(trustedRootTokens.get());
        
        try {
            logger.info("KamuSM XML deposu online olarak yenileniyor: {}", rootUrl);
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
            logger.info("KamuSM kok sertifikalari basariyla yenilendi ({} adet)", certificates.size());
            
            // Trusted certificate source'u da guncelle
            updateTrustedCertificateSource();
            
        } catch (Exception ex) {
            logger.warn("KamuSM kok sertifikalarini yenileme basarisiz: {} - mevcut liste korunuyor", ex.getMessage());
            logger.debug("Kok sertifika yenileme hata detayi", ex);
            
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
        if (rootUrl.startsWith("classpath:") || rootUrl.startsWith("file:")) {
            Resource resource = resourceLoader.getResource(rootUrl);
            if (!resource.exists()) {
                throw new IllegalStateException("Resource not found: " + rootUrl);
            }
            try (InputStream inputStream = resource.getInputStream()) {
                byte[] bytes = IOUtils.toByteArray(inputStream);
                return new String(bytes, StandardCharsets.UTF_8);
            }
        }
        ResponseEntity<String> response = restTemplate.getForEntity(rootUrl, String.class);
        if (response.getStatusCode() != HttpStatus.OK || response.getBody() == null) {
            logger.warn("KamuSM kok sertifika indirme basarisiz. HTTP durum: {}", response.getStatusCode());
            return null;
        }
        return response.getBody();
    }
}
