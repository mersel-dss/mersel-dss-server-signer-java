package io.mersel.dss.signer.api.services;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Güvenilir kök sertifika servisi (wrapper)
 * Üç farklı resolver'ı destekler:
 * - KamuSMXmlDepoOnlineResolver: İnternet üzerinden KamuSM XML deposunu yükler
 * - KamuSMXmlDepoOfflineResolver: Yerel dosyadan KamuSM XML deposunu yükler
 * - CertificateFolderResolver: Klasördeki tüm .crt/.cer dosyalarını yükler
 */
@Service
public class KamusmRootCertificateService {

    private static final Logger logger = LoggerFactory.getLogger(KamusmRootCertificateService.class);
    
    private final TrustedRootCertificateResolver resolver;

    @Autowired
    public KamusmRootCertificateService(
            @Value("${trusted.root.resolver.type:kamusm-online}") String resolverType,
            @Qualifier("kamuSMXmlDepoOnlineResolver") TrustedRootCertificateResolver onlineResolver,
            @Qualifier("kamuSMXmlDepoOfflineResolver") TrustedRootCertificateResolver offlineResolver,
            @Qualifier("certificateFolderResolver") TrustedRootCertificateResolver folderResolver) {
        
        switch (resolverType.toLowerCase()) {
            case "kamusm-online":
                logger.info("Using KamuSM XML Depo Online Resolver");
                this.resolver = onlineResolver;
                break;
            case "kamusm-offline":
                logger.info("Using KamuSM XML Depo Offline Resolver");
                this.resolver = offlineResolver;
                break;
            case "certificate-folder":
            case "folder":
                logger.info("Using Certificate Folder Resolver");
                this.resolver = folderResolver;
                break;
            default:
                logger.warn("Unknown resolver type: {}, defaulting to kamusm-online", resolverType);
                this.resolver = onlineResolver;
        }
    }

    @PostConstruct
    public void init() {
        refreshTrustedRoots();
    }

    @Scheduled(cron = "${trusted.root.refresh-cron:0 15 3 * * *}")
    public void refreshTrustedRoots() {
        resolver.refreshTrustedRoots();
    }

    public List<X509Certificate> getTrustedRoots() {
        return resolver.getTrustedRoots();
    }

    public List<CertificateToken> getTrustedRootTokens() {
        return resolver.getTrustedRootTokens();
    }

    public CommonTrustedCertificateSource getTrustedCertificateSource() {
        return resolver.getTrustedCertificateSource();
    }

    public void addTrustedCertificate(CertificateToken certificate) {
        resolver.addTrustedCertificate(certificate);
    }

    public void addTrustedCertificate(X509Certificate certificate) {
        resolver.addTrustedCertificate(certificate);
    }

    public boolean isTrusted(CertificateToken certificate) {
        return resolver.isTrusted(certificate);
    }
}
