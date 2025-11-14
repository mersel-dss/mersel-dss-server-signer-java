package io.mersel.dss.signer.api.config;

import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.validation.RevocationDataVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
import io.mersel.dss.signer.api.models.SigningContext;
import io.mersel.dss.signer.api.models.SigningMaterial;
import io.mersel.dss.signer.api.models.configurations.SignatureServiceConfiguration;
import io.mersel.dss.signer.api.services.SigningMaterialFactory;
import io.mersel.dss.signer.api.services.certificate.CertificateChainProvider;
import io.mersel.dss.signer.api.services.certificate.LocalCertificateChainProvider;
import io.mersel.dss.signer.api.services.certificate.OnlineCertificateChainProvider;
import io.mersel.dss.signer.api.services.keystore.KeyStoreProvider;
import io.mersel.dss.signer.api.services.keystore.PKCS11KeyStoreProvider;
import io.mersel.dss.signer.api.services.keystore.PfxKeyStoreProvider;
import io.mersel.dss.signer.api.services.KamusmRootCertificateService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Semaphore;

/**
 * İmza servisleri için ana yapılandırma.
 * Elektronik imza işlemleri için gereken tüm bean'leri ayarlar.
 */
@Configuration
public class SignatureConfiguration {

    private final SignatureServiceConfiguration config;
    private final KamusmRootCertificateService rootCertificateService;

    public SignatureConfiguration(SignatureServiceConfiguration config,
                                 KamusmRootCertificateService rootCertificateService) {
        this.config = config;
        this.rootCertificateService = rootCertificateService;
        
        // DSS OCSP için GET metodu kullanımını etkinleştir
        System.setProperty("dss.http.use.get.for.ocsp", "true");
    }

    /**
     * Yapılandırmaya göre KeyStoreProvider sağlar.
     * Library path yapılandırılmışsa PKCS11, yoksa PFX tercih edilir.
     */
    @Bean
    public KeyStoreProvider keyStoreProvider() {
        if (StringUtils.hasText(config.getPkcs11LibraryPath())) {
            return new PKCS11KeyStoreProvider(
                config.getPkcs11LibraryPath(),
                config.getPkcs11Slot(),
                config.getPkcs11SlotIndex()
            );
        }
        
        if (StringUtils.hasText(config.getPfxPath())) {
            return new PfxKeyStoreProvider(config.getPfxPath());
        }
        
        throw new IllegalStateException(
            "Ne PKCS11_LIBRARY ne de PFX_PATH yapılandırılmamış. " +
            "En az bir keystore kaynağı belirtilmelidir.");
    }

    /**
     * Öncelik sırasına göre sertifika zinciri sağlayıcılarını verir.
     */
    @Bean
    public List<CertificateChainProvider> certificateChainProviders() {
        List<CertificateChainProvider> providers = new ArrayList<>();
        
        // Online sağlayıcı (yüksek öncelik)
        if (config.isCertificateChainGetOnline()) {
            providers.add(new OnlineCertificateChainProvider());
        }
        
        // Yerel dosya sağlayıcı (yedek)
        if (StringUtils.hasText(config.getIssuerCertificatePath()) || 
            StringUtils.hasText(config.getCaCertificatePath())) {
            providers.add(new LocalCertificateChainProvider(
                config.getIssuerCertificatePath(),
                config.getCaCertificatePath()
            ));
        }
        
        return providers;
    }

    /**
     * Uygulama için ana imzalama materyalini sağlar.
     * Başlangıçta bir kez oluşturulur ve tüm imzalama işlemleri için tekrar kullanılır.
     */
    @Bean
    public SigningMaterial signingMaterial(SigningMaterialFactory factory,
                                          KeyStoreProvider provider) {
        char[] pin = config.getCertificatePin().toCharArray();
        
        SigningContext context = factory.createSigningContext(
            provider,
            pin,
            config.getCertificateAlias(),
            config.getCertificateSerialNumber()
        );
        
        return context.getMaterial();
    }

    /**
     * Keystore işlemleri için imzalama alias'ını sağlar.
     */
    @Bean
    public String signingAlias(SigningMaterialFactory factory,
                              KeyStoreProvider provider) {
        char[] pin = config.getCertificatePin().toCharArray();
        
        SigningContext context = factory.createSigningContext(
            provider,
            pin,
            config.getCertificateAlias(),
            config.getCertificateSerialNumber()
        );
        
        return context.getAlias();
    }

    /**
     * İmzalama PIN'ini char dizisi olarak sağlar.
     */
    @Bean
    public char[] signingPin() {
        return config.getCertificatePin().toCharArray();
    }

    /**
     * Güvenilir kök sertifikalar listesini sağlar.
     */
    @Bean
    public List<X509Certificate> trustedRootCertificates() {
        return rootCertificateService.getTrustedRoots();
    }

    /**
     * Eşzamanlı imza işlemlerini kontrol etmek için semaphore sağlar.
     */
    @Bean
    public Semaphore signatureSemaphore() {
        return new Semaphore(config.getMaxSessionCount());
    }

    /**
     * Tam yapılandırılmış DSS sertifika doğrulayıcısını sağlar.
     */
    @Bean
    public CertificateVerifier certificateVerifier() {
        CommonCertificateVerifier verifier = new CommonCertificateVerifier();
        
        // Güvenilir sertifika kaynaklarını yapılandır
        CommonTrustedCertificateSource trustedSource = new CommonTrustedCertificateSource();
        rootCertificateService.getTrustedRootTokens()
            .forEach(trustedSource::addCertificate);
        verifier.setTrustedCertSources(trustedSource);

        // Güvenilmeyen zincirler için iptal kontrolünü etkinleştir
        verifier.setCheckRevocationForUntrustedChains(true);

        // İptal verisi doğrulayıcısını yapılandır
        RevocationDataVerifier revocationVerifier = 
            RevocationDataVerifier.createDefaultRevocationDataVerifier();
        Long fiveMinutes = 5 * 60 * 1000L;
        revocationVerifier.setCheckRevocationFreshnessNextUpdate(true);
        revocationVerifier.setSignatureMaximumRevocationFreshness(fiveMinutes);
        revocationVerifier.setTimestampMaximumRevocationFreshness(fiveMinutes);
        revocationVerifier.setRevocationMaximumRevocationFreshness(fiveMinutes);
        verifier.setRevocationDataVerifier(revocationVerifier);

        // İptal yedeklemeyi etkinleştir
        verifier.setRevocationFallback(true);

        // OCSP kaynağını yapılandır
        OnlineOCSPSource ocspSource = new OnlineOCSPSource();
        verifier.setOcspSource(ocspSource);

        // Zincir oluşturma için AIA kaynağını yapılandır
        DefaultAIASource aiaSource = new DefaultAIASource();
        verifier.setAIASource(aiaSource);

        // CRL kaynağını yapılandır
        OnlineCRLSource crlSource = new OnlineCRLSource();
        verifier.setCrlSource(crlSource);

        return verifier;
    }

    /**
     * Sertifika doğrulayıcı ile yapılandırılmış XAdES servisini sağlar.
     */
    @Bean
    public eu.europa.esig.dss.xades.signature.XAdESService xadesService(CertificateVerifier certificateVerifier) {
        return new eu.europa.esig.dss.xades.signature.XAdESService(certificateVerifier);
    }
}

