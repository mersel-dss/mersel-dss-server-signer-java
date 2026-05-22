package io.mersel.dss.signer.api.config;

import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.validation.RevocationDataVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
import eu.europa.esig.dss.xades.signature.XAdESSigningTimeZoneHolder;
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
import io.mersel.dss.signer.api.services.keystore.iaik.IaikPkcs11Module;
import io.mersel.dss.signer.api.services.KamusmRootCertificateService;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;

import java.security.cert.X509Certificate;
import java.time.ZoneId;
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

    private static final org.slf4j.Logger LOGGER =
            org.slf4j.LoggerFactory.getLogger(SignatureConfiguration.class);

    public SignatureConfiguration(SignatureServiceConfiguration config,
                                 KamusmRootCertificateService rootCertificateService) {
        this.config = config;
        this.rootCertificateService = rootCertificateService;
        
        // DSS OCSP için GET metodu kullanımını etkinleştir
        System.setProperty("dss.http.use.get.for.ocsp", "true");

        configureXadesSigningTimeZone();
    }

    /**
     * XAdES {@code <SigningTime>} timezone'unu Spring config'ten okuyup DSS
     * override builder'ın gördüğü statik holder'a yansıtır. Spring container
     * dışında çalışan testlerde holder default'ta ({@code +03:00}) kalır.
     *
     * <p>Geçersiz timezone string'i fail-fast davranır: container açılışta
     * patlar, üretimde sessizce yanlış formatta imza üretmek yerine erken
     * hata.</p>
     */
    private void configureXadesSigningTimeZone() {
        ZoneId zone = config.getXadesSigningTimeZone();
        XAdESSigningTimeZoneHolder.setZone(zone);
        LOGGER.info("XAdES SigningTime timezone yapılandırıldı: {} (raw='{}')",
                zone, config.getXadesSigningTimeZoneRaw());
    }

    /**
     * KeyStore sağlayıcısı bean'i.
     *
     * <p>Konfigürasyon tarafından hangi yol seçilirse o sağlayıcı üretilir:
     * <ul>
     *   <li>PKCS#11 ({@code PKCS11_LIBRARY}) → {@link PKCS11KeyStoreProvider}.
     *       Bu sağlayıcı artık <b>sadece listing'in eski JCA fallback yolu</b>
     *       için var; gerçek imzalama akışı {@link IaikPkcs11Module} üzerinden
     *       yürütülür.</li>
     *   <li>PFX ({@code PFX_PATH}) → {@link PfxKeyStoreProvider}.</li>
     * </ul>
     * </p>
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
     * IAIK PKCS#11 modülü — yalnızca {@code PKCS11_LIBRARY} property'si
     * <b>boş olmayan</b> bir değer içeriyorsa Spring container'da bean
     * olarak yaratılır.
     *
     * <p><b>Neden {@link ConditionalOnExpression}?</b> Spring Boot'un
     * {@code @ConditionalOnProperty(name = "X")} davranışı: property
     * <em>tanımlı</em> ve değeri {@code "false"} değilse bean'i aktive
     * eder. Yani {@code PKCS11_LIBRARY=} (boş string) ya da
     * {@code PKCS11_LIBRARY=   } (whitespace) durumunda bean aktive olur
     * ve {@link IaikPkcs11Module} boş library path ile startup'ta patlar.</p>
     *
     * <p>{@code StringUtils.hasText} ile null + boş + whitespace
     * vakalarının üçü de elenir. Bu, container ortamlarında env var'ı
     * boş bırakma (örn. {@code -e PKCS11_LIBRARY=}) hatasının erken
     * yakalanmasını sağlar.</p>
     *
     * <p>Inisializasyon sırasında native kütüphane yüklenir, token açılır ve
     * USER ile login olunur. Spring yaşam döngüsünden çıkarken
     * {@code destroyMethod="destroy"} otomatik çağrılır ve token temiz
     * kapatılır.</p>
     *
     * <p>PFX yapılandırmasında bu bean container'da YOK demektir; aşağıdaki
     * {@link #signingMaterial} bean'i {@link ObjectProvider} üzerinden
     * yokluğu algılar ve PFX yoluna düşer.</p>
     */
    @Bean(destroyMethod = "destroy")
    @ConditionalOnExpression("#{T(org.springframework.util.StringUtils).hasText('${PKCS11_LIBRARY:}')}")
    public IaikPkcs11Module iaikPkcs11Module() {
        char[] pin = config.getCertificatePin().toCharArray();
        Long slot = sanitizeSlotConfig(config.getPkcs11Slot());
        Long slotIndex = sanitizeSlotConfig(config.getPkcs11SlotIndex());

        // MAX_SESSION_COUNT hem Spring semaphore'a hem de IAIK PKCS11Token
        // internal pool'una aynı değeri besler. Tek-slider model: operatör
        // için tek tavan kavramı, mismatch riski yok. Detaylı gerekçe için
        // SignatureServiceConfiguration.maxSessionCount Javadoc'una bakın.
        //
        // AKİS yolunda (forceNullInitArgs=true) IaikPkcs11Module bu değeri
        // yoksayıp her zaman numSessions=1 kullanır (PKCS#11 §5.4 güvenlik
        // önceliği). Bu güvenlik kararı modül içinde verilir — burada özel
        // bir branch'a gerek yok.
        return new IaikPkcs11Module(
            config.getPkcs11LibraryPath(),
            slot,
            slotIndex,
            pin,
            config.isPkcs11NullInitArgs(),
            config.getMaxSessionCount());
    }

    /** {@code PKCS11_SLOT:-1} default convention'ını {@code null}'a normalize eder. */
    private static Long sanitizeSlotConfig(Long raw) {
        return raw != null && raw >= 0 ? raw : null;
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
     * Singleton {@link SigningContext} — başlangıçta bir kez çözümlenir.
     *
     * <p>Backend seçimi: container'da {@link IaikPkcs11Module} bean'i varsa
     * HSM yolu, yoksa PFX yolu kullanılır.
     * {@link ObjectProvider#getIfAvailable()} bean yokluğunu temiz şekilde
     * algılamamızı sağlar.</p>
     */
    @Bean
    public SigningContext signingContext(SigningMaterialFactory factory,
                                         KeyStoreProvider keyStoreProvider,
                                         ObjectProvider<IaikPkcs11Module> iaikModuleProvider) {
        IaikPkcs11Module iaikModule = iaikModuleProvider.getIfAvailable();
        if (iaikModule != null) {
            return factory.createPkcs11SigningContext(
                iaikModule,
                config.getCertificateAlias(),
                config.getCertificateSerialNumber());
        }

        char[] pin = config.getCertificatePin().toCharArray();
        return factory.createPfxSigningContext(
            keyStoreProvider,
            pin,
            config.getCertificateAlias(),
            config.getCertificateSerialNumber());
    }

    /**
     * Uygulama için ana imzalama materyalini sağlar.
     * Başlangıçta bir kez oluşturulur ve tüm imzalama işlemleri için tekrar kullanılır.
     */
    @Bean
    public SigningMaterial signingMaterial(SigningContext signingContext) {
        return signingContext.getMaterial();
    }

    /**
     * Keystore işlemleri için imzalama alias'ını sağlar.
     */
    @Bean
    public String signingAlias(SigningContext signingContext) {
        return signingContext.getAlias();
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

    /**
     * Sertifika doğrulayıcı ile yapılandırılmış CAdES servisini sağlar.
     */
    @Bean
    public eu.europa.esig.dss.cades.signature.CAdESService cadesService(CertificateVerifier certificateVerifier) {
        return new eu.europa.esig.dss.cades.signature.CAdESService(certificateVerifier);
    }
}

