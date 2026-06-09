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
import io.mersel.dss.signer.api.services.keystore.iaik.Pkcs11ModulePort;
import io.mersel.dss.signer.api.services.keystore.iaik.bridge.Pkcs11BridgeConditions;
import io.mersel.dss.signer.api.services.keystore.iaik.bridge.Pkcs11HelperProcess;
import io.mersel.dss.signer.api.services.keystore.iaik.bridge.RemotePkcs11Module;
import io.mersel.dss.signer.api.services.KamusmRootCertificateService;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Semaphore;
import java.util.stream.Collectors;

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
    @Conditional(Pkcs11BridgeConditions.InProcess.class)
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

    /**
     * Out-of-process PKCS#11 köprüsü — JVM ile DLL bit'liği uyuşmadığında
     * (auto modda) veya {@code PKCS11_BRIDGE_MODE=remote} verildiğinde aktive
     * olur. DLL'i kendi bit'liğinde yükleyen helper JVM'ini başlatır ve imza
     * çağrılarını ona delege eden {@link RemotePkcs11Module}'ü döndürür.
     *
     * <p>{@link Pkcs11BridgeConditions.InProcess} ile karşılıklı dışlayan —
     * ikisinden en fazla biri container'da bulunur; ikisi de
     * {@link Pkcs11ModulePort} olduğu için {@link #signingContext} ayırt
     * etmek zorunda kalmaz.</p>
     */
    @Bean(destroyMethod = "destroy")
    @Conditional(Pkcs11BridgeConditions.Remote.class)
    public RemotePkcs11Module remotePkcs11Module() {
        String helperJava = config.getPkcs11HelperJava();
        if (!StringUtils.hasText(helperJava)) {
            throw new IllegalStateException(
                "PKCS#11 köprüsü (remote mod) gerekli ama PKCS11_HELPER_JAVA ayarlı değil. "
                + "DLL'in bit'liğine uygun bir java çalıştırılabilirinin yolunu verin "
                + "(örn. 32-bit DLL için 32-bit JRE'nin java'sı).");
        }

        Map<String, String> env = new LinkedHashMap<>();
        env.put("PKCS11_LIBRARY", config.getPkcs11LibraryPath());
        env.put("CERTIFICATE_PIN", config.getCertificatePin());
        if (config.getPkcs11Slot() != null) {
            env.put("PKCS11_SLOT", String.valueOf(config.getPkcs11Slot()));
        }
        if (config.getPkcs11SlotIndex() != null) {
            env.put("PKCS11_SLOT_LIST_INDEX", String.valueOf(config.getPkcs11SlotIndex()));
        }
        env.put("PKCS11_NULL_INIT_ARGS", String.valueOf(config.isPkcs11NullInitArgs()));
        env.put("MAX_SESSION_COUNT", String.valueOf(config.getMaxSessionCount()));
        // Sertifika seçimi + heartbeat helper'da (DLL'e bitişik) çalışır.
        if (StringUtils.hasText(config.getCertificateAlias())) {
            env.put("CERTIFICATE_ALIAS", config.getCertificateAlias());
        }
        if (StringUtils.hasText(config.getCertificateSerialNumber())) {
            env.put("CERTIFICATE_SERIAL_NUMBER", config.getCertificateSerialNumber());
        }
        env.put("HSM_HEARTBEAT_ENABLED", String.valueOf(config.isHsmHeartbeatEnabled()));
        env.put("HSM_HEARTBEAT_INTERVAL_SECONDS", String.valueOf(config.getHsmHeartbeatIntervalSeconds()));

        List<String> jvmOpts = parseJvmOpts(config.getPkcs11HelperJvmOpts());
        String classpath = StringUtils.hasText(config.getPkcs11HelperClasspath())
            ? config.getPkcs11HelperClasspath()
            : System.getProperty("java.class.path");

        Pkcs11HelperProcess helper = new Pkcs11HelperProcess(
            helperJava,
            jvmOpts,
            classpath,
            config.getPkcs11HelperLauncher(),
            config.getPkcs11BridgeHost(),
            config.getPkcs11HelperReadyTimeoutMs(),
            env);
        try {
            helper.start();
        } catch (IOException e) {
            throw new io.mersel.dss.signer.api.exceptions.KeyStoreException(
                "PKCS#11 helper process başlatılamadı: " + e.getMessage(), e);
        }
        return new RemotePkcs11Module(
            helper,
            config.getPkcs11HelperConnectTimeoutMs(),
            config.getPkcs11HelperReadTimeoutMs());
    }

    /** Boşlukla ayrılmış JVM opt string'ini listeye çevirir (boş token'ları eler). */
    private static List<String> parseJvmOpts(String raw) {
        if (!StringUtils.hasText(raw)) {
            return new ArrayList<>();
        }
        return Arrays.stream(raw.trim().split("\\s+"))
            .filter(s -> !s.isEmpty())
            .collect(Collectors.toList());
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
                                         ObjectProvider<Pkcs11ModulePort> pkcs11ModuleProvider) {
        Pkcs11ModulePort pkcs11Module = pkcs11ModuleProvider.getIfAvailable();
        if (pkcs11Module != null) {
            return factory.createPkcs11SigningContext(
                pkcs11Module,
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

