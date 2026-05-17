package io.mersel.dss.signer.api.e2e.verifier;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

import java.time.Duration;

/**
 * mersel-dss-verifier-api-java servisinin Testcontainers wrapper'ı.
 *
 * <h3>Neden singleton?</h3>
 * <p>Verifier imajı GHCR'dan ilk pull edildiğinde ~700MB indirir, ardından
 * Spring Boot startup + KamuSM XML deposunu çekip TSL doğrulaması ~30-60sn
 * sürer. Her test sınıfı için yeniden başlatmak gereksiz; tek instance
 * tüm E2E suite boyunca yaşar (JVM kapanırken Ryuk temizler).</p>
 *
 * <h3>Trust anchor stratejisi</h3>
 * <p>Verifier varsayılan olarak {@code TRUSTED_ROOT_RESOLVER_TYPE=kamusm-online}
 * çalışır ve <code>http://depo.kamusm.gov.tr/depo/SertifikaDeposu.xml</code>
 * adresinden güvenilir kökleri çeker. Bizim test PFX'lerinin (testkurum01/02/03)
 * issuer'ları KamuSM'nin TEST CA'larıdır ve onlar da KamuSM XML deposunda
 * yer aldığı için extra mount gerekmez. İnternet bağlantısı zorunludur —
 * air-gapped ortamda bu testler skip edilmeli ya da
 * {@code TRUSTED_ROOT_RESOLVER_TYPE=certificate-folder} ile yeniden
 * yapılandırılmalıdır.</p>
 *
 * <h3>OCSP/CRL revocation kontrolü</h3>
 * <p>Verifier image'ın production default'u {@code signer-strict} profile:
 * imzacı sertifika için OCSP/CRL <strong>zorunlu</strong> (FAIL), ara CA
 * için WARN. Bizim test'lerimiz bu en güvenli senaryonun gerçekten
 * çalıştığını doğrulamak için ek bir override yapmaz:</p>
 * <ul>
 *   <li>{@code ONLINE_VALIDATION_ENABLED=true} — DSS, KamuSM TEST CA'sının
 *       CRL/OCSP uçlarına internet üzerinden gerçek istek atar.</li>
 *   <li>{@code DSS_POLICY_PROFILE=signer-strict} — verifier'ın yayınladığı
 *       production default; explicit set etmiyoruz, sessiz davranış
 *       değişimine karşı dokümantasyon için yorum bırakıyoruz.</li>
 *   <li>{@code DSS_POLICY_PATH} <em>set edilmez</em> — test ile production
 *       arasındaki tek konfigürasyon farkı log seviyesi + heap boyutu
 *       olsun. Test geçerse "default kurulum, default policy ile
 *       Mali Mühür imzalarını doğru doğruluyor" diyebiliriz.</li>
 * </ul>
 *
 * <p><b>Internet bağlantısı zorunludur</b>: hem KamuSM trust anchor XML
 * deposu (startup'ta) hem de CRL/OCSP fetch'leri için. Air-gapped CI
 * runner'larında bu testler skip edilmeli ya da
 * {@code TRUSTED_ROOT_RESOLVER_TYPE=certificate-folder} + offline CRL
 * cache ile yeniden yapılandırılmalıdır.</p>
 *
 * <h3>Yaşam döngüsü</h3>
 * <p>{@link #INSTANCE} ilk erişimde lazy başlatılır. Testcontainers'ın
 * Ryuk container'ı JVM kapanırken process'i temizler; explicit
 * {@code stop()} çağrısına gerek yok.</p>
 */
public final class VerifierApiContainer {

    private static final Logger LOGGER = LoggerFactory.getLogger(VerifierApiContainer.class);

    /**
     * Verifier imajı; default GHCR'daki main tag.
     *
     * <p>Lokal geliştirme sırasında imajı kendin {@code docker build}
     * ile üretip kullanmak istersen:</p>
     *
     * <pre>{@code
     *   cd ~/Projects/.../mersel-dss-verifier-api-java
     *   docker build -t mersel-dss-verifier-api:local -f devops/docker/Dockerfile .
     *   mvn test -DverifierImage=mersel-dss-verifier-api:local ...
     * }</pre>
     *
     * <p>System property {@code verifierImage} default'u override eder. CI'da
     * (özellikle GHCR'de henüz yayınlanmamış bir fix'i test ederken) bu kanca
     * çok faydalı.</p>
     */
    private static final DockerImageName IMAGE = DockerImageName.parse(
            System.getProperty("verifierImage",
                    "ghcr.io/mersel-dss/mersel-dss-verifier-api-java:main"));

    /** Verifier API'nin container içindeki sabit dinleme portu. */
    private static final int CONTAINER_PORT = 8086;

    /**
     * Singleton instance. Static initializer'da değil, {@link #getInstance()}'ta
     * lazy yaratılır — testler hiç çağırmazsa container hiç ayağa kalkmaz.
     */
    private static volatile GenericContainer<?> INSTANCE;

    private VerifierApiContainer() {
        // utility class
    }

    /**
     * Singleton container'a erişim sağlar; gerektiğinde başlatır.
     *
     * @return başlatılmış (ve health check'i geçmiş) verifier container
     */
    public static synchronized GenericContainer<?> getInstance() {
        if (INSTANCE == null) {
            INSTANCE = createContainer();
            LOGGER.info("Verifier API container başlatılıyor (imaj: {})...", IMAGE);
            INSTANCE.start();
            LOGGER.info("Verifier API hazır → {}", baseUrl());
        }
        return INSTANCE;
    }

    /**
     * Doğrulama isteklerinin gönderileceği base URL ({@code http://host:port}).
     * Container'ın map ettiği random host portunu döner.
     */
    public static String baseUrl() {
        GenericContainer<?> c = getInstance();
        return "http://" + c.getHost() + ":" + c.getMappedPort(CONTAINER_PORT);
    }

    private static GenericContainer<?> createContainer() {
        return new GenericContainer<>(IMAGE)
                .withExposedPorts(CONTAINER_PORT)
                .withEnv("SERVER_PORT", String.valueOf(CONTAINER_PORT))
                // KamuSM online resolver default; test PFX'lerinin kökü zaten
                // o depoda var. Override etmek isteyenler için açık bırakıyoruz.
                .withEnv("TRUSTED_ROOT_RESOLVER_TYPE", "kamusm-online")
                // Production default + maksimum güvenlik: imzacı için
                // OCSP/CRL gerçekten çekilsin ve doğrulansın. signer-strict
                // profile (verifier default) imzacı revocation'ı FAIL olarak
                // tutuyor; bu env olmadan her doğrulama
                // INDETERMINATE/NO_REVOCATION_DATA döner.
                .withEnv("ONLINE_VALIDATION_ENABLED", "true")
                // DSS_POLICY_PROFILE explicit set edilmiyor → verifier
                // image'ın yayınladığı default ("signer-strict") kullanılır.
                // Üretimde de aynı kombosyon koşar. Override gerekirse:
                //   .withEnv("DSS_POLICY_PROFILE", "strict") veya
                //   .withCopyFileToContainer(...) + .withEnv("DSS_POLICY_PATH", ...)
                // Testlerde noisy log istemiyoruz; WARN yeterli.
                .withEnv("LOG_LEVEL", "WARN")
                // Daha düşük heap — CI/local dev makinelerine dost.
                .withEnv("JAVA_OPTS", "-Xmx512m -Xms256m -XX:+UseG1GC")
                // Spring Boot Actuator health endpoint'ini bekle. Hazır
                // olunca DSS bean'leri ayakta + KamuSM XML deposu yüklenmiş
                // demektir (kamusm-online resolver bunu startup'ta yapar).
                .waitingFor(Wait.forHttp("/actuator/health")
                        .forStatusCode(200)
                        .forResponsePredicate(body -> body != null && body.contains("\"UP\""))
                        .withStartupTimeout(Duration.ofMinutes(3)))
                .withLogConsumer(new Slf4jLogConsumer(LOGGER).withPrefix("verifier-api"));
    }
}
