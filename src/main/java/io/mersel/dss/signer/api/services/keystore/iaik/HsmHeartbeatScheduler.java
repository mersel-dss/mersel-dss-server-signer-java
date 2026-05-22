package io.mersel.dss.signer.api.services.keystore.iaik;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import io.mersel.dss.signer.api.models.SigningMaterial;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.concurrent.atomic.AtomicLong;

/**
 * SafeNet HSM ailesinde gözlenen idle-time secure channel teardown
 * davranışını önleyen periyodik gerçek-imza heartbeat'i.
 *
 * <h2>Neden var?</h2>
 * <p>SafeNet Luna / ProtectServer / ProtectToolkit HSM'lerinde client ile
 * HSM arasındaki secure messaging session-key'leri belirli bir idle
 * süresinden sonra HSM tarafında reap edilir. Bir sonraki kullanıcı
 * isteğinde xipki {@code PKCS11Token} havuzdan cached session handle'ı
 * verir, üstüne {@code Session.login()} çağrılır ve HSM tarafında secure
 * channel zaten yıkıldığı için secure messaging key türetimi başarısız
 * olur. Sonuç: vendor hata kodu {@code CKR_NO_SESSION_KEYS = 0x80000387}.</p>
 *
 * <p>Operasyon ekipleri tarihsel olarak bunu dışarıdan periyodik bir cron
 * script'i (boş XML imzala) ile çözdü. Bu scheduler aynı stratejiyi
 * uygulama içine taşır: konfigürasyon-tabanlı, opt-in, operasyonel bus
 * factor'ünü azaltır, dış sistem bağımlılığı yok.</p>
 *
 * <h2>Aktivasyon koşulu</h2>
 * <ol>
 *   <li>{@code PKCS11_LIBRARY} dolu — yani HSM yolu kullanılıyor</li>
 *   <li>{@code HSM_HEARTBEAT_ENABLED=true} — operatör explicit olarak açtı</li>
 * </ol>
 * <p>Her iki koşul karşılanmadığında bean container'da yaratılmaz; PFX
 * kullanıcıları ve heartbeat'i istemeyen operatörler için sıfır maliyet.</p>
 *
 * <h2>Hata davranışı</h2>
 * <p>Heartbeat sign'i kendisi {@code CKR_NO_SESSION_KEYS} veya benzer bir
 * hata aldığında: WARN log + counter artırılır, scheduler crash etmez.
 * Bir sonraki interval'da tekrar denenir — pratikte başarısız ilk çağrı
 * HSM tarafında secure channel'ı re-init eder ve takip eden çağrılar
 * başarılı olur. Üst üste 5 başarısız heartbeat → ERROR (alerting hook).</p>
 *
 * <h2>Concurrency</h2>
 * <p>{@code @Scheduled} fixedDelay kullanır: önceki heartbeat tamamlanmadan
 * yeni iteration başlamaz. Heartbeat üst seviye {@code signatureSemaphore}
 * permit tüketmez — yoğun yük altında aç kalmamalı.</p>
 */
@Component
@ConditionalOnExpression(
    "#{T(org.springframework.util.StringUtils).hasText('${PKCS11_LIBRARY:}')"
    + " && '${HSM_HEARTBEAT_ENABLED:false}' == 'true'}")
public class HsmHeartbeatScheduler {

    private static final Logger LOGGER = LoggerFactory.getLogger(HsmHeartbeatScheduler.class);

    /**
     * Üst üste başarısız heartbeat sayısı bu eşiği geçtiğinde ERROR
     * seviyesine yükseltilir; future-extension: alerting hook'a bağlanır.
     */
    private static final int CONSECUTIVE_FAILURE_ERROR_THRESHOLD = 5;

    private final IaikPkcs11Module module;
    private final long privateKeyHandle;
    private final SignatureAlgorithm signatureAlgorithm;
    private final String alias;

    private final AtomicLong successCount = new AtomicLong();
    private final AtomicLong failureCount = new AtomicLong();
    private final AtomicLong consecutiveFailures = new AtomicLong();
    private volatile long lastSuccessAtMillis = 0L;

    public HsmHeartbeatScheduler(IaikPkcs11Module module,
                                 SigningMaterial signingMaterial,
                                 @Value("${HSM_HEARTBEAT_INTERVAL_SECONDS:60}")
                                 int intervalSeconds) {
        this.module = module;
        if (!signingMaterial.isPkcs11()) {
            // Defensive: @ConditionalOnExpression PKCS11_LIBRARY varlığına
            // bakar ama signingMaterial nihai backend kararını verir. PFX'e
            // düşmüşsek (örn. PKCS11 init başarısız ve fallback yoksa) bu
            // scheduler hiç çalışmamalı — bu durum konfigürasyon hatasıdır.
            throw new IllegalStateException(
                "HsmHeartbeatScheduler aktive edildi ama SigningMaterial PKCS#11 değil; "
                + "konfigürasyon tutarsız. HSM_HEARTBEAT_ENABLED yalnızca PKCS#11 yolu "
                + "etkin olduğunda aktive edilmelidir.");
        }
        Pkcs11Signer signer = signingMaterial.getPkcs11Signer();
        if (!(signer instanceof IaikPkcs11Signer)) {
            // ipkcs11wrapper dışında bir signer implementasyonu pratik
            // olarak yok (Pkcs11Signer tek implementasyonu IaikPkcs11Signer);
            // ileride değişirse explicit hata mesajı görsün.
            throw new IllegalStateException(
                "Beklenmeyen Pkcs11Signer implementasyonu: "
                + signer.getClass().getName() + ". HsmHeartbeatScheduler yalnızca "
                + "IaikPkcs11Signer ile uyumludur.");
        }
        this.privateKeyHandle = ((IaikPkcs11Signer) signer).getPrivateKeyHandle();
        this.alias = signer.getAlias();
        this.signatureAlgorithm = deriveAlgorithm(signer);
        LOGGER.info("HSM heartbeat scheduler aktive edildi: alias='{}', alg={}, intervalSeconds={}",
            alias, signatureAlgorithm, intervalSeconds);
    }

    /**
     * Sertifikanın public key tipinden + SHA-256 digest'inden DSS
     * {@link SignatureAlgorithm} türetir. RSA ve ECDSA'nın her ikisi de
     * tüm modern HSM'lerde universal destekli — heartbeat için ek mekanizma
     * uyumluluk problemi yaratmaz.
     */
    private static SignatureAlgorithm deriveAlgorithm(Pkcs11Signer signer) {
        EncryptionAlgorithm enc = EncryptionAlgorithm.forKey(signer.getCertificate().getPublicKey());
        SignatureAlgorithm sa = SignatureAlgorithm.getAlgorithm(enc, DigestAlgorithm.SHA256);
        if (sa == null) {
            throw new IllegalStateException(
                "Heartbeat için SignatureAlgorithm türetilemedi: enc=" + enc
                + ". HSM sertifikasının public key tipi desteklenmiyor olabilir.");
        }
        return sa;
    }

    /**
     * Periyodik heartbeat tetikleyici.
     *
     * <p>{@code fixedDelayString} ile saniye → ms dönüşümü yapılır;
     * {@code initialDelayString} startup race'i önler (token init/login
     * tamamlanmadan heartbeat tetiklenirse {@code CKR_USER_NOT_LOGGED_IN}
     * gibi gürültülü hatalar üretir).</p>
     */
    @Scheduled(
        fixedDelayString = "#{${HSM_HEARTBEAT_INTERVAL_SECONDS:60} * 1000}",
        initialDelayString = "15000")
    public void heartbeat() {
        long t0 = System.currentTimeMillis();
        try {
            module.heartbeatSign(privateKeyHandle, signatureAlgorithm);
            long elapsed = System.currentTimeMillis() - t0;
            long s = successCount.incrementAndGet();
            long priorConsecutiveFailures = consecutiveFailures.getAndSet(0);
            lastSuccessAtMillis = System.currentTimeMillis();
            if (priorConsecutiveFailures > 0) {
                // Failure -> success state change: operatör için kritik bir
                // sinyaller (HSM secure channel kendini iyileştirdi).
                LOGGER.info("HSM heartbeat RECOVERED: alias='{}', alg={}, elapsed={}ms, "
                    + "öncesindeki ardışık başarısızlık={}, totalSuccess={}, totalFail={}",
                    alias, signatureAlgorithm, elapsed,
                    priorConsecutiveFailures, s, failureCount.get());
            } else {
                LOGGER.info("HSM heartbeat OK: alias='{}', alg={}, elapsed={}ms, totalSuccess={}",
                    alias, signatureAlgorithm, elapsed, s);
            }
        } catch (Exception e) {
            long f = failureCount.incrementAndGet();
            long c = consecutiveFailures.incrementAndGet();
            // İlk hata WARN; eşik aşılınca ERROR (monitoring/alert kancası).
            if (c >= CONSECUTIVE_FAILURE_ERROR_THRESHOLD) {
                LOGGER.error("HSM heartbeat ÜST ÜSTE BAŞARISIZ ({}x): alias='{}', alg={}, "
                    + "totalFail={}, son hata='{}'. HSM durumu kontrol edilmeli "
                    + "(secure channel / partition / firmware).",
                    c, alias, signatureAlgorithm, f, e.getMessage());
            } else {
                LOGGER.warn("HSM heartbeat başarısız (denenenecek): alias='{}', alg={}, "
                    + "totalFail={}, hata='{}'",
                    alias, signatureAlgorithm, f, e.getMessage());
            }
            // ASLA throw etme — Spring scheduler exception fırlatan task'ı
            // pool'dan düşürmez ama ardışık iteration'larda da exception
            // fırlatırsa log spam'i yaratır. Sessizce devam etmek doğru.
        }
    }

    // ----------------------------------------------------------------
    // Observability (test + future Micrometer hook)
    // ----------------------------------------------------------------

    public long getSuccessCount() {
        return successCount.get();
    }

    public long getFailureCount() {
        return failureCount.get();
    }

    public long getConsecutiveFailureCount() {
        return consecutiveFailures.get();
    }

    public long getLastSuccessAtMillis() {
        return lastSuccessAtMillis;
    }
}
