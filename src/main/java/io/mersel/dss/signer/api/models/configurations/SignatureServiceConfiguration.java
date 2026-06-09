package io.mersel.dss.signer.api.models.configurations;

import eu.europa.esig.dss.xades.signature.XAdESSigningTimeZoneHolder;
import io.mersel.dss.signer.api.services.timestamp.tubitak.TubitakTspDetector;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.ZoneId;

@Component
public class SignatureServiceConfiguration {

    @Value("${PFX_PATH:}")
    private String pfxPath;

    @Value("${PKCS11_LIBRARY:}")
    private String pkcs11LibraryPath;

    @Value("${PKCS11_SLOT:-1}")
    private Long pkcs11Slot;

    @Value("${PKCS11_SLOT_LIST_INDEX:-1}")
    private Long pkcs11SlotIndex;

    /**
     * TÜBİTAK BİLGEM AKİS macOS/Linux sürücüsü gibi standart
     * {@code C_Initialize(CK_C_INITIALIZE_ARGS{flags=CKF_OS_LOCKING_OK})}
     * çağrısını {@code CKR_ARGUMENTS_BAD} ile reddeden kütüphaneler için
     * trial-and-error yapmadan doğrudan {@code C_Initialize(NULL)} yoluna
     * gidilir. Auto-detect zaten devrede; bu bayrak yalnızca operatöre
     * "ben biliyorum, hemen NULL'a git" demek için.
     *
     * <p>Yan etki: kütüphane PKCS#11 v2.40 §5.4 gereği thread-unsafe
     * sayılacağı için {@code PKCS11Token} havuzu {@code numSessions=1}'e
     * sıkıştırılır. Akıllı kart donanımı paralel oturum kaldırmadığı için
     * pratik bir performans kaybı yoktur.</p>
     */
    @Value("${PKCS11_NULL_INIT_ARGS:false}")
    private boolean pkcs11NullInitArgs;

    // ====================================================================
    // PKCS#11 köprü (out-of-process helper) yapılandırması
    // --------------------------------------------------------------------
    // JVM ile PKCS#11 DLL bit'liği uyuşmadığında (örn. 64-bit JVM + 32-bit
    // mali mühür DLL'i) native kütüphane ana process'e yüklenemez. Bu durumda
    // DLL'i kendi bit'liğinde yükleyen ayrı bir helper JVM başlatılır ve imza
    // çağrıları loopback IPC ile ona iletilir. Ağır DSS belge işleme 64-bit
    // ana process'te kaldığı için 32-bit helper'ın dar adres alanı sorun olmaz.
    // ====================================================================

    /**
     * Köprü stratejisi: {@code auto} (default; bit'lik karşılaştır),
     * {@code in-process} (her zaman ana JVM'e yükle) veya {@code remote}
     * (her zaman helper kullan).
     */
    @Value("${PKCS11_BRIDGE_MODE:auto}")
    private String pkcs11BridgeMode;

    /**
     * Helper process'i başlatacak {@code java} çalıştırılabilirinin yolu —
     * DLL'in bit'liğine uygun olmalı (örn. 32-bit DLL için 32-bit JRE'nin
     * {@code java.exe}'si). Remote moda düşülür ve bu boşsa startup fail-fast.
     */
    @Value("${PKCS11_HELPER_JAVA:}")
    private String pkcs11HelperJava;

    /** Helper JVM argümanları (boşlukla ayrılmış). Default dar heap. */
    @Value("${PKCS11_HELPER_JVM_OPTS:-Xmx256m}")
    private String pkcs11HelperJvmOpts;

    /** Helper classpath'i. Boşsa ana process'in {@code java.class.path}'i kullanılır (fat-jar). */
    @Value("${PKCS11_HELPER_CLASSPATH:}")
    private String pkcs11HelperClasspath;

    /** Helper başlatma yöntemi: {@code auto} | {@code propertieslauncher} | {@code direct}. */
    @Value("${PKCS11_HELPER_LAUNCHER:auto}")
    private String pkcs11HelperLauncher;

    /** Loopback bind host'u (helper + client). Default güvenli loopback. */
    @Value("${PKCS11_BRIDGE_HOST:127.0.0.1}")
    private String pkcs11BridgeHost;

    /** Helper'ın READY vermesi için beklenecek azami süre (ms). */
    @Value("${PKCS11_HELPER_READY_TIMEOUT_MS:30000}")
    private int pkcs11HelperReadyTimeoutMs;

    /** Helper'a bağlanma timeout'u (ms). */
    @Value("${PKCS11_HELPER_CONNECT_TIMEOUT_MS:5000}")
    private int pkcs11HelperConnectTimeoutMs;

    /** Helper'dan yanıt okuma timeout'u (ms) — HSM round-trip + reinit penceresi için cömert. */
    @Value("${PKCS11_HELPER_READ_TIMEOUT_MS:60000}")
    private int pkcs11HelperReadTimeoutMs;

    @Value("${CERTIFICATE_PIN}")
    private String certificatePin;

    @Value("${CERTIFICATE_SERIAL_NUMBER:}")
    private String certificateSerialNumber;

    @Value("${CERTIFICATE_ALIAS:}")
    private String certificateAlias;

    @Value("${CERTIFICATE_CHAIN_GET_ONLINE:true}")
    private boolean certificateChainGetOnline;

    @Value("${ISSUER_CERTIFICATE_PATH:/}")
    private String issuerCertificatePath;

    @Value("${CA_CERTIFICATE_PATH:/}")
    private String caCertificatePath;

    @Value("${TS_SERVER_HOST:http://zd.kamusm.gov.tr}")
    private String timeStampServerHost;

    @Value("${TS_DIGEST_ALGORITHM:SHA-256}")
    private String timeStampDigestAlgorithm;

    @Value("${TS_USER_ID:0}")
    private String timeStampUserId;

    @Value("${TS_USER_PASSWORD:0}")
    private String timeStampUserPassword;

    @Value("${IS_TUBITAK_TSP:false}")
    private boolean isTubitakTsp;

    /**
     * Eş zamanlı imza tavanı — tek bir kavram, iki katmanda uygulanır:
     *
     * <ol>
     *   <li><b>Spring semaphore</b> — pipeline'a giriş bileti
     *       ({@link io.mersel.dss.signer.api.config.SignatureConfiguration#signatureSemaphore()}).
     *       Hem PFX hem HSM yolunda geçerli.</li>
     *   <li><b>IAIK PKCS11Token internal pool</b> — wrapper'ın
     *       {@code numSessions} ctor parametresine geçirilir. Sadece HSM
     *       yolunda anlamlı; PFX yolunda yoksayılır.</li>
     * </ol>
     *
     * <p>Aynı değerin iki katmana da uygulanması <b>kasıtlı</b>: operatör
     * için tek-slider model, mismatch riski yok. Spring semaphore + wrapper
     * pool ayrı tutulsaydı küçük olan efektif tavanı belirlerdi, büyük olan
     * için ya kuyruk bekleme (tail latency) ya da boşa kapasite olurdu.</p>
     *
     * <h3>Neden bu kadar kritik?</h3>
     * <p>{@code ipkcs11wrapper 1.0.9} {@code PKCS11Token} ctor'unda
     * {@code numSessions=null} verilirse <b>hard cap = 32</b> uygular
     * ({@code Math.min(32, tokenMaxSessionCount)}). {@code MAX_SESSION_COUNT}
     * değerinin {@link io.mersel.dss.signer.api.config.SignatureConfiguration}
     * tarafından wrapper'a explicit geçirilmesi bu sessiz 32-cap'i by-pass
     * eder; yoksa 256 set etseniz bile fiili throughput 32'de tıkanır.</p>
     *
     * <h3>HSM tipine göre önerilen değerler</h3>
     * <ul>
     *   <li><b>1</b> → akıllı kart / TÜBİTAK AKİS USB mali mühür. AKİS yolu
     *       ({@code PKCS11_NULL_INIT_ARGS=true}) bu değeri zaten zorla 1
     *       yapar; operatör 5 set etse bile güvenlik önceliği geçer.</li>
     *   <li><b>5 (default)</b> → muhafazakar; küçük PFX yükü ve test ortamı.</li>
     *   <li><b>32-64</b> → SoftHSM2 yük testi, ProtectServer.</li>
     *   <li><b>64-128</b> → SafeNet Luna Network HSM (HSM-tarafı
     *       {@code htl-cb} ve session quota'sına dikkat).</li>
     *   <li><b>128+</b> → çok nadir; HSM'in raporladığı
     *       {@code tokenMaxSessionCount} üst sınırı zaten kapatır.</li>
     * </ul>
     *
     * <h3>AKİS güvenlik önceliği</h3>
     * <p>{@code PKCS11_NULL_INIT_ARGS=true} aktifken
     * {@link io.mersel.dss.signer.api.services.keystore.iaik.IaikPkcs11Module}
     * <b>her durumda</b> wrapper'a {@code numSessions=1} verir; operatör bu
     * property'yi yüksek set etse bile yoksayılır. PKCS#11 v2.40 §5.4:
     * NULL-init-args modunda kütüphane thread-unsafe sayılır, paralel
     * session yaratmak SIGSEGV / sessiz data corruption riski taşır.</p>
     */
    @Value("${MAX_SESSION_COUNT:5}")
    private int maxSessionCount;

    /**
     * SafeNet / Thales HSM ailesinde gözlenen secure messaging katmanı
     * çöküşlerini (vendor hata kodları:
     * {@code CKR_NO_SESSION_KEYS = 0x80000387} — Luna NTLS idle teardown;
     * {@code CKR_SMS_ERROR = 0x80000384} — PTK-C Secure Messaging System
     * çöküşü, üretimde gözlendi) önlemek için periyodik gerçek
     * {@code C_Sign} heartbeat'i aktive eder.
     *
     * <h2>Self-healing davranışı (v0.6.4+)</h2>
     * <p>Heartbeat 3 ardışık başarısızlığa ulaşırsa
     * {@code IaikPkcs11Module.reinitializeForSmsRecovery} ile Cryptoki
     * global state'ini {@code C_Finalize + C_Initialize} ile yeniden
     * kurar; key handle'ları otomatik refresh eder. Reinit başarısızsa
     * exponential backoff: 0s → 60s → 5dk → 15dk → 30dk cap.</p>
     *
     * <p>Müşteri sign isteği de SMS-aile hata alırsa
     * {@code IaikPkcs11Module.signOnSession(ResolvedKey,...)} tek-shot
     * reinit + retry yapar — heartbeat henüz tetiklenmemişse bile
     * müşteri kısa pencerede recovered sonuç görür.</p>
     *
     * <p>Default {@code false} (opt-in). PFX modunda bayrak aktif edilse bile
     * ilgili scheduler bean'i Spring container'da yaratılmaz — etkisizdir.
     * SafeNet Luna / ProtectServer / Thales PTK-C kullanıcıları için tipik
     * üretim ayarı: {@code HSM_HEARTBEAT_ENABLED=true}.</p>
     */
    @Value("${HSM_HEARTBEAT_ENABLED:false}")
    private boolean hsmHeartbeatEnabled;

    /**
     * Heartbeat sign çağrıları arasındaki saniye cinsinden bekleme süresi.
     * Default 60 sn — SafeNet Luna Network HSM'in tipik NTLS idle reap
     * eşiğinin (25-30 sn) iki katından kısa, ancak gereksiz HSM yükü
     * yaratmayacak kadar büyük.
     *
     * <p>Luna Network HSM yapılandırmaları için 30-45 sn aralığına çekmek
     * uygundur; PCIe / USB / ProtectServer kart için 60 sn yeterlidir.</p>
     */
    @Value("${HSM_HEARTBEAT_INTERVAL_SECONDS:60}")
    private int hsmHeartbeatIntervalSeconds;


    @Value("${CERTSTORE_PATH:SertifikaDeposu.svt}")
    private String certStorePath;

    /**
     * XAdES {@code <SigningTime>} elemanının XML çıktısında kullanılacak
     * zaman dilimi. Default {@code +03:00} — TÜBİTAK MA3 referans çıktısı
     * ve İMZAGER lokal gösterimi ile birebir uyumlu (bkz. issue #7).
     *
     * <p>Desteklenen değerler:</p>
     * <ul>
     *   <li>Sabit ofset: {@code +03:00}, {@code -05:30}</li>
     *   <li>UTC: {@code Z}, {@code UTC}, {@code GMT}</li>
     *   <li>IANA bölge: {@code Europe/Istanbul} (DST destekli)</li>
     * </ul>
     *
     * <p><b>ETSI/EN 319 132-1 saf yorumu</b> {@code Z} ister; bu kullanıcılar
     * için ENV'i {@code Z} olarak set etmek yeterlidir. Default Türkiye
     * ekosistemi gözetilerek {@code +03:00} bırakılmıştır.</p>
     */
    @Value("${XADES_SIGNING_TIME_ZONE:+03:00}")
    private String xadesSigningTimeZone;

    public String getPkcs11LibraryPath() {
        return pkcs11LibraryPath;
    }

    public String getCertificatePin() {
        return certificatePin;
    }

    public String getCertificateSerialNumber() {
        return certificateSerialNumber;
    }

    public String getCertificateAlias() {
        return certificateAlias;
    }

    public Long getPkcs11Slot() {
        return pkcs11Slot;
    }

    public Long getPkcs11SlotIndex() {
        return pkcs11SlotIndex;
    }

    public boolean isPkcs11NullInitArgs() {
        return pkcs11NullInitArgs;
    }

    public String getPkcs11BridgeMode() {
        return pkcs11BridgeMode;
    }

    public String getPkcs11HelperJava() {
        return pkcs11HelperJava;
    }

    public String getPkcs11HelperJvmOpts() {
        return pkcs11HelperJvmOpts;
    }

    public String getPkcs11HelperClasspath() {
        return pkcs11HelperClasspath;
    }

    public String getPkcs11HelperLauncher() {
        return pkcs11HelperLauncher;
    }

    public String getPkcs11BridgeHost() {
        return pkcs11BridgeHost;
    }

    public int getPkcs11HelperReadyTimeoutMs() {
        return pkcs11HelperReadyTimeoutMs;
    }

    public int getPkcs11HelperConnectTimeoutMs() {
        return pkcs11HelperConnectTimeoutMs;
    }

    public int getPkcs11HelperReadTimeoutMs() {
        return pkcs11HelperReadTimeoutMs;
    }

    public String getIssuerCertificatePath() {
        return issuerCertificatePath;
    }

    public String getCaCertificatePath() {
        return caCertificatePath;
    }

    public boolean isCertificateChainGetOnline() {
        return certificateChainGetOnline;
    }

    public String getTimeStampServerHost() {
        return timeStampServerHost;
    }

    public String getTimeStampDigestAlgorithm() {
        return timeStampDigestAlgorithm;
    }

    public String getTimeStampUserId() {
        return timeStampUserId;
    }

    public String getTimeStampUserPassword() {
        return timeStampUserPassword;
    }

    public String getPfxPath() {
        return pfxPath;
    }

    public String getCertStorePath() {
        return certStorePath;
    }

    public int getMaxSessionCount() {
        return maxSessionCount;
    }

    public boolean isHsmHeartbeatEnabled() {
        return hsmHeartbeatEnabled;
    }

    public int getHsmHeartbeatIntervalSeconds() {
        return hsmHeartbeatIntervalSeconds;
    }

    /**
     * Etkin TÜBİTAK modu. {@code IS_TUBITAK_TSP} açıkça {@code true} ise
     * her zaman {@code true}; aksi halde {@code TS_SERVER_HOST} KamuSM
     * zaman damgası endpoint'lerinden birine işaret ediyorsa otomatik
     * olarak {@code true} döner. Operatörün bayrağı set etmeyi
     * unutmasına karşı fail-safe.
     */
    public boolean isTubitakTsp() {
        return TubitakTspDetector.resolveTubitakTspMode(isTubitakTsp, timeStampServerHost);
    }

    /**
     * XAdES {@code <SigningTime>} için yapılandırılmış zaman dilimini ham
     * string olarak döner. Çoğunlukla loglama / observability içindir;
     * çözümlenmiş hâli için {@link #getXadesSigningTimeZone()} kullanın.
     */
    public String getXadesSigningTimeZoneRaw() {
        return xadesSigningTimeZone;
    }

    /**
     * XAdES {@code <SigningTime>} için kullanılacak {@link ZoneId}. Parse
     * başarısız olursa fail-fast: uygulama açılışta hatayla durur, böylece
     * üretimde sessizce yanlış formatta imza üretmek yerine yapılandırma
     * problemi erken yakalanır.
     */
    public ZoneId getXadesSigningTimeZone() {
        return XAdESSigningTimeZoneHolder.parseZone(xadesSigningTimeZone);
    }
}