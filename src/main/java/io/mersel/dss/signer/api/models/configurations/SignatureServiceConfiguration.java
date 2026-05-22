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

    @Value("${MA3API_LICENSE_PATH:0}")
    private String ma3apiLicensePath;

    @Value("${MAX_SESSION_COUNT:5}")
    private int maxSessionCount;

    /**
     * SafeNet HSM ailesinde gözlenen idle-time secure channel teardown
     * davranışını (vendor hata kodu {@code CKR_NO_SESSION_KEYS = 0x80000387})
     * önlemek için periyodik gerçek {@code C_Sign} heartbeat'i aktive eder.
     *
     * <p>Default {@code false} (opt-in). PFX modunda bayrak aktif edilse bile
     * ilgili scheduler bean'i Spring container'da yaratılmaz — etkisizdir.
     * SafeNet Luna / ProtectServer kullanıcıları için tipik üretim ayarı:
     * {@code HSM_HEARTBEAT_ENABLED=true}.</p>
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

    public String getMa3apiLicensePath() {
        return ma3apiLicensePath;
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