package io.mersel.dss.signer.api.services.keystore.iaik;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import io.mersel.dss.signer.api.dtos.CertificateInfoDto;
import io.mersel.dss.signer.api.exceptions.KeyStoreException;
import io.mersel.dss.signer.api.services.X509ExtensionInspector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.StringUtils;
import org.xipki.pkcs11.wrapper.AttributeVector;
import org.xipki.pkcs11.wrapper.Mechanism;
import org.xipki.pkcs11.wrapper.PKCS11Constants;
import org.xipki.pkcs11.wrapper.PKCS11Exception;
import org.xipki.pkcs11.wrapper.PKCS11Module;
import org.xipki.pkcs11.wrapper.PKCS11Token;
import org.xipki.pkcs11.wrapper.Slot;
import org.xipki.pkcs11.wrapper.Token;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.pkcs11.wrapper.TokenInfo;

import java.io.ByteArrayInputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * xipki/ipkcs11wrapper (IAIK PKCS#11 Wrapper 1.6.8 kod tabanı) üzerinden HSM
 * ile konuşan tek nokta. Spring container'da singleton bean olarak yaşar.
 *
 * <h2>Neden bu wrapper?</h2>
 * <p>SunPKCS11 P11KeyStore, {@code CKF_LOGIN_REQUIRED} flag'i set olmayan
 * tokenlerde (SafeNet ProtectServer K7, ProtectToolkit ve bazı Luna
 * yapılandırmaları) alias map'i boş bırakıyor; sonuçta {@code keyStore.aliases()}
 * sıfır entry döner ve hem listing hem imza akışı patlar. ipkcs11wrapper bu
 * JCA-soyutlama katmanını tamamen by-pass eder; doğrudan PKCS#11 native
 * köprüsünü kullanarak C_FindObjects / C_Sign çağırır.</p>
 *
 * <h2>Yaşam döngüsü</h2>
 * <ol>
 *   <li>{@link InitializingBean#afterPropertiesSet()} → Module yükle, Slot
 *       seç, {@link PKCS11Token} oluştur (ctor login dahil).</li>
 *   <li>{@link #findSigner(String, String)} → alias veya serial üzerinden
 *       eşleşen private key + cert + zincir bulup {@link Pkcs11Signer} döndür.</li>
 *   <li>{@link #signOnSession(long, byte[], SignatureAlgorithm)} →
 *       (package-private) {@link IaikPkcs11Signer} bu metodu çağırır.</li>
 *   <li>{@link DisposableBean#destroy()} → token kapat (logout dahil), module
 *       finalize.</li>
 * </ol>
 *
 * <h2>Thread-safety</h2>
 * <p>{@link PKCS11Token} kendi içinde session pool ve lock yönetir; imzalama
 * ({@link #signOnSession}) ve nesne okuma ({@link #collectAllRelevantObjects})
 * akışları paralel yürür. Eş zamanlı imza üst sınırı <b>tek bir kavramdır</b>
 * ({@code MAX_SESSION_COUNT}) ve iki katmana aynı değer beslenir:</p>
 * <ol>
 *   <li><b>Spring semaphore</b> — uygulama-seviyesi soft cap.
 *       {@link io.mersel.dss.signer.api.config.SignatureConfiguration#signatureSemaphore()}.
 *       Pipeline'a giriş bileti; PFX ve HSM yollarının ikisinde de geçerli.</li>
 *   <li><b>PKCS11Token internal pool</b> — wrapper-seviyesi hard cap. Ctor'un
 *       {@code numSessions} parametresinden okur. {@code null} verilirse
 *       wrapper {@code Math.min(32, tokenMaxSessionCount)} uygular —
 *       <b>sessiz 32-cap</b>. Bu sınıf, {@code sessionPoolSize > 0} olduğunda
 *       wrapper'a explicit değer geçerek by-pass eder; aksi halde geriye uyumlu
 *       default davranış geçerlidir.</li>
 * </ol>
 * <p>Üretimde {@link io.mersel.dss.signer.api.config.SignatureConfiguration}
 * her iki katmana da {@code MAX_SESSION_COUNT} değerini besler — tek-slider
 * model, mismatch riski yok. Test/CLI yolları kısa ctor'ları kullanır ve
 * wrapper default'una (cap 32) düşer.</p>
 * <p>Yalnızca {@link #destroy()} ve cache yazma
 * ({@link ConcurrentHashMap#computeIfAbsent}) koruma altında.</p>
 *
 * <h2>Acknowledgment</h2>
 * <p>This product includes software developed by IAIK of Graz University of
 * Technology.</p>
 */
public class IaikPkcs11Module implements InitializingBean, DisposableBean, Pkcs11ModulePort {

    private static final Logger LOGGER = LoggerFactory.getLogger(IaikPkcs11Module.class);

    private final String libraryPath;
    private final Long slot;
    private final Long slotIndex;
    private final char[] pin;

    /**
     * Operatör elinde "bu kütüphane standart {@code C_Initialize(args)} kabul
     * etmiyor" bilgisi varsa (TÜBİTAK BİLGEM AKİS macOS sürücüsünün klasik
     * bug'ı) trial-and-error yapmadan doğrudan NULL-args yoluna gitmesini
     * sağlar. Env var: {@code PKCS11_NULL_INIT_ARGS=true}.
     */
    private final boolean forceNullInitArgs;

    /**
     * Per-thread {@link CertificateFactory}. {@code CertificateFactory} JDK
     * specifikasyonunda <em>thread-safe garanti edilmiyor</em>: "Some
     * implementations are thread-safe ... while others are not." SUN sağlayıcı
     * X.509 pratikte güvenli çalışıyor ama production'da paralel cert listing
     * altında nadir parse hatalarına açık kalmamak için ThreadLocal kullanıyoruz.
     * Maliyet: thread başına bir kez factory.getInstance — ihmal edilebilir.
     */
    private static final ThreadLocal<CertificateFactory> CERT_FACTORY =
        ThreadLocal.withInitial(IaikPkcs11Module::createCertFactory);

    private volatile PKCS11Module module;
    private volatile PKCS11Token token;

    /**
     * {@link #reinitializeForSmsRecovery(String, String)} ile {@link #destroy()}
     * arasındaki yarış için ayrı bir monitör. {@code synchronized(this)}
     * {@link #destroy()} tarafından kullanıldığı için reinit'i bağımsız bir
     * lock üzerinde tutuyoruz — destroy reinit ortasında çalışırsa
     * {@code reinitLock} drain edip sonra {@code this} üzerinde temizliği yapar.
     *
     * <p>Bu lock <b>sign çağrılarını engellemez</b>: reinit sırasında
     * in-flight {@code token.sign(...)} çağrıları stale token/module
     * referansıyla yarışır ve çoğu PKCS11Exception ile patlar. Bunlar
     * {@link #signOnSession(ResolvedKey, byte[], SignatureAlgorithm)}
     * tek-shot SMS-aile recovery branch'i tarafından yakalanır ve retry
     * edilir — net etki: müşteri kısa pencerede 1 fail görür ama sonraki
     * istekleri yeni kanal üzerinden başarılı olur.</p>
     */
    private final Object reinitLock = new Object();

    /**
     * PKCS#11 Cryptoki global state'ini <b>biz mi</b> initialize ettik —
     * yoksa aynı process içindeki başka bir bileşen mi?
     *
     * <p>PKCS#11 spec'inde {@code C_Initialize} ve {@code C_Finalize}
     * <b>process-global</b> state taşırlar; reference counting yoktur.
     * {@code C_Finalize}'i kim çağırırsa, aynı kütüphane üzerinden çalışan
     * tüm bileşenleri kapatır. Bu yüzden başka bir bileşen
     * ({@code CKR_CRYPTOKI_ALREADY_INITIALIZED} ile karşılaştığımız
     * senaryolarda) Cryptoki'yi init etmişse <b>biz finalize çağırmayız</b>;
     * aksi halde paylaşımlı state'i agresifçe kapatıp diğer akışları
     * patlatabiliriz (örn. uygulamada paralel çalışan başka bir HSM
     * entegrasyonu, mock-CA test harness'i vb.).</p>
     *
     * <p>Yalnızca {@link #afterPropertiesSet()} içindeki
     * {@code module.initialize()} çağrısı başarıyla geçtiğinde true
     * olur; {@code CKR_CRYPTOKI_ALREADY_INITIALIZED} dönerse false kalır.</p>
     */
    private volatile boolean ownsInitialization = false;

    /**
     * AKİS / TÜBİTAK uyumluluk yolu: {@code C_Initialize} {@code NULL} args ile
     * yapıldıysa true. PKCS#11 v2.40 spec §5.4: "If pInitArgs is NULL_PTR,
     * Cryptoki may not use threads." Bu yüzden bu modda {@link PKCS11Token}
     * havuzunu <b>tek session</b>'a sıkıştırıyoruz — kütüphanenin paralel
     * çağrı altında çökmesini ya da sessiz veri bozulmasını önlemek için.
     * Akıllı kart donanımı zaten paralel oturum kaldırmıyor; bu kısıt gerçek
     * kullanım için maliyetsiz.
     */
    private volatile boolean singleThreadedMode = false;

    /**
     * {@link PKCS11Token} ctor'una geçilecek {@code numSessions} değeri.
     * Üretimde {@link io.mersel.dss.signer.api.config.SignatureConfiguration}
     * tarafından {@code MAX_SESSION_COUNT} property'sinden beslenir; test
     * ve CLI listing yollarında kısa ctor üzerinden {@code 0} geçer.
     *
     * <p><b>Anlamlar:</b></p>
     * <ul>
     *   <li>{@code <= 0} → wrapper default'u uygula
     *       ({@code Math.min(32, tokenMaxSessionCount)}); geriye uyumlu davranış.</li>
     *   <li>{@code > 0}  → explicit pool boyutu; wrapper yine HSM'in raporladığı
     *       {@code tokenMaxSessionCount} ile {@code min} alır, yani işletim
     *       sisteminin tanıdığı tavanın üstüne çıkamayız (sessizce capped).</li>
     * </ul>
     *
     * <p>{@link #singleThreadedMode} aktifken bu değer <b>yoksayılır</b>;
     * AKİS güvenlik kuralı her zaman önceliklidir (bkz. {@link #afterPropertiesSet()}).</p>
     */
    private final int sessionPoolSize;

    /**
     * İmza ataçımı için bulunan ilk private key + cert eşleşmesi cache'i.
     * Concurrent: {@link ConcurrentHashMap#computeIfAbsent} ile lock-free okuma.
     */
    private final Map<String, ResolvedKey> resolvedKeyCache = new ConcurrentHashMap<>();

    /**
     * Geriye uyumlu kısa ctor: {@code forceNullInitArgs=false} ve
     * {@code sessionPoolSize=0} (wrapper default cap=32). Testler ve
     * CLI listing yolu bu formu kullanır.
     */
    public IaikPkcs11Module(String libraryPath, Long slot, Long slotIndex, char[] pin) {
        this(libraryPath, slot, slotIndex, pin, false, 0);
    }

    /**
     * Geriye uyumlu 5-arg ctor: {@code sessionPoolSize=0} (wrapper default).
     * {@code SignatureApplication} CLI listing yolu ve {@code AKİS}
     * uyumluluk testleri bu formu kullanır.
     */
    public IaikPkcs11Module(String libraryPath, Long slot, Long slotIndex, char[] pin,
                            boolean forceNullInitArgs) {
        this(libraryPath, slot, slotIndex, pin, forceNullInitArgs, 0);
    }

    /**
     * Tam ctor — session pool boyutunu dışarıdan kontrol etmek isteyen
     * üretim yapılandırması ({@code SignatureConfiguration} bean factory)
     * bu formu kullanır.
     *
     * @param sessionPoolSize {@link PKCS11Token} ctor'una geçilecek
     *                        {@code numSessions} değeri. {@code <= 0} ise
     *                        wrapper default'u (32) uygulanır. AKİS
     *                        ({@code forceNullInitArgs=true}) yolunda
     *                        bu değer yoksayılır ve 1 forced.
     */
    public IaikPkcs11Module(String libraryPath, Long slot, Long slotIndex, char[] pin,
                            boolean forceNullInitArgs, int sessionPoolSize) {
        this.libraryPath = libraryPath;
        this.slot = slot;
        this.slotIndex = slotIndex;
        this.pin = pin == null ? null : pin.clone();
        this.forceNullInitArgs = forceNullInitArgs;
        this.sessionPoolSize = sessionPoolSize;
    }

    // --------------------------------------------------------------------
    // Lifecycle
    // --------------------------------------------------------------------

    @Override
    public void afterPropertiesSet() {
        try {
            openTokenAndModuleInternal(false /* isReinit */);
        } catch (Exception e) {
            cleanupOnFailure();
            throw new KeyStoreException(
                "ipkcs11wrapper modülü initialize edilemedi: " + libraryPath, e);
        }
    }

    /**
     * PKCS#11 modülü + token açma + login akışı. {@link #afterPropertiesSet()}
     * ile {@link #reinitializeForSmsRecovery(String, String)} aynı kod
     * yolunu paylaşır — boot ile recovery arasında davranış farkı olmamalı.
     *
     * <p>{@code isReinit=true} sadece log severity'sini değiştirir (recovery
     * patikası WARN ile başlar, operatör için sinyal güçlüdür).</p>
     */
    private void openTokenAndModuleInternal(boolean isReinit) throws Exception {
        LOGGER.info("ipkcs11wrapper modülü yükleniyor: library={}, mode={}",
            libraryPath, isReinit ? "REINIT" : "BOOT");
        module = PKCS11Module.getInstance(libraryPath);
        InitOutcome outcome = initializeIdempotent(module, forceNullInitArgs);
        ownsInitialization = outcome.owned;
        singleThreadedMode = outcome.singleThreaded;

        Token rawToken = resolveToken();
        TokenInfo info = rawToken.getTokenInfo();
        LOGGER.info("Token açıldı: label='{}', manufacturer='{}', serial='{}'",
            safeTrim(info.getLabel()),
            safeTrim(info.getManufacturerID()),
            safeTrim(info.getSerialNumber()));

        // PKCS11Token ctor login'i kendisi yapar (pin verilirse). PIN
        // sağlanmamışsa anonymous okuma denenir; CKA_PRIVATE=true objeleri
        // okuma/imza patlar — operasyonel görünürlük için warn'leyelim.
        char[] effectivePin = (pin != null && pin.length > 0) ? pin : null;
        if (effectivePin == null) {
            LOGGER.warn("PIN sağlanmadı; private key'lere erişim "
                + "CKA_PRIVATE=true objeler için başarısız olacak.");
        }
        // ─────────────────────────────────────────────────────────────
        // Session pool boyutu — üç katmanlı karar:
        // ─────────────────────────────────────────────────────────────
        //  1) singleThreadedMode (AKİS / NULL-init-args)
        //       → her zaman 1; sessionPoolSize property'si yoksayılır.
        //         PKCS#11 v2.40 §5.4 gereği kütüphane thread güvencesi
        //         vermez; paralel session = SIGSEGV / sessiz data
        //         corruption riski.
        //
        //  2) sessionPoolSize > 0  (operatör explicit set etti)
        //       → wrapper'a {@code numSessions=sessionPoolSize} geç;
        //         wrapper yine HSM'in {@code tokenMaxSessionCount}
        //         raporuyla {@code min} alır (HSM-tarafı tavanı korunur).
        //         Bu yol, default {@code Math.min(32, tokenMaxSessionCount)}
        //         hard cap'ini by-pass etmek için tasarlandı —
        //         Luna/ProtectServer/Utimaco gibi yüksek-paralel HSM'lerde
        //         throughput'un 32'de sessizce tıkanmasını önler.
        //
        //  3) sessionPoolSize <= 0 (default / unset)
        //       → wrapper default'u uygula; cap=32. Geriye uyumlu davranış.
        // ─────────────────────────────────────────────────────────────
        if (singleThreadedMode) {
            LOGGER.info("AKİS uyumluluk modu aktif: PKCS11Token tek session ile "
                + "yaratılıyor (kütüphane paralel session güvencesi vermiyor; "
                + "MAX_SESSION_COUNT={} değeri yoksayıldı).", sessionPoolSize);
            token = new PKCS11Token(rawToken, true /* readOnly */, effectivePin,
                Integer.valueOf(1));
        } else if (sessionPoolSize > 0) {
            LOGGER.info("PKCS11Token session havuzu explicit yapılandırıldı: "
                + "numSessions={} (wrapper, HSM tokenMaxSessionCount ile min "
                + "alacak; wrapper'ın default 32-cap'i by-pass edildi).", sessionPoolSize);
            token = new PKCS11Token(rawToken, true /* readOnly */, effectivePin,
                Integer.valueOf(sessionPoolSize));
        } else {
            LOGGER.info("PKCS11Token session havuzu default modda — wrapper "
                + "hard cap = min(32, tokenMaxSessionCount). Yüksek concurrency "
                + "için MAX_SESSION_COUNT env var'ı ile artırılabilir (üretim "
                + "yolu zaten bu değeri pool'a besler; bu mesaj test/CLI yolunda görülür).");
            token = new PKCS11Token(rawToken, true /* readOnly */, effectivePin);
        }
        if (effectivePin != null) {
            LOGGER.info("HSM token'a USER olarak login başarılı.");
        }
    }

    @Override
    public void destroy() {
        synchronized (this) {
            try {
                if (token != null) {
                    try {
                        token.logout();
                    } catch (Exception e) {
                        LOGGER.debug("Logout sırasında (yoksayılan) hata: {}", e.getMessage());
                    }
                    try {
                        token.closeAllSessions();
                    } catch (Exception e) {
                        LOGGER.warn("Session close sırasında hata: {}", e.getMessage());
                    }
                    token = null;
                }
                if (module != null) {
                    if (ownsInitialization) {
                        try {
                            module.finalize(null);
                            LOGGER.debug("PKCS#11 modülü finalize edildi (ownership=us).");
                        } catch (Exception e) {
                            LOGGER.warn("Module finalize sırasında hata: {}", e.getMessage());
                        }
                    } else {
                        // CKR_CRYPTOKI_ALREADY_INITIALIZED ile gelen durumda
                        // başka bir bileşen Cryptoki state'i tutuyor; finalize
                        // çağırmak onların session/handle'larını da invalidate
                        // eder. Reference yok ⇒ kontrolü onlara bırak.
                        LOGGER.info("PKCS#11 modülü bizim tarafımızdan initialize "
                            + "edilmediği için finalize çağrılmıyor (paylaşımlı Cryptoki "
                            + "state korunur).");
                    }
                    module = null;
                    ownsInitialization = false;
                    singleThreadedMode = false;
                }
                if (pin != null) {
                    Arrays.fill(pin, '\0');
                }
                resolvedKeyCache.clear();
                LOGGER.info("ipkcs11wrapper modülü kapatıldı.");
            } catch (Exception e) {
                LOGGER.warn("Modül kapatılırken hata: {}", e.getMessage());
            }
        }
    }

    /**
     * Thales PTK-C / SafeNet ailesinde gözlenen secure messaging
     * çöküşünden (CKR_SMS_ERROR=0x80000384, CKR_NO_SESSION_KEYS=0x80000387)
     * agresif kurtarma: Cryptoki modülünü {@code C_Finalize} +
     * {@code C_Initialize} ile yeniden başlatır, token'a yeniden login
     * eder, key handle cache'ini temizler ve <b>aynı alias için yeni
     * handle'ı re-resolve edip döner</b>.
     *
     * <h2>Neden Cryptoki-level reset?</h2>
     * <p>Production'da gözlendi (Mayıs 2026 incident, 3297x ardışık fail,
     * 54+ saat self-recovery yok): xipki wrapper kendi içinde session
     * recovery dener — önce {@code C_GetSessionInfo}, sonra
     * {@code C_Login}. Ama PTK-C tarafında secure messaging katmanı
     * komple çöktüğünde {@code C_Login} de CKR_SMS_ERROR atar çünkü
     * spec gereği login de secure channel üstünden gider. <b>Tek çare:
     * Cryptoki global state'ini sıfırdan kurmak.</b></p>
     *
     * <h2>Thread-safety / in-flight sign çağrıları</h2>
     * <p>Reinit anında başka thread'ler {@code token.sign(...)} ortasında
     * olabilir. Onları durdurmuyoruz — drain {@code signatureSemaphore}
     * üzerinde uzun bir pencere açar ve customer p99 latency'yi şişirir.
     * Yerine: stale token/module referansları üstünde patlayan in-flight
     * sign'lar {@link #signOnSession(ResolvedKey, byte[], SignatureAlgorithm)}
     * SMS-aile recovery branch'i tarafından yakalanır ve yeni kanal
     * üstünde retry edilir. Net etki: kısa pencerede 1 fail, sonra
     * transparent recovery.</p>
     *
     * <h2>Re-resolve cascade</h2>
     * <p>Cryptoki C_Finalize/C_Initialize <b>tüm handle'ları invalidate
     * eder</b> — eski key handle bir daha geçerli değil.
     * {@link #resolvedKeyCache} temizlenir; aynı alias için yeni handle
     * resolve edilir; <b>çağıran (heartbeat scheduler / signer)</b>
     * dönen {@link ResolvedKey}'i alır VEYA elindeki referansı
     * in-place günceller. {@link ResolvedKey} field'ları
     * {@code volatile}; refresh atomik.</p>
     *
     * @param alias  re-resolve için CKA_LABEL (mevcut scheduler'ın
     *               cached alias'ı). {@code null}/boş ise serial bazlı arama.
     * @param serialHex sertifika serial; {@code null} ise alias yeterli.
     * @return yeni handle ile {@link ResolvedKey} (her zaman taze instance).
     * @throws KeyStoreException Cryptoki-level reset başarısız olursa
     *         (HSM gerçekten ölü, network kesik, partition lock vb.).
     *         Çağıran bu durumda exponential backoff'a girmeli.
     */
    public ResolvedKey reinitializeForSmsRecovery(String alias, String serialHex) {
        synchronized (reinitLock) {
            long t0 = System.currentTimeMillis();
            LOGGER.warn("Module REINIT başlıyor — secure messaging recovery "
                + "(alias='{}', serialHex='{}')", alias, serialHex);

            closeQuietlyForReinit();

            try {
                openTokenAndModuleInternal(true /* isReinit */);
            } catch (Exception e) {
                throw new KeyStoreException(
                    "Module reinit (C_Finalize+C_Initialize) başarısız: " + e.getMessage(), e);
            }

            resolvedKeyCache.clear();
            ResolvedKey refreshed = resolveFromToken(alias, serialHex);

            long elapsed = System.currentTimeMillis() - t0;
            LOGGER.info("Module REINIT başarılı: alias='{}', yeni keyHandle=0x{}, elapsed={}ms",
                refreshed.alias, Long.toHexString(refreshed.privateKeyHandle), elapsed);
            return refreshed;
        }
    }

    /**
     * Reinit için sessiz kapanış. {@link #destroy()}'dan farkı:
     * <ul>
     *   <li>{@code synchronized(this)} <b>almıyor</b> — çağıran
     *       {@code reinitLock} altında zaten.</li>
     *   <li>{@code module.finalize()} ownership'ten bağımsız <b>her zaman</b>
     *       çağrılır — paylaşımlı state riskini reinit zamanında kabul
     *       ediyoruz; secure channel zaten ölü, başka bileşen de bunu
     *       hissediyordur.</li>
     *   <li>Hata olursa swallow + debug log; reinit akışı kesilmez.</li>
     * </ul>
     */
    private void closeQuietlyForReinit() {
        if (token != null) {
            try { token.logout(); } catch (Exception ignored) { }
            try { token.closeAllSessions(); } catch (Exception ignored) { }
            token = null;
        }
        if (module != null) {
            try {
                module.finalize(null);
                LOGGER.debug("Reinit: PKCS#11 modülü finalize edildi.");
            } catch (Exception e) {
                LOGGER.debug("Reinit: module.finalize() hatası (yoksayıldı): {}", e.getMessage());
            }
            module = null;
            ownsInitialization = false;
            singleThreadedMode = false;
        }
    }

    // --------------------------------------------------------------------
    // Public API — findSigner + listCertificates
    // --------------------------------------------------------------------

    /**
     * Verilen alias veya serial numarasına eşleşen ilk imzalama materyalini
     * döndürür. İkisi de boş bırakılırsa private key'i olan ilk sertifikayı
     * seçer.
     *
     * @param alias  CKA_LABEL ile eşleşme; {@code null}/boş ise dikkate alınmaz
     * @param serialHex sertifika serial numarası (hex); {@code null}/boş ise dikkate alınmaz
     * @return imza atmaya hazır {@link Pkcs11Signer}
     * @throws KeyStoreException eşleşen anahtar yoksa
     */
    /**
     * Sertifika ya da private key handle'ı değişen (yeniden import, revoke,
     * key rotation) durumlarda dahili cache'i sıfırlar. Operasyonel admin
     * komutu / health endpoint'i bu metodu çağırabilir.
     *
     * <p>Cache aslında tek-shot startup-time için doluyor; uzun süren
     * sunucularda HSM token'ında yeni sertifika eklenirse yeni
     * {@code findSigner} çağrısı stale veri görmesin diye eklenmiştir.</p>
     */
    public void invalidateKeyCache() {
        int size = resolvedKeyCache.size();
        resolvedKeyCache.clear();
        LOGGER.info("ResolvedKey cache temizlendi (önceki entry sayısı: {}).", size);
    }

    public Pkcs11Signer findSigner(String alias, String serialHex) {
        String cacheKey = (alias == null ? "" : alias) + "|" + (serialHex == null ? "" : serialHex);

        // ConcurrentHashMap.computeIfAbsent → tek anahtar için tek arama;
        // farklı alias talepleri paralel çözümlenir.
        ResolvedKey resolved = resolvedKeyCache.computeIfAbsent(cacheKey,
            k -> resolveFromToken(alias, serialHex));

        return new IaikPkcs11Signer(this, resolved);
    }

    private ResolvedKey resolveFromToken(String alias, String serialHex) {
        List<TokenObject> objects = collectAllRelevantObjects();
        ResolvedKey resolved = matchKey(objects, alias, serialHex);
        if (resolved == null) {
            List<String> aliases = new ArrayList<>();
            for (TokenObject obj : objects) {
                if (obj.cert != null && obj.label != null) {
                    aliases.add(obj.label);
                }
            }
            throw new KeyStoreException(
                "Token'da eşleşen imzalama anahtarı bulunamadı"
                + (StringUtils.hasText(alias) ? " (alias='" + alias + "')" : "")
                + (StringUtils.hasText(serialHex) ? " (serial=" + serialHex + ")" : "")
                + ". Mevcut alias'lar: " + aliases);
        }

        LOGGER.info("İmzalama anahtarı çözüldü: alias='{}', serial={}, keyHandle=0x{}",
            resolved.alias,
            toHex(resolved.certificate.getSerialNumber()),
            Long.toHexString(resolved.privateKeyHandle));
        return resolved;
    }

    /**
     * Token üzerindeki tüm sertifikaları (kombine private key bilgileriyle)
     * listeler. SunPKCS11 alias map'ine bağımlı DEĞİLDİR — JCA katmanı boş
     * dönse de buradan tam liste gelir.
     */
    public List<CertificateInfoDto> listCertificates() {
        List<TokenObject> objects = collectAllRelevantObjects();
        Map<String, CertificateInfoDto> byAlias = new LinkedHashMap<>();
        int orphanKeyCounter = 0;

        for (TokenObject obj : objects) {
            if (obj.cert == null) {
                continue;
            }
            String serialHex = toHex(obj.cert.getSerialNumber());
            String baseAlias = obj.label != null && !obj.label.isEmpty()
                ? obj.label
                : ("cert-" + (byAlias.size() + 1));
            // Duplicate label koruması (Codex regresyonu, Mayıs 2026): aynı
            // CKA_LABEL'a sahip iki sertifika varsa map.put() birinciyi ezerdi.
            // Operasyonel görünürlük için ikinciye serial-suffix ekliyoruz —
            // kullanıcı listing'de iki entry görür ve hangisini istediğini
            // serial ile seçebilir.
            String alias = baseAlias;
            if (byAlias.containsKey(alias)) {
                String suffix = serialHex.length() > 8
                    ? serialHex.substring(serialHex.length() - 8)
                    : serialHex;
                alias = baseAlias + "@" + suffix;
                LOGGER.warn("Duplicate alias '{}' tespit edildi; bu entry '{}' olarak listeleniyor.",
                    baseAlias, alias);
            }
            CertificateInfoDto dto = new CertificateInfoDto();
            dto.setAlias(alias);
            dto.setSerialNumberHex(serialHex);
            dto.setSerialNumberDec(obj.cert.getSerialNumber().toString());
            dto.setSubject(obj.cert.getSubjectX500Principal().toString());
            dto.setIssuer(obj.cert.getIssuerX500Principal().toString());
            dto.setValidFrom(obj.cert.getNotBefore());
            dto.setValidTo(obj.cert.getNotAfter());
            dto.setType(obj.cert.getType());
            dto.setSignatureAlgorithm(obj.cert.getSigAlgName());
            dto.setHasPrivateKey(hasMatchingKey(obj, objects));
            dto.setKeyUsage(X509ExtensionInspector.extractKeyUsage(obj.cert));
            dto.setExtendedKeyUsage(X509ExtensionInspector.extractExtendedKeyUsage(obj.cert));
            dto.setCertificatePolicies(X509ExtensionInspector.extractCertificatePolicies(obj.cert));
            dto.setPublicKeyAlgorithm(obj.cert.getPublicKey().getAlgorithm());
            // base64EncodedCertificate kasıtlı olarak set edilmez — token'da
            // onlarca sertifika varken /list payload'unu şişirmiyoruz; manuel
            // XAdES için /signingCertificate endpoint'i kullanılmalı.
            byAlias.put(alias, dto);
        }

        // Yetim private key'leri (matching cert'i yok) ayrı entry olarak
        // göster — operasyonel görünürlük için.
        for (TokenObject obj : objects) {
            if (obj.privateKeyHandle == 0L || obj.cert != null) {
                continue;
            }
            if (matchingCertExists(obj, objects)) {
                continue;
            }
            orphanKeyCounter++;
            String alias = obj.label != null && !obj.label.isEmpty()
                ? obj.label
                : ("orphan-key-" + orphanKeyCounter);
            CertificateInfoDto dto = new CertificateInfoDto();
            dto.setAlias(alias);
            dto.setHasPrivateKey(true);
            dto.setSubject("(yetim private key — token'da matching sertifika yok)");
            byAlias.put(alias, dto);
        }

        LOGGER.info("Token listing: {} entry (cert+key={}, orphan-key={}).",
            byAlias.size(), byAlias.size() - orphanKeyCounter, orphanKeyCounter);
        return new ArrayList<>(byAlias.values());
    }

    // --------------------------------------------------------------------
    // Package-private — IaikPkcs11Signer tarafından çağrılır
    // --------------------------------------------------------------------

    /**
     * Sağlanan private key handle'ı üzerinden HSM'de imza atar.
     *
     * <p>{@link IaikSignatureMechanisms} ile DSS algoritmasını PKCS#11
     * mekanizmasına çevirir; ECDSA için her zaman raw {@code CKM_ECDSA} +
     * dış digest kullanır (universal HSM uyumu). RSA için combined
     * {@code CKM_<HASH>_RSA_PKCS} ile tek round-trip imza atar; mekanizma
     * reddedilirse {@link #signWithRawFallback} ile raw {@code CKM_RSA_PKCS} +
     * PKCS#1 DigestInfo wrap'e düşer.</p>
     *
     * <p>PKCS11Token kendi içinde thread-safe oturum havuzu yönettiği için
     * bu metoda eş zamanlı çağrı sağlanır; üst sınır
     * {@code signatureSemaphore} ile kontrol edilir.</p>
     */
    /**
     * Heartbeat amaçlı tek-shot imza. SafeNet HSM ailesinde idle kalan
     * secure messaging session-key'i HSM tarafında reap edilir
     * ({@code CKR_NO_SESSION_KEYS = 0x80000387}); periyodik bir gerçek
     * {@code C_Sign} round-trip'i secure channel'ı sıcak tutar.
     *
     * <p>Tasarım: mevcut {@link #signOnSession} yolunu olduğu gibi kullanır
     * (mekanizma çözümleme, fallback, normalize tüm pipeline reused) ve
     * çıkan imzayı drop eder — heartbeat'in görevi sadece HSM tarafında
     * secure messaging context'in canlı kalması.</p>
     *
     * <p>Çağıran ({@code HsmHeartbeatScheduler}) exception yakalamadan
     * sorumludur; modül başarısızlığı sessiz yutmaz.</p>
     */
    public int heartbeatSign(long privateKeyHandle, SignatureAlgorithm signatureAlgorithm) {
        byte[] payload = HEARTBEAT_PAYLOAD;
        byte[] signature = signOnSession(privateKeyHandle, payload, signatureAlgorithm);
        // İmza byte'larını okumadan drop ediyoruz; sadece HSM round-trip'in
        // başarısı önemli. signOnSession patladıysa zaten exception fırlattı.
        // sigLen'i çağırana döndürüyoruz ki scheduler tek bir INFO satırında
        // 'gerçekten bir imza atıldı' kanıtını gösterebilsin.
        return signature.length;
    }

    /**
     * Heartbeat round-trip'inde HSM'e gönderilen sabit payload. RSA için
     * combined mekanizma kendi içinde digest alır, ECDSA için
     * {@link #signOnSession} dış digest çağırır — yani byte uzunluğu önemli
     * değil. ASCII, sabit, kolay tanınabilir bir marker seçildi.
     */
    private static final byte[] HEARTBEAT_PAYLOAD =
        "mersel-hsm-heartbeat-ping-v1".getBytes(java.nio.charset.StandardCharsets.US_ASCII);

    /**
     * SafeNet PTK-C / Luna ailesine özgü vendor-defined hata kodları
     * (kaynak: Thales PTK-C Vendor-Defined Error Codes tablosu).
     *
     * <ul>
     *   <li>{@code 0x80000384} = CKR_SMS_ERROR — Secure Messaging System
     *       genel hatası (HSM ya da network kaynaklı).</li>
     *   <li>{@code 0x80000387} = CKR_NO_SESSION_KEYS — secure messaging
     *       session-key'leri reap edildi (idle teardown).</li>
     * </ul>
     *
     * <p>Bu iki kod aynı kök nedenin (SMS layer çöküşü) iki yüzü; ikisinde de
     * tek-shot strateji: {@link #reinitializeForSmsRecovery(String, String)}
     * ile Cryptoki global state'ini sıfırdan kurup yeni handle ile retry.</p>
     */
    private static final long CKR_SMS_ERROR        = 0x80000384L;
    private static final long CKR_NO_SESSION_KEYS  = 0x80000387L;

    private static boolean isSmsFamilyError(long errorCode) {
        return errorCode == CKR_SMS_ERROR || errorCode == CKR_NO_SESSION_KEYS;
    }

    /**
     * Alias-aware {@code signOnSession} overload'u — {@link IaikPkcs11Signer}
     * müşteri isteklerinde bu yolu kullanır. Mevcut handle-bazlı overload
     * heartbeat scheduler tarafından korunur (heartbeat L1 yolu üzerinden
     * reinit'i bağımsız tetikler).
     *
     * <h2>L2 — caller-path SMS-aile recovery</h2>
     * <p>İlk {@code C_Sign} çağrısı {@code CKR_SMS_ERROR} (0x80000384) veya
     * {@code CKR_NO_SESSION_KEYS} (0x80000387) ile reddedilirse:</p>
     * <ol>
     *   <li>{@link #reinitializeForSmsRecovery(String, String)} ile
     *       Cryptoki tam reset.</li>
     *   <li>Dönen yeni {@link ResolvedKey} alanları, çağıranın elindeki
     *       {@code rk} instance'ına <b>in-place</b> kopyalanır (volatile
     *       field write; aynı referansı tutan heartbeat scheduler yeni
     *       handle'ı görür).</li>
     *   <li>Sign tek kez retry edilir; bu kez yeni kanal üstünden.</li>
     * </ol>
     *
     * <p>Retry de SMS-aile hatası alırsa <b>tekrar reinit denemiyoruz</b>
     * (sonsuz döngü riski); orijinal exception propagate eder. Heartbeat
     * L1 yolu o zaman exponential backoff'a alır.</p>
     *
     * <p>Eşzamanlı çağrılarda yarış: birden çok request thread'i aynı
     * anda SMS hatası alıp reinit'e girebilir. {@code reinitLock} ilkini
     * çalıştırır, diğerleri lock'ta bekler; lock serbest kaldığında yeni
     * (canlı) handle'ı görürler ve retry'ları direkt başarılı olur.</p>
     */
    byte[] signOnSession(ResolvedKey rk,
                         byte[] dataToSign,
                         SignatureAlgorithm signatureAlgorithm) {
        try {
            return signOnSession(rk.privateKeyHandle, dataToSign, signatureAlgorithm);
        } catch (io.mersel.dss.signer.api.exceptions.SignatureException sigEx) {
            long smsErrorCode = extractSmsFamilyErrorCode(sigEx);
            if (smsErrorCode == 0L) {
                throw sigEx;
            }
            LOGGER.warn("L2 SMS-aile hata yakalandı (CKR=0x{}, alias='{}'); "
                + "module reinit + tek-shot retry deniyor.",
                Long.toHexString(smsErrorCode), rk.alias);
            ResolvedKey refreshed;
            try {
                refreshed = reinitializeForSmsRecovery(rk.alias, null);
            } catch (Exception reinitEx) {
                LOGGER.error("L2 reinit başarısız (alias='{}'): {}; orijinal SMS "
                    + "hatası propagate ediliyor.", rk.alias, reinitEx.getMessage());
                throw sigEx;
            }
            // In-place refresh — çağıranın referansları (heartbeat scheduler
            // dahil) yeni handle'ı bir sonraki sign'da otomatik okur.
            rk.privateKeyHandle = refreshed.privateKeyHandle;
            rk.certificate = refreshed.certificate;
            rk.certificateChain = refreshed.certificateChain;
            LOGGER.info("L2 reinit tamam, sign retry'sı atılıyor (alias='{}', yeni handle=0x{}).",
                rk.alias, Long.toHexString(rk.privateKeyHandle));
            // Tek-shot — retry'da yine SMS-aile hatası gelirse oraya kadar.
            return signOnSession(rk.privateKeyHandle, dataToSign, signatureAlgorithm);
        }
    }

    /**
     * {@link io.mersel.dss.signer.api.exceptions.SignatureException} sarıcısının
     * altındaki PKCS11Exception'a bakıp SMS-aile error code'unu çıkarır;
     * SMS-aile değilse {@code 0L} döner.
     */
    private static long extractSmsFamilyErrorCode(Throwable t) {
        Throwable cur = t;
        // Genelde sigEx.getCause() == PKCS11Exception; defensive bir kaç hop
        // dolaş — gelecekte wrap zinciri büyürse de çalışsın.
        for (int i = 0; cur != null && i < 5; i++, cur = cur.getCause()) {
            if (cur instanceof PKCS11Exception) {
                long code = ((PKCS11Exception) cur).getErrorCode();
                if (isSmsFamilyError(code)) {
                    return code;
                }
                return 0L;
            }
        }
        return 0L;
    }

    /**
     * Pre-hashed digest yolu — caller zaten hesaplanmış digest baytlarını verir.
     *
     * <p>Bu yol {@link #signOnSession(ResolvedKey, byte[], SignatureAlgorithm)}'dan
     * iki farklılıkla ayrılır:</p>
     * <ol>
     *   <li><b>Hash basamağı atlanır</b> &mdash; çağıran zaten hashlemiş; backend
     *       tekrar hashlerse çıktı double-hashed olur ve doğrulayıcı reddeder.</li>
     *   <li><b>Daima raw mekanizma kullanılır</b> &mdash; RSA için
     *       {@code CKM_RSA_PKCS} + {@link Pkcs1DigestInfo} wrap, ECDSA için
     *       {@code CKM_ECDSA} + raw digest. Combined mekanizmalar
     *       ({@code CKM_<HASH>_RSA_PKCS}) HSM içinde digest aldığı için kullanılmaz.</li>
     * </ol>
     *
     * <p>SMS-aile recovery (CKR=0x80000384/0x80000387) yolu mevcut
     * {@link #signOnSession(ResolvedKey, byte[], SignatureAlgorithm)} ile birebir
     * aynı şekilde uygulanır.</p>
     *
     * @param rk           token üzerindeki imzalama anahtarı için resolved handle
     * @param digest       pre-computed hash baytları
     * @param digestAlg    DigestInfo prefix seçimi için DSS digest algoritması
     * @param enc          imzalama anahtarının enc tipi (RSA / ECDSA / PLAIN_ECDSA);
     *                     DSA bu yolda <b>reddedilir</b> (raw CKM_DSA fallback path
     *                     henüz implement edilmedi — RSA/ECDSA dışı T.C. e-imza
     *                     pazarında pratik olarak ölü)
     * @return JCA uyumlu imza byte'ları (RSA: PKCS#1 v1.5 padded RSA cipher
     *         output; ECDSA: DER SEQUENCE { r, s })
     */
    byte[] signOnSessionRawDigest(ResolvedKey rk,
                                   byte[] digest,
                                   DigestAlgorithm digestAlg,
                                   EncryptionAlgorithm enc) {
        try {
            return signOnSessionRawDigest(rk.privateKeyHandle, digest, digestAlg, enc);
        } catch (io.mersel.dss.signer.api.exceptions.SignatureException sigEx) {
            long smsErrorCode = extractSmsFamilyErrorCode(sigEx);
            if (smsErrorCode == 0L) {
                throw sigEx;
            }
            LOGGER.warn("L2 SMS-aile hata yakalandı (raw-digest path, CKR=0x{}, alias='{}'); "
                + "module reinit + tek-shot retry deniyor.",
                Long.toHexString(smsErrorCode), rk.alias);
            ResolvedKey refreshed;
            try {
                refreshed = reinitializeForSmsRecovery(rk.alias, null);
            } catch (Exception reinitEx) {
                LOGGER.error("L2 reinit başarısız (raw-digest path, alias='{}'): {}; orijinal SMS "
                    + "hatası propagate ediliyor.", rk.alias, reinitEx.getMessage());
                throw sigEx;
            }
            rk.privateKeyHandle = refreshed.privateKeyHandle;
            rk.certificate = refreshed.certificate;
            rk.certificateChain = refreshed.certificateChain;
            LOGGER.info("L2 reinit tamam (raw-digest path), retry atılıyor (alias='{}', "
                + "yeni handle=0x{}).", rk.alias, Long.toHexString(rk.privateKeyHandle));
            return signOnSessionRawDigest(rk.privateKeyHandle, digest, digestAlg, enc);
        }
    }

    private byte[] signOnSessionRawDigest(long privateKeyHandle,
                                           byte[] digest,
                                           DigestAlgorithm digestAlg,
                                           EncryptionAlgorithm enc) {
        ensureTokenOpen();
        if (enc == EncryptionAlgorithm.DSA) {
            throw new io.mersel.dss.signer.api.exceptions.SignatureException(
                "DSA pre-hashed digest imzalama bu kod yolunda implement edilmedi. "
                + "Lütfen RSA veya ECDSA anahtarı kullanın.");
        }
        if (enc == EncryptionAlgorithm.RSASSA_PSS) {
            throw new io.mersel.dss.signer.api.exceptions.SignatureException(
                "RSA-PSS pre-hashed digest imzalama bu kod yolunda implement edilmedi. "
                + "PSS salt + MGF parametreleri için ayrı bir akış gerekir; "
                + "şu an PKCS#1 v1.5 (RSA) ve ECDSA destekleniyor.");
        }
        Mechanism rawMech = (enc == EncryptionAlgorithm.ECDSA || enc == EncryptionAlgorithm.PLAIN_ECDSA)
            ? IaikSignatureMechanisms.fallbackToRawEcdsa()
            : IaikSignatureMechanisms.fallbackToRawRsaPkcs();
        byte[] inputData = (enc == EncryptionAlgorithm.RSA)
            ? Pkcs1DigestInfo.wrap(digest, digestAlg)
            : digest;
        // invokeSign yalnızca normalize + logging için SignatureAlgorithm bekler;
        // enc + digest kombinasyonundan tek doğru DSS algoritması üretilir.
        SignatureAlgorithm dssAlg = SignatureAlgorithm.getAlgorithm(enc, digestAlg);
        try {
            return invokeSign(rawMech, privateKeyHandle, inputData, dssAlg, digest.length);
        } catch (PKCS11Exception ckEx) {
            throw new io.mersel.dss.signer.api.exceptions.SignatureException(
                "HSM raw-digest imza başarısız (CKR=0x"
                    + Long.toHexString(ckEx.getErrorCode()) + "): " + ckEx.getMessage(), ckEx);
        } catch (Exception e) {
            throw new io.mersel.dss.signer.api.exceptions.SignatureException(
                "HSM raw-digest imza başarısız", e);
        }
    }

    byte[] signOnSession(long privateKeyHandle,
                         byte[] dataToSign,
                         SignatureAlgorithm signatureAlgorithm) {
        ensureTokenOpen();
        Mechanism mechanism = IaikSignatureMechanisms.resolveMechanism(signatureAlgorithm);
        byte[] inputData = IaikSignatureMechanisms.requiresExternalDigest(mechanism)
            ? hash(dataToSign, signatureAlgorithm)
            : dataToSign;

        try {
            return invokeSign(mechanism, privateKeyHandle, inputData,
                signatureAlgorithm, dataToSign.length);
        } catch (PKCS11Exception ckEx) {
            long errorCode = ckEx.getErrorCode();
            // ─────────────────────────────────────────────────────────────
            // Mekanizma uyumsuzluğu → raw fallback
            // ─────────────────────────────────────────────────────────────
            // ECDSA için {@link IaikSignatureMechanisms} zaten her zaman raw
            // CKM_ECDSA kullanır — bu yüzden combined-mode mekanizma reddi
            // pratik olarak yalnızca RSA tarafında oluşabilir. Yine de tüm
            // standart "mekanizma desteklenmiyor" hata kodları için aynı
            // savunmacı davranışı uyguluyoruz.
            //
            // RSA-PSS hariç (raw CKM_RSA_PKCS'e indirgeme PSS imzasını
            // sessizce v1.5'e çevirir → yanlış imza; açıkça reddediyoruz).
            // ─────────────────────────────────────────────────────────────
            boolean mechanismRejected =
                errorCode == PKCS11Constants.CKR_MECHANISM_INVALID
                || errorCode == PKCS11Constants.CKR_FUNCTION_NOT_SUPPORTED
                || errorCode == PKCS11Constants.CKR_KEY_TYPE_INCONSISTENT
                || errorCode == PKCS11Constants.CKR_OPERATION_NOT_INITIALIZED;
            if (mechanismRejected) {
                if (signatureAlgorithm.getEncryptionAlgorithm() == EncryptionAlgorithm.RSASSA_PSS) {
                    throw new io.mersel.dss.signer.api.exceptions.SignatureException(
                        "HSM bu sürümüyle RSA-PSS imzayı desteklemiyor (CKR=0x"
                            + Long.toHexString(errorCode) + "); raw fallback PKCS#1 v1.5'e "
                            + "indirgeme yapar, bu imza GEÇERSİZ olur. Lütfen RSA-PSS yerine "
                            + "RSA-PKCS#1 v1.5 algoritmasıyla yapılandırın veya HSM "
                            + "firmware'ini güncelleyin.", ckEx);
                }
                LOGGER.warn("Mekanizma reddedildi (CKR=0x{}, alg={}, mech=0x{}); "
                    + "raw fallback'e düşülüyor.",
                    Long.toHexString(errorCode), signatureAlgorithm,
                    Long.toHexString(mechanism.getMechanismCode()));
                return signWithRawFallback(privateKeyHandle, dataToSign, signatureAlgorithm);
            }
            throw new io.mersel.dss.signer.api.exceptions.SignatureException(
                "HSM imza başarısız: " + ckEx.getMessage(), ckEx);
        } catch (Exception e) {
            throw new io.mersel.dss.signer.api.exceptions.SignatureException(
                "HSM imza başarısız", e);
        }
    }

    /**
     * Tek bir {@code token.sign} çağrısını sarmalar (logging + EC/DSA
     * normalize dahil). Doğrudan PKCS11Token'ın public API'sini kullanır;
     * private internals'a reflection ile dokunmuyoruz.
     *
     * <h3>xipki/ipkcs11wrapper 1.0.9 opInit() swallow-bug</h3>
     * <p>{@link PKCS11Token#sign(Mechanism, long, byte[])} kendi içinde
     * {@code opInit()} çağırır; bu metot {@code C_SignInit} hatalarından SADECE
     * {@code CKR_USER_NOT_LOGGED_IN}'i yakalar, diğer her
     * {@code PKCS11Exception}'ı (CKR_MECHANISM_INVALID, CKR_KEY_HANDLE_INVALID,
     * vs.) <em>sessizce yutar</em>; sonuç altta {@code CKR_OPERATION_NOT_INITIALIZED}
     * olarak görünür ve gerçek hata kodu kaybolur.</p>
     *
     * <p>Bu bug'i deterministik tetiklemenin ana yolu (CI'da gözlenen) ECDSA
     * combined mekanizmalarıydı ({@code CKM_ECDSA_SHA256} SoftHSM2'de
     * mechanism-list'te var ama C_SignInit'te reddediliyor).
     * {@link IaikSignatureMechanisms} ECDSA için her zaman raw {@code CKM_ECDSA}
     * üreterek bu yolu by-pass eder. RSA combined mekanizmaları
     * ({@code CKM_<HASH>_RSA_PKCS}) tüm production HSM'lerinde stabil
     * çalışmıştır; bu yolda swallow-bug'a değme olasılığı pratik olarak yok.</p>
     *
     * <p>Upstream tracking: xipki/ipkcs11wrapper master {@code else throw ex}
     * ile düzeltildi (commit 2024-11); resmi {@code v1.1+} sürümü yayınlandığında
     * bu Javadoc notu kaldırılabilir.</p>
     */
    private byte[] invokeSign(Mechanism mechanism,
                              long privateKeyHandle,
                              byte[] inputData,
                              SignatureAlgorithm signatureAlgorithm,
                              int originalDataLen) throws TokenException {
        byte[] signature = token.sign(mechanism, privateKeyHandle, inputData);
        LOGGER.debug("HSM imza tamamlandı: mech=0x{}, dataLen={}, sigLen={}",
            Long.toHexString(mechanism.getMechanismCode()),
            originalDataLen, signature.length);
        return normalizeIfEcOrDsa(signature, signatureAlgorithm);
    }

    private byte[] signWithRawFallback(long privateKeyHandle,
                                       byte[] dataToSign,
                                       SignatureAlgorithm signatureAlgorithm) {
        try {
            EncryptionAlgorithm enc = signatureAlgorithm.getEncryptionAlgorithm();

            // DSA için raw fallback yapmıyoruz: DSA'ya özel raw CKM_DSA
            // mekanizması var ama IAIK fallback path'inde implement edilmedi.
            // Yanlışlıkla CKM_RSA_PKCS'e indirgemek DSA private key ile
            // anlamsız hatalar üretir (key/mechanism mismatch). DSA Türkiye
            // e-imza pazarında pratik olarak ölü — explicit reject daha doğru.
            if (enc == EncryptionAlgorithm.DSA) {
                throw new io.mersel.dss.signer.api.exceptions.SignatureException(
                    "HSM bu sürümüyle CKM_DSA_<HASH> mekanizmasını desteklemiyor "
                    + "ve DSA için raw fallback bu kod yolunda uygulanmıyor. "
                    + "Lütfen RSA veya ECDSA anahtarı kullanın.");
            }

            Mechanism rawMech = (enc == EncryptionAlgorithm.ECDSA || enc == EncryptionAlgorithm.PLAIN_ECDSA)
                ? IaikSignatureMechanisms.fallbackToRawEcdsa()
                : IaikSignatureMechanisms.fallbackToRawRsaPkcs();
            byte[] inputData = hash(dataToSign, signatureAlgorithm);
            if (enc == EncryptionAlgorithm.RSA) {
                inputData = Pkcs1DigestInfo.wrap(inputData, signatureAlgorithm.getDigestAlgorithm());
            }
            // Raw mekanizma için de aynı invokeSign yolu kullanılır
            // (token.sign + normalizeIfEcOrDsa). DRY: tek logging + normalize
            // davranışı her iki kod yolunda da geçerlidir.
            return invokeSign(rawMech, privateKeyHandle, inputData,
                signatureAlgorithm, dataToSign.length);
        } catch (io.mersel.dss.signer.api.exceptions.SignatureException e) {
            throw e;
        } catch (Exception e) {
            throw new io.mersel.dss.signer.api.exceptions.SignatureException(
                "Raw fallback imza da başarısız", e);
        }
    }

    /**
     * EC/DSA mekanizmalarında PKCS#11 spec'i imzayı <b>raw r||s</b> formatında
     * verir; JCA / CMS / PAdES / XAdES ise ASN.1 DER SEQUENCE bekler. Bu
     * dönüşüm yapılmazsa imza doğrulayıcılar tarafından reddedilir.
     *
     * <p>RSA imzaları (v1.5 ve PSS) zaten standardize encoded formatta gelir,
     * dönüşüm gerekmez — bu metot RSA için imzayı olduğu gibi döndürür.</p>
     *
     * <p>Defensive: bazı HSM sürücüleri standart dışı davranıp zaten DER
     * üretebilir; bu durumda {@link Pkcs11EcdsaSignatureEncoder#normalizeToDer}
     * idempotent davranır ve yeniden sarmalamaz.</p>
     */
    private static byte[] normalizeIfEcOrDsa(byte[] signature, SignatureAlgorithm signatureAlgorithm) {
        EncryptionAlgorithm enc = signatureAlgorithm.getEncryptionAlgorithm();
        if (enc == EncryptionAlgorithm.ECDSA
            || enc == EncryptionAlgorithm.PLAIN_ECDSA
            || enc == EncryptionAlgorithm.DSA) {
            return Pkcs11EcdsaSignatureEncoder.normalizeToDer(signature);
        }
        return signature;
    }

    // --------------------------------------------------------------------
    // Helpers
    // --------------------------------------------------------------------

    /** Token üzerindeki tüm cert ve private key objelerini handle + label + cert + id ile derle. */
    private List<TokenObject> collectAllRelevantObjects() {
        ensureTokenOpen();
        List<TokenObject> result = new ArrayList<>();
        try {
            // 1) Tüm X.509 sertifikalar
            long[] certHandles = token.findAllObjects(AttributeVector.newX509Certificate());
            for (long handle : certHandles) {
                AttributeVector av = token.getAttrValues(handle,
                    PKCS11Constants.CKA_LABEL,
                    PKCS11Constants.CKA_ID,
                    PKCS11Constants.CKA_VALUE);
                TokenObject to = new TokenObject();
                to.label = av.getStringAttrValue(PKCS11Constants.CKA_LABEL);
                to.id = av.getByteArrayAttrValue(PKCS11Constants.CKA_ID);
                to.cert = parseCert(av.getByteArrayAttrValue(PKCS11Constants.CKA_VALUE));
                result.add(to);
            }

            // 2) Tüm private key'ler
            long[] keyHandles = token.findAllObjects(AttributeVector.newPrivateKey());
            for (long handle : keyHandles) {
                AttributeVector av = token.getAttrValues(handle,
                    PKCS11Constants.CKA_LABEL,
                    PKCS11Constants.CKA_ID);
                String label = av.getStringAttrValue(PKCS11Constants.CKA_LABEL);
                byte[] id = av.getByteArrayAttrValue(PKCS11Constants.CKA_ID);

                // Aynı cert ile eşleşen TokenObject zaten varsa private
                // key handle'ını oraya iliştir; aksi halde key-only entry oluştur.
                TokenObject match = findByIdOrLabel(result, id, label, true);
                if (match != null) {
                    // Güvenlik (Codex regresyonu, Mayıs 2026): cert'e zaten
                    // bir private key bağlandıysa, ikinci bağlama girişimi
                    // duplicate label/id'yi gösterir — yanlış key'i seçmek
                    // yerine ilk bağlamayı koru ve loglayarak operatöre bildir.
                    if (match.privateKeyHandle != 0L) {
                        LOGGER.warn("Sertifika (CKA_LABEL='{}', CKA_ID={}) için birden fazla "
                            + "private key adayı bulundu. İlk bağlama (handle=0x{}) korundu; "
                            + "yeni handle=0x{} atlanıyor. HSM'de duplicate label/id "
                            + "olabilir — admin kontrolü gerekir.",
                            match.label,
                            id == null ? "<empty>" : org.bouncycastle.util.encoders.Hex.toHexString(id),
                            Long.toHexString(match.privateKeyHandle),
                            Long.toHexString(handle));
                        // İlk bağlamayı koru, yeni handle'ı yetim key olarak da ekle.
                        TokenObject orphan = new TokenObject();
                        orphan.label = label;
                        orphan.id = id;
                        orphan.privateKeyHandle = handle;
                        result.add(orphan);
                    } else {
                        match.privateKeyHandle = handle;
                    }
                } else {
                    TokenObject to = new TokenObject();
                    to.label = label;
                    to.id = id;
                    to.privateKeyHandle = handle;
                    result.add(to);
                }
            }
        } catch (TokenException e) {
            throw new KeyStoreException("Token nesneleri okunamadı", e);
        }
        return result;
    }

    private ResolvedKey matchKey(List<TokenObject> objects, String alias, String serialHex) {
        TokenObject best = null;
        for (TokenObject obj : objects) {
            if (obj.cert == null || obj.privateKeyHandle == 0L) {
                continue;
            }
            boolean aliasOk = !StringUtils.hasText(alias) || alias.equals(obj.label);
            boolean serialOk = !StringUtils.hasText(serialHex)
                || serialHexEquals(obj.cert.getSerialNumber(), serialHex);
            if (aliasOk && serialOk) {
                best = obj;
                break;
            }
        }
        if (best == null) {
            return null;
        }
        ResolvedKey rk = new ResolvedKey();
        rk.alias = best.label != null ? best.label : toHex(best.cert.getSerialNumber());
        rk.certificate = best.cert;
        rk.certificateChain = Collections.singletonList(best.cert);
        rk.privateKeyHandle = best.privateKeyHandle;
        return rk;
    }

    private static boolean hasMatchingKey(TokenObject certObj, List<TokenObject> all) {
        if (certObj.privateKeyHandle != 0L) {
            return true;
        }
        TokenObject m = findByIdOrLabel(all, certObj.id, certObj.label, false);
        return m != null && m.privateKeyHandle != 0L;
    }

    private static boolean matchingCertExists(TokenObject keyObj, List<TokenObject> all) {
        TokenObject m = findByIdOrLabel(all, keyObj.id, keyObj.label, false);
        return m != null && m.cert != null && m != keyObj;
    }

    /**
     * Token üzerinde {@code cert ↔ private key} eşleştirmesi yapar.
     *
     * <h3>Güvenlik kontratı (Codex regresyonu, Mayıs 2026)</h3>
     * <p>PKCS#11 standart pratiğinde {@code CKA_ID} bir keypair için benzersizdir
     * (cert ve private key aynı ID'yi paylaşır). {@code CKA_LABEL} sadece
     * human-readable bir isim olduğu için duplicate olabilir — özellikle key
     * rotation, yanlış import, ya da admin hatası sonucu.</p>
     *
     * <p>Bu metod şu sıkı kuralları uygular:</p>
     * <ol>
     *   <li><b>CKA_ID present</b> ise: yalnızca ID eşleşmesi geçerlidir.
     *       Label fallback YAPILMAZ — duplicate label durumunda yanlış
     *       eşleşme = yanlış imza riski var. Eşleşme yoksa {@code null} döner.</li>
     *   <li><b>CKA_ID absent</b> (her iki tarafta da boş) ise: label fallback
     *       yapılır AMA sadece tek-eşleşme garantili olmak şartıyla. Birden
     *       fazla aday varsa belirsizlik var demektir — {@code null} dönüp
     *       ambiguity'yi loglarız, asla rastgele bir aday seçmeyiz.</li>
     * </ol>
     *
     * <p>Bu strict politika "sessiz yanlış imza" üretmek yerine "key not found"
     * hatası verir; doğru davranış budur.</p>
     */
    private static TokenObject findByIdOrLabel(List<TokenObject> objects,
                                              byte[] id,
                                              String label,
                                              boolean preferCertSide) {
        // (1) CKA_ID present → yalnızca ID eşleşmesi geçerli; label fallback yok.
        if (id != null && id.length > 0) {
            for (TokenObject obj : objects) {
                if (obj.id != null && obj.id.length > 0
                    && Arrays.equals(obj.id, id)
                    && (!preferCertSide || obj.cert != null)) {
                    return obj;
                }
            }
            // ID verilmiş ama eşleşme yok — burada label fallback'e
            // dönmek key rotation senaryosunda yanlış key bağlar.
            return null;
        }

        // (2) CKA_ID absent → label fallback'e tek-eşleşme garantili izin ver.
        if (label != null && !label.isEmpty()) {
            TokenObject only = null;
            int matches = 0;
            for (TokenObject obj : objects) {
                if (!label.equals(obj.label)) continue;
                if (preferCertSide && obj.cert == null) continue;
                // Sadece kendisi de id-boş olan adaylarla eşle.
                // (id'si dolu olanlar yukarıdaki yolla bağlanmalıdır.)
                if (obj.id != null && obj.id.length > 0) continue;
                only = obj;
                if (++matches > 1) {
                    break;
                }
            }
            if (matches == 1) {
                return only;
            }
            if (matches > 1) {
                LOGGER.warn("Belirsiz eşleşme: CKA_LABEL='{}' ve CKA_ID yok; "
                    + "birden fazla aday var, hiçbiri seçilmiyor (sessiz yanlış "
                    + "imza riskinden kaçınmak için).", label);
            }
        }
        return null;
    }

    private void ensureTokenOpen() {
        if (token == null) {
            throw new KeyStoreException("ipkcs11wrapper modülü kapalı veya init edilmedi");
        }
    }

    private Token resolveToken() throws PKCS11Exception {
        Slot[] slots = module.getSlotList(true /* token present */);
        if (slots.length == 0) {
            throw new KeyStoreException("HSM'de hiç token bulunamadı (library=" + libraryPath + ")");
        }
        if (slot != null) {
            for (Slot s : slots) {
                if (s.getSlotID() == slot.longValue()) {
                    return s.getToken();
                }
            }
            throw new KeyStoreException("PKCS11_SLOT=" + slot + " için token bulunamadı");
        }
        int idx = slotIndex != null ? slotIndex.intValue() : 0;
        if (idx < 0 || idx >= slots.length) {
            throw new KeyStoreException("PKCS11_SLOT_INDEX=" + idx
                + " sınır dışı; toplam slot=" + slots.length);
        }
        return slots[idx].getToken();
    }

    private void cleanupOnFailure() {
        try { if (token != null) token.closeAllSessions(); } catch (Exception ignored) { }
        // Sadece bizim initialize ettiğimiz Cryptoki'yi finalize et — paylaşımlı
        // state korunmalı (destroy()'daki aynı ownership kuralı). Aksi halde
        // init başarısızlığında, paylaşımlı kütüphaneyi de patlatırız.
        if (module != null && ownsInitialization) {
            try { module.finalize(null); } catch (Exception ignored) { }
        }
        token = null;
        module = null;
        ownsInitialization = false;
        singleThreadedMode = false;
    }

    private static X509Certificate parseCert(byte[] der) {
        if (der == null || der.length == 0) return null;
        try {
            return (X509Certificate) CERT_FACTORY.get()
                .generateCertificate(new ByteArrayInputStream(der));
        } catch (Exception e) {
            LOGGER.warn("CKA_VALUE X.509 olarak parse edilemedi: {}", e.getMessage());
            return null;
        }
    }

    private static CertificateFactory createCertFactory() {
        try {
            return CertificateFactory.getInstance("X.509");
        } catch (java.security.cert.CertificateException e) {
            // JRE'de X.509 hep mevcuttur; buraya düşmek = bozuk JRE.
            throw new IllegalStateException("X.509 CertificateFactory bulunamadı", e);
        }
    }

    /**
     * Aynı kütüphane bir başka bileşen tarafından önceden {@code C_Initialize}
     * edilmişse SafeNet PSI-E3 gibi yapılar {@code CKR_CRYPTOKI_ALREADY_INITIALIZED}
     * fırlatır. Bu durumu ölümcül kabul etmiyoruz — modülü zaten kullanabiliriz.
     *
     * <h3>AKİS uyumluluk fallback'i</h3>
     * <p>TÜBİTAK BİLGEM'in {@code libakisp11.dylib} (macOS) ve bazı eski
     * {@code libakisp11.so} (Linux) sürücüleri xipki'nin standart
     * {@code C_Initialize(CK_C_INITIALIZE_ARGS{flags=CKF_OS_LOCKING_OK})}
     * çağrısına {@code CKR_ARGUMENTS_BAD} döner — kütüphane macOS/Linux'ta
     * yalnızca {@code C_Initialize(NULL)} formunu kabul ediyor (Windows
     * portunda problem yok). Bu sürücü bug'ı için xipki'nin
     * {@code PKCS11Module.initialize()} metodunu by-pass edip alttaki
     * {@code PKCS11Implementation.C_Initialize(null, true)}'a doğrudan
     * gidiyoruz; ardından {@code moduleInfo} ve {@code initVendor()}'ı
     * reflection ile çalıştırıyoruz.</p>
     *
     * <p><b>Trade-off:</b> NULL args = PKCS#11 spec §5.4 gereği kütüphane
     * thread-unsafe sayılır; {@link #afterPropertiesSet()} bu modu algılayıp
     * {@link PKCS11Token} pool'unu {@code numSessions=1}'e indirir. Akıllı
     * kart donanımı zaten paralel oturum kaldırmıyor → kullanıcı için
     * görünür bir performans kaybı yok.</p>
     *
     * @return Sahiplik (finalize bizde mi?) ve mod (tek-thread mu?) bilgisi.
     */
    private static InitOutcome initializeIdempotent(PKCS11Module module,
                                                    boolean forceNullInitArgs) throws PKCS11Exception {
        if (forceNullInitArgs) {
            LOGGER.info("PKCS11_NULL_INIT_ARGS=true → standart C_Initialize denenmeden "
                + "doğrudan NULL-args yoluna gidiliyor (AKİS / TÜBİTAK uyumluluk modu).");
            initializeWithNullArgs(module);
            return new InitOutcome(true, true);
        }
        try {
            module.initialize();
            return new InitOutcome(true, false);
        } catch (PKCS11Exception e) {
            if (e.getErrorCode() == PKCS11Constants.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
                LOGGER.info("PKCS#11 modülü önceden initialize edilmiş; mevcut state kullanılıyor "
                    + "ve destroy() üzerinde finalize çağrılmayacak (paylaşımlı state korunur).");
                return new InitOutcome(false, false);
            }
            if (e.getErrorCode() == PKCS11Constants.CKR_ARGUMENTS_BAD) {
                // AKİS macOS sürücüsü tipik davranışı. Reflection ile NULL-args
                // yoluna düş; başarılıysa singleThreadedMode aktive ederiz.
                LOGGER.warn("Standart C_Initialize CKR_ARGUMENTS_BAD ile reddedildi "
                    + "(genellikle TÜBİTAK AKİS macOS/Linux sürücüsü). NULL-args "
                    + "fallback deneniyor (AKİS uyumluluk modu).");
                initializeWithNullArgs(module);
                LOGGER.info("NULL-args fallback başarılı; bundan sonra tek session "
                    + "modunda çalışacağız (PKCS#11 spec §5.4).");
                return new InitOutcome(true, true);
            }
            throw e;
        }
    }

    /**
     * xipki {@link PKCS11Module} private {@code pkcs11} alanını reflection ile
     * tutuyoruz; alttaki IAIK {@code PKCS11Implementation.C_Initialize(null, true)}
     * çağrısını doğrudan yapıyoruz. Ardından moduleInfo + vendor init adımlarını
     * da reflection ile çalıştırıyoruz ki sonraki çağrılar (örn.
     * {@code module.codeToName}) çökmeyelim.
     *
     * <p>İstisna yönetimi: moduleInfo / initVendor adımları best-effort —
     * vendor.conf'ta AKİS girdisi yok, sorun değil; standart RSA/ECDSA
     * mekanizmaları ipkcs11wrapper'da vendor-bağımsız çözülür.</p>
     */
    private static void initializeWithNullArgs(PKCS11Module module) throws PKCS11Exception {
        try {
            Field pkcs11Field = PKCS11Module.class.getDeclaredField("pkcs11");
            pkcs11Field.setAccessible(true);
            Object pkcs11Impl = pkcs11Field.get(module);
            if (pkcs11Impl == null) {
                throw new IllegalStateException("PKCS11Module.pkcs11 reflection alanı null döndü; "
                    + "ipkcs11wrapper sürümü beklenenden farklı olabilir.");
            }

            Method cInit = pkcs11Impl.getClass()
                .getMethod("C_Initialize", Object.class, boolean.class);
            try {
                // Object[] cast explicit — varargs ambiguity'den kaçınmak için.
                cInit.invoke(pkcs11Impl, new Object[] { null, Boolean.TRUE });
            } catch (java.lang.reflect.InvocationTargetException ite) {
                Throwable cause = ite.getCause();
                if (cause instanceof iaik.pkcs.pkcs11.wrapper.PKCS11Exception) {
                    iaik.pkcs.pkcs11.wrapper.PKCS11Exception iaikEx =
                        (iaik.pkcs.pkcs11.wrapper.PKCS11Exception) cause;
                    if (iaikEx.getErrorCode() == PKCS11Constants.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
                        // Ortak bir bileşen Cryptoki state'i zaten tutuyor;
                        // outer initializeIdempotent ALREADY_INITIALIZED dalında
                        // ownership=false döndürmeli — biz buraya düştüysek
                        // demek ki ilk denemede başarılı olmadık ama başka biri
                        // initialize etmiş. Bu nadir bir yarış; konservatif:
                        // sahipliği reddet.
                        throw new PKCS11Exception(iaikEx.getErrorCode());
                    }
                    throw new PKCS11Exception(iaikEx.getErrorCode());
                }
                throw new IllegalStateException("Beklenmedik native C_Initialize hatası", cause);
            }

            // Best-effort: moduleInfo + initVendor.
            try {
                Method cGetInfo = pkcs11Impl.getClass().getMethod("C_GetInfo");
                Object ckInfo = cGetInfo.invoke(pkcs11Impl);
                Class<?> ckInfoClass = Class.forName("iaik.pkcs.pkcs11.wrapper.CK_INFO");
                Class<?> moduleInfoClass = Class.forName("org.xipki.pkcs11.wrapper.ModuleInfo");
                Object moduleInfo = moduleInfoClass
                    .getConstructor(ckInfoClass).newInstance(ckInfo);
                Field moduleInfoField = PKCS11Module.class.getDeclaredField("moduleInfo");
                moduleInfoField.setAccessible(true);
                moduleInfoField.set(module, moduleInfo);
            } catch (Exception ignored) {
                LOGGER.debug("moduleInfo best-effort populate başarısız (kritik değil): {}",
                    ignored.getMessage());
            }
            try {
                Method initVendor = PKCS11Module.class.getDeclaredMethod("initVendor");
                initVendor.setAccessible(true);
                initVendor.invoke(module);
            } catch (Exception ignored) {
                LOGGER.debug("initVendor best-effort çağrı başarısız (kritik değil): {}",
                    ignored.getMessage());
            }
        } catch (PKCS11Exception | RuntimeException ex) {
            throw ex;
        } catch (Exception ex) {
            // Reflection / native köprüsünde beklenmedik hata → operatöre
            // mesaj zincirini görünür tut.
            throw new IllegalStateException(
                "ipkcs11wrapper NULL-init-args fallback yolu başarısız: "
                + ex.getMessage(), ex);
        }
    }

    /** {@link #initializeIdempotent} sonucu. Çağıran sınıf hangi yolu aldığımızı bilmeli. */
    private static final class InitOutcome {
        final boolean owned;
        final boolean singleThreaded;
        InitOutcome(boolean owned, boolean singleThreaded) {
            this.owned = owned;
            this.singleThreaded = singleThreaded;
        }
    }

    private static String safeTrim(Object value) {
        if (value == null) return "";
        if (value instanceof char[]) {
            return new String((char[]) value).trim();
        }
        return value.toString().trim();
    }

    private static String toHex(BigInteger n) {
        return n == null ? "" : n.toString(16).toUpperCase();
    }

    private static boolean serialHexEquals(BigInteger candidate, String requested) {
        try {
            return Objects.equals(candidate, new BigInteger(requested, 16));
        } catch (Exception e) {
            return false;
        }
    }

    private static byte[] hash(byte[] data, SignatureAlgorithm sa) {
        try {
            String algo = sa.getDigestAlgorithm().getJavaName();
            return MessageDigest.getInstance(algo).digest(data);
        } catch (Exception e) {
            throw new io.mersel.dss.signer.api.exceptions.SignatureException(
                "Digest hesaplanamadı: " + sa, e);
        }
    }

    // --------------------------------------------------------------------
    // Data classes
    // --------------------------------------------------------------------

    /** Token üzerinde bulunan tek bir obje (cert, private key veya her ikisi). */
    private static final class TokenObject {
        String label;
        byte[] id;
        X509Certificate cert;
        long privateKeyHandle; // 0 = yok
    }

    /**
     * {@link #findSigner} sonucu: cert + chain + key handle. {@link IaikPkcs11Signer}
     * bu yapıyı tutar ve sign çağrısında handle'ı modüle delege eder.
     */
    static final class ResolvedKey {
        String alias;
        // SMS recovery (CKR_SMS_ERROR / CKR_NO_SESSION_KEYS) sonrası
        // reinitializeForSmsRecovery() çağrısı bu instance'ı in-place
        // günceller — çağıran (IaikPkcs11Signer, HsmHeartbeatScheduler)
        // referansı koruyup yeni handle ile devam edebilsin. volatile,
        // sign-thread'in stale long okumamasını garantiler.
        volatile X509Certificate certificate;
        volatile List<X509Certificate> certificateChain;
        volatile long privateKeyHandle;
    }
}
