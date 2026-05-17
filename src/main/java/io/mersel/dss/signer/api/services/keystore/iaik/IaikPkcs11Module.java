package io.mersel.dss.signer.api.services.keystore.iaik;

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
 * akışları paralel yürür. Eş zamanlı imza üst sınırı
 * {@link io.mersel.dss.signer.api.config.SignatureConfiguration} semaphore'u
 * tarafından belirlenir. Yalnızca {@link #destroy()} ve cache yazma
 * ({@link ConcurrentHashMap#computeIfAbsent}) koruma altında.</p>
 *
 * <h2>Acknowledgment</h2>
 * <p>This product includes software developed by IAIK of Graz University of
 * Technology.</p>
 */
public class IaikPkcs11Module implements InitializingBean, DisposableBean {

    private static final Logger LOGGER = LoggerFactory.getLogger(IaikPkcs11Module.class);

    private final String libraryPath;
    private final Long slot;
    private final Long slotIndex;
    private final char[] pin;

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
     * İmza ataçımı için bulunan ilk private key + cert eşleşmesi cache'i.
     * Concurrent: {@link ConcurrentHashMap#computeIfAbsent} ile lock-free okuma.
     */
    private final Map<String, ResolvedKey> resolvedKeyCache = new ConcurrentHashMap<>();

    public IaikPkcs11Module(String libraryPath, Long slot, Long slotIndex, char[] pin) {
        this.libraryPath = libraryPath;
        this.slot = slot;
        this.slotIndex = slotIndex;
        this.pin = pin == null ? null : pin.clone();
    }

    // --------------------------------------------------------------------
    // Lifecycle
    // --------------------------------------------------------------------

    @Override
    public void afterPropertiesSet() {
        try {
            LOGGER.info("ipkcs11wrapper modülü yükleniyor: library={}", libraryPath);
            module = PKCS11Module.getInstance(libraryPath);
            ownsInitialization = initializeIdempotent(module);

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
            token = new PKCS11Token(rawToken, true /* readOnly */, effectivePin);
            if (effectivePin != null) {
                LOGGER.info("HSM token'a USER olarak login başarılı.");
            }
        } catch (Exception e) {
            cleanupOnFailure();
            throw new KeyStoreException(
                "ipkcs11wrapper modülü initialize edilemedi: " + libraryPath, e);
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
     * Sağlanan private key handle'ı üzerinden HSM'de imza atar. Eğer
     * {@link IaikSignatureMechanisms} ECDSA / RSA-PKCS mekanizmasını
     * destekleyemiyor diye raw mekanizmaya düşürmek isterse digest'i
     * dışarıda hesaplayıp raw byte'ları imzalatır.
     */
    /**
     * Token üzerinde imza atar. PKCS11Token kendi içinde thread-safe oturum
     * havuzu yönettiği için bu metoda eş zamanlı çağrı sağlanır; üst sınır
     * {@code signatureSemaphore} ile kontrol edilir.
     */
    byte[] signOnSession(long privateKeyHandle,
                         byte[] dataToSign,
                         SignatureAlgorithm signatureAlgorithm) {
        ensureTokenOpen();
        try {
            Mechanism mechanism = IaikSignatureMechanisms.resolveMechanism(signatureAlgorithm);
            byte[] inputData = IaikSignatureMechanisms.requiresExternalDigest(mechanism)
                ? hash(dataToSign, signatureAlgorithm)
                : dataToSign;

            byte[] signature = token.sign(mechanism, privateKeyHandle, inputData);
            LOGGER.debug("HSM imza tamamlandı: mech=0x{}, dataLen={}, sigLen={}",
                Long.toHexString(mechanism.getMechanismCode()),
                dataToSign.length, signature.length);
            return normalizeIfEcOrDsa(signature, signatureAlgorithm);
        } catch (PKCS11Exception ckEx) {
            // Bazı eski HSM'lerde CKM_<HASH>_ECDSA / CKM_<HASH>_RSA_PKCS
            // desteklenmez. Fallback'i deneyelim — RSA-PSS hariç (raw
            // CKM_RSA_PKCS'e indirgeme PSS imzasını sessizce v1.5'e çevirir,
            // bu yanlış imzadır → açıkça reddet).
            if (ckEx.getErrorCode() == PKCS11Constants.CKR_MECHANISM_INVALID) {
                if (signatureAlgorithm.getEncryptionAlgorithm() == EncryptionAlgorithm.RSASSA_PSS) {
                    throw new io.mersel.dss.signer.api.exceptions.SignatureException(
                        "HSM bu sürümüyle RSA-PSS imzayı desteklemiyor; raw fallback "
                        + "PKCS#1 v1.5'e indirgeme yapar, bu imza GEÇERSİZ olur. "
                        + "Lütfen RSA-PSS yerine RSA-PKCS#1 v1.5 algoritmasıyla "
                        + "yapılandırın veya HSM firmware'ini güncelleyin.", ckEx);
                }
                LOGGER.warn("Mekanizma reddedildi (CKR_MECHANISM_INVALID); raw fallback'e düşülüyor.");
                return signWithRawFallback(privateKeyHandle, dataToSign, signatureAlgorithm);
            }
            throw new io.mersel.dss.signer.api.exceptions.SignatureException(
                "HSM imza başarısız: " + ckEx.getMessage(), ckEx);
        } catch (Exception e) {
            throw new io.mersel.dss.signer.api.exceptions.SignatureException(
                "HSM imza başarısız", e);
        }
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
            byte[] signature = token.sign(rawMech, privateKeyHandle, inputData);
            return normalizeIfEcOrDsa(signature, signatureAlgorithm);
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
     * @return {@code true} eğer {@code C_Initialize} bu çağrıda başarıyla
     *         çalıştıysa (sahiplik bizdedir; destroy'da finalize çağrılabilir);
     *         {@code false} eğer Cryptoki başka bir bileşen tarafından zaten
     *         init edilmişse (finalize çağırırsak diğer bileşenleri patlatırız).
     */
    private static boolean initializeIdempotent(PKCS11Module module) throws PKCS11Exception {
        try {
            module.initialize();
            return true;
        } catch (PKCS11Exception e) {
            if (e.getErrorCode() == PKCS11Constants.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
                LOGGER.info("PKCS#11 modülü önceden initialize edilmiş; mevcut state kullanılıyor "
                    + "ve destroy() üzerinde finalize çağrılmayacak (paylaşımlı state korunur).");
                return false;
            }
            throw e;
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
        X509Certificate certificate;
        List<X509Certificate> certificateChain;
        long privateKeyHandle;
    }
}
