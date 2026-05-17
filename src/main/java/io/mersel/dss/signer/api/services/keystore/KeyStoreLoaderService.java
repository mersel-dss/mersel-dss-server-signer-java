package io.mersel.dss.signer.api.services.keystore;

import io.mersel.dss.signer.api.exceptions.KeyStoreException;
import io.mersel.dss.signer.api.models.SigningKeyEntry;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.math.BigInteger;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

/**
 * PFX / PKCS#12 yolu için keystore yükleme ve imzalama anahtarı çözümleme.
 *
 * <p>Bu servis artık <b>sadece JCA tabanlı keystore'lar</b> (PFX dosyaları)
 * için çalışır. PKCS#11 (HSM) yolu tamamen
 * {@link io.mersel.dss.signer.api.services.keystore.iaik.IaikPkcs11Module}
 * üzerinden yürütülür ve bu servisten geçmez.</p>
 */
@Service
public class KeyStoreLoaderService {

    private static final Logger LOGGER = LoggerFactory.getLogger(KeyStoreLoaderService.class);

    /** Sağlayıcı üzerinden JCA KeyStore yükler. */
    public KeyStore loadKeyStore(KeyStoreProvider provider, char[] pin) {
        return provider.loadKeyStore(pin);
    }

    /**
     * Backward-compat — tek metod ismi, provider parametresi olmadan da çalışır.
     */
    public SigningKeyEntry resolveKeyEntry(KeyStore keyStore,
                                          char[] pin,
                                          String certificateAlias,
                                          String certificateSerialNumber) {
        return resolveKeyEntry(keyStore, null, pin, certificateAlias, certificateSerialNumber);
    }

    /**
     * Alias veya seri numarasına göre keystore'dan imzalama anahtar girdisini çözümler.
     *
     * <p>Alias verilmişse doğrudan {@code keyStore.getEntry(alias, ...)}; serial
     * verilmişse {@code keyStore.aliases()} üzerinde döner ve serial eşleşeni
     * bulur. İkisi de verilmemişse private key'i olan ilk entry seçilir.</p>
     *
     * @param keyStore Yüklenmiş PFX KeyStore
     * @param provider {@link KeyStoreProvider} — sadece hata mesajları için referans, listing yapmaz
     * @param pin Private key'lere erişim için PIN
     * @param certificateAlias İsteğe bağlı alias
     * @param certificateSerialNumber İsteğe bağlı serial (hex)
     */
    public SigningKeyEntry resolveKeyEntry(KeyStore keyStore,
                                          KeyStoreProvider provider,
                                          char[] pin,
                                          String certificateAlias,
                                          String certificateSerialNumber) {
        try {
            KeyStore.PasswordProtection protection = new KeyStore.PasswordProtection(pin);
            ensureBouncyCastleRegistered();

            if (StringUtils.hasText(certificateAlias)) {
                return resolveByAlias(keyStore, certificateAlias, protection);
            }
            return resolveByIteration(keyStore, certificateSerialNumber, protection);
        } catch (KeyStoreException e) {
            throw e;
        } catch (Exception e) {
            throw new KeyStoreException("Keystore'dan imzalama anahtarı çözümlenemedi", e);
        }
    }

    private SigningKeyEntry resolveByAlias(KeyStore keyStore,
                                           String alias,
                                           KeyStore.PasswordProtection protection) throws Exception {
        if (!keyStore.isKeyEntry(alias)) {
            throw new KeyStoreException(
                "Alias '" + alias + "' KeyStore'da key entry değil. "
                + "Mevcut alias'lar: " + listAliasesSafe(keyStore));
        }
        KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, protection);
        if (entry == null) {
            throw new KeyStoreException("Alias '" + alias + "' için getEntry() null döndü");
        }
        LOGGER.info("İmzalama anahtarı bulundu: alias='{}'", alias);
        return new SigningKeyEntry(alias, entry);
    }

    private SigningKeyEntry resolveByIteration(KeyStore keyStore,
                                              String requestedSerial,
                                              KeyStore.PasswordProtection protection) throws Exception {
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            try {
                if (!keyStore.isKeyEntry(alias)) {
                    continue;
                }
                if (StringUtils.hasText(requestedSerial)) {
                    java.security.cert.Certificate c = keyStore.getCertificate(alias);
                    if (!(c instanceof X509Certificate)) {
                        continue;
                    }
                    if (!serialHexEquals(((X509Certificate) c).getSerialNumber(), requestedSerial)) {
                        continue;
                    }
                }
                KeyStore.PrivateKeyEntry entry =
                    (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, protection);
                if (entry != null) {
                    LOGGER.info("İmzalama anahtarı bulundu: alias='{}'", alias);
                    return new SigningKeyEntry(alias, entry);
                }
            } catch (Exception e) {
                LOGGER.warn("Alias '{}' incelenirken hata: {}", alias, e.getMessage());
            }
        }
        throw new KeyStoreException(
            "KeyStore'da uygun imzalama anahtarı bulunamadı"
            + (StringUtils.hasText(requestedSerial) ? " (serial=" + requestedSerial + ")" : "")
            + ". Mevcut alias'lar: " + listAliasesSafe(keyStore));
    }

    private static boolean serialHexEquals(BigInteger candidate, String requestedHex) {
        try {
            return candidate != null && candidate.equals(new BigInteger(requestedHex, 16));
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private static List<String> listAliasesSafe(KeyStore keyStore) {
        List<String> result = new ArrayList<>();
        try {
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                result.add(aliases.nextElement());
            }
        } catch (Exception ignored) {
            // boş liste OK
        }
        return result;
    }

    /**
     * PFX yolunda BouncyCastle JCA provider'ını garanti eder. PFX dosyalarındaki
     * EC anahtarları SunEC'nin parse edemediği explicit ECParameters içerebilir;
     * BC eklenince hem named hem explicit form parse edilir.
     *
     * <h3>⚠️ JVM-wide yan etki</h3>
     * <p>Bu metod {@code Security.removeProvider("SunEC")} + BouncyCastle'ı
     * {@code position=1} olarak ekler. Bu değişiklik <b>process'in tüm JCA
     * akışını etkiler</b>: TLS handshake, DSS validation, başka bir bean'in
     * {@code Signature.getInstance}'ı vs. Migration öncesi davranış — yeni
     * bir yan etki değil. Yine de farkındalık:</p>
     * <ul>
     *   <li>İlk PFX yükleme anında bir kez tetiklenir, sonra idempotent.</li>
     *   <li>HSM/PKCS#11 yolunda bu metoda <b>hiç</b> uğranılmaz — JVM provider
     *       sırası bozulmaz.</li>
     *   <li>Eğer ileride başka bir bileşen FIPS-only veya SunEC-specific
     *       davranışa bağlı çalışırsa, PFX yolunu kullanıma soktuğunuzda
     *       beklenmedik regression görebilirsiniz.</li>
     * </ul>
     */
    private static synchronized void ensureBouncyCastleRegistered() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) != null
                && Security.getProvider("SunEC") == null) {
            return;
        }
        Security.removeProvider("SunEC");
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        }
        LOGGER.info("BouncyCastle EC AlgorithmParameters desteği etkinleştirildi, SunEC kaldırıldı");
    }
}
