package io.mersel.dss.signer.api.services.keystore;

/**
 * PKCS#11 yapılandırması için marker {@link KeyStoreProvider}.
 *
 * <p>Eski sürümlerde bu sınıf SunPKCS11 üzerinden gerçek bir JCA
 * {@link java.security.KeyStore} oluşturuyordu (forceLogin, slot list index,
 * showInfo gibi config tweak'leri dahil). Artık tüm PKCS#11 operasyonları
 * {@link io.mersel.dss.signer.api.services.keystore.iaik.IaikPkcs11Module}
 * üzerinden yürütüldüğü için bu sınıf yalnızca <em>type discrimination</em>
 * için kullanılır:</p>
 *
 * <ul>
 *   <li>{@link io.mersel.dss.signer.api.config.SignatureConfiguration}
 *       PKCS#11 yapılandırmasında bu bean'i {@code KeyStoreProvider}
 *       arabiriminin somut implementasyonu olarak üretir; controller ve
 *       service'ler {@code instanceof PKCS11KeyStoreProvider} ile yola
 *       bakabilir.</li>
 *   <li>{@link #getType()} → "PKCS11" — info endpoint'i için.</li>
 *   <li>{@link #loadKeyStore} → {@link UnsupportedOperationException}.
 *       Gerçek anahtar materyali HSM'de kalır; JCA {@code KeyStore} arayüzü
 *       üzerinden yüklenmez.</li>
 * </ul>
 */
public class PKCS11KeyStoreProvider implements KeyStoreProvider {

    private final String libraryPath;
    private final Long slot;
    private final Long slotIndex;

    public PKCS11KeyStoreProvider(String libraryPath, Long slot, Long slotIndex) {
        this.libraryPath = libraryPath;
        this.slot = slot;
        this.slotIndex = slotIndex;
    }

    @Override
    public java.security.KeyStore loadKeyStore(char[] pin) {
        throw new UnsupportedOperationException(
            "PKCS#11 yolunda JCA KeyStore artık yüklenmiyor. "
            + "İmzalama ve listeleme akışı IaikPkcs11Module üzerinden çalışır. "
            + "PFX yapılandırması için PfxKeyStoreProvider kullanın.");
    }

    @Override
    public String getType() {
        return "PKCS11";
    }

    public String getLibraryPath() {
        return libraryPath;
    }

    public Long getSlot() {
        return slot;
    }

    public Long getSlotIndex() {
        return slotIndex;
    }
}
