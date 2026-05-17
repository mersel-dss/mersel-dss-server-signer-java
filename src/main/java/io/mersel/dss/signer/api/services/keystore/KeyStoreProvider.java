package io.mersel.dss.signer.api.services.keystore;

import java.security.KeyStore;

/**
 * Farklı kaynaklardan KeyStore yüklemek için interface.
 *
 * <p>Bu arabirim artık <b>yalnızca JCA-tabanlı kaynaklar</b> (PFX/PKCS#12)
 * için anlamlıdır. PKCS#11 (HSM) yapılandırmasında
 * {@link PKCS11KeyStoreProvider} sadece tip markörü olarak vardır;
 * {@code loadKeyStore} çağrılırsa {@link UnsupportedOperationException}
 * fırlatır çünkü gerçek anahtar materyali HSM'de kalır ve
 * {@link io.mersel.dss.signer.api.services.keystore.iaik.IaikPkcs11Module}
 * üzerinden erişilir.</p>
 */
public interface KeyStoreProvider {

    /**
     * Yapılandırılmış kaynaktan bir KeyStore yükler.
     *
     * @param pin Keystore'u açmak için PIN/şifre
     * @return Yüklenmiş KeyStore örneği
     * @throws io.mersel.dss.signer.api.exceptions.KeyStoreException Yükleme başarısız olursa
     * @throws UnsupportedOperationException PKCS#11 yolunda çağrılırsa
     */
    KeyStore loadKeyStore(char[] pin);

    /**
     * Bu sağlayıcının yönettiği keystore tipini döndürür.
     *
     * @return KeyStore tipi (örn. "PKCS11", "PKCS12")
     */
    String getType();
}

