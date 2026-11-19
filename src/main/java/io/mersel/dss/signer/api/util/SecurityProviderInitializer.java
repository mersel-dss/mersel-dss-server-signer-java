package io.mersel.dss.signer.api.util;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

/**
 * BouncyCastle JCE provider'ının tek noktadan, idempotent şekilde kaydını sağlar.
 *
 * <p>Daha önce {@code CertificateFolderResolver} ve {@code AbstractKamuSMXmlDepoResolver}
 * aynı {@code Security.addProvider(new BouncyCastleProvider())} çağrısını ayrı
 * static bloklarda tekrarlıyordu. Burada toplanarak tekrar giderildi ve
 * "zaten kayıtlıysa tekrar ekleme" güvencesi eklendi.</p>
 *
 * <p><b>Not:</b> Bu yardımcı, provider'ı listenin <i>sonuna</i> ekler (mevcut
 * davranışın korunması için). {@code KeyStoreLoaderService} ise bilinçli olarak
 * farklı bir kayıt yapar (BC'yi 1. sıraya alıp SunEC'i kaldırır); o özel mantık
 * kasıtlı olduğundan buraya taşınmamıştır.</p>
 */
public final class SecurityProviderInitializer {

    private SecurityProviderInitializer() {
        // Utility class - örneklenmemeli
    }

    /**
     * BouncyCastle provider'ı kayıtlı değilse ekler. Birden çok kez çağrılması güvenlidir.
     */
    public static void ensureBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }
}
