package io.mersel.dss.signer.api.e2e.verifier;

import io.mersel.dss.signer.api.models.SigningKeyEntry;
import io.mersel.dss.signer.api.models.SigningMaterial;
import io.mersel.dss.signer.api.services.keystore.KeyStoreLoaderService;
import io.mersel.dss.signer.api.services.keystore.PfxKeyStoreProvider;
import io.mersel.dss.signer.api.testsupport.PfxBackedPkcs11Signer;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * E2E testleri için PFX dosyalarından {@link SigningMaterial} üretir.
 *
 * <p>Production kodundaki {@link io.mersel.dss.signer.api.services.SigningMaterialFactory}
 * ile aynı yolu kullanır ({@link KeyStoreLoaderService} → JCA KeyStore →
 * {@link KeyStore.PrivateKeyEntry}); sertifika zinciri PFX'in kendi
 * <code>{@link KeyStore#getCertificateChain(String)}</code> çıktısından alınır,
 * online AIA fetch yapılmaz (test izolasyonu için kritik — internet flaky
 * olduğunda testler sallanmasın).</p>
 */
public final class E2eSigningMaterialFactory {

    private static final KeyStoreLoaderService LOADER = new KeyStoreLoaderService();

    private E2eSigningMaterialFactory() {
        // utility class
    }

    /**
     * Verilen PFX'i yükler ve içindeki ilk imzalama anahtarı için
     * {@link SigningMaterial} döner.
     *
     * <p>Sertifika zinciri PFX'te bulunduğu şekilde alınır (genellikle
     * leaf + intermediate; bazı PFX'lerde root da gömülüdür). Verifier
     * eksik halkaları kendi trust anchor deposundan tamamlar.</p>
     */
    public static SigningMaterial load(PfxTestKey key) {
        LoadedPfx loaded = loadPfx(key);
        return new SigningMaterial(loaded.privateKey, loaded.signingCert, loaded.chain);
    }

    /**
     * Verilen PFX'i test-only {@link PfxBackedPkcs11Signer} olarak sarar.
     *
     * <p>Bu materyal gerçek SoftHSM değildir; ancak production HSM branch'lerini
     * gerçek kriptografik imza ile çalıştırır. Default hızlı testlerde HSM kod
     * yolunu kör bırakmamak için kullanılır.</p>
     */
    public static SigningMaterial loadAsPkcs11(PfxTestKey key) {
        LoadedPfx loaded = loadPfx(key);
        PfxBackedPkcs11Signer signer = new PfxBackedPkcs11Signer(
            key.getAlias(), loaded.privateKey, loaded.signingCert, loaded.chain);
        return new SigningMaterial(signer, loaded.signingCert, loaded.chain);
    }

    private static LoadedPfx loadPfx(PfxTestKey key) {
        char[] pin = key.getPassword();
        try {
            PfxKeyStoreProvider provider = new PfxKeyStoreProvider(key.getAbsolutePath());
            KeyStore keyStore = LOADER.loadKeyStore(provider, pin);
            // NOT: alias parametresi BİLEREK null. KeyStoreLoaderService'in
            // PFX yolu BouncyCastle'ı JVM-wide priority 1 yapıyor (SunEC
            // kaldırılır). İlk yüklemede SunJSSE PKCS12 alias'ı "1" olarak
            // okurken, sonraki çağrılarda BC PKCS12 reader devreye girer ve
            // friendlyName yerine localKeyId hex'ini ("01000000" vb.) alias
            // yapar. Test PFX'lerinde tek key entry olduğundan null geçmek
            // iterasyon yoluna düşer ve provider farkından bağımsız ilk
            // (ve tek) key'i bulur. Production'a dokunmadan en güvenli yol.
            SigningKeyEntry keyEntry = LOADER.resolveKeyEntry(
                    keyStore, provider, pin, null, null);

            PrivateKey privateKey = keyEntry.getEntry().getPrivateKey();
            X509Certificate signingCert =
                    (X509Certificate) keyEntry.getEntry().getCertificate();

            // KeyStore.getCertificateChain → leaf + (varsa) intermediate'lar.
            // PFX'in içindeki ne varsa onu kullanıyoruz; eksikleri verifier
            // KamuSM trust deposundan tamamlar.
            Certificate[] storeChain;
            try {
                storeChain = keyStore.getCertificateChain(keyEntry.getAlias());
            } catch (java.security.KeyStoreException e) {
                throw new IllegalStateException(
                        "PFX'ten sertifika zinciri alınamadı: " + key.getFileName(), e);
            }

            List<X509Certificate> chain;
            if (storeChain != null && storeChain.length > 0) {
                chain = new ArrayList<>(storeChain.length);
                for (Certificate c : storeChain) {
                    if (c instanceof X509Certificate) {
                        chain.add((X509Certificate) c);
                    }
                }
            } else {
                chain = Collections.singletonList(signingCert);
            }

            return new LoadedPfx(privateKey, signingCert, chain);

        } finally {
            // Defensive — JCA pin char[]'ını sıfırla. PFX yolu için
            // teknik olarak şart değil ama hijyen.
            java.util.Arrays.fill(pin, '\0');
        }
    }

    private static final class LoadedPfx {
        private final PrivateKey privateKey;
        private final X509Certificate signingCert;
        private final List<X509Certificate> chain;

        private LoadedPfx(PrivateKey privateKey,
                          X509Certificate signingCert,
                          List<X509Certificate> chain) {
            this.privateKey = privateKey;
            this.signingCert = signingCert;
            this.chain = chain;
        }
    }
}
