package io.mersel.dss.signer.api.services;

import io.mersel.dss.signer.api.models.SigningContext;
import io.mersel.dss.signer.api.models.SigningKeyEntry;
import io.mersel.dss.signer.api.models.SigningMaterial;
import io.mersel.dss.signer.api.services.certificate.CertificateChainBuilderService;
import io.mersel.dss.signer.api.services.certificate.CertificateValidatorService;
import io.mersel.dss.signer.api.services.keystore.KeyStoreLoaderService;
import io.mersel.dss.signer.api.services.keystore.KeyStoreProvider;
import io.mersel.dss.signer.api.services.keystore.iaik.Pkcs11ModulePort;
import io.mersel.dss.signer.api.services.keystore.iaik.Pkcs11Signer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * {@link SigningContext} oluşturan fabrika. İki backend'i tek API'nin
 * arkasına alır:
 *
 * <ul>
 *   <li>{@link #createPfxSigningContext} — JCA {@link KeyStore} +
 *       {@link PrivateKey} kullanır. PFX/PKCS#12 dosyaları için ideal.</li>
 *   <li>{@link #createPkcs11SigningContext} — {@link Pkcs11ModulePort}
 *       üzerinden HSM'de C_FindObjects + C_Sign çağırır (in-process veya
 *       out-of-process köprü); SunPKCS11'in P11KeyStore alias-mapping
 *       katmanını tamamen by-pass eder.</li>
 * </ul>
 *
 * <p>İki yol da {@link SigningContext} döner; çağıran kod
 * ({@link io.mersel.dss.signer.api.config.SignatureConfiguration}) hangi
 * backend'in yapılandırıldığına bakıp birini çağırır.</p>
 */
@Service
public class SigningMaterialFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(SigningMaterialFactory.class);

    private final KeyStoreLoaderService keyStoreLoader;
    private final CertificateChainBuilderService chainBuilder;
    private final CertificateValidatorService certificateValidator;

    public SigningMaterialFactory(KeyStoreLoaderService keyStoreLoader,
                                 CertificateChainBuilderService chainBuilder,
                                 CertificateValidatorService certificateValidator) {
        this.keyStoreLoader = keyStoreLoader;
        this.chainBuilder = chainBuilder;
        this.certificateValidator = certificateValidator;
    }

    /**
     * PFX / PKCS#12 yolunda {@link SigningContext} üretir. JCA {@link KeyStore}
     * yüklenir, {@link PrivateKey} alınır, zincir derlenir.
     */
    public SigningContext createPfxSigningContext(KeyStoreProvider provider,
                                                  char[] pin,
                                                  String certificateAlias,
                                                  String certificateSerialNumber) {
        try {
            LOGGER.info("{} keystore kullanılarak (PFX yolu) signing context oluşturuluyor",
                provider.getType());

            KeyStore keyStore = keyStoreLoader.loadKeyStore(provider, pin);
            SigningKeyEntry keyEntry = keyStoreLoader.resolveKeyEntry(
                keyStore, provider, pin, certificateAlias, certificateSerialNumber);

            PrivateKey privateKey = keyEntry.getEntry().getPrivateKey();
            X509Certificate certificate = (X509Certificate) keyEntry.getEntry().getCertificate();

            certificateValidator.validateCertificateDates(certificate);
            List<X509Certificate> chain = chainBuilder.buildCertificateChain(certificate);
            SigningMaterial material = new SigningMaterial(privateKey, certificate, chain);

            LOGGER.info("PFX signing context hazır. Sertifika: {}, Zincir uzunluğu: {}",
                certificate.getSubjectX500Principal(), chain.size());

            return new SigningContext(keyEntry.getAlias(), material);

        } catch (Exception e) {
            LOGGER.error("PFX signing context oluşturulamadı", e);
            throw new io.mersel.dss.signer.api.exceptions.KeyStoreException(
                "PFX signing context oluşturulamadı: " + e.getMessage(), e);
        }
    }

    /**
     * HSM / PKCS#11 yolunda {@link SigningContext} üretir.
     * {@link Pkcs11ModulePort#findSigner} ile token'da private key + cert
     * çözülür; private key referansı HSM'de (veya helper process'te) kalır.
     */
    public SigningContext createPkcs11SigningContext(Pkcs11ModulePort module,
                                                     String certificateAlias,
                                                     String certificateSerialNumber) {
        try {
            LOGGER.info("IAIK PKCS#11 modülü kullanılarak (HSM yolu) signing context oluşturuluyor");

            Pkcs11Signer signer = module.findSigner(certificateAlias, certificateSerialNumber);
            X509Certificate certificate = signer.getCertificate();

            certificateValidator.validateCertificateDates(certificate);
            List<X509Certificate> chain = chainBuilder.buildCertificateChain(certificate);
            SigningMaterial material = new SigningMaterial(signer, certificate, chain);

            LOGGER.info("HSM signing context hazır. Sertifika: {}, Zincir uzunluğu: {}, alias: {}",
                certificate.getSubjectX500Principal(), chain.size(), signer.getAlias());

            return new SigningContext(signer.getAlias(), material);

        } catch (Exception e) {
            LOGGER.error("HSM signing context oluşturulamadı", e);
            throw new io.mersel.dss.signer.api.exceptions.KeyStoreException(
                "HSM signing context oluşturulamadı: " + e.getMessage(), e);
        }
    }
}

