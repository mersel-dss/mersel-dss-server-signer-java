package io.mersel.dss.signer.api.services;

import io.mersel.dss.signer.api.dtos.CertificateInfoDto;
import io.mersel.dss.signer.api.exceptions.KeyStoreException;
import io.mersel.dss.signer.api.models.SigningMaterial;
import io.mersel.dss.signer.api.services.keystore.KeyStoreProvider;
import io.mersel.dss.signer.api.services.keystore.PKCS11KeyStoreProvider;
import io.mersel.dss.signer.api.services.keystore.iaik.Pkcs11ModulePort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.KeyStore;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Enumeration;
import java.util.List;

/**
 * Keystore içerisindeki sertifika bilgilerini listeleme servisi.
 *
 * <p>Üç katmanlı kaynak sırası:</p>
 * <ol>
 *   <li><b>PKCS#11</b> (container'da {@link Pkcs11ModulePort} bean'i
 *       varsa — in-process veya remote köprü) — primary kaynak. SunPKCS11'in
 *       P11KeyStore alias map'inden bağımsızdır.</li>
 *   <li><b>JCA {@link KeyStore#aliases()}</b> — PFX gibi non-HSM
 *       sağlayıcılar için.</li>
 * </ol>
 */
@Service
public class CertificateInfoService {

    private static final Logger LOGGER = LoggerFactory.getLogger(CertificateInfoService.class);

    /** Spring inject eder; PFX yapılandırmasında {@code null}. CLI yolunda manuel set.
     *  In-process ({@code IaikPkcs11Module}) veya remote köprü olabilir. */
    private final Pkcs11ModulePort iaikModule;

    /**
     * Aktif imza yapılandırmasındaki materyal. {@code /signingCertificate}
     * endpoint'i bu singleton'dan beslenir; CLI yolunda ({@link #CertificateInfoService()})
     * {@code null} kalır ve tek-sertifika yolu kapanır.
     */
    private final SigningMaterial signingMaterial;

    @Autowired
    public CertificateInfoService(@Autowired(required = false) Pkcs11ModulePort iaikModule,
                                  @Autowired(required = false) SigningMaterial signingMaterial) {
        this.iaikModule = iaikModule;
        this.signingMaterial = signingMaterial;
    }

    /**
     * CLI / non-Spring kullanımı için no-arg constructor. PKCS#11 listeleme
     * istiyorsa {@link #CertificateInfoService(Pkcs11ModulePort, SigningMaterial)} kullan.
     */
    public CertificateInfoService() {
        this(null, null);
    }

    /**
     * Geriye dönük uyumluluk: yalnızca {@link Pkcs11ModulePort} ile inject —
     * mevcut testler ve CLI yolu için. {@code /signingCertificate} endpoint'i
     * bu yolda kullanılamaz; HSM listing'i çalışmaya devam eder.
     */
    public CertificateInfoService(Pkcs11ModulePort iaikModule) {
        this(iaikModule, null);
    }

    /**
     * Verilen keystore provider'dan tüm sertifikaları listeler.
     *
     * <p>Container'da {@link Pkcs11ModulePort} bean'i (HSM yapılandırması)
     * mevcutsa <b>onun</b> {@code listCertificates()}'i çağrılır — token
     * üzerinde doğrudan {@code C_FindObjects}. Aksi halde JCA
     * {@code KeyStore.aliases()} fallback'i kullanılır.</p>
     */
    public List<CertificateInfoDto> listCertificates(KeyStoreProvider provider, char[] pin) {
        LOGGER.info("Keystore'dan sertifikalar listeleniyor: {}", provider.getType());

        if (iaikModule != null) {
            try {
                List<CertificateInfoDto> certs = iaikModule.listCertificates();
                LOGGER.info("IAIK üzerinden {} entry listelendi.", certs.size());
                return certs;
            } catch (Exception e) {
                // PKCS#11 yapılandırmasında PFX fallback YOL DEĞİL —
                // PKCS11KeyStoreProvider.loadKeyStore() artık her zaman
                // UnsupportedOperationException atıyor. IAIK hatasını
                // sarmalayarak yukarıya bildiriyoruz; orijinal hata mesajı
                // (HSM device error, session closed, vs.) korunsun.
                if (provider instanceof PKCS11KeyStoreProvider) {
                    throw new KeyStoreException(
                        "HSM (PKCS#11) sertifika listelemesi başarısız: " + e.getMessage()
                        + ". PKCS#11 yapılandırmasında PFX/JCA fallback yoktur — "
                        + "token bağlantısını ve PIN'i kontrol edin.", e);
                }
                LOGGER.warn("IAIK listing başarısız; JCA KeyStore.aliases() fallback'ine düşülüyor: {}",
                    e.getMessage(), e);
            }
        }

        return listViaKeyStoreAliases(provider, pin);
    }

    /**
     * Geriye dönük uyumluluk için orijinal {@link KeyStore#aliases()} tabanlı
     * enumeration. PFX/PKCS12 keystore'lar için yeterlidir; HSM'lerde alias
     * mapping kuralları nedeniyle eksik sonuç verebilir.
     */
    private List<CertificateInfoDto> listViaKeyStoreAliases(KeyStoreProvider provider, char[] pin) {
        List<CertificateInfoDto> certificates = new ArrayList<>();
        try {
            KeyStore keyStore = provider.loadKeyStore(pin);
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                // Tek alias için tüm okuma adımlarını (isCertificateEntry, isKeyEntry,
                // getCertificate, extension extraction) tek try ile saralayalım;
                // legacy/bozuk entry'lerde sessiz skip davranışı korunsun.
                try {
                    if (!keyStore.isCertificateEntry(alias) && !keyStore.isKeyEntry(alias)) {
                        continue;
                    }
                    X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
                    if (cert == null) {
                        LOGGER.debug("Alias '{}' için sertifika boş döndü, atlanıyor", alias);
                        continue;
                    }
                    CertificateInfoDto dto = convertToCertificateInfoDto(cert);
                    dto.setAlias(alias);
                    dto.setHasPrivateKey(keyStore.isKeyEntry(alias));
                    certificates.add(dto);
                    LOGGER.debug("Sertifika bulundu - Alias: {}, Serial: {}, Subject: {}",
                            alias, dto.getSerialNumberHex(), dto.getSubject());
                } catch (Exception e) {
                    LOGGER.warn("Alias için sertifika bilgisi alınamadı: {} - {}", alias, e.getMessage());
                }
            }

            LOGGER.info("Toplam {} sertifika bulundu", certificates.size());

        } catch (Exception e) {
            throw new KeyStoreException("Sertifika listesi alınamadı: " + e.getMessage(), e);
        }

        return certificates;
    }

    /**
     * Aktif imza yapılandırmasındaki imzacı sertifika bilgilerini döner.
     *
     * <p>Listing endpoint'lerinden farklı olarak {@code base64EncodedCertificate}
     * alanını da doldurur — bu, manuel XAdES {@code <ds:X509Certificate>} elementi
     * dolduran client'lar için tek-shot lookup hedefler. {@code hasPrivateKey}
     * her zaman {@code true}'dur çünkü {@link SigningMaterial} constructor'ı
     * geçerli bir backend (JCA private key veya PKCS#11 key handle) garanti eder.</p>
     *
     * @throws IllegalStateException Spring bağlamı içinde {@link SigningMaterial}
     *     bean'i mevcut değilse (CLI yapılandırması veya bootstrap hatası).
     */
    public CertificateInfoDto getSigningCertificateInfo() throws CertificateEncodingException {
        if (signingMaterial == null) {
            throw new IllegalStateException(
                "SigningMaterial bean'i bulunamadı. /signingCertificate endpoint'i yalnızca "
                + "imza yapılandırması başlatılmış Spring context'inde kullanılabilir.");
        }
        X509Certificate cert = signingMaterial.getSigningCertificate();
        CertificateInfoDto dto = convertToCertificateInfoDto(cert);
        // SigningMaterial constructor private key veya HSM key handle olmadan
        // oluşturulmaz; backend tipinden bağımsız olarak imzacı materyali
        // burada her zaman privateKey-equivalent içerir.
        dto.setHasPrivateKey(true);
        dto.setBase64EncodedCertificate(Base64.getEncoder().encodeToString(cert.getEncoded()));
        return dto;
    }

    /**
     * Listing/info DTO mapping'i — base64 encoded sertifika kasıtlı olarak
     * doldurulmaz. {@code /list} endpoint'i çağrı başına onlarca entry
     * dönebileceği için payload şişmesini önlüyoruz; manuel XAdES için
     * {@link #getSigningCertificateInfo()} kullanılmalıdır.
     */
    private CertificateInfoDto convertToCertificateInfoDto(X509Certificate cert) {
        if (cert == null) return null;
        CertificateInfoDto dto = new CertificateInfoDto();
        dto.setSerialNumberHex(cert.getSerialNumber().toString(16).toUpperCase());
        dto.setSerialNumberDec(cert.getSerialNumber().toString());
        dto.setSubject(cert.getSubjectX500Principal().toString());
        dto.setIssuer(cert.getIssuerX500Principal().toString());
        dto.setValidFrom(cert.getNotBefore());
        dto.setValidTo(cert.getNotAfter());
        dto.setType(cert.getType());
        dto.setSignatureAlgorithm(cert.getSigAlgName());
        dto.setKeyUsage(X509ExtensionInspector.extractKeyUsage(cert));
        dto.setExtendedKeyUsage(X509ExtensionInspector.extractExtendedKeyUsage(cert));
        dto.setCertificatePolicies(X509ExtensionInspector.extractCertificatePolicies(cert));
        dto.setPublicKeyAlgorithm(cert.getPublicKey().getAlgorithm());
        return dto;
    }


    /**
     * Sertifika bilgilerini konsol formatında yazdırır.
     * Command-line kullanımı için.
     */
    public void printCertificates(List<CertificateInfoDto> certificates) {
        if (certificates.isEmpty()) {
            System.out.println("\n⚠️  Keystore'da sertifika bulunamadı\n");
            return;
        }
        
        String separator = createSeparator(80, '=');
        String lineSeparator = createSeparator(80, '-');
        
        System.out.println("\n" + separator);
        System.out.println("🔐 KEYSTORE SERTİFİKALARI");
        System.out.println(separator);
        System.out.println();
        
        for (int i = 0; i < certificates.size(); i++) {
            CertificateInfoDto cert = certificates.get(i);
            
            System.out.println(String.format("📜 Sertifika #%d", i + 1));
            System.out.println(lineSeparator);
            System.out.println(String.format("  Alias:             %s", cert.getAlias()));
            System.out.println(String.format("  Serial (hex):      %s", cert.getSerialNumberHex()));
            System.out.println(String.format("  Serial (dec):      %s", cert.getSerialNumberDec()));
            System.out.println(String.format("  Subject:           %s", cert.getSubject()));
            System.out.println(String.format("  Issuer:            %s", cert.getIssuer()));
            System.out.println(String.format("  Valid From:        %s", cert.getValidFrom()));
            System.out.println(String.format("  Valid To:          %s", cert.getValidTo()));
            System.out.println(String.format("  Has Private Key:   %s", cert.isHasPrivateKey() ? "✅ Yes" : "❌ No"));
            System.out.println(String.format("  Type:              %s", cert.getType()));
            System.out.println(String.format("  Signature Algo:    %s", cert.getSignatureAlgorithm()));
            
            // OID bilgileri
            if (cert.getKeyUsage() != null && !cert.getKeyUsage().isEmpty()) {
                System.out.println(String.format("  Key Usage:         %s", cert.getKeyUsage()));
            }
            if (cert.getExtendedKeyUsage() != null && !cert.getExtendedKeyUsage().isEmpty()) {
                System.out.println(String.format("  Ext. Key Usage:    %s", cert.getExtendedKeyUsage()));
            }
            if (cert.getCertificatePolicies() != null && !cert.getCertificatePolicies().isEmpty()) {
                System.out.println(String.format("  Cert. Policies:    %s", cert.getCertificatePolicies()));
            }
            System.out.println();
        }
        
        System.out.println(separator);
        System.out.println(String.format("✅ Toplam %d sertifika bulundu\n", certificates.size()));
        
        // Environment variable örnekleri
        if (!certificates.isEmpty()) {
            CertificateInfoDto first = certificates.get(0);
            System.out.println("💡 Environment Variable Örnekleri:");
            System.out.println(lineSeparator);
            System.out.println(String.format("export CERTIFICATE_ALIAS=%s", first.getAlias()));
            System.out.println(String.format("export CERTIFICATE_SERIAL_NUMBER=%s", first.getSerialNumberHex()));
            System.out.println();
        }
    }

    /**
     * Java 8 uyumlu separator oluşturur (String.repeat() Java 11'de geldi).
     */
    private String createSeparator(int length, char character) {
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(character);
        }
        return sb.toString();
    }

}

