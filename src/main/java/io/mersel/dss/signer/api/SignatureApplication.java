package io.mersel.dss.signer.api;

import io.mersel.dss.signer.api.dtos.CertificateInfoDto;
import io.mersel.dss.signer.api.services.CertificateInfoService;
import io.mersel.dss.signer.api.services.keystore.KeyStoreProvider;
import io.mersel.dss.signer.api.services.keystore.PKCS11KeyStoreProvider;
import io.mersel.dss.signer.api.services.keystore.PfxKeyStoreProvider;
import io.mersel.dss.signer.api.services.keystore.iaik.IaikPkcs11Module;
import org.apache.commons.lang3.math.NumberUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.util.StringUtils;

import java.util.List;

/**
 * Dijital İmza Servisi API'nin ana uygulaması.
 * <p>
 * XAdES, PAdES ve WS-Security imzalama servisleri sağlar.
 * <p>
 * Command-line kullanım:
 * - java -jar mersel-dss-signer.jar                    : API sunucusunu başlatır
 * - java -jar mersel-dss-signer.jar --list-certificates : Keystore sertifikalarını listeler
 * - java -jar mersel-dss-signer.jar --help             : Yardım mesajını gösterir
 */
@SpringBootApplication
@EnableScheduling
public class SignatureApplication {

    private static final Logger LOGGER = LoggerFactory.getLogger(SignatureApplication.class);

    public static final String FileSeparator = System.getProperty("file.separator");
    public static final String ROOT_FILE_FOLDER = ".mersel-signature-service";
    public static final String ROOT_DIR = System.getProperty("user.home") + FileSeparator + ROOT_FILE_FOLDER + FileSeparator;

    public static void main(String[] args) {
        // Command-line argümanlarını kontrol et
        if (args.length > 0) {
            String command = args[0];

            if ("--list-certificates".equals(command) || "--list-certs".equals(command)) {
                listCertificates();
                System.exit(0);
                return;
            } else if ("--help".equals(command) || "-h".equals(command)) {
                printHelp();
                System.exit(0);
                return;
            } else if ("--version".equals(command) || "-v".equals(command)) {
                printVersion();
                System.exit(0);
                return;
            }
        }

        // Normal Spring Boot başlatma
        LOGGER.info("Mersel DSS Signer API başlatılıyor...");
        LOGGER.info("Log dizini: {}", System.getProperty("LOG_PATH", "./logs"));

        SpringApplication.run(SignatureApplication.class, args);

        LOGGER.info("Mersel DSS Signer API başarıyla başlatıldı");
    }

    /**
     * Keystore'daki sertifikaları listeler.
     * Spring context olmadan çalışır.
     */
    private static void listCertificates() {
        System.out.println("\n🔐 Mersel DSS Signer - Certificate Lister\n");

        try {
            // Environment variable'lardan yapılandırmayı oku
            String pkcs11Library = System.getenv("PKCS11_LIBRARY");
            String pkcs11SlotListIndexStr = System.getenv("PKCS11_SLOT_LIST_INDEX");
            String pkcs11SlotStr = System.getenv("PKCS11_SLOT");
            // AKİS / TÜBİTAK uyumluluk: bkz. IaikPkcs11Module Javadoc.
            // Auto-detect zaten CKR_ARGUMENTS_BAD'da devreye girer; bu env var
            // operatöre "doğrudan NULL-args'a git" demek için escape hatch.
            String pkcs11NullInitArgsStr = System.getenv("PKCS11_NULL_INIT_ARGS");
            String pfxPath = System.getenv("PFX_PATH");
            String pin = System.getenv("CERTIFICATE_PIN");

            if (pin == null || pin.isEmpty()) {
                System.err.println("❌ CERTIFICATE_PIN environment variable tanımlanmamış!");
                System.err.println("\nÖrnek:");
                System.err.println("  export CERTIFICATE_PIN=yourpin");
                System.exit(1);
                return;
            }

            KeyStoreProvider provider;
            IaikPkcs11Module iaikModule = null;

            // StringUtils.hasText: null / "" / "   " (whitespace) hepsini boş
            // sayar — Spring config tarafındaki @ConditionalOnExpression ile
            // tutarlı. Aksi halde PKCS11_LIBRARY="   " gibi yanlış env var
            // çağrısı CLI'da PKCS#11 yoluna sapar ve IaikPkcs11Module ctor
            // anlamsız bir hata atar.
            if (StringUtils.hasText(pkcs11Library)) {
                Long slot = NumberUtils.isDigits(pkcs11SlotStr) ? Long.parseLong(pkcs11SlotStr) : null;
                Long slotIndex = NumberUtils.isDigits(pkcs11SlotListIndexStr) ? Long.parseLong(pkcs11SlotListIndexStr) : null;
                slot = slot != null && slot >= 0 ? slot : -1;
                slotIndex = slotIndex != null && slotIndex >= 0 ? slotIndex : -1;


                boolean forceNullInitArgs = "true".equalsIgnoreCase(
                    pkcs11NullInitArgsStr == null ? "" : pkcs11NullInitArgsStr.trim());

                System.out.println("📦 Keystore Type: PKCS#11 (IAIK)");
                System.out.println("📂 Library: " + pkcs11Library);
                System.out.println("🎰 Slot: " + (slot != null ? slot : "<unset>"));
                System.out.println("🎰 Slot List Index: " + (slotIndex != null ? slotIndex : "<unset>"));
                if (forceNullInitArgs) {
                    System.out.println("⚙️  Init args: NULL (AKİS / TÜBİTAK uyumluluk modu)");
                }
                System.out.println();

                // PKCS#11 yolunda IAIK Module ile listeliyoruz; SunPKCS11
                // alias-mapping katmanından bağımsız. Module manuel olarak
                // initialize edilip listing sonunda kapatılır.
                iaikModule = new IaikPkcs11Module(
                    pkcs11Library, slot, slotIndex, pin.toCharArray(), forceNullInitArgs);
                iaikModule.afterPropertiesSet();
                // KeyStoreProvider sadece getType()/info için referans olarak duruyor.
                provider = new PKCS11KeyStoreProvider(
                        pkcs11Library,
                        slot != null ? slot : -1L,
                        slotIndex != null ? slotIndex : -1L);

            } else if (StringUtils.hasText(pfxPath)) {
                System.out.println("📦 Keystore Type: PFX/PKCS12");
                System.out.println("📂 Path: " + pfxPath);
                System.out.println();

                provider = new PfxKeyStoreProvider(pfxPath);

            } else {
                System.err.println("❌ Ne PKCS11_LIBRARY ne de PFX_PATH tanımlanmamış!");
                System.err.println("\nPKCS#11 için:");
                System.err.println("  export PKCS11_LIBRARY=/usr/local/lib/libakisp11.dylib");
                System.err.println("  export PKCS11_SLOT=0");
                System.err.println("  export CERTIFICATE_PIN=yourpin");
                System.err.println("\nPFX için:");
                System.err.println("  export PFX_PATH=/path/to/certificate.pfx");
                System.err.println("  export CERTIFICATE_PIN=yourpassword");
                System.exit(1);
                return;
            }

            try {
                CertificateInfoService service = new CertificateInfoService(iaikModule);
                List<CertificateInfoDto> certificates = service.listCertificates(provider, pin.toCharArray());
                service.printCertificates(certificates);
            } finally {
                if (iaikModule != null) {
                    iaikModule.destroy();
                }
            }

        } catch (Exception e) {
            System.err.println("\n❌ Hata: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    /**
     * Yardım mesajını gösterir.
     */
    private static void printHelp() {
        System.out.println("\n🔐 Mersel DSS Signer API - Dijital İmza Servisi\n");
        System.out.println("Kullanım:");
        System.out.println("  java -jar mersel-dss-signer.jar [SEÇENEK]\n");
        System.out.println("Seçenekler:");
        System.out.println("  (seçeneksiz)           API sunucusunu başlatır (varsayılan port: 8085)");
        System.out.println("  --list-certificates    Keystore'daki sertifikaları listeler");
        System.out.println("  --list-certs           (kısa versiyon)");
        System.out.println("  --help, -h             Bu yardım mesajını gösterir");
        System.out.println("  --version, -v          Versiyon bilgisini gösterir\n");
        System.out.println("Environment Variables:");
        System.out.println("  PKCS#11 Keystore:");
        System.out.println("    PKCS11_LIBRARY          PKCS#11 kütüphane yolu");
        System.out.println("    PKCS11_SLOT             Slot numarası (varsayılan: 0)");
        System.out.println("    PKCS11_NULL_INIT_ARGS   AKİS / TÜBİTAK uyumluluk modu (true/false)");
        System.out.println("                            Sürücü CKR_ARGUMENTS_BAD dönerse otomatik");
        System.out.println("                            aktive olur; explicit set etmek operatöre");
        System.out.println("                            trial-and-error'u atlatır.");
        System.out.println("    CERTIFICATE_PIN         PIN kodu\n");
        System.out.println("  PFX Keystore:");
        System.out.println("    PFX_PATH                PFX dosya yolu");
        System.out.println("    CERTIFICATE_PIN         Şifre\n");
        System.out.println("  Sertifika Seçimi (İsteğe bağlı):");
        System.out.println("    CERTIFICATE_ALIAS            Sertifika alias'ı");
        System.out.println("    CERTIFICATE_SERIAL_NUMBER    Sertifika seri numarası (hex)\n");
        System.out.println("Örnekler:");
        System.out.println("  # PKCS#11 sertifikalarını listele");
        System.out.println("  export PKCS11_LIBRARY=/usr/local/lib/libakisp11.dylib");
        System.out.println("  export PKCS11_SLOT=0");
        System.out.println("  export CERTIFICATE_PIN=1234");
        System.out.println("  java -jar mersel-dss-signer.jar --list-certificates\n");
        System.out.println("  # PFX sertifikalarını listele");
        System.out.println("  export PFX_PATH=/path/to/certificate.pfx");
        System.out.println("  export CERTIFICATE_PIN=password");
        System.out.println("  java -jar mersel-dss-signer.jar --list-certs\n");
        System.out.println("Dokümantasyon:");
        System.out.println("  https://github.com/mersel-dss/mersel-dss-server-signer-java\n");
    }

    /**
     * Versiyon bilgisini gösterir.
     */
    private static void printVersion() {
        String version = SignatureApplication.class.getPackage().getImplementationVersion();
        if (version == null) {
            version = "development";
        }
        System.out.println("Mersel DSS Signer API v" + version);
    }
}

