package io.mersel.dss.signer.api.services.keystore.iaik.bridge;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Bir process veya native kütüphanenin <b>bit'liğini</b> (32 vs 64) tespit
 * eder. PKCS#11 köprüsünün otomatik karar matrisinin temelidir: JVM ve DLL
 * bit'liği uyuşuyorsa in-process yol, uyuşmuyorsa out-of-process helper
 * gerekir (bkz. {@code RemotePkcs11Module}).
 *
 * <h2>Neden gerek var?</h2>
 * <p>JNI'da demir kural: bir process yalnızca kendi mimarisindeki native
 * kütüphaneyi yükleyebilir. 64-bit JVM 32-bit DLL'i yüklemeye kalkarsa
 * {@code UnsatisfiedLinkError} ("Can't load IA 32-bit .dll on a AMD 64-bit
 * platform") alır. Bu sınıf, kullanıcı tek bir {@code PKCS11_LIBRARY} verince
 * sistemin doğru stratejiyi kendiliğinden seçmesini sağlar.</p>
 *
 * <h2>Desteklenen formatlar</h2>
 * <ul>
 *   <li><b>Windows PE</b> ({@code .dll}): {@code e_lfanew} → {@code PE\0\0}
 *       imzası → {@code IMAGE_FILE_HEADER.Machine} alanı.</li>
 *   <li><b>ELF</b> ({@code .so}): {@code EI_CLASS} (offset 4).</li>
 *   <li><b>Mach-O</b> ({@code .dylib}): magic. Fat/universal binary'lerde
 *       (aynı dosyada hem 32 hem 64) {@link Bitness#UNIVERSAL} döner —
 *       JVM hangi dilimi yüklerse onu kullanır, mismatch oluşmaz.</li>
 * </ul>
 */
public final class NativeArchitecture {

    private static final Logger LOGGER = LoggerFactory.getLogger(NativeArchitecture.class);

    private NativeArchitecture() {
    }

    /** Tespit edilen mimari bit'liği. */
    public enum Bitness {
        BITS_32,
        BITS_64,
        /** Mach-O fat/universal binary — hem 32 hem 64 dilim içerir. */
        UNIVERSAL,
        /** Header okunamadı / tanınmayan format. */
        UNKNOWN;

        public boolean isKnown() {
            return this == BITS_32 || this == BITS_64 || this == UNIVERSAL;
        }

        /**
         * Bu kütüphane bit'liği, verilen JVM bit'liğiyle aynı process'te
         * yüklenebilir mi? {@link #UNIVERSAL} her zaman uyumludur; {@link #UNKNOWN}
         * iyimser kabul edilir (operatör in-process'i zorlamak isteyebilir,
         * native loader gerçek hatayı zaten net verir).
         */
        public boolean isCompatibleWith(Bitness jvmBitness) {
            if (this == UNIVERSAL || this == UNKNOWN) {
                return true;
            }
            return this == jvmBitness;
        }
    }

    // ---- PE (Windows) ----
    private static final int PE_MACHINE_I386  = 0x014c;
    private static final int PE_MACHINE_AMD64 = 0x8664;
    private static final int PE_MACHINE_ARM64 = 0xAA64;
    private static final int PE_MACHINE_IA64  = 0x0200;

    /**
     * Çalışan JVM'in bit'liği. {@code sun.arch.data.model} HotSpot/OpenJDK'da
     * her zaman dolu gelir ("32" / "64"); yoksa {@code os.arch}'tan türetilir.
     */
    public static Bitness jvmBitness() {
        String dataModel = System.getProperty("sun.arch.data.model");
        if ("32".equals(dataModel)) {
            return Bitness.BITS_32;
        }
        if ("64".equals(dataModel)) {
            return Bitness.BITS_64;
        }
        String osArch = String.valueOf(System.getProperty("os.arch")).toLowerCase();
        if (osArch.contains("64")) {
            return Bitness.BITS_64;
        }
        if (osArch.contains("86") || osArch.contains("x86") || osArch.contains("i386")
            || osArch.contains("arm") && !osArch.contains("64")) {
            return Bitness.BITS_32;
        }
        LOGGER.warn("JVM bit'liği belirlenemedi (sun.arch.data.model='{}', os.arch='{}'); "
            + "BITS_64 varsayılıyor.", dataModel, osArch);
        return Bitness.BITS_64;
    }

    /**
     * Verilen native kütüphane dosyasının bit'liğini header'ından okur.
     * Dosya yoksa / okunamazsa / format tanınmazsa {@link Bitness#UNKNOWN}.
     */
    public static Bitness detectLibrary(String libraryPath) {
        if (libraryPath == null || libraryPath.trim().isEmpty()) {
            return Bitness.UNKNOWN;
        }
        Path path = Paths.get(libraryPath.trim());
        if (!Files.isRegularFile(path)) {
            LOGGER.warn("PKCS#11 kütüphanesi dosya olarak bulunamadı: {} "
                + "(bit'lik tespiti atlandı).", libraryPath);
            return Bitness.UNKNOWN;
        }
        try (RandomAccessFile raf = new RandomAccessFile(path.toFile(), "r")) {
            if (raf.length() < 4) {
                return Bitness.UNKNOWN;
            }
            byte[] magic = new byte[4];
            raf.seek(0);
            raf.readFully(magic);

            // ELF: 0x7F 'E' 'L' 'F'
            if (magic[0] == 0x7F && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F') {
                return detectElf(raf);
            }
            // PE/COFF: 'M' 'Z' DOS stub başlığı
            if (magic[0] == 'M' && magic[1] == 'Z') {
                return detectPe(raf);
            }
            // Mach-O
            Bitness macho = detectMachO(magic);
            if (macho != Bitness.UNKNOWN) {
                return macho;
            }
            LOGGER.warn("Tanınmayan native kütüphane formatı (magic={}): {}",
                hex(magic), libraryPath);
            return Bitness.UNKNOWN;
        } catch (IOException e) {
            LOGGER.warn("PKCS#11 kütüphanesi header'ı okunamadı ({}): {}",
                libraryPath, e.getMessage());
            return Bitness.UNKNOWN;
        }
    }

    private static Bitness detectElf(RandomAccessFile raf) throws IOException {
        // EI_CLASS, offset 4: 1 = ELFCLASS32, 2 = ELFCLASS64
        raf.seek(4);
        int eiClass = raf.readUnsignedByte();
        switch (eiClass) {
            case 1:
                return Bitness.BITS_32;
            case 2:
                return Bitness.BITS_64;
            default:
                return Bitness.UNKNOWN;
        }
    }

    private static Bitness detectPe(RandomAccessFile raf) throws IOException {
        // e_lfanew: PE header offset'i, DOS header'ın 0x3C konumunda (little-endian DWORD)
        raf.seek(0x3C);
        long peOffset = readUInt32LE(raf);
        if (peOffset <= 0 || peOffset + 6 > raf.length()) {
            return Bitness.UNKNOWN;
        }
        raf.seek(peOffset);
        byte[] sig = new byte[4];
        raf.readFully(sig);
        if (!(sig[0] == 'P' && sig[1] == 'E' && sig[2] == 0 && sig[3] == 0)) {
            return Bitness.UNKNOWN;
        }
        // IMAGE_FILE_HEADER hemen PE imzasından sonra; ilk alan Machine (WORD, LE)
        int machine = readUInt16LE(raf);
        switch (machine) {
            case PE_MACHINE_I386:
                return Bitness.BITS_32;
            case PE_MACHINE_AMD64:
            case PE_MACHINE_ARM64:
            case PE_MACHINE_IA64:
                return Bitness.BITS_64;
            default:
                LOGGER.warn("Bilinmeyen PE Machine değeri: 0x{}",
                    Integer.toHexString(machine));
                return Bitness.UNKNOWN;
        }
    }

    private static Bitness detectMachO(byte[] magic) {
        long m = ((magic[0] & 0xFFL) << 24) | ((magic[1] & 0xFFL) << 16)
               | ((magic[2] & 0xFFL) << 8) | (magic[3] & 0xFFL);
        // 32-bit: FEEDFACE (BE) / CEFAEDFE (LE)
        if (m == 0xFEEDFACEL || m == 0xCEFAEDFEL) {
            return Bitness.BITS_32;
        }
        // 64-bit: FEEDFACF (BE) / CFFAEDFE (LE)
        if (m == 0xFEEDFACFL || m == 0xCFFAEDFEL) {
            return Bitness.BITS_64;
        }
        // Fat/universal: CAFEBABE (BE) / BEBAFECA (LE)
        if (m == 0xCAFEBABEL || m == 0xBEBAFECAL) {
            return Bitness.UNIVERSAL;
        }
        return Bitness.UNKNOWN;
    }

    private static long readUInt32LE(RandomAccessFile raf) throws IOException {
        int b0 = raf.readUnsignedByte();
        int b1 = raf.readUnsignedByte();
        int b2 = raf.readUnsignedByte();
        int b3 = raf.readUnsignedByte();
        return (b0) | (b1 << 8) | (b2 << 16) | ((long) b3 << 24);
    }

    private static int readUInt16LE(RandomAccessFile raf) throws IOException {
        int b0 = raf.readUnsignedByte();
        int b1 = raf.readUnsignedByte();
        return (b0) | (b1 << 8);
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) {
            sb.append(String.format("%02X", x & 0xFF));
        }
        return sb.toString();
    }
}
