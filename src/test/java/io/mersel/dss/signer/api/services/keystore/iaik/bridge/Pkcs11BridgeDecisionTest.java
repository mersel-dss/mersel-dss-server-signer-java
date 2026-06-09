package io.mersel.dss.signer.api.services.keystore.iaik.bridge;

import io.mersel.dss.signer.api.services.keystore.iaik.bridge.NativeArchitecture.Bitness;
import io.mersel.dss.signer.api.services.keystore.iaik.bridge.Pkcs11BridgeDecision.Strategy;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * {@link Pkcs11BridgeDecision} karar matrisi — özellikle <b>fail-safe</b>
 * garantisi: {@code auto} modu mevcut (köprü öncesi) davranıştan asla daha
 * riskli olmamalı; tespit hatası ya da helper eksikliğinde IN_PROCESS'e düşer.
 */
class Pkcs11BridgeDecisionTest {

    @Test
    @DisplayName("PKCS11_LIBRARY boşsa → NONE (PFX yolu, etkilenmez)")
    void blankLibraryIsNone() {
        assertEquals(Strategy.NONE, Pkcs11BridgeDecision.decide(null, "auto", true));
        assertEquals(Strategy.NONE, Pkcs11BridgeDecision.decide("   ", "remote", false));
    }

    @Test
    @DisplayName("Açık in-process → her zaman IN_PROCESS (dosya okunmaz)")
    void explicitInProcess() {
        assertEquals(Strategy.IN_PROCESS,
            Pkcs11BridgeDecision.decide("/yok/olmayan.dll", "in-process", false));
        assertEquals(Strategy.IN_PROCESS,
            Pkcs11BridgeDecision.decide("/yok/olmayan.dll", "inprocess", false));
    }

    @Test
    @DisplayName("Açık remote → operatör tercihi, katı REMOTE")
    void explicitRemoteIsStrict() {
        assertEquals(Strategy.REMOTE,
            Pkcs11BridgeDecision.decide("/yok/olmayan.dll", "remote", false));
    }

    @Test
    @DisplayName("auto + tanınmayan/erişilemeyen DLL → IN_PROCESS (UNKNOWN iyimser)")
    void autoUnknownFallsBackInProcess() {
        assertEquals(Strategy.IN_PROCESS,
            Pkcs11BridgeDecision.decide("/yok/olmayan.dll", "auto", true));
        assertEquals(Strategy.IN_PROCESS,
            Pkcs11BridgeDecision.decide("/yok/olmayan.dll", null, false));
    }

    @Test
    @DisplayName("FAIL-SAFE: auto + bitness uyuşmuyor AMA helper yok → IN_PROCESS (köprü öncesi davranış)")
    void autoIncompatibleButNoHelperStaysInProcess(@TempDir Path dir) throws IOException {
        Path mismatchedDll = writePeWithOppositeBitness(dir);
        assertEquals(Strategy.IN_PROCESS,
            Pkcs11BridgeDecision.decide(mismatchedDll.toString(), "auto", false),
            "Helper hazır değilken auto uyuşmazlıkta IN_PROCESS'e düşmeli");
    }

    @Test
    @DisplayName("auto + bitness uyuşmuyor + helper hazır → REMOTE")
    void autoIncompatibleWithHelperGoesRemote(@TempDir Path dir) throws IOException {
        Path mismatchedDll = writePeWithOppositeBitness(dir);
        assertEquals(Strategy.REMOTE,
            Pkcs11BridgeDecision.decide(mismatchedDll.toString(), "auto", true));
    }

    /**
     * Çalışan JVM'in <b>tersi</b> bitness'inde minimal geçerli bir PE/COFF
     * dosyası üretir; böylece auto modda deterministik "uyumsuz" kararı alınır.
     */
    private static Path writePeWithOppositeBitness(Path dir) throws IOException {
        boolean jvm64 = NativeArchitecture.jvmBitness() == Bitness.BITS_64;
        int machine = jvm64 ? 0x014c /* i386 */ : 0x8664 /* amd64 */;

        byte[] pe = new byte[0x100];
        pe[0] = 'M';
        pe[1] = 'Z';
        int peOffset = 0x80;
        // e_lfanew @ 0x3C (uint32 LE)
        pe[0x3C] = (byte) (peOffset & 0xFF);
        pe[0x3D] = (byte) ((peOffset >> 8) & 0xFF);
        pe[0x3E] = 0;
        pe[0x3F] = 0;
        // 'PE\0\0' imzası
        pe[peOffset] = 'P';
        pe[peOffset + 1] = 'E';
        pe[peOffset + 2] = 0;
        pe[peOffset + 3] = 0;
        // IMAGE_FILE_HEADER.Machine (uint16 LE)
        pe[peOffset + 4] = (byte) (machine & 0xFF);
        pe[peOffset + 5] = (byte) ((machine >> 8) & 0xFF);

        Path file = dir.resolve("mismatched.dll");
        Files.write(file, pe);
        return file;
    }
}
