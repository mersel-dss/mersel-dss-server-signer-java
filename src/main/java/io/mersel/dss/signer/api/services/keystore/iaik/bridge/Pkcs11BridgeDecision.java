package io.mersel.dss.signer.api.services.keystore.iaik.bridge;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * "Native DLL'i bu process'in içinde mi (in-process) yoksa ayrı bit'likteki
 * bir helper process'te mi (remote) yükleyelim?" kararını veren tek otorite.
 * Hem Spring {@code @Conditional} sınıfları hem de bean factory aynı mantığı
 * kullanır — tutarsızlık riski yok.
 *
 * <p>{@code PKCS11_BRIDGE_MODE}:</p>
 * <ul>
 *   <li>{@code auto} (default) → JVM ile DLL bit'liğini karşılaştır; uyumluysa
 *       in-process, değilse remote.</li>
 *   <li>{@code in-process} → her zaman in-process (operatör override).</li>
 *   <li>{@code remote} → her zaman helper üzerinden (test / zorlama).</li>
 * </ul>
 *
 * <h2>Fail-safe (geriye tam uyum garantisi)</h2>
 * <p>{@code auto} modu <b>asla</b> mevcut (köprü öncesi) davranıştan daha
 * riskli olamaz: tespit sırasında beklenmedik bir hata olursa ya da bitness
 * uyuşmazlığı bulunsa bile helper hazır değilse ({@code PKCS11_HELPER_JAVA}
 * tanımsız), karar <b>IN_PROCESS</b>'e düşer — yani "bu çalışmadan önce nasıl
 * davranıyorsa aynen öyle". Native loader gerçek bir uyumsuzlukta hatayı zaten
 * eskisi gibi verir. Sadece operatör <b>açıkça</b> {@code remote} derse katı
 * davranılır (bilinçli tercih).</p>
 */
public final class Pkcs11BridgeDecision {

    private static final Logger LOGGER = LoggerFactory.getLogger(Pkcs11BridgeDecision.class);

    private Pkcs11BridgeDecision() {
    }

    public enum Strategy {
        /** PKCS#11 yapılandırılmamış (PFX yolu veya hiç). */
        NONE,
        /** DLL ana JVM'e JNI ile yüklenir. */
        IN_PROCESS,
        /** DLL ayrı bit'likteki helper process'te yüklenir; IPC ile konuşulur. */
        REMOTE
    }

    /**
     * Geriye dönük imza — {@code remoteReady=true} varsayar (operatörün remote
     * altyapıyı hazır ettiği). Yeni çağrılar {@link #decide(String, String, boolean)}
     * kullanmalı; auto modun fail-safe davranışı oradadır.
     */
    public static Strategy decide(String libraryPath, String bridgeMode) {
        return decide(libraryPath, bridgeMode, true);
    }

    /**
     * @param remoteReady remote köprünün ön koşulu sağlanmış mı
     *        ({@code PKCS11_HELPER_JAVA} tanımlı mı). {@code auto} modda
     *        uyuşmazlık bulunsa bile bu {@code false} ise IN_PROCESS'e düşülür.
     */
    public static Strategy decide(String libraryPath, String bridgeMode, boolean remoteReady) {
        if (libraryPath == null || libraryPath.trim().isEmpty()) {
            return Strategy.NONE;
        }
        String mode = bridgeMode == null ? "auto" : bridgeMode.trim().toLowerCase();
        switch (mode) {
            case "in-process":
            case "inprocess":
                return Strategy.IN_PROCESS;
            case "remote":
                // Operatörün bilinçli tercihi — katı. Helper hazır değilse
                // bean factory net bir hata verir (yanlış yapılandırma görünür olsun).
                return Strategy.REMOTE;
            default:
                return decideAuto(libraryPath, remoteReady);
        }
    }

    private static Strategy decideAuto(String libraryPath, boolean remoteReady) {
        try {
            NativeArchitecture.Bitness jvm = NativeArchitecture.jvmBitness();
            NativeArchitecture.Bitness dll = NativeArchitecture.detectLibrary(libraryPath);
            boolean compatible = dll.isCompatibleWith(jvm);
            if (compatible) {
                LOGGER.info("PKCS#11 köprü kararı (auto): JVM={}, DLL={}, uyumlu=true → IN_PROCESS",
                    jvm, dll);
                return Strategy.IN_PROCESS;
            }
            // Uyumsuzluk var; ancak fail-safe: helper hazır değilse mevcut
            // (köprü öncesi) davranışı koru — IN_PROCESS'te kal.
            if (!remoteReady) {
                LOGGER.warn("JVM bit'liği ({}) ile PKCS#11 DLL bit'liği ({}) uyuşmuyor ama "
                    + "PKCS11_HELPER_JAVA tanımsız; fail-safe olarak IN_PROCESS'te kalınıyor "
                    + "(köprü öncesi davranışla aynı). Köprüyü kullanmak için PKCS11_HELPER_JAVA "
                    + "ayarlayın veya PKCS11_BRIDGE_MODE=remote verin.", jvm, dll);
                return Strategy.IN_PROCESS;
            }
            LOGGER.warn("JVM bit'liği ({}) ile PKCS#11 DLL bit'liği ({}) uyuşmuyor; "
                + "out-of-process helper köprüsü devreye alınacak.", jvm, dll);
            return Strategy.REMOTE;
        } catch (Throwable t) {
            // Beklenmedik herhangi bir tespit hatası asla açılışı bozmamalı:
            // köprü öncesi davranışa düş.
            LOGGER.warn("PKCS#11 köprü auto-tespiti beklenmedik şekilde başarısız; "
                + "fail-safe olarak IN_PROCESS'e düşülüyor (köprü öncesi davranış). Sebep: {}",
                t.toString());
            return Strategy.IN_PROCESS;
        }
    }
}
