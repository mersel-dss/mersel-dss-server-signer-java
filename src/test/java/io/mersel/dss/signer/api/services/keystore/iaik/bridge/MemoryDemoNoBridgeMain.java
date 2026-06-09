package io.mersel.dss.signer.api.services.keystore.iaik.bridge;

/**
 * "Köprü KAPALI" senaryosunu temsil eden child process. In-process imzalama
 * yolunda olduğu gibi, imzalanacak <b>tüm belgeyi kendi heap'inde</b> tutmaya
 * çalışır. Dar heap tavanlı bir JVM'de ({@code -Xmx64m} ile başlatılır — 32-bit
 * dar adres alanının emülasyonu) bu allocation {@link OutOfMemoryError} ile
 * patlar.
 *
 * <p>Gerçek hayatta: 64-bit JVM + 32-bit DLL senaryosunda köprü olmadan tek
 * çıkış 32-bit JVM'de in-process çalışmaktır; orada da ~2GB adres alanı belgeyi
 * + DSS DOM/base64 çalışma setini kaldıramaz.</p>
 *
 * <p>args[0] = belge boyutu (byte).</p>
 */
public final class MemoryDemoNoBridgeMain {

    private MemoryDemoNoBridgeMain() {
    }

    public static void main(String[] args) {
        int docSize = Integer.parseInt(args[0]);
        System.out.println("NO_BRIDGE: belge buffer'ı heap'te ayrılıyor: " + docSize + " byte");
        // In-process imza yolunun yapmak zorunda olduğu şey: belgeyi belleğe al.
        // Dar heap tavanında bu tek satır OutOfMemoryError fırlatır.
        byte[] document = new byte[docSize];
        // DSS pipeline'ın belge üzerinde ürettiği çalışma kopyalarının (base64,
        // canonicalization, DOM) simülasyonu — buraya ulaşırsa zaten heap geniş.
        document[0] = 1;
        document[docSize - 1] = 1;
        System.out.println("NO_BRIDGE: SIGN_OK (beklenmedik — heap belgeyi kaldırdı)");
    }
}
