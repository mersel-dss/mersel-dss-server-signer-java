package io.mersel.dss.signer.api.services.keystore.iaik.bridge;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * PKCS#11 köprüsünün <b>varlık nedenini</b> kanıtlayan demo testi: aynı dar
 * heap tavanlı ({@code -Xmx64m}) process'te aynı büyüklükteki belgeyle,
 * <em>tek değişken</em> büyük verinin o process'e girip girmemesidir.
 *
 * <h2>Neden -Xmx64m?</h2>
 * <p>Bu host'ta gerçek 32-bit JVM yok (32-bit JRE pratikte yalnızca Windows/
 * Linux Java 8). Ama 32-bit'in patlatan kısıtı dar adres alanı = düşük heap
 * tavanıdır; {@code -Xmx64m} bunu birebir emüle eder. Bağlayıcı kısıt (belgenin
 * heap'e sığması) matematiksel olarak aynıdır.</p>
 *
 * <h2>İki senaryo</h2>
 * <ol>
 *   <li><b>Köprü KAPALI</b> ({@link MemoryDemoNoBridgeMain}): dar process
 *       belgeyi kendi heap'inde tutmak zorunda → {@link OutOfMemoryError}.</li>
 *   <li><b>Köprü AÇIK</b> ({@link MemoryDemoHelperMain}): dar process (helper)
 *       başlar; köprüden yalnızca 32 byte digest geçer → patlamaz.</li>
 * </ol>
 *
 * <p>Çalıştırma: {@code mvn test -Dgroups=bridge-memory-demo -DexcludedGroups=}</p>
 */
@Tag("bridge-memory-demo")
class Pkcs11BridgeMemoryDemoTest {

    /** Dar heap tavanı — 32-bit adres alanı emülasyonu. */
    private static final String CHILD_XMX = "-Xmx64m";

    /** 256 MB belge — 64 MB heap'e asla sığmaz (deterministik OOM). */
    private static final int DOC_SIZE = 256 * 1024 * 1024;

    @Test
    @DisplayName("Köprü KAPALI: dar heap'li process büyük belgede OutOfMemoryError ile patlar")
    void inProcessLargeDocumentBlowsUp() throws Exception {
        Process p = launch(MemoryDemoNoBridgeMain.class.getName(),
            true /* mergeErr */, CHILD_XMX, String.valueOf(DOC_SIZE));
        StringBuilder output = drain(p.getInputStream());
        boolean finished = p.waitFor(60, TimeUnit.SECONDS);
        assertTrue(finished, "NO_BRIDGE child 60s içinde bitmeliydi");

        int exit = p.exitValue();
        System.out.println("---- NO_BRIDGE child çıktısı ----\n" + output
            + "\n---- exit code: " + exit + " ----");

        assertNotEquals(0, exit,
            "Köprü kapalıyken dar heap'te büyük belge patlamalıydı (exit != 0)");
        assertTrue(output.toString().contains("OutOfMemoryError"),
            "Beklenen OutOfMemoryError görülmedi. Çıktı:\n" + output);
        assertTrue(!output.toString().contains("SIGN_OK"),
            "Belge dar heap'e sığmamalıydı ama SIGN_OK görüldü.");
    }

    @Test
    @DisplayName("Köprü AÇIK: dar heap'li helper başlar, sadece 32 byte digest geçer, patlamaz")
    void bridgeForwardsOnlyDigestAndSurvives() throws Exception {
        Process helper = launch(MemoryDemoHelperMain.class.getName(), false /* mergeErr */, CHILD_XMX);
        AtomicReference<String> errTail = new AtomicReference<>("");
        StringBuilder helperStderr = drain(helper.getErrorStream());

        int port = awaitReadyPort(helper.getInputStream(), 30_000);
        assertTrue(port > 0, "Helper READY portu alınamadı");
        System.out.println("Helper hazır, port=" + port);

        // Büyük belgeyi ana (geniş-heap) tarafta streaming digest'liyoruz; köprüden
        // yalnızca 32 byte geçecek. Belgeyi tek parça heap'te tutmuyoruz bile.
        byte[] digest = streamingDigestOf(DOC_SIZE);
        assertEquals(32, digest.length, "SHA-256 digest 32 byte olmalı");

        byte[] signature = signDigestViaBridge("127.0.0.1", port, digest);
        System.out.println("Köprüden imza alındı: " + signature.length + " byte (belge boyutu="
            + DOC_SIZE + " byte, köprüden geçen=" + digest.length + " byte)");
        assertEquals(32, signature.length, "Stub imza (SHA-256) 32 byte olmalı");

        boolean finished = helper.waitFor(20, TimeUnit.SECONDS);
        assertTrue(finished, "Helper SHUTDOWN sonrası temiz kapanmalıydı");
        int exit = helper.exitValue();
        errTail.set(helperStderr.toString());
        System.out.println("---- helper stderr ----\n" + errTail.get() + "\n---- exit: " + exit + " ----");

        assertEquals(0, exit, "Helper küçük veriyle patlamamalı, exit 0 olmalı. stderr:\n" + errTail.get());
        assertTrue(!errTail.get().contains("OutOfMemoryError"),
            "Helper'da OutOfMemoryError olmamalı. stderr:\n" + errTail.get());
    }

    // ------------------------------------------------------------------
    // Yardımcılar
    // ------------------------------------------------------------------

    /** Aynı JVM + aynı (test) classpath ile bir child process başlatır. */
    private Process launch(String mainClass, boolean mergeErr, String... extra) throws IOException {
        String javaBin = System.getProperty("java.home") + File.separator + "bin" + File.separator + "java";
        String classpath = System.getProperty("java.class.path");
        List<String> cmd = new ArrayList<>();
        cmd.add(javaBin);
        // extra'nın başındaki JVM opt'ları (örn -Xmx) main class'tan önce gelmeli.
        List<String> jvmOpts = new ArrayList<>();
        List<String> appArgs = new ArrayList<>();
        for (String e : extra) {
            if (e.startsWith("-")) {
                jvmOpts.add(e);
            } else {
                appArgs.add(e);
            }
        }
        cmd.addAll(jvmOpts);
        cmd.add("-cp");
        cmd.add(classpath);
        cmd.add(mainClass);
        cmd.addAll(appArgs);
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(mergeErr);
        return pb.start();
    }

    /** Stream'i arka planda bir StringBuilder'a boşaltır (deadlock önler). */
    private StringBuilder drain(InputStream is) {
        StringBuilder sb = new StringBuilder();
        Thread t = new Thread(() -> {
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(is, StandardCharsets.UTF_8))) {
                String line;
                while ((line = br.readLine()) != null) {
                    synchronized (sb) {
                        sb.append(line).append('\n');
                    }
                }
            } catch (IOException ignored) {
            }
        });
        t.setDaemon(true);
        t.start();
        return sb;
    }

    /** Helper stdout'undan READY satırını bekleyip portu döner. */
    private int awaitReadyPort(InputStream stdout, long timeoutMs) throws IOException {
        long deadline = System.currentTimeMillis() + timeoutMs;
        BufferedReader br = new BufferedReader(new InputStreamReader(stdout, StandardCharsets.UTF_8));
        String line;
        while (System.currentTimeMillis() < deadline && (line = br.readLine()) != null) {
            System.out.println("[helper-stdout] " + line);
            if (line.startsWith(HelperEnv.READY_PREFIX)) {
                return Integer.parseInt(line.substring(HelperEnv.READY_PREFIX.length()).trim());
            }
        }
        return -1;
    }

    /**
     * {@code size} byte'lık bir belgenin SHA-256'sını, belgeyi tek parça heap'te
     * tutmadan, küçük chunk'lar halinde besleyerek hesaplar. Köprünün ana
     * (geniş-heap) tarafında gerçekte olan da budur: büyük veri akışla işlenir,
     * dar process'e yalnızca digest gider.
     */
    private byte[] streamingDigestOf(int size) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] chunk = new byte[1 << 20]; // 1 MB
        int remaining = size;
        while (remaining > 0) {
            int n = Math.min(chunk.length, remaining);
            md.update(chunk, 0, n);
            remaining -= n;
        }
        return md.digest();
    }

    /** Gerçek wire-protokolüyle köprüye AUTH + SIGN_DIGEST yapıp imzayı alır. */
    private byte[] signDigestViaBridge(String host, int port, byte[] digest) throws IOException {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), 5000);
            socket.setSoTimeout(10_000);
            DataOutputStream out =
                new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));
            DataInputStream in = new DataInputStream(socket.getInputStream());

            // AUTH
            Pkcs11WireProtocol.writeFrame(out, Pkcs11WireProtocol.newPayload()
                .writeByte(Pkcs11WireProtocol.OP_AUTH)
                .writeString("demo-token")
                .toByteArray());
            expectOk(Pkcs11WireProtocol.readFrame(in));

            // SIGN_DIGEST — köprüden geçen TEK büyük olmayan veri.
            Pkcs11WireProtocol.writeFrame(out, Pkcs11WireProtocol.newPayload()
                .writeByte(Pkcs11WireProtocol.OP_SIGN_DIGEST)
                .writeInt(1)
                .writeString("SHA256")
                .writeBytes(digest)
                .toByteArray());
            Pkcs11WireProtocol.PayloadReader r = expectOk(Pkcs11WireProtocol.readFrame(in));
            byte[] sig = r.readBytes();

            // Temiz kapanış.
            Pkcs11WireProtocol.writeFrame(out, Pkcs11WireProtocol.newPayload()
                .writeByte(Pkcs11WireProtocol.OP_SHUTDOWN)
                .toByteArray());
            try { expectOk(Pkcs11WireProtocol.readFrame(in)); } catch (Exception ignored) { }
            return sig;
        }
    }

    private Pkcs11WireProtocol.PayloadReader expectOk(byte[] frame) {
        Pkcs11WireProtocol.PayloadReader r = new Pkcs11WireProtocol.PayloadReader(frame);
        byte status = r.readByte();
        if (status != Pkcs11WireProtocol.STATUS_OK) {
            fail("Köprü OK dönmedi, status=" + status);
        }
        return r;
    }
}
