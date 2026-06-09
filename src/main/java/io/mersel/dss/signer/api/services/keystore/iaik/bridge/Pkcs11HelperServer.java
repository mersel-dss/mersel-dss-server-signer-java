package io.mersel.dss.signer.api.services.keystore.iaik.bridge;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import io.mersel.dss.signer.api.dtos.CertificateInfoDto;
import io.mersel.dss.signer.api.services.keystore.iaik.IaikPkcs11Module;
import io.mersel.dss.signer.api.services.keystore.iaik.Pkcs11Signer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Helper process'in IPC sunucusu. {@link IaikPkcs11Module}'ü (native DLL'i bu
 * process'in kendi bit'liğinde yükleyerek) sarmalar ve loopback üzerinden gelen
 * istekleri (find-signer, list-certificates, sign, sign-digest) ona delege eder.
 *
 * <p>Bağlantı başına bir worker thread; her bağlantı önce {@link
 * Pkcs11WireProtocol#OP_AUTH} ile token doğrular. Eş zamanlı imza paralelliği
 * client'ın bağlantı havuzu boyutuyla (ana process'teki {@code MAX_SESSION_COUNT})
 * belirlenir; {@link IaikPkcs11Module}'ün kendi session pool'u alttan
 * eşzamanlılığı yönetir.</p>
 *
 * <p>Native handle hiç wire'dan geçmez: client {@link OP_FIND_SIGNER} ile
 * opak bir {@code signerId} (int) alır; sonraki sign çağrılarında bu id ile
 * helper'daki gerçek {@link Pkcs11Signer}'a yönlenir. SMS-recovery /
 * Cryptoki reinit tamamen helper içindeki {@link IaikPkcs11Module} tarafından,
 * yani DLL'e bitişik şekilde yürür — client transparan olarak imzayı alır.</p>
 */
public final class Pkcs11HelperServer {

    private static final Logger LOGGER = LoggerFactory.getLogger(Pkcs11HelperServer.class);

    private final IaikPkcs11Module module;
    private final byte[] expectedTokenBytes;
    private final String bindHost;
    private final int requestedPort;

    private final ConcurrentHashMap<Integer, Pkcs11Signer> signers = new ConcurrentHashMap<>();
    private final AtomicInteger signerIdGen = new AtomicInteger();
    private final AtomicBoolean running = new AtomicBoolean(false);
    private volatile ServerSocket serverSocket;
    /** Remote heartbeat monitör'ünün IPC ile durumunu sorabilmesi için; null = kapalı. */
    private volatile HelperHeartbeat heartbeat;

    public Pkcs11HelperServer(IaikPkcs11Module module,
                              String expectedToken,
                              String bindHost,
                              int requestedPort) {
        this.module = module;
        this.expectedTokenBytes = expectedToken == null
            ? new byte[0]
            : expectedToken.getBytes(StandardCharsets.UTF_8);
        this.bindHost = bindHost;
        this.requestedPort = requestedPort;
    }

    /** Heartbeat'i (varsa) bağlar; {@code OP_HEARTBEAT_STATUS} bu örneği sorar. */
    public void setHeartbeat(HelperHeartbeat heartbeat) {
        this.heartbeat = heartbeat;
    }

    /**
     * Sunucuyu başlatır, dinlenen gerçek portu döner ve accept loop'unu bu
     * thread'de çalıştırır (bloklar). Çağıran (helper main) portu READY
     * satırıyla parent'a bildirir.
     */
    public int start() throws IOException {
        InetAddress addr = InetAddress.getByName(bindHost);
        serverSocket = new ServerSocket(requestedPort, 64, addr);
        running.set(true);
        int actualPort = serverSocket.getLocalPort();
        LOGGER.info("PKCS#11 helper sunucusu dinliyor: {}:{}", bindHost, actualPort);
        return actualPort;
    }

    /** Accept loop — {@link #start()} sonrası çağrılır; sunucu kapanana dek bloklar. */
    public void serve() {
        while (running.get()) {
            final Socket socket;
            try {
                socket = serverSocket.accept();
            } catch (IOException e) {
                if (running.get()) {
                    LOGGER.warn("accept() hatası: {}", e.getMessage());
                }
                break;
            }
            Thread t = new Thread(() -> handleConnection(socket), "pkcs11-helper-conn");
            t.setDaemon(true);
            t.start();
        }
    }

    public void stop() {
        running.set(false);
        try {
            if (serverSocket != null) {
                serverSocket.close();
            }
        } catch (IOException ignored) {
        }
    }

    private void handleConnection(Socket socket) {
        try {
            socket.setTcpNoDelay(true);
            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));

            // İlk frame her zaman AUTH olmalı.
            byte[] first = Pkcs11WireProtocol.readFrame(in);
            Pkcs11WireProtocol.PayloadReader r0 = new Pkcs11WireProtocol.PayloadReader(first);
            byte op0 = r0.readByte();
            if (op0 != Pkcs11WireProtocol.OP_AUTH || !authOk(r0.readString())) {
                LOGGER.warn("Auth başarısız; bağlantı kapatılıyor.");
                writeStatus(out, Pkcs11WireProtocol.STATUS_AUTH_FAILED, "auth failed");
                socket.close();
                return;
            }
            writeStatus(out, Pkcs11WireProtocol.STATUS_OK, null);

            // Komut döngüsü.
            while (running.get()) {
                byte[] frame;
                try {
                    frame = Pkcs11WireProtocol.readFrame(in);
                } catch (EOFException eof) {
                    break; // client kapandı
                }
                dispatch(frame, out);
            }
        } catch (IOException e) {
            LOGGER.debug("Bağlantı sonlandı: {}", e.getMessage());
        } finally {
            try { socket.close(); } catch (IOException ignored) { }
        }
    }

    private void dispatch(byte[] frame, DataOutputStream out) throws IOException {
        Pkcs11WireProtocol.PayloadReader r = new Pkcs11WireProtocol.PayloadReader(frame);
        byte op = r.readByte();
        try {
            switch (op) {
                case Pkcs11WireProtocol.OP_PING:
                    writeStatus(out, Pkcs11WireProtocol.STATUS_OK, null);
                    break;
                case Pkcs11WireProtocol.OP_HEARTBEAT_STATUS:
                    handleHeartbeatStatus(out);
                    break;
                case Pkcs11WireProtocol.OP_FIND_SIGNER:
                    handleFindSigner(r, out);
                    break;
                case Pkcs11WireProtocol.OP_LIST_CERTIFICATES:
                    handleListCertificates(out);
                    break;
                case Pkcs11WireProtocol.OP_SIGN:
                    handleSign(r, out, false);
                    break;
                case Pkcs11WireProtocol.OP_SIGN_DIGEST:
                    handleSign(r, out, true);
                    break;
                case Pkcs11WireProtocol.OP_INVALIDATE_CACHE:
                    module.invalidateKeyCache();
                    signers.clear();
                    writeStatus(out, Pkcs11WireProtocol.STATUS_OK, null);
                    break;
                case Pkcs11WireProtocol.OP_SHUTDOWN:
                    writeStatus(out, Pkcs11WireProtocol.STATUS_OK, null);
                    stop();
                    break;
                default:
                    writeStatus(out, Pkcs11WireProtocol.STATUS_ERROR, "bilinmeyen opcode: " + op);
            }
        } catch (Exception e) {
            LOGGER.warn("Komut işlenirken hata (op={}): {}", op, e.toString());
            writeStatus(out, Pkcs11WireProtocol.STATUS_ERROR,
                e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private void handleFindSigner(Pkcs11WireProtocol.PayloadReader r, DataOutputStream out)
            throws IOException {
        String alias = r.readString();
        String serial = r.readString();
        Pkcs11Signer signer = module.findSigner(alias, serial);
        int id = signerIdGen.incrementAndGet();
        signers.put(id, signer);

        Pkcs11WireProtocol.PayloadWriter w = Pkcs11WireProtocol.newPayload();
        w.writeByte(Pkcs11WireProtocol.STATUS_OK);
        w.writeInt(id);
        w.writeString(signer.getAlias());
        w.writeBytes(WireCodec.encodeCert(signer.getCertificate()));
        w.writeBytes(WireCodec.encodeCertChain(signer.getCertificateChain()));
        Pkcs11WireProtocol.writeFrame(out, w.toByteArray());
    }

    private void handleHeartbeatStatus(DataOutputStream out) throws IOException {
        HelperHeartbeat hb = this.heartbeat;
        HelperHeartbeat.Status st = hb != null ? hb.currentStatus() : HelperHeartbeat.Status.disabled();
        Pkcs11WireProtocol.PayloadWriter w = Pkcs11WireProtocol.newPayload()
            .writeByte(Pkcs11WireProtocol.STATUS_OK)
            .writeByte(st.enabled ? 1 : 0)
            .writeLong(st.successCount)
            .writeLong(st.failureCount)
            .writeLong(st.consecutiveFailures)
            .writeLong(st.reinitAttempts)
            .writeLong(st.reinitSuccesses)
            .writeLong(st.reinitFailures)
            .writeLong(st.lastSuccessAtMillis)
            .writeString(st.lastErrorMessage);
        Pkcs11WireProtocol.writeFrame(out, w.toByteArray());
    }

    private void handleListCertificates(DataOutputStream out) throws IOException {
        List<CertificateInfoDto> certs = module.listCertificates();
        byte[] json = WireCodec.encodeCertInfoList(certs);
        Pkcs11WireProtocol.PayloadWriter w = Pkcs11WireProtocol.newPayload();
        w.writeByte(Pkcs11WireProtocol.STATUS_OK);
        w.writeBytes(json);
        Pkcs11WireProtocol.writeFrame(out, w.toByteArray());
    }

    private void handleSign(Pkcs11WireProtocol.PayloadReader r, DataOutputStream out, boolean digestMode)
            throws IOException {
        int signerId = r.readInt();
        String algName = r.readString();
        byte[] data = r.readBytes();
        Pkcs11Signer signer = signers.get(signerId);
        if (signer == null) {
            writeStatus(out, Pkcs11WireProtocol.STATUS_ERROR,
                Pkcs11WireProtocol.UNKNOWN_SIGNER_MARKER + " signerId=" + signerId
                + " (helper restart olmuş olabilir)");
            return;
        }
        byte[] signature = digestMode
            ? signer.signDigest(data, DigestAlgorithm.valueOf(algName))
            : signer.sign(data, SignatureAlgorithm.valueOf(algName));
        Pkcs11WireProtocol.PayloadWriter w = Pkcs11WireProtocol.newPayload();
        w.writeByte(Pkcs11WireProtocol.STATUS_OK);
        w.writeBytes(signature);
        Pkcs11WireProtocol.writeFrame(out, w.toByteArray());
    }

    private void writeStatus(DataOutputStream out, byte status, String message) throws IOException {
        Pkcs11WireProtocol.PayloadWriter w = Pkcs11WireProtocol.newPayload();
        w.writeByte(status);
        if (status != Pkcs11WireProtocol.STATUS_OK) {
            w.writeString(message);
        }
        Pkcs11WireProtocol.writeFrame(out, w.toByteArray());
    }

    /** Sabit-zamanlı token karşılaştırması (timing-attack korunaklı). */
    private boolean authOk(String presented) {
        byte[] presentedBytes = presented == null
            ? new byte[0] : presented.getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(presentedBytes, expectedTokenBytes);
    }
}
