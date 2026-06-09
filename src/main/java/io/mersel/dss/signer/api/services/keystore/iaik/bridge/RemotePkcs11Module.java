package io.mersel.dss.signer.api.services.keystore.iaik.bridge;

import io.mersel.dss.signer.api.dtos.CertificateInfoDto;
import io.mersel.dss.signer.api.exceptions.KeyStoreException;
import io.mersel.dss.signer.api.exceptions.SignatureException;
import io.mersel.dss.signer.api.services.keystore.iaik.Pkcs11ModulePort;
import io.mersel.dss.signer.api.services.keystore.iaik.Pkcs11Signer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * {@link Pkcs11ModulePort}'un <b>out-of-process</b> implementasyonu. Native
 * DLL'i hiç yüklemez; tüm çağrıları, DLL'i kendi bit'liğinde yükleyen helper
 * process'e ({@link Pkcs11HelperProcess}) loopback IPC ile iletir.
 *
 * <p>Bu sayede 64-bit ana JVM, yalnızca 32-bit'i bulunan bir PKCS#11 DLL'i
 * (örn. eski mali mühür / akıllı kart sürücüsü) kullanabilir — üstelik ağır
 * DSS belge işleme 64-bit tarafta, geniş heap'te kalır. 32-bit helper sadece
 * digest→imza round-trip'i yaptığı için dar adres alanı sorun olmaz.</p>
 *
 * <h2>Bağlantı modeli</h2>
 * <p>İstek başına kısa-ömürlü loopback bağlantı (connect → auth → 1 round-trip
 * → close). HSM imzası zaten ms mertebesinde donanım round-trip'i olduğundan
 * loopback connect maliyeti ihmal edilebilir; ayrıca bu model helper restart'ı
 * (port değişimi) şeffaf yönetir — her istek güncel portu sorar.</p>
 */
public final class RemotePkcs11Module implements Pkcs11ModulePort {

    private static final Logger LOGGER = LoggerFactory.getLogger(RemotePkcs11Module.class);

    /** Köprü sağlıklı kaldığı sürece "yaşıyorum" logunu en fazla bu sıklıkta yaz. */
    private static final long HEALTH_LOG_INTERVAL_MS = 5 * 60_000L;

    private final Pkcs11HelperProcess helper;
    private final int connectTimeoutMs;
    private final int readTimeoutMs;

    /** Sağlık gözlemlenebilirliği — durum-geçişli, spam'lemeyen loglama için. */
    private final AtomicLong successCount = new AtomicLong();
    private final AtomicBoolean healthy = new AtomicBoolean(true);
    private volatile long lastHealthyLogAtMs = 0L;

    public RemotePkcs11Module(Pkcs11HelperProcess helper, int connectTimeoutMs, int readTimeoutMs) {
        this.helper = helper;
        this.connectTimeoutMs = connectTimeoutMs;
        this.readTimeoutMs = readTimeoutMs;
    }

    @Override
    public Pkcs11Signer findSigner(String alias, String serialHex) {
        return resolveSigner(alias, serialHex);
    }

    /** Helper'dan taze bir signerId + cert + chain çözer ve remote signer üretir. */
    RemotePkcs11Signer resolveSigner(String alias, String serialHex) {
        Pkcs11WireProtocol.PayloadWriter w = Pkcs11WireProtocol.newPayload()
            .writeByte(Pkcs11WireProtocol.OP_FIND_SIGNER)
            .writeString(alias)
            .writeString(serialHex);
        Pkcs11WireProtocol.PayloadReader r = call(w.toByteArray(), "findSigner");
        int signerId = r.readInt();
        String resolvedAlias = r.readString();
        X509Certificate cert = WireCodec.decodeCert(r.readBytes());
        List<X509Certificate> chain = WireCodec.decodeCertChain(r.readBytes());
        LOGGER.info("Remote signer çözüldü: alias='{}', signerId={}", resolvedAlias, signerId);
        return new RemotePkcs11Signer(this, signerId, resolvedAlias, alias, serialHex, cert, chain);
    }

    @Override
    public List<CertificateInfoDto> listCertificates() {
        Pkcs11WireProtocol.PayloadWriter w = Pkcs11WireProtocol.newPayload()
            .writeByte(Pkcs11WireProtocol.OP_LIST_CERTIFICATES);
        Pkcs11WireProtocol.PayloadReader r = call(w.toByteArray(), "listCertificates");
        return WireCodec.decodeCertInfoList(r.readBytes());
    }

    @Override
    public void invalidateKeyCache() {
        Pkcs11WireProtocol.PayloadWriter w = Pkcs11WireProtocol.newPayload()
            .writeByte(Pkcs11WireProtocol.OP_INVALIDATE_CACHE);
        call(w.toByteArray(), "invalidateKeyCache");
    }

    @Override
    public void destroy() {
        LOGGER.info("Remote PKCS#11 modülü kapatılıyor (helper teardown).");
        helper.close();
    }

    // ------------------------------------------------------------------
    // Sağlık / gözlemlenebilirlik (Actuator health probe'u için)
    // ------------------------------------------------------------------

    /**
     * Hafif canlılık kontrolü: helper'a {@code OP_PING} round-trip'i yapar.
     * Native DLL'e veya HSM session'larına dokunmaz (helper server PING'i
     * doğrudan {@code STATUS_OK} ile yanıtlar), bu yüzden eşzamanlı imzaları
     * etkilemez. Başarılıysa köprü sağlık durumunu günceller (gerekirse
     * "toparlandı" loglar); başarısızsa exception fırlatır.
     */
    public void ping() {
        Pkcs11WireProtocol.PayloadWriter w = Pkcs11WireProtocol.newPayload()
            .writeByte(Pkcs11WireProtocol.OP_PING);
        call(w.toByteArray(), "ping");
    }

    /** Son IPC denemesi sağlıklı mıydı (durum bayrağı; aktif probe yapmaz). */
    public boolean isIpcHealthy() {
        return healthy.get();
    }

    /** Helper process hâlâ ayakta mı. */
    public boolean isHelperAlive() {
        return helper.isAlive();
    }

    /** Helper'ın dinlediği güncel port (restart sonrası değişebilir; -1 = bilinmiyor). */
    public int getHelperPort() {
        return helper.getPort();
    }

    /** Köprü üzerinden tamamlanan başarılı IPC işlemi sayısı (ping dahil). */
    public long getSuccessfulOperationCount() {
        return successCount.get();
    }

    /**
     * Helper içindeki heartbeat'in anlık sayaç durumunu IPC ile sorar
     * ({@code OP_HEARTBEAT_STATUS}). Ana process'teki {@code RemoteHsmHeartbeatMonitor}
     * bunu periyodik çağırıp geçişlerde operatör bildirimi (Slack/webhook) atar.
     */
    public HeartbeatStatus heartbeatStatus() {
        Pkcs11WireProtocol.PayloadReader r = call(
            Pkcs11WireProtocol.newPayload()
                .writeByte(Pkcs11WireProtocol.OP_HEARTBEAT_STATUS)
                .toByteArray(),
            "heartbeatStatus");
        boolean enabled = r.readByte() != 0;
        return new HeartbeatStatus(enabled,
            r.readLong(), r.readLong(), r.readLong(),
            r.readLong(), r.readLong(), r.readLong(),
            r.readLong(), r.readString());
    }

    /** Helper heartbeat sayaçlarının ana process tarafındaki değişmez görüntüsü. */
    public static final class HeartbeatStatus {
        public final boolean enabled;
        public final long successCount;
        public final long failureCount;
        public final long consecutiveFailures;
        public final long reinitAttempts;
        public final long reinitSuccesses;
        public final long reinitFailures;
        public final long lastSuccessAtMillis;
        public final String lastErrorMessage;

        public HeartbeatStatus(boolean enabled, long successCount, long failureCount,
                               long consecutiveFailures, long reinitAttempts, long reinitSuccesses,
                               long reinitFailures, long lastSuccessAtMillis, String lastErrorMessage) {
            this.enabled = enabled;
            this.successCount = successCount;
            this.failureCount = failureCount;
            this.consecutiveFailures = consecutiveFailures;
            this.reinitAttempts = reinitAttempts;
            this.reinitSuccesses = reinitSuccesses;
            this.reinitFailures = reinitFailures;
            this.lastSuccessAtMillis = lastSuccessAtMillis;
            this.lastErrorMessage = lastErrorMessage;
        }
    }

    /**
     * {@link RemotePkcs11Signer} buradan imza ister. Helper restart sonucu
     * {@code signerId} kaybolmuşsa signer'ı yeniden çözüp tek-shot retry yapar.
     */
    byte[] sign(RemotePkcs11Signer signer, byte[] data, String algName, boolean digestMode) {
        try {
            return signOnce(signer.getSignerId(), data, algName, digestMode);
        } catch (UnknownSignerException stale) {
            LOGGER.warn("Remote signerId stale (helper restart); signer re-resolve + retry. alias='{}'",
                signer.getAlias());
            RemotePkcs11Signer refreshed = resolveSigner(signer.getRequestedAlias(),
                signer.getRequestedSerial());
            signer.refreshFrom(refreshed);
            return signOnce(signer.getSignerId(), data, algName, digestMode);
        }
    }

    private byte[] signOnce(int signerId, byte[] data, String algName, boolean digestMode) {
        byte op = digestMode ? Pkcs11WireProtocol.OP_SIGN_DIGEST : Pkcs11WireProtocol.OP_SIGN;
        Pkcs11WireProtocol.PayloadWriter w = Pkcs11WireProtocol.newPayload()
            .writeByte(op)
            .writeInt(signerId)
            .writeString(algName)
            .writeBytes(data);
        Pkcs11WireProtocol.PayloadReader r = call(w.toByteArray(), digestMode ? "signDigest" : "sign");
        return r.readBytes();
    }

    // ------------------------------------------------------------------
    // IPC plumbing
    // ------------------------------------------------------------------

    /**
     * Bağlanır, auth eder, tek frame gönderir, yanıtı okur. Status OK ise
     * (status byte'ı tüketilmiş) {@link Pkcs11WireProtocol.PayloadReader} döner;
     * hata ise uygun exception fırlatır.
     */
    private Pkcs11WireProtocol.PayloadReader call(byte[] requestPayload, String opName) {
        int port = helper.getPort();
        if (port < 0) {
            throw new SignatureException("PKCS#11 helper hazır değil (port bilinmiyor); "
                + opName + " yapılamıyor.");
        }
        Socket socket = new Socket();
        try {
            socket.connect(new InetSocketAddress(helper.getBindHost(), port), connectTimeoutMs);
            socket.setSoTimeout(readTimeoutMs);
            socket.setTcpNoDelay(true);
            DataOutputStream out = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));
            DataInputStream in = new DataInputStream(socket.getInputStream());

            // Auth.
            Pkcs11WireProtocol.writeFrame(out, Pkcs11WireProtocol.newPayload()
                .writeByte(Pkcs11WireProtocol.OP_AUTH)
                .writeString(helper.getToken())
                .toByteArray());
            checkStatus(Pkcs11WireProtocol.readFrame(in), opName + " (auth)");

            // İstek + yanıt.
            Pkcs11WireProtocol.writeFrame(out, requestPayload);
            byte[] respFrame = Pkcs11WireProtocol.readFrame(in);
            // Helper'dan yanıt frame'i alındı → IPC taşıması sağlıklı.
            recordHealthy(opName);
            return checkStatus(respFrame, opName);
        } catch (IOException e) {
            recordUnhealthy(opName, e);
            throw new SignatureException("PKCS#11 helper IPC hatası (" + opName + "): "
                + e.getMessage(), e);
        } finally {
            try { socket.close(); } catch (IOException ignored) { }
        }
    }

    /**
     * Başarılı bir IPC round-trip kaydeder ve köprünün stabil çalıştığını
     * <b>durum-geçişli</b> loglar: ilk doğrulama, dejenerasyon sonrası
     * toparlanma ve periyodik (5 dk) "sağlıklı" sinyali. Her işlemde log
     * basmaz — production log gürültüsü yaratmaz.
     */
    private void recordHealthy(String opName) {
        long n = successCount.incrementAndGet();
        if (healthy.compareAndSet(false, true)) {
            LOGGER.info("PKCS#11 köprüsü TOPARLANDI: helper IPC yeniden sağlıklı "
                + "(op={}, toplam başarılı işlem={}).", opName, n);
            lastHealthyLogAtMs = System.currentTimeMillis();
            return;
        }
        long now = System.currentTimeMillis();
        if (n == 1) {
            LOGGER.info("PKCS#11 köprüsü çalışır durumda DOĞRULANDI: ilk helper IPC "
                + "round-trip başarılı (op={}). Native DLL helper process'inde, ağır DSS "
                + "işleme ana process'te; köprüden yalnızca küçük veri geçiyor.", opName);
            lastHealthyLogAtMs = now;
        } else if (now - lastHealthyLogAtMs >= HEALTH_LOG_INTERVAL_MS) {
            LOGGER.info("PKCS#11 köprüsü sağlıklı: helper IPC çalışıyor "
                + "(toplam başarılı işlem={}).", n);
            lastHealthyLogAtMs = now;
        }
    }

    /** İlk başarısızlık geçişinde bir kez ERROR loglar (sürekli spam yok). */
    private void recordUnhealthy(String opName, Exception cause) {
        if (healthy.compareAndSet(true, false)) {
            LOGGER.error("PKCS#11 köprüsü DEJENERE oldu: helper IPC başarısız (op={}): {}. "
                + "Supervisor helper'ı yeniden başlatmayı deneyecek; sonraki başarılı "
                + "işlemde toparlanma loglanacak.", opName, cause.getMessage());
        }
    }

    /** Yanıt frame'inin status byte'ını kontrol eder; OK değilse exception. */
    private Pkcs11WireProtocol.PayloadReader checkStatus(byte[] frame, String opName) {
        Pkcs11WireProtocol.PayloadReader r = new Pkcs11WireProtocol.PayloadReader(frame);
        byte status = r.readByte();
        if (status == Pkcs11WireProtocol.STATUS_OK) {
            return r;
        }
        String message = r.readString();
        if (status == Pkcs11WireProtocol.STATUS_AUTH_FAILED) {
            throw new KeyStoreException("PKCS#11 helper auth reddedildi (" + opName + ")");
        }
        if (message != null && message.startsWith(Pkcs11WireProtocol.UNKNOWN_SIGNER_MARKER)) {
            throw new UnknownSignerException(message);
        }
        throw new SignatureException("PKCS#11 helper hata döndürdü (" + opName + "): " + message);
    }

    /** Stale signerId sinyali — {@link #sign} re-resolve için yakalar. */
    private static final class UnknownSignerException extends RuntimeException {
        UnknownSignerException(String message) {
            super(message);
        }
    }
}
