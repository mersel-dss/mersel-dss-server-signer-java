package io.mersel.dss.signer.api.services.keystore.iaik.bridge;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;

/**
 * 64-bit ana process ile farklı bit'likteki PKCS#11 helper process arasındaki
 * IPC için minimal, dependency'siz binary protokol.
 *
 * <h2>Çerçeveleme (framing)</h2>
 * <p>Her mesaj {@code [int32 length][payload]} biçimindedir. {@code length}
 * big-endian (Java {@link DataOutputStream#writeInt}). İlk byte opcode (istek)
 * veya status (yanıt); kalanı opcode'a özgü alanlar.</p>
 *
 * <h2>Neden binary, neden minimal?</h2>
 * <p>Helper 32-bit JVM'de dar adres alanında çalışır; gRPC/protobuf/netty gibi
 * ağır bir stack onu şişirir. Sign yolundan geçen veri zaten küçük (digest +
 * imza), JSON overhead'i gereksiz. Yalnızca sertifika listesi gibi yapısal
 * veriler Jackson JSON ile (zaten classpath'te) taşınır.</p>
 *
 * <h2>Güvenlik</h2>
 * <p>Bağlantı loopback (127.0.0.1) üzerinden; ilk frame her zaman
 * {@link #OP_AUTH} ile tek-seferlik paylaşılan token taşır. Token eşleşmezse
 * server bağlantıyı {@link #STATUS_AUTH_FAILED} ile kapatır. PIN asla wire'dan
 * geçmez — helper'a kendi env/argümanıyla verilir.</p>
 */
public final class Pkcs11WireProtocol {

    private Pkcs11WireProtocol() {
    }

    // ---- Opcodes (istek ilk byte'ı) ----
    public static final byte OP_AUTH              = 1;
    public static final byte OP_FIND_SIGNER       = 2;
    public static final byte OP_LIST_CERTIFICATES = 3;
    public static final byte OP_SIGN              = 4;
    public static final byte OP_SIGN_DIGEST       = 5;
    public static final byte OP_INVALIDATE_CACHE  = 6;
    public static final byte OP_PING              = 7;
    public static final byte OP_SHUTDOWN          = 8;
    public static final byte OP_HEARTBEAT_STATUS  = 9;

    // ---- Status (yanıt ilk byte'ı) ----
    public static final byte STATUS_OK          = 0;
    public static final byte STATUS_ERROR       = 1;
    public static final byte STATUS_AUTH_FAILED = 2;

    /**
     * Helper restart olduğunda eski {@code signerId} kaybolur. Bu durumu
     * client'ın hedefli olarak yakalayıp signer'ı yeniden çözmesi (re-resolve)
     * + retry yapması için hata mesajı bu marker ile başlar.
     */
    public static final String UNKNOWN_SIGNER_MARKER = "UNKNOWN_SIGNER";

    /**
     * Tek bir mesaj çerçevesini yazar (uzunluk-prefix'li). Çağıran payload'ı
     * {@link #newPayload()} ile kurar.
     */
    public static void writeFrame(DataOutputStream out, byte[] payload) throws IOException {
        out.writeInt(payload.length);
        out.write(payload);
        out.flush();
    }

    /** Tek bir mesaj çerçevesini okur. Karşı taraf kapanırsa {@link EOFException}. */
    public static byte[] readFrame(DataInputStream in) throws IOException {
        int len = in.readInt();
        if (len < 0 || len > MAX_FRAME_BYTES) {
            throw new IOException("Geçersiz frame uzunluğu: " + len);
        }
        byte[] buf = new byte[len];
        in.readFully(buf);
        return buf;
    }

    /** 64 MB üst sınır — digest/imza/sertifika listesi bunun çok altındadır;
     *  bozuk/zararlı uzunluk değerine karşı koruma. */
    private static final int MAX_FRAME_BYTES = 64 * 1024 * 1024;

    /** Payload builder yardımcıları. */
    public static PayloadWriter newPayload() {
        return new PayloadWriter();
    }

    /** {@link DataOutputStream} sarmalı; null-güvenli string + length-prefix'li byte[]. */
    public static final class PayloadWriter {
        private final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        private final DataOutputStream dos = new DataOutputStream(baos);

        public PayloadWriter writeByte(int b) {
            try { dos.writeByte(b); } catch (IOException e) { throw new IllegalStateException(e); }
            return this;
        }

        public PayloadWriter writeInt(int v) {
            try { dos.writeInt(v); } catch (IOException e) { throw new IllegalStateException(e); }
            return this;
        }

        public PayloadWriter writeLong(long v) {
            try { dos.writeLong(v); } catch (IOException e) { throw new IllegalStateException(e); }
            return this;
        }

        public PayloadWriter writeString(String s) {
            try {
                if (s == null) {
                    dos.writeBoolean(false);
                } else {
                    dos.writeBoolean(true);
                    byte[] b = s.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                    dos.writeInt(b.length);
                    dos.write(b);
                }
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
            return this;
        }

        public PayloadWriter writeBytes(byte[] b) {
            try {
                if (b == null) {
                    dos.writeInt(-1);
                } else {
                    dos.writeInt(b.length);
                    dos.write(b);
                }
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
            return this;
        }

        public byte[] toByteArray() {
            try { dos.flush(); } catch (IOException e) { throw new IllegalStateException(e); }
            return baos.toByteArray();
        }
    }

    /** {@link DataInputStream} sarmalı; {@link PayloadWriter} ile simetrik okuma. */
    public static final class PayloadReader {
        private final DataInputStream dis;

        public PayloadReader(byte[] payload) {
            this.dis = new DataInputStream(new java.io.ByteArrayInputStream(payload));
        }

        public byte readByte() {
            try { return dis.readByte(); } catch (IOException e) { throw new IllegalStateException(e); }
        }

        public int readInt() {
            try { return dis.readInt(); } catch (IOException e) { throw new IllegalStateException(e); }
        }

        public long readLong() {
            try { return dis.readLong(); } catch (IOException e) { throw new IllegalStateException(e); }
        }

        public String readString() {
            try {
                if (!dis.readBoolean()) {
                    return null;
                }
                int len = dis.readInt();
                byte[] b = new byte[len];
                dis.readFully(b);
                return new String(b, java.nio.charset.StandardCharsets.UTF_8);
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        }

        public byte[] readBytes() {
            try {
                int len = dis.readInt();
                if (len < 0) {
                    return null;
                }
                byte[] b = new byte[len];
                dis.readFully(b);
                return b;
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        }
    }
}
