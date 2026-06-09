package io.mersel.dss.signer.api.services.keystore.iaik.bridge;

import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;

/**
 * "Köprü AÇIK" senaryosundaki helper process'in bellek davranışını temsil
 * eder. Gerçek {@link Pkcs11HelperServer} ile <b>aynı wire-protokolünü</b>
 * ({@link Pkcs11WireProtocol}) konuşur; tek farkı, native PKCS#11 yerine
 * stub bir "imza" (digest'in SHA-256'sı) üretmesidir — burada test edilen şey
 * kriptografi değil, <b>bellek</b>: helper hiçbir zaman büyük belgeyi görmez,
 * yalnızca ~32 byte digest alır.
 *
 * <p>Bu yüzden {@code -Xmx64m} gibi dar bir heap tavanında (32-bit adres
 * alanı emülasyonu) rahatça çalışır ve patlamaz. Belge, köprünün diğer
 * ucundaki geniş-heap'li ana process'te kalır.</p>
 */
public final class MemoryDemoHelperMain {

    private MemoryDemoHelperMain() {
    }

    public static void main(String[] args) throws Exception {
        try (ServerSocket server = new ServerSocket(0, 16, InetAddress.getByName("127.0.0.1"))) {
            System.out.println(HelperEnv.READY_PREFIX + server.getLocalPort());
            System.out.flush();

            try (Socket socket = server.accept()) {
                socket.setTcpNoDelay(true);
                DataInputStream in = new DataInputStream(socket.getInputStream());
                DataOutputStream out =
                    new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));

                // AUTH (token doğrulamasını demo'da basit tutuyoruz; kabul et).
                Pkcs11WireProtocol.readFrame(in);
                writeOk(out, null);

                while (true) {
                    byte[] frame;
                    try {
                        frame = Pkcs11WireProtocol.readFrame(in);
                    } catch (EOFException eof) {
                        break;
                    }
                    Pkcs11WireProtocol.PayloadReader r = new Pkcs11WireProtocol.PayloadReader(frame);
                    byte op = r.readByte();
                    if (op == Pkcs11WireProtocol.OP_SIGN_DIGEST) {
                        r.readInt();              // signerId
                        r.readString();           // alg
                        byte[] digest = r.readBytes();  // KÜÇÜK veri — büyük allocation YOK
                        byte[] signature = MessageDigest.getInstance("SHA-256").digest(digest);
                        System.out.println("HELPER: digest alındı (" + digest.length
                            + " byte), stub imza üretildi (" + signature.length + " byte)");
                        writeOk(out, signature);
                    } else if (op == Pkcs11WireProtocol.OP_SHUTDOWN) {
                        writeOk(out, null);
                        break;
                    } else {
                        writeOk(out, null);
                    }
                }
            }
        }
        System.out.println("HELPER: temiz kapandı (OOM yok).");
    }

    private static void writeOk(DataOutputStream out, byte[] data) throws java.io.IOException {
        Pkcs11WireProtocol.PayloadWriter w = Pkcs11WireProtocol.newPayload()
            .writeByte(Pkcs11WireProtocol.STATUS_OK);
        if (data != null) {
            w.writeBytes(data);
        }
        Pkcs11WireProtocol.writeFrame(out, w.toByteArray());
    }
}
