package io.mersel.dss.signer.api.services.keystore.iaik;

import io.mersel.dss.signer.api.dtos.CertificateInfoDto;

import java.util.List;

/**
 * PKCS#11 modülünün uygulamaya açık <b>belge-imzalama + listeleme yüzeyi</b>.
 * Köprü mimarisinin (bkz. {@code bridge} alt paketi) ana soyutlamasıdır:
 *
 * <ul>
 *   <li>{@link IaikPkcs11Module} — <b>in-process</b> implementasyon; native
 *       DLL'i JVM'in kendi process'ine JNI ile yükler. JVM ve DLL bit'liği
 *       uyuştuğunda kullanılır (sıfır overhead).</li>
 *   <li>{@code RemotePkcs11Module} — <b>out-of-process</b> implementasyon;
 *       çağrıları IPC üzerinden, DLL'i kendi process'inde yükleyen ayrı
 *       bit'likteki bir helper'a iletir. 64-bit JVM + 32-bit DLL (veya tersi)
 *       senaryosunda devreye girer.</li>
 * </ul>
 *
 * <p>Önemli: bu yüzeyden geçen veri her zaman küçüktür (sertifika listesi,
 * digest/imza baytları). Ağır DSS belge işleme her zaman ana process'te
 * kalır; remote modda bile büyük belgeler IPC sınırını <b>geçmez</b>. Bu,
 * 32-bit helper'ın dar adres alanını (heap baskısını) önemsizleştirir.</p>
 *
 * <p>Heartbeat / SMS-recovery gibi düşük seviye, native-handle bağımlı
 * davranışlar <b>bu arayüzde değildir</b>: in-process modda
 * {@link IaikPkcs11Module}'ün concrete metotları üzerinden, remote modda
 * helper process'in içinde — yani her iki durumda da DLL'e bitişik —
 * çalışır.</p>
 */
public interface Pkcs11ModulePort {

    /**
     * Verilen alias/serial ile eşleşen imzalama materyalini döndürür.
     * Bkz. {@link IaikPkcs11Module#findSigner(String, String)}.
     */
    Pkcs11Signer findSigner(String alias, String serialHex);

    /**
     * Token üzerindeki tüm sertifikaları listeler.
     * Bkz. {@link IaikPkcs11Module#listCertificates()}.
     */
    List<CertificateInfoDto> listCertificates();

    /** İmza anahtarı çözümleme cache'ini sıfırlar. */
    void invalidateKeyCache();

    /** Modülü kapatır (token logout, native finalize veya helper teardown). */
    void destroy();
}
