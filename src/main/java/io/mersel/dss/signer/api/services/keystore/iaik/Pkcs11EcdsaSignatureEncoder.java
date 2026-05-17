package io.mersel.dss.signer.api.services.keystore.iaik;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;

/**
 * PKCS#11 ECDSA/DSA mekanizmaları imza çıktısını JCA/CMS uyumlu formata
 * normalize eder.
 *
 * <h2>Neden gerekli?</h2>
 * <p>PKCS#11 v2.40/v3.0 §2.3.1 (ECDSA) ve §2.3.5 (DSA) spec'i diyor ki:</p>
 * <blockquote>
 *   "For these mechanisms, signatures shall be represented as the
 *   concatenation of (r, s), where each integer is encoded as an octet
 *   string of equal length, padded to the left with zeros if necessary."
 * </blockquote>
 * <p>Yani HSM bize <b>raw r||s</b> verir (sabit uzunluk, byte concat).</p>
 *
 * <p>Buna karşılık <b>JCA, CMS, PAdES, XAdES, DSS doğrulayıcıları</b> hep
 * ASN.1 DER format bekler:</p>
 * <pre>
 *   ECDSA-Sig-Value ::= SEQUENCE {
 *       r  INTEGER,
 *       s  INTEGER
 *   }
 * </pre>
 *
 * <p>İki format uyumsuzdur. Eğer raw byte'ları doğrudan CMS akışına
 * verirsek imza <b>doğrulamadan geçemez</b> — Adobe Reader, GİB e-Fatura
 * doğrulayıcısı, DSS validator, hepsi reddeder. Bu sınıf bu dönüşümü
 * gerçekleştirir.</p>
 *
 * <p>NOT: PFX yolunda (JCA {@link java.security.Signature#sign}) bu işlem
 * platform tarafından otomatik yapılır; HSM yolunda <b>biz</b> yapmak
 * zorundayız.</p>
 *
 * <h2>RSA için neden gerekmez?</h2>
 * <p>PKCS#11 RSA mekanizmaları (CKM_*_RSA_PKCS, CKM_*_RSA_PKCS_PSS)
 * RSASSA-PKCS1-v1_5 ya da RSASSA-PSS standardına göre encoded imza
 * döndürür — bu format JCA çıktısıyla birebir aynı. Dönüşüm gerekmez.</p>
 */
public final class Pkcs11EcdsaSignatureEncoder {

    private Pkcs11EcdsaSignatureEncoder() {
        throw new UnsupportedOperationException("static utility");
    }

    /**
     * HSM'den gelen raw r||s byte dizisini ASN.1 DER SEQUENCE { r, s }'a sarar.
     *
     * @param rawConcat r ve s'in sabit uzunlukta birleştirilmiş hali (HSM çıktısı)
     * @return DER-encoded {@code SEQUENCE { INTEGER r, INTEGER s }}
     * @throws IllegalArgumentException null, boş, ya da tek-sayılı uzunluk
     */
    public static byte[] toDer(byte[] rawConcat) {
        if (rawConcat == null) {
            throw new IllegalArgumentException("rawConcat null olamaz");
        }
        if (rawConcat.length == 0 || (rawConcat.length & 1) != 0) {
            throw new IllegalArgumentException(
                "ECDSA/DSA raw imzası çift uzunlukta olmalı (r||s eşit uzunluk); "
                + "bulunan uzunluk: " + rawConcat.length);
        }

        int half = rawConcat.length / 2;
        byte[] rBytes = Arrays.copyOfRange(rawConcat, 0, half);
        byte[] sBytes = Arrays.copyOfRange(rawConcat, half, rawConcat.length);

        // BigInteger(1, ...) → unsigned interpretation; sıfır-leading byte'lar
        // kabul edilir, INTEGER negatif olmaz (high-bit set olsa bile).
        BigInteger r = new BigInteger(1, rBytes);
        BigInteger s = new BigInteger(1, sBytes);

        ASN1EncodableVector vec = new ASN1EncodableVector();
        vec.add(new ASN1Integer(r));
        vec.add(new ASN1Integer(s));
        try {
            return new DERSequence(vec).getEncoded("DER");
        } catch (IOException e) {
            // DER encoding'in IO hatası vermesi pratik olarak imkansızdır
            // (memory stream); programatik bug işareti.
            throw new IllegalStateException("DER encode başarısız", e);
        }
    }

    /**
     * Strict DER algılaması: imzayı tam ASN.1 olarak parse etmeyi dener ve
     * <em>kanonik DER roundtrip</em> kontrolü yapar.
     *
     * <p><b>Neden bu kadar katı?</b> PKCS#11 spec'i EC/DSA mekanizmalarında
     * <b>raw r||s</b> üretir; ama 32 byte'lık (P-256) bir raw imza tesadüfen
     * {@code 30 3E 02 ...} gibi DER benzeri bir prefix taşıyabilir
     * (olasılık 1/2²⁴ civarı, hiç de imkansız değil). Yüzeysel "tag 0x30 +
     * length match" heuristiği bu durumda raw'ı DER sanıp dönüştürmeden
     * geçirir → imza sporadik şekilde doğrulanamaz.</p>
     *
     * <p>Bu metot şu üç koşulu birden sağlarsa DER kabul eder:</p>
     * <ol>
     *   <li>Byte dizisi geçerli ASN.1 SEQUENCE olarak <b>tam tüketimle</b>
     *       parse ediliyor (artakalan byte yok).</li>
     *   <li>SEQUENCE içinde tam <b>iki</b> öğe var ve ikisi de
     *       {@link ASN1Integer}.</li>
     *   <li>Aynı yapı tekrar DER encode edilince <b>byte-bit aynı</b>
     *       imzaya geri dönüyor (kanonik DER deterministiktir; raw r||s
     *       bu deterministik forma rastlamış olamaz).</li>
     * </ol>
     *
     * <p>Roundtrip + tam tüketim, yanlış-pozitif olasılığını pratik olarak
     * sıfıra indirir.</p>
     */
    public static boolean looksLikeDer(byte[] signature) {
        if (signature == null || signature.length < 8) {
            return false;
        }
        try {
            ASN1Primitive parsed = ASN1Primitive.fromByteArray(signature);
            if (!(parsed instanceof ASN1Sequence)) {
                return false;
            }
            ASN1Sequence seq = (ASN1Sequence) parsed;
            if (seq.size() != 2) {
                return false;
            }
            if (!(seq.getObjectAt(0) instanceof ASN1Integer)
                || !(seq.getObjectAt(1) instanceof ASN1Integer)) {
                return false;
            }
            // Kanonik DER roundtrip — raw r||s burayı geçemez çünkü
            // BigInteger leading-zero handling, length encoding ve INTEGER
            // padding kuralları deterministik bir output üretir.
            byte[] reencoded = seq.getEncoded(ASN1Encoding.DER);
            return Arrays.equals(signature, reencoded);
        } catch (IOException | IllegalStateException | ClassCastException e) {
            return false;
        }
    }

    /**
     * Eğer giriş zaten DER ise olduğu gibi döndürür, raw r||s ise DER'e sarar.
     * Çağıran tarafın "iki defa sarmama" yükünü kaldırır. DER algılaması
     * {@link #looksLikeDer} ile strict yapıldığı için yanlış-pozitif
     * olasılığı pratik sıfırdır.
     */
    public static byte[] normalizeToDer(byte[] signature) {
        if (looksLikeDer(signature)) {
            return signature;
        }
        return toDer(signature);
    }

    /**
     * DER-encoded ECDSA imzayı (CMS / PKCS#7 / PAdES / CAdES formatı) <b>raw
     * r||s</b> formatına çevirir (XMLDsig / RFC 4051 formatı).
     *
     * <h3>Neden gerekli?</h3>
     * <p>Aynı ECDSA imzası için iki farklı standart format vardır:</p>
     * <ul>
     *   <li><b>CMS / CAdES / PAdES</b> (RFC 5652) →
     *       {@code DER SEQUENCE { INTEGER r, INTEGER s }}</li>
     *   <li><b>XMLDsig / WS-Security</b> (RFC 4051 §3.4.1) →
     *       {@code concat(r, s)} — sabit uzunluklu, leading-zero ile padded</li>
     * </ul>
     *
     * <p>{@link #toDer} bu yönde tek yönlü dönüşüm yapıyor; XML imza akışında
     * tersini (DER → raw) yapmak gerekir. Bu metot {@code BigInteger.toByteArray()}'ın
     * leading-zero handling'i ile dikkatli çalışır.</p>
     *
     * @param der DER-encoded ECDSA imzası
     * @param fieldSizeBytes EC curve field uzunluğu byte cinsinden
     *                       (P-256 = 32, P-384 = 48, P-521 = 66)
     * @return raw {@code r || s} (uzunluk: {@code 2 * fieldSizeBytes})
     * @throws IllegalArgumentException girdi DER değil ya da r veya s
     *                                  {@code fieldSizeBytes}'tan büyük
     */
    public static byte[] derToRaw(byte[] der, int fieldSizeBytes) {
        if (fieldSizeBytes <= 0) {
            throw new IllegalArgumentException("fieldSizeBytes pozitif olmalı: " + fieldSizeBytes);
        }
        if (!looksLikeDer(der)) {
            throw new IllegalArgumentException(
                "Girdi DER ECDSA-Sig-Value değil; derToRaw çağrısı geçersiz.");
        }
        try {
            ASN1Sequence seq = (ASN1Sequence) ASN1Primitive.fromByteArray(der);
            BigInteger r = ((ASN1Integer) seq.getObjectAt(0)).getValue();
            BigInteger s = ((ASN1Integer) seq.getObjectAt(1)).getValue();
            if (r.signum() < 0 || s.signum() < 0) {
                throw new IllegalArgumentException(
                    "ECDSA r/s pozitif tam sayı olmalı (negatif değer yorumlanamaz).");
            }
            byte[] raw = new byte[fieldSizeBytes * 2];
            writeUnsignedFixedLength(raw, 0, r, fieldSizeBytes);
            writeUnsignedFixedLength(raw, fieldSizeBytes, s, fieldSizeBytes);
            return raw;
        } catch (IOException e) {
            throw new IllegalArgumentException("DER parse hatası", e);
        }
    }

    private static void writeUnsignedFixedLength(byte[] target, int offset,
                                                 BigInteger value, int fieldSizeBytes) {
        byte[] bytes = value.toByteArray();
        // BigInteger.toByteArray() iki şey yapabilir:
        //   (a) pozitif değer + high-bit set → 0x00 leading byte ekler
        //       (örn. 0xFF... için [0x00, 0xFF, ...])
        //   (b) pozitif değer + high-bit clear → minimal length
        // Her iki durumda da fieldSize'a sığacak şekilde sağa hizalanır.
        //
        // GÜVENLİK: Eğer kaynak gerçekten fieldSize'tan büyük (ham olarak
        // anlamlı byte içeriyor) ise sessizce kırpmak imzanın matematiksel
        // değerini değiştirir → encoder farklı bir (r,s) ürettir. Bu nedenle
        // önce "kırpılacak ön byte'lar TAMAMEN sıfır mı?" kontrolü yapıyoruz.
        // Sadece BigInteger'in eklediği sign-padding 0x00'ları atıyoruz; anlamlı
        // veri kayboluyorsa fail-fast.
        if (bytes.length > fieldSizeBytes) {
            int excess = bytes.length - fieldSizeBytes;
            for (int i = 0; i < excess; i++) {
                if (bytes[i] != 0x00) {
                    throw new IllegalArgumentException(
                        "r veya s curve fieldSize'tan büyük: actual="
                            + bytes.length + " byte, expected<=" + fieldSizeBytes
                            + " (anlamlı üst byte=0x"
                            + String.format("%02X", bytes[i] & 0xFF)
                            + " offset=" + i + ")");
                }
            }
        }
        int start = bytes.length > fieldSizeBytes ? bytes.length - fieldSizeBytes : 0;
        int length = bytes.length - start;
        int dstOffset = offset + (fieldSizeBytes - length);
        System.arraycopy(bytes, start, target, dstOffset, length);
        // Soldaki padding bytes zaten 0 (new byte[] default).
    }
}
