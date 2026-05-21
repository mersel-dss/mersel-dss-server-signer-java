package io.mersel.dss.signer.api.services.signature.xades;

import java.util.regex.Pattern;

import io.mersel.dss.signer.api.exceptions.SignatureException;

/**
 * Kullanıcının verdiği {@code signatureId}'yi DSS'in {@code deterministicId}
 * olarak güvenle kullanabileceği bir XML {@code NCName} forma normalize eder.
 *
 * <h3>Neden gerekli?</h3>
 * <p>DSS, {@code deterministicId}'yi sorgu sormadan dört ayrı yere basar:
 * <ul>
 *   <li>{@code <ds:Signature Id="...">}</li>
 *   <li>{@code <xades:QualifyingProperties Target="#...">}</li>
 *   <li>{@code <xades:SignedProperties Id="xades-..."/>} ve buna işaret eden
 *       {@code <ds:Reference URI="#xades-..."/>}</li>
 *   <li>{@code KeyInfo} ve {@code SignatureValue} ID'leri</li>
 * </ul>
 * Eğer ham {@code signatureId} XML {@code NCName} kurallarını ihlal eden bir
 * karakter (örn. {@code '#'}) içerirse, sonuçta üretilen {@code URI="#xades-..."}
 * referansı RFC 3986'ya göre malformed olur ({@code fragment} içinde
 * {@code '#'} yasaktır) ve TÜBİTAK/GİB tarafındaki XAdES doğrulayıcılar
 * SignedProperties node'unu çözümleyemez → digest karşılaştırması
 * yapılamaz → imza geçersiz işaretlenir.</p>
 *
 * <h3>Kabul ettiği girdiler ve davranış</h3>
 * <pre>
 *   "Attach_1"                  -&gt; "Signature_Attach_1"
 *   "Signature_Attach_1"        -&gt; "Signature_Attach_1"   (çift prefix yok)
 *   "#Signature_Attach_1"       -&gt; "Signature_Attach_1"   (URI fragment temizlenir)
 *   "##Signature_x"             -&gt; "Signature_x"          (peş peşe '#' temizlenir)
 *   "id-9f3...e89fd"            -&gt; "Signature_id-9f3...e89fd"
 * </pre>
 *
 * <h3>Reddedilen girdiler</h3>
 * <p>Sonuç {@code NCName} kurallarını karşılamıyorsa
 * {@link SignatureException} fırlatılır (errorCode = {@code INVALID_SIGNATURE_ID}).
 * Örnekler:
 * <ul>
 *   <li>{@code "abc#def"} - tek başına '#' içeriyor, prefix sonrasında da
 *       NCName olmaz</li>
 *   <li>{@code "9starts-with-digit"} - NCName harf veya '_' ile başlamalıdır</li>
 *   <li>{@code ""} (sadece prefix kalır) - boş suffix</li>
 * </ul>
 *
 * <h3>Spec referansları</h3>
 * <ul>
 *   <li>W3C XML 1.0 §3.5 "Names and Tokens" - NCName tanımı</li>
 *   <li>RFC 3986 §3.5 "Fragment" - URI fragment karakterleri</li>
 *   <li>XAdES 1.3.2 §6.3 - SignedProperties referansının URI çözümlemesi</li>
 * </ul>
 */
final class SignatureIdNormalizer {

    /**
     * DSS davranışıyla uyumlu prefix. {@link XAdESParametersBuilderService}
     * eski sürümlerinde sabit kod olarak yer alıyordu; ayrı bir sabit haline
     * getirilerek normalize + idempotency mantığı tek noktada toplandı.
     */
    private static final String PREFIX = "Signature_";

    /**
     * XML 1.0 NCName regex'i. {@code Letter} sınıfını basitleştirip Java {@code \w}
     * (ASCII letter/digit/underscore) + nokta + tire ile sınırladık çünkü:
     * <ol>
     *   <li>Bu projede signatureId genelde UUID, Base32 veya alfa-sayısal
     *       string olarak veriliyor (e2e testler ve örnek istemciler bu
     *       konvansiyonu kullanıyor).</li>
     *   <li>Latin-1 dışı karakterleri kabul etmek, downstream verifier'larda
     *       (Apache Santuario, .NET XmlDsig) edge-case sürprizleri açabilir.</li>
     * </ol>
     */
    private static final Pattern NC_NAME_PATTERN =
            Pattern.compile("[A-Za-z_][A-Za-z0-9_.\\-]*");

    private SignatureIdNormalizer() {
        // statik utility
    }

    /**
     * Ham {@code signatureId}'yi normalize eder ve geçerli bir
     * {@code deterministicId} döner.
     *
     * @param rawSignatureId Kullanıcının HTTP isteğiyle gönderdiği değer.
     *                      {@code null} veya {@code blank} ise {@code null} döner
     *                      (DSS kendi UUID-based default'unu kullanır).
     * @return DSS'in güvenle kullanabileceği NCName uyumlu kimlik, veya {@code null}.
     * @throws SignatureException Kullanıcı geçersiz bir girdi verdiyse
     *         ({@code errorCode = INVALID_SIGNATURE_ID}). Sessiz kırılma yerine
     *         400 üretmek tercih edilir; aksi halde imza üretilir ama tüketici
     *         tarafta doğrulama random şekilde patlar.
     */
    static String normalize(String rawSignatureId) {
        if (rawSignatureId == null) {
            return null;
        }
        String trimmed = rawSignatureId.trim();
        if (trimmed.isEmpty()) {
            return null;
        }

        // 1) Kullanıcı URI fragment formunda yapıştırmış olabilir ("#Signature_X")
        //    - ApplicationResponse/eFatura body'sinde DigitalSignatureAttachment
        //      URI'sı bu formdadır; bu yüzden refleksif olarak "#" eklenir.
        String stripped = trimmed;
        while (stripped.startsWith("#")) {
            stripped = stripped.substring(1);
        }

        // 2) Çift "Signature_" prefix önlenmesi
        //    - Kullanıcı zaten tam ID verdiyse ("Signature_Attach_1") yine de
        //      tek prefix'le bitir.
        String withPrefix = stripped.startsWith(PREFIX) ? stripped : PREFIX + stripped;

        // 3) NCName doğrulaması
        if (!NC_NAME_PATTERN.matcher(withPrefix).matches()) {
            throw new SignatureException(
                    "INVALID_SIGNATURE_ID",
                    "signatureId XML NCName kuralı dışında karakter içeriyor: '"
                            + rawSignatureId + "' -> '" + withPrefix + "'. "
                            + "İzin verilen: harf/rakam/'_'/'.'/'-' (başlangıç harf veya '_'). "
                            + "Özellikle '#' karakteri yasaktır; URI fragment olarak "
                            + "düşünüyorsanız sadece fragment gövdesini gönderin.");
        }

        return withPrefix;
    }
}
