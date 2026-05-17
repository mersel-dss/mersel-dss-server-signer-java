package io.mersel.dss.signer.api.e2e.verifier;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

/**
 * <code>resources/test-fixtures/wssecurity/</code> altındaki gerçek SOAP
 * envelope örneklerini tipli olarak ifade eder.
 *
 * <p>Her enum değeri:</p>
 * <ul>
 *   <li>Dosya adı (uzantı dahil),</li>
 *   <li>{@code useSoap12} flag'i — {@code WsSecuritySignatureService} hem
 *       SOAP 1.1 hem SOAP 1.2 namespace'lerini destekler ve doğru body
 *       seçimi bu flag'e bağlıdır,</li>
 *   <li>İnsan-okur kısa ad (test parametrize raporları için).</li>
 * </ul>
 *
 * <h3>Senaryo dağılımı</h3>
 * <p>Mevcut 9 fixture <b>3 kategoriye</b> ayrılır:</p>
 * <ol>
 *   <li><b>Generic envelope'lar</b> ({@link #SOAP_1_1}, {@link #SOAP_1_2})
 *       — minimal SOAP body; tüm matrise koşar; baseline regression
 *       kapsamı.</li>
 *   <li><b>Production-parity envelope'lar</b>
 *       ({@link #GIB_EFATURA_SOAP}, {@link #SOAP_LARGE_50KB},
 *       {@link #SOAP_MULTIBODY}, {@link #SOAP_MTOM_XOP}) — gerçek-dünya
 *       SOAP yapılarına yakın; namespace, element order, performans,
 *       multipart placeholder vs. regresyon vektörleri.</li>
 *   <li><b>Contract envelope'ları</b>
 *       ({@link #SOAP_WITH_WSA}, {@link #SOAP_WITH_EXISTING_WSU_ID},
 *       {@link #SOAP_WITH_EXISTING_SECURITY_HEADER}) — signer'ın
 *       belirli davranış kontratlarını ({@code wsu:Id} override,
 *       WS-Addressing preservation, Security append-not-overwrite)
 *       teyit eden envelope'lar. Bunların özel assertion'ları
 *       {@code WsSecurityContractE2ETest} sınıfında yapılır.</li>
 * </ol>
 */
public enum SoapEnvelopeFixture {

    SOAP_1_1("soap-1.1-envelope.xml", /*useSoap12*/ false, "SOAP 1.1 envelope"),
    SOAP_1_2("soap-1.2-envelope.xml", /*useSoap12*/ true,  "SOAP 1.2 envelope"),

    /**
     * GİB e-Fatura / e-Arşiv Mali Mühür request iskeleti.
     * Production envelope ile namespace ve element order paritesi:
     * birden fazla namespace declaration ({@code soapenv}, {@code ei},
     * {@code xsd}, {@code xsi}, {@code gib}), attribute kullanımı
     * ({@code xsi:type}, {@code schemeID}), Türkçe karakterli element
     * value'ları.
     */
    GIB_EFATURA_SOAP("gib-efatura-soap.xml", false, "GİB e-Fatura SOAP request (real-world parity)"),

    /**
     * WS-Addressing header'ları içeren SOAP 1.2 envelope.
     * Beklenen kontrat: signer Security header'ı insert ederken
     * {@code wsa:MessageID}, {@code wsa:To}, {@code wsa:Action},
     * {@code wsa:ReplyTo} child element'lerine dokunmamalı.
     * Özel assertion {@code WsSecurityContractE2ETest}'tedir.
     */
    SOAP_WITH_WSA("soap-with-wsa.xml", true, "WS-Addressing header'larıyla SOAP 1.2"),

    /**
     * Body'de zaten {@code wsu:Id} attribute'u set olan envelope.
     * {@link io.mersel.dss.signer.api.services.signature.wssecurity.WsSecuritySignatureService}
     * mevcut {@code wsu:Id}'yi <b>siler</b> ve kendi
     * {@code Id="SignedSoapBodyContent"} attribute'unu set eder
     * (shadow-reference saldırılarına karşı). Özel assertion
     * {@code WsSecurityContractE2ETest}'tedir.
     */
    SOAP_WITH_EXISTING_WSU_ID("soap-with-existing-wsu-id.xml", false,
            "Body'de mevcut wsu:Id (override kontratı)"),

    /**
     * Body'de birden fazla child element içeren envelope.
     * SOAP spec'i (1.1 §4.3, 1.2 §5.3.1) "zero or more" child kabul eder;
     * batch / document-style request'lerde sıkça karşılaşılır. WS-Security
     * Body element'in tüm subtree'sini imzaladığı için child sayısı imza
     * kapsamını değiştirmez.
     */
    SOAP_MULTIBODY("soap-multibody.xml", false, "Multiple body children (batch request)"),

    /**
     * ~50KB SOAP envelope (120 child item). c14n + digest pipeline'ın
     * orta büyüklükte body'de performans/memory regresyonu yapmadığını
     * doğrular; her iterasyon &lt; 2 saniye olmalı.
     */
    SOAP_LARGE_50KB("soap-large-50kb.xml", false, "~50KB body (perf regression)"),

    /**
     * XOP:Include element'leri içeren envelope (MTOM placeholder).
     * Gerçek MTOM multipart wrapper signer scope'unun dışında; bu
     * fixture sadece XML envelope kısmı üzerinden c14n'in
     * {@code <xop:Include href="cid:…"/>} element'lerini olduğu
     * gibi koruduğunu test eder.
     */
    SOAP_MTOM_XOP("soap-mtom-xop.xml", false, "MTOM/XOP placeholder envelope"),

    /**
     * Header'da mevcut {@code <wsse:Security>} + {@code UsernameToken}
     * bulunan envelope. {@code createSecurityHeader} mevcut element'i
     * reuse eder; UsernameToken sign sonrası hâlâ korunmuş olmalı
     * (append-not-overwrite kontratı). Özel assertion
     * {@code WsSecurityContractE2ETest}'tedir.
     */
    SOAP_WITH_EXISTING_SECURITY_HEADER("soap-with-existing-security-header.xml", false,
            "Mevcut Security/UsernameToken (append-not-overwrite)");

    private static final String FIXTURE_DIR = "resources/test-fixtures/wssecurity";

    private final String fileName;
    private final boolean useSoap12;
    private final String displayName;

    SoapEnvelopeFixture(String fileName, boolean useSoap12, String displayName) {
        this.fileName = fileName;
        this.useSoap12 = useSoap12;
        this.displayName = displayName;
    }

    public String getFileName() {
        return fileName;
    }

    public boolean isUseSoap12() {
        return useSoap12;
    }

    /** Mutlak dosya yolu — Maven testlerde user.dir repo köküdür. */
    public File getFile() {
        return new File(FIXTURE_DIR, fileName).getAbsoluteFile();
    }

    /**
     * Dosya içeriğini byte dizisi olarak okur.
     *
     * @throws IllegalStateException fixture dosyası bulunamazsa veya okunamazsa
     */
    public byte[] readBytes() {
        File file = getFile();
        if (!file.isFile()) {
            throw new IllegalStateException(
                    "SOAP envelope fixture bulunamadı: " + file.getAbsolutePath()
                            + " (resources/test-fixtures/wssecurity/ klasörünü kontrol edin)");
        }
        try {
            return Files.readAllBytes(file.toPath());
        } catch (IOException e) {
            throw new IllegalStateException(
                    "SOAP envelope fixture okunamadı: " + file.getAbsolutePath(), e);
        }
    }

    @Override
    public String toString() {
        return name() + " (" + displayName + ")";
    }
}
