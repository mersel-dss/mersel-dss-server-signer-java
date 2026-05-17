package io.mersel.dss.signer.api.e2e.verifier;

import io.mersel.dss.signer.api.models.enums.DocumentType;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

/**
 * <code>resources/test-fixtures/xades/</code> altındaki XAdES için imzalanabilir
 * gerçek belge örneklerini tipli olarak ifade eder.
 *
 * <p>Her enum değeri:</p>
 * <ul>
 *   <li>Dosya adı (uzantı dahil),</li>
 *   <li>{@link DocumentType} eşlemesi — production signer'ın hangi placement
 *       stratejisini seçeceğini belirler,</li>
 *   <li>İnsan-okur kısa ad (test parametrize raporları için).</li>
 * </ul>
 *
 * <h3>e-Arşiv Raporu hakkında not</h3>
 * <p>{@link #EARSIV_RAPORU} {@link DocumentType#EArchiveReport} ile işaretlidir;
 * production'da bu tetikleme {@code XAdES-B → XAdES-A} yükseltmesi ister ve
 * TSA bağımlılığı doğurur. E2E test ortamında TSA olmadığı için
 * {@code XAdESLevelUpgradeService} sessizce upgrade'i atlar ve belge XAdES-B
 * olarak üretilir. Verifier API bunu XAdES-B-LEVEL olarak görür ve kabul eder
 * (TSA olmadan üretildiği için "indication=TOTAL_PASSED" beklenir, "T" seviye
 * kontrolü yapılmaz).</p>
 */
public enum XadesDocumentFixture {

    EFATURA("efatura.xml", DocumentType.UblDocument, "e-Fatura (UBL Invoice)"),
    EIRSALIYE("eirsaliye.xml", DocumentType.UblDocument, "e-İrsaliye (UBL DespatchAdvice)"),
    EMUSTAHSIL("emustahsil.xml", DocumentType.UblDocument, "e-Müstahsil Makbuzu (UBL CreditNote)"),
    EARSIV_RAPORU("earsiv-raporu.xml", DocumentType.EArchiveReport, "e-Arşiv Raporu"),
    HRXML("hrxml.xml", DocumentType.HrXml, "HR-XML (ProcessUserAccount)"),

    /**
     * Çok kalemli e-Fatura UBL Invoice (~5 MB, 4797 {@code <cac:InvoiceLine>}).
     * <b>Standart XAdES matrislerine dahil değildir</b> &mdash; tek başına
     * {@code XAdESLargeDocumentE2ETest} tarafından performans + c14n stress
     * yolu için kullanılır. {@link #standardFixtures()} bunu hariç tutar;
     * mevcut SoftHSM + verifier matrisleri 5 küçük fixture'da koşmaya
     * devam eder. Tipik üretim senaryosu: toptan satış / e-ticaret fatura
     * toplulukları.
     */
    EFATURA_LARGE("efatura-large.xml", DocumentType.UblDocument,
            "e-Fatura çok kalemli (~5MB UBL Invoice, 4797 satır)"),

    /**
     * {@link #EFATURA} ile bayt-bayt aynı UBL Invoice, ancak başında
     * <b>UTF-8 BOM (<code>EF BB BF</code>)</b> var. Üretildi: signer'ın
     * BOM'lu girdileri tolere ettiğini ve verifier roundtrip'in bozulmadığını
     * regression olarak yakalamak için. <b>Standart XAdES matrislerine
     * dahil değildir</b> &mdash; {@link #standardFixtures()} bunu hariç tutar.
     *
     * <p>Beklenen davranış: UBL XAdES enveloped olduğundan BOM XML
     * prolog'undan önce yer alır ve <code>Reference URI=""</code>
     * canonical c14n kapsamı dışındadır; bu yüzden BOM imza akışını
     * kırmamalı ve doğrulayıcı <code>TOTAL_PASSED</code> dönmeli.</p>
     */
    EFATURA_WITH_BOM("efatura-with-bom.xml", DocumentType.UblDocument,
            "e-Fatura UTF-8 BOM ile (encoding regression fixture)"),

    /**
     * {@link #EFATURA}'nın ilk yarısı CRLF, ikinci yarısı LF satır
     * sonu kullanır. XML 1.0 §2.11 parser'ın CRLF'yi LF'e normalize
     * etmesini şart koşar; signer'ın bu normalizasyona güvendiğini ve
     * c14n öncesi/sonrası determinist davrandığını test eder.
     * {@code scripts/generate-xades-fixture-variants.py} ile üretilir.
     */
    EFATURA_MIXED_NEWLINES("efatura-mixed-newlines.xml", DocumentType.UblDocument,
            "e-Fatura mixed CRLF/LF (line-ending normalization regression)"),

    /**
     * {@link #EFATURA}'nın <code>&lt;cbc:Note&gt;</code> alanına
     * <code>&lt;![CDATA[…&amp;…]]&gt;</code> enjekte edilmiş hali.
     * XML c14n CDATA'yı escape-edilmiş text'e çevirir; signer'ın
     * CDATA'lı girdiyi tolere ettiğini ve verifier'ın aynı digest'i
     * matematiksel olarak ürettiğini doğrular. Ampersand özellikle
     * c14n'de <code>&amp;amp;</code> olarak escape edilmelidir.
     */
    XML_WITH_CDATA("xml-with-cdata.xml", DocumentType.UblDocument,
            "UBL with CDATA + ampersand (c14n escape regression)"),

    /**
     * {@link #EFATURA} + üç farklı noktaya XML yorumu (prolog sonrası,
     * <code>cac:InvoiceLine</code> öncesi/sonrası). Exclusive C14N
     * (XAdES default) yorumları çıkarır; doğrulama bozulmamalı. Signer'ın
     * XML parsing pipeline'ında yorumların ID attribute resolution'ı
     * veya placement'ı bozması durumu burada yakalanır.
     */
    XML_WITH_COMMENTS("xml-with-comments.xml", DocumentType.UblDocument,
            "UBL with XML comments (c14n exclusive should strip)"),

    /**
     * {@link #EFATURA} + UBL namespace prefix'leri yeniden adlandırıldı:
     * <code>cbc → tcbc</code>, <code>cac → tcac</code> (URI'ler aynı).
     * Signer prefix'ten bağımsız, NS URI üzerinden çalışmalı &mdash;
     * "<code>lookupElement(\"cbc:…\")</code>" gibi string-bağımlı bir
     * kod yolu olduğunda fixture imzalanamaz veya verifier reddeder.
     * <code>ext</code>, <code>ds</code>, <code>xades</code> prefix'leri
     * dokunulmadan kalır (UBLExtensions placement'ı + XAdES içeriği).
     */
    XML_FOREIGN_NAMESPACE_PREFIX("xml-foreign-namespace-prefix.xml", DocumentType.UblDocument,
            "UBL with tcbc/tcac prefixes (NS-URI agnosticism regression)"),

    /**
     * {@link #EFATURA}'nın <code>&lt;cbc:Note&gt;</code> alanına Unicode
     * 2/3/4-byte karakterler (Latin extended <code>ñoño</code>, CJK
     * <code>中文</code>, emoji 🚀 [<code>U+1F680</code>, 4-byte UTF-8 /
     * surrogate pair]) eklenmiş hali. Surrogate-pair'i yarım yutan veya
     * UTF-8'i yanlış indeksleyen bir serializer regresyonu burada
     * yakalanır; verifier kripto doğrulamasıyla aynı bayt akışının her
     * iki tarafta da görüldüğünü onaylar.
     */
    EFATURA_UNICODE_EMOJI("efatura-unicode-emoji.xml", DocumentType.UblDocument,
            "e-Fatura Unicode 4-byte (emoji + CJK + diakritik)");

    private static final String FIXTURE_DIR = "resources/test-fixtures/xades";

    private final String fileName;
    private final DocumentType documentType;
    private final String displayName;

    XadesDocumentFixture(String fileName, DocumentType documentType, String displayName) {
        this.fileName = fileName;
        this.documentType = documentType;
        this.displayName = displayName;
    }

    public String getFileName() {
        return fileName;
    }

    public DocumentType getDocumentType() {
        return documentType;
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
                    "XAdES fixture bulunamadı: " + file.getAbsolutePath()
                            + " (resources/test-fixtures/xades/ klasörünü kontrol edin)");
        }
        try {
            return Files.readAllBytes(file.toPath());
        } catch (IOException e) {
            throw new IllegalStateException(
                    "XAdES fixture okunamadı: " + file.getAbsolutePath(), e);
        }
    }

    @Override
    public String toString() {
        return name() + " (" + displayName + ")";
    }

    /**
     * Standart (küçük, &lt;100 KB) XAdES fixture'ları &mdash; SoftHSM ve
     * verifier-api matrisleri varsayılan olarak bunları kullanır. Çok büyük
     * dokümanlar (örn. {@link #EFATURA_LARGE}) ayrı suite'lerde koşturulur ki
     * mevcut roundtrip'lerin determinist süresi bozulmasın.
     */
    public static XadesDocumentFixture[] standardFixtures() {
        return new XadesDocumentFixture[] {
                EFATURA, EIRSALIYE, EMUSTAHSIL, EARSIV_RAPORU, HRXML
        };
    }
}
