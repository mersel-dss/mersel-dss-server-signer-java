package io.mersel.dss.signer.api.util.xml;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerFactory;

/**
 * XML parser ve transformer factory'leri için XXE-güvenli (hardened) merkezi
 * yardımcı sınıf.
 *
 * <p>Bu sınıf <b>tek meşru kaynaktır</b>: production kodunda
 * {@link DocumentBuilderFactory#newInstance()} veya
 * {@link TransformerFactory#newInstance()} doğrudan ÇAĞRILMAMALIDIR.
 * Bunun yerine bu sınıfın factory metotları kullanılmalıdır.</p>
 *
 * <h2>Kapatılan saldırı vektörleri</h2>
 * <ul>
 *   <li><b>XXE (XML eXternal Entity)</b>: <code>&lt;!DOCTYPE&gt;</code>
 *       bildirimleri reddedilir. Saldırgan
 *       <code>&lt;!ENTITY xxe SYSTEM "file:///etc/passwd"&gt;</code> ile
 *       sunucu dosyalarını okuyamaz.</li>
 *   <li><b>SSRF via XXE</b>: External general/parameter entity'ler kapalı;
 *       saldırgan <code>SYSTEM "http://..."</code> ile iç servislere istek
 *       atamaz (örn. <code>169.254.169.254</code> cloud metadata).</li>
 *   <li><b>Billion Laughs / DoS</b>: Entity expansion kapalı; çok seviyeli
 *       entity referansları ile bellek patlatılamaz.</li>
 *   <li><b>XInclude</b>: <code>xi:include</code> ile dosya inclusion kapalı.</li>
 *   <li><b>XSLT injection</b>: Transformer'da external DTD / stylesheet
 *       erişimi engellendi.</li>
 * </ul>
 *
 * <h2>Etki / Geriye dönük uyumluluk</h2>
 * <ul>
 *   <li>UBL-TR 2.1 (e-Fatura, e-Arşiv, e-İrsaliye) XML belgeleri XSD tabanlıdır,
 *       DOCTYPE içermez → etkilenmez.</li>
 *   <li>SOAP 1.1/1.2 envelope'lar DOCTYPE içermez → etkilenmez.</li>
 *   <li>W3C XML-DSig canonicalization DOCTYPE'lı belgeleri zaten desteklemez
 *       → imzalanan belgelerin DOCTYPE'sız olması beklenir.</li>
 *   <li>KamuSM TSL/XML depo response'ları DOCTYPE içermez → etkilenmez.</li>
 * </ul>
 *
 * @see <a href="https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html">OWASP XXE Prevention Cheat Sheet</a>
 */
public final class SecureXmlFactories {

    private static final String FEATURE_DISALLOW_DOCTYPE =
            "http://apache.org/xml/features/disallow-doctype-decl";
    private static final String FEATURE_EXTERNAL_GENERAL_ENTITIES =
            "http://xml.org/sax/features/external-general-entities";
    private static final String FEATURE_EXTERNAL_PARAMETER_ENTITIES =
            "http://xml.org/sax/features/external-parameter-entities";
    private static final String FEATURE_LOAD_EXTERNAL_DTD =
            "http://apache.org/xml/features/nonvalidating/load-external-dtd";

    private SecureXmlFactories() {
    }

    /**
     * Namespace-aware (varsayılan) XXE-güvenli {@link DocumentBuilderFactory}.
     *
     * @return hardened factory; tekrar kullanılabilir (her builder yeni)
     */
    public static DocumentBuilderFactory newDocumentBuilderFactory() {
        return newDocumentBuilderFactory(true);
    }

    /**
     * Namespace-aware ayarı parametrik XXE-güvenli {@link DocumentBuilderFactory}.
     *
     * @param namespaceAware namespace-aware modu (XAdES/SOAP için {@code true},
     *                       KamuSM legacy XML için {@code false} kullanılır)
     * @return hardened factory
     */
    public static DocumentBuilderFactory newDocumentBuilderFactory(boolean namespaceAware) {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(namespaceAware);

        // En güçlü kalkan: DOCTYPE görürse parse fail eder. XXE'yi kökten keser.
        trySetFeature(factory, FEATURE_DISALLOW_DOCTYPE, true);

        // Genel güvenli işleme: JAXP'nin şüpheli özelliklerini reddet.
        trySetFeature(factory, XMLConstants.FEATURE_SECURE_PROCESSING, true);

        // External entity expansion'ı kapat (DOCTYPE açık olsa bile koruma).
        trySetFeature(factory, FEATURE_EXTERNAL_GENERAL_ENTITIES, false);
        trySetFeature(factory, FEATURE_EXTERNAL_PARAMETER_ENTITIES, false);
        trySetFeature(factory, FEATURE_LOAD_EXTERNAL_DTD, false);

        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);

        return factory;
    }

    /**
     * XSLT injection ve external DTD erişimine kapalı {@link TransformerFactory}.
     *
     * <p>Bu factory yalnızca DOM serileştirme (DOM → byte) için yeterli
     * şekilde sertleştirilmiştir. XSLT stylesheet çalıştırılması gerekiyorsa
     * (şu an gerekmiyor), ayrı bir hardening seti gerekir.</p>
     *
     * @return hardened transformer factory
     */
    public static TransformerFactory newTransformerFactory() {
        TransformerFactory factory = TransformerFactory.newInstance();

        // External DTD / stylesheet erişimini engelle (XSLT injection koruması).
        trySetAttribute(factory, XMLConstants.ACCESS_EXTERNAL_DTD, "");
        trySetAttribute(factory, XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");

        // JAXP secure processing.
        try {
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        } catch (TransformerConfigurationException e) {
            throw new IllegalStateException(
                    "TransformerFactory FEATURE_SECURE_PROCESSING ayarlanamadı; "
                            + "JAXP implementasyonu spec-uyumsuz", e);
        }

        return factory;
    }

    private static void trySetFeature(DocumentBuilderFactory factory,
                                      String feature,
                                      boolean value) {
        try {
            factory.setFeature(feature, value);
        } catch (ParserConfigurationException e) {
            // Spec-uyumlu bir JAXP implementasyonunda bu feature'lar
            // desteklenmek zorundadır. Desteklemiyorsa fail-fast davranış
            // güvenlik açısından doğrudur: XXE'ye açık çalışmaktansa
            // başlatmayı reddet.
            throw new IllegalStateException(
                    "DocumentBuilderFactory hardening başarısız (feature=" + feature
                            + ", value=" + value + "); JAXP implementasyonu güvenli değil",
                    e);
        }
    }

    private static void trySetAttribute(TransformerFactory factory,
                                        String attribute,
                                        Object value) {
        try {
            factory.setAttribute(attribute, value);
        } catch (IllegalArgumentException e) {
            // ACCESS_EXTERNAL_* her JAXP implementasyonunda yoktur (eski JRE'ler).
            // Bu attribute desteklenmiyorsa best-effort: warn yerine sessiz
            // geçiyoruz çünkü FEATURE_SECURE_PROCESSING zaten genel koruma
            // sağlar.
        }
    }
}
