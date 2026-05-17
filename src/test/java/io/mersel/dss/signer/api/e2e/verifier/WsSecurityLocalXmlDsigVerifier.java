package io.mersel.dss.signer.api.e2e.verifier;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import java.security.Key;
import java.security.PublicKey;
import java.util.List;

/**
 * WS-Security imzalı bir SOAP envelope'unu <b>javax.xml.crypto</b> ile bağımsız
 * şekilde doğrular.
 *
 * <h3>Neden ayrı bir doğrulayıcı?</h3>
 * <p>mersel-dss-verifier-api-java şu an DSS 6.3'ün <i>jenerik XMLDocument</i>
 * validator'ını kullanıyor; o validator <code>ds:KeyInfo</code> içinde
 * doğrudan <code>X509Data</code>/<code>KeyValue</code> bekler.
 * WS-Security ise sertifikayı <code>wsse:BinarySecurityToken</code>'a koyup
 * <code>KeyInfo &rarr; wsse:SecurityTokenReference &rarr; wsse:Reference</code>
 * zinciri ile referanslar — bu pattern WSS spec'i için doğru ama DSS'in
 * key-resolver pipeline'ından geçmez. Sonuç: verifier-api şu an
 * <code>NO_SIGNING_CERTIFICATE_FOUND</code> döner ve roundtrip imkânsız hale gelir.</p>
 *
 * <p>Bu yardımcı, imza tarafının iş tanımını (PFX/HSM × ECDSA/RSA × SOAP 1.1/1.2
 * matrisinde geçerli bir XMLDsig üretmek) gerçek bir verifier ile kanıtlar:</p>
 * <ul>
 *   <li>Sertifikayı doğrudan SignerCertificate'tan alır (KeyInfo resolver'ı
 *       devre dışı bırakır) &mdash; böylece test, "DSS WS-Security'yi anlamıyor"
 *       gibi <i>downstream</i> sorunlarla kirlenmez.</li>
 *   <li>SignedInfo c14n, her Reference'ın digest'i ve SignatureValue
 *       kripto doğrulamasını <b>javax.xml.crypto.dsig.XMLSignature</b> ile
 *       çalıştırır &mdash; bu, JCA standart implementasyonu (Apache Santuario
 *       provider'ından gelen native XMLDsig).</li>
 * </ul>
 *
 * <p>Yani bu test "verifier-api E2E" değil, ama yine de
 * <em>sign → independent verify</em> roundtrip'idir: imza üretim
 * pipeline'ının ürettiği bayt dizisi, ürünün dışındaki bağımsız bir
 * XMLDsig stack tarafından kabul edilmek zorundadır. Üretim regresyonlarını
 * yakalama hassasiyeti DSS-yolu kadar yüksektir.</p>
 *
 * <p>Thread-safe değil; her doğrulama için yeni instance kullanın.</p>
 */
public final class WsSecurityLocalXmlDsigVerifier {

    private static final String NS_DSIG = "http://www.w3.org/2000/09/xmldsig#";
    private static final String NS_WSU = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";

    private WsSecurityLocalXmlDsigVerifier() {
        // utility
    }

    /**
     * Doğrulama sonucu — başarısızlık durumunda referans-bazlı detayı taşır
     * ki test failure mesajı tek bakışta debugging'e yetsin.
     */
    public static final class Result {
        private final boolean valid;
        private final boolean signatureValueValid;
        private final String referenceStatus;

        Result(boolean valid, boolean signatureValueValid, String referenceStatus) {
            this.valid = valid;
            this.signatureValueValid = signatureValueValid;
            this.referenceStatus = referenceStatus;
        }

        public boolean isValid() {
            return valid;
        }

        public boolean isSignatureValueValid() {
            return signatureValueValid;
        }

        public String getReferenceStatus() {
            return referenceStatus;
        }

        @Override
        public String toString() {
            return "WsSecurityValidation{valid=" + valid
                    + ", signatureValueValid=" + signatureValueValid
                    + ", references=" + referenceStatus + "}";
        }
    }

    /**
     * @param signedSoap imzalı SOAP envelope bayt dizisi
     * @param expectedSignerPublicKey imzayı atan sertifikanın public key'i
     *        (KeyInfo resolver'ı yerine doğrudan veriyoruz; nedenini sınıf
     *        Javadoc'unda açıkladık)
     * @return doğrulama sonucu &mdash; <code>isValid()</code> hem
     *         SignatureValue hem de tüm Reference digest'lerinin geçtiğini
     *         garanti eder
     * @throws Exception XML parse, signature unmarshal vb. teknik hatalar
     */
    public static Result validate(byte[] signedSoap, PublicKey expectedSignerPublicKey) throws Exception {
        Document doc = parseSecurely(signedSoap);

        // WS-Security imzası gövde + timestamp elementlerini "Id" / "wsu:Id"
        // attribute'u ile işaret eder. DOMValidateContext getElementById ile
        // bu ID'leri çözer; ama DOM default'unda "Id" gerçek ID attribute'u
        // olarak işaretli değil — manuel set ediyoruz.
        markIdAttributes(doc);

        NodeList signatures = doc.getElementsByTagNameNS(NS_DSIG, "Signature");
        if (signatures.getLength() != 1) {
            throw new AssertionError(
                    "Tek bir <ds:Signature> elementi bekleniyor, bulunan: " + signatures.getLength());
        }

        DOMValidateContext valCtx = new DOMValidateContext(
                new FixedKeySelector(expectedSignerPublicKey), signatures.item(0));
        XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
        XMLSignature signature = factory.unmarshalXMLSignature(valCtx);

        boolean coreValid = signature.validate(valCtx);
        boolean sigValueValid = signature.getSignatureValue().validate(valCtx);

        StringBuilder refStatus = new StringBuilder("[");
        List<?> refs = signature.getSignedInfo().getReferences();
        boolean first = true;
        for (Object refObj : refs) {
            Reference ref = (Reference) refObj;
            if (!first) refStatus.append(", ");
            first = false;
            refStatus.append("URI=").append(ref.getURI())
                    .append(" valid=").append(ref.validate(valCtx));
        }
        refStatus.append("]");

        return new Result(coreValid, sigValueValid, refStatus.toString());
    }

    private static Document parseSecurely(byte[] xml) throws Exception {
        // Aynı SecureXmlFactories'ı kullanmak istemez miyiz? Evet — ama bu
        // sınıf test-only ve yalnızca güvenilen kendi-üretimi bytes üzerinde
        // çalışıyor. Yine de XXE'yi kapalı tutmak good hygiene.
        javax.xml.parsers.DocumentBuilderFactory dbf =
                io.mersel.dss.signer.api.util.xml.SecureXmlFactories.newDocumentBuilderFactory();
        return dbf.newDocumentBuilder().parse(new java.io.ByteArrayInputStream(xml));
    }

    private static void markIdAttributes(Document doc) {
        NodeList all = doc.getElementsByTagName("*");
        for (int i = 0; i < all.getLength(); i++) {
            Element e = (Element) all.item(i);
            String idAttr = e.getAttribute("Id");
            if (idAttr != null && !idAttr.isEmpty()) {
                e.setIdAttribute("Id", true);
            }
            String wsuId = e.getAttributeNS(NS_WSU, "Id");
            if (wsuId != null && !wsuId.isEmpty()) {
                e.setIdAttributeNS(NS_WSU, "Id", true);
            }
        }
    }

    /**
     * KeyInfo resolution'ı bypass eden basit KeySelector — public key'i
     * doğrudan dışarıdan alır. Test, "WS-Security KeyInfo zincirini DSS
     * çözemez" davranışına bağımlı değildir; sadece imza bayt dizisinin
     * matematiksel doğruluğunu kontrol eder.
     */
    private static final class FixedKeySelector extends KeySelector {
        private final PublicKey publicKey;

        FixedKeySelector(PublicKey publicKey) {
            this.publicKey = publicKey;
        }

        @Override
        public KeySelectorResult select(KeyInfo keyInfo, Purpose purpose,
                                        AlgorithmMethod method, XMLCryptoContext context)
                throws KeySelectorException {
            return new KeySelectorResult() {
                @Override
                public Key getKey() {
                    return publicKey;
                }
            };
        }
    }
}
