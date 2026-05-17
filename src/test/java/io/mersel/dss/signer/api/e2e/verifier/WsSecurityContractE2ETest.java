package io.mersel.dss.signer.api.e2e.verifier;

import io.mersel.dss.signer.api.models.SignResponse;
import io.mersel.dss.signer.api.models.SigningMaterial;
import io.mersel.dss.signer.api.services.crypto.DigestAlgorithmResolverService;
import io.mersel.dss.signer.api.services.signature.wssecurity.WsSecuritySignatureService;
import io.mersel.dss.signer.api.testsupport.SignedArtifactExporter;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Severity;
import io.qameta.allure.SeverityLevel;
import io.mersel.dss.signer.api.util.xml.SecureXmlFactories;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIfSystemProperty;
import org.junit.jupiter.api.extension.ExtendWith;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Semaphore;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * WS-Security signing service'in <b>XML structural davranış
 * kontratlarını</b> doğrulayan E2E test seti.
 *
 * <h3>Neden ayrı sınıf?</h3>
 * <p>{@link WsSecuritySignAndLocalVerifyE2ETest} 5 PFX × 2 backend × 9
 * fixture = 90 senaryoda <em>sadece</em> "sign → independent-verify
 * roundtrip + ECDSA r||s format" invariant'larını test eder. Bunlar
 * key-tipinden bağımsız structural kontrat'lar (örn. "wsu:Id silindi"
 * mi); PFX/backend matrislemesi değer eklemez ve CI süresini gereksiz
 * uzatır. Burada her contract için <b>tek bir RSA PFX × JCA backend</b>
 * yeterli — kontrat <em>XML davranışı</em>dır.</p>
 *
 * <h3>Kapsanan kontratlar (her biri 1 test method)</h3>
 * <ol>
 *   <li><b>wsu:Id override (security-critical)</b> — Body'de client-provided
 *       {@code wsu:Id} varsa signer SİLER ve kendi
 *       {@code Id="SignedSoapBodyContent"} attribute'unu set eder.
 *       Aksi halde shadow-reference saldırılarına alan kalır.</li>
 *   <li><b>WS-Addressing preservation</b> — Header'daki
 *       {@code wsa:MessageID}, {@code wsa:To}, {@code wsa:Action},
 *       {@code wsa:ReplyTo} child element'lerine signer
 *       <em>dokunmamalıdır</em>; routing davranışı bozulmamalı.</li>
 *   <li><b>Security append-not-overwrite</b> — Header'da zaten
 *       {@code <wsse:Security>} varsa signer onu reuse eder ve mevcut
 *       child element'leri (örn. {@code UsernameToken}) silmeden
 *       BST/Timestamp/Signature ekler.</li>
 * </ol>
 *
 * <h3>Tag stratejisi</h3>
 * <p>{@code "verifier-e2e"} — aynı job'da koşar, Docker bağımlılığı yok.</p>
 */
@Tag("verifier-e2e")
@DisabledIfSystemProperty(named = "skip.verifier.e2e", matches = "true")
@ExtendWith(SignedArtifactExporter.class)
@DisplayName("WS-Security structural davranış kontratları (XML-level)")
@Epic("Signature Roundtrip")
@Feature("WS-Security Contract")
@Severity(SeverityLevel.CRITICAL)
class WsSecurityContractE2ETest {

    private static WsSecuritySignatureService wsService;
    private static SigningMaterial defaultMaterial;

    /**
     * Tüm contract test'ler için sabit minimum stack: ilk RSA PFX + JCA backend.
     * Kontrat XML davranışı olduğu için PFX/backend çeşitliliği değer eklemez.
     */
    @BeforeAll
    static void initSigningStack() {
        wsService = new WsSecuritySignatureService(
                new Semaphore(2),
                new DigestAlgorithmResolverService());
        // Default: ilk PfxTestKey (deterministic) + PFX/JCA backend (kontrat
        // HSM yolu için de aynıdır, JCA daha hızlı koşar).
        defaultMaterial = E2eSigningBackend.PFX_JCA.load(PfxTestKey.positiveValues()[0]);
    }

    // ─────────────────────────────────────────────────────────────────
    // Kontrat 1: Body wsu:Id override (security-critical)
    // ─────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("Body'deki client-provided wsu:Id silinir, signer kendi Id'sini set eder")
    void wsuIdOverrideContract() throws Exception {
        SoapEnvelopeFixture fixture = SoapEnvelopeFixture.SOAP_WITH_EXISTING_WSU_ID;
        Document soapDoc = parseXmlSecurely(fixture.readBytes());

        // Pre-condition: fixture gerçekten wsu:Id taşımalı (regresyon koruması).
        Element preBody = (Element) soapDoc
                .getElementsByTagNameNS(soapNs(fixture), "Body").item(0);
        assertNotNull(preBody, "fixture'da Body yok");
        String preWsuId = preBody.getAttributeNS(WSU_NS, "Id");
        assertEquals("ClientProvidedBodyId-do-not-trust", preWsuId,
                "fixture wsu:Id'sini kaybetmiş (script bozuk?)");

        SignResponse signed = sign(soapDoc, fixture);

        // Post-condition: imzalı Body'de
        //   - Id="SignedSoapBodyContent" var (signer set etti)
        //   - wsu:Id YOK (signer sildi)
        Document signedDoc = parseXmlSecurely(signed.getSignedDocument());
        Element postBody = (Element) signedDoc
                .getElementsByTagNameNS(soapNs(fixture), "Body").item(0);
        assertNotNull(postBody, "imzalı dokümanda Body yok");

        String postId = postBody.getAttribute("Id");
        assertEquals("SignedSoapBodyContent", postId,
                "signer kendi Id'sini Body'ye yazmadı");

        String postWsuId = postBody.getAttributeNS(WSU_NS, "Id");
        assertTrue(postWsuId == null || postWsuId.isEmpty(),
                "Client-provided wsu:Id SİLİNMEDİ — shadow-reference saldırı vektörü "
                        + "açık kalıyor (post-value=\"" + postWsuId + "\")");
    }

    // ─────────────────────────────────────────────────────────────────
    // Kontrat 2: WS-Addressing header'ları korunur
    // ─────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("WS-Addressing header'ları (MessageID, To, Action, ReplyTo) sign sonrası korunur")
    void wsAddressingPreservationContract() throws Exception {
        SoapEnvelopeFixture fixture = SoapEnvelopeFixture.SOAP_WITH_WSA;
        Document soapDoc = parseXmlSecurely(fixture.readBytes());

        // Beklenen WS-Addressing değerleri (fixture'dan):
        String expectedMessageId = "urn:uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        String expectedTo = "https://efaturatest.gib.gov.tr/EarsivPortalIntegration";
        String expectedAction = "http://test.example.com/SendDocument";
        String expectedReplyToAddress = "http://www.w3.org/2005/08/addressing/anonymous";

        SignResponse signed = sign(soapDoc, fixture);

        Document signedDoc = parseXmlSecurely(signed.getSignedDocument());
        assertEquals(expectedMessageId,
                singleTextContent(signedDoc, WSA_NS, "MessageID"),
                "wsa:MessageID sign sonrası kaybolmuş/değişmiş");
        assertEquals(expectedTo,
                singleTextContent(signedDoc, WSA_NS, "To"),
                "wsa:To sign sonrası kaybolmuş/değişmiş");
        assertEquals(expectedAction,
                singleTextContent(signedDoc, WSA_NS, "Action"),
                "wsa:Action sign sonrası kaybolmuş/değişmiş");
        assertEquals(expectedReplyToAddress,
                singleTextContent(signedDoc, WSA_NS, "Address"),
                "wsa:ReplyTo/wsa:Address sign sonrası kaybolmuş/değişmiş");

        // Sanity: imza da geçerli olmalı (kontratın "imza bozulmaz" tarafı).
        WsSecurityLocalXmlDsigVerifier.Result result =
                WsSecurityLocalXmlDsigVerifier.validate(
                        signed.getSignedDocument(),
                        defaultMaterial.getSigningCertificate().getPublicKey());
        assertTrue(result.isValid(),
                "WS-Addressing korunsa da imza doğrulanamadı: " + result);
    }

    // ─────────────────────────────────────────────────────────────────
    // Kontrat 3: Mevcut <wsse:Security> reuse + child append (overwrite değil)
    // ─────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("Mevcut <wsse:Security>/UsernameToken silinmez, signer child'larını append eder")
    void existingSecurityHeaderAppendContract() throws Exception {
        SoapEnvelopeFixture fixture = SoapEnvelopeFixture.SOAP_WITH_EXISTING_SECURITY_HEADER;
        Document soapDoc = parseXmlSecurely(fixture.readBytes());

        SignResponse signed = sign(soapDoc, fixture);
        Document signedDoc = parseXmlSecurely(signed.getSignedDocument());

        // Tek bir <wsse:Security> olmalı (signer yeni bir tane yaratmamalı).
        NodeList allSec = signedDoc.getElementsByTagNameNS(WSSE_NS, "Security");
        assertEquals(1, allSec.getLength(),
                "Security header sayısı != 1; signer mevcut Security'yi reuse "
                        + "etmek yerine yeni bir tane oluşturmuş.");
        Element security = (Element) allSec.item(0);

        // Mevcut UsernameToken hâlâ var olmalı + içerik korunmuş olmalı.
        NodeList userTokens = security.getElementsByTagNameNS(WSSE_NS, "UsernameToken");
        assertEquals(1, userTokens.getLength(),
                "Mevcut UsernameToken sign sonrası kaybolmuş — append yerine override.");
        Element userToken = (Element) userTokens.item(0);

        String username = singleChildTextContent(userToken, WSSE_NS, "Username");
        assertEquals("preexisting-test-user", username,
                "UsernameToken/Username değiştirilmiş; signer body'sine dokunmamalı.");

        // Signer-eklenen 3 child'in (BST, Timestamp, Signature) hepsi olmalı.
        assertEquals(1,
                security.getElementsByTagNameNS(WSSE_NS, "BinarySecurityToken").getLength(),
                "BinarySecurityToken sign sonrası yok");
        assertEquals(1,
                security.getElementsByTagNameNS(WSU_NS, "Timestamp").getLength(),
                "Timestamp sign sonrası yok");
        assertEquals(1,
                security.getElementsByTagNameNS(DSIG_NS, "Signature").getLength(),
                "ds:Signature sign sonrası yok");

        // Toplam direct-child Element sayısı = 4 (UsernameToken + signer'ın 3'ü).
        List<Element> directChildren = directChildElements(security);
        assertEquals(4, directChildren.size(),
                "Security direct-child sayısı beklenenden farklı (4 olmalı, "
                        + directChildren.size() + " bulundu) — beklenmedik append/silme.");

        // İmza yine de geçerli olmalı (kontratın "ekle ama bozma" tarafı).
        WsSecurityLocalXmlDsigVerifier.Result result =
                WsSecurityLocalXmlDsigVerifier.validate(
                        signed.getSignedDocument(),
                        defaultMaterial.getSigningCertificate().getPublicKey());
        assertTrue(result.isValid(),
                "Append davranışı doğruysa da imza doğrulanamadı: " + result);

        // Negatif sanity: client'ın eski şifresi de korunmuş olmalı (signer
        // password'a dokunmamalı — opake bir element).
        String password = singleChildTextContent(userToken, WSSE_NS, "Password");
        assertEquals("preexisting-secret", password,
                "Password değiştirilmiş; signer'ın UsernameToken içeriğine "
                        + "dokunma yetkisi yok.");
        assertFalse(password.contains("Signed"),
                "Password textinde signer artığı var; içerik mutate edilmiş.");
    }

    // ─────────────────────────────────────────────────────────────────
    // Ortak yardımcılar
    // ─────────────────────────────────────────────────────────────────

    private static final String SOAP_1_1_NS = "http://schemas.xmlsoap.org/soap/envelope/";
    private static final String SOAP_1_2_NS = "http://www.w3.org/2003/05/soap-envelope";
    private static final String WSU_NS =
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
    private static final String WSSE_NS =
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    private static final String WSA_NS = "http://www.w3.org/2005/08/addressing";
    private static final String DSIG_NS = "http://www.w3.org/2000/09/xmldsig#";

    private static String soapNs(SoapEnvelopeFixture fixture) {
        return fixture.isUseSoap12() ? SOAP_1_2_NS : SOAP_1_1_NS;
    }

    private SignResponse sign(Document soapDoc, SoapEnvelopeFixture fixture) {
        SignResponse response = wsService.signSoapEnvelope(
                soapDoc,
                fixture.isUseSoap12(),
                defaultMaterial,
                /*alias*/ "test",
                /*pin*/   new char[0]);
        // Her contract test'in imzalı çıktısını disk'e export — kontrat
        // davranışını (wsu:Id override, WSA preservation, Security append)
        // SoapUI/WSS4J ile manuel doğrulamak için.
        SignedArtifactExporter.export(
                SignedArtifactExporter.Format.WSSECURITY,
                response.getSignedDocument(),
                fixture.name().toLowerCase());
        return response;
    }

    private static Document parseXmlSecurely(byte[] xml) throws Exception {
        DocumentBuilderFactory dbf = SecureXmlFactories.newDocumentBuilderFactory();
        DocumentBuilder db = dbf.newDocumentBuilder();
        return db.parse(new ByteArrayInputStream(xml));
    }

    /** Belge genelinde tek bir element bekler ve text content'ini döndürür. */
    private static String singleTextContent(Document doc, String ns, String localName) {
        NodeList list = doc.getElementsByTagNameNS(ns, localName);
        assertEquals(1, list.getLength(),
                "Beklenen 1 element bulunamadı: {" + ns + "}" + localName
                        + " (gerçek=" + list.getLength() + ")");
        return list.item(0).getTextContent();
    }

    /** Belirli bir parent altında tek direct/descendant child bekler. */
    private static String singleChildTextContent(Element parent, String ns, String localName) {
        NodeList list = parent.getElementsByTagNameNS(ns, localName);
        assertEquals(1, list.getLength(),
                "Beklenen 1 child bulunamadı: {" + ns + "}" + localName
                        + " parent=" + parent.getLocalName());
        return list.item(0).getTextContent();
    }

    /** Verilen element'in sadece direct Element child'larını döndürür (text node'lar hariç). */
    private static List<Element> directChildElements(Element parent) {
        List<Element> result = new ArrayList<>();
        NodeList children = parent.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node n = children.item(i);
            if (n.getNodeType() == Node.ELEMENT_NODE) {
                result.add((Element) n);
            }
        }
        return result;
    }
}
