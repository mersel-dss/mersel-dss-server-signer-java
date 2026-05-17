package io.mersel.dss.signer.api.e2e.verifier;

import io.mersel.dss.signer.api.models.SignResponse;
import io.mersel.dss.signer.api.models.SigningMaterial;
import io.mersel.dss.signer.api.services.crypto.DigestAlgorithmResolverService;
import io.mersel.dss.signer.api.services.keystore.iaik.Pkcs11EcdsaSignatureEncoder;
import io.mersel.dss.signer.api.services.signature.wssecurity.WsSecuritySignatureService;
import io.mersel.dss.signer.api.testsupport.SignedArtifactExporter;
import io.mersel.dss.signer.api.util.xml.SecureXmlFactories;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Severity;
import io.qameta.allure.SeverityLevel;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.condition.DisabledIfSystemProperty;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.util.concurrent.Semaphore;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * WS-Security için uçtan-uca sign → independent-verify roundtrip testi.
 *
 * <h3>Senaryo matrisi</h3>
 * <p>5 test PFX × 2 backend (PFX/JCA, PFX-backed PKCS#11) × <b>tüm 9
 * {@link SoapEnvelopeFixture} değeri</b> = <b>90 senaryo</b>. Fixture
 * yelpazesi: 2 baseline minimal envelope (SOAP 1.1, 1.2), 4
 * production-parity envelope (GİB e-Fatura, ~50KB large, multi-body,
 * MTOM/XOP), 3 contract envelope (WS-Addressing, mevcut wsu:Id,
 * mevcut Security). Contract-specific davranış assertion'ları
 * {@code WsSecurityContractE2ETest}'tedir; burada her envelope sadece
 * "sign-verify roundtrip + ECDSA r||s format invariantı" kontrolünden
 * geçer (PFX/backend çeşitliliği XML structural davranıştan bağımsız).</p>
 *
 * <h3>Neden verifier-api yerine lokal XMLDsig?</h3>
 * <p>mersel-dss-verifier-api-java DSS 6.3'ün jenerik XMLDocumentValidator'ını
 * kullanır; bu validator <code>ds:KeyInfo</code>'da doğrudan
 * <code>X509Data</code> / <code>KeyValue</code> bekler. WS-Security ise
 * sertifikayı <code>wsse:BinarySecurityToken</code>'da tutup
 * <code>KeyInfo → SecurityTokenReference → Reference URI="#…"</code>
 * zinciri ile gösterir — WSS spec'i için doğru ama DSS'in key-resolver
 * pipeline'ından geçmez ve <code>NO_SIGNING_CERTIFICATE_FOUND</code>
 * (<code>INDETERMINATE</code>) döner. Bu, <b>downstream verifier'ın
 * sınırlaması</b>dır, signer'ın değil. Detay
 * {@link WsSecurityLocalXmlDsigVerifier}'da.</p>
 *
 * <p>Roundtrip yine de gerçek bir doğrulayıcıdan geçer:
 * <code>javax.xml.crypto.dsig.XMLSignature</code> ile SignedInfo c14n,
 * her Reference digest'i ve SignatureValue kripto kontrolü çalıştırılır.
 * Production-regression hassasiyeti DSS-yolundaki diğer E2E testleriyle
 * eşdeğer.</p>
 *
 * <h3>Ekstra invariant: ECDSA SignatureValue raw r||s formatında olmalı</h3>
 * <p>Daha önce {@code XAdESSignatureService} için aynı problem tespit edildi:
 * DSS bazı yollarda DER bytes'ı plain'e dönüştürmeden XML'e yazıyor ve
 * verifier <code>SIG_CRYPTO_FAILURE</code> üretiyor. WS-Security'de bu
 * dönüşümü {@code WsSecuritySignatureService} explicit yapıyor. Her
 * iterasyonda XML içindeki SignatureValue'nun DER görünümünde
 * <b>olmadığını</b> ve uzunluğun curve field size'a uygun olduğunu (P-256
 * → 64, P-384 → 96 byte) da doğruluyoruz; regresyon olursa burada yakalanır,
 * lokal validator zaten patlardı ama failure mesajı çok daha anlaşılır.</p>
 *
 * <h3>Tag stratejisi</h3>
 * <p>Etiket {@code "verifier-e2e"}: CI'ın aynı roundtrip job'unda
 * (integration-tests.yml → verifier-e2e) koşar; Docker bağımlılığı yoktur
 * yani daemon erişilemese bile çalışır (saniyeler sürer). Tag tutarlılığı,
 * "imzala-doğrula" testlerinin tek komutla tetiklenebilmesi için tercih
 * edildi.</p>
 */
@Tag("verifier-e2e")
@DisabledIfSystemProperty(named = "skip.verifier.e2e", matches = "true")
@ExtendWith(SignedArtifactExporter.class)
@Epic("Signature Roundtrip")
@Feature("WS-Security SOAP")
@Severity(SeverityLevel.CRITICAL)
class WsSecuritySignAndLocalVerifyE2ETest {

    private static WsSecuritySignatureService wsService;

    @BeforeAll
    static void initSigningStack() {
        wsService = new WsSecuritySignatureService(
                new Semaphore(2),
                new DigestAlgorithmResolverService());
    }

    static Stream<Arguments> matrix() {
        Stream.Builder<Arguments> b = Stream.builder();
        // Pozitif matriks: yalnızca Status.VALID PFX'ler. Lifecycle negatif
        // sertifikaları CertificateLifecycleNegativeE2ETest ele alır.
        for (PfxTestKey key : PfxTestKey.positiveValues()) {
            for (E2eSigningBackend backend : E2eSigningBackend.values()) {
                for (SoapEnvelopeFixture envelope : SoapEnvelopeFixture.values()) {
                    b.add(Arguments.of(key, backend, envelope));
                }
            }
        }
        return b.build();
    }

    @ParameterizedTest(name = "{index} → {0} / {1} / {2}")
    @MethodSource("matrix")
    @DisplayName("WS-Security roundtrip: imzala → javax.xml.crypto.XMLSignature ile bağımsız doğrula")
    void wsSecurityRoundtripIsValid(PfxTestKey key,
                                    E2eSigningBackend backend,
                                    SoapEnvelopeFixture envelope) throws Exception {
        SigningMaterial material = backend.load(key);
        Document soapDoc = parseXmlSecurely(envelope.readBytes());

        SignResponse signed = wsService.signSoapEnvelope(
                soapDoc,
                envelope.isUseSoap12(),
                material,
                /*alias*/ "test",
                /*pin*/   new char[0]);

        assertNotNull(signed, "signResponse null olmamalı");
        assertNotNull(signed.getSignedDocument(), "imzalı SOAP bytes null olmamalı");
        assertTrue(signed.getSignedDocument().length > 0, "imzalı SOAP bytes boş olmamalı");

        // İmzalı SOAP envelope'unu disk'e export et — SoapUI / WSS4J / xmlsec1
        // ile manuel cross-validation için.
        SignedArtifactExporter.export(
                SignedArtifactExporter.Format.WSSECURITY, signed.getSignedDocument());

        // 1) ECDSA için XMLDsig raw r||s format invariantı.
        if (material.getSigningCertificate().getPublicKey() instanceof ECPublicKey) {
            assertEcdsaSignatureValueIsRaw(signed.getSignedDocument(),
                    (ECPublicKey) material.getSigningCertificate().getPublicKey(),
                    key, backend, envelope);
        }

        // 2) Asıl roundtrip: bağımsız XMLDsig validator imzayı kabul etmeli.
        WsSecurityLocalXmlDsigVerifier.Result result =
                WsSecurityLocalXmlDsigVerifier.validate(
                        signed.getSignedDocument(),
                        material.getSigningCertificate().getPublicKey());

        assertTrue(result.isValid(),
                String.format("WS-Security imzası lokal XMLDsig doğrulamasından geçemedi "
                                + "(%s / %s / %s): %s",
                        key, backend, envelope, result));
    }

    private static void assertEcdsaSignatureValueIsRaw(byte[] signedSoap,
                                                       ECPublicKey ecKey,
                                                       PfxTestKey key,
                                                       E2eSigningBackend backend,
                                                       SoapEnvelopeFixture envelope) throws Exception {
        Document signedDoc = parseXmlSecurely(signedSoap);
        NodeList list = signedDoc.getElementsByTagNameNS(
                "http://www.w3.org/2000/09/xmldsig#", "SignatureValue");
        assertEquals(1, list.getLength(), "Tek <ds:SignatureValue> bekleniyor");
        String b64 = list.item(0).getTextContent().replaceAll("\\s", "");
        byte[] sigBytes = Base64.getDecoder().decode(b64);

        int fieldSize = (ecKey.getParams().getCurve().getField().getFieldSize() + 7) / 8;
        int expectedRawLen = 2 * fieldSize;

        String diag = String.format("(%s / %s / %s)", key, backend, envelope);

        assertFalse(Pkcs11EcdsaSignatureEncoder.looksLikeDer(sigBytes),
                "ECDSA SignatureValue DER görünümünde — derToRaw kaçırılmış " + diag);
        assertEquals(expectedRawLen, sigBytes.length,
                "ECDSA SignatureValue raw r||s uzunluğu yanlış (beklenen=" + expectedRawLen
                        + ", bulunan=" + sigBytes.length + ") " + diag);
    }

    private static Document parseXmlSecurely(byte[] xml) throws Exception {
        DocumentBuilderFactory dbf = SecureXmlFactories.newDocumentBuilderFactory();
        DocumentBuilder db = dbf.newDocumentBuilder();
        return db.parse(new ByteArrayInputStream(xml));
    }
}
