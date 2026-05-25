package io.mersel.dss.signer.api.services.signature.xades;

import eu.europa.esig.dss.alert.SilentOnStatusAlert;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.signature.XAdESService;
import eu.europa.esig.dss.xades.signature.XAdESSigningTimeZoneHolder;
import io.mersel.dss.signer.api.e2e.verifier.E2eFixtures;
import io.mersel.dss.signer.api.e2e.verifier.E2eSigningMaterialFactory;
import io.mersel.dss.signer.api.e2e.verifier.PfxTestKey;
import io.mersel.dss.signer.api.models.SignResponse;
import io.mersel.dss.signer.api.models.SigningMaterial;
import io.mersel.dss.signer.api.models.enums.DocumentType;
import io.mersel.dss.signer.api.services.crypto.CryptoSignerService;
import io.mersel.dss.signer.api.services.crypto.DigestAlgorithmResolverService;
import io.mersel.dss.signer.api.services.crypto.SignatureAlgorithmResolverService;
import io.mersel.dss.signer.api.services.timestamp.TimestampConfigurationService;
import io.mersel.dss.signer.api.services.util.CompressionService;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Severity;
import io.qameta.allure.SeverityLevel;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.UUID;
import java.util.concurrent.Semaphore;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * XAdES {@code <SigningTime>} elemanının XML çıktısında configure edilmiş
 * zaman dilimini kullandığını uçtan uca doğrular.
 *
 * <h3>Neden bu testi yazıyoruz?</h3>
 * <p>Issue #7'de raporlandığı üzere DSS upstream her zaman UTC ({@code Z})
 * basıyordu; bu da TÜBİTAK MA3 referans çıktısı ile uyumsuzdu. Override ile
 * timezone parametrik hâle getirildi. Bu test, override yanlışlıkla silinir
 * veya {@link XAdESSigningTimeZoneHolder} bypass edilirse anında patlar —
 * regression koruması.</p>
 *
 * <p>Verifier container'ı GEREKTİRMEZ — sadece imzalama akışını çalıştırır
 * ve XML'i kendi parse eder. Default Surefire suite'inde koşar.</p>
 */
@Epic("XAdES Conformance")
@Feature("SigningTime Timezone (issue #7)")
@Severity(SeverityLevel.CRITICAL)
class XAdESSigningTimeFormatTest {

    private static final Pattern PLUS_THREE_PATTERN = Pattern.compile(
            "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\+03:00$");
    private static final Pattern UTC_Z_PATTERN = Pattern.compile(
            "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$");
    private static final Pattern NEGATIVE_OFFSET_PATTERN = Pattern.compile(
            "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}-05:00$");

    private XAdESSignatureService service;

    /**
     * Holder global statik olduğu için her test öncesi/sonrası TÜBİTAK
     * default'una geri çekilir. Aksi halde paralel/sıralı test akışlarında
     * önceki testin zone'u sızabilir.
     */
    @BeforeEach
    @AfterEach
    void resetHolderToDefault() {
        XAdESSigningTimeZoneHolder.setZone(XAdESSigningTimeZoneHolder.DEFAULT_ZONE);
    }

    private XAdESSignatureService buildService() {
        CommonCertificateVerifier verifier = new CommonCertificateVerifier();
        verifier.setAlertOnMissingRevocationData(new SilentOnStatusAlert());
        verifier.setAlertOnNoRevocationAfterBestSignatureTime(new SilentOnStatusAlert());
        verifier.setAlertOnRevokedCertificate(new SilentOnStatusAlert());
        verifier.setAlertOnInvalidTimestamp(new SilentOnStatusAlert());
        verifier.setAlertOnExpiredCertificate(new SilentOnStatusAlert());
        verifier.setAlertOnNotYetValidCertificate(new SilentOnStatusAlert());

        XAdESService dssService = new XAdESService(verifier);
        DigestAlgorithmResolverService digestResolver = new DigestAlgorithmResolverService();
        SignatureAlgorithmResolverService sigAlgResolver = new SignatureAlgorithmResolverService();
        CryptoSignerService crypto = new CryptoSignerService(sigAlgResolver);
        XAdESParametersBuilderService paramsBuilder =
                new XAdESParametersBuilderService(digestResolver);
        XmlProcessingService xmlProcessor = new XmlProcessingService();
        XAdESDocumentPlacementService placement = new XAdESDocumentPlacementService();
        TimestampConfigurationService tsConfig = new TimestampConfigurationService(
                "", "", "", false);
        XAdESLevelUpgradeService upgrade = new XAdESLevelUpgradeService(verifier, tsConfig);
        CompressionService compression = new CompressionService();
        return new XAdESSignatureService(
                dssService, paramsBuilder, xmlProcessor, placement, upgrade,
                crypto, verifier, compression, new Semaphore(2));
    }

    private XAdESSignatureService serviceOrInit() {
        if (service == null) {
            service = buildService();
        }
        return service;
    }

    @Test
    @DisplayName("Default zone (TÜBİTAK +03:00) ile imzada SigningTime '+03:00' son eki taşır")
    void defaultZoneEmitsPlusThreeOffset() throws Exception {
        signAndAssertSigningTime(
                XAdESSigningTimeZoneHolder.DEFAULT_ZONE,
                PLUS_THREE_PATTERN,
                "+03:00");
    }

    @Test
    @DisplayName("UTC zone'a çevrilirse SigningTime 'Z' son eki taşır (ETSI saf yorumu)")
    void utcZoneEmitsZSuffix() throws Exception {
        signAndAssertSigningTime(ZoneOffset.UTC, UTC_Z_PATTERN, "Z");
    }

    @Test
    @DisplayName("Negatif offset (-05:00) seçilirse SigningTime aynı son eki taşır")
    void arbitraryOffsetIsRespected() throws Exception {
        signAndAssertSigningTime(ZoneOffset.of("-05:00"), NEGATIVE_OFFSET_PATTERN, "-05:00");
    }

    private void signAndAssertSigningTime(ZoneId zone, Pattern expectedPattern, String expectedSuffix)
            throws Exception {
        XAdESSigningTimeZoneHolder.setZone(zone);

        SigningMaterial material = E2eSigningMaterialFactory.load(PfxTestKey.KURUM01_RSA2048);
        SignResponse signed = serviceOrInit().signXml(
                new ByteArrayInputStream(E2eFixtures.efaturaXml()),
                DocumentType.UblDocument,
                "id-" + UUID.randomUUID().toString().replace("-", ""),
                /*zipped*/ false,
                material,false);

        assertNotNull(signed.getSignedDocument(), "signedDocument null olmamalı");

        String signingTime = extractSigningTime(signed.getSignedDocument());
        assertNotNull(signingTime, "SigningTime elementi XAdES çıktısında bulunamadı");
        assertTrue(expectedPattern.matcher(signingTime).matches(),
                () -> "SigningTime beklenen formatı taşımıyor. Beklenen son ek: '"
                        + expectedSuffix + "', gözlenen: '" + signingTime + "'. "
                        + "Bu hata DSS override (XAdESSignatureBuilder#incorporateSigningTime) "
                        + "veya XAdESSigningTimeZoneHolder davranışında bir regression olduğunu gösterir.");
    }

    private static String extractSigningTime(byte[] signedXml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document dom = db.parse(new InputSource(new StringReader(new String(signedXml))));
        // XAdES 1.3.2 default namespace; xades132 paketinde kullanılan.
        NodeList nodes = dom.getElementsByTagNameNS(
                "http://uri.etsi.org/01903/v1.3.2#", "SigningTime");
        if (nodes.getLength() == 0) {
            // XAdES 1.4.1 namespace fallback (LT/A seviyeleri için)
            nodes = dom.getElementsByTagNameNS(
                    "http://uri.etsi.org/01903/v1.4.1#", "SigningTime");
        }
        if (nodes.getLength() == 0) {
            return null;
        }
        return nodes.item(0).getTextContent().trim();
    }
}
