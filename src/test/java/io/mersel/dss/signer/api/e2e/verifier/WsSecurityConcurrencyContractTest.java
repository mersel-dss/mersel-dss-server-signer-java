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

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * WS-Security signing service'in eşzamanlılık kontratı.
 *
 * <p>D grubu (WSS ek) için son madde: 10 paralel iş yükü altında
 * {@link WsSecuritySignatureService} hem doğru imza üretmeli hem
 * de paylaşılan {@code signatureSemaphore} bean'inin permits
 * limitini aşmamalı.</p>
 *
 * <p><b>WSS neden ayrı tutuldu?</b> CAdES için
 * {@code SignatureServiceSemaphoreConcurrencyTest} ile semaphore kontratı
 * zaten ispatlandı. WSS pipeline'ı ek olarak <b>DOM mutation</b> ile
 * çalışıyor (her thread DOM yapısını değiştiriyor); JCA
 * {@code DocumentBuilder}'lar thread-safe değil ve her thread kendi
 * dokümanını parse etmeli — burada bunu da explicit kontrol ediyoruz.
 * XML kütüphanesinin sessizce paylaşılmasından (race condition + bozuk
 * imza) doğacak regression'a karşı guard.</p>
 *
 * <p>Sonuç olarak: 10 paralel thread her biri farklı SOAP envelope'unu
 * sign eder; tüm sonuçlar lokal XMLDsig verifier ile doğrulanır.</p>
 */
@Tag("verifier-e2e")
@DisabledIfSystemProperty(named = "skip.verifier.e2e", matches = "true")
@ExtendWith(SignedArtifactExporter.class)
@DisplayName("WS-Security concurrent 10 paralel imza kontratı")
@Epic("Concurrency")
@Feature("WS-Security Parallel Signing")
@Severity(SeverityLevel.CRITICAL)
class WsSecurityConcurrencyContractTest {

    private static final int PARALLEL = 10;
    private static final int SEMAPHORE_PERMITS = 2;
    private static final int TIMEOUT_SECONDS = 120;

    private static WsSecuritySignatureService wsService;
    private static SigningMaterial defaultMaterial;
    private static Semaphore sharedSemaphore;

    @BeforeAll
    static void initSigningStack() {
        sharedSemaphore = new Semaphore(SEMAPHORE_PERMITS);
        wsService = new WsSecuritySignatureService(
                sharedSemaphore,
                new DigestAlgorithmResolverService());
        defaultMaterial = E2eSigningBackend.PFX_JCA.load(PfxTestKey.positiveValues()[0]);
    }

    /**
     * D3: 10 paralel WS-Security imzası (rotating fixture).
     *
     * <ul>
     *   <li>Hiçbir paralel görev exception fırlatmamalı.</li>
     *   <li>Her dönüş imzası lokal XMLDsig validator ile geçerli olmalı.</li>
     *   <li>Semaphore permits sızıntısı olmamalı — koşum sonunda
     *       availablePermits == başlangıç değeri.</li>
     * </ul>
     */
    @Test
    void parallel10WsSecuritySignatures_allValid_noLeak() throws Exception {
        SoapEnvelopeFixture[] fixtures = {
                SoapEnvelopeFixture.SOAP_1_1,
                SoapEnvelopeFixture.SOAP_1_2,
                SoapEnvelopeFixture.SOAP_MULTIBODY,
                SoapEnvelopeFixture.GIB_EFATURA_SOAP,
                SoapEnvelopeFixture.SOAP_WITH_WSA
        };
        int initialPermits = sharedSemaphore.availablePermits();

        ExecutorService pool = Executors.newFixedThreadPool(PARALLEL);
        CountDownLatch startGate = new CountDownLatch(1);
        AtomicInteger successCount = new AtomicInteger(0);
        List<Future<byte[]>> futures = new ArrayList<>(PARALLEL);

        try {
            for (int i = 0; i < PARALLEL; i++) {
                final SoapEnvelopeFixture fixture = fixtures[i % fixtures.length];
                futures.add(pool.submit(() -> {
                    startGate.await();
                    // Her thread kendi DocumentBuilder + Document'ını yaratmalı
                    // (JCA DocumentBuilder thread-safe değil).
                    Document doc = parseXmlSecurely(fixture.readBytes());
                    SignResponse signed = wsService.signSoapEnvelope(
                            doc,
                            fixture.isUseSoap12(),
                            defaultMaterial,
                            "test",
                            new char[0]);
                    assertNotNull(signed);
                    assertNotNull(signed.getSignedDocument());
                    successCount.incrementAndGet();
                    return signed.getSignedDocument();
                }));
            }
            startGate.countDown();

            int sampleIdx = 0;
            for (Future<byte[]> future : futures) {
                byte[] signedBytes = future.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
                WsSecurityLocalXmlDsigVerifier.Result result =
                        WsSecurityLocalXmlDsigVerifier.validate(
                                signedBytes,
                                defaultMaterial.getSigningCertificate().getPublicKey());
                assertTrue(result.isValid(),
                        "Paralel WSS imzası lokal XMLDsig doğrulamasından geçemedi: " + result);
                // 10 paralel imzanın hepsini export etmek folder'ı şişirir;
                // ilk 3'ünü sample olarak yaz (race-condition altında
                // determinist çıktıyı görmek için yeterli).
                if (sampleIdx < 3) {
                    SignedArtifactExporter.export(
                            SignedArtifactExporter.Format.WSSECURITY,
                            signedBytes,
                            "parallel-sample-" + sampleIdx);
                }
                sampleIdx++;
            }
        } finally {
            pool.shutdownNow();
        }

        assertEquals(PARALLEL, successCount.get(),
                "Tüm paralel imzalar başarıyla tamamlanmalı");
        assertEquals(initialPermits, sharedSemaphore.availablePermits(),
                "Semaphore permits sızıntısı yok — tüm acquire'lar release ile dengelenmiş");
    }

    private static Document parseXmlSecurely(byte[] xml) throws Exception {
        DocumentBuilderFactory dbf = SecureXmlFactories.newDocumentBuilderFactory();
        DocumentBuilder db = dbf.newDocumentBuilder();
        return db.parse(new ByteArrayInputStream(xml));
    }
}
