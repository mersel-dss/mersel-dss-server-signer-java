package io.mersel.dss.signer.api.services.metrics;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tags;
import io.micrometer.core.instrument.Timer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

/**
 * Uygulama seviyesinde <b>imza iş metrikleri</b>. PKCS#11 köprüsünün düşük seviye
 * IPC sayaçlarından ({@code pkcs11_bridge_*}) bağımsız olarak; format, belge tipi,
 * profil ve sonuç (başarı/hata) kırılımında imza hacmini, belge boyutunu ve imza
 * süresini Prometheus'a yayınlar.
 *
 * <h2>Yayınlanan metrikler</h2>
 * <ul>
 *   <li>{@code signer_signatures_total} — sayaç; toplam imza isteği.
 *       Etiketler: {@code format}, {@code document_type}, {@code profile},
 *       {@code outcome} (success|failure).</li>
 *   <li>{@code signer_document_bytes} — DistributionSummary; <b>girdi</b> belge
 *       boyutu (byte). {@code _count}/{@code _sum} ile ortalama boyut, {@code _bucket}
 *       ile histogram/heatmap ve {@code histogram_quantile} desteği. Etiketler:
 *       {@code format}, {@code document_type}.</li>
 *   <li>{@code signer_signed_bytes} — DistributionSummary; <b>çıktı</b> (imzalı)
 *       belge boyutu (byte). Etiket: {@code format}.</li>
 *   <li>{@code signer_signature_duration_seconds} — Timer; imza süresi (controller
 *       içi uçtan uca). Percentile-histogram açık. Etiketler: {@code format},
 *       {@code document_type}, {@code outcome}.</li>
 * </ul>
 *
 * <h2>Kardinalite</h2>
 * <p>Tüm etiket değerleri sınırlı kümelerden gelir (sabit format/profil isimleri,
 * {@link io.mersel.dss.signer.api.models.enums.DocumentType} enum'u, success/failure).
 * Serbest metin (dosya adı, hata mesajı) <b>etiket olarak kullanılmaz</b>; bu yüzden
 * seri patlaması olmaz.</p>
 *
 * <h2>Tasarım</h2>
 * <p>Koşulsuz {@code @Component} — imzalama her modda (HSM/PFX, in-process/remote)
 * yapıldığından metrikler de her zaman üretilir. Meter'lar Micrometer registry'de
 * id (isim + etiket) bazında önbelleğe alınır; aynı etiket kombinasyonu için tekrar
 * {@code builder(...).register(registry)} çağrısı mevcut meter'ı döndürür, yeni meter
 * yaratmaz. Kayıt yolu salt-yan-etki (counter/summary increment) olduğundan imza
 * performansına etkisi ihmal edilebilir.</p>
 */
@Component
public class SignatureMetrics {

    private static final Logger LOGGER = LoggerFactory.getLogger(SignatureMetrics.class);

    private static final String COUNTER = "signer.signatures";
    private static final String INPUT_BYTES = "signer.document.bytes";
    private static final String SIGNED_BYTES = "signer.signed.bytes";
    private static final String DURATION = "signer.signature.duration";

    private static final String NA = "n/a";

    /** Belge boyutu histogram kovaları (byte): 1 KB … 200 MB. */
    private static final double[] SIZE_SLO_BYTES = {
        1_024,        // 1 KB
        10_240,       // 10 KB
        51_200,       // 50 KB
        102_400,      // 100 KB
        512_000,      // 500 KB
        1_048_576,    // 1 MB
        5_242_880,    // 5 MB
        10_485_760,   // 10 MB
        52_428_800,   // 50 MB
        104_857_600,  // 100 MB
        209_715_200   // 200 MB
    };

    private final MeterRegistry registry;

    public SignatureMetrics(MeterRegistry registry) {
        this.registry = registry;
        LOGGER.info("İmza iş metrikleri etkin (Prometheus): signer_signatures_total, "
            + "signer_document_bytes, signer_signed_bytes, signer_signature_duration_seconds.");
    }

    /**
     * Yeni bir imza ölçümü başlatır. Dönen {@link Sample} controller akışı boyunca
     * taşınır ve {@link Sample#success}/{@link Sample#failure} ile sonlandırılır.
     *
     * @param format       imza formatı (örn. {@code CAdES}, {@code PAdES}, {@code XAdES})
     * @param documentType belge tipi; XAdES için {@code DocumentType} adı, diğerleri için sabit
     * @param profile      profil/mod (örn. {@code XADES_BES}, {@code detached}, {@code SOAP1.2})
     * @return ölçüm örneği
     */
    public Sample start(String format, String documentType, String profile) {
        return new Sample(safe(format), safe(documentType), safe(profile));
    }

    private void recordInputSize(String format, String documentType, long bytes) {
        if (bytes <= 0) {
            return;
        }
        DistributionSummary.builder(INPUT_BYTES)
            .description("İmzalanan girdi belgesinin boyutu (byte)")
            .baseUnit("bytes")
            .tags("format", format, "document_type", documentType)
            .serviceLevelObjectives(SIZE_SLO_BYTES)
            .register(registry)
            .record(bytes);
    }

    private void recordSignedSize(String format, long bytes) {
        if (bytes <= 0) {
            return;
        }
        DistributionSummary.builder(SIGNED_BYTES)
            .description("Üretilen imzalı çıktı belgesinin boyutu (byte)")
            .baseUnit("bytes")
            .tags("format", format)
            .serviceLevelObjectives(SIZE_SLO_BYTES)
            .register(registry)
            .record(bytes);
    }

    private void recordCountAndDuration(String format, String documentType, String profile,
                                        String outcome, long durationNanos) {
        Counter.builder(COUNTER)
            .description("Toplam imza isteği sayısı (sonuç kırılımıyla)")
            .tags(Tags.of(
                "format", format,
                "document_type", documentType,
                "profile", profile,
                "outcome", outcome))
            .register(registry)
            .increment();

        Timer.builder(DURATION)
            .description("İmza süresi (controller içi uçtan uca)")
            .tags("format", format, "document_type", documentType, "outcome", outcome)
            .publishPercentileHistogram()
            .register(registry)
            .record(durationNanos, TimeUnit.NANOSECONDS);
    }

    private static String safe(String value) {
        if (value == null || value.trim().isEmpty()) {
            return NA;
        }
        return value;
    }

    /**
     * Tek bir imza işleminin ömrünü temsil eder. Controller {@code try} bloğunda
     * {@link SignatureMetrics#start} ile açılır; başarıda {@link #success}, hatada
     * {@link #failure} çağrılır. {@code start} anındaki {@code nanoTime} ile süre
     * hesaplanır.
     */
    public final class Sample {
        private final String format;
        private final String documentType;
        private final String profile;
        private final long startNanos;

        private Sample(String format, String documentType, String profile) {
            this.format = format;
            this.documentType = documentType;
            this.profile = profile;
            this.startNanos = System.nanoTime();
        }

        /**
         * Başarılı imzayı kaydeder: sayaç + süre + girdi/çıktı boyut dağılımı.
         *
         * @param inputBytes  girdi belge boyutu (byte); {@code <=0} ise atlanır
         * @param signedBytes imzalı çıktı boyutu (byte); {@code <=0} ise atlanır
         */
        public void success(long inputBytes, long signedBytes) {
            long elapsed = System.nanoTime() - startNanos;
            recordCountAndDuration(format, documentType, profile, "success", elapsed);
            recordInputSize(format, documentType, inputBytes);
            recordSignedSize(format, signedBytes);
        }

        /**
         * Başarısız imzayı kaydeder: sayaç + süre. Girdi boyutu varsa dağılıma da
         * eklenir (hata öncesi belge boyutu profilini bozmamak için opsiyonel).
         *
         * @param inputBytes girdi belge boyutu (byte); bilinmiyorsa {@code <=0} geçilebilir
         */
        public void failure(long inputBytes) {
            long elapsed = System.nanoTime() - startNanos;
            recordCountAndDuration(format, documentType, profile, "failure", elapsed);
            recordInputSize(format, documentType, inputBytes);
        }
    }
}
