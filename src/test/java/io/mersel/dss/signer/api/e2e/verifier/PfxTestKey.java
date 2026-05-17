package io.mersel.dss.signer.api.e2e.verifier;

import java.io.File;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Repo kökündeki <code>resources/test-certs/</code> dizininde bulunan PFX
 * dosyalarını tipli olarak ifade eden enum.
 *
 * <h3>Naming convention</h3>
 * Pozitif dosya adları şu kalıbı izler:
 * <pre>
 *   {kurum}_{algo}@{domain}_{password}.pfx
 *   ↑       ↑       ↑       ↑
 *   adı    rsa2048 sahibi   PKCS#12 şifresi (alias da "1")
 *           ec384
 * </pre>
 *
 * <p>Negatif (revoked / expired / suspended) PFX'ler için <b>aynı</b>
 * convention'a en az invasive ek: algoritma sonrasına status suffix'i
 * (<code>_revoked</code>, <code>_expired</code>, <code>_suspended</code>)
 * eklenir; şifre yine son segment olarak parse edilir:</p>
 * <pre>
 *   testkurum_revoked_rsa2048@test.com.tr_{password}.pfx
 *   testkurum_expired_ec384@test.com.tr_{password}.pfx
 *   testkurum_suspended_rsa2048@test.com.tr_{password}.pfx
 * </pre>
 *
 * <p>Şifre dosya adının son segmentinden çıkarılır — bu Dockerfile'da da
 * kullanılan aynı convention. Üretim sertifikaları için bu yaklaşım
 * elbette uygun değil; sadece Kamu SM'in publicly published test
 * sertifikaları için kullanılıyor.</p>
 *
 * <h3>Status</h3>
 * <p>Her enum constant kendi {@link Status}'unu taşır:</p>
 * <ul>
 *   <li>{@link Status#VALID} — pozitif, ana matriksde kullanılır.</li>
 *   <li>{@link Status#REVOKED} / {@link Status#EXPIRED} / {@link Status#SUSPENDED}
 *       — sadece {@code CertificateLifecycleNegativeE2ETest} (ve benzeri
 *       opt-in testler) tarafından kullanılır. Default suite ve pozitif
 *       E2E matrisleri {@link #positiveValues()} üzerinden iterate eder
 *       ki negative key'ler yanlışlıkla pozitif assertion'lara karışmasın.</li>
 * </ul>
 *
 * <h3>Dosya yokken davranış</h3>
 * <p>Negatif PFX'ler Kamu SM'den manuel download gerektirir (login + email
 * onayı, otomatik indirme yapılmaz). {@link #isAvailable()} ile test'ler
 * graceful skip yapabilir (<code>Assumptions.assumeTrue(key.isAvailable())</code>);
 * repo'ya henüz konmamış PFX yüzünden CI kırılmaz.</p>
 */
public enum PfxTestKey {

    // ─────────────────────── POZİTİF (default matriks) ───────────────────────
    KURUM01_RSA2048("testkurum01_rsa2048@test.com.tr_614573.pfx", Status.VALID),
    KURUM02_RSA2048("testkurum02_rsa2048@sm.gov.tr_059025.pfx", Status.VALID),
    KURUM02_EC384("testkurum02_ec384@test.com.tr_825095.pfx", Status.VALID),
    KURUM03_RSA2048("testkurum03_rsa2048@test.com.tr_181193.pfx", Status.VALID),
    KURUM03_EC384("testkurum03_ec384@test.com.tr_540425.pfx", Status.VALID),

    // ─────────────────────── NEGATİF (opt-in, lifecycle testleri) ───────────
    // Kamu SM tablosundan manuel indirilen sertifikalar; dosya adının son
    // segmenti PFX şifresidir (Kamu SM ZIP içinden çıkar). Tüm 6 dosya
    // 2026-05-18 itibarıyla repo'da; yeni bir negatif PFX yenilenirse
    // sadece file-name (son segment = yeni password) güncellenmelidir.
    KAMUSM_REVOKED_RSA2048("testkurum_revoked_rsa2048@test.com.tr_498272.pfx", Status.REVOKED),
    KAMUSM_REVOKED_EC384("testkurum_revoked_ec384@test.com.tr_670246.pfx", Status.REVOKED),
    KAMUSM_EXPIRED_RSA2048("testkurum_expired_rsa2048@test.com.tr_787579.pfx", Status.EXPIRED),
    KAMUSM_EXPIRED_EC384("testkurum_expired_ec384@test.com.tr_041207.pfx", Status.EXPIRED),
    KAMUSM_SUSPENDED_RSA2048("testkurum_suspended_rsa2048@test.com.tr_073938.pfx", Status.SUSPENDED),
    KAMUSM_SUSPENDED_EC384("testkurum_suspended_ec384@test.com.tr_242195.pfx", Status.SUSPENDED);

    /** Repo köküne göre PFX dizini (Maven user.dir testlerde repo kökü olur). */
    private static final String PFX_DIR = "resources/test-certs";

    /** Dockerfile ve PFX üretim akışıyla aynı sabit alias. */
    public static final String DEFAULT_ALIAS = "1";

    /**
     * Sertifika lifecycle status'u — pozitif/negatif ayrımı + downstream
     * verifier beklentisi için.
     */
    public enum Status {
        /** Geçerli (notBefore/notAfter ok + not revoked + not suspended). */
        VALID,
        /** İptal edilmiş — Kamu SM CRL/OCSP'de revoked. */
        REVOKED,
        /** Süresi dolmuş — notAfter < now. */
        EXPIRED,
        /** Askıya alınmış — OCSP <em>certificateHold</em> (geçici revoke). */
        SUSPENDED
    }

    private final String fileName;
    private final char[] password;
    private final Status status;

    PfxTestKey(String fileName, Status status) {
        this.fileName = fileName;
        this.password = parsePassword(fileName);
        this.status = status;
    }

    public String getFileName() {
        return fileName;
    }

    /** Mutlak dosya yolu. */
    public File getFile() {
        return new File(PFX_DIR, fileName).getAbsoluteFile();
    }

    public String getAbsolutePath() {
        return getFile().getAbsolutePath();
    }

    /**
     * PIN/şifrenin <em>kopyasını</em> döner. Aynı array'i birden çok yerde
     * paylaşmamak için her çağrıda yeni copy üretir — JCA bazı yollarda
     * array'i sıfırlayabiliyor.
     */
    public char[] getPassword() {
        return password.clone();
    }

    public String getAlias() {
        return DEFAULT_ALIAS;
    }

    /** Sertifika lifecycle status'u (VALID / REVOKED / EXPIRED / SUSPENDED). */
    public Status status() {
        return status;
    }

    /** {@code true} → pozitif sertifika (Status.VALID), pozitif matrislerde kullanılır. */
    public boolean isPositive() {
        return status == Status.VALID;
    }

    /** {@code true} → negatif sertifika (revoked/expired/suspended). */
    public boolean isNegative() {
        return status != Status.VALID;
    }

    /**
     * Dosya repo'da var mı? Negatif PFX'ler Kamu SM'den manuel indirilir;
     * dosya gelmeden testler {@code Assumptions.assumeTrue(key.isAvailable())}
     * ile graceful skip yapabilsin.
     *
     * <p>Geçmişte enum'da PLACEHOLDER suffix bir guard olarak kullanılıyordu;
     * artık tüm negatif PFX file-name'leri gerçek password'le tanımlı. Yine
     * de defensive guard: dosya adı hâlâ PLACEHOLDER taşıyorsa
     * (regression / yeniden manuel rotasyon sırasında) {@code false} dön ki
     * yanlış password'le yükleme deneyip cryptic hata vermesin.</p>
     */
    public boolean isAvailable() {
        if (fileName.contains("PLACEHOLDER")) {
            return false;
        }
        return getFile().isFile();
    }

    /** Test parametrize raporları için okunabilir isim. */
    public String displayName() {
        return name() + " (" + fileName + ")";
    }

    // ════════════════════════ Pozitif/negatif filtreler ════════════════════════

    /**
     * Pozitif (Status.VALID) PFX'lerin dizisi. Mevcut pozitif E2E matrisleri
     * (XAdES / CAdES / PAdES / WS-Security) bu helper üzerinden iterate eder;
     * negatif key'ler yanlışlıkla pozitif assertion'lara karışmaz.
     */
    public static PfxTestKey[] positiveValues() {
        return Arrays.stream(values())
                .filter(PfxTestKey::isPositive)
                .toArray(PfxTestKey[]::new);
    }

    /**
     * Negatif (revoked / expired / suspended) PFX'lerin dizisi.
     * {@code CertificateLifecycleNegativeE2ETest} ve benzeri opt-in testler
     * tarafından kullanılır.
     */
    public static PfxTestKey[] negativeValues() {
        return Arrays.stream(values())
                .filter(PfxTestKey::isNegative)
                .toArray(PfxTestKey[]::new);
    }

    private static char[] parsePassword(String fileName) {
        // NOT: regex'i enum-level static field olarak tutamayız çünkü Java
        // enum constants kendi <clinit>'inde DİĞER static field'lardan ÖNCE
        // initialize edilir; bu yüzden constructor'dan erişilen herhangi bir
        // static field forward-reference NPE'sine yol açar. Lazy holder
        // class pattern Java spec'i ile bu sorunu temizce çözer — holder
        // class ilk erişimde (yani ilk parsePassword çağrısında) yüklenir;
        // o sırada outer enum init zaten tamamlanmıştır.
        Matcher m = FilenamePattern.INSTANCE.matcher(fileName);
        if (!m.matches()) {
            throw new IllegalStateException(
                    "PFX dosya adı convention'a uymuyor: " + fileName
                            + " (beklenen: ..._{password}.pfx)");
        }
        return m.group(1).toCharArray();
    }

    /** Lazy initialization holder — enum forward-reference bug'ını engeller. */
    private static final class FilenamePattern {
        static final Pattern INSTANCE = Pattern.compile("^.+_([A-Za-z0-9]+)\\.pfx$");
    }
}
