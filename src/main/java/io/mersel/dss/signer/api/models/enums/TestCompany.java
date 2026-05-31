package io.mersel.dss.signer.api.models.enums;

/**
 * GİB <strong>test ortamı</strong> akışları için kullanılan Kamu SM
 * <em>publicly-published</em> mali mühür test sertifikalarını tipli olarak
 * ifade eden enum.
 *
 * <h3>Ne işe yarar?</h3>
 * <p>Test ortamında entegratör (DSS imzalayıcı) zaten mali mührüyle
 * imzaladığı HrXml (kullanıcı açma/kapama) belgesine, GİB'in
 * beklediği "kurum imzası" yerine geçecek bir <b>counter signature</b>
 * eklemek gerekir. Üretim akışında bu imza gerçek kurumun mali mührüyle
 * atılır; test akışında ise Kamu SM'in test ortamına özel açık yayımladığı
 * RSA test sertifikalarından biri kullanılır.</p>
 *
 * <h3>Production'da KULLANILMAZ</h3>
 * <ul>
 *   <li>Burada listelenen PFX'ler <code>resources/test-certs/</code> altında,
 *       Kamu SM'nin yayımladığı, mali mühür yetkisi olmayan, şifresi dosya
 *       adında açıkça yer alan test sertifikalarıdır.</li>
 *   <li>Production akışlarında bu enum hiçbir yerden çağrılmaz; yalnızca
 *       {@code /v1/testusercountersign} endpoint'i (GİB test ortamı için)
 *       bu enum'u tüketir.</li>
 * </ul>
 *
 * <h3>Naming convention</h3>
 * <pre>
 *   testkurum{NN}_rsa2048@{domain}_{password}.pfx
 * </pre>
 * <p>Şifre dosya adının son <code>_</code> segmentindedir; alias tüm
 * Kamu SM test PFX'lerinde sabit olarak <code>"1"</code>'dir
 * (Dockerfile ve PFX üretim akışıyla aynı convention).</p>
 *
 * <h3>Yeni test kurum eklemek</h3>
 * <p>Repo'ya yeni bir RSA test PFX'i konduktan sonra (aynı naming
 * convention'a uyarak) bu enum'a yeni bir constant eklemek yeterlidir;
 * şifre dosya adından parse edilmez, enum'a explicit yazılır ki
 * production akışlarında dosya adı parse'ına bağımlı kalmayalım.</p>
 */
public enum TestCompany {

    /** Kamu SM "TestKurum01" RSA-2048 mali mühür test sertifikası. */
    TestKurum1("testkurum01_rsa2048@test.com.tr_614573.pfx", "614573", "1"),

    /** Kamu SM "TestKurum02" RSA-2048 mali mühür test sertifikası. */
    TestKurum2("testkurum02_rsa2048@sm.gov.tr_059025.pfx", "059025", "1"),

    /** Kamu SM "TestKurum03" RSA-2048 mali mühür test sertifikası. */
    TestKurum3("testkurum03_rsa2048@test.com.tr_181193.pfx", "181193", "1");

    private final String pfxFileName;
    private final String pfxPassword;
    private final String alias;

    TestCompany(String pfxFileName, String pfxPassword, String alias) {
        this.pfxFileName = pfxFileName;
        this.pfxPassword = pfxPassword;
        this.alias = alias;
    }

    /** PFX dosya adı (sadece file-name; dizinle birleştirme caller'da). */
    public String getPfxFileName() {
        return pfxFileName;
    }

    /**
     * PKCS#12 şifresi. <strong>Kasıtlı olarak public</strong> çünkü Kamu SM
     * bu sertifikaları zaten şifresiyle birlikte yayımlıyor; production
     * sırrı taşımıyor.
     */
    public String getPfxPassword() {
        return pfxPassword;
    }

    /** PFX içindeki private key alias'ı. Tüm Kamu SM test PFX'lerinde sabit <code>"1"</code>. */
    public String getAlias() {
        return alias;
    }
}
