# Changelog

Tüm önemli değişiklikler bu dosyada dokümante edilmektedir.

Format [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) standardına dayanmaktadır,
ve bu proje [Semantic Versioning](https://semver.org/spec/v2.0.0.html) kullanmaktadır.

## [Unreleased]

## [0.9.2] - 2026-05-26

### Fixed

- **Jackson sürüm split-brain → `NoSuchFieldError` runtime hatası**: API endpoint'lerine ilk JSON request geldiğinde
  `java.lang.NoSuchFieldError: READ_UNKNOWN_ENUM_VALUES_USING_DEFAULT_VALUE` ile patlama yaşanıyordu
  (`com.fasterxml.jackson.databind.deser.std.EnumDeserializer.createContextual` içinden, Spring MVC
  message converter aşamasında).
  - **Kök neden**: `pom.xml` yalnızca `jackson-core`, `jackson-databind` ve `jackson-dataformat-xml`
    artefaktlarını explicit `<version>2.15.3</version>` ile override ediyordu. Spring Boot 2.7.18
    starter-parent'ın `jackson-bom` 2.13.5'i transitive olarak getirdiği `jackson-annotations`,
    `jackson-datatype-jdk8`, `jackson-datatype-jsr310`, `jackson-module-parameter-names` ve
    `jackson-dataformat-yaml` modülleri **2.13.5**'te kalıyordu. Jackson modülleri "in-lockstep"
    çalışır — `jackson-databind 2.15.3`'ün `EnumDeserializer`'ı `DeserializationFeature` üzerinde
    2.13.x'te bulunmayan bir enum field'ına reflect ettiğinde JVM `NoSuchFieldError` fırlatıyordu.
  - **Çözüm**: `pom.xml` `<properties>` bloğuna `<jackson-bom.version>2.15.3</jackson-bom.version>`
    eklendi. Spring Boot starter-parent kendi `jackson-bom` import'unu bu property üzerinden çözer;
    artık TÜM jackson-* artefaktları (annotations / datatype-jdk8 / datatype-jsr310 /
    module-parameter-names / dataformat-yaml / dataformat-xml / core / databind) **2.15.3** lockstep'inde
    resolve edilir. Explicit dependency declaration'lardaki `<version>` etiketleri de kaldırıldı
    (DRY — versiyon tek otoriter kaynaktan, BOM'dan, yönetiliyor).
  - **Etki**: Sıfır kod değişikliği, sıfır API contract kırılması; sadece dependency graph
    hizalandı. Runtime `NoSuchFieldError` artık reproducible değil.

## [0.9.1] - 2026-05-26

### Changed

- **.NET istemci SDK (`MERSEL.Services.DssSigner.Client`) hedef framework
  konsolidasyonu**: Multi-target `net6.0;net7.0;net8.0;net9.0` yerine
  **`netstandard2.0;net8.0`** hibrit hedeflemeye geçildi.
  - **Genişleme**: Artık **.NET Framework 4.6.1+**, **Mono 5.4+**, **Xamarin**
    ve **Unity** tüketicileri tek paketle desteklenir. Legacy ön muhasebe /
    ERP / e-Belge entegratör senaryolarında migration olmadan istemci adoption
    yapılabilir.
  - **Modern .NET'te değişiklik yok**: .NET 8 LTS kullanıcıları aynı inbox
    `lib/net8.0/` binary'sini almaya devam eder; .NET 9 / .NET 10 / .NET 11
    kullanıcıları NuGet roll-forward ile `lib/net8.0/` binary'sini optimum
    şekilde tüketir.
  - **EOL runtime'lar için fallback**: .NET 6 (EOL Kas 2024) ve .NET 7
    (EOL May 2024) tüketicileri `lib/netstandard2.0/` binary'sini çeker;
    `System.Text.Json 8.0.5` ve `Microsoft.Bcl.AsyncInterfaces 8.0.0`
    polyfill'leri otomatik gelir. Public API yüzeyi **birebir aynı** —
    kaynak kod değişikliği gerekmez.
  - **Marjinal davranış farkı**: netstandard2.0 fallback yolunda
    `HttpContent.ReadAs*Async(CancellationToken)` overload'ları olmadığı
    için `CancellationToken` yalnızca request fazında onurlandırılır,
    stream-read fazında ignored olur. HSM bekleyişi olan uzun çağrılarda
    cancel davranışı modern .NET'e göre marjinal değişebilir.
  - **Paket bağımlılığı sürüm hizalaması**: Her TFM için ayrı
    `Microsoft.Extensions.*` sürüm ItemGroup'u kaldırıldı; tek major
    (`8.0.x`) tüm hedeflerde paylaşılıyor. Bu, Microsoft'un kendi
    `Microsoft.Extensions.Http 8.x` paketinin izlediği "tek major, çok
    runtime" stratejisiyle birebir aynıdır.
  - **CI / pack ergonomisi**: `nuget.yml` workflow'unda SDK matrix
    `6.0.x;7.0.x;8.0.x;9.0.x` yerine yalnızca `8.0.x` kuruluyor; pack
    süresi ve `.snupkg` boyutu yarıya düştü.
- **README.md** içine "Desteklenen Platformlar" tablosu ve .NET Framework
  için TLS 1.2 / 1.3 etkinleştirme notu eklendi.

## [0.9.0] - 2026-05-26

### Added

- **`POST /v1/hashsign` — pre-hashed digest imzalama endpoint'i.**
  - **Use case**: e-Defter mali mührü, manuel XAdES `<ds:SignedInfo>` digest
    imzalama ve benzeri akışlar. Caller hash'i kendisi hesaplar; server
    digest'i <em>tekrar hash'lemez</em>.
  - **Akış**:
    - **RSA**: `Pkcs1DigestInfo.wrap(digest, algorithm)` ile PKCS#1 v1.5
      DigestInfo prefix eklenir; JCA path'inde `Cipher("RSA/ECB/PKCS1Padding")`,
      PKCS#11 path'inde `CKM_RSA_PKCS` mekanizması kullanılır.
    - **ECDSA**: Hash doğrudan eğri üzerinde imzalanır; JCA path'inde
      `NONEwithECDSA`, PKCS#11 path'inde `CKM_ECDSA` kullanılır. Çıktı
      DER SEQUENCE `{ r, s }` olarak normalize edilir.
  - **Validation**: Decoded digest uzunluğu `digestAlgorithm` ile
    eşleşmiyorsa 400 INVALID_INPUT döner (caller yanlışlıkla raw veri
    göndermiş regresyonunu erkenden yakalar). Geçersiz base64, eksik
    body / digest field hepsi 400 ile reddedilir.
  - **Request kontratı**:
    ```json
    {
      "base64EncodedDigest": "...",
      "digestAlgorithm": "SHA256"
    }
    ```
  - **Yanıt kontratı**:
    ```json
    {
      "base64EncodedSignature": "..."
    }
    ```
  - **Mimari**: Yeni `HashSignatureController` + `RawHashSignatureService`
    (paket: `services.signature.raw`). XAdES belge imzalama akışlarından
    SRP gereği ayrılmıştır. Backend katmanında `SigningBackend.signDigest`
    + `Pkcs11Signer.signDigest` kontratları eklendi; her iki yolda da
    SMS-aile recovery (CKR=0x80000384/0x80000387) korunur.
  - **Güvenlik notu**: Endpoint bir signing oracle olduğu için private
    network içinde tüketilmek üzere tasarlanmıştır. Public exposure
    senaryosunda API key authentication, audit log ve rate limiting
    eklenmesi önerilir.

### Changed

- `Pkcs1DigestInfo` (PKCS#1 v1.5 DigestInfo encoder) artık `public` —
  raw RSA imzalama yolunda hem JCA hem PKCS#11 backend'leri tarafından
  ortak kullanılıyor.

## [0.8.0] - 2026-05-25

### Changed (BREAKING)

- **`POST /v1/xadessign`: imza profili (XADES_BES / XADES_A) tamamen request
  parametresi ile belirlenir; `documentType` artık seviye kararına dahil
  değildir.**
  - **Davranış değişimi**: Önceki sürümde `documentType=EArchiveReport`
    veya `documentType=EBiletReport` gönderildiğinde sistem **proaktif
    olarak** XAdES-A seviyesine yükseltme yapıyordu (TSA çağrısı dahil).
    Bu davranış kaldırıldı: rapor tipi gönderilse bile request'te
    `signatureLevel=XADES_A` açıkça istenmediği sürece archive timestamp
    eklenmez.
  - **Migration**: e-Arşiv Raporu / e-Bilet Raporu akışı kullanan
    client'lar artık aşağıdaki gibi explicit profil seçmek zorundadır:
    ```
    documentType=EArchiveReport
    signatureLevel=XADES_A          # archive timestamp ekler (eski default)
    ```
    `signatureLevel` alanı omit edilirse veya `XADES_BES` gönderilirse
    yalnızca baseline imza üretilir.
  - **Mali sorumluluk notu**: e-Arşiv Raporu / e-Bilet Raporu gibi 10 yıllık
    saklama gerektiren akışlarda `XADES_A` talebi artık çağıran tarafın
    sorumluluğundadır. Pasif (implicit) XAdES-A davranışı kaldırıldığı
    için, rapor üreten servislerin bu PR'a geçişte istek payload'unu
    `signatureLevel=XADES_A` ekleyerek güncellemesi gerekir.
  - **Niçin breaking yaptık**: Negatif boolean flag (`DisableTimestamp`)
    yerine pozitif explicit enum, (a) GİB / ETSI nomenclature ile birebir
    uyumlu, (b) Swagger UI'da self-documenting, (c) ileride XAdES-T,
    XAdES-LT vb. baseline seviyelerine genişletmek için breaking change
    üretmeden zemin sağlar. `DisableTimestamp` v1 API'sine merge
    edilmeden bu refactor tercih edildi.

### Added

- **Yeni `XadesSignatureLevel` enum (`XADES_BES`, `XADES_A`).**
  - `SignXadesDto.SignatureLevel` alanı **non-null** kontrata sahip: omit
    edilirse veya `null` set edilirse DTO setter/getter katmanı
    `XADES_BES` default uygular. Swagger UI'da dropdown olarak görünür
    ve `defaultValue=XADES_BES` ile dokümante edilir.
  - **`XADES_BES`** (DSS `XAdES_BASELINE_B`): yalnızca imza; TSA
    çağrılmaz, kontör harcanmaz. e-Fatura, e-Arşiv faturası, irsaliye,
    uygulama yanıtı, HrXml ve **e-Adisyon raporu / e-Döviz raporu
    (iptal hariç)** gibi timestamp gerektirmeyen tüm akışlar için
    uygundur. **API'nin yeni default'udur.**
  - **`XADES_A`** (DSS `XAdES_BASELINE_LTA`, legacy ETSI TS 101 903
    terminolojisinde XAdES-A): imza + signature timestamp + archive
    timestamp. e-Arşiv Raporu / e-Bilet Raporu gibi arşivsel akışlar
    için uygundur. TSA yapılandırılmamışsa istek `TIMESTAMP_ERROR` ile
    reddedilir (fail-fast, silent XAdES_BES fallback üretilmez).
  - **Non-null sözleşmesi**: Service ve LevelUpgradeService imzaları
    `null` kabul etmez; null safety DTO katmanında garanti edilir
    (multipart binding edge case'inde alan boş gelse bile setter
    `XADES_BES`'e düşürür).
- `**GET /api/certificates/signingCertificate` — aktif imzacı sertifikayı
base64 encoded biçimde de döndüren tek-shot endpoint.**
  - **Motivasyon**: Manuel XAdES imza akışı (özellikle GİB UBL-TR 2.1
  için özel namespace prefix gereksinimi olan senaryolar)
  `<ds:Signature>` elementini elle kuruyor; bu sırada
  `<ds:X509Certificate>` elementine basılacak base64 encoded
  sertifika için server'a tekrar tekrar dosya okuma / `/list`
  endpoint'i + alias-serial filtreleme döngüsü yapmak zorunda
  kalıyordu. `/list` çağrı başına token'daki tüm entry'leri döner
  ve büyük HSM'lerde (50+ sertifika) gereksiz payload üretir.
  - **Mekanizma**: Yeni endpoint, Spring container'da başlangıçta
  resolve edilmiş tek `SigningMaterial` singleton'ından beslenir.
  Token'a fazladan istek atılmaz; sertifika materyali zaten
  bootstrap'ta okunduğu için yanıt sub-millisecond düzeyde döner.
  - **Yanıt sözleşmesi**: `CertificateInfoDto` formatında — listing
  endpoint'iyle birebir aynı şema. İki ek alan: `publicKeyAlgorithm`
  (örn. `RSA`, `EC`) ve `base64EncodedCertificate` (X.509 DER
  encoding'in base64'lenmiş hali). `hasPrivateKey` her zaman
  `true` döner; HSM (PKCS#11) yapılandırmasında JCA katmanı private
  key handle'ı `null` yansıtsa bile imza materyali fiilen token'da
  yaşadığı için bilgilendirme doğru.
  - **Cache sözleşmesi**: `SigningMaterial` başlangıçta resolve
  edildiği için içerik uygulama yaşam döngüsü boyunca **değişmez**.
  Yanıt `Cache-Control: private, max-age=3600, immutable` header'ı
  taşır; reverse-proxy ve client tarafı in-memory cache'ler tekrarlı
  çağrılarda 0-RTT lookup yapabilir.
  - **Listing endpoint hijenı**: `base64EncodedCertificate` alanı
  `/list` yanıtında kasıtlı olarak `null` bırakılır — 50+ sertifika
  içeren HSM'lerde payload'un 100 KB+'a şişmesini önler. Manuel
  XAdES kullanan akışlar `/signingCertificate`'a yönlendirilir.

### Fixed

- `**CertificateInfoService` listing yolunda iki minör regresyon
kapatıldı.**
  - **Belirti 1**: Helper'a çıkarılan `convertToCertificateInfoDto(...)`
  sonrası `cert == null` durumu yalnızca NPE → catch → warn log
  pattern'iyle yakalanıyordu; exception ile kontrol akışı.
  **Çözüm**: Null sertifika explicit `continue` ile sessizce
  atlanır, debug seviyesi log düşer.
  - **Belirti 2**: Refactor sırasında `keyStore.isCertificateEntry()`
  ve `keyStore.isKeyEntry()` çağrıları per-alias try-catch dışına
  çıkmıştı; bu metotlar legacy/bozuk keystore entry'lerinde
  `KeyStoreException` atabildiği için tek bir kötü alias tüm
  listing'i patlatıyordu. **Çözüm**: Tüm alias-bazlı okuma adımları
  tek try ile sarmalandı — eski "sessiz skip" davranışı korundu.
- `**CertificateInfoDto.toString()` log satırı başına 1.5–2 KB
şişmesin diye base64 sertifika kasıtlı olarak değer yerine
uzunlukla loglanır.** Aksi halde DTO'nun debug seviyesinde
loglandığı yerlerde her satır devasa base64 string içerir; 0.7.0'da
gelen `LogHeadersFilter` ile birlikte log dosya boyutları görünür
şekilde patlardı.
- `**scripts/check-changelog-updated.sh` awk regex'inde gizli bug
düzeltildi — her PR yanlışlıkla "CHANGELOG güncellenmemiş" hatası
alıyordu.**
  - **Belirti**: `Verify CHANGELOG.md is updated` GitHub Actions
  check'i, [Unreleased] bölümüne entry ekleyen PR'larda dahi
  "[Unreleased] bolumune yeni satir eklenmemis gibi gorunuyor"
  hatası veriyordu. Hasan'ın PR #20 commit'i ve önceki
  `feat(observability)` commit'i (`54c8ce0`) hep aynı false
  positive ile fail dönüyordu; production'a etkisiz çünkü doğrudan
  main'e push edilen commit'lerde CI failure merge'i engellemiyor,
  ama PR akışında engelleyici.
  - **Kök neden**: Awk pattern `/^[+\-] ## \[Unreleased\]/` iki
  sorunu birden taşıyordu. (a) Unified diff format'ında marker
  (`+`/`-`) ile içerik arasında boşluk yoktur (`+## ...`), ama
  pattern literal boşluk bekliyordu. (b) Mevcut `## [Unreleased]`
  header'ı, eklemeler altına yapıldığı için diff'te **context
  satır** ( `## [Unreleased]`, space-prefix'li) olarak görünür;
  karakter sınıfı `[+\-]` boşluğu kapsamadığı için context satır
  zone'a hiç giremezdi. Sonuç: pattern fiilen hiçbir gerçek diff
  formatında match etmez.
  - **Çözüm**: Zone trigger karakter sınıfı `[+\- ]`'ye genişletildi
  (space dahil), marker ile `##` arasındaki literal boşluk
  kaldırıldı, zone exit pattern'i `## [0-9]` ile sürüm-numaralı
  section'lara odaklandı (yine "Unreleased" yakalanmasın diye).
  Doğrulama: mevcut PR + iki geçmiş feature commit (`54c8ce0`,
  `a9ae7dd`) artık PASSED dönerken, CHANGELOG güncellemesi
  olmayan saf-kod commit'i (Hasan'ın orijinal `880c784` commit'i)
  hâlâ doğru şekilde FAILED veriyor — negatif case korundu.
- `**integration-tests.yml` workflow'undaki `XadesSoftHsmVerifierE2ETest`
iterasyon sayısı 25 → 20 olarak güncellendi.**
  - **Belirti**: 0.7.0 release'inde `XadesDocumentFixture.standardFixtures()`
  fixture listesi 5'ten 4'e düşürüldü (EARSIV_RAPORU XAdES-A TSA
  zorunluluğu nedeniyle hariç tutuldu; bkz. yukarıdaki XAdES fail-fast
  sözleşmesi). Ancak CI workflow'undaki assertion (`expected=25`,
  "5 PfxTestKey × 5 XadesDocumentFixture") güncellenmediği için
  HSM integration check her PR'da fail veriyor (gerçek: 20, beklenen: 25).
  - **Görünmezlik sebebi**: 0.7.0 commit'i (`10ed0a6`) doğrudan main'e
  push edildiği için CI failure merge'i engellemedi; bug ilk PR
  (#20) main'e rebase olunca yüzeye çıktı.
  - **Çözüm**: `expected=20`, açıklama yorumlarında "5 × 4 = 20"
  matematiği netleştirildi, hem step adındaki "(25 HSM+verifier
  iterations)" başlığı hem üst seviye workflow header'ı 0.7.0
  fixture daralmasına atıfla güncellendi.

## [0.7.0] - 2026-05-25

### Added

- `**x-log-`* request header'ları artık tüm log satırlarında JSON olarak
otomatik görünür — opt-in correlation/trace observability sözleşmesi.**
  - **Motivasyon**: Operatör, çağıran sistemden gelen takip metadatasını
  (örn. `X-Log-Id: abc`, `X-Log-Kimlik: kajsdh`) controller / service
  kodunda elle parametre olarak taşımadan, GİB submission ID'si veya
  müşteri tarafı correlation key'lerini info/warn/error satırlarının
  hepsinde gözleyebilmeli. Manuel `LOGGER.info("[{}]", traceId, ...)`
  pattern'i 6 controller, ~40 servis ve `GlobalExceptionHandler`
  arasında çoğaltılması anlamsız boilerplate.
  - **Mekanizma**: Yeni `LogHeadersFilter`
  (`Ordered.HIGHEST_PRECEDENCE + 50`) request başında `x-log-` prefix'li
  tüm header'ları (case-insensitive) yakalayıp SLF4J `MDC`'ye
  `xlog.<lower-case-name>` formunda yazar. Yeni `LogHeadersConverter`
  Logback `ClassicConverter`'ı pattern içinde `%xLogHeaders` olarak
  kayıtlı; her log event'inde `xlog.`* MDC entry'lerini alfabetik
  sırada JSON nesnesine serialize eder. Hiç header yoksa boş string
  döner — mevcut log gürültüsü artmaz.
  - **Çıktı formatı**: `xlog={"x-log-id":"abc","x-log-kimlik":"kajsdh"}`.
  Konum: standart pattern'in sonunda (`%msg` sonrası, `%n` öncesi).
  CONSOLE / `application.log` / `error.log` / `signature.log`
  appender'larının hepsi yeni pattern'i kullanır.
  - **Güvenlik sertleştirmesi**: (a) request başına en fazla
  20 `x-log-`* header işlenir — şişirilmiş header bombasına karşı
  sınır; (b) her değer 512 karaktere kırpılır; (c) CR/LF + diğer
  ASCII kontrol karakterleri boşluğa çevrilir — klasik CRLF log
  injection vektörü kapatılır; (d) converter ikinci savunma hattı
  olarak `<0x20` kontrol karakterlerini RFC 8259 JSON kaçışına
  uğratır.
  - **MDC sözleşmesi**: Filter sadece kendi koyduğu `xlog.`*
  anahtarlarını `finally` bloğunda temizler — uygulamanın başka bir
  yerinde MDC'ye konmuş tenant/trace anahtarları korunur.
  - **Async sınırlama**: SLF4J MDC thread-local; `@Async` ya da
  explicit executor dispatch'lerinde context propagate olmaz. Mevcut
  imza pipeline'ları request thread'i üzerinde sync çalıştığı için
  pratik sorun değil; ileride async eklenirse `MDC.getCopyOfContextMap()`
  ile elle taşınmalı.
  - **Migration**: Client'lar için davranış değişikliği yok — header
  göndermeyenlerde log çıktısı aynı. Header gönderenler için
  zero-effort observability kazanımı.

### Changed (BREAKING)

- 🛑 `**XAdESLevelUpgradeService` artık `EArchiveReport` / `EBiletReport`
için TSA tanımlı değilken sessiz XAdES-B fallback yapmaz — fail-fast
`TimestampException` fırlatır.**
  - **Belirti**: Önceki davranışta `TS_SERVER_HOST` boşken
  `XAdESLevelUpgradeService.upgradeIfNeeded(...)` `WARN` log düşüp
  orijinal XAdES-B belgesini döndürüyordu. e-Arşiv ve e-Bilet
  raporları GİB tarafına XAdES-A (archival) seviyesinde
  gönderilmek zorundadır; XAdES-B'lik bir rapor sessizce uyumsuz
  çıktı üretir, GİB validator'a gidene kadar fark edilmez ve
  rapor reddedilir (klasik "silent data corruption" pattern).
  - **Çözüm — fail-fast sözleşmesi**: TSA yapılandırılmamışsa
  veya XAdES-A yükseltmesi sırasında herhangi bir hata oluşursa
  `TimestampException` (`errorCode=TIMESTAMP_ERROR`) fırlatılır.
  HTTP katmanında `GlobalExceptionHandler` bunu **503
  SERVICE_UNAVAILABLE + `TIMESTAMP_ERROR` envelope**'una map'ler;
  client config eksikliğini (TSA URL'si, kimlik bilgileri) anında
  görür ve düzeltebilir.
  - **Mesaj kontratı**: TSA-eksik mesajı belge tipini
  (`EArchiveReport` / `EBiletReport`) ve yapılandırılması gereken
  property adını (`TS_SERVER_HOST`) içerir; upgrade-fail mesajı
  "XAdES-A" bağlamını net eder ki client yarım imza üretilmediğini
  anlar.
  - **Test ortamı etkisi**: `XadesDocumentFixture.standardFixtures()`
  artık `EARSIV_RAPORU`'yu hariç tutar; `XAdESSignAndVerifyE2ETest`
  matrisi `requiresTsa()` filtresiyle TSA-bağımsız fixture'larda
  çalışır. e-Arşiv için fail-fast davranışını sınayan dedike test
  eklendi: `earchiveReportFailsFastWhenTsaUnconfigured`. Pozitif
  XAdES-A roundtrip testi TSA-mock'lı ayrı bir suite'in işidir.
  - **Migration**: TSA yapılandırması ile e-Arşiv / e-Bilet rapor
  imzalayan müşterilerin yapması gereken değişiklik *yok* —
  TSA URL'si dolu olduğu sürece davranış aynı (XAdES-A üretir).
  Yapılandırması eksik olan ortamlar artık imza isteğinde HTTP 503
  görür; bu davranış doğrudur ve uyumlu olmayan rapor üretiminden
  iyidir.

### Fixed

- **HSM heartbeat self-healing — `CKR_SMS_ERROR` (0x80000384) ardından
Cryptoki-level otomatik reinit + müşteri tarafı tek-shot recovery.**
  - **Belirti**: Production'da 22 May 2026 boot sonrası ilk 71 dakikalık
  happy-path'in ardından bir `C_Sign` çağrısı ~99 dakika asılı kaldı;
  secure messaging katmanı çöktü ve **3297 ardışık başarısız heartbeat**
  boyunca (54+ saat) hiç self-recovery olmadı. Müşteri istekleri
  `{ "code": "SIGNATURE_FAILED", "message": "HSM imza başarısız: CKR_0X80000384" }` dönüyordu — Thales PTK-C vendor tablosundan
  `CKR_SMS_ERROR` (kaynak:
  [https://thalesdocs.com/gphsm/ptk/5.9/docs/Content/PTK-C_Program/PTK-C_Mechs/vendor_def_error.htm](https://thalesdocs.com/gphsm/ptk/5.9/docs/Content/PTK-C_Program/PTK-C_Mechs/vendor_def_error.htm)).
  - **Kök neden — varsayım hatası**: Mevcut heartbeat tasarımı
  *"pratikte başarısız ilk çağrı HSM tarafında secure channel'ı
  re-init eder"* varsayımına dayanıyordu. Thales PTK-C tarafında SMS
  layer komple çöktüğünde xipki wrapper'ın token-level recovery'si
  (`getSessionInfo` → `C_Login`) **çalışmıyor** çünkü PKCS#11 spec
  gereği `C_Login` de secure messaging üstünden gider; login bile
  `CKR_SMS_ERROR` döner. Production log'larında her başarısız
  iterasyon için satır deseni:
    ```
    WARN  org.xipki.pkcs11.wrapper - error getSessionInfo: CKR_0X80000384
    WARN  org.xipki.pkcs11.wrapper - login failed as user of type CKU_USER: CKR_0X80000384
    WARN  i.m.d.s.a.s.k.i.HsmHeartbeatScheduler - HSM heartbeat başarısız ...
    ```
    Yani recovery için **tek çare** Cryptoki global state'ini
    `C_Finalize + C_Initialize` ile sıfırdan kurmak — token-level reset
    yetmiyor.
  - **Çözüm — iki katmanlı koruma**:
    - **L1 — Heartbeat self-healing**: `HsmHeartbeatScheduler`
    ardışık 3 başarısızlığa ulaştığında
    `IaikPkcs11Module.reinitializeForSmsRecovery(alias, null)` ile
    Cryptoki tam reset tetikler. Reinit kendi başarısız olursa
    exponential backoff aktif: 0s → 60s → 5dk → 15dk → 30dk cap.
    Backoff penceresi içinde heartbeat normal şekilde tetiklenir
    (HSM dış müdahaleyle iyileşirse hemen fark eder) ama yeniden
    reinit denemez — log spam ve HSM-side rate limiting önlenir.
    Başarılı sign sonrası tüm state sıfırlanır (RECOVERED log +
    counter reset).
    - **L2 — Caller-path recovery**: `IaikPkcs11Module.signOnSession`
    yeni alias-aware overload'ı (`ResolvedKey` parametresi alır)
    müşteri sign isteklerinin yolunda devreye girer. İlk `C_Sign`
    çağrısı `CKR_SMS_ERROR` veya `CKR_NO_SESSION_KEYS` ile reddedilirse
    tek-shot reinit + retry yapar. Heartbeat henüz tetiklenmemiş olsa
    bile **müşteri kısa pencerede 1 fail yerine recovered sonuç görür**.
    Tek-shot kontratı: retry de SMS-aile hata alırsa **tekrar reinit
    denenmez** (sonsuz döngü koruması), orijinal hata propagate eder
    ve L1 backoff'a alır.
  - **Thread-safety — no-drain rasyoneli**: Reinit anında başka
  thread'lerin in-flight `token.sign(...)` çağrıları olabilir. Bu
  çağrıları drain etmiyoruz çünkü `signatureSemaphore.acquire(N)`
  uzun bir pencere açar ve p99 latency'yi şişirir. Yerine stale
  referansla patlayan in-flight sign'lar L2 branch'i tarafından
  yakalanır ve yeni kanal üstünde retry edilir. Reinit ~1-3 sn;
  kısa pencerede en fazla pool-size kadar müşteri 1 fail görebilir,
  sonraki istekleri transparent recovery.
  - `**ResolvedKey` cascade**: Cryptoki finalize tüm key handle'ları
  invalidate eder. `ResolvedKey.privateKeyHandle` artık `volatile`;
  reinit dönen taze handle çağıran (heartbeat scheduler / signer)
  tarafından **in-place** kopyalanır. `IaikPkcs11Signer.sign()`
  her çağrıda `resolvedKey.privateKeyHandle`'i fresh okur — aynı
  instance referansını paylaşan tüm holderlar yeni handle'ı bir
  sonraki sign'da otomatik görür.
  - `**IaikPkcs11Signer` API değişikliği**: `getPrivateKeyHandle()`
  deprecated; yerine `getResolvedKey()` eklendi. İçeride
  `module.signOnSession(resolvedKey, ...)` yeni overload kullanılır.
  Public `Pkcs11Signer` sözleşmesi değişmedi — sadece internal
  paket-private signer'da fark var.
  - **Test kapsamı**: `IaikPkcs11ModuleSmsRecoveryTest` (yeni, 7 test)
  L2 branch'ini kapsar — SMS-aile hata kodları, non-SMS hata
  propagation, reinit fail propagation, tek-shot kontratı, nested
  wrap chain unwrap. `HsmHeartbeatSchedulerTest$L1ReinitSelfHealing`
  (yeni, 5 test) L1 state machine'ini kapsar — eşik, in-place handle
  refresh, backoff penceresi, success-resets-state, repeated reinit
  failures. `IaikPkcs11SignerTest` yeni overload'a uyarlandı +
  volatile-handle-refresh testi eklendi. Toplam: 434 test yeşil,
  sıfır regresyon.
  - **Deferred**: `C_Sign` wrapper-level timeout (JNI hang koruması —
  99 dakikalık scheduling-1 thread hang'ini deterministik önler) ve
  Spring Boot actuator `HsmHealthIndicator` (`lastSuccessAtMillis`
  bazlı readiness probe) ayrı bir PR'da gelecek; bu PR mevcut
  production incident'ını acil deploy ile çözmek için odaklandı.

## [0.6.3] - 2026-05-24

### Changed

- **.NET istemci SDK'sı `clients/dotnet-client/` altına taşındı + paket adıyla hizalı csproj.**
  - **Belirti**: `.NET` istemci projesi `src/Client/` altında, Maven'ın `src/main`
  ve `src/test` dizinleriyle aynı seviyede öksüz duruyordu. Yeni geliştirici
  repo'yu açtığında "burada bir Maven kararsızlığı mı var?" diye bir saniye
  duraksıyordu; ayrıca csproj dosyası generic `Client.csproj` adıyla
  paket kimliğini yansıtmıyordu.
  - **Çözüm**: Repo kökünde `clients/` namespace açıldı; .NET istemcisi
  `clients/dotnet-client/` altına `git mv` ile **history korunarak**
  taşındı (37 dosya, %100 similarity rename). `Client.csproj` →
  `MERSEL.Services.DssSigner.Client.csproj` olarak yeniden adlandırıldı;
  `PackageId`/`AssemblyName`/`RootNamespace` zaten bu değeri taşıyordu,
  artık dosya adı da uyumlu. Bu kalıp `mersel-os` ekosisteminde
  `ebelge-xslt-service/clients/dotnet-client/MERSEL.Services.XsltService.Client.csproj`
  referansıyla aynı — geliştirici hangi repo'ya bakarsa baksın aynı
  konuma aynı isimde dosya bulur.
  - **Downstream uyumluluğu**: `AssemblyName` ve `PackageId` değişmediği için
  üretilen `MERSEL.Services.DssSigner.Client.dll` ve
  `MERSEL.Services.DssSigner.Client.<VER>.nupkg` adları aynen kaldı.
  `dotnet add package MERSEL.Services.DssSigner.Client` deneyimi ve
  tüketici tarafındaki `using MERSEL.Services.DssSigner.Client;` kullanımı
  **sıfır kırılma** ile devam eder.
  - **CI uyumu**: `.github/workflows/nuget.yml` içindeki `CLIENT_CSPROJ`
  env değişkeni yeni path'e güncellendi. `.gitignore` içindeki bin/obj
  artifact path'leri de yeni dizine taşındı. Pack output kontrat (regex
  `MERSEL.Services.DssSigner.Client.<VERSION>.nupkg`) korunduğu için
  `verify pack output` adımı break etmez.
  - **Mimari kazanım**: `clients/` namespace artık açık — ileride Java
  SDK (`clients/java-client/`), Python (`clients/python-client/`) veya
  TypeScript istemcisi eklemek istendiğinde yer hazır. Mikroservis
  çok dilli tüketici hedefliyor; monorepo'da server'la **versiyon-senkron**
  SDK kardeşleri tutmak release pipeline'ını sade tutar (tek tag → JAR +
  Docker imajı + NuGet paketi paralel fırlar; `release.yml` / `docker.yml`
  / `nuget.yml` üçlüsünün koordinasyon prensibi korundu).
- `**DssSignerClientOptions`'tan ölü `ApiKey` / `BasicAuth` surface'i kaldırıldı.**
  - **Belirti**: Client `DssSignerClientOptions` üzerinde `ApiKey`,
  `ApiKeyHeaderName`, `BasicAuthUsername`, `BasicAuthPassword` property'leri
  yaşıyor; `DependencyInjection.ConfigureHttpClient` bu değerleri set
  edildiğinde her isteğe `X-API-Key` veya `Authorization: Basic ...`
  header'ı olarak ekliyordu. Ancak sunucu tarafında **hiçbir auth
  mekanizması yok**: `SecurityConfiguration` yalnızca CORS yapıyor,
  `pom.xml`'de `spring-security` dependency'si yok, tek bir controller'da
  `@PreAuthorize`/`@Secured` annotation'ı yok, OpenAPI `Components`'ı boş
  (`securitySchemes` tanımlanmamış). `SECURITY.md` zaten bunu açıkça beyan
  ediyor: *"Bu API şu anda authentication olmadan çalışmaktadır. Internal
  kullanım için tasarlanmıştır. Production ortamında API Gateway arkasında
  çalıştırılmalı."*
  - **Risk**: Kullanıcı `o.ApiKey = "secret"` set ettiğinde "güvenliği
  ayarladım" yanılgısına düşüyordu; server hiçbir doğrulama yapmadığı için
  bu sahte güvenlik hissiydi. SDK surface'i sunucu kontratını yansıtmıyordu.
  - **Çözüm**: Dört property `DssSignerClientOptions`'tan çıkarıldı; ilgili
  13 satırlık header injection bloğu `DependencyInjection`'dan söküldü;
  `System.Text` import'u artık gereksiz olduğu için temizlendi; README ve
  XML doc'lardaki `appsettings.json` örnekleri ile inline kod örneklerinden
  auth alanları çıkarıldı. Çıkan property'ler **opsiyonel + nullable**
  olduğu için tüketici tarafında set etmeyen kullanıcılar **sıfır kırılma**
  yaşar; sadece bu alanları açıkça kullanan kullanıcılar (sunucu kontratı
  gereği zaten etkisizdi) küçük bir compile hatası alır ve dış zincirden
  eklemeye yönlendirilir.
  - **Forward-compat (API Gateway senaryosu)**: SDK'yı Nginx/Kong/AWS API
  Gateway arkasında çalıştırıp gateway'in talep ettiği header'ı geçmek
  isteyen kullanıcılar için README'ye standart `IHttpClientFactory`
  örüntüsü eklendi:
    ```csharp
    builder.Services.AddHttpClient(DssSignerClientOptions.HttpClientName)
        .ConfigureHttpClient(http =>
        {
            http.DefaultRequestHeaders.Add("X-API-Key", "gateway-secret");
        });
    // veya: .AddHttpMessageHandler<MyAuthDelegatingHandler>();
    ```
    Bu .NET'in idiomatic yolu — SDK'nın opinionated yüzeyine sahte güvenlik
    abstraction'ı çakmıyoruz, kullanıcının özgür alanına bırakıyoruz.
    `AddDssSignerClient(...)` zaten `IHttpClientBuilder` zincirine bağlı bir
    typed-client kaydı yapıyor; `ConfigureHttpClient` veya
    `AddHttpMessageHandler` zinciri bozulmadan eklenir.
  - **Endpoint parity korundu**: Bu temizlik yalnızca opsiyonel
  config surface'ini hedefler; 10/10 server endpoint'i
  (`/v1/xadessign`, `/v1/wssecuritysign`, `/v1/cadessign`, `/v1/padessign`,
  `/api/timestamp/{get,validate,status}`, `/api/tubitak/credit`,
  `/api/certificates/{list,info}`) ve tüm request/response header alanları
  (`x-signature-value`, `X-Timestamp-{Time,TSA,Serial,Hash-Algorithm,Nonce}`)
  aynen taşınmaya devam eder.
  - **Test güvencesi**: `dotnet build -c Release` (net9.0) → **0 warning /
  0 error**; `dotnet pack` çıktısı
  `MERSEL.Services.DssSigner.Client.<VER>.{nupkg,snupkg}` adlandırması
  değişmedi. Repo geneli `ApiKey|BasicAuth|AuthenticationHeaderValue`
  araması C# kodunda sıfır referans döndürür; kalan tek geçiş README'deki
  bilinçli "gateway senaryosu" not bloğudur.

## [0.6.2] - 2026-05-22

### Added

- **EC P-384 + e-Fatura UBL roundtrip için odaklı E2E verifier testi**
(`XAdESEcdsaP384EfaturaE2ETest`).
  - **Niçin ayrı bir test sınıfı?** Mevcut `XAdESSignAndVerifyE2ETest`
  matriksinde EC384 + e-Fatura zaten 130 senaryo arasında koşuyordu;
  fakat bir failure debug'ı bu kadar geniş matrikste localize etmesi
  zor. Yeni sınıf **sadece** ECDSA P-384 + UBL e-Fatura roundtrip'ine
  odaklanır → 4 senaryo, Allure raporunda net görünür, regression
  suspect olduğunda ilk bakılacak yer.
  - **Senaryo matrisi (4 senaryo)**: 2 EC384 PFX
  (`KURUM02_EC384`, `KURUM03_EC384`) × 2 backend (`PFX_JCA`,
  `PFX_BACKED_PKCS11`).
  - **Backend ayrımının kritikliği**: PKCS#11 yolu ECDSA imzayı raw
  `r || s` formatında üretir (PKCS#11 v2.40 §5.13), XML-DSig ise DER
  `SEQUENCE { INTEGER r, INTEGER s }` ister.
  `XAdESSignatureService#ensureXadesSignatureValueFormat` bu dönüşümü
  `Pkcs11EcdsaSignatureEncoder.normalizeToDer` üzerinden uygular; bu
  test o dönüşümü siyah-kutu olarak doğrular. Verifier
  `cryptographicVerificationSuccessful=false` dönerse format
  regresyonunu doğrudan işaret eder.
  - **Pre-flight cryptographic sanity check**: PFX'in gerçekten EC P-384
  taşıdığı `ECPublicKey.getParams().getCurve().getField().getFieldSize() == 384`
  ile imza akışı başlamadan önce doğrulanır → yanlış fixture seçiminde
  erken/net hata, "alg neydi ki?" debug turunu eler.
  - **Diagnostic logging**: imza süresi, verify süresi, subject DN,
  `sigAlgName`, field bits hepsi `INFO` seviyesinde log'lanır;
  failure'da diag string `(XADES / KURUM02_EC384 / PFX_BACKED_PKCS11 /ECDSA-P384/EFATURA) details=intact:X,cryptoOk:Y,trustAnchor:Z,…`
  formunda root cause yön gösterir.
  - **Strict assertion kontratı**: `CAdESSignAndVerifyE2ETest.assertVerificationPassed`
  helper'ı paylaşılır (5-katmanlı kontrol: `result.isValid()` +
  `indication=TOTAL_PASSED` + `cryptographicVerificationSuccessful` +
  `trustAnchorReached` + `certificateNotExpired`). XAdES'e özel ek
  olarak `signatureFormat XAdES`* ile başlamalı assertion'ı eklendi
  (verifier kontrat regresyonu için).
  - **Failure-mode okuma kılavuzu** Javadoc içinde: hangi flag `false`
  dönerse hangi kod yolunun (Pkcs11EcdsaSignatureEncoder vs DSS LOTL
  trust vs AIA fetch vs PFX rotasyonu) suçlu olduğu eşlemesi.
  - **Çalıştırma doğrulaması**: Lokal Docker Desktop açıkken tam
  verifier-e2e suite'i koşturuldu — **307 test, 0 failure, 4/4 EC384
  senaryosu yeşil** (`Tests run: 4, Failures: 0, Errors: 0, Skipped: 0, Time elapsed: 1.933 s`). Tek environmental error
  (`XadesSoftHsmVerifierE2ETest`) macOS arm64 / Rosetta JVM
  x86_64 native lib mimari uyumsuzluğundan kaynaklanıyor, kod
  değişikliğiyle alakası yok; CI/Linux'ta zaten görünmez.

### Changed

- **PKCS#11 session pool tavanı artık `MAX_SESSION_COUNT`'tan beslenir →
ipkcs11wrapper'ın sessiz 32-cap'i by-pass edildi.**
  - **Belirti**: Yüksek concurrency yük testlerinde (100+ Tomcat thread,
  rack HSM) `MAX_SESSION_COUNT=256` set edilmesine rağmen throughput
  ~15 req/s'de sıkışıp kalıyor; `pct95ResTime / pct50ResTime` oranı
  5-6× tail latency üretiyor, `maxResTime` 8sn'ye dayanıyor.
  - **Kök neden**: `xipki/ipkcs11wrapper 1.0.9` `PKCS11Token` ctor'unda
  `numSessions=null` verilirse defansif olarak `Math.min(32, tokenMaxSessionCount)` uyguluyor. Önceki kodumuz 3-arg ctor
  (`new PKCS11Token(token, true, pin)`) çağırıyordu ve bu overload
  internally `numSessions=null` ile delegate ettiği için pool **her zaman
  32'de hard-cap**'leniyordu. Spring katmanındaki semaphore (`MAX_SESSION_COUNT=256`)
  256 thread'i pipeline'a sokuyordu ama bunlar `borrowSession()`
  kuyruğunda 10sn timeout ile bekliyor → tail latency.
  - **Çözüm**: `IaikPkcs11Module` ctor'una yeni `sessionPoolSize`
  parametresi (6-arg overload). `> 0` ise wrapper'ın 4-arg ctor'u
  (`numSessions` explicit) kullanılır, defansif 32-cap dalı hiç
  değerlendirilmez. `SignatureConfiguration` bean factory
  `MAX_SESSION_COUNT` değerini hem Spring semaphore'a hem IAIK
  pool'a aynı anda besler — **tek-slider model**; iki ayrı property
  olmadığı için operatör tarafında mismatch riski yok.
  - **HSM-tarafı tavan korunur**: Wrapper hâlâ `Math.min(numSessions, tokenMaxSessionCount)` alır. HSM `htl-cb` quota'sını veya firmware
  limitini ezmeyiz; örn. `MAX_SESSION_COUNT=200` set edilse bile HSM
  `tokenMaxSessionCount=50` raporluyorsa effective pool 50'de kalır
  (doğru davranış; startup'ta xipki `tokenMaxSessionCount={..}, maxSessionCount={..}` log satırından teyit edilebilir).
  - **AKİS güvenlik önceliği korunur**: `PKCS11_NULL_INIT_ARGS=true`
  yolunda (TÜBİTAK BİLGEM macOS/Linux sürücüsü) `numSessions=1` zorla
  uygulanır ve `MAX_SESSION_COUNT` değeri **yoksayılır**. PKCS#11 v2.40
  §5.4: NULL-init-args modunda kütüphane thread-unsafe sayılır;
  paralel session yaratmak SIGSEGV / sessiz data corruption riski.
  Karar modül içinde verilir, log'a açıkça yansıtılır:
  `AKİS uyumluluk modu aktif: ... MAX_SESSION_COUNT={N} değeri yoksayıldı`.
  - **Önerilen değerler (HSM tipine göre)**:
    - Akıllı kart / AKİS USB mali mühür: `1` (driver zaten zorla 1)
    - SoftHSM2 (yük testi): `64`
    - SafeNet Luna Network HSM: `64-128`
    - Thales ProtectServer / Utimaco: `32-64`
  - **Geriye uyumluluk**: Mevcut 4-arg ve 5-arg ctor'lar korundu, yeni
  6-arg ctor'a `sessionPoolSize=0` ile delegate ediyorlar; testler
  (`IaikPkcs11ModuleContractTest`, `IaikPkcs11ModuleKeyBindingTest`,
  `SoftHsm2TestSupport`) ve `SignatureApplication` CLI listing yolu
  aynen wrapper default davranışına (cap 32) düşer. Operatör tarafında
  sıfır kırılma; var olan `MAX_SESSION_COUNT` değerleri otomatik
  devreye girer.
  - **Test güvencesi**: Mevcut 81 test (IAIK kontrat + key binding +
  XAdES + signing time + ECDSA format + namespace) yeşil, regresyon
  yok. Yeni davranış için entegrasyon testi gerekmedi — yol değişimi
  `if (sessionPoolSize > 0)` branch'inde ve mevcut `PKCS11Token` ctor
  overload'ı zaten kütüphane tarafından kapsamlı test edilmiş.

## [0.6.1] - 2026-05-22

### Changed

- **HSM heartbeat scheduler operasyonel görünürlüğü artırıldı.** Önceki sürümde
her başarılı test imza `DEBUG` seviyesinde loglanıyordu — production'da
varsayılan `INFO+` log level'ı yüzünden operatör scheduler'ın canlı olup
olmadığını göremiyordu. Artık her tetikleme tek bir net `INFO` satırı
basar:
  ```
  INFO  HsmHeartbeatScheduler - HSM heartbeat test imzası atıldı:
    alias='efatura-2026', alg=RSA_SHA256, sigLen=256, elapsed=12ms,
    totalSuccess=N
  ```
  - `**sigLen**` alanı eklendi: HSM'in döndürdüğü imza byte uzunluğu — test
  imza gerçekten bir `C_Sign` round-trip yaptığının kanıtı (RSA-2048 için
  `256`, ECDSA-P256 DER için `64–72`).
  - **"test imza" terminolojisi**: production loglarında heartbeat'in
  audit amaçlı gerçek imza olmadığı açıkça görülür; sahte imza arayan
  forensic taramalarda karışıklık yok.
  - **Failure → success geçişi (`RECOVERED`)**: ayrı bir `INFO` satırı,
  önceki ardışık başarısızlık sayısını belirtir. Alerting kuralları için
  kıymetli sinyal ("üst üste N hata sonra düzeldi" deseni).
  60sn varsayılan interval'da ~1440 INFO satırı/gün; modern log altyapıları
  için ihmal edilebilir. Sessizlik isteyen operatör
  `logback-spring.xml`'de `io.mersel.dss.signer.api.services.keystore.iaik.HsmHeartbeatScheduler`
  kategorisini `WARN`'a çekebilir; failure görünürlüğü kaybolmaz.
  API değişikliği (minor, internal): `IaikPkcs11Module#heartbeatSign` artık
  `void` yerine `int` (sigLen) döndürüyor. Public surface (`IaikPkcs11Module`)
  zaten Spring-bean kapsamında, dış çağıran yok.

## [0.6.0] - 2026-05-22

### Added

- **SafeNet HSM idle-time `CKR_NO_SESSION_KEYS` workaround: in-process heartbeat
scheduler.**
  - **Belirti**: SafeNet Luna / ProtectServer / ProtectToolkit HSM'lerde uzun
  idle sonrası ilk imza isteği vendor hata kodu `CKR_0x80000387`
  (= `CKR_NO_SESSION_KEYS`) ile patlıyor; stack `PKCS11Token.borrowSession` →
  `Session.login(...)` üzerinde.
  - **Kök neden**: HSM-side secure messaging session-key idle reap olduktan
  sonra xipki `PKCS11Token` cached session handle'ı veriyor; üstüne login
  çağrılınca secure channel key türetimi başarısız.
  - **Tarihsel çözüm**: Operasyon ekipleri dışarıdan periyodik "boş XML imza"
  cron'u ile secure channel'ı sıcak tutuyordu — bus-factor riski + sahte
  audit gürültüsü.
  - **Yeni çözüm**: `HsmHeartbeatScheduler` (`@Component` +
  `@ConditionalOnExpression`), opt-in `HSM_HEARTBEAT_ENABLED=true` ile
  aktive olur ve `HSM_HEARTBEAT_INTERVAL_SECONDS` (default `60`) saniye
  aralıkla gerçek bir `C_Sign` round-trip atar; sonuç drop edilir, secure
  channel canlı kalır. Mevcut `signOnSession` pipeline'ı yeniden kullanılır
  (mekanizma çözümleme + fallback + EC/DSA normalize). Üst üste 5 başarısız
  heartbeat ERROR seviyesine yükseltilir (alerting hook).
  - **Geçiş notu**: Mevcut dış cron'lar bayrak aktif edildikten sonra
  kapatılabilir. PFX modunda no-op.
  - **Test güvencesi**: `HsmHeartbeatSchedulerTest` happy path + exception
  swallow + consecutive failure threshold + algoritma türetme (RSA/ECDSA) +
  PFX SigningMaterial guard senaryolarını kapsar.
  - **Yeni env var'lar**: `HSM_HEARTBEAT_ENABLED` (default `false`),
  `HSM_HEARTBEAT_INTERVAL_SECONDS` (default `60`). Detay: README'deki
  [HSM Heartbeat](README.md#hsm-heartbeat-safenet-ckr_no_session_keys-workaround)
  bölümü.

## [0.5.3] - 2026-05-22

JMeter Stres testi eklendi.

## [0.5.2] - 2026-05-21

### Fixed

- **UBL/XAdES — `xmlns:ext` namespace asimetrisi yüzünden geçersiz
çıkan imzalar düzeltildi** (ApplicationResponse-tipi minimal UBL
belgeleri).
  - **Belirti**: `Invoice` / `DespatchAdvice` gibi kök elemanda
  `xmlns:ext` declare edilmiş şablonlarda imza geçerli, ama
  `ApplicationResponse` (ve UBLExtensions iskeletini bizim
  eklediğimiz tüm "minimal" UBL'lerde) imza GİB/TÜBİTAK
  doğrulayıcılarında **digest mismatch** ile reddediliyordu.
  - **Kök neden**: DSS, ENVELOPED packaging'de `Signature` elementini
  önce kök altına yerleştirip `SignedProperties` referansının
  digest'ini bu konumda hesaplar; sonra biz Signature'ı
  `UBLExtensions/UBLExtension/ExtensionContent` içine taşırız.
  Inclusive C14N (XML-C14N 1.0) kuralı gereği subtree tepe elementine
  "scope'ta olan tüm in-scope namespace declaration'ları" yazılır.
  `xmlns:ext` sadece `UBLExtensions` üzerinde declare edilmişse,
  SignedProperties subtree'sinin scope'u kök altındayken `xmlns:ext`
  içermez, ExtensionContent altındayken içerir → c14n bytes farkı
  → digest karşılaştırması fail.
  - **Çözüm**: `XAdESDocumentPlacementService.ensureUblExtensionContentExists(...)`
  artık her zaman `xmlns:ext`'i kök elemana da declare ediyor
  (idempotent — zaten varsa dokunmuyor). Aynı namespace URI'sini
  birden fazla yerde declare etmek XML semantiğini değiştirmez;
  sadece c14n çıktısını imzalama–doğrulama arasında **simetrik**
  yapar. Bu davranış UBL-TR e-Fatura/e-İrsaliye şablonlarının
  yerleşik konvansiyonuyla uyumludur.
  - **Test güvencesi**:
  `XAdESNamespaceCanonicalizationSymmetryTest` regresyonu kilitler:
  fix YOKKEN root-altı vs ExtensionContent-içi SignedProperties
  c14n bytes'ları **farklı**, fix VARKEN **aynı** olduğunu kanıtlar.
  Ek olarak `XAdESDocumentPlacementServiceTest` üç yeni unit case
  ile kapsama: yeni iskelet eklerken, hazır iskelet üzerine
  eklerken ve idempotency.
- `**signatureId` artık XML NCName / RFC 3986 fragment kurallarına
zorla uyum sağlıyor** (yeni `SignatureIdNormalizer`).
  - **Belirti**: Kullanıcı `signatureId="#Signature_Attach_1"` (URI
  fragment formunda) veya boşluk içeren bir değer gönderdiğinde,
  DSS bunu olduğu gibi `<ds:Signature Id=...>`,
  `<xades:QualifyingProperties Target="#...">`,
  `<xades:SignedProperties Id="xades-...">` ve buna işaret eden
  `<ds:Reference URI="#xades-...">` alanlarına basıyordu. Sonuç:
  `URI="#xades-Signature_#Signature_Attach_1"` gibi RFC 3986
  fragment kuralını ihlal eden bir referans, ki TÜBİTAK/GİB
  doğrulayıcısı SignedProperties node'unu çözemediği için imza
  geçersiz işaretliyordu.
  - **Çözüm**: `XAdESParametersBuilderService` artık `signatureId`'yi
  doğrudan `setDeterministicId(...)`'ya basmadan önce
  `SignatureIdNormalizer.normalize(...)` üzerinden geçiriyor:
  leading `#` karakterleri temizlenir, çift `Signature_` prefix
  önlenir (idempotent), trim yapılır, son kontrol XML 1.0 NCName
  regex'idir. NCName kurallarını ihlal eden girdiler 400 üreten
  `SignatureException(errorCode=INVALID_SIGNATURE_ID)` ile
  erkenden reddedilir — sessiz kırılma yerine açık hata.
  - **Kapsanan davranışlar**:
    - `"Attach_1"` → `"Signature_Attach_1"` (prefix eklenir)
    - `"Signature_Attach_1"` → `"Signature_Attach_1"` (çift prefix yok)
    - `"#Signature_Attach_1"` → `"Signature_Attach_1"` (URI fragment
    temizlenir)
    - `"##Signature_x"` → `"Signature_x"` (peş peşe `#` temizlenir)
    - `"abc#def"`, `"a/b"`, `"ns:local"`, `"a@b"`, boşluk içerenler
    → `INVALID_SIGNATURE_ID` ile reddedilir.
  - **Test güvencesi**: 18 case'lik `SignatureIdNormalizerTest`
  (happy path / fallback / negatif).
- **PKCS#11 `CKR_OPERATION_NOT_INITIALIZED` artık mechanism-rejected
fallback yolunu tetikliyor** — `IaikPkcs11Module.signWithToken(...)`
içindeki "ECDSA için raw `CKM_ECDSA` + dış SHA-*" fallback mantığı,
`xipki` PKCS#11 wrapper'ının `opInit()` çağrısının hatasını yutması
sonucu sürücünün `C_Sign`'da geri attığı `CKR_OPERATION_NOT_INITIALIZED`
kodunu da artık "mekanizma reddedildi" olarak yorumluyor.
  - **Belirti**: Bazı AKİS/SoftHSM2 sürüm kombinasyonlarında ECDSA
  imzalama, `CKR_MECHANISM_INVALID` yerine `CKR_OPERATION_NOT_INITIALIZED`
  döndüğü için fallback path'i devreye girmiyordu; istek üst katmana
  `SignatureException` olarak çıkıyordu.
  - **Kapsam**: Sadece fallback eligibility — RSASSA-PSS için zaten
  fırlatılan açıklayıcı hata davranışı korundu (PSS bu yolda
  desteklenmediği için).

### Fixed

- **İmza digest algoritmasının CA imza algoritmasına sürüklenmesi** —
`DigestAlgorithmResolverService` ve `CryptoUtils.getSignatureAlgorithm(PrivateKey, X509Certificate)`
artık digest seçimini **yalnızca sertifikanın public key parametresinden**
türetir. CA'nın bu sertifikayı imzalarken kullandığı algoritma
(`cert.getSigAlgName()`, ör. `SHA384withRSA`) kasıtlı olarak yok sayılır.
  - **Belirti**: Aynı RSA-2048 son-kullanıcı sertifikasıyla üretilen
  imzalar, ara-CA'nın SHA-384'e geçişiyle birlikte `rsa-sha256` yerine
  `rsa-sha384` (ve digest `sha-256` yerine `sha-384`) dönmeye başlamıştı.
  GİB ve KamuSM tarafındaki yerleşik verifier'lar SHA-256 bekledikleri
  için bu durum üretim ortamında uyumluluk riski oluşturuyordu.
  - **Kök neden**: X.509 `Signature Algorithm` alanı, "CA bu sertifikayı
  imzalarken hangi algoritmayı kullandı" bilgisini taşır; **son
  kullanıcının imzalama algoritmasıyla hiçbir ilgisi yoktur**. Doğru
  sinyal `Public Key` parametresidir (RSA → SHA-256 default, EC → curve
  büyüklüğüne göre NIST SP 800-57).
  - **Etki**: Tüm imza yolları — XAdES (`XAdESParametersBuilderService`),
  CAdES (`CAdESSignatureService`), PAdES (`PAdESSignatureService`),
  WS-Security (`WsSecuritySignatureService`).
  - **Tespit**: İZİBİZ test ortamı, `Hasan Yıldız` (20.05.2026). Teşekkürler.
- **Opsiyonel global override**: Operatörler artık
`SIGNING_DIGEST_ALGORITHM` env değişkeniyle (veya
`signing.digest.algorithm` property'siyle) belirli bir digest'i tüm
imzalama yollarında zorlayabilir. Kabul edilen değerler: `SHA256`,
`SHA384`, `SHA512`, `SHA224`, `SHA1` (tire/altçizgi varyantları da kabul).
- **Test**: `DigestAlgorithmResolverServiceTest` ve
`CryptoUtilsSignatureAlgorithmTest` regresyon vakalarıyla güncellendi —
"CA cert'i SHA-384 ile imzalamış olsa bile RSA public key → SHA-256"
varsayımı artık explicit test ile korunuyor.

## [0.5.0] - 2026-05-20

### Added

- **Profesyonel & immutable release hattı — otomatik JAR derleme, semver
versioning, CHANGELOG-driven release notes**
([docs/RELEASE_PROCESS.md](docs/RELEASE_PROCESS.md)).
  - **Yeni workflow `.github/workflows/release.yml`**: `v*` tag push'unda
  veya `workflow_dispatch` ile tetiklenir. Üç aşamalı:
  `validate` (tag↔pom version eşleşmesi, `-SNAPSHOT` reddi, CHANGELOG
  `## [VERSION]` başlık doğrulaması, mevcut release idempotent skip) →
  `build` (`mvn package` + reproducible build timestamp + manifest + SBOM)
  → `publish` (GitHub Release, asset upload, CHANGELOG-extracted notes).
  - **Yeni workflow `.github/workflows/changelog-check.yml`**: PR'larda
  significant kod değişikliği (src/, pom.xml, devops/, scripts/,
  workflows/) varsa `CHANGELOG.md`'nin `[Unreleased]` bölümünün de
  güncellenmiş olduğunu doğrular. Bypass için PR title veya commit
  message'a `[skip changelog]`.
  - **Build-info JAR'a embed**: `pom.xml` `maven-jar-plugin`'e
  manifestEntries (`Implementation-Version`, `Build-Revision`,
  `Build-Time`, `Build-Number`, `Built-By` vb.) + `spring-boot-maven-plugin`
  `build-info` execution (`META-INF/build-info.properties` → `/actuator/info`
  endpoint'i). Production'da çalışan instance'ın hangi commit'ten geldiği
  tek HTTP çağrısıyla doğrulanabilir.
  - **CycloneDX SBOM** (`cyclonedx-maven-plugin` 2.8.0, Java 8 uyumlu):
  `mvn package` çıktısı olarak `target/bom.json` + `target/bom.xml`
  (CycloneDX 1.5 spec). Her release'de asset olarak yayınlanır.
  NIST SSDF, EU CRA, SLSA Level 3 gereksinimlerine altyapı sağlar.
  - **SHA-256 checksum** her release artifact için (`*.jar.sha256`,
  `*-sbom.json.sha256` vb.) — immutability anchor.
  - **Reproducible build**: `project.build.outputTimestamp` commit author
  date'inden türetilir; aynı commit'ten build edilen JAR aynı bytes'ları üretir.
  - `**scripts/release.sh`**: lokal release hazırlayıcı (clean tree check,
  pom bump, CHANGELOG finalize `[Unreleased]` → `[X.Y.Z] - YYYY-MM-DD`,
  `mvn test+package`, release commit, annotated/signed tag).
  `--dry-run`, `--yes`, `--no-build`, `--no-test`, `--skip-clean` flag'leri.
  Push'u kullanıcıya bırakır; REMOTE'a otomatik bir şey gitmez.
  - `**scripts/bump-version.sh`**: `pom.xml` proje-level `<version>` bumper.
  `major`/`minor`/`patch`/`rc` ya da explicit SemVer geçilir. Parent
  block'a dokunmaz (Spring Boot `2.7.18` korunur). SemVer 2.0.0 validation.
  - `**scripts/extract-release-notes.sh**`: CHANGELOG.md'den ilgili
  `## [X.Y.Z]` bölümünü çıkartır. Release workflow `gh release create --notes-file` ile bu çıktıyı kullanır.
  - `**scripts/check-changelog-updated.sh**`: PR-time CHANGELOG güncellik
  kontrolü. `[Unreleased]` bölümüne diff'te `+` satırı eklenmiş mi?
  - **Immutability politikası**: tag bir kere oluşturulduktan sonra
  silinmemeli/taşınmamalı. Bozuk release için yeni PATCH sürümü çıkarılır,
  eski tag GitHub UI'da "deprecated" notuyla işaretlenir. Detay:
  [docs/RELEASE_PROCESS.md](docs/RELEASE_PROCESS.md) "Hotfix & Rollback".
  - **CI build artifact retention**: `ci.yml` her başarılı build'in JAR'ını
  ve SBOM'unu 14 gün saklar (`build-artifact-<sha>`). QA develop branch
  binary'sini doğrudan indirebilir.

### Fixed

- **HSM (PKCS#11) imza akışında upstream xipki 1.0.9 bug workaround'u**
(`IaikPkcs11Module.signOnSession`).
  - **Semptom (CI'da gözlenen)**: `XadesSoftHsmVerifierE2ETest` ve
  `SoftHsm2Pkcs11IntegrationTest` testleri `Tests run: 31, Errors: 12`
  deseniyle patlıyordu — N başarılı imza sonrası ardarda
  `CKR_OPERATION_NOT_INITIALIZED` (cascade failure).
  - **Root cause**: `org.xipki:ipkcs11wrapper:1.0.9`
  `[PKCS11Token.opInit()](https://github.com/xipki/ipkcs11wrapper/blob/v1.0.9/src/main/java/org/xipki/pkcs11/wrapper/PKCS11Token.java)`
  yalnızca `CKR_USER_NOT_LOGGED_IN` için re-init yapıyor; diğer tüm
  `PKCS11Exception`'ları **sessizce yutuyor** (`else` dalı yok). Sonuçta
  alttaki `session.sign(data)` çağrısı `C_SignInit` yapılmamış bir
  session üzerinde koşar ve `CKR_OPERATION_NOT_INITIALIZED` döner. Bozuk
  session pool'a geri eklendiği için sonraki sign'lar da aynı şekilde
  fail eder.
  - **Master'da düzeltildi** (`else { throw ex; }`) ama 2024-07-20 sonrası
  yeni release yok; Maven Central'da hâlâ 1.0.9. Upgrade yolu kapalı.
  - **Bizim defensive katman**: `signOnSession` `CKR_OPERATION_NOT_INITIALIZED`
  yakaladığında `token.closeAllSessions()` ile pool'u flush eder (corrupt
  session'lar atılır) ve sign'ı bir kez daha dener. İkinci deneme de
  fail ediyorsa kalıcı bir HSM/driver sorunu var demektir — gerçek hata
  yukarı bırakılır (sessiz başarısızlık üretilmez). Detaylı `WARN` log
  operatöre upstream bug'ı tanıtır.
  - Upstream takip notu `TEST_BACKLOG.md` "Known upstream issues" bölümüne
  eklendi; xipki > 1.0.9 publish edildiğinde workaround kaldırılabilir.

### Added

- `**scripts/run-integration-tests-locally.sh` — Integration testleri yerelde
CI parite modunda koşturucu** (`.github/workflows/integration-tests.yml`
iki job'unun yerel karşılığı).
  - `**--pkcs11`** (default): SoftHSM2 modül auto-detect (macOS Apple Silicon
  `/opt/homebrew/lib/softhsm/libsofthsm2.{so,dylib}`, Intel `/usr/local/`,
  Linux `/usr/lib/`) → `mvn validate` → `mvn test -Dgroups=pkcs11-integration`
  → workflow'un test-count guardrail'leri (6 + 25 iterasyon).
  - `**--verifier-e2e`**: Docker daemon check → GHCR `:main` pull (veya
  `--build-verifier` ile sibling `mersel-dss-verifier-api-java` repo'sundan
  source build) → `mvn test -Dgroups=verifier-e2e -DverifierImage=...`
  → 277 iterasyon guard.
  - `**--all**`: ikisini sırayla; `**--quick**`: count assertion'larını atla
  (hızlı feedback); `**--skip-pull**`: offline koşum.
  - **CI parite**: Workflow'daki `Verify SoftHsm2Pkcs11IntegrationTest`,
  `Verify XadesSoftHsmVerifierE2ETest` ve `Verify expected verifier-e2e test count` step'lerinin assertion'larını birebir uygular — yerelde
  "yeşil ama aslında skip" sessiz başarısızlığı CI'la aynı katılıkta
  yakalanır.
  - **macOS prereq**: `brew install softhsm opensc` + Docker Desktop.
  Linux prereq: `sudo apt-get install -y softhsm2 opensc` + Docker.
- **Run/Debug profilleri — IntelliJ, Cursor, VS Code ve CLI tek-tıkla**
([docs/RUN_PROFILES.md](docs/RUN_PROFILES.md)).
  - **Spring profile katmanları**: `local` (ortak ortam ayarları — network off,
  DEBUG log) + bir alt-profile birleşimi. PFX varyantları: `pfx-kurum01-rsa2048`
  (default), `pfx-kurum02-rsa2048` (sm.gov.tr), `pfx-kurum02-ec384`,
  `pfx-kurum03-rsa2048`, `pfx-kurum03-ec384`. HSM varyantları (OS-spesifik
  PKCS#11 yolu): `mali-muhur-akis-mac`, `mali-muhur-akis-linux`, `mali-muhur-akis-windows`.
  - **IntelliJ/Cursor**: `.run/` klasöründe 11 paylaşımlı run configuration —
  Spring Boot main class, aktif profile ve `WORKING_DIRECTORY=$PROJECT_DIR$`
  önceden set. Geliştirici Run dropdown'undan seçip ▶ veya 🐞 basıyor.
  - **VS Code**: `.vscode/launch.json` + `.vscode/tasks.json` aynı senaryoları
  `vscode-java` debugger ve Maven hedefleri olarak sağlar.
  - **CLI (IDE'siz)**: `scripts/dev-run.sh` (POSIX) ve `scripts/dev-run.bat`
  (Windows) — OSTYPE / uname tabanlı OS auto-detect; HSM senaryosunda
  `CERTIFICATE_PIN` yoksa fail-fast. `./scripts/dev-run.sh list` ile
  yardım çıktısı.
  - PFX dosyaları repo-relatif yolla referans edilir (`resources/test-certs/`);
  macOS / Linux / Windows üçünde de fark gözetmeden çalışır. HSM
  profillerindeki `PKCS11_LIBRARY` default yolu OS-spesifik (AKİS Homebrew
  / apt / Windows installer konvansiyonu).
- **DevOps — Linux SystemD + Windows Service production deployment paketleri**
([devops/systemd/](devops/systemd/), [devops/windows-service/](devops/windows-service/)).
  - **Linux SystemD**: hardened unit dosyası (`NoNewPrivileges`, `ProtectSystem=strict`,
  `PrivateTmp`, `RestrictNamespaces` vb.) + idempotent `install.sh` (signer
  kullanıcısı, dizin yapısı, `EnvironmentFile` 0640) ve `--purge` destekli
  `uninstall.sh`. `MemoryDenyWriteExecute=false` bilinçli (JVM JIT zorunluluğu);
  `PrivateDevices=no` AKİS smart card için açık.
  - **Windows Service**: WinSW (Windows Service Wrapper) XML şablonu +
  `Install-Service.ps1` (WinSW indirme, `.env` parse → XML `<env>` injection,
  NTFS ACL ile XML kilidi, opsiyonel dedicated service account). `SCardSvr`
  bağımlılığı, `delayedAutoStart`, restart-on-failure policy. NSSM alternatifi
  ayrıca README'de dokümante. `Uninstall-Service.ps1` `-KeepLogs` ve `-Purge`
  bayraklarıyla.
  - `**devops/docker/`** modernize edildi: `docker-compose.yml` env bloğu
  `SPRING_PROFILES_ACTIVE`, `XADES_SIGNING_TIME_ZONE`, PKCS#11 grubu,
  `TRUSTED_ROOT_CERT_FOLDER_PATH` ve `CORS_ALLOWED_ORIGINS`'ı kapsıyor;
  README'deki var olmayan `start-test-kurum{1,2,3}` dosya referansları
  gerçekteki parametreli `start-test-kurum.{sh,ps1}` script'iyle hizalandı.
  - `**devops/README.md`** sıfırdan yazıldı: 4-yollu deployment karar matrisi
  (Docker / SystemD / Windows / K8s), Spring profile vs ENV variable ayrımı,
  sertifika yerleşim konvansiyonu, ortak env variable tablosu.
- **XAdES `<SigningTime>` timezone parametrik hâle getirildi**
([issue #7](https://github.com/mersel-dss/mersel-dss-server-signer-java/issues/7)).
  - Default `+03:00` (TÜBİTAK MA3 referans çıktısı ile birebir aynı; İMZAGER
  lokal gösterimi ile tutarlı). DSS upstream her zaman UTC (`Z`) basıyordu,
  bu da TÜBİTAK ekosistemindeki imzalarla diff üretiyordu.
  - `XADES_SIGNING_TIME_ZONE` ENV ile değiştirilebilir: `Z`/`UTC` (ETSI saf
  yorumu), `+03:00` (default), `+05:30` (ileride farklı pazar) veya
  `Europe/Istanbul` (IANA bölge) kabul edilir. Geçersiz string fail-fast.
  - Yeni override: `XAdESSignatureBuilder#incorporateSigningTime()` artık
  `XAdESSigningTimeZoneHolder.formatSigningTime()` üzerinden gider; eski
  `DomUtils.createXMLGregorianCalendar()` çağrısı OVERRIDE_DSS marker'ı ile
  kapatıldı. Detay: `DSS_OVERRIDE.md` bölüm 7a.
  - Yeni testler: `XAdESSigningTimeZoneHolderTest` (parse/format birim),
  `XAdESSigningTimeFormatTest` (uçtan uca XML çıktısı doğrulaması).

### Fixed

- `**CertificateLifecycleNegativeE2ETest` — 24/24 PASS, 0 SKIP** (default GHCR
`:main` image ile, flag gerekmiyor).
  - **Root cause** (önce gözlemlenen): `mersel-dss-verifier-api` GHCR `:main`
  image fat-jar içinde `dss-cms-object` + `dss-pades-pdfbox` JAR'ları VAR
  ama runtime'da DSS `ServiceLoader` provider'ı bulamıyordu — Spring Boot
  fat-jar packaging stale cache şüphesi
  ([verifier#2](https://github.com/mersel-dss/mersel-dss-verifier-api-java/issues/2)).
  - **Fix**: `workflow_dispatch` ile `docker-publish.yml` yeniden tetiklendi;
  GHCR fresh image push (sha256:65764b48..., 1 dk 1 sn). Eski stale image
  silinip fresh pull edildikten sonra `mvn test` (flag yok) **24/24 PASS**.
  - **Sertifikalandı çıktılar** (auditor sidecar'ları
  `target/signed-artifacts/{xades,cades,pades,wssecurity}-negative-cert/`):
    - REVOKED   × tüm formatlar → `INDETERMINATE / REVOKED_NO_POE`
    - EXPIRED   × tüm formatlar → `INDETERMINATE / CERTIFICATE_CHAIN_GENERAL_FAILURE`
    - SUSPENDED × tüm formatlar → `INDETERMINATE / TRY_LATER`
  - Skip-tolerant test design (`Assumptions.assumeTrue(false)`) korundu;
  ileride benzer image transition'larında CI kırılmaz.

> Sonraki sürüm için açık iş kalemleri buraya eklenir. **0.4.0**'da
> teslim edilen tüm değişiklikler aşağıdaki versiyon bölümüne dökümante
> edilmiştir.

---

## [0.4.0] - 2026-05-18

> **🎯 Sürüm Vizyonu — "Kanıt-Temelli İmza Hattı"**
>
> 0.4.0, signer'ın bir "imzala-ve-bırak" servisinden, her imzanın yanına
> bağımsız doğrulanabilir kanıt iliştiren bir **kanıt zinciri (evidence
> chain)** mimarisine geçişini teslim eder. Üç yapısal hamle ile:
>
> 1. **Imza arka ucu modernize edildi** — Sun PKCS#11'in
>   sertifika listeleme / alias çözümleme uyumsuzluklarını gideren
>    **IAIK native PKCS#11 wrapper** entegre edildi; tek soyutlama (`SigningBackend`)
>    arkasında JCA (PFX) ve PKCS#11 (HSM) eşit yurttaş.
> 2. **Doğrulanabilirlik kanıt seviyesine taşındı** — Default suite 326,
>   `verifier-e2e` suite 290+ teste çıktı; her senaryonun **imzalı bytes**'ı
>    ve **verifier-api JSON yanıtı** `target/signed-artifacts/` altına
>    yazılıyor. Adobe Reader, EU DSS Demo, xmlsec1 gibi üçüncü taraf
>    araçlarla aynı çıktıyı tekrar doğrulayabilirsiniz.
> 3. **Kanıt site'ı kamuya açıldı** — Her `main` push'unda
>   `[mersel-dss.github.io/mersel-dss-server-signer-java/](https://mersel-dss.github.io/mersel-dss-server-signer-java/)`
>    adresinde Allure raporu (her test attachment'ında imzalı dosya +
>    verifier response), JaCoCo coverage, OpenAPI snapshot ve OWASP
>    Dependency-Check raporu otomatik yayımlanır.
>
> Bu yaklaşım, geleneksel bulut çözümlerinin "siyah kutu — sadece success
> mesajı" imza akışına karşı somut bir alternatif: **her imza, üretildiği
> anda mahkemede sunulabilir kanıtla birlikte doğar.** Mali müşavir veya
> auditor, signer'a iman etmek zorunda kalmadan imzanın validitesini
> bağımsız bir doğrulayıcıyla teyit edebilir.

### Highlights (öne çıkanlar)


| #   | Başlık                                                                          | Etki                                                                                                                                                                                                                                                                  | Anahtar dosyalar                                                                                     |
| --- | ------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| 1   | 🔐 **Native PKCS#11 (IAIK) backend + `SigningBackend` soyutlaması**             | KamuSM, SafeNet ProtectToolkit, Luna gibi HSM'lerde alias-keşif sorunları çözüldü. CAdES/PAdES/XAdES/WSS dört format da JCA ile aynı API yüzeyinden HSM ile çalışır.                                                                                                  | `services/keystore/iaik/*`, `models/{Jca,Pkcs11,SigningBackend}*`                                    |
| 2   | 🧪 **Test envanteri ~290 E2E + 326 default + 31 PKCS#11 = 600+ teste yükseldi** | XAdES/CAdES/PAdES/WSS dört formatta E2E roundtrip; Sun PKCS#11 (PfxBackedPkcs11Signer) ve gerçek SoftHSM2 ile çift-rota.                                                                                                                                              | `src/test/java/.../e2e/verifier/*`, `testsupport/*`                                                  |
| 3   | 📤 **Signed-artifact export + `.verify.json` sidecar**                          | Her test imzalı bytes'ı + verifier-api JSON yanıtını `target/signed-artifacts/<format>/<method>__<scenario>.<ext>` formatında diske yazar. Üçüncü taraf araçlarla cross-validation.                                                                                   | `testsupport/SignedArtifactExporter.java` (895 satır)                                                |
| 4   | 🌐 **Public Evidence Site (GitHub Pages)**                                      | Her `main` push'unda landing + Allure + JaCoCo + Swagger UI snapshot + OWASP raporu otomatik yayımlanır. Trend grafiği için Allure history cache.                                                                                                                     | `.github/workflows/publish-pages.yml`, `docs/landing/index.html`                                     |
| 5   | 🛡️ **XML saldırı yüzeyi tamamen kapatıldı**                                    | `SecureXmlFactories` ile XXE, SSRF-via-XXE, Billion Laughs, XInclude, XSLT injection vektörleri default factory'ler yerine kullanılır. Negatif fixture + parser testleri regresyon koruması.                                                                          | `util/xml/SecureXmlFactories.java`, `test-fixtures/negative/*`                                       |
| 6   | 📦 **Test fixture katalogu**                                                    | XAdES: 12 varyant (BOM, mixed-newlines, unicode-emoji, CDATA, foreign-NS, comments, large 5 MB, e-Fatura, e-İrsaliye, e-Müstahsil, EArchive, HR-XML). PAdES: 4 PDF (e-Fatura görsel, Türkçe karakter, A3 landscape, 50 sayfa). WSS: 9 SOAP envelope. CAdES: 4 binary. | `resources/test-fixtures/*`                                                                          |
| 7   | 🐳 **SoftHSM2 / PKCS#11 entegrasyon pipeline**                                  | Gerçek HSM ile sign+verify roundtrip; opt-in `@Tag("pkcs11-integration")` suite. Native bağımlılık (softhsm2, opensc) workflow'unda kurulur.                                                                                                                          | `devops/docker/Dockerfile.pkcs11-tests`, `.github/workflows/integration-tests.yml`                   |
| 8   | 🛠️ **Geliştirici ergonomisi**                                                  | `serve-pages-locally.sh` ile Pages workflow'u local'de birebir çalışır (flag'lerle dakika cinsinden seçilebilir kapsam). Fixture üretici Python script'leri (`scripts/generate-*-fixtures.py`). README rozetleri + Evidence Site linki.                               | `scripts/serve-pages-locally.sh`, `scripts/generate-*.py`                                            |
| 9   | 🔧 **Production HTTP yüzeyi sertleşti**                                         | `415 WRONG_CONTENT_TYPE` mapping (multipart olmayan istekler için), multipart limit contract testleri, semaphore concurrency davranışı testlenir hale geldi.                                                                                                          | `api/GlobalExceptionHandler.java`, `MultipartLimit*Test`, `SignatureServiceSemaphoreConcurrencyTest` |
| 10  | 🗑️ **Eski bağımlılık yükü temizlendi**                                         | `src/main/lib/sunpkcs11.jar` ve `mvn install:install-file` hook'u kaldırıldı; `resources/test-documents/EFATURA.xml` yerini `resources/test-fixtures/xades/efatura.xml`'e bıraktı.                                                                                    | (silindi)                                                                                            |


---

### Added

#### 🔐 Mimari — Imza arka ucu soyutlaması

- **Native IAIK PKCS#11 entegrasyonu** — Sun PKCS#11'in alias-keşif
sorunları (SafeNet ProtectToolkit, Luna, bazı KamuSM token'ları)
yerine `org.xipki:ipkcs11wrapper` (IAIK PKCS#11 Wrapper 1.6.8 kod
tabanından üretilmiş, aktif sürdürülen halefi) üzerinden doğrudan
PKCS#11 API'sine geçildi. Yeni paket: `src/main/java/io/mersel/dss/signer/api/services/keystore/iaik/`.
  - `IaikPkcs11Module` — singleton bean, Cryptoki lifecycle sahibi.
  - `IaikPkcs11Signer`, `IaikContentSigner` — DSS 2-aşamalı imza API'siyle uyumlu signer.
  - `IaikSignatureMechanisms` — PKCS#11 mekanizma enum mapping (CKM_*).
  - `Pkcs11EcdsaSignatureEncoder` — ECDSA raw `r||s` ↔ DER SEQUENCE dönüşümleri.
  - `Pkcs1DigestInfo` — DigestInfo wrapping (CKM_RSA_PKCS yolunda explicit OID).
  - `Pkcs11Signer` — generic alt-sınıf, format-agnostic.
- `**SigningBackend` interface + iki uygulama** (`models/`) — CAdES/PAdES/XAdES/WSS
servisleri artık `SigningBackend` üzerine bina edilmiştir; `JcaSigningBackend`
(PFX/PKCS#12) ve `Pkcs11SigningBackend` (HSM) aynı sözleşmeye uyar.
`SigningMaterial.getBackend()` doğru implementasyonu döndürür; format
servislerinde `instanceof` kontrolü yok.
- `**SigningMaterialContentSigner`** — BouncyCastle `ContentSigner`
arabirimini backend-agnostic olarak gerçekler; CAdES için CMS
imza yolunda kullanılır.
- `**X509ExtensionInspector`** — sertifika seçimi için Key Usage,
Extended Key Usage, Subject Alt Name, OID listesi ve policies
inspect eder; HSM sertifika keşfinde tek-eşleşme garantisini
yapısal olarak doğrular.
- `**SignatureAlgorithmResolverService**` — PKCS#11 yolu için
digestAlgorithm × keyAlgorithm matrisinden CKM_* mekanizmaya
çözüm yapar; bilinmeyen kombinasyonda **sessiz fallback yerine
açık `SignatureException*`* atar (önceki PSS-RSA bug'ının
kök çözümü).

#### 🧪 Test envanteri — 600+ test koşumu

> **Suite sayıları** (turn başlarındaki ~115 testten itibaren büyük sıçrama):
>
>
> | Suite                                                | Önce (0.3.0) | Sonra (0.4.0) | Artış    |
> | ---------------------------------------------------- | ------------ | ------------- | -------- |
> | `default` (`mvn test`)                               | ~115         | **326**       | +211     |
> | `verifier-e2e` (`-Dgroups=verifier-e2e`)             | 0            | **~290**      | +290     |
> | `pkcs11-integration` (`-Dgroups=pkcs11-integration`) | 0            | **31**        | +31      |
> | **Toplam koşulabilir test**                          | ~115         | **~647**      | **+532** |
>

- **🆕 E2E verifier-api suite** (16 yeni test sınıfı `src/test/java/io/mersel/dss/signer/api/e2e/verifier/`)
— Testcontainers ile `ghcr.io/mersel-dss/mersel-dss-verifier-api-java:main`
ayağa kaldırılır; imzalanmış her bayt verifier-api'ye POST edilip
`result.isValid()=true` + `indication=TOTAL_PASSED` beklenir:
  - **CAdES**: `CAdESSignAndVerifyE2ETest` (20), `CAdESBinaryVariationsE2ETest`
  (4 fixture × attached/detached), `CAdESTamperedE2ETest` (1).
  - **PAdES**: `PAdESSignAndVerifyE2ETest` (10), `PAdESDocumentVariationsE2ETest`
  (4 PDF), `PAdESRuntimeScenariosE2ETest` (cosign + encrypted + form-fields + attachment),
  `PAdESTamperedE2ETest` (1, ByteRange byte flip).
  - **XAdES**: `XAdESSignAndVerifyE2ETest` (130 = 5 PFX × 2 backend × 12 fixture
    - 10 generic `OtherXmlDocument`), `XAdESNegativeE2ETest` (3 — wrap-attack +
    tampered-after-sign + sig-value bit-flip), `XAdESSha1LegacyE2ETest` (1, legacy
    crypto policy), `XadesSoftHsmVerifierE2ETest` (25, opt-in `pkcs11-integration`).
  - **WS-Security**: `WsSecuritySignAndLocalVerifyE2ETest` (90 = 5 PFX ×
  2 backend × 9 SOAP envelope), `WsSecurityContractE2ETest` (3 yapısal
  kontrat: wsu:Id override, WS-Addressing preservation, Security
  append-not-overwrite), `WsSecurityConcurrencyContractTest` (10 paralel
  imza).
  - **Smoke**: `VerifierContainerSmokeTest` (container health), `AbstractVerifierE2ETest`
  base, `VerifierApiClient`, `VerifierApiContainer` (image override
  `-DverifierImage=<tag>` ile).
- **🆕 Service-layer + contract testleri** — production sınıflarının davranış
invariantları izole edildi:
  - WS-Security: `WsSecuritySignatureServiceTest` (yeni),
  `WsSecurityHashAlgorithmParametrizedTest` (SHA-256/384/512 × RSA/ECDSA),
  `WsSecurityEnvelopeShapeParityTest` (signer/verifier envelope shape eşitliği).
  - CAdES: `CAdESSignatureServiceTest` genişletildi (attached + detached + empty input).
  - PAdES: `PAdESSignatureServiceTest` (yeni — ByteRange + imza placement davranışı).
  - XAdES: `XAdESEcdsaSignatureFormatTest` (5 PFX × ECDSA, plain `r||s` regresyonu).
  - `CryptoSignerServiceTest` — backend-dispatch matrisini izole eder.
  - `CertificateInfoServiceTest`, `X509ExtensionInspectorTest`,
  `SigningMaterialTest` — sertifika introspection ve materyal seçimi.
  - `KeyStoreLoaderServiceContractTest` — keystore yükleme davranışı (PFX, PKCS#11).
  - `TimestampServiceContractTest` — RFC 3161 TSP davranışı.
  - `MultipartConfigSanityTest`, `MultipartLimitHttpContractTest` —
  multipart sınırı + 415 mapping kontratı.
  - `SignEndpointHttpEnvelopeContractTest`, `PadesControllerTest` —
  HTTP yüzey kontratı.
  - `SignatureServiceSemaphoreConcurrencyTest` — eş zamanlı imzalama
  semaphore davranışı.
- **🆕 IAIK PKCS#11 contract suite** — `services/keystore/iaik/`
altındaki 8 yeni test: `IaikContentSignerTest`, `IaikPkcs11ModuleContractTest`,
`IaikPkcs11ModuleKeyBindingTest`, `IaikPkcs11SignerTest`,
`IaikSignatureMechanismsTest`, `Pkcs11EcdsaSignatureEncoderTest`,
`Pkcs1DigestInfoTest`, `SoftHsm2Pkcs11IntegrationTest` (opt-in).
- **🆕 Test support paketi** (`testsupport/`):
  - `PfxBackedPkcs11Signer` — Sun PKCS#11 olmadan HSM davranışını
  simüle eder; PFX'i `IaikPkcs11Signer` arayüzü ile sarar. E2E
  suite'in JCA ve PKCS#11 yollarını aynı PFX ile koşturmasını sağlar.
  - `SignedArtifactExporter` — JUnit 5 extension, **895 satır**, aşağıda detay.
  - `SoftHsm2TestSupport` — `softhsm2-util` çıktısını parse eder,
  token init + key import için CI-uyumlu.
- **🆕 E2E fixture yardımcıları** (`e2e/verifier/`): `E2eFixtures`,
`E2eSigningBackend`, `E2eSigningMaterialFactory`, `PfxTestKey`
(5 PFX × algo enum), `CadesBinaryFixture`, `PadesDocumentFixture`,
`SoapEnvelopeFixture`, `XadesDocumentFixture`, `WsSecurityLocalXmlDsigVerifier`.

#### 📤 Signed-artifact export sistemi

- `**SignedArtifactExporter`** (`testsupport/SignedArtifactExporter.java`) —
JUnit 5 extension, `**@ExtendWith(SignedArtifactExporter.class)`** veya
`@RegisterExtension` ile aktif edilir; her test imzaladığı bytes'ı
`target/signed-artifacts/<format>/<methodName>__<sanitize(label)>.<ext>`
yoluna semantic adıyla yazar.
  - **Yeni isimlendirme**: class prefix kaldırıldı, sade
  `<methodName>__<PFX_ALGO_BACKEND_FIXTURE>` formatı; örnek:
  `xades/xadesFixtureRoundtripIsValid__KURUM01_RSA2048_PFX_JCA_EFATURA.xml`,
  `pades-negative/byteRangeBitFlipFailsVerification__byte100-bitflip.pdf`.
  - **Otomatik root purge**: her `mvn test` koşumu başlangıcında
  (ilk export çağrısında) `target/signed-artifacts/` tamamen silinir
  → klasörde **yalnızca son run'un** çıktıları kalır; eski
  runlardan hayalet dosyalar birikmez. `-Dsigned.artifacts.purge=false`
  ile incremental debug için kapatılabilir.
  - `**.verify.json` sidecar** — `exportWithVerification(...)`
  çağrısı verifier-api yanıtını flatten halde aynı dizine yazar
  (örn. `efatura.xml` yanına `efatura.verify.json`). Auditor
  imzalı dosyayı ve aynı anda doğrulayıcının kararını yan yana
  görür.
  - **Allure attachment entegrasyonu** — Her test detayında imzalı
  dosya + verifier response Allure raporuna otomatik gömülür;
  Evidence Site'da test card'ı tıklandığında attachment listesi
  açılır.
  - **Üçüncü taraf cross-validation amacı**: Adobe Acrobat Reader
  (PAdES), EU DSS Demo Webapp (XAdES/CAdES), `xmlsec1` (XML-DSig),
  `openssl smime` (CMS/CAdES), SoapUI (WSS) ile aynı çıktının
  bağımsız doğrulanması için.
- **Toggle'lar**: `-Dsigned.artifacts.export=false` (kapatır),
`-Dsigned.artifacts.dir=/abs/path` (alternatif konum),
`-Dsigned.artifacts.purge=false` (paralel forkCount > 1 için).

#### 🌐 Public Evidence Site (GitHub Pages)

- `**.github/workflows/publish-pages.yml`** — Her `main` push'unda
ve manuel `workflow_dispatch` ile çalışır. URL yapısı:
  - `/` — Tailwind CDN ile özel landing (build #, commit SHA, run timestamp,
  test count, coverage % rozetleri).
  - `/test-report/` — Allure Report (Suites / Behaviors / Categories / Trend
  grafiği). Her test attachment'ında imzalı dosya + `.verify.json`.
  - `/coverage/` — JaCoCo HTML (line + branch coverage).
  - `/openapi/` — Swagger UI 5.17.14 standalone bundle + canlı Spring Boot'tan
  çekilmiş `openapi.json` snapshot'ı.
  - `/security/` — OWASP Dependency-Check HTML rapor.
- `**docs/landing/index.html`** — Framework-free (sadece Tailwind CDN +
Inter/JetBrains Mono fontları); build metadata `envsubst` veya
Python fallback ile inject edilir. Auditor-friendly: hızlı yükleme,
WCAG-temiz kontrast, JS framework yok.
- **Allure history cache** — `actions/cache@v4` ile `.allure-history/`
klasörü her run sonunda saklanır; bir sonraki run trend grafiğini
yeniden inşa eder.
- **NVD cache** — OWASP Dependency-Check'in ilk koşumdaki ~5 dk
download'u `actions/cache` ile aydan aya yenilenir.
- **Fail-tolerant publish stratejisi**: Test fail olsa bile Pages
yayımlanır (`continue-on-error: true`) — fail kanıtı da değerlidir;
yalnızca infra hatası (checkout/JDK/Maven) durumunda deploy skip
edilir. README rozetleri (CI / Integration Tests / Publish Evidence
Pages) eklendi.

#### 🛠️ Geliştirici ergonomisi

- `**scripts/serve-pages-locally.sh`** — Pages workflow'unun birebir
aynısını local'de üretir ve `python3 -m http.server 8765` üzerinden
açar. Flag'ler kapsamı dakikalardan dakikalara değişen modlara böler:
  - `--fast` → unit testler + Allure + JaCoCo + landing (≈ 2 dk).
  - `--skip-tests` → mevcut `target/`'i kullan (sanity preview).
  - `--skip-e2e`, `--skip-owasp`, `--skip-openapi`, `--no-serve`, `--port`.
  - Landing template injection için `envsubst` (linux) veya
  `python3` (macOS) fallback.
- `**scripts/generate-cades-fixtures.py`** ve
`**scripts/generate-xades-fixture-variants.py**` — Test fixture'larının
deterministic üretimi; git history'de "neden bu byte" şeffaf kalır.
CAdES: `sample.txt` UTF-8 Türkçe, `sample.bin` SHA-256 zinciri
(seed `mersel-cades-sample-bin-v1`), `empty.bin`, `utf16-text.txt`
(UTF-16 BE + BOM). XAdES: `efatura.xml`'den 5 varyant
(mixed-newlines, CDATA, comments, foreign-NS prefix, unicode-emoji).
- `**src/main/resources/application-local.properties**` — Local/CI
snapshot için Spring Boot dev profili: test PFX yolu + dummy PIN
  - offline TSP/chain. OpenAPI snapshot job'ı bu profile ile boot eder;
  production'a sızmaz (profile aktif edilmediğinde property'ler
  yüklenmez).
- `**TEST_BACKLOG.md**` — 805 satırlık kapsamlı backlog (suite
envanteri, fixture matrisi, tasarım notları, Public Evidence Site
ve signed-artifact export bölümleri); GitHub Issues'a 1:1
dönüştürülebilir.

#### 🛡️ Güvenlik — XML saldırı yüzeyi

- `**SecureXmlFactories**` (`util/xml/SecureXmlFactories.java`) —
Production kodunda `DocumentBuilderFactory.newInstance()` veya
`TransformerFactory.newInstance()` doğrudan ÇAĞRILMAZ; bu sınıfın
hardened factory metotları kullanılır. Kapatılan vektörler:
  - **XXE** (`<!ENTITY xxe SYSTEM "file:///etc/passwd">`),
  **SSRF-via-XXE** (`SYSTEM "http://169.254.169.254/..."`),
  **Billion Laughs** (10^9 entity expansion DoS),
  **XInclude** (`xi:include`), **XSLT injection** (external DTD/stylesheet).
  - `disallow-doctype-decl=true`, `external-general-entities=false`,
  `external-parameter-entities=false`,
  `XMLConstants.FEATURE_SECURE_PROCESSING=true`.
- **Negatif fixture'lar** — `resources/test-fixtures/negative/`:
`xxe-attack.xml` (gerçek XXE payload), `billion-laughs.xml`
(9-seviye nested entity, 10^9 expansion).
- **Parser-level negatif testler** (default suite) — `XmlSecurityTest`,
`SecureXmlFactoriesTest`: `SAXParseException` ile reddediliyor mu,
süre < 5s assertion'ı.

#### 📦 Test fixture katalogu

> Tek source-of-truth fixture enum'ları (`XadesDocumentFixture`,
> `PadesDocumentFixture`, `CadesBinaryFixture`, `SoapEnvelopeFixture`)
> her formatta tüm varyantları metadata + Javadoc'lu olarak indeksler.

- **XAdES** (`resources/test-fixtures/xades/`, 12 fixture × 5 PFX × 2 backend = 120 senaryo + 10 generic):
`efatura.xml`, `eirsaliye.xml`, `emustahsil.xml` (UBL e-Belge);
`earsiv-raporu.xml` (EArchive raporu); `hrxml.xml` (HR-XML 3.x); `efatura-large.xml`
(~5 MB); `efatura-with-bom.xml` (UTF-8 BOM); `efatura-mixed-newlines.xml`
(CRLF + LF karışık); `xml-with-cdata.xml`; `xml-with-comments.xml`;
`xml-foreign-namespace-prefix.xml` (cbc → tcbc, cac → tcac); `efatura-unicode-emoji.xml`
(🚀 4-byte UTF-8 surrogate pair + CJK `中文` + Latin extended `ñoño`).
- **PAdES** (`resources/test-fixtures/pades/`, iText 5.4.1 + Cp1254):
`efatura-pdf.pdf` (3 sayfa, UBL-benzeri görsel e-Fatura),
`turkish-chars.pdf` (Cp1254 Türkçe alfabe), `landscape-a3.pdf`
(1190.55 × 841.89 pt, 8-kolon tablo), `large-50pages.pdf`
(`.gitignore`'da; CI'da generator ile üretilir).
- **CAdES** (`resources/test-fixtures/cades/`, 4 fixture × attached/detached):
`sample.txt` (UTF-8 Türkçe, 2.4 KB, diakritik yoğun),
`sample.bin` (deterministic random 10 KB, SHA-256 seed
`mersel-cades-sample-bin-v1`), `empty.bin` (0 byte, RFC 5652 §5.3
graceful kontratı), `utf16-text.txt` (UTF-16 BE + BOM).
- **WS-Security** (`resources/test-fixtures/wssecurity/`, 9 envelope):
`soap-1.1.xml`/`soap-1.2.xml` (baseline), `gib-efatura-soap.xml`
(GİB Mali Mühür request paritesi, multi-NS + Türkçe + `xsi:type`),
`soap-with-wsa.xml` (WS-Addressing header'ları, SOAP 1.2),
`soap-with-existing-wsu-id.xml` (client-provided `wsu:Id` override),
`soap-multibody.xml` (3 ayrı operation child),
`soap-large-50kb.xml` (120 child item, c14n perf vektörü),
`soap-mtom-xop.xml` (`xop:Include cid:...`),
`soap-with-existing-security-header.xml` (append-not-overwrite kontratı).

#### 🐳 SoftHSM2 / PKCS#11 entegrasyon pipeline

- `**devops/docker/Dockerfile.pkcs11-tests`** — Ubuntu tabanlı,
`softhsm2`, `opensc`, `libsofthsm2.so` ile birlikte JDK 8 +
Maven; lokal `docker run` ile SoftHSM2 PKCS#11 testlerini koşturur.
- `**scripts/run-pkcs11-tests.sh`** — Docker'la SoftHSM2 PKCS#11
test suite'ini lokal makinede çalıştırır; native bağımlılık olmadan
developer experience'ı korur.
- `**.github/workflows/integration-tests.yml**` — Yeni workflow,
iki job: `verifier-e2e` (~290 sign+verify roundtrip) ve
`pkcs11-integration` (gerçek SoftHSM2 + verifier roundtrip,
Linux runner). Native eksikliği yüzünden sessiz "skip → yeşil"
riskine karşı her job'da explicit test-count guard.
- `**@Tag("pkcs11-integration")` opt-in suite** — `SoftHsm2Pkcs11IntegrationTest`
(5 sequential + 1 paralel sign) ve `XadesSoftHsmVerifierE2ETest`
(5 PFX × 5 XAdES fixture = 25 iterasyon).

#### 🔧 Production-side iyileştirmeler

- `**GlobalExceptionHandler` — 415 mapping**: `HttpMediaTypeNotSupportedException`
→ `WRONG_CONTENT_TYPE` (`415 UNSUPPORTED_MEDIA_TYPE`). Client
`application/json` veya `text/plain` ile POST attığında "İstek
multipart/form-data ile gönderilmeli" mesajı; önceki generic
500 yerine doğru HTTP kontratı.
- `**CryptoSignerService` — backend dispatch**: `SigningMaterial.getBackend()`
üzerinden `JcaSigningBackend` veya `Pkcs11SigningBackend`'e yönlendirir;
servis kodunda `instanceof` veya `switch` yok.
- `**CertificateInfoController` + `CertificateInfoService` API**:
Sertifika listeleme ve introspection genişletildi; OID, Key Usage,
Extended Key Usage, Policies, SAN bilgileri.
- `**XAdESDocumentPlacementService`** — Yeni XAdES placement
stratejisi sınıfı; UBL e-Belge / EArchive / e-Bilet için doğru
yerleştirme noktasını tek dosyada karar verir.
- `**XmlProcessingService` (XAdES) refactor** — XML parsing,
c14n preparation ve namespace handling tek hat.
- `**AbstractKamuSMXmlDepoResolver` + `Utilities` refactor** — Kod
netliği ve test edilebilirlik.
- `**KeyStoreLoaderService`, `KeyStoreProvider`, `PKCS11KeyStoreProvider` refactor**
— Dual-backend desteği; HSM kaynaklı sertifika ve key resolution.
- `**SignatureApplication`** — Application bootstrap iyileştirmeleri,
`--list-certificates` CLI argümanı ile uyum.

#### 📦 Maven build pipeline

- `pom.xml` yeni plugin/dependency'ler:
  - `**io.qameta.allure:allure-junit5` 2.27.0** + `**allure-maven` 2.12.0**
    - AspectJ Weaver 1.9.21 (test scope, javaagent ile inject).
    `@Epic` / `@Feature` / `@Story` / `@Severity` / `Allure.addAttachment()`
    annotation'ları runtime'da yakalanır.
  - `**org.jacoco:jacoco-maven-plugin` 0.8.11** — `prepare-agent` +
  `report` execution. Surefire `argLine` JaCoCo agent'ı + AspectJ
  weaver ile birlikte.
  - `**org.owasp:dependency-check-maven` 9.2.0** — `failBuildOnCVSS=11`
  (info-only), NVD veri tabanı `~/.m2/repository/org/owasp/dependency-check-data`'da
  cache'lenir.
  - `**org.xipki:ipkcs11wrapper` 1.0.9** — IAIK PKCS#11 wrapper.
  - Surefire `<argLine>` güncellemesi: `@{argLine}` (JaCoCo agent inherit)
    - `-XX:-OmitStackTraceInFastThrow` + `-javaagent:aspectjweaver`.
- `.gitignore` build artifact'ları için genişletildi:
`target/signed-artifacts/`, `signed-artifacts/`, `pages-output/`,
`openapi-snapshot/`, `.allure-history/`, `.allure/`,
generator-only fixture'lar (`large-10mb.bin`, `large-50pages.pdf`).

#### 🧪 Önceki turn'ların öne çıkan eklemeleri (turn-3 → turn-8, "Unreleased" altında biriken)

> Aşağıdaki maddeler 0.4.0 release'in temellerini oluşturan
> incremental katmanlardır; tarih sırasıyla:

- **🧪 CAdES + PAdES Fixture Varyasyon Suite'leri Eklendi (8 yeni senaryo)** —
Mevcut `CAdESSignAndVerifyE2ETest` / `PAdESSignAndVerifyE2ETest` PFX × backend
matrisleri (20 + 10 senaryo) tek programatik girdi üzerinde koşar; yeni
`**CAdESBinaryVariationsE2ETest`** ve `**PAdESDocumentVariationsE2ETest`**
fixture-içerik çeşitliliğini kapsar. Smart matrix: tek RSA PFX × JCA backend
(key-tipinden bağımsız → CI yükü minimal).
  - **CAdES fixture'ları** (4, `resources/test-fixtures/cades/`):
    - `sample.txt` (2.4 KB) — UTF-8 Türkçe gerçekçi metin, diakritik yoğun
    (~405 byte multibyte). Production "açıklama / sözleşme gövdesi" benzeri.
    - `sample.bin` (10 KB) — deterministic random binary, SHA-256 zinciri
    (seed `mersel-cades-sample-bin-v1`). Reproducible.
    - `empty.bin` (0 byte) — edge-case. Test `assertEmptyInputHandledGracefully`
    iki davranışı kabul eder: RuntimeException (defansif) **veya** boş
    ContentInfo (RFC 5652 §5.3 spec-uyumlu, DSS 6.x default). Build kırıcı
    değil; log üzerinden hangi davranış gözlendi rapor eder.
    - `utf16-text.txt` (1.4 KB) — UTF-16 BE + BOM (`FE FF`) Türkçe text.
    Signer'ın byte-stream-agnostic davranışı (encoding sniff yok) kontratı.
  - **PAdES fixture'ları** (4, `resources/test-fixtures/pades/`, iText 5.4.1 +
  Cp1254 ile programatik üretildi; generator class çalıştırılıp silindi —
  `commit_only` strategy):
    - `efatura-pdf.pdf` (3.7 KB, 3 sayfa) — UBL-benzeri görsel e-Fatura
    (başlık + satıcı/alıcı + kalemler tablosu + tutar özeti, Türkçe + ₺).
    Multi-page ByteRange coverage testi.
    - `turkish-chars.pdf` (2.4 KB) — Cp1254 Türkçe alfabe yoğun gövde.
    - `landscape-a3.pdf` (2.6 KB) — A3 landscape (1190.55 × 841.89 pt) +
    8-kolon geniş tablo. Visible signature hazırlığı.
    - `large-50pages.pdf` (22 KB, 50 sayfa) — page-count regresyon vektörü;
    PDF compression sayesinde küçük boyut.
  - **Test sınıfları**:
    - `CAdESBinaryVariationsE2ETest` (4 senaryo, attached mode) — PDF magic
    byte sanity, signed bytes > input invariant'ları, EMPTY_BIN graceful
    kontratı.
    - `PAdESDocumentVariationsE2ETest` (4 senaryo) — `%PDF-` magic byte
    sanity, signed PDF orijinalden büyük olmalı, verifier roundtrip VALID.
  - **CI etkisi**: verifier-e2e 260 → **268** (`expected=268` test-count
  guard güncellendi).
  - **Temizlik**: önceki turn'dan yarım kalmış `PdfFixtureGenerator`,
  `CAdESBinaryFixturesE2ETest`, `PAdESDocumentFixturesE2ETest` ve
  kullanılmayan 5 PDF (with-form-fields, with-attachment, scan-image-only,
  already-signed, encrypted-userpassword) + 2 CAdES fixture (docx-sample,
  zip-archive) silindi. Kullanıcı kararı: `commit_only`, sadece bu turda
  üretilenler.
- 🧪 **Negatif Test Suite Eklendi (8 senaryo)** — "verifier yanlış yere
ses çıkarmıyor" kontratını kapatan 4 yeni test sınıfı + 2 statik fixture.
Hibrit fixture stratejisi:
  - **Statik commit** (parser-level):
    - `resources/test-fixtures/negative/xxe-attack.xml` — `<!ENTITY xxe SYSTEM "file:///etc/passwd">` payload'ı.
    - `resources/test-fixtures/negative/billion-laughs.xml` — 9-seviye
    nested entity, 10^9 expansion (DOS).
  - **Runtime üretim** (sign+tamper+verify-must-fail) — cert expire
  olduğunda kırılmayan, sign akışını canlı her CI'da koşturan strateji.
  - **Yeni test sınıfları**:
    - `XmlSecurityTest` (default suite, +2): `SecureXmlFactories`
    DOCTYPE'ı `SAXParseException` ile reddediyor mu? Süre < 5s
    assertion'ı zayıf parser flag'lerine karşı koruma.
    - `XAdESNegativeE2ETest` (verifier-e2e, 3): wrap-attack (DOM'a
    yabancı element enjeksiyon → reference digest mismatch),
    tampered-after-sign (cbc:UUID text mutate), signature-value
    bit-flip (kripto verify fail). Her testin pre-tamper VALID
    baseline'ı sahte-pozitiften korur.
    - `PAdESTamperedE2ETest` (verifier-e2e, 1): PDF byte[100] flip
    (ByteRange dahilinde) → `signatureIntact=false`.
    - `CAdESTamperedE2ETest` (verifier-e2e, 1): detached CMS
    orijinal payload byte flip; `.p7s` ve cert sağlam ama digest
    mismatch.
    - `XAdESSha1LegacyE2ETest` (verifier-e2e, 1): DSS XAdESService'i
    DigestAlgorithm.SHA1 ile DOĞRUDAN çağırıp (signer servisi bypass —
    production servisi zaten SHA-1 üretmez) verifier crypto policy
    davranışını test eder. Üç senaryo: reject / warn / sessiz-trust;
    üçüncüsü = fail (regresyon).
  - **CI etkisi**: default suite 279 → 281; verifier-e2e 254 → 260
  (`expected=260` test-count guard güncellendi).
- 🧪 **WS-Security Suite Genişletildi (20 → 93 senaryo)** —
7 yeni SOAP envelope fixture'ı eklendi ve `SoapEnvelopeFixture` enum'una
metadata + Javadoc'lu olarak entegre edildi:
  - `gib-efatura-soap.xml` (3101 B) — GİB Mali Mühür request paritesi
  (`soapenv/ei/xsd/xsi/gib` multi-NS, `xsi:type`, Türkçe content).
  - `soap-with-wsa.xml` (1269 B) — WS-Addressing header'ları
  (MessageID/To/Action/ReplyTo); SOAP 1.2.
  - `soap-with-existing-wsu-id.xml` (1235 B) — Body'de client-provided
  `wsu:Id` (override kontratı).
  - `soap-multibody.xml` (1199 B) — Body'de 3 ayrı operation child.
  - `soap-large-50kb.xml` (50.5 KB) — 120 child item, c14n + digest
  pipeline performans regresyon vektörü.
  - `soap-mtom-xop.xml` (1855 B) — `<xop:Include href="cid:..."/>`
  placeholder; XML c14n MTOM-include korumalı.
  - `soap-with-existing-security-header.xml` (2321 B) — Mevcut
  `<wsse:Security>/UsernameToken`; append-not-overwrite kontratı.
  - **Ana matrix**: `WsSecuritySignAndLocalVerifyE2ETest` artık
  5 PFX × 2 backend × **9 envelope = 90 senaryo** (her senaryoda
  independent javax.xml.crypto roundtrip + ECDSA r||s invariant).
  - **Davranış kontratları**: yeni `WsSecurityContractE2ETest` (3 method,
  RSA PFX × JCA — kontrat XML davranışı, key-tipinden bağımsız):
    - `wsuIdOverrideContract` — Body wsu:Id silinir, signer Id
    override eder (shadow-reference attack negatif kontrolü).
    - `wsAddressingPreservationContract` — wsa:MessageID/To/Action/
    ReplyTo sign sonrası bayt-bayt korunur.
    - `existingSecurityHeaderAppendContract` — Tek Security var,
    UsernameToken korunur, direct-child sayısı = 4 (BST + Timestamp +
    UsernameToken + Signature), imza yine valid.
  - **Toplam**: 20 → 93 senaryo (+73). Lokal koşum ~20s. CI'da
  `verifier-e2e` job 181 → **254** test (`expected=254` guard güncellendi).
- 🧪 **XAdES Ana Suite Yine Genişletildi (80 → 130 senaryo)** —
`XAdESSignAndVerifyE2ETest` ana matriksine `efatura.xml`'den deterministic
üretilen **5 yeni regresyon fixture'ı** dahil edildi:
  - `efatura-mixed-newlines.xml` — ilk yarı CRLF + ikinci yarı LF
  (XML 1.0 §2.11 line-ending normalization vektörü).
  - `xml-with-cdata.xml` — `<cbc:Note>` içine CDATA + ampersand
  (c14n CDATA→text + `&` escape doğrulaması).
  - `xml-with-comments.xml` — 3 noktada `<!-- … -->` (prolog sonrası +
  `cac:InvoiceLine` öncesi/sonrası; EXC-C14N yorumları çıkarmalı,
  ID resolution bozulmamalı).
  - `xml-foreign-namespace-prefix.xml` — `cbc → tcbc`, `cac → tcac`
  (URI'ler aynı; signer'ın prefix-bağımsız çalıştığını test eder).
  - `efatura-unicode-emoji.xml` — 🚀 (U+1F680, 4-byte UTF-8 / surrogate
  pair) + CJK `中文` + Latin extended `ñoño` (UTF-8 indexing /
  surrogate handling regresyonu).
  - Üretici: `scripts/generate-xades-fixture-variants.py` — tekrarlanabilir
    - auditable, git history'de niye/nasıl şeffaf.
  - Yeni matriks: 5 PFX × 2 backend × **12 fixture** = **120 senaryo** +
  10 generic `OtherXmlDocument` = **130 toplam XAdES**.
  - **Sonuç**: 130/130 yeşil; signer'ın c14n, XML parsing, namespace
  handling ve UTF-8 pipeline'ı tek matriste regresyon koruması altında.
- 🧪 **XAdES Ana Suite Genişletildi (20 → 80 senaryo)** —
`XAdESSignAndVerifyE2ETest` artık 5 PFX × 2 backend × **tüm 7 fixture**
(UBL e-Fatura/e-İrsaliye/e-Müstahsil + EArchive Raporu + HR-XML +
Large ~5 MB + UTF-8 BOM) + 10 generic `OtherXmlDocument` = **80 senaryo**
koşturur. Önceki bölünmüş yaklaşım (Large ve BOM ayrı sınıfta)
konsolide edildi:
  - `XAdESLargeDocumentE2ETest` ve `XAdESBomEncodingE2ETest` sınıfları
  **silindi**; özel davranışlar ana metoda fixture-conditional olarak taşındı:
    - BOM fixture'ı için ilk 3 byte (`EF BB BF`) sanity check;
    - Large fixture'ı için sign + verify süre log'u (INFO).
  - Tek source-of-truth: `XadesDocumentFixture` enum + ek
  `standardFixtures()` helper (Large/BOM hariç tutmak isteyen
  `XadesSoftHsmVerifierE2ETest` gibi suite'ler için).
  - Yeni `efatura-with-bom.xml` fixture'ı mevcut `efatura.xml`'den
  üretildi (8320 → 8323 byte, baş kısma UTF-8 BOM eklendi).
  - Doğrulanan kontrat: tüm fixture'larda `isValid()` +
  `TOTAL_PASSED` + trust anchor reach + cryptographic verify OK.
  - Log gözlemi: DSS DOM-roundtrip BOM'u tipik olarak kaybediyor
  (`signedHasBom=false`); spec-uyumlu davranış, hard assert yok.
- 🧪 **WS-Security E2E Test Suite** — `WsSecuritySignAndLocalVerifyE2ETest` ile
5 PFX × 2 backend (PFX/JCA + HSM-emulated) × 2 SOAP versiyon (1.1, 1.2)
= **20 senaryo** sign→verify roundtrip'i. `verifier-e2e` job'una eklendi.
- 🧪 **Toplam `verifier-e2e` test sayısı 76 → 275'e çıkarıldı**:
20 CAdES + **7 CAdES binary fixture (yeni)** + 10 PAdES + 1 smoke +
130 XAdES + 90 WS-Security ana matrix + 3 WS-Security kontratı +
6 negatif test.
CI `expected=275` test-count guard güncellendi. (Tarihsel: 76 → 131
WS-Security baseline ve 7 XAdES fixture eklemesiyle; 131 → 181 5 yeni
XAdES regresyon fixture'ı ile; 181 → 254 7 yeni WS-Security envelope
  - 3 davranış kontratı ile; 254 → 260 6 negatif security testi ile;
  260 → 267 CAdES binary fixture seti ile; 267 → 275 PAdES PDF yapısal
  fixture seti ile.)
  - Doğrulayıcı: `javax.xml.crypto.dsig.XMLSignature` (lokal, Apache Santuario
  provider) — mersel-dss-verifier-api-java'nın WSS limitasyonu nedeniyle
  bypass edilir (DSS jenerik XML validator `KeyInfo → wsse:SecurityTokenReference → wsse:Reference → wsse:BinarySecurityToken` zincirini resolve edemediği
  için `NO_SIGNING_CERTIFICATE_FOUND` döner). Detay
  `WsSecurityLocalXmlDsigVerifier` Javadoc'unda.
  - Her iterasyonda ECDSA için ek invariant: SignatureValue raw `r||s`
  formatında (RFC 4051 §3.4.1) ve curve field size'a (P-256→64, P-384→96)
  uygun — DER bytes regresyonu derhal yakalanır.
- 🔐 **HSM / PKCS#11 Tam Entegrasyonu (IAIK Migration)** — SunPKCS11'in alias-keşif sorunları (örn. SafeNet ProtectToolkit, Luna) yerine `org.xipki:ipkcs11wrapper` üzerinden doğrudan PKCS#11 API'sine geçildi.
  - Yeni: `IaikPkcs11Module`, `IaikPkcs11Signer`, `IaikContentSigner`, `IaikSignatureMechanisms`, `Pkcs11EcdsaSignatureEncoder`.
  - CAdES / PAdES / XAdES yolları DSS'in 2-aşamalı API'si üzerinden HSM ile sorunsuz çalışır.
  - **WS-Security artık HSM ile de çalışıyor** — manuel XMLDsig builder ile JCA `XMLSignatureFactory`'nin `PrivateKey` zorunluluğu bypass edildi (Apache Santuario `Canonicalizer`).
  - ECDSA imzaları için spec-correct format dönüşümleri: CMS/CAdES için raw r||s → DER SEQUENCE; XMLDsig/WS-Security için DER → raw r||s (RFC 4051 §3.4.1).
  - Strict cert↔private key bağlama: `CKA_ID` öncelikli, label-only fallback yalnızca tek-eşleşmede; key rotation veya duplicate label senaryosunda sessiz yanlış imza riski yok.
  - Lifecycle ownership: `CKR_CRYPTOKI_ALREADY_INITIALIZED` durumunda `module.finalize()` atlanır (paylaşımlı Cryptoki state korunur — aynı process'te başka bileşen kullanıyor olabilir).
- 🎫 **e-Bilet Rapor Desteği** (PR [#12](https://github.com/mersel-dss/mersel-dss-server-signer-java/pull/12)) - Katkıcı: [@ozlemkzn](https://github.com/ozlemkzn) / e-Platform Bulut Bilişim A.Ş.
- 🧪 **Yeni Test Coverage** - 22 yeni test (toplam: 115)
- 🐳 **GHCR Desteği** - Docker Hub + GHCR'e tek workflow'dan paralel push
- 📦 **Docker Image İçinde 5 Test Sertifikası** - Runtime'da `-e` ile değiştirilebilir

### Changed

- 🔧 `**CryptoSignerService` PKCS#11/JCA dispatch** — Servis kodunda
`instanceof SunPkcs11SigningMaterial` veya backend switch yok;
`SigningMaterial.getBackend()` dönüşü direkt `SigningBackend.sign(...)`
ile çağrılır. Format servislerinin (`CAdESSignatureService`,
`PAdESSignatureService`, `XAdESSignatureService`, `WsSecuritySignatureService`)
hepsi bu sözleşme üzerinden çalışır → key kaynağı transparan.
- 🔄 `**KeyStoreLoaderService`, `KeyStoreProvider`, `PKCS11KeyStoreProvider`
refactor** — Dual-backend desteği için yeniden organize; `SigningMaterialFactory`
PFX yolundan `JcaSigningBackend`, PKCS#11 yolundan `Pkcs11SigningBackend`
döndürür.
- 🔧 `**SignatureAlgorithmResolverService`** — `EncryptionAlgorithm` × `DigestAlgorithm`
matrisi PKCS#11 CKM_* mekanizmaları ile genişletildi; sessiz fallback yerine
açık exception (örn. PSS mekanizması yoksa).
- 🔄 `**XAdESDocumentPlacementService*`* — UBL e-Belge, EArchive raporu,
e-Bilet ve generic XML belge yerleştirme noktaları tek dosyada karar
verir; XAdES servisi placement bilgisini bu sınıfa delege eder.
- 🔧 `**XmlProcessingService` (XAdES)** — XML parse + c14n hazırlığı +
namespace resolution akışı yeniden organize edildi; `SecureXmlFactories`
ile entegre.
- 🔄 `**AbstractKamuSMXmlDepoResolver` ve `Utilities` refactor** —
Kod netliği + test edilebilirlik (ilgili yeni testler default suite'te).
- 🔄 `**CertificateInfoController` + `CertificateInfoService` API** —
Sertifika listeleme yanıtı OID, KeyUsage, ExtendedKeyUsage, Policies,
SAN bilgileri ile genişletildi; HSM token'larında da çalışır.
- 🐳 `**devops/docker/Dockerfile`** — Yeni Allure / JaCoCo / IAIK
bağımlılıklarıyla uyumlu, application-local.properties opt-in.
- 📦 `**pom.xml`** — IAIK PKCS#11 wrapper + Allure 2.27 + JaCoCo
0.8.11 + OWASP Dependency-Check 9.2.0 + AspectJ Weaver eklendi;
Surefire `<argLine>` JaCoCo agent + AspectJ weaver inject edecek
şekilde güncellendi.
- 📋 `**README.md**` — CI / Integration Tests / Publish Evidence Pages
rozetleri, Evidence Site linki, `scripts/serve-pages-locally.sh`
local preview rehberi eklendi.
- 📜 `**devops/monitoring/load-test.sh**` ve `**examples/curl/timestamp-example.sh**`
güncel API yüzeyi ile senkronlandı.
- 🔄 **GitHub Actions Konsolidasyonu** - 3 workflow → 2 workflow, sıfır çakışma
(0.3.0'dan miras; 0.4.0'da `integration-tests.yml` + `publish-pages.yml`
eklenerek toplam 4 workflow'a çıktı — her biri farklı sorumluluk).
- ⬆️ **Actions v3 → v4** - Deprecated action hataları giderildi
- 🐳 **Dockerfile** - Mevcut test sertifikaları image'a gömüldü, varsayılan ENV'ler eklendi

### Fixed

- 🐛 **XAdES-A Yükseltme Hatası** - e-Bilet raporları XAdES-B'de kalıyordu
- 🔧 **CI Workflow** - `actions/upload-artifact@v3` deprecated hatası
- 🔐 **HSM/PKCS#11 WS-Security 500 Hatası** - `material.isPkcs11()` durumunda servis SignatureException atıyordu; manuel XMLDsig akışına taşındı.
- 🔐 **HSM ECDSA İmzaları** - PKCS#11 raw r||s çıktısı DER SEQUENCE'a normalize ediliyor; CAdES/PAdES/XAdES doğrulayıcılar artık reddetmiyor.
- 🔐 **PKCS#11 RSA-PSS Sessiz Fallback** - Mekanizma bulunamadığında PKCS#1 v1.5'e düşmek yerine açıkça `SignatureException` atılıyor (yanlış formatta imza üretme riski kaldırıldı).
- 🔐 **PKCS#11 Lifecycle Ownership** - Paylaşımlı Cryptoki init senaryosunda agresif finalize atlanıyor; diğer process bileşenleri etkilenmiyor.
- 🔐 **XAdES ECDSA `SIG_CRYPTO_FAILURE`** - JCA `SHAxxxwithECDSA` provider'ı ASN.1 DER SEQUENCE döndürürken XML-DSig spec'i plain `r||s` istiyor; DSS 6.3'ün `XAdESSignatureBuilder.signDocument` içindeki `ensurePlainSignatureValue` çağrısı bazı pipeline'larda etkisiz kalıyordu. `XAdESSignatureService.ensureXadesSignatureValueFormat` ile DSS'e gitmeden önce explicit r||s'e çeviriyoruz; RSA için no-op. Regression koruması: `XAdESEcdsaSignatureFormatTest` (5/5 PFX, default Surefire suite'inde).
- 🔐 **Verifier E2E `Accept` Header'ı** - `VerifierApiClient` HTTP isteğinde `Accept: application/json` set etmiyordu; verifier image content-negotiation'da XML döndürdüğü için Jackson parse hatası fırlatıyordu.
- ✅ **E2E Suite Full-Green (CAdES + PAdES + XAdES)** — `mersel-dss-verifier-api-java`
tarafında üç temel bulgu (eksik `dss-cms-object`, eksik `dss-pades-pdfbox`,
KamuSM trust chain'in policy nedeniyle `CERTIFICATE_CHAIN_GENERAL_FAILURE`
vermesi) giderildi. Bu repo'daki "skip-on-backend-unavailable" wrapper'ları
ve gevşek assertion'lar kaldırıldı; `assertVerificationPassed` artık
`**result.isValid()=true` + `indication=TOTAL_PASSED`** talep ediyor.
76/76 verifier-e2e testi 0 fail / 0 skip ile geçiyor.
- 🧪 `**VerifierApiContainer.IMAGE` override hook'u** — `-DverifierImage=<tag>`
ile lokal-build verifier image'larıyla test koşumu mümkün (üretim/GHCR
imajını yayınlamadan fix doğrulaması yapmak için).
- 🛡️ **E2E testler artık production default kombosu ile koşar** —
Verifier container'a hiçbir policy override geçilmiyor:
  - `DSS_POLICY_PROFILE` set edilmez → verifier image'ın yayınladığı
  default (`signer-strict`) aktif olur. İmzacı sertifika için
  **OCSP/CRL gerçekten çekilir ve doğrulanır**.
  - `ONLINE_VALIDATION_ENABLED=true` — DSS, KamuSM TEST CA'sının
  CRL/OCSP uçlarına internet üzerinden gerçek istek atar.
  - `DSS_POLICY_PATH` set edilmez — test ile production arasındaki
  tek konfigürasyon farkı log seviyesi + heap boyutu.
  Önceki "test-only permissive XML mount" yaklaşımı kaldırıldı; sertifika
  iptali kontrolleri pas geçilen "kolay yol" yerine **gerçek üretim
  senaryosunu** test ediyoruz. Trade-off: internet bağlantısı zorunlu
  (zaten KamuSM root resolver için de gerekiyordu).
- 🐛 **Pages — JaCoCo coverage % regex** (`publish-pages.yml`) —
Eski regex `[0-9]+%` HTML'deki `class="ctr2"` attribute'undaki
"2"yi de tutuyordu; landing'e yanlış coverage rakamı düşüyordu.
`<td class="ctr2">[0-9]+%` deseni + `sed` ile değer çıkarımı ile
düzeltildi.
- 🐛 **Pages — OpenAPI endpoint path** (`publish-pages.yml`) —
Springdoc-openapi 1.7.0 (Spring Boot 2.x stilinde) default endpoint
`**/api-docs`**; workflow yanlışlıkla Spring Boot 3 / springdoc 2.x
default'u olan `/v3/api-docs`'a istek atıyordu → 404 → snapshot boş.
Doğru path'e güncellendi.
- 🐛 **Pages — Spring Boot bootstrap zorunlu env** — OpenAPI snapshot
job'ı için boot edilen JAR `PFX_PATH` + `CERTIFICATE_PIN` olmadan
ayağa kalkmıyordu. `application-local.properties` ile profile-gated
varsayılanlar (test PFX + dummy PIN) tanımlandı; `--spring.profiles.active=local`
ile aktif edilir, production'da inert.
- 🐛 **Verifier E2E `Accept` Header'ı** (önceden yapıldı, fixed olarak
yerinde bırakıldı) — `VerifierApiClient` `Accept: application/json`
set ediyor; XML content-negotiation yüzünden Jackson parse hatası
almıyoruz.

### Security

- 🛡️ **XXE / SSRF / Billion-Laughs / XInclude / XSLT injection
vektörleri tamamen kapatıldı** — `SecureXmlFactories` (`util/xml/`)
tek meşru `DocumentBuilderFactory` / `TransformerFactory` kaynağı;
production kodu artık `*.newInstance()` çağırmıyor. Saldırgan
`<!ENTITY xxe SYSTEM "file:///etc/passwd">` ile sunucu dosyalarını
okuyamaz, `SYSTEM "http://169.254.169.254/..."` ile cloud metadata
istemez, 10^9 entity expansion ile belleği patlatamaz.
- 🛡️ **Negatif test suite** (default + verifier-e2e):
  - Parser-level (statik fixture): `XmlSecurityTest`, `SecureXmlFactoriesTest`
  — `xxe-attack.xml` ve `billion-laughs.xml` `SAXParseException` ile
  reddediliyor; süre < 5s assertion'ı zayıf parser flag'lerine karşı koruma.
  - Sign+tamper (runtime): `XAdESNegativeE2ETest` (wrap-attack +
  tampered-after-sign + signature-value bit-flip), `PAdESTamperedE2ETest`
  (ByteRange byte flip), `CAdESTamperedE2ETest` (detached payload
  byte flip), `XAdESSha1LegacyE2ETest` (SHA-1 crypto policy reject).
- 🛡️ **PKCS#11 — strict cert↔private key bağlama** — `CKA_ID` öncelikli
eşleme, label-only fallback yalnızca tek-eşleşmede. Key rotation veya
duplicate label senaryosunda sessiz "yanlış key ile imza" riski
yapısal olarak kaldırıldı (`IaikPkcs11Module` + `X509ExtensionInspector`).
- 🛡️ **PKCS#11 — RSA-PSS sessiz fallback engellendi** — Mekanizma
bulunamadığında PKCS#1 v1.5'e düşmek yerine `SignatureException`
atılıyor. Önceki davranışta `RSASSA-PSS` istenen yerde sessizce
`PKCS#1 v1.5` üretip "imza valid" görünüyor olabilirdi.
- 🛡️ **PKCS#11 — paylaşımlı Cryptoki lifecycle** —
`CKR_CRYPTOKI_ALREADY_INITIALIZED` durumunda `module.finalize()`
atlanır; aynı process'te başka bileşen (örn. başka Java/JNI lib)
Cryptoki state'i kullanıyor olabilir, agresif finalize ile crashlemesin.
- 🛡️ **OWASP Dependency-Check pipeline** — `dependency-check-maven` 9.2.0
Pages workflow'unda her main push'unda koşar; rapor
`[/security/](https://mersel-dss.github.io/mersel-dss-server-signer-java/security/)`
altında yayımlanır. `failBuildOnCVSS=11` (info-only — build kırıcı
değil; bilinçli olarak gözlem-modu, CVE triajı manuel).
- 🛡️ **HTTP yüzey sertleşmesi** — `415 WRONG_CONTENT_TYPE` mapping
(multipart olmayan istekler için doğru hata), multipart limit
contract testleri (`MultipartLimitHttpContractTest`,
`MultipartConfigSanityTest`), sign endpoint envelope contract testleri.

### Removed

- 🗑️ `**src/main/lib/sunpkcs11.jar`** — Lokal JDK Sun PKCS#11 wrapper
artık bağımlılık değil. `pom.xml`'deki `mvn install:install-file`
hook'u temizlendi; CI'daki `mvn validate -B` adımı artık hiçbir lokal
jar yüklemiyor — sadece default Maven validate fazını çalıştırır.
HSM erişimi tamamen `org.xipki:ipkcs11wrapper` 1.0.9 üzerinden.
- 🗑️ `**resources/test-documents/EFATURA.xml`** — Yerini
`resources/test-fixtures/xades/efatura.xml` aldı. Yeni dizin
yapısı (`test-fixtures/{xades,pades,cades,wssecurity,negative}/`)
her formata kendi fixture klasörünü atar; eski tek-belge
`test-documents/` yaklaşımı emekliye ayrıldı.
- 🗑️ **"Skip-on-backend-unavailable" wrapper'ları + gevşek E2E
assertion'ları** — `assertVerificationPassed` artık katı
(`isValid()=true` + `TOTAL_PASSED`); önceki yumuşak
"verifier yoksa testler skip" davranışı kaldırıldı, infra
hatası gizlenmiyor.

### Known issues (verifier projesi tarafında)

> Önceki sürümlerde dokümante edilen üç verifier bulgusu
> `[mersel-dss-verifier-api-java](https://github.com/mersel-dss/mersel-dss-verifier-api-java)`
> üzerinde çözüldü (yeni `pom.xml` + production-grade policy mimarisi
> `signer-strict|strict` profilleri + tam custom `dss.policy.path` override).
> Bu repo'nun E2E suite'i %100 yeşil; upstream sürüm yayınlanır yayınlanmaz
> `VerifierApiContainer.IMAGE` default'u GHCR tag'ine geri çekilebilir.

---

## [0.3.0] - 2026-03-11

### Added

- 🎫 **e-Bilet Rapor İmzalama** (PR [#12](https://github.com/mersel-dss/mersel-dss-server-signer-java/pull/12))
  - `EBiletReport` document type (`DocumentType` enum)
  - `NS_BILET` XML namespace sabiti (`XmlConstants`)
  - e-Bilet rapor belgelerinde `baslik` elemanı altına imza yerleştirme (`XAdESDocumentPlacementService`)
  - e-Bilet raporları için XAdES-A seviyesine yükseltme
  - e-Bilet imzalama sonrası OCSP cache temizliği
  - Katkıcı: [@ozlemkzn](https://github.com/ozlemkzn) / e-Platform Bulut Bilişim A.Ş.
- 🧪 **Test Coverage Artışı** - 22 yeni test eklendi (93 → 115)
  - `XAdESDocumentPlacementServiceTest` - e-Bilet, e-Arşiv, UBL ve OtherXml belge yerleştirme testleri
  - `XAdESLevelUpgradeServiceTest` - XAdES-A yükseltme/atlama ve timestamp servis testleri
  - `XadesControllerTest` - e-Bilet document type controller testleri
- 🐳 **GHCR (GitHub Container Registry) Desteği**
  - `ghcr.io/mersel-dss/mersel-dss-server-signer-java:latest`
  - Multi-platform: `linux/amd64`, `linux/arm64`
  - Smoke test: container başlatılıp health check doğrulanıyor
  - Docker Hub ve GHCR'e tek workflow'dan paralel push
- 📦 **Docker Image İçinde Test Sertifikaları** - Hazır kullanıma uygun 5 sertifika
  - `testkurum01_rsa2048@test.com.tr` (RSA-2048, parola: 614573) - **varsayılan**
  - `testkurum02_ec384@test.com.tr` (EC-384, parola: 825095)
  - `testkurum02_rsa2048@sm.gov.tr` (RSA-2048, parola: 059025)
  - `testkurum03_ec384@test.com.tr` (EC-384, parola: 540425)
  - `testkurum03_rsa2048@test.com.tr` (RSA-2048, parola: 181193)
  - Güvenilir köklere (KamuSM) uyumlu, zincir doğrulaması çalışıyor
  - `docker run -e PFX_PATH=... -e CERTIFICATE_PIN=... -e CERTIFICATE_ALIAS=...` ile runtime'da değiştirilebilir

### Changed

- 🔄 **GitHub Actions Workflow Konsolidasyonu** - 3 workflow → 2 workflow, sıfır çakışma
  - `ci.yml`: PR ve develop branch'te çalışır (build + test + code quality)
  - `docker.yml`: main push ve tag'lerde çalışır (test → Docker Hub + GHCR push + smoke test)
  - Eski workflow'lar silindi: `docker-publish.yml`, `ghcr-publish.yml`
  - Her push'ta 3x build+test yerine 1x çalışıyor
- ⬆️ **GitHub Actions Versiyon Güncellemeleri**
  - `actions/checkout@v3` → `@v4`
  - `actions/setup-java@v3` → `@v4`
  - `actions/upload-artifact@v3` → `@v4`
  - `mvn validate -B` adımı eklendi (o tarihte `src/main/lib/sunpkcs11.jar` lokal kurulumu içindi; **Unreleased**'da bu jar kaldırıldı — adım artık sadece default Maven validate fazını çalıştırır).
- 🐳 **Dockerfile Güncellendi** - Test sertifikaları ile production-ready
  - Mevcut test sertifikaları image'a gömülüyor (`/app/test-certs/`)
  - Varsayılan ENV'ler: `PFX_PATH`, `CERTIFICATE_PIN=614573`, `CERTIFICATE_ALIAS=1`

### Fixed

- 🐛 **XAdES-A Yükseltme Hatası** - e-Bilet raporları için XAdES-A yükseltme yapılmıyordu
  - `XAdESLevelUpgradeService`: `EBiletReport` document type eksikti, XAdES-B'de kalıyordu
  - OCSP cache temizliği çalışıyor ama yükseltme atlanıyordu (tutarsızlık)
  - Log mesajları dinamik hale getirildi (document type bilgisi)
- 🔧 **CI Workflow Hatası** - `actions/upload-artifact@v3` deprecated olduğu için build başarısız oluyordu

---

## [0.2.1] - 2026-03-03

### Added

- 🔏 **CAdES İmza Desteği** (PR [#11](https://github.com/mersel-dss/mersel-dss-server-signer-java/pull/11))
  - DSS kütüphanesi ile CAdES-BES imzalama
  - Katkıcı: [@Burak-Attila](https://github.com/Burak-Attila)

---

## [0.2.0] - 2026-03-02

### Fixed

- 🐛 **UBLExtensions Hiyerarşisi** (PR [#10](https://github.com/mersel-dss/mersel-dss-server-signer-java/pull/10))
  - Eksik `UBLExtensions/UBLExtension/ExtensionContent` hiyerarşisi otomatik oluşturuluyor
  - Kısmi UBLExtensions yapısı graceful olarak handle ediliyor
  - Import'lar ve hata yönetimi iyileştirildi
  - Katkıcı: [@batuhanonerr](https://github.com/batuhanonerr)

---

## [0.1.5] - 2026-02-19

### Changed

- 🔧 **Kriptografik İyileştirmeler** - İmza işleme ve şifreleme fonksiyonelliği geliştirildi

### Fixed

- 🐛 **UBLExtensions Auto-Create** - Eksik `UBLExtensions/UBLExtension/ExtensionContent` yapısı otomatik oluşturuluyor

---

## [0.1.4] - 2026-02-04

### Fixed

- 🐛 **WS-Security signDocument** (PR [#8](https://github.com/mersel-dss/mersel-dss-server-signer-java/pull/8))
  - WS-Security imzalama hatası düzeltildi
  - Katkıcı: [@batuhanonerr](https://github.com/batuhanonerr)
- 🐛 **Zip Okuma Problemi** - Zip dosyalarının okunmasındaki hata giderildi

---

## [0.1.3] - 2025-11-16

### Added

- 🔌 **PKCS#11 Slot Yapılandırması** (PR [#6](https://github.com/mersel-dss/mersel-dss-server-signer-java/pull/6))
  - `PKCS11_SLOT` ve `PKCS11_SLOT_LIST_INDEX` parametreleri ayrı ayrı kullanılabilir
  - Katkıcı: [@hasanyildiz](https://github.com/hasanyildiz)

---

## [0.1.2] - 2025-11-13

### Fixed

- 🐛 **TÜBİTAK ECDSA Doğrulama** (PR [#3](https://github.com/mersel-dss/mersel-dss-server-signer-java/pull/3))
  - TÜBİTAK XAdES için ECDSA doğrulama iyileştirmeleri
  - TÜBİTAK customization for XAdES BES signature
  - Katkıcı: [@hasanyildiz](https://github.com/hasanyildiz)

---

## [0.1.1] - 2025-11-10

### Added

- ⏰ **RFC 3161 Zaman Damgası Servisi**
  - `POST /api/timestamp/get` - RFC 3161 uyumlu timestamp
  - `POST /api/timestamp/validate` - Timestamp doğrulama
  - `GET /api/timestamp/status` - TSP sunucu durumu
  - `TimestampStatusDto` eklendi
  - TÜBİTAK ESYA, KAMUSM ve standart TSP sunucuları desteği
  - 22 unit test (TimestampServiceTest + TimestampControllerTest)
- 🔧 **Güvenilir Kök Sertifika Resolver Sistemi**
  - **KamuSM XML Depo Online Resolver**: İnternet üzerinden otomatik indirme ve periyodik güncelleme
  - **KamuSM XML Depo Offline Resolver**: Air-gapped sistemler için yerel dosya
  - **Certificate Folder Resolver**: Klasördeki .crt/.cer/.pem dosyalarını yükleme
  - `trusted.root.resolver.type=kamusm-online|kamusm-offline|certificate-folder`
- 🔐 **Sertifika Listeleme API'si**
  - `GET /api/certificates/list` - Keystore'daki tüm sertifikaları listele
  - `GET /api/certificates/info` - Keystore tipi ve parametreleri
  - `--list-certificates` CLI argümanı (Spring context olmadan)
  - OID, Key Usage, Extended Key Usage, Certificate Policies bilgileri
- 🎨 **Scalar API Documentation** - Swagger UI yerine modern Scalar arayüzü
- 📊 **Prometheus Metrics Export**
  - `/actuator/prometheus` - 40+ metrik
  - HTTP, JVM, System, Tomcat metrikleri
  - Percentile histogram (p50, p95, p99)
- 🔍 **Spring Boot Actuator**
  - `/actuator/health`, `/actuator/info`
  - Kubernetes liveness/readiness probe desteği

### Changed

- 🌐 **CORS** - Timestamp ve signature header'ları exposed headers'a eklendi
- 🔧 **Sertifika Yapılandırması** - `CERTIFICATE_ALIAS` ve `CERTIFICATE_SERIAL_NUMBER` opsiyonel
- 🎯 **SignatureApplication** - `--list-certificates`, `--help`, `--version` CLI argümanları

### Fixed

- 🐛 CI workflow ve test hataları düzeltildi
- 🐛 Docker publish workflow düzeltildi

---

## [0.1.0] - 2025-11-07

### 🎉 İlk Public Release

#### Added

- 🐳 **Docker & Docker Compose Desteği**
  - Multi-stage Dockerfile (Maven build + Eclipse Temurin 8 JRE)
  - docker-compose.yml ile Prometheus + Grafana monitoring stack
  - Non-root user, built-in health check, ~250MB image
- 🖥️ **Cross-Platform Script Desteği**
  - Unix/Linux/macOS bash script'leri (`scripts/unix/`)
  - Windows PowerShell script'leri (`scripts/windows/`)
  - Docker helper script'leri (test kurum başlatma)
- 📂 **DevOps Organizasyonu** - `devops/docker/`, `devops/monitoring/`, `devops/kubernetes/`
- 🚀 **Hızlı Başlatma Script'leri** - Test sertifikaları ile tek komutla başlatma
- 🔐 **Test Sertifikaları** - 3 adet test PFX (`resources/test-certs/`)
- 📚 **Kapsamlı Dokümantasyon** - MONITORING.md, ACTUATOR_ENDPOINTS.md, CERTIFICATE_SELECTION.md
- 📝 **SECURITY.md** - Güvenlik politikası ve best practices
- 🔒 **CORS Yapılandırması** - Güvenli cross-origin resource sharing
- 🛡️ **Security Headers** - XSS, Clickjacking koruması
- 📊 **Performance Guide** - JVM tuning rehberi (docs/PERFORMANCE.md)
- 🧪 **Unit Testler** - Temel servis ve controller testleri
- 📋 **CHANGELOG.md** - Versiyon geçmişi takibi

#### Changed

- ♻️ **Log Yönetimi** - logback-spring.xml, rolling file appenders, ayrı error.log/signature.log
- 📦 **Dependency Güncellemeleri** (JDK 1.8 uyumlu)
  - Spring Boot: 2.3.7 → 2.7.18
  - Jackson: 2.11.2 → 2.15.3
  - BouncyCastle: 1.50 → 1.70
  - Apache HttpClient: 4.5.10 → 4.5.14
  - SpringDoc OpenAPI: 1.4.8 → 1.7.0
  - Sentry: 4.1.0 → 6.34.0

#### Fixed

- 🐛 Log dosyalarının ana dizinde oluşması sorunu
- 📝 application.properties syntax düzeltmeleri
- 🔧 Maven compiler encoding yapılandırması

---

## [0.0.1] - 2025-10-XX

### İlk İç Versiyon

- ✅ XAdES imzalama (e-Fatura, e-Arşiv, e-İrsaliye)
- ✅ PAdES imzalama
- ✅ WS-Security imzalama
- ✅ TÜBİTAK timestamp entegrasyonu
- ✅ HSM (PKCS#11) desteği
- ✅ DSS kütüphanesi custom override'ları
- ✅ OCSP/CRL cache mekanizması
- ✅ KamuSM root sertifikası desteği

---

## Gelecek Sürümler

> **Not:** 0.4.0 sürümü orijinal yol haritasında "Kubernetes / rate
> limit / batch" odaklıydı; ancak HSM uyumsuzluğu + auditor-grade
> kanıt zinciri ihtiyacı öne çekildi. Operasyonel kalemler bir kademe
> kaydırıldı.

### v0.5.0 (Planlanan)

- Kubernetes manifests
- Rate limiting
- API Authentication
- Asenkron imzalama
- Batch imzalama

### v0.6.0 (Planlanan)

- WebSocket bildirimler
- Kafka/RabbitMQ entegrasyonu
- Dashboard UI

