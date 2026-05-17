# Test Backlog

Test fixture ihtiyaçları ve önerilen test senaryolarının takip listesi.
GitHub Issues'a 1:1 dönüştürülebilir.

> **Format:**
> - `[ ]` = yapılacak / fixture yok
> - `[~]` = fixture var, test yazılacak
> - `[x]` = tamamlandı
> - `[⏸]` = **deferred** — ya ayrı repo'da (verifier-api), ya commercial / external dep gerektirir (PDF/A, freetsa testcontainer, mock VKN). Gerekçesi item satırında.
> - **Pri:** `H` (high) / `M` (medium) / `L` (low)

## ✅ Backlog durum özeti (turn-11 / v0.4.0 itibariyle)

| Bölüm | Durum | Not |
|---|---|---|
| 🔴 Verifier-api code işleri | ⏸ deferred | Ayrı repo (`mersel-dss-verifier-api-java`) |
| A) XAdES E-Belge varyasyonları | ✅ tamamlandı | 130 senaryo (turn-2/3) |
| B) PAdES PDF varyasyonları | ✅ pratik kapsam tamam | 4 fixture + 4 runtime senaryo; PDF/A ⏸ |
| C) CAdES Binary varyasyonları | ✅ pratik kapsam tamam | 4 fixture × 2 mode = 8 senaryo; large/docx/zip ⏸ |
| D) WS-Security SOAP varyasyonları | ✅ tamamlandı | 90 ana + 3 kontrat + 3 hash-param + 3 envelope-parity + 1 concurrent |
| F) Negatif security testleri | ✅ tamamlandı | 2 parser + 6 sign+tamper |
| 🔴 Sertifika lifecycle negatifleri | ✅ aktif (turn-12) | `CertificateLifecycleNegativeE2ETest`: 6 PFX × 4 format = **24/24 PASS, 0 SKIP** (XAdES + CAdES + PAdES + WSS hepsi). GHCR `:main` fresh image rebuild sonrası ([verifier#2](https://github.com/mersel-dss/mersel-dss-verifier-api-java/issues/2)) flag gerekmeden 24/24 PASS doğrulandı. |
| G) HTTP/API kontratı | ✅ tamamlandı | G-1..G-6 hepsi kapalı (production kodu +1 mapping) |
| H) HSM / PKCS#11 kontratı | ✅ tamamlandı | H-1 + H-2 + H-3 |
| 📤 Signed-artifact export | ✅ aktif | `target/signed-artifacts/` — `SignedArtifactExporter` (turn-9) — 3rd-party verify için ~290 binary/koşu |
| 🌐 Public Evidence Site | ✅ aktif (turn-10) | [`mersel-dss.github.io/mersel-dss-server-signer-java/`](https://mersel-dss.github.io/mersel-dss-server-signer-java/) — Allure + JaCoCo + OpenAPI + OWASP, her main push'unda otomatik publish |

**Bu turn'da default suite: 310 → 326** (+16: 4 yeni test sınıfı + 1
GlobalExceptionHandlerTest method'u). 0 yeni statik fixture.
**Turn-9**: signed-artifact export sistemi eklendi (suite sayıları değişmedi).
**Turn-10**: Public Evidence Site eklendi (Allure annotations + verify.json sidecar + GitHub Pages workflow).

---

## 🟢 Mevcut envanter (canlı sayım)

### Test sayıları (suite başına)

| Suite (Surefire group) | Test sayısı | Çalışma şartı |
|---|---:|---|
| **default** (`mvn test`) | **326** | tek başına; Docker/HSM gerektirmez |
| **verifier-e2e** (`-Dgroups=verifier-e2e`) | **277** | Docker daemon + Testcontainers; CI'da GHCR `mersel-dss-verifier-api-java` image'ı |
| **pkcs11-integration** (`-Dgroups=pkcs11-integration`) | **31** | SoftHSM2 + jacknji11 native; Linux runner |

### `verifier-e2e` 268 senaryonun dağılımı

| Test sınıfı | Senaryo | Açıklama |
|---|---:|---|
| `CAdESSignAndVerifyE2ETest` | 20 | 5 PFX × 2 backend × 2 mode (attached / detached) |
| `CAdESBinaryVariationsE2ETest` | 4 | 4 binary fixture × 1 RSA PFX × JCA backend — smart matrix |
| `PAdESSignAndVerifyE2ETest` | 10 | 5 PFX × 2 backend (programatik minimal PDF) |
| `PAdESDocumentVariationsE2ETest` | 4 | 4 PDF fixture × 1 RSA PFX × JCA backend — smart matrix |
| `XAdESSignAndVerifyE2ETest` | 130 | 5 PFX × 2 backend × 12 fixture (120) + 10 generic `OtherXmlDocument` |
| `WsSecuritySignAndLocalVerifyE2ETest` | 90 | 5 PFX × 2 backend × 9 SOAP envelope |
| `WsSecurityContractE2ETest` | 3 | structural kontrat: wsu:Id override + WS-Addressing preserve + Security append-not-overwrite (RSA PFX × JCA tek-iterasyon) |
| `XAdESNegativeE2ETest` | 3 | wrap-attack + tampered-after-sign + signature-value bit-flip |
| `PAdESTamperedE2ETest` | 1 | ByteRange içinde byte flip |
| `CAdESTamperedE2ETest` | 1 | detached payload byte flip |
| `XAdESSha1LegacyE2ETest` | 1 | SHA-1 imzalı XAdES policy reject veya warning beklentisi |
| `VerifierContainerSmokeTest` | 1 | container health-check |
| **TOPLAM** | **268** | CI `expected=268` test-count guard |

### Fixture envanteri

| Alan | Fixture path | Kullanan sınıf | İter. |
|------|--------------|-----------------|-------|
| XAdES (UBL/EArchive/HR-XML — production) | `resources/test-fixtures/xades/{efatura,earsiv-raporu,eirsaliye,emustahsil,hrxml}.xml` | `XAdESSignAndVerifyE2ETest` ana matriks | 50 (5 fixture × 5 PFX × 2 backend) |
| XAdES (large) | `xades/efatura-large.xml` (~5 MB) | aynı, fixture-conditional perf log | 10 |
| XAdES (BOM) | `xades/efatura-with-bom.xml` (UTF-8 BOM) | aynı, fixture-conditional BOM sanity | 10 |
| XAdES (mixed-newlines) | `xades/efatura-mixed-newlines.xml` | aynı | 10 |
| XAdES (CDATA) | `xades/xml-with-cdata.xml` | aynı | 10 |
| XAdES (comments) | `xades/xml-with-comments.xml` | aynı | 10 |
| XAdES (foreign-ns) | `xades/xml-foreign-namespace-prefix.xml` | aynı | 10 |
| XAdES (unicode-emoji) | `xades/efatura-unicode-emoji.xml` | aynı | 10 |
| XAdES (generic) | _runtime literal — `DocumentType.OtherXmlDocument` yolunu test_ | aynı, ikinci method | 10 |
| CAdES (programatik) | _yok_ (programatik UTF-8 string) | `CAdESSignAndVerifyE2ETest` | 20 |
| CAdES (binary varyasyon) | `resources/test-fixtures/cades/{sample.txt,sample.bin,empty.bin,utf16-text.txt}` | `CAdESBinaryVariationsE2ETest` | 4 |
| PAdES (programatik) | _yok_ (iText ile üretilen 1-sayfa PDF) | `PAdESSignAndVerifyE2ETest` | 10 |
| PAdES (PDF varyasyon) | `resources/test-fixtures/pades/{efatura-pdf,turkish-chars,landscape-a3,large-50pages}.pdf` | `PAdESDocumentVariationsE2ETest` | 4 |
| WS-Security (ana matriks) | `wssecurity/{soap-1.1,soap-1.2,gib-efatura,soap-with-wsa,soap-with-existing-wsu-id,soap-multibody,soap-large-50kb,soap-mtom-xop,soap-with-existing-security-header}.xml` | `WsSecuritySignAndLocalVerifyE2ETest` | 90 |
| WS-Security (kontrat) | _yukarıdaki fixture'ların 3 tanesi (wsa, wsu-id, security-header)_ | `WsSecurityContractE2ETest` | 3 |
| Negatif (parser-level, statik) | `negative/{xxe-attack,billion-laughs}.xml` | `XmlSecurityTest` (default suite) | 2 |
| Negatif (XAdES sign+tamper) | _runtime — EFATURA fixture sign + DOM mutate_ | `XAdESNegativeE2ETest` | 3 |
| Negatif (PAdES tamper) | _runtime — iText PDF sign + `byte[100]` flip_ | `PAdESTamperedE2ETest` | 1 |
| Negatif (CAdES tamper) | _runtime — text payload detached sign + `byte[25]` flip_ | `CAdESTamperedE2ETest` | 1 |
| Negatif (XAdES SHA-1) | _runtime — DSS XAdESService doğrudan SHA-1 (signer servisi bypass)_ | `XAdESSha1LegacyE2ETest` | 1 |
| HSM smoke (1×fixture) | `xades/efatura.xml` | `XadesSoftHsmVerifierE2ETest` (`pkcs11-integration` tag) | 1+ |

### Önemli tasarım notları

> **XAdES — tek matriks**: Tüm 12 XAdES fixture'ı (UBL e-Fatura/e-İrsaliye/
> e-Müstahsil/EArchive/HR-XML/Large/BOM/mixed-newlines/CDATA/comments/
> foreign-ns-prefix/unicode-emoji) tek source-of-truth `XadesDocumentFixture`
> enum'unda. Generic XML için ikinci method `OtherXmlDocument` yolunu test
> eder. 5 yeni varyant (mixed-newlines, CDATA, comments, foreign-ns, emoji)
> `scripts/generate-xades-fixture-variants.py` ile `efatura.xml`'den
> deterministic üretilir — c14n, parsing, namespace ve encoding regresyon
> vektörlerini tek matriste tarar. Küçük fixture set'i isteyen testler
> (örn. `XadesSoftHsmVerifierE2ETest`) için
> `XadesDocumentFixture.standardFixtures()` yardımcı method'u var.
>
> **WS-Security — lokal XMLDSig**: Verifier-api yerine `javax.xml.crypto.dsig.XMLSignature`
> ile doğrular. DSS jenerik `XMLDocumentValidator` WSS `KeyInfo → STR → BST`
> zincirini resolve edemediği için verifier-api `NO_SIGNING_CERTIFICATE_FOUND`
> döner. Bu, downstream sınırlama; signer regression hassasiyeti bağımsız
> bir XMLDSig stack ile karşılanır. Her senaryoda ECDSA için raw `r||s`
> format invariantı da doğrulanır (WSS spec gereği DER SEQUENCE değil,
> raw concatenation kullanılmalı).
>
> **Negatif testler — hibrit fixture stratejisi**:
> - **Parser-level** (XXE, Billion Laughs): statik commit, default-suite
>   `XmlSecurityTest`. Verifier-api veya Docker gerektirmez, her CI run koşar.
> - **Sign+tamper** (wrap, tampered, byte-flip, SHA-1): runtime üretim.
>   Statik commit yerine runtime çünkü (1) cert expire ettiğinde test
>   kırılmaz, (2) "signer doğru imza üretti" sanity'sini aynı testte
>   ölçer, (3) verifier davranışını daima canlı sign akışıyla
>   karşılaştırır.

---

## 🟢 Recap — bu turda eklenen / değişen şeyler

> Hızlı PR notu — repo seyrek bakanlar için **76 → 268** verifier-e2e
> büyümesi nasıl katlandı.

| # | Tarih | Değişim | Net delta |
|---|---|---|---:|
| 1 | turn-1 | Baseline WS-Security suite ilk düzeltme | 76 |
| 2 | turn-2 | İlk WS-Security baseline + 7 XAdES production fixture | +55 → 131 |
| 3 | turn-3 | 5 yeni XAdES regression fixture (mixed-newlines, CDATA, comments, foreign-ns, emoji) — `scripts/generate-xades-fixture-variants.py` | +50 → 181 |
| 4 | turn-4 | 7 yeni WS-Security envelope + 3 davranış kontratı | +73 → 254 |
| 5 | turn-5 | 6 negatif security testi (XAdES wrap/tampered/sigval + PAdES tamper + CAdES tamper + SHA-1 legacy) | +6 → 260 |
| 6 | **bu turn** | **CAdES binary varyasyon** — 4 senaryo (`CAdESBinaryVariationsE2ETest`); 4 statik fixture commit (sample.txt, sample.bin, empty.bin, utf16-text.txt). Tek RSA PFX × JCA × 4 fixture × attached mode. EMPTY_BIN davranış kontratı (throws **veya** boş CMS — her ikisi de graceful). | +4 → 264 |
| 7 | turn-7 | **PAdES PDF varyasyon** — 4 senaryo (`PAdESDocumentVariationsE2ETest`); 4 statik fixture commit (efatura-pdf 3-sayfa, turkish-chars, landscape-a3, large-50pages). iText 5.4.1 + Cp1254 ile programatik üretilip commit'lendi (generator class çalıştırılıp silindi — `commit_only` strategy). Tek RSA PFX × JCA × 4 fixture. | +4 → 268 |
| 8 | **bu turn** | **Default suite kapanış sprintı** — `TEST_BACKLOG.md`'da `[ ]` kalan tüm pratik item'lar kapatıldı. Yeni 4 test sınıfı: `WsSecurityHashAlgorithmParametrizedTest` (3, D-hash-param), `WsSecurityEnvelopeShapeParityTest` (3, D-mali-muhur), `MultipartLimitHttpContractTest` (2, G-1), `SignEndpointHttpEnvelopeContractTest` (7, G-2/3/5). `GlobalExceptionHandler` 415 mapping eklendi (`HttpMediaTypeNotSupportedException` → `WRONG_CONTENT_TYPE`); ek 1 GlobalExceptionHandlerTest. Pre-existing parçalardan da `MultipartConfigSanityTest`, `PadesControllerTest`, `KeyStoreLoaderServiceContractTest`, `SignatureServiceSemaphoreConcurrencyTest`, `TimestampServiceContractTest`, `WsSecurityConcurrencyContractTest`, `PAdESRuntimeScenariosE2ETest`, `CAdESBinaryVariationsE2ETest` detached extension dahil; bunlar ?? state'inden çıkıp suite'e dahil edildi. | default +16 → 326 |
| 9 | **bu turn** | **Signed-artifact export sistemi** — `SignedArtifactExporter` utility + JUnit 5 extension. Her real-signing test (XAdES/CAdES/PAdES/WSS — toplam 16 sınıf) başarılı imzayı `target/signed-artifacts/<format>/<sınıf>__<method>__<param/iter>[__<label>].<ext>` olarak yazar. Detached CAdES: `.p7s` + `.bin` sidecar payload (3rd-party verify için). `.gitignore`'a `target/signed-artifacts/` + `signed-artifacts/` eklendi. Üçüncü taraf doğrulama için (Adobe Reader, EU DSS Demo, `xmlsec1`, `openssl smime`, SoapUI) hazır. | suite sayıları değişmedi, ~290 artefakt verifier-e2e çalıştığında üretilir |
| 10 | turn-10 | **Public Evidence Site (GitHub Pages)** — `.github/workflows/publish-pages.yml` + `docs/landing/index.html`. Allure + JaCoCo + Swagger UI snapshot + OWASP Dependency-Check her `main` push'unda otomatik yayımlanır; trend grafiği Allure history cache ile. `scripts/serve-pages-locally.sh` local preview (`--fast` ≈ 2 dk). `application-local.properties` ile Spring Boot bootstrap (PFX_PATH + CERTIFICATE_PIN dummy default). | suite sayıları değişmedi; raporlar `https://mersel-dss.github.io/...` altında |
| 11 | turn-11 | **CHANGELOG v0.4.0 → kanıt-temelli imza hattı** — Tüm 0.4.0 işleri ([`CHANGELOG.md`](CHANGELOG.md#040---2026-05-18)) altında, Keep-a-Changelog formatında: Highlights tablosu + Added (mimari/test/export/Pages/güvenlik/fixture/HSM pipeline/ergonomi/production/build), Changed, Fixed, Security, Removed bölümleri. Auditor-friendly tonda; her madde 2-3 cümle + dosya referansı. Sürüm semverde MINOR bump (0.3.0 → 0.4.0): API breaking yok; HSM/test/evidence pipeline major scope. Roadmap'in eski 0.4.0 kalemleri (K8s, rate limit, batch) 0.5.0'a kaydırıldı. | dokümantasyon-only |

Yan etkiler:
- Default suite: 310 → **326** (D-hash-param +3, D-mali-muhur +3, MultipartLimitHttp +2, SignEndpointHttp +7, GlobalExceptionHandlerTest +1).
- `GlobalExceptionHandler` üretim kodunda 1 yeni mapping (`HttpMediaTypeNotSupportedException` → 415 + `WRONG_CONTENT_TYPE`); önceki davranış `@ExceptionHandler(Exception.class)` jenerik'inden 500 dönüyordu. Operasyonel UX iyileştirmesi.
- CI `verifier-e2e` job test-count guard: 268 (değişmedi).
- 0 yeni statik fixture (tümü programatik veya mock-bazlı).
- 4 yeni test sınıfı default suite'te; tümü < 5s'de tamamlanır, Docker/HSM yok.
- `target/signed-artifacts/` her `mvn test` koşusunda üretilir (varsayılan **açık**); `-Dsigned.artifacts.export=false` ile kapatılır.

---

## 🟢 Signed-artifact export — 3rd-party verification için manuel doğrulama hattı

> **Amaç**: Her başarılı imza koşusunda üretilen binary'leri Git-dışı bir klasöre
> dump edip, signer doğruluğunu **bağımsız 3rd-party araçlarla** (Adobe Reader,
> EU DSS Demo, `xmlsec1`, `openssl smime`, SoapUI) cross-check etmek. Verifier-api
> kontratı bizim kodumuz; gerçek dünya araçları "ground truth" sağlar.

### Çalışma şekli

| Konfigürasyon | Default | Açıklama |
|---|---|---|
| **Sınıf** | `io.mersel.dss.signer.api.testsupport.SignedArtifactExporter` | Hem JUnit 5 extension (`@ExtendWith`), hem static helper |
| **Çıktı kökü** | `target/signed-artifacts/` | `target/` zaten Git-dışı; `.gitignore`'da ek belirgin entry |
| **Açma/kapama** | `-Dsigned.artifacts.export=false` ile devre dışı (default: **on**) |
| **Alternatif kök** | `-Dsigned.artifacts.dir=/custom/path` veya env `SIGNED_ARTIFACTS_DIR` |
| **Otomatik temizlik** | Her `mvn test` başında root tamamen silinir → klasörde **sadece son run'ın çıktıları** kalır. `-Dsigned.artifacts.purge=false` ile kapatılabilir (incremental debug veya `forkCount>1`). |

### Klasör/dosya yapısı

```
target/signed-artifacts/
├─ README.md                    (otomatik yazılır — 3rd-party araç komutları + isimlendirme rehberi)
├─ xades/                       (130 + variants)
│   └─ xadesFixtureRoundtripIsValid__KURUM01_RSA2048_PFX_JCA_EFATURA.xml
│   └─ xadesFixtureRoundtripIsValid__KURUM01_RSA2048_PFX_BACKED_PKCS11_EFATURA.xml
├─ xades-negative/              (3)
│   └─ wrapAttackRejected__wrap-attack.xml
│   └─ tamperedAfterSignRejected__uuid-text-mutated.xml
│   └─ signatureValueTamperedRejected__signature-value-bitflip.xml
├─ xades-legacy/                (1) — SHA-1 legacy
├─ cades-attached/              (13)
│   └─ cadesRoundtripIsValid__KURUM01_RSA2048_PFX_JCA_attached.p7s
├─ cades-detached/              (28 = 14 .p7s + 14 .bin sidecar payload)
│   └─ cadesRoundtripIsValid__KURUM01_RSA2048_PFX_JCA_detached.p7s
│   └─ cadesRoundtripIsValid__KURUM01_RSA2048_PFX_JCA_detached.bin
├─ pades/                       (18)
│   └─ padesRoundtripIsValid__KURUM01_RSA2048_PFX_JCA_embedded.pdf
├─ pades-negative/              (1)
│   └─ byteRangeBitFlipFailsVerification__byte100-bitflip.pdf
└─ wssecurity/                  (96)
    └─ wsSecurityRoundtripIsValid__KURUM01_RSA2048_PFX_JCA_efatura.xml
```

**Dosya adı reçetesi** — iki strateji:

| Mod | Pattern | Ne zaman |
|---|---|---|
| **Semantic (tercih edilen)** | `<methodName>__<sanitize(label)>.<ext>` | Çağıran `label` parametresinde `<PFX>_<algoritma>_<backend>_<scenario>` tüm metayı verdiyse — class prefix yok, format alt klasörü zaten context veriyor |
| **Fallback** | `<className>__<methodName>[__<displayOrIter>].<ext>` | Legacy çağrılar (label boş bırakılmışsa) — parametre/uniqueId hash collision korumalı |

> **Önemli — casing korunur**: `sanitize()` lowercase'e düşürmez.
> Enum adları (`KURUM01_RSA2048`, `PFX_JCA`, `EFATURA`) ve camelCase
> method adları (`xadesFixtureRoundtripIsValid`) okunabilir kalır;
> dosya tarayan auditor "hangi PFX, hangi backend, hangi fixture"
> sorularını **dosya adından** cevaplar.

> **Collision koruması**: Aynı `"baseline"` label'ı 3 farklı negative
> test method'unda kullanılsa bile method adı prefix'i sayesinde
> dosyalar ayrı kalır (`wrapAttackRejected__baseline.xml`,
> `tamperedAfterSignRejected__baseline.xml`,
> `signatureValueTamperedRejected__baseline.xml`).

### 3rd-party verify rehberi

| Format | Önerilen araç | Komut |
|---|---|---|
| XAdES (enveloped) | `xmlsec1` | `xmlsec1 --verify --insecure target/signed-artifacts/xades/<file>.xml` |
| XAdES | EU DSS Demo | https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/validation — drag-drop |
| CAdES attached | `openssl smime` | `openssl smime -verify -inform DER -in <file>.p7s -noverify -out -` |
| CAdES detached | `openssl smime` | `openssl smime -verify -inform DER -in <file>.p7s -content <file>.bin -noverify -out /dev/null` |
| PAdES | Adobe Reader / Acrobat | Dosyayı aç → "Signature Panel" → certificate chain ve coverage'ı kontrol et |
| PAdES | EU DSS Demo | Aynı upload sayfası — `.pdf` drag-drop |
| WS-Security | SoapUI | Project import → Outgoing WS-Security config tanımı → "Validate Incoming" |
| WS-Security | `xmlsec1` | `xmlsec1 --verify --id-attr:Id "*" --insecure <file>.xml` |

> `--insecure` / `-noverify` cert chain doğrulamayı kapatır — sebep:
> testlerimiz **self-signed test PFX'leri** kullanıyor (KURUM01/02/03_RSA2048/EC384).
> Production'da TR-EsHS / Kamu SM zincirleri ile gerçek validation yapılır.

### Negatif testlerin export edilmesi (label stratejisi)

`XAdESNegativeE2ETest`, `CAdESTamperedE2ETest`, `PAdESTamperedE2ETest` gibi
sınıflar 3rd-party araçlarda **`INVALID`** raporu üretmesi gereken artefaktları
da export eder (`xades-negative/`, `cades-detached/...__baseline.p7s/.bin`,
`pades-negative/`). `label` parametresi (`baseline` vs `tampered` vs
`wrap-attack`) dosya adında suffix olur — manuel inspeksiyonda baseline ile
tampered'ı yan yana karşılaştırmak için ipucu.

### Concurrency

`WsSecurityConcurrencyContractTest` (50 paralel thread) sadece **ilk 3
örneği** export eder. Sebep: 50 dosya = doğrulama gürültüsü; 3 örnek
"paralel imza içerik-doğru" sanity'sini karşılar. `InheritableThreadLocal`
ile child thread'lerde `ExtensionContext` resolve edilir.

### Üretim trafiği etkisi

| Trafik | Davranış |
|---|---|
| `mvn test` (default) | XAdES negatif + bazı default-suite testler export eder (~5 dosya, < 100 KB) |
| `mvn test -Dgroups='verifier-e2e'` | **~290 dosya, ~15-30 MB** (en büyük: WS-Security 50 KB SOAP fixture'ları) |
| `mvn test -Dgroups='pkcs11-integration'` | SoftHSM2 varsa 1 dosya (`xades/xadessoftHsm…__efatura.xml`) |
| CI | `target/` zaten artifact upload edilmez; isteğe bağlı GHA `actions/upload-artifact` ile dump alınabilir |

### Kapatma / temizlik

```bash
mvn test -Dsigned.artifacts.export=false       # tek koşu için export'u kapat
mvn test -Dsigned.artifacts.purge=false        # otomatik root purge'unu kapat (eski runları sakla)
rm -rf target/signed-artifacts                  # manuel temizlik
mvn clean                                        # tüm target/ ile birlikte
```

> **Default davranış**: `mvn test` her koşulduğunda root klasör
> tamamen silinir → sadece o run'da koşan testlerin çıktıları kalır.
> Yani `target/signed-artifacts/xades/` içinde **hayalet** dosya
> (önceki run'da koşmuş ama bu run'da koşmamış test'in çıktısı)
> görmezsiniz. Bu özellik PR review'larda "bu artefakt güncel mi?"
> sorusunu eler.

---

## 🔴 Önce yapılacak kod işleri — ⏸ DEFERRED (ayrı repo: `mersel-dss-verifier-api-java`)

> Bu maddeler **signer repo'sunun scope'unda değil**. Hepsi
> `mersel-dss-verifier-api-java` repo'sunda kapanmalıdır; signer
> repo'sundaki bir testle çözülemezler (verifier servisinin internal
> implementation'ına bağımlı). Burada yalnızca cross-repo backlog
> görünürlüğü için bırakılmıştır.

- [⏸] **(H)** Verifier `AdvancedSignatureVerificationService` için unit test
  - `openValidationPolicyStream()` resolution mantığı (5-6 test)
  - Dosya: `mersel-dss-verifier-api-java/src/test/java/.../AdvancedSignatureVerificationServiceTest.java`

- [⏸] **(H)** Verifier image GHCR push (yeni policy mimarisi ile)
  - Versiyon bump (SemVer minor — yeni profile sistem); `:main` veya `:v0.x.y` tag GHCR'a
  - Sonrası: signer CI'da `verifier_image_source=ghcr` default'u doğal çalışır

- [⏸] **(M)** Verifier built-in policy XML'leri için build-time smoke test
  - DSS `ValidationPolicyXmlLoader` ile parse ve validate
  - Dosya: `mersel-dss-verifier-api-java/src/test/java/.../PolicyXmlSmokeTest.java`

---

## A) XAdES — E-Belge varyasyonları — ✅ tamamlandı

> Tüm 12 production + regression fixture'ı `XadesDocumentFixture` enum'unda;
> `XAdESSignAndVerifyE2ETest` parametrize matrisi 5 PFX × 2 backend × 12
> fixture = 120 senaryo + 10 generic = 130 toplam. Yeni fixture eklemek
> için tek yol: enum'a yeni değer + `scripts/generate-xades-fixture-variants.py`'a
> (üretilebilir varyant için) yeni helper.

- [x] **(H)** `xades/efatura.xml`, `xades/earsiv-raporu.xml`, `xades/eirsaliye.xml`,
      `xades/emustahsil.xml`, `xades/hrxml.xml` — 5 production fixture
      (UBL e-Fatura, e-Arşiv Raporu, e-İrsaliye, e-Müstahsil, HR-XML).
      Her biri 10 iterasyon (5 PFX × 2 backend).
- [x] **(M)** `xades/efatura-large.xml` (~5 MB, 4797 `<cac:InvoiceLine>`) —
      ana matrise entegre; fixture-conditional perf log INFO seviyesinde
      yazılır (PR diff'inde gözle takip).
- [x] **(M)** `xades/efatura-with-bom.xml` (8323 byte = BOM 3 + efatura 8320) —
      ana matrise entegre; fixture-conditional sanity check ilk 3 byte'ın
      gerçekten `EF BB BF` olduğunu doğrular. Log gözlemi: signer DOM-roundtrip
      BOM'u tipik olarak kaybediyor (spec-uyumlu; verifier `TOTAL_PASSED`).
- [x] **(M)** `xades/efatura-mixed-newlines.xml` (8234 byte, 87 CRLF + 88 LF
      satır) — `scripts/generate-xades-fixture-variants.py` ile `efatura.xml`'den
      deterministic. XML 1.0 §2.11 line-ending normalization regresyon vektörü.
- [x] **(M)** `xades/xml-with-cdata.xml` (8160 byte). `<cbc:Note>` içine
      `<![CDATA[...&...]]>` enjekte; c14n CDATA→text + ampersand escape kontrolü.
- [x] **(M)** `xades/xml-with-comments.xml` (8297 byte, 3 yorum enjekte:
      prolog sonrası + `cac:InvoiceLine` öncesi/sonrası). EXC-C14N yorumları
      çıkarır, doğrulama bozulmamalı.
- [x] **(L)** `xades/xml-foreign-namespace-prefix.xml` (8374 byte, `cbc → tcbc`,
      `cac → tcac`; URI'ler aynı, `ext`/`ds`/`xades` korundu). Signer NS-URI
      agnostic olmalı; "lookupElement('cbc:…')" gibi prefix-bağımlı bir kod
      yolu burada patlar.
- [x] **(L)** `xades/efatura-unicode-emoji.xml` (8165 byte; 🚀 4-byte UTF-8
      + CJK 3-byte `中文` + Latin extended `ñoño` 2-byte). Surrogate-pair /
      UTF-8 indexing regresyon vektörü.

> **Bundan sonra ekleme isteği gelirse**: enum'a yeni entry + (üretilebilir
> ise) generator script'e helper; ana matriks otomatik 10 yeni iterasyon
> ekler. CI `expected` count'unu unutma.

---

## B) PAdES — PDF varyasyonları — ✅ kısmen tamamlandı (4 fixture, core kapsam)

> 4 fixture `PadesDocumentFixture` enum'unda + `PAdESDocumentVariationsE2ETest`
> içinde test entegrasyonu yapıldı. Fixture'lar iText 5.4.1 + Cp1254 ile
> programatik üretilip git'e commit edildi (generator class çalıştırılıp
> silindi — `commit_only` strategy). Yeniden üretmek gerekirse: yeni geçici
> bootstrap test class'ı, çıktıyı `resources/test-fixtures/pades/` altına dump.

### Test sınıfları

- [x] **(H)** `PAdESTamperedE2ETest` ✅ — tampered byte flip kontratı
      (1 senaryo, runtime üretim, fixture commit'siz). `byte[100]` flip
      ByteRange dahilinde → verifier `signatureIntact=false`. Detayları
      F bölümünde.
- [x] **(H)** `PAdESDocumentVariationsE2ETest` ✅ — PDF varyasyon (4
      senaryo, smart matrix: 1 PFX × 1 backend × 4 fixture). Pattern:
      mevcut `PAdESSignAndVerifyE2ETest` PFX/backend matrisini
      kopyalamak yerine, PDF yapısının key-tipinden bağımsız olduğunu
      varsayar ve sadece **PDF struct → sign + verify roundtrip**'e
      odaklanır. PDF magic byte sanity, signed PDF orijinalden büyük
      olmalı invariant'ları.

### Fixture envanteri — bu turda eklenen 4 fixture (tümü ✅)

- [x] **(H)** `pades/efatura-pdf.pdf` ✅ üretildi (3749 byte, 3 sayfa) —
      UBL-benzeri görsel e-Fatura (başlık + satıcı/alıcı + kalemler
      tablosu + tutar özeti). Türkçe karakter + ₺ sembolü + tablo
      yapısı. Multi-page byte-range coverage testi.
- [x] **(L)** `pades/turkish-chars.pdf` ✅ üretildi (2472 byte) —
      Cp1254 encoding ile tam Türkçe alfabe (ç, ş, ı, ğ, ü, ö, İ) +
      uzun paragraflar. Signer'ın PDF bayt akışını encoding-agnostic
      işlemesi gerek; aksi takdirde Türkçe glyph render farklılığı
      ByteRange digest mismatch oluşturur.
- [x] **(L)** `pades/landscape-a3.pdf` ✅ üretildi (2624 byte) —
      `PageSize.A3.rotate()` (1190.55 × 841.89 pt) + 8-kolon tablo
      (geniş layout). Visible signature (ileride) için yer testi;
      mevcut görünmez imzanın sayfa boyutuna kayıtsız çalıştığı
      doğrulanır.
- [x] **(M)** `pades/large-50pages.pdf` ✅ üretildi (22861 byte = 50
      sayfa, sayfa başına 15 paragraf). PDF compression sayesinde
      boyut küçük (~22KB) ama page-count regresyon vektörü olarak
      değerlidir; ByteRange kapsamının çok-sayfa PDF'de doğru hesaplandığı
      test edilir.

### Runtime senaryolar — ✅ tamamlandı (PAdESRuntimeScenariosE2ETest)

`PAdESRuntimeScenariosE2ETest` (verifier-e2e tag) 4 runtime senaryo
test eder; her senaryo iText 5.4.1 ile in-memory PDF üretir (commit
yok, JVM heap ile sınırlı):

- [x] **(L)** B-cosign: `appendMode=true` ile çift imza →
      PDF reader 2 signature dictionary görmeli, dosya büyümeli.
- [x] **(L)** B-encrypted: user-password ile şifrelenmiş PDF →
      `SignatureException` (sessiz başarı olmaz).
- [x] **(L)** B-form: AcroForm text field içeren PDF → imza sonrası
      field hâlâ AcroFields'ta görünür ve değer korunur.
- [x] **(L)** B-attachment: embedded file PDF/A-3 simülasyonu →
      imza sonrası PDF boyutu attachment dahil yeterince büyür.

### Açık (deferred — gelecek turda istenirse, commercial/external dep)

- [⏸] **(H)** Gerçek e-Fatura görsel PDF (mock VKN ile üretilmiş, QR +
      barkod + GİB template). Sentetik üretim "real e-Fatura" karakterini
      taşımaz; production'da gerçek bir test mükellefi PDF'i ideal.
      Mock VKN üretimi out-of-scope.
- [⏸] **(H)** `pades/pdfa-1b.pdf`, `pades/pdfa-2b.pdf` — PDF/A conformant.
      iText 5'in `PdfAWriter` desteği var ama font/colorspace conformance
      ayarları kompleks; veraPDF ile gerçek conformant fixture üretmek
      veya iText 7 commercial PDF/A modülü gerekir.
- [⏸] **(L)** `pades/scan-image-only.pdf` — image-only PDF (no OCR). Image
      ref'in PDF content stream'inde imza akışını bozmadığı doğrulanır.
      Düşük değer (`PAdESDocumentVariationsE2ETest` zaten `landscape-a3`
      + multi-page fixture ile ByteRange genişlik kontratını test ediyor).

---

## C) CAdES — Binary varyasyonları — ✅ kısmen tamamlandı (4 fixture, core kapsam)

> 4 fixture `CadesBinaryFixture` enum'unda + `CAdESBinaryVariationsE2ETest`
> içinde test entegrasyonu yapıldı. Fixture'lar elle (sample.txt) +
> Python tek-shot script ile (sample.bin SHA-256 seed, utf16-text.txt
> Python encoding, empty.bin touch) üretilip git'e commit edildi.
> Reproducibility: sample.bin için seed `mersel-cades-sample-bin-v1` +
> SHA-256 zinciri (10240 byte); reproducible.

### Test sınıfları

- [x] **(H)** `CAdESTamperedE2ETest` ✅ — tampered detached payload
      (1 senaryo, runtime üretim, fixture commit'siz). `byte[25]` flip
      → verifier reject. Detayları F bölümünde.
- [x] **(H)** `CAdESBinaryVariationsE2ETest` ✅ — fixture varyasyon
      (4 senaryo, smart matrix: 1 PFX × 1 backend × 4 fixture). Pattern:
      mevcut `CAdESSignAndVerifyE2ETest` PFX/backend matrisini kopyalamak
      yerine, fixture davranışının key-tipinden bağımsız olduğunu varsayar
      ve sadece **payload bayt-akışı**na odaklanır. Attached mode (verifier
      tek dosya kontratı daha basit; detached mode kontratı zaten ana
      matriste 5×2×2 ile karşılanıyor).

### Fixture envanteri — bu turda eklenen 4 fixture (tümü ✅)

- [x] **(H)** `cades/sample.txt` ✅ üretildi (2384 byte) — UTF-8 Türkçe
      gerçekçi metin payload, Türkçe diakritikler (ç, ş, ı, ğ, ü, ö, İ)
      + uzun ASCII paragrafları (asal sayı tekerlemesi, paragraf yapısı).
      Multibyte UTF-8 (~405 byte) regresyon vektörü.
- [x] **(H)** `cades/sample.bin` ✅ üretildi (10240 byte) — deterministic
      random binary, SHA-256 zinciri (seed `mersel-cades-sample-bin-v1`).
      C14n yok, saf binary CMS attached için. Reproducible.
- [x] **(M)** `cades/empty.bin` ✅ üretildi (0 byte) — edge case kontratı.
      Test `assertEmptyInputHandledGracefully` davranışı assert etmek
      yerine <em>dokümante</em> eder: signer ya RuntimeException atar
      (defansif) ya da boş ContentInfo üretir (RFC 5652 §5.3 spec-uyumlu —
      DSS 6.x default). Lokal gözlem: signer 1462 byte CMS overhead üretti
      (yapı geçerli, içerik boş). Build kırıcı değil; log üzerinden gözlem.
- [x] **(L)** `cades/utf16-text.txt` ✅ üretildi (1376 byte) — UTF-16 BE
      + BOM (`FE FF`) Türkçe text. Signer byte-stream-agnostic olmalı;
      encoding sniff'leyip conversion yapmamalı. CAdES output bayt-bayt
      aynı input'u digest etmeli; aksi takdirde verifier hash mismatch.

### Tamamlanan ek geliştirme

- [x] **(L)** Attached + detached mode varyasyon ✅ — 4 fixture × 2 mode = 8
      senaryo. `CAdESBinaryVariationsE2ETest` artık iki ayrı
      `@ParameterizedTest` method'u içerir:
      `cadesBinaryRoundtripIsValid` (attached, verifier API) +
      `cadesBinaryDetached_signatureIsCryptographicallyValid` (detached,
      lokal BouncyCastle `CMSSignedData` parser + `SignerInformation.verify`).
      RFC 5652 §5.1 detached invariant'ları (eContent null, signer cert
      store'da, cryptografically verify) explicit assert edilir.
      EMPTY_BIN edge-case her iki modda da graceful (throws veya valid
      empty CMS).

### Açık (gelecek turda istenirse — düşük öncelik, deferred)

- [⏸] **(M)** `cades/large-10mb.bin` — 10 MB deterministic binary;
      streaming + perf regresyon. Commit boyutu 10 MB git'i şişirir;
      runtime üretim daha temiz (`@BeforeAll` ile in-memory). Şu an
      değer/maliyet oranı düşük (perf vektörü WS-Security 50KB ile
      kapsanıyor).
- [⏸] **(M)** `cades/docx-sample.docx` — minimal valid OOXML; ZIP-based
      binary. Production "sözleşme imzalama" senaryosu. CAdES kontratı
      payload-shape-agnostic; mevcut 4 fixture (text + binary + empty +
      UTF-16) zaten encoding-agnostic kontratı kanıtlıyor. Yeni format
      eklemek için runtime üretim daha temiz.
- [⏸] **(L)** `cades/zip-archive.zip` — nested ZIP. Yukarıdakiyle aynı
      gerekçe — payload bytes-shape kontratı zaten kanıtlı.

---

## D) WS-Security — SOAP varyasyonları — ✅ tamamlandı

> Tüm 9 SOAP envelope (`SoapEnvelopeFixture` enum) `WsSecuritySignAndLocalVerifyE2ETest`
> matrisinde 5 PFX × 2 backend × 9 = **90 senaryo**; ek 3 structural kontrat
> `WsSecurityContractE2ETest` içinde (RSA PFX × JCA tek-iterasyon).

### Baseline

- [x] **(M)** `wssecurity/soap-1.1-envelope.xml` (648 byte) — baseline minimal envelope.
- [x] **(M)** `wssecurity/soap-1.2-envelope.xml` (618 byte) — baseline minimal envelope.

### Production parity + contract (eklendi)

- [x] **(H)** `wssecurity/gib-efatura-soap.xml` ✅ (3101 byte) —
      `soapenv/ei/xsd/xsi/gib` multi-NS + `xsi:type` + Türkçe element
      value + GİB endpoint paritesi. Ana matriste 10 iterasyon.
- [x] **(H)** `wssecurity/soap-with-wsa.xml` ✅ (1269 byte) —
      `wsa:MessageID`, `wsa:To`, `wsa:Action`, `wsa:ReplyTo/Address`.
      Ana matriste 10 + `WsSecurityContractE2ETest.wsAddressingPreservationContract`
      ile 4 element'in sign sonrası bayt-bayt korunduğu assert edilir.
- [x] **(H)** `wssecurity/soap-with-existing-wsu-id.xml` ✅ (1235 byte) —
      Body'de `wsu:Id="ClientProvidedBodyId-do-not-trust"`. Ana matriste
      10 + `WsSecurityContractE2ETest.wsuIdOverrideContract` ile sign
      sonrası `Id=SignedSoapBodyContent` var + `wsu:Id` silindi assert
      (shadow-reference saldırısı negatif kontrolü).
- [x] **(M)** `wssecurity/soap-multibody.xml` ✅ (1199 byte) — Body altında
      3 ayrı operation element. Ana matriste 10 iterasyon.
- [x] **(M)** `wssecurity/soap-large-50kb.xml` ✅ (50570 byte ≈ 49.4 KB;
      120 child item). Ana matriste 10 iterasyon — c14n + digest orta-büyüklük
      performans regresyonu vektörü. Lokal süre ölçümü: ana matriste 5 PFX
      × 2 backend × 9 fixture 90 iterasyon toplam ~3.7s, yani large fixture
      iterasyon başına < 100ms; CI'da rahat sığar.
- [x] **(M)** `wssecurity/soap-mtom-xop.xml` ✅ (1855 byte) —
      `<xop:Include href="cid:..."/>` element'leri içeren envelope. Gerçek
      MTOM multipart signer scope dışı; bu fixture sadece XML c14n'in
      XOP:Include element'lerini olduğu gibi koruduğunu test eder.
- [x] **(L)** `wssecurity/soap-with-existing-security-header.xml` ✅ (2321 byte) —
      Header'da `<wsse:Security>` + `UsernameToken`. Ana matriste 10 +
      `WsSecurityContractE2ETest.existingSecurityHeaderAppendContract` ile:
      - tek bir Security var (yeni yaratılmamış);
      - UsernameToken sign sonrası hâlâ var + username/password textual
        content değişmemiş;
      - Security direct-child = 4 (UsernameToken + signer'ın BST + Timestamp
        + Signature);
      - sign yine de valid.

### Ek geliştirme önerileri (fixture eklemeden) — ✅ tamamlandı

- [x] **(M)** Hash algorithm parametrize (SHA-256/384/512) ✅
      `WsSecurityHashAlgorithmParametrizedTest` (3 senaryo). Mock
      `DigestAlgorithmResolverService` ile her SHA varyantı zorlanır;
      imzalı SOAP çıktısında `ds:DigestMethod/@Algorithm` ve
      `ds:SignatureMethod/@Algorithm` URI'lerinin **birbirleriyle ve
      seçilen SHA ile tutarlı** olduğu assert edilir + lokal
      `javax.xml.crypto.dsig.XMLSignature` ile imza geçerli kalır
      (DigestMethod URI ↔ MessageDigest implementasyonu eşleşmeli).
      Regression vektörü: URI map'i bozulursa silent digest mismatch
      yerine net assertion failure.
- [x] **(M)** Mali Mühür envelope vs minimal envelope structural parity ✅
      `WsSecurityEnvelopeShapeParityTest` (3 senaryo). GİB Mali Mühür
      request envelope (`gib-efatura-soap.xml` — multi-namespace,
      `xsi:type`, Türkçe business element'leri) vs minimal SOAP 1.1
      envelope (`soap-1.1-envelope.xml` — header'sız, KamuSM-benzeri
      generic shape). İki envelope için de signer **aynı Security
      header skeleton'ı** (BST + Timestamp + Signature + 2 Reference)
      üretmeli; ek olarak Mali Mühür envelope'unun Türkçe business
      content'i (VKN, sender adı, alıcı adı) sign sonrası bayt-bayt
      korunur ve iki çıktı da lokal XMLDsig verifier'dan geçer.
- [x] **(M)** Concurrent 10 paralel WS-Security imzası ✅
      `WsSecurityConcurrencyContractTest.parallel10WsSecuritySignatures_allValid_noLeak`
      (1 senaryo; 10 paralel iş yükü + semaphore leak kontrolü).
      Rotating fixture, her thread kendi DocumentBuilder + Document'ı,
      hepsi lokal XMLDsig validator'dan geçer, semaphore permits
      başlangıç durumuna döner.

---

## F) Negatif test'ler (security) — ✅ tamamlandı

> Hibrit fixture stratejisi:
> - **Parser-level (xxe, billion-laughs)**: statik commit + `XmlSecurityTest`
>   (default suite, verifier-api yok — saf `SecureXmlFactories` regression).
> - **Sign+tamper (wrap, tampered, byte-flip, SHA-1)**: runtime üretim
>   (test başında fresh sign → DOM/byte mutation → verifier-MUST-fail).
>   Statik commit yerine runtime çünkü: (1) cert expire ettiğinde test
>   kırılmaz, (2) "signer doğru imza üretti" sanity'sini aynı testte ölçer,
>   (3) verifier davranışını daima canlı sign akışıyla karşılaştırır.
>
> **Toplam**: +2 default suite (XmlSecurityTest) + 6 verifier-e2e
> (XAdES wrap/tampered/sigval + PAdES tamper + CAdES tamper + SHA-1).

- [x] **(H)** `negative/xxe-attack.xml` ✅ statik commit (`<!DOCTYPE foo [
      <!ENTITY xxe SYSTEM "file:///etc/passwd">]>`); test:
      `XmlSecurityTest.xxeAttackIsRejected` — `SecureXmlFactories` parser'ı
      SAXParseException fırlatır (`disallow-doctype-decl` aktif). Hata
      mesajında "DOCTYPE" geçtiği da explicit assert; başka parse hatası
      ile yanlış-pozitif geçmesin diye.
- [x] **(H)** `negative/billion-laughs.xml` ✅ statik commit (9-seviye nested
      entity, 10^9 expansion); test: `XmlSecurityTest.billionLaughsIsRejected`
      — DOCTYPE reject ile defense-in-depth, expansion'a sıra gelmez.
      Süre < 5s assertion'ı parser zayıflığında uyarır.
- [x] **(H)** Wrap-attack runtime ✅ `XAdESNegativeE2ETest.wrapAttackRejected`:
      runtime UBL e-Fatura sign → DOM'da cbc:UUID altına yabancı element
      enjekte → verifier reference digest mismatch raporlamalı.
- [x] **(H)** Tampered-after-sign runtime ✅ `XAdESNegativeE2ETest.
      tamperedAfterSignRejected`: runtime sign → cbc:UUID text mutate
      → verifier digest mismatch. Pre-tamper baseline VALID kontrolü ile
      "test'in baseline'ı bozuk" sahte-pozitiften korunur.
- [x] **(H)** SignatureValue bit-flip ✅ `XAdESNegativeE2ETest.
      signatureValueTamperedRejected`: <ds:SignatureValue> base64
      decode → ilk byte flip → re-encode → verifier
      `cryptographicVerificationSuccessful=false`. Reference digest sağlam
      kalır; sadece kripto verify fail.
- [x] **(M)** `negative/tampered.pdf` runtime ✅ `PAdESTamperedE2ETest.
      pdfTamperedAfterSignRejected`: runtime PAdES sign → `byte[100]`
      flip (ByteRange dahilinde) → verifier `signatureIntact=false`.
- [x] **(M)** `negative/tampered.cms` runtime ✅ `CAdESTamperedE2ETest.
      cmsTamperedAfterSignRejected`: runtime CAdES **detached** sign →
      orijinal payload `byte[25]` flip (signature p7s'i değiştirilmiyor)
      → verifier reject. Detached mode pattern'i temiz çünkü payload
      ve signature ayrı bayt dizileri.
- [x] **(L)** `negative/old-sha1.xml` runtime ✅ `XAdESSha1LegacyE2ETest.
      sha1XadesIsRejectedOrWarnedByPolicy`: DSS `XAdESService`'i
      DigestAlgorithm.SHA1 ile DOĞRUDAN çağırır (signer servisi bypass —
      production servisi zaten SHA-1 üretmez). Verifier policy davranışı:
      `valid=false` (outright reject) **veya** `valid=true` + warning
      içinde SHA-1 mention. Üçüncü senaryo (`valid=true` + sessiz, hiçbir
      warning yok) regresyon = fail.

---

## 🎯 Allure best-practice patern (model: turn-11)

`CertificateLifecycleNegativeE2ETest` ve `XAdESPreSignedFixtureNegativeE2ETest`
artık Allure raporlama için **model-class** seviyesinde — tüm 7 best-practice
boyutu kullanılıyor; diğer 12 E2E testine pattern olarak yayılabilir:

| Boyut | Annotation / API | Sample değer (Lifecycle testinden) |
|---|---|---|
| **Epic** (top-level hierarchy) | `@Epic` | "Negative — Certificate Lifecycle" |
| **Feature** (alt-feature) | `@Feature` | "Revoked / Expired / Suspended Cert × XAdES/CAdES/PAdES/WSS" |
| **Story** (3. katman — dinamik) | `Allure.story(...)` | "REVOKED" / "EXPIRED" / "SUSPENDED" (test başına farklı) |
| **Severity** (kritiklik) | `@Severity` | `CRITICAL` / `BLOCKER` |
| **Description** (zengin HTML) | `@Description` | Birincil/ikincil kontrat + mali bağlam (VUK Md. 230) |
| **Owner** (sorumlu takım) | `@Owner` | "dss-signer-core" |
| **Link** (mevzuat + fixture ref'leri) | `@Link` | ETSI EN 319 102-1, Kamu SM tablosu, README |
| **Parameters** (auditor filtre) | `Allure.parameter(...)` | `certificateStatus`, `certificateAlgorithm`, `signatureFormat`, `pfxFile` |
| **Steps** (timeline) | `Allure.step(name, lambda)` | 6 adım: PFX kontrol → yükle → imzala → verify → export → assert |
| **Step-altı attachments** | `SignedArtifactExporter` → `Allure.addAttachment` | `.xml` + `.verify.json` step 5'in altına otomatik |

**Auditor faydası**: Allure UI'da "Behaviors" sekmesinde
`Negative — Certificate Lifecycle > ... > REVOKED` ağacını açtığında 6 senaryo
görür; her birinde `certificateStatus=REVOKED` filtresi vurabilir; timeline
6 step ile zenginleştirilmiş; step 5'in altında signed artifact + .verify.json
download'lanabilir; üst kısımda 3 mevzuat/fixture linki tek-tık erişim.

> Bu paterni diğer E2E testlerine de yaymak için en yüksek değerli üç
> dönüşüm sırasıyla: **(a)** method-level `@Description` zenginleştirme
> (Javadoc paralel), **(b)** `Allure.parameter(...)` ile parameterized
> testlerin filtrelenebilir hale gelmesi, **(c)** `Allure.step(...)` ile
> timeline zenginliği. Epic/Feature/Severity zaten 14/14 E2E'de bağlı.

---

## 🔴 Negatif sertifika lifecycle testleri — ✅ aktif (2026-05-18, turn-12)

> **Durum**: 6 negatif PFX (`testkurum_{status}_{algo}@test.com.tr_{pwd}.pfx`)
> `resources/test-certs/` altında. `PfxTestKey` enum gerçek password'lerle
> bağlandı. **Son koşum** (lokal verifier image):
> ```bash
> mvn test -Dtest=CertificateLifecycleNegativeE2ETest \
>   -Dgroups=verifier-e2e -DexcludedGroups= \
>   -DverifierImage=mersel-dss-verifier-api:local
> ```
> → **24 senaryo, 24 PASS, 0 SKIP, 0 FAIL** ✅
>
> | Format        | PASS | Not |
> |---|---|---|
> | XAdES         | 6/6 | DSS XAdES validator, KamuSM TEST CA chain, OCSP/CRL canlı |
> | CAdES         | 6/6 | DSS CAdES + `dss-cms-object` provider çözüldü (lokal build) |
> | PAdES         | 6/6 | DSS PAdES + `dss-pades-pdfbox` provider çözüldü (lokal build) |
> | WS-Security   | 6/6 | DSS XAdES validator (WS-Security gövdesini XAdES olarak görür) |
>
> 24 senaryonun her birinde **birincil kontrat** (`r.isValid() == false`)
> ve **ikincil kontrat** (`indication != "TOTAL_PASSED"`) sağlandı.
>
> ### Gözlemlenen subIndication tablosu (auditor sidecar'ından)
>
> | Status × Format | subIndication | Hint listesinde? |
> |---|---|---|
> | REVOKED   × XAdES | `REVOKED_NO_POE` | ✅ |
> | REVOKED   × CAdES | `REVOKED_NO_POE` | ✅ |
> | REVOKED   × PAdES | `REVOKED_NO_POE` | ✅ |
> | EXPIRED   × XAdES | `CERTIFICATE_CHAIN_GENERAL_FAILURE` | ⚠ (ama yine de INVALID) |
> | SUSPENDED × XAdES | `TRY_LATER` | ✅ |
> | REVOKED   × WSS   | `NO_SIGNING_CERTIFICATE_FOUND` | ⚠ (WSS BST yolu DSS XAdES validator'la cert reach edemiyor; rejection yine de doğru) |
>
> ### GHCR `:main` image rebuild — ✅ fix sertifikalandı
>
> Önceki koşumda `-DverifierImage` flag olmadan CAdES + PAdES senaryolarında
> 12 SKIP vardı (`No implementation found for ICMSUtils/IPdfObjFactory`).
> Sebep: GHCR `:main` image fat-jar içinde JAR'lar VAR ama Spring Boot
> runtime'da `ServiceLoader` provider'ları görmüyordu — packaging stale cache.
>
> [mersel-dss/mersel-dss-verifier-api-java#2](https://github.com/mersel-dss/mersel-dss-verifier-api-java/issues/2)
> ile `workflow_dispatch` rebuild tetiklendi (1m 1s, success).
> Fresh image pull edildikten sonra **flag gerekmeden** 24/24 PASS doğrulandı.
> Skip-tolerant test design'ı (`Assumptions.assumeTrue(false)`) korundu —
> gelecek benzer image transition'larında CI kırılmaz.

---

### Geçmiş — scaffolded turn (referans)

> Kamu SM test ortamı tablosundaki **revoked / expired / suspended** test
> sertifikalarıyla (RSA-2048 + EC-384 × 3 status = 6 PFX) sign+verify
> roundtrip negatifleri. Tamper testlerinden (F bölümü) farklı: imza
> matematik olarak doğru, sertifika lifecycle'ı geçersiz — verifier'ın
> bunu yakalaması ETSI EN 319 102-1 §5.2.6 gereği zorunludur.

### Mali/operasyonel önem

- **VUK Madde 230** + **e-Belge tebliği**: İmzanın `INDETERMINATE` /
  `REVOKED` / `EXPIRED` dönmesi durumunda düzenleyici fatura **hiç
  düzenlenmemiş** sayılır → KDV beyannamesinde aynı gün düzeltme
  cezası gündeme gelir. Signer'ın "yine de imzalar, verifier yakalar"
  defense-in-depth davranışını test ediyoruz.
- **Production behavior**: `CertificateValidatorService.validateCertificateDates`
  expired sertifikayı sign-time'da reddeder
  (`SigningMaterialFactory:73,103`). Revoked/suspended için signer revocation
  kontrolü yapmaz (`setRevocationEnabled(false)`); downstream verifier
  yakalar. Bu test verifier-side kontratı doğrular.

### Beklenen 6 PFX (manuel indirme — Kamu SM)

| # | Status | Algoritma | Beklenen dosya adı | Beklenen verifier davranışı |
|---|---|---|---|---|
| 1 | REVOKED   | RSA-2048 | `testkurum_revoked_rsa2048@test.com.tr_{PWD}.pfx`   | indication ≠ TOTAL_PASSED, sub=REVOKED / REVOKED_NO_POE |
| 2 | REVOKED   | EC-P384  | `testkurum_revoked_ec384@test.com.tr_{PWD}.pfx`     | indication ≠ TOTAL_PASSED, sub=REVOKED / REVOKED_NO_POE |
| 3 | EXPIRED   | RSA-2048 | `testkurum_expired_rsa2048@test.com.tr_{PWD}.pfx`   | indication ≠ TOTAL_PASSED, sub=OUT_OF_BOUNDS_NOT_FRESH / EXPIRED |
| 4 | EXPIRED   | EC-P384  | `testkurum_expired_ec384@test.com.tr_{PWD}.pfx`     | indication ≠ TOTAL_PASSED, sub=OUT_OF_BOUNDS_NOT_FRESH / EXPIRED |
| 5 | SUSPENDED | RSA-2048 | `testkurum_suspended_rsa2048@test.com.tr_{PWD}.pfx` | indication ≠ TOTAL_PASSED, sub=CERTIFICATE_HOLD / TRY_LATER |
| 6 | SUSPENDED | EC-P384  | `testkurum_suspended_ec384@test.com.tr_{PWD}.pfx`   | indication ≠ TOTAL_PASSED, sub=CERTIFICATE_HOLD / TRY_LATER |

> Kamu SM'den indirme adımları:
> [`resources/test-certs/README.md`](resources/test-certs/README.md).

### Repo tarafında yapılanlar (this turn)

- [x] **PfxTestKey enum genişletildi** — `Status` enum (VALID/REVOKED/
      EXPIRED/SUSPENDED), 6 yeni negatif constant
      (`KAMUSM_REVOKED_RSA2048`, `KAMUSM_REVOKED_EC384`,
      `KAMUSM_EXPIRED_RSA2048`, `KAMUSM_EXPIRED_EC384`,
      `KAMUSM_SUSPENDED_RSA2048`, `KAMUSM_SUSPENDED_EC384`),
      `positiveValues()` / `negativeValues()` filtreleri,
      `isAvailable()` (PLACEHOLDER token veya dosya yokken `false`).
- [x] **Mevcut pozitif matrisler korundu** —
      `XAdESSignAndVerifyE2ETest`, `CAdESSignAndVerifyE2ETest`,
      `PAdESSignAndVerifyE2ETest`, `WsSecuritySignAndLocalVerifyE2ETest`,
      `XadesSoftHsmVerifierE2ETest` artık `PfxTestKey.positiveValues()`
      üzerinden iterate eder (negatif key'ler pozitif assertion'lara
      karışmaz). `@EnumSource(PfxTestKey.class)` annotasyonları
      (`XAdESEcdsaSignatureFormatTest`, `SoftHsm2Pkcs11IntegrationTest`)
      `mode = MATCH_NONE, names = ".*_(REVOKED|EXPIRED|SUSPENDED)_.*"` ile filtreli.
- [x] **`CertificateLifecycleNegativeE2ETest`** —
      `@Tag("verifier-e2e")`, 6 PFX × 4 format (XAdES / CAdES / PAdES /
      WS-Security) = **24 senaryo**. Her senaryo
      `Assumptions.assumeTrue(key.isAvailable())` ile PFX yokken
      graceful skip. Pre-flight `validateCertificateDates`'i bypass
      eden `E2eSigningMaterialFactory` üzerinden imza üretir;
      verifier'a yollar; **primer kontrat**: `r.isValid() == false`.
      **Secondary kontrat**: `indication != "TOTAL_PASSED"`.
      Exact subIndication assertion'ı bilinçli yumuşak (DSS sürümleri
      6.x / 5.x farklı granülerlikte rapor verir); `.verify.json`
      sidecar'ına actual sub yazılır, auditor manuel inceleme yapar.
- [x] **`SignedArtifactExporter.Format`** — 4 yeni entry:
      `XADES_NEGATIVE_CERT`, `CADES_NEGATIVE_CERT`, `PADES_NEGATIVE_CERT`,
      `WSSECURITY_NEGATIVE_CERT`. "Tampered" (XADES_NEGATIVE) ile
      "negatif sertifika ile imzalanmış" (XADES_NEGATIVE_CERT)
      dump'ları klasör isminden ayırt edilir → auditor karıştırmaz.
- [x] **`resources/test-certs/README.md`** — naming convention, 6 PFX
      indirme tablosu (Kamu SM URL + email onay akışı), rename adımları,
      test komutu, klasör hijyeni.

### Kullanıcı aksiyonu (PFX yerleştirme akışı)

```bash
# 1) Kamu SM'den 6 ZIP indir (login + email onayı gerekir)
# 2) ZIP'i aç, içindeki pass.txt'yi oku
# 3) PFX'i resources/test-certs/ altına aşağıdaki adla rename + kopyala
mv ~/Downloads/RevokedRSA.pfx \
   resources/test-certs/testkurum_revoked_rsa2048@test.com.tr_${PASS}.pfx
# 4) Hepsi yerleşti mi kontrol:
ls -la resources/test-certs/testkurum_*.pfx
# 5) Testleri tetikle:
mvn test -Dtest=CertificateLifecycleNegativeE2ETest \
         -Dgroups=verifier-e2e -DexcludedGroups=
```

PFX yokken testler skip olur (verifier-e2e suite kırılmaz); PFX
geldikçe ilgili senaryolar otomatik aktive olur.

### Dump çıktısı (PFX yerleştikten sonra)

```
target/signed-artifacts/
├─ xades-negative-cert/      (6 dosya — 6 negatif PFX × XAdES)
│   └─ negativeCertSignAndVerify_verifierRejects__KAMUSM_REVOKED_RSA2048_XADES.xml
│   └─ ... + 5 daha + 6 .verify.json sidecar
├─ cades-negative-cert/      (6 .p7s)
├─ pades-negative-cert/      (6 .pdf)
└─ wssecurity-negative-cert/ (6 .xml)
```

Her `.verify.json` sidecar'da:
```json
{
  "certificateStatus": "REVOKED",
  "indication": "INDETERMINATE",
  "subIndication": "REVOKED_NO_POE",
  "expectedFailure": true,
  "expectedFailureReason": "Sertifika lifecycle revoked — verifier PASSED dönmemeli (DSS BBB / ETSI EN 319 102-1 §5.2.6)",
  "expectedSubIndicationHints": "REVOKED, REVOKED_NO_POE, REVOKED_CA_NO_POE",
  "expectationMet": true
}
```

Auditor Pages Evidence Site'ta dosyayı + sidecar'ı yan yana görür →
"negatif sertifika ile imzalandı, verifier şu subIndication ile
reddetti" kanıt zinciri.

---

## G) HTTP/API kontratı (controller-level, fixture beklemez) — ✅ tamamlandı

- [x] **(H)** G-1: `>200MB` upload → 413 ✅
      - `MultipartConfigSanityTest` (3 senaryo): production
        `application/properties`'te limit'in `200MB` olarak pinli kalması
        regresyonu (max-file-size + max-request-size + multipart.enabled).
      - `GlobalExceptionHandlerTest.testHandleMaxUploadSizeExceeded_returns413`:
        exception → 413 + `FILE_TOO_LARGE` ErrorModel mapping unit testi.
      - `MultipartLimitHttpContractTest` (2 senaryo): MockMvc seviyesinde
        tam HTTP flow — interceptor trap `MaxUploadSizeExceededException`
        atar, response status + ErrorModel JSON body assert edilir.
- [x] **(H)** G-2: Malformed multipart → 400 ✅
      `SignEndpointHttpEnvelopeContractTest`:
      - Yanlış field name'li multipart ("wrongFieldName" vs "document")
        → 400 INVALID_INPUT + ErrorModel JSON.
      - 0-byte document part → 400 (controller `isEmpty()` branch).
      Production'da 500 generic'e düşmemeli kontratı.
- [x] **(H)** G-3: Empty body → 400 ✅
      `SignEndpointHttpEnvelopeContractTest` (CAdES + PAdES parite):
      multipart body'de `document` part hiç olmasa controller 400 +
      INVALID_INPUT + ErrorModel JSON döner. Direkt invocation seviyesi
      `PadesControllerTest.g3_nullDocument_shouldReturnBadRequest` ve
      `CadesControllerTest.nullDocument_shouldReturnBadRequest` ile;
      MockMvc seviyesi yeni eklenen test ile.
- [x] **(M)** G-4: Concurrent 50 istek ✅
      `SignatureServiceSemaphoreConcurrencyTest` (3 senaryo, default
      suite). 50 paralel + Semaphore(2) → highWaterMark ≤ 2 +
      permit leak yok + cross-service shared semaphore.
- [x] **(M)** G-5: Wrong content-type → 415 ✅
      `SignEndpointHttpEnvelopeContractTest` (3 senaryo): CAdES + PAdES
      için `application/json` POST → 415 + `WRONG_CONTENT_TYPE` ErrorModel;
      CAdES için `text/plain` POST → 415.
      `GlobalExceptionHandlerTest.testHandleHttpMediaTypeNotSupported_returns415WithWrongContentTypeCode`
      unit seviyesi mapping testi.
      **Production kodu değişikliği**: `GlobalExceptionHandler`'a explicit
      `HttpMediaTypeNotSupportedException` handler eklendi — önceki
      davranışta generic `@ExceptionHandler(Exception.class)` 500
      döndürüyordu, şimdi spec-uyumlu 415.
- [x] **(L)** G-6: Chunked response streaming davranışı ✅
      `PadesControllerTest.g6_chunkedStreamingContract_bodyIsByteArrayNotStream`:
      response body `byte[]` (Content-Length set, chunked encoding değil)
      — proxy/LB uyumluluğu kontratı.

---

## H) HSM / PKCS#11 kontratı (fixture beklemez) — ✅ tamamlandı

- [x] **(H)** H-1: 2 paralel imzalama isteği aynı session'da ✅
      `SoftHsm2Pkcs11IntegrationTest.h1_parallelSign_onSameHsmToken_bothSucceed`
      (`pkcs11-integration` tag). RSA-2048, 2 thread × 3 iterasyon,
      her imza public key ile doğrulanır. IAIK PKCS#11 wrapper session
      pool'u race condition'sız tamamlamalı.
- [x] **(M)** H-2: PFX'te 2 anahtar varsa alias resolution ✅
      `KeyStoreLoaderServiceContractTest` (default suite, 3 senaryo):
      - `h2_multiKeyPfx_resolvesByExplicitAlias` — synthetic 2-key
        PFX'te keyA/keyB alias ile doğru entry resolve eder.
      - `h2_multiKeyPfx_resolvesBySerialNumber` — alias bilinmediğinde
        serial number ile resolution; BigInteger eşitliği.
      - `h2_multiKeyPfx_unknownAlias_throwsKeyStoreExceptionWithAliasList`
        — bilinmeyen alias hata mesajında mevcut alias'ları listeler
        (operator debug için kritik).
- [x] **(M)** H-3: PFX şifresi yanlış ✅
      `KeyStoreLoaderServiceContractTest.h3_wrongPin_throwsKeyStoreException`:
      yanlış PIN ile yükleme deterministik olarak `IOException`
      (PKCS12 HMAC integrity fail) atar; Spring layer
      `GlobalExceptionHandler.handleKeyStoreException` 500 + sabit
      `KEYSTORE_ERROR` koduna map eder (ham JCA exception sızmaz).

---

## 🌐 Public Evidence Site — `mersel-dss.github.io/mersel-dss-server-signer-java/`

> **Vizyon**: Auditor "düzenleyici signer'ı validate ettin mi?" diye sorduğunda → tek URL → 290+ testin pass/fail durumu + her imzalı dosyanın yanında `mersel-verifier-api` PASSED/INDETERMINATE response'u + coverage + API docs + security scan. **Pazardaki geleneksel bulut çözümleri "yeşil tik" UI gösterir, biz kanıt zincirini açıyoruz**.

### Site URL haritası

| URL | İçerik | Üretici |
|---|---|---|
| `/` | Custom landing (Tailwind CDN, build badge'leri, son commit SHA, test count, coverage %) | [`docs/landing/index.html`](docs/landing/index.html) + workflow `envsubst` |
| `/test-report/` | Allure Report (Suites / Behaviors / Categories / Graphs / Timeline / Trend) | `allure-maven-plugin` 2.12.0 + `allure-junit5` 2.27.0 |
| `/test-report/data/attachments/...` | Her test case için signed artifact + `mersel-verifier-api` response JSON | [`SignedArtifactExporter.exportWithVerification()`](src/test/java/io/mersel/dss/signer/api/testsupport/SignedArtifactExporter.java) |
| `/coverage/` | JaCoCo HTML (line/branch/method coverage) | `jacoco-maven-plugin` 0.8.11 |
| `/openapi/` | Scalar API Reference (canlı Spring Boot'tan `/v3/api-docs` çekildi + CDN-loaded `@scalar/api-reference`) | Workflow `Build runnable jar` + `Extract OpenAPI spec` adımları |
| `/security/` | OWASP Dependency-Check raporu (HTML + JSON) | `dependency-check-maven` 9.2.0 |

### Local preview — push'lamadan üret + serve

> Pages'e push edilenin **birebir aynısını** kendi makinende üretmek için:

```bash
./scripts/serve-pages-locally.sh --fast          # unit testler + Allure + JaCoCo + landing (~2 dk)
./scripts/serve-pages-locally.sh                 # tam: unit + verifier-e2e + OWASP + OpenAPI snapshot (~10 dk)
./scripts/serve-pages-locally.sh --skip-tests    # mevcut target/'i kullan, en hızlı sanity (~20s)
./scripts/serve-pages-locally.sh --help          # tüm flag'ler
```

Script `publish-pages.yml` workflow'unun aynı adımlarını local'de koşturur:

1. `mvn verify` (JaCoCo agent + Allure dump) — `--skip-e2e` ile sadece unit
2. `mvn allure:report` — `target/site/allure-maven-plugin/`
3. `mvn dependency-check:check` — `target/dependency-check-report.html`
4. `mvn package -DskipTests` + Spring Boot başlat + `curl /v3/api-docs` + Scalar API Reference (CDN-loaded HTML)
5. Test count + coverage % hesapla
6. `pages-output/` assembly: `test-report/` + `coverage/` + `openapi/` + `security/` + `index.html` (envsubst veya python ile metadata inject)
7. `python3 -m http.server 8765` ile serve + browser otomatik açılır

| Flag | Etkisi | Tipik kullanım |
|---|---|---|
| `--skip-tests` | Mevcut `target/`'i kullan | Sadece landing/assembly testlemek |
| `--skip-e2e` | Verifier-e2e suite atlanır | Docker yoksa, hızlı geri bildirim |
| `--skip-owasp` | NVD scan atlanır | İlk koşumda 5dk NVD download'u atla |
| `--skip-openapi` | Spring Boot bootstrap atlanır | App ayağa kalkmıyorsa veya hızlanmak için |
| `--fast` | `--skip-e2e --skip-owasp` shortcut | Günlük dev loop |
| `--no-serve` | Üret ama HTTP server başlatma | CI/headless |
| `--port N` | Alternatif port (default 8765) | 8765 kullanımdaysa |

> **macOS uyarısı**: `envsubst` (gettext paketinde) yoksa script python fallback kullanır → ekstra `brew install gettext` gerekmez.

### Workflow

`.github/workflows/publish-pages.yml` — trigger: `push: main` + `workflow_dispatch`. İki job:

1. **build** (~25 dk):
   - JDK 8 + Maven cache
   - NVD database cache (ay başı invalidate, key'de `YYYY-MM`)
   - Allure history cache restore (trend grafiği için previous-build `history/` klasörü)
   - `mvn verify` — JaCoCo agent inject + 290+ test (`-Dgroups= -DexcludedGroups=pkcs11-integration`)
   - `mvn allure:report` — Allure history dahil HTML üret
   - Allure history cache save (sonraki build için)
   - `mvn dependency-check:check` — NVD scan (continue-on-error; rate-limit varsa rapor eksik kalır)
   - `mvn package -DskipTests` → `java -jar` background → `curl /v3/api-docs` → Scalar API Reference (CDN-loaded `@scalar/api-reference`)
   - Test count + coverage % hesapla (landing'e `envsubst` ile inject)
   - `pages-output/` assembly: test-report/ + coverage/ + openapi/ + security/ + landing index.html
   - `actions/configure-pages@v5` + `actions/upload-pages-artifact@v3`
2. **deploy**: `actions/deploy-pages@v4` — `github-pages` environment, Pages URL'i workflow run output'una bağlı.

**Önemli prensip**: Tüm test/rapor adımları `continue-on-error: true`. **Test fail olsa bile Pages publish edilir** — fail kanıtı da auditor için değerli. Yalnızca checkout/JDK kurulum bozulursa deploy skip.

### `.verify.json` sidecar formatı

Her positive E2E test, imzalı artifact'ın yanına flatten verifier-api response'u yazar. Örnek:

```json
{
  "artifact": "xades__xadesfixtureroundtripisvalid__kurum01_rsa2048_pfx_jca_efatura.xml",
  "format": "XADES",
  "generatedAt": "2026-05-17T22:34:13.214Z",
  "generatedBy": "XAdESSignAndVerifyE2ETest#xadesFixtureRoundtripIsValid",
  "verifierName": "mersel-verifier-api",
  "verifierEndpoint": "http://localhost:54219",
  "validationTime": "2026-05-17T22:34:12.998Z",
  "overallValid": true,
  "overallStatus": "VALID",
  "signatureType": "XADES",
  "signatureCount": 1,
  "indication": "TOTAL_PASSED",
  "subIndication": null,
  "signatureFormat": "XAdES-BASELINE-B",
  "signatureLevel": "XAdES-BASELINE-B",
  "signedBy": "CN=KURUM01_RSA2048, O=KamuSM Test, C=TR",
  "issuer": "CN=KamuSM SSLR Test CA, O=KamuSM Test, C=TR",
  "validationDetails": {
    "signatureIntact": true,
    "certificateChainValid": true,
    "certificateNotExpired": true,
    "certificateNotRevoked": true,
    "trustAnchorReached": true,
    "timestampValid": false,
    "cryptographicVerificationSuccessful": true,
    "revocationCheckPerformed": false
  },
  "expectedIndication": "TOTAL_PASSED",
  "expectationMet": true
}
```

Negative testlerde ek alanlar:

```json
{
  "expectedFailure": true,
  "expectedFailureReason": "wrap-attack: cbc:UUID altına yabancı element enjekte; reference digest mismatch beklenir",
  "indication": "TOTAL_FAILED",
  "expectationMet": true
}
```

`expectationMet=true` her iki tarafta da yeşil işarettir: positive'de PASSED bekledik PASSED geldi, negative'de FAIL bekledik FAIL geldi.

### Allure Behaviors hierarchy

Test class'larına eklenen annotation'lar (`@Epic`/`@Feature`/`@Severity`) Allure UI'da **Behaviors** tab'inde 2-seviyeli drilldown sağlar:

- **Signature Roundtrip** → XAdES / CAdES / PAdES / WS-Security positive testler
- **Negative — Tampering** → XAdES wrap-attack/tamper/sig-flip, CAdES detached tamper, PAdES ByteRange tamper
- **Negative — Crypto Policy** → XAdES SHA-1 legacy
- **Concurrency** → WS-Security 10 paralel imza
- **Infrastructure** → Verifier API container smoke
- **Service Layer** → unit testler (CAdESSignatureService, PAdESSignatureService, WS-Security service)
- **Crypto Conformance** → XAdES ECDSA r||s format

### Debug rehberi

| Symptom | Olası neden | Aksiyon |
|---|---|---|
| Pages publish'i fail oldu, deploy adımında | `pages-output/` boş veya checkout/JDK fail | build job log'larına bak; Maven adımları `continue-on-error` ama base kurulum fail ederse `pages-output` üretilmez |
| Landing'de `${BUILD_NUMBER}` literal görünüyor | `envsubst` çalışmadı veya placeholder bulunamadı | Workflow `Assemble pages-output` adımındaki env block'una bak; tüm placeholder'lar tanımlı mı? |
| Allure'da trend grafiği boş | İlk build (history yok) veya cache key değişti | 2. build sonrası görünmeli; cache key `allure-history-{repo_id}-v1` sabit |
| `/openapi/` Scalar API Reference boş veya "loading…" görünüyor | Spring Boot context init fail oldu veya `/v3/api-docs` 30s'de cevap vermedi; ya da CDN (`cdn.jsdelivr.net/@scalar/api-reference`) erişilemiyor | `boot.log` tail'ına bak (workflow output'unda); springdoc dependency var mı kontrol et; offline ortamda doğrudan `openapi.json` linkine bak |
| Coverage % `0%` görünüyor | JaCoCo agent inject olmamış veya report goal koşmamış | `mvn verify` koştu mu? `target/jacoco.exec` var mı? Surefire argLine'da `@{argLine}` literal duruyor mu? |
| OWASP report `/security/index.html` "unavailable" gösteriyor | NVD download rate-limit (`NVD_API_KEY` secret'ı yok) | Repo'ya `NVD_API_KEY` secret ekle (NVD'den ücretsiz alınır); cache hit'lerde ihtiyaç azalır |
| Test fail oldu ama Pages yine deploy edildi | Beklenen davranış (`continue-on-error: true`) | Allure raporundaki RED satırlara bak; **fail kanıtı da Pages'in değeri** |
| `.verify.json` boş veya `verifierResponseMissing: true` | Verifier container ayağa kalkmadı veya `VerifierBackendUnavailable` throw oldu (eksik DSS modülü) | Verifier image'in DSS modüllerini içerdiğinden emin ol; `:main` tag'i kullanılıyor — eski image'da `dss-cms-object` yoksa CAdES verify fail |

### One-time setup (kullanıcı)

GitHub Settings'ten Pages source'u "GitHub Actions" olarak işaretlemek gerekir (legacy "Deploy from branch" değil):

```bash
# CLI üzerinden aktif et
gh api -X POST /repos/mersel-dss/mersel-dss-server-signer-java/pages \
  -f build_type=workflow
```

veya UI: `Settings → Pages → Source → GitHub Actions`.

İlk push sonrası site `https://mersel-dss.github.io/mersel-dss-server-signer-java/` üzerinde canlı olur. Custom domain (örn. `evidence.mersel.io`) DNS setup gerektirir; şu an default subdomain kullanılıyor.

### Mali yorum (neden bu yatırım önemli)

- **e-Belge ekosisteminde "imzaladım" demek yetmez** — VUK 230, e-Belge tebliği 509 ve teknik kılavuzlar imzanın `INDETERMINATE` / `REVOKED` / `EXPIRED` dönmesini fatura reddine bağlar. Auditor "düzenleyici signer'ı validate ettin mi?" diye sorduğunda → tek URL → 290 satır, hepsi PASSED, her satırın altında verifier response → 30 saniyede ikna.
- **Pazardaki geleneksel bulut çözümleri** "yeşil tik" UI gösterir, kanıtı kullanıcıya açmaz. Biz CI'da otomatik public publish ile **transparency premium** sunuyoruz — özellikle YMM ofisleri ve dış denetim alıcıları için diferansiyel.
- **Regression hızlı yakalanır** — Allure trend grafiği build-build pass/fail eğrisini gösterir; bir signer regression'ı yeşilden sarıya/kırmızıya geçiş anında görsel olarak fark edilir.
