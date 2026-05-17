# `resources/test-certs/` — Kamu SM test sertifikaları

Bu dizin, Kamu Sertifikasyon Merkezi (Kamu SM) test ortamında **publicly published**
mali mühür test sertifikalarını barındırır. Buradaki PFX'ler:

- Production değildir — Kamu SM tarafından test amaçlı yayımlanmış,
  şifreleri dosya adının son segmentinde **bilerek açıkta** tutulan
  sertifikalardır.
- Mali mühür yetkisi yoktur, gerçek e-Belge gönderiminde kullanılamaz.
- Repo'ya commit edilir çünkü hem CI hem de yerel `verifier-e2e` suite'i
  bunlara bağımlıdır.

> Üretim mali mühür PFX'i bu repo'ya **asla** girmez — production'da
> HSM/PKCS#11 üzerinden referans alınır.

## Naming convention

```
{kurum}_{algo}[_{status}]@{domain}_{password}.pfx
```

- `kurum` — `testkurum01`, `testkurum02`, `testkurum03` (pozitifler) veya
  `testkurum` (negatifler — Kamu SM'in tek bir test cert publish ettiği case'ler)
- `algo` — `rsa2048` veya `ec384`
- `status` (opsiyonel) — `revoked` / `expired` / `suspended`
  (yoksa = `valid`, pozitif default)
- `domain` — Kamu SM ZIP'inde geçen sahiplik adı (`test.com.tr`, `sm.gov.tr`)
- `password` — PKCS#12 password (dosya adının son `_` ile başlayan segmenti);
  `PfxTestKey.parsePassword()` regex'i: `^.+_([A-Za-z0-9]+)\.pfx$`

Alias her PFX için sabit: `"1"` (`PfxTestKey.DEFAULT_ALIAS`).

## Pozitif (Status.VALID) — mevcut envanter (✓)

Bu PFX'ler repo'da var ve default `verifier-e2e` matriksinde aktif:

| Dosya | Algoritma | Sahiplik domain |
|---|---|---|
| `testkurum01_rsa2048@test.com.tr_614573.pfx` | RSA-2048 | test.com.tr |
| `testkurum02_rsa2048@sm.gov.tr_059025.pfx`   | RSA-2048 | sm.gov.tr |
| `testkurum02_ec384@test.com.tr_825095.pfx`   | EC-P384  | test.com.tr |
| `testkurum03_rsa2048@test.com.tr_181193.pfx` | RSA-2048 | test.com.tr |
| `testkurum03_ec384@test.com.tr_540425.pfx`   | EC-P384  | test.com.tr |

## Negatif (Status.REVOKED / EXPIRED / SUSPENDED) — beklenen (⏳ manuel indirme)

`CertificateLifecycleNegativeE2ETest` aşağıdaki 6 PFX'i bekler. Bunlar Kamu SM
sayfasında **manuel download + email onayı** gerektirdiği için repo'ya
otomatik konmamıştır:

| # | Kamu SM sayfasındaki link adı | Hedef dosya adı | Beklenen verifier davranışı |
|---|---|---|---|
| 1 | "Kamu SM — İptal Edilmiş Mali Mühür Test Sertifikası" (RSA) | `testkurum_revoked_rsa2048@test.com.tr_{PWD}.pfx` | INDETERMINATE/TOTAL_FAILED, sub=REVOKED |
| 2 | "Kamu SM — İptal Edilmiş EC384 Mali Mühür Test Sertifikası" (EC) | `testkurum_revoked_ec384@test.com.tr_{PWD}.pfx`   | INDETERMINATE/TOTAL_FAILED, sub=REVOKED |
| 3 | "Kamu SM — Bir Günlük Zamanı Geçmiş Mali Mühür Test Sertifikası" (RSA) | `testkurum_expired_rsa2048@test.com.tr_{PWD}.pfx` | INDETERMINATE/TOTAL_FAILED, sub=OUT_OF_BOUNDS_NOT_FRESH / EXPIRED |
| 4 | "Kamu SM — Bir Günlük Zamanı Geçmiş EC384 Mali Mühür Test Sertifikası" (EC) | `testkurum_expired_ec384@test.com.tr_{PWD}.pfx`   | INDETERMINATE/TOTAL_FAILED, sub=OUT_OF_BOUNDS_NOT_FRESH / EXPIRED |
| 5 | "Kamu SM — Askıya Alınmış Mali Mühür Test Sertifikası" (RSA) | `testkurum_suspended_rsa2048@test.com.tr_{PWD}.pfx` | INDETERMINATE, sub=CERTIFICATE_HOLD |
| 6 | "Kamu SM — Askıya Alınmış EC384 Mali Mühür Test Sertifikası" (EC) | `testkurum_suspended_ec384@test.com.tr_{PWD}.pfx`   | INDETERMINATE, sub=CERTIFICATE_HOLD |

### Adım adım indirme

1. https://yazilim.kamusm.gov.tr/ → Test Sertifikaları sayfasına git
   (Mali Mühür → Test Sertifikası bölümü).
2. Yukarıdaki tabloda listelenen 6 ZIP'i ayrı ayrı indir. Her ZIP için
   Kamu SM email onayı + captcha isteyebilir; otomasyona uygun değildir.
3. ZIP'i aç → içinde 1 adet `.pfx` ve 1 adet `pass.txt` (veya benzer)
   vardır. `pass.txt`'deki PKCS#12 şifresini hatırla.
4. PFX'i `resources/test-certs/` altına aşağıdaki adla **rename ederek**
   kopyala:

   ```
   testkurum_revoked_rsa2048@test.com.tr_{PASS.TXT İÇERİĞİ}.pfx
   ```

   Örnek: pass.txt → `847291` ise dosya adı
   `testkurum_revoked_rsa2048@test.com.tr_847291.pfx` olur.

5. 6 PFX dosyasının da repo'da görüldüğünü doğrula:

   ```bash
   ls -la resources/test-certs/testkurum_*.pfx
   ```

### Şifrenin dosya adında olmasının nedeni

`PfxTestKey` enum constructor'ı dosya adının son `_` segmentinden PKCS#12
şifresini parse eder (yani enum'a şifre **yazmaz**). Bu yaklaşım:

- Yeni PFX eklemek için kod değişikliği gerektirmez (sadece enum'a yeni
  constant eklenir, dosya adından şifre okunur).
- Test sertifikaları zaten public olduğu için "güvenlik" gerekçesi yok.
- Production yolunda **kullanılmaz**: production'da PIN HSM'de saklanır,
  PFX/şifre kombinasyonu yoktur.

## Testleri çalıştırma

PFX'leri yerleştirdikten sonra:

```bash
# Sadece lifecycle negatif testleri (verifier-e2e tag'i)
mvn test \
    -Dtest=CertificateLifecycleNegativeE2ETest \
    -Dgroups=verifier-e2e \
    -DexcludedGroups=

# Tüm verifier-e2e suite (pozitif + negatif)
mvn test -Dgroups=verifier-e2e -DexcludedGroups=
```

Dosya yoksa testler `Assumptions.assumeTrue(...)` ile graceful skip eder —
suite kırılmaz, sadece "skipped" raporlanır.

## Klasör hijyeni

- `*.pfx` dosyaları repo'ya commit edilir (yukarıda açıklandığı üzere — test material).
- ZIP, `pass.txt` veya başka indirilmiş artefakt **bu dizine konmaz**;
  sadece rename edilmiş `.pfx` dosyası kalır.
- Bu README'yi güncel tut: yeni Kamu SM test sertifikası kategorisi
  eklendiğinde önce bu tabloya satır ekle, sonra `PfxTestKey` enum'una.
