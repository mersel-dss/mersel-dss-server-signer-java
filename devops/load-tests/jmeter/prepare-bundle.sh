#!/usr/bin/env bash
# prepare-bundle.sh — Self-contained JMeter test paketi hazırlar.
#
# Çıktı klasörünü test makinesine `scp -r` veya `rsync` ile gönderirsin,
# orada sadece `./run.sh --host signer.prod.local ...` koşturursun. Repo
# kopyalamaya, mvn'e, başka bağımlılığa gerek yok — sadece JMeter.
#
# Kullanım:
#   ./devops/load-tests/jmeter/prepare-bundle.sh /tmp/signer-loadtest
#   ./devops/load-tests/jmeter/prepare-bundle.sh /tmp/signer-loadtest --tgz
#   ./devops/load-tests/jmeter/prepare-bundle.sh /tmp/signer-loadtest \
#       --extra-xades /home/me/custom-fatura.xml
#
# Üretilen layout:
#   <target>/
#   ├── run.sh                    (bundle-aware, repo'ya bağımlı değil)
#   ├── signer-stress.jmx         (verifier round-trip script INLINE — CDATA)
#   ├── xades-fixtures.csv        (path'leri xades/* olarak rewrite edilmiş)
#   ├── pades-fixtures.csv        (path'leri pades/* olarak rewrite edilmiş)
#   ├── xades/*.xml               (fixture binary'leri)
#   ├── pades/*.pdf
#   └── README.md                 (bundle-spesifik kısa kullanım)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

if [[ $# -lt 1 ]]; then
  cat <<EOF
Kullanım: $0 <target-dir> [opsiyonlar]

Opsiyonlar:
  --tgz                  Bundle'ı ek olarak <target>.tgz olarak da paketler
  --extra-xades <path>   XAdES CSV'ye ek bir XML ekler (birden çok kez verilebilir)
  --extra-pades <path>   PAdES CSV'ye ek bir PDF ekler (birden çok kez verilebilir)
  --no-defaults          Repo'daki default fixture'ları DAHIL ETME (sadece --extra-* ile)
  -h, --help             Bu mesajı göster

Örnekler:
  $0 /tmp/signer-loadtest
  $0 /tmp/signer-loadtest --tgz
  $0 /tmp/signer-loadtest --extra-xades /home/me/special-fatura.xml --tgz
EOF
  exit 0
fi

TARGET_DIR="$1"; shift
MAKE_TGZ="false"
INCLUDE_DEFAULTS="true"
EXTRA_XADES=()
EXTRA_PADES=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tgz) MAKE_TGZ="true"; shift ;;
    --no-defaults) INCLUDE_DEFAULTS="false"; shift ;;
    --extra-xades) EXTRA_XADES+=("$2"); shift 2 ;;
    --extra-pades) EXTRA_PADES+=("$2"); shift 2 ;;
    -h|--help)
      "$0"  # arg'sız çağrı help basar
      exit 0
      ;;
    *) echo "Bilinmeyen flag: $1" >&2; exit 2 ;;
  esac
done

# --------- Hazırlık ---------
if [[ -e "${TARGET_DIR}" && -n "$(ls -A "${TARGET_DIR}" 2>/dev/null)" ]]; then
  echo "⚠️  Hedef klasör boş değil: ${TARGET_DIR}"
  read -r -p "İçeriği silinsin mi? [y/N] " ans
  if [[ "${ans}" =~ ^[Yy]$ ]]; then
    rm -rf "${TARGET_DIR}"
  else
    echo "İptal."
    exit 1
  fi
fi

mkdir -p "${TARGET_DIR}/xades" "${TARGET_DIR}/pades"

# --------- 1) Çekirdek dosyalar ---------
# verifier-bridge.groovy artık JMX'in <script> CDATA'sında inline gömülü;
# ayrı dosya kopyalanmıyor (self-contained, tek source of truth).
cp "${SCRIPT_DIR}/run.sh"                            "${TARGET_DIR}/run.sh"
cp "${SCRIPT_DIR}/plan/signer-stress.jmx"            "${TARGET_DIR}/signer-stress.jmx"
chmod +x "${TARGET_DIR}/run.sh"

# --------- 2) Fixture binary'leri + CSV path rewrite ---------
{
  echo "filePath,documentType,mimeType"
  if [[ "${INCLUDE_DEFAULTS}" == "true" ]]; then
    # Repo default'larını bundle'a kopyala + path'leri xades/<file>'a indir
    awk -F, 'NR>1 && $1 != "" {print}' "${SCRIPT_DIR}/data/xades-fixtures.csv" |
      while IFS=, read -r filePath documentType mimeType; do
        srcAbs="${REPO_ROOT}/${filePath}"
        if [[ ! -f "${srcAbs}" ]]; then
          echo "⚠️  Atlandı (repo'da bulunamadı): ${filePath}" >&2
          continue
        fi
        fname="$(basename "${srcAbs}")"
        cp -n "${srcAbs}" "${TARGET_DIR}/xades/${fname}"
        echo "xades/${fname},${documentType},${mimeType}"
      done
  fi
  # Extra XML'ler
  for extra in "${EXTRA_XADES[@]}"; do
    if [[ ! -f "${extra}" ]]; then
      echo "⚠️  --extra-xades atlandı (yok): ${extra}" >&2
      continue
    fi
    fname="$(basename "${extra}")"
    cp "${extra}" "${TARGET_DIR}/xades/${fname}"
    echo "xades/${fname},UblDocument,application/xml"
  done
} > "${TARGET_DIR}/xades-fixtures.csv"

{
  echo "filePath,mimeType"
  if [[ "${INCLUDE_DEFAULTS}" == "true" ]]; then
    awk -F, 'NR>1 && $1 != "" {print}' "${SCRIPT_DIR}/data/pades-fixtures.csv" |
      while IFS=, read -r filePath mimeType; do
        srcAbs="${REPO_ROOT}/${filePath}"
        if [[ ! -f "${srcAbs}" ]]; then
          echo "⚠️  Atlandı (repo'da bulunamadı): ${filePath}" >&2
          continue
        fi
        fname="$(basename "${srcAbs}")"
        cp -n "${srcAbs}" "${TARGET_DIR}/pades/${fname}"
        echo "pades/${fname},${mimeType}"
      done
  fi
  for extra in "${EXTRA_PADES[@]}"; do
    if [[ ! -f "${extra}" ]]; then
      echo "⚠️  --extra-pades atlandı (yok): ${extra}" >&2
      continue
    fi
    fname="$(basename "${extra}")"
    cp "${extra}" "${TARGET_DIR}/pades/${fname}"
    echo "pades/${fname},application/pdf"
  done
} > "${TARGET_DIR}/pades-fixtures.csv"

# --------- 3) Bundle-spesifik kısa README ---------
cat > "${TARGET_DIR}/README.md" <<'BUNDLE_README'
# Mersel DSS Signer — JMeter Stres Test Bundle

Bu klasör, **kendi içinde tam çalışır** bir JMeter yük test paketidir. Repo
kopyalamaya, mvn/maven'a, başka bağımlılığa **gerek yoktur** — sadece bu
makinede `jmeter` 5.6+ kurulu olsun yeter.

## Hızlı Kullanım — CLI

```bash
# Yalnızca imza testi
./run.sh --host signer.prod.local --port 443 --protocol https

# İmza + Verifier API doğrulaması (her başarılı imzayı verifier'a yolla)
./run.sh \
  --host signer.prod.local --port 443 --protocol https \
  --verify --verifier-url https://verifier.prod.local

# Auth gerekiyorsa
AUTH_HEADER="Bearer eyJ..." ./run.sh \
  --host signer.prod.local --port 443 --protocol https \
  --verify --verifier-url https://verifier.prod.local

# Hızlı sanity (30 sn)
./run.sh --smoke --host signer.prod.local --port 443 --protocol https

# Stres (15 dk, 200 thread)
./run.sh --stress --host signer.prod.local --port 443 --protocol https
```

## JMeter GUI ile Kullanım

> ⚠️ GUI **debug / sanity / parametre tweak** için ideal. Büyük yük testleri
> (`--stress`, `--soak`, `--spike`) için **CLI kullan** — GUI sonuçları çarpıtır.

```bash
# JMeter'ı HERHANGİ BİR DİZİNDEN aç — path resolution otomatik.
jmeter -t /opt/signer-loadtest/signer-stress.jmx
# (veya boş JMeter aç → File → Open ile .jmx'i seç)

# Sol panel → "Stress Test Variables" → HOST, VERIFIER_URL, vs. doldur
# Sol panel → "View Results Tree" → sağ tık → Enable (debug için)
# Yeşil ▶ ile koş
# Bittikten sonra Tools → Generate HTML Report
```

GUI'de göreceğin yapı: Test Plan altında **setUp — Resolve Paths** thread group
(test başında 1 kere çalışır, CSV/fixture/verifier-script path'lerini
auto-resolve eder) + 2 normal Thread Group (XAdES sustained + PAdES sporadic),
her birinin altında HTTP Sampler + Response Assertion + Verifier PostProcessor.
Listener'lar default disabled, GUI'de sağ tık → Enable ile açılır (sonra kapat
ki sonraki koşumu kasmasın).

`setUp — Resolve Paths` sampler `jmeter.log`'a layout/path bilgisini basar —
"FileNotFoundException" gibi bir hata alırsan log'dan path'leri kontrol et.

## Profiller

| Profil       | XAdES thread | Duration | Amaç                                  |
| ------------ | ------------:| --------:| ------------------------------------- |
| `--smoke`    |            5 |    30 sn | Endpoint sanity / CI                  |
| _(baseline)_ |           50 |     5 dk | Tipik production benzeri yük          |
| `--stress`   |          200 |    15 dk | Kapasite tavanı arama                 |
| `--soak`     |          100 |     1 sa | Memory / session / TLS leak avı       |
| `--spike`    |          500 |     2 dk | Ani trafik (backlog, connection pool) |

`./run.sh --help` ile tüm flag listesi.

## Çıktı

```
results/<timestamp>-<profile>/
├── result.jtl       # Raw sample data (CSV)
├── jmeter.log       # JMeter motor logu
└── report/index.html # Apache JMeter HTML dashboard ← burada
```

## Kendi Fixture'larını Eklemek

`xades/` ve `pades/` klasörlerine kendi dosyalarını koyup CSV'lere bir satır
ekle. Format:

`xades-fixtures.csv`:
```
filePath,documentType,mimeType
xades/my-document.xml,UblDocument,application/xml
```

`pades-fixtures.csv`:
```
filePath,mimeType
pades/my-document.pdf,application/pdf
```

DocumentType değerleri: `UblDocument`, `EArchiveReport`, `EBiletReport`,
`HrXml`, `OtherXmlDocument`.

## Dosya Listesi

```
.
├── run.sh                   # Launcher (bundle-aware)
├── signer-stress.jmx        # JMeter test planı (verifier script INLINE)
├── xades-fixtures.csv       # XAdES fixture listesi
├── pades-fixtures.csv       # PAdES fixture listesi
├── xades/*.xml              # XAdES test belgeleri
└── pades/*.pdf              # PAdES test belgeleri
```

## Verifier round-trip

Verifier'a POST atan Groovy script **JMX'in `<script>` CDATA'sında inline** —
bundle'da ayrı bir `.groovy` dosyası YOK, gerek de yok. `VERIFIER_ENABLED=false`
(default) iken hiçbir dosya açılmaz, sıfır overhead. İleri seviye kullanım için
kendi script'ini geçmek istersen `--verifier-script /abs/path/x.groovy` ile
inline'ı override edebilirsin.

## Sorun Giderme

| Belirti                              | Çözüm                                                |
| ------------------------------------ | ---------------------------------------------------- |
| `JMeter bulunamadı`                  | `brew install jmeter` / official tarball             |
| Tüm istekler `Connection refused`    | `--host`/`--port` yanlış veya firewall               |
| Tüm istekler `401`                   | `AUTH_HEADER="Bearer ..." ./run.sh ...`              |
| Tüm istekler `SSLHandshakeException` | `--protocol https` set ettiğine emin ol              |
| `Read timed out`                     | `--response-timeout 180000` (büyük PDF / yavaş HSM)  |
| Verifier `VERIFY_ERROR` çoğalıyor    | `--verifier-timeout 60000` veya verifier-api logu    |
| `Script file '...verifier-bridge.groovy' is not a file` | Eski JMX kullanıyorsun — bu bundle'da script INLINE. Tekrar `prepare-bundle.sh` ile bundle oluştur. |

Detaylı dokümantasyon için repo'daki `devops/load-tests/jmeter/README.md`'ye
bakabilirsin.
BUNDLE_README

# --------- 4) Özet ---------
xadesCount=$(find "${TARGET_DIR}/xades" -type f | wc -l | tr -d ' ')
padesCount=$(find "${TARGET_DIR}/pades" -type f | wc -l | tr -d ' ')
totalSize=$(du -sh "${TARGET_DIR}" | awk '{print $1}')

cat <<EOF

✅ Bundle hazır: ${TARGET_DIR}

   📦 Boyut       : ${totalSize}
   📄 XAdES dosya : ${xadesCount}
   📄 PAdES dosya : ${padesCount}

İçindekiler:
$(find "${TARGET_DIR}" -maxdepth 2 -type f | sort | sed 's|^|   |')

EOF

# --------- 5) Tarball (opsiyonel) ---------
if [[ "${MAKE_TGZ}" == "true" ]]; then
  parentDir="$(dirname "${TARGET_DIR}")"
  baseName="$(basename "${TARGET_DIR}")"
  tarballPath="${parentDir}/${baseName}.tgz"
  (cd "${parentDir}" && tar -czf "${tarballPath}" "${baseName}")
  echo "📦 Tarball : ${tarballPath} ($(du -h "${tarballPath}" | awk '{print $1}'))"
  echo ""
  echo "Test makinesine yolla:"
  echo "   scp '${tarballPath}' user@test-host:/opt/"
  echo "   ssh user@test-host 'cd /opt && tar -xzf ${baseName}.tgz && cd ${baseName} && ./run.sh --help'"
else
  echo "Test makinesine yolla:"
  echo "   rsync -av '${TARGET_DIR}/' user@test-host:/opt/${baseName:-signer-loadtest}/"
fi

echo ""
echo "Sonra orada:"
echo "   ./run.sh --host signer.prod.local --port 443 --protocol https \\"
echo "            --verify --verifier-url https://verifier.prod.local"
echo ""
