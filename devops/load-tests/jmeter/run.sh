#!/usr/bin/env bash
# Mersel DSS Signer — JMeter stres test launcher
#
# Senaryo: API ayrı bir sunucuda gerçek HSM ile çalışıyor (Luna / Utimaco /
# SafeNet vb. — thread-safe, çoklu-session). Sana sadece bir endpoint URL'i
# veriliyor; bu script o endpoint'e XAdES sürekli + PAdES ara ara stres atar.
#
# Path resolution: Bu script'i HERHANGİ BİR DİZİNDEN çalıştırabilirsin.
# JMX içindeki "setUp — Resolve Paths" thread group, CSV ve verifier script
# path'lerini layout-aware (repo / bundle) ve CWD-bağımsız olarak otomatik
# çözer. Custom değer vermek istersen aşağıdaki --xades-csv / --pades-csv /
# --verifier-script / --data-dir flag'lerini kullan.
#
# Kullanım:
#   ./devops/load-tests/jmeter/run.sh --host signer.prod.local              # default baseline
#   ./devops/load-tests/jmeter/run.sh --smoke --host signer.prod.local      # 30 sn sanity
#   ./devops/load-tests/jmeter/run.sh --stress --host signer.prod.local     # 200 thread, 15 dk
#   ./devops/load-tests/jmeter/run.sh --soak --host signer.prod.local       # 1 saat endurance
#   ./devops/load-tests/jmeter/run.sh --spike --host signer.prod.local      # ani 500 thread
#
#   # HTTPS endpoint
#   ./devops/load-tests/jmeter/run.sh --host signer.prod.local --port 443 --protocol https
#
#   # Bearer / API key (opsiyonel — sunucu auth istiyorsa)
#   AUTH_HEADER="Bearer eyJhbGc..." ./devops/load-tests/jmeter/run.sh --host signer.prod.local
#
#   # Verifier API entegrasyonu — her imzayı verifier'a doğrulat
#   ./devops/load-tests/jmeter/run.sh --host signer.prod.local \
#       --verify --verifier-url https://verifier.prod.local
#
#   # Dışarıdan fixture seti (kendi CSV + dosyalarınla)
#   ./devops/load-tests/jmeter/run.sh --host signer.prod.local \
#       --data-dir /home/me/my-fixtures
#   ./devops/load-tests/jmeter/run.sh --host signer.prod.local \
#       --xades-csv /abs/path/to/my-xades.csv --pades-csv /abs/path/to/my-pades.csv
#
#   # İnce ayar (env)
#   XADES_THREADS=300 DURATION_SEC=1800 JVM_HEAP=4g \
#     ./devops/load-tests/jmeter/run.sh --host signer.prod.local
#
# Çıktı:
#   devops/load-tests/jmeter/results/<timestamp>-<profile>/
#     ├── result.jtl
#     ├── jmeter.log
#     └── report/index.html   ← Apache JMeter dashboard

set -euo pipefail

# --------- Path bootstrap — JMX dosyasını bul, layout-agnostic ---------
# İki olası layout destekleniyor:
#
#   Repo layout:        devops/load-tests/jmeter/
#                        ├── run.sh
#                        ├── plan/signer-stress.jmx        (verifier script INLINE)
#                        └── data/{xades,pades}-fixtures.csv
#
#   Bundle layout:      load-test-bundle/
#                        ├── run.sh                        (kopya)
#                        ├── signer-stress.jmx             (verifier script INLINE)
#                        ├── {xades,pades}-fixtures.csv
#                        ├── xades/*.xml
#                        └── pades/*.pdf
#
# Diğer path'leri (fixture base, CSV) JMX içindeki "setUp — Resolve Paths"
# thread group otomatik çözer (CWD-bağımsız). Verifier round-trip Groovy
# script'i JMX'in PostProcessor `<script>` CDATA'sına gömülü — ayrı dosya
# yok. Burada sadece JMeter'a vereceğimiz JMX dosyasının yerini buluyoruz.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -f "${SCRIPT_DIR}/signer-stress.jmx" ]]; then
  PLAN="${SCRIPT_DIR}/signer-stress.jmx"            # bundle layout
elif [[ -f "${SCRIPT_DIR}/plan/signer-stress.jmx" ]]; then
  PLAN="${SCRIPT_DIR}/plan/signer-stress.jmx"       # repo layout
else
  echo "❌ signer-stress.jmx bulunamadı." >&2
  echo "   Aranan yerler:" >&2
  echo "     - ${SCRIPT_DIR}/signer-stress.jmx (bundle layout)" >&2
  echo "     - ${SCRIPT_DIR}/plan/signer-stress.jmx (repo layout)" >&2
  exit 6
fi

RESULTS_BASE="${SCRIPT_DIR}/results"

# --------- Defaults (override via env or CLI flags) ---------
HOST="${HOST:-localhost}"
PORT="${PORT:-8085}"
PROTOCOL="${PROTOCOL:-http}"
DURATION_SEC="${DURATION_SEC:-300}"
XADES_THREADS="${XADES_THREADS:-50}"
XADES_RAMPUP="${XADES_RAMPUP:-30}"
PADES_THREADS="${PADES_THREADS:-2}"
PADES_RAMPUP="${PADES_RAMPUP:-5}"
PADES_RPM="${PADES_RPM:-6}"            # PAdES istek hızı: req/min
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-5000}"
RESPONSE_TIMEOUT="${RESPONSE_TIMEOUT:-60000}"
JVM_HEAP="${JVM_HEAP:-2g}"             # JMeter JVM heap
SKIP_HEALTH="${SKIP_HEALTH:-false}"    # Prod endpoint actuator/health açık olmayabilir

# Verifier API entegrasyonu — default KAPALI (ekstra trafik olur)
VERIFIER_ENABLED="${VERIFIER_ENABLED:-false}"
VERIFIER_URL="${VERIFIER_URL:-}"
VERIFIER_LEVEL="${VERIFIER_LEVEL:-SIMPLE}"   # SIMPLE (perf) | COMPREHENSIVE (ağır)
VERIFIER_TIMEOUT="${VERIFIER_TIMEOUT:-30000}"

# Fixture & script path'leri — boşsa JMX setUp otomatik resolve eder
# (layout-aware, CWD-bağımsız). Dolu verilirse -J ile geçilip JMX'teki
# default override edilir.
XADES_CSV="${XADES_CSV:-}"
PADES_CSV="${PADES_CSV:-}"
VERIFIER_SCRIPT="${VERIFIER_SCRIPT:-}"
DATA_DIR_OVERRIDE=""                   # --data-dir geldiyse dolar

# --------- CLI flags ---------
profile="baseline"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --smoke|--quick)
      # Sanity / CI smoke — 30sn, az thread. PIN/sertifika/endpoint hayatta mı?
      profile="smoke"
      XADES_THREADS=5
      PADES_THREADS=1
      DURATION_SEC=30
      XADES_RAMPUP=5
      PADES_RPM=4
      shift
      ;;
    --stress)
      # Kapasite tavanı arama — yüksek concurrency, 15 dk.
      profile="stress"
      XADES_THREADS=200
      PADES_THREADS=5
      DURATION_SEC=900
      XADES_RAMPUP=60
      PADES_RPM=18
      shift
      ;;
    --soak)
      # Endurance / leak avı — orta concurrency, 1 saat.
      profile="soak"
      XADES_THREADS=100
      PADES_THREADS=3
      DURATION_SEC=3600
      XADES_RAMPUP=60
      PADES_RPM=12
      RESPONSE_TIMEOUT=120000
      shift
      ;;
    --spike)
      # Ani trafik — kısa süreli 500 thread, connection pool & backlog davranışı.
      profile="spike"
      XADES_THREADS=500
      PADES_THREADS=10
      DURATION_SEC=120
      XADES_RAMPUP=5
      PADES_RPM=30
      shift
      ;;
    --host) HOST="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --protocol) PROTOCOL="$2"; shift 2 ;;
    --duration) DURATION_SEC="$2"; shift 2 ;;
    --xades-threads) XADES_THREADS="$2"; shift 2 ;;
    --pades-threads) PADES_THREADS="$2"; shift 2 ;;
    --pades-rpm) PADES_RPM="$2"; shift 2 ;;
    --response-timeout) RESPONSE_TIMEOUT="$2"; shift 2 ;;
    --skip-health) SKIP_HEALTH="true"; shift ;;
    # ── Verifier API ────────────────────────────────────────────────────────
    --verify) VERIFIER_ENABLED="true"; shift ;;
    --no-verify) VERIFIER_ENABLED="false"; shift ;;
    --verifier-url) VERIFIER_URL="$2"; VERIFIER_ENABLED="true"; shift 2 ;;
    --verifier-level) VERIFIER_LEVEL="$2"; shift 2 ;;
    --verifier-timeout) VERIFIER_TIMEOUT="$2"; shift 2 ;;
    --verifier-script) VERIFIER_SCRIPT="$2"; shift 2 ;;
    # ── Dışarıdan fixture ───────────────────────────────────────────────────
    --data-dir) DATA_DIR_OVERRIDE="$2"; shift 2 ;;
    --xades-csv) XADES_CSV="$2"; shift 2 ;;
    --pades-csv) PADES_CSV="$2"; shift 2 ;;
    -h|--help)
      grep -E '^# ' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "Bilinmeyen flag: $1" >&2
      exit 2
      ;;
  esac
done

# --------- JMeter binary keşfi ---------
JMETER_BIN="${JMETER_BIN:-}"
if [[ -z "${JMETER_BIN}" ]]; then
  if command -v jmeter >/dev/null 2>&1; then
    JMETER_BIN="$(command -v jmeter)"
  elif [[ -n "${JMETER_HOME:-}" && -x "${JMETER_HOME}/bin/jmeter" ]]; then
    JMETER_BIN="${JMETER_HOME}/bin/jmeter"
  else
    echo "❌ JMeter bulunamadı. Kurulum:" >&2
    echo "   macOS:  brew install jmeter" >&2
    echo "   Linux:  https://jmeter.apache.org/download_jmeter.cgi (5.6+ önerilir)" >&2
    echo "   veya: JMETER_BIN=/path/to/jmeter ./run.sh" >&2
    exit 3
  fi
fi

# --------- Run klasörü ---------
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
RUN_DIR="${RESULTS_BASE}/${TIMESTAMP}-${profile}"
mkdir -p "${RUN_DIR}"

JTL="${RUN_DIR}/result.jtl"
LOG="${RUN_DIR}/jmeter.log"
REPORT_DIR="${RUN_DIR}/report"

# --------- Health check (opsiyonel) ---------
if [[ "${SKIP_HEALTH}" != "true" ]]; then
  echo "🩺 Endpoint hayatta mı? → ${PROTOCOL}://${HOST}:${PORT}/actuator/health"
  if curl -sfkm 3 "${PROTOCOL}://${HOST}:${PORT}/actuator/health" >/dev/null 2>&1; then
    echo "✅ Endpoint UP"
  else
    echo "⚠️  Health endpoint cevap vermedi (actuator kapalı olabilir veya farklı path)."
    echo "    Yine de devam ediliyor. Atlamak için: --skip-health"
  fi
fi

# --------- Auth header (opsiyonel) ---------
AUTH_JMETER_ARG=()
if [[ -n "${AUTH_HEADER:-}" ]]; then
  echo "🔑 Authorization header kullanılacak (uzunluk: ${#AUTH_HEADER} char)"
  AUTH_JMETER_ARG=(-JauthHeader="${AUTH_HEADER}")
fi

# --------- Verifier API (opsiyonel) ---------
VERIFIER_JMETER_ARG=()
if [[ "${VERIFIER_ENABLED}" == "true" ]]; then
  if [[ -z "${VERIFIER_URL}" ]]; then
    echo "❌ --verify aktif ama --verifier-url verilmedi (örn: https://verifier.prod.local)" >&2
    exit 2
  fi
  # --verifier-script ile EXPLICIT path verildiyse var mı diye bak; verilmediyse
  # JMX setUp script'i kendi default'unu (plan dizini altındaki dosya) kullanır.
  if [[ -n "${VERIFIER_SCRIPT}" && ! -f "${VERIFIER_SCRIPT}" ]]; then
    echo "❌ Verifier bridge script bulunamadı: ${VERIFIER_SCRIPT}" >&2
    exit 4
  fi
  echo "🔍 Verifier API entegrasyonu aktif → ${VERIFIER_URL}  (level=${VERIFIER_LEVEL})"
  VERIFIER_JMETER_ARG=(
    -JverifierEnabled="true"
    -JverifierUrl="${VERIFIER_URL}"
    -JverifierLevel="${VERIFIER_LEVEL}"
    -JverifierTimeout="${VERIFIER_TIMEOUT}"
  )
  [[ -n "${VERIFIER_SCRIPT}" ]] && VERIFIER_JMETER_ARG+=(-JverifierScript="${VERIFIER_SCRIPT}")
else
  VERIFIER_JMETER_ARG=(-JverifierEnabled="false")
fi

# --------- Fixture CSV path'leri ---------
# --data-dir verildiyse, CSV explicit verilmemişse onlardan türet.
if [[ -n "${DATA_DIR_OVERRIDE}" ]]; then
  [[ -z "${XADES_CSV}" ]] && XADES_CSV="${DATA_DIR_OVERRIDE}/xades-fixtures.csv"
  [[ -z "${PADES_CSV}" ]] && PADES_CSV="${DATA_DIR_OVERRIDE}/pades-fixtures.csv"
fi
# Explicit verilen CSV'ler için varlık kontrolü (yanlış path'i erken yakala).
# Verilmediyse JMX setUp script'i layout-aware default'u kullanır.
for c in "${XADES_CSV}" "${PADES_CSV}"; do
  if [[ -n "${c}" && ! -f "${c}" ]]; then
    echo "❌ Custom CSV bulunamadı: ${c}" >&2
    exit 5
  fi
done
FIXTURE_JMETER_ARG=()
[[ -n "${XADES_CSV}" ]] && FIXTURE_JMETER_ARG+=(-JxadesCsv="${XADES_CSV}")
[[ -n "${PADES_CSV}" ]] && FIXTURE_JMETER_ARG+=(-JpadesCsv="${PADES_CSV}")

# --------- Özet ---------
cat <<EOF

╔══════════════════════════════════════════════════════════════╗
║              MERSEL DSS SIGNER — STRESS TEST                  ║
╠══════════════════════════════════════════════════════════════╣
║ Profile        : ${profile}
║ Target         : ${PROTOCOL}://${HOST}:${PORT}
║ Duration       : ${DURATION_SEC}s
║ XAdES threads  : ${XADES_THREADS} (ramp-up ${XADES_RAMPUP}s)  → sustained
║ PAdES threads  : ${PADES_THREADS} (ramp-up ${PADES_RAMPUP}s)  → sporadic @ ${PADES_RPM} req/min
║ Response TO    : ${RESPONSE_TIMEOUT}ms
║ XAdES CSV      : ${XADES_CSV:-<setUp default>}
║ PAdES CSV      : ${PADES_CSV:-<setUp default>}
║ Verifier       : ${VERIFIER_ENABLED} ${VERIFIER_URL:+(${VERIFIER_URL}, level=${VERIFIER_LEVEL})}
║ Output         : ${RUN_DIR}
╚══════════════════════════════════════════════════════════════╝

EOF

# --------- JMeter run ---------
export HEAP="-Xms512m -Xmx${JVM_HEAP} -XX:MaxMetaspaceSize=256m"

"${JMETER_BIN}" -n \
  -t "${PLAN}" \
  -l "${JTL}" \
  -j "${LOG}" \
  -e -o "${REPORT_DIR}" \
  -Jhost="${HOST}" \
  -Jport="${PORT}" \
  -Jprotocol="${PROTOCOL}" \
  -Jduration="${DURATION_SEC}" \
  -JxadesThreads="${XADES_THREADS}" \
  -JxadesRampup="${XADES_RAMPUP}" \
  -JpadesThreads="${PADES_THREADS}" \
  -JpadesRampup="${PADES_RAMPUP}" \
  -JpadesRpm="${PADES_RPM}" \
  -JconnectTimeout="${CONNECT_TIMEOUT}" \
  -JresponseTimeout="${RESPONSE_TIMEOUT}" \
  ${FIXTURE_JMETER_ARG[@]+"${FIXTURE_JMETER_ARG[@]}"} \
  ${AUTH_JMETER_ARG[@]+"${AUTH_JMETER_ARG[@]}"} \
  ${VERIFIER_JMETER_ARG[@]+"${VERIFIER_JMETER_ARG[@]}"}

echo ""
echo "✅ Test tamamlandı."
echo "   📊 HTML rapor : ${REPORT_DIR}/index.html"
echo "   📄 Raw JTL    : ${JTL}"
echo "   🪵 JMeter log : ${LOG}"
echo ""
echo "Açmak için:  open '${REPORT_DIR}/index.html'   (macOS)"
