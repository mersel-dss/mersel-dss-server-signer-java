#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  run-integration-tests-locally.sh
#
#  .github/workflows/integration-tests.yml içindeki iki job'u (pkcs11-integration
#  ve verifier-e2e) yerelde — CI runner ile birebir adım paritesinde — koşturur.
#
#  Neden bu script var?
#  ────────────────────
#  CI'da "PKCS#11 Integration" job'u patladığında, log GitHub Actions auth wall'ı
#  arkasında. Geliştiricinin "tam aynı koşumu yerelde reproduce edebilmesi" için
#  workflow .yml'sini elle taklit etmek hatalı; bu script "tek source-of-truth":
#  her CI step'inin yerel karşılığı + aynı test-count assertion'ları + aynı
#  verifier image stratejisi (ghcr default, --build-verifier ile sibling repo
#  source build).
#
#  Job'lar:
#    pkcs11-integration:
#      - Native: SoftHSM2 + OpenSC (yoksa kullanıcıya kurulum komutu önerir)
#      - Token init + 5 PFX import + SOFTHSM2_CONF/MODULE env export
#      - mvn test -Dgroups=pkcs11-integration
#      - Workflow'daki test-count assertion'ları (6 raw + 25 E2E iterasyon)
#
#    verifier-e2e:
#      - Docker daemon check
#      - Verifier image: GHCR pull (default) veya sibling repo build (--build-verifier)
#      - mvn test -Dgroups=verifier-e2e
#      - Workflow'daki test-count assertion (277 toplam)
#
#  Platform desteği:
#    - macOS Apple Silicon: /opt/homebrew/lib/softhsm/libsofthsm2.{so,dylib}
#    - macOS Intel:         /usr/local/lib/softhsm/libsofthsm2.{so,dylib}
#    - Linux:               /usr/lib/softhsm/libsofthsm2.so
#                           /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
#    Test class'ı (SoftHsm2TestSupport) hepsini tarar; bulamazsa Assumption.skip
#    eder — script "all skipped" durumunu count assertion'ında YAKALAR.
#
#  Kullanım:
#    ./scripts/run-integration-tests-locally.sh                   # = --pkcs11 (default; CI'da patlayan job)
#    ./scripts/run-integration-tests-locally.sh --verifier-e2e    # sadece verifier-e2e
#    ./scripts/run-integration-tests-locally.sh --all             # ikisini de
#    ./scripts/run-integration-tests-locally.sh --quick           # count assertion'larını atla (hızlı feedback)
#    ./scripts/run-integration-tests-locally.sh --build-verifier  # sibling repo'dan verifier image build
#    ./scripts/run-integration-tests-locally.sh --skip-pull       # GHCR pull'u atla (offline)
#    ./scripts/run-integration-tests-locally.sh --verifier-image IMAGE  # özel image tag
#
#  Bağımlılıklar:
#    - JDK 8+, Maven                          (zaten gerek)
#    - macOS: brew install softhsm opensc     (script önerir + auto-install çalıştırmaz)
#    - Linux: sudo apt-get install -y softhsm2 opensc
#    - Docker (verifier-e2e için zorunlu, pkcs11-integration için Testcontainers verifier-api'yi kaldırır)
# ─────────────────────────────────────────────────────────────────────────────

set -uo pipefail

# ─── Repo root'a normalize et (her yerden çağrılabilsin) ─────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# ─── Flags ───────────────────────────────────────────────────────────────────
RUN_PKCS11=false
RUN_VERIFIER=false
QUICK=false
BUILD_VERIFIER=false
SKIP_PULL=false
# Default: GHCR'daki upstream :main tag'i — CI workflow ile aynı.
VERIFIER_IMAGE="${VERIFIER_IMAGE:-ghcr.io/mersel-dss/mersel-dss-verifier-api-java:main}"

# Hiç flag verilmezse: pkcs11 (kullanıcının asıl ihtiyacı: CI'da patlayan job)
if [ $# -eq 0 ]; then
  RUN_PKCS11=true
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --pkcs11)            RUN_PKCS11=true ;;
    --verifier-e2e)      RUN_VERIFIER=true ;;
    --all)               RUN_PKCS11=true; RUN_VERIFIER=true ;;
    --quick)             QUICK=true ;;
    --build-verifier)    BUILD_VERIFIER=true; RUN_VERIFIER=true ;;
    --skip-pull)         SKIP_PULL=true ;;
    --verifier-image)    VERIFIER_IMAGE="$2"; shift ;;
    --verifier-image=*)  VERIFIER_IMAGE="${1#*=}" ;;
    -h|--help)
      sed -n '2,60p' "$0"
      exit 0
      ;;
    *)
      echo "Bilinmeyen flag: $1 (--help ile kullanım)" >&2
      exit 2
      ;;
  esac
  shift
done

# ─── Pretty logging ──────────────────────────────────────────────────────────
if [ -t 1 ]; then
  BOLD=$(printf '\033[1m'); DIM=$(printf '\033[2m'); RESET=$(printf '\033[0m')
  GREEN=$(printf '\033[32m'); YELLOW=$(printf '\033[33m'); RED=$(printf '\033[31m')
  BLUE=$(printf '\033[34m'); CYAN=$(printf '\033[36m')
else
  BOLD=""; DIM=""; RESET=""; GREEN=""; YELLOW=""; RED=""; BLUE=""; CYAN=""
fi

step() { echo ""; echo "${BOLD}${BLUE}▶ $*${RESET}"; }
ok()   { echo "${GREEN}✓${RESET} $*"; }
warn() { echo "${YELLOW}⚠${RESET} $*"; }
err()  { echo "${RED}✗${RESET} $*" >&2; }
info() { echo "${DIM}  $*${RESET}"; }
hr()   { printf "${DIM}%s${RESET}\n" "────────────────────────────────────────────────────────────────"; }

START_EPOCH=$(date +%s)

# ─── Platform detection ──────────────────────────────────────────────────────
OS_NAME="$(uname -s)"
ARCH_NAME="$(uname -m)"
case "$OS_NAME" in
  Darwin) IS_MACOS=true; IS_LINUX=false ;;
  Linux)  IS_MACOS=false; IS_LINUX=true ;;
  *)      err "Desteklenmeyen OS: $OS_NAME"; exit 1 ;;
esac

# ─── Konfigürasyon özeti ─────────────────────────────────────────────────────
step "Integration Tests — Local Runner (CI parite modu)"
info "Repo:             $REPO_ROOT"
info "Platform:         $OS_NAME ($ARCH_NAME)"
info "pkcs11-integration: $([ "$RUN_PKCS11" = true ] && echo "${GREEN}ÇALIŞACAK${RESET}" || echo "atlandı")"
info "verifier-e2e:       $([ "$RUN_VERIFIER" = true ] && echo "${GREEN}ÇALIŞACAK${RESET}" || echo "atlandı")"
info "Verifier image:     $VERIFIER_IMAGE"
info "Build verifier:     $([ "$BUILD_VERIFIER" = true ] && echo "EVET (sibling repo)" || echo "hayır")"
info "Skip GHCR pull:     $([ "$SKIP_PULL" = true ] && echo "EVET" || echo "hayır")"
info "Quick mode:         $([ "$QUICK" = true ] && echo "EVET (count assertion'ları atlanacak)" || echo "hayır (CI parite)")"

# ═════════════════════════════════════════════════════════════════════════════
# Ortak bağımlılık kontrolleri
# ═════════════════════════════════════════════════════════════════════════════
step "Ortak bağımlılık kontrolleri"

if ! command -v mvn >/dev/null 2>&1; then
  err "Maven (mvn) bulunamadı. macOS: 'brew install maven', Linux: 'apt install maven'"
  exit 1
fi
ok "Maven: $(mvn -v 2>&1 | head -1)"

if ! command -v java >/dev/null 2>&1; then
  err "Java bulunamadı"
  exit 1
fi
JAVA_VER=$(java -version 2>&1 | head -1)
ok "Java:  $JAVA_VER"

# ═════════════════════════════════════════════════════════════════════════════
# pkcs11-integration job
# ═════════════════════════════════════════════════════════════════════════════
PKCS11_EXIT=0
PKCS11_RAN=false

if [ "$RUN_PKCS11" = true ]; then
  hr
  step "JOB: pkcs11-integration (workflow: integration-tests.yml → pkcs11-integration)"

  # ─── Step 1: SoftHSM2 + OpenSC ─────────────────────────────────────────────
  step "1/4) Native bağımlılıklar (SoftHSM2 + OpenSC)"

  HAS_SOFTHSM2_UTIL=false
  HAS_PKCS11_TOOL=false
  if command -v softhsm2-util >/dev/null 2>&1; then
    HAS_SOFTHSM2_UTIL=true
    ok "softhsm2-util: $(softhsm2-util --version 2>&1 | head -1)"
  else
    warn "softhsm2-util bulunamadı"
  fi
  if command -v pkcs11-tool >/dev/null 2>&1; then
    HAS_PKCS11_TOOL=true
    # CI'da bu komutun --version'ı OpenSC 0.25+'ta exit 2 dönüyor; sadece varlığı önemli
    ok "pkcs11-tool: $(command -v pkcs11-tool)"
  else
    warn "pkcs11-tool bulunamadı"
  fi

  if [ "$HAS_SOFTHSM2_UTIL" = false ] || [ "$HAS_PKCS11_TOOL" = false ]; then
    echo ""
    err "Native PKCS#11 araçları eksik. Kurulum:"
    if [ "$IS_MACOS" = true ]; then
      echo "    brew install softhsm opensc"
    else
      echo "    sudo apt-get update && sudo apt-get install -y softhsm2 opensc"
    fi
    echo ""
    err "Test class'ı (SoftHsm2TestSupport) eksik araç görürse Assumption.skip eder;"
    err "CI'da bu sessiz skip 'expected count' assertion'ında patlar. Yerelde de aynı."
    exit 1
  fi

  # ─── Step 2: libsofthsm2 modülünü bul ──────────────────────────────────────
  step "2/4) libsofthsm2 modülü tespit"

  # Test class ile birebir aynı candidate listesi (SoftHsm2TestSupport.requireSoftHsmModule)
  SOFTHSM2_MODULE_CANDIDATES=(
    "${SOFTHSM2_MODULE:-}"
    "/usr/lib/softhsm/libsofthsm2.so"
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"
    "/usr/local/lib/softhsm/libsofthsm2.so"
    "/usr/local/lib/softhsm/libsofthsm2.dylib"
    "/opt/homebrew/lib/softhsm/libsofthsm2.so"
    "/opt/homebrew/lib/softhsm/libsofthsm2.dylib"
  )
  RESOLVED_MODULE=""
  for c in "${SOFTHSM2_MODULE_CANDIDATES[@]}"; do
    if [ -n "$c" ] && [ -f "$c" ]; then
      RESOLVED_MODULE="$c"
      break
    fi
  done

  if [ -z "$RESOLVED_MODULE" ]; then
    err "libsofthsm2 modülü bulunamadı. Arandı:"
    for c in "${SOFTHSM2_MODULE_CANDIDATES[@]}"; do
      [ -n "$c" ] && echo "    $c"
    done
    err "SOFTHSM2_MODULE env'i ile manuel verebilirsin:"
    echo "    SOFTHSM2_MODULE=/path/to/libsofthsm2.so $0 --pkcs11"
    exit 1
  fi
  export SOFTHSM2_MODULE="$RESOLVED_MODULE"
  ok "SOFTHSM2_MODULE = $SOFTHSM2_MODULE"

  # ─── Step 3: Maven validate (CI step: 'Install local Maven dependencies') ──
  step "3/4) Maven validate (local dependency'ler hazır mı?)"
  if mvn validate -B -q; then
    ok "mvn validate OK"
  else
    err "mvn validate başarısız. resources/lib/*.jar local install fail olmuş olabilir."
    exit 1
  fi

  # ─── Step 4: PKCS#11 testlerini koş ────────────────────────────────────────
  step "4/4) PKCS#11 integration testleri koşturuluyor"
  info "mvn test -Dgroups=pkcs11-integration -DexcludedGroups="
  echo ""

  PKCS11_RAN=true
  if mvn test -B \
        -Dgroups=pkcs11-integration \
        -DexcludedGroups=; then
    ok "Maven test koşumu tamamlandı"
  else
    PKCS11_EXIT=$?
    err "Maven test koşumu fail (exit=$PKCS11_EXIT)"
    # Devam et — assertion'lar daha net hata mesajı verebilir
  fi

  # ─── Workflow'daki test-count assertion'larını uygula ──────────────────────
  if [ "$QUICK" = false ]; then
    step "Test-count doğrulamaları (workflow ile parite)"

    # SoftHsm2Pkcs11IntegrationTest: 6 iterasyon (5 sequential + 1 paralel)
    SOFTHSM_REPORT="target/surefire-reports/io.mersel.dss.signer.api.services.keystore.iaik.SoftHsm2Pkcs11IntegrationTest.txt"
    if [ ! -f "$SOFTHSM_REPORT" ]; then
      err "Surefire raporu bulunamadı: $SOFTHSM_REPORT"
      ls -la target/surefire-reports/ 2>/dev/null | head -20 || true
      PKCS11_EXIT=1
    else
      echo "${DIM}--- $SOFTHSM_REPORT ---${RESET}"
      cat "$SOFTHSM_REPORT"
      echo "${DIM}---${RESET}"

      SOFTHSM_EXPECTED=6
      SOFTHSM_RUN=$(grep -oE 'Tests run: [0-9]+' "$SOFTHSM_REPORT" | head -1 | grep -oE '[0-9]+' || echo "0")
      SOFTHSM_SKIPPED=$(grep -oE 'Skipped: [0-9]+' "$SOFTHSM_REPORT" | head -1 | grep -oE '[0-9]+' || echo "0")

      if [ "$SOFTHSM_RUN" != "$SOFTHSM_EXPECTED" ]; then
        err "SoftHsm2Pkcs11IntegrationTest: beklenen $SOFTHSM_EXPECTED iterasyon, gerçek $SOFTHSM_RUN"
        PKCS11_EXIT=1
      elif [ "$SOFTHSM_SKIPPED" != "0" ]; then
        err "SoftHsm2Pkcs11IntegrationTest: $SOFTHSM_SKIPPED iterasyon atlandı (native araç eksik?)"
        PKCS11_EXIT=1
      else
        ok "SoftHsm2Pkcs11IntegrationTest: $SOFTHSM_EXPECTED iterasyon, hepsi koştu"
      fi
    fi

    # XadesSoftHsmVerifierE2ETest: 25 iterasyon (5 PFX × 5 fixture)
    XADES_REPORT="target/surefire-reports/io.mersel.dss.signer.api.e2e.verifier.XadesSoftHsmVerifierE2ETest.txt"
    if [ ! -f "$XADES_REPORT" ]; then
      err "Surefire raporu bulunamadı: $XADES_REPORT"
      PKCS11_EXIT=1
    else
      echo "${DIM}--- $XADES_REPORT ---${RESET}"
      cat "$XADES_REPORT"
      echo "${DIM}---${RESET}"

      XADES_EXPECTED=25
      XADES_RUN=$(grep -oE 'Tests run: [0-9]+' "$XADES_REPORT" | head -1 | grep -oE '[0-9]+' || echo "0")
      XADES_SKIPPED=$(grep -oE 'Skipped: [0-9]+' "$XADES_REPORT" | head -1 | grep -oE '[0-9]+' || echo "0")

      if [ "$XADES_RUN" != "$XADES_EXPECTED" ]; then
        err "XadesSoftHsmVerifierE2ETest: beklenen $XADES_EXPECTED iterasyon, gerçek $XADES_RUN"
        PKCS11_EXIT=1
      elif [ "$XADES_SKIPPED" != "0" ]; then
        err "XadesSoftHsmVerifierE2ETest: $XADES_SKIPPED iterasyon atlandı (Docker/HSM eksik?)"
        PKCS11_EXIT=1
      else
        ok "XadesSoftHsmVerifierE2ETest: $XADES_EXPECTED iterasyon, hepsi koştu"
      fi
    fi
  else
    info "Quick mode — test-count assertion'ları atlandı"
  fi
fi

# ═════════════════════════════════════════════════════════════════════════════
# verifier-e2e job
# ═════════════════════════════════════════════════════════════════════════════
VERIFIER_EXIT=0
VERIFIER_RAN=false

if [ "$RUN_VERIFIER" = true ]; then
  hr
  step "JOB: verifier-e2e (workflow: integration-tests.yml → verifier-e2e)"

  # ─── Docker daemon ─────────────────────────────────────────────────────────
  step "1/3) Docker daemon kontrolü"
  if ! docker info >/dev/null 2>&1; then
    err "Docker daemon erişilemiyor."
    if [ "$IS_MACOS" = true ]; then
      err "Docker Desktop'ı başlat (open -a 'Docker') ve yeniden dene."
    fi
    exit 1
  fi
  ok "$(docker version --format 'docker {{.Client.Version}} / engine {{.Server.Version}}' 2>/dev/null)"

  # ─── Verifier image hazırlığı ──────────────────────────────────────────────
  step "2/3) Verifier image hazırlığı"

  if [ "$BUILD_VERIFIER" = true ]; then
    info "Sibling repo'dan source build (workflow_dispatch: verifier_image_source=build)"
    SIBLING_DIR="${SIBLING_DIR:-../mersel-dss-verifier-api-java}"
    if [ ! -d "$SIBLING_DIR" ]; then
      err "Sibling verifier repo bulunamadı: $SIBLING_DIR"
      err "Clone et: git clone https://github.com/mersel-dss/mersel-dss-verifier-api-java $SIBLING_DIR"
      exit 1
    fi
    VERIFIER_IMAGE="mersel-dss-verifier-api:ci-local"
    info "Build path: $SIBLING_DIR → $VERIFIER_IMAGE"
    if ! (cd "$SIBLING_DIR" && docker build \
            --tag "$VERIFIER_IMAGE" \
            --file devops/docker/Dockerfile .); then
      err "Verifier source build başarısız"
      exit 1
    fi
    ok "Verifier image built: $VERIFIER_IMAGE"
  elif [ "$SKIP_PULL" = false ]; then
    info "GHCR pull: $VERIFIER_IMAGE"
    if ! docker pull "$VERIFIER_IMAGE"; then
      warn "Image pull başarısız. GHCR auth gerekebilir veya offline'sın."
      warn "Devam ediliyor — Testcontainers kendi pull'unu deneyecek."
    else
      ok "Image hazır: $VERIFIER_IMAGE"
    fi
  else
    info "Pull atlandı (--skip-pull). Local'de image var olduğu varsayılıyor."
  fi

  # ─── verifier-e2e testleri koş ─────────────────────────────────────────────
  step "3/3) Verifier E2E testleri koşturuluyor"
  info "mvn test -Dgroups=verifier-e2e -DexcludedGroups= -DverifierImage=$VERIFIER_IMAGE"
  echo ""

  VERIFIER_RAN=true
  if mvn test -B \
        -Dgroups=verifier-e2e \
        -DexcludedGroups= \
        -DverifierImage="$VERIFIER_IMAGE"; then
    ok "Maven test koşumu tamamlandı"
  else
    VERIFIER_EXIT=$?
    err "Maven test koşumu fail (exit=$VERIFIER_EXIT)"
  fi

  # ─── Workflow'daki test-count assertion'ı (277) ────────────────────────────
  if [ "$QUICK" = false ]; then
    step "Test-count doğrulaması (workflow ile parite: 277 iterasyon)"
    # NUL-separated find+xargs: boşluklu/non-ASCII dosya adlarına güvenli
    VERIFIER_TOTAL=$(find target/surefire-reports \
                       -name 'TEST-io.mersel.dss.signer.api.e2e.verifier.*.xml' \
                       -print0 2>/dev/null \
                       | xargs -0 grep -hoE 'tests="[0-9]+"' 2>/dev/null \
                       | grep -oE '[0-9]+' \
                       | awk '{s+=$1} END {print s+0}')
    VERIFIER_EXPECTED=277
    info "Koşulan: $VERIFIER_TOTAL / Beklenen: $VERIFIER_EXPECTED"
    if [ "${VERIFIER_TOTAL:-0}" -lt "$VERIFIER_EXPECTED" ]; then
      err "Verifier E2E: en az $VERIFIER_EXPECTED iterasyon bekleniyordu, $VERIFIER_TOTAL gerçek"
      err "  Bu, verifier image'ın ayağa kalkmadığı veya tag filter'ın bozulduğu sinyalidir."
      VERIFIER_EXIT=1
    else
      ok "Verifier E2E: $VERIFIER_TOTAL iterasyon koştu (≥ $VERIFIER_EXPECTED)"
    fi
  else
    info "Quick mode — test-count assertion atlandı"
  fi
fi

# ═════════════════════════════════════════════════════════════════════════════
# Özet
# ═════════════════════════════════════════════════════════════════════════════
hr
ELAPSED=$(( $(date +%s) - START_EPOCH ))
step "Özet (toplam süre: ${ELAPSED}s)"

if [ "$PKCS11_RAN" = true ]; then
  if [ "$PKCS11_EXIT" -eq 0 ]; then
    ok "pkcs11-integration   PASSED"
  else
    err "pkcs11-integration   FAILED (exit=$PKCS11_EXIT)"
  fi
fi
if [ "$VERIFIER_RAN" = true ]; then
  if [ "$VERIFIER_EXIT" -eq 0 ]; then
    ok "verifier-e2e         PASSED"
  else
    err "verifier-e2e         FAILED (exit=$VERIFIER_EXIT)"
  fi
fi

# Exit code: herhangi biri fail ise non-zero
if [ "$PKCS11_EXIT" -ne 0 ] || [ "$VERIFIER_EXIT" -ne 0 ]; then
  echo ""
  err "Triage için failed test bodies (CI workflow son step ile aynı):"
  for f in target/surefire-reports/*.txt; do
    [ -f "$f" ] || continue
    if grep -q "FAILED\|ERROR\|Skipped: [1-9]" "$f" 2>/dev/null; then
      echo "${DIM}===== $f =====${RESET}"
      cat "$f"
    fi
  done
  exit 1
fi

ok "Tüm seçili job'lar PASSED — CI ile parite sağlandı."
exit 0
