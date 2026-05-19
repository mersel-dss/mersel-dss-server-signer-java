#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  serve-pages-locally.sh
#
#  GitHub Pages'e push edilen "Evidence Site"in birebir aynısını local'de
#  üretir ve bir HTTP server üzerinden browser'da açar.
#
#  Üretilenler (publish-pages.yml workflow ile aynı yapı):
#    pages-output/
#    ├─ index.html              custom landing (build/test/coverage badge'leri)
#    ├─ 404.html                ana sayfaya redirect
#    ├─ test-report/            Allure Report (Suites/Behaviors/Trend + attachments)
#    ├─ coverage/               JaCoCo HTML (line/branch coverage)
#    ├─ openapi/                Scalar API Reference (CDN-loaded, tek HTML + openapi.json)
#    ├─ security/               OWASP Dependency-Check raporu
#    └─ deployment/             Production Deployment Runbook (Linux/Win/Docker/Run Profiles
#                               tabbed; devops/ ve docs/RUN_PROFILES.md'den pandoc render)
#
#  Kullanım:
#    ./scripts/serve-pages-locally.sh                    # tam koşum (E2E dahil)
#    ./scripts/serve-pages-locally.sh --skip-e2e         # sadece unit testler
#    ./scripts/serve-pages-locally.sh --skip-tests       # mevcut target/'i kullan
#    ./scripts/serve-pages-locally.sh --skip-owasp       # NVD scan'i atla (~5dk tasarruf)
#    ./scripts/serve-pages-locally.sh --skip-openapi     # OpenAPI bootstrap'ı atla
#    ./scripts/serve-pages-locally.sh --skip-deployment  # deployment/ runbook'u atla
#    ./scripts/serve-pages-locally.sh --port 9000        # alternatif port
#    ./scripts/serve-pages-locally.sh --no-serve         # üret ama serve etme
#    ./scripts/serve-pages-locally.sh --fast             # = --skip-e2e --skip-owasp
#
#  Bağımlılıklar:
#    - JDK 8+, Maven
#    - python3 (HTTP server + landing/runbook template injection için)
#    - envsubst veya python (landing template injection için)
#    - pandoc (deployment runbook render için — yoksa o section atlanır)
#         macOS: brew install pandoc | Ubuntu: sudo apt-get install -y pandoc
#    - Docker (sadece --skip-e2e DEĞİLSE — verifier-api container için)
# ─────────────────────────────────────────────────────────────────────────────

set -uo pipefail

# Repo root'a normalize et (script'i her yerden çağırabilesin)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# ─── Flags ───────────────────────────────────────────────────────────────────
SKIP_TESTS=false
SKIP_E2E=false
SKIP_OWASP=false
SKIP_OPENAPI=false
SKIP_DEPLOYMENT=false
NO_SERVE=false
PORT=8765

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-tests)      SKIP_TESTS=true ;;
    --skip-e2e)        SKIP_E2E=true ;;
    --skip-owasp)      SKIP_OWASP=true ;;
    --skip-openapi)    SKIP_OPENAPI=true ;;
    --skip-deployment) SKIP_DEPLOYMENT=true ;;
    --no-serve)        NO_SERVE=true ;;
    --fast)            SKIP_E2E=true; SKIP_OWASP=true ;;
    --port)            PORT="$2"; shift ;;
    --port=*)          PORT="${1#*=}" ;;
    -h|--help)
      sed -n '2,40p' "$0"
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

START_EPOCH=$(date +%s)

# ─── Konfigürasyon özeti ─────────────────────────────────────────────────────
step "Local Evidence Site üretici"
info "Repo:           $REPO_ROOT"
info "Test koşumu:    $([ "$SKIP_TESTS" = true ] && echo "ATLANDI (mevcut target/)" || echo "ÇALIŞACAK")"
info "E2E suite:      $([ "$SKIP_E2E" = true ] && echo "ATLANDI" || echo "DAHİL (Docker gerekli)")"
info "OWASP scan:     $([ "$SKIP_OWASP" = true ] && echo "ATLANDI" || echo "ÇALIŞACAK (ilk koşumda ~5dk NVD download)")"
info "OpenAPI bundle: $([ "$SKIP_OPENAPI" = true ] && echo "ATLANDI" || echo "Spring Boot başlat → /v3/api-docs çek")"
info "Deployment:     $([ "$SKIP_DEPLOYMENT" = true ] && echo "ATLANDI" || echo "ÇALIŞACAK (pandoc → tabbed runbook)")"
info "HTTP serve:     $([ "$NO_SERVE" = true ] && echo "HAYIR" || echo "EVET (port $PORT)")"

# ─── 1) Test koşumu ──────────────────────────────────────────────────────────
if [ "$SKIP_TESTS" = false ]; then
  step "1) Test suite koşuluyor (JaCoCo agent + Allure dump)"
  if [ "$SKIP_E2E" = true ]; then
    info "Sadece unit testler (verifier-e2e + pkcs11-integration ATLANIYOR)"
    # mvn verify ile jacoco:prepare-agent + jacoco:report tetiklenir
    if mvn verify -B -DskipITs=false; then
      ok "Unit testler tamamlandı"
    else
      warn "Bazı testler fail oldu — rapor üretmeye devam (Pages prensibi: fail kanıtı da değerli)"
    fi
  else
    info "Tam suite (unit + verifier-e2e) — Docker'da verifier-api container'ı kalkacak"
    if ! docker info > /dev/null 2>&1; then
      err "Docker daemon erişilemiyor. --skip-e2e ile sadece unit testleri koşabilirsiniz."
      exit 1
    fi
    if mvn verify -B -Dgroups= -DexcludedGroups=pkcs11-integration; then
      ok "Full suite tamamlandı"
    else
      warn "Bazı testler fail oldu — rapor üretmeye devam"
    fi
  fi
else
  warn "Test koşumu atlandı — target/ altındaki mevcut artefaktlar kullanılacak"
  if [ ! -d target/surefire-reports ]; then
    err "target/surefire-reports/ yok; en az bir kez 'mvn test' koşmuş olmalı"
    exit 1
  fi
fi

# ─── 2) Allure report ────────────────────────────────────────────────────────
step "2) Allure HTML raporu üretiliyor"
if mvn allure:report -B -q; then
  if [ -d target/site/allure-maven-plugin ]; then
    ok "Allure report: target/site/allure-maven-plugin/"
  else
    warn "allure:report tamamlandı ama target/site/allure-maven-plugin/ yok"
  fi
else
  warn "Allure rapor üretilemedi (allure-results boş olabilir)"
fi

# ─── 3) OWASP Dependency-Check (opsiyonel) ───────────────────────────────────
if [ "$SKIP_OWASP" = false ]; then
  step "3) OWASP Dependency-Check (NVD scan)"
  info "İlk koşumda ~5dk NVD feed download eder; sonraki koşumlar cache'ten çalışır"
  if mvn dependency-check:check -B 2>&1 | tail -20; then
    if [ -f target/dependency-check-report.html ]; then
      ok "OWASP raporu: target/dependency-check-report.html"
    else
      warn "Rapor HTML üretilmedi"
    fi
  else
    warn "OWASP scan başarısız (NVD download ya da rate-limit) — security/ section boş kalır"
  fi
else
  info "OWASP scan atlandı (--skip-owasp)"
fi

# ─── 4) OpenAPI snapshot (opsiyonel) ─────────────────────────────────────────
OPENAPI_OK=false
if [ "$SKIP_OPENAPI" = false ]; then
  step "4) OpenAPI snapshot — Spring Boot başlatılıp /v3/api-docs çekiliyor"

  # Eski Swagger UI bundle cache temizliği — artık Scalar kullanıyoruz, dist
  # dosyaları (swagger-ui-bundle.js, .swagger-ui-version vb.) yer kaplıyor.
  if [ -d openapi-snapshot ] && \
     { [ -f openapi-snapshot/swagger-initializer.js ] || \
       [ -f openapi-snapshot/.swagger-ui-version ]; }; then
    info "Eski Swagger UI bundle temizleniyor (Scalar'a geçildi)"
    rm -rf openapi-snapshot
  fi

  # Jar yoksa üret
  JAR=$(ls target/*.jar 2>/dev/null | grep -v sources | grep -v javadoc | head -1)
  if [ -z "$JAR" ]; then
    info "Runnable jar bulunamadı; mvn package -DskipTests çalıştırılıyor"
    mvn package -B -DskipTests -q || warn "mvn package başarısız"
    JAR=$(ls target/*.jar 2>/dev/null | grep -v sources | grep -v javadoc | head -1)
  fi

  if [ -n "$JAR" ]; then
    OAPI_PORT=8088
    info "Boot: $JAR (port $OAPI_PORT)"
    # Önceden çalışan instance varsa kapat
    lsof -ti tcp:$OAPI_PORT 2>/dev/null | xargs -r kill -9 2>/dev/null || true

    # 'local' Spring profile aktivasyonu → application-local.properties
    # yüklenir: test PFX + dummy PIN + offline chain/TSP. Geliştirici
    # elle hiç env vermez. Test PFX repo'da olduğu için snapshot
    # extraction'a yeter.
    PFX_FOR_BOOT="resources/test-certs/testkurum01_rsa2048@test.com.tr_614573.pfx"

    if [ ! -f "$PFX_FOR_BOOT" ]; then
      warn "Test PFX yok: $PFX_FOR_BOOT — OpenAPI snapshot atlanıyor"
    else
      nohup java -jar "$JAR" \
        --server.port=$OAPI_PORT \
        --spring.main.banner-mode=off \
        --spring.profiles.active=local \
        > /tmp/mersel-boot.log 2>&1 &
      BOOT_PID=$!
      info "Boot PID: $BOOT_PID"

      # NOT: springdoc-openapi 1.7.0 (Spring Boot 2.x stilinde) default
      # endpoint /api-docs — Spring Boot 3 / springdoc 2.x'teki /v3/api-docs
      # değil. Hangi versiyon olduğunu görmek için: mvn dependency:tree | grep springdoc
      ok_health=false
      for i in $(seq 1 30); do
        sleep 2
        if curl -sf "http://localhost:$OAPI_PORT/api-docs" -o /tmp/mersel-openapi.json 2>/dev/null; then
          ok "OpenAPI spec çekildi ($i. denemede, $(wc -c < /tmp/mersel-openapi.json) byte)"
          ok_health=true
          break
        fi
      done
      kill "$BOOT_PID" 2>/dev/null || true
      sleep 1

      if [ "$ok_health" = true ]; then
        # Scalar API Reference — CDN-loaded standalone HTML.
        # Eski Swagger UI 5.x bundle'ı (~3 MB, 19 dosya) yerine tek HTML +
        # openapi.json bırakıyoruz. CDN script tag'i <script id="api-reference">
        # tag'ini bulup data-url ile gösterilen spec'i render eder.
        # Tema: "deepSpace" (koyu, modern); diğer seçenekler:
        # default, alternate, moon, purple, solarized, bluePlanet, saturn,
        # kepler, mars, none.
        # Offline ortamda CDN script'i çekilemez ama openapi.json hala
        # erişilebilir — auditor "spec'i nereden alabilirim?" derse direkt JSON.
        rm -rf openapi-snapshot
        mkdir -p openapi-snapshot
        cp /tmp/mersel-openapi.json openapi-snapshot/openapi.json
        cat > openapi-snapshot/index.html <<'SCALAR_EOF'
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Mersel DSS Signer API — Reference</title>
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Ctext y='.9em' font-size='90'%3E%F0%9F%94%90%3C/text%3E%3C/svg%3E" />
  </head>
  <body>
    <script
      id="api-reference"
      data-url="./openapi.json"
      data-configuration='{"theme":"deepSpace","layout":"modern","hideDownloadButton":false,"metaData":{"title":"Mersel DSS Signer API","description":"XAdES / CAdES / PAdES / WS-Security digital signature API"}}'></script>
    <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script>
  </body>
</html>
SCALAR_EOF
        ok "Scalar API Reference template yazıldı (openapi.json $(wc -c < openapi-snapshot/openapi.json) byte)"
        OPENAPI_OK=true
      else
        warn "Spring Boot 60s içinde UP olmadı — /tmp/mersel-boot.log son satırları:"
        tail -20 /tmp/mersel-boot.log | sed 's/^/    /'
      fi
    fi
  else
    warn "Jar bulunamadı; OpenAPI snapshot atlandı"
  fi
else
  info "OpenAPI snapshot atlandı (--skip-openapi)"
fi

# ─── 5) Test metrics hesapla ─────────────────────────────────────────────────
step "5) Test metrikleri + coverage % hesaplanıyor"
TEST_TOTAL=0; TEST_PASSED=0; TEST_FAILED=0
if compgen -G "target/surefire-reports/TEST-*.xml" > /dev/null; then
  for f in target/surefire-reports/TEST-*.xml; do
    t=$(grep -oE 'tests="[0-9]+"' "$f" | head -1 | grep -oE '[0-9]+' || echo 0)
    er=$(grep -oE 'errors="[0-9]+"' "$f" | head -1 | grep -oE '[0-9]+' || echo 0)
    fa=$(grep -oE 'failures="[0-9]+"' "$f" | head -1 | grep -oE '[0-9]+' || echo 0)
    sk=$(grep -oE 'skipped="[0-9]+"' "$f" | head -1 | grep -oE '[0-9]+' || echo 0)
    TEST_TOTAL=$((TEST_TOTAL + t))
    TEST_FAILED=$((TEST_FAILED + er + fa))
    TEST_PASSED=$((TEST_PASSED + t - er - fa - sk))
  done
fi
info "Tests: ${GREEN}$TEST_PASSED passed${RESET} ${DIM}/${RESET} ${RED}$TEST_FAILED failed${RESET} ${DIM}/${RESET} $TEST_TOTAL total"

COVERAGE_PCT=0; BRANCH_COVERAGE_PCT=0
if [ -f target/site/jacoco/index.html ]; then
  # NOT: '[0-9]+' direkt regex'i kullanılırsa "ctr2"deki "2" de matchlenir.
  # '>' karakteri ile rakamı tag açılışına yakın yere kilitle, sonra %'i çıkar.
  COVERAGE_PCT=$(grep -oE '<td class="ctr2">[0-9]+%' target/site/jacoco/index.html \
    | sed -E 's/.*>([0-9]+)%/\1/' | head -1 || echo 0)
  BRANCH_COVERAGE_PCT=$(grep -oE '<td class="ctr2">[0-9]+%' target/site/jacoco/index.html \
    | sed -E 's/.*>([0-9]+)%/\1/' | sed -n '2p' || echo 0)
  [ -z "$COVERAGE_PCT" ] && COVERAGE_PCT=0
  [ -z "$BRANCH_COVERAGE_PCT" ] && BRANCH_COVERAGE_PCT=0
fi
info "Coverage: ${CYAN}${COVERAGE_PCT}% line${RESET} / ${CYAN}${BRANCH_COVERAGE_PCT}% branch${RESET}"

# ─── 6) pages-output/ assembly ───────────────────────────────────────────────
step "6) pages-output/ klasörü hazırlanıyor"
rm -rf pages-output
mkdir -p pages-output/{test-report,coverage,openapi,security}

# Allure
if [ -d target/site/allure-maven-plugin ]; then
  cp -r target/site/allure-maven-plugin/. pages-output/test-report/
  ok "test-report/ ← Allure"
else
  cat > pages-output/test-report/index.html <<'EOF'
<!doctype html><meta charset=utf-8><title>Test report unavailable</title>
<h1>Test report unavailable</h1>
<p>Allure report could not be generated. allure-results boş olabilir veya
   mvn allure:report başarısız oldu.</p>
EOF
  warn "test-report/ ← placeholder (Allure yok)"
fi

# JaCoCo
if [ -d target/site/jacoco ]; then
  cp -r target/site/jacoco/. pages-output/coverage/
  ok "coverage/ ← JaCoCo"
else
  cat > pages-output/coverage/index.html <<'EOF'
<!doctype html><meta charset=utf-8><title>Coverage unavailable</title>
<h1>Coverage unavailable</h1>
<p>JaCoCo report could not be generated.</p>
EOF
  warn "coverage/ ← placeholder (JaCoCo yok)"
fi

# OpenAPI / Scalar API Reference
if [ "$OPENAPI_OK" = true ] && [ -d openapi-snapshot ]; then
  cp -r openapi-snapshot/. pages-output/openapi/
  ok "openapi/ ← Scalar API Reference (CDN-loaded)"
else
  cat > pages-output/openapi/index.html <<'EOF'
<!doctype html><meta charset=utf-8><title>OpenAPI snapshot unavailable</title>
<h1>OpenAPI snapshot unavailable</h1>
<p>Spring Boot uygulaması başlatılamadı veya --skip-openapi flag'i verildi.</p>
EOF
  warn "openapi/ ← placeholder"
fi

# OWASP
if [ -f target/dependency-check-report.html ]; then
  cp target/dependency-check-report.html pages-output/security/index.html
  if [ -f target/dependency-check-report.json ]; then
    cp target/dependency-check-report.json pages-output/security/report.json
  fi
  ok "security/ ← OWASP Dependency-Check"
else
  cat > pages-output/security/index.html <<'EOF'
<!doctype html><meta charset=utf-8><title>Security report unavailable</title>
<h1>Security report unavailable</h1>
<p>OWASP Dependency-Check raporu üretilmedi (--skip-owasp veya NVD download başarısız).</p>
EOF
  warn "security/ ← placeholder"
fi

# Build metadata — hem landing hem deployment build için aynı değerler
# kullanılmalı; deployment'tan ÖNCE export edip aşağıdaki tüm child
# process'lerden erişilebilsin.
export BUILD_NUMBER="local-$(date +%H%M%S)"
export COMMIT_SHORT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
export COMMIT_URL="$(git config --get remote.origin.url 2>/dev/null | sed 's|\.git$||')/commit/$(git rev-parse HEAD 2>/dev/null || echo HEAD)"
export GENERATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
export TEST_TOTAL TEST_PASSED TEST_FAILED COVERAGE_PCT BRANCH_COVERAGE_PCT
export REPO_SLUG="mersel-dss/mersel-dss-server-signer-java"
export GIT_REF="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo main)"

# Deployment Runbook — pandoc varsa devops/ + docs/RUN_PROFILES.md'yi
# tabbed HTML'e render eder. Yoksa minimal placeholder bırakır (link'ler
# GitHub blob'a düşer; auditor markdown'ı oradan da okuyabilir).
mkdir -p pages-output/deployment
if [ "$SKIP_DEPLOYMENT" = true ]; then
  cat > pages-output/deployment/index.html <<'EOF'
<!doctype html><meta charset=utf-8><title>Deployment runbook skipped</title>
<h1>Deployment runbook üretimi atlandı</h1>
<p><code>--skip-deployment</code> flag'i verildi. <code>bash docs/deployment/build.sh</code>
   ile manuel üretebilirsin.</p>
EOF
  warn "deployment/ ← placeholder (--skip-deployment)"
elif ! command -v pandoc >/dev/null 2>&1; then
  cat > pages-output/deployment/index.html <<'EOF'
<!doctype html><meta charset=utf-8><title>Deployment runbook unavailable</title>
<h1>Deployment runbook üretilemedi</h1>
<p>pandoc yüklü değil. <code>brew install pandoc</code> veya
   <code>sudo apt-get install -y pandoc</code> sonrası tekrar koş.</p>
EOF
  warn "deployment/ ← placeholder (pandoc yok — 'brew install pandoc' önerilir)"
else
  if bash docs/deployment/build.sh -o pages-output/deployment >/dev/null; then
    ok "deployment/ ← Production Runbook (Linux | Windows | Docker | Run Profiles)"
  else
    warn "deployment/ build.sh başarısız — placeholder yazılıyor"
    cat > pages-output/deployment/index.html <<'EOF'
<!doctype html><meta charset=utf-8><title>Deployment runbook failed</title>
<h1>Deployment runbook üretimi başarısız</h1>
<p>Detay için: <code>bash docs/deployment/build.sh -o pages-output/deployment</code>
   komutunu manuel olarak çalıştır.</p>
EOF
  fi
fi

# Landing — envsubst veya python fallback ile placeholder injection

if command -v envsubst >/dev/null 2>&1; then
  envsubst < docs/landing/index.html > pages-output/index.html
  ok "index.html ← envsubst ile metadata inject edildi"
else
  info "envsubst yok (brew install gettext öner.); python ile inject ediyorum"
  python3 - <<'PYEOF'
import os
src = open("docs/landing/index.html").read()
for k in ("BUILD_NUMBER","COMMIT_SHORT","COMMIT_URL","GENERATED_AT",
          "TEST_TOTAL","TEST_PASSED","TEST_FAILED",
          "COVERAGE_PCT","BRANCH_COVERAGE_PCT","REPO_SLUG"):
    src = src.replace("${"+k+"}", os.environ.get(k, ""))
open("pages-output/index.html","w").write(src)
PYEOF
  ok "index.html ← python ile metadata inject edildi"
fi

# 404
cat > pages-output/404.html <<'EOF'
<!doctype html>
<meta charset=utf-8>
<meta http-equiv="refresh" content="0; url=./">
<title>Not found — Mersel DSS Evidence</title>
<p>Aradığınız sayfa burada değil; <a href="./">ana sayfa</a>ya yönlendiriliyorsunuz.</p>
EOF

echo ""
ok "pages-output/ hazır:"
find pages-output -maxdepth 2 -type d | sort | sed 's/^/    /'
echo ""
TOTAL_SIZE=$(du -sh pages-output 2>/dev/null | awk '{print $1}')
info "Toplam boyut: $TOTAL_SIZE"

ELAPSED=$(( $(date +%s) - START_EPOCH ))
info "Build süresi: ${ELAPSED}s"

# ─── 7) HTTP serve ───────────────────────────────────────────────────────────
if [ "$NO_SERVE" = true ]; then
  echo ""
  ok "Hazır. Tarayıcıda görmek için:"
  echo "    cd pages-output && python3 -m http.server $PORT"
  exit 0
fi

step "7) HTTP server başlatılıyor (port $PORT)"
# Port kullanımdaysa temizle
if lsof -ti tcp:$PORT 2>/dev/null | head -1 > /dev/null; then
  warn "Port $PORT zaten kullanılıyor; kapatılıyor"
  lsof -ti tcp:$PORT 2>/dev/null | xargs -r kill -9 2>/dev/null || true
  sleep 1
fi

URL="http://localhost:$PORT/"
echo ""
echo "${BOLD}${GREEN}╔═══════════════════════════════════════════════════════════════╗${RESET}"
echo "${BOLD}${GREEN}║  Evidence Site hazır:${RESET}                                         "
echo "${BOLD}${GREEN}║${RESET}    ${CYAN}$URL${RESET}                                       "
echo "${BOLD}${GREEN}║${RESET}                                                                 "
echo "${BOLD}${GREEN}║${RESET}  Doğrudan linkler:                                              "
echo "${BOLD}${GREEN}║${RESET}    ${CYAN}${URL}test-report/${RESET}     → Allure (PASS/FAIL/Trend)        "
echo "${BOLD}${GREEN}║${RESET}    ${CYAN}${URL}coverage/${RESET}        → JaCoCo (line/branch coverage)    "
echo "${BOLD}${GREEN}║${RESET}    ${CYAN}${URL}openapi/${RESET}         → Scalar API Reference            "
echo "${BOLD}${GREEN}║${RESET}    ${CYAN}${URL}security/${RESET}        → OWASP Dependency-Check          "
echo "${BOLD}${GREEN}║${RESET}    ${CYAN}${URL}deployment/${RESET}      → Production Runbook (Linux/Win/Docker)"
echo "${BOLD}${GREEN}╚═══════════════════════════════════════════════════════════════╝${RESET}"
echo ""
info "Ctrl+C ile durdur."

# Browser aç (macOS / Linux)
if command -v open >/dev/null 2>&1; then
  ( sleep 1 && open "$URL" ) &
elif command -v xdg-open >/dev/null 2>&1; then
  ( sleep 1 && xdg-open "$URL" ) &
fi

# python3 ile serve — file traversal ve absolute path olmadığı için güvenli
cd pages-output
exec python3 -m http.server "$PORT"
