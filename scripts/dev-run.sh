#!/usr/bin/env bash
# =====================================================================
#  dev-run.sh — Mersel DSS Signer'ı IDE'siz çalıştırmak için
#               OS auto-detect eden geliştirici scripti.
# =====================================================================
#  Kullanım:
#    ./scripts/dev-run.sh                  → default (KURUM01 RSA PFX)
#    ./scripts/dev-run.sh kurum02-ec384    → KURUM02 EC-P384 PFX
#    ./scripts/dev-run.sh mali-muhur-akis  → Mali Mühür AKİS (OS auto)
#    ./scripts/dev-run.sh list             → mevcut profilleri listele
#
#  Senaryo isimleri = application-<senaryo>.properties (pfx- veya mali-muhur-
#  prefix'i olmadan; script prefix'leri kendi seçer). 'list' altında detay görürsün.
#
#  Gereklilikler:
#    • Java 8+ (JDK). 'java -version' başarılı olmalı.
#    • Maven 3.6+ (./mvnw varsa onu kullanır, yoksa sistem 'mvn').
#    • Mali Mühür senaryolarında: CERTIFICATE_PIN env'i veya -p <PIN> argumanı.
# =====================================================================

set -euo pipefail

# ───────────────────────────────────────── helpers
die() { printf '\033[31m✗\033[0m %s\n' "$*" >&2; exit 1; }
info() { printf '\033[36m›\033[0m %s\n' "$*"; }
ok() { printf '\033[32m✓\033[0m %s\n' "$*"; }

# ───────────────────────────────────────── OS detection
detect_os() {
  case "${OSTYPE:-$(uname -s | tr '[:upper:]' '[:lower:]')}" in
    darwin*) echo "mac" ;;
    linux*)  echo "linux" ;;
    cygwin*|mingw*|msys*) echo "windows" ;;
    *)
      # uname -s fallback (zsh/bash farklılığı için)
      case "$(uname -s 2>/dev/null || true)" in
        Darwin) echo "mac" ;;
        Linux) echo "linux" ;;
        MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
        *) echo "unknown" ;;
      esac
      ;;
  esac
}

# ───────────────────────────────────────── senaryo → profile mapping
# PFX senaryolar tüm OS'larda aynı dosyayı kullanır; Mali Mühür senaryolar OS-spesifik.
# NOT: `list` modu burada İŞLENMEZ — main()'in başında erken-dönüş yapılıyor;
#      aksi halde command substitution içindeki `exit` yalnızca subshell'i
#      kapatır, ana akış devam eder ve "list" string'i profile sanılır.
resolve_profile() {
  local scenario="$1"
  local os="$2"
  case "$scenario" in
    ""|default|kurum01-rsa2048)
      echo "local,pfx-kurum01-rsa2048" ;;
    kurum02-rsa2048)
      echo "local,pfx-kurum02-rsa2048" ;;
    kurum02-ec384)
      echo "local,pfx-kurum02-ec384" ;;
    kurum03-rsa2048)
      echo "local,pfx-kurum03-rsa2048" ;;
    kurum03-ec384)
      echo "local,pfx-kurum03-ec384" ;;
    mali-muhur-akis|mali-muhur)
      echo "local,mali-muhur-akis-${os}" ;;
    *)
      die "Bilinmeyen senaryo: '$scenario'. './scripts/dev-run.sh list' ile listele."
      ;;
  esac
}

# `list` senaryosu için yardım çıktısı.
print_scenarios() {
  cat <<'EOF'
Mevcut senaryolar:
  default | kurum01-rsa2048   → testkurum01 RSA-2048 (PIN=614573) [default]
  kurum02-rsa2048              → testkurum02 RSA-2048 sm.gov.tr (PIN=059025)
  kurum02-ec384                → testkurum02 EC-P384       (PIN=825095)
  kurum03-rsa2048              → testkurum03 RSA-2048      (PIN=181193)
  kurum03-ec384                → testkurum03 EC-P384       (PIN=540425)
  mali-muhur-akis | mali-muhur → Mali Mühür AKİS (OS auto: mac / linux / windows)

Kullanım:
  ./scripts/dev-run.sh                          # default
  ./scripts/dev-run.sh kurum02-ec384            # PFX EC-384
  CERTIFICATE_PIN=1234 ./scripts/dev-run.sh mali-muhur-akis
EOF
}

# ───────────────────────────────────────── main
main() {
  local scenario="${1:-default}"

  # list modu — başka iş yapmadan yardımı bas ve çık.
  if [[ "$scenario" == "list" || "$scenario" == "-h" || "$scenario" == "--help" ]]; then
    print_scenarios
    exit 0
  fi

  local os
  os="$(detect_os)"

  if [[ "$os" == "unknown" ]]; then
    die "İşletim sistemi tespit edilemedi (OSTYPE=$OSTYPE)."
  fi

  local profiles
  profiles="$(resolve_profile "$scenario" "$os")"

  info "OS         : $os"
  info "Senaryo    : $scenario"
  info "Profiles   : $profiles"

  # Java sağlık kontrolü
  if ! command -v java >/dev/null 2>&1; then
    die "java bulunamadı — JDK 8+ kurulu olmalı."
  fi
  local java_version
  java_version="$(java -version 2>&1 | head -n1)"
  info "Java       : $java_version"

  # Mali Mühür (HSM) senaryosunda PIN zorunlu — fail-fast
  if [[ "$profiles" == *mali-muhur-akis* && -z "${CERTIFICATE_PIN:-}" ]]; then
    die "Mali Mühür senaryosu için CERTIFICATE_PIN env'i gerekli. Örnek:
       CERTIFICATE_PIN=1234 ./scripts/dev-run.sh mali-muhur-akis"
  fi

  # Maven runner — wrapper varsa onu tercih et
  local mvn_cmd="mvn"
  if [[ -x "./mvnw" ]]; then
    mvn_cmd="./mvnw"
  elif ! command -v mvn >/dev/null 2>&1; then
    die "mvn (veya ./mvnw) bulunamadı — Maven 3.6+ kurulu olmalı."
  fi
  info "Maven      : $mvn_cmd"

  ok "Başlatılıyor..."
  exec "$mvn_cmd" spring-boot:run -Dspring-boot.run.profiles="$profiles"
}

main "$@"
