#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  docs/deployment/build.sh
#
#  Production Deployment Runbook sayfasını üretir:
#    pages-output/deployment/index.html
#
#  Kaynaklar (DRY — tek-doğruluk-kaynağı README'ler):
#    - devops/systemd/README.md         → Linux tab
#    - devops/windows-service/README.md → Windows tab
#    - devops/docker/README.md          → Docker tab
#    - docs/RUN_PROFILES.md             → Run Profilleri tab
#
#  Pipeline:
#    1) pandoc her markdown'ı `<section-divs>` HTML fragment'ına çevirir
#       (`--from gfm` GitHub Flavored MD; tablo, fenced code, task list).
#    2) Repo-içi `.md` linkleri rewrite edilir:
#         - Aynı README'ye anchor → olduğu gibi bırak
#         - `docs/RUN_PROFILES.md`, `devops/.../README.md` → sayfa-içi tab
#           (`#linux`, `#windows`, `#docker`, `#run-profiles`)
#         - Diğer `.md` yolları → GitHub blob URL'sine çevir
#    3) `docs/deployment/template.html` içindeki BEGIN_*_CONTENT
#       sentinel'leri arasına fragment'lar inject edilir.
#    4) Build metadata (run number, ISO timestamp) footer'a yazılır.
#
#  Kullanım:
#    bash docs/deployment/build.sh -o pages-output/deployment
#    BUILD_NUMBER=42 GITHUB_REPOSITORY=owner/repo bash docs/deployment/build.sh
#
#  Bağımlılıklar:
#    - pandoc 2.x veya 3.x (ubuntu-latest'te `apt-get install -y pandoc`)
#    - python3 (template injection için — pandoc'tan daha güvenli regex
#               handling; sed'in multi-line replace'i POSIX'te kırılgan)
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ─── Repo root'a normalize ──────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

# ─── Args ───────────────────────────────────────────────────────────────────
OUT_DIR="pages-output/deployment"
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|--out) OUT_DIR="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,30p' "$0"; exit 0 ;;
    *)
      echo "✗ Bilinmeyen argüman: $1" >&2; exit 1 ;;
  esac
done

# ─── Dependency check ──────────────────────────────────────────────────────
if ! command -v pandoc >/dev/null 2>&1; then
  echo "✗ pandoc bulunamadı." >&2
  echo "  Ubuntu: sudo apt-get install -y pandoc" >&2
  echo "  macOS : brew install pandoc" >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "✗ python3 bulunamadı (template injection için gerekli)." >&2
  exit 1
fi

PANDOC_VERSION="$(pandoc --version | head -1)"
echo "› Pandoc        : $PANDOC_VERSION"
echo "› Out dir       : $OUT_DIR"

# ─── Build metadata (CI'da inject edilir; local'de placeholder) ────────────
BUILD_NUMBER="${BUILD_NUMBER:-${GITHUB_RUN_NUMBER:-dev}}"
GENERATED_AT="${GENERATED_AT:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
REPO_SLUG="${REPO_SLUG:-${GITHUB_REPOSITORY:-mersel-dss/mersel-dss-server-signer-java}}"
GIT_REF="${GIT_REF:-${GITHUB_REF_NAME:-main}}"

# ─── Pandoc fragment renderer ─────────────────────────────────────────────
# `--standalone` KULLANMIYORUZ — bütün <html><head><body> wrapper'ı istemiyoruz,
# sadece body fragment'ı. Pandoc default'u zaten "fragment-only".
#
# `--no-highlight`: production'da Tailwind prose kod bloklarını kendi
# temasıyla styler (template.html'deki <style>); pandoc'un Pygments-style
# inline highlighting'iyle çakışmasın.
#
# Fragment'ları geçici dosyaya yaz, link rewriting'i Python ile yap
# (heredoc içinden Python'a string geçirmek escape edge case'leri açar;
# tmpfile yolu en güvenli).

TMPDIR_RENDER="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_RENDER"' EXIT

render_to_tmpfile() {
  local src="$1"
  local panel_id="$2"

  if [ ! -f "$src" ]; then
    echo "::warning::Kaynak yok, boş fragment üretiliyor: $src" >&2
    echo "<p><em>Kaynak markdown bulunamadı: <code>$src</code></em></p>" \
      > "$TMPDIR_RENDER/$panel_id.html"
    return 0
  fi

  pandoc "$src" \
    --from gfm \
    --to html \
    --no-highlight \
    --wrap=preserve \
    > "$TMPDIR_RENDER/$panel_id.raw.html"

  # Repo-içi link rewriting
  GIT_REF="$GIT_REF" REPO_SLUG="$REPO_SLUG" \
  python3 "$SCRIPT_DIR/rewrite_links.py" \
    "$TMPDIR_RENDER/$panel_id.raw.html" \
    "$panel_id" \
    > "$TMPDIR_RENDER/$panel_id.html"

  local lines
  lines="$(wc -l < "$TMPDIR_RENDER/$panel_id.html")"
  echo "  ✓ $panel_id ($lines satır HTML)"
}

# ─── 4 panel'i render et ──────────────────────────────────────────────────
echo "› Pandoc render..."
render_to_tmpfile devops/systemd/README.md          linux
render_to_tmpfile devops/windows-service/README.md  windows
render_to_tmpfile devops/docker/README.md           docker
render_to_tmpfile docs/RUN_PROFILES.md              run-profiles

# ─── Template injection ───────────────────────────────────────────────────
mkdir -p "$OUT_DIR"
TEMPLATE="$SCRIPT_DIR/template.html"
OUT_FILE="$OUT_DIR/index.html"

BUILD_NUMBER="$BUILD_NUMBER" \
GENERATED_AT="$GENERATED_AT" \
python3 "$SCRIPT_DIR/inject_template.py" \
  "$TEMPLATE" \
  "$TMPDIR_RENDER/linux.html" \
  "$TMPDIR_RENDER/windows.html" \
  "$TMPDIR_RENDER/docker.html" \
  "$TMPDIR_RENDER/run-profiles.html" \
  > "$OUT_FILE"

# Sanity check — template iskeletinin kendisi ~10 KB. Çıktı bunun altındaysa
# muhtemelen injection sırasında bir yerde patladı (sentinel match miss,
# fragment file boş vs.). Bu durumda silent-deploy yerine fail-fast ile
# uyarı verelim; outer caller (workflow / serve-pages-locally.sh) buna
# göre placeholder yazar.
OUT_BYTES="$(wc -c < "$OUT_FILE")"
MIN_BYTES=8000
if [ "$OUT_BYTES" -lt "$MIN_BYTES" ]; then
  echo "✗ Çıktı tuhaf küçük: $OUT_FILE = $OUT_BYTES byte (min $MIN_BYTES bekleniyordu)" >&2
  echo "  Olası neden: pandoc fragment boş, sentinel bulunamadı, veya inject_template hata verdi." >&2
  exit 2
fi

echo "› Çıktı         : $OUT_FILE ($OUT_BYTES byte)"
echo "✓ Deployment runbook üretildi."
