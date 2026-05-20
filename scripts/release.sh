#!/usr/bin/env bash
#
# release.sh
# =============================================================================
# Mersel DSS Signer API — Lokal release hazırlama yardımcısı.
#
# Bu script bir release'i "fırlatılabilir" hale getirir:
#   1. Working tree temiz olmalı (uncommitted change yok).
#   2. main branch üzerinde olmalı.
#   3. pom.xml sürümü yeni release sürümüne bump'lanır (opsiyonel — zaten
#      bump'lanmışsa atlanır).
#   4. CHANGELOG.md'nin [Unreleased] bölümü '[X.Y.Z] - YYYY-MM-DD' başlığına
#      finalize edilir; yeni boş [Unreleased] bloğu üste eklenir.
#   5. release commit'i oluşturulur ("release: vX.Y.Z").
#   6. v{X.Y.Z} annotated + signed (mümkünse) git tag'i atılır.
#   7. Push'u kullanıcıya bırakır — onay olmadan REMOTE'a hiçbir şey gitmez.
#
# Kullanım:
#   ./scripts/release.sh <VERSION>          # explicit: 0.5.0, 1.0.0-rc.1, ...
#   ./scripts/release.sh patch              # 0.4.0 → 0.4.1
#   ./scripts/release.sh minor              # 0.4.0 → 0.5.0
#   ./scripts/release.sh major              # 0.4.0 → 1.0.0
#
# Bayraklar:
#   --no-build      → mvn package adımını atla (sadece doc/tag işlemleri)
#   --no-test       → mvn test atla (build sürer ama test koşmaz)
#   --skip-clean    → working tree clean check'i atla (DİKKAT)
#   --dry-run       → hiçbir dosya değişikliği veya git komutu yapma; ne yapacağını yaz
#   --yes           → tüm "devam edelim mi?" promptlarına evet de
#
# Tag immutability:
#   Tag zaten varsa script reddeder. Tag'i silmek için manuel müdahale
#   gerekir — bu kasıtlı. Push edilmiş bir tag'i silmek "release immutability"
#   kuralını ihlal eder; release'i geri çağırmak yerine yeni patch sürümü
#   çıkarın.
#
# Bağımlılıklar: bash, git, perl, sed; mvn (--no-build verilmezse).
# -----------------------------------------------------------------------------

set -euo pipefail

# Renkler (TTY ise)
if [[ -t 1 ]]; then
    R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'; NC='\033[0m'
else
    R=''; G=''; Y=''; B=''; NC=''
fi

info()  { printf "${B}ℹ${NC}  %s\n" "$*"; }
ok()    { printf "${G}✓${NC}  %s\n" "$*"; }
warn()  { printf "${Y}⚠${NC}  %s\n" "$*" >&2; }
fail()  { printf "${R}✗${NC}  %s\n" "$*" >&2; exit 1; }

# -----------------------------------------------------------------------------
# Argüman parse
# -----------------------------------------------------------------------------

VERSION_ARG=""
DO_BUILD=1
DO_TEST=1
SKIP_CLEAN_CHECK=0
DRY_RUN=0
YES=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-build)    DO_BUILD=0 ;;
        --no-test)     DO_TEST=0 ;;
        --skip-clean)  SKIP_CLEAN_CHECK=1 ;;
        --dry-run)     DRY_RUN=1 ;;
        --yes|-y)      YES=1 ;;
        -h|--help)
            sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        -*)
            fail "Bilinmeyen bayrak: $1 (--help için: $0 --help)"
            ;;
        *)
            if [[ -n "$VERSION_ARG" ]]; then
                fail "Birden fazla sürüm argümanı verildi: '$VERSION_ARG' ve '$1'"
            fi
            VERSION_ARG="$1"
            ;;
    esac
    shift
done

if [[ -z "$VERSION_ARG" ]]; then
    fail "Sürüm argümanı zorunlu. Örnek: $0 0.5.0  veya  $0 patch"
fi

# -----------------------------------------------------------------------------
# Yardımcı
# -----------------------------------------------------------------------------

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_ROOT="$( cd "${SCRIPT_DIR}/.." && pwd )"
POM="${REPO_ROOT}/pom.xml"
CHANGELOG="${REPO_ROOT}/CHANGELOG.md"

cd "$REPO_ROOT"

run() {
    # dry-run modunda komutu sadece basar, çalıştırmaz
    if [[ $DRY_RUN -eq 1 ]]; then
        printf "${Y}[DRY-RUN]${NC} %s\n" "$*"
    else
        "$@"
    fi
}

confirm() {
    local prompt="$1"
    if [[ $YES -eq 1 ]]; then
        return 0
    fi
    read -r -p "$(printf "${Y}?${NC} %s [y/N] " "$prompt")" reply
    [[ "$reply" =~ ^[Yy]$ ]]
}

# -----------------------------------------------------------------------------
# 1. Working tree temiz mi?
# -----------------------------------------------------------------------------

info "Git çalışma ağacı kontrol ediliyor..."
if [[ $SKIP_CLEAN_CHECK -eq 0 ]]; then
    if ! git diff-index --quiet HEAD --; then
        warn "Working tree temiz değil:"
        git status --short
        confirm "Yine de devam edeyim mi?" || fail "İptal edildi."
    else
        ok "Working tree temiz."
    fi
else
    warn "Working tree check atlandı (--skip-clean)."
fi

# -----------------------------------------------------------------------------
# 2. Branch kontrolü
# -----------------------------------------------------------------------------

CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
info "Mevcut branch: ${CURRENT_BRANCH}"
if [[ "$CURRENT_BRANCH" != "main" ]]; then
    warn "Production release genellikle 'main' branch'inden yapılır."
    confirm "'$CURRENT_BRANCH' üzerinden devam edeyim mi?" || fail "İptal edildi."
fi

# -----------------------------------------------------------------------------
# 3. Mevcut sürümü oku ve hedef sürümü hesapla
# -----------------------------------------------------------------------------

CURRENT_VERSION=$(perl -0777 -ne '
    s|<parent>.*?</parent>||s;
    if (/<version>([^<]+)<\/version>/) { print $1; exit }
' "$POM")
[[ -n "$CURRENT_VERSION" ]] || fail "pom.xml'den mevcut sürüm okunamadı."

# Eğer arg zaten X.Y.Z formatındaysa direkt kullan; major/minor/patch ise bump et
case "$VERSION_ARG" in
    major|minor|patch|rc)
        TARGET_VERSION=$("${SCRIPT_DIR}/bump-version.sh" "$VERSION_ARG" 2>/dev/null | tail -n 1)
        # bump-version.sh dosyayı değiştirir; geri al — biz birazdan dry-run-safe biçimde
        # yeniden çağıracağız. Şimdi sadece hedef sürümü öğrenmek istedik.
        if [[ $DRY_RUN -eq 0 ]]; then
            git checkout -- "$POM" 2>/dev/null || true
        fi
        ;;
    *)
        TARGET_VERSION="$VERSION_ARG"
        ;;
esac

info "Mevcut sürüm: ${CURRENT_VERSION}"
info "Hedef sürüm:  ${TARGET_VERSION}"

# SemVer doğrula
if [[ ! "$TARGET_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.\-]+)?$ ]]; then
    fail "Hedef sürüm SemVer 2.0.0 formatında değil: ${TARGET_VERSION}"
fi

# -SNAPSHOT yasak
if [[ "$TARGET_VERSION" == *SNAPSHOT* ]]; then
    fail "Release sürümü -SNAPSHOT içeremez: ${TARGET_VERSION}"
fi

TAG="v${TARGET_VERSION}"

# -----------------------------------------------------------------------------
# 4. Tag çakışması kontrolü (immutability)
# -----------------------------------------------------------------------------

info "Tag çakışması kontrol ediliyor: ${TAG}"
if git rev-parse "$TAG" >/dev/null 2>&1; then
    fail "Tag '${TAG}' lokal repository'de zaten var. Release tag'leri immutable'dır; silinmemeli."
fi
if git ls-remote --tags origin "refs/tags/${TAG}" 2>/dev/null | grep -q "$TAG"; then
    fail "Tag '${TAG}' REMOTE'da zaten var. Release immutable'dır — yeni patch sürümü çıkarın."
fi
ok "Tag '${TAG}' boşta — devam ediliyor."

# -----------------------------------------------------------------------------
# 5. CHANGELOG.md kontrolü
# -----------------------------------------------------------------------------

[[ -f "$CHANGELOG" ]] || fail "CHANGELOG.md bulunamadı: $CHANGELOG"

if ! grep -qE '^## \[Unreleased\]' "$CHANGELOG"; then
    fail "CHANGELOG.md'de '## [Unreleased]' başlığı bulunamadı."
fi

# Hedef sürüm header zaten varsa — bu finalize edilmiş demektir
if grep -qE "^## \[${TARGET_VERSION}\]" "$CHANGELOG"; then
    warn "CHANGELOG.md'de '## [${TARGET_VERSION}]' başlığı zaten var — finalize adımı atlanacak."
    CHANGELOG_ALREADY_FINALIZED=1
else
    CHANGELOG_ALREADY_FINALIZED=0
fi

# Unreleased section'unun içinde gerçek bir içerik var mı?
UNRELEASED_BODY=$(awk '
    /^## \[Unreleased\]/ { in_section = 1; next }
    in_section && /^## \[/ { exit }
    in_section { print }
' "$CHANGELOG" | grep -v -E '^[[:space:]]*$' || true)

if [[ -z "$UNRELEASED_BODY" && $CHANGELOG_ALREADY_FINALIZED -eq 0 ]]; then
    warn "CHANGELOG.md [Unreleased] bölümü boş görünüyor."
    confirm "Yine de devam edeyim mi?" || fail "İptal edildi."
fi

# -----------------------------------------------------------------------------
# 6. pom.xml'i bump et (gerekiyorsa)
# -----------------------------------------------------------------------------

if [[ "$CURRENT_VERSION" != "$TARGET_VERSION" ]]; then
    info "pom.xml güncelleniyor: ${CURRENT_VERSION} → ${TARGET_VERSION}"
    if [[ $DRY_RUN -eq 0 ]]; then
        "${SCRIPT_DIR}/bump-version.sh" "$TARGET_VERSION" >/dev/null
    else
        printf "${Y}[DRY-RUN]${NC} ${SCRIPT_DIR}/bump-version.sh ${TARGET_VERSION}\n"
    fi
    ok "pom.xml güncellendi."
else
    info "pom.xml zaten ${TARGET_VERSION} — bump atlandı."
fi

# -----------------------------------------------------------------------------
# 7. CHANGELOG.md finalize
# -----------------------------------------------------------------------------

if [[ $CHANGELOG_ALREADY_FINALIZED -eq 0 ]]; then
    TODAY=$(date -u +%Y-%m-%d)
    info "CHANGELOG.md finalize ediliyor: [Unreleased] → [${TARGET_VERSION}] - ${TODAY}"
    if [[ $DRY_RUN -eq 0 ]]; then
        # perl ile in-place: '## [Unreleased]' satırını '## [Unreleased]\n\n## [VER] - DATE' yap
        TARGET_VER="$TARGET_VERSION" TODAY="$TODAY" perl -i -0777 -pe '
            my $ver = $ENV{TARGET_VER};
            my $today = $ENV{TODAY};
            # Mevcut "## [Unreleased]" başlığını koru ve hemen ALTINA yeni release başlığını ekle.
            # Boş bir Unreleased iskeleti üstte kalır → sonraki dev için hazır.
            my $new_block = "## [Unreleased]\n\n## [$ver] - $today";
            s|^## \[Unreleased\]|$new_block|m;
        ' "$CHANGELOG"
        ok "CHANGELOG.md finalize edildi."
    else
        printf "${Y}[DRY-RUN]${NC} CHANGELOG.md'ye '## [${TARGET_VERSION}] - ${TODAY}' eklenecek.\n"
    fi
fi

# -----------------------------------------------------------------------------
# 8. (Opsiyonel) Test ve build
# -----------------------------------------------------------------------------

if [[ $DO_TEST -eq 1 ]]; then
    info "Unit testler çalıştırılıyor: mvn test"
    if [[ $DRY_RUN -eq 0 ]]; then
        if ! mvn -B test; then
            fail "Testler başarısız — release iptal edildi."
        fi
        ok "Testler geçti."
    else
        printf "${Y}[DRY-RUN]${NC} mvn -B test\n"
    fi
else
    warn "Test atlandı (--no-test)."
fi

if [[ $DO_BUILD -eq 1 ]]; then
    info "Build koşturuluyor: mvn package -DskipTests"
    if [[ $DRY_RUN -eq 0 ]]; then
        if ! mvn -B package -DskipTests; then
            fail "Build başarısız — release iptal edildi."
        fi
        ok "Build başarılı."
        JAR=$(find target -maxdepth 1 -name '*.jar' ! -name '*-sources.jar' ! -name '*-javadoc.jar' ! -name '*.original' 2>/dev/null | head -1)
        if [[ -n "$JAR" ]]; then
            info "Üretilen artifact: $JAR ($(du -h "$JAR" | cut -f1))"
        fi
    else
        printf "${Y}[DRY-RUN]${NC} mvn -B package -DskipTests\n"
    fi
else
    warn "Build atlandı (--no-build)."
fi

# -----------------------------------------------------------------------------
# 9. Git commit + tag
# -----------------------------------------------------------------------------

confirm "pom.xml + CHANGELOG.md değişikliklerini commit edeyim mi?" || {
    warn "Commit ve tag atlandı. Değişiklikler working tree'de duruyor."
    exit 0
}

info "git add + commit"
run git add "$POM" "$CHANGELOG"
COMMIT_MSG="release: ${TAG}

CHANGELOG.md finalize edildi: [Unreleased] -> [${TARGET_VERSION}].
pom.xml version: ${CURRENT_VERSION} -> ${TARGET_VERSION}.

Tag '${TAG}' immutable'dır; CI/CD release.yml workflow'u bu tag'i
tetikleyici olarak kullanır."

if [[ $DRY_RUN -eq 0 ]]; then
    git commit -m "$COMMIT_MSG"
else
    printf "${Y}[DRY-RUN]${NC} git commit -m \"release: ${TAG}\"\n"
fi
ok "Commit oluşturuldu."

# Tag — mümkünse signed (GPG / SSH key)
info "Annotated tag oluşturuluyor: ${TAG}"
TAG_MSG="Mersel DSS Signer API ${TAG}

CHANGELOG'tan ilgili bölüm için bkz. CHANGELOG.md."

# Signed tag denenir; key yoksa annotated fallback
SIGN_FLAG=""
if [[ $DRY_RUN -eq 0 ]]; then
    if git config --get user.signingkey >/dev/null 2>&1; then
        SIGN_FLAG="-s"
        info "git signingkey set — signed tag deneniyor."
    fi
    if ! git tag $SIGN_FLAG -a "$TAG" -m "$TAG_MSG" 2>/dev/null; then
        warn "Signed tag oluşturulamadı, annotated (unsigned) deneniyor."
        git tag -a "$TAG" -m "$TAG_MSG"
    fi
    ok "Tag '${TAG}' oluşturuldu."
else
    printf "${Y}[DRY-RUN]${NC} git tag -a ${TAG} -m '...'\n"
fi

# -----------------------------------------------------------------------------
# 10. Push talimatı (manuel — script ASLA otomatik push yapmaz)
# -----------------------------------------------------------------------------

cat <<EOF

${G}╔══════════════════════════════════════════════════════════════╗${NC}
${G}║  Lokal release hazirligi tamamlandi: ${TAG}$(printf '%*s' $((28 - ${#TAG})) '')║${NC}
${G}╚══════════════════════════════════════════════════════════════╝${NC}

Siradaki adimlar (manuel):

  ${B}1. Commit ve tag'i remote'a push edin:${NC}
     git push origin ${CURRENT_BRANCH}
     git push origin ${TAG}

  ${B}2. release.yml workflow'u otomatik tetiklenir:${NC}
     - JAR + sources.jar + SBOM build eder
     - SHA-256 checksum'lar uretir
     - CHANGELOG'tan ${TAG} bolumunu cikartip GitHub Release acar
     - Release artifact'lerini upload eder (immutable)

  ${B}3. Docker workflow'u paralel olarak imaj yayinlar:${NC}
     ghcr.io/mersel-dss/mersel-dss-server-signer-java:${TARGET_VERSION}

${Y}NOT:${NC} Tag '${TAG}' push edildikten sonra silinmemeli. Release
mekanizmamiz tag'leri immutable kabul eder; geri almak yerine
yeni patch surumu cikarin (release.sh patch).
EOF
