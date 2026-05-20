#!/usr/bin/env bash
#
# bump-version.sh
# =============================================================================
# pom.xml'in proje (parent değil) <version> satırını günceller.
#
# Kullanım:
#   ./scripts/bump-version.sh <NEW_VERSION>
#   ./scripts/bump-version.sh major
#   ./scripts/bump-version.sh minor
#   ./scripts/bump-version.sh patch
#   ./scripts/bump-version.sh rc        # mevcut sürümü 0.5.0 ise 0.5.0-rc.1, rc.1 ise rc.2 yapar
#
# Doğrudan SemVer string'i verebilir (örn. "0.5.0", "1.0.0-rc.2") veya
# bump tipi geçebilirsiniz (major/minor/patch/rc).
#
# Bu script SADECE pom.xml'i değiştirir; commit / push / tag yapmaz.
# Onları `release.sh` yapar. Tek başına da çağrılabilir
# (örn. main branch'te bir sonraki development sürümünü açmak için).
#
# Bağımlılık: bash, sed, awk, grep, perl. macOS BSD sed ile de uyumlu.
#
# Exit kodları:
#   0 → güncellendi
#   1 → kullanım hatası
#   2 → pom.xml bulunamadı veya çoklu <version> match'i
#   3 → invalid SemVer
# -----------------------------------------------------------------------------

set -euo pipefail

usage() {
    cat >&2 <<EOF
Kullanım: $0 <NEW_VERSION | major | minor | patch | rc>

Örnekler:
  $0 0.5.0              # explicit sürüm
  $0 1.0.0-rc.1         # explicit pre-release
  $0 patch              # 0.4.0 → 0.4.1
  $0 minor              # 0.4.0 → 0.5.0
  $0 major              # 0.4.0 → 1.0.0
  $0 rc                 # 0.5.0 → 0.5.0-rc.1   |  0.5.0-rc.1 → 0.5.0-rc.2

Sürüm SemVer 2.0.0'a uymalıdır: MAJOR.MINOR.PATCH[-PRERELEASE]
EOF
    exit 1
}

if [[ $# -ne 1 ]]; then
    usage
fi

ARG="$1"

# Repo root'tan çalış (pom.xml her ihtimalde script'in iki üstünde aranır)
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_ROOT="$( cd "${SCRIPT_DIR}/.." && pwd )"
POM="${REPO_ROOT}/pom.xml"

if [[ ! -f "$POM" ]]; then
    echo "HATA: pom.xml bulunamadı: $POM" >&2
    exit 2
fi

# Mevcut sürümü oku — sadece proje <version>'ı (parent değil).
# Bizim pom.xml struct'ı: <parent>...<version>2.7.18</version></parent>
# <groupId>...</groupId><artifactId>...</artifactId><version>0.4.0</version>
# perl -0777 ile dosyayı tek string olarak yutup parent block'unu
# maskeleyip kalandaki ilk <version>'ı yakalıyoruz. macOS BSD awk
# match() capture group'larını desteklemediği için perl tek seçenek.
CURRENT_VERSION=$(perl -0777 -ne '
    s|<parent>.*?</parent>||s;
    if (/<version>([^<]+)<\/version>/) { print $1; exit }
' "$POM")

if [[ -z "$CURRENT_VERSION" ]]; then
    echo "HATA: pom.xml içinden mevcut sürüm okunamadı." >&2
    exit 2
fi

echo "Mevcut sürüm: $CURRENT_VERSION" >&2

# SemVer parse fonksiyonu: girdi "1.2.3-rc.4" → MAJOR=1 MINOR=2 PATCH=3 PRE=rc.4
parse_semver() {
    local v="$1"
    if [[ ! "$v" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)(-([A-Za-z0-9.\-]+))?$ ]]; then
        echo "HATA: '$v' geçerli bir SemVer 2.0.0 sürümü değil." >&2
        echo "      Beklenen format: MAJOR.MINOR.PATCH[-PRERELEASE]" >&2
        exit 3
    fi
    P_MAJOR="${BASH_REMATCH[1]}"
    P_MINOR="${BASH_REMATCH[2]}"
    P_PATCH="${BASH_REMATCH[3]}"
    P_PRE="${BASH_REMATCH[5]:-}"
}

parse_semver "$CURRENT_VERSION"

case "$ARG" in
    major)
        NEW_VERSION="$((P_MAJOR + 1)).0.0"
        ;;
    minor)
        NEW_VERSION="${P_MAJOR}.$((P_MINOR + 1)).0"
        ;;
    patch)
        NEW_VERSION="${P_MAJOR}.${P_MINOR}.$((P_PATCH + 1))"
        ;;
    rc)
        # Mevcut zaten rc.N ise N+1; değilse rc.1 ekle
        if [[ "$P_PRE" =~ ^rc\.([0-9]+)$ ]]; then
            NEW_RC="$((BASH_REMATCH[1] + 1))"
            NEW_VERSION="${P_MAJOR}.${P_MINOR}.${P_PATCH}-rc.${NEW_RC}"
        else
            NEW_VERSION="${P_MAJOR}.${P_MINOR}.${P_PATCH}-rc.1"
        fi
        ;;
    *)
        # Explicit version verildi → SemVer doğrula
        parse_semver "$ARG"
        NEW_VERSION="$ARG"
        ;;
esac

echo "Hedef sürüm:  $NEW_VERSION" >&2

if [[ "$NEW_VERSION" == "$CURRENT_VERSION" ]]; then
    echo "Sürüm zaten $NEW_VERSION — değişiklik yapılmadı." >&2
    exit 0
fi

# pom.xml'i güncelle — sadece parent disindaki ilk <version> satirini degistir.
# perl ile in-place edit; macOS/BSD sed ve GNU sed farkini by-pass eder.
# Degerleri env var olarak gecirip script icinde quoting-sorunu yasamiyoruz.
CUR_VER="$CURRENT_VERSION" NEW_VER="$NEW_VERSION" perl -i -0777 -pe '
    my $cur = $ENV{CUR_VER};
    my $new = $ENV{NEW_VER};
    my $saved_parent;
    if (s|(<parent>.*?</parent>)|__PARENT_BLOCK__|s) {
        $saved_parent = $1;
    }
    s|<version>\Q$cur\E</version>|<version>$new</version>|;
    if (defined $saved_parent) {
        s|__PARENT_BLOCK__|$saved_parent|s;
    }
' "$POM"

# Maven CLI doğrulaması (opsiyonel; varsa kullan, yoksa atla)
if command -v mvn >/dev/null 2>&1; then
    ACTUAL=$(mvn -q -Dexec.executable="echo" -Dexec.args='${project.version}' --non-recursive exec:exec 2>/dev/null | tail -n 1 | tr -d '\r')
    if [[ -n "$ACTUAL" && "$ACTUAL" != "$NEW_VERSION" ]]; then
        echo "UYARI: Maven 'project.version' ($ACTUAL) güncel pom.xml ile uyuşmuyor." >&2
        echo "       pom.xml manuel kontrol gerekebilir." >&2
    fi
fi

echo "pom.xml güncellendi: $CURRENT_VERSION → $NEW_VERSION" >&2
echo "$NEW_VERSION"
