#!/usr/bin/env bash
#
# check-changelog-updated.sh
# =============================================================================
# PR'lar icin CHANGELOG.md guncellik kontrolu.
#
# Kural: PR'da bir 'src/main/' veya 'pom.xml' veya 'devops/' dosyasi
# degisiyorsa, CHANGELOG.md'nin [Unreleased] bolumu de mutlaka
# guncellenmis olmalidir.
#
# Bu script GitHub Actions changelog-check.yml workflow'unda kosturulur;
# yerel olarak da PR oncesi sanity check icin cagrilabilir.
#
# Kullanim:
#   ./scripts/check-changelog-updated.sh [BASE_REF] [HEAD_REF]
#
# Default'lar:
#   BASE_REF = origin/main
#   HEAD_REF = HEAD
#
# GitHub Actions'ta workflow şu env'leri set ediyor:
#   BASE_REF = github.event.pull_request.base.sha
#   HEAD_REF = github.event.pull_request.head.sha
#
# Exit kodları:
#   0 → kontrol passed (CHANGELOG güncellenmiş veya code dosyası değişmemiş)
#   1 → kontrol failed (code degisiyor ama CHANGELOG sabit)
#   2 → kullanim hatasi / git ref problemi
#
# Bypass: PR title veya commit message'da '[skip changelog]' veya
# '[no-changelog]' string'i varsa kontrol passed sayılır (tipo düzeltme
# gibi trivial PR'lar için).
# -----------------------------------------------------------------------------

set -euo pipefail

BASE_REF="${1:-${BASE_REF:-origin/main}}"
HEAD_REF="${2:-${HEAD_REF:-HEAD}}"

# Bypass tetikleyici string'ler
BYPASS_PATTERNS='\[skip changelog\]|\[no-changelog\]|\[skip-changelog\]'

if ! git rev-parse "$BASE_REF" >/dev/null 2>&1; then
    echo "HATA: BASE_REF '${BASE_REF}' git'te yok." >&2
    echo "      CI'da actions/checkout@v4 'fetch-depth: 0' ile cagrildi mi?" >&2
    exit 2
fi
if ! git rev-parse "$HEAD_REF" >/dev/null 2>&1; then
    echo "HATA: HEAD_REF '${HEAD_REF}' git'te yok." >&2
    exit 2
fi

# PR'daki commit mesajlarini topla; bypass var mi?
COMMIT_MSGS=$(git log --pretty=%B "${BASE_REF}..${HEAD_REF}" 2>/dev/null || echo "")
if echo "$COMMIT_MSGS" | grep -qE "$BYPASS_PATTERNS"; then
    echo "✓ Commit mesajinda bypass tag'i bulundu — changelog kontrolu atlandi."
    exit 0
fi

# PR title icin de bypass tetikleyici kontrol et (GitHub Actions PR_TITLE env)
if [[ -n "${PR_TITLE:-}" ]] && echo "$PR_TITLE" | grep -qE "$BYPASS_PATTERNS"; then
    echo "✓ PR title'da bypass tag'i bulundu — changelog kontrolu atlandi."
    exit 0
fi

# Degisen dosyalari listele
CHANGED_FILES=$(git diff --name-only "${BASE_REF}..${HEAD_REF}")

if [[ -z "$CHANGED_FILES" ]]; then
    echo "✓ PR'da dosya degisikligi yok — kontrol gereksiz."
    exit 0
fi

# 'Significant' dosyalar: kod, deployment, build, workflow, devops scripts.
# Test fixture generator scripts'lerini (scripts/generate-*) significant saymıyoruz
# çünkü sadece test verisi üretirler — runtime davranışını değiştirmezler.
# POSIX ERE (grep -E) negative-lookahead desteklemediği için iki adımda filtreliyoruz.
SIGNIFICANT_PATTERN='^(src/main/|src/test/|pom\.xml$|devops/|scripts/|\.github/workflows/)'
SIGNIFICANT_CHANGED=$(echo "$CHANGED_FILES" \
    | grep -E "$SIGNIFICANT_PATTERN" \
    | grep -vE '^scripts/generate-' \
    || true)

if [[ -z "$SIGNIFICANT_CHANGED" ]]; then
    echo "✓ PR sadece doc/cosmetic dosyalari etkiliyor — CHANGELOG guncellenmesi gerekmez."
    echo "Degisen dosyalar:"
    echo "$CHANGED_FILES" | sed 's/^/   /'
    exit 0
fi

# CHANGELOG.md degisikliklerini incele
if ! echo "$CHANGED_FILES" | grep -q '^CHANGELOG\.md$'; then
    cat >&2 <<EOF
✗ CHANGELOG.md kontrolu FAILED.

PR su 'significant' dosyalari degistiriyor:
$(echo "$SIGNIFICANT_CHANGED" | sed 's/^/   /')

Ancak CHANGELOG.md guncellenmedi. Lutfen [Unreleased] bolumune
degisikligi yansitan bir giris ekleyin (Keep a Changelog 1.0.0 format).

Bypass etmek icin (sadece trivial degisiklikler icin):
  - Commit message'a '[skip changelog]' ekleyin, veya
  - PR title'ina '[skip changelog]' ekleyin.

Format ornegi:

  ## [Unreleased]

  ### Added
  - Yeni XAdES-T desteği eklendi (#42).

  ### Fixed
  - PKCS#11 oturum havuzu sızıntısı düzeltildi (#43).
EOF
    exit 1
fi

# CHANGELOG.md degismis ama [Unreleased] bolumune mi eklendi?
# diff'i kontrol et — Unreleased icinde + satiri var mi?
UNRELEASED_DIFF=$(git diff "${BASE_REF}..${HEAD_REF}" -- CHANGELOG.md | awk '
    /^@@/      { in_hunk = 1; in_unreleased_zone = 0; next }
    /^[+\-] ## \[Unreleased\]/ { in_unreleased_zone = 1; next }
    /^[+\-] ## \[/             { in_unreleased_zone = 0 }
    in_unreleased_zone && /^[+][^+]/ { print; found = 1 }
    END { exit (found ? 0 : 1) }
' || true)

if [[ -z "$UNRELEASED_DIFF" ]]; then
    cat >&2 <<EOF
✗ CHANGELOG.md degisti ama [Unreleased] bolumune yeni satir eklenmemis gibi gorunuyor.

Eger sadece bir sonraki release icin notlari yaziyorsaniz, [Unreleased]
header'ı altına ekleme yapın. Eğer eski sürüm satırlarını düzelttiyseniz
ve bilinçliyse '[skip changelog]' ile bypass edin.
EOF
    exit 1
fi

echo "✓ CHANGELOG.md [Unreleased] bolumu guncellenmiş — kontrol passed."
echo ""
echo "Eklenen satirlar:"
echo "$UNRELEASED_DIFF" | sed 's/^/   /'
exit 0
