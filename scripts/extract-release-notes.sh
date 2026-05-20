#!/usr/bin/env bash
#
# extract-release-notes.sh
# =============================================================================
# CHANGELOG.md dosyasından belirli bir sürümün notlarını çıkartır.
#
# Kullanım:
#   ./scripts/extract-release-notes.sh <VERSION> [CHANGELOG_PATH]
#
# Örnek:
#   ./scripts/extract-release-notes.sh 0.4.0
#   ./scripts/extract-release-notes.sh 0.4.0 CHANGELOG.md > notes.md
#
# Sürüm string'i `0.4.0` veya `v0.4.0` olabilir; baştaki `v` otomatik atılır.
#
# CHANGELOG formatı (Keep a Changelog 1.0.0):
#   ## [Unreleased]
#   ...
#   ## [0.4.0] - 2025-05-18
#   ### Added
#   - ...
#   ## [0.3.0] - 2025-04-12
#   ...
#
# Script ilgili `## [VERSION]` başlığı ile bir sonraki `## [` başlığı arasındaki
# satırları stdout'a basar. Başlık satırını çıktıya dahil etmez (release body
# üst kısmında zaten görünür).
#
# Exit kodları:
#   0 → bulundu ve stdout'a basıldı
#   1 → kullanım hatası (eksik argüman vb.)
#   2 → CHANGELOG dosyası bulunamadı
#   3 → istenen sürüm CHANGELOG'da yok
#   4 → çıkartılan içerik boş (formatta sorun olabilir)
#
# Bu script GitHub Actions release workflow'unda da kullanılır; oraya stdin/
# stdout köprüsü ile takılır.
# -----------------------------------------------------------------------------

set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "Kullanım: $0 <VERSION> [CHANGELOG_PATH]" >&2
    echo "Örnek:    $0 0.4.0" >&2
    exit 1
fi

VERSION="${1#v}"
CHANGELOG_PATH="${2:-CHANGELOG.md}"

if [[ ! -f "$CHANGELOG_PATH" ]]; then
    echo "HATA: CHANGELOG dosyası bulunamadı: $CHANGELOG_PATH" >&2
    exit 2
fi

# awk ile state-machine: hedef header'a girdiğimizde kayıt başlatır,
# bir sonraki '## [...' header'ı görünce durur.
#
# Header pattern'i: '## [VERSION]' literal match. Köşeli parantez içeriği regex
# special olmasın diye literal karşılaştırma yapıyoruz.
EXTRACTED=$(awk -v ver="$VERSION" '
    BEGIN {
        target = "## [" ver "]"
        in_section = 0
    }
    {
        # Hedef başlığa ilk kez denk gelirsek kayıt başlat (başlığı atla)
        if (in_section == 0 && index($0, target) == 1) {
            in_section = 1
            next
        }
        # Section içindeyken yeni "## [" görürsek bittik
        if (in_section == 1 && /^## \[/) {
            exit
        }
        if (in_section == 1) {
            print
        }
    }
' "$CHANGELOG_PATH")

if [[ -z "$EXTRACTED" ]]; then
    # Header tamamen yok mu yoksa boş mu — ayırt et
    if ! grep -qF "## [$VERSION]" "$CHANGELOG_PATH"; then
        echo "HATA: CHANGELOG.md içinde '## [$VERSION]' başlığı bulunamadı." >&2
        echo "      Önce CHANGELOG.md'deki [Unreleased] bölümünü '[${VERSION}] - YYYY-MM-DD' olarak finalize edin." >&2
        exit 3
    fi
    echo "HATA: '## [$VERSION]' başlığı bulundu ama altındaki içerik boş." >&2
    exit 4
fi

# Baştaki ve sondaki boş satırları sıkıştır (release body daha temiz olsun)
echo "$EXTRACTED" | awk '
    BEGIN { started = 0; blank = 0 }
    {
        if ($0 ~ /^[[:space:]]*$/) {
            if (started) blank = 1
            next
        }
        if (blank && started) print ""
        print
        started = 1
        blank = 0
    }
'
