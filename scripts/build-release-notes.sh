#!/usr/bin/env bash
#
# build-release-notes.sh
# =============================================================================
# CHANGELOG'tan ilgili sürümün notlarını çıkartıp altına "Build Provenance"
# tablosunu ekler. Release workflow'unun GitHub Release body'si olarak
# kullanılır.
#
# Kullanım:
#   ./scripts/build-release-notes.sh <VERSION> [OUTPUT_PATH]
#
# Environment variable'lar (release workflow'undan set edilir):
#   TAG               (örn. v0.5.0)
#   COMMIT_SHA        (github.sha)
#   COMMIT_URL        (github.server_url/github.repository/commit/SHA)
#   BUILD_TIME        (ISO-8601 UTC)
#   BUILD_NUMBER      (CI run number)
#   BUILD_RUN_ID      (CI run ID)
#   BUILD_RUN_URL     (CI run HTML URL)
#   JAVA_VERSION      (örn. 8)
#   JAVA_DIST         (örn. temurin)
#   RUNNER_LABEL      (örn. ubuntu-latest)
#   ARTIFACT_NAME     (örn. mersel-dss-signer-api-0.5.0.jar)
#
# Eksik env'ler "n/a" olarak doldurulur (lokal test için).
# -----------------------------------------------------------------------------

set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "Kullanım: $0 <VERSION> [OUTPUT_PATH]" >&2
    exit 1
fi

VERSION="${1#v}"
OUTPUT_PATH="${2:-target/RELEASE_NOTES.md}"

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

mkdir -p "$(dirname "$OUTPUT_PATH")"

# 1. CHANGELOG bölümünü çıkar
"${SCRIPT_DIR}/extract-release-notes.sh" "$VERSION" CHANGELOG.md > "$OUTPUT_PATH"

# 2. Build provenance footer ekle.
# Env default'ları
TAG="${TAG:-v${VERSION}}"
COMMIT_SHA="${COMMIT_SHA:-n/a}"
COMMIT_URL="${COMMIT_URL:-#}"
BUILD_TIME="${BUILD_TIME:-n/a}"
BUILD_NUMBER="${BUILD_NUMBER:-n/a}"
BUILD_RUN_ID="${BUILD_RUN_ID:-n/a}"
BUILD_RUN_URL="${BUILD_RUN_URL:-#}"
JAVA_VERSION="${JAVA_VERSION:-8}"
JAVA_DIST="${JAVA_DIST:-temurin}"
RUNNER_LABEL="${RUNNER_LABEL:-ubuntu-latest}"
ARTIFACT_NAME="${ARTIFACT_NAME:-mersel-dss-signer-api-${VERSION}.jar}"

# Short SHA (ilk 7 karakter)
SHORT_SHA="${COMMIT_SHA:0:7}"

cat >> "$OUTPUT_PATH" <<EOF

***

## Build Provenance

| Alan | Değer |
|---|---|
| Tag | \`${TAG}\` |
| Commit | [\`${SHORT_SHA}\`](${COMMIT_URL}) |
| Build Time (UTC) | \`${BUILD_TIME}\` |
| Build Number | \`${BUILD_NUMBER}\` (workflow run [\`${BUILD_RUN_ID}\`](${BUILD_RUN_URL})) |
| JDK | \`${JAVA_VERSION} (${JAVA_DIST})\` |
| Runner | \`${RUNNER_LABEL}\` |

### Artifact'ler

| Dosya | Açıklama |
|---|---|
| \`${ARTIFACT_NAME}\` | Spring Boot executable fat JAR |
| \`${ARTIFACT_NAME}.sha256\` | SHA-256 checksum (immutability anchor) |
| \`mersel-dss-signer-api-${VERSION}-sources.jar\` | Kaynak kod JAR'ı |
| \`mersel-dss-signer-api-${VERSION}-sbom.json\` | CycloneDX SBOM (JSON) |
| \`mersel-dss-signer-api-${VERSION}-sbom.xml\` | CycloneDX SBOM (XML) |

### Runtime Doğrulama

Bu sürümün hangi commit'ten geldiğini production'da çalışan instance
üzerinde doğrulamak için:

\`\`\`bash
curl -s http://<host>:8085/actuator/info | jq .build
\`\`\`

Çıktıda \`revision: "${COMMIT_SHA}"\` görmelisiniz.

### SHA-256 Checksum Doğrulama

\`\`\`bash
gh release download ${TAG} -p '*.jar' -p '*.jar.sha256'
sha256sum -c ${ARTIFACT_NAME}.sha256
\`\`\`

### SBOM (Software Bill of Materials)

CycloneDX 1.5 spec'ine uygun JSON/XML formatında her bağımlılığın
group/name/version/license/PURL bilgisini içerir. OWASP
Dependency-Track veya \`cyclonedx-cli\` ile CVE tarama yapılabilir.
EOF

echo "Release notes yazıldı: $OUTPUT_PATH"
echo ""
echo "=== Preview (ilk 30 satır) ==="
head -30 "$OUTPUT_PATH"
