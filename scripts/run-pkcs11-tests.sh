#!/usr/bin/env bash
#
# pkcs11-integration test'lerini izole Docker container'da koşturur.
#
# Avantaj: host'a softhsm2 / opensc / JDK kurma derdi yok. macOS (Intel/Apple
# Silicon), Linux ve Windows (Docker Desktop / WSL2) arasında bit-for-bit
# aynı ortam. CI workflow'undaki Ubuntu runner ile de aynı tooling.
#
# Kullanım:
#   ./scripts/run-pkcs11-tests.sh                                           # default: tüm pkcs11-integration
#   ./scripts/run-pkcs11-tests.sh test -B -DexcludedGroups= -Dtest=SoftHsm2Pkcs11IntegrationTest
#   ./scripts/run-pkcs11-tests.sh test -B -Dgroups=verifier-e2e -DexcludedGroups=
#
# Kısa yol: Eğer geçilen ilk argüman tireyle başlıyorsa (örn. -Dtest=...,
# -DexcludedGroups=) script otomatik olarak başına "test -B" ekler. Bu sayede
# kullanıcı küçük override'ları rahatça geçebilir:
#   ./scripts/run-pkcs11-tests.sh -Dtest=SoftHsm2Pkcs11IntegrationTest
#
# İlk argüman bir Maven goal/phase ise (örn. "verify", "test", "clean test")
# olduğu gibi mvn'e iletilir.
#
# Argüman geçilmezse image'in CMD'si geçerli (Dockerfile'da pkcs11-integration tag'i).
#
# Ön koşullar:
#   - Docker daemon erişilebilir (`docker info` çalışıyor olmalı)
#   - İlk koşumda ~600MB image build edilir (maven + jdk + softhsm); sonra cached
#
# Çıkış kodu: container içindeki mvn exit code'unun aynısı.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

IMAGE_TAG="${PKCS11_TEST_IMAGE:-mersel/dss-signer-pkcs11-tests:latest}"
DOCKERFILE="$PROJECT_ROOT/devops/docker/Dockerfile.pkcs11-tests"
DOCKER_CONTEXT="$PROJECT_ROOT/devops/docker"

# Maven local repo cache — host'ta varsa reuse; yoksa script ad-hoc yaratır.
# Reuse sayesinde dependency'ler her koşumda yeniden indirilmez.
M2_CACHE="${M2_CACHE:-${HOME}/.m2}"
mkdir -p "$M2_CACHE"

# ---------------------------------------------------------- pre-flight checks
if ! command -v docker >/dev/null 2>&1; then
    echo "✗ docker bulunamadı. Docker Desktop veya engine kurulu olmalı." >&2
    exit 1
fi
if ! docker info >/dev/null 2>&1; then
    echo "✗ Docker daemon erişilemiyor (docker info başarısız)." >&2
    echo "  Docker Desktop'ı başlatın veya docker servisinin çalıştığından emin olun." >&2
    exit 1
fi

# ------------------------------------------------------------- image build
# Idempotent: layer cache var ise BuildKit hızlı geçer (~saniyeler).
echo "→ Test image hazırlanıyor: $IMAGE_TAG"
DOCKER_BUILDKIT=1 docker build \
    --tag "$IMAGE_TAG" \
    --file "$DOCKERFILE" \
    "$DOCKER_CONTEXT"

# ---------------------------------------------------------- docker run args
#
# Network mantığı: Testcontainers, build container'ın *İÇİNDEN* yeni child
# container'lar başlatır (verifier-api, vb.). Host Docker daemon'ı socket
# üzerinden paylaşıldığından child container'lar host network namespace'inde
# doğar; bunlara test JVM'inden erişmek için host DNS gerek:
#   - macOS / Windows Docker Desktop'ta host.docker.internal otomatik resolve
#   - Linux'ta --add-host=host.docker.internal:host-gateway ile manuel resolve
# Ryuk (Testcontainers'ın cleanup container'ı) DinD/sibling setup'ta bazen
# privileged ister; CI veya kısıtlı ortamda devre dışı bırakılabilir:
#   TESTCONTAINERS_RYUK_DISABLED=true ./scripts/run-pkcs11-tests.sh
#
# Argüman geçildiyse onlar mvn'e iletilir; geçilmezse Dockerfile CMD geçerli
# (pkcs11-integration tag'i).
DOCKER_ARGS=(
    --rm
    --interactive
    --volume "$PROJECT_ROOT:/work"
    --volume "$M2_CACHE:/root/.m2"
    --volume /var/run/docker.sock:/var/run/docker.sock
    --workdir /work
    --env "TESTCONTAINERS_HOST_OVERRIDE=${TESTCONTAINERS_HOST_OVERRIDE:-host.docker.internal}"
    --env "TESTCONTAINERS_RYUK_DISABLED=${TESTCONTAINERS_RYUK_DISABLED:-false}"
    --add-host "host.docker.internal:host-gateway"
)

# tty yalnızca interaktif terminalde — CI'da yok, IDE'den çağrıda var.
if [ -t 1 ]; then
    DOCKER_ARGS+=(--tty)
fi

echo "→ pkcs11-integration test'leri container içinde koşturuluyor..."
echo ""

if [ "$#" -gt 0 ]; then
    # User override: ilk argüman tireyle başlıyorsa (property-only kullanım)
    # mvn'in geçerli bir goal'e ihtiyacı var → "test -B" ekleyip diğerlerini geç.
    # Aksi halde kullanıcı goal verdiyse (örn. "verify -DskipTests=false")
    # olduğu gibi geç.
    if [[ "$1" == -* ]]; then
        exec docker run "${DOCKER_ARGS[@]}" "$IMAGE_TAG" test -B "$@"
    else
        exec docker run "${DOCKER_ARGS[@]}" "$IMAGE_TAG" "$@"
    fi
else
    # Default: Dockerfile CMD (pkcs11-integration tag'i).
    exec docker run "${DOCKER_ARGS[@]}" "$IMAGE_TAG"
fi
