#!/usr/bin/env bash
# =============================================================================
#  install.sh — Mersel DSS Signer'ı Linux'a SystemD servisi olarak kur.
# =============================================================================
#  Yaptığı:
#    1) signer kullanıcısını oluşturur (varsa atlanır)
#    2) Dizin yapısını kurar: /opt, /etc, /var/log
#    3) JAR dosyasını /opt/mersel-dss-signer/ altına kopyalar
#    4) Unit + env şablonunu doğru yerlere kopyalar (env dosyası varsa
#       ÜZERİNE YAZILMAZ — operatörün düzenlemeleri korunur)
#    5) systemctl daemon-reload + enable + start
#
#  Kullanım:
#    sudo ./install.sh [JAR_PATH]
#
#    JAR_PATH verilmezse target/mersel-dss-signer-api-*.jar otomatik
#    aranır (script'in proje kökünden çalıştırıldığı varsayılır).
#
#  Idempotent — birden çok kez çalıştırılabilir; servis çalışıyorsa restart edilir.
# =============================================================================

set -euo pipefail

# ───────────────────────────────────────── helpers
die() { printf '\033[31m✗\033[0m %s\n' "$*" >&2; exit 1; }
info() { printf '\033[36m›\033[0m %s\n' "$*"; }
ok() { printf '\033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '\033[33m⚠\033[0m %s\n' "$*"; }

# ───────────────────────────────────────── sabitler
readonly SERVICE_NAME="mersel-dss-signer"
readonly SERVICE_USER="signer"
readonly INSTALL_DIR="/opt/${SERVICE_NAME}"
readonly CONFIG_DIR="/etc/${SERVICE_NAME}"
readonly LOG_DIR="/var/log/${SERVICE_NAME}"
readonly UNIT_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
readonly ENV_FILE="${CONFIG_DIR}/${SERVICE_NAME}.env"

# Script'in bulunduğu dizin (devops/systemd/)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Repo kökü (devops/systemd/../../)
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# ───────────────────────────────────────── root kontrolü
if [[ $EUID -ne 0 ]]; then
  die "Bu script root yetkisi ister: sudo ./install.sh"
fi

# ───────────────────────────────────────── JAR yolu
if [[ $# -ge 1 ]]; then
  JAR_SRC="$1"
else
  # target/ altında ilk eşleşeni al — birden fazla varsa en yeniyi
  JAR_SRC="$(ls -t "${REPO_ROOT}/target/${SERVICE_NAME}-api-"*.jar 2>/dev/null | head -n1 || true)"
fi

if [[ -z "${JAR_SRC:-}" || ! -f "${JAR_SRC}" ]]; then
  die "JAR bulunamadı. Önce 'mvn clean package -DskipTests' çalıştır veya
       sudo ./install.sh /tam/yol/mersel-dss-signer-api-X.Y.Z.jar geçir."
fi

info "JAR kaynağı : ${JAR_SRC}"

# ───────────────────────────────────────── kullanıcı oluştur
if id -u "${SERVICE_USER}" >/dev/null 2>&1; then
  info "Kullanıcı '${SERVICE_USER}' zaten var, atlanıyor."
else
  useradd --system --no-create-home \
          --home-dir "${INSTALL_DIR}" \
          --shell /usr/sbin/nologin \
          "${SERVICE_USER}"
  ok "Kullanıcı oluşturuldu: ${SERVICE_USER}"
fi

# ───────────────────────────────────────── dizinler
install -d -o "${SERVICE_USER}" -g "${SERVICE_USER}" -m 0755 "${INSTALL_DIR}"
install -d -o "${SERVICE_USER}" -g "${SERVICE_USER}" -m 0755 "${INSTALL_DIR}/logs"
install -d -o "${SERVICE_USER}" -g "${SERVICE_USER}" -m 0755 "${INSTALL_DIR}/work"
install -d -o "${SERVICE_USER}" -g "${SERVICE_USER}" -m 0755 "${LOG_DIR}"
# /etc/mersel-dss-signer — env dosyası root tarafından düzenlenir, servis okur
install -d -o root -g "${SERVICE_USER}" -m 0750 "${CONFIG_DIR}"
install -d -o root -g "${SERVICE_USER}" -m 0750 "${CONFIG_DIR}/certs"

ok "Dizinler hazırlandı"

# ───────────────────────────────────────── JAR'ı kopyala
install -o "${SERVICE_USER}" -g "${SERVICE_USER}" -m 0644 \
        "${JAR_SRC}" "${INSTALL_DIR}/${SERVICE_NAME}-api.jar"
ok "JAR yerleştirildi → ${INSTALL_DIR}/${SERVICE_NAME}-api.jar"

# ───────────────────────────────────────── unit dosyası
install -o root -g root -m 0644 \
        "${SCRIPT_DIR}/${SERVICE_NAME}.service" "${UNIT_FILE}"
ok "Unit yerleştirildi → ${UNIT_FILE}"

# ───────────────────────────────────────── env dosyası (varsa KORU)
if [[ -f "${ENV_FILE}" ]]; then
  warn "Env dosyası zaten var, üzerine yazılmadı: ${ENV_FILE}"
  warn "Şablonu görmek için: cat ${SCRIPT_DIR}/${SERVICE_NAME}.env.example"
else
  install -o root -g "${SERVICE_USER}" -m 0640 \
          "${SCRIPT_DIR}/${SERVICE_NAME}.env.example" "${ENV_FILE}"
  ok "Env şablonu yerleştirildi → ${ENV_FILE}"
  warn "Servisi başlatmadan ÖNCE ${ENV_FILE} dosyasını düzenle:
       - CERTIFICATE_PIN
       - PFX_PATH veya PKCS11_LIBRARY
       - TS_USER_ID / TS_USER_PASSWORD (TÜBİTAK kullanıyorsan)"
fi

# ───────────────────────────────────────── systemd
systemctl daemon-reload
ok "systemctl daemon-reload"

if systemctl is-enabled --quiet "${SERVICE_NAME}"; then
  info "Servis zaten enabled — restart ediliyor"
  systemctl restart "${SERVICE_NAME}"
else
  systemctl enable "${SERVICE_NAME}"
  ok "Servis enabled (boot'ta otomatik başlar)"
  if [[ ! -f "${ENV_FILE}" ]] || ! grep -q '^CERTIFICATE_PIN=[^_]' "${ENV_FILE}" 2>/dev/null; then
    warn "Env dosyasında CERTIFICATE_PIN doldurulmamış görünüyor."
    warn "Düzenledikten sonra: sudo systemctl start ${SERVICE_NAME}"
  else
    systemctl start "${SERVICE_NAME}"
    ok "Servis başlatıldı"
  fi
fi

# ───────────────────────────────────────── son durum
echo
systemctl status "${SERVICE_NAME}" --no-pager --lines=10 || true
echo
info "Logları izle      : sudo journalctl -u ${SERVICE_NAME} -f"
info "Yeniden başlat    : sudo systemctl restart ${SERVICE_NAME}"
info "Durdur            : sudo systemctl stop ${SERVICE_NAME}"
info "Health kontrolü   : curl http://localhost:8085/actuator/health"
