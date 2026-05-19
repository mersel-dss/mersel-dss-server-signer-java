#!/usr/bin/env bash
# =============================================================================
#  uninstall.sh — Mersel DSS Signer SystemD servisini sistemden kaldır.
# =============================================================================
#  Kullanım:
#    sudo ./uninstall.sh                  # servis + JAR + unit kaldır
#    sudo ./uninstall.sh --purge          # YUKARI + env dosyası + log + user
#
#  Default davranış (purge YOK):
#    - Servisi durdurur ve disable eder
#    - JAR ve unit dosyasını siler
#    - /etc/mersel-dss-signer ve loglar KORUNUR (operatörün veri kaybı yaşamaması için)
#    - signer kullanıcısı KORUNUR
#
#  --purge ile EK olarak:
#    - /etc/mersel-dss-signer (env + cert) silinir
#    - /var/log/mersel-dss-signer silinir
#    - signer kullanıcısı silinir
# =============================================================================

set -euo pipefail

die() { printf '\033[31m✗\033[0m %s\n' "$*" >&2; exit 1; }
info() { printf '\033[36m›\033[0m %s\n' "$*"; }
ok() { printf '\033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '\033[33m⚠\033[0m %s\n' "$*"; }

readonly SERVICE_NAME="mersel-dss-signer"
readonly SERVICE_USER="signer"
readonly INSTALL_DIR="/opt/${SERVICE_NAME}"
readonly CONFIG_DIR="/etc/${SERVICE_NAME}"
readonly LOG_DIR="/var/log/${SERVICE_NAME}"
readonly UNIT_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

PURGE=false
if [[ "${1:-}" == "--purge" ]]; then
  PURGE=true
fi

if [[ $EUID -ne 0 ]]; then
  die "Bu script root yetkisi ister: sudo ./uninstall.sh"
fi

# ───────────────────────────────────────── servisi durdur + disable
if systemctl list-unit-files --no-legend | grep -q "^${SERVICE_NAME}.service"; then
  if systemctl is-active --quiet "${SERVICE_NAME}"; then
    systemctl stop "${SERVICE_NAME}"
    ok "Servis durduruldu"
  fi
  if systemctl is-enabled --quiet "${SERVICE_NAME}" 2>/dev/null; then
    systemctl disable "${SERVICE_NAME}"
    ok "Servis disable edildi"
  fi
fi

# ───────────────────────────────────────── unit dosyasını sil
if [[ -f "${UNIT_FILE}" ]]; then
  rm -f "${UNIT_FILE}"
  ok "Unit silindi: ${UNIT_FILE}"
fi
systemctl daemon-reload

# ───────────────────────────────────────── JAR ve install dizini
if [[ -d "${INSTALL_DIR}" ]]; then
  rm -rf "${INSTALL_DIR}"
  ok "Install dizini silindi: ${INSTALL_DIR}"
fi

# ───────────────────────────────────────── purge modu
if [[ "${PURGE}" == true ]]; then
  if [[ -d "${CONFIG_DIR}" ]]; then
    rm -rf "${CONFIG_DIR}"
    ok "Config dizini silindi: ${CONFIG_DIR}"
  fi
  if [[ -d "${LOG_DIR}" ]]; then
    rm -rf "${LOG_DIR}"
    ok "Log dizini silindi: ${LOG_DIR}"
  fi
  if id -u "${SERVICE_USER}" >/dev/null 2>&1; then
    userdel "${SERVICE_USER}" 2>/dev/null || true
    ok "Kullanıcı silindi: ${SERVICE_USER}"
  fi
else
  warn "Config (${CONFIG_DIR}) ve loglar (${LOG_DIR}) KORUNDU."
  warn "Komple temizlik için: sudo ./uninstall.sh --purge"
fi

ok "Tamamlandı."
