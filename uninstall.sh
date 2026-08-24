#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="/opt/ppflight-looking-glass"
CONFIG_DIR="/etc/ppflight-looking-glass"
STATE_DIR="/var/lib/ppflight-looking-glass"
UNIT_FILE="/etc/systemd/system/ppflight-looking-glass.service"
SERVICE_NAME="ppflight-looking-glass.service"
SERVICE_USER="ppflight-lg"
PURGE=0

if [[ "${1:-}" == "--purge" ]]; then
  PURGE=1
elif [[ $# -gt 0 ]]; then
  echo "Usage: sudo ./uninstall.sh [--purge]" >&2
  exit 2
fi

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run uninstall.sh as root." >&2
  exit 1
fi

systemctl disable --now "${SERVICE_NAME}" >/dev/null 2>&1 || true
rm -f -- "${UNIT_FILE}"
systemctl daemon-reload

rm -f -- \
  "${APP_DIR}/agent.py" \
  "${APP_DIR}/ag.py" \
  "${APP_DIR}/bind.sh" \
  "${APP_DIR}/uninstall.sh" \
  "${APP_DIR}/config.example.json" \
  "${APP_DIR}/python3"
if [[ -f /usr/local/bin/ag ]] && \
   grep -Fq 'PPFLIGHT_LOOKING_GLASS_AG_WRAPPER=1' /usr/local/bin/ag; then
  rm -f -- "/usr/local/bin/ag"
fi
rmdir -- "${APP_DIR}" 2>/dev/null || true

if [[ "${PURGE}" -eq 1 ]]; then
  rm -f -- "${CONFIG_DIR}/config.json" "${STATE_DIR}/state.json"
  rmdir -- "${CONFIG_DIR}" "${STATE_DIR}" 2>/dev/null || true
  userdel "${SERVICE_USER}" >/dev/null 2>&1 || true
  echo "Agent, local configuration and token state were removed."
else
  echo "Agent removed. Configuration and token state were retained."
  echo "Use --purge to remove them permanently."
fi
