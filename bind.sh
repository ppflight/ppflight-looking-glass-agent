#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="${PPFLIGHT_LG_APP_DIR:-/opt/ppflight-looking-glass}"
CONFIG_FILE="${PPFLIGHT_LG_CONFIG:-/etc/ppflight-looking-glass/config.json}"
STATE_FILE="/var/lib/ppflight-looking-glass/state.json"
SERVICE_NAME="ppflight-looking-glass.service"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this script as root so the token can be written for the service user." >&2
  exit 1
fi

if [[ ! -f "${CONFIG_FILE}" ]]; then
  echo "Missing configuration: ${CONFIG_FILE}" >&2
  exit 1
fi

if [[ ! -x "${APP_DIR}/python3" || ! -f "${APP_DIR}/agent.py" ]]; then
  echo "Agent is not installed. Run install.sh first." >&2
  exit 1
fi

if [[ -t 0 ]]; then
  read -r -s -p "One-time binding code from PPFlight ADMIN: " BINDING_CODE
  echo
else
  IFS= read -r BINDING_CODE
fi

if [[ -z "${BINDING_CODE}" ]]; then
  echo "Binding code must not be empty." >&2
  exit 1
fi

install -d -m 0750 -o ppflight-lg -g ppflight-lg "$(dirname "${STATE_FILE}")"
printf '%s\n' "${BINDING_CODE}" | runuser -u ppflight-lg -- \
  "${APP_DIR}/python3" "${APP_DIR}/agent.py" --config "${CONFIG_FILE}" bind --code-stdin
unset BINDING_CODE

chmod 0600 "${STATE_FILE}"
chown ppflight-lg:ppflight-lg "${STATE_FILE}"
systemctl enable "${SERVICE_NAME}"
systemctl restart "${SERVICE_NAME}"
echo "PPFlight Looking Glass agent is bound and running."
