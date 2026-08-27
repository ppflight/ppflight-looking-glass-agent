#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="/opt/ppflight-looking-glass"
CONFIG_DIR="/etc/ppflight-looking-glass"
STATE_DIR="/var/lib/ppflight-looking-glass"
UNIT_FILE="/etc/systemd/system/ppflight-looking-glass.service"
SERVICE_NAME="ppflight-looking-glass.service"
SERVICE_USER="ppflight-lg"
SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
BIND_CODE_FILE=""
NON_INTERACTIVE=0
ROLLBACK_DIR=""
ROLLBACK_ARMED=0
CREATED_USER=0
WAS_ACTIVE=0
declare -a CREATED_FILES=()
declare -a BACKED_UP_FILES=()
declare -a CREATED_DIRS=()

usage() {
  cat <<'EOF'
Usage: sudo ./install.sh [--bind-code-file FILE] [--non-interactive]

  --bind-code-file FILE  Read a one-time ADMIN binding code from FILE without
                         exposing it in shell history or the process list.
  --non-interactive      Install only; do not prompt for a binding code.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bind-code-file)
      [[ $# -ge 2 ]] || { echo "--bind-code-file requires a file" >&2; exit 2; }
      BIND_CODE_FILE="$2"
      shift 2
      ;;
    --non-interactive)
      NON_INTERACTIVE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run install.sh as root." >&2
  exit 1
fi

for required in agent.py ag.py ag-lg bind.sh uninstall.sh config.example.json; do
  [[ -f "${SOURCE_DIR}/${required}" ]] || {
    echo "Installation source is incomplete: ${required}" >&2
    exit 1
  }
done

if [[ -n "${BIND_CODE_FILE}" && ( ! -f "${BIND_CODE_FILE}" || ! -r "${BIND_CODE_FILE}" ) ]]; then
  echo "Binding code file is not readable: ${BIND_CODE_FILE}" >&2
  exit 1
fi

if [[ -e /usr/local/bin/ag-lg || -L /usr/local/bin/ag-lg ]]; then
  if [[ -L /usr/local/bin/ag-lg ]] || \
     ! grep -Fq 'PPFLIGHT_LOOKING_GLASS_AG_WRAPPER=1' /usr/local/bin/ag-lg; then
    echo "/usr/local/bin/ag-lg already exists and is not owned by PPFlight; installation stopped." >&2
    exit 1
  fi
fi

if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
  WAS_ACTIVE=1
fi

ROLLBACK_DIR="$(mktemp -d /var/tmp/ppflight-lg-install.XXXXXX)"

backup_file() {
  local path="$1"
  local backup
  if [[ -e "${path}" || -L "${path}" ]]; then
    backup="${ROLLBACK_DIR}${path}"
    mkdir -p "$(dirname "${backup}")"
    cp -a -- "${path}" "${backup}"
    BACKED_UP_FILES+=("${path}")
  else
    CREATED_FILES+=("${path}")
  fi
}

rollback() {
  local status=$?
  [[ "${ROLLBACK_ARMED}" -eq 1 ]] || exit "${status}"
  trap - ERR EXIT
  echo "Installation failed; restoring the previous agent files." >&2
  systemctl stop "${SERVICE_NAME}" >/dev/null 2>&1 || true
  local path
  for path in "${CREATED_FILES[@]}"; do
    rm -f -- "${path}"
  done
  for path in "${BACKED_UP_FILES[@]}"; do
    rm -f -- "${path}"
    mkdir -p "$(dirname "${path}")"
    cp -a -- "${ROLLBACK_DIR}${path}" "${path}"
  done
  systemctl daemon-reload >/dev/null 2>&1 || true
  if [[ "${WAS_ACTIVE}" -eq 1 ]]; then
    systemctl start "${SERVICE_NAME}" >/dev/null 2>&1 || true
  fi
  if [[ "${CREATED_USER}" -eq 1 ]]; then
    userdel "${SERVICE_USER}" >/dev/null 2>&1 || true
  fi
  for path in "${CREATED_DIRS[@]}"; do
    rmdir -- "${path}" >/dev/null 2>&1 || true
  done
  rm -rf -- "${ROLLBACK_DIR}"
  exit "${status}"
}
trap rollback ERR EXIT
ROLLBACK_ARMED=1

install_packages() {
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y python3 iputils-ping traceroute mtr-tiny ca-certificates
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y python3 iputils traceroute mtr ca-certificates
    if ! python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 9))'; then
      dnf install -y python3.9
    fi
  elif command -v yum >/dev/null 2>&1; then
    yum install -y python3 iputils traceroute mtr ca-certificates
    if ! python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 9))'; then
      yum install -y python39
    fi
  else
    echo "Supported package manager not found (apt, dnf or yum required)." >&2
    return 1
  fi
}

install_packages

PYTHON_BIN=""
for candidate in python3.13 python3.12 python3.11 python3.10 python3.9 python3; do
  if command -v "${candidate}" >/dev/null 2>&1 && \
     "$(command -v "${candidate}")" -c 'import sys; raise SystemExit(sys.version_info < (3, 9))'; then
    PYTHON_BIN="$(command -v "${candidate}")"
    break
  fi
done
[[ -n "${PYTHON_BIN}" ]] || { echo "Python 3.9 or newer is required." >&2; exit 1; }

if ! getent passwd "${SERVICE_USER}" >/dev/null; then
  useradd --system --home-dir "${STATE_DIR}" --shell /usr/sbin/nologin "${SERVICE_USER}"
  CREATED_USER=1
fi

for path in "${APP_DIR}" "${CONFIG_DIR}" "${STATE_DIR}"; do
  [[ -d "${path}" ]] || CREATED_DIRS=("${path}" "${CREATED_DIRS[@]}")
done
install -d -m 0755 -o root -g root "${APP_DIR}"
install -d -m 0750 -o root -g "${SERVICE_USER}" "${CONFIG_DIR}"
install -d -m 0750 -o "${SERVICE_USER}" -g "${SERVICE_USER}" "${STATE_DIR}"

for path in \
  "${APP_DIR}/agent.py" \
  "${APP_DIR}/ag.py" \
  "${APP_DIR}/bind.sh" \
  "${APP_DIR}/uninstall.sh" \
  "${APP_DIR}/config.example.json" \
  "${APP_DIR}/python3" \
  "${CONFIG_DIR}/config.json" \
  "${STATE_DIR}/state.json" \
  "/usr/local/bin/ag-lg" \
  "/usr/local/bin/ag" \
  "${UNIT_FILE}"; do
  backup_file "${path}"
done

install -m 0755 -o root -g root "${SOURCE_DIR}/agent.py" "${APP_DIR}/agent.py"
install -m 0755 -o root -g root "${SOURCE_DIR}/ag.py" "${APP_DIR}/ag.py"
install -m 0755 -o root -g root "${SOURCE_DIR}/ag-lg" "/usr/local/bin/ag-lg"
if [[ -f /usr/local/bin/ag && ! -L /usr/local/bin/ag ]] && \
   grep -Fq 'PPFLIGHT_LOOKING_GLASS_AG_WRAPPER=1' /usr/local/bin/ag; then
  rm -f -- "/usr/local/bin/ag"
fi
install -m 0755 -o root -g root "${SOURCE_DIR}/bind.sh" "${APP_DIR}/bind.sh"
install -m 0755 -o root -g root "${SOURCE_DIR}/uninstall.sh" "${APP_DIR}/uninstall.sh"
install -m 0644 -o root -g root "${SOURCE_DIR}/config.example.json" "${APP_DIR}/config.example.json"
ln -sfn -- "${PYTHON_BIN}" "${APP_DIR}/python3"

if [[ ! -f "${CONFIG_DIR}/config.json" ]]; then
  install -m 0640 -o root -g "${SERVICE_USER}" \
    "${SOURCE_DIR}/config.example.json" "${CONFIG_DIR}/config.json"
else
  chown root:"${SERVICE_USER}" "${CONFIG_DIR}/config.json"
  chmod 0640 "${CONFIG_DIR}/config.json"
fi

cat >"${UNIT_FILE}" <<EOF
[Unit]
Description=PPFlight Looking Glass Agent
Documentation=https://www.ppflight.com/
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
ExecStart=${APP_DIR}/python3 ${APP_DIR}/agent.py --config ${CONFIG_DIR}/config.json run
Restart=on-failure
RestartSec=5s
TimeoutStopSec=20s
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
MemoryDenyWriteExecute=true
CapabilityBoundingSet=CAP_NET_RAW
AmbientCapabilities=CAP_NET_RAW
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
ReadWritePaths=${STATE_DIR}
UMask=0077

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "${UNIT_FILE}"

systemctl daemon-reload
runuser -u "${SERVICE_USER}" -- \
  "${APP_DIR}/python3" "${APP_DIR}/agent.py" --config "${CONFIG_DIR}/config.json" check

if [[ -n "${BIND_CODE_FILE}" ]]; then
  PPFLIGHT_LG_APP_DIR="${APP_DIR}" PPFLIGHT_LG_CONFIG="${CONFIG_DIR}/config.json" \
    "${APP_DIR}/bind.sh" <"${BIND_CODE_FILE}"
elif [[ "${NON_INTERACTIVE}" -eq 0 && -t 0 ]]; then
  echo "Installation complete. Enter the one-time ADMIN code to bind this node."
  PPFLIGHT_LG_APP_DIR="${APP_DIR}" PPFLIGHT_LG_CONFIG="${CONFIG_DIR}/config.json" \
    "${APP_DIR}/bind.sh"
elif [[ -s "${STATE_DIR}/state.json" ]]; then
  systemctl enable --now "${SERVICE_NAME}"
else
  echo "Installed but not started. Run: sudo ${APP_DIR}/bind.sh"
fi

if [[ "${WAS_ACTIVE}" -eq 1 ]]; then
  systemctl restart "${SERVICE_NAME}"
fi

ROLLBACK_ARMED=0
trap - ERR EXIT
rm -rf -- "${ROLLBACK_DIR}"
echo "PPFlight Looking Glass agent installation completed."
