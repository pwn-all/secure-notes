#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${ENV_FILE:-${REPO_ROOT}/.env}"

DOMAIN="${1:-}"
EMAIL="${2:-}"

if [[ -z "${DOMAIN}" || -z "${EMAIL}" ]]; then
  echo "Usage: $0 <domain> <email>"
  exit 1
fi

LETSENCRYPT_DIR="${LETSENCRYPT_DIR:-/etc/letsencrypt/live}"
CERT_PATH="${LETSENCRYPT_DIR}/${DOMAIN}/fullchain.pem"
KEY_PATH="${LETSENCRYPT_DIR}/${DOMAIN}/privkey.pem"

# ---------------------------------------------------------------------------
# Obtain certificate if not present
# ---------------------------------------------------------------------------
if [[ -f "${CERT_PATH}" && -f "${KEY_PATH}" ]]; then
  echo "Certificate already exists:"
  echo "  cert: ${CERT_PATH}"
  echo "  key : ${KEY_PATH}"
else
  if ! command -v certbot >/dev/null 2>&1; then
    echo "certbot is required but was not found in PATH."
    exit 1
  fi

  if [[ "${EUID}" -ne 0 ]]; then
    echo "Run as root (or via sudo) to bind :80 and write /etc/letsencrypt."
    exit 1
  fi

  cmd=(
    certbot certonly
    --standalone
    --preferred-challenges http
    --non-interactive
    --agree-tos
    --keep-until-expiring
    --email "${EMAIL}"
    -d "${DOMAIN}"
  )

  [[ "${LETSENCRYPT_STAGING:-0}" == "1" ]] && cmd+=(--staging)

  "${cmd[@]}"

  echo "Certificate ready:"
  echo "  cert: ${CERT_PATH}"
  echo "  key : ${KEY_PATH}"
fi

# ---------------------------------------------------------------------------
# Write TLS paths into .env
# ---------------------------------------------------------------------------
if [[ ! -f "${ENV_FILE}" ]]; then
  cp "${REPO_ROOT}/.env.example" "${ENV_FILE}"
fi

set_env_var() {
  local key="$1" val="$2"
  if grep -q "^${key}=" "${ENV_FILE}"; then
    sed -i.bak "s|^${key}=.*|${key}=${val}|" "${ENV_FILE}"
    rm -f "${ENV_FILE}.bak"
  else
    printf '%s=%s\n' "${key}" "${val}" >> "${ENV_FILE}"
  fi
}

set_env_var "TLS_CERT_PATH" "${CERT_PATH}"
set_env_var "TLS_KEY_PATH"  "${KEY_PATH}"

echo ".env updated → ${ENV_FILE}"
