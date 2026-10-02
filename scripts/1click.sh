#!/usr/bin/env bash
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${ENV_FILE:-${REPO_ROOT}/.env}"

DOMAIN="${1:-}"
EMAIL="${2:-}"

if [[ -z "${DOMAIN}" || -z "${EMAIL}" ]]; then
  echo "Usage: $0 <domain> <email>"
  exit 1
fi

if [[ ! "${DOMAIN}" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ || "${DOMAIN}" == *..* || ${#DOMAIN} -gt 253 ]]; then
  echo "Invalid certificate hostname."
  exit 1
fi
if [[ -L "${ENV_FILE}" ]]; then
  echo "Refusing to replace a symlink used as ENV_FILE."
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
  local key="$1" val="$2" line found=0 temporary
  temporary="$(mktemp "${ENV_FILE}.XXXXXX")"
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" == "${key}="* ]]; then
      printf '%s=%s\n' "$key" "$val"
      found=1
    else
      printf '%s\n' "$line"
    fi
  done < "${ENV_FILE}" > "$temporary"
  if [[ "$found" == 0 ]]; then printf '%s=%s\n' "$key" "$val" >> "$temporary"; fi
  chmod 600 "$temporary"
  mv "$temporary" "${ENV_FILE}"
}

set_env_var "TLS_CERT_PATH" "${CERT_PATH}"
set_env_var "TLS_KEY_PATH"  "${KEY_PATH}"
set_env_var "PUBLIC_HOST" "${DOMAIN}"

echo ".env updated → ${ENV_FILE}"
if [[ "${EUID}" == 0 ]]; then
  echo "The .env file remains root-owned with mode 0600."
  echo "Configure a dedicated service to load it and read the TLS key; an ordinary user cannot use these files directly."
fi
echo "Configure certificate renewal and a successful TLS reload before exposing the service publicly."
