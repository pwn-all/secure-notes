#!/usr/bin/env bash
set -euo pipefail

# Mode 1: existing cert files
if [[ -f "${TLS_CERT_PATH:-}" && -f "${TLS_KEY_PATH:-}" ]]; then
  exec ./secure_notes
fi

# Mode 2: auto-obtain via Let's Encrypt
DOMAIN="${DOMAIN:-}"
EMAIL="${EMAIL:-}"

if [[ -z "$DOMAIN" || -z "$EMAIL" ]]; then
  echo "ERROR: provide either:"
  echo "  -e TLS_CERT_PATH=... -e TLS_KEY_PATH=...  (existing certificate)"
  echo "  -e DOMAIN=example.com -e EMAIL=admin@example.com  (auto Let's Encrypt)"
  exit 1
fi

STAGING_FLAG=""
[[ "${LETSENCRYPT_STAGING:-0}" == "1" ]] && STAGING_FLAG="--staging"

certbot certonly \
  --standalone \
  --non-interactive \
  --agree-tos \
  --keep-until-expiring \
  --email "$EMAIL" \
  -d "$DOMAIN" \
  $STAGING_FLAG

export TLS_CERT_PATH="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
export TLS_KEY_PATH="/etc/letsencrypt/live/${DOMAIN}/privkey.pem"

exec ./secure_notes
