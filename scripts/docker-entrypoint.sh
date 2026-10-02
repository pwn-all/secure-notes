#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly APP_UID=65532 APP_GID=65532 RUNTIME_TLS_DIR=/run/secnote

fail() { echo "ERROR: $*" >&2; exit 1; }

mode="${1:-}"
[[ $# -le 1 && ( -z "$mode" || "$mode" == "--reload-tls" ) ]] || fail "unsupported entrypoint arguments"
current_uid="$(id -u)"

if [[ "$mode" == "--reload-tls" ]]; then
  [[ "$current_uid" == 0 ]] || fail "TLS material refresh requires docker exec --user 0"
  [[ "$(cat /proc/1/comm 2>/dev/null || true)" == secure_notes ]] || fail "PID 1 is not the SecNote server"
fi

DOMAIN="${DOMAIN:-}"
EMAIL="${EMAIL:-}"

if [[ -n "${TLS_CERT_PATH:-}" || -n "${TLS_KEY_PATH:-}" ]]; then
  [[ -r "${TLS_CERT_PATH:-}" && -r "${TLS_KEY_PATH:-}" ]] || fail "both TLS_CERT_PATH and TLS_KEY_PATH must be readable files"
  [[ -f "$TLS_CERT_PATH" && -f "$TLS_KEY_PATH" ]] || fail "TLS certificate and key must be regular files"
else
  [[ -n "$DOMAIN" ]] || fail "provide TLS_CERT_PATH/TLS_KEY_PATH or DOMAIN/EMAIL"
  [[ "$DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ && "$DOMAIN" != *..* && ${#DOMAIN} -le 253 ]] || fail "invalid certificate hostname"

  if [[ "$mode" != "--reload-tls" ]]; then
    [[ "$current_uid" == 0 ]] || fail "automatic certificate setup requires root; use readable existing certificates for a nonroot container"
    [[ -n "$EMAIL" ]] || fail "EMAIL is required for automatic certificate setup"
    certbot_args=(certonly --standalone --non-interactive --agree-tos --keep-until-expiring --email "$EMAIL" -d "$DOMAIN")
    [[ "${LETSENCRYPT_STAGING:-0}" == 1 ]] && certbot_args+=(--staging)
    certbot "${certbot_args[@]}"
  fi

  export TLS_CERT_PATH="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
  export TLS_KEY_PATH="/etc/letsencrypt/live/${DOMAIN}/privkey.pem"
  export PUBLIC_HOST="${PUBLIC_HOST:-${DOMAIN}}"
  [[ -r "$TLS_CERT_PATH" && -r "$TLS_KEY_PATH" ]] || fail "certificate setup did not provide readable TLS files"
fi

# An explicit nonroot container already controls its readable certificate paths
# and bind permissions. Never attempt to raise its privileges.
if [[ "$current_uid" != 0 ]]; then
  exec ./secure_notes
fi

# Keep original ACME material root-only. The server reads private copies through
# its dedicated primary group, without gaining permission to alter the files.
[[ ! -L "$RUNTIME_TLS_DIR" ]] || fail "runtime TLS directory must not be a symlink"
install -d -o 0 -g "$APP_GID" -m 0750 "$RUNTIME_TLS_DIR"
temporary_tls="$(mktemp -d "${RUNTIME_TLS_DIR}/.tls.XXXXXX")"
trap 'rm -rf -- "$temporary_tls"' EXIT
install -o 0 -g "$APP_GID" -m 0640 -- "$TLS_CERT_PATH" "${temporary_tls}/fullchain.pem"
install -o 0 -g "$APP_GID" -m 0640 -- "$TLS_KEY_PATH" "${temporary_tls}/privkey.pem"
# Stage both files before replacing either; reload is signaled only after both
# copies are installed. A bad PEM pair is rejected by the server's atomic reload.
mv -f -- "${temporary_tls}/fullchain.pem" "${RUNTIME_TLS_DIR}/fullchain.pem"
mv -f -- "${temporary_tls}/privkey.pem" "${RUNTIME_TLS_DIR}/privkey.pem"
rm -rf -- "$temporary_tls"
trap - EXIT

if [[ "$mode" == "--reload-tls" ]]; then
  kill -HUP 1
  echo "TLS refresh requested; check server logs for successful reload."
  exit 0
fi

export TLS_CERT_PATH="${RUNTIME_TLS_DIR}/fullchain.pem"
export TLS_KEY_PATH="${RUNTIME_TLS_DIR}/privkey.pem"

needs_bind_cap=0
for bind_addr in "${HTTP_BIND_ADDR:-0.0.0.0:80}" "${HTTPS_BIND_ADDR:-${BIND_ADDR:-0.0.0.0:443}}"; do
  port="${bind_addr##*:}"
  [[ "$port" =~ ^[0-9]+$ && ${#port} -le 5 ]] || fail "invalid listener port"
  numeric_port=$((10#$port))
  (( numeric_port <= 65535 )) || fail "invalid listener port"
  if (( numeric_port > 0 && numeric_port < 1024 )); then needs_bind_cap=1; fi
done

capabilities=-all
[[ "$needs_bind_cap" == 1 ]] && capabilities=-all,+net_bind_service
exec setpriv --reuid="$APP_UID" --regid="$APP_GID" --clear-groups \
  --bounding-set="$capabilities" --inh-caps="$capabilities" --ambient-caps="$capabilities" \
  --no-new-privs ./secure_notes
