# SecNote

[![CI](https://github.com/pwn-all/secure-notes/actions/workflows/rust.yml/badge.svg)](https://github.com/pwn-all/secure-notes/actions/workflows/rust.yml)
[![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](LICENSE)
[![Rust 2024](https://img.shields.io/badge/rust-2024%20edition-orange.svg?logo=rust)](Cargo.toml)
[![i18n](https://img.shields.io/badge/i18n-12%20languages-informational.svg)](website/langs/)
[![Tor Browser](https://img.shields.io/badge/Tor%20Browser-compatible-7D4698.svg)](website/)
[![Offline](https://img.shields.io/badge/frontend-works%20offline-success.svg)](website/)

RAM-only service for self-destructing end-to-end encrypted notes.

The server stores only ciphertext — it never sees the key, never touches disk, and atomically destroys the note on first read. Zero configuration required for self-hosting.

---

## How it works

1. The browser encrypts the note with AES-256-GCM (WebCrypto). The key never leaves the client.
2. The server receives only ciphertext and stores it in RAM — no disk writes.
3. The key lives in the URL `#fragment`, which browsers never include in HTTP requests.
4. The note is atomically deleted on the first read (or when its TTL expires / the process restarts).

## Offline / Tor Browser use

The entire frontend is plain HTML + JS + CSS with no build step, no CDN dependencies, and no server-side rendering. You can:

- **Download once, use anywhere** — save [`index.html`](website/index.html), [`app.js`](website/app.js), [`styles.css`](website/styles.css), and [`pow-worker.js`](website/pow-worker.js) to a local folder and open `index.html` directly in any browser, including Tor Browser.
- **Point at any backend** — use `?api=https://your-server` in the URL (or enter it in the settings panel) to connect the local frontend to any SecNote instance.
- **Distrust the server's frontend delivery** — if you don't trust that the server is serving unmodified JS, audit the files once and use your own copy. The server never needs to touch your frontend again.
- **Full functionality offline** — encryption, PoW solving, QR code generation, and i18n all run locally. Only the API calls (`/api/v1/*`) go to the network.

No apps to install, no packages to build, no runtime to configure. Works in air-gapped environments and high-privacy contexts where installing software is not an option.

## Security properties

| Property | Detail |
|---|---|
| Zero-knowledge server | Stores only `nid`, `blob`, and timestamps — never the key |
| Burn protection | Reading requires `view_token = SHA-256(aes_key)`; knowing only `nid` is not enough |
| Payload-bound PoW | `SHA-256(challenge ‖ nonce ‖ SHA-256(ttl ‖ blob))` — challenge can't be reused for a different payload |
| One-time challenge | Both challenge and note are consumed atomically |
| IP privacy | Anti-abuse state keyed on `SHA-256(IP ‖ server_salt)`; raw IPs never stored |
| Ephemeral salt | `server_salt` is random per process start; all anti-abuse state lost on restart |
| Authenticated API responses | Every `/api/v1/*` and `/info` response is signed with an ephemeral Ed25519 key generated at startup; the client verifies the signature before parsing — a network-level attacker with a forged TLS cert cannot inject or replay responses |
| Strict CSP | `default-src 'none'` with minimal allowlist |
| Offline shell | Service worker caches static assets; API calls always bypass the cache |

---

## Comparison with similar projects

> Legend: ✅ Yes &nbsp;|&nbsp; ⚠️ Partial / optional &nbsp;|&nbsp; ❌ No

| Feature | **SecNote** | [PrivateBin](https://github.com/nicktacular/PrivateBin) | [Cryptgeon](https://github.com/cupcakearmy/cryptgeon) | [Yopass](https://github.com/jhaals/yopass) | [One-Time Secret](https://github.com/onetimesecret/onetimesecret) |
|---|:---:|:---:|:---:|:---:|:---:|
| **Backend language** | Rust | PHP | Rust + TS | Go | Ruby |
| **Storage** | RAM only | Filesystem / DB | Redis / RAM | Memcached / Redis | Redis |
| **External service required** | ✅ None | ✅ None | ⚠️ Optional | ❌ Required | ❌ Required |
| **Client-side encryption** | ✅ | ✅ | ✅ | ✅ | ❌ Server-side |
| **Zero-knowledge server** | ✅ | ✅ | ✅ | ✅ | ❌ |
| **Burn after read** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Authenticated API responses** | ✅ Ed25519 per-response | ❌ | ❌ | ❌ | ❌ |
| **Anti-spam / bot protection** | ✅ Proof-of-Work | ⚠️ CAPTCHA opt-in | ❌ | ❌ | ❌ |
| **Burn-read protection¹** | ✅ `view_token` | ❌ | ❌ | ❌ | ❌ |
| **IP privacy by design** | ✅ Hashed | ❌ Raw IPs | ❌ Raw IPs | ❌ Raw IPs | ❌ Raw IPs |
| **Built-in TLS** | ✅ Rustls | ❌ Web server | ❌ Proxy | ❌ Proxy | ❌ Proxy |
| **PWA + offline support** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Downloadable offline frontend²** | ✅ Open as local file | ❌ Needs PHP | ❌ Needs build | ❌ Needs build | ❌ Server-rendered |
| **Tor Browser compatible** | ✅ | ⚠️ JS-heavy | ❌ | ❌ | ❌ |
| **i18n** | ✅ 12 languages | ✅ Many | ⚠️ Few | ❌ English only | ❌ English only |
| **Self-host: zero config** | ✅ | ✅ | ⚠️ Needs Docker | ⚠️ Needs Docker | ⚠️ Needs Redis |
| **License** | GPL-3.0 | zlib | AGPL-3.0 | Apache-2.0 | MIT |

¹ *Burn-read protection means knowing the note ID alone is not sufficient to read the note — a second secret derived from the encryption key is also required. Without this, anyone who observes a note ID (e.g. from a server log) can burn the note before the intended recipient reads it.*

² *Downloadable offline frontend means you can save the static files locally and open them directly in a browser (including Tor Browser) without any server, build tool, or package manager. Use `?api=https://your-server` to point your local copy at any backend.*

**Where SecNote trades off:** state is volatile — notes are lost if the server restarts. There is no persistent backend; RAM-only storage is the threat model, not a limitation to work around.

---

## Running locally

```bash
cargo run
```

No configuration required — the API URL and privacy policy auto-detect from the page origin. The server starts on `0.0.0.0:443` (HTTPS) and `0.0.0.0:80` (redirect) and requires TLS certificates at startup.

Default TLS paths: `/etc/letsencrypt/live/localhost/fullchain.pem` and `privkey.pem`.  
Override with `TLS_CERT_PATH` / `TLS_KEY_PATH` or copy `.env.example` → `.env`.

## One-click setup (certbot + .env)

`scripts/1click.sh` gets a Let's Encrypt certificate and writes the paths into `.env` in one step.

```bash
sudo ./scripts/1click.sh example.com admin@example.com
```

- Runs certbot in standalone mode (binds `:80` temporarily — requires root and a free port 80).
- Idempotent: skips certbot if the certificate files already exist.
- Creates `.env` from `.env.example` if it doesn't exist yet, then sets `TLS_CERT_PATH` and `TLS_KEY_PATH` automatically.

After the script finishes, start the server:

```bash
cargo run --release
```

**Optional env vars for the script:**

| Variable | Default | Description |
|---|---|---|
| `LETSENCRYPT_DIR` | `/etc/letsencrypt/live` | Base directory for certificate files |
| `LETSENCRYPT_STAGING` | `0` | Set to `1` to use Let's Encrypt staging CA (for testing) |
| `ENV_FILE` | `<repo-root>/.env` | Path to the `.env` file to write |

## Docker

The image handles everything — build, certificate, and server — in one command. No local clone required; Docker fetches the source directly from GitHub.

### One-click (auto Let's Encrypt)

```bash
docker build -t secnote https://github.com/pwn-all/secure-notes.git

docker run -d \
  --name secnote \
  --restart unless-stopped \
  -p 80:80 \
  -p 443:443 \
  -v letsencrypt:/etc/letsencrypt \
  -e DOMAIN=example.com \
  -e EMAIL=admin@example.com \
  secnote
```

The container runs certbot on first start, obtains a certificate, then starts the server. The `/etc/letsencrypt` volume persists the certificate across restarts — certbot skips renewal if the cert is still valid.

Set `-e LETSENCRYPT_STAGING=1` to use the Let's Encrypt staging CA while testing.

### Bring your own certificate

If you already have a certificate (from certbot, another ACME client, or a CA):

```bash
docker run -d \
  --name secnote \
  --restart unless-stopped \
  -p 80:80 \
  -p 443:443 \
  -v /etc/letsencrypt:/etc/letsencrypt:ro \
  -e TLS_CERT_PATH=/etc/letsencrypt/live/example.com/fullchain.pem \
  -e TLS_KEY_PATH=/etc/letsencrypt/live/example.com/privkey.pem \
  secnote
```

Notes hold no state outside the process — there is no data volume to mount. Restarting the container clears all notes (by design).

## Environment variables

All variables are optional. The server works with defaults.

| Variable | Default | Description |
|---|---|---|
| `HTTP_BIND_ADDR` | `0.0.0.0:80` | HTTP redirect listener |
| `HTTPS_BIND_ADDR` | `0.0.0.0:443` | HTTPS listener (`BIND_ADDR` is a legacy alias) |
| `PUBLIC_HOST` | (from `Host` header) | Hostname used in HTTP→HTTPS redirects; inferred from the request `Host` header if not set |
| `TLS_CERT_PATH` | `/etc/letsencrypt/live/localhost/fullchain.pem` | TLS certificate chain |
| `TLS_KEY_PATH` | `/etc/letsencrypt/live/localhost/privkey.pem` | TLS private key |
| `CHALLENGE_TTL_SECS` | `150` | PoW challenge lifetime |
| `POW_BITS_CREATE` | `17` | Base PoW difficulty for note creation (alias: `POW_BITS`) |
| `POW_BITS_CREATE_MAX` | `28` | Max PoW difficulty under load (alias: `POW_BITS_MAX`) |
| `POW_BITS_VIEW` | `16` | Base PoW difficulty for note reading |
| `POW_BITS_VIEW_MAX` | `24` | Max PoW difficulty for reading under load |
| `MAX_PLAINTEXT_BYTES` | `4096` | Maximum plaintext size |
| `MAX_BLOB_BYTES` | `16384` | Maximum encrypted blob size |
| `POW_FAIL_WINDOW_SECS` | `600` | Window for counting PoW failures per IP |
| `BAN_SHORT_SECS` | `300` | Short ban (3+ failures) |
| `BAN_MEDIUM_SECS` | `1800` | Medium ban (6+ failures) |
| `BAN_LONG_SECS` | `43200` | Long ban (10+ failures) |
| `CLEANUP_INTERVAL_SECS` | `30` | Expired entry cleanup interval |
| `RATE_INIT_PER_MIN` | `30` | `/api/v1/init` rate limit per IP |
| `RATE_CREATE_PER_MIN` | `30` | Note creation rate limit per IP |
| `RATE_VIEW_PER_MIN` | `60` | Note reading rate limit per IP |

## API

Base URL is the server's own origin; no API key required. All write operations require a solved PoW challenge.

### Response signing

Every response from `/info` and all `/api/v1/*` endpoints carries an Ed25519 signature:

```
x-secnote-sig: <base64url(Ed25519 signature of the raw response body bytes)>
```

The server's Ed25519 public key is returned by `GET /info` as `pubkey` (base64url, 32 bytes). The signing key is generated ephemerally at startup — it changes on every restart. The official frontend fetches and caches this key on first connect, then verifies every subsequent response before parsing — meaning a network-level attacker who can intercept TLS (e.g. a corporate proxy with a trusted CA cert) still cannot inject or tamper with API responses.

### `GET /api/v1/init?scope=create|view`

Returns a PoW challenge, encryption parameters, and server limits.

```json
{
  "ok": true,
  "server_time": 1700000000,
  "pow": {
    "scope": "create",
    "alg": "sha256-leading-zero-bits",
    "bits": 22,
    "expires_at": 1700000150,
    "challenge": "<base64url>"
  },
  "encryption": { "alg": "aes-256-gcm", "key_bytes": 32, "nonce_bytes": 12, "tag_bytes": 16 },
  "limits": { "max_plaintext_bytes": 4096, "max_blob_bytes": 16384, "ttls": [43200, 86400] }
}
```

### `POST /api/v1/notes`

```json
{
  "alg": "aes-256-gcm",
  "challenge": "<base64url>",
  "nonce": "<base64url(pow_nonce)>",
  "ttl": 43200,
  "blob": "<base64url(iv ‖ ciphertext ‖ tag)>",
  "view_token": "<base64url(SHA-256(aes_key_bytes))>"
}
```

Response: `{ "ok": true, "nid": "<base64url>", "expires_at": 1700086400 }`

### `POST /api/v1/notes/{nid}/view`

```json
{
  "challenge": "<base64url>",
  "nonce": "<base64url(pow_nonce)>",
  "view_token": "<base64url(SHA-256(aes_key_bytes))>"
}
```

Response: `{ "ok": true, "blob": "<base64url(iv ‖ ciphertext ‖ tag)>", "deleted": true }`  
Gone/expired: `410` with `{ "ok": false, "error": { "code": "gone", "message": "note is gone" } }`

### `GET /stat`

`{ "notes": 42, "ram_usage": "2 mb" }` — anonymous aggregate, no user identifiers.

## Frontend

Static files served from `website/`. The Rust backend handles only `/api/v1/*`, `/stat`, and `/.well-known/api-catalog`; everything else is served by `ServeDir`.

| File | Purpose |
|---|---|
| `index.html` | App shell |
| `app-config.js` | Empty runtime config — API URL auto-detects from `location.origin` |
| `app.js` | Client logic: encryption, PoW, i18n, privacy policy rendering |
| `pow-worker.js` | PoW solver (Web Worker) |
| `styles.css` | Styles |
| `sw.js` | Service worker (offline shell cache) |
| `manifest.json` | PWA manifest |
| `langs/*.json` | UI translations (12 languages) |

The frontend auto-connects to the API at its own origin — no configuration needed. Use `?api=https://other-host` to point at a different backend.

Privacy Policy and contact email are rendered client-side from `location.host`, so self-hosted instances get the correct operator information without any setup.

## Self-hosting

1. Clone the repo and build: `cargo build --release`
2. Get a TLS certificate for your domain (see above)
3. Set `TLS_CERT_PATH` / `TLS_KEY_PATH` pointing to your cert, then run the binary
4. Open your domain — the UI connects to your API automatically

The Privacy Policy shown to users will automatically display your domain and `legal@yourdomain` as the contact. Update the policy text in `website/index.html` if needed to reflect your jurisdiction.

## Tests

```bash
cargo test
```

## Third-party code

[qrcode-svg](https://github.com/datalog/qrcode-svg) — MIT License. Copyright and license notice retained in this repository.
