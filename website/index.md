# SecNote — Zero-Knowledge Encrypted Notes

SecNote is a free, open-source, browser-based tool for sending one-time encrypted notes. Notes are encrypted entirely in the browser using AES-256-GCM before transmission. The decryption key exists only in the URL fragment and is never sent to the server.

**Live app:** /  
**Source code:** https://github.com/pwn-all/secure-notes  
**API status:** /stat  

## How It Works

1. **Write** your message in the browser.
2. **Encrypt** — your browser generates a random 256-bit AES key and encrypts the message locally.
3. **Send** — the encrypted ciphertext is uploaded. The key never leaves your device (it stays in the URL `#fragment`).
4. **Share** — the recipient opens the link once. The note is permanently destroyed on the server immediately after first read.

## Security Properties

- **AES-256-GCM** authenticated encryption via the browser's native WebCrypto API
- **Zero-knowledge relay** — server stores only ciphertext; key is never transmitted
- **Burn after read** — atomic fetch-and-delete; note cannot be read twice
- **RAM-only storage** — no database, no disk writes; server restart clears all notes
- **SHA-256 Proof-of-Work** anti-spam on each note creation
- **No account required** — no sign-up, no tracking, no cookies

## REST API

**Base URL:** `/`

All write operations require a SHA-256 Proof-of-Work challenge solved client-side. There is no API key or OAuth; the PoW prevents bulk automated abuse.

### Initialize PoW challenge

```
GET /api/v1/init?scope={create|view}
Accept: application/json
```

Returns a SHA-256 Proof-of-Work challenge that must be solved before creating or reading a note.

**Response:**
```json
{
  "ok": true,
  "server_time": 1714500000,
  "pow": {
    "scope": "create",
    "alg": "sha256-leading-zero-bits",
    "bits": 22,
    "expires_at": 1714500150,
    "challenge": "<base64url>"
  },
  "encryption": { "alg": "aes-256-gcm", "key_bytes": 32, "nonce_bytes": 12, "tag_bytes": 16 },
  "limits": { "max_plaintext_bytes": 4096, "max_blob_bytes": 16384, "ttls": [43200, 86400] }
}
```

### Create a note

```
POST /api/v1/notes
Content-Type: application/json
```

```json
{
  "alg": "aes-256-gcm",
  "challenge": "<challenge from /init>",
  "nonce": "<base64url PoW nonce>",
  "ttl": 43200,
  "blob": "<base64url(12-byte-IV || AES-GCM-ciphertext)>",
  "view_token": "<base64url(SHA-256(aes_key_bytes))>"
}
```

Returns `{ "ok": true, "nid": "<note-id>", "expires_at": <unix-ts> }`.

### Read and destroy a note

```
POST /api/v1/notes/{nid}/view
Content-Type: application/json
```

```json
{
  "challenge": "<challenge from /init?scope=view>",
  "nonce": "<base64url PoW nonce>",
  "view_token": "<base64url(SHA-256(aes_key_bytes))>"
}
```

Returns the encrypted blob. The note is permanently deleted atomically. Returns HTTP 410 if already read or expired.

### Server statistics

```
GET /stat
```

Returns `{ "notes": <count>, "ram_usage": "<mb>" }`.

## Privacy

- No personally identifiable information collected
- No cookies, no analytics, no tracking
- Server access logs retained ≤ 7 days for security purposes
- GDPR compliant
