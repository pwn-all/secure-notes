# SecNote — Zero-Knowledge Encrypted Notes

SecNote is a free, open-source, browser-based tool for sending one-time encrypted notes. Notes are encrypted entirely in the browser using AES-256-GCM before transmission. The decryption key exists only in the URL fragment and is never sent to the server.

**Live app:** /  
**Source code:** https://github.com/pwn-all/secure-notes  
**API status:** /info

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
- **Memory-hard Argon2id Proof-of-Work** (RFC 9106) on each note creation and read, computed in plain JavaScript without WebAssembly
- **Optional encrypted files** — when the operator enables them, attachments are encrypted in the browser inside the same note
- **No account required** — no sign-up, no tracking, no cookies

## REST API

**Base URL:** `/`

Creating and reading notes require an Argon2id Proof-of-Work challenge solved client-side, with several independent solutions per request. Argon2id is the only scheme. There is no API key or OAuth; the PoW and per-IP rate limits prevent bulk automated abuse. Protocol and test vectors: `docs/pow-spec.md` in the source repository.

### Initialize PoW challenge

```
GET /api/v1/init?scope={create|view}
Accept: application/json
```

Returns a Proof-of-Work challenge that must be solved before creating or reading a note. `pow.alg` is always `argon2id-leading-zero-bits`; `rounds` is the number of distinct 8-byte solutions and `params` the Argon2id cost parameters. `limits.max_file_bytes` is the total attachment budget per note (`0` = file uploads disabled); `max_blob_bytes` already includes it.

**Response:**
```json
{
  "ok": true,
  "server_time": 1714500000,
  "pow": {
    "scope": "create",
    "alg": "argon2id-leading-zero-bits",
    "bits": 4,
    "rounds": 4,
    "params": { "m_kib": 4096, "t": 1, "p": 1, "tag_bytes": 32, "nonce_bytes": 8 },
    "expires_at": 1714500150,
    "challenge": "<base64url>"
  },
  "encryption": { "alg": "aes-256-gcm", "key_bytes": 32, "nonce_bytes": 12, "tag_bytes": 16 },
  "limits": { "max_plaintext_bytes": 32768, "max_blob_bytes": 49152, "max_file_bytes": 0, "ttls": [43200, 86400] }
}
```

Solving: `salt = SHA-256("secnote-pow-argon2id-v1" || challenge || payload_hash)` with `payload_hash = SHA-256(ttl as 8-byte big-endian || blob)` for create and `SHA-256("view:" || nid)` for read. Find `rounds` distinct 8-byte nonces whose `Argon2id(password = nonce, salt, m = m_kib, t, p = 1, 32-byte tag, version 0x13)` starts with `bits` zero bits, and send their concatenation, base64url-encoded, as `nonce`.

### Create a note

```
POST /api/v1/notes
Content-Type: application/json
```

```json
{
  "alg": "aes-256-gcm",
  "challenge": "<challenge from /init>",
  "nonce": "<base64url(rounds × 8-byte PoW solutions)>",
  "ttl": 43200,
  "blob": "<base64url(12-byte-IV || AES-GCM-ciphertext)>",
  "view_token": "<base64url(SHA-256(aes_key_bytes))>"
}
```

Returns `{ "ok": true, "nid": "<note-id>", "expires_at": <unix-ts> }`. A challenge is spent once its proof is checked, even if the proof is wrong; fetch a new one to retry.

Notes with files (only when `limits.max_file_bytes` > 0) encrypt an envelope instead of raw text: bytes `00 53 4E 46 01`, a 4-byte big-endian header length, a UTF-8 JSON header `{"v":1,"text":<text bytes>,"files":[{"name","type","size"}]}`, then the text bytes, then the file bytes in order. Text-only notes are raw UTF-8. The server never sees or parses either.

### Read and destroy a note

```
POST /api/v1/notes/{nid}/view
Content-Type: application/json
```

```json
{
  "challenge": "<challenge from /init?scope=view>",
  "nonce": "<base64url(rounds × 8-byte PoW solutions)>",
  "view_token": "<base64url(SHA-256(aes_key_bytes))>"
}
```

Returns the encrypted blob. The note is permanently deleted atomically. Returns HTTP 410 if already read or expired.

### Server statistics

```
GET /info
```

Returns `{ "ok": true, "notes": <count>, "ram_usage": "<mb>", "pubkey": "<base64url>", "max_file_bytes": <bytes>, "passport": { … } }` — the passport is the server's self-reported version, start time, SHA-256 of the running binary and RAM-only hardening flags (core dumps off, non-dumpable, memory locked, swap present, zeroize on drop); see `docs/ram-only.md` in the source repository for what it does and does not prove. The official client verifies Ed25519 v2 signatures against a trusted public key, a fresh request ID, and the full request context before parsing API responses. See the source README for the signing format and trust model.

## Privacy

- The backend keeps salted IP hashes in transient anti-abuse state
- No cookies, no analytics, no tracking
- Access logs and their retention depend on the instance operator and deployment
- The server disables its own core dumps and pins its memory when the host allows it; it cannot prevent host-level swap configuration, VM snapshots or memory access by the host operator
