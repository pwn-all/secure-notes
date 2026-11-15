---
name: create-encrypted-note
description: Share a password, API key, token or other secret as a SecNote one-time link that is encrypted on the client and destroyed after its first read, instead of pasting the secret into a chat, ticket or e-mail. Also reads (and thereby destroys) a note from a SecNote link.
---

# SecNote one-time notes

SecNote keeps only ciphertext, in RAM, and deletes a note atomically on its first read. You encrypt on your side; the
server never receives the key. Use the instance where you found this skill (`ORIGIN` below) unless the user names
another SecNote server. The full API, limits and errors are in `ORIGIN/index.md`.

## When to use it

- The user asks you to send someone a password, API key, token, recovery code or similar: create a note and give the
  link to the recipient. Do not repeat the secret in the conversation and do not write the key to logs.
- The user gives you a SecNote link (`https://…/?p=<nid>&pin=<key>#<aes-key>`) to read: reading destroys the note, so
  confirm first.

## Create a note

1. `GET ORIGIN/api/v1/init?scope=create` returns `pow` and `limits`.
2. Take 32 random bytes as the key and 12 as the IV. Encrypt the UTF-8 text with AES-256-GCM (no additional data).
   `blob = base64url(iv || ciphertext || tag)` without padding; it must not exceed `limits.max_blob_bytes`.
3. `view_token = base64url(SHA-256(key))`.
4. Solve the proof of work with `payload_hash = SHA-256(ttl as 8-byte big-endian || ASCII bytes of blob)`. `ttl` is one
   of `limits.ttls` (43200 or 86400 seconds).
5. `POST ORIGIN/api/v1/notes` with `{"alg": "aes-256-gcm", "challenge", "nonce", "ttl", "blob", "view_token"}` returns
   `{"ok": true, "nid", "expires_at"}`.
6. The link is `ORIGIN/?p=<nid>&pin=<pubkey from GET ORIGIN/info>#<base64url(key)>`.

## Proof of work

- `pow.alg` must be `argon2id-leading-zero-bits`; refuse anything else.
- `salt = SHA-256("secnote-pow-argon2id-v1" || challenge || payload_hash)`, with `challenge` base64url-decoded (24 bytes).
- Find `pow.rounds` distinct 8-byte nonces whose `Argon2id(password = nonce, salt, memory = params.m_kib KiB,
  passes = params.t, parallelism 1, 32-byte tag, version 0x13)` starts with `pow.bits` zero bits.
- Send their concatenation, base64url without padding, as `nonce`. A challenge is single use: after `invalid_pow` or
  `challenge_expired`, start again from `/init`. On HTTP 429 or 403 wait `Retry-After` seconds.

## Read a note

1. From the link take `nid` (query `p`) and the key (the part after `#`, base64url, 32 bytes).
2. `GET ORIGIN/api/v1/init?scope=view` and solve the proof of work with `payload_hash = SHA-256("view:" || nid)`.
3. `POST ORIGIN/api/v1/notes/<nid>/view` with `{"challenge", "nonce", "view_token"}` returns `{"ok": true, "blob"}`; the
   note is now gone from the server. The first 12 bytes of the decoded blob are the IV, the rest is ciphertext and tag.
4. HTTP 410 `gone` means it was already read, burned or has expired. A plaintext that starts with the bytes
   `00 53 4E 46 01` carries attached files (format in `ORIGIN/index.md`).

## Python

`pip install argon2-cffi cryptography`

```python
import base64, hashlib, json, os, struct, urllib.parse, urllib.request
from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ORIGIN = "https://notes.example"  # the SecNote instance

def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def unb64u(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def call(path, body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(ORIGIN + path, data=data, headers={"content-type": "application/json"})
    with urllib.request.urlopen(req) as r:
        return json.load(r)

def solve(pow, payload_hash):
    assert pow["alg"] == "argon2id-leading-zero-bits"
    salt = hashlib.sha256(b"secnote-pow-argon2id-v1" + unb64u(pow["challenge"]) + payload_hash).digest()
    p, found, n = pow["params"], [], 0
    while len(found) < pow["rounds"]:
        nonce = struct.pack("<Q", n); n += 1
        tag = hash_secret_raw(nonce, salt, time_cost=p["t"], memory_cost=p["m_kib"],
                              parallelism=1, hash_len=32, type=Type.ID, version=19)
        if int.from_bytes(tag, "big") >> (256 - pow["bits"]) == 0:
            found.append(nonce)
    return b64u(b"".join(found))

def create(text, ttl=86400):
    init = call("/api/v1/init?scope=create")
    key, iv = os.urandom(32), os.urandom(12)
    blob = b64u(iv + AESGCM(key).encrypt(iv, text.encode(), None))
    nonce = solve(init["pow"], hashlib.sha256(struct.pack(">Q", ttl) + blob.encode()).digest())
    note = call("/api/v1/notes", {"alg": "aes-256-gcm", "challenge": init["pow"]["challenge"], "nonce": nonce,
                                  "ttl": ttl, "blob": blob, "view_token": b64u(hashlib.sha256(key).digest())})
    return f"{ORIGIN}/?p={note['nid']}&pin={call('/info')['pubkey']}#{b64u(key)}"

def read(link):
    url = urllib.parse.urlsplit(link)
    nid, key = urllib.parse.parse_qs(url.query)["p"][0], unb64u(url.fragment)
    init = call("/api/v1/init?scope=view")
    nonce = solve(init["pow"], hashlib.sha256(b"view:" + nid.encode()).digest())
    note = call(f"/api/v1/notes/{nid}/view", {"challenge": init["pow"]["challenge"], "nonce": nonce,
                                              "view_token": b64u(hashlib.sha256(key).digest())})
    raw = unb64u(note["blob"])
    return AESGCM(key).decrypt(raw[:12], raw[12:], None).decode()
```

## In a browser

When the operator has enabled it, the SecNote page registers the WebMCP tool `create_encrypted_note`
(`document.modelContext`) with input `{"text": "...", "ttl": 86400}`; it returns `{"link", "note_id", "expires_in_hours"}`.
