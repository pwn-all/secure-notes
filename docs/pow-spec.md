# SecNote proof-of-work: `argon2id-leading-zero-bits`

Version 1 — November 2026. Status: implemented in `src/lib.rs` (verifier), `website/pow-worker.js` and `website/app.js` (solver), `website/argon2.js` (Argon2id), with interoperability vectors in `tests/fixtures/pow-argon2id-vector.json`.

SecNote has no accounts, so the only cost an anonymous caller pays for creating or reading a note is a proof-of-work. This document specifies the memory-hard scheme, the measurements behind its default parameters, and what it does and does not buy. It is written so that an independent client (CLI, bot, another frontend) can be implemented from it alone.

Argon2id is the only scheme. The earlier SHA-256 leading-zero-bits scheme was removed without a fallback: the server never issues or accepts it, the official client refuses any other `alg`, and the server refuses to start when `POW_ALG` names anything but `argon2id` or when a `POW_BITS*` setting exceeds 12 (an old SHA-256 difficulty such as 17 would mean 2^17 Argon2id evaluations per note).

## 1. Why the SHA-256 scheme was replaced

The SHA-256 scheme required `SHA-256(challenge ‖ nonce ‖ payload_hash)` to start with `bits` zero bits (17 for create by default). Its problem was the gap between an honest browser and an attacker: a browser can only reach SHA-256 through `crypto.subtle.digest`, one asynchronous call per attempt, while native code and GPUs hash at full speed.

Measured on the reference machine (one core of an AMD EPYC 9355P; browser figures from Chromium and from Node.js 22 running the same code in its global context):

| Property | SHA-256, 17 bits (old default) | Argon2id 4 MiB, 4 bits × 4 rounds (new default) |
| --- | --- | --- |
| Cost unit | one SHA-256: ≈ 27 µs via `crypto.subtle` (call overhead), ≈ 0.12 µs native (OpenSSL, one core) | one Argon2id evaluation: ≈ 14 ms in `website/argon2.js`, ≈ 1.14 ms native (RustCrypto `argon2` 0.6, release build, AVX2) |
| Expected attempts per note | 2^17 = 131 072 | 4 × 2^4 = 64 |
| Honest latency, desktop browser | ≈ 3.5 s | ≈ 0.9 s (p50 ≈ 0.8 s, p95 ≈ 1.7 s) |
| Honest latency, phone-class CPU² | ≈ 14 s (×4 of desktop, estimated) | ≈ 3.8 s (p50 ≈ 3.5 s, p95 ≈ 7.2 s) |
| Native CPU cost per note (one core) | ≈ 16 ms | ≈ 73 ms |
| Native-over-browser advantage on the same core | ≈ 230× | ≈ 12× |
| GPU throughput per note (rough estimate³) | ~10^5 notes/s per high-end GPU | ~10^3 notes/s per high-end GPU |
| Latency variance (single request) | geometric: p95 ≈ 3 × mean | sum of 4 geometrics: p95 ≈ 1.9 × mean |
| Server verification cost | ≈ 0.1 µs | ≈ 4.6 ms CPU and 4 MiB RAM (4 evaluations), bounded by `POW_VERIFY_CONCURRENCY` |
| Client dependencies | WebCrypto | `website/argon2.js` (plain JavaScript, no WebAssembly — works in Tor Browser at the Safer level) |

² Chromium with CPU throttling ×4 (the "mid-tier mobile" emulation used by Lighthouse) measured ≈ 59 ms per evaluation. Real phones vary by a factor of two or more in either direction.

³ Not measured. Argon2id with 4 MiB and t = 1 moves roughly 12 MiB through memory per evaluation, so a GPU with 1–3 TB/s of bandwidth is bounded at very roughly 10^5 evaluations per second, i.e. ~10^3 notes per second at the default difficulty. SHA-256 GPUs reach ~10^10 hashes per second, i.e. ~10^5 notes per second at 17 bits. Treat both as order-of-magnitude estimates.

The honest claim is therefore: at a quarter of the old honest latency, a native CPU attacker pays about 4–5× more per note than before, the attacker's advantage over a legitimate browser on the same core drops from ~230× to ~12×, and a GPU attacker loses roughly two orders of magnitude of throughput (estimate). It does not make an attacker and a browser equal, and verification becomes measurably more expensive, which is why the server bounds verification concurrency, consumes each challenge before verifying it, and keeps the per-IP rate limits and bans as the primary flood control.

## 2. Terms

- `challenge` — 24 random bytes issued by `GET /api/v1/init?scope=create|view`, base64url without padding, single use, bound to the caller's hashed IP, scope and expiry.
- `payload_hash` — 32 bytes binding the proof to the request:
  - create: `SHA-256(ttl_be64 ‖ blob)` where `ttl_be64` is the TTL in seconds as an 8-byte big-endian integer and `blob` is the base64url ciphertext string as sent;
  - view: `SHA-256("view:" ‖ nid)` over the ASCII note id.
- `bits` — required number of leading zero bits in each tag.
- `rounds` — number of distinct solutions required (1–16).
- `m_kib`, `t`, `p` — Argon2id memory in KiB, passes and lanes. The server always issues `p = 1`.
- `nonce` (wire field) — base64url of `rounds × 8` bytes: the concatenation of the solutions, in any order.

## 3. Challenge advertisement

```json
"pow": {
  "scope": "create",
  "alg": "argon2id-leading-zero-bits",
  "bits": 4,
  "rounds": 4,
  "params": { "m_kib": 4096, "t": 1, "p": 1, "tag_bytes": 32, "nonce_bytes": 8 },
  "expires_at": 1700000150,
  "challenge": "<base64url 32 chars>"
}
```

Clients must check that `alg` is `argon2id-leading-zero-bits` and reject parameters outside the ranges in §6; there is no other scheme to fall back to. The response is covered by the Ed25519 `x-secnote-sig-v2` signature, so a network attacker cannot inflate the advertised parameters for a client that pins the server key.

## 4. Solving

```
salt      = SHA-256("secnote-pow-argon2id-v1" ‖ challenge ‖ payload_hash)      // 32 bytes
solutions = {}
counter   = 0
while |solutions| < rounds:
    nonce_i = LE64(counter); counter += 1
    tag     = Argon2id(P = nonce_i, S = salt, K = ∅, X = ∅,
                       m = m_kib, t = t, p = 1, T = 32, version = 0x13)
    if leading_zero_bits(tag) >= bits and nonce_i ∉ solutions:
        solutions ∪= { nonce_i }
nonce     = base64url(solutions[0] ‖ solutions[1] ‖ … )
```

- The domain string is the ASCII bytes `secnote-pow-argon2id-v1` with no terminator. Lengths are fixed (23 + 24 + 32 bytes), so no length prefixes are needed.
- The nonce is the Argon2 *password*; the salt carries all context. Argon2 requires a salt of at least 8 bytes; 32 are used.
- A counter from 0 is a valid strategy: the challenge is random per client, so there is no cross-client work sharing to avoid. Any 8-byte values work as long as they are distinct.
- Expected work is `rounds × 2^bits` evaluations. Each evaluation allocates `m_kib` KiB; the memory may be reused across attempts.

## 5. Verification

The server, in order:

1. Looks up the challenge; rejects unknown, expired, wrong-IP or wrong-scope challenges (these cost no Argon2 work).
2. Decodes `nonce`; it must be exactly `rounds × 8` bytes (`invalid_nonce`, the challenge stays usable because no work was done).
3. Removes the challenge from the table. From here on the challenge is spent whatever the outcome, so one challenge can trigger at most one verification; a second request with the same challenge fails with `invalid_challenge`.
4. Rejects nonces whose 8-byte chunks are not pairwise distinct (`invalid_pow`), so one solution cannot be presented `rounds` times.
5. Computes `salt` from the stored challenge bytes and the payload hash of the *received* request.
6. For each chunk, in order, computes the tag and stops at the first chunk without `bits` leading zero bits (`invalid_pow`). A garbage proof therefore costs the server exactly one evaluation (≈ 1.1 ms).

Argon2id verification runs on the blocking thread pool behind a semaphore of `POW_VERIFY_CONCURRENCY` permits (default: CPU count, max 64). Peak verifier memory is `POW_VERIFY_CONCURRENCY × POW_ARGON2_M_KIB`; with the defaults on a 4-core host that is 16 MiB. Invalid proofs count towards the per-IP failure window (3 failures → short ban), and every verification needs a fresh challenge from the rate-limited `/api/v1/init` (30 per minute per IP by default), which bounds how many evaluations one address can force.

## 6. Parameter ranges

| Parameter | Server default | Server range | Client acceptance |
| --- | --- | --- | --- |
| `bits` create | 4, up to 7 under load | 1–12 | 1–12 |
| `bits` view | 3, up to 5 under load | 1–12 | 1–12 |
| `rounds` create / view | 4 / 2 | 1–16 | 1–16 |
| `m_kib` | 4096 | 256–65536 | 8·p–65536 |
| `t` | 1 | 1–8 | 1–8 |
| `p` | 1 | 1 | 1–4 |
| `tag_bytes`, `nonce_bytes` | 32, 8 | fixed | must equal 32, 8 |

Load scaling: +1 bit above 100 active challenges, +2 above 300, +3 above 800, +4 above 2000, capped at `POW_BITS_*_MAX`. Each bit doubles the expected work; operators who raise the cap should keep `rounds × 2^bits_max × 60 ms` within what their users will tolerate on a phone. At the default caps that is 512 evaluations (≈ 7 s desktop, ≈ 30 s phone) for create and 64 (≈ 0.9 s / ≈ 3.8 s) for view.

### Why these defaults

- **4 MiB, t = 1.** ≈ 14 ms per evaluation in plain JavaScript on a desktop core and ≈ 59 ms phone-class; small enough for low-memory phones, large enough that memory bandwidth, not arithmetic, bounds a GPU.
- **create: 4 bits × 4 rounds.** Expected 64 evaluations: ≈ 0.9 s on a desktop, ≈ 3.8 s on a phone-class CPU (p95 ≈ 1.7 s / 7.2 s). The server verifies 4 evaluations (≈ 4.6 ms), a 16× asymmetry between solving and verifying.
- **view: 3 bits × 2 rounds.** Expected 16 evaluations: ≈ 0.25 s / ≈ 1 s; the proof is pre-solved while the recipient looks at the confirmation, so it is rarely visible.
- **Rounds instead of a single harder puzzle.** A single geometric search has a coefficient of variation ≈ 1 regardless of difficulty; four independent searches cut it to ≈ 0.5. The server pays one evaluation per round on success, which is acceptable at SecNote's request rates and bounded as described above.

## 7. Test vectors

### Argon2id implementation

`website/argon2.js` and the `argon2` Rust crate are both checked against RFC 9106 §5.3 (Argon2id, m=32, t=3, p=4, with secret and associated data: tag `0d640df5…01e659`). `website/argon2.js` is additionally checked against the Argon2id vectors from the reference implementation's `src/test.c` (version 0x13, `password` / `somesalt`): t=2 m=256 p=1 → `9dfeb910…c68bfe`, t=2 m=256 p=2 → `6d093c50…f57037`, t=1 m=65536 p=1 → `f6a5adc1…9ca98` (slow, `SECNOTE_SLOW_TESTS=1`). BLAKE2b is compared with OpenSSL's `blake2b512` on inputs straddling the 128-byte block boundary.

### Protocol vector

`tests/fixtures/pow-argon2id-vector.json` fixes one create request end to end (challenge, ttl, blob → payload hash → salt → tags for four nonces → a solved two-round, three-bit proof). The JavaScript side generated it and the Rust test `argon2id_pow_matches_the_frontend_interoperability_vector` recomputes every value with the Rust crate and checks that the solved proof verifies, and that one more bit of difficulty, a different payload, a repeated chunk and a truncated nonce all fail. `tests/runtime-smoke.cjs` solves live challenges from the compiled server with `website/argon2.js`.

## 8. Known limits and future work

- Memory-hardness narrows but does not close the gap to a dedicated attacker; the per-IP bans and rate limits remain the primary flood control. Behind a reverse proxy those keys see one IP, so a trusted-proxy policy is still required (see the security review).
- Plain-JavaScript Argon2 is ≈ 12× slower than native code on the same core. A WebAssembly build would narrow that further but is blocked by Tor Browser at the Safer/Safest security levels, which SecNote supports on purpose; it could be offered as an optional accelerator with the JS implementation as the fallback.
- Argon2id is used as a pure work function here, not as a password hash. No secret is derived from it, so no KDF-strength arguments apply; only the cost asymmetry matters.
- Privacy Pass style tokens (RFC 9576–9578) would let repeat users skip the proof entirely; that requires an issuer and is out of scope for a RAM-only service with no accounts.
