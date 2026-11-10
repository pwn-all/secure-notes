# RAM-only: process hardening and the instance passport

Version 1 — November 2026. Implemented in `src/hardening.rs`, `src/lib.rs` (`/info`), `src/main.rs` and the settings panel of `website/app.js`.

"RAM-only" is a statement about the architecture: notes live in a `HashMap`, there is no database and no disk write path. That leaves three things the process can influence itself: whether its heap may be paged to swap, whether it can be dumped or traced, and whether freed note buffers keep their contents. The server enforces what it can at startup and reports the outcome in the signed `/info` response, so operators and users can see misconfiguration instead of guessing. It is transparency, not attestation — section 3 spells out the difference.

## 1. What the server enforces at startup

`hardening::harden_process()` runs before the TLS key or signing seed are read:

| Step | Mechanism | Effect | Reported as |
| --- | --- | --- | --- |
| No core dumps | `setrlimit(RLIMIT_CORE, 0)` (all Unix) | A crash writes no core file containing ciphertext, keys or tokens. | `core_dump_limit_zero` |
| Non-dumpable | `prctl(PR_SET_DUMPABLE, 0)` (Linux) | Blocks `ptrace`, `/proc/<pid>/mem` and `/proc/<pid>/maps` for unprivileged peers of the same user; also implies no core dump. Root and `CAP_SYS_PTRACE` holders are not stopped. | `dumpable: false` |
| Memory pinned | `mlockall(MCL_CURRENT \| MCL_FUTURE \| MCL_ONFAULT)` (Linux), only when `RLIMIT_MEMLOCK` is unlimited | Pages are never swapped out, including future heap growth. `MCL_ONFAULT` locks pages as they are touched instead of pre-faulting every thread stack. | `memory_locked`, with `memory_lock_detail` when it is `false` |
| Swap observation | `/proc/swaps` (Linux) | Tells the reader whether locking matters on this host at all. | `swap_present` |
| Zeroize on drop | `zeroize` on `NoteEntry` and on the read response wrapper | The stored ciphertext and read-token hash are overwritten with zeros when a note is read, expires or is evicted, not merely unlinked from the map. (Argon2id proof-of-work inputs are public, so the verifier's memory holds nothing secret.) | `zeroize_on_drop: true` |

Zeroize is defense in depth for the long-lived copy, not a guarantee that no copy survives. Transient copies are not zeroized: the request body buffer and the deserialized JSON on create, the serialized and signed response body on read (including the signature message built in `sign_response_middleware`), TLS and HTTP/2 buffers, and allocator spare capacity. They are short-lived and freed, but their pages may keep old bytes until reused.

Memory locking is deliberately conservative. With `MCL_FUTURE` and a finite limit, the first allocation past the limit fails and the process aborts instead of silently staying unlocked, so the server only locks when the limit is unlimited and otherwise says why:

```bash
# systemd
LimitMEMLOCK=infinity
# docker (the entrypoint drops CAP_IPC_LOCK, so the rlimit is the way in)
docker run --ulimit memlock=-1:-1 ... secnote
# shell
ulimit -l unlimited
```

Pinned memory cannot be reclaimed by swapping. With file uploads enabled (`MAX_FILE_BYTES`), stored notes and request buffers can be large; size the container or host memory for `MAX_NOTE_STORAGE_BYTES` plus roughly `MAX_CONCURRENT_API_REQUESTS × 3 × max_blob_bytes`, otherwise the kernel's OOM killer, not swap, handles the overflow — and a restart drops every note.

## 2. The instance passport

`GET /info` returns, inside the same signed body as the note count and the Ed25519 public key:

```json
"passport": {
  "version": "0.1.0",
  "started_at": 1762560000,
  "uptime_secs": 86400,
  "binary_sha256": "9f2c…e1",
  "ram_only": {
    "dumpable": false,
    "core_dump_limit_zero": true,
    "memory_locked": false,
    "memory_lock_detail": "RLIMIT_MEMLOCK is finite; start with an unlimited memlock limit to pin memory",
    "swap_present": false,
    "zeroize_on_drop": true
  }
}
```

- `started_at` / `uptime_secs` — when this process started. A process restart drops every note, so if the binary is honest nothing older than `started_at` can exist on this instance.
- `binary_sha256` — SHA-256 of the executable read through `/proc/self/exe` at startup.
- `ram_only` — the table above. `null` means "not applicable on this platform".
- The whole `/info` body is covered by `x-secnote-sig-v2`.

Set `PUBLISH_PASSPORT=0` to omit the block. The server logs the same facts at startup (`Instance passport collected`). The settings panel of the official frontend shows them after the signature check that every API response goes through.

## 3. What this does and does not prove

The passport is **self-reported** by the process. The Ed25519 signature proves that it was produced by whoever holds the pinned signing key and was not rewritten by a proxy, CDN or network attacker in between. It proves nothing against the operator: a modified binary can publish any version, any hash and any flags, and the signing key is the operator's.

Useful for:

- detecting misconfiguration on an honest deployment: memory not pinned, swap present, a stale build still running, an unexpected restart;
- operators and auditors comparing what a deployment reports with what they built and deployed;
- clients that pin the key, to know the report was not altered in transit.

Not a proof of:

- which code is running. Even an honest hash only identifies a build: Rust builds are not reproducible out of the box (toolchain version, target CPU features and embedded paths change the bytes), so matching `binary_sha256` against a published checksum requires a reproducible-build setup this project does not ship yet;
- anything about the kernel, the hypervisor or physical memory: root, a VM snapshot, a cold-boot attack or a memory-dumping hypervisor still see stored ciphertext and read-token hashes;
- that the TLS terminator, reverse proxy or CDN in front of the instance keeps no logs of `nid`s;
- that no transient copy of a note remains in freed memory (section 1).

Hardware attestation (AMD SEV-SNP or Intel TDX reports embedded in the passport, with a verifier in the client) would move "trust the operator" to "trust the CPU vendor". It is not implemented: it needs a confidential-VM deployment path and client-side report verification.

## 4. Checking an instance by hand

```bash
# 1. Fetch the passport and the signature
curl -sD headers.txt -H "x-secnote-request-id: $(head -c16 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=')" \
     https://notes.example/info -o info.json
# 2. Check the Ed25519 signature as described in README.md (Response signing)
# 3. Read the flags and the build identity the process reports
jq .passport.ram_only info.json
jq -r .passport.binary_sha256 info.json
```

On a host you control, compare with the binary you deployed and the process state:

```bash
sha256sum /app/secure_notes
docker exec secnote sh -c 'awk "/^(Uid|Gid|CapEff|NoNewPrivs|VmLck):/" /proc/1/status; grep -c . /proc/swaps'
```

`VmLck` shows how many kilobytes are locked; with `memory_locked: true` it grows with the note store.
