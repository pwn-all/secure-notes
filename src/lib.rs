use std::{
    collections::HashMap,
    env,
    mem::size_of,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

pub mod hardening;

use argon2::{Algorithm, Argon2, Params, Version};
use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{ConnectInfo, DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header, uri::Authority},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::{
    sync::{Mutex, Semaphore},
    time::Duration,
};
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;
use zeroize::Zeroize;

pub use hardening::{InstancePassport, RamOnlyReport};

const NOTE_TTLS: [u64; 2] = [12 * 3600, 24 * 3600];
const NOTE_ALG: &str = "aes-256-gcm";
const NOTE_KEY_BYTES: usize = 32;
const NOTE_NONCE_BYTES: usize = 12;
const NOTE_TAG_BYTES: usize = 16;
const CHALLENGE_BYTES: usize = 24;
const POW_NONCE_BYTES: usize = 8;
/// Memory-hard proof-of-work: one Argon2id evaluation per attempt (docs/pow-spec.md).
const POW_ALG_ARGON2ID: &str = "argon2id-leading-zero-bits";
/// Domain separator mixed into the Argon2id salt so tags are bound to this protocol.
const POW_ARGON2_SALT_DOMAIN: &[u8] = b"secnote-pow-argon2id-v1";
const MAX_POW_BITS: u8 = 12;
const MAX_POW_ROUNDS: u8 = 16;
const POW_ARGON2_TAG_BYTES: usize = 32;
const POW_ARGON2_M_KIB_MIN: u32 = 256;
const POW_ARGON2_M_KIB_MAX: u32 = 65_536;
const POW_ARGON2_T_MAX: u32 = 8;
const POW_VERIFY_CONCURRENCY_MAX: usize = 64;
/// Environment variables that carry a difficulty in leading zero bits.
const POW_BITS_ENV_VARS: [&str; 6] = [
    "POW_BITS_CREATE",
    "POW_BITS",
    "POW_BITS_CREATE_MAX",
    "POW_BITS_MAX",
    "POW_BITS_VIEW",
    "POW_BITS_VIEW_MAX",
];
/// Budget for the client-side file envelope: magic (5) + header length (4) + JSON header.
/// The server never parses the envelope (it is inside the AES-GCM ciphertext); it only
/// reserves this many plaintext bytes for it when file uploads are enabled.
pub const FILE_ENVELOPE_OVERHEAD_BYTES: usize = 16 * 1024;
/// Upper bound for `MAX_FILE_BYTES`.
pub const MAX_FILE_BYTES_LIMIT: usize = 64 * 1024 * 1024;
const BASE_REQUEST_TIMEOUT_SECS: u64 = 10;
const DEFAULT_UPLOAD_TIMEOUT_SECS: u64 = 120;
const UPLOAD_TIMEOUT_SECS_MAX: u64 = 600;
const GENERATED_NID_BYTES: usize = 16;
const GENERATED_NID_B64_LEN: usize = 22;
const JSON_BODY_OVERHEAD_BYTES: usize = 2048;
/// Minimum response size buffered for signing; grows with the effective blob limit.
const SIG_BODY_LIMIT_MIN: usize = 512 * 1024;
const MAX_SUPPORTED_BLOB_BYTES: usize = 48 * 1024;
const REQUEST_ID_HEADER: &str = "x-secnote-request-id";
const SIGNATURE_V2_HEADER: &str = "x-secnote-sig-v2";
const DEFAULT_MAX_ACTIVE_CHALLENGES: usize = 10_000;
const DEFAULT_MAX_NOTES: usize = 50_000;
const DEFAULT_MAX_TRACKING_ENTRIES: usize = 100_000;

#[derive(Clone, Debug)]
pub struct RateLimits {
    pub init_per_minute: u32,
    pub create_per_minute: u32,
    pub view_per_minute: u32,
}

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub server_salt: Vec<u8>,
    pub challenge_ttl_secs: u64,
    pub pow_bits_create: u8,
    pub pow_bits_create_max: u8,
    pub pow_bits_view: u8,
    pub pow_bits_view_max: u8,
    /// Distinct Argon2id solutions required per create request.
    pub pow_rounds_create: u8,
    /// Distinct Argon2id solutions required per read request.
    pub pow_rounds_view: u8,
    /// Argon2id memory cost in KiB per evaluation.
    pub pow_argon2_m_kib: u32,
    /// Argon2id passes per evaluation.
    pub pow_argon2_t: u32,
    /// Maximum Argon2id verifications running at once (bounds CPU and RAM: this × m_kib).
    pub pow_verify_concurrency: usize,
    /// Include the signed instance passport (binary hash, hardening flags, uptime) in `/info`.
    pub publish_passport: bool,
    /// Maximum UTF-8 text bytes per note.
    pub max_plaintext_bytes: usize,
    /// Maximum encoded blob for text-only notes (`MAX_BLOB_BYTES`); see
    /// [`AppConfig::effective_max_blob_bytes`] for the limit that is enforced.
    pub max_blob_bytes: usize,
    /// Maximum total size of attached files per note; 0 disables file uploads.
    pub max_file_bytes: usize,
    /// Body read and handler deadline for API requests while file uploads are enabled.
    pub upload_timeout_secs: u64,
    pub max_active_challenges: usize,
    pub max_notes: usize,
    pub max_note_storage_bytes: usize,
    pub max_concurrent_api_requests: usize,
    pub max_tracking_entries: usize,
    pub pow_fail_window_secs: u64,
    pub ban_short_secs: u64,
    pub ban_medium_secs: u64,
    pub ban_long_secs: u64,
    pub cleanup_interval_secs: u64,
    pub rate_limits: RateLimits,
}

impl AppConfig {
    pub fn from_env() -> Self {
        // Difficulty counts Argon2id evaluations (a 4 MiB evaluation takes ~15 ms in a desktop
        // browser, ~60 ms on a phone-class CPU), so the defaults are a few bits; see
        // docs/pow-spec.md for the calibration.
        let pow_bits_create = env::var("POW_BITS_CREATE")
            .ok()
            .or_else(|| env::var("POW_BITS").ok())
            .and_then(|v| v.parse::<u8>().ok())
            .unwrap_or(4)
            .clamp(1, MAX_POW_BITS);
        let pow_bits_create_max = env::var("POW_BITS_CREATE_MAX")
            .ok()
            .or_else(|| env::var("POW_BITS_MAX").ok())
            .and_then(|v| v.parse::<u8>().ok())
            .unwrap_or(7)
            .clamp(pow_bits_create, MAX_POW_BITS);
        let pow_bits_view = parse_env_u8("POW_BITS_VIEW", 3).clamp(1, MAX_POW_BITS);
        let pow_bits_view_max =
            parse_env_u8("POW_BITS_VIEW_MAX", 5).clamp(pow_bits_view, MAX_POW_BITS);
        let default_verify_concurrency = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(2);

        Self {
            server_salt: random_bytes(32),
            challenge_ttl_secs: parse_env_u64("CHALLENGE_TTL_SECS", 150),
            pow_bits_create,
            pow_bits_create_max,
            pow_bits_view,
            pow_bits_view_max,
            pow_rounds_create: parse_env_u8("POW_ROUNDS_CREATE", 4).clamp(1, MAX_POW_ROUNDS),
            pow_rounds_view: parse_env_u8("POW_ROUNDS_VIEW", 2).clamp(1, MAX_POW_ROUNDS),
            pow_argon2_m_kib: parse_env_u32("POW_ARGON2_M_KIB", 4096)
                .clamp(POW_ARGON2_M_KIB_MIN, POW_ARGON2_M_KIB_MAX),
            pow_argon2_t: parse_env_u32("POW_ARGON2_T", 1).clamp(1, POW_ARGON2_T_MAX),
            pow_verify_concurrency: parse_env_usize(
                "POW_VERIFY_CONCURRENCY",
                default_verify_concurrency,
            )
            .clamp(1, POW_VERIFY_CONCURRENCY_MAX),
            publish_passport: parse_env_bool("PUBLISH_PASSPORT", true),
            max_plaintext_bytes: parse_env_usize("MAX_PLAINTEXT_BYTES", 32768).clamp(1, 32768),
            max_blob_bytes: parse_env_usize("MAX_BLOB_BYTES", MAX_SUPPORTED_BLOB_BYTES).clamp(
                ((NOTE_NONCE_BYTES + NOTE_TAG_BYTES + 1) * 4).div_ceil(3),
                MAX_SUPPORTED_BLOB_BYTES,
            ),
            max_file_bytes: parse_env_usize("MAX_FILE_BYTES", 0).min(MAX_FILE_BYTES_LIMIT),
            upload_timeout_secs: parse_env_u64("UPLOAD_TIMEOUT_SECS", DEFAULT_UPLOAD_TIMEOUT_SECS)
                .clamp(BASE_REQUEST_TIMEOUT_SECS, UPLOAD_TIMEOUT_SECS_MAX),
            max_active_challenges: parse_env_usize(
                "MAX_ACTIVE_CHALLENGES",
                DEFAULT_MAX_ACTIVE_CHALLENGES,
            ),
            max_notes: parse_env_usize("MAX_NOTES", DEFAULT_MAX_NOTES),
            max_note_storage_bytes: parse_env_usize("MAX_NOTE_STORAGE_BYTES", 64 * 1024 * 1024),
            max_concurrent_api_requests: parse_env_usize("MAX_CONCURRENT_API_REQUESTS", 64)
                .clamp(1, 1024),
            max_tracking_entries: parse_env_usize(
                "MAX_TRACKING_ENTRIES",
                DEFAULT_MAX_TRACKING_ENTRIES,
            ),
            pow_fail_window_secs: parse_env_u64("POW_FAIL_WINDOW_SECS", 600),
            ban_short_secs: parse_env_u64("BAN_SHORT_SECS", 300),
            ban_medium_secs: parse_env_u64("BAN_MEDIUM_SECS", 1800),
            ban_long_secs: parse_env_u64("BAN_LONG_SECS", 12 * 3600),
            cleanup_interval_secs: parse_env_u64("CLEANUP_INTERVAL_SECS", 30),
            rate_limits: RateLimits {
                init_per_minute: parse_env_u32("RATE_INIT_PER_MIN", 30),
                create_per_minute: parse_env_u32("RATE_CREATE_PER_MIN", 30),
                view_per_minute: parse_env_u32("RATE_VIEW_PER_MIN", 60),
            },
        }
    }

    /// Largest plaintext (inside the AES-GCM blob) a note may carry. With file uploads enabled
    /// this covers the text limit, the client-side file envelope and the file budget.
    pub fn effective_max_plaintext_bytes(&self) -> usize {
        if self.max_file_bytes == 0 {
            self.max_plaintext_bytes
        } else {
            self.max_plaintext_bytes
                .saturating_add(FILE_ENVELOPE_OVERHEAD_BYTES)
                .saturating_add(self.max_file_bytes)
        }
    }

    /// Largest base64url blob accepted and advertised as `limits.max_blob_bytes`.
    pub fn effective_max_blob_bytes(&self) -> usize {
        if self.max_file_bytes == 0 {
            self.max_blob_bytes
        } else {
            b64url_no_pad_len(
                NOTE_NONCE_BYTES + NOTE_TAG_BYTES + self.effective_max_plaintext_bytes(),
            )
            .max(self.max_blob_bytes)
        }
    }

    /// Request body limit for API calls: the largest blob plus JSON framing.
    fn max_request_body_bytes(&self) -> usize {
        self.effective_max_blob_bytes()
            .saturating_add(JSON_BODY_OVERHEAD_BYTES)
            .max(JSON_BODY_OVERHEAD_BYTES)
    }

    /// Largest response buffered for signing (a read returns the whole blob).
    fn signed_response_limit(&self) -> usize {
        self.max_request_body_bytes().max(SIG_BODY_LIMIT_MIN)
    }

    /// Deadline for reading a request body and for running the handler.
    fn request_timeout(&self) -> Duration {
        if self.max_file_bytes == 0 {
            Duration::from_secs(BASE_REQUEST_TIMEOUT_SECS)
        } else {
            Duration::from_secs(self.upload_timeout_secs.max(BASE_REQUEST_TIMEOUT_SECS))
        }
    }
}

/// Rejects proof-of-work settings this build cannot honour instead of silently clamping them:
/// the SHA-256 scheme is gone (no fallback), and SHA-256 sized difficulties such as 17 bits
/// would mean 2^17 Argon2id evaluations, i.e. hours per note in a browser.
pub fn validate_pow_env() -> Result<(), String> {
    check_pow_env(|name| env::var(name).ok())
}

fn check_pow_env(get: impl Fn(&str) -> Option<String>) -> Result<(), String> {
    if let Some(alg) = get("POW_ALG") {
        let alg = alg.trim();
        if !alg.is_empty() && !alg.eq_ignore_ascii_case("argon2id") {
            return Err(format!(
                "POW_ALG={alg} is not supported: only argon2id proof-of-work exists \
                 (the SHA-256 scheme was removed); unset POW_ALG or set it to argon2id. \
                 See docs/pow-spec.md"
            ));
        }
    }
    for name in POW_BITS_ENV_VARS {
        let Some(raw) = get(name) else { continue };
        if let Ok(bits) = raw.trim().parse::<u64>()
            && bits > u64::from(MAX_POW_BITS)
        {
            return Err(format!(
                "{name}={bits} exceeds {MAX_POW_BITS}: difficulty now counts Argon2id \
                 evaluations, not SHA-256 hashes (defaults: create 4..7, view 3..5). \
                 See docs/pow-spec.md"
            ));
        }
    }
    Ok(())
}

fn b64url_no_pad_len(raw_bytes: usize) -> usize {
    raw_bytes.saturating_mul(4).div_ceil(3)
}

fn parse_env_u8(name: &str, default: u8) -> u8 {
    env::var(name)
        .ok()
        .and_then(|v| v.parse::<u8>().ok())
        .unwrap_or(default)
}

fn parse_env_u32(name: &str, default: u32) -> u32 {
    env::var(name)
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(default)
}

fn parse_env_u64(name: &str, default: u64) -> u64 {
    env::var(name)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
}

fn parse_env_usize(name: &str, default: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(default)
}

fn parse_env_bool(name: &str, default: bool) -> bool {
    match env::var(name) {
        Ok(value) => match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => true,
            "0" | "false" | "no" | "off" => false,
            _ => default,
        },
        Err(_) => default,
    }
}

#[derive(Clone)]
pub struct AppState {
    inner: Arc<StateInner>,
}

struct StateInner {
    config: AppConfig,
    signing_key: Option<SigningKey>,
    passport: InstancePassport,
    challenges: Mutex<HashMap<String, ChallengeEntry>>,
    notes: Mutex<NoteStore>,
    api_permits: Semaphore,
    pow_verify_permits: Semaphore,
    abuse: Mutex<HashMap<String, AbuseEntry>>,
    rate_windows: Mutex<HashMap<String, RateEntry>>,
}

/// Everything a client needs to solve, and the server needs to verify, one challenge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PowSpec {
    bits: u8,
    rounds: u8,
    m_kib: u32,
    t_cost: u32,
}

impl PowSpec {
    fn nonce_bytes(&self) -> usize {
        POW_NONCE_BYTES * usize::from(self.rounds)
    }
}

#[derive(Clone, Copy)]
struct StatSnapshot {
    notes: usize,
    estimated_bytes: usize,
}

#[derive(Clone)]
struct ChallengeEntry {
    client_key: String,
    scope: PowScope,
    challenge_bytes: Vec<u8>,
    spec: PowSpec,
    expires_at: u64,
}

/// Stored ciphertext. Overwritten with zeros when it leaves the store (read, expiry,
/// eviction) so freed heap pages do not keep note contents around. Defense in depth only:
/// transient copies in request/response buffers are not covered (docs/ram-only.md).
#[derive(Clone)]
struct NoteEntry {
    blob: String,
    view_token_hash: [u8; 32],
    expires_at: u64,
}

impl Drop for NoteEntry {
    fn drop(&mut self) {
        self.blob.zeroize();
        self.view_token_hash.zeroize();
    }
}

/// Response field that zeroizes its String after serialization.
struct SecretString(String);

impl Serialize for SecretString {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Default)]
struct NoteStore {
    entries: HashMap<String, NoteEntry>,
    blob_bytes: usize,
}

impl NoteStore {
    fn remove(&mut self, nid: &str) -> Option<NoteEntry> {
        let note = self.entries.remove(nid)?;
        self.blob_bytes -= note.blob.len();
        Some(note)
    }

    fn remove_expired(&mut self, now: u64) {
        self.entries.retain(|_, note| {
            if note.expires_at <= now {
                self.blob_bytes -= note.blob.len();
                false
            } else {
                true
            }
        });
    }
}

#[derive(Clone, Default)]
struct AbuseEntry {
    fail_count: u32,
    window_start: u64,
    banned_until: u64,
}

#[derive(Clone, Default)]
struct RateEntry {
    window_start: u64,
    count: u32,
}

impl AppState {
    pub fn new(config: AppConfig) -> Self {
        Self::with_signing_key(config, None)
    }

    pub fn with_signing_key(config: AppConfig, signing_key: Option<SigningKey>) -> Self {
        Self::with_passport(config, signing_key, InstancePassport::unknown())
    }

    pub fn with_passport(
        config: AppConfig,
        signing_key: Option<SigningKey>,
        passport: InstancePassport,
    ) -> Self {
        Self {
            inner: Arc::new(StateInner {
                api_permits: Semaphore::new(config.max_concurrent_api_requests),
                pow_verify_permits: Semaphore::new(config.pow_verify_concurrency.max(1)),
                config,
                signing_key,
                passport,
                challenges: Mutex::new(HashMap::new()),
                notes: Mutex::new(NoteStore::default()),
                abuse: Mutex::new(HashMap::new()),
                rate_windows: Mutex::new(HashMap::new()),
            }),
        }
    }

    fn config(&self) -> &AppConfig {
        &self.inner.config
    }

    /// The configuration this state was built with.
    pub fn app_config(&self) -> &AppConfig {
        &self.inner.config
    }

    pub fn pubkey_b64(&self) -> Option<String> {
        self.inner
            .signing_key
            .as_ref()
            .map(|k| URL_SAFE_NO_PAD.encode(k.verifying_key().to_bytes()))
    }

    async fn cleanup_expired(&self, now: u64) {
        {
            let mut challenges = self.inner.challenges.lock().await;
            challenges.retain(|_, c| c.expires_at > now);
        }

        {
            let mut notes = self.inner.notes.lock().await;
            notes.remove_expired(now);
        }

        {
            let mut abuse = self.inner.abuse.lock().await;
            let window = self.config().pow_fail_window_secs;
            abuse.retain(|_, entry| {
                entry.banned_until > now || now.saturating_sub(entry.window_start) <= window
            });
        }

        {
            let mut rate_windows = self.inner.rate_windows.lock().await;
            rate_windows.retain(|_, entry| now.saturating_sub(entry.window_start) <= 120);
        }
    }

    async fn stat_snapshot(&self) -> StatSnapshot {
        let notes_guard = self.inner.notes.lock().await;
        let notes_count = notes_guard.entries.len();
        let notes_bytes = notes_guard.blob_bytes
            + notes_count
                * (size_of::<String>() + GENERATED_NID_B64_LEN + size_of::<NoteEntry>() + 32);
        drop(notes_guard);

        let challenges_guard = self.inner.challenges.lock().await;
        let challenges_bytes = challenges_guard.len()
            * (size_of::<String>() + 32 + size_of::<ChallengeEntry>() + 43 + CHALLENGE_BYTES + 32);
        drop(challenges_guard);

        let abuse_guard = self.inner.abuse.lock().await;
        let abuse_bytes =
            abuse_guard.len() * (size_of::<String>() + 43 + size_of::<AbuseEntry>() + 24);
        drop(abuse_guard);

        let rates_guard = self.inner.rate_windows.lock().await;
        let rates_bytes =
            rates_guard.len() * (size_of::<String>() + 50 + size_of::<RateEntry>() + 24);

        StatSnapshot {
            notes: notes_count,
            estimated_bytes: notes_bytes + challenges_bytes + abuse_bytes + rates_bytes,
        }
    }
}

#[derive(Clone, Copy)]
enum Endpoint {
    Init,
    Create,
    View,
}

impl Endpoint {
    fn as_str(self) -> &'static str {
        match self {
            Self::Init => "init",
            Self::Create => "create",
            Self::View => "view",
        }
    }
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
    retry_after_secs: Option<u64>,
}

impl ApiError {
    fn new(status: StatusCode, code: &'static str, message: &'static str) -> Self {
        Self {
            status,
            code,
            message,
            retry_after_secs: None,
        }
    }

    fn with_retry_after(mut self, retry_after_secs: u64) -> Self {
        self.retry_after_secs = Some(retry_after_secs.max(1));
        self
    }
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: &'static str,
}

#[derive(Serialize)]
struct ErrorEnvelope {
    ok: bool,
    error: ErrorBody,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut response = (
            self.status,
            Json(ErrorEnvelope {
                ok: false,
                error: ErrorBody {
                    code: self.code,
                    message: self.message,
                },
            }),
        )
            .into_response();

        if let Some(retry_after) = self.retry_after_secs
            && let Ok(value) = HeaderValue::from_str(&retry_after.to_string())
        {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }

        response
    }
}

#[derive(Serialize)]
struct PowResponse {
    scope: &'static str,
    alg: &'static str,
    bits: u8,
    rounds: u8,
    params: PowArgon2Params,
    expires_at: u64,
    challenge: String,
}

#[derive(Serialize, Clone, Copy)]
struct PowArgon2Params {
    m_kib: u32,
    t: u32,
    p: u32,
    tag_bytes: usize,
    nonce_bytes: usize,
}

impl PowResponse {
    fn new(scope: PowScope, spec: PowSpec, expires_at: u64, challenge: String) -> Self {
        Self {
            scope: scope.as_str(),
            alg: POW_ALG_ARGON2ID,
            bits: spec.bits,
            rounds: spec.rounds,
            params: PowArgon2Params {
                m_kib: spec.m_kib,
                t: spec.t_cost,
                p: 1,
                tag_bytes: POW_ARGON2_TAG_BYTES,
                nonce_bytes: POW_NONCE_BYTES,
            },
            expires_at,
            challenge,
        }
    }
}

#[derive(Serialize)]
struct LimitsResponse {
    /// UTF-8 text limit per note.
    max_plaintext_bytes: usize,
    /// Effective encoded blob limit (grows with `max_file_bytes`).
    max_blob_bytes: usize,
    /// Total attached file bytes per note; 0 means uploads are disabled.
    max_file_bytes: usize,
    ttls: [u64; 2],
}

#[derive(Serialize)]
struct EncryptionResponse {
    alg: &'static str,
    key_bytes: usize,
    nonce_bytes: usize,
    tag_bytes: usize,
}

#[derive(Serialize)]
struct InitResponse {
    ok: bool,
    server_time: u64,
    pow: PowResponse,
    encryption: EncryptionResponse,
    limits: LimitsResponse,
}

#[derive(Deserialize)]
struct CreateNoteRequest {
    alg: String,
    challenge: String,
    nonce: String,
    ttl: u64,
    blob: String,
    view_token: String,
}

#[derive(Serialize)]
struct CreateNoteResponse {
    ok: bool,
    nid: String,
    expires_at: u64,
}

#[derive(Deserialize, Default)]
struct ViewNoteRequest {
    challenge: String,
    nonce: String,
    view_token: String,
}

#[derive(Serialize)]
struct ViewNoteResponse {
    ok: bool,
    blob: SecretString,
    deleted: bool,
}

#[derive(Serialize)]
struct InfoResponse {
    ok: bool,
    notes: usize,
    ram_usage: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pubkey: Option<String>,
    /// Total attached file bytes per note; 0 means uploads are disabled.
    max_file_bytes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    passport: Option<PassportResponse>,
}

/// The instance passport as published through the signed `/info` response. Self-reported by
/// this process; see docs/ram-only.md for what it does and does not prove.
#[derive(Serialize)]
struct PassportResponse {
    version: &'static str,
    started_at: u64,
    uptime_secs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    binary_sha256: Option<String>,
    ram_only: RamOnlyReport,
}

impl PassportResponse {
    fn from_passport(passport: &InstancePassport) -> Self {
        Self {
            version: passport.version,
            started_at: passport.started_at,
            uptime_secs: passport.uptime_secs(),
            binary_sha256: passport.binary_sha256.clone(),
            ram_only: passport.ram_only.clone(),
        }
    }
}

#[derive(Deserialize, Default)]
struct InitQuery {
    #[serde(default)]
    scope: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PowScope {
    Create,
    View,
}

impl PowScope {
    fn from_query(scope: Option<&str>) -> Result<Self, ApiError> {
        match scope.unwrap_or("create") {
            "create" => Ok(Self::Create),
            "view" => Ok(Self::View),
            _ => Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "invalid_scope",
                "scope must be create or view",
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::View => "view",
        }
    }
}

async fn sign_response_middleware(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let p = req.uri().path();
    if p != "/info" && !p.starts_with("/api/v1/") {
        return next.run(req).await;
    }

    // Reject overload before buffering JSON or waiting on a shared state lock.
    let Ok(_permit) = state.inner.api_permits.try_acquire() else {
        return ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_busy",
            "too many active requests",
        )
        .with_retry_after(5)
        .into_response();
    };
    let request_id = match req.headers().get(REQUEST_ID_HEADER) {
        None => String::new(), // Legacy clients may omit the freshness nonce.
        Some(value) => match value.to_str().ok().filter(|id| {
            id.len() == GENERATED_NID_B64_LEN
                && URL_SAFE_NO_PAD.decode(id).is_ok_and(|v| v.len() == 16)
        }) {
            Some(value) => value.to_owned(),
            None => {
                return ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "invalid_request_id",
                    "invalid request id",
                )
                .into_response();
            }
        },
    };
    let method = req.method().to_string();
    let target = req
        .uri()
        .path_and_query()
        .map(|v| v.as_str())
        .unwrap_or("/")
        .to_owned();
    let (parts, body) = req.into_parts();
    let body_limit = state.config().max_request_body_bytes();
    let deadline = state.config().request_timeout();
    let request_bytes = match tokio::time::timeout(deadline, to_bytes(body, body_limit)).await {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(_)) => {
            return ApiError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "body_too_large",
                "request body is too large or unreadable",
            )
            .into_response();
        }
        Err(_) => {
            return ApiError::new(
                StatusCode::REQUEST_TIMEOUT,
                "request_timeout",
                "request timed out",
            )
            .into_response();
        }
    };
    let request_hash = URL_SAFE_NO_PAD.encode(sha256_bytes(&request_bytes));
    let request = Request::from_parts(parts, Body::from(request_bytes));
    let response = match tokio::time::timeout(deadline, next.run(request)).await {
        Ok(response) => response,
        Err(_) => ApiError::new(
            StatusCode::REQUEST_TIMEOUT,
            "request_timeout",
            "request timed out",
        )
        .into_response(),
    };

    let Some(signing_key) = state.inner.signing_key.as_ref() else {
        return response;
    };

    let (parts, body) = response.into_parts();
    let response_limit = state.config().signed_response_limit();
    let (mut parts, bytes) = match to_bytes(body, response_limit).await {
        Ok(bytes) => (parts, bytes),
        Err(_) => {
            let error = ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "response_error",
                "response unavailable",
            )
            .into_response();
            let (parts, body) = error.into_parts();
            (
                parts,
                to_bytes(body, response_limit)
                    .await
                    .expect("fixed error body fits signing limit"),
            )
        }
    };

    let sig = signing_key.sign(&bytes);
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
    if let Ok(val) = HeaderValue::from_str(&sig_b64) {
        parts
            .headers
            .insert(header::HeaderName::from_static("x-secnote-sig"), val);
    }

    let message = response_signature_message(
        &method,
        &target,
        &request_id,
        &request_hash,
        parts.status,
        &bytes,
    );
    let signature = URL_SAFE_NO_PAD.encode(signing_key.sign(&message).to_bytes());
    parts.headers.insert(
        header::HeaderName::from_static(SIGNATURE_V2_HEADER),
        HeaderValue::from_str(&signature).expect("base64url signature is a valid header"),
    );

    Response::from_parts(parts, Body::from(bytes))
}

fn response_signature_message(
    method: &str,
    target: &str,
    request_id: &str,
    request_hash: &str,
    status: StatusCode,
    body: &[u8],
) -> Vec<u8> {
    let mut message = format!(
        "secnote-response-v2\n{method}\n{target}\n{request_id}\n{request_hash}\n{}\n",
        status.as_u16()
    )
    .into_bytes();
    message.extend_from_slice(body);
    message
}

pub fn build_router(state: AppState) -> Router {
    let max_body_bytes = state.config().max_request_body_bytes();

    Router::new()
        .route("/info", get(info_handler))
        .route("/.well-known/api-catalog", get(api_catalog_handler))
        .route("/api/v1/init", get(init_handler))
        .route("/api/v1/notes", post(create_note_handler))
        .route("/api/v1/notes/{nid}/view", post(view_note_handler))
        .fallback_service(ServeDir::new("website").append_index_html_on_directories(true))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            sign_response_middleware,
        ))
        .with_state(state)
        .layer(DefaultBodyLimit::max(max_body_bytes))
        .layer(middleware::from_fn(security_headers_middleware))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET, Method::POST])
                .allow_headers([
                    header::CONTENT_TYPE,
                    header::ACCEPT,
                    header::HeaderName::from_static(REQUEST_ID_HEADER),
                ])
                .expose_headers([
                    header::HeaderName::from_static("x-secnote-sig"),
                    header::HeaderName::from_static(SIGNATURE_V2_HEADER),
                    header::RETRY_AFTER,
                ]),
        )
}

pub fn spawn_cleanup_task(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let interval = Duration::from_secs(state.config().cleanup_interval_secs.max(5));
        let mut ticker = tokio::time::interval(interval);

        loop {
            ticker.tick().await;
            state.cleanup_expired(now_ts()).await;
        }
    })
}

async fn info_handler(State(state): State<AppState>) -> Json<InfoResponse> {
    let snapshot = state.stat_snapshot().await;
    let mb = snapshot.estimated_bytes / (1024 * 1024);
    Json(InfoResponse {
        ok: true,
        notes: snapshot.notes,
        ram_usage: format!("{mb} mb"),
        pubkey: state.pubkey_b64(),
        max_file_bytes: state.config().max_file_bytes,
        passport: state
            .config()
            .publish_passport
            .then(|| PassportResponse::from_passport(&state.inner.passport)),
    })
}

async fn init_handler(
    State(state): State<AppState>,
    ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
    Query(query): Query<InitQuery>,
) -> Result<Json<InitResponse>, ApiError> {
    let now = now_ts();
    let client_ip = client_addr.ip();
    let client_key = client_key_from_ip(state.config(), client_ip);
    let scope = PowScope::from_query(query.scope.as_deref())?;

    ensure_not_banned(&state, &client_key, now).await?;
    enforce_rate_limit(&state, &client_key, Endpoint::Init, now).await?;

    let (base_bits, bits_max, rounds) = match scope {
        PowScope::Create => (
            state.config().pow_bits_create,
            state.config().pow_bits_create_max,
            state.config().pow_rounds_create,
        ),
        PowScope::View => (
            state.config().pow_bits_view,
            state.config().pow_bits_view_max,
            state.config().pow_rounds_view,
        ),
    };
    let (challenge, spec, expires_at) = {
        let mut challenges = state.inner.challenges.lock().await;
        if challenges.len() >= state.config().max_active_challenges {
            challenges.retain(|_, c| c.expires_at > now);
        }

        if challenges.len() >= state.config().max_active_challenges {
            return Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_busy",
                "too many active challenges",
            )
            .with_retry_after(5));
        }

        let active_challenges = challenges.len();
        let mut bits = base_bits;
        if active_challenges > 2000 {
            bits = bits.saturating_add(4);
        } else if active_challenges > 800 {
            bits = bits.saturating_add(3);
        } else if active_challenges > 300 {
            bits = bits.saturating_add(2);
        } else if active_challenges > 100 {
            bits = bits.saturating_add(1);
        }
        bits = bits.min(bits_max);
        let spec = PowSpec {
            bits,
            rounds,
            m_kib: state.config().pow_argon2_m_kib,
            t_cost: state.config().pow_argon2_t,
        };

        let challenge_bytes = random_bytes(CHALLENGE_BYTES);
        let challenge = URL_SAFE_NO_PAD.encode(&challenge_bytes);
        let expires_at = now.saturating_add(state.config().challenge_ttl_secs);

        challenges.insert(
            challenge.clone(),
            ChallengeEntry {
                client_key: client_key.clone(),
                scope,
                challenge_bytes,
                spec,
                expires_at,
            },
        );

        (challenge, spec, expires_at)
    };

    Ok(Json(InitResponse {
        ok: true,
        server_time: now,
        pow: PowResponse::new(scope, spec, expires_at, challenge),
        encryption: EncryptionResponse {
            alg: NOTE_ALG,
            key_bytes: NOTE_KEY_BYTES,
            nonce_bytes: NOTE_NONCE_BYTES,
            tag_bytes: NOTE_TAG_BYTES,
        },
        limits: LimitsResponse {
            max_plaintext_bytes: state.config().max_plaintext_bytes,
            max_blob_bytes: state.config().effective_max_blob_bytes(),
            max_file_bytes: state.config().max_file_bytes,
            ttls: NOTE_TTLS,
        },
    }))
}

async fn create_note_handler(
    State(state): State<AppState>,
    ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<CreateNoteRequest>,
) -> Result<Json<CreateNoteResponse>, ApiError> {
    let now = now_ts();
    let client_ip = client_addr.ip();
    let client_key = client_key_from_ip(state.config(), client_ip);

    ensure_not_banned(&state, &client_key, now).await?;
    enforce_rate_limit(&state, &client_key, Endpoint::Create, now).await?;
    decode_b64url_exact(
        &payload.challenge,
        CHALLENGE_BYTES,
        "invalid_challenge",
        "challenge must be 24 bytes base64url",
    )?;

    if !NOTE_TTLS.contains(&payload.ttl) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_ttl",
            "ttl must be 43200 or 86400",
        ));
    }

    if payload.alg != NOTE_ALG {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_alg",
            "alg must be aes-256-gcm",
        ));
    }

    if payload.blob.len() > state.config().effective_max_blob_bytes() {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "blob_too_large",
            "blob is too large",
        ));
    }

    let blob_size = validate_aes_blob_format(&payload.blob)?;
    let plaintext_size = blob_size.saturating_sub(NOTE_NONCE_BYTES + NOTE_TAG_BYTES);
    if plaintext_size > state.config().effective_max_plaintext_bytes() {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "plaintext_too_large",
            "plaintext is too large",
        ));
    }
    let view_token_bytes = decode_b64url_exact(
        &payload.view_token,
        NOTE_KEY_BYTES,
        "invalid_view_token",
        "view_token must be 32 bytes base64url",
    )?;
    let view_token_hash = sha256_bytes(&view_token_bytes);

    let (challenge_entry, nonce_bytes) = take_challenge(
        &state,
        &payload.challenge,
        &client_key,
        PowScope::Create,
        &payload.nonce,
        now,
    )
    .await?;
    let payload_hash = payload_hash_for_create(payload.ttl, &payload.blob);

    if !verify_pow(&state, &challenge_entry, nonce_bytes, payload_hash).await? {
        register_pow_failure(&state, &client_key, now).await;
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_pow",
            "pow solution is invalid",
        ));
    }

    reset_pow_failures(&state, &client_key, now).await;

    let nid = random_b64url(GENERATED_NID_BYTES);
    let expires_at = now.saturating_add(payload.ttl);

    {
        let mut notes = state.inner.notes.lock().await;
        if notes.entries.len() >= state.config().max_notes
            || notes.blob_bytes.saturating_add(payload.blob.len())
                > state.config().max_note_storage_bytes
        {
            notes.remove_expired(now);
        }
        if notes.entries.len() >= state.config().max_notes
            || notes.blob_bytes.saturating_add(payload.blob.len())
                > state.config().max_note_storage_bytes
        {
            return Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_busy",
                "note storage capacity reached",
            )
            .with_retry_after(30));
        }
        notes.blob_bytes += payload.blob.len();
        notes.entries.insert(
            nid.clone(),
            NoteEntry {
                blob: payload.blob,
                view_token_hash,
                expires_at,
            },
        );
    }

    Ok(Json(CreateNoteResponse {
        ok: true,
        nid,
        expires_at,
    }))
}

async fn view_note_handler(
    State(state): State<AppState>,
    ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
    Path(nid): Path<String>,
    Json(payload): Json<ViewNoteRequest>,
) -> Result<Json<ViewNoteResponse>, ApiError> {
    let now = now_ts();
    let client_ip = client_addr.ip();
    let client_key = client_key_from_ip(state.config(), client_ip);

    if !is_valid_nid(&nid) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_nid",
            "note id format is invalid",
        ));
    }
    decode_b64url_exact(
        &payload.challenge,
        CHALLENGE_BYTES,
        "invalid_challenge",
        "challenge must be 24 bytes base64url",
    )?;

    ensure_not_banned(&state, &client_key, now).await?;
    enforce_rate_limit(&state, &client_key, Endpoint::View, now).await?;

    let (challenge_entry, nonce_bytes) = take_challenge(
        &state,
        &payload.challenge,
        &client_key,
        PowScope::View,
        &payload.nonce,
        now,
    )
    .await?;
    let payload_hash = payload_hash_for_view(&nid);

    if !verify_pow(&state, &challenge_entry, nonce_bytes, payload_hash).await? {
        register_pow_failure(&state, &client_key, now).await;
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_pow",
            "pow solution is invalid",
        ));
    }

    let view_token_bytes = decode_b64url_exact(
        &payload.view_token,
        NOTE_KEY_BYTES,
        "invalid_view_token",
        "view_token must be 32 bytes base64url",
    )?;
    let provided_view_token_hash = sha256_bytes(&view_token_bytes);

    let mut note = {
        let mut notes = state.inner.notes.lock().await;
        let Some(existing) = notes.entries.get(&nid) else {
            return Err(ApiError::new(StatusCode::GONE, "gone", "note is gone"));
        };
        if existing.expires_at <= now {
            notes.remove(&nid);
            return Err(ApiError::new(StatusCode::GONE, "gone", "note is gone"));
        }
        if !constant_time_eq_32(&existing.view_token_hash, &provided_view_token_hash) {
            return Err(ApiError::new(StatusCode::GONE, "gone", "note is gone"));
        }
        notes
            .remove(&nid)
            .ok_or_else(|| ApiError::new(StatusCode::GONE, "gone", "note is gone"))?
    };

    reset_pow_failures(&state, &client_key, now).await;

    // Move the ciphertext out so the store's copy (and its token hash) is zeroized right here;
    // the response copy is zeroized after serialization by SecretString.
    let blob = std::mem::take(&mut note.blob);
    drop(note);

    Ok(Json(ViewNoteResponse {
        ok: true,
        blob: SecretString(blob),
        deleted: true,
    }))
}

async fn security_headers_middleware(req: Request<Body>, next: Next) -> Response {
    let is_homepage = matches!(req.uri().path(), "/" | "/index.html");
    let mut response = next.run(req).await;
    let headers = response.headers_mut();

    headers.insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=63072000; includeSubDomains; preload"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; script-src 'self'; worker-src 'self'; child-src 'none'; frame-src 'none'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self' https:; manifest-src 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'; form-action 'none'",
        ),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, max-age=0"),
    );
    headers.insert(
        header::HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static(
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()",
        ),
    );

    if is_homepage {
        headers.insert(
            header::LINK,
            HeaderValue::from_static(r#"</.well-known/api-catalog>; rel="api-catalog""#),
        );
    }

    response
}

async fn api_catalog_handler(headers: HeaderMap) -> Response {
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .and_then(sanitize_authority)
        .unwrap_or_else(|| "localhost".to_owned());
    let host = host.strip_suffix(":443").unwrap_or(&host);
    let base = format!("https://{}", host);
    let catalog = serde_json::json!({
        "linkset": [
            {
                "anchor": &base,
                "api-catalog": [{"href": format!("{}/.well-known/api-catalog", base)}]
            },
            {
                "anchor": format!("{}/api/v1", base),
                "service-doc": [{"href": "https://github.com/pwn-all/secure-notes", "title": "SecNote API Documentation"}],
                "status": [{"href": format!("{}/info", base)}]
            }
        ]
    });
    let mut res = Response::new(Body::from(catalog.to_string()));
    *res.status_mut() = StatusCode::OK;
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/linkset+json"),
    );
    res
}

fn sanitize_authority(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > 300 || raw.contains('@') || raw.contains('/') {
        return None;
    }

    let authority = raw.parse::<Authority>().ok()?;
    let value = authority.as_str();
    if value.is_empty()
        || value.contains('@')
        || value.bytes().any(|b| {
            b.is_ascii_control()
                || b.is_ascii_whitespace()
                || matches!(b, b'/' | b'\\' | b'#' | b'?')
        })
    {
        return None;
    }
    let host = authority_host_without_port(value)?;
    if !is_valid_authority_host(host) {
        return None;
    }
    Some(value.to_ascii_lowercase())
}

fn authority_host_without_port(authority: &str) -> Option<&str> {
    if authority.starts_with('[') {
        let end = authority.find(']')?;
        let host = &authority[..=end];
        let suffix = &authority[end + 1..];
        if suffix.is_empty() || valid_authority_port_suffix(suffix) {
            return Some(host);
        }
        return None;
    }

    if authority.matches(':').count() > 1 {
        return None;
    }

    match authority.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && is_valid_authority_port(port) => Some(host),
        Some(_) => None,
        None => Some(authority),
    }
}

fn valid_authority_port_suffix(suffix: &str) -> bool {
    suffix
        .strip_prefix(':')
        .is_some_and(is_valid_authority_port)
}

fn is_valid_authority_port(port: &str) -> bool {
    !port.is_empty() && port.parse::<u16>().is_ok()
}

fn is_valid_authority_host(host: &str) -> bool {
    if host.starts_with('[') && host.ends_with(']') {
        return host[1..host.len() - 1]
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_ipv6());
    }

    if host.parse::<IpAddr>().is_ok() {
        return true;
    }

    let dns = host.trim_end_matches('.');
    if dns.is_empty() || dns.len() > 253 || !dns.is_ascii() {
        return false;
    }

    dns.split('.').all(is_valid_dns_label)
}

fn is_valid_dns_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    if bytes.is_empty() || bytes.len() > 63 {
        return false;
    }
    if !bytes[0].is_ascii_alphanumeric() || !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
        return false;
    }
    bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
}

fn is_base64url_no_pad(value: &str) -> bool {
    !value.is_empty()
        && value.len() % 4 != 1
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

fn is_valid_nid(nid: &str) -> bool {
    nid.len() == GENERATED_NID_B64_LEN && is_base64url_no_pad(nid)
}

fn decode_b64url_exact(
    value: &str,
    expected_len: usize,
    code: &'static str,
    message: &'static str,
) -> Result<Vec<u8>, ApiError> {
    if !is_base64url_no_pad(value) {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, code, message));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, code, message))?;
    if decoded.len() != expected_len {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, code, message));
    }
    Ok(decoded)
}

fn random_b64url(len: usize) -> String {
    URL_SAFE_NO_PAD.encode(random_bytes(len))
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    rand::rng().fill(bytes.as_mut_slice());
    bytes
}

fn now_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn validate_aes_blob_format(blob: &str) -> Result<usize, ApiError> {
    let decoded = URL_SAFE_NO_PAD.decode(blob).map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_format",
            "blob must be base64url",
        )
    })?;

    let min_len = NOTE_NONCE_BYTES + NOTE_TAG_BYTES;
    if decoded.len() < min_len {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_blob",
            "blob must contain nonce(12)+ciphertext+tag(16)",
        ));
    }

    Ok(decoded.len())
}

fn sha256_bytes(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().into()
}

fn constant_time_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.ct_eq(b).into()
}

fn payload_hash_for_create(ttl: u64, blob: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ttl.to_be_bytes());
    hasher.update(blob.as_bytes());
    hasher.finalize().into()
}

fn payload_hash_for_view(nid: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"view:");
    hasher.update(nid.as_bytes());
    hasher.finalize().into()
}

/// Decodes the proof nonce: `rounds` × 8 bytes, base64url without padding.
fn decode_pow_nonce(value: &str, spec: &PowSpec) -> Result<Vec<u8>, ApiError> {
    decode_b64url_exact(
        value,
        spec.nonce_bytes(),
        "invalid_nonce",
        "nonce must be 8 bytes per round, base64url",
    )
}

/// Checks a challenge against this client and endpoint and removes it from the map before
/// any proof is verified, so one challenge can trigger at most one Argon2id verification.
/// A rejected proof therefore burns the challenge; the client fetches a new one.
async fn take_challenge(
    state: &AppState,
    challenge: &str,
    client_key: &str,
    scope: PowScope,
    nonce: &str,
    now: u64,
) -> Result<(ChallengeEntry, Vec<u8>), ApiError> {
    // (error, counts as a PoW failure)
    let outcome: Result<(ChallengeEntry, Vec<u8>), (ApiError, bool)> = {
        let mut challenges = state.inner.challenges.lock().await;
        let checked = match challenges.get(challenge) {
            None => Err((
                ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "invalid_challenge",
                    "challenge is missing or already used",
                ),
                false,
            )),
            Some(entry) if entry.client_key != client_key => Err((
                ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "challenge_client_mismatch",
                    "challenge does not belong to this ip",
                ),
                true,
            )),
            Some(entry) if entry.expires_at <= now => Err((
                ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "challenge_expired",
                    "challenge has expired",
                ),
                false,
            )),
            Some(entry) if entry.scope != scope => Err((
                ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "challenge_scope_mismatch",
                    "challenge scope is invalid for this endpoint",
                ),
                true,
            )),
            Some(entry) => decode_pow_nonce(nonce, &entry.spec).map_err(|err| (err, false)),
        };
        match checked {
            Ok(nonce_bytes) => match challenges.remove(challenge) {
                Some(entry) => Ok((entry, nonce_bytes)),
                None => Err((
                    ApiError::new(
                        StatusCode::BAD_REQUEST,
                        "invalid_challenge",
                        "challenge is missing or already used",
                    ),
                    false,
                )),
            },
            Err(failure) => Err(failure),
        }
    };
    match outcome {
        Ok(taken) => Ok(taken),
        Err((err, counts_as_failure)) => {
            if counts_as_failure {
                register_pow_failure(state, client_key, now).await;
            }
            Err(err)
        }
    }
}

/// Argon2id salt: binds the proof to this challenge and to the exact payload.
fn argon2_pow_salt(challenge: &[u8], payload_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(POW_ARGON2_SALT_DOMAIN);
    hasher.update(challenge);
    hasher.update(payload_hash);
    hasher.finalize().into()
}

/// One Argon2id evaluation: `Argon2id(P = nonce, S = salt, p = 1, T = 32)`, version 0x13.
fn argon2_pow_tag(
    nonce: &[u8],
    salt: &[u8; 32],
    m_kib: u32,
    t_cost: u32,
) -> Result<[u8; POW_ARGON2_TAG_BYTES], argon2::Error> {
    let params = Params::new(m_kib, t_cost, 1, Some(POW_ARGON2_TAG_BYTES))?;
    let hasher = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut tag = [0u8; POW_ARGON2_TAG_BYTES];
    hasher.hash_password_into(nonce, salt, &mut tag)?;
    Ok(tag)
}

/// Every 8-byte nonce chunk must be a distinct Argon2id solution with `bits` leading zero
/// bits. Stops at the first failing chunk so garbage costs one evaluation.
fn verify_pow_argon2id(
    challenge: &[u8],
    nonce: &[u8],
    payload_hash: &[u8; 32],
    spec: &PowSpec,
) -> Result<bool, argon2::Error> {
    if nonce.len() != spec.nonce_bytes() || !pow_nonce_chunks_are_distinct(nonce) {
        return Ok(false);
    }
    let salt = argon2_pow_salt(challenge, payload_hash);
    for chunk in nonce.as_chunks::<POW_NONCE_BYTES>().0 {
        let tag = argon2_pow_tag(chunk, &salt, spec.m_kib, spec.t_cost)?;
        if !has_leading_zero_bits(&tag, spec.bits) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Repeating one solution `rounds` times must not count as `rounds` solutions.
fn pow_nonce_chunks_are_distinct(nonce: &[u8]) -> bool {
    let chunks = nonce.as_chunks::<POW_NONCE_BYTES>().0;
    chunks
        .iter()
        .enumerate()
        .all(|(i, a)| chunks[..i].iter().all(|b| a != b))
}

/// Verifies a proof against a taken challenge. Argon2id runs on the blocking pool behind
/// `POW_VERIFY_CONCURRENCY` permits so verification can never starve the async runtime.
async fn verify_pow(
    state: &AppState,
    entry: &ChallengeEntry,
    nonce: Vec<u8>,
    payload_hash: [u8; 32],
) -> Result<bool, ApiError> {
    let busy = || {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_busy",
            "proof verification unavailable",
        )
        .with_retry_after(5)
    };
    let _permit = state
        .inner
        .pow_verify_permits
        .acquire()
        .await
        .map_err(|_| busy())?;
    let challenge = entry.challenge_bytes.clone();
    let spec = entry.spec;
    let started = std::time::Instant::now();
    let verified = tokio::task::spawn_blocking(move || {
        verify_pow_argon2id(&challenge, &nonce, &payload_hash, &spec)
    })
    .await
    .map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "proof verification failed",
        )
    })?
    .map_err(|err| {
        tracing::error!(error = %err, "argon2id verification error");
        busy()
    })?;
    tracing::debug!(
        elapsed_ms = started.elapsed().as_millis() as u64,
        rounds = spec.rounds,
        m_kib = spec.m_kib,
        verified,
        "argon2id proof checked"
    );
    Ok(verified)
}

fn has_leading_zero_bits(digest: &[u8], bits: u8) -> bool {
    let full_bytes = (bits / 8) as usize;
    let rem_bits = bits % 8;

    if digest.len() < full_bytes {
        return false;
    }

    if digest.iter().take(full_bytes).any(|b| *b != 0) {
        return false;
    }

    if rem_bits == 0 {
        return true;
    }

    let mask = 0xFFu8 << (8 - rem_bits);
    digest
        .get(full_bytes)
        .map(|b| (b & mask) == 0)
        .unwrap_or(false)
}

fn client_key_from_ip(config: &AppConfig, ip: IpAddr) -> String {
    let mut hasher = Sha256::new();
    hasher.update(ip.to_string().as_bytes());
    hasher.update(&config.server_salt);
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

async fn ensure_not_banned(state: &AppState, client_key: &str, now: u64) -> Result<(), ApiError> {
    let mut abuse = state.inner.abuse.lock().await;
    if let Some(entry) = abuse.get_mut(client_key)
        && entry.banned_until > now
    {
        let retry_after = entry.banned_until.saturating_sub(now).max(1);
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "banned",
            "too many invalid PoW attempts",
        )
        .with_retry_after(retry_after));
    }
    Ok(())
}

async fn enforce_rate_limit(
    state: &AppState,
    client_key: &str,
    endpoint: Endpoint,
    now: u64,
) -> Result<(), ApiError> {
    let limit = match endpoint {
        Endpoint::Init => state.config().rate_limits.init_per_minute,
        Endpoint::Create => state.config().rate_limits.create_per_minute,
        Endpoint::View => state.config().rate_limits.view_per_minute,
    };

    if limit == 0 {
        return Ok(());
    }

    let map_key = format!("{}:{}", client_key, endpoint.as_str());
    let mut windows = state.inner.rate_windows.lock().await;
    if !windows.contains_key(&map_key) && windows.len() >= state.config().max_tracking_entries {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "too many clients",
        )
        .with_retry_after(60));
    }
    let entry = windows.entry(map_key).or_default();

    if now.saturating_sub(entry.window_start) >= 60 {
        entry.window_start = now;
        entry.count = 0;
    }

    if entry.count >= limit {
        let retry_after = 60u64
            .saturating_sub(now.saturating_sub(entry.window_start))
            .max(1);
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "too many requests",
        )
        .with_retry_after(retry_after));
    }

    entry.count = entry.count.saturating_add(1);
    Ok(())
}

async fn register_pow_failure(state: &AppState, client_key: &str, now: u64) {
    let window = state.config().pow_fail_window_secs;
    let mut abuse = state.inner.abuse.lock().await;
    if !abuse.contains_key(client_key) && abuse.len() >= state.config().max_tracking_entries {
        return;
    }
    let entry = abuse.entry(client_key.to_owned()).or_default();

    if entry.window_start == 0 || now.saturating_sub(entry.window_start) > window {
        entry.window_start = now;
        entry.fail_count = 0;
    }

    entry.fail_count = entry.fail_count.saturating_add(1);

    let ban_secs = if entry.fail_count >= 10 {
        state.config().ban_long_secs
    } else if entry.fail_count >= 6 {
        state.config().ban_medium_secs
    } else if entry.fail_count >= 3 {
        state.config().ban_short_secs
    } else {
        0
    };

    if ban_secs > 0 {
        entry.banned_until = now.saturating_add(ban_secs);
    }
}

async fn reset_pow_failures(state: &AppState, client_key: &str, now: u64) {
    let mut abuse = state.inner.abuse.lock().await;
    if let Some(entry) = abuse.get_mut(client_key) {
        entry.fail_count = 0;
        entry.window_start = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, Request, StatusCode};
    use http_body_util::BodyExt;
    use serde_json::{Value, json};
    use tower::ServiceExt;

    /// Argon2id with the smallest supported memory and one round, so handler tests stay fast
    /// in debug builds; difficulty-specific tests raise bits and rounds explicitly.
    fn test_config() -> AppConfig {
        AppConfig {
            server_salt: vec![42u8; 32],
            challenge_ttl_secs: 5,
            pow_bits_create: 1,
            pow_bits_create_max: 2,
            pow_bits_view: 1,
            pow_bits_view_max: 1,
            pow_rounds_create: 1,
            pow_rounds_view: 1,
            pow_argon2_m_kib: 256,
            pow_argon2_t: 1,
            pow_verify_concurrency: 2,
            publish_passport: true,
            max_plaintext_bytes: 32768,
            max_blob_bytes: 48 * 1024,
            max_file_bytes: 0,
            upload_timeout_secs: DEFAULT_UPLOAD_TIMEOUT_SECS,
            max_active_challenges: DEFAULT_MAX_ACTIVE_CHALLENGES,
            max_notes: DEFAULT_MAX_NOTES,
            max_note_storage_bytes: 64 * 1024 * 1024,
            max_concurrent_api_requests: 64,
            max_tracking_entries: DEFAULT_MAX_TRACKING_ENTRIES,
            pow_fail_window_secs: 600,
            ban_short_secs: 300,
            ban_medium_secs: 1800,
            ban_long_secs: 3600,
            cleanup_interval_secs: 30,
            rate_limits: RateLimits {
                init_per_minute: 100,
                create_per_minute: 100,
                view_per_minute: 100,
            },
        }
    }

    async fn send_json(
        app: &Router,
        method: Method,
        uri: &str,
        body: Option<Value>,
    ) -> (StatusCode, HeaderMap, Value) {
        send_json_as(app, method, uri, body, "203.0.113.10").await
    }

    async fn send_json_as(
        app: &Router,
        method: Method,
        uri: &str,
        body: Option<Value>,
        ip: &str,
    ) -> (StatusCode, HeaderMap, Value) {
        let addr = SocketAddr::new(ip.parse().expect("test ip must parse"), 40_000);
        let builder = Request::builder()
            .method(method)
            .uri(uri)
            .extension(ConnectInfo(addr))
            .header(header::CONTENT_TYPE, "application/json");

        let request = if let Some(body) = body {
            builder
                .body(Body::from(body.to_string()))
                .expect("request should build")
        } else {
            builder.body(Body::empty()).expect("request should build")
        };

        let response = app
            .clone()
            .oneshot(request)
            .await
            .expect("router should respond");

        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body must collect")
            .to_bytes();
        let json: Value = serde_json::from_slice(&bytes).expect("valid json response");

        (status, headers, json)
    }

    /// Parses the scheme `/api/v1/init` advertised, as the client sees it.
    fn spec_from_init(body: &Value) -> PowSpec {
        let pow = &body["pow"];
        assert_eq!(pow["alg"], POW_ALG_ARGON2ID);
        assert_eq!(pow["params"]["p"], json!(1));
        assert_eq!(pow["params"]["tag_bytes"], json!(POW_ARGON2_TAG_BYTES));
        assert_eq!(pow["params"]["nonce_bytes"], json!(POW_NONCE_BYTES));
        PowSpec {
            bits: pow["bits"].as_u64().expect("bits") as u8,
            rounds: pow["rounds"].as_u64().expect("rounds") as u8,
            m_kib: pow["params"]["m_kib"].as_u64().expect("m_kib") as u32,
            t_cost: pow["params"]["t"].as_u64().expect("t") as u32,
        }
    }

    /// Solves a challenge exactly like the frontend worker: counter nonces, one Argon2id
    /// evaluation per attempt, `rounds` distinct solutions concatenated.
    fn solve_pow(challenge_b64: &str, spec: PowSpec, payload_hash: &[u8; 32]) -> String {
        let challenge = URL_SAFE_NO_PAD
            .decode(challenge_b64)
            .expect("challenge must decode");
        let salt = argon2_pow_salt(&challenge, payload_hash);
        let mut solutions: Vec<u8> = Vec::new();
        let mut found = 0u8;
        for counter in 0u64.. {
            let candidate = counter.to_le_bytes();
            let tag = argon2_pow_tag(&candidate, &salt, spec.m_kib, spec.t_cost)
                .expect("argon2id parameters are valid");
            if has_leading_zero_bits(&tag, spec.bits) {
                solutions.extend_from_slice(&candidate);
                found += 1;
                if found == spec.rounds {
                    return URL_SAFE_NO_PAD.encode(solutions);
                }
            }
        }
        unreachable!("nonce space is practically unbounded")
    }

    /// A well-formed nonce (distinct chunks, right length) whose first chunk is not a solution.
    fn unsolved_nonce(challenge_b64: &str, spec: PowSpec, payload_hash: &[u8; 32]) -> String {
        let challenge = URL_SAFE_NO_PAD
            .decode(challenge_b64)
            .expect("challenge must decode");
        let salt = argon2_pow_salt(&challenge, payload_hash);
        let first = (0u64..)
            .map(u64::to_le_bytes)
            .find(|candidate| {
                let tag = argon2_pow_tag(candidate, &salt, spec.m_kib, spec.t_cost).unwrap();
                !has_leading_zero_bits(&tag, spec.bits)
            })
            .expect("must find an unsolved nonce");
        let mut nonce = first.to_vec();
        for round in 1..spec.rounds {
            nonce.extend_from_slice(&(u64::MAX - u64::from(round)).to_le_bytes());
        }
        URL_SAFE_NO_PAD.encode(nonce)
    }

    fn solve_pow_for_create(challenge_b64: &str, spec: PowSpec, ttl: u64, blob: &str) -> String {
        solve_pow(challenge_b64, spec, &payload_hash_for_create(ttl, blob))
    }

    fn fake_aes_blob(seed: &[u8]) -> String {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0x11u8; NOTE_NONCE_BYTES]);
        bytes.extend_from_slice(seed);
        bytes.extend_from_slice(&[0x22u8; NOTE_TAG_BYTES]);
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn test_view_token() -> String {
        URL_SAFE_NO_PAD.encode(vec![0x33u8; 32])
    }

    fn solve_pow_for_view(challenge_b64: &str, spec: PowSpec, nid: &str) -> String {
        solve_pow(challenge_b64, spec, &payload_hash_for_view(nid))
    }

    async fn init_once(app: &Router, scope: &str) -> (String, PowSpec) {
        let (status, _, body) = send_json(
            app,
            Method::GET,
            &format!("/api/v1/init?scope={scope}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["ok"], Value::Bool(true));

        (
            body["pow"]["challenge"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
            spec_from_init(&body),
        )
    }

    async fn create_test_note(app: &Router, blob: &str) -> (StatusCode, Value) {
        let (challenge, bits) = init_once(app, "create").await;
        let ttl = NOTE_TTLS[0];
        let nonce = solve_pow_for_create(&challenge, bits, ttl, blob);
        let (status, _, body) = send_json(
            app,
            Method::POST,
            "/api/v1/notes",
            Some(json!({
                "alg": NOTE_ALG, "challenge": challenge, "nonce": nonce, "ttl": ttl,
                "blob": blob, "view_token": test_view_token()
            })),
        )
        .await;
        (status, body)
    }

    #[tokio::test]
    async fn note_storage_budget_is_released_after_read_and_expiry() {
        let blob = fake_aes_blob(b"budget test");
        let mut config = test_config();
        config.max_note_storage_bytes = blob.len();
        let state = AppState::new(config);
        let app = build_router(state.clone());
        let (status, body) = create_test_note(&app, &blob).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            create_test_note(&app, &blob).await.0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        let nid = body["nid"].as_str().unwrap();
        let (challenge, bits) = init_once(&app, "view").await;
        let nonce = solve_pow_for_view(&challenge, bits, nid);
        let (status, _, _) = send_json(
            &app,
            Method::POST,
            &format!("/api/v1/notes/{nid}/view"),
            Some(json!({
                "challenge": challenge, "nonce": nonce, "view_token": test_view_token()
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(state.inner.notes.lock().await.blob_bytes, 0);
        assert_eq!(create_test_note(&app, &blob).await.0, StatusCode::OK);
        state.cleanup_expired(now_ts() + NOTE_TTLS[0] + 1).await;
        assert_eq!(state.inner.notes.lock().await.blob_bytes, 0);
        assert_eq!(create_test_note(&app, &blob).await.0, StatusCode::OK);
    }

    #[tokio::test]
    async fn active_request_limit_rejects_overload_and_recovers() {
        let mut config = test_config();
        config.max_concurrent_api_requests = 1;
        let state = AppState::new(config);
        let app = build_router(state.clone());
        let permit = state.inner.api_permits.acquire().await.unwrap();
        let (status, headers, body) = send_json(&app, Method::GET, "/info", None).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"]["code"], "server_busy");
        assert!(headers.contains_key(header::RETRY_AFTER));
        drop(permit);
        assert_eq!(
            send_json(&app, Method::GET, "/info", None).await.0,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn request_body_limit_applies_before_json_parsing() {
        let mut config = test_config();
        config.max_blob_bytes = 100;
        let app = build_router(AppState::new(config));
        let (status, _, body) = send_json(
            &app,
            Method::POST,
            "/api/v1/notes",
            Some(json!({
                "padding": "x".repeat(JSON_BODY_OVERHEAD_BYTES + 101)
            })),
        )
        .await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(body["error"]["code"], "body_too_large");
    }

    #[tokio::test]
    async fn signatures_bind_status_method_target_nonce_and_request_body() {
        use ed25519_dalek::Signature;
        let key = SigningKey::from_bytes(&[7; 32]);
        let verify_key = key.verifying_key();
        let app = build_router(AppState::with_signing_key(test_config(), Some(key)));
        let request_id = URL_SAFE_NO_PAD.encode([1; 16]);
        let target = "/api/v1/init?scope=invalid";
        let request_body = b"{}";
        let request = Request::builder()
            .method(Method::GET)
            .uri(target)
            .extension(ConnectInfo(
                "203.0.113.10:40000".parse::<SocketAddr>().unwrap(),
            ))
            .header(REQUEST_ID_HEADER, &request_id)
            .body(Body::from(request_body.as_slice()))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let signature = Signature::from_slice(
            &URL_SAFE_NO_PAD
                .decode(response.headers()[SIGNATURE_V2_HEADER].as_bytes())
                .unwrap(),
        )
        .unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let request_hash = URL_SAFE_NO_PAD.encode(sha256_bytes(request_body));
        let message = response_signature_message(
            "GET",
            target,
            &request_id,
            &request_hash,
            StatusCode::BAD_REQUEST,
            &body,
        );
        assert!(verify_key.verify_strict(&message, &signature).is_ok());
        for mutated in [
            response_signature_message(
                "POST",
                target,
                &request_id,
                &request_hash,
                StatusCode::BAD_REQUEST,
                &body,
            ),
            response_signature_message(
                "GET",
                "/info",
                &request_id,
                &request_hash,
                StatusCode::BAD_REQUEST,
                &body,
            ),
            response_signature_message(
                "GET",
                target,
                "another-request",
                &request_hash,
                StatusCode::BAD_REQUEST,
                &body,
            ),
            response_signature_message(
                "GET",
                target,
                &request_id,
                "another-body",
                StatusCode::BAD_REQUEST,
                &body,
            ),
            response_signature_message(
                "GET",
                target,
                &request_id,
                &request_hash,
                StatusCode::OK,
                &body,
            ),
            response_signature_message(
                "GET",
                target,
                &request_id,
                &request_hash,
                StatusCode::BAD_REQUEST,
                b"tampered",
            ),
        ] {
            assert!(verify_key.verify_strict(&mutated, &signature).is_err());
        }
    }

    #[tokio::test]
    async fn server_signature_matches_the_frontend_interoperability_vector() {
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/signed-response.json")).unwrap();
        let mut config = test_config();
        // The passport carries the start time; keep the signed vector deterministic.
        config.publish_passport = false;
        let app = build_router(AppState::with_signing_key(
            config,
            Some(SigningKey::from_bytes(&[7; 32])),
        ));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/info")
                    .header(
                        REQUEST_ID_HEADER,
                        fixture["context"]["requestId"].as_str().unwrap(),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.headers()[SIGNATURE_V2_HEADER],
            fixture["signature"].as_str().unwrap()
        );
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], fixture["body"].as_str().unwrap().as_bytes());
    }

    #[tokio::test]
    async fn cors_supports_signed_requests_from_an_offline_frontend() {
        let app = build_router(AppState::new(test_config()));
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/api/v1/notes")
                    .header(header::ORIGIN, "null")
                    .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                    .header(
                        header::ACCESS_CONTROL_REQUEST_HEADERS,
                        "content-type,x-secnote-request-id",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
        assert!(
            response.headers()[header::ACCESS_CONTROL_ALLOW_HEADERS]
                .to_str()
                .unwrap()
                .contains(REQUEST_ID_HEADER)
        );
    }

    #[tokio::test]
    async fn happy_path_read_once_then_gone() {
        let state = AppState::new(test_config());
        let app = build_router(state);

        let (challenge, bits) = init_once(&app, "create").await;
        let blob = fake_aes_blob(b"nonce_and_ciphertext");
        let ttl = 43_200u64;
        let nonce = solve_pow_for_create(&challenge, bits, ttl, &blob);

        let (send_status, _, send_body) = send_json(
            &app,
            Method::POST,
            "/api/v1/notes",
            Some(json!({
                "alg": "aes-256-gcm",
                "challenge": challenge,
                "nonce": nonce,
                "ttl": ttl,
                "blob": blob,
                "view_token": test_view_token()
            })),
        )
        .await;

        assert_eq!(send_status, StatusCode::OK);
        assert_eq!(send_body["ok"], Value::Bool(true));
        let nid = send_body["nid"].as_str().expect("nid should exist");

        let (view_challenge, view_bits) = init_once(&app, "view").await;
        let view_nonce = solve_pow_for_view(&view_challenge, view_bits, nid);
        let (view_status, _, view_body) = send_json(
            &app,
            Method::POST,
            &format!("/api/v1/notes/{nid}/view"),
            Some(json!({
                "challenge": view_challenge,
                "nonce": view_nonce,
                "view_token": test_view_token()
            })),
        )
        .await;
        assert_eq!(view_status, StatusCode::OK);
        assert_eq!(view_body["ok"], Value::Bool(true));
        assert_eq!(view_body["deleted"], Value::Bool(true));

        let (view_challenge2, view_bits2) = init_once(&app, "view").await;
        let view_nonce2 = solve_pow_for_view(&view_challenge2, view_bits2, nid);
        let (view_status2, _, view_body2) = send_json(
            &app,
            Method::POST,
            &format!("/api/v1/notes/{nid}/view"),
            Some(json!({
                "challenge": view_challenge2,
                "nonce": view_nonce2,
                "view_token": test_view_token()
            })),
        )
        .await;
        assert_eq!(view_status2, StatusCode::GONE);
        assert_eq!(
            view_body2["error"]["code"],
            Value::String("gone".to_owned())
        );
    }

    #[tokio::test]
    async fn security_headers_are_present_and_restrictive() {
        let state = AppState::new(test_config());
        let app = build_router(state);

        let (status, headers, _) = send_json(&app, Method::GET, "/info", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers.get(header::STRICT_TRANSPORT_SECURITY),
            Some(&HeaderValue::from_static(
                "max-age=63072000; includeSubDomains; preload"
            ))
        );
        assert_eq!(
            headers.get(header::X_FRAME_OPTIONS),
            Some(&HeaderValue::from_static("DENY"))
        );
        assert_eq!(
            headers.get(header::CONTENT_SECURITY_POLICY),
            Some(&HeaderValue::from_static(
                "default-src 'none'; script-src 'self'; worker-src 'self'; child-src 'none'; frame-src 'none'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self' https:; manifest-src 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'; form-action 'none'"
            ))
        );
    }

    #[tokio::test]
    async fn invalid_ttl_rejected() {
        let state = AppState::new(test_config());
        let app = build_router(state);

        let (challenge, bits) = init_once(&app, "create").await;
        let blob = fake_aes_blob(b"ciphertext");
        let nonce = solve_pow_for_create(&challenge, bits, 43_200, &blob);

        let (status, _, body) = send_json(
            &app,
            Method::POST,
            "/api/v1/notes",
            Some(json!({
                "alg": "aes-256-gcm",
                "challenge": challenge,
                "nonce": nonce,
                "ttl": 60,
                "blob": blob,
                "view_token": test_view_token()
            })),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body["error"]["code"],
            Value::String("invalid_ttl".to_owned())
        );
    }

    #[tokio::test]
    async fn invalid_alg_rejected() {
        let state = AppState::new(test_config());
        let app = build_router(state);

        let (challenge, bits) = init_once(&app, "create").await;
        let blob = fake_aes_blob(b"ciphertext");
        let nonce = solve_pow_for_create(&challenge, bits, 43_200, &blob);

        let (status, _, body) = send_json(
            &app,
            Method::POST,
            "/api/v1/notes",
            Some(json!({
                "alg": "aes-128-gcm",
                "challenge": challenge,
                "nonce": nonce,
                "ttl": 43200,
                "blob": blob,
                "view_token": test_view_token()
            })),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body["error"]["code"],
            Value::String("invalid_alg".to_owned())
        );
    }

    #[tokio::test]
    async fn oversized_blob_rejected() {
        let mut cfg = test_config();
        cfg.max_blob_bytes = 10;
        let state = AppState::new(cfg);
        let app = build_router(state);

        let (challenge, bits) = init_once(&app, "create").await;
        let blob = fake_aes_blob(b"this_is_longer_than_ten_bytes");
        let nonce = solve_pow_for_create(&challenge, bits, 43_200, &blob);

        let (status, _, body) = send_json(
            &app,
            Method::POST,
            "/api/v1/notes",
            Some(json!({
                "alg": "aes-256-gcm",
                "challenge": challenge,
                "nonce": nonce,
                "ttl": 43200,
                "blob": blob,
                "view_token": test_view_token()
            })),
        )
        .await;

        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            body["error"]["code"],
            Value::String("blob_too_large".to_owned())
        );
    }

    #[tokio::test]
    async fn plaintext_too_large_rejected() {
        let state = AppState::new(test_config());
        let app = build_router(state);

        let (challenge, bits) = init_once(&app, "create").await;
        let oversized_plaintext = vec![b'a'; 32769];
        let blob = fake_aes_blob(&oversized_plaintext);
        let nonce = solve_pow_for_create(&challenge, bits, 43_200, &blob);

        let (status, _, body) = send_json(
            &app,
            Method::POST,
            "/api/v1/notes",
            Some(json!({
                "alg": "aes-256-gcm",
                "challenge": challenge,
                "nonce": nonce,
                "ttl": 43200,
                "blob": blob,
                "view_token": test_view_token()
            })),
        )
        .await;

        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            body["error"]["code"],
            Value::String("plaintext_too_large".to_owned())
        );
    }

    #[tokio::test]
    async fn payload_bound_pow_rejects_mutated_blob() {
        let state = AppState::new(test_config());
        let app = build_router(state);
        let blob_a = fake_aes_blob(b"blob_a");
        let blob_b = fake_aes_blob(b"blob_b");

        // A low-difficulty proof can also satisfy another payload by chance; pick a challenge
        // where it does not, so the assertion below is about binding, not luck.
        let (challenge, nonce) = loop {
            let (challenge, spec) = init_once(&app, "create").await;
            let nonce = solve_pow_for_create(&challenge, spec, 43_200, &blob_a);
            let challenge_bytes = URL_SAFE_NO_PAD.decode(&challenge).unwrap();
            let nonce_bytes = URL_SAFE_NO_PAD.decode(&nonce).unwrap();
            let other = payload_hash_for_create(43_200, &blob_b);
            if !verify_pow_argon2id(&challenge_bytes, &nonce_bytes, &other, &spec).unwrap() {
                break (challenge, nonce);
            }
        };

        let (status, _, body) = send_json(
            &app,
            Method::POST,
            "/api/v1/notes",
            Some(json!({
                "alg": "aes-256-gcm",
                "challenge": challenge,
                "nonce": nonce,
                "ttl": 43200,
                "blob": blob_b,
                "view_token": test_view_token()
            })),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body["error"]["code"],
            Value::String("invalid_pow".to_owned())
        );

        // The rejected proof burned the challenge: the genuine payload cannot reuse it.
        let (status, _, body) = send_json(
            &app,
            Method::POST,
            "/api/v1/notes",
            Some(json!({
                "alg": "aes-256-gcm",
                "challenge": challenge,
                "nonce": nonce,
                "ttl": 43200,
                "blob": blob_a,
                "view_token": test_view_token()
            })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body["error"]["code"],
            Value::String("invalid_challenge".to_owned())
        );
    }

    #[tokio::test]
    async fn pow_challenges_are_bound_to_endpoint_scope() {
        let state = AppState::new(test_config());
        let app = build_router(state);

        let (view_challenge, view_bits) = init_once(&app, "view").await;
        let blob = fake_aes_blob(b"wrong_scope_create");
        let create_nonce = solve_pow_for_create(&view_challenge, view_bits, 43_200, &blob);
        let (create_status, _, create_body) = send_json(
            &app,
            Method::POST,
            "/api/v1/notes",
            Some(json!({
                "alg": "aes-256-gcm",
                "challenge": view_challenge,
                "nonce": create_nonce,
                "ttl": 43200,
                "blob": blob,
                "view_token": test_view_token()
            })),
        )
        .await;
        assert_eq!(create_status, StatusCode::BAD_REQUEST);
        assert_eq!(
            create_body["error"]["code"],
            Value::String("challenge_scope_mismatch".to_owned())
        );

        let (challenge, bits) = init_once(&app, "create").await;
        let blob = fake_aes_blob(b"valid_note_for_scope_test");
        let nonce = solve_pow_for_create(&challenge, bits, 43_200, &blob);
        let (send_status, _, send_body) = send_json(
            &app,
            Method::POST,
            "/api/v1/notes",
            Some(json!({
                "alg": "aes-256-gcm",
                "challenge": challenge,
                "nonce": nonce,
                "ttl": 43200,
                "blob": blob,
                "view_token": test_view_token()
            })),
        )
        .await;
        assert_eq!(send_status, StatusCode::OK);
        let nid = send_body["nid"]
            .as_str()
            .expect("nid should exist")
            .to_owned();

        let (create_challenge, create_bits) = init_once(&app, "create").await;
        let view_nonce = solve_pow_for_view(&create_challenge, create_bits, &nid);
        let (view_status, _, view_body) = send_json(
            &app,
            Method::POST,
            &format!("/api/v1/notes/{nid}/view"),
            Some(json!({
                "challenge": create_challenge,
                "nonce": view_nonce,
                "view_token": test_view_token()
            })),
        )
        .await;
        assert_eq!(view_status, StatusCode::BAD_REQUEST);
        assert_eq!(
            view_body["error"]["code"],
            Value::String("challenge_scope_mismatch".to_owned())
        );
    }

    #[tokio::test]
    async fn invalid_view_token_does_not_burn_note() {
        let state = AppState::new(test_config());
        let app = build_router(state);

        let (challenge, bits) = init_once(&app, "create").await;
        let blob = fake_aes_blob(b"nonce_and_ciphertext");
        let ttl = 43_200u64;
        let nonce = solve_pow_for_create(&challenge, bits, ttl, &blob);

        let (send_status, _, send_body) = send_json(
            &app,
            Method::POST,
            "/api/v1/notes",
            Some(json!({
                "alg": "aes-256-gcm",
                "challenge": challenge,
                "nonce": nonce,
                "ttl": ttl,
                "blob": blob,
                "view_token": test_view_token()
            })),
        )
        .await;
        assert_eq!(send_status, StatusCode::OK);
        let nid = send_body["nid"]
            .as_str()
            .expect("nid should exist")
            .to_owned();

        let (bad_view_challenge, bad_view_bits) = init_once(&app, "view").await;
        let bad_view_nonce = solve_pow_for_view(&bad_view_challenge, bad_view_bits, &nid);
        let wrong_token = URL_SAFE_NO_PAD.encode(vec![0x44u8; 32]);
        let (bad_status, _, bad_body) = send_json(
            &app,
            Method::POST,
            &format!("/api/v1/notes/{nid}/view"),
            Some(json!({
                "challenge": bad_view_challenge,
                "nonce": bad_view_nonce,
                "view_token": wrong_token
            })),
        )
        .await;
        assert_eq!(bad_status, StatusCode::GONE);
        assert_eq!(bad_body["error"]["code"], Value::String("gone".to_owned()));

        let (good_view_challenge, good_view_bits) = init_once(&app, "view").await;
        let good_view_nonce = solve_pow_for_view(&good_view_challenge, good_view_bits, &nid);
        let (good_status, _, good_body) = send_json(
            &app,
            Method::POST,
            &format!("/api/v1/notes/{nid}/view"),
            Some(json!({
                "challenge": good_view_challenge,
                "nonce": good_view_nonce,
                "view_token": test_view_token()
            })),
        )
        .await;
        assert_eq!(good_status, StatusCode::OK);
        assert_eq!(good_body["ok"], Value::Bool(true));
    }

    #[tokio::test]
    async fn wrong_pow_leads_to_progressive_ban_with_retry_after() {
        let mut cfg = test_config();
        cfg.ban_short_secs = 600;
        let state = AppState::new(cfg);
        let app = build_router(state);

        for _ in 0..3 {
            let (challenge, bits) = init_once(&app, "create").await;
            let challenge_bytes = URL_SAFE_NO_PAD
                .decode(challenge)
                .expect("challenge must decode");
            let blob = fake_aes_blob(b"ciphertext");
            let ttl = 43_200u64;
            let wrong_nonce = URL_SAFE_NO_PAD
                .decode(unsolved_nonce(
                    &URL_SAFE_NO_PAD.encode(&challenge_bytes),
                    bits,
                    &payload_hash_for_create(ttl, &blob),
                ))
                .unwrap();

            let (status, _, body) = send_json(
                &app,
                Method::POST,
                "/api/v1/notes",
                Some(json!({
                    "alg": "aes-256-gcm",
                    "challenge": URL_SAFE_NO_PAD.encode(challenge_bytes.clone()),
                    "nonce": URL_SAFE_NO_PAD.encode(wrong_nonce),
                    "ttl": ttl,
                    "blob": blob,
                    "view_token": test_view_token()
                })),
            )
            .await;

            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(
                body["error"]["code"],
                Value::String("invalid_pow".to_owned())
            );
        }

        let (status, headers, body) = send_json(&app, Method::GET, "/api/v1/init", None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"]["code"], Value::String("banned".to_owned()));
        assert!(headers.get(header::RETRY_AFTER).is_some());
    }

    #[tokio::test]
    async fn challenge_expiry_is_enforced() {
        let mut cfg = test_config();
        cfg.challenge_ttl_secs = 1;
        let state = AppState::new(cfg);
        let app = build_router(state);

        let (challenge, bits) = init_once(&app, "create").await;
        let blob = fake_aes_blob(b"ciphertext");
        let nonce = solve_pow_for_create(&challenge, bits, 43_200, &blob);

        tokio::time::sleep(Duration::from_secs(2)).await;

        let (status, _, body) = send_json(
            &app,
            Method::POST,
            "/api/v1/notes",
            Some(json!({
                "alg": "aes-256-gcm",
                "challenge": challenge,
                "nonce": nonce,
                "ttl": 43200,
                "blob": blob,
                "view_token": test_view_token()
            })),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body["error"]["code"],
            Value::String("challenge_expired".to_owned())
        );
    }

    #[tokio::test]
    async fn init_issues_distinct_challenges_for_same_ip_and_scope() {
        let cfg = test_config();
        let state = AppState::new(cfg);
        let app = build_router(state);

        let ip = "203.0.113.77";

        let (s1, _, b1) =
            send_json_as(&app, Method::GET, "/api/v1/init?scope=create", None, ip).await;
        assert_eq!(s1, StatusCode::OK);
        let challenge = b1["pow"]["challenge"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let bits = spec_from_init(&b1);

        let (s2, _, b2) =
            send_json_as(&app, Method::GET, "/api/v1/init?scope=create", None, ip).await;
        assert_eq!(s2, StatusCode::OK);
        let challenge2 = b2["pow"]["challenge"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let bits2 = spec_from_init(&b2);
        assert_ne!(challenge, challenge2);
        assert_eq!(bits, bits2);

        let blob = fake_aes_blob(b"same-ip-different-ua");
        let nonce = solve_pow_for_create(&challenge, bits, 43_200, &blob);
        let (s3, _, b3) = send_json_as(
            &app,
            Method::POST,
            "/api/v1/notes",
            Some(json!({
                "alg": "aes-256-gcm",
                "challenge": challenge,
                "nonce": nonce,
                "ttl": 43200,
                "blob": blob,
                "view_token": test_view_token()
            })),
            ip,
        )
        .await;
        assert_eq!(s3, StatusCode::OK);
        assert_eq!(b3["ok"], Value::Bool(true));
    }

    #[tokio::test]
    async fn rate_limit_is_enforced_with_retry_after() {
        let mut cfg = test_config();
        cfg.rate_limits.init_per_minute = 1;
        let state = AppState::new(cfg);
        let app = build_router(state);

        let (status1, _, _) = send_json(&app, Method::GET, "/api/v1/init", None).await;
        assert_eq!(status1, StatusCode::OK);

        let (status2, headers2, body2) = send_json(&app, Method::GET, "/api/v1/init", None).await;
        assert_eq!(status2, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            body2["error"]["code"],
            Value::String("rate_limited".to_owned())
        );
        assert!(headers2.get(header::RETRY_AFTER).is_some());
    }

    #[tokio::test]
    async fn info_endpoint_returns_anonymous_aggregate_data() {
        let state = AppState::new(test_config());
        let app = build_router(state);

        let (status, _, body) = send_json(&app, Method::GET, "/info", None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["notes"].is_u64());
        assert!(body["ram_usage"].is_string());
        assert!(
            body["ram_usage"]
                .as_str()
                .unwrap_or_default()
                .ends_with(" mb")
        );
    }

    #[tokio::test]
    async fn e2e_read_once_is_atomic_under_parallel_view_requests() {
        let mut cfg = test_config();
        cfg.challenge_ttl_secs = 60;
        cfg.rate_limits = RateLimits {
            init_per_minute: 1_000,
            create_per_minute: 1_000,
            view_per_minute: 1_000,
        };
        let state = AppState::new(cfg);
        let app = build_router(state);

        let create_ip = "203.0.113.20";
        let (challenge, bits, _) = {
            let (status, _, body) = send_json_as(
                &app,
                Method::GET,
                "/api/v1/init?scope=create",
                None,
                create_ip,
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            (
                body["pow"]["challenge"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
                spec_from_init(&body),
                body,
            )
        };
        let blob = fake_aes_blob(b"nonce_and_ciphertext_e2e");
        let nonce = solve_pow_for_create(&challenge, bits, 43_200, &blob);
        let (send_status, _, send_body) = send_json_as(
            &app,
            Method::POST,
            "/api/v1/notes",
            Some(json!({
                "alg": "aes-256-gcm",
                "challenge": challenge,
                "nonce": nonce,
                "ttl": 43200,
                "blob": blob,
                "view_token": test_view_token()
            })),
            create_ip,
        )
        .await;
        assert_eq!(send_status, StatusCode::OK);
        let nid = send_body["nid"]
            .as_str()
            .expect("nid must exist")
            .to_owned();

        let mut tasks: Vec<tokio::task::JoinHandle<StatusCode>> = Vec::new();
        for idx in 0..20 {
            let app = app.clone();
            let nid = nid.clone();
            tasks.push(tokio::spawn(async move {
                let ip = format!("203.0.113.{}", 60 + idx);
                let (init_status, _, init_body) =
                    send_json_as(&app, Method::GET, "/api/v1/init?scope=view", None, &ip).await;
                assert_eq!(init_status, StatusCode::OK);
                let challenge = init_body["pow"]["challenge"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned();
                let bits = spec_from_init(&init_body);
                let nonce = solve_pow_for_view(&challenge, bits, &nid);
                let (status, _, _) = send_json_as(
                    &app,
                    Method::POST,
                    &format!("/api/v1/notes/{nid}/view"),
                    Some(json!({
                        "challenge": challenge,
                        "nonce": nonce,
                        "view_token": test_view_token()
                    })),
                    &ip,
                )
                .await;
                status
            }));
        }

        let mut ok_count = 0usize;
        let mut gone_count = 0usize;
        for task in tasks {
            let status = task.await.expect("task should not panic");
            if status == StatusCode::OK {
                ok_count += 1;
            } else if status == StatusCode::GONE {
                gone_count += 1;
            }
        }

        assert_eq!(ok_count, 1, "exactly one reader must get the note");
        assert_eq!(gone_count, 19, "all other readers must get gone");
    }

    #[tokio::test]
    async fn e2e_challenge_is_one_time_under_parallel_send_requests() {
        let mut cfg = test_config();
        cfg.challenge_ttl_secs = 60;
        cfg.rate_limits = RateLimits {
            init_per_minute: 1_000,
            create_per_minute: 1_000,
            view_per_minute: 1_000,
        };
        let state = AppState::new(cfg);
        let app = build_router(state);

        let ip = "203.0.113.20";
        let (challenge, bits): (String, PowSpec) = {
            let (status, _, body) =
                send_json_as(&app, Method::GET, "/api/v1/init?scope=create", None, ip).await;
            assert_eq!(status, StatusCode::OK);
            (
                body["pow"]["challenge"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
                spec_from_init(&body),
            )
        };
        let blob = fake_aes_blob(b"nonce_and_ciphertext");
        let nonce = solve_pow_for_create(&challenge, bits, 43_200, &blob);

        let mut tasks: Vec<tokio::task::JoinHandle<(StatusCode, String)>> = Vec::new();
        for _ in 0..2 {
            let app = app.clone();
            let challenge = challenge.clone();
            let nonce = nonce.clone();
            let blob = blob.clone();
            let ip = ip.to_owned();
            tasks.push(tokio::spawn(async move {
                let (status, _, body) = send_json_as(
                    &app,
                    Method::POST,
                    "/api/v1/notes",
                    Some(json!({
                        "alg": "aes-256-gcm",
                        "challenge": challenge,
                        "nonce": nonce,
                        "ttl": 43200,
                        "blob": blob,
                        "view_token": test_view_token()
                    })),
                    &ip,
                )
                .await;
                (
                    status,
                    body["error"]["code"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned(),
                )
            }));
        }

        let mut success_count = 0usize;
        let mut invalid_challenge_count = 0usize;
        for task in tasks {
            let (status, error_code) = task.await.expect("task should not panic");
            if status == StatusCode::OK {
                success_count += 1;
            } else if status == StatusCode::BAD_REQUEST && error_code == "invalid_challenge" {
                invalid_challenge_count += 1;
            }
        }

        assert_eq!(success_count, 1, "challenge must be consumed once");
        assert_eq!(
            invalid_challenge_count, 1,
            "second request must fail because challenge is one-time"
        );
    }

    #[tokio::test]
    async fn e2e_parallel_pow_and_send_requests_succeed() {
        let mut cfg = test_config();
        cfg.challenge_ttl_secs = 60;
        cfg.rate_limits = RateLimits {
            init_per_minute: 1_000,
            create_per_minute: 1_000,
            view_per_minute: 1_000,
        };
        let state = AppState::new(cfg);
        let app = build_router(state);

        let mut tasks: Vec<tokio::task::JoinHandle<(StatusCode, Option<String>)>> = Vec::new();
        for idx in 0..12 {
            let app = app.clone();
            tasks.push(tokio::spawn(async move {
                let ip = format!("203.0.114.{}", 10 + idx);
                let (init_status, _, init_body) =
                    send_json_as(&app, Method::GET, "/api/v1/init?scope=create", None, &ip).await;
                assert_eq!(init_status, StatusCode::OK);
                let challenge = init_body["pow"]["challenge"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned();
                let bits = spec_from_init(&init_body);
                let blob = fake_aes_blob(format!("cipher-{idx}").as_bytes());
                let nonce = solve_pow_for_create(&challenge, bits, 43_200, &blob);

                let (status, _, body) = send_json_as(
                    &app,
                    Method::POST,
                    "/api/v1/notes",
                    Some(json!({
                        "alg": "aes-256-gcm",
                        "challenge": challenge,
                        "nonce": nonce,
                        "ttl": 43200,
                        "blob": blob,
                        "view_token": test_view_token()
                    })),
                    &ip,
                )
                .await;
                (status, body["nid"].as_str().map(str::to_owned))
            }));
        }

        let mut success_count = 0usize;
        for task in tasks {
            let (status, nid) = task.await.expect("task should not panic");
            if status == StatusCode::OK && nid.is_some() {
                success_count += 1;
            }
        }

        assert_eq!(
            success_count, 12,
            "all parallel PoW+send flows must succeed"
        );
    }

    fn hex_lower(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Argon2id ticket with several rounds, to exercise multi-solution proofs.
    fn test_config_rounds() -> AppConfig {
        let mut config = test_config();
        config.pow_rounds_create = 2;
        config.pow_rounds_view = 2;
        config.challenge_ttl_secs = 60;
        config
    }

    async fn post_note(
        app: &Router,
        challenge: &str,
        nonce: &str,
        blob: &str,
    ) -> (StatusCode, Value) {
        let (status, _, body) = send_json(
            app,
            Method::POST,
            "/api/v1/notes",
            Some(json!({
                "alg": NOTE_ALG, "challenge": challenge, "nonce": nonce, "ttl": NOTE_TTLS[0],
                "blob": blob, "view_token": test_view_token()
            })),
        )
        .await;
        (status, body)
    }

    async fn read_note(app: &Router, nid: &str) -> (StatusCode, Value) {
        let (challenge, spec) = init_once(app, "view").await;
        let nonce = solve_pow_for_view(&challenge, spec, nid);
        let (status, _, body) = send_json(
            app,
            Method::POST,
            &format!("/api/v1/notes/{nid}/view"),
            Some(json!({
                "challenge": challenge, "nonce": nonce, "view_token": test_view_token()
            })),
        )
        .await;
        (status, body)
    }

    #[test]
    fn argon2id_matches_the_rfc_9106_test_vector() {
        // RFC 9106 §5.3: Argon2id, m=32 KiB, t=3, p=4, 32-byte tag, with secret K and data X.
        let params = argon2::ParamsBuilder::new()
            .m_cost(32)
            .t_cost(3)
            .p_cost(4)
            .data(argon2::AssociatedData::new(&[0x04; 12]).unwrap())
            .output_len(32)
            .build()
            .unwrap();
        let hasher =
            Argon2::new_with_secret(&[0x03; 8], Algorithm::Argon2id, Version::V0x13, params)
                .unwrap();
        let mut tag = [0u8; 32];
        hasher
            .hash_password_into(&[0x01; 32], &[0x02; 16], &mut tag)
            .unwrap();
        assert_eq!(
            hex_lower(&tag),
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
        );
    }

    #[test]
    fn argon2id_pow_matches_the_frontend_interoperability_vector() {
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/pow-argon2id-vector.json"))
                .unwrap();
        assert_eq!(fixture["alg"], POW_ALG_ARGON2ID);
        assert_eq!(
            fixture["salt_domain"].as_str().unwrap().as_bytes(),
            POW_ARGON2_SALT_DOMAIN
        );
        let challenge = URL_SAFE_NO_PAD
            .decode(fixture["challenge"].as_str().unwrap())
            .unwrap();
        let ttl = fixture["create"]["ttl"].as_u64().unwrap();
        let blob = fixture["create"]["blob"].as_str().unwrap();
        let payload_hash = payload_hash_for_create(ttl, blob);
        assert_eq!(
            hex_lower(&payload_hash),
            fixture["payload_hash_hex"].as_str().unwrap()
        );
        let salt = argon2_pow_salt(&challenge, &payload_hash);
        assert_eq!(hex_lower(&salt), fixture["salt_hex"].as_str().unwrap());

        let m_kib = fixture["params"]["m_kib"].as_u64().unwrap() as u32;
        let t_cost = fixture["params"]["t"].as_u64().unwrap() as u32;
        for case in fixture["cases"].as_array().unwrap() {
            let nonce = URL_SAFE_NO_PAD
                .decode(case["nonce"].as_str().unwrap())
                .unwrap();
            let tag = argon2_pow_tag(&nonce, &salt, m_kib, t_cost).unwrap();
            assert_eq!(hex_lower(&tag), case["tag_hex"].as_str().unwrap());
        }

        let solved = &fixture["solved"];
        let spec = PowSpec {
            bits: solved["bits"].as_u64().unwrap() as u8,
            rounds: solved["rounds"].as_u64().unwrap() as u8,
            m_kib,
            t_cost,
        };
        let nonce = URL_SAFE_NO_PAD
            .decode(solved["nonce"].as_str().unwrap())
            .unwrap();
        assert!(verify_pow_argon2id(&challenge, &nonce, &payload_hash, &spec).unwrap());

        // One extra bit of difficulty, a different payload, or a repeated solution all fail.
        let harder = PowSpec {
            bits: spec.bits + 1,
            ..spec
        };
        assert!(!verify_pow_argon2id(&challenge, &nonce, &payload_hash, &harder).unwrap());
        let other_payload = payload_hash_for_create(ttl + 1, blob);
        assert!(!verify_pow_argon2id(&challenge, &nonce, &other_payload, &spec).unwrap());
        let repeated: Vec<u8> = [&nonce[..8], &nonce[..8]].concat();
        assert!(!verify_pow_argon2id(&challenge, &repeated, &payload_hash, &spec).unwrap());
        assert!(!verify_pow_argon2id(&challenge, &nonce[..8], &payload_hash, &spec).unwrap());
    }

    #[test]
    fn nonce_chunks_must_be_pairwise_distinct() {
        assert!(pow_nonce_chunks_are_distinct(&[
            1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0
        ]));
        assert!(!pow_nonce_chunks_are_distinct(&[7u8; 16]));
        assert!(pow_nonce_chunks_are_distinct(&[7u8; 8]));
    }

    #[test]
    fn legacy_pow_settings_are_rejected_instead_of_clamped() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |name: &str| {
                pairs
                    .iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| (*value).to_owned())
            }
        };
        assert!(check_pow_env(env(&[])).is_ok());
        assert!(check_pow_env(env(&[("POW_ALG", "argon2id")])).is_ok());
        assert!(check_pow_env(env(&[("POW_ALG", " ARGON2ID ")])).is_ok());
        assert!(check_pow_env(env(&[("POW_BITS_CREATE", "12"), ("POW_BITS_VIEW", "3")])).is_ok());
        let err = check_pow_env(env(&[("POW_ALG", "sha256")])).unwrap_err();
        assert!(
            err.contains("POW_ALG") && err.contains("docs/pow-spec.md"),
            "{err}"
        );
        for name in POW_BITS_ENV_VARS {
            let pairs: &'static [(&'static str, &'static str)] =
                Box::leak(vec![(name, "17")].into_boxed_slice());
            let err = check_pow_env(env(pairs)).unwrap_err();
            assert!(err.starts_with(name), "{err}");
        }
        // Unparseable values keep their previous meaning (fall back to the default).
        assert!(check_pow_env(env(&[("POW_BITS", "lots")])).is_ok());
    }

    #[tokio::test]
    async fn init_advertises_the_argon2id_scheme_and_file_limits() {
        let app = build_router(AppState::new(test_config_rounds()));
        let (status, _, body) = send_json(&app, Method::GET, "/api/v1/init", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["pow"]["alg"], POW_ALG_ARGON2ID);
        assert_eq!(body["pow"]["scope"], "create");
        assert_eq!(body["pow"]["rounds"], json!(2));
        assert_eq!(
            body["pow"]["params"],
            json!({ "m_kib": 256, "t": 1, "p": 1, "tag_bytes": 32, "nonce_bytes": 8 })
        );
        assert_eq!(body["limits"]["max_file_bytes"], json!(0));
        assert_eq!(body["limits"]["max_plaintext_bytes"], json!(32768));
        assert_eq!(body["limits"]["max_blob_bytes"], json!(48 * 1024));
        let (_, _, info) = send_json(&app, Method::GET, "/info", None).await;
        assert_eq!(info["max_file_bytes"], json!(0));
    }

    #[tokio::test]
    async fn argon2id_round_trip_binds_payload_rounds_and_length() {
        let app = build_router(AppState::new(test_config_rounds()));
        let blob = fake_aes_blob(b"argon2id round trip");
        let ttl = NOTE_TTLS[0];

        // A proof for one blob does not transfer to another (pick a challenge where it does
        // not hold by chance at this low test difficulty).
        let other_blob = fake_aes_blob(b"argon2id other blob");
        let (challenge, nonce) = loop {
            let (challenge, spec) = init_once(&app, "create").await;
            assert_eq!(spec.rounds, 2);
            let nonce = solve_pow_for_create(&challenge, spec, ttl, &blob);
            let other = payload_hash_for_create(ttl, &other_blob);
            if !verify_pow_argon2id(
                &URL_SAFE_NO_PAD.decode(&challenge).unwrap(),
                &URL_SAFE_NO_PAD.decode(&nonce).unwrap(),
                &other,
                &spec,
            )
            .unwrap()
            {
                break (challenge, nonce);
            }
        };
        assert_eq!(URL_SAFE_NO_PAD.decode(&nonce).unwrap().len(), 16);
        let (status, body) = post_note(&app, &challenge, &nonce, &other_blob).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "invalid_pow");

        // Repeating one solution for both rounds is not two solutions.
        let (challenge, spec) = init_once(&app, "create").await;
        let nonce = solve_pow_for_create(&challenge, spec, ttl, &blob);
        let nonce_bytes = URL_SAFE_NO_PAD.decode(&nonce).unwrap();
        let first = &nonce_bytes[..8];
        let repeated = URL_SAFE_NO_PAD.encode([first, first].concat());
        let (status, body) = post_note(&app, &challenge, &repeated, &blob).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "invalid_pow");

        // A single-round nonce has the wrong length for a two-round ticket; a malformed
        // nonce does not cost a verification and leaves the challenge usable.
        let (challenge, spec) = init_once(&app, "create").await;
        let nonce = solve_pow_for_create(&challenge, spec, ttl, &blob);
        let first = &URL_SAFE_NO_PAD.decode(&nonce).unwrap()[..8];
        let (status, body) =
            post_note(&app, &challenge, &URL_SAFE_NO_PAD.encode(first), &blob).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "invalid_nonce");

        // The genuine proof creates the note; the challenge is then consumed.
        let (status, body) = post_note(&app, &challenge, &nonce, &blob).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let nid = body["nid"].as_str().unwrap().to_owned();
        let (status, body) = post_note(&app, &challenge, &nonce, &blob).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "invalid_challenge");

        // Reading uses the view scope with its own rounds and the nid-bound payload hash.
        let (status, body) = read_note(&app, &nid).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["blob"], Value::String(blob.clone()));
        assert_eq!(body["deleted"], Value::Bool(true));
        assert_eq!(read_note(&app, &nid).await.0, StatusCode::GONE);
    }

    #[tokio::test]
    async fn a_rejected_proof_burns_the_challenge() {
        let app = build_router(AppState::new(test_config_rounds()));
        let blob = fake_aes_blob(b"burned challenge");
        let (challenge, spec) = init_once(&app, "create").await;
        let wrong = unsolved_nonce(
            &challenge,
            spec,
            &payload_hash_for_create(NOTE_TTLS[0], &blob),
        );
        let (status, body) = post_note(&app, &challenge, &wrong, &blob).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "invalid_pow");
        let right = solve_pow_for_create(&challenge, spec, NOTE_TTLS[0], &blob);
        let (status, body) = post_note(&app, &challenge, &right, &blob).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "invalid_challenge");
    }

    #[tokio::test]
    async fn argon2id_wrong_proof_counts_as_pow_failure() {
        let mut cfg = test_config_rounds();
        cfg.ban_short_secs = 600;
        let app = build_router(AppState::new(cfg));
        let blob = fake_aes_blob(b"argon2id wrong proof");
        let payload_hash = payload_hash_for_create(NOTE_TTLS[0], &blob);
        for _ in 0..3 {
            let (challenge, spec) = init_once(&app, "create").await;
            let garbage = unsolved_nonce(&challenge, spec, &payload_hash);
            let (status, body) = post_note(&app, &challenge, &garbage, &blob).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(body["error"]["code"], "invalid_pow");
        }
        let (status, _, body) = send_json(&app, Method::GET, "/api/v1/init", None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"]["code"], "banned");
    }

    #[test]
    fn file_budget_extends_the_effective_limits() {
        let mut config = test_config();
        assert_eq!(config.effective_max_plaintext_bytes(), 32768);
        assert_eq!(config.effective_max_blob_bytes(), 48 * 1024);
        assert_eq!(config.request_timeout(), Duration::from_secs(10));
        assert_eq!(config.signed_response_limit(), SIG_BODY_LIMIT_MIN);
        config.max_file_bytes = 1_000_000;
        let plaintext = 32768 + FILE_ENVELOPE_OVERHEAD_BYTES + 1_000_000;
        assert_eq!(config.effective_max_plaintext_bytes(), plaintext);
        assert_eq!(
            config.effective_max_blob_bytes(),
            (NOTE_NONCE_BYTES + NOTE_TAG_BYTES + plaintext) * 4 / 3 + 1
        );
        assert_eq!(
            config.signed_response_limit(),
            config.effective_max_blob_bytes() + JSON_BODY_OVERHEAD_BYTES
        );
        assert_eq!(
            config.request_timeout(),
            Duration::from_secs(DEFAULT_UPLOAD_TIMEOUT_SECS)
        );
    }

    #[tokio::test]
    async fn file_notes_within_the_admin_budget_round_trip() {
        let mut config = test_config();
        config.max_file_bytes = 200_000;
        let effective_blob = config.effective_max_blob_bytes();
        let app = build_router(AppState::new(config));

        let (_, _, init) = send_json(&app, Method::GET, "/api/v1/init", None).await;
        assert_eq!(init["limits"]["max_file_bytes"], json!(200_000));
        assert_eq!(init["limits"]["max_plaintext_bytes"], json!(32768));
        assert_eq!(init["limits"]["max_blob_bytes"], json!(effective_blob));
        let (_, _, info) = send_json(&app, Method::GET, "/info", None).await;
        assert_eq!(info["max_file_bytes"], json!(200_000));

        // Larger than any text note, inside the file budget: accepted and read back intact.
        let blob = fake_aes_blob(&vec![0x5a; 150_000]);
        assert!(blob.len() > MAX_SUPPORTED_BLOB_BYTES);
        let (status, body) = create_test_note(&app, &blob).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let nid = body["nid"].as_str().unwrap().to_owned();
        let (status, body) = read_note(&app, &nid).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["blob"], Value::String(blob));

        // Over the effective plaintext budget: rejected before any proof is checked.
        let over = 32768 + FILE_ENVELOPE_OVERHEAD_BYTES + 200_000 + 1;
        let blob = fake_aes_blob(&vec![0x5a; over]);
        assert!(blob.len() > effective_blob);
        let (challenge, _) = init_once(&app, "create").await;
        let (status, body) = post_note(&app, &challenge, "AAAAAAAAAAA", &blob).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(body["error"]["code"], "blob_too_large");

        // Beyond the request body limit: rejected while reading the body.
        let (status, _, body) = send_json(
            &app,
            Method::POST,
            "/api/v1/notes",
            Some(json!({ "padding": "x".repeat(effective_blob + JSON_BODY_OVERHEAD_BYTES + 1) })),
        )
        .await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(body["error"]["code"], "body_too_large");
    }

    #[tokio::test]
    async fn file_uploads_stay_disabled_by_default() {
        let app = build_router(AppState::new(test_config()));
        // Fits the text blob limit but exceeds the text plaintext limit: without a file budget
        // there is nothing else it could be.
        let blob = fake_aes_blob(&vec![0x5a; 34_000]);
        assert!(blob.len() <= 48 * 1024);
        let (challenge, _) = init_once(&app, "create").await;
        let (status, body) = post_note(&app, &challenge, "AAAAAAAAAAA", &blob).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(body["error"]["code"], "plaintext_too_large");
        let blob = fake_aes_blob(&vec![0x5a; 40_000]);
        let (status, _, body) = send_json(
            &app,
            Method::POST,
            "/api/v1/notes",
            Some(json!({
                "alg": NOTE_ALG, "challenge": challenge, "nonce": "AAAAAAAAAAA",
                "ttl": NOTE_TTLS[0], "blob": blob, "view_token": test_view_token()
            })),
        )
        .await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(body["error"]["code"], "body_too_large");
    }

    #[tokio::test]
    async fn info_publishes_the_instance_passport_unless_disabled() {
        let passport = InstancePassport::collect(hardening::harden_process());
        let state = AppState::with_passport(test_config(), None, passport.clone());
        let app = build_router(state);
        let (status, _, body) = send_json(&app, Method::GET, "/info", None).await;
        assert_eq!(status, StatusCode::OK);
        let published = &body["passport"];
        assert_eq!(
            published["version"],
            Value::String(env!("CARGO_PKG_VERSION").to_owned())
        );
        assert_eq!(published["started_at"], json!(passport.started_at));
        assert!(published["uptime_secs"].is_u64());
        assert_eq!(
            published["binary_sha256"].as_str().map(str::len),
            Some(64),
            "the test binary must be hashable"
        );
        assert_eq!(published["ram_only"]["zeroize_on_drop"], Value::Bool(true));
        #[cfg(target_os = "linux")]
        {
            assert_eq!(published["ram_only"]["dumpable"], Value::Bool(false));
            assert!(published["ram_only"]["memory_locked"].is_boolean());
            assert!(published["ram_only"]["swap_present"].is_boolean());
        }
        #[cfg(unix)]
        assert_eq!(
            published["ram_only"]["core_dump_limit_zero"],
            Value::Bool(true)
        );

        let mut quiet = test_config();
        quiet.publish_passport = false;
        let app = build_router(AppState::new(quiet));
        let (_, _, body) = send_json(&app, Method::GET, "/info", None).await;
        assert!(body.get("passport").is_none());
        assert!(body["notes"].is_u64());
    }

    #[test]
    fn note_entries_zeroize_their_ciphertext_when_dropped() {
        // Observable through the moved-out String: the store copy is emptied before drop and
        // the response wrapper serializes what it holds.
        let mut entry = NoteEntry {
            blob: "ciphertext".to_owned(),
            view_token_hash: [7u8; 32],
            expires_at: 1,
        };
        let blob = std::mem::take(&mut entry.blob);
        assert_eq!(entry.blob, "");
        drop(entry);
        let secret = SecretString(blob);
        assert_eq!(serde_json::to_string(&secret).unwrap(), "\"ciphertext\"");
        let mut hash = [7u8; 32];
        hash.zeroize();
        assert_eq!(hash, [0u8; 32]);
    }

    /// Native verification cost of one 4 MiB evaluation, for docs/pow-spec.md.
    /// `cargo test --release -- --ignored --nocapture argon2id_native_cost`
    #[test]
    #[ignore = "benchmark"]
    fn argon2id_native_cost() {
        let salt = [9u8; 32];
        for (m_kib, iterations) in [(4096u32, 50u32), (256, 200)] {
            let started = std::time::Instant::now();
            for i in 0..iterations {
                argon2_pow_tag(&u64::from(i).to_le_bytes(), &salt, m_kib, 1).unwrap();
            }
            let per = started.elapsed() / iterations;
            println!("argon2id m={m_kib} KiB t=1: {per:?} per evaluation");
        }
    }

    #[test]
    fn api_catalog_authority_validation_rejects_poisoned_hosts() {
        assert_eq!(
            sanitize_authority("Example.COM:8443"),
            Some("example.com:8443".to_owned())
        );
        assert_eq!(
            sanitize_authority("[::1]:8443"),
            Some("[::1]:8443".to_owned())
        );

        for bad in [
            "",
            "evil.com:bad",
            "evil..com",
            "-evil.com",
            "evil.com-",
            "evil_com",
            "evil.com/path",
            "user@evil.com",
            "evil.com\\path",
            "bad host",
        ] {
            assert_eq!(sanitize_authority(bad), None, "{bad} should be rejected");
        }
    }
}
