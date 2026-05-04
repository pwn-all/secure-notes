use std::{
    collections::HashMap,
    env,
    mem::size_of,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{ConnectInfo, DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header, uri::Authority},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use ed25519_dalek::{Signer, SigningKey};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::{sync::Mutex, time::Duration};
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;

const NOTE_TTLS: [u64; 2] = [12 * 3600, 24 * 3600];
const NOTE_ALG: &str = "aes-256-gcm";
const NOTE_KEY_BYTES: usize = 32;
const NOTE_NONCE_BYTES: usize = 12;
const NOTE_TAG_BYTES: usize = 16;
const CHALLENGE_BYTES: usize = 24;
const POW_NONCE_BYTES: usize = 8;
const MAX_POW_BITS: u8 = 28;
const GENERATED_NID_BYTES: usize = 16;
const GENERATED_NID_B64_LEN: usize = 22;
const JSON_BODY_OVERHEAD_BYTES: usize = 2048;
const SIG_BODY_LIMIT: usize = 512 * 1024;
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
    pub max_plaintext_bytes: usize,
    pub max_blob_bytes: usize,
    pub max_active_challenges: usize,
    pub max_notes: usize,
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
        let pow_bits_create = env::var("POW_BITS_CREATE")
            .ok()
            .or_else(|| env::var("POW_BITS").ok())
            .and_then(|v| v.parse::<u8>().ok())
            .unwrap_or(17)
            .clamp(1, MAX_POW_BITS);
        let pow_bits_create_max = env::var("POW_BITS_CREATE_MAX")
            .ok()
            .or_else(|| env::var("POW_BITS_MAX").ok())
            .and_then(|v| v.parse::<u8>().ok())
            .unwrap_or(MAX_POW_BITS)
            .clamp(pow_bits_create, MAX_POW_BITS);
        let pow_bits_view = parse_env_u8("POW_BITS_VIEW", 16).clamp(1, MAX_POW_BITS);
        let pow_bits_view_max =
            parse_env_u8("POW_BITS_VIEW_MAX", 24).clamp(pow_bits_view, MAX_POW_BITS);

        Self {
            server_salt: random_bytes(32),
            challenge_ttl_secs: parse_env_u64("CHALLENGE_TTL_SECS", 150),
            pow_bits_create,
            pow_bits_create_max,
            pow_bits_view,
            pow_bits_view_max,
            max_plaintext_bytes: parse_env_usize("MAX_PLAINTEXT_BYTES", 4096),
            max_blob_bytes: parse_env_usize("MAX_BLOB_BYTES", 16 * 1024),
            max_active_challenges: parse_env_usize(
                "MAX_ACTIVE_CHALLENGES",
                DEFAULT_MAX_ACTIVE_CHALLENGES,
            ),
            max_notes: parse_env_usize("MAX_NOTES", DEFAULT_MAX_NOTES),
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

#[derive(Clone)]
pub struct AppState {
    inner: Arc<StateInner>,
}

struct StateInner {
    config: AppConfig,
    signing_key: Option<SigningKey>,
    challenges: Mutex<HashMap<String, ChallengeEntry>>,
    notes: Mutex<HashMap<String, NoteEntry>>,
    abuse: Mutex<HashMap<String, AbuseEntry>>,
    rate_windows: Mutex<HashMap<String, RateEntry>>,
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
    bits: u8,
    expires_at: u64,
}

#[derive(Clone)]
struct NoteEntry {
    blob: String,
    view_token_hash: [u8; 32],
    expires_at: u64,
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
        Self {
            inner: Arc::new(StateInner {
                config,
                signing_key,
                challenges: Mutex::new(HashMap::new()),
                notes: Mutex::new(HashMap::new()),
                abuse: Mutex::new(HashMap::new()),
                rate_windows: Mutex::new(HashMap::new()),
            }),
        }
    }

    fn config(&self) -> &AppConfig {
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
            notes.retain(|_, n| n.expires_at > now);
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
        let notes_count = notes_guard.len();
        let notes_bytes = notes_guard
            .iter()
            .map(|(nid, note)| {
                size_of::<String>() + nid.len() + size_of::<NoteEntry>() + note.blob.len() + 32 // rough HashMap bucket/allocator overhead per note entry
            })
            .sum::<usize>();
        drop(notes_guard);

        let challenges_guard = self.inner.challenges.lock().await;
        let challenges_bytes = challenges_guard
            .iter()
            .map(|(challenge_id, challenge)| {
                size_of::<String>()
                    + challenge_id.len()
                    + size_of::<ChallengeEntry>()
                    + challenge.client_key.len()
                    + challenge.challenge_bytes.len()
                    + 32
            })
            .sum::<usize>();
        drop(challenges_guard);

        let abuse_guard = self.inner.abuse.lock().await;
        let abuse_bytes = abuse_guard
            .keys()
            .map(|k| size_of::<String>() + k.len() + size_of::<AbuseEntry>() + 24)
            .sum::<usize>();
        drop(abuse_guard);

        let rates_guard = self.inner.rate_windows.lock().await;
        let rates_bytes = rates_guard
            .keys()
            .map(|k| size_of::<String>() + k.len() + size_of::<RateEntry>() + 24)
            .sum::<usize>();

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
    expires_at: u64,
    challenge: String,
}

#[derive(Serialize)]
struct LimitsResponse {
    max_plaintext_bytes: usize,
    max_blob_bytes: usize,
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
    blob: String,
    deleted: bool,
}

#[derive(Serialize)]
struct InfoResponse {
    ok: bool,
    notes: usize,
    ram_usage: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pubkey: Option<String>,
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
    let should_sign = {
        let p = req.uri().path();
        p == "/info" || p.starts_with("/api/v1/")
    };

    let response = next.run(req).await;

    let Some(signing_key) = state.inner.signing_key.as_ref() else {
        return response;
    };
    if !should_sign {
        return response;
    }

    let (mut parts, body) = response.into_parts();
    let Ok(bytes) = to_bytes(body, SIG_BODY_LIMIT).await else {
        return Response::from_parts(parts, Body::empty());
    };

    let sig = signing_key.sign(&bytes);
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
    if let Ok(val) = HeaderValue::from_str(&sig_b64) {
        parts.headers.insert(
            header::HeaderName::from_static("x-secnote-sig"),
            val,
        );
    }

    Response::from_parts(parts, Body::from(bytes))
}

pub fn build_router(state: AppState) -> Router {
    let max_body_bytes = state
        .config()
        .max_blob_bytes
        .saturating_add(JSON_BODY_OVERHEAD_BYTES)
        .max(JSON_BODY_OVERHEAD_BYTES);

    Router::new()
        .route("/info", get(info_handler))
        .route("/.well-known/api-catalog", get(api_catalog_handler))
        .route("/api/v1/init", get(init_handler))
        .route("/api/v1/notes", post(create_note_handler))
        .route("/api/v1/notes/{nid}/view", post(view_note_handler))
        .fallback_service(ServeDir::new("website").append_index_html_on_directories(true))
        .layer(middleware::from_fn_with_state(state.clone(), sign_response_middleware))
        .with_state(state)
        .layer(DefaultBodyLimit::max(max_body_bytes))
        .layer(middleware::from_fn(security_headers_middleware))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET, Method::POST])
                .allow_headers([header::CONTENT_TYPE, header::ACCEPT])
                .expose_headers([header::HeaderName::from_static("x-secnote-sig")]),
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

    let (base_bits, bits_max) = match scope {
        PowScope::Create => (
            state.config().pow_bits_create,
            state.config().pow_bits_create_max,
        ),
        PowScope::View => (
            state.config().pow_bits_view,
            state.config().pow_bits_view_max,
        ),
    };
    let (challenge, bits, expires_at) = {
        let mut challenges = state.inner.challenges.lock().await;
        challenges.retain(|_, c| c.expires_at > now);

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

        let challenge_bytes = random_bytes(CHALLENGE_BYTES);
        let challenge = URL_SAFE_NO_PAD.encode(&challenge_bytes);
        let expires_at = now.saturating_add(state.config().challenge_ttl_secs);

        challenges.insert(
            challenge.clone(),
            ChallengeEntry {
                client_key: client_key.clone(),
                scope,
                challenge_bytes,
                bits,
                expires_at,
            },
        );

        (challenge, bits, expires_at)
    };

    Ok(Json(InitResponse {
        ok: true,
        server_time: now,
        pow: PowResponse {
            scope: scope.as_str(),
            alg: "sha256-leading-zero-bits",
            bits,
            expires_at,
            challenge,
        },
        encryption: EncryptionResponse {
            alg: NOTE_ALG,
            key_bytes: NOTE_KEY_BYTES,
            nonce_bytes: NOTE_NONCE_BYTES,
            tag_bytes: NOTE_TAG_BYTES,
        },
        limits: LimitsResponse {
            max_plaintext_bytes: state.config().max_plaintext_bytes,
            max_blob_bytes: state.config().max_blob_bytes,
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

    if payload.blob.len() > state.config().max_blob_bytes {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "blob_too_large",
            "blob is too large",
        ));
    }

    let blob_size = validate_aes_blob_format(&payload.blob)?;
    let plaintext_size = blob_size.saturating_sub(NOTE_NONCE_BYTES + NOTE_TAG_BYTES);
    if plaintext_size > state.config().max_plaintext_bytes {
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

    let challenge_entry = {
        let challenges = state.inner.challenges.lock().await;
        challenges.get(&payload.challenge).cloned()
    }
    .ok_or_else(|| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_challenge",
            "challenge is missing or already used",
        )
    })?;

    if challenge_entry.client_key != client_key {
        register_pow_failure(&state, &client_key, now).await;
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "challenge_client_mismatch",
            "challenge does not belong to this ip",
        ));
    }

    if challenge_entry.expires_at <= now {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "challenge_expired",
            "challenge has expired",
        ));
    }

    if challenge_entry.scope != PowScope::Create {
        register_pow_failure(&state, &client_key, now).await;
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "challenge_scope_mismatch",
            "challenge scope is invalid for this endpoint",
        ));
    }

    let nonce_bytes = decode_b64url_exact(
        &payload.nonce,
        POW_NONCE_BYTES,
        "invalid_nonce",
        "nonce must be 8 bytes base64url",
    )?;

    if !verify_pow_for_create(
        &challenge_entry.challenge_bytes,
        &nonce_bytes,
        payload.ttl,
        &payload.blob,
        challenge_entry.bits,
    ) {
        register_pow_failure(&state, &client_key, now).await;
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_pow",
            "pow solution is invalid",
        ));
    }

    let consumed = {
        let mut challenges = state.inner.challenges.lock().await;
        challenges.remove(&payload.challenge)
    };
    if consumed.is_none() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_challenge",
            "challenge is missing or already used",
        ));
    }

    reset_pow_failures(&state, &client_key, now).await;

    let nid = random_b64url(GENERATED_NID_BYTES);
    let expires_at = now.saturating_add(payload.ttl);

    {
        let mut notes = state.inner.notes.lock().await;
        notes.retain(|_, note| note.expires_at > now);
        if notes.len() >= state.config().max_notes {
            return Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_busy",
                "too many active notes",
            )
            .with_retry_after(30));
        }
        notes.insert(
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

    let challenge_entry = {
        let challenges = state.inner.challenges.lock().await;
        challenges.get(&payload.challenge).cloned()
    }
    .ok_or_else(|| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_challenge",
            "challenge is missing or already used",
        )
    })?;

    if challenge_entry.client_key != client_key {
        register_pow_failure(&state, &client_key, now).await;
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "challenge_client_mismatch",
            "challenge does not belong to this ip",
        ));
    }

    if challenge_entry.expires_at <= now {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "challenge_expired",
            "challenge has expired",
        ));
    }

    if challenge_entry.scope != PowScope::View {
        register_pow_failure(&state, &client_key, now).await;
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "challenge_scope_mismatch",
            "challenge scope is invalid for this endpoint",
        ));
    }

    let nonce_bytes = decode_b64url_exact(
        &payload.nonce,
        POW_NONCE_BYTES,
        "invalid_nonce",
        "nonce must be 8 bytes base64url",
    )?;

    if !verify_pow_for_view(
        &challenge_entry.challenge_bytes,
        &nonce_bytes,
        &nid,
        challenge_entry.bits,
    ) {
        register_pow_failure(&state, &client_key, now).await;
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_pow",
            "pow solution is invalid",
        ));
    }

    let consumed = {
        let mut challenges = state.inner.challenges.lock().await;
        challenges.remove(&payload.challenge)
    };
    if consumed.is_none() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_challenge",
            "challenge is missing or already used",
        ));
    }

    let view_token_bytes = decode_b64url_exact(
        &payload.view_token,
        NOTE_KEY_BYTES,
        "invalid_view_token",
        "view_token must be 32 bytes base64url",
    )?;
    let provided_view_token_hash = sha256_bytes(&view_token_bytes);

    let note = {
        let mut notes = state.inner.notes.lock().await;
        let Some(existing) = notes.get(&nid) else {
            return Err(ApiError::new(StatusCode::GONE, "gone", "note is gone"));
        };
        if existing.expires_at <= now {
            notes.remove(&nid);
            return Err(ApiError::new(StatusCode::GONE, "gone", "note is gone"));
        }
        if !constant_time_eq_32(&existing.view_token_hash, &provided_view_token_hash) {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "invalid_view_token",
                "view token is invalid",
            ));
        }
        notes
            .remove(&nid)
            .ok_or_else(|| ApiError::new(StatusCode::GONE, "gone", "note is gone"))?
    };

    reset_pow_failures(&state, &client_key, now).await;

    Ok(Json(ViewNoteResponse {
        ok: true,
        blob: note.blob,
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
    Some(value.to_ascii_lowercase())
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

fn verify_pow_for_create(challenge: &[u8], nonce: &[u8], ttl: u64, blob: &str, bits: u8) -> bool {
    let payload_hash = payload_hash_for_create(ttl, blob);
    verify_pow_with_payload_hash(challenge, nonce, &payload_hash, bits)
}

fn verify_pow_for_view(challenge: &[u8], nonce: &[u8], nid: &str, bits: u8) -> bool {
    let payload_hash = payload_hash_for_view(nid);
    verify_pow_with_payload_hash(challenge, nonce, &payload_hash, bits)
}

fn verify_pow_with_payload_hash(
    challenge: &[u8],
    nonce: &[u8],
    payload_hash: &[u8; 32],
    bits: u8,
) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(challenge);
    hasher.update(nonce);
    hasher.update(payload_hash);
    let digest = hasher.finalize();
    has_leading_zero_bits(&digest, bits)
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

    fn test_config() -> AppConfig {
        AppConfig {
            server_salt: vec![42u8; 32],
            challenge_ttl_secs: 5,
            pow_bits_create: 8,
            pow_bits_create_max: 12,
            pow_bits_view: 6,
            pow_bits_view_max: 10,
            max_plaintext_bytes: 4096,
            max_blob_bytes: 16 * 1024,
            max_active_challenges: DEFAULT_MAX_ACTIVE_CHALLENGES,
            max_notes: DEFAULT_MAX_NOTES,
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

    fn solve_pow_for_create(challenge_b64: &str, bits: u8, ttl: u64, blob: &str) -> String {
        let challenge = URL_SAFE_NO_PAD
            .decode(challenge_b64)
            .expect("challenge must decode");

        for nonce in 0u64.. {
            let candidate = nonce.to_le_bytes();
            if verify_pow_for_create(&challenge, &candidate, ttl, blob, bits) {
                return URL_SAFE_NO_PAD.encode(candidate);
            }
        }

        unreachable!("nonce space is practically unbounded")
    }

    fn fake_aes_blob(seed: &[u8]) -> String {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&vec![0x11u8; NOTE_NONCE_BYTES]);
        bytes.extend_from_slice(seed);
        bytes.extend_from_slice(&vec![0x22u8; NOTE_TAG_BYTES]);
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn test_view_token() -> String {
        URL_SAFE_NO_PAD.encode(vec![0x33u8; 32])
    }

    fn solve_pow_for_view(challenge_b64: &str, bits: u8, nid: &str) -> String {
        let challenge = URL_SAFE_NO_PAD
            .decode(challenge_b64)
            .expect("challenge must decode");

        for nonce in 0u64.. {
            let candidate = nonce.to_le_bytes();
            if verify_pow_for_view(&challenge, &candidate, nid, bits) {
                return URL_SAFE_NO_PAD.encode(candidate);
            }
        }

        unreachable!("nonce space is practically unbounded")
    }

    async fn init_once(app: &Router, scope: &str) -> (String, u8) {
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
            body["pow"]["bits"].as_u64().unwrap_or(0) as u8,
        )
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
        let oversized_plaintext = vec![b'a'; 4097];
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
        let mut cfg = test_config();
        cfg.pow_bits_create = 14;
        cfg.pow_bits_create_max = 14;
        let state = AppState::new(cfg);
        let app = build_router(state);

        let (challenge, bits) = init_once(&app, "create").await;
        let blob_a = fake_aes_blob(b"blob_a");
        let blob_b = fake_aes_blob(b"blob_b");
        let nonce = solve_pow_for_create(&challenge, bits, 43_200, &blob_a);

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
        assert_eq!(bad_status, StatusCode::FORBIDDEN);
        assert_eq!(
            bad_body["error"]["code"],
            Value::String("invalid_view_token".to_owned())
        );

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
            let wrong_nonce = (0u64..)
                .map(|n| n.to_le_bytes())
                .find(|candidate| {
                    !verify_pow_for_create(&challenge_bytes, candidate, ttl, &blob, bits)
                })
                .expect("must find invalid nonce");

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
        let bits = b1["pow"]["bits"].as_u64().unwrap_or(0) as u8;

        let (s2, _, b2) =
            send_json_as(&app, Method::GET, "/api/v1/init?scope=create", None, ip).await;
        assert_eq!(s2, StatusCode::OK);
        let challenge2 = b2["pow"]["challenge"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let bits2 = b2["pow"]["bits"].as_u64().unwrap_or(0) as u8;
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
        cfg.pow_bits_create = 10;
        cfg.pow_bits_create_max = 10;
        cfg.pow_bits_view = 8;
        cfg.pow_bits_view_max = 8;
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
                body["pow"]["bits"].as_u64().unwrap_or(0) as u8,
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
                let bits = init_body["pow"]["bits"].as_u64().unwrap_or(0) as u8;
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
        cfg.pow_bits_create = 10;
        cfg.pow_bits_create_max = 10;
        cfg.challenge_ttl_secs = 60;
        cfg.rate_limits = RateLimits {
            init_per_minute: 1_000,
            create_per_minute: 1_000,
            view_per_minute: 1_000,
        };
        let state = AppState::new(cfg);
        let app = build_router(state);

        let ip = "203.0.113.20";
        let (challenge, bits): (String, u8) = {
            let (status, _, body) =
                send_json_as(&app, Method::GET, "/api/v1/init?scope=create", None, ip).await;
            assert_eq!(status, StatusCode::OK);
            (
                body["pow"]["challenge"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
                body["pow"]["bits"].as_u64().unwrap_or(0) as u8,
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
        cfg.pow_bits_create = 10;
        cfg.pow_bits_create_max = 10;
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
                let bits = init_body["pow"]["bits"].as_u64().unwrap_or(0) as u8;
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
}
