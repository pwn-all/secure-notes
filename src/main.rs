use std::{env, io, net::IpAddr, net::SocketAddr, time::Duration};

use axum::{
    Router,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, Uri, header, uri::Authority},
    response::{IntoResponse, Redirect},
};
use axum_server::{Handle, tls_rustls::RustlsConfig};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use rand::RngExt;
use secure_notes::{AppConfig, AppState, build_router, spawn_cleanup_task};
use tokio::signal;
use tracing::info;

#[derive(Clone, Debug)]
struct RedirectState {
    https_port: u16,
    public_host: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = dotenvy::dotenv();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "secure_notes=info,tower_http=info".into()),
        )
        .init();

    let config = AppConfig::from_env();
    let http_bind_addr = env::var("HTTP_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:80".to_owned());
    let https_bind_addr = env::var("HTTPS_BIND_ADDR")
        .or_else(|_| env::var("BIND_ADDR"))
        .unwrap_or_else(|_| "0.0.0.0:443".to_owned());
    let tls_cert_path = env::var("TLS_CERT_PATH")
        .unwrap_or_else(|_| "/etc/letsencrypt/live/localhost/fullchain.pem".to_owned());
    let tls_key_path = env::var("TLS_KEY_PATH")
        .unwrap_or_else(|_| "/etc/letsencrypt/live/localhost/privkey.pem".to_owned());
    let public_host = match env::var("PUBLIC_HOST") {
        Ok(value) => Some(normalize_redirect_host(&value).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "PUBLIC_HOST is not a valid host",
            )
        })?),
        Err(_) => None,
    };

    let http_addr: SocketAddr = http_bind_addr.parse()?;
    let https_addr: SocketAddr = https_bind_addr.parse()?;
    let https_port = https_addr.port();
    let tls_config = RustlsConfig::from_pem_file(tls_cert_path, tls_key_path).await?;

    let signing_key = load_or_generate_signing_key()?;
    let state = AppState::with_signing_key(config, Some(signing_key));
    let _cleanup_handle = spawn_cleanup_task(state.clone());

    let app = build_router(state);
    let redirect_app = Router::new()
        .fallback(redirect_http_to_https)
        .with_state(RedirectState {
            https_port,
            public_host,
        });

    let handle = Handle::new();
    let shutdown_handle = handle.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        shutdown_handle.graceful_shutdown(Some(Duration::from_secs(10)));
    });

    info!("HTTP redirect listening on {}", http_addr);
    info!("HTTPS listening on {}", https_addr);

    let http_server = axum_server::bind(http_addr)
        .handle(handle.clone())
        .serve(redirect_app.into_make_service());
    let https_server = axum_server::bind_rustls(https_addr, tls_config)
        .handle(handle)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>());

    tokio::try_join!(http_server, https_server)?;

    Ok(())
}

async fn redirect_http_to_https(
    State(config): State<RedirectState>,
    headers: HeaderMap,
    uri: Uri,
) -> impl IntoResponse {
    let requested_host = headers.get(header::HOST).and_then(|v| v.to_str().ok());
    let Some(authority) = authority_for_https(requested_host, &config) else {
        return StatusCode::BAD_REQUEST.into_response();
    };

    let path_and_query = uri.path_and_query().map(|v| v.as_str()).unwrap_or("/");
    let mut response =
        Redirect::permanent(&format!("https://{}{}", authority, path_and_query)).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, max-age=0"),
    );
    response
}

fn authority_for_https(requested_host: Option<&str>, config: &RedirectState) -> Option<String> {
    let host = if let Some(public_host) = &config.public_host {
        public_host.clone()
    } else {
        normalize_redirect_host(requested_host?)?
    };

    if config.https_port == 443 {
        Some(host)
    } else {
        Some(format!("{host}:{}", config.https_port))
    }
}

fn normalize_redirect_host(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > 300 || raw.contains('@') || raw.contains('/') {
        return None;
    }

    let authority = raw.parse::<Authority>().ok()?;
    let authority = authority.as_str();
    if authority.is_empty() || authority.contains('@') {
        return None;
    }

    let host = host_without_port(authority)?;
    if !is_valid_host(host) {
        return None;
    }

    Some(host.to_ascii_lowercase())
}

fn host_without_port(authority: &str) -> Option<&str> {
    if authority.starts_with('[') {
        let end = authority.find(']')?;
        let host = &authority[..=end];
        let suffix = &authority[end + 1..];
        if suffix.is_empty() || valid_port_suffix(suffix) {
            return Some(host);
        }
        return None;
    }

    if authority.matches(':').count() > 1 {
        return None;
    }

    match authority.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && is_valid_port(port) => Some(host),
        Some(_) => None,
        None => Some(authority),
    }
}

fn valid_port_suffix(suffix: &str) -> bool {
    suffix
        .strip_prefix(':')
        .is_some_and(is_valid_port)
}

fn is_valid_port(port: &str) -> bool {
    !port.is_empty() && port.parse::<u16>().is_ok()
}

fn is_valid_host(host: &str) -> bool {
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

fn load_or_generate_signing_key() -> Result<SigningKey, Box<dyn std::error::Error>> {
    if let Ok(raw) = env::var("SIGNING_KEY") {
        let key_bytes: [u8; 32] = URL_SAFE_NO_PAD
            .decode(raw.trim())
            .map_err(|_| "SIGNING_KEY is not valid base64url")?
            .try_into()
            .map_err(|_| "SIGNING_KEY must be exactly 32 bytes")?;
        let key = SigningKey::from_bytes(&key_bytes);
        let pubkey = URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes());
        info!("Loaded signing key from SIGNING_KEY. Public key: {pubkey}");
        info!("Configure clients with: <api-url>|{pubkey}");
        return Ok(key);
    }

    let mut key_bytes = [0u8; 32];
    rand::rng().fill(&mut key_bytes);
    let key = SigningKey::from_bytes(&key_bytes);
    let pubkey = URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes());
    info!("Generated ephemeral signing key (SIGNING_KEY not set). Key is in-memory only.");
    info!("Configure clients with: <api-url>|{pubkey}");
    Ok(key)
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
