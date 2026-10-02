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
use hyper_util::{
    rt::{TokioExecutor, TokioTimer},
    server::conn::auto::Builder as HttpBuilder,
};
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
    let tls_config = RustlsConfig::from_pem_file(&tls_cert_path, &tls_key_path).await?;
    #[cfg(unix)]
    let _tls_reload_handle =
        spawn_tls_reload_task(tls_config.clone(), tls_cert_path, tls_key_path)?;

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

    let mut http_listener = axum_server::bind(http_addr).handle(handle.clone());
    configure_http(http_listener.http_builder());
    let http_server = http_listener.serve(redirect_app.into_make_service());

    let mut https_listener = axum_server::bind_rustls(https_addr, tls_config).handle(handle);
    configure_http(https_listener.http_builder());
    let https_server =
        https_listener.serve(app.into_make_service_with_connect_info::<SocketAddr>());

    tokio::try_join!(http_server, https_server)?;

    Ok(())
}

fn configure_http(builder: &mut HttpBuilder<TokioExecutor>) {
    // Hyper's default header deadline is inactive unless a timer is installed.
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(10))
        .max_buf_size(32 * 1024)
        .max_headers(64);

    builder
        .http2()
        .timer(TokioTimer::new())
        .max_concurrent_streams(64)
        .max_header_list_size(16 * 1024)
        .max_send_buf_size(64 * 1024)
        .keep_alive_interval(Duration::from_secs(30))
        .keep_alive_timeout(Duration::from_secs(10));
}

#[cfg(unix)]
fn spawn_tls_reload_task(
    config: RustlsConfig,
    cert_path: String,
    key_path: String,
) -> io::Result<tokio::task::JoinHandle<()>> {
    let mut hangup = signal::unix::signal(signal::unix::SignalKind::hangup())?;
    Ok(tokio::spawn(async move {
        while hangup.recv().await.is_some() {
            match config.reload_from_pem_file(&cert_path, &key_path).await {
                Ok(()) => info!("TLS certificate reloaded without restarting the server"),
                Err(error) => tracing::warn!(
                    error_kind = ?error.kind(),
                    "TLS certificate reload failed; keeping previous TLS configuration"
                ),
            }
        }
    }))
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
    suffix.strip_prefix(':').is_some_and(is_valid_port)
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

#[cfg(test)]
mod tests {
    use super::*;
    use hyper_util::{rt::TokioIo, service::TowerToHyperService};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn public_host_overrides_untrusted_redirect_host() {
        let config = RedirectState {
            https_port: 8443,
            public_host: Some("notes.example.com".to_owned()),
        };
        assert_eq!(
            authority_for_https(Some("attacker.example"), &config),
            Some("notes.example.com:8443".to_owned())
        );
        assert_eq!(
            authority_for_https(None, &config),
            Some("notes.example.com:8443".to_owned())
        );
    }

    #[test]
    fn redirect_host_validation_rejects_ambiguous_authorities() {
        for host in [
            "",
            "user@notes.example.com",
            "notes.example.com/path",
            "notes.example.com\\attacker.example",
            "notes.example.com:65536",
            "notes.example.com:invalid",
            "notes.example.com#fragment",
            "notes.example.com?query",
            "-notes.example.com",
            "notes..example.com",
            "[localhost]",
        ] {
            assert_eq!(normalize_redirect_host(host), None, "accepted {host}");
        }
        assert_eq!(
            normalize_redirect_host("NOTES.Example.com:80"),
            Some("notes.example.com".to_owned())
        );
        assert_eq!(
            normalize_redirect_host("[::1]:80"),
            Some("[::1]".to_owned())
        );
    }

    #[tokio::test]
    async fn incomplete_http_headers_are_closed_before_reaching_the_router() {
        let (mut stream, server_stream) = tokio::io::duplex(1024);
        let mut builder = HttpBuilder::new(TokioExecutor::new());
        configure_http(&mut builder);
        let service = TowerToHyperService::new(
            Router::new().fallback(|| async { "unexpected router response" }),
        );
        let task = tokio::spawn(async move {
            builder
                .serve_connection(TokioIo::new(server_stream), service)
                .await
        });
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Slow: ")
            .await
            .unwrap();
        let mut response = Vec::new();
        let outcome =
            tokio::time::timeout(Duration::from_secs(12), stream.read_to_end(&mut response)).await;
        task.abort();
        assert!(outcome.is_ok(), "incomplete headers remained open");
        assert!(
            !String::from_utf8_lossy(&response).contains("unexpected router response"),
            "incomplete request reached the router"
        );
    }
}
