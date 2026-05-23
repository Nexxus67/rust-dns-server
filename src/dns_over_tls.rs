use dns_parser::{Packet, QueryType};
use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};
use lru::LruCache;
use once_cell::sync::Lazy;
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::fs::File;
use std::io::BufReader;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, instrument, warn};

use crate::common::{build_dns_response, DNS_HEADER_SIZE, FALLBACK_IPV4, FALLBACK_IPV6};
use crate::resolver;

struct Metrics {
    total_queries: AtomicUsize,
    failed_parses: AtomicUsize,
}

static METRICS: Metrics = Metrics {
    total_queries: AtomicUsize::new(0),
    failed_parses: AtomicUsize::new(0),
};

static CACHE: Lazy<Mutex<LruCache<String, Vec<u8>>>> =
    Lazy::new(|| Mutex::new(LruCache::new(100)));

static RATE_LIMITER: Lazy<RateLimiter<NotKeyed, InMemoryState, DefaultClock>> = Lazy::new(|| {
    let quota = Quota::per_second(NonZeroU32::new(100).unwrap());
    RateLimiter::direct(quota)
});

#[instrument]
pub async fn run_dot_server() -> Result<(), Box<dyn std::error::Error>> {
    let bind_addr = std::env::var("DNS_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:853".to_string());
    let default_ttl = std::env::var("DNS_DEFAULT_TTL")
        .unwrap_or_else(|_| "60".to_string())
        .parse::<u32>()?;

    let cert_path = std::env::var("DNS_CERT_PATH").unwrap_or_else(|_| "certs/cert.pem".to_string());
    let key_path = std::env::var("DNS_KEY_PATH").unwrap_or_else(|_| "certs/key.pem".to_string());

    let cert_file = File::open(&cert_path)
        .map_err(|e| format!("Cannot open cert file '{}': {}", cert_path, e))?;
    let key_file = File::open(&key_path)
        .map_err(|e| format!("Cannot open key file '{}': {}", key_path, e))?;

    let certs = certs(&mut BufReader::new(cert_file))?
        .into_iter()
        .map(Certificate)
        .collect::<Vec<_>>();

    let keys = pkcs8_private_keys(&mut BufReader::new(key_file))?;
    let key = keys.into_iter().next().ok_or("Private key not found")?;
    let key = PrivateKey(key);

    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("Error configuring certificates: {}", e))?;

    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind(&bind_addr).await?;
    info!("DNS-over-TLS server started on {}", bind_addr);

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        info!(%peer_addr, "New TLS connection established");

        if RATE_LIMITER.check().is_err() {
            warn!(%peer_addr, "Rate limit reached");
            continue;
        }

        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_dot_connection(acceptor, stream, peer_addr, default_ttl).await {
                error!(%peer_addr, error = %e, "Error handling DoT connection");
            }
        });
    }
}

#[instrument(skip(acceptor, stream))]
async fn handle_dot_connection(
    acceptor: TlsAcceptor,
    stream: TcpStream,
    peer_addr: std::net::SocketAddr,
    ttl: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut tls_stream = acceptor.accept(stream).await?;
    info!(%peer_addr, "TLS connection established");

    let mut len_bytes = [0u8; 2];
    tls_stream.read_exact(&mut len_bytes).await?;
    let len = u16::from_be_bytes(len_bytes) as usize;

    if len < DNS_HEADER_SIZE {
        warn!(%peer_addr, len, "DNS-over-TLS query too short");
        return Ok(());
    }

    let mut buf = vec![0u8; len];
    tls_stream.read_exact(&mut buf).await?;

    METRICS.total_queries.fetch_add(1, Ordering::Relaxed);

    let packet = match Packet::parse(&buf) {
        Ok(p) => p,
        Err(e) => {
            METRICS.failed_parses.fetch_add(1, Ordering::Relaxed);
            error!(%peer_addr, error = %e, "Failed to parse DNS packet");
            return Ok(());
        }
    };

    let [question] = packet.questions.as_slice() else {
        warn!(%peer_addr, question_count = packet.questions.len(), "Unsupported question count");
        return Ok(());
    };

    let domain = question.qname.to_string();
    info!(%peer_addr, %domain, "Processing DNS query");

    let cached = match CACHE.lock() {
        Ok(mut cache) => cache.get(&domain).cloned(),
        Err(e) => {
            warn!(%peer_addr, error = %e, "DNS cache unavailable");
            None
        }
    };
    if let Some(response) = cached {
        info!(%peer_addr, %domain, "Served response from cache");
        tls_stream.write_all(&response).await?;
        return Ok(());
    }

    let response = match question.qtype {
        QueryType::A => {
            let ip = resolver::resolve_recursively_async(domain.clone())
                .await
                .unwrap_or(IpAddr::V4(FALLBACK_IPV4));
            info!(%peer_addr, %domain, ip = %ip, "Resolved DNS A record");
            build_dns_response(&buf, &question.qname, ip, ttl)?
        }
        QueryType::AAAA => {
            let ip = IpAddr::V6(FALLBACK_IPV6);
            build_dns_response(&buf, &question.qname, ip, ttl)?
        }
        _ => {
            warn!(%peer_addr, %domain, qtype = ?question.qtype, "Unsupported query type");
            return Ok(());
        }
    };

    let framed_response = frame_dns_message(&response)?;

    match CACHE.lock() {
        Ok(mut cache) => {
            cache.put(domain.clone(), framed_response.clone());
        }
        Err(e) => {
            warn!(%peer_addr, error = %e, "DNS cache unavailable");
        }
    }

    tls_stream.write_all(&framed_response).await?;
    info!(%peer_addr, %domain, "Response sent");

    Ok(())
}

fn frame_dns_message(message: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let len = u16::try_from(message.len()).map_err(|_| "DNS response too large")?;
    let mut framed = Vec::with_capacity(message.len() + 2);
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(message);
    Ok(framed)
}
