use dns_parser::{Packet, RData, ResourceRecord, Class, QueryType};
use rustls::{ServerConfig, Certificate, PrivateKey};
use rustls_pemfile::{certs, pkcs8_private_keys};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use governor::{Quota, RateLimiter};
use lru::LruCache;
use once_cell::sync::Lazy;
use tracing::{info, warn, error, instrument};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::num::NonZeroU32;

use crate::resolver;
use crate::common::serialize_resource_record;

struct Metrics {
    total_queries: AtomicUsize,
    failed_parses: AtomicUsize,
}

static METRICS: Metrics = Metrics {
    total_queries: AtomicUsize::new(0),
    failed_parses: AtomicUsize::new(0),
};

static CACHE: Lazy<Mutex<LruCache<String, Vec<u8>>>> = Lazy::new(|| {
    Mutex::new(LruCache::new(100))
});

static RATE_LIMITER: Lazy<RateLimiter> = Lazy::new(|| {
    let quota = Quota::per_second(NonZeroU32::new(100).unwrap());
    RateLimiter::direct(quota)
});

#[instrument]
pub async fn run_dot_server() -> Result<(), Box<dyn std::error::Error>> {
    let bind_addr = std::env::var("DNS_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:853".to_string());
    let default_ttl = std::env::var("DNS_DEFAULT_TTL")
        .unwrap_or_else(|_| "60".to_string())
        .parse::<u32>()?;

    let cert = include_bytes!("../certs/cert.pem");
    let key = include_bytes!("../certs/key.pem");

    let certs = certs(&mut &cert[..])?
        .into_iter()
        .map(Certificate)
        .collect::<Vec<_>>();

    let mut key_reader = &key[..];
    let keys = pkcs8_private_keys(&mut key_reader)?;
    let key = keys.into_iter()
        .next()
        .ok_or("Private key not found")?;
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

        if RATE_LIMITER.check_one().is_err() {
            warn!(%peer_addr, "Rate limit reached");
            continue;
        }

        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_dot_connection(acceptor, stream, peer_addr).await {
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
) -> Result<(), Box<dyn std::error::Error>> {
    let mut tls_stream = acceptor.accept(stream).await?;
    info!(%peer_addr, "TLS connection established");

    let mut len_bytes = [0u8; 2];
    tls_stream.read_exact(&mut len_bytes).await?;
    let len = u16::from_be_bytes(len_bytes) as usize;

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

    info!(%peer_addr, query = ?packet, "Received DNS-over-TLS query");

    if packet.questions.is_empty() {
        warn!(%peer_addr, "Packet has no questions");
        return Ok(());
    }

    for question in &packet.questions {
        let domain = question.qname.to_string();
        info!(%peer_addr, %domain, "Processing DNS query");

        if let Some(response) = CACHE.lock().unwrap().get(&domain).cloned() {
            info!(%peer_addr, %domain, "Served response from cache");
            tls_stream.write_all(&response).await?;
            continue;
        }

        let response = match question.qtype {
            QueryType::A => {
                let ip = resolver::resolve_recursively(&domain)
                    .unwrap_or_else(|| "192.168.1.1".parse().unwrap());
                info!(%peer_addr, %domain, ip = %ip, "Resolved DNS A record");
                build_dns_response(&buf, &question.qname, ip, 60)?
            }
            QueryType::AAAA => {
                let ip = "::1".parse().unwrap();
                build_dns_response(&buf, &question.qname, ip, 60)?
            }
            _ => {
                warn!(%peer_addr, %domain, qtype = ?question.qtype, "Unsupported query type");
                continue;
            }
        };

        CACHE.lock().unwrap().put(domain.clone(), response.clone());
        tls_stream.write_all(&response).await?;
        info!(%peer_addr, %domain, "Response sent");
    }

    Ok(())
}

fn build_dns_response(
    query: &[u8],
    qname: &dns_parser::Name,
    ip: IpAddr,
    ttl: u32,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut response = Vec::new();
    response.extend_from_slice(&query[..2]); // Transaction ID
    response.push(0x81); // Flags: Standard query response
    response.push(0x80);
    response.extend_from_slice(&query[4..6]); // QDCOUNT
    response.extend_from_slice(b"\x00\x01"); // ANCOUNT
    response.extend_from_slice(b"\x00\x00"); // NSCOUNT
    response.extend_from_slice(b"\x00\x00"); // ARCOUNT
    response.extend_from_slice(&query[12..]); // Original question

    let rdata = match ip {
        IpAddr::V4(ipv4) => RData::A(dns_parser::rdata::A(ipv4)),
        IpAddr::V6(ipv6) => RData::AAAA(dns_parser::rdata::Aaaa(ipv6)),
    };

    let record = ResourceRecord {
        name: qname.clone(),
        cls: Class::IN,
        ttl,
        data: rdata,
        multicast_unique: false,
    };

    serialize_resource_record(&record, &mut response)?;
    Ok(response)
}
