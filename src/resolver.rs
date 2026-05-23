use once_cell::sync::Lazy;
use std::net::IpAddr;
use trust_dns_resolver::Resolver;

static RESOLVER: Lazy<Option<Resolver>> = Lazy::new(|| Resolver::default().ok());

pub fn resolve_recursively(domain: &str) -> Option<IpAddr> {
    RESOLVER.as_ref()?.lookup_ip(domain).ok()?.iter().next()
}

/// Offloads the blocking resolver to Tokio's blocking pool so the async
/// runtime threads stay free to handle other connections.
pub async fn resolve_recursively_async(domain: String) -> Option<IpAddr> {
    tokio::task::spawn_blocking(move || resolve_recursively(&domain))
        .await
        .ok()
        .flatten()
}
