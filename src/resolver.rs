use once_cell::sync::Lazy;
use std::net::IpAddr;
use trust_dns_resolver::Resolver;

static RESOLVER: Lazy<Option<Resolver>> = Lazy::new(|| Resolver::default().ok());

pub fn resolve_recursively(domain: &str) -> Option<IpAddr> {
    RESOLVER.as_ref()?.lookup_ip(domain).ok()?.iter().next()
}
