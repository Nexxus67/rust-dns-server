use std::net::IpAddr;
use trust_dns_resolver::Resolver;

pub fn resolve_recursively(domain: &str) -> Option<IpAddr> {
    let resolver = Resolver::default().ok()?;
    resolver.lookup_ip(domain).ok()?.iter().next()
}
