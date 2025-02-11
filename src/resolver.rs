use trust_dns_resolver::Resolver;
use std::net::IpAddr;

pub fn resolve_recursively(domain: &str) -> Option<IpAddr> {
    let resolver = Resolver::default().unwrap();
    resolver.lookup_ip(domain).ok()?.iter().next()
}
