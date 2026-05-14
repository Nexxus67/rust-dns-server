use crate::common::{build_dns_response, DNS_HEADER_SIZE, DNS_UDP_BUFFER_SIZE, FALLBACK_IPV4};
use crate::resolver;
use dns_parser::Packet;
use std::net::IpAddr;
use tokio::net::UdpSocket;
use tracing::{info, warn};

pub async fn run_dns_server() -> Result<(), Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind("0.0.0.0:53").await?;
    info!("DNS server started on 0.0.0.0:53");

    let mut buf = [0u8; DNS_UDP_BUFFER_SIZE];

    loop {
        let (size, src) = socket.recv_from(&mut buf).await?;
        let query = &buf[..size];

        if query.len() < DNS_HEADER_SIZE {
            continue;
        }

        let packet = match Packet::parse(query) {
            Ok(p) => p,
            Err(_) => continue,
        };

        let [question] = packet.questions.as_slice() else {
            warn!(%src, question_count = packet.questions.len(), "Skipping packet with unexpected question count");
            continue;
        };

        info!(%src, domain = %question.qname, "Received DNS query");

        let ip = resolver::resolve_recursively(&question.qname.to_string())
            .unwrap_or(IpAddr::V4(FALLBACK_IPV4));

        let response = match build_dns_response(query, &question.qname, ip, 60) {
            Ok(r) => r,
            Err(e) => {
                warn!(%src, error = %e, "Failed to build DNS response");
                continue;
            }
        };

        socket.send_to(&response, src).await?;
    }
}
