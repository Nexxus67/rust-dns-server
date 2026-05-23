use crate::common::{build_dns_response, DNS_HEADER_SIZE, DNS_UDP_BUFFER_SIZE, FALLBACK_IPV4};
use crate::resolver;
use dns_parser::Packet;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{info, warn};

pub async fn run_dns_server() -> Result<(), Box<dyn std::error::Error>> {
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:53").await?);
    info!("DNS server started on 0.0.0.0:53");

    let mut buf = [0u8; DNS_UDP_BUFFER_SIZE];

    loop {
        let (size, src) = socket.recv_from(&mut buf).await?;

        if size < DNS_HEADER_SIZE {
            continue;
        }

        let query = buf[..size].to_vec();
        let socket = Arc::clone(&socket);

        // Handle each query concurrently so a slow resolution does not stall
        // the receive loop.
        tokio::spawn(async move {
            let packet = match Packet::parse(&query) {
                Ok(p) => p,
                Err(_) => return,
            };

            let [question] = packet.questions.as_slice() else {
                warn!(%src, question_count = packet.questions.len(), "Skipping packet with unexpected question count");
                return;
            };

            info!(%src, domain = %question.qname, "Received DNS query");

            let ip = resolver::resolve_recursively_async(question.qname.to_string())
                .await
                .unwrap_or(IpAddr::V4(FALLBACK_IPV4));

            let response = match build_dns_response(&query, &question.qname, ip, 60) {
                Ok(r) => r,
                Err(e) => {
                    warn!(%src, error = %e, "Failed to build DNS response");
                    return;
                }
            };

            if let Err(e) = socket.send_to(&response, src).await {
                warn!(%src, error = %e, "Failed to send DNS response");
            }
        });
    }
}
