use dns_parser::{Packet, RData, ResourceRecord, Class};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::net::UdpSocket;
use crate::resolver;
use crate::common::serialize_resource_record;

pub async fn run_dns_server() -> Result<(), Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind("0.0.0.0:53").await?;
    println!("Servidor DNS básico iniciado en 0.0.0.0:53");

    let mut buf = [0u8; 512];

    loop {
        let (size, src) = socket.recv_from(&mut buf).await?;
        let query = &buf[..size];

        if let Ok(packet) = Packet::parse(query) {
            println!("Consulta DNS recibida desde {:?}: {:?}", src, packet);

            let mut response = Vec::new();
            response.extend_from_slice(&query[..2]); // ID de la consulta
            response.push(0x81); // Flags: Respuesta estándar
            response.push(0x80);
            response.extend_from_slice(&query[4..6]); // QDCOUNT
            response.extend_from_slice(b"\x00\x01"); // ANCOUNT (1 respuesta)
            response.extend_from_slice(b"\x00\x00"); // NSCOUNT
            response.extend_from_slice(b"\x00\x00"); // ARCOUNT

            response.extend_from_slice(&query[12..]);

            // Resolver recursivamente o usar una IP fija
            let domain = packet.questions[0].qname.to_string();
            let ip = resolver::resolve_recursively(&domain).unwrap_or_else(|| "192.168.1.1".parse().unwrap());

            let rdata = match ip {
                IpAddr::V4(ipv4) => RData::A(dns_parser::rdata::A(ipv4)),
                IpAddr::V6(ipv6) => RData::AAAA(dns_parser::rdata::Aaaa(ipv6)),
            };

            let record = ResourceRecord {
                name: packet.questions[0].qname.clone(),
                cls: Class::IN, // Clase IN (Internet)
                ttl: 60,       // TTL
                data: rdata,
                multicast_unique: false, // Campo multicast_unique
            };

            // Serializar manualmente el registro DNS
            serialize_resource_record(&record, &mut response)?;

            socket.send_to(&response, src).await?;
        }
    }
}
