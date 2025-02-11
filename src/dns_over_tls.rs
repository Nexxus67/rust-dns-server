use dns_parser::{Packet, RData, ResourceRecord, Class};
use rustls::{ServerConfig, Certificate, PrivateKey};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use crate::resolver;
use crate::common::serialize_resource_record;
use rustls_pemfile::{certs, pkcs8_private_keys};

pub async fn run_dot_server() -> Result<(), Box<dyn std::error::Error>> {
    // Leer los certificados y la clave privada
    let cert = include_bytes!("../certs/cert.pem");
    let key = include_bytes!("../certs/key.pem");

    // Cargar certificados
    let certs = certs(&mut &cert[..])?
        .into_iter()
        .map(Certificate)
        .collect::<Vec<_>>();

    // Cargar clave privada
    let mut key_reader = &key[..];
    let keys = pkcs8_private_keys(&mut key_reader)?;
    let key = keys.into_iter()
        .next()
        .ok_or("No se encontró ninguna clave privada")?;
    let key = PrivateKey(key);

    // Configurar TLS
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth() // No se requiere autenticación del cliente
        .with_single_cert(certs, key)
        .unwrap();

    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("0.0.0.0:853").await?;
    println!("Servidor DNS-over-TLS iniciado en 0.0.0.0:853");

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        println!("Nueva conexión TLS desde: {}", peer_addr);
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_dot_connection(acceptor, stream, peer_addr).await {
                eprintln!("Error al manejar conexión DoT: {}", e);
            }
        });
    }
}

async fn handle_dot_connection(
    acceptor: TlsAcceptor,
    stream: TcpStream,
    peer_addr: std::net::SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut tls_stream = acceptor.accept(stream).await?;
    println!("Conexión TLS establecida con: {}", peer_addr);

    let mut buf = [0u8; 512];
    let size = tls_stream.read(&mut buf).await?;
    let query = &buf[..size];

    if let Ok(packet) = Packet::parse(query) {
        println!("Consulta DNS-over-TLS recibida desde {}: {:?}", peer_addr, packet);

        // Extraer el dominio consultado
        let domain = packet.questions[0].qname.to_string();
        println!("Cliente {} visitó el sitio: {}", peer_addr, domain);

        // Resolver el dominio
        let ip = resolver::resolve_recursively(&domain).unwrap_or_else(|| "192.168.1.1".parse().unwrap());
        println!("Resolviendo {} como {}", domain, ip);

        // Construir la respuesta DNS
        let mut response = Vec::new();
        response.extend_from_slice(&query[..2]); // ID de la consulta
        response.push(0x81); // Flags: Respuesta estándar
        response.push(0x80);
        response.extend_from_slice(&query[4..6]); // QDCOUNT
        response.extend_from_slice(b"\x00\x01"); // ANCOUNT (1 respuesta)
        response.extend_from_slice(b"\x00\x00"); // NSCOUNT
        response.extend_from_slice(b"\x00\x00"); // ARCOUNT
        response.extend_from_slice(&query[12..]);

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

        // Enviar la respuesta al cliente
        tls_stream.write_all(&response).await?;
        println!("Respuesta enviada a {}: {:?}", peer_addr, response);
    }

    Ok(())
}