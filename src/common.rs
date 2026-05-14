use dns_parser::{Class, Name, RData, ResourceRecord};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const DNS_HEADER_SIZE: usize = 12;
pub const DNS_UDP_BUFFER_SIZE: usize = 512;
pub const FALLBACK_IPV4: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
pub const FALLBACK_IPV6: Ipv6Addr = Ipv6Addr::LOCALHOST;

const DNS_FLAGS_STANDARD_RESPONSE: [u8; 2] = [0x81, 0x80];

pub fn build_dns_response(
    query: &[u8],
    qname: &Name,
    ip: IpAddr,
    ttl: u32,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if query.len() < DNS_HEADER_SIZE {
        return Err("DNS query too short".into());
    }

    let mut response = Vec::new();
    response.extend_from_slice(&query[..2]); // Transaction ID
    response.extend_from_slice(&DNS_FLAGS_STANDARD_RESPONSE);
    response.extend_from_slice(&query[4..6]); // QDCOUNT
    response.extend_from_slice(b"\x00\x01"); // ANCOUNT
    response.extend_from_slice(b"\x00\x00"); // NSCOUNT
    response.extend_from_slice(b"\x00\x00"); // ARCOUNT
    response.extend_from_slice(&query[DNS_HEADER_SIZE..]); // Original question

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

pub fn serialize_resource_record(
    record: &dns_parser::ResourceRecord,
    buf: &mut Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    serialize_name(&record.name, buf)?;

    let record_type: u16 = match &record.data {
        RData::A(_) => 1,
        RData::AAAA(_) => 28,
        _ => return Err("Unsupported record type".into()),
    };
    buf.write_all(&record_type.to_be_bytes())?;
    buf.write_all(&(Class::IN as u16).to_be_bytes())?;

    buf.write_all(&record.ttl.to_be_bytes())?;
    let data_len_pos = buf.len();
    buf.extend_from_slice(&[0, 0]);

    let start_len = buf.len();
    match &record.data {
        RData::A(a) => buf.write_all(&a.0.octets())?,
        RData::AAAA(aaaa) => buf.write_all(&aaaa.0.octets())?,
        _ => return Err("Unsupported record type".into()),
    }
    let end_len = buf.len();

    let data_len = (end_len - start_len) as u16;
    buf[data_len_pos..data_len_pos + 2].copy_from_slice(&data_len.to_be_bytes());

    Ok(())
}

fn serialize_name(
    name: &dns_parser::Name,
    buf: &mut Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    for label in name.to_string().split('.') {
        if !label.is_empty() {
            let len = label.len();
            if len > 63 {
                return Err("DNS label too long".into());
            }
            buf.push(len as u8);
            buf.extend_from_slice(label.as_bytes());
        }
    }
    buf.push(0);
    Ok(())
}
