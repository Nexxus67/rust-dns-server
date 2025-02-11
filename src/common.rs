use dns_parser::{RData, Class};
use std::io::Write;

pub fn serialize_resource_record(record: &dns_parser::ResourceRecord, buf: &mut Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
    // Serializar el nombre del registro
    serialize_name(&record.name, buf)?;

    // Serializar el tipo y clase
    let record_type: u16 = match &record.data {
        RData::A(_) => 1,       // Tipo A (IPv4)
        RData::AAAA(_) => 28,   // Tipo AAAA (IPv6)
        _ => return Err("Tipo de registro no soportado".into()),
    };
    buf.write_all(&record_type.to_be_bytes())?;
    buf.write_all(&(Class::IN as u16).to_be_bytes())?;

    // Serializar el TTL y la longitud de los datos
    buf.write_all(&record.ttl.to_be_bytes())?;
    let data_len_pos = buf.len();
    buf.extend_from_slice(&[0, 0]); // Reservar espacio para la longitud

    // Serializar los datos del registro
    let start_len = buf.len();
    match &record.data {
        RData::A(a) => buf.write_all(&a.0.octets())?,
        RData::AAAA(aaaa) => buf.write_all(&aaaa.0.octets())?,
        _ => return Err("Tipo de registro no soportado".into()),
    }
    let end_len = buf.len();

    let data_len = (end_len - start_len) as u16;
    buf[data_len_pos..data_len_pos + 2].copy_from_slice(&data_len.to_be_bytes());

    Ok(())
}

fn serialize_name(name: &dns_parser::Name, buf: &mut Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
    let s = name.to_string();
    for label in s.split('.') {
        if !label.is_empty() {
            let len = label.len();
            if len > 63 {
                return Err("Etiqueta demasiado larga".into());
            }
            buf.push(len as u8);
            buf.extend_from_slice(label.as_bytes());
        }
    }
    buf.push(0);
    Ok(())
}
