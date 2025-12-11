use cid::Cid;
use iroh_car::CarHeader;
use std::io::Write;

pub fn write_varint<W: Write>(mut writer: W, mut value: u64) -> std::io::Result<()> {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        writer.write_all(&[byte])?;
        if value == 0 {
            break;
        }
    }
    Ok(())
}

pub fn ld_write<W: Write>(mut writer: W, data: &[u8]) -> std::io::Result<()> {
    write_varint(&mut writer, data.len() as u64)?;
    writer.write_all(data)?;
    Ok(())
}

pub fn encode_car_header(root_cid: &Cid) -> Vec<u8> {
    let header = CarHeader::new_v1(vec![root_cid.clone()]);
    let header_cbor = header.encode().unwrap_or_default();

    let mut result = Vec::new();
    write_varint(&mut result, header_cbor.len() as u64).unwrap();
    result.extend_from_slice(&header_cbor);
    result
}
