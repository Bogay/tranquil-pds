use cid::Cid;
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
    let header = serde_ipld_dagcbor::to_vec(&serde_json::json!({
        "version": 1u64,
        "roots": [root_cid.to_bytes()]
    }))
    .unwrap_or_default();
    header
}
