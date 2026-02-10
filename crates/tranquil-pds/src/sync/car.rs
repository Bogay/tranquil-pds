use cid::Cid;
use iroh_car::CarHeader;
use std::io::Write;

#[derive(Debug)]
pub enum CarEncodeError {
    CborEncodeFailed(String),
}

impl std::fmt::Display for CarEncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CborEncodeFailed(e) => write!(f, "Failed to encode CAR header: {}", e),
        }
    }
}

impl std::error::Error for CarEncodeError {}

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
    write_varint(
        &mut writer,
        u64::try_from(data.len()).expect("len fits u64"),
    )?;
    writer.write_all(data)?;
    Ok(())
}

pub fn encode_car_header_with_root(root_cid: Option<&Cid>) -> Result<Vec<u8>, CarEncodeError> {
    let roots = root_cid.map_or_else(Vec::new, |cid| vec![*cid]);
    let header = CarHeader::new_v1(roots);
    let header_cbor = header
        .encode()
        .map_err(|e| CarEncodeError::CborEncodeFailed(format!("{:?}", e)))?;
    let mut result = Vec::new();
    write_varint(
        &mut result,
        u64::try_from(header_cbor.len()).expect("len fits u64"),
    )
    .expect("Writing to Vec<u8> should never fail");
    result.extend_from_slice(&header_cbor);
    Ok(result)
}

pub fn encode_car_header(root_cid: &Cid) -> Result<Vec<u8>, CarEncodeError> {
    encode_car_header_with_root(Some(root_cid))
}

pub fn encode_car_header_null_root() -> Result<Vec<u8>, CarEncodeError> {
    encode_car_header_with_root(None)
}

pub fn encode_car_block(cid: &Cid, block: &[u8]) -> Vec<u8> {
    let cid_bytes = cid.to_bytes();
    let total_len = cid_bytes.len() + block.len();
    let mut buf = Vec::with_capacity(10 + total_len);
    write_varint(&mut buf, u64::try_from(total_len).unwrap_or(u64::MAX))
        .unwrap_or_else(|_| unreachable!());
    buf.extend_from_slice(&cid_bytes);
    buf.extend_from_slice(block);
    buf
}
