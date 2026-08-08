use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use brotli::{CompressorWriter, Decompressor};
use std::fmt;
use std::io::{Read, Write};

const COMPRESSED_PREFIX: &str = "$br$";
const QUALITY: u32 = 9;
const WINDOW_BITS: u32 = 16;
const BUFFER_SIZE: usize = 4096;
const MAX_SCOPE_LEN: u64 = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeDecodeError {
    Base64DecodeFailed,
    DecompressFailed,
    TooLarge,
}

impl fmt::Display for ScopeDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Base64DecodeFailed => write!(f, "Base64 decode of compressed scope failed"),
            Self::DecompressFailed => write!(f, "Brotli decompression of scope failed"),
            Self::TooLarge => write!(f, "Decompressed scope exceeds maximum length"),
        }
    }
}

impl std::error::Error for ScopeDecodeError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeEncodeError {
    TooLarge,
}

impl fmt::Display for ScopeEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => write!(f, "Scope exceeds maximum length"),
        }
    }
}

impl std::error::Error for ScopeEncodeError {}

fn brotli_compress(input: &str) -> Vec<u8> {
    let mut writer = CompressorWriter::new(Vec::new(), BUFFER_SIZE, QUALITY, WINDOW_BITS);

    writer
        .write_all(input.as_bytes())
        .expect("writing to a Vec cannot fail");

    writer.into_inner()
}

fn brotli_decompress(input: &[u8]) -> Result<String, ScopeDecodeError> {
    let mut output = String::new();

    Decompressor::new(input, BUFFER_SIZE)
        .take(MAX_SCOPE_LEN + 1)
        .read_to_string(&mut output)
        .map_err(|_| ScopeDecodeError::DecompressFailed)?;

    if output.len() as u64 > MAX_SCOPE_LEN {
        return Err(ScopeDecodeError::TooLarge);
    }

    Ok(output)
}

pub fn encode_scope(scope: &str) -> Result<String, ScopeEncodeError> {
    if scope.len() as u64 > MAX_SCOPE_LEN {
        return Err(ScopeEncodeError::TooLarge);
    }

    let encoded = URL_SAFE_NO_PAD.encode(brotli_compress(scope));

    if COMPRESSED_PREFIX.len() + encoded.len() < scope.len() {
        Ok(format!("{COMPRESSED_PREFIX}{encoded}"))
    } else {
        Ok(scope.to_owned())
    }
}

pub fn decode_scope(scope: &str) -> Result<String, ScopeDecodeError> {
    let Some(encoded) = scope.strip_prefix(COMPRESSED_PREFIX) else {
        return Ok(scope.to_owned());
    };

    let compressed = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ScopeDecodeError::Base64DecodeFailed)?;

    brotli_decompress(&compressed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn long_scope() -> String {
        let mut scope = String::from("transition:generic transition:chat.bsky");
        for collection in [
            "social.colibri.message",
            "social.colibri.community",
            "social.colibri.reaction",
            "social.colibri.member",
            "social.colibri.channel.read",
        ] {
            scope.push_str(&format!(" repo:{collection}?action=create&action=delete"));
        }
        scope
    }

    #[test]
    fn long_scope_roundtrips_through_compression() {
        let scope = long_scope();
        let encoded = encode_scope(&scope).unwrap();

        assert!(encoded.starts_with(COMPRESSED_PREFIX));
        assert!(encoded.len() < scope.len());
        assert_eq!(decode_scope(&encoded).unwrap(), scope);
    }

    #[test]
    fn short_scope_stays_plaintext() {
        let encoded = encode_scope("com.atproto.access").unwrap();

        assert_eq!(encoded, "com.atproto.access");
        assert_eq!(decode_scope(&encoded).unwrap(), "com.atproto.access");
    }

    #[test]
    fn untagged_scope_passes_through() {
        assert_eq!(
            decode_scope("com.atproto.refresh").unwrap(),
            "com.atproto.refresh"
        );
        assert_eq!(decode_scope("").unwrap(), "");
    }

    #[test]
    fn malformed_compressed_scope_errors_instead_of_panicking() {
        assert_eq!(
            decode_scope("$br$not valid base64!"),
            Err(ScopeDecodeError::Base64DecodeFailed)
        );
        assert_eq!(
            decode_scope("$br$AAAAAAAAAAAAAAAA"),
            Err(ScopeDecodeError::DecompressFailed)
        );
    }

    #[test]
    fn compression_bomb_is_rejected() {
        let bomb = URL_SAFE_NO_PAD.encode(brotli_compress(&"a".repeat(MAX_SCOPE_LEN as usize * 2)));

        assert_eq!(
            decode_scope(&format!("{COMPRESSED_PREFIX}{bomb}")),
            Err(ScopeDecodeError::TooLarge)
        );
    }

    #[test]
    fn encode_rejects_oversized_scope() {
        let oversized = "a".repeat(MAX_SCOPE_LEN as usize + 1);

        assert_eq!(encode_scope(&oversized), Err(ScopeEncodeError::TooLarge));
        assert!(encode_scope(&"a".repeat(MAX_SCOPE_LEN as usize)).is_ok());
    }
}
