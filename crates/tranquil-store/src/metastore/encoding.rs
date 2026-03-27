use smallvec::SmallVec;

const NULL_ESCAPE: u8 = 0x01;
const NULL_TERMINATOR: [u8; 2] = [0x00, 0x00];

pub fn encode_u64(buf: &mut SmallVec<[u8; 128]>, value: u64) {
    buf.extend_from_slice(&value.to_be_bytes());
}

pub fn decode_u64(src: &[u8]) -> Option<(u64, &[u8])> {
    let (bytes, rest) = src.split_first_chunk::<8>()?;
    Some((u64::from_be_bytes(*bytes), rest))
}

pub fn encode_i64(buf: &mut SmallVec<[u8; 128]>, value: i64) {
    let encoded = (value as u64) ^ (1u64 << 63);
    buf.extend_from_slice(&encoded.to_be_bytes());
}

pub fn decode_i64(src: &[u8]) -> Option<(i64, &[u8])> {
    let (bytes, rest) = src.split_first_chunk::<8>()?;
    let raw = u64::from_be_bytes(*bytes) ^ (1u64 << 63);
    Some((raw as i64, rest))
}

pub fn encode_u32(buf: &mut SmallVec<[u8; 128]>, value: u32) {
    buf.extend_from_slice(&value.to_be_bytes());
}

pub fn decode_u32(src: &[u8]) -> Option<(u32, &[u8])> {
    let (bytes, rest) = src.split_first_chunk::<4>()?;
    Some((u32::from_be_bytes(*bytes), rest))
}

pub fn encode_u16(buf: &mut SmallVec<[u8; 128]>, value: u16) {
    buf.extend_from_slice(&value.to_be_bytes());
}

pub fn decode_u16(src: &[u8]) -> Option<(u16, &[u8])> {
    let (bytes, rest) = src.split_first_chunk::<2>()?;
    Some((u16::from_be_bytes(*bytes), rest))
}

pub fn encode_bool(buf: &mut SmallVec<[u8; 128]>, value: bool) {
    buf.push(u8::from(value));
}

pub fn decode_bool(src: &[u8]) -> Option<(bool, &[u8])> {
    let (&byte, rest) = src.split_first()?;
    match byte {
        0 => Some((false, rest)),
        1 => Some((true, rest)),
        _ => None,
    }
}

pub fn encode_bytes(buf: &mut SmallVec<[u8; 128]>, value: &[u8]) {
    value.iter().for_each(|&b| match b {
        0x00 => {
            buf.push(0x00);
            buf.push(NULL_ESCAPE);
        }
        other => buf.push(other),
    });
    buf.extend_from_slice(&NULL_TERMINATOR);
}

pub fn decode_bytes(src: &[u8]) -> Option<(Vec<u8>, &[u8])> {
    let mut result = Vec::new();
    let mut i = 0;
    loop {
        match src.get(i)? {
            0x00 => match src.get(i + 1)? {
                0x00 => return Some((result, &src[i + 2..])),
                &NULL_ESCAPE => {
                    result.push(0x00);
                    i += 2;
                }
                _ => return None,
            },
            &b => {
                result.push(b);
                i += 1;
            }
        }
    }
}

pub fn encode_string(buf: &mut SmallVec<[u8; 128]>, value: &str) {
    encode_bytes(buf, value.as_bytes());
}

pub fn decode_string(src: &[u8]) -> Option<(String, &[u8])> {
    let (bytes, rest) = decode_bytes(src)?;
    String::from_utf8(bytes).ok().map(|s| (s, rest))
}

pub struct KeyBuilder(SmallVec<[u8; 128]>);

impl KeyBuilder {
    pub fn new() -> Self {
        Self(SmallVec::new())
    }

    pub fn with_capacity(cap: usize) -> Self {
        Self(SmallVec::with_capacity(cap))
    }

    pub fn u64(mut self, value: u64) -> Self {
        encode_u64(&mut self.0, value);
        self
    }

    pub fn i64(mut self, value: i64) -> Self {
        encode_i64(&mut self.0, value);
        self
    }

    pub fn u32(mut self, value: u32) -> Self {
        encode_u32(&mut self.0, value);
        self
    }

    pub fn u16(mut self, value: u16) -> Self {
        encode_u16(&mut self.0, value);
        self
    }

    pub fn bool(mut self, value: bool) -> Self {
        encode_bool(&mut self.0, value);
        self
    }

    pub fn bytes(mut self, value: &[u8]) -> Self {
        encode_bytes(&mut self.0, value);
        self
    }

    pub fn string(mut self, value: &str) -> Self {
        encode_string(&mut self.0, value);
        self
    }

    pub fn tag(mut self, tag: super::keys::KeyTag) -> Self {
        self.0.push(tag.raw());
        self
    }

    pub fn fixed<const N: usize>(mut self, bytes: &[u8; N]) -> Self {
        self.0.extend_from_slice(bytes);
        self
    }

    pub fn raw(mut self, bytes: &[u8]) -> Self {
        self.0.extend_from_slice(bytes);
        self
    }

    pub fn build(self) -> SmallVec<[u8; 128]> {
        self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Default for KeyBuilder {
    fn default() -> Self {
        Self::new()
    }
}

pub struct KeyReader<'a>(&'a [u8]);

impl<'a> KeyReader<'a> {
    pub fn new(src: &'a [u8]) -> Self {
        Self(src)
    }

    pub fn u64(&mut self) -> Option<u64> {
        let (val, rest) = decode_u64(self.0)?;
        self.0 = rest;
        Some(val)
    }

    pub fn i64(&mut self) -> Option<i64> {
        let (val, rest) = decode_i64(self.0)?;
        self.0 = rest;
        Some(val)
    }

    pub fn u32(&mut self) -> Option<u32> {
        let (val, rest) = decode_u32(self.0)?;
        self.0 = rest;
        Some(val)
    }

    pub fn u16(&mut self) -> Option<u16> {
        let (val, rest) = decode_u16(self.0)?;
        self.0 = rest;
        Some(val)
    }

    pub fn bool(&mut self) -> Option<bool> {
        let (val, rest) = decode_bool(self.0)?;
        self.0 = rest;
        Some(val)
    }

    pub fn bytes(&mut self) -> Option<Vec<u8>> {
        let (val, rest) = decode_bytes(self.0)?;
        self.0 = rest;
        Some(val)
    }

    pub fn string(&mut self) -> Option<String> {
        let (val, rest) = decode_string(self.0)?;
        self.0 = rest;
        Some(val)
    }

    pub fn tag(&mut self) -> Option<u8> {
        let (&tag, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(tag)
    }

    pub fn remaining(&self) -> &'a [u8] {
        self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

pub fn exclusive_upper_bound(prefix: &[u8]) -> Option<SmallVec<[u8; 128]>> {
    prefix.iter().rposition(|&b| b != 0xFF).map(|pos| {
        let mut result = SmallVec::from_slice(&prefix[..=pos]);
        result[pos] = prefix[pos].wrapping_add(1);
        result
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn u64_roundtrip_boundaries() {
        [0u64, 1, u64::MAX / 2, u64::MAX - 1, u64::MAX]
            .iter()
            .for_each(|&v| {
                let mut buf = SmallVec::new();
                encode_u64(&mut buf, v);
                let (decoded, rest) = decode_u64(&buf).unwrap();
                assert_eq!(decoded, v);
                assert!(rest.is_empty());
            });
    }

    #[test]
    fn i64_roundtrip_boundaries() {
        [i64::MIN, -1, 0, 1, i64::MAX].iter().for_each(|&v| {
            let mut buf = SmallVec::new();
            encode_i64(&mut buf, v);
            let (decoded, rest) = decode_i64(&buf).unwrap();
            assert_eq!(decoded, v);
            assert!(rest.is_empty());
        });
    }

    #[test]
    fn bool_roundtrip() {
        [false, true].iter().for_each(|&v| {
            let mut buf = SmallVec::new();
            encode_bool(&mut buf, v);
            let (decoded, rest) = decode_bool(&buf).unwrap();
            assert_eq!(decoded, v);
            assert!(rest.is_empty());
        });
    }

    #[test]
    fn bytes_with_nulls() {
        let input = &[0x00, 0x01, 0x00, 0xFF, 0x00];
        let mut buf = SmallVec::new();
        encode_bytes(&mut buf, input);
        let (decoded, rest) = decode_bytes(&buf).unwrap();
        assert_eq!(decoded, input);
        assert!(rest.is_empty());
    }

    #[test]
    fn empty_bytes_roundtrip() {
        let mut buf = SmallVec::new();
        encode_bytes(&mut buf, &[]);
        let (decoded, rest) = decode_bytes(&buf).unwrap();
        assert!(decoded.is_empty());
        assert!(rest.is_empty());
    }

    #[test]
    fn empty_string_roundtrip() {
        let mut buf = SmallVec::new();
        encode_string(&mut buf, "");
        let (decoded, rest) = decode_string(&buf).unwrap();
        assert_eq!(decoded, "");
        assert!(rest.is_empty());
    }

    #[test]
    fn string_with_null_bytes() {
        let input = "hello\x00world";
        let mut buf = SmallVec::new();
        encode_string(&mut buf, input);
        let (decoded, rest) = decode_string(&buf).unwrap();
        assert_eq!(decoded, input);
        assert!(rest.is_empty());
    }

    #[test]
    fn key_builder_composite_roundtrip() {
        let key = KeyBuilder::new()
            .tag(super::super::keys::KeyTag::RECORDS)
            .u64(42)
            .string("app.bsky.feed.post")
            .string("3k2a")
            .build();

        let mut reader = KeyReader::new(&key);
        assert_eq!(
            reader.tag(),
            Some(super::super::keys::KeyTag::RECORDS.raw())
        );
        assert_eq!(reader.u64(), Some(42));
        assert_eq!(reader.string(), Some("app.bsky.feed.post".to_string()));
        assert_eq!(reader.string(), Some("3k2a".to_string()));
        assert!(reader.is_empty());
    }

    #[test]
    fn key_builder_ordering_preserves_field_order() {
        let key_a = KeyBuilder::new().u64(1).string("aaa").build();
        let key_b = KeyBuilder::new().u64(1).string("bbb").build();
        let key_c = KeyBuilder::new().u64(2).string("aaa").build();

        assert!(key_a.as_slice() < key_b.as_slice());
        assert!(key_b.as_slice() < key_c.as_slice());
    }

    #[test]
    fn decode_bytes_rejects_invalid_escape() {
        assert!(decode_bytes(&[0x00, 0x02]).is_none());
        assert!(decode_bytes(&[0x00, 0xFF]).is_none());
        assert!(decode_bytes(&[0x41, 0x00, 0x03]).is_none());
    }

    #[test]
    fn decode_bytes_rejects_truncated_input() {
        assert!(decode_bytes(&[]).is_none());
        assert!(decode_bytes(&[0x00]).is_none());
        assert!(decode_bytes(&[0x41]).is_none());
        assert!(decode_bytes(&[0x41, 0x00]).is_none());
        assert!(decode_bytes(&[0x00, 0x01]).is_none());
    }

    #[test]
    fn decode_bool_rejects_invalid_byte() {
        assert!(decode_bool(&[0x02]).is_none());
        assert!(decode_bool(&[0xFF]).is_none());
        assert!(decode_bool(&[]).is_none());
    }

    #[test]
    fn decode_string_rejects_invalid_utf8() {
        let mut buf = SmallVec::new();
        encode_bytes(&mut buf, &[0xFF, 0xFE]);
        assert!(decode_string(&buf).is_none());
    }

    #[test]
    fn decode_u64_rejects_short_input() {
        assert!(decode_u64(&[]).is_none());
        assert!(decode_u64(&[0x00; 7]).is_none());
    }

    #[test]
    fn decode_u32_rejects_short_input() {
        assert!(decode_u32(&[]).is_none());
        assert!(decode_u32(&[0x00; 3]).is_none());
    }

    #[test]
    fn decode_u16_rejects_short_input() {
        assert!(decode_u16(&[]).is_none());
        assert!(decode_u16(&[0x00]).is_none());
    }

    #[test]
    fn decode_i64_rejects_short_input() {
        assert!(decode_i64(&[]).is_none());
        assert!(decode_i64(&[0x00; 7]).is_none());
    }

    #[test]
    fn fixed_key_roundtrip() {
        let data: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];
        let key = KeyBuilder::new()
            .tag(super::super::keys::KeyTag::RECORDS)
            .fixed(&data)
            .build();

        let mut reader = KeyReader::new(&key);
        assert_eq!(
            reader.tag(),
            Some(super::super::keys::KeyTag::RECORDS.raw())
        );
        assert_eq!(reader.remaining(), &data);
    }

    proptest! {
        #[test]
        fn prop_u64_roundtrip(v: u64) {
            let mut buf = SmallVec::new();
            encode_u64(&mut buf, v);
            let (decoded, rest) = decode_u64(&buf).unwrap();
            prop_assert_eq!(decoded, v);
            prop_assert!(rest.is_empty());
        }

        #[test]
        fn prop_u64_ordering(a: u64, b: u64) {
            let mut buf_a = SmallVec::new();
            let mut buf_b = SmallVec::new();
            encode_u64(&mut buf_a, a);
            encode_u64(&mut buf_b, b);
            prop_assert_eq!(buf_a.as_slice().cmp(buf_b.as_slice()), a.cmp(&b));
        }

        #[test]
        fn prop_i64_roundtrip(v: i64) {
            let mut buf = SmallVec::new();
            encode_i64(&mut buf, v);
            let (decoded, rest) = decode_i64(&buf).unwrap();
            prop_assert_eq!(decoded, v);
            prop_assert!(rest.is_empty());
        }

        #[test]
        fn prop_i64_ordering(a: i64, b: i64) {
            let mut buf_a = SmallVec::new();
            let mut buf_b = SmallVec::new();
            encode_i64(&mut buf_a, a);
            encode_i64(&mut buf_b, b);
            prop_assert_eq!(buf_a.as_slice().cmp(buf_b.as_slice()), a.cmp(&b));
        }

        #[test]
        fn prop_u32_roundtrip(v: u32) {
            let mut buf = SmallVec::new();
            encode_u32(&mut buf, v);
            let (decoded, rest) = decode_u32(&buf).unwrap();
            prop_assert_eq!(decoded, v);
            prop_assert!(rest.is_empty());
        }

        #[test]
        fn prop_u32_ordering(a: u32, b: u32) {
            let mut buf_a = SmallVec::new();
            let mut buf_b = SmallVec::new();
            encode_u32(&mut buf_a, a);
            encode_u32(&mut buf_b, b);
            prop_assert_eq!(buf_a.as_slice().cmp(buf_b.as_slice()), a.cmp(&b));
        }

        #[test]
        fn prop_u16_roundtrip(v: u16) {
            let mut buf = SmallVec::new();
            encode_u16(&mut buf, v);
            let (decoded, rest) = decode_u16(&buf).unwrap();
            prop_assert_eq!(decoded, v);
            prop_assert!(rest.is_empty());
        }

        #[test]
        fn prop_u16_ordering(a: u16, b: u16) {
            let mut buf_a = SmallVec::new();
            let mut buf_b = SmallVec::new();
            encode_u16(&mut buf_a, a);
            encode_u16(&mut buf_b, b);
            prop_assert_eq!(buf_a.as_slice().cmp(buf_b.as_slice()), a.cmp(&b));
        }

        #[test]
        fn prop_bool_roundtrip(v: bool) {
            let mut buf = SmallVec::new();
            encode_bool(&mut buf, v);
            let (decoded, rest) = decode_bool(&buf).unwrap();
            prop_assert_eq!(decoded, v);
            prop_assert!(rest.is_empty());
        }

        #[test]
        fn prop_bool_ordering(a: bool, b: bool) {
            let mut buf_a = SmallVec::new();
            let mut buf_b = SmallVec::new();
            encode_bool(&mut buf_a, a);
            encode_bool(&mut buf_b, b);
            prop_assert_eq!(buf_a.as_slice().cmp(buf_b.as_slice()), a.cmp(&b));
        }

        #[test]
        fn prop_bytes_roundtrip(v in proptest::collection::vec(any::<u8>(), 0..256)) {
            let mut buf = SmallVec::new();
            encode_bytes(&mut buf, &v);
            let (decoded, rest) = decode_bytes(&buf).unwrap();
            prop_assert_eq!(decoded, v);
            prop_assert!(rest.is_empty());
        }

        #[test]
        fn prop_bytes_ordering(
            a in proptest::collection::vec(any::<u8>(), 0..64),
            b in proptest::collection::vec(any::<u8>(), 0..64),
        ) {
            let mut buf_a = SmallVec::new();
            let mut buf_b = SmallVec::new();
            encode_bytes(&mut buf_a, &a);
            encode_bytes(&mut buf_b, &b);
            prop_assert_eq!(buf_a.as_slice().cmp(buf_b.as_slice()), a.cmp(&b));
        }

        #[test]
        fn prop_string_roundtrip(v in "\\PC{0,128}") {
            let mut buf = SmallVec::new();
            encode_string(&mut buf, &v);
            let (decoded, rest) = decode_string(&buf).unwrap();
            prop_assert_eq!(decoded, v);
            prop_assert!(rest.is_empty());
        }

        #[test]
        fn prop_string_ordering(
            a in "[\\x00-\\xff]{0,32}",
            b in "[\\x00-\\xff]{0,32}",
        ) {
            let mut buf_a = SmallVec::new();
            let mut buf_b = SmallVec::new();
            encode_string(&mut buf_a, &a);
            encode_string(&mut buf_b, &b);
            prop_assert_eq!(
                buf_a.as_slice().cmp(buf_b.as_slice()),
                a.as_bytes().cmp(b.as_bytes())
            );
        }

        #[test]
        fn prop_composite_roundtrip(
            tag_raw in 0u8..=255,
            num in any::<u64>(),
            s1 in "\\PC{0,32}",
            s2 in "\\PC{0,32}",
        ) {
            let tag = super::super::keys::KeyTag::from_raw_unchecked(tag_raw);
            let key = KeyBuilder::new()
                .tag(tag)
                .u64(num)
                .string(&s1)
                .string(&s2)
                .build();

            let mut reader = KeyReader::new(&key);
            prop_assert_eq!(reader.tag(), Some(tag_raw));
            prop_assert_eq!(reader.u64(), Some(num));
            prop_assert_eq!(reader.string(), Some(s1));
            prop_assert_eq!(reader.string(), Some(s2));
            prop_assert!(reader.is_empty());
        }

        #[test]
        fn prop_composite_ordering(
            tag_raw in 0u8..=10,
            a_num in any::<u64>(),
            b_num in any::<u64>(),
            a_str in "[a-z]{0,8}",
            b_str in "[a-z]{0,8}",
        ) {
            let tag = super::super::keys::KeyTag::from_raw_unchecked(tag_raw);
            let key_a = KeyBuilder::new().tag(tag).u64(a_num).string(&a_str).build();
            let key_b = KeyBuilder::new().tag(tag).u64(b_num).string(&b_str).build();

            let expected = a_num.cmp(&b_num).then_with(|| a_str.as_bytes().cmp(b_str.as_bytes()));
            prop_assert_eq!(key_a.as_slice().cmp(key_b.as_slice()), expected);
        }
    }
}
