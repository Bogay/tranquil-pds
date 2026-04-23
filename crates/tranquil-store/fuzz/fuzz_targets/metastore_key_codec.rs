#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use tranquil_store::metastore::encoding::{KeyBuilder, KeyReader};

#[derive(Arbitrary, Debug, PartialEq, Eq)]
enum Field {
    U64(u64),
    I64(i64),
    U32(u32),
    U16(u16),
    Bool(bool),
    Bytes(Vec<u8>),
    String(String),
}

fn append(builder: KeyBuilder, field: &Field) -> KeyBuilder {
    match field {
        Field::U64(v) => builder.u64(*v),
        Field::I64(v) => builder.i64(*v),
        Field::U32(v) => builder.u32(*v),
        Field::U16(v) => builder.u16(*v),
        Field::Bool(v) => builder.bool(*v),
        Field::Bytes(v) => builder.bytes(v),
        Field::String(v) => builder.string(v),
    }
}

fn consume(reader: &mut KeyReader<'_>, field: &Field) -> bool {
    match field {
        Field::U64(v) => reader.u64() == Some(*v),
        Field::I64(v) => reader.i64() == Some(*v),
        Field::U32(v) => reader.u32() == Some(*v),
        Field::U16(v) => reader.u16() == Some(*v),
        Field::Bool(v) => reader.bool() == Some(*v),
        Field::Bytes(v) => reader.bytes().as_deref() == Some(v.as_slice()),
        Field::String(v) => reader.string().as_deref() == Some(v.as_str()),
    }
}

#[derive(Arbitrary, Debug)]
enum Mode {
    Roundtrip(Vec<Field>),
    Raw(Vec<u8>),
}

fuzz_target!(|mode: Mode| {
    match mode {
        Mode::Roundtrip(fields) => {
            let encoded1 = fields.iter().fold(KeyBuilder::new(), append).build();

            let mut reader = KeyReader::new(encoded1.as_slice());
            let all_match = fields.iter().all(|f| consume(&mut reader, f));
            assert!(all_match, "roundtrip decode failed");
            assert!(reader.is_empty(), "trailing bytes after decode");

            let encoded2 = fields.iter().fold(KeyBuilder::new(), append).build();
            assert_eq!(
                encoded1.as_slice(),
                encoded2.as_slice(),
                "encoding not deterministic",
            );
        }
        Mode::Raw(data) => {
            let mut reader = KeyReader::new(&data);
            let _ = reader.u64();
            let _ = reader.i64();
            let _ = reader.u32();
            let _ = reader.u16();
            let _ = reader.bool();
            let _ = reader.bytes();
            let _ = reader.string();
            let _ = reader.tag();
        }
    }
});
