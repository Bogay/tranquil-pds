use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
pub struct LexiconDoc {
    pub lexicon: u32,
    pub id: String,
    #[serde(default)]
    pub defs: HashMap<String, LexDef>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum LexDef {
    #[serde(rename = "record")]
    Record(LexRecord),
    #[serde(rename = "object")]
    Object(LexObject),
    #[serde(rename = "token")]
    Token {},
    #[serde(rename = "string")]
    StringDef(LexStringDef),
    #[serde(rename = "query")]
    Query {},
    #[serde(rename = "procedure")]
    Procedure {},
    #[serde(rename = "subscription")]
    Subscription {},
    #[serde(rename = "params")]
    Params {},
    #[serde(rename = "permission")]
    Permission {},
    #[serde(rename = "permission-set")]
    PermissionSet {},
}

#[derive(Debug, Deserialize)]
pub struct LexRecord {
    #[serde(default)]
    pub key: Option<String>,
    pub record: LexObject,
}

#[derive(Debug, Deserialize)]
pub struct LexObject {
    #[serde(default)]
    pub required: Vec<String>,
    #[serde(default)]
    pub nullable: Vec<String>,
    #[serde(default)]
    pub properties: HashMap<String, LexProperty>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum LexProperty {
    #[serde(rename = "string")]
    String(LexString),
    #[serde(rename = "integer")]
    Integer(LexInteger),
    #[serde(rename = "boolean")]
    Boolean {},
    #[serde(rename = "bytes")]
    Bytes(LexBytes),
    #[serde(rename = "cid-link")]
    CidLink {},
    #[serde(rename = "blob")]
    Blob(LexBlob),
    #[serde(rename = "unknown")]
    Unknown {},
    #[serde(rename = "ref")]
    Ref(LexRef),
    #[serde(rename = "union")]
    Union(LexUnion),
    #[serde(rename = "array")]
    Array(LexArray),
    #[serde(rename = "object")]
    Object(LexObject),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LexString {
    #[serde(default)]
    pub max_length: Option<u64>,
    #[serde(default)]
    pub min_length: Option<u64>,
    #[serde(default)]
    pub max_graphemes: Option<u64>,
    #[serde(default)]
    pub min_graphemes: Option<u64>,
    #[serde(default)]
    pub format: Option<StringFormat>,
    #[serde(default)]
    pub known_values: Option<Vec<String>>,
    #[serde(rename = "enum", default)]
    pub enum_values: Option<Vec<String>>,
    #[serde(rename = "const", default)]
    pub const_value: Option<String>,
    #[serde(default)]
    pub default: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LexInteger {
    #[serde(default)]
    pub minimum: Option<i64>,
    #[serde(default)]
    pub maximum: Option<i64>,
    #[serde(default)]
    pub default: Option<i64>,
    #[serde(rename = "enum", default)]
    pub enum_values: Option<Vec<i64>>,
    #[serde(rename = "const", default)]
    pub const_value: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LexBytes {
    #[serde(default)]
    pub max_length: Option<u64>,
    #[serde(default)]
    pub min_length: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LexBlob {
    #[serde(default)]
    pub accept: Option<Vec<String>>,
    #[serde(default)]
    pub max_size: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LexArray {
    pub items: Box<LexProperty>,
    #[serde(default)]
    pub min_length: Option<u64>,
    #[serde(default)]
    pub max_length: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct LexUnion {
    #[serde(default)]
    pub refs: Vec<String>,
    #[serde(default)]
    pub closed: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LexRef {
    #[serde(rename = "ref")]
    pub reference: String,
}

#[derive(Debug, Clone, Deserialize)]
pub enum StringFormat {
    #[serde(rename = "did")]
    Did,
    #[serde(rename = "handle")]
    Handle,
    #[serde(rename = "at-uri")]
    AtUri,
    #[serde(rename = "datetime")]
    Datetime,
    #[serde(rename = "uri")]
    Uri,
    #[serde(rename = "cid")]
    Cid,
    #[serde(rename = "language")]
    Language,
    #[serde(rename = "tid")]
    Tid,
    #[serde(rename = "record-key")]
    RecordKey,
    #[serde(rename = "at-identifier")]
    AtIdentifier,
    #[serde(rename = "nsid")]
    Nsid,
}

pub enum ParsedRef<'a> {
    Local(&'a str),
    Qualified { nsid: &'a str, fragment: &'a str },
    Bare(&'a str),
}

pub fn parse_ref(reference: &str) -> ParsedRef<'_> {
    match reference.strip_prefix('#') {
        Some(local) => ParsedRef::Local(local),
        None => {
            let stripped = reference.strip_prefix("lex:").unwrap_or(reference);
            match stripped.split_once('#') {
                Some((nsid, fragment)) => ParsedRef::Qualified { nsid, fragment },
                None => ParsedRef::Bare(stripped),
            }
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LexStringDef {}
