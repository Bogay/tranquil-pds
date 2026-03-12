use crate::formats::validate_format;
use crate::registry::LexiconRegistry;
use crate::schema::{
    LexArray, LexBlob, LexBytes, LexDef, LexObject, LexProperty, LexString, LexUnion, ParsedRef,
    parse_ref,
};
use thiserror::Error;
use unicode_segmentation::UnicodeSegmentation;

const MAX_RECURSION_DEPTH: u32 = 32;

#[derive(Debug, Error)]
pub enum LexValidationError {
    #[error("Lexicon not found: {0}")]
    LexiconNotFound(String),
    #[error("Missing required field: {path}")]
    MissingRequired { path: String },
    #[error("Invalid field at {path}: {message}")]
    InvalidField { path: String, message: String },
    #[error("Recursion depth exceeded at {path}")]
    RecursionDepthExceeded { path: String },
}

impl LexValidationError {
    fn field(path: &str, message: impl Into<String>) -> Self {
        Self::InvalidField {
            path: path.to_string(),
            message: message.into(),
        }
    }
}

fn resolve_union_ref(reference: &str, context_nsid: &str) -> String {
    match parse_ref(reference) {
        ParsedRef::Local(local) => format!("{}#{}", context_nsid, local),
        ParsedRef::Qualified { nsid, fragment } => format!("{}#{}", nsid, fragment),
        ParsedRef::Bare(nsid) => nsid.to_string(),
    }
}

fn ref_to_context_nsid<'a>(reference: &'a str, current_context: &'a str) -> &'a str {
    match parse_ref(reference) {
        ParsedRef::Local(_) => current_context,
        ParsedRef::Qualified { nsid, .. } | ParsedRef::Bare(nsid) => nsid,
    }
}

pub fn validate_record(
    registry: &LexiconRegistry,
    nsid: &str,
    value: &serde_json::Value,
) -> Result<(), LexValidationError> {
    let doc = registry
        .get_record_def(nsid)
        .ok_or_else(|| LexValidationError::LexiconNotFound(nsid.to_string()))?;

    let LexDef::Record(rec) = doc
        .defs
        .get("main")
        .expect("get_record_def guarantees main exists")
    else {
        unreachable!("get_record_def guarantees main is Record")
    };

    validate_object(registry, nsid, &rec.record, value, "", 0)
}

fn validate_object(
    registry: &LexiconRegistry,
    context_nsid: &str,
    schema: &LexObject,
    value: &serde_json::Value,
    path: &str,
    depth: u32,
) -> Result<(), LexValidationError> {
    if depth > MAX_RECURSION_DEPTH {
        return Err(LexValidationError::RecursionDepthExceeded {
            path: path.to_string(),
        });
    }

    let obj = value
        .as_object()
        .ok_or_else(|| LexValidationError::field(path, "expected an object"))?;

    schema.required.iter().try_for_each(|field| {
        let is_present = obj
            .get(field.as_str())
            .is_some_and(|v| !v.is_null() || schema.nullable.contains(field));
        if is_present {
            Ok(())
        } else {
            Err(LexValidationError::MissingRequired {
                path: field_path(path, field),
            })
        }
    })?;

    schema
        .properties
        .iter()
        .filter(|(key, _)| obj.contains_key(key.as_str()))
        .try_for_each(|(key, prop)| {
            let field_val = &obj[key.as_str()];
            let fp = field_path(path, key);

            if schema.nullable.contains(key) && field_val.is_null() {
                return Ok(());
            }

            validate_property(registry, context_nsid, prop, field_val, &fp, depth + 1)
        })
}

fn validate_property(
    registry: &LexiconRegistry,
    context_nsid: &str,
    prop: &LexProperty,
    value: &serde_json::Value,
    path: &str,
    depth: u32,
) -> Result<(), LexValidationError> {
    if depth > MAX_RECURSION_DEPTH {
        return Err(LexValidationError::RecursionDepthExceeded {
            path: path.to_string(),
        });
    }

    match prop {
        LexProperty::String(lex_str) => validate_string(lex_str, value, path),
        LexProperty::Integer(lex_int) => {
            let n = value
                .as_i64()
                .or_else(|| {
                    value.as_f64().and_then(|f| {
                        (f.fract() == 0.0 && (i64::MIN as f64..=i64::MAX as f64).contains(&f))
                            .then_some(f as i64)
                    })
                })
                .ok_or_else(|| LexValidationError::field(path, "expected an integer"))?;
            if let Some(min) = lex_int.minimum
                && n < min
            {
                return Err(LexValidationError::field(
                    path,
                    format!("value {} below minimum {}", n, min),
                ));
            }
            if let Some(max) = lex_int.maximum
                && n > max
            {
                return Err(LexValidationError::field(
                    path,
                    format!("value {} above maximum {}", n, max),
                ));
            }
            if let Some(ref enum_vals) = lex_int.enum_values
                && !enum_vals.contains(&n)
            {
                return Err(LexValidationError::field(
                    path,
                    format!("value {} not in enum", n),
                ));
            }
            if let Some(const_val) = lex_int.const_value
                && n != const_val
            {
                return Err(LexValidationError::field(
                    path,
                    format!("expected const value {}", const_val),
                ));
            }
            Ok(())
        }
        LexProperty::Boolean {} => value
            .is_boolean()
            .then_some(())
            .ok_or_else(|| LexValidationError::field(path, "expected a boolean")),
        LexProperty::CidLink {} => validate_cid_link(value, path),
        LexProperty::Blob(lex_blob) => validate_blob_ref(lex_blob, value, path),
        LexProperty::Unknown {} => Ok(()),
        LexProperty::Bytes(lex_bytes) => validate_bytes(lex_bytes, value, path),
        LexProperty::Ref(lex_ref) => validate_ref(
            registry,
            context_nsid,
            &lex_ref.reference,
            value,
            path,
            depth,
        ),
        LexProperty::Union(union_def) => {
            validate_union(registry, context_nsid, union_def, value, path, depth)
        }
        LexProperty::Array(array_def) => {
            validate_array(registry, context_nsid, array_def, value, path, depth)
        }
        LexProperty::Object(obj_def) => {
            validate_object(registry, context_nsid, obj_def, value, path, depth)
        }
    }
}

fn validate_string(
    lex_str: &LexString,
    value: &serde_json::Value,
    path: &str,
) -> Result<(), LexValidationError> {
    let s = value
        .as_str()
        .ok_or_else(|| LexValidationError::field(path, "expected a string"))?;

    if let Some(max_len) = lex_str.max_length
        && s.len() as u64 > max_len
    {
        return Err(LexValidationError::field(
            path,
            format!("string length {} exceeds max_length {}", s.len(), max_len),
        ));
    }

    if let Some(min_len) = lex_str.min_length
        && (s.len() as u64) < min_len
    {
        return Err(LexValidationError::field(
            path,
            format!("string length {} below min_length {}", s.len(), min_len),
        ));
    }

    if lex_str.max_graphemes.is_some() || lex_str.min_graphemes.is_some() {
        let count = s.graphemes(true).count() as u64;
        if let Some(max_graphemes) = lex_str.max_graphemes
            && count > max_graphemes
        {
            return Err(LexValidationError::field(
                path,
                format!(
                    "grapheme count {} exceeds max_graphemes {}",
                    count, max_graphemes
                ),
            ));
        }
        if let Some(min_graphemes) = lex_str.min_graphemes
            && count < min_graphemes
        {
            return Err(LexValidationError::field(
                path,
                format!(
                    "grapheme count {} below min_graphemes {}",
                    count, min_graphemes
                ),
            ));
        }
    }

    if let Some(ref format) = lex_str.format
        && !validate_format(format, s)
    {
        return Err(LexValidationError::field(
            path,
            format!("invalid format: {:?}", format),
        ));
    }

    if let Some(ref enum_vals) = lex_str.enum_values
        && !enum_vals.iter().any(|v| v == s)
    {
        return Err(LexValidationError::field(
            path,
            format!("value '{}' not in enum", s),
        ));
    }

    if let Some(ref const_val) = lex_str.const_value
        && s != const_val.as_str()
    {
        return Err(LexValidationError::field(
            path,
            format!("expected const value '{}'", const_val),
        ));
    }

    Ok(())
}

fn validate_cid_link(value: &serde_json::Value, path: &str) -> Result<(), LexValidationError> {
    let obj = value
        .as_object()
        .ok_or_else(|| LexValidationError::field(path, "expected cid-link object"))?;

    if !obj.contains_key("$link") {
        return Err(LexValidationError::field(path, "cid-link missing $link"));
    }

    Ok(())
}

fn validate_blob_ref(
    lex_blob: &LexBlob,
    value: &serde_json::Value,
    path: &str,
) -> Result<(), LexValidationError> {
    let obj = value
        .as_object()
        .ok_or_else(|| LexValidationError::field(path, "expected blob object"))?;

    let has_type = obj
        .get("$type")
        .and_then(|v| v.as_str())
        .is_some_and(|t| t == "blob");

    let has_ref = obj.contains_key("ref") && obj.contains_key("mimeType");

    let has_cid = obj.contains_key("cid");

    if !has_type && !has_ref && !has_cid {
        return Err(LexValidationError::field(
            path,
            "invalid blob reference structure",
        ));
    }

    if let Some(ref accept) = lex_blob.accept {
        let mime_type = obj.get("mimeType").and_then(|v| v.as_str()).unwrap_or("");
        let matched = accept
            .iter()
            .any(|pattern| match pattern.strip_suffix("/*") {
                Some(prefix) => {
                    mime_type.starts_with(prefix)
                        && mime_type.as_bytes().get(prefix.len()) == Some(&b'/')
                }
                None => mime_type == pattern,
            });
        if !mime_type.is_empty() && !matched {
            return Err(LexValidationError::field(
                path,
                format!("blob mimeType '{}' not in accepted types", mime_type),
            ));
        }
    }

    if let Some(max_size) = lex_blob.max_size {
        if let Some(size) = obj.get("size").and_then(|v| v.as_u64()) {
            if size > max_size {
                return Err(LexValidationError::field(
                    path,
                    format!("blob size {} exceeds max_size {}", size, max_size),
                ));
            }
        }
    }

    Ok(())
}

fn validate_bytes(
    lex_bytes: &LexBytes,
    value: &serde_json::Value,
    path: &str,
) -> Result<(), LexValidationError> {
    let obj = value
        .as_object()
        .ok_or_else(|| LexValidationError::field(path, "expected bytes object with $bytes key"))?;

    let encoded = obj
        .get("$bytes")
        .and_then(|v| v.as_str())
        .ok_or_else(|| LexValidationError::field(path, "bytes object missing $bytes key"))?;

    let byte_len = encoded.len() as u64 * 3 / 4;

    if let Some(max_len) = lex_bytes.max_length
        && byte_len > max_len
    {
        return Err(LexValidationError::field(
            path,
            format!("bytes length ~{} exceeds max_length {}", byte_len, max_len),
        ));
    }

    if let Some(min_len) = lex_bytes.min_length
        && byte_len < min_len
    {
        return Err(LexValidationError::field(
            path,
            format!("bytes length ~{} below min_length {}", byte_len, min_len),
        ));
    }

    Ok(())
}

fn validate_ref(
    registry: &LexiconRegistry,
    context_nsid: &str,
    reference: &str,
    value: &serde_json::Value,
    path: &str,
    depth: u32,
) -> Result<(), LexValidationError> {
    let target_context = ref_to_context_nsid(reference, context_nsid);
    match registry.resolve_ref(reference, context_nsid) {
        Some(resolved) => {
            if resolved.is_token() {
                Ok(())
            } else if let Some(obj) = resolved.as_object() {
                validate_object(registry, target_context, obj, value, path, depth + 1)
            } else {
                Ok(())
            }
        }
        None => Ok(()),
    }
}

fn validate_union(
    registry: &LexiconRegistry,
    context_nsid: &str,
    union_def: &LexUnion,
    value: &serde_json::Value,
    path: &str,
    depth: u32,
) -> Result<(), LexValidationError> {
    let obj = value
        .as_object()
        .ok_or_else(|| LexValidationError::field(path, "union value must be an object"))?;

    let type_str = obj
        .get("$type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| LexValidationError::field(path, "union object missing $type"))?;

    let matched_ref = union_def.refs.iter().find(|r| {
        let resolved = resolve_union_ref(r, context_nsid);
        resolved == type_str
    });

    match matched_ref {
        Some(reference) => validate_ref(registry, context_nsid, reference, value, path, depth),
        None => {
            if union_def.closed {
                Err(LexValidationError::field(
                    path,
                    format!("union type '{}' not in allowed refs", type_str),
                ))
            } else {
                Ok(())
            }
        }
    }
}

fn validate_array(
    registry: &LexiconRegistry,
    context_nsid: &str,
    array_def: &LexArray,
    value: &serde_json::Value,
    path: &str,
    depth: u32,
) -> Result<(), LexValidationError> {
    let arr = value
        .as_array()
        .ok_or_else(|| LexValidationError::field(path, "expected an array"))?;

    if let Some(max_len) = array_def.max_length
        && arr.len() as u64 > max_len
    {
        return Err(LexValidationError::field(
            path,
            format!("array length {} exceeds max_length {}", arr.len(), max_len),
        ));
    }

    if let Some(min_len) = array_def.min_length
        && (arr.len() as u64) < min_len
    {
        return Err(LexValidationError::field(
            path,
            format!("array length {} below min_length {}", arr.len(), min_len),
        ));
    }

    arr.iter().enumerate().try_for_each(|(i, item)| {
        let item_path = format!("{}/{}", path, i);
        validate_property(
            registry,
            context_nsid,
            &array_def.items,
            item,
            &item_path,
            depth + 1,
        )
    })
}

fn field_path(parent: &str, field: &str) -> String {
    if parent.is_empty() {
        field.to_string()
    } else {
        format!("{}/{}", parent, field)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_schemas::test_registry;
    use serde_json::json;

    #[test]
    fn test_validate_valid_record() {
        let registry = test_registry();
        let record = json!({
            "$type": "com.test.basic",
            "text": "Hello, world!",
            "createdAt": "2024-01-01T00:00:00.000Z"
        });
        assert!(validate_record(&registry, "com.test.basic", &record).is_ok());
    }

    #[test]
    fn test_validate_missing_required() {
        let registry = test_registry();
        let record = json!({
            "$type": "com.test.basic",
            "createdAt": "2024-01-01T00:00:00.000Z"
        });
        let err = validate_record(&registry, "com.test.basic", &record).unwrap_err();
        assert!(matches!(err, LexValidationError::MissingRequired { .. }));
    }

    #[test]
    fn test_validate_string_too_long_bytes() {
        let registry = test_registry();
        let record = json!({
            "$type": "com.test.basic",
            "text": "a".repeat(101),
            "createdAt": "2024-01-01T00:00:00.000Z"
        });
        let err = validate_record(&registry, "com.test.basic", &record).unwrap_err();
        assert!(matches!(err, LexValidationError::InvalidField { .. }));
    }

    #[test]
    fn test_validate_string_too_many_graphemes() {
        let registry = test_registry();
        let record = json!({
            "$type": "com.test.basic",
            "text": "a".repeat(51),
            "createdAt": "2024-01-01T00:00:00.000Z"
        });
        let err = validate_record(&registry, "com.test.basic", &record).unwrap_err();
        assert!(matches!(err, LexValidationError::InvalidField { .. }));
    }

    #[test]
    fn test_validate_grapheme_counting_emoji() {
        let registry = test_registry();
        let emoji_text = "👨‍👩‍👧‍👦".repeat(11);
        let record = json!({
            "$type": "com.test.profile",
            "displayName": emoji_text
        });
        let err = validate_record(&registry, "com.test.profile", &record).unwrap_err();
        assert!(matches!(err, LexValidationError::InvalidField { .. }));
    }

    #[test]
    fn test_validate_integer_bounds() {
        let registry = test_registry();
        let record = json!({
            "$type": "com.test.basic",
            "text": "ok",
            "createdAt": "2024-01-01T00:00:00.000Z",
            "count": 101
        });
        let err = validate_record(&registry, "com.test.basic", &record).unwrap_err();
        assert!(matches!(err, LexValidationError::InvalidField { .. }));

        let record_neg = json!({
            "$type": "com.test.basic",
            "text": "ok",
            "createdAt": "2024-01-01T00:00:00.000Z",
            "count": -1
        });
        let err = validate_record(&registry, "com.test.basic", &record_neg).unwrap_err();
        assert!(matches!(err, LexValidationError::InvalidField { .. }));
    }

    #[test]
    fn test_validate_integer_float_coercion() {
        let registry = test_registry();
        let record = json!({
            "$type": "com.test.basic",
            "text": "ok",
            "createdAt": "2024-01-01T00:00:00.000Z",
            "count": 5.0
        });
        assert!(validate_record(&registry, "com.test.basic", &record).is_ok());

        let record_frac = json!({
            "$type": "com.test.basic",
            "text": "ok",
            "createdAt": "2024-01-01T00:00:00.000Z",
            "count": 5.5
        });
        let err = validate_record(&registry, "com.test.basic", &record_frac).unwrap_err();
        assert!(matches!(err, LexValidationError::InvalidField { .. }));
    }

    #[test]
    fn test_validate_boolean() {
        let registry = test_registry();
        let record = json!({
            "$type": "com.test.basic",
            "text": "ok",
            "createdAt": "2024-01-01T00:00:00.000Z",
            "active": "not-a-bool"
        });
        let err = validate_record(&registry, "com.test.basic", &record).unwrap_err();
        assert!(matches!(err, LexValidationError::InvalidField { .. }));
    }

    #[test]
    fn test_validate_array_max_length() {
        let registry = test_registry();
        let record = json!({
            "$type": "com.test.basic",
            "text": "ok",
            "createdAt": "2024-01-01T00:00:00.000Z",
            "tags": ["a", "b", "c", "d"]
        });
        let err = validate_record(&registry, "com.test.basic", &record).unwrap_err();
        assert!(matches!(err, LexValidationError::InvalidField { .. }));
    }

    #[test]
    fn test_validate_array_within_limit() {
        let registry = test_registry();
        let record = json!({
            "$type": "com.test.basic",
            "text": "ok",
            "createdAt": "2024-01-01T00:00:00.000Z",
            "tags": ["a", "b", "c"]
        });
        assert!(validate_record(&registry, "com.test.basic", &record).is_ok());
    }

    #[test]
    fn test_validate_cross_schema_ref() {
        let registry = test_registry();
        let record = json!({
            "$type": "com.test.withref",
            "subject": {
                "uri": "at://did:plc:abc/com.test.basic/123",
                "cid": "bafyreiabcdef"
            },
            "createdAt": "2024-01-01T00:00:00.000Z"
        });
        assert!(validate_record(&registry, "com.test.withref", &record).is_ok());
    }

    #[test]
    fn test_validate_cross_schema_ref_missing_field() {
        let registry = test_registry();
        let record = json!({
            "$type": "com.test.withref",
            "subject": {
                "cid": "bafyreiabcdef"
            },
            "createdAt": "2024-01-01T00:00:00.000Z"
        });
        let err = validate_record(&registry, "com.test.withref", &record).unwrap_err();
        assert!(matches!(err, LexValidationError::MissingRequired { .. }));
    }

    #[test]
    fn test_validate_local_ref_resolution() {
        let registry = test_registry();
        let record = json!({
            "$type": "com.test.withreply",
            "text": "reply",
            "createdAt": "2024-01-01T00:00:00.000Z",
            "reply": {
                "root": {
                    "uri": "at://did:plc:abc/com.test.basic/123",
                    "cid": "bafyreiabcdef"
                },
                "parent": {
                    "uri": "at://did:plc:abc/com.test.basic/456",
                    "cid": "bafyreiabcdef"
                }
            }
        });
        assert!(validate_record(&registry, "com.test.withreply", &record).is_ok());
    }

    #[test]
    fn test_validate_union_bare_nsid_ref() {
        let registry = test_registry();
        let record = json!({
            "$type": "com.test.withreply",
            "text": "with images",
            "createdAt": "2024-01-01T00:00:00.000Z",
            "embed": {
                "$type": "com.test.images",
                "images": [
                    {
                        "image": {
                            "$type": "blob",
                            "ref": { "$link": "bafyreiabcdef" },
                            "mimeType": "image/jpeg",
                            "size": 12345
                        },
                        "alt": "test"
                    }
                ]
            }
        });
        assert!(validate_record(&registry, "com.test.withreply", &record).is_ok());

        let bad_embed = json!({
            "$type": "com.test.withreply",
            "text": "bad",
            "createdAt": "2024-01-01T00:00:00.000Z",
            "embed": {
                "$type": "com.test.images",
                "images": "not-an-array"
            }
        });
        assert!(
            validate_record(&registry, "com.test.withreply", &bad_embed).is_err(),
            "union with bare NSID ref must validate the matched schema"
        );
    }

    #[test]
    fn test_validate_cross_schema_local_ref_in_union() {
        let registry = test_registry();
        let record = json!({
            "$type": "com.test.withreply",
            "text": "external",
            "createdAt": "2024-01-01T00:00:00.000Z",
            "embed": {
                "$type": "com.test.external",
                "external": {
                    "uri": "https://example.com",
                    "title": "Example",
                    "description": "A test"
                }
            }
        });
        assert!(validate_record(&registry, "com.test.withreply", &record).is_ok());

        let bad_external = json!({
            "$type": "com.test.withreply",
            "text": "bad",
            "createdAt": "2024-01-01T00:00:00.000Z",
            "embed": {
                "$type": "com.test.external",
                "external": {
                    "title": "missing uri and description"
                }
            }
        });
        assert!(
            validate_record(&registry, "com.test.withreply", &bad_external).is_err(),
            "local #ref in cross-schema union must resolve against the correct schema"
        );
    }

    #[test]
    fn test_validate_gate_with_union_fragment_ref() {
        let registry = test_registry();
        let record = json!({
            "$type": "com.test.withgate",
            "post": "at://did:plc:abc/com.test.basic/123",
            "createdAt": "2024-01-01T00:00:00.000Z",
            "rules": [
                { "$type": "com.test.withgate#disableRule" }
            ]
        });
        assert!(validate_record(&registry, "com.test.withgate", &record).is_ok());
    }

    #[test]
    fn test_validate_did_format() {
        let registry = test_registry();
        let record = json!({
            "$type": "com.test.withdid",
            "subject": "did:plc:abc123",
            "createdAt": "2024-01-01T00:00:00.000Z"
        });
        assert!(validate_record(&registry, "com.test.withdid", &record).is_ok());

        let bad_did = json!({
            "$type": "com.test.withdid",
            "subject": "not-a-did",
            "createdAt": "2024-01-01T00:00:00.000Z"
        });
        assert!(validate_record(&registry, "com.test.withdid", &bad_did).is_err());
    }

    #[test]
    fn test_validate_nullable_field() {
        let registry = test_registry();
        let record = json!({
            "$type": "com.test.nullable",
            "name": "test",
            "value": null
        });
        assert!(validate_record(&registry, "com.test.nullable", &record).is_ok());
    }

    #[test]
    fn test_validate_unknown_lexicon() {
        let registry = test_registry();
        let record = json!({"$type": "com.example.nonexistent"});
        let err = validate_record(&registry, "com.example.nonexistent", &record).unwrap_err();
        assert!(matches!(err, LexValidationError::LexiconNotFound(_)));
    }

    #[test]
    fn test_validate_extra_properties_allowed() {
        let registry = test_registry();
        let record = json!({
            "$type": "com.test.basic",
            "text": "ok",
            "createdAt": "2024-01-01T00:00:00.000Z",
            "unknownField": "this is fine"
        });
        assert!(validate_record(&registry, "com.test.basic", &record).is_ok());
    }

    #[test]
    fn test_validate_no_required_fields() {
        let registry = test_registry();
        let record = json!({"$type": "com.test.profile"});
        assert!(validate_record(&registry, "com.test.profile", &record).is_ok());
    }

    #[test]
    fn test_validate_profile_display_name_graphemes() {
        let registry = test_registry();
        let record = json!({
            "$type": "com.test.profile",
            "displayName": "a".repeat(11)
        });
        let err = validate_record(&registry, "com.test.profile", &record).unwrap_err();
        assert!(matches!(err, LexValidationError::InvalidField { .. }));
    }

    #[test]
    fn test_required_nullable_field_accepts_null() {
        let registry = test_registry();
        let record = json!({
            "$type": "com.test.requirednullable",
            "name": "test",
            "value": null
        });
        assert!(
            validate_record(&registry, "com.test.requirednullable", &record).is_ok(),
            "a field that is both required and nullable must accept null values"
        );
    }

    #[test]
    fn test_required_nullable_field_rejects_absent() {
        let registry = test_registry();
        let record = json!({
            "$type": "com.test.requirednullable",
            "name": "test"
        });
        assert!(
            matches!(
                validate_record(&registry, "com.test.requirednullable", &record).unwrap_err(),
                LexValidationError::MissingRequired { .. }
            ),
            "a field that is required+nullable must still be present (even if null)"
        );
    }

    #[test]
    fn test_required_nullable_field_accepts_value() {
        let registry = test_registry();
        let record = json!({
            "$type": "com.test.requirednullable",
            "name": "test",
            "value": "hello"
        });
        assert!(
            validate_record(&registry, "com.test.requirednullable", &record).is_ok(),
            "a field that is required+nullable must accept non-null values"
        );
    }
}
