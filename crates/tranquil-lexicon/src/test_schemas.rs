use crate::registry::LexiconRegistry;
use crate::schema::LexiconDoc;

pub(crate) fn test_registry() -> LexiconRegistry {
    let mut registry = LexiconRegistry::new();
    all().into_iter().for_each(|doc| registry.register(doc));
    registry
}

fn parse(json: serde_json::Value) -> LexiconDoc {
    serde_json::from_value(json).expect("invalid test schema JSON")
}

fn all() -> Vec<LexiconDoc> {
    [
        basic_schema(),
        profile_schema(),
        with_ref_schema(),
        strong_ref_schema(),
        with_reply_schema(),
        images_schema(),
        external_schema(),
        with_gate_schema(),
        with_did_schema(),
        nullable_schema(),
        required_nullable_schema(),
    ]
    .into()
}

fn basic_schema() -> LexiconDoc {
    parse(serde_json::json!({
        "lexicon": 1,
        "id": "com.test.basic",
        "defs": {
            "main": {
                "type": "record",
                "record": {
                    "type": "object",
                    "required": ["text", "createdAt"],
                    "properties": {
                        "text": {"type": "string", "maxLength": 100, "maxGraphemes": 50},
                        "createdAt": {"type": "string", "format": "datetime"},
                        "count": {"type": "integer", "minimum": 0, "maximum": 100},
                        "active": {"type": "boolean"},
                        "tags": {
                            "type": "array", "maxLength": 3,
                            "items": {"type": "string", "maxLength": 50}
                        },
                        "langs": {
                            "type": "array", "maxLength": 2,
                            "items": {"type": "string", "format": "language"}
                        }
                    }
                }
            }
        }
    }))
}

fn profile_schema() -> LexiconDoc {
    parse(serde_json::json!({
        "lexicon": 1,
        "id": "com.test.profile",
        "defs": {
            "main": {
                "type": "record",
                "record": {
                    "type": "object",
                    "properties": {
                        "displayName": {"type": "string", "maxGraphemes": 10, "maxLength": 100},
                        "description": {"type": "string", "maxGraphemes": 50, "maxLength": 500},
                        "avatar": {"type": "blob", "accept": ["image/png", "image/jpeg"], "maxSize": 1000000}
                    }
                }
            }
        }
    }))
}

fn with_ref_schema() -> LexiconDoc {
    parse(serde_json::json!({
        "lexicon": 1,
        "id": "com.test.withref",
        "defs": {
            "main": {
                "type": "record",
                "record": {
                    "type": "object",
                    "required": ["subject", "createdAt"],
                    "properties": {
                        "subject": {"type": "ref", "ref": "com.test.strongref"},
                        "createdAt": {"type": "string", "format": "datetime"}
                    }
                }
            }
        }
    }))
}

fn strong_ref_schema() -> LexiconDoc {
    parse(serde_json::json!({
        "lexicon": 1,
        "id": "com.test.strongref",
        "defs": {
            "main": {
                "type": "object",
                "required": ["uri", "cid"],
                "properties": {
                    "uri": {"type": "string", "format": "at-uri"},
                    "cid": {"type": "string", "format": "cid"}
                }
            }
        }
    }))
}

fn with_reply_schema() -> LexiconDoc {
    parse(serde_json::json!({
        "lexicon": 1,
        "id": "com.test.withreply",
        "defs": {
            "main": {
                "type": "record",
                "record": {
                    "type": "object",
                    "required": ["text", "createdAt"],
                    "properties": {
                        "text": {"type": "string"},
                        "createdAt": {"type": "string", "format": "datetime"},
                        "reply": {"type": "ref", "ref": "#replyRef"},
                        "embed": {
                            "type": "union",
                            "refs": ["com.test.images", "com.test.external"]
                        }
                    }
                }
            },
            "replyRef": {
                "type": "object",
                "required": ["root", "parent"],
                "properties": {
                    "root": {"type": "ref", "ref": "com.test.strongref"},
                    "parent": {"type": "ref", "ref": "com.test.strongref"}
                }
            }
        }
    }))
}

fn images_schema() -> LexiconDoc {
    parse(serde_json::json!({
        "lexicon": 1,
        "id": "com.test.images",
        "defs": {
            "main": {
                "type": "object",
                "required": ["images"],
                "properties": {
                    "images": {
                        "type": "array", "maxLength": 4,
                        "items": {"type": "ref", "ref": "#image"}
                    }
                }
            },
            "image": {
                "type": "object",
                "required": ["image", "alt"],
                "properties": {
                    "image": {"type": "blob", "accept": ["image/*"], "maxSize": 1000000},
                    "alt": {"type": "string"}
                }
            }
        }
    }))
}

fn external_schema() -> LexiconDoc {
    parse(serde_json::json!({
        "lexicon": 1,
        "id": "com.test.external",
        "defs": {
            "main": {
                "type": "object",
                "required": ["external"],
                "properties": {
                    "external": {"type": "ref", "ref": "#external"}
                }
            },
            "external": {
                "type": "object",
                "required": ["uri", "title", "description"],
                "properties": {
                    "uri": {"type": "string", "format": "uri"},
                    "title": {"type": "string"},
                    "description": {"type": "string"}
                }
            }
        }
    }))
}

fn with_gate_schema() -> LexiconDoc {
    parse(serde_json::json!({
        "lexicon": 1,
        "id": "com.test.withgate",
        "defs": {
            "main": {
                "type": "record",
                "record": {
                    "type": "object",
                    "required": ["post", "createdAt"],
                    "properties": {
                        "post": {"type": "string", "format": "at-uri"},
                        "createdAt": {"type": "string", "format": "datetime"},
                        "rules": {
                            "type": "array", "maxLength": 5,
                            "items": {"type": "union", "refs": ["#disableRule"]}
                        }
                    }
                }
            },
            "disableRule": {
                "type": "object",
                "properties": {}
            }
        }
    }))
}

fn with_did_schema() -> LexiconDoc {
    parse(serde_json::json!({
        "lexicon": 1,
        "id": "com.test.withdid",
        "defs": {
            "main": {
                "type": "record",
                "record": {
                    "type": "object",
                    "required": ["subject", "createdAt"],
                    "properties": {
                        "subject": {"type": "string", "format": "did"},
                        "createdAt": {"type": "string", "format": "datetime"}
                    }
                }
            }
        }
    }))
}

fn nullable_schema() -> LexiconDoc {
    parse(serde_json::json!({
        "lexicon": 1,
        "id": "com.test.nullable",
        "defs": {
            "main": {
                "type": "record",
                "record": {
                    "type": "object",
                    "required": ["name"],
                    "nullable": ["value"],
                    "properties": {
                        "name": {"type": "string"},
                        "value": {"type": "string"}
                    }
                }
            }
        }
    }))
}

fn required_nullable_schema() -> LexiconDoc {
    parse(serde_json::json!({
        "lexicon": 1,
        "id": "com.test.requirednullable",
        "defs": {
            "main": {
                "type": "record",
                "record": {
                    "type": "object",
                    "required": ["name", "value"],
                    "nullable": ["value"],
                    "properties": {
                        "name": {"type": "string"},
                        "value": {"type": "string"}
                    }
                }
            }
        }
    }))
}
