use crate::schema::{LexDef, LexObject, LexiconDoc, ParsedRef, parse_ref};
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use tranquil_types::Nsid;

static REGISTRY: OnceLock<LexiconRegistry> = OnceLock::new();

pub struct LexiconRegistry {
    schemas: HashMap<Nsid, Arc<LexiconDoc>>,
    #[cfg(feature = "resolve")]
    dynamic: crate::dynamic::DynamicRegistry,
}

impl Default for LexiconRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl LexiconRegistry {
    pub fn global() -> &'static Self {
        REGISTRY.get_or_init(Self::new)
    }

    pub fn new() -> Self {
        Self {
            schemas: HashMap::new(),
            #[cfg(feature = "resolve")]
            dynamic: crate::dynamic::DynamicRegistry::from_env(),
        }
    }

    pub fn register(&mut self, doc: LexiconDoc) {
        let id = doc.id.clone();
        self.schemas.insert(id, Arc::new(doc));
    }

    #[cfg(feature = "resolve")]
    pub fn preload(&self, doc: LexiconDoc) {
        self.dynamic.insert_schema(doc);
    }

    pub fn get_doc(&self, nsid: &Nsid) -> Option<Arc<LexiconDoc>> {
        self.get_doc_by_key(nsid.as_str())
    }

    fn get_doc_by_key(&self, key: &str) -> Option<Arc<LexiconDoc>> {
        self.schemas.get(key).cloned().or_else(|| {
            #[cfg(feature = "resolve")]
            {
                Nsid::new(key)
                    .ok()
                    .and_then(|nsid| self.dynamic.get_cached(&nsid))
            }
            #[cfg(not(feature = "resolve"))]
            {
                None
            }
        })
    }

    pub fn get_record_def(&self, nsid: &Nsid) -> Option<Arc<LexiconDoc>> {
        let doc = self.get_doc(nsid)?;
        match doc.defs.get("main")? {
            LexDef::Record(_) => Some(doc),
            _ => None,
        }
    }

    pub fn resolve_ref(&self, reference: &str, context_nsid: &str) -> Option<ResolvedRef> {
        match parse_ref(reference) {
            ParsedRef::Local(local) => {
                let doc = self.get_doc(context_nsid)?;
                Self::def_to_resolved(&doc, local)
            }
            ParsedRef::Qualified { nsid, fragment } => {
                let doc = self.get_doc_by_key(nsid)?;
                Self::def_to_resolved(&doc, fragment)
            }
            ParsedRef::Bare(nsid) => {
                let doc = self.get_doc_by_key(nsid)?;
                Self::def_to_resolved(&doc, "main")
            }
        }
    }

    fn def_to_resolved(doc: &Arc<LexiconDoc>, def_name: &str) -> Option<ResolvedRef> {
        let def = doc.defs.get(def_name)?;
        match def {
            LexDef::Object(_) | LexDef::Record(_) | LexDef::Token {} | LexDef::StringDef(_) => {
                Some(ResolvedRef {
                    doc: Arc::clone(doc),
                    def_name: def_name.to_string(),
                })
            }
            _ => None,
        }
    }

    pub fn has_schema(&self, nsid: &Nsid) -> bool {
        self.get_doc(nsid).is_some()
    }

    pub fn schema_count(&self) -> usize {
        let embedded = self.schemas.len();
        #[cfg(feature = "resolve")]
        {
            embedded + self.dynamic.schema_count()
        }
        #[cfg(not(feature = "resolve"))]
        {
            embedded
        }
    }

    #[cfg(feature = "resolve")]
    pub async fn resolve_dynamic(
        &self,
        nsid: &Nsid,
    ) -> Result<Arc<LexiconDoc>, crate::resolve::ResolveError> {
        self.dynamic.resolve_and_cache(nsid).await
    }

    #[cfg(feature = "resolve")]
    pub fn is_negative_cached(&self, nsid: &Nsid) -> bool {
        self.dynamic.is_negative_cached(nsid)
    }
}

pub struct ResolvedRef {
    doc: Arc<LexiconDoc>,
    def_name: String,
}

impl ResolvedRef {
    pub fn as_object(&self) -> Option<&LexObject> {
        match self.doc.defs.get(&self.def_name)? {
            LexDef::Object(obj) => Some(obj),
            LexDef::Record(rec) => Some(&rec.record),
            _ => None,
        }
    }

    pub fn is_token(&self) -> bool {
        self.doc
            .defs
            .get(&self.def_name)
            .is_some_and(|def| matches!(def, LexDef::Token {} | LexDef::StringDef(_)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nsid(s: &str) -> Nsid {
        s.parse().unwrap()
    }

    #[test]
    fn test_empty_registry() {
        let registry = LexiconRegistry::new();
        assert_eq!(registry.schema_count(), 0);
        assert!(!registry.has_schema(&nsid("app.bsky.feed.post")));
    }

    #[test]
    fn test_register_and_lookup() {
        let mut registry = LexiconRegistry::new();
        let doc = LexiconDoc {
            lexicon: 1,
            id: nsid("com.example.test"),
            defs: HashMap::new(),
        };
        registry.register(doc);
        assert_eq!(registry.schema_count(), 1);
        assert!(registry.has_schema(&nsid("com.example.test")));
        assert!(!registry.has_schema(&nsid("com.example.other")));
    }

    #[test]
    fn test_get_record_def() {
        let registry = crate::test_schemas::test_registry();
        let doc = registry.get_record_def(&nsid("com.test.basic"));
        assert!(doc.is_some());
        let doc = doc.unwrap();
        match doc.defs.get("main").unwrap() {
            LexDef::Record(rec) => {
                assert!(rec.record.required.contains(&"text".to_string()));
                assert!(rec.record.required.contains(&"createdAt".to_string()));
            }
            _ => panic!("expected record def"),
        }
    }

    #[test]
    fn test_get_record_def_unknown() {
        let registry = LexiconRegistry::new();
        assert!(
            registry
                .get_record_def(&nsid("com.example.nonexistent"))
                .is_none()
        );
    }

    #[test]
    fn test_resolve_ref_cross_schema() {
        let registry = crate::test_schemas::test_registry();
        let resolved = registry.resolve_ref("com.test.strongref", "com.test.withref");
        assert!(resolved.is_some_and(|r| r.as_object().is_some()));
    }

    #[test]
    fn test_resolve_local_ref() {
        let registry = crate::test_schemas::test_registry();
        let resolved = registry.resolve_ref("#replyRef", "com.test.withreply");
        assert!(resolved.is_some_and(|r| r.as_object().is_some()));
    }

    #[test]
    fn test_has_schema() {
        let registry = crate::test_schemas::test_registry();
        assert!(registry.has_schema(&nsid("com.test.basic")));
        assert!(!registry.has_schema(&nsid("com.example.nonexistent")));
    }
}
