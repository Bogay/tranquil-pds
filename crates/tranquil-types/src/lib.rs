use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::fmt;
use std::ops::Deref;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, sqlx::Type)]
#[serde(transparent)]
#[sqlx(transparent)]
pub struct Did(String);

impl<'de> Deserialize<'de> for Did {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Did::new(&s).map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}

impl From<Did> for String {
    fn from(did: Did) -> Self {
        did.0
    }
}

impl From<String> for Did {
    fn from(s: String) -> Self {
        Did(s)
    }
}

impl<'a> From<&'a Did> for Cow<'a, str> {
    fn from(did: &'a Did) -> Self {
        Cow::Borrowed(&did.0)
    }
}

impl Did {
    pub fn new(s: impl Into<String>) -> Result<Self, DidError> {
        let s = s.into();
        jacquard::types::string::Did::new(&s).map_err(|_| DidError::Invalid(s.clone()))?;
        Ok(Self(s))
    }

    pub fn new_unchecked(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }

    pub fn is_plc(&self) -> bool {
        self.0.starts_with("did:plc:")
    }

    pub fn is_web(&self) -> bool {
        self.0.starts_with("did:web:")
    }
}

impl AsRef<str> for Did {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl PartialEq<str> for Did {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for Did {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl PartialEq<String> for Did {
    fn eq(&self, other: &String) -> bool {
        self.0 == *other
    }
}

impl PartialEq<Did> for String {
    fn eq(&self, other: &Did) -> bool {
        *self == other.0
    }
}

impl PartialEq<Did> for &str {
    fn eq(&self, other: &Did) -> bool {
        *self == other.0
    }
}

impl Deref for Did {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for Did {
    type Err = DidError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum DidError {
    #[error("invalid DID: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[serde(transparent)]
#[sqlx(transparent)]
pub struct Handle(String);

impl From<Handle> for String {
    fn from(handle: Handle) -> Self {
        handle.0
    }
}

impl From<String> for Handle {
    fn from(s: String) -> Self {
        Handle(s)
    }
}

impl<'a> From<&'a Handle> for Cow<'a, str> {
    fn from(handle: &'a Handle) -> Self {
        Cow::Borrowed(&handle.0)
    }
}

impl Handle {
    pub fn new(s: impl Into<String>) -> Result<Self, HandleError> {
        let s = s.into();
        jacquard::types::string::Handle::new(&s).map_err(|_| HandleError::Invalid(s.clone()))?;
        Ok(Self(s))
    }

    pub fn new_unchecked(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl AsRef<str> for Handle {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Deref for Handle {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PartialEq<str> for Handle {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for Handle {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl PartialEq<String> for Handle {
    fn eq(&self, other: &String) -> bool {
        self.0 == *other
    }
}

impl PartialEq<Handle> for String {
    fn eq(&self, other: &Handle) -> bool {
        *self == other.0
    }
}

impl PartialEq<Handle> for &str {
    fn eq(&self, other: &Handle) -> bool {
        *self == other.0
    }
}

impl fmt::Display for Handle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for Handle {
    type Err = HandleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum HandleError {
    #[error("invalid handle: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AtIdentifier {
    Did(Did),
    Handle(Handle),
}

impl AtIdentifier {
    pub fn new(s: impl AsRef<str>) -> Result<Self, AtIdentifierError> {
        let s = s.as_ref();
        if s.starts_with("did:") {
            Did::new(s)
                .map(AtIdentifier::Did)
                .map_err(|_| AtIdentifierError::Invalid(s.to_string()))
        } else {
            Handle::new(s)
                .map(AtIdentifier::Handle)
                .map_err(|_| AtIdentifierError::Invalid(s.to_string()))
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            AtIdentifier::Did(d) => d.as_str(),
            AtIdentifier::Handle(h) => h.as_str(),
        }
    }

    pub fn into_inner(self) -> String {
        match self {
            AtIdentifier::Did(d) => d.into_inner(),
            AtIdentifier::Handle(h) => h.into_inner(),
        }
    }

    pub fn is_did(&self) -> bool {
        matches!(self, AtIdentifier::Did(_))
    }

    pub fn is_handle(&self) -> bool {
        matches!(self, AtIdentifier::Handle(_))
    }

    pub fn as_did(&self) -> Option<&Did> {
        match self {
            AtIdentifier::Did(d) => Some(d),
            AtIdentifier::Handle(_) => None,
        }
    }

    pub fn as_handle(&self) -> Option<&Handle> {
        match self {
            AtIdentifier::Handle(h) => Some(h),
            AtIdentifier::Did(_) => None,
        }
    }
}

impl From<Did> for AtIdentifier {
    fn from(did: Did) -> Self {
        AtIdentifier::Did(did)
    }
}

impl From<Handle> for AtIdentifier {
    fn from(handle: Handle) -> Self {
        AtIdentifier::Handle(handle)
    }
}

impl AsRef<str> for AtIdentifier {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Deref for AtIdentifier {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl fmt::Display for AtIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for AtIdentifier {
    type Err = AtIdentifierError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl Serialize for AtIdentifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for AtIdentifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        AtIdentifier::new(&s).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum AtIdentifierError {
    #[error("invalid AT identifier: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[serde(transparent)]
#[sqlx(type_name = "rkey")]
pub struct Rkey(String);

impl From<Rkey> for String {
    fn from(rkey: Rkey) -> Self {
        rkey.0
    }
}

impl From<String> for Rkey {
    fn from(s: String) -> Self {
        Rkey(s)
    }
}

impl<'a> From<&'a Rkey> for Cow<'a, str> {
    fn from(rkey: &'a Rkey) -> Self {
        Cow::Borrowed(&rkey.0)
    }
}

impl Rkey {
    pub fn new(s: impl Into<String>) -> Result<Self, RkeyError> {
        let s = s.into();
        jacquard::types::string::Rkey::new(&s).map_err(|_| RkeyError::Invalid(s.clone()))?;
        Ok(Self(s))
    }

    pub fn new_unchecked(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn generate() -> Self {
        use jacquard::types::integer::LimitedU32;
        Self(jacquard::types::string::Tid::now(LimitedU32::MIN).to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }

    pub fn is_tid(&self) -> bool {
        jacquard::types::string::Tid::from_str(&self.0).is_ok()
    }
}

impl AsRef<str> for Rkey {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Deref for Rkey {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PartialEq<str> for Rkey {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for Rkey {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl PartialEq<String> for Rkey {
    fn eq(&self, other: &String) -> bool {
        self.0 == *other
    }
}

impl PartialEq<Rkey> for String {
    fn eq(&self, other: &Rkey) -> bool {
        *self == other.0
    }
}

impl PartialEq<Rkey> for &str {
    fn eq(&self, other: &Rkey) -> bool {
        *self == other.0
    }
}

impl fmt::Display for Rkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for Rkey {
    type Err = RkeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum RkeyError {
    #[error("invalid rkey: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[serde(transparent)]
#[sqlx(type_name = "nsid")]
pub struct Nsid(String);

impl From<Nsid> for String {
    fn from(nsid: Nsid) -> Self {
        nsid.0
    }
}

impl From<String> for Nsid {
    fn from(s: String) -> Self {
        Nsid(s)
    }
}

impl<'a> From<&'a Nsid> for Cow<'a, str> {
    fn from(nsid: &'a Nsid) -> Self {
        Cow::Borrowed(&nsid.0)
    }
}

impl Nsid {
    pub fn new(s: impl Into<String>) -> Result<Self, NsidError> {
        let s = s.into();
        jacquard::types::string::Nsid::new(&s).map_err(|_| NsidError::Invalid(s.clone()))?;
        Ok(Self(s))
    }

    pub fn new_unchecked(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }

    pub fn authority(&self) -> Option<&str> {
        let parts: Vec<&str> = self.0.rsplitn(2, '.').collect();
        if parts.len() == 2 {
            Some(parts[1])
        } else {
            None
        }
    }

    pub fn name(&self) -> Option<&str> {
        self.0.rsplit('.').next()
    }
}

impl AsRef<str> for Nsid {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Deref for Nsid {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PartialEq<str> for Nsid {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for Nsid {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl PartialEq<String> for Nsid {
    fn eq(&self, other: &String) -> bool {
        self.0 == *other
    }
}

impl PartialEq<Nsid> for String {
    fn eq(&self, other: &Nsid) -> bool {
        *self == other.0
    }
}

impl PartialEq<Nsid> for &str {
    fn eq(&self, other: &Nsid) -> bool {
        *self == other.0
    }
}

impl fmt::Display for Nsid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for Nsid {
    type Err = NsidError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum NsidError {
    #[error("invalid NSID: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[serde(transparent)]
#[sqlx(type_name = "at_uri")]
pub struct AtUri(String);

impl From<AtUri> for String {
    fn from(uri: AtUri) -> Self {
        uri.0
    }
}

impl From<String> for AtUri {
    fn from(s: String) -> Self {
        AtUri(s)
    }
}

impl<'a> From<&'a AtUri> for Cow<'a, str> {
    fn from(uri: &'a AtUri) -> Self {
        Cow::Borrowed(&uri.0)
    }
}

impl AtUri {
    pub fn new(s: impl Into<String>) -> Result<Self, AtUriError> {
        let s = s.into();
        jacquard::types::string::AtUri::new(&s).map_err(|_| AtUriError::Invalid(s.clone()))?;
        Ok(Self(s))
    }

    pub fn new_unchecked(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn from_parts(did: &str, collection: &str, rkey: &str) -> Self {
        Self(format!("at://{}/{}/{}", did, collection, rkey))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }

    pub fn did(&self) -> Option<&str> {
        self.0
            .strip_prefix("at://")
            .and_then(|s| s.split('/').next())
    }

    pub fn collection(&self) -> Option<&str> {
        self.0
            .strip_prefix("at://")
            .and_then(|s| s.split('/').nth(1))
    }

    pub fn rkey(&self) -> Option<&str> {
        self.0
            .strip_prefix("at://")
            .and_then(|s| s.split('/').nth(2))
    }
}

impl AsRef<str> for AtUri {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Deref for AtUri {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PartialEq<str> for AtUri {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for AtUri {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl PartialEq<String> for AtUri {
    fn eq(&self, other: &String) -> bool {
        self.0 == *other
    }
}

impl PartialEq<AtUri> for String {
    fn eq(&self, other: &AtUri) -> bool {
        *self == other.0
    }
}

impl PartialEq<AtUri> for &str {
    fn eq(&self, other: &AtUri) -> bool {
        *self == other.0
    }
}

impl fmt::Display for AtUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for AtUri {
    type Err = AtUriError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum AtUriError {
    #[error("invalid AT URI: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[serde(transparent)]
#[sqlx(transparent)]
pub struct Tid(String);

impl From<Tid> for String {
    fn from(tid: Tid) -> Self {
        tid.0
    }
}

impl From<String> for Tid {
    fn from(s: String) -> Self {
        Tid(s)
    }
}

impl<'a> From<&'a Tid> for Cow<'a, str> {
    fn from(tid: &'a Tid) -> Self {
        Cow::Borrowed(&tid.0)
    }
}

impl Tid {
    pub fn new(s: impl Into<String>) -> Result<Self, TidError> {
        let s = s.into();
        jacquard::types::string::Tid::from_str(&s).map_err(|_| TidError::Invalid(s.clone()))?;
        Ok(Self(s))
    }

    pub fn new_unchecked(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn now() -> Self {
        use jacquard::types::integer::LimitedU32;
        Self(jacquard::types::string::Tid::now(LimitedU32::MIN).to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl AsRef<str> for Tid {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Deref for Tid {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PartialEq<str> for Tid {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for Tid {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl PartialEq<String> for Tid {
    fn eq(&self, other: &String) -> bool {
        self.0 == *other
    }
}

impl PartialEq<Tid> for String {
    fn eq(&self, other: &Tid) -> bool {
        *self == other.0
    }
}

impl PartialEq<Tid> for &str {
    fn eq(&self, other: &Tid) -> bool {
        *self == other.0
    }
}

impl fmt::Display for Tid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for Tid {
    type Err = TidError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum TidError {
    #[error("invalid TID: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[serde(transparent)]
#[sqlx(transparent)]
pub struct Datetime(String);

impl From<Datetime> for String {
    fn from(dt: Datetime) -> Self {
        dt.0
    }
}

impl From<String> for Datetime {
    fn from(s: String) -> Self {
        Datetime(s)
    }
}

impl<'a> From<&'a Datetime> for Cow<'a, str> {
    fn from(dt: &'a Datetime) -> Self {
        Cow::Borrowed(&dt.0)
    }
}

impl Datetime {
    pub fn new(s: impl Into<String>) -> Result<Self, DatetimeError> {
        let s = s.into();
        jacquard::types::string::Datetime::from_str(&s)
            .map_err(|_| DatetimeError::Invalid(s.clone()))?;
        Ok(Self(s))
    }

    pub fn new_unchecked(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn now() -> Self {
        Self(
            chrono::Utc::now()
                .format("%Y-%m-%dT%H:%M:%S%.3fZ")
                .to_string(),
        )
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl AsRef<str> for Datetime {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Deref for Datetime {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PartialEq<str> for Datetime {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for Datetime {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl PartialEq<String> for Datetime {
    fn eq(&self, other: &String) -> bool {
        self.0 == *other
    }
}

impl PartialEq<Datetime> for String {
    fn eq(&self, other: &Datetime) -> bool {
        *self == other.0
    }
}

impl PartialEq<Datetime> for &str {
    fn eq(&self, other: &Datetime) -> bool {
        *self == other.0
    }
}

impl fmt::Display for Datetime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for Datetime {
    type Err = DatetimeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum DatetimeError {
    #[error("invalid datetime: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[serde(transparent)]
#[sqlx(transparent)]
pub struct Language(String);

impl From<Language> for String {
    fn from(lang: Language) -> Self {
        lang.0
    }
}

impl From<String> for Language {
    fn from(s: String) -> Self {
        Language(s)
    }
}

impl<'a> From<&'a Language> for Cow<'a, str> {
    fn from(lang: &'a Language) -> Self {
        Cow::Borrowed(&lang.0)
    }
}

impl Language {
    pub fn new(s: impl Into<String>) -> Result<Self, LanguageError> {
        let s = s.into();
        jacquard::types::string::Language::from_str(&s)
            .map_err(|_| LanguageError::Invalid(s.clone()))?;
        Ok(Self(s))
    }

    pub fn new_unchecked(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl AsRef<str> for Language {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Deref for Language {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PartialEq<str> for Language {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for Language {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl PartialEq<String> for Language {
    fn eq(&self, other: &String) -> bool {
        self.0 == *other
    }
}

impl PartialEq<Language> for String {
    fn eq(&self, other: &Language) -> bool {
        *self == other.0
    }
}

impl PartialEq<Language> for &str {
    fn eq(&self, other: &Language) -> bool {
        *self == other.0
    }
}

impl fmt::Display for Language {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for Language {
    type Err = LanguageError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum LanguageError {
    #[error("invalid language tag: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[serde(transparent)]
#[sqlx(transparent)]
pub struct CidLink(String);

impl From<CidLink> for String {
    fn from(cid: CidLink) -> Self {
        cid.0
    }
}

impl From<String> for CidLink {
    fn from(s: String) -> Self {
        CidLink(s)
    }
}

impl<'a> From<&'a CidLink> for Cow<'a, str> {
    fn from(cid: &'a CidLink) -> Self {
        Cow::Borrowed(&cid.0)
    }
}

impl CidLink {
    pub fn new(s: impl Into<String>) -> Result<Self, CidLinkError> {
        let s = s.into();
        cid::Cid::from_str(&s).map_err(|_| CidLinkError::Invalid(s.clone()))?;
        Ok(Self(s))
    }

    pub fn new_unchecked(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }

    pub fn to_cid(&self) -> Result<cid::Cid, cid::Error> {
        cid::Cid::from_str(&self.0)
    }
}

impl AsRef<str> for CidLink {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Deref for CidLink {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PartialEq<str> for CidLink {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for CidLink {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl PartialEq<String> for CidLink {
    fn eq(&self, other: &String) -> bool {
        self.0 == *other
    }
}

impl PartialEq<CidLink> for String {
    fn eq(&self, other: &CidLink) -> bool {
        *self == other.0
    }
}

impl PartialEq<CidLink> for &str {
    fn eq(&self, other: &CidLink) -> bool {
        *self == other.0
    }
}

impl fmt::Display for CidLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for CidLink {
    type Err = CidLinkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum CidLinkError {
    #[error("invalid CID: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountState {
    Active,
    Deactivated {
        at: chrono::DateTime<chrono::Utc>,
    },
    TakenDown {
        reference: String,
    },
    Migrated {
        at: chrono::DateTime<chrono::Utc>,
        to_pds: String,
    },
}

impl AccountState {
    pub fn from_db_fields(
        deactivated_at: Option<chrono::DateTime<chrono::Utc>>,
        takedown_ref: Option<String>,
        migrated_to_pds: Option<String>,
        migrated_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Self {
        if let Some(reference) = takedown_ref {
            AccountState::TakenDown { reference }
        } else if let (Some(at), Some(to_pds)) = (deactivated_at, migrated_to_pds) {
            let migrated_at = migrated_at.unwrap_or(at);
            AccountState::Migrated {
                at: migrated_at,
                to_pds,
            }
        } else if let Some(at) = deactivated_at {
            AccountState::Deactivated { at }
        } else {
            AccountState::Active
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(self, AccountState::Active)
    }

    pub fn is_deactivated(&self) -> bool {
        matches!(self, AccountState::Deactivated { .. })
    }

    pub fn is_takendown(&self) -> bool {
        matches!(self, AccountState::TakenDown { .. })
    }

    pub fn is_migrated(&self) -> bool {
        matches!(self, AccountState::Migrated { .. })
    }

    pub fn can_login(&self) -> bool {
        matches!(self, AccountState::Active)
    }

    pub fn can_access_repo(&self) -> bool {
        matches!(
            self,
            AccountState::Active | AccountState::Deactivated { .. }
        )
    }

    pub fn status_string(&self) -> &'static str {
        match self {
            AccountState::Active => "active",
            AccountState::Deactivated { .. } => "deactivated",
            AccountState::TakenDown { .. } => "takendown",
            AccountState::Migrated { .. } => "deactivated",
        }
    }

    pub fn status_for_session(&self) -> Option<&'static str> {
        match self {
            AccountState::Active => None,
            AccountState::Deactivated { .. } => Some("deactivated"),
            AccountState::TakenDown { .. } => Some("takendown"),
            AccountState::Migrated { .. } => Some("migrated"),
        }
    }
}

impl fmt::Display for AccountState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AccountState::Active => write!(f, "active"),
            AccountState::Deactivated { at } => write!(f, "deactivated ({})", at),
            AccountState::TakenDown { reference } => write!(f, "takendown ({})", reference),
            AccountState::Migrated { to_pds, .. } => write!(f, "migrated to {}", to_pds),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(transparent)]
pub struct PlainPassword(String);

impl PlainPassword {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl AsRef<str> for PlainPassword {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl AsRef<[u8]> for PlainPassword {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl Deref for PlainPassword {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone, Serialize, sqlx::Type)]
#[serde(transparent)]
#[sqlx(transparent)]
pub struct PasswordHash(String);

impl PasswordHash {
    pub fn from_hash(hash: impl Into<String>) -> Self {
        Self(hash.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl AsRef<str> for PasswordHash {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<String> for PasswordHash {
    fn from(s: String) -> Self {
        Self(s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenSource {
    Session,
    OAuth {
        client_id: Option<String>,
    },
    ServiceAuth {
        lxm: Option<String>,
        aud: Option<String>,
    },
}

impl TokenSource {
    pub fn is_session(&self) -> bool {
        matches!(self, TokenSource::Session)
    }

    pub fn is_oauth(&self) -> bool {
        matches!(self, TokenSource::OAuth { .. })
    }

    pub fn is_service_auth(&self) -> bool {
        matches!(self, TokenSource::ServiceAuth { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct JwkThumbprint(String);

impl JwkThumbprint {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl AsRef<str> for JwkThumbprint {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Deref for JwkThumbprint {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<String> for JwkThumbprint {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl PartialEq<str> for JwkThumbprint {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<String> for JwkThumbprint {
    fn eq(&self, other: &String) -> bool {
        &self.0 == other
    }
}

impl PartialEq<JwkThumbprint> for String {
    fn eq(&self, other: &JwkThumbprint) -> bool {
        self == &other.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DPoPProofId(String);

impl DPoPProofId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl AsRef<str> for DPoPProofId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Deref for DPoPProofId {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<String> for DPoPProofId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[serde(transparent)]
#[sqlx(transparent)]
pub struct TokenId(String);

impl TokenId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl AsRef<str> for TokenId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Deref for TokenId {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<String> for TokenId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl fmt::Display for TokenId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[serde(transparent)]
#[sqlx(transparent)]
pub struct ClientId(String);

impl ClientId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl AsRef<str> for ClientId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Deref for ClientId {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<String> for ClientId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl fmt::Display for ClientId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[serde(transparent)]
#[sqlx(transparent)]
pub struct DeviceId(String);

impl DeviceId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl AsRef<str> for DeviceId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Deref for DeviceId {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<String> for DeviceId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[serde(transparent)]
#[sqlx(transparent)]
pub struct RequestId(String);

impl RequestId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl AsRef<str> for RequestId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Deref for RequestId {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<String> for RequestId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[serde(transparent)]
#[sqlx(transparent)]
pub struct Jti(String);

impl Jti {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl AsRef<str> for Jti {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Deref for Jti {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<String> for Jti {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl fmt::Display for Jti {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[serde(transparent)]
#[sqlx(transparent)]
pub struct AuthorizationCode(String);

impl AuthorizationCode {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl AsRef<str> for AuthorizationCode {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Deref for AuthorizationCode {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<String> for AuthorizationCode {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl fmt::Display for AuthorizationCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[serde(transparent)]
#[sqlx(transparent)]
pub struct RefreshToken(String);

impl RefreshToken {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl AsRef<str> for RefreshToken {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Deref for RefreshToken {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<String> for RefreshToken {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl fmt::Display for RefreshToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[serde(transparent)]
#[sqlx(transparent)]
pub struct InviteCode(String);

impl InviteCode {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl AsRef<str> for InviteCode {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Deref for InviteCode {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<String> for InviteCode {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl fmt::Display for InviteCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_did_validation() {
        assert!(Did::new("did:plc:abc123").is_ok());
        assert!(Did::new("did:web:example.com").is_ok());
        assert!(Did::new("not-a-did").is_err());
        assert!(Did::new("").is_err());
    }

    #[test]
    fn test_did_methods() {
        let plc = Did::new("did:plc:abc123").unwrap();
        assert!(plc.is_plc());
        assert!(!plc.is_web());
        assert_eq!(plc.as_str(), "did:plc:abc123");

        let web = Did::new("did:web:example.com").unwrap();
        assert!(!web.is_plc());
        assert!(web.is_web());
    }

    #[test]
    fn test_did_conversions() {
        let did = Did::new("did:plc:test123").unwrap();
        let s: String = did.clone().into();
        assert_eq!(s, "did:plc:test123");
        assert_eq!(format!("{}", did), "did:plc:test123");
    }

    #[test]
    fn test_did_serde() {
        let did = Did::new("did:plc:test123").unwrap();
        let json = serde_json::to_string(&did).unwrap();
        assert_eq!(json, "\"did:plc:test123\"");

        let parsed: Did = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, did);
    }

    #[test]
    fn test_handle_validation() {
        assert!(Handle::new("user.bsky.social").is_ok());
        assert!(Handle::new("test.example.com").is_ok());
        assert!(Handle::new("invalid handle with spaces").is_err());
        assert!(Handle::new("alice.pds.test").is_ok());
    }

    #[test]
    fn test_rkey_validation() {
        assert!(Rkey::new("self").is_ok());
        assert!(Rkey::new("3jzfcijpj2z2a").is_ok());
        assert!(Rkey::new("invalid/rkey").is_err());
    }

    #[test]
    fn test_rkey_generate() {
        let rkey = Rkey::generate();
        assert!(rkey.is_tid());
        assert!(!rkey.as_str().is_empty());
    }

    #[test]
    fn test_nsid_validation() {
        assert!(Nsid::new("app.bsky.feed.post").is_ok());
        assert!(Nsid::new("com.atproto.repo.createRecord").is_ok());
        assert!(Nsid::new("invalid").is_err());
    }

    #[test]
    fn test_nsid_parts() {
        let nsid = Nsid::new("app.bsky.feed.post").unwrap();
        assert_eq!(nsid.name(), Some("post"));
    }

    #[test]
    fn test_at_uri_validation() {
        assert!(AtUri::new("at://did:plc:abc123/app.bsky.feed.post/xyz").is_ok());
        assert!(AtUri::new("not-an-at-uri").is_err());
    }

    #[test]
    fn test_at_uri_from_parts() {
        let uri = AtUri::from_parts("did:plc:abc123", "app.bsky.feed.post", "xyz");
        assert_eq!(uri.as_str(), "at://did:plc:abc123/app.bsky.feed.post/xyz");
    }

    #[test]
    fn test_type_safety() {
        fn takes_did(_: &Did) {}
        fn takes_handle(_: &Handle) {}

        let did = Did::new("did:plc:test").unwrap();
        let handle = Handle::new("test.bsky.social").unwrap();

        takes_did(&did);
        takes_handle(&handle);
    }

    #[test]
    fn test_tid_validation() {
        let tid = Tid::now();
        assert!(!tid.as_str().is_empty());
        assert!(Tid::new(tid.as_str()).is_ok());
        assert!(Tid::new("invalid").is_err());
    }

    #[test]
    fn test_datetime_validation() {
        assert!(Datetime::new("2024-01-15T12:30:45.123Z").is_ok());
        assert!(Datetime::new("not-a-date").is_err());
        let now = Datetime::now();
        assert!(!now.as_str().is_empty());
    }

    #[test]
    fn test_language_validation() {
        assert!(Language::new("en").is_ok());
        assert!(Language::new("en-US").is_ok());
        assert!(Language::new("ja").is_ok());
    }

    #[test]
    fn test_cidlink_validation() {
        assert!(
            CidLink::new("bafyreib74ckyq525l3y6an5txykwwtb3dgex6ofzakml53di77oxwr5pfe").is_ok()
        );
        assert!(CidLink::new("not-a-cid").is_err());
    }

    #[test]
    fn test_at_identifier_validation() {
        let did_ident = AtIdentifier::new("did:plc:abc123").unwrap();
        assert!(did_ident.is_did());
        assert!(!did_ident.is_handle());
        assert!(did_ident.as_did().is_some());
        assert!(did_ident.as_handle().is_none());

        let handle_ident = AtIdentifier::new("user.bsky.social").unwrap();
        assert!(!handle_ident.is_did());
        assert!(handle_ident.is_handle());
        assert!(handle_ident.as_did().is_none());
        assert!(handle_ident.as_handle().is_some());

        assert!(AtIdentifier::new("invalid identifier").is_err());
    }

    #[test]
    fn test_at_identifier_serde() {
        let ident = AtIdentifier::new("did:plc:test123").unwrap();
        let json = serde_json::to_string(&ident).unwrap();
        assert_eq!(json, "\"did:plc:test123\"");

        let parsed: AtIdentifier = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.as_str(), "did:plc:test123");
    }

    #[test]
    fn test_account_state_active() {
        let state = AccountState::from_db_fields(None, None, None, None);
        assert!(state.is_active());
        assert!(!state.is_deactivated());
        assert!(!state.is_takendown());
        assert!(!state.is_migrated());
        assert!(state.can_login());
        assert!(state.can_access_repo());
        assert_eq!(state.status_string(), "active");
    }

    #[test]
    fn test_account_state_deactivated() {
        let now = chrono::Utc::now();
        let state = AccountState::from_db_fields(Some(now), None, None, None);
        assert!(!state.is_active());
        assert!(state.is_deactivated());
        assert!(!state.is_takendown());
        assert!(!state.is_migrated());
        assert!(!state.can_login());
        assert!(state.can_access_repo());
        assert_eq!(state.status_string(), "deactivated");
    }

    #[test]
    fn test_account_state_takendown() {
        let state = AccountState::from_db_fields(None, Some("mod-action-123".into()), None, None);
        assert!(!state.is_active());
        assert!(!state.is_deactivated());
        assert!(state.is_takendown());
        assert!(!state.is_migrated());
        assert!(!state.can_login());
        assert!(!state.can_access_repo());
        assert_eq!(state.status_string(), "takendown");
    }

    #[test]
    fn test_account_state_migrated() {
        let now = chrono::Utc::now();
        let state =
            AccountState::from_db_fields(Some(now), None, Some("https://other.pds".into()), None);
        assert!(!state.is_active());
        assert!(!state.is_deactivated());
        assert!(!state.is_takendown());
        assert!(state.is_migrated());
        assert!(!state.can_login());
        assert!(!state.can_access_repo());
        assert_eq!(state.status_string(), "deactivated");
    }

    #[test]
    fn test_account_state_takedown_priority() {
        let now = chrono::Utc::now();
        let state = AccountState::from_db_fields(
            Some(now),
            Some("mod-action".into()),
            Some("https://other.pds".into()),
            None,
        );
        assert!(state.is_takendown());
    }
}
