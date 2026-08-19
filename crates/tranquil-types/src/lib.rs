use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::fmt;
use std::hash::Hash;
use std::marker::PhantomData;
use std::ops::Deref;
use std::str::FromStr;

macro_rules! impl_string_common {
    ($name:ident) => {
        impl $name {
            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn into_inner(self) -> String {
                self.0
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl std::borrow::Borrow<str> for $name {
            fn borrow(&self) -> &str {
                &self.0
            }
        }

        impl Deref for $name {
            type Target = str;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl From<$name> for String {
            fn from(val: $name) -> Self {
                val.0
            }
        }

        impl<'a> From<&'a $name> for Cow<'a, str> {
            fn from(val: &'a $name) -> Self {
                Cow::Borrowed(&val.0)
            }
        }

        impl PartialEq<str> for $name {
            fn eq(&self, other: &str) -> bool {
                self.0 == other
            }
        }

        impl PartialEq<&str> for $name {
            fn eq(&self, other: &&str) -> bool {
                self.0 == *other
            }
        }

        impl PartialEq<String> for $name {
            fn eq(&self, other: &String) -> bool {
                self.0 == *other
            }
        }

        impl PartialEq<$name> for String {
            fn eq(&self, other: &$name) -> bool {
                *self == other.0
            }
        }

        impl PartialEq<$name> for &str {
            fn eq(&self, other: &$name) -> bool {
                *self == other.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

macro_rules! simple_string_newtype {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident;
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, sqlx::Type)]
        #[serde(transparent)]
        #[sqlx(transparent)]
        $vis struct $name(String);

        impl $name {
            pub fn new(s: impl Into<String>) -> Self {
                Self(s.into())
            }
        }

        impl From<String> for $name {
            fn from(s: String) -> Self {
                Self(s)
            }
        }

        impl_string_common!($name);
    };
}

macro_rules! simple_string_newtype_no_sqlx {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident;
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(transparent)]
        $vis struct $name(String);

        impl $name {
            pub fn new(s: impl Into<String>) -> Self {
                Self(s.into())
            }
        }

        impl From<String> for $name {
            fn from(s: String) -> Self {
                Self(s)
            }
        }

        impl_string_common!($name);
    };
}

macro_rules! validated_string_newtype {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident;
        error = $error:ident;
        label = $label:expr;
        validator = $validator:expr;
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, sqlx::Type)]
        #[serde(transparent)]
        #[sqlx(transparent)]
        $vis struct $name(String);

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let s = String::deserialize(deserializer)?;
                $name::new(&s).map_err(|e| serde::de::Error::custom(e.to_string()))
            }
        }

        impl $name {
            pub fn new(s: impl Into<String>) -> Result<Self, $error> {
                let s = s.into();
                // The validator gives back the string it accepted rather than unit
                // because the jacquard-common 0.9 that tranquil has for now
                // normalizes as it parses and strips `at://` prefix at the same time,
                // so storing the caller's input instead would leave Did::new(x).as_str()
                // and x in a split-brain bork.
                let validator: fn(&str) -> Result<String, ()> = $validator;
                match validator(&s) {
                    Ok(validated) => Ok(Self(validated)),
                    Err(()) => Err($error::Invalid(s)),
                }
            }
        }

        impl FromStr for $name {
            type Err = $error;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::new(s)
            }
        }

        impl_string_common!($name);

        #[derive(Debug, Clone)]
        pub enum $error {
            Invalid(String),
        }

        impl std::fmt::Display for $error {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    Self::Invalid(s) => write!(f, concat!("invalid ", $label, ": {}"), s),
                }
            }
        }

        impl std::error::Error for $error {}
    };
}

validated_string_newtype! {
    pub struct Did;
    error = DidError;
    label = "DID";
    validator = |s| jacquard_common::types::string::Did::new(s).map(|v| v.as_str().to_owned()).map_err(|_| ());
}

impl Did {
    pub fn is_plc(&self) -> bool {
        self.0.starts_with("did:plc:")
    }

    pub fn is_web(&self) -> bool {
        self.0.starts_with("did:web:")
    }
}

const DID_REF_MAX_LEN: usize = 2048;
const SERVICE_ID_MAX_LEN: usize = 128;

const fn is_pchar(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'-' | b'.'
                | b'_'
                | b'~'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'@'
        )
}

fn is_service_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= SERVICE_ID_MAX_LEN && s.bytes().all(is_pchar)
}

validated_string_newtype! {
    pub struct DidRef;
    error = DidRefError;
    label = "DID reference";
    validator = |s| {
        if s.len() > DID_REF_MAX_LEN {
            return Err(());
        }
        match s.split_once('#') {
            None => jacquard_common::types::string::Did::new(s)
                .map(|v| v.as_str().to_owned())
                .map_err(|_| ()),
            Some((did, service_id)) => {
                if !is_service_id(service_id) {
                    return Err(());
                }
                let base = jacquard_common::types::string::Did::new(did).map_err(|_| ())?;
                Ok(format!("{}#{}", base.as_str(), service_id))
            }
        }
    };
}

impl From<Did> for DidRef {
    fn from(did: Did) -> Self {
        Self(did.0)
    }
}

impl From<&Did> for DidRef {
    fn from(did: &Did) -> Self {
        Self(did.0.clone())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, sqlx::Type)]
#[serde(transparent)]
#[sqlx(transparent)]
pub struct Handle(String);

impl<'de> Deserialize<'de> for Handle {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Handle::new(&s).map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}

impl Handle {
    // In jacquard-common 0.9, `Handle::new` strips the prefix
    // and checks the regex but then seems to reject every reserved TLD
    // except literal "handle.invalid"
    // where instead we need all of them to parse
    // such that validation can report `DisallowedTld` against them.
    //
    // And jacquard hands the stripped slice back without ever lowercasing it
    // so lowercasing here gets `Eq` & `Hash` agreeing for a given account.
    pub fn new(s: impl Into<String>) -> Result<Self, HandleError> {
        let s = s.into();
        let stripped = s
            .strip_prefix("at://")
            .or_else(|| s.strip_prefix('@'))
            .unwrap_or(&s);
        match stripped.len() <= 253
            && jacquard_common::types::handle::HANDLE_REGEX.is_match(stripped)
        {
            true => Ok(Self(stripped.to_ascii_lowercase())),
            false => Err(HandleError::Invalid(s)),
        }
    }

    pub fn has_disallowed_tld(&self) -> bool {
        jacquard_common::types::ends_with(&self.0, jacquard_common::types::DISALLOWED_TLDS)
    }
}

impl FromStr for Handle {
    type Err = HandleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl_string_common!(Handle);

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

validated_string_newtype! {
    pub struct Rkey;
    error = RkeyError;
    label = "rkey";
    validator = |s| jacquard_common::types::string::Rkey::new(s).map(|v| v.as_str().to_owned()).map_err(|_| ());
}

impl Rkey {
    pub fn generate() -> Self {
        use jacquard_common::types::integer::LimitedU32;
        Self(jacquard_common::types::string::Tid::now(LimitedU32::MIN).to_string())
    }

    pub fn is_tid(&self) -> bool {
        Tid::new(&self.0).is_ok()
    }

    pub fn to_tid(&self) -> Option<Tid> {
        Tid::new(&self.0).ok()
    }
}

validated_string_newtype! {
    pub struct Nsid;
    error = NsidError;
    label = "NSID";
    validator = |s| jacquard_common::types::string::Nsid::new(s).map(|v| v.as_str().to_owned()).map_err(|_| ());
}

impl Nsid {
    pub fn authority(&self) -> &str {
        self.0.split('.').rev().nth(1).unwrap_or("")
    }

    pub fn name(&self) -> &str {
        self.0.split('.').next_back().unwrap_or("")
    }
}

validated_string_newtype! {
    pub struct AtUri;
    error = AtUriError;
    label = "AT URI";
    validator = |s| jacquard_common::types::string::AtUri::new(s).map(|v| v.as_str().to_owned()).map_err(|_| ());
}

impl AtUri {
    pub fn from_parts(did: &Did, collection: &Nsid, rkey: &Rkey) -> Self {
        Self(format!("at://{}/{}/{}", did, collection, rkey))
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

validated_string_newtype! {
    pub struct Tid;
    error = TidError;
    label = "TID";
    validator = |s| jacquard_common::types::string::Tid::from_str(s).map(|v| v.as_str().to_owned()).map_err(|_| ());
}

impl Tid {
    pub fn now() -> Self {
        use jacquard_common::types::integer::LimitedU32;
        Self(jacquard_common::types::string::Tid::now(LimitedU32::MIN).to_string())
    }

    // TIDs sort like plain strings over base32-sortable
    // whose lowest character is '2'
    // so 13 of those is the smallest well-formed TID
    // I can make.
    // Any sentinel outside base32 would sort lower still
    // (cough cough how I used to do it when being lazy with "0")
    // but can't round-trip through `Tid::new`.
    pub fn earliest() -> Self {
        Self("2222222222222".to_owned())
    }
}

impl From<jacquard_common::types::string::Tid> for Tid {
    fn from(tid: jacquard_common::types::string::Tid) -> Self {
        Self(tid.to_string())
    }
}

validated_string_newtype! {
    pub struct Datetime;
    error = DatetimeError;
    label = "datetime";
    validator = |s| jacquard_common::types::string::Datetime::from_str(s).map(|v| v.as_str().to_owned()).map_err(|_| ());
}

impl Datetime {
    pub fn now() -> Self {
        Self(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true))
    }

    pub fn to_chrono(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        chrono::DateTime::parse_from_rfc3339(&self.0)
            .ok()
            .map(|dt| dt.with_timezone(&chrono::Utc))
    }
}

validated_string_newtype! {
    pub struct Language;
    error = LanguageError;
    label = "language";
    validator = |s| jacquard_common::types::string::Language::from_str(s).map(|v| v.as_str().to_owned()).map_err(|_| ());
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, sqlx::Type)]
#[serde(transparent)]
#[sqlx(transparent)]
pub struct CidLink(String);

impl<'de> Deserialize<'de> for CidLink {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        CidLink::new(&s).map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}

impl CidLink {
    pub fn new(s: impl Into<String>) -> Result<Self, CidLinkError> {
        let s = s.into();
        cid::Cid::from_str(&s).map_err(|_| CidLinkError::Invalid(s.clone()))?;
        Ok(Self(s))
    }

    pub fn from_cid(cid: &cid::Cid) -> Self {
        Self(cid.to_string())
    }

    pub fn to_cid(&self) -> Option<cid::Cid> {
        cid::Cid::from_str(&self.0).ok()
    }
}

impl From<cid::Cid> for CidLink {
    fn from(cid: cid::Cid) -> Self {
        Self(cid.to_string())
    }
}

impl From<&cid::Cid> for CidLink {
    fn from(cid: &cid::Cid) -> Self {
        Self(cid.to_string())
    }
}

impl FromStr for CidLink {
    type Err = CidLinkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl_string_common!(CidLink);

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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[serde(transparent)]
#[sqlx(transparent)]
pub struct PasswordHash(String);

impl PasswordHash {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for PasswordHash {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum TokenSource {
    #[serde(rename = "session")]
    Session,
    #[serde(rename = "oauth")]
    OAuth { client_id: ClientId, scope: String },
    #[serde(rename = "service_auth")]
    ServiceAuth { aud: Did, lxm: Option<Nsid> },
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

simple_string_newtype_no_sqlx! {
    pub struct JwkThumbprint;
}

simple_string_newtype_no_sqlx! {
    pub struct DPoPProofId;
}

simple_string_newtype! {
    pub struct TokenId;
}

impl TokenId {
    pub fn generate() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }
}

simple_string_newtype! {
    pub struct ClientId;
}

simple_string_newtype! {
    pub struct DeviceId;
}

impl DeviceId {
    pub fn generate() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }
}

simple_string_newtype! {
    pub struct RequestId;
}

impl RequestId {
    pub fn generate() -> Self {
        Self(format!(
            "urn:ietf:params:oauth:request_uri:{}",
            uuid::Uuid::new_v4()
        ))
    }
}

simple_string_newtype! {
    pub struct Jti;
}

simple_string_newtype_no_sqlx! {
    pub struct CrossPdsState;
}

simple_string_newtype! {
    pub struct AuthorizationCode;
}

impl AuthorizationCode {
    pub fn generate() -> Self {
        Self(generate_url_safe_secret())
    }
}

simple_string_newtype! {
    pub struct RefreshToken;
}

impl RefreshToken {
    pub fn generate() -> Self {
        Self(generate_url_safe_secret())
    }
}

fn generate_url_safe_secret() -> String {
    use rand::Rng;
    let bytes: [u8; 32] = rand::thread_rng().r#gen();
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
}

simple_string_newtype! {
    pub struct InviteCode;
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "comms_channel", rename_all = "snake_case")]
#[derive(Copy)]
pub enum CommsChannel {
    Email,
    Discord,
    Telegram,
    Signal,
}

impl CommsChannel {
    pub fn as_str(&self) -> &'static str {
        match self {
            CommsChannel::Email => "email",
            CommsChannel::Discord => "discord",
            CommsChannel::Telegram => "telegram",
            CommsChannel::Signal => "signal",
        }
    }

    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s {
            "email" => Some(CommsChannel::Email),
            "discord" => Some(CommsChannel::Discord),
            "telegram" => Some(CommsChannel::Telegram),
            "signal" => Some(CommsChannel::Signal),
            _ => None,
        }
    }
}

impl fmt::Display for CommsChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostReach {
    Global,
    Loopback,
    Private,
}

fn ipv4_reach(ip: std::net::Ipv4Addr) -> HostReach {
    let [a, b, c, _] = ip.octets();
    match ip {
        _ if ip.is_loopback() => HostReach::Loopback,
        _ if ip.is_private()
            || ip.is_link_local()
            || ip.is_multicast()
            || ip.is_documentation()
            || a == 0
            || a == 100 && (64..128).contains(&b)
            || a == 192 && b == 0 && c == 0
            || a == 192 && b == 88 && c == 99
            || a == 198 && (18..20).contains(&b)
            || a & 0xf0 == 240 =>
        {
            HostReach::Private
        }
        _ => HostReach::Global,
    }
}

fn ipv6_reach(ip: std::net::Ipv6Addr) -> HostReach {
    let seg = ip.segments();
    let embedded_ipv4 =
        |hi: u16, lo: u16| std::net::Ipv4Addr::from((u32::from(hi) << 16) | u32::from(lo));
    match ip.to_ipv4_mapped() {
        Some(mapped) => ipv4_reach(mapped),
        None => match ip {
            _ if ip.is_loopback() => HostReach::Loopback,
            _ if seg[..6] == [0, 0, 0, 0, 0, 0] => ipv4_reach(embedded_ipv4(seg[6], seg[7])),
            _ if seg[..2] == [0x2001, 0] => ipv4_reach(embedded_ipv4(!seg[6], !seg[7])),
            _ if seg[0] == 0x2002 => ipv4_reach(embedded_ipv4(seg[1], seg[2])),
            _ if seg[..6] == [0x64, 0xff9b, 0, 0, 0, 0] => {
                ipv4_reach(embedded_ipv4(seg[6], seg[7]))
            }
            _ if seg[..3] == [0x64, 0xff9b, 1] => HostReach::Private,
            _ if ip.is_unspecified()
                || ip.is_multicast()
                || seg[0] & 0xfe00 == 0xfc00
                || seg[0] & 0xffc0 == 0xfe80
                || seg[..2] == [0x2001, 0x0db8] =>
            {
                HostReach::Private
            }
            _ => HostReach::Global,
        },
    }
}

fn host_reach(host: url::Host<&str>) -> HostReach {
    match host {
        url::Host::Ipv4(ip) => ipv4_reach(ip),
        url::Host::Ipv6(ip) => ipv6_reach(ip),
        url::Host::Domain(name) => {
            let name = name.trim_end_matches('.').to_ascii_lowercase();
            match name.as_str() {
                "localhost" => HostReach::Loopback,
                _ if name.ends_with(".localhost") => HostReach::Loopback,
                _ if name.ends_with(".local")
                    || name.ends_with(".internal")
                    || name.ends_with(".home.arpa")
                    || name == "home.arpa" =>
                {
                    HostReach::Private
                }
                _ => HostReach::Global,
            }
        }
    }
}

pub fn url_reach(url: &url::Url) -> Option<HostReach> {
    url.host().map(host_reach)
}

pub fn ip_reach(ip: std::net::IpAddr) -> HostReach {
    match ip {
        std::net::IpAddr::V4(v4) => ipv4_reach(v4),
        std::net::IpAddr::V6(v6) => ipv6_reach(v6),
    }
}

pub fn reach_permits(reach: HostReach, policy: ReachPolicy) -> bool {
    matches!(
        (reach, policy),
        (HostReach::Global, _)
            | (
                HostReach::Loopback,
                ReachPolicy::AllowLoopback | ReachPolicy::AllowPrivate,
            )
            | (HostReach::Private, ReachPolicy::AllowPrivate)
    )
}

pub fn url_reach_permits(url: &url::Url, policy: ReachPolicy) -> bool {
    let Some(reach) = url_reach(url) else {
        return false;
    };
    let scheme_permits = matches!(
        (url.scheme(), reach),
        ("https", _) | ("http", HostReach::Loopback | HostReach::Private)
    );
    scheme_permits && reach_permits(reach, policy)
}

fn parse_http_url(s: &str, policy: ReachPolicy, allow_query: bool) -> Option<url::Url> {
    let parsed = url::Url::parse(s).ok()?;
    let rejected = (parsed.query().is_some() && !allow_query)
        || parsed.fragment().is_some()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || !url_reach_permits(&parsed, policy);
    match rejected {
        true => None,
        false => Some(parsed),
    }
}

const REDIRECT_HOP_LIMIT: usize = 5;

pub fn redirect_policy(policy: ReachPolicy) -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(move |attempt| {
        let over_limit = attempt.previous().len() > REDIRECT_HOP_LIMIT;
        let permitted = url_reach_permits(attempt.url(), policy);
        let target = attempt.url().clone();
        match (over_limit, permitted) {
            (true, _) => attempt.error(format!("more than {} redirect hops", REDIRECT_HOP_LIMIT)),
            (false, false) => attempt.error(format!(
                "redirect target {} is outside the allowed host reach",
                target
            )),
            (false, true) => attempt.follow(),
        }
    })
}

pub struct ReachGuardedDns(ReachPolicy);

impl reqwest::dns::Resolve for ReachGuardedDns {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let policy = self.0;
        Box::pin(async move {
            let host = name.as_str().to_owned();
            let permitted: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await?
                .filter(|addr| reach_permits(ip_reach(addr.ip()), policy))
                .collect();
            match permitted.is_empty() {
                true => Err(format!(
                    "no resolved address for {} is inside the allowed host reach",
                    host
                )
                .into()),
                false => Ok(Box::new(permitted.into_iter()) as reqwest::dns::Addrs),
            }
        })
    }
}

pub fn dns_guard(policy: ReachPolicy) -> std::sync::Arc<ReachGuardedDns> {
    std::sync::Arc::new(ReachGuardedDns(policy))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReachPolicy {
    AllowLoopback,
    AllowPrivate,
    GlobalOnly,
}

impl ReachPolicy {
    #[cfg(debug_assertions)]
    pub const DEBUG_LOOPBACK: ReachPolicy = ReachPolicy::AllowLoopback;
    #[cfg(not(debug_assertions))]
    pub const DEBUG_LOOPBACK: ReachPolicy = ReachPolicy::GlobalOnly;
}

pub trait UrlKind {
    const LABEL: &'static str;
    const REACH_POLICY: ReachPolicy;
    const ALLOW_QUERY: bool;
}

pub mod url_kind {
    use super::{ReachPolicy, UrlKind};

    pub struct AuthServerEndpoint;
    impl UrlKind for AuthServerEndpoint {
        const LABEL: &'static str = "authorization server endpoint";
        const REACH_POLICY: ReachPolicy = ReachPolicy::GlobalOnly;
        const ALLOW_QUERY: bool = true;
    }

    pub struct Issuer;
    impl UrlKind for Issuer {
        const LABEL: &'static str = "issuer";
        const REACH_POLICY: ReachPolicy = ReachPolicy::GlobalOnly;
        const ALLOW_QUERY: bool = false;
    }

    pub struct Jwks;
    impl UrlKind for Jwks {
        const LABEL: &'static str = "JWKS URI";
        const REACH_POLICY: ReachPolicy = ReachPolicy::DEBUG_LOOPBACK;
        const ALLOW_QUERY: bool = true;
    }

    pub struct Pds;
    impl UrlKind for Pds {
        const LABEL: &'static str = "PDS URL";
        const REACH_POLICY: ReachPolicy = ReachPolicy::GlobalOnly;
        const ALLOW_QUERY: bool = false;
    }

    pub struct SchemaHost;
    impl UrlKind for SchemaHost {
        const LABEL: &'static str = "schema host URL";
        const REACH_POLICY: ReachPolicy = ReachPolicy::DEBUG_LOOPBACK;
        const ALLOW_QUERY: bool = false;
    }

    pub struct SsoIssuer;
    impl UrlKind for SsoIssuer {
        const LABEL: &'static str = "SSO issuer";
        const REACH_POLICY: ReachPolicy = ReachPolicy::AllowPrivate;
        const ALLOW_QUERY: bool = false;
    }

    pub struct SsoJwks;
    impl UrlKind for SsoJwks {
        const LABEL: &'static str = "SSO JWKS URI";
        const REACH_POLICY: ReachPolicy = ReachPolicy::AllowPrivate;
        const ALLOW_QUERY: bool = true;
    }
}

pub struct HttpUrl<K: UrlKind> {
    raw: String,
    parsed: url::Url,
    kind: PhantomData<fn() -> K>,
}

pub type AuthServerEndpoint = HttpUrl<url_kind::AuthServerEndpoint>;
pub type Issuer = HttpUrl<url_kind::Issuer>;
pub type JwksUri = HttpUrl<url_kind::Jwks>;
pub type PdsUrl = HttpUrl<url_kind::Pds>;
pub type SchemaHostUrl = HttpUrl<url_kind::SchemaHost>;
pub type SsoIssuer = HttpUrl<url_kind::SsoIssuer>;
pub type SsoJwksUri = HttpUrl<url_kind::SsoJwks>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidHttpUrl {
    pub kind: &'static str,
    pub value: String,
}

impl fmt::Display for InvalidHttpUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid {}: {}", self.kind, self.value)
    }
}

impl std::error::Error for InvalidHttpUrl {}

impl<K: UrlKind> HttpUrl<K> {
    pub fn new(s: impl Into<String>) -> Result<Self, InvalidHttpUrl> {
        let raw = s.into();
        match parse_http_url(&raw, K::REACH_POLICY, K::ALLOW_QUERY) {
            Some(parsed) => Ok(Self {
                raw,
                parsed,
                kind: PhantomData,
            }),
            None => Err(InvalidHttpUrl {
                kind: K::LABEL,
                value: raw,
            }),
        }
    }

    /// The URL as given.
    /// OIDC & OAuth define issuer comparison as an
    /// exact string match,
    /// so anything sent to or compared against a peer uses this.
    /// Give it to us raw & wriggling!!
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// The parsed form: lowercased scheme and host, with `/` for a bare authority.
    /// Cache keys use this so `https://oyster.cafe` and `https://oyster.cafe/` share one entry.
    pub fn canonical(&self) -> &str {
        self.parsed.as_str()
    }

    pub fn url(&self) -> &url::Url {
        &self.parsed
    }

    pub fn endpoint(&self, path: &str) -> url::Url {
        let mut url = self.parsed.clone();
        let base = url.path().trim_end_matches('/').to_owned();
        url.set_path(&format!("{}/{}", base, path.trim_start_matches('/')));
        url
    }
}

pub mod http_url {
    use super::{HttpUrl, UrlKind};
    use serde::Deserialize;

    pub fn deserialize_optional<'de, D, K>(deserializer: D) -> Result<Option<HttpUrl<K>>, D::Error>
    where
        D: serde::Deserializer<'de>,
        K: UrlKind,
    {
        Ok(Option::<String>::deserialize(deserializer)?.and_then(|s| {
            HttpUrl::new(s)
                .inspect_err(|e| tracing::warn!(error = %e, "discarding unusable URL field"))
                .ok()
        }))
    }
}

impl<K: UrlKind> FromStr for HttpUrl<K> {
    type Err = InvalidHttpUrl;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl<K: UrlKind> fmt::Debug for HttpUrl<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}({})", K::LABEL, self.raw)
    }
}

impl<K: UrlKind> fmt::Display for HttpUrl<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

impl<K: UrlKind> Clone for HttpUrl<K> {
    fn clone(&self) -> Self {
        Self {
            raw: self.raw.clone(),
            parsed: self.parsed.clone(),
            kind: PhantomData,
        }
    }
}

impl<K: UrlKind> PartialEq for HttpUrl<K> {
    fn eq(&self, other: &Self) -> bool {
        self.parsed == other.parsed
    }
}

impl<K: UrlKind> Eq for HttpUrl<K> {}

impl<K: UrlKind> Hash for HttpUrl<K> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.parsed.hash(state);
    }
}

impl<K: UrlKind> Serialize for HttpUrl<K> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.raw)
    }
}

impl<'de, K: UrlKind> Deserialize<'de> for HttpUrl<K> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::new(s).map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmailTokenPurpose {
    UpdateEmail,
    ConfirmEmail,
    DeleteAccount,
    ResetPassword,
    PlcOperation,
}

impl EmailTokenPurpose {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UpdateEmail => "update_email",
            Self::ConfirmEmail => "confirm_email",
            Self::DeleteAccount => "delete_account",
            Self::ResetPassword => "reset_password",
            Self::PlcOperation => "plc_operation",
        }
    }
}

impl fmt::Display for EmailTokenPurpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "comms_type", rename_all = "snake_case")]
pub enum CommsType {
    Verification,
    PasswordReset,
    AccountDeleted,
    AccountMigrated,
    PasskeyRecovery,
    MigrationVerification,
}

pub mod did_doc {
    use crate::{HttpUrl, InvalidHttpUrl, UrlKind};

    #[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
    pub enum PdsEndpointError {
        #[error("DID document has no atproto PDS service entry")]
        Missing,
        #[error(transparent)]
        Invalid(#[from] InvalidHttpUrl),
    }

    pub fn extract_pds_endpoint<K: UrlKind>(
        doc: &serde_json::Value,
    ) -> Result<HttpUrl<K>, PdsEndpointError> {
        doc.get("service")
            .and_then(|s| s.as_array())
            .and_then(|services| {
                services.iter().find_map(|svc| {
                    let id = svc.get("id").and_then(|v| v.as_str()).unwrap_or_default();
                    let svc_type = svc.get("type").and_then(|v| v.as_str()).unwrap_or_default();
                    ((id == "#atproto_pds" || id.ends_with("#atproto_pds"))
                        && svc_type == "AtprotoPersonalDataServer")
                        .then(|| svc.get("serviceEndpoint").and_then(|v| v.as_str()))?
                })
            })
            .ok_or(PdsEndpointError::Missing)
            .and_then(|endpoint| HttpUrl::new(endpoint).map_err(PdsEndpointError::Invalid))
    }

    pub fn extract_handle(doc: &serde_json::Value) -> Option<crate::Handle> {
        doc.get("alsoKnownAs")
            .and_then(|a| a.as_array())
            .and_then(|aliases| {
                aliases.iter().find_map(|alias| {
                    alias
                        .as_str()
                        .and_then(|s| s.strip_prefix("at://"))
                        .and_then(|h| crate::Handle::new(h).ok())
                })
            })
    }
}

#[cfg(test)]
mod http_url_tests {
    use super::did_doc::{PdsEndpointError, extract_pds_endpoint};
    use super::{
        AuthServerEndpoint, Issuer, JwksUri, PdsUrl, SchemaHostUrl, SsoIssuer, SsoJwksUri,
    };

    #[test]
    fn extract_pds_endpoint_selects_the_pds_service_and_reports_missing_or_invalid() {
        let labeler = serde_json::json!({
            "id": "#atproto_labeler",
            "type": "AtprotoLabeler",
            "serviceEndpoint": "https://labeler.nel.pet"
        });
        let pds = |endpoint: &str| {
            serde_json::json!({
                "id": "#atproto_pds",
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": endpoint
            })
        };
        let both = serde_json::json!({ "service": [labeler.clone(), pds("https://oyster.cafe")] });
        assert_eq!(
            extract_pds_endpoint::<super::url_kind::Pds>(&both)
                .unwrap()
                .as_str(),
            "https://oyster.cafe"
        );
        [
            serde_json::json!({ "service": [labeler] }),
            serde_json::json!({}),
        ]
        .iter()
        .for_each(|doc| {
            assert_eq!(
                extract_pds_endpoint::<super::url_kind::Pds>(doc).unwrap_err(),
                PdsEndpointError::Missing
            );
        });
        let plain_http = serde_json::json!({ "service": [pds("http://oyster.cafe")] });
        assert!(matches!(
            extract_pds_endpoint::<super::url_kind::Pds>(&plain_http),
            Err(PdsEndpointError::Invalid(_))
        ));
    }

    #[test]
    fn pds_and_jwks_kinds_reject_private_and_reserved_addresses() {
        [
            "https://10.0.0.1",
            "https://192.168.1.1",
            "https://172.16.0.1",
            "https://169.254.169.254/latest/meta-data",
            "https://100.64.0.1",
            "https://0.1.2.3",
            "https://192.0.0.8",
            "https://192.88.99.1",
            "https://[fd00::1]",
            "https://[fe80::1]",
            "https://[ff02::1]",
            "https://[::ffff:10.0.0.1]",
            "https://[64:ff9b::a00:1]",
            "https://[64:ff9b:1::1]",
            "https://[2002:a00:1::]",
            "https://[::10.0.0.1]",
            "https://[2001:0:0:0:0:0:f5ff:fffe]",
            "https://kelp.internal",
            "https://whelk.local",
            "https://limpet.home.arpa",
        ]
        .iter()
        .for_each(|url| {
            assert!(PdsUrl::new(*url).is_err(), "PdsUrl must reject {url}");
            assert!(JwksUri::new(*url).is_err(), "JwksUri must reject {url}");
        });
        [
            "https://oyster.cafe",
            "https://[64:ff9b::808:808]",
            "https://[::8.8.8.8]",
            "https://[2001::f7f7:f7f7]",
        ]
        .iter()
        .for_each(|url| assert!(PdsUrl::new(*url).is_ok(), "PdsUrl must accept {url}"));
    }

    #[test]
    fn each_kind_applies_its_own_local_host_policy() {
        assert!(PdsUrl::new("http://127.0.0.1:2583").is_err());
        assert!(PdsUrl::new("https://localhost").is_err());
        assert!(Issuer::new("http://localhost:8080").is_err());
        assert_eq!(
            JwksUri::new("http://localhost:8080/keys").is_ok(),
            cfg!(debug_assertions)
        );
        assert_eq!(
            SchemaHostUrl::new("http://127.0.0.1:2583").is_ok(),
            cfg!(debug_assertions)
        );
        assert!(SsoJwksUri::new("http://127.0.0.1:8080/keys").is_ok());
        assert!(SsoJwksUri::new("http://[::1]:8080/keys").is_ok());
        assert!(SsoJwksUri::new("http://squid.localhost:8080/keys").is_ok());
        assert!(SsoJwksUri::new("https://keycloak.internal/keys?client=squid").is_ok());
        assert!(SsoJwksUri::new("http://oyster.cafe/keys").is_err());
        assert!(SsoIssuer::new("https://keycloak.internal/realms/uni").is_ok());
        assert!(SsoIssuer::new("http://10.0.0.5:8080").is_ok());
        assert!(SsoIssuer::new("http://localhost:8080").is_ok());
        assert!(SsoIssuer::new("http://oyster.cafe").is_err());
        assert!(AuthServerEndpoint::new("https://oyster.cafe/oauth/par?tenant=uni").is_ok());
        [
            "https://169.254.169.254/oauth/par",
            "https://[fd00::1]/oauth/par",
            "http://127.0.0.1:2583/oauth/par",
            "http://oyster.cafe/oauth/par",
        ]
        .iter()
        .for_each(|url| {
            assert!(
                AuthServerEndpoint::new(*url).is_err(),
                "AuthServerEndpoint must reject {url}"
            );
        });
    }

    #[test]
    fn canonicalization_keeps_identity_and_rejects_query_fragment_and_userinfo() {
        assert_eq!(
            PdsUrl::new("HTTPS://oyster.cafe").unwrap().canonical(),
            "https://oyster.cafe/"
        );
        let bare = PdsUrl::new("https://oyster.cafe").unwrap();
        let slashed = PdsUrl::new("https://oyster.cafe/").unwrap();
        assert_eq!(bare, slashed);
        assert_eq!(bare.canonical(), slashed.canonical());
        let issuer = Issuer::new("https://accounts.google.com").unwrap();
        assert_eq!(issuer.as_str(), "https://accounts.google.com");
        assert_eq!(issuer.canonical(), "https://accounts.google.com/");
        assert_eq!(
            PdsUrl::new("https://oyster.cafe/pds/")
                .unwrap()
                .endpoint(".well-known/oauth-protected-resource")
                .as_str(),
            "https://oyster.cafe/pds/.well-known/oauth-protected-resource"
        );
        assert_eq!(
            JwksUri::new("https://oyster.cafe/keys?appid=abc")
                .expect("JwksUri keeps the query")
                .canonical(),
            "https://oyster.cafe/keys?appid=abc"
        );
        assert!(PdsUrl::new("https://oyster.cafe/?x=1").is_err());
        assert!(PdsUrl::new("https://oyster.cafe/#frag").is_err());
        assert!(PdsUrl::new("https://nel:pw@oyster.cafe").is_err());
        assert!(Issuer::new("https://oyster.cafe/?x=1").is_err());
        assert!(JwksUri::new("https://oyster.cafe/keys#frag").is_err());
    }
}

#[cfg(test)]
mod dns_guard_tests {
    use super::{ReachPolicy, dns_guard};
    use reqwest::dns::Resolve;

    #[tokio::test]
    async fn the_policy_gates_loopback_resolution() {
        let name = |host: &str| host.parse::<reqwest::dns::Name>().expect("valid hostname");
        assert!(
            dns_guard(ReachPolicy::GlobalOnly)
                .resolve(name("localhost"))
                .await
                .is_err()
        );
        let addrs: Vec<_> = dns_guard(ReachPolicy::AllowLoopback)
            .resolve(name("localhost"))
            .await
            .expect("localhost resolves")
            .collect();
        assert!(!addrs.is_empty());
        assert!(addrs.iter().all(|a| a.ip().is_loopback()));
    }
}

#[cfg(test)]
mod validated_newtype_tests {
    use super::*;

    #[test]
    fn a_did_stores_the_string_the_validator_accepted() {
        assert_eq!(
            Did::new("at://did:plc:nel").unwrap().as_str(),
            "did:plc:nel",
            "jacquard validates the at:// stripped form, so the stripped form must be stored"
        );
        assert_eq!(Did::new("did:plc:nel").unwrap().as_str(), "did:plc:nel");
    }

    #[test]
    fn a_handle_stores_the_string_the_validator_accepted() {
        assert_eq!(Handle::new("@nel.pet").unwrap().as_str(), "nel.pet");
        assert_eq!(Handle::new("at://nel.pet").unwrap().as_str(), "nel.pet");
        assert_eq!(Handle::new("nel.pet").unwrap().as_str(), "nel.pet");
    }

    #[test]
    fn a_handle_lowercases_on_construction() {
        assert_eq!(Handle::new("Nel.Pet").unwrap().as_str(), "nel.pet");
        assert_eq!(
            Handle::new("WHELK.OYSTER.CAFE").unwrap(),
            Handle::new("whelk.oyster.cafe").unwrap()
        );
    }

    #[test]
    fn a_prefixed_did_round_trips_through_its_own_constructor() {
        let once = Did::new("at://did:plc:whelk").unwrap();
        let twice = Did::new(once.as_str()).unwrap();
        assert_eq!(once, twice);
    }

    #[test]
    fn an_invalid_value_reports_the_string_it_was_given() {
        let err = Did::new("at://not-a-did").unwrap_err();
        assert!(
            err.to_string().contains("at://not-a-did"),
            "the error names the caller's input, got {err}"
        );
    }

    #[test]
    fn a_bare_did_ref_names_no_service() {
        let aud = DidRef::new("did:plc:abc").unwrap();
        assert_eq!(
            aud.as_str(),
            "did:plc:abc",
            "an absent fragment is not the same as an empty one, so nothing may be appended"
        );
    }

    #[test]
    fn a_did_ref_keeps_the_service_id_it_was_given() {
        let aud = DidRef::new("did:web:api.colibri.social#colibri_appview").unwrap();
        assert_eq!(
            aud.as_str(),
            "did:web:api.colibri.social#colibri_appview",
            "the fragment is what tells the receiver which of its services was audienced, \
             so it must survive entirely"
        );
    }

    #[test]
    fn a_did_ref_normalizes_its_did_half_the_way_a_did_does() {
        assert_eq!(
            DidRef::new("at://did:plc:abc#colibri_appview")
                .unwrap()
                .as_str(),
            "did:plc:abc#colibri_appview"
        );
        assert_eq!(
            DidRef::new("did:plc:def").unwrap().as_str(),
            Did::new("did:plc:def").unwrap().as_str(),
            "a fragmentless DidRef must be byte-identical to the Did it replaces"
        );
    }

    #[test]
    fn a_did_ref_rejects_anything_that_cannot_name_one_service() {
        for bad in [
            "did:web:oyster.cafe#",
            "did:web:oyster.cafe#a#b",
            "did:web:oyster.cafe# whelk",
            "did:web:oyster.cafe#a/b",
            "did:web:oyster.cafe#a?b",
            "did:web:oyster.cafe#<script>",
            "did:web:oyster.cafe#a%20b",
            "did:web:oyster.cafe#a%5Fb",
            "did:web:oyster.cafe#a\"b",
            "did:web:oyster.cafe#a[b]",
            "did:web:oyster.cafe#atproto_p\u{200b}ds",
            "did:web:oyster.cafe#\u{feff}atproto_pds",
            "not-a-did#colibri_appview",
            "#colibri_appview",
        ] {
            assert!(
                DidRef::new(bad).is_err(),
                "{bad} should not parse as a DID reference"
            );
        }
    }

    #[test]
    fn a_did_ref_does_not_second_guess_the_service_ids_it_has_not_seen() {
        for good in [
            "did:web:oyster.cafe#atproto_pds",
            "did:web:oyster.cafe#atproto_labeler",
            "did:plc:abc#bsky_chat",
            "did:web:oyster.cafe#whelk.v2",
            "did:web:oyster.cafe#atproto~pds",
            "did:web:oyster.cafe#service:1",
        ] {
            assert!(
                DidRef::new(good).is_ok(),
                "{good} names a service the receiver resolves in its own DID document, \
                 so rejecting it here would recreate the bug this type exists to fix"
            );
        }
    }

    #[test]
    fn an_over_long_service_id_is_rejected_before_the_did_ref_bound_bites() {
        let did = "did:web:oyster.cafe";
        let longest_accepted = format!("{did}#{}", "a".repeat(SERVICE_ID_MAX_LEN));
        assert!(DidRef::new(&longest_accepted).is_ok());
        let one_too_long = format!("{did}#{}", "a".repeat(SERVICE_ID_MAX_LEN + 1));
        assert!(
            DidRef::new(&one_too_long).is_err(),
            "no service names itself in more than {SERVICE_ID_MAX_LEN} bytes, and the 2048-byte \
             aud bound is far too loose to catch a fragment used as a payload"
        );
    }

    #[test]
    fn an_over_long_did_ref_is_rejected() {
        let did = format!("did:plc:{}", "a".repeat(DID_REF_MAX_LEN - "did:plc:".len()));
        assert_eq!(did.len(), DID_REF_MAX_LEN);
        assert!(
            Did::new(&did).is_ok(),
            "the DID half has to stand on its own, or the bound below proves nothing"
        );
        assert!(
            DidRef::new(format!("{did}#x")).is_err(),
            "the lexicon bounds aud at {DID_REF_MAX_LEN} bytes, which a whole DID plus the shortest service id already exceeds"
        );
    }

    #[test]
    fn a_did_ref_built_from_a_did_names_no_service() {
        let did = Did::new("did:plc:def").unwrap();
        assert_eq!(
            DidRef::from(&did).as_str(),
            did.as_str(),
            "a DID that named no service must not gain one on the way in"
        );
        assert_eq!(
            DidRef::from(did.clone()).as_str(),
            did.as_str(),
            "the owned conversion must land on the same bytes as the borrowed one"
        );
    }

    #[test]
    fn the_earliest_tid_sorts_below_every_generated_tid() {
        let earliest = Tid::earliest();
        assert!(Tid::new(earliest.as_str()).is_ok());
        assert!(earliest.as_str() < Tid::now().as_str());
    }

    #[test]
    fn a_reserved_tld_handle_parses_but_reports_its_tld_as_disallowed() {
        assert!(
            !Handle::new("whelk.oyster.cafe")
                .unwrap()
                .has_disallowed_tld()
        );
        assert!(
            Handle::new("whelk.pds.internal")
                .unwrap()
                .has_disallowed_tld()
        );
        assert!(
            Handle::new("whelk.test.local")
                .unwrap()
                .has_disallowed_tld()
        );
        assert!(Handle::new("not a handle").is_err());
        assert!(Handle::new("nodots").is_err());
    }
}
