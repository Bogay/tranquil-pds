use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::fmt;
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

        impl From<String> for $name {
            fn from(s: String) -> Self {
                Self(s)
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
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
        #[serde(transparent)]
        #[sqlx(transparent)]
        $vis struct $name(String);

        impl $name {
            pub fn new(s: impl Into<String>) -> Self {
                Self(s.into())
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
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, sqlx::Type)]
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
                let validator: fn(&str) -> Result<(), ()> = $validator;
                validator(&s).map_err(|_| $error::Invalid(s.clone()))?;
                Ok(Self(s))
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
    validator = |s| jacquard_common::types::string::Did::new(s).map(|_| ()).map_err(|_| ());
}

impl Did {
    pub fn is_plc(&self) -> bool {
        self.0.starts_with("did:plc:")
    }

    pub fn is_web(&self) -> bool {
        self.0.starts_with("did:web:")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, sqlx::Type)]
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
    pub fn new(s: impl Into<String>) -> Result<Self, HandleError> {
        let s = s.into();
        jacquard_common::types::string::Handle::new(&s)
            .map_err(|_| HandleError::Invalid(s.clone()))?;
        Ok(Self(s))
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
    validator = |s| jacquard_common::types::string::Rkey::new(s).map(|_| ()).map_err(|_| ());
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
    validator = |s| jacquard_common::types::string::Nsid::new(s).map(|_| ()).map_err(|_| ());
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
    validator = |s| jacquard_common::types::string::AtUri::new(s).map(|_| ()).map_err(|_| ());
}

impl AtUri {
    pub fn from_parts(did: &str, collection: &str, rkey: &str) -> Self {
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
    validator = |s| jacquard_common::types::string::Tid::from_str(s).map(|_| ()).map_err(|_| ());
}

impl Tid {
    pub fn now() -> Self {
        use jacquard_common::types::integer::LimitedU32;
        Self(jacquard_common::types::string::Tid::now(LimitedU32::MIN).to_string())
    }
}

validated_string_newtype! {
    pub struct Datetime;
    error = DatetimeError;
    label = "datetime";
    validator = |s| jacquard_common::types::string::Datetime::from_str(s).map(|_| ()).map_err(|_| ());
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
    validator = |s| jacquard_common::types::string::Language::from_str(s).map(|_| ()).map_err(|_| ());
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, sqlx::Type)]
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

simple_string_newtype! {
    pub struct ClientId;
}

simple_string_newtype! {
    pub struct DeviceId;
}

simple_string_newtype! {
    pub struct RequestId;
}

simple_string_newtype! {
    pub struct Jti;
}

simple_string_newtype! {
    pub struct AuthorizationCode;
}

simple_string_newtype! {
    pub struct RefreshToken;
}

simple_string_newtype! {
    pub struct InviteCode;
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "comms_channel", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
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

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "comms_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum CommsType {
    Verification,
    PasswordReset,
    AccountDeleted,
    AccountMigrated,
    PasskeyRecovery,
    MigrationVerification,
}
