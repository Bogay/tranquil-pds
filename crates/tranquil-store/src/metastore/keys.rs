use serde::{Deserialize, Serialize};
use siphasher::sip::SipHasher24;
use std::hash::Hasher;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UserHash(u64);

const SIPHASH_KEY0: u64 = 0x7472_616e_7175_696c;
const SIPHASH_KEY1: u64 = 0x7064_735f_7573_6572;

impl UserHash {
    pub fn from_did(did: &str) -> Self {
        let mut hasher = SipHasher24::new_with_keys(SIPHASH_KEY0, SIPHASH_KEY1);
        hasher.write(did.as_bytes());
        Self(hasher.finish())
    }

    pub fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    pub fn raw(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for UserHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyTag(u8);

impl KeyTag {
    pub const REPO_META: Self = Self(0x01);
    pub const RECORDS: Self = Self(0x02);
    pub const USER_BLOCKS: Self = Self(0x03);
    pub const HANDLES: Self = Self(0x04);
    pub const BLOBS: Self = Self(0x05);
    pub const BACKLINKS: Self = Self(0x06);
    pub const BLOB_BY_CID: Self = Self(0x07);

    pub const USER_MAP: Self = Self(0x10);
    pub const USER_MAP_REVERSE: Self = Self(0x11);

    pub const REV_TO_SEQ: Self = Self(0x20);
    pub const SEQ_META: Self = Self(0x21);
    pub const SEQ_TOMBSTONE: Self = Self(0x22);
    pub const METASTORE_CURSOR: Self = Self(0x23);
    pub const DID_EVENTS: Self = Self(0x24);

    pub const RECORD_BLOBS: Self = Self(0x30);
    pub const BACKLINK_BY_USER: Self = Self(0x31);

    pub const USER_PRIMARY: Self = Self(0x40);
    pub const USER_BY_HANDLE: Self = Self(0x41);
    pub const USER_BY_EMAIL: Self = Self(0x42);
    pub const USER_PASSKEYS: Self = Self(0x43);
    pub const USER_PASSKEY_BY_CRED: Self = Self(0x44);
    pub const USER_TOTP: Self = Self(0x45);
    pub const USER_BACKUP_CODES: Self = Self(0x46);
    pub const USER_WEBAUTHN_CHALLENGE: Self = Self(0x47);
    pub const USER_RESET_CODE: Self = Self(0x48);
    pub const USER_RECOVERY_TOKEN: Self = Self(0x49);
    pub const USER_DID_WEB_OVERRIDES: Self = Self(0x4A);
    pub const USER_HANDLE_RESERVATION: Self = Self(0x4B);
    pub const USER_COMMS_CHANNEL: Self = Self(0x4C);
    pub const USER_TELEGRAM_LOOKUP: Self = Self(0x4D);
    pub const USER_DISCORD_LOOKUP: Self = Self(0x4E);

    pub const SESSION_PRIMARY: Self = Self(0x50);
    pub const SESSION_BY_ACCESS: Self = Self(0x51);
    pub const SESSION_BY_REFRESH: Self = Self(0x52);
    pub const SESSION_USED_REFRESH: Self = Self(0x53);
    pub const SESSION_APP_PASSWORD: Self = Self(0x54);
    pub const SESSION_BY_DID: Self = Self(0x55);
    pub const SESSION_LAST_REAUTH: Self = Self(0x56);
    pub const SESSION_ID_COUNTER: Self = Self(0x57);

    pub const OAUTH_TOKEN: Self = Self(0x60);
    pub const OAUTH_TOKEN_BY_ID: Self = Self(0x61);
    pub const OAUTH_TOKEN_BY_REFRESH: Self = Self(0x62);
    pub const OAUTH_TOKEN_BY_PREV_REFRESH: Self = Self(0x63);
    pub const OAUTH_USED_REFRESH: Self = Self(0x64);
    pub const OAUTH_AUTH_REQUEST: Self = Self(0x65);
    pub const OAUTH_AUTH_BY_CODE: Self = Self(0x66);
    pub const OAUTH_DEVICE: Self = Self(0x67);
    pub const OAUTH_ACCOUNT_DEVICE: Self = Self(0x68);
    pub const OAUTH_DPOP_JTI: Self = Self(0x69);
    pub const OAUTH_2FA_CHALLENGE: Self = Self(0x6A);
    pub const OAUTH_2FA_BY_REQUEST: Self = Self(0x6B);
    pub const OAUTH_SCOPE_PREFS: Self = Self(0x6C);
    pub const OAUTH_AUTH_CLIENT: Self = Self(0x6D);
    pub const OAUTH_DEVICE_TRUST: Self = Self(0x6E);
    pub const OAUTH_TOKEN_FAMILY_COUNTER: Self = Self(0x6F);

    pub const INFRA_COMMS_QUEUE: Self = Self(0x70);
    pub const INFRA_INVITE_CODE: Self = Self(0x71);
    pub const INFRA_INVITE_USE: Self = Self(0x72);
    pub const INFRA_INVITE_BY_ACCOUNT: Self = Self(0x73);
    pub const INFRA_INVITE_BY_USER: Self = Self(0x74);
    pub const INFRA_SIGNING_KEY: Self = Self(0x75);
    pub const INFRA_SIGNING_KEY_BY_ID: Self = Self(0x76);
    pub const INFRA_DELETION_REQUEST: Self = Self(0x77);
    pub const INFRA_DELETION_BY_DID: Self = Self(0x78);
    pub const INFRA_ACCOUNT_PREF: Self = Self(0x79);
    pub const INFRA_SERVER_CONFIG: Self = Self(0x7A);
    pub const INFRA_REPORT: Self = Self(0x7B);
    pub const INFRA_PLC_TOKEN: Self = Self(0x7C);
    pub const INFRA_COMMS_HISTORY: Self = Self(0x7D);
    pub const INFRA_INVITE_CODE_USED_BY: Self = Self(0x7E);

    pub const DELEG_GRANT: Self = Self(0x80);
    pub const DELEG_BY_CONTROLLER: Self = Self(0x81);
    pub const DELEG_AUDIT_LOG: Self = Self(0x82);

    pub const SSO_IDENTITY: Self = Self(0x90);
    pub const SSO_BY_PROVIDER: Self = Self(0x91);
    pub const SSO_AUTH_STATE: Self = Self(0x92);
    pub const SSO_PENDING_REG: Self = Self(0x93);
    pub const SSO_BY_ID: Self = Self(0x94);

    pub const OAUTH_TOKEN_BY_FAMILY: Self = Self(0xA0);

    pub const FORMAT_VERSION: Self = Self(0xFF);

    pub const fn raw(self) -> u8 {
        self.0
    }

    pub fn exclusive_prefix_bound(self) -> [u8; 1] {
        match self.0.checked_add(1) {
            Some(next) => [next],
            None => panic!("cannot compute exclusive upper bound for tag 0xFF"),
        }
    }

    #[cfg(test)]
    pub fn from_raw_unchecked(raw: u8) -> Self {
        Self(raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_hash_deterministic() {
        let a = UserHash::from_did("did:plc:abc123");
        let b = UserHash::from_did("did:plc:abc123");
        assert_eq!(a, b);
    }

    #[test]
    fn user_hash_different_dids_differ() {
        let a = UserHash::from_did("did:plc:abc123");
        let b = UserHash::from_did("did:plc:xyz789");
        assert_ne!(a, b);
    }

    #[test]
    fn user_hash_display_is_hex() {
        let h = UserHash::from_raw(0xDEAD_BEEF_CAFE_BABE);
        assert_eq!(h.to_string(), "deadbeefcafebabe");
    }

    #[test]
    fn key_tags_are_distinct() {
        let tags = [
            KeyTag::REPO_META,
            KeyTag::RECORDS,
            KeyTag::USER_BLOCKS,
            KeyTag::HANDLES,
            KeyTag::BLOBS,
            KeyTag::BACKLINKS,
            KeyTag::BLOB_BY_CID,
            KeyTag::USER_MAP,
            KeyTag::USER_MAP_REVERSE,
            KeyTag::REV_TO_SEQ,
            KeyTag::SEQ_META,
            KeyTag::SEQ_TOMBSTONE,
            KeyTag::METASTORE_CURSOR,
            KeyTag::DID_EVENTS,
            KeyTag::RECORD_BLOBS,
            KeyTag::BACKLINK_BY_USER,
            KeyTag::USER_PRIMARY,
            KeyTag::USER_BY_HANDLE,
            KeyTag::USER_BY_EMAIL,
            KeyTag::USER_PASSKEYS,
            KeyTag::USER_PASSKEY_BY_CRED,
            KeyTag::USER_TOTP,
            KeyTag::USER_BACKUP_CODES,
            KeyTag::USER_WEBAUTHN_CHALLENGE,
            KeyTag::USER_RESET_CODE,
            KeyTag::USER_RECOVERY_TOKEN,
            KeyTag::USER_DID_WEB_OVERRIDES,
            KeyTag::USER_HANDLE_RESERVATION,
            KeyTag::USER_COMMS_CHANNEL,
            KeyTag::USER_TELEGRAM_LOOKUP,
            KeyTag::USER_DISCORD_LOOKUP,
            KeyTag::SESSION_PRIMARY,
            KeyTag::SESSION_BY_ACCESS,
            KeyTag::SESSION_BY_REFRESH,
            KeyTag::SESSION_USED_REFRESH,
            KeyTag::SESSION_APP_PASSWORD,
            KeyTag::SESSION_BY_DID,
            KeyTag::SESSION_LAST_REAUTH,
            KeyTag::SESSION_ID_COUNTER,
            KeyTag::OAUTH_TOKEN,
            KeyTag::OAUTH_TOKEN_BY_ID,
            KeyTag::OAUTH_TOKEN_BY_REFRESH,
            KeyTag::OAUTH_TOKEN_BY_PREV_REFRESH,
            KeyTag::OAUTH_USED_REFRESH,
            KeyTag::OAUTH_AUTH_REQUEST,
            KeyTag::OAUTH_AUTH_BY_CODE,
            KeyTag::OAUTH_DEVICE,
            KeyTag::OAUTH_ACCOUNT_DEVICE,
            KeyTag::OAUTH_DPOP_JTI,
            KeyTag::OAUTH_2FA_CHALLENGE,
            KeyTag::OAUTH_2FA_BY_REQUEST,
            KeyTag::OAUTH_SCOPE_PREFS,
            KeyTag::OAUTH_AUTH_CLIENT,
            KeyTag::OAUTH_DEVICE_TRUST,
            KeyTag::OAUTH_TOKEN_FAMILY_COUNTER,
            KeyTag::INFRA_COMMS_QUEUE,
            KeyTag::INFRA_INVITE_CODE,
            KeyTag::INFRA_INVITE_USE,
            KeyTag::INFRA_INVITE_BY_ACCOUNT,
            KeyTag::INFRA_INVITE_BY_USER,
            KeyTag::INFRA_SIGNING_KEY,
            KeyTag::INFRA_SIGNING_KEY_BY_ID,
            KeyTag::INFRA_DELETION_REQUEST,
            KeyTag::INFRA_DELETION_BY_DID,
            KeyTag::INFRA_ACCOUNT_PREF,
            KeyTag::INFRA_SERVER_CONFIG,
            KeyTag::INFRA_REPORT,
            KeyTag::INFRA_PLC_TOKEN,
            KeyTag::INFRA_COMMS_HISTORY,
            KeyTag::INFRA_INVITE_CODE_USED_BY,
            KeyTag::DELEG_GRANT,
            KeyTag::DELEG_BY_CONTROLLER,
            KeyTag::DELEG_AUDIT_LOG,
            KeyTag::SSO_IDENTITY,
            KeyTag::SSO_BY_PROVIDER,
            KeyTag::SSO_AUTH_STATE,
            KeyTag::SSO_PENDING_REG,
            KeyTag::SSO_BY_ID,
            KeyTag::OAUTH_TOKEN_BY_FAMILY,
            KeyTag::FORMAT_VERSION,
        ];
        let mut raw: Vec<u8> = tags.iter().map(|t| t.raw()).collect();
        let original_len = raw.len();
        raw.sort();
        raw.dedup();
        assert_eq!(raw.len(), original_len);
    }

    #[test]
    fn key_tag_ordering() {
        assert!(KeyTag::REPO_META < KeyTag::RECORDS);
        assert!(KeyTag::RECORDS < KeyTag::USER_BLOCKS);
    }

    #[test]
    fn exclusive_prefix_bound_is_tag_plus_one() {
        assert_eq!(
            KeyTag::REPO_META.exclusive_prefix_bound(),
            [KeyTag::REPO_META.raw() + 1]
        );
        assert_eq!(KeyTag::HANDLES.exclusive_prefix_bound(), [0x05]);
    }

    #[test]
    #[should_panic(expected = "cannot compute exclusive upper bound for tag 0xFF")]
    fn exclusive_prefix_bound_panics_for_0xff() {
        KeyTag::FORMAT_VERSION.exclusive_prefix_bound();
    }
}
