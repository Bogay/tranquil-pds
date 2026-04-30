use std::fs;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use ed25519_dalek::pkcs8::DecodePrivateKey as _;
use lettre::Message;
use lettre::message::dkim::{
    DkimCanonicalization, DkimCanonicalizationType, DkimConfig as LettreDkimConfig,
    DkimSigningAlgorithm, DkimSigningKey,
};
use lettre::message::header::HeaderName;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::pkcs8::LineEnding;

use super::types::{DkimKeyPath, DkimSelector, EmailDomain};
use crate::sender::SendError;

const SIGNED_HEADERS: &[&str] = &[
    "From",
    "Sender",
    "Reply-To",
    "To",
    "Cc",
    "Subject",
    "Date",
    "In-Reply-To",
    "References",
    "MIME-Version",
    "Content-Type",
    "Content-Transfer-Encoding",
];

pub struct DkimSigner {
    config: LettreDkimConfig,
}

impl DkimSigner {
    pub fn load(
        selector: DkimSelector,
        domain: EmailDomain,
        path: DkimKeyPath,
    ) -> Result<Self, SendError> {
        let pem = fs::read_to_string(path.as_path()).map_err(|e| {
            SendError::DkimSign(format!("read DKIM key {}: {e}", path.as_path().display()))
        })?;
        Self::from_pem(selector, domain, &pem)
    }

    pub fn from_pem(
        selector: DkimSelector,
        domain: EmailDomain,
        pem: &str,
    ) -> Result<Self, SendError> {
        let key = parse_key(pem)?;
        let canonicalization = DkimCanonicalization {
            header: DkimCanonicalizationType::Relaxed,
            body: DkimCanonicalizationType::Relaxed,
        };
        let headers = SIGNED_HEADERS
            .iter()
            .copied()
            .map(HeaderName::new_from_ascii_str)
            .collect();
        let config = LettreDkimConfig::new(
            selector.into_inner(),
            domain.into_inner(),
            key,
            headers,
            canonicalization,
        );
        Ok(Self { config })
    }

    pub fn sign(&self, message: &mut Message) {
        message.sign(&self.config);
    }
}

impl std::fmt::Debug for DkimSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DkimSigner")
    }
}

fn parse_key(input: &str) -> Result<DkimSigningKey, SendError> {
    let trimmed = input.trim_start();
    match trimmed {
        s if s.starts_with("-----BEGIN RSA PRIVATE KEY-----") => {
            DkimSigningKey::new(input, DkimSigningAlgorithm::Rsa)
                .map_err(|e| SendError::DkimSign(format!("RSA PKCS#1 PEM rejected: {e}")))
        }
        s if s.starts_with("-----BEGIN PRIVATE KEY-----") => parse_pkcs8(input),
        s if s.starts_with("-----BEGIN") => Err(SendError::DkimSign(
            "unrecognized PEM type; expected an RSA or Ed25519 private key".to_string(),
        )),
        _ => DkimSigningKey::new(input.trim(), DkimSigningAlgorithm::Ed25519).map_err(|e| {
            SendError::DkimSign(format!(
                "expected base64-encoded 32-byte Ed25519 seed or a PEM-wrapped key: {e}"
            ))
        }),
    }
}

fn parse_pkcs8(pem: &str) -> Result<DkimSigningKey, SendError> {
    let ed25519_err = match ed25519_dalek::SigningKey::from_pkcs8_pem(pem) {
        Ok(key) => {
            let seed = BASE64_STANDARD.encode(key.to_bytes());
            return DkimSigningKey::new(&seed, DkimSigningAlgorithm::Ed25519)
                .map_err(|e| SendError::DkimSign(format!("re-import Ed25519 seed: {e}")));
        }
        Err(e) => e,
    };

    let rsa_err = match rsa::RsaPrivateKey::from_pkcs8_pem(pem) {
        Ok(key) => {
            let pkcs1 = key
                .to_pkcs1_pem(LineEnding::LF)
                .map_err(|e| SendError::DkimSign(format!("re-encode RSA PKCS#8 as PKCS#1: {e}")))?;
            return DkimSigningKey::new(pkcs1.as_str(), DkimSigningAlgorithm::Rsa)
                .map_err(|e| SendError::DkimSign(format!("re-import RSA PKCS#1: {e}")));
        }
        Err(e) => e,
    };

    Err(SendError::DkimSign(format!(
        "PKCS#8 PEM rejected by both parsers; ed25519: {ed25519_err}; rsa: {rsa_err}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::pkcs8::EncodePrivateKey as _;
    use lettre::message::Mailbox;
    use lettre::message::header::ContentType;
    use rsa::pkcs1::DecodeRsaPrivateKey as _;

    const ED25519_RAW_SEED_B64: &str = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=";

    const RSA_PKCS1_PEM: &str = include_str!("test_fixtures/rsa2048-priv-pkcs1.pem");

    fn ed25519_pkcs8_pem() -> String {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string()
    }

    fn rsa_pkcs8_pem() -> String {
        let key = rsa::RsaPrivateKey::from_pkcs1_pem(RSA_PKCS1_PEM).unwrap();
        key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string()
    }

    fn signer(pem: &str) -> DkimSigner {
        DkimSigner::from_pem(
            DkimSelector::parse("default").unwrap(),
            EmailDomain::parse("nel.pet").unwrap(),
            pem,
        )
        .expect("key should load")
    }

    fn signed_headers(signer: &DkimSigner) -> String {
        let from: Mailbox = "sender@nel.pet".parse().unwrap();
        let to: Mailbox = "recipient@nel.pet".parse().unwrap();
        let mut message = Message::builder()
            .from(from)
            .to(to)
            .subject("Roundtrip")
            .header(ContentType::TEXT_PLAIN)
            .body("Body".to_string())
            .unwrap();
        signer.sign(&mut message);
        String::from_utf8(message.formatted()).unwrap()
    }

    #[test]
    fn rejects_garbage() {
        assert!(matches!(
            parse_key("not a key"),
            Err(SendError::DkimSign(_))
        ));
    }

    #[test]
    fn rejects_unknown_pem_type() {
        let pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----\n";
        match parse_key(pem) {
            Err(SendError::DkimSign(msg)) => assert!(msg.contains("unrecognized"), "msg: {msg}"),
            other => panic!("expected unrecognized PEM error, got {other:?}"),
        }
    }

    #[test]
    fn ed25519_raw_seed_signs() {
        let raw = signed_headers(&signer(ED25519_RAW_SEED_B64));
        assert_signed_with(&raw, "a=ed25519-sha256");
    }

    #[test]
    fn ed25519_pkcs8_pem_signs() {
        let raw = signed_headers(&signer(&ed25519_pkcs8_pem()));
        assert_signed_with(&raw, "a=ed25519-sha256");
    }

    #[test]
    fn rsa_pkcs1_pem_signs() {
        let raw = signed_headers(&signer(RSA_PKCS1_PEM));
        assert_signed_with(&raw, "a=rsa-sha256");
    }

    #[test]
    fn rsa_pkcs8_pem_signs() {
        let raw = signed_headers(&signer(&rsa_pkcs8_pem()));
        assert_signed_with(&raw, "a=rsa-sha256");
    }

    fn assert_signed_with(raw: &str, algorithm: &str) {
        assert!(
            raw.contains("DKIM-Signature:"),
            "no signature header: {raw}"
        );
        assert!(raw.contains(algorithm), "missing {algorithm}: {raw}");
        assert!(
            raw.contains("c=relaxed/relaxed"),
            "expected relaxed/relaxed canonicalization: {raw}"
        );
    }
}
