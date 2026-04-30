use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("empty value")]
    Empty,
    #[error("invalid character {0:?}")]
    InvalidChar(char),
    #[error("zero {0}")]
    Zero(&'static str),
    #[error("invalid TLS mode {0:?}")]
    InvalidTlsMode(String),
}

fn parse_token(raw: &str, lowercase: bool, strip_trailing_dot: bool) -> Result<String, ParseError> {
    let mut s = raw.trim();
    if strip_trailing_dot {
        s = s.trim_end_matches('.');
    }
    match s {
        "" => Err(ParseError::Empty),
        _ if s.chars().any(char::is_whitespace) => Err(ParseError::InvalidChar(' ')),
        _ => Ok(match lowercase {
            true => s.to_lowercase(),
            false => s.to_string(),
        }),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SmtpHost(String);

impl SmtpHost {
    pub fn parse(raw: &str) -> Result<Self, ParseError> {
        parse_token(raw, true, false).map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SmtpPort(u16);

impl SmtpPort {
    pub fn parse(raw: u16) -> Result<Self, ParseError> {
        match raw {
            0 => Err(ParseError::Zero("smtp port")),
            n => Ok(Self(n)),
        }
    }

    pub fn as_u16(self) -> u16 {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HeloName(String);

impl HeloName {
    pub fn parse(raw: &str) -> Result<Self, ParseError> {
        parse_token(raw, false, false).map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EmailDomain(String);

impl EmailDomain {
    pub fn parse(raw: &str) -> Result<Self, ParseError> {
        parse_token(raw, true, true).map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MxHost(String);

impl MxHost {
    pub fn parse(raw: &str) -> Result<Self, ParseError> {
        parse_token(raw, true, true).map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MxPriority(u16);

impl MxPriority {
    pub fn new(value: u16) -> Self {
        Self(value)
    }

    pub fn as_u16(self) -> u16 {
        self.0
    }
}

#[derive(Debug, Clone)]
pub struct MxRecord {
    pub priority: MxPriority,
    pub host: MxHost,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DkimSelector(String);

impl DkimSelector {
    pub fn parse(raw: &str) -> Result<Self, ParseError> {
        let trimmed = raw.trim();
        let valid = !trimmed.is_empty() && trimmed.split('.').all(valid_subdomain);
        match valid {
            true => Ok(Self(trimmed.to_string())),
            false => Err(ParseError::InvalidChar('?')),
        }
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

fn valid_subdomain(seg: &str) -> bool {
    let starts_alnum = seg
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric());
    let ends_alnum = seg
        .chars()
        .next_back()
        .is_some_and(|c| c.is_ascii_alphanumeric());
    let body_ok = seg.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
    starts_alnum && ends_alnum && body_ok
}

#[derive(Debug, Clone)]
pub struct DkimKeyPath(PathBuf);

impl DkimKeyPath {
    pub fn parse(raw: &str) -> Result<Self, ParseError> {
        let trimmed = raw.trim();
        match trimmed.is_empty() {
            true => Err(ParseError::Empty),
            false => Ok(Self(PathBuf::from(trimmed))),
        }
    }

    pub fn as_path(&self) -> &std::path::Path {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmtpUsername(String);

impl SmtpUsername {
    pub fn parse(raw: &str) -> Result<Self, ParseError> {
        match raw.is_empty() {
            true => Err(ParseError::Empty),
            false => Ok(Self(raw.to_string())),
        }
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

#[derive(Clone)]
pub struct SmtpPassword(secrecy::SecretString);

impl SmtpPassword {
    pub fn parse(raw: &str) -> Result<Self, ParseError> {
        match raw.is_empty() {
            true => Err(ParseError::Empty),
            false => Ok(Self(secrecy::SecretString::from(raw.to_string()))),
        }
    }

    pub fn expose(&self) -> &str {
        use secrecy::ExposeSecret;
        self.0.expose_secret()
    }
}

impl std::fmt::Debug for SmtpPassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SmtpPassword(***)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    Implicit,
    Starttls,
    None,
}

impl TlsMode {
    pub fn parse(raw: &str) -> Result<Self, ParseError> {
        match raw.to_ascii_lowercase().as_str() {
            "implicit" => Ok(Self::Implicit),
            "starttls" => Ok(Self::Starttls),
            "none" => Ok(Self::None),
            other => Err(ParseError::InvalidTlsMode(other.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smtp_host_lowercases_and_trims() {
        let h = SmtpHost::parse("  SMTP.NEL.PET  ").unwrap();
        assert_eq!(h.as_str(), "smtp.nel.pet");
    }

    #[test]
    fn smtp_host_rejects_whitespace() {
        assert!(SmtpHost::parse("a b").is_err());
    }

    #[test]
    fn smtp_host_rejects_empty() {
        assert!(SmtpHost::parse("").is_err());
        assert!(SmtpHost::parse("   ").is_err());
    }

    #[test]
    fn smtp_port_rejects_zero() {
        assert!(SmtpPort::parse(0).is_err());
        assert_eq!(SmtpPort::parse(587).unwrap().as_u16(), 587);
    }

    #[test]
    fn email_domain_strips_trailing_dot() {
        assert_eq!(EmailDomain::parse("Nel.pet.").unwrap().as_str(), "nel.pet");
    }

    #[test]
    fn dkim_selector_validates() {
        assert!(DkimSelector::parse("default").is_ok());
        assert!(DkimSelector::parse("s1.nel.pet").is_ok());
        assert!(DkimSelector::parse("s2024-q1").is_ok());
        assert!(DkimSelector::parse("mailo-2024.nel.pet").is_ok());
        assert!(DkimSelector::parse("a-b").is_ok());
        assert!(DkimSelector::parse("").is_err());
        assert!(DkimSelector::parse("a..b").is_err());
        assert!(DkimSelector::parse("-leading").is_err());
        assert!(DkimSelector::parse("trailing-").is_err());
        assert!(DkimSelector::parse("s_under").is_err());
    }

    #[test]
    fn tls_mode_parses_known_modes() {
        assert_eq!(TlsMode::parse("STARTTLS").unwrap(), TlsMode::Starttls);
        assert_eq!(TlsMode::parse("implicit").unwrap(), TlsMode::Implicit);
        assert_eq!(TlsMode::parse("none").unwrap(), TlsMode::None);
        assert!(TlsMode::parse("garbage").is_err());
    }

    #[test]
    fn smtp_password_redacts_in_debug() {
        let p = SmtpPassword::parse("hunter2").unwrap();
        let dbg = format!("{:?}", p);
        assert_eq!(dbg, "SmtpPassword(***)");
        assert!(!dbg.contains("hunter2"));
    }
}
