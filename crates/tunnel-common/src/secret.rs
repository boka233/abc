//! Redacted secret wrapper.
//!
//! Node secrets, PSKs, JWT signing keys and private-key material must never
//! reach the logs. Wrapping them in [`Secret`] makes accidental
//! `tracing::info!(?config)` safe: the payload renders as `***`.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Explicit, greppable accessor. Call sites are auditable.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(***)")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("***")
    }
}

impl From<String> for Secret {
    fn from(v: String) -> Self {
        Secret(v)
    }
}

impl From<&str> for Secret {
    fn from(v: &str) -> Self {
        Secret(v.to_string())
    }
}

impl Serialize for Secret {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Serialisation is used for config distribution over an authenticated
        // TLS channel, so the real value is emitted here. Logging goes through
        // Debug/Display, which stay redacted.
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_and_display_are_redacted() {
        let s = Secret::new("super-secret-psk");
        assert_eq!(format!("{s:?}"), "Secret(***)");
        assert_eq!(format!("{s}"), "***");
        assert!(!format!("{s:?}").contains("psk"));
        assert_eq!(s.expose(), "super-secret-psk");
    }

    #[test]
    fn serde_roundtrip_keeps_value() {
        let s = Secret::new("abc");
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, "\"abc\"");
        let back: Secret = serde_json::from_str(&json).unwrap();
        assert_eq!(back.expose(), "abc");
    }
}
