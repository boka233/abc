//! Session tokens and login throttling.
//!
//! # Token design
//!
//! JWT (HS256) carrying `sub`, `username`, `role`, `exp` and `iat`. Stateless on
//! purpose: the control plane must be restartable without invalidating every
//! session, and there is no second instance to share session state with.
//!
//! The cost of statelessness is that a token cannot be revoked before it
//! expires. Mitigations: a 12-hour default TTL, and password change / account
//! disable both take effect on the next request because every request re-checks
//! the account (see [`crate::api::middleware`]).
//!
//! # Login throttling
//!
//! Per-IP counters with a lockout window. Argon2 verification is deliberately
//! expensive, so unthrottled login is also a CPU-exhaustion vector, not just a
//! credential-stuffing one.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use tunnel_common::Secret;

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("session expired")]
    Expired,
    #[error("invalid token")]
    InvalidToken,
    #[error("too many attempts; try again in {retry_after_secs}s")]
    Throttled { retry_after_secs: u64 },
    #[error("account is disabled")]
    Disabled,
    #[error("password change required")]
    PasswordChangeRequired,
}

/// JWT claims. Field names are the registered short forms where they exist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// User id.
    pub sub: String,
    pub username: String,
    pub role: String,
    /// Expiry, seconds since epoch.
    pub exp: i64,
    /// Issued at, seconds since epoch.
    pub iat: i64,
}

impl Claims {
    pub fn is_admin(&self) -> bool {
        self.role == "admin"
    }
}

pub struct TokenIssuer {
    encoding: EncodingKey,
    decoding: DecodingKey,
    ttl: Duration,
    validation: Validation,
}

impl TokenIssuer {
    pub fn new(secret: &Secret, ttl: Duration) -> Self {
        let mut validation = Validation::new(Algorithm::HS256);
        // Expiry is the only claim we rely on; no audience or issuer to check in
        // a single-tenant deployment.
        validation.set_required_spec_claims(&["exp", "sub"]);
        // A few seconds of tolerance for clock skew between the panel and the
        // server, without meaningfully extending a session.
        validation.leeway = 5;

        Self {
            encoding: EncodingKey::from_secret(secret.as_bytes()),
            decoding: DecodingKey::from_secret(secret.as_bytes()),
            ttl,
            validation,
        }
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    pub fn issue(&self, user_id: &str, username: &str, role: &str) -> Result<String, AuthError> {
        let now = chrono::Utc::now();
        let claims = Claims {
            sub: user_id.to_string(),
            username: username.to_string(),
            role: role.to_string(),
            iat: now.timestamp(),
            exp: (now + chrono::Duration::from_std(self.ttl).unwrap_or(chrono::Duration::hours(12)))
                .timestamp(),
        };
        encode(&Header::new(Algorithm::HS256), &claims, &self.encoding)
            .map_err(|_| AuthError::InvalidToken)
    }

    pub fn verify(&self, token: &str) -> Result<Claims, AuthError> {
        match decode::<Claims>(token, &self.decoding, &self.validation) {
            Ok(data) => Ok(data.claims),
            Err(e) => Err(match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::Expired,
                _ => AuthError::InvalidToken,
            }),
        }
    }
}

/// Per-IP failed-login tracking.
#[derive(Debug)]
pub struct LoginThrottle {
    attempts: DashMap<IpAddr, AttemptRecord>,
    limit: u32,
    lockout: Duration,
}

#[derive(Debug, Clone, Copy)]
struct AttemptRecord {
    count: u32,
    first_at: Instant,
    locked_until: Option<Instant>,
}

impl LoginThrottle {
    pub fn new(limit: u32, lockout: Duration) -> Self {
        Self {
            attempts: DashMap::new(),
            limit: limit.max(1),
            lockout,
        }
    }

    /// Check before verifying credentials.
    pub fn check(&self, ip: IpAddr) -> Result<(), AuthError> {
        if let Some(record) = self.attempts.get(&ip) {
            if let Some(until) = record.locked_until {
                let remaining = until.saturating_duration_since(Instant::now());
                if !remaining.is_zero() {
                    return Err(AuthError::Throttled {
                        retry_after_secs: remaining.as_secs().max(1),
                    });
                }
            }
        }
        Ok(())
    }

    /// Record a failure and lock out on the threshold.
    pub fn record_failure(&self, ip: IpAddr) {
        let now = Instant::now();
        let mut entry = self.attempts.entry(ip).or_insert(AttemptRecord {
            count: 0,
            first_at: now,
            locked_until: None,
        });

        // Roll the window so a slow trickle of failures over hours does not
        // eventually lock out a legitimate user.
        if now.duration_since(entry.first_at) > self.lockout.saturating_mul(2) {
            entry.count = 0;
            entry.first_at = now;
            entry.locked_until = None;
        }

        entry.count = entry.count.saturating_add(1);
        if entry.count >= self.limit {
            entry.locked_until = Some(now + self.lockout);
        }
    }

    /// Clear on success so one bad password does not haunt a valid session.
    pub fn record_success(&self, ip: IpAddr) {
        self.attempts.remove(&ip);
    }

    /// Drop expired records. Called on a timer; without it the map grows with
    /// every distinct attacking IP.
    pub fn prune(&self) {
        let now = Instant::now();
        let window = self.lockout.saturating_mul(2);
        self.attempts.retain(|_, record| {
            let unlocked = record
                .locked_until
                .map(|until| until > now)
                .unwrap_or(false);
            unlocked || now.duration_since(record.first_at) <= window
        });
    }

    pub fn tracked_ips(&self) -> usize {
        self.attempts.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issuer(ttl_secs: u64) -> TokenIssuer {
        TokenIssuer::new(
            &Secret::new("test-signing-secret-at-least-32-chars"),
            Duration::from_secs(ttl_secs),
        )
    }

    #[test]
    fn issue_then_verify() {
        let issuer = issuer(3600);
        let token = issuer.issue("u1", "admin", "admin").unwrap();
        let claims = issuer.verify(&token).unwrap();
        assert_eq!(claims.sub, "u1");
        assert_eq!(claims.username, "admin");
        assert!(claims.is_admin());
        assert!(claims.exp > claims.iat);
    }

    #[test]
    fn tampered_token_is_rejected() {
        let issuer = issuer(3600);
        let token = issuer.issue("u1", "admin", "admin").unwrap();

        // Flip a character in the payload; the signature must no longer match.
        let mut parts: Vec<&str> = token.split('.').collect();
        let payload = parts[1].to_string();
        let tampered_payload = format!("{}X", &payload[..payload.len() - 1]);
        parts[1] = &tampered_payload;
        let tampered = parts.join(".");

        assert!(matches!(
            issuer.verify(&tampered),
            Err(AuthError::InvalidToken)
        ));
    }

    #[test]
    fn token_from_another_secret_is_rejected() {
        // The scenario that matters if a deployment rotates its signing key, or
        // if an attacker guesses a weak one.
        let a = issuer(3600);
        let b = TokenIssuer::new(&Secret::new("a-completely-different-secret-value"), Duration::from_secs(3600));
        let token = a.issue("u1", "admin", "admin").unwrap();
        assert!(b.verify(&token).is_err());
    }

    #[test]
    fn expired_token_is_reported_as_expired() {
        // Zero TTL plus the validation leeway means we must go further back;
        // issue with a TTL of 0 and rely on `exp == iat` being in the past once
        // leeway is accounted for by a manual claim.
        let issuer = issuer(1);
        let now = chrono::Utc::now();
        let claims = Claims {
            sub: "u1".into(),
            username: "admin".into(),
            role: "admin".into(),
            iat: (now - chrono::Duration::hours(2)).timestamp(),
            exp: (now - chrono::Duration::hours(1)).timestamp(),
        };
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(b"test-signing-secret-at-least-32-chars"),
        )
        .unwrap();
        assert!(matches!(issuer.verify(&token), Err(AuthError::Expired)));
    }

    #[test]
    fn garbage_tokens_do_not_panic() {
        let issuer = issuer(3600);
        for bad in ["", "not.a.token", "a.b", "...", &"x".repeat(5000)] {
            assert!(issuer.verify(bad).is_err(), "accepted `{bad}`");
        }
    }

    #[test]
    fn unsigned_token_is_rejected() {
        // The classic JWT `alg: none` attack.
        use base64::Engine;
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = engine.encode(br#"{"alg":"none","typ":"JWT"}"#);
        let payload = engine.encode(
            br#"{"sub":"u1","username":"admin","role":"admin","exp":9999999999,"iat":1}"#,
        );
        let forged = format!("{header}.{payload}.");
        assert!(issuer(3600).verify(&forged).is_err());
    }

    #[test]
    fn throttle_locks_out_after_the_limit() {
        let ip: IpAddr = "198.51.100.5".parse().unwrap();
        let throttle = LoginThrottle::new(3, Duration::from_secs(60));

        throttle.check(ip).unwrap();
        throttle.record_failure(ip);
        throttle.check(ip).unwrap();
        throttle.record_failure(ip);
        throttle.check(ip).unwrap();
        throttle.record_failure(ip);

        // Third failure hits the limit.
        let err = throttle.check(ip).unwrap_err();
        assert!(matches!(err, AuthError::Throttled { .. }), "{err:?}");
    }

    #[test]
    fn throttle_is_per_ip() {
        let a: IpAddr = "198.51.100.5".parse().unwrap();
        let b: IpAddr = "198.51.100.6".parse().unwrap();
        let throttle = LoginThrottle::new(2, Duration::from_secs(60));

        throttle.record_failure(a);
        throttle.record_failure(a);
        assert!(throttle.check(a).is_err());
        // One attacker must not lock out everyone else.
        assert!(throttle.check(b).is_ok());
    }

    #[test]
    fn success_clears_the_counter() {
        let ip: IpAddr = "198.51.100.5".parse().unwrap();
        let throttle = LoginThrottle::new(3, Duration::from_secs(60));
        throttle.record_failure(ip);
        throttle.record_failure(ip);
        throttle.record_success(ip);
        // Counter reset: two more failures must not lock out.
        throttle.record_failure(ip);
        throttle.record_failure(ip);
        assert!(throttle.check(ip).is_ok());
        assert_eq!(throttle.tracked_ips(), 1);
    }

    #[test]
    fn lockout_expires() {
        let ip: IpAddr = "198.51.100.5".parse().unwrap();
        let throttle = LoginThrottle::new(1, Duration::from_millis(80));
        throttle.record_failure(ip);
        assert!(throttle.check(ip).is_err());
        std::thread::sleep(Duration::from_millis(140));
        assert!(throttle.check(ip).is_ok(), "lockout never expired");
    }

    #[test]
    fn prune_bounds_the_map() {
        // Without pruning, a distributed attack grows this map without limit.
        let throttle = LoginThrottle::new(5, Duration::from_millis(50));
        for i in 0..100u8 {
            let ip: IpAddr = format!("198.51.100.{i}").parse().unwrap();
            throttle.record_failure(ip);
        }
        assert_eq!(throttle.tracked_ips(), 100);
        std::thread::sleep(Duration::from_millis(150));
        throttle.prune();
        assert_eq!(throttle.tracked_ips(), 0, "prune did not release records");
    }

    #[test]
    fn prune_keeps_active_lockouts() {
        let ip: IpAddr = "198.51.100.5".parse().unwrap();
        let throttle = LoginThrottle::new(1, Duration::from_secs(300));
        throttle.record_failure(ip);
        throttle.prune();
        assert!(
            throttle.check(ip).is_err(),
            "prune must not release an active lockout"
        );
    }

    #[test]
    fn zero_limit_is_clamped_to_one() {
        // A limit of 0 would otherwise lock out on the first request, before any
        // failure.
        let ip: IpAddr = "198.51.100.5".parse().unwrap();
        let throttle = LoginThrottle::new(0, Duration::from_secs(60));
        assert!(throttle.check(ip).is_ok());
        throttle.record_failure(ip);
        assert!(throttle.check(ip).is_err());
    }
}
