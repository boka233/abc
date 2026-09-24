//! User repository and password hashing.
//!
//! # Password storage
//!
//! Argon2id with the crate's default parameters (19 MiB, 2 iterations, 1 lane at
//! the time of writing). Argon2id rather than Argon2i or Argon2d because it
//! resists both side-channel and GPU-cracking attacks; the memory cost is what
//! makes offline cracking expensive, which bcrypt's tiny working set does not.
//!
//! The stored value is a PHC string carrying algorithm, parameters and salt, so
//! raising the cost later does not invalidate existing hashes — they verify with
//! their own recorded parameters.
//!
//! # Timing
//!
//! [`UserRepo::verify_login`] hashes a dummy password when the username does not
//! exist, so a missing account and a wrong password take comparable time. Without
//! that, response latency enumerates valid usernames.

use argon2::password_hash::{rand_core::OsRng, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Argon2, PasswordHash};
use sqlx::Row;

use crate::db::{new_id, now_string, Database, DbError, Result};
use crate::models::{UserDto, UserRow};

/// Hash used for the dummy verification on the "user not found" path.
/// Generated once; its plaintext is irrelevant.
const DUMMY_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21lc2FsdA$\
                          J0Lq3bRxJ8VYmHhKqOJWLJ0qHZ8sJ9K0cLmNvXpQrSs";

pub struct UserRepo<'a> {
    db: &'a Database,
}

/// Hash a password for storage.
pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| DbError::Other(format!("password hashing failed: {e}")))
}

/// Verify a password against a stored PHC hash.
///
/// A malformed stored hash returns `false` rather than an error: a corrupted row
/// must fail the login, not hand the caller a distinguishable error.
pub fn verify_password(password: &str, hash: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// Minimum acceptable password. Short enough not to annoy, long enough that
/// online guessing is hopeless against a rate-limited login.
pub const MIN_PASSWORD_LEN: usize = 12;

pub fn validate_password(password: &str) -> Result<()> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(DbError::Invalid(format!(
            "password must be at least {MIN_PASSWORD_LEN} characters"
        )));
    }
    if password.len() > 1024 {
        // Argon2 cost scales with input; cap it so a huge body cannot be used
        // as a CPU-exhaustion vector.
        return Err(DbError::Invalid("password is too long".into()));
    }
    Ok(())
}

fn validate_username(username: &str) -> Result<()> {
    let n = username.chars().count();
    if !(3..=64).contains(&n) {
        return Err(DbError::Invalid(
            "username must be between 3 and 64 characters".into(),
        ));
    }
    if !username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return Err(DbError::Invalid(
            "username may contain only letters, digits, '_', '-' and '.'".into(),
        ));
    }
    Ok(())
}

impl<'a> UserRepo<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    pub async fn count(&self) -> Result<i64> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
            .fetch_one(self.db.pool())
            .await?;
        Ok(row.0)
    }

    pub async fn create(
        &self,
        username: &str,
        password: &str,
        role: &str,
        must_change_password: bool,
    ) -> Result<UserDto> {
        validate_username(username)?;
        validate_password(password)?;
        let hash = hash_password(password)?;
        let id = new_id();
        let now = now_string();

        sqlx::query(
            "INSERT INTO users
             (id, username, password_hash, role, must_change_password, disabled, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, 0, ?, ?)",
        )
        .bind(&id)
        .bind(username)
        .bind(&hash)
        .bind(role)
        .bind(i64::from(must_change_password))
        .bind(&now)
        .bind(&now)
        .execute(self.db.pool())
        .await
        .map_err(|e| DbError::from_sqlx_with_context(e, "username"))?;

        self.get(&id).await
    }

    pub async fn get(&self, id: &str) -> Result<UserDto> {
        let row: Option<UserRow> = sqlx::query_as("SELECT * FROM users WHERE id = ?")
            .bind(id)
            .fetch_optional(self.db.pool())
            .await?;
        row.map(UserDto::from)
            .ok_or_else(|| DbError::NotFound(format!("user {id}")))
    }

    pub async fn find_by_username(&self, username: &str) -> Result<Option<UserRow>> {
        let row: Option<UserRow> = sqlx::query_as("SELECT * FROM users WHERE username = ?")
            .bind(username)
            .fetch_optional(self.db.pool())
            .await?;
        Ok(row)
    }

    pub async fn list(&self) -> Result<Vec<UserDto>> {
        let rows: Vec<UserRow> = sqlx::query_as("SELECT * FROM users ORDER BY username")
            .fetch_all(self.db.pool())
            .await?;
        Ok(rows.into_iter().map(UserDto::from).collect())
    }

    /// Authenticate. Returns the user on success, `None` on any failure.
    ///
    /// Constant-ish time across "no such user" and "wrong password": the dummy
    /// verification on the missing-user path keeps the two comparable so login
    /// latency does not enumerate accounts.
    pub async fn verify_login(&self, username: &str, password: &str) -> Result<Option<UserDto>> {
        let Some(row) = self.find_by_username(username).await? else {
            let _ = verify_password(password, DUMMY_HASH);
            return Ok(None);
        };
        if row.disabled != 0 {
            let _ = verify_password(password, &row.password_hash);
            return Ok(None);
        }
        if !verify_password(password, &row.password_hash) {
            return Ok(None);
        }
        let id = row.id.clone();
        sqlx::query("UPDATE users SET last_login_at = ?, updated_at = ? WHERE id = ?")
            .bind(now_string())
            .bind(now_string())
            .bind(&id)
            .execute(self.db.pool())
            .await?;
        Ok(Some(UserDto::from(row)))
    }

    /// Change a password, requiring the current one.
    pub async fn change_password(
        &self,
        id: &str,
        current: &str,
        new_password: &str,
    ) -> Result<()> {
        let row: Option<UserRow> = sqlx::query_as("SELECT * FROM users WHERE id = ?")
            .bind(id)
            .fetch_optional(self.db.pool())
            .await?;
        let row = row.ok_or_else(|| DbError::NotFound(format!("user {id}")))?;

        if !verify_password(current, &row.password_hash) {
            return Err(DbError::Invalid("current password is incorrect".into()));
        }
        validate_password(new_password)?;
        if verify_password(new_password, &row.password_hash) {
            return Err(DbError::Invalid(
                "new password must differ from the current one".into(),
            ));
        }

        let hash = hash_password(new_password)?;
        sqlx::query(
            "UPDATE users
             SET password_hash = ?, must_change_password = 0, updated_at = ?
             WHERE id = ?",
        )
        .bind(hash)
        .bind(now_string())
        .bind(id)
        .execute(self.db.pool())
        .await?;
        Ok(())
    }

    /// Administrative reset: no current password required.
    pub async fn reset_password(&self, id: &str, new_password: &str) -> Result<()> {
        validate_password(new_password)?;
        let hash = hash_password(new_password)?;
        let result = sqlx::query(
            "UPDATE users
             SET password_hash = ?, must_change_password = 1, updated_at = ?
             WHERE id = ?",
        )
        .bind(hash)
        .bind(now_string())
        .bind(id)
        .execute(self.db.pool())
        .await?;
        if result.rows_affected() == 0 {
            return Err(DbError::NotFound(format!("user {id}")));
        }
        Ok(())
    }

    pub async fn set_disabled(&self, id: &str, disabled: bool) -> Result<()> {
        // Refuse to disable the last enabled admin: locking everyone out of the
        // panel has no recovery path short of editing the database by hand.
        if disabled {
            let remaining: (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM users WHERE disabled = 0 AND role = 'admin' AND id <> ?",
            )
            .bind(id)
            .fetch_one(self.db.pool())
            .await?;
            if remaining.0 == 0 {
                return Err(DbError::Invalid(
                    "cannot disable the last enabled administrator".into(),
                ));
            }
        }
        let result = sqlx::query("UPDATE users SET disabled = ?, updated_at = ? WHERE id = ?")
            .bind(i64::from(disabled))
            .bind(now_string())
            .bind(id)
            .execute(self.db.pool())
            .await?;
        if result.rows_affected() == 0 {
            return Err(DbError::NotFound(format!("user {id}")));
        }
        Ok(())
    }

    pub async fn delete(&self, id: &str) -> Result<()> {
        let remaining: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM users WHERE role = 'admin' AND id <> ?")
                .bind(id)
                .fetch_one(self.db.pool())
                .await?;
        if remaining.0 == 0 {
            return Err(DbError::Invalid(
                "cannot delete the last administrator".into(),
            ));
        }
        let result = sqlx::query("DELETE FROM users WHERE id = ?")
            .bind(id)
            .execute(self.db.pool())
            .await?;
        if result.rows_affected() == 0 {
            return Err(DbError::NotFound(format!("user {id}")));
        }
        Ok(())
    }

    /// Create the initial admin if no users exist.
    ///
    /// Returns the generated password when it created an account, so the caller
    /// can print it once. Nothing is logged from inside this function.
    pub async fn ensure_bootstrap_admin(&self, username: &str) -> Result<Option<String>> {
        if self.count().await? > 0 {
            return Ok(None);
        }
        let password = generate_password(24);
        self.create(username, &password, "admin", true).await?;
        Ok(Some(password))
    }

    /// Does this user still need to rotate their bootstrap password?
    pub async fn must_change_password(&self, id: &str) -> Result<bool> {
        let row = sqlx::query("SELECT must_change_password FROM users WHERE id = ?")
            .bind(id)
            .fetch_optional(self.db.pool())
            .await?;
        match row {
            Some(r) => Ok(r.get::<i64, _>(0) != 0),
            None => Err(DbError::NotFound(format!("user {id}"))),
        }
    }
}

/// Random password from an unambiguous alphabet (no 0/O, 1/l/I).
pub fn generate_password(len: usize) -> String {
    use rand::Rng;
    const ALPHABET: &[u8] = b"abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut rng = rand::thread_rng();
    (0..len.max(MIN_PASSWORD_LEN))
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn db() -> Database {
        Database::connect_in_memory().await.unwrap()
    }

    #[test]
    fn hash_then_verify() {
        let hash = hash_password("correct horse battery").unwrap();
        assert!(verify_password("correct horse battery", &hash));
        assert!(!verify_password("wrong horse battery", &hash));
    }

    #[test]
    fn hash_is_argon2id_and_salted() {
        let a = hash_password("same-password-here").unwrap();
        let b = hash_password("same-password-here").unwrap();
        assert!(a.starts_with("$argon2id$"), "expected Argon2id, got {a}");
        assert_ne!(a, b, "identical passwords must produce different hashes");
        // Both must still verify: the salt lives in the PHC string.
        assert!(verify_password("same-password-here", &a));
        assert!(verify_password("same-password-here", &b));
    }

    #[test]
    fn plaintext_never_appears_in_the_hash() {
        let hash = hash_password("hunter2-hunter2-hunter2").unwrap();
        assert!(!hash.contains("hunter2"));
    }

    #[test]
    fn malformed_stored_hash_fails_closed() {
        assert!(!verify_password("anything", "not-a-phc-string"));
        assert!(!verify_password("anything", ""));
        assert!(!verify_password("anything", "$argon2id$broken"));
    }

    #[test]
    fn dummy_hash_is_parseable() {
        // The timing-equalisation path depends on this actually running Argon2
        // rather than short-circuiting on a parse error.
        assert!(
            PasswordHash::new(DUMMY_HASH).is_ok(),
            "DUMMY_HASH must parse or the timing defence does nothing"
        );
    }

    #[test]
    fn password_policy() {
        assert!(validate_password("short").is_err());
        assert!(validate_password("exactly12chr").is_ok());
        assert!(validate_password(&"x".repeat(2000)).is_err());
    }

    #[test]
    fn username_policy() {
        assert!(validate_username("ab").is_err());
        assert!(validate_username("admin").is_ok());
        assert!(validate_username("ops.team_1-a").is_ok());
        assert!(validate_username("bad name").is_err());
        assert!(validate_username("drop;table").is_err());
        assert!(validate_username(&"x".repeat(100)).is_err());
    }

    #[test]
    fn generated_passwords_are_long_and_unique() {
        let a = generate_password(24);
        let b = generate_password(24);
        assert_eq!(a.len(), 24);
        assert_ne!(a, b);
        // Ambiguous characters are excluded so an operator can retype it.
        assert!(!a.contains('0') && !a.contains('O'));
        assert!(!a.contains('1') && !a.contains('l') && !a.contains('I'));
        // A too-short request is raised to the policy minimum.
        assert!(generate_password(4).len() >= MIN_PASSWORD_LEN);
    }

    #[tokio::test]
    async fn create_and_login() {
        let db = db().await;
        let repo = UserRepo::new(&db);
        let user = repo
            .create("admin", "initial-password-1", "admin", true)
            .await
            .unwrap();
        assert_eq!(user.username, "admin");
        assert!(user.must_change_password);

        let logged_in = repo
            .verify_login("admin", "initial-password-1")
            .await
            .unwrap();
        assert!(logged_in.is_some());
        assert!(repo.verify_login("admin", "wrong").await.unwrap().is_none());
        assert!(repo.verify_login("nobody", "x").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn login_records_the_timestamp() {
        let db = db().await;
        let repo = UserRepo::new(&db);
        let user = repo
            .create("admin", "initial-password-1", "admin", false)
            .await
            .unwrap();
        assert!(user.last_login_at.is_none());
        repo.verify_login("admin", "initial-password-1")
            .await
            .unwrap();
        assert!(repo.get(&user.id).await.unwrap().last_login_at.is_some());
    }

    #[tokio::test]
    async fn duplicate_username_is_a_conflict() {
        let db = db().await;
        let repo = UserRepo::new(&db);
        repo.create("admin", "initial-password-1", "admin", false)
            .await
            .unwrap();
        let err = repo
            .create("admin", "another-password-1", "admin", false)
            .await
            .unwrap_err();
        assert!(matches!(err, DbError::Conflict(_)), "{err:?}");
    }

    #[tokio::test]
    async fn weak_password_is_rejected_at_creation() {
        let db = db().await;
        let repo = UserRepo::new(&db);
        assert!(matches!(
            repo.create("admin", "short", "admin", false).await,
            Err(DbError::Invalid(_))
        ));
        assert_eq!(repo.count().await.unwrap(), 0, "no row should be written");
    }

    #[tokio::test]
    async fn change_password_requires_the_current_one() {
        let db = db().await;
        let repo = UserRepo::new(&db);
        let user = repo
            .create("admin", "initial-password-1", "admin", true)
            .await
            .unwrap();

        assert!(repo
            .change_password(&user.id, "wrong-current", "new-password-12")
            .await
            .is_err());
        repo.change_password(&user.id, "initial-password-1", "new-password-12")
            .await
            .unwrap();

        // Old password no longer works; the new one does.
        assert!(repo
            .verify_login("admin", "initial-password-1")
            .await
            .unwrap()
            .is_none());
        assert!(repo
            .verify_login("admin", "new-password-12")
            .await
            .unwrap()
            .is_some());
        // The forced-rotation flag clears once the password is changed.
        assert!(!repo.must_change_password(&user.id).await.unwrap());
    }

    #[tokio::test]
    async fn changing_to_the_same_password_is_refused() {
        let db = db().await;
        let repo = UserRepo::new(&db);
        let user = repo
            .create("admin", "initial-password-1", "admin", false)
            .await
            .unwrap();
        assert!(repo
            .change_password(&user.id, "initial-password-1", "initial-password-1")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn admin_reset_forces_a_rotation() {
        let db = db().await;
        let repo = UserRepo::new(&db);
        let user = repo
            .create("operator", "initial-password-1", "admin", false)
            .await
            .unwrap();
        repo.reset_password(&user.id, "reset-password-99").await.unwrap();
        assert!(repo.must_change_password(&user.id).await.unwrap());
        assert!(repo
            .verify_login("operator", "reset-password-99")
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn disabled_user_cannot_log_in() {
        let db = db().await;
        let repo = UserRepo::new(&db);
        repo.create("admin", "keep-this-account-1", "admin", false)
            .await
            .unwrap();
        let second = repo
            .create("operator", "initial-password-1", "admin", false)
            .await
            .unwrap();

        repo.set_disabled(&second.id, true).await.unwrap();
        assert!(repo
            .verify_login("operator", "initial-password-1")
            .await
            .unwrap()
            .is_none());

        repo.set_disabled(&second.id, false).await.unwrap();
        assert!(repo
            .verify_login("operator", "initial-password-1")
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn last_admin_cannot_be_disabled_or_deleted() {
        // Otherwise the panel becomes unreachable with no in-product recovery.
        let db = db().await;
        let repo = UserRepo::new(&db);
        let only = repo
            .create("admin", "initial-password-1", "admin", false)
            .await
            .unwrap();

        assert!(repo.set_disabled(&only.id, true).await.is_err());
        assert!(repo.delete(&only.id).await.is_err());

        // With a second admin present, both operations are allowed.
        let second = repo
            .create("admin2", "initial-password-2", "admin", false)
            .await
            .unwrap();
        repo.set_disabled(&second.id, true).await.unwrap();
        repo.delete(&second.id).await.unwrap();
        assert_eq!(repo.count().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn bootstrap_admin_is_created_once() {
        let db = db().await;
        let repo = UserRepo::new(&db);

        let password = repo.ensure_bootstrap_admin("admin").await.unwrap();
        let password = password.expect("first call should create an admin");
        assert!(password.len() >= MIN_PASSWORD_LEN);
        assert!(repo.verify_login("admin", &password).await.unwrap().is_some());

        // Second call must be a no-op, not a password reset.
        assert!(repo.ensure_bootstrap_admin("admin").await.unwrap().is_none());
        assert_eq!(repo.count().await.unwrap(), 1);
        assert!(
            repo.verify_login("admin", &password).await.unwrap().is_some(),
            "existing credentials must survive a restart"
        );
    }

    #[tokio::test]
    async fn bootstrap_admin_must_rotate_its_password() {
        let db = db().await;
        let repo = UserRepo::new(&db);
        repo.ensure_bootstrap_admin("admin").await.unwrap();
        let users = repo.list().await.unwrap();
        assert!(users[0].must_change_password);
    }

    #[tokio::test]
    async fn operations_on_a_missing_user_report_not_found() {
        let db = db().await;
        let repo = UserRepo::new(&db);
        // Keep an admin around so the last-admin guard is not what fires.
        repo.create("admin", "initial-password-1", "admin", false)
            .await
            .unwrap();

        assert!(matches!(
            repo.get("nope").await,
            Err(DbError::NotFound(_))
        ));
        assert!(matches!(
            repo.reset_password("nope", "new-password-12").await,
            Err(DbError::NotFound(_))
        ));
        assert!(matches!(
            repo.set_disabled("nope", true).await,
            Err(DbError::NotFound(_))
        ));
    }
}
