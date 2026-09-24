//! HTTP error mapping.
//!
//! Every handler returns [`ApiError`], which decides the status code and the
//! body. Two rules drive the mapping:
//!
//! 1. **Storage errors map to meaningful codes.** A duplicate route name is a
//!    409, not a 500, so the panel can show "that name is taken".
//! 2. **Internal detail never reaches the client.** Database and I/O errors are
//!    logged in full and returned as a generic message; an SQL error string in a
//!    browser response is an information leak.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

use crate::auth::AuthError;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{0}")]
    BadRequest(String),
    #[error("authentication required")]
    Unauthorized,
    #[error("{0}")]
    Forbidden(String),
    #[error("{0} not found")]
    NotFound(String),
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    Throttled(String),
    /// Anything unexpected. The message is logged, not returned.
    #[error("internal error")]
    Internal(String),
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
    /// Stable machine-readable code so the frontend can branch without parsing
    /// prose.
    code: &'static str,
}

impl ApiError {
    fn parts(&self) -> (StatusCode, &'static str) {
        match self {
            ApiError::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            ApiError::Forbidden(_) => (StatusCode::FORBIDDEN, "forbidden"),
            ApiError::NotFound(_) => (StatusCode::NOT_FOUND, "not_found"),
            ApiError::Conflict(_) => (StatusCode::CONFLICT, "conflict"),
            ApiError::Throttled(_) => (StatusCode::TOO_MANY_REQUESTS, "throttled"),
            ApiError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        }
    }

    pub fn internal(msg: impl Into<String>) -> Self {
        ApiError::Internal(msg.into())
    }

    pub fn bad_request(msg: impl Into<String>) -> Self {
        ApiError::BadRequest(msg.into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = self.parts();
        let message = match &self {
            // Log the detail, return a generic message.
            ApiError::Internal(detail) => {
                tracing::error!(error = %detail, "request failed");
                "internal server error".to_string()
            }
            other => other.to_string(),
        };
        (status, Json(ErrorBody { error: message, code })).into_response()
    }
}

impl From<tunnel_storage::DbError> for ApiError {
    fn from(e: tunnel_storage::DbError) -> Self {
        use tunnel_storage::DbError;
        match e {
            DbError::NotFound(what) => ApiError::NotFound(what),
            DbError::Conflict(msg) => ApiError::Conflict(msg),
            DbError::Invalid(msg) => ApiError::BadRequest(msg),
            // Raw SQL errors must not reach the client.
            DbError::Sqlx(inner) => ApiError::Internal(format!("database: {inner}")),
            DbError::Migrate(inner) => ApiError::Internal(format!("migration: {inner}")),
            DbError::Other(msg) => ApiError::Internal(msg),
        }
    }
}

impl From<AuthError> for ApiError {
    fn from(e: AuthError) -> Self {
        match e {
            AuthError::InvalidCredentials => ApiError::Unauthorized,
            AuthError::Expired | AuthError::InvalidToken => ApiError::Unauthorized,
            AuthError::Disabled => ApiError::Forbidden("account is disabled".into()),
            AuthError::PasswordChangeRequired => {
                ApiError::Forbidden("password change required".into())
            }
            AuthError::Throttled { retry_after_secs } => ApiError::Throttled(format!(
                "too many attempts; try again in {retry_after_secs}s"
            )),
        }
    }
}

impl From<tunnel_common::Error> for ApiError {
    fn from(e: tunnel_common::Error) -> Self {
        use tunnel_common::Error;
        match e {
            Error::Config(msg) => ApiError::BadRequest(msg),
            Error::NotFound(what) => ApiError::NotFound(what),
            other => ApiError::Internal(other.to_string()),
        }
    }
}

pub type ApiResult<T> = std::result::Result<T, ApiError>;

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use tunnel_storage::DbError;

    async fn body_of(err: ApiError) -> (StatusCode, serde_json::Value) {
        let response = err.into_response();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    #[tokio::test]
    async fn status_codes_are_mapped_per_variant() {
        let cases = vec![
            (ApiError::BadRequest("x".into()), StatusCode::BAD_REQUEST),
            (ApiError::Unauthorized, StatusCode::UNAUTHORIZED),
            (ApiError::Forbidden("x".into()), StatusCode::FORBIDDEN),
            (ApiError::NotFound("route".into()), StatusCode::NOT_FOUND),
            (ApiError::Conflict("x".into()), StatusCode::CONFLICT),
            (ApiError::Throttled("x".into()), StatusCode::TOO_MANY_REQUESTS),
            (
                ApiError::Internal("x".into()),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        ];
        for (err, expected) in cases {
            let (status, _) = body_of(err).await;
            assert_eq!(status, expected);
        }
    }

    #[tokio::test]
    async fn internal_errors_do_not_leak_detail() {
        // The scenario: a malformed query reaches the client as a generic 500
        // rather than an SQL fragment naming tables and columns.
        let err = ApiError::Internal(
            "database: no such column: secret_token in table users".into(),
        );
        let (status, body) = body_of(err).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        let message = body["error"].as_str().unwrap();
        assert_eq!(message, "internal server error");
        assert!(!message.contains("secret_token"));
        assert!(!message.contains("users"));
    }

    #[tokio::test]
    async fn client_errors_keep_their_message() {
        let (_, body) = body_of(ApiError::Conflict("route name already exists".into())).await;
        assert_eq!(body["error"], "route name already exists");
        assert_eq!(body["code"], "conflict");
    }

    #[tokio::test]
    async fn every_response_carries_a_machine_readable_code() {
        let (_, body) = body_of(ApiError::Unauthorized).await;
        assert_eq!(body["code"], "unauthorized");
        assert!(body["error"].is_string());
    }

    #[test]
    fn storage_conflicts_become_409_not_500() {
        // The important mapping: a duplicate name is user error, not a server bug.
        let err: ApiError = DbError::Conflict("route name already exists".into()).into();
        assert!(matches!(err, ApiError::Conflict(_)));
        assert_eq!(err.parts().0, StatusCode::CONFLICT);
    }

    #[test]
    fn storage_validation_becomes_400() {
        let err: ApiError = DbError::Invalid("port must be 1-65535".into()).into();
        assert_eq!(err.parts().0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn storage_not_found_becomes_404() {
        let err: ApiError = DbError::NotFound("route r1".into()).into();
        assert_eq!(err.parts().0, StatusCode::NOT_FOUND);
    }

    #[test]
    fn auth_failures_map_without_distinguishing_cause() {
        // A caller must not be able to tell "no such user" from "wrong password"
        // or "expired token" by status code.
        for e in [
            AuthError::InvalidCredentials,
            AuthError::Expired,
            AuthError::InvalidToken,
        ] {
            let err: ApiError = e.into();
            assert_eq!(err.parts().0, StatusCode::UNAUTHORIZED);
        }
    }

    #[test]
    fn throttling_maps_to_429_with_a_retry_hint() {
        let err: ApiError = AuthError::Throttled {
            retry_after_secs: 42,
        }
        .into();
        assert_eq!(err.parts().0, StatusCode::TOO_MANY_REQUESTS);
        assert!(err.to_string().contains("42"));
    }

    #[test]
    fn common_config_errors_are_client_errors() {
        // A bad bundle is the operator's configuration mistake, so 400.
        let err: ApiError = tunnel_common::Error::config("pool size too large").into();
        assert_eq!(err.parts().0, StatusCode::BAD_REQUEST);
    }
}
