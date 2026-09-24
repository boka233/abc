//! WebSocket telemetry stream.
//!
//! # Why incremental push instead of polling
//!
//! The dashboard needs second-resolution graphs. Polling a REST endpoint every
//! second means re-serialising the whole fleet state every second per open tab,
//! and it still lags. Pushing each node's report as it arrives sends the same
//! information once, when it changes.
//!
//! # Backpressure
//!
//! The broadcast channel is bounded. A tab that stops reading (backgrounded,
//! throttled by the browser, on a bad connection) falls behind and is dropped
//! from the stream with a `lagged` notice rather than being waited for. A stalled
//! browser must never slow the telemetry path for anyone else.
//!
//! # Authentication
//!
//! The browser WebSocket API cannot set an `Authorization` header, so the token
//! arrives as a query parameter. It is verified *before* the upgrade, so an
//! unauthenticated socket is never established.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::Response;
use serde::Deserialize;
use tokio::sync::broadcast::error::RecvError;

use crate::api::error::ApiError;
use crate::state::{AppState, Event};

#[derive(Deserialize)]
pub struct WsQuery {
    /// Session token. Query rather than header, because the browser WebSocket
    /// API offers no way to set headers.
    pub token: Option<String>,
}

/// Authenticated WebSocket caller.
///
/// This is an *extractor* rather than a check in the handler body on purpose.
/// Axum runs every extractor before the handler runs, so a check written in the
/// body would happen after `WebSocketUpgrade` had already rejected an
/// unauthenticated request with 400 for missing upgrade headers. Making auth an
/// extractor and declaring it first means an anonymous request is refused as 401
/// on its own merits, regardless of what headers it did or did not send.
pub struct WsAuth {
    username: String,
}

impl axum::extract::FromRequestParts<Arc<AppState>> for WsAuth {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let token = crate::api::middleware::query_token(parts.uri.query())
            .ok_or(ApiError::Unauthorized)?;
        let claims = state.tokens.verify(&token)?;

        // Re-check the account, same as the REST extractor, so a disabled user's
        // open tab stops receiving telemetry.
        let user = tunnel_storage::users::UserRepo::new(&state.db)
            .find_by_username(&claims.username)
            .await?
            .ok_or(ApiError::Unauthorized)?;
        if user.disabled != 0 {
            return Err(ApiError::Forbidden("account is disabled".into()));
        }

        Ok(WsAuth {
            username: claims.username,
        })
    }
}

pub async fn ws_handler(
    State(state): State<Arc<AppState>>,
    auth: WsAuth,
    ws: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    Ok(ws.on_upgrade(move |socket| handle_socket(socket, state, auth.username)))
}

/// Interval for the fleet summary push. Fast enough to feel live, slow enough
/// that it is not doing real work on every frame.
const SUMMARY_INTERVAL: Duration = Duration::from_secs(2);

/// Ping interval, to detect a browser that vanished without closing.
const PING_INTERVAL: Duration = Duration::from_secs(30);

async fn handle_socket(mut socket: WebSocket, state: Arc<AppState>, username: String) {
    tracing::debug!(user = %username, "telemetry socket opened");

    let mut events = state.subscribe();
    let mut summary_timer = tokio::time::interval(SUMMARY_INTERVAL);
    let mut ping_timer = tokio::time::interval(PING_INTERVAL);
    summary_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    ping_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // Send an immediate summary so a fresh tab is not blank until the first tick.
    let stale = Duration::from_secs(state.config().agent.stale_after_secs);
    if send_event(&mut socket, &Event::Summary(Box::new(state.summary(stale)))).await.is_err() {
        return;
    }

    loop {
        tokio::select! {
            received = events.recv() => {
                match received {
                    Ok(event) => {
                        if send_event(&mut socket, &event).await.is_err() {
                            break;
                        }
                    }
                    Err(RecvError::Lagged(skipped)) => {
                        // This client fell behind. Tell it so it can refetch
                        // rather than silently showing stale data.
                        tracing::debug!(
                            user = %username,
                            skipped,
                            "telemetry client lagged; it will resync from the next summary"
                        );
                        let notice = serde_json::json!({
                            "type": "lagged",
                            "skipped": skipped,
                        });
                        if socket
                            .send(Message::Text(notice.to_string().into()))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(RecvError::Closed) => break,
                }
            }

            _ = summary_timer.tick() => {
                let stale = Duration::from_secs(state.config().agent.stale_after_secs);
                let event = Event::Summary(Box::new(state.summary(stale)));
                if send_event(&mut socket, &event).await.is_err() {
                    break;
                }
            }

            _ = ping_timer.tick() => {
                // A half-open socket otherwise lingers until the OS notices.
                if socket.send(Message::Ping(Vec::new().into())).await.is_err() {
                    break;
                }
            }

            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(_)) => break,
                    // The client has nothing to say; Pong and stray frames are
                    // ignored rather than parsed. A read-only telemetry socket
                    // accepting commands would be an unnecessary attack surface.
                    Some(Ok(_)) => {}
                }
            }
        }
    }

    tracing::debug!(user = %username, "telemetry socket closed");
}

async fn send_event(socket: &mut WebSocket, event: &Event) -> Result<(), ()> {
    let text = match serde_json::to_string(event) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "could not serialise telemetry event");
            return Ok(());
        }
    };
    socket
        .send(Message::Text(text.into()))
        .await
        .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ControlConfig;
    use tunnel_storage::Database;

    async fn state() -> Arc<AppState> {
        let db = Database::connect_in_memory().await.unwrap();
        let mut cfg = ControlConfig::default();
        cfg.ensure_jwt_secret();
        AppState::new(db, cfg)
    }

    #[tokio::test]
    async fn upgrade_without_a_token_is_unauthorized() {
        // Asserted at the verification layer rather than through a real upgrade,
        // because constructing a WebSocketUpgrade needs a live connection.
        let state = state().await;
        assert!(state.tokens.verify("").is_err());
    }

    #[tokio::test]
    async fn a_valid_token_verifies_before_upgrade() {
        let state = state().await;
        let token = state.tokens.issue("u1", "admin", "admin").unwrap();
        let claims = state.tokens.verify(&token).unwrap();
        assert_eq!(claims.username, "admin");
    }

    #[tokio::test]
    async fn a_token_signed_elsewhere_is_refused() {
        let state = state().await;
        let other = crate::auth::TokenIssuer::new(
            &tunnel_common::Secret::new("some-other-signing-secret-value"),
            Duration::from_secs(3600),
        );
        let forged = other.issue("u1", "admin", "admin").unwrap();
        assert!(state.tokens.verify(&forged).is_err());
    }

    #[test]
    fn events_serialise_with_a_discriminating_tag() {
        // The frontend switches on `type`; every variant must carry one.
        let cases = vec![
            (
                serde_json::to_string(&Event::ConfigChanged {
                    entity: "routes".into(),
                })
                .unwrap(),
                "config_changed",
            ),
            (
                serde_json::to_string(&Event::Summary(Box::default())).unwrap(),
                "summary",
            ),
            (
                serde_json::to_string(&Event::NodeOffline {
                    node_id: "n1".into(),
                    node_name: "sh-01".into(),
                })
                .unwrap(),
                "node_offline",
            ),
        ];
        for (json, expected_tag) in cases {
            assert!(
                json.contains(&format!("\"type\":\"{expected_tag}\"")),
                "missing tag {expected_tag} in {json}"
            );
        }
    }

    #[test]
    fn lag_notice_is_valid_json_the_client_can_branch_on() {
        let notice = serde_json::json!({ "type": "lagged", "skipped": 12u64 });
        let text = notice.to_string();
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed["type"], "lagged");
        assert_eq!(parsed["skipped"], 12);
    }

    #[tokio::test]
    async fn intervals_are_sane() {
        // A summary faster than the agent heartbeat would push duplicate data;
        // much slower would make the dashboard feel dead.
        assert!(SUMMARY_INTERVAL >= Duration::from_secs(1));
        assert!(SUMMARY_INTERVAL <= Duration::from_secs(10));
        assert!(PING_INTERVAL > SUMMARY_INTERVAL);
    }
}
