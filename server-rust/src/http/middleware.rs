use axum::{
    body::Body,
    extract::State,
    extract::connect_info::ConnectInfo,
    http::{HeaderMap, Method, Request, Uri, header},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::{
    AppError, auth::session::Session, config::Config, http::tls::ClientAddr, state::AppState,
};

#[derive(Debug, Clone)]
pub struct CurrentSession(pub Session);

/// Refusal message for an unenrolled session while `security.require_totp` is
/// on. The frontend matches on it to redirect to enrolment.
pub const ENROLMENT_REQUIRED: &str = "two-factor enrolment required";

pub async fn protected(
    State(state): State<AppState>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    if state.config.auth_disabled() {
        return next.run(req).await;
    }

    let Some(token) = bearer_or_cookie(req.headers()) else {
        return AppError::Unauthorized.into_response();
    };

    let Some(session) = state.sessions.validate(&token).await else {
        return AppError::Unauthorized.into_response();
    };

    if state.config.security.require_csrf && is_state_changing(req.method()) {
        let csrf_header = req
            .headers()
            .get("x-csrf-token")
            .and_then(|value| value.to_str().ok());
        if csrf_header != Some(session.csrf_token.as_str()) {
            return AppError::Forbidden("missing or invalid CSRF token".to_string())
                .into_response();
        }
        if !validate_http_origin(req.headers(), &state.config) {
            return AppError::Forbidden("invalid request origin".to_string()).into_response();
        }
    }

    if enrolment_required(&state, &session.username)
        && !allowed_while_unenrolled(req.method(), req.uri().path())
    {
        return AppError::Forbidden(ENROLMENT_REQUIRED.to_string()).into_response();
    }

    req.extensions_mut().insert(CurrentSession(session));
    next.run(req).await
}

/// Evaluated per request, so enrolling or clearing the policy applies at once.
/// An unreadable account file counts as unenrolled: the policy fails closed.
fn enrolment_required(state: &AppState, username: &str) -> bool {
    state.require_totp() && !state.accounts.totp_enabled(username).unwrap_or(false)
}

/// Enough to enrol, and to leave. Deliberately excludes the policy toggle.
fn allowed_while_unenrolled(method: &Method, path: &str) -> bool {
    matches!(
        (method, path),
        (&Method::GET, "/api/auth/account")
            | (&Method::GET, "/api/auth/totp")
            | (&Method::POST, "/api/auth/totp/enroll")
            | (&Method::POST, "/api/auth/totp/confirm")
            | (&Method::POST, "/api/auth/logout")
    )
}

pub async fn picoclaw_internal(req: Request<Body>, next: Next) -> Response {
    let remote = req
        .extensions()
        .get::<ConnectInfo<ClientAddr>>()
        .map(|ConnectInfo(ClientAddr(addr))| *addr);
    if crate::api::picoclaw::has_valid_loopback_internal_token(req.headers(), remote) {
        return next.run(req).await;
    }
    AppError::Unauthorized.into_response()
}

fn is_state_changing(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

fn validate_http_origin(headers: &HeaderMap, config: &Config) -> bool {
    if let Some(origin) = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    {
        return is_allowed_origin(origin, headers, config);
    }

    if let Some(referer) = headers
        .get(header::REFERER)
        .and_then(|value| value.to_str().ok())
    {
        let Some(origin) = normalize_origin(referer) else {
            return false;
        };
        return is_allowed_origin(&origin, headers, config);
    }

    true
}

fn is_allowed_origin(origin: &str, headers: &HeaderMap, config: &Config) -> bool {
    let Some(origin) = normalize_origin(origin) else {
        return false;
    };
    if config
        .security
        .allowed_origins
        .iter()
        .filter_map(|item| normalize_origin(item))
        .any(|item| item == origin)
    {
        return true;
    }

    let Some(host) = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    origin == format!("http://{host}") || origin == format!("https://{host}")
}

fn normalize_origin(value: &str) -> Option<String> {
    let uri = value.parse::<Uri>().ok()?;
    let scheme = uri.scheme_str()?;
    let authority = uri.authority()?.as_str();
    Some(format!("{scheme}://{authority}"))
}

fn bearer_or_cookie(headers: &HeaderMap) -> Option<String> {
    if let Some(auth) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if let Some(token) = auth.strip_prefix("Bearer ") {
            return Some(token.to_string());
        }
    }

    let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
    for item in cookie.split(';') {
        let item = item.trim();
        if let Some(token) = item.strip_prefix("nano-kvm-token=") {
            return Some(token.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    #[test]
    fn validates_same_host_origin() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("kvm.local"));
        headers.insert(header::ORIGIN, HeaderValue::from_static("http://kvm.local"));

        assert!(validate_http_origin(&headers, &Config::default()));
    }

    #[test]
    fn rejects_cross_host_origin() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("kvm.local"));
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("http://evil.local"),
        );

        assert!(!validate_http_origin(&headers, &Config::default()));
    }

    #[test]
    fn validates_same_host_referer() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("kvm.local"));
        headers.insert(
            header::REFERER,
            HeaderValue::from_static("https://kvm.local/settings"),
        );

        assert!(validate_http_origin(&headers, &Config::default()));
    }

    #[test]
    fn allows_non_browser_requests_without_origin_headers() {
        assert!(validate_http_origin(&HeaderMap::new(), &Config::default()));
    }

    #[test]
    fn unenrolled_whitelist_excludes_anything_that_weakens_the_policy() {
        for (method, path) in [
            (Method::POST, "/api/auth/totp/required"),
            (Method::DELETE, "/api/auth/totp"),
            (Method::POST, "/api/auth/totp/backup-codes"),
            (Method::POST, "/api/auth/password"),
            (Method::GET, "/api/ws"),
            (Method::HEAD, "/api/auth/totp"),
        ] {
            assert!(!allowed_while_unenrolled(&method, path), "{method} {path}");
        }
    }

    mod enrolment_gate {
        use axum::{
            body::{Body, to_bytes},
            http::{HeaderValue, StatusCode},
        };
        use tower::ServiceExt;

        use super::*;
        use crate::{auth::password::TotpConfig, http::routes};

        async fn state() -> (tempfile::TempDir, AppState, Session) {
            let dir = tempfile::tempdir().unwrap();
            let mut config = Config::default();
            config.paths.account_file = dir.path().canonicalize().unwrap().join("pwd");
            let state = AppState::new(config).await.unwrap();
            state
                .accounts
                .set_account("operator", "correct horse battery")
                .unwrap();
            let session = state.sessions.issue("operator", 900).await;
            (dir, state, session)
        }

        fn enrol(state: &AppState) {
            let totp = TotpConfig {
                secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string(),
                backup_codes: vec![],
                enrolled_at: 0,
            };
            state.accounts.set_totp("operator", totp).unwrap();
        }

        async fn call(
            state: &AppState,
            session: &Session,
            method: Method,
            path: &str,
            body: &'static str,
        ) -> (StatusCode, String) {
            let req = Request::builder()
                .method(method)
                .uri(path)
                .header(header::AUTHORIZATION, format!("Bearer {}", session.token))
                .header(
                    "x-csrf-token",
                    HeaderValue::from_str(&session.csrf_token).unwrap(),
                )
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap();
            let rsp = routes::build(state.clone()).oneshot(req).await.unwrap();
            let status = rsp.status();
            let bytes = to_bytes(rsp.into_body(), usize::MAX).await.unwrap();
            (status, String::from_utf8_lossy(&bytes).into_owned())
        }

        fn gated((status, body): &(StatusCode, String)) -> bool {
            *status == StatusCode::FORBIDDEN && body.contains(ENROLMENT_REQUIRED)
        }

        #[tokio::test]
        async fn unenrolled_session_is_confined_while_the_policy_is_on() {
            let (_dir, state, session) = state().await;
            state.set_require_totp(true);

            let other = call(&state, &session, Method::GET, "/api/vm/session-lock", "").await;
            assert!(gated(&other), "{other:?}");

            for path in ["/api/auth/totp", "/api/auth/account"] {
                let allowed = call(&state, &session, Method::GET, path, "").await;
                assert!(!gated(&allowed), "{path}: {allowed:?}");
            }
        }

        #[tokio::test]
        async fn confined_session_cannot_switch_the_policy_off() {
            let (_dir, state, session) = state().await;
            state.set_require_totp(true);

            let body = r#"{"required": false}"#;
            let rsp = call(
                &state,
                &session,
                Method::POST,
                "/api/auth/totp/required",
                body,
            )
            .await;

            assert!(gated(&rsp), "{rsp:?}");
            assert!(state.require_totp(), "policy must still be on");
        }

        #[tokio::test]
        async fn enrolling_lifts_the_restriction_for_the_same_session() {
            let (_dir, state, session) = state().await;
            state.set_require_totp(true);
            let path = "/api/vm/session-lock";
            assert!(gated(&call(&state, &session, Method::GET, path, "").await));

            enrol(&state);

            let rsp = call(&state, &session, Method::GET, path, "").await;
            assert_eq!(rsp.0, StatusCode::OK, "{rsp:?}");
        }

        #[tokio::test]
        async fn unenrolled_accounts_are_unrestricted_without_the_policy() {
            let (_dir, state, session) = state().await;

            let rsp = call(&state, &session, Method::GET, "/api/vm/session-lock", "").await;

            assert_eq!(rsp.0, StatusCode::OK, "{rsp:?}");
        }
    }
}
