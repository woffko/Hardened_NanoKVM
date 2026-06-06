use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Method, Request, header},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::{AppError, auth::session::Session, state::AppState};

#[derive(Debug, Clone)]
pub struct CurrentSession(pub Session);

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
    }

    req.extensions_mut().insert(CurrentSession(session));
    next.run(req).await
}

fn is_state_changing(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
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
