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

    req.extensions_mut().insert(CurrentSession(session));
    next.run(req).await
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
}
