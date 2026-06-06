use axum::http::{HeaderMap, header};

use crate::config::Config;

pub fn validate_ws_origin(headers: &HeaderMap, config: &Config) -> bool {
    if !config.security.websocket_origin_check {
        return true;
    }

    let Some(origin) = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };

    if config
        .security
        .allowed_origins
        .iter()
        .any(|item| item == origin)
    {
        return true;
    }

    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    origin == format!("http://{host}") || origin == format!("https://{host}")
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    #[test]
    fn rejects_missing_origin() {
        assert!(!validate_ws_origin(&HeaderMap::new(), &Config::default()));
    }

    #[test]
    fn accepts_same_host_origin() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("nanokvm.local"));
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("http://nanokvm.local"),
        );
        assert!(validate_ws_origin(&headers, &Config::default()));
    }
}
