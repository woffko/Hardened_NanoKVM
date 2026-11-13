use axum::{
    body::Body,
    http::{HeaderValue, Request, header},
    middleware::Next,
    response::Response,
};

/// The policy for a request whose host cannot be named: same origin only.
const STRICT_POLICY: &str = "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

/// The page's policy. Keyboard, mouse, video and terminal all run over
/// WebSockets of this host. Current browsers count those as `'self'`; older
/// ones do not and would leave the interface without input and picture, so
/// the two WebSocket origins of the host the page was reached by are named.
/// No other host is: `ws:` and `wss:` used to be allowed everywhere.
fn content_security_policy(host: Option<&str>) -> String {
    match host.filter(|host| is_authority(host)) {
        Some(host) => STRICT_POLICY.replace(
            "connect-src 'self'",
            &format!("connect-src 'self' ws://{host} wss://{host}"),
        ),
        None => STRICT_POLICY.to_string(),
    }
}

/// A host name, IPv4 address or bracketed IPv6 address with an optional port,
/// and nothing that could end the directive or start another.
fn is_authority(host: &str) -> bool {
    let (name, port) = match host.rsplit_once(':') {
        Some((name, port)) if !host.ends_with(']') => (name, Some(port)),
        _ => (host, None),
    };
    let name_ok = match name
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        Some(address) => {
            !address.is_empty()
                && address.len() <= 45
                && address
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() || matches!(byte, b':' | b'.'))
        }
        None => {
            !name.is_empty()
                && name.len() <= 253
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        }
    };
    name_ok
        && port.is_none_or(|port| {
            !port.is_empty() && port.len() <= 5 && port.bytes().all(|byte| byte.is_ascii_digit())
        })
}

pub async fn security_headers(req: Request<Body>, next: Next) -> Response {
    let path = req.uri().path().to_string();
    let is_api = path.starts_with("/api/");
    let is_html_shell = path == "/" || path.ends_with(".html");
    let policy = content_security_policy(
        req.headers()
            .get(header::HOST)
            .and_then(|value| value.to_str().ok())
            .or_else(|| req.uri().authority().map(|authority| authority.as_str())),
    );
    let mut response = next.run(req).await;
    let headers = response.headers_mut();

    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_str(&policy).unwrap_or_else(|_| HeaderValue::from_static(STRICT_POLICY)),
    );
    headers.insert(
        "Permissions-Policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    if is_api || is_html_shell {
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store, max-age=0"),
        );
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_policy_names_only_this_hosts_websockets() {
        for host in [
            "192.0.2.10",
            "192.0.2.10:8443",
            "kvm.example",
            "KVM-1.example:443",
            "[2001:db8::1]",
            "[2001:db8::1]:8443",
            "[::ffff:192.0.2.10]",
        ] {
            let policy = content_security_policy(Some(host));
            assert!(
                policy.contains(&format!("connect-src 'self' ws://{host} wss://{host};")),
                "{host}: {policy}"
            );
            // Nothing else moved, and no scheme is allowed on its own.
            assert_eq!(
                policy.replace(&format!(" ws://{host} wss://{host}"), ""),
                STRICT_POLICY
            );
            assert!(!policy.contains("ws: ") && !policy.contains("wss:;"));
        }
    }

    #[test]
    fn a_host_that_is_no_plain_authority_adds_nothing() {
        for host in [
            "",
            "kvm.example; script-src *",
            "kvm.example 'unsafe-inline'",
            "kvm.example/path",
            "user@kvm.example",
            "kvm.example:",
            "kvm.example:port",
            "kvm.example:123456",
            "[]",
            "[2001:db8::1",
            "[2001:db8::1]x",
            "[zz::1]",
            "kvm.example\r\nX-Injected: 1",
            "*",
        ] {
            assert_eq!(
                content_security_policy(Some(host)),
                STRICT_POLICY,
                "{host:?}"
            );
        }
        assert_eq!(content_security_policy(None), STRICT_POLICY);
        for directive in [
            "default-src 'self'",
            "script-src 'self'",
            "base-uri 'none'",
            "form-action 'self'",
            "frame-ancestors 'none'",
        ] {
            assert!(STRICT_POLICY.contains(directive), "{directive}");
        }
    }
}
