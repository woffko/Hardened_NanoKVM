use super::*;
use axum::http::HeaderValue;
use std::cell::Cell;

const SYNTHETIC_TOKEN: &str = "synthetic-local-capability-fixture";

#[test]
fn empty_store_is_never_internal_authority() {
    let mut rejected = 0;
    for provided in [None, Some("")] {
        let mut headers = HeaderMap::new();
        if let Some(value) = provided {
            headers.insert(INTERNAL_TOKEN_HEADER, HeaderValue::from_static(value));
        }
        rejected += usize::from(!authorize_loopback_internal_token(
            &headers,
            Some("127.0.0.1:12345".parse().unwrap()),
            || Ok(String::new()),
        ));
    }
    assert_eq!(rejected, 2);
}

#[test]
fn missing_empty_malformed_or_duplicate_headers_do_not_load_a_credential() {
    let mut cases = vec![HeaderMap::new()];
    for value in [
        HeaderValue::from_static(""),
        HeaderValue::from_static(" "),
        HeaderValue::from_static("synthetic fixture with spaces"),
        HeaderValue::from_bytes(&[0x80]).unwrap(),
        HeaderValue::from_str(&"x".repeat(257)).unwrap(),
    ] {
        let mut headers = HeaderMap::new();
        headers.insert(INTERNAL_TOKEN_HEADER, value);
        cases.push(headers);
    }
    let mut duplicate = HeaderMap::new();
    duplicate.append(
        INTERNAL_TOKEN_HEADER,
        HeaderValue::from_static(SYNTHETIC_TOKEN),
    );
    duplicate.append(
        INTERNAL_TOKEN_HEADER,
        HeaderValue::from_static(SYNTHETIC_TOKEN),
    );
    cases.push(duplicate);
    let loads = Cell::new(0);
    let rejected = cases
        .iter()
        .filter(|headers| {
            !authorize_loopback_internal_token(
                headers,
                Some("127.0.0.1:12345".parse().unwrap()),
                || {
                    loads.set(loads.get() + 1);
                    Ok(SYNTHETIC_TOKEN.to_string())
                },
            )
        })
        .count();
    assert_eq!(rejected, cases.len());
    assert_eq!(loads.get(), 0);
}

#[test]
fn valid_local_header_keeps_access_while_remote_mismatch_and_load_failure_deny() {
    let mut headers = HeaderMap::new();
    headers.insert(
        INTERNAL_TOKEN_HEADER,
        HeaderValue::from_static(SYNTHETIC_TOKEN),
    );
    for address in ["127.0.0.1:12345", "[::1]:12345"] {
        assert!(authorize_loopback_internal_token(
            &headers,
            Some(address.parse().unwrap()),
            || Ok(SYNTHETIC_TOKEN.to_string()),
        ));
    }
    for remote in [None, Some("192.0.2.1:12345".parse().unwrap())] {
        assert!(!authorize_loopback_internal_token(&headers, remote, || {
            panic!("nonloopback request must not load credentials")
        }));
    }
    let local = Some("127.0.0.1:12345".parse().unwrap());
    assert!(!authorize_loopback_internal_token(&headers, local, || {
        Ok("synthetic-different-fixture".to_string())
    }));
    assert!(!authorize_loopback_internal_token(&headers, local, || {
        Err(AppError::Config("synthetic unavailable store".to_string()))
    }));
}

#[test]
fn valid_header_never_turns_malformed_stored_values_into_authority() {
    let mut headers = HeaderMap::new();
    headers.insert(
        INTERNAL_TOKEN_HEADER,
        HeaderValue::from_static(SYNTHETIC_TOKEN),
    );
    for stored in [
        String::new(),
        " ".to_string(),
        "synthetic\nfixture".to_string(),
        "synthetic\0fixture".to_string(),
        "synthetic-\u{80}".to_string(),
        "x".repeat(257),
    ] {
        assert!(!authorize_loopback_internal_token(
            &headers,
            Some("127.0.0.1:12345".parse().unwrap()),
            || Ok(stored),
        ));
    }
}
