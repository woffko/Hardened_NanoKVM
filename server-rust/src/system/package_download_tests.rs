use super::*;

fn leak(value: String) -> &'static str {
    Box::leak(value.into_boxed_str())
}

#[tokio::test]
async fn a_plain_http_url_is_refused_before_any_request() {
    // Actual curl: the server would answer, but nothing may connect to it.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("package.tgz");
    let package = Pinned {
        url: leak(format!(
            "http://{}/package.tgz",
            listener.local_addr().unwrap()
        )),
        size: 4,
        sha256: leak(format!("{:x}", Sha256::digest(b"data"))),
    };

    assert!(
        fetch(&package, &target, Duration::from_secs(20))
            .await
            .is_err()
    );
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock,
        "curl connected to a plain HTTP server"
    );
    assert!(!target.exists());
}

#[test]
fn only_the_pinned_bytes_are_kept() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("package.tgz");
    fs::write(&path, b"pinned package bytes").unwrap();
    let pinned = format!("{:x}", Sha256::digest(b"pinned package bytes"));
    keep_if_pinned(&path, &pinned).unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"pinned package bytes");

    let other = format!("{:x}", Sha256::digest(b"other package bytes"));
    assert!(keep_if_pinned(&path, &other).is_err());
    assert!(!path.exists(), "a file with another digest was kept");
    assert!(keep_if_pinned(&path, &pinned).is_err());
}

#[test]
fn curl_is_limited_to_https_and_the_pinned_size() {
    let package = Pinned {
        url: "https://example.invalid/package.tgz",
        size: 1234,
        sha256: "",
    };
    let args: Vec<String> = curl_args(
        &package,
        Path::new("/tmp/package.tgz"),
        Duration::from_secs(600),
    )
    .into_iter()
    .map(|arg| arg.into_string().unwrap())
    .collect();
    for pair in [
        ["--proto", "=https"],
        ["--proto-redir", "=https"],
        ["--max-filesize", "1234"],
        ["--max-time", "600"],
        ["--output", "/tmp/package.tgz"],
    ] {
        assert!(
            args.windows(2).any(|window| window == pair),
            "{pair:?} missing from {args:?}"
        );
    }
    assert_eq!(args.last().unwrap(), package.url);
}

#[test]
fn the_shipped_pins_are_exact_https_release_files() {
    for package in [
        &crate::api::tailscale::PACKAGE,
        &crate::api::picoclaw::PACKAGE,
    ] {
        assert!(package.url.starts_with("https://"), "{}", package.url);
        assert!(!package.url.contains("latest"), "{}", package.url);
        assert!(package.size > 0);
        assert_eq!(package.sha256.len(), 64, "{}", package.url);
        assert!(
            package
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "{}",
            package.url
        );
    }
}
