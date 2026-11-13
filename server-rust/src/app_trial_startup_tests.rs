//! Actual run/HTTP/TLS startup with a host-only libkvm ABI fixture, never a
//! claim of native hardware, broker trial launch, health or release acceptance.
use super::*;
use nanokvm_rust_server::update::app_trial::wire;
use nix::mount::{MsFlags, mount};
use std::{
    fs::File,
    io::Read,
    net::{SocketAddr, TcpStream},
    os::{fd::OwnedFd, unix::net::UnixStream},
    process::{Child, Command, Stdio},
    sync::Arc,
    time::Instant,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const TRANSACTION: [u8; 16] = [0x71; 16];
const DEADLINE: Duration = Duration::from_secs(20);

struct OwnedChild(Child);
impl OwnedChild {
    fn wait(&mut self) -> process::ExitStatus {
        let deadline = Instant::now() + DEADLINE;
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                return status;
            }
            assert!(Instant::now() < deadline, "trial child failed to finish");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn private_file(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn connect(addr: SocketAddr) -> TcpStream {
    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
}

fn assert_unserved(addr: SocketAddr) -> TcpStream {
    let mut stream = connect(addr);
    stream
        .write_all(b"GET /trial-fixture HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut byte = [0];
    let error = stream.read(&mut byte).expect_err("served before Commit");
    assert!(matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    ));
    stream
}

fn http_response(stream: &mut TcpStream) -> Vec<u8> {
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut bytes = vec![0; 1024];
    let size = stream.read(&mut bytes).unwrap();
    bytes.truncate(size);
    assert!(bytes.starts_with(b"HTTP/1.1 "), "no HTTP response");
    bytes
}

#[test]
fn actual_trial_startup_child() {
    let Some(root) = std::env::var_os("NANOKVM_MAIN_TRIAL_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    if std::env::var("NANOKVM_MAIN_TRIAL_ROLE").unwrap() == "server" {
        // The production main does exactly this before constructing Tokio.
        let startup = Startup::adopt_stdin().unwrap();
        nix::unistd::chroot(&root).unwrap();
        std::env::set_current_dir("/").unwrap();
        assert!(Config::load().is_err());
        let result = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
            .block_on(run(Some(startup)));
        assert!(result.is_err(), "bad/missing Commit was accepted");
        return;
    }
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_PRIVATE | MsFlags::MS_REC,
        None::<&str>,
    )
    .unwrap();
    for directory in ["etc/kvm", "kvmapp/server/dl_lib", "dev"] {
        fs::create_dir_all(root.join(directory)).unwrap();
    }
    File::create(root.join("dev/null")).unwrap();
    mount(
        Some("/dev/null"),
        &root.join("dev/null"),
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .unwrap();
    let library = PathBuf::from(std::env::var_os("NANOKVM_MAIN_TRIAL_LIBRARY").unwrap());
    fs::copy(library, root.join("kvmapp/server/dl_lib/libkvm.so")).unwrap();

    // Hold the actual three production exclusion inodes, not a substitute
    // test-only namespace or an exposed library-private permit constructor.
    let exclusions = [
        "update-operation",
        "state-writer-admission",
        "state-writer-activity",
    ];
    let _locks = exclusions.map(|name| {
        let path = root.join("etc/kvm").join(name);
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let file = File::open(path).unwrap();
        rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
        file
    });
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    tls::install_crypto_provider();

    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let certificate = cert.der().clone();
    private_file(&root.join("etc/kvm/trial.crt"), cert.pem().as_bytes());
    private_file(
        &root.join("etc/kvm/trial.key"),
        key_pair.serialize_pem().as_bytes(),
    );
    private_file(
        &root.join("etc/kvm/session_secret"),
        b"synthetic-trial-existing-session\n",
    );
    private_file(
        &root.join("etc/kvm/account.json"),
        br#"{"username":"trial-fixture","password":"inactive-synthetic-hash"}"#,
    );

    for proto in ["http", "https"] {
        for outcome in ["commit", "wrong-commit", "eof"] {
            let held_http = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let held_https = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let http = held_http.local_addr().unwrap();
            let https = held_https.local_addr().unwrap();
            let mut config = Config {
                host: "127.0.0.1".into(),
                proto: proto.into(),
                port: nanokvm_rust_server::config::Port {
                    http: http.port(),
                    https: https.port(),
                },
                cert: nanokvm_rust_server::config::Cert {
                    crt: "/etc/kvm/trial.crt".into(),
                    key: "/etc/kvm/trial.key".into(),
                },
                ..Config::default()
            };
            config.security.allow_default_admin = true;
            config.paths.account_file = "/etc/kvm/account.json".into();
            private_file(
                &root.join("etc/kvm/server.yaml"),
                serde_yaml::to_string(&config).unwrap().as_bytes(),
            );
            let snapshot: Vec<_> = ["server.yaml", "session_secret", "account.json"]
                .map(|name| fs::read(root.join("etc/kvm").join(name)).unwrap())
                .into();
            let (mut control, server) = UnixStream::pair().unwrap();
            control
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            drop((held_http, held_https));
            let mut child = OwnedChild(
                Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "app_trial_startup_tests::actual_trial_startup_child",
                        "--nocapture",
                        "--test-threads=1",
                    ])
                    .env_clear()
                    .env("NANOKVM_MAIN_TRIAL_ROOT", &root)
                    .env("NANOKVM_MAIN_TRIAL_ROLE", "server")
                    .stdin(Stdio::from(OwnedFd::from(server)))
                    .stdout(Stdio::null())
                    .stderr(Stdio::inherit())
                    .spawn()
                    .unwrap(),
            );
            control
                .write_all(&wire::frame(wire::Event::Begin, TRANSACTION).unwrap())
                .unwrap();
            let mut ready = [0; wire::BYTES];
            control.read_exact(&mut ready).unwrap();
            assert_eq!(
                wire::parse(&ready, wire::Event::Ready).unwrap(),
                TRANSACTION
            );
            let mut pending_http = assert_unserved(http);
            let pending_https = (proto == "https").then(|| assert_unserved(https));
            match outcome {
                "commit" => {
                    control
                        .write_all(&wire::frame(wire::Event::Commit, TRANSACTION).unwrap())
                        .unwrap();
                    let response = http_response(&mut pending_http);
                    if proto == "https" {
                        assert!(response.starts_with(b"HTTP/1.1 307"));
                        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
                        roots.add(certificate.clone()).unwrap();
                        let tls = tokio_rustls::rustls::ClientConfig::builder()
                            .with_root_certificates(roots)
                            .with_no_client_auth();
                        runtime.block_on(async {
                            time::timeout(Duration::from_secs(4), async {
                                let stream = tokio::net::TcpStream::connect(https).await.unwrap();
                                let mut stream = tokio_rustls::TlsConnector::from(Arc::new(tls))
                                    .connect("localhost".try_into().unwrap(), stream)
                                    .await
                                    .unwrap();
                                stream.write_all(b"GET /trial-fixture HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await.unwrap();
                                let mut bytes = [0; 1024];
                                let size = stream.read(&mut bytes).await.unwrap();
                                assert!(bytes[..size].starts_with(b"HTTP/1.1 "));
                            }).await.unwrap();
                        });
                    }
                    nix::sys::signal::kill(
                        nix::unistd::Pid::from_raw(child.0.id() as i32),
                        nix::sys::signal::Signal::SIGTERM,
                    )
                    .unwrap();
                }
                "wrong-commit" => control
                    .write_all(&wire::frame(wire::Event::Commit, [0x72; 16]).unwrap())
                    .unwrap(),
                _ => drop(control),
            }
            assert!(child.wait().success(), "{proto}/{outcome}");
            for addr in [Some(http), (proto == "https").then_some(https)]
                .into_iter()
                .flatten()
            {
                assert!(TcpStream::connect_timeout(&addr, Duration::from_secs(1)).is_err());
            }
            if outcome != "commit" {
                let mut byte = [0];
                assert!(!matches!(pending_http.read(&mut byte), Ok(1)));
            }
            drop(pending_https);
            for (index, name) in ["server.yaml", "session_secret", "account.json"]
                .into_iter()
                .enumerate()
            {
                assert_eq!(
                    fs::read(root.join("etc/kvm").join(name)).unwrap(),
                    snapshot[index]
                );
            }
            for name in exclusions {
                let second = File::open(root.join("etc/kvm").join(name)).unwrap();
                assert_eq!(
                    rustix::fs::flock(
                        &second,
                        rustix::fs::FlockOperation::NonBlockingLockExclusive
                    ),
                    Err(rustix::io::Errno::WOULDBLOCK)
                );
            }
        }
    }
}

#[test]
fn real_http_and_https_trial_listeners_serve_only_after_commit() {
    let root = tempfile::tempdir().unwrap();
    let library = root.path().join("host-startup-fixture.so");
    let result = Command::new("rustc")
        .args([
            "--edition=2021",
            "--crate-type=cdylib",
            "-Cpanic=abort",
            "-o",
        ])
        .arg(&library)
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/trial_kvm.rs"))
        .output()
        .unwrap();
    assert!(result.status.success(), "{result:?}");
    let mut child = OwnedChild(
        Command::new("/usr/bin/unshare")
            .args([
                "--user",
                "--map-root-user",
                "--mount",
                "--pid",
                "--fork",
                "--kill-child=KILL",
                "--",
            ])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "app_trial_startup_tests::actual_trial_startup_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env_clear()
            .env("NANOKVM_MAIN_TRIAL_ROOT", root.path())
            .env("NANOKVM_MAIN_TRIAL_ROLE", "parent")
            .env("NANOKVM_MAIN_TRIAL_LIBRARY", library)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    assert!(child.wait().success());
}
