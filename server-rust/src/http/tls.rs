use std::{fs::File, io, net::SocketAddr, path::Path, sync::Arc, time::Duration};

use axum::{
    extract::connect_info::Connected,
    serve::{IncomingStream, Listener},
};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use tokio::{net::TcpListener, task::JoinSet, time};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        ServerConfig,
        pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    },
    server::TlsStream,
};
use tracing::{debug, warn};

use crate::{AppError, Result, system::files};

const MAX_PENDING_TLS_HANDSHAKES: usize = 8;
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy)]
pub struct ClientAddr(pub SocketAddr);

pub struct TlsListener {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    handshakes: JoinSet<(SocketAddr, io::Result<TlsStream<tokio::net::TcpStream>>)>,
    max_handshakes: usize,
    handshake_timeout: Duration,
}

impl Connected<IncomingStream<'_, TcpListener>> for ClientAddr {
    fn connect_info(stream: IncomingStream<'_, TcpListener>) -> Self {
        Self(*stream.remote_addr())
    }
}

impl TlsListener {
    pub fn new(listener: TcpListener, config: ServerConfig) -> Self {
        Self {
            listener,
            acceptor: TlsAcceptor::from(Arc::new(config)),
            handshakes: JoinSet::new(),
            max_handshakes: MAX_PENDING_TLS_HANDSHAKES,
            handshake_timeout: TLS_HANDSHAKE_TIMEOUT,
        }
    }
}

impl Listener for TlsListener {
    type Io = TlsStream<tokio::net::TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            tokio::select! {
                // Drain completed tasks before admitting more TCP clients. The
                // JoinSet owns and aborts pending handshakes when we are dropped.
                biased;
                completed = self.handshakes.join_next(), if !self.handshakes.is_empty() => {
                    match completed {
                        Some(Ok((addr, Ok(stream)))) => return (stream, addr),
                        Some(Ok((addr, Err(err)))) => {
                            debug!(%addr, error = ?err, "TLS handshake rejected");
                        }
                        Some(Err(err)) => warn!(error = ?err, "TLS handshake task failed"),
                        None => {}
                    }
                }
                accepted = self.listener.accept() => {
                    let (stream, addr) = match accepted {
                        Ok(connection) => connection,
                        Err(err) => {
                            warn!(error = ?err, "failed to accept tcp connection");
                            time::sleep(Duration::from_secs(1)).await;
                            continue;
                        }
                    };
                    if self.handshakes.len() >= self.max_handshakes {
                        // Reject overload without allocating another task or
                        // retaining an unbounded queue of unauthenticated peers.
                        drop(stream);
                        continue;
                    }
                    let acceptor = self.acceptor.clone();
                    let timeout = self.handshake_timeout;
                    self.handshakes.spawn(async move {
                        let result = match time::timeout(timeout, acceptor.accept(stream)).await {
                            Ok(result) => result,
                            Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out")),
                        };
                        (addr, result)
                    });
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}

impl Connected<IncomingStream<'_, TlsListener>> for ClientAddr {
    fn connect_info(stream: IncomingStream<'_, TlsListener>) -> Self {
        Self(*stream.remote_addr())
    }
}

pub fn install_crypto_provider() {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
}

pub fn load_server_config(
    cert_path: impl AsRef<Path>,
    key_path: impl AsRef<Path>,
) -> Result<ServerConfig> {
    let cert_file = File::open(cert_path.as_ref())?;
    let key_file = File::open(key_path.as_ref())?;
    server_config_from_readers(cert_file, key_file)
}

/// Trial startup supplies pinned, bounded existing files, not mutable paths.
pub(crate) fn server_config_from_pem(cert: &[u8], key: &[u8]) -> Result<ServerConfig> {
    server_config_from_readers(cert, key)
}

fn server_config_from_readers(
    cert_file: impl io::Read,
    key_file: impl io::Read,
) -> Result<ServerConfig> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_reader_iter(cert_file)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|err| AppError::Config(format!("failed to read TLS certificate: {err}")))?;
    if certs.is_empty() {
        return Err(AppError::Config(
            "TLS certificate file is empty".to_string(),
        ));
    }

    let key = PrivateKeyDer::from_pem_reader(key_file)
        .map_err(|err| AppError::Config(format!("failed to read TLS private key: {err}")))?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| AppError::Config(format!("failed to configure TLS certificate: {err}")))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

/// Keeps a certificate and key that rustls loads as a matching pair, so the
/// device keeps its TLS identity when HTTPS is enabled again and an
/// administrator's own pair is never replaced. Otherwise publishes a new
/// self-signed pair for `names`, key first and each file atomically, and loads
/// it back. Returns whether a new pair was written.
pub fn ensure_server_cert(
    cert_path: impl AsRef<Path>,
    key_path: impl AsRef<Path>,
    names: Vec<String>,
) -> Result<bool> {
    let (cert_path, key_path) = (cert_path.as_ref(), key_path.as_ref());
    if load_server_config(cert_path, key_path).is_ok() {
        return Ok(false);
    }
    let CertifiedKey { cert, key_pair } = generate_simple_self_signed(names)
        .map_err(|err| AppError::Internal(format!("failed to generate TLS certificate: {err}")))?;
    files::write_atomic(key_path, key_pair.serialize_pem().as_bytes(), 0o600)?;
    files::write_atomic(cert_path, cert.pem().as_bytes(), 0o644)?;
    load_server_config(cert_path, key_path)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use super::*;
    use tokio::{io::AsyncReadExt, net::TcpStream};
    use tokio_rustls::{
        TlsConnector,
        rustls::{ClientConfig, RootCertStore, pki_types::ServerName},
    };

    fn test_configs() -> (ServerConfig, ClientConfig) {
        install_crypto_provider();
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(["localhost".to_string()]).unwrap();
        let certificate = cert.der().clone();
        let server = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate.clone()],
                PrivateKeyDer::Pkcs8(key_pair.serialize_der().into()),
            )
            .unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(certificate).unwrap();
        let client = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        (server, client)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn idle_tcp_client_does_not_block_other_tls_handshakes() {
        let (server, client) = test_configs();
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let _idle = TcpStream::connect(addr).await.unwrap();
        let mut listener = TlsListener::new(tcp, server);
        let accepting = listener.accept();
        tokio::pin!(accepting);
        // Poll acceptance while only the idle connection exists, then keep the
        // same future alive while a second client performs a real handshake.
        assert!(
            time::timeout(Duration::from_millis(50), &mut accepting)
                .await
                .is_err()
        );
        let stream = TcpStream::connect(addr).await.unwrap();
        let connector = TlsConnector::from(Arc::new(client));
        let result = time::timeout(Duration::from_secs(2), async {
            tokio::join!(
                &mut accepting,
                connector.connect(ServerName::try_from("localhost").unwrap(), stream)
            )
        })
        .await;
        let (_, connected) = result.expect("idle TCP client blocked a second TLS handshake");
        assert!(connected.is_ok());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tls_handshakes_are_bounded_and_expire() {
        let (server, _) = test_configs();
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let mut first = TcpStream::connect(addr).await.unwrap();
        let mut second = TcpStream::connect(addr).await.unwrap();
        let mut overflow = TcpStream::connect(addr).await.unwrap();
        let mut listener = TlsListener::new(tcp, server);
        listener.max_handshakes = 2;
        listener.handshake_timeout = Duration::from_millis(200);
        assert!(
            time::timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
        assert!(listener.handshakes.len() <= 2);
        let mut byte = [0];
        assert_eq!(
            time::timeout(Duration::from_millis(100), overflow.read(&mut byte))
                .await
                .expect("over-capacity peer was retained")
                .unwrap(),
            0
        );
        for stream in [&mut first, &mut second] {
            assert_eq!(
                time::timeout(Duration::from_secs(1), stream.read(&mut byte))
                    .await
                    .expect("idle handshake did not expire")
                    .unwrap(),
                0
            );
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dropping_tls_listener_aborts_pending_handshakes() {
        let (server, _) = test_configs();
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let mut idle = TcpStream::connect(addr).await.unwrap();
        let mut listener = TlsListener::new(tcp, server);
        assert!(
            time::timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
        drop(listener);
        let mut byte = [0];
        assert_eq!(
            time::timeout(Duration::from_secs(1), idle.read(&mut byte))
                .await
                .expect("listener drop retained an unauthenticated peer")
                .unwrap(),
            0
        );
    }

    /// Whether a client that trusts exactly this certificate accepts it for `name`.
    fn verifies_for(cert_pem: &[u8], name: &str) -> bool {
        use tokio_rustls::rustls::{
            client::{WebPkiServerVerifier, danger::ServerCertVerifier},
            pki_types::UnixTime,
        };
        let cert = CertificateDer::pem_slice_iter(cert_pem)
            .next()
            .unwrap()
            .unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(cert.clone()).unwrap();
        let verifier = WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .unwrap();
        let name = ServerName::try_from(name.to_string()).unwrap();
        verifier
            .verify_server_cert(&cert, &[], &name, &[], UnixTime::now())
            .is_ok()
    }

    fn pair(name: &str) -> (String, String) {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed([name.to_string()]).unwrap();
        (cert.pem(), key_pair.serialize_pem())
    }

    #[test]
    fn a_missing_pair_is_generated_for_the_given_names() {
        install_crypto_provider();
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("server.crt");
        let key = dir.path().join("server.key");
        let names = vec!["localhost".to_string(), "kvm-test.local".to_string()];

        assert!(ensure_server_cert(&cert, &key, names).unwrap());
        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&key), 0o600);
        assert_eq!(mode(&cert), 0o644);
        assert!(load_server_config(&cert, &key).is_ok());
        let pem = fs::read(&cert).unwrap();
        assert!(verifies_for(&pem, "kvm-test.local"));
        assert!(!verifies_for(&pem, "other.local"));
    }

    #[test]
    fn a_matching_pair_is_kept_byte_for_byte() {
        install_crypto_provider();
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("server.crt");
        let key = dir.path().join("server.key");
        // An administrator's own pair, or the one an earlier enable generated.
        let (cert_pem, key_pem) = pair("kvm.example.net");
        fs::write(&cert, &cert_pem).unwrap();
        fs::write(&key, &key_pem).unwrap();

        assert!(!ensure_server_cert(&cert, &key, vec!["localhost".to_string()]).unwrap());
        assert_eq!(fs::read_to_string(&cert).unwrap(), cert_pem);
        assert_eq!(fs::read_to_string(&key).unwrap(), key_pem);
    }

    #[test]
    fn a_mismatched_or_unreadable_pair_is_replaced() {
        install_crypto_provider();
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("server.crt");
        let key = dir.path().join("server.key");
        let (cert_pem, _) = pair("one.example.net");
        let (_, other_key_pem) = pair("two.example.net");
        for (cert_bytes, key_bytes) in [
            (cert_pem.as_bytes(), other_key_pem.as_bytes()),
            (b"not a certificate".as_slice(), other_key_pem.as_bytes()),
        ] {
            fs::write(&cert, cert_bytes).unwrap();
            fs::write(&key, key_bytes).unwrap();
            assert!(load_server_config(&cert, &key).is_err());

            assert!(ensure_server_cert(&cert, &key, vec!["localhost".to_string()]).unwrap());
            assert!(load_server_config(&cert, &key).is_ok());
            assert_ne!(fs::read(&key).unwrap(), key_bytes);
        }
    }
}
