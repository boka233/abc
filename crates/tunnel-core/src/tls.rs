//! rustls configuration for the tunnel, with hot-reloadable certificates.
//!
//! ## Why TLS 1.3 only
//!
//! The tunnel is a closed system: both ends are our own binaries, built from
//! the same workspace. There is no legacy peer to accommodate, so there is no
//! reason to keep TLS 1.2 enabled. Restricting to 1.3 removes downgrade
//! attacks, removes CBC/RSA-key-exchange cipher suites, and gets us
//! encrypt-then-MAC AEAD everywhere by construction.
//!
//! We never implement crypto here. Key exchange, AEAD and certificate
//! verification are all rustls + ring.
//!
//! ## Certificate rotation
//!
//! Certificates live behind an [`ArcSwap`]. `SIGHUP` (or a control-plane push)
//! calls [`TlsMaterial::reload`], which loads and validates the new material
//! *before* swapping it in. A bad certificate on disk therefore leaves the
//! running configuration untouched instead of breaking every future handshake.
//! Established connections keep the config they started with; new handshakes
//! pick up the new one. That is the correct behaviour — tearing down live
//! tunnels to install a certificate would be self-inflicted downtime.
//!
//! ## mTLS
//!
//! When `require_client_auth` is set, the exit demands and verifies a client
//! certificate against the configured CA. Combined with the PSK proof in the
//! handshake, an attacker needs both a CA-signed client certificate and the PSK.

use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwap;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tunnel_common::model::TlsConfig;
use tunnel_common::{Error, Result};

/// TLS 1.3 only. Explicit so a dependency bump cannot silently re-enable 1.2.
static TLS13_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];

/// Loaded and validated certificate material.
struct Material {
    server: Option<Arc<ServerConfig>>,
    client: Arc<ClientConfig>,
    /// Fingerprint of the leaf certificate, for display in the panel. Never a
    /// private key.
    leaf_fingerprint: Option<String>,
    generation: u64,
}

/// Hot-reloadable TLS material shared by every tunnel on a node.
pub struct TlsMaterial {
    inner: ArcSwap<Material>,
    config: std::sync::Mutex<TlsConfig>,
}

impl std::fmt::Debug for TlsMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let m = self.inner.load();
        f.debug_struct("TlsMaterial")
            .field("has_server_config", &m.server.is_some())
            .field("generation", &m.generation)
            .field("leaf_fingerprint", &m.leaf_fingerprint)
            .finish()
    }
}

impl TlsMaterial {
    /// Load from config. Fails if the exit role lacks a usable keypair, or if
    /// any configured path is unreadable/malformed.
    pub fn load(cfg: &TlsConfig, need_server: bool) -> Result<Arc<Self>> {
        let material = Self::build(cfg, need_server, 1)?;
        Ok(Arc::new(Self {
            inner: ArcSwap::from_pointee(material),
            config: std::sync::Mutex::new(cfg.clone()),
        }))
    }

    fn build(cfg: &TlsConfig, need_server: bool, generation: u64) -> Result<Material> {
        let roots = build_root_store(cfg)?;

        // --- server side (exit role) ---
        let mut leaf_fingerprint = None;
        let server = if need_server {
            let (Some(cert_path), Some(key_path)) = (&cfg.cert_path, &cfg.key_path) else {
                return Err(Error::config(
                    "exit role requires tls.cert_path and tls.key_path",
                ));
            };
            let certs = load_certs(cert_path)?;
            let key = load_private_key(key_path)?;
            leaf_fingerprint = certs.first().map(|c| fingerprint(c));

            let builder = ServerConfig::builder_with_protocol_versions(TLS13_ONLY);
            let mut sc = if cfg.require_client_auth {
                let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots.clone()))
                    .build()
                    .map_err(|e| Error::tls(format!("client verifier: {e}")))?;
                builder
                    .with_client_cert_verifier(verifier)
                    .with_single_cert(certs, key)
                    .map_err(|e| Error::tls(format!("server cert/key rejected: {e}")))?
            } else {
                builder
                    .with_no_client_auth()
                    .with_single_cert(certs, key)
                    .map_err(|e| Error::tls(format!("server cert/key rejected: {e}")))?
            };
            // The tunnel protocol does its own framing; session resumption and
            // tickets add state for no benefit on long-lived connections.
            sc.send_half_rtt_data = false;
            Some(Arc::new(sc))
        } else {
            None
        };

        // --- client side (entry role) ---
        let builder = ClientConfig::builder_with_protocol_versions(TLS13_ONLY);
        let mut client = if cfg.insecure_skip_verify {
            // Lab-only. The control plane refuses to distribute a bundle with
            // this set when the deployment is marked production.
            tracing::warn!(
                "TLS certificate verification is DISABLED (tls.insecure_skip_verify); \
                 this is unsafe outside a lab"
            );
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier::new()))
                .with_no_client_auth()
        } else if let (Some(cert_path), Some(key_path)) =
            (&cfg.client_cert_path, &cfg.client_key_path)
        {
            let certs = load_certs(cert_path)?;
            let key = load_private_key(key_path)?;
            builder
                .with_root_certificates(roots)
                .with_client_auth_cert(certs, key)
                .map_err(|e| Error::tls(format!("client cert/key rejected: {e}")))?
        } else {
            if cfg.require_client_auth {
                tracing::warn!(
                    "tls.require_client_auth is set but no client certificate is configured; \
                     outbound tunnels will be rejected by an mTLS peer"
                );
            }
            builder.with_root_certificates(roots).with_no_client_auth()
        };
        client.enable_early_data = false;

        Ok(Material {
            server,
            client: Arc::new(client),
            leaf_fingerprint,
            generation,
        })
    }

    /// Rebuild from disk and swap atomically.
    ///
    /// On failure the previous material stays live and the error is returned to
    /// the caller for logging. This is the whole point: a botched cert renewal
    /// must not take the node down.
    pub fn reload(&self) -> Result<u64> {
        let cfg = self
            .config
            .lock()
            .map_err(|_| Error::other("tls config lock poisoned"))?
            .clone();
        let need_server = self.inner.load().server.is_some();
        let next_gen = self.inner.load().generation + 1;

        let material = Self::build(&cfg, need_server, next_gen)?;
        let fingerprint = material.leaf_fingerprint.clone();
        self.inner.store(Arc::new(material));
        tracing::info!(
            generation = next_gen,
            fingerprint = fingerprint.as_deref().unwrap_or("-"),
            "TLS material reloaded"
        );
        Ok(next_gen)
    }

    /// Replace the configuration (e.g. a control-plane push changed the paths)
    /// and reload in one step.
    pub fn apply_config(&self, cfg: &TlsConfig, need_server: bool) -> Result<u64> {
        let next_gen = self.inner.load().generation + 1;
        // Validate before mutating any shared state.
        let material = Self::build(cfg, need_server, next_gen)?;
        {
            let mut guard = self
                .config
                .lock()
                .map_err(|_| Error::other("tls config lock poisoned"))?;
            *guard = cfg.clone();
        }
        self.inner.store(Arc::new(material));
        Ok(next_gen)
    }

    pub fn acceptor(&self) -> Result<TlsAcceptor> {
        let m = self.inner.load();
        let server = m
            .server
            .clone()
            .ok_or_else(|| Error::config("no server TLS configuration loaded"))?;
        Ok(TlsAcceptor::from(server))
    }

    pub fn connector(&self) -> TlsConnector {
        TlsConnector::from(self.inner.load().client.clone())
    }

    pub fn generation(&self) -> u64 {
        self.inner.load().generation
    }

    pub fn leaf_fingerprint(&self) -> Option<String> {
        self.inner.load().leaf_fingerprint.clone()
    }
}

/// Convenience wrapper describing what a node needs from TLS.
#[derive(Debug, Clone)]
pub struct TunnelTlsConfig {
    pub material: Arc<TlsMaterial>,
    pub handshake_timeout: std::time::Duration,
}

fn build_root_store(cfg: &TlsConfig) -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();

    if let Some(ca_path) = &cfg.ca_path {
        // A pinned private CA: deliberately do NOT also trust the system store.
        // Trusting both would mean any public CA could impersonate our exit.
        let certs = load_certs(ca_path)?;
        let count = certs.len();
        for cert in certs {
            roots
                .add(cert)
                .map_err(|e| Error::tls(format!("CA certificate in {ca_path} rejected: {e}")))?;
        }
        if roots.is_empty() {
            return Err(Error::config(format!(
                "no usable CA certificates found in {ca_path}"
            )));
        }
        tracing::debug!(ca_path, count, "loaded private CA bundle");
    } else if !cfg.insecure_skip_verify {
        let result = rustls_native_certs::load_native_certs();
        for cert in result.certs {
            // Ignore individual malformed system certs; the store as a whole is
            // what matters.
            let _ = roots.add(cert);
        }
        if roots.is_empty() {
            return Err(Error::config(
                "no CA configured and the system trust store is empty; \
                 set tls.ca_path to your tunnel CA",
            ));
        }
    }
    Ok(roots)
}

fn load_certs(path: impl AsRef<Path>) -> Result<Vec<CertificateDer<'static>>> {
    let path = path.as_ref();
    let file = std::fs::File::open(path).map_err(|e| {
        Error::config(format!("cannot open certificate file {}: {e}", path.display()))
    })?;
    let mut reader = BufReader::new(file);
    let certs: std::result::Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    let certs = certs
        .map_err(|e| Error::tls(format!("malformed PEM in {}: {e}", path.display())))?;
    if certs.is_empty() {
        return Err(Error::config(format!(
            "no certificates found in {}",
            path.display()
        )));
    }
    Ok(certs)
}

fn load_private_key(path: impl AsRef<Path>) -> Result<PrivateKeyDer<'static>> {
    let path: PathBuf = path.as_ref().to_path_buf();

    // Warn on a world-readable key. Not fatal — refusing to start over file
    // permissions would be its own outage — but it must be visible.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(&path) {
            let mode = meta.permissions().mode() & 0o077;
            if mode != 0 {
                tracing::warn!(
                    path = %path.display(),
                    "private key is readable by group/other; tighten to 0600"
                );
            }
        }
    }

    let file = std::fs::File::open(&path)
        .map_err(|e| Error::config(format!("cannot open key file {}: {e}", path.display())))?;
    let mut reader = BufReader::new(file);
    // Error messages here must never include file contents.
    let key = rustls_pemfile::private_key(&mut reader)
        .map_err(|e| Error::tls(format!("malformed private key in {}: {e}", path.display())))?
        .ok_or_else(|| {
            Error::config(format!(
                "no PKCS#8/PKCS#1/SEC1 private key found in {}",
                path.display()
            ))
        })?;
    Ok(key)
}

/// SHA-256 fingerprint of a certificate, colon-separated, for display in the
/// panel. Operates on the public certificate only — never on key material.
fn fingerprint(cert: &CertificateDer<'_>) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(cert.as_ref());
    digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Certificate verifier that accepts anything. Only reachable via
/// `insecure_skip_verify`, which logs a warning on every load.
#[derive(Debug)]
struct NoVerifier {
    supported: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl NoVerifier {
    fn new() -> Self {
        Self {
            supported: rustls::crypto::ring::default_provider().signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        // TLS 1.2 is not enabled; reaching this would be a rustls bug.
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        // Still verify the handshake signature binds to the presented key; only
        // the chain-to-CA check is skipped.
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Generates a throwaway CA + leaf so the tests exercise real PEM parsing
    /// and a real rustls handshake rather than mocks.
    struct TestPki {
        dir: PathBuf,
        ca_path: PathBuf,
        cert_path: PathBuf,
        key_path: PathBuf,
        client_cert_path: PathBuf,
        client_key_path: PathBuf,
    }

    impl TestPki {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "tunnel-tls-test-{}-{}",
                name,
                std::process::id()
            ));
            std::fs::create_dir_all(&dir).unwrap();

            let mut ca_params = rcgen::CertificateParams::default();
            ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            ca_params
                .distinguished_name
                .push(rcgen::DnType::CommonName, "tunnel-test-ca");
            let ca_key = rcgen::KeyPair::generate().unwrap();
            let ca_cert = ca_params.self_signed(&ca_key).unwrap();

            let mut leaf_params =
                rcgen::CertificateParams::new(vec!["exit.internal".to_string()]).unwrap();
            leaf_params
                .distinguished_name
                .push(rcgen::DnType::CommonName, "exit.internal");
            let leaf_key = rcgen::KeyPair::generate().unwrap();
            let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();

            let mut client_params =
                rcgen::CertificateParams::new(vec!["entry.internal".to_string()]).unwrap();
            client_params
                .distinguished_name
                .push(rcgen::DnType::CommonName, "entry.internal");
            let client_key = rcgen::KeyPair::generate().unwrap();
            let client_cert = client_params
                .signed_by(&client_key, &ca_cert, &ca_key)
                .unwrap();

            let write = |path: &PathBuf, contents: String| {
                let mut f = std::fs::File::create(path).unwrap();
                f.write_all(contents.as_bytes()).unwrap();
            };

            let ca_path = dir.join("ca.pem");
            let cert_path = dir.join("exit.pem");
            let key_path = dir.join("exit.key");
            let client_cert_path = dir.join("entry.pem");
            let client_key_path = dir.join("entry.key");

            write(&ca_path, ca_cert.pem());
            write(&cert_path, leaf_cert.pem());
            write(&key_path, leaf_key.serialize_pem());
            write(&client_cert_path, client_cert.pem());
            write(&client_key_path, client_key.serialize_pem());

            Self {
                dir,
                ca_path,
                cert_path,
                key_path,
                client_cert_path,
                client_key_path,
            }
        }

        fn server_config(&self) -> TlsConfig {
            TlsConfig {
                cert_path: Some(self.cert_path.display().to_string()),
                key_path: Some(self.key_path.display().to_string()),
                ca_path: Some(self.ca_path.display().to_string()),
                require_client_auth: false,
                client_cert_path: None,
                client_key_path: None,
                insecure_skip_verify: false,
            }
        }

        fn mtls_config(&self) -> TlsConfig {
            TlsConfig {
                require_client_auth: true,
                client_cert_path: Some(self.client_cert_path.display().to_string()),
                client_key_path: Some(self.client_key_path.display().to_string()),
                ..self.server_config()
            }
        }
    }

    impl Drop for TestPki {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn loads_server_and_client_material() {
        let pki = TestPki::new("load");
        let m = TlsMaterial::load(&pki.server_config(), true).unwrap();
        assert!(m.acceptor().is_ok());
        assert_eq!(m.generation(), 1);
        let fp = m.leaf_fingerprint().expect("leaf fingerprint");
        assert_eq!(fp.split(':').count(), 32, "expected SHA-256 fingerprint");
    }

    #[test]
    fn entry_role_does_not_need_a_server_certificate() {
        let pki = TestPki::new("entry-only");
        let cfg = TlsConfig {
            ca_path: Some(pki.ca_path.display().to_string()),
            ..Default::default()
        };
        let m = TlsMaterial::load(&cfg, false).unwrap();
        assert!(m.acceptor().is_err(), "no server config should be present");
        let _ = m.connector();
    }

    #[test]
    fn exit_role_without_a_keypair_is_a_config_error() {
        let pki = TestPki::new("no-key");
        let cfg = TlsConfig {
            ca_path: Some(pki.ca_path.display().to_string()),
            ..Default::default()
        };
        let err = TlsMaterial::load(&cfg, true).unwrap_err();
        assert!(matches!(err, Error::Config(_)), "{err:?}");
    }

    #[test]
    fn missing_certificate_file_is_reported_clearly() {
        let pki = TestPki::new("missing-cert");
        let cfg = TlsConfig {
            cert_path: Some("/nonexistent/cert.pem".into()),
            key_path: Some("/nonexistent/key.pem".into()),
            ca_path: Some(pki.ca_path.display().to_string()),
            ..Default::default()
        };
        let err = TlsMaterial::load(&cfg, true).unwrap_err();
        assert!(err.to_string().contains("cert.pem"), "{err}");
    }

    #[test]
    fn malformed_pem_is_rejected_without_leaking_contents() {
        let pki = TestPki::new("malformed-pem");
        let dir = std::env::temp_dir().join(format!("tunnel-tls-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bad = dir.join("bad.pem");
        std::fs::write(&bad, b"-----BEGIN CERTIFICATE-----\nnot base64\n").unwrap();

        let cfg = TlsConfig {
            cert_path: Some(bad.display().to_string()),
            key_path: Some(bad.display().to_string()),
            ca_path: Some(pki.ca_path.display().to_string()),
            ..Default::default()
        };
        let err = TlsMaterial::load(&cfg, true).unwrap_err();
        let msg = err.to_string();
        assert!(!msg.contains("not base64"), "file contents leaked: {msg}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reload_bumps_the_generation_and_keeps_serving() {
        let pki = TestPki::new("reload");
        let m = TlsMaterial::load(&pki.server_config(), true).unwrap();
        assert_eq!(m.generation(), 1);
        assert_eq!(m.reload().unwrap(), 2);
        assert_eq!(m.generation(), 2);
        assert!(m.acceptor().is_ok());
    }

    #[test]
    fn failed_reload_preserves_the_live_configuration() {
        // The scenario that matters: certbot writes a truncated file and HUPs us.
        let pki = TestPki::new("reload-fail");
        let m = TlsMaterial::load(&pki.server_config(), true).unwrap();
        let good_fp = m.leaf_fingerprint();

        std::fs::write(&pki.cert_path, b"garbage").unwrap();
        assert!(m.reload().is_err());

        assert_eq!(m.generation(), 1, "generation must not advance on failure");
        assert_eq!(m.leaf_fingerprint(), good_fp, "live material must be intact");
        assert!(m.acceptor().is_ok(), "node must keep accepting handshakes");
    }

    #[test]
    fn empty_ca_bundle_is_rejected() {
        let dir = std::env::temp_dir().join(format!("tunnel-tls-noca-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let empty = dir.join("empty.pem");
        std::fs::write(&empty, b"# nothing here\n").unwrap();
        let cfg = TlsConfig {
            ca_path: Some(empty.display().to_string()),
            ..Default::default()
        };
        assert!(TlsMaterial::load(&cfg, false).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mtls_config_builds_on_both_sides() {
        let pki = TestPki::new("mtls");
        let m = TlsMaterial::load(&pki.mtls_config(), true).unwrap();
        assert!(m.acceptor().is_ok());
        let _ = m.connector();
    }

    #[test]
    fn insecure_mode_builds_a_client_config() {
        let cfg = TlsConfig {
            insecure_skip_verify: true,
            ..Default::default()
        };
        let m = TlsMaterial::load(&cfg, false).unwrap();
        let _ = m.connector();
    }

    /// Full handshake over a loopback socket, asserting the negotiated version
    /// is 1.3. This is the check that catches a dependency re-enabling 1.2.
    #[tokio::test]
    async fn real_handshake_negotiates_tls13() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let pki = TestPki::new("handshake");
        let server_material = TlsMaterial::load(&pki.server_config(), true).unwrap();
        let client_material = TlsMaterial::load(
            &TlsConfig {
                ca_path: Some(pki.ca_path.display().to_string()),
                ..Default::default()
            },
            false,
        )
        .unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = server_material.acceptor().unwrap();

        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(sock).await.unwrap();
            let mut buf = [0u8; 5];
            tls.read_exact(&mut buf).await.unwrap();
            tls.write_all(b"pong!").await.unwrap();
            tls.flush().await.unwrap();
            let (_, conn) = tls.get_ref();
            conn.protocol_version()
        });

        let connector = client_material.connector();
        let sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        let name = ServerName::try_from("exit.internal").unwrap();
        let mut tls = connector.connect(name, sock).await.unwrap();
        tls.write_all(b"ping!").await.unwrap();
        tls.flush().await.unwrap();
        let mut buf = [0u8; 5];
        tls.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong!");

        let (_, conn) = tls.get_ref();
        assert_eq!(
            conn.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3),
            "client negotiated a version other than TLS 1.3"
        );
        assert_eq!(
            server.await.unwrap(),
            Some(rustls::ProtocolVersion::TLSv1_3),
            "server negotiated a version other than TLS 1.3"
        );
    }

    /// An untrusted certificate must fail the handshake, not warn and continue.
    #[tokio::test]
    async fn untrusted_certificate_is_rejected() {
        let server_pki = TestPki::new("untrusted-server");
        let other_pki = TestPki::new("untrusted-client");

        let server_material = TlsMaterial::load(&server_pki.server_config(), true).unwrap();
        // Client trusts a *different* CA.
        let client_material = TlsMaterial::load(
            &TlsConfig {
                ca_path: Some(other_pki.ca_path.display().to_string()),
                ..Default::default()
            },
            false,
        )
        .unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = server_material.acceptor().unwrap();
        tokio::spawn(async move {
            if let Ok((sock, _)) = listener.accept().await {
                let _ = acceptor.accept(sock).await;
            }
        });

        let connector = client_material.connector();
        let sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        let name = ServerName::try_from("exit.internal").unwrap();
        assert!(
            connector.connect(name, sock).await.is_err(),
            "handshake against an untrusted CA must fail"
        );
    }

    #[tokio::test]
    async fn wrong_server_name_is_rejected() {
        let pki = TestPki::new("wrong-sni");
        let server_material = TlsMaterial::load(&pki.server_config(), true).unwrap();
        let client_material = TlsMaterial::load(
            &TlsConfig {
                ca_path: Some(pki.ca_path.display().to_string()),
                ..Default::default()
            },
            false,
        )
        .unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = server_material.acceptor().unwrap();
        tokio::spawn(async move {
            if let Ok((sock, _)) = listener.accept().await {
                let _ = acceptor.accept(sock).await;
            }
        });

        let connector = client_material.connector();
        let sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        // Certificate is for exit.internal; we claim to expect someone else.
        let name = ServerName::try_from("attacker.example").unwrap();
        assert!(connector.connect(name, sock).await.is_err());
    }

    /// mTLS: a client with no certificate must be refused by the exit.
    #[tokio::test]
    async fn mtls_rejects_a_client_without_a_certificate() {
        use tokio::io::AsyncWriteExt;

        let pki = TestPki::new("mtls-reject");
        let server_material = TlsMaterial::load(&pki.mtls_config(), true).unwrap();
        let client_material = TlsMaterial::load(
            &TlsConfig {
                ca_path: Some(pki.ca_path.display().to_string()),
                ..Default::default()
            },
            false,
        )
        .unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = server_material.acceptor().unwrap();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            acceptor.accept(sock).await.is_ok()
        });

        let connector = client_material.connector();
        let sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        let name = ServerName::try_from("exit.internal").unwrap();
        // The client handshake may appear to succeed; the failure surfaces on
        // first write or on the server side. Assert the server rejected it.
        if let Ok(mut tls) = connector.connect(name, sock).await {
            let _ = tls.write_all(b"x").await;
            let _ = tls.flush().await;
        }
        assert!(
            !server.await.unwrap(),
            "exit accepted a client with no certificate under require_client_auth"
        );
    }

    /// mTLS happy path with a CA-signed client certificate.
    #[tokio::test]
    async fn mtls_accepts_a_valid_client_certificate() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let pki = TestPki::new("mtls-accept");
        let server_material = TlsMaterial::load(&pki.mtls_config(), true).unwrap();
        let client_material = TlsMaterial::load(&pki.mtls_config(), false).unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = server_material.acceptor().unwrap();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(sock).await.unwrap();
            let mut buf = [0u8; 2];
            tls.read_exact(&mut buf).await.unwrap();
            tls.write_all(b"ok").await.unwrap();
            tls.flush().await.unwrap();
            true
        });

        let connector = client_material.connector();
        let sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        let name = ServerName::try_from("exit.internal").unwrap();
        let mut tls = connector.connect(name, sock).await.unwrap();
        tls.write_all(b"hi").await.unwrap();
        tls.flush().await.unwrap();
        let mut buf = [0u8; 2];
        tls.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ok");
        assert!(server.await.unwrap());
    }
}
