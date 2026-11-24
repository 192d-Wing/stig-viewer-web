//! TLS crypto provider for outbound connections (#215).
//!
//! reqwest (webhooks, OIDC, DISA sync) and lettre (SMTP STARTTLS) both use
//! rustls' process-wide default `CryptoProvider`. This module builds that
//! provider on aws-lc-rs (the AWS-LC FIPS module in a `fips` build) and
//! installs it once at startup, so every outbound TLS connection runs on the
//! same library as the rest of `src/crypto`.
//!
//! Key exchange offers, strongest first: the `X25519MLKEM768` hybrid, pure
//! `ML-KEM-1024` (the CNSA 2.0 KEM), `X25519` (non-FIPS builds only), then
//! P-384 and P-256 for peers without a post-quantum group. `SecP384r1MLKEM1024`
//! is not in rustls 0.23. In a `fips` build the two ML-KEM groups are pending
//! validation and offered only when listed in `STIG_FIPS_PENDING_ALGS`
//! ([`crate::fips::FipsPolicy`]). TLS 1.2 stays enabled for legacy peers.
//!
//! Outbound TLS only: inbound TLS is terminated by a reverse proxy.

use std::sync::Arc;

use anyhow::{bail, Result};
use rustls::crypto::aws_lc_rs::{self as lc, kx_group};
use rustls::crypto::{CryptoProvider, SupportedKxGroup};

use crate::fips::{self, FipsPolicy, PendingAlg};

type Group = &'static dyn SupportedKxGroup;

/// Which post-quantum key-exchange groups the client offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PqOffer {
    pub hybrid_x25519_mlkem768: bool,
    pub mlkem1024: bool,
}

impl PqOffer {
    /// Follows the pending-algorithm policy: everything is offered unless a
    /// FIPS build is enforcing and the algorithm is not opted in.
    pub fn for_policy(policy: &FipsPolicy) -> Self {
        Self {
            hybrid_x25519_mlkem768: policy.permits(PendingAlg::X25519MlKem768),
            mlkem1024: policy.permits(PendingAlg::MlKem1024),
        }
    }
}

/// Key-exchange groups in preference order for `pq`.
pub fn kx_groups(pq: PqOffer) -> Vec<Group> {
    let mut v: Vec<Group> = Vec::new();
    if pq.hybrid_x25519_mlkem768 {
        v.push(kx_group::X25519MLKEM768);
    }
    if pq.mlkem1024 {
        v.push(kx_group::MLKEM1024);
    }
    if !fips::compiled() {
        v.push(kx_group::X25519);
    }
    v.push(kx_group::SECP384R1);
    v.push(kx_group::SECP256R1);
    v
}

/// The application's TLS provider: AWS-LC with the group list above.
pub fn provider(pq: PqOffer) -> CryptoProvider {
    CryptoProvider {
        kx_groups: kx_groups(pq),
        ..lc::default_provider()
    }
}

fn group_names(p: &CryptoProvider) -> Vec<String> {
    p.kx_groups
        .iter()
        .map(|g| format!("{:?}", g.name()))
        .collect()
}

/// Names of the key-exchange groups offered under `policy`, in order (recorded
/// in the `system.fips_policy` audit event).
pub fn offered_group_names(policy: &FipsPolicy) -> Vec<String> {
    group_names(&provider(PqOffer::for_policy(policy)))
}

/// FIPS self-check: a client configuration built on `provider` must report
/// `fips()`.
fn check_client_fips(provider: &CryptoProvider) -> Result<()> {
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(provider.clone()))
        .with_safe_default_protocol_versions()
        .map_err(|e| anyhow::anyhow!("TLS protocol versions: {e}"))?
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    if !cfg.fips() {
        bail!("refusing to start: the TLS client configuration is not FIPS-approved");
    }
    Ok(())
}

/// An already-installed provider is fine only if it offers the same groups.
fn reconcile_existing(wanted: &CryptoProvider, existing: &CryptoProvider) -> Result<()> {
    if group_names(existing) != group_names(wanted) {
        bail!("a different rustls CryptoProvider is already installed");
    }
    Ok(())
}

/// Install the process-wide provider for `policy`. In a `fips` build, refuses
/// unless a client configuration built on it reports `fips()`. `main` calls
/// this at startup and is authoritative; [`ensure_installed`] is only a
/// fallback for code that runs without `main` (tests).
pub fn install(policy: &FipsPolicy) -> Result<()> {
    let provider = provider(PqOffer::for_policy(policy));
    if fips::compiled() {
        check_client_fips(&provider)?;
    }
    let groups = group_names(&provider);
    if let Err(existing) = provider.clone().install_default() {
        reconcile_existing(&provider, &existing)?;
    }
    tracing::info!(kx_groups = ?groups, "outbound TLS key-exchange groups");
    Ok(())
}

/// Idempotent install for code paths that can run without `main` (tests, or
/// a client built before startup finished). Does nothing once a provider is
/// installed (`main`'s [`install`] is authoritative); otherwise installs the
/// one `STIG_FIPS_PENDING_ALGS` selects. A failure is fatal: carrying on
/// without a provider would panic later inside reqwest or lettre anyway.
pub fn ensure_installed() {
    if CryptoProvider::get_default().is_some() {
        return;
    }
    let raw = std::env::var(fips::PENDING_ALGS_ENV).ok();
    let policy = FipsPolicy::from_vars(fips::compiled(), raw.as_deref()).unwrap_or_else(|e| {
        tracing::warn!("{e:#}; offering no pending algorithms");
        FipsPolicy::from_vars(fips::compiled(), None)
            .unwrap_or_else(|e| panic!("TLS crypto provider policy: {e:#}"))
    });
    if let Err(e) = install(&policy) {
        panic!("installing the TLS crypto provider failed: {e:#}");
    }
}

/// `reqwest::Client::builder()` on the application's TLS provider. Use this
/// instead of `reqwest::Client::new()`, which panics without a provider.
pub fn http_client_builder() -> reqwest::ClientBuilder {
    ensure_installed();
    reqwest::Client::builder()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::HandshakeKind;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::time::Duration;

    const ALL: PqOffer = PqOffer {
        hybrid_x25519_mlkem768: true,
        mlkem1024: true,
    };
    const NONE: PqOffer = PqOffer {
        hybrid_x25519_mlkem768: false,
        mlkem1024: false,
    };

    fn names(pq: PqOffer) -> Vec<String> {
        kx_groups(pq)
            .iter()
            .map(|g| format!("{:?}", g.name()))
            .collect()
    }

    #[test]
    fn group_order_follows_the_offer() {
        let tail = if fips::compiled() {
            vec!["secp384r1", "secp256r1"]
        } else {
            vec!["X25519", "secp384r1", "secp256r1"]
        };
        let mut all = vec!["X25519MLKEM768", "MLKEM1024"];
        all.extend(&tail);
        assert_eq!(names(ALL), all);
        assert_eq!(names(NONE), tail);
        let mut only_1024 = vec!["MLKEM1024"];
        only_1024.extend(&tail);
        assert_eq!(
            names(PqOffer {
                hybrid_x25519_mlkem768: false,
                mlkem1024: true
            }),
            only_1024
        );
    }

    #[test]
    fn x25519_only_outside_fips_builds() {
        assert_eq!(names(ALL).iter().any(|n| n == "X25519"), !fips::compiled());
    }

    #[test]
    fn provider_fips_flag_matches_the_build() {
        assert_eq!(provider(NONE).fips(), fips::compiled());
        if fips::compiled() {
            assert!(provider(ALL).fips());
        }
    }

    #[test]
    fn offer_follows_the_pending_list() {
        let off = FipsPolicy::from_vars(true, None).unwrap();
        assert_eq!(PqOffer::for_policy(&off), NONE);
        let on = FipsPolicy::from_vars(true, Some("X25519MLKEM768,ML-KEM-1024")).unwrap();
        assert_eq!(PqOffer::for_policy(&on), ALL);
        let hybrid = FipsPolicy::from_vars(true, Some("X25519MLKEM768")).unwrap();
        assert!(PqOffer::for_policy(&hybrid).hybrid_x25519_mlkem768);
        assert!(!PqOffer::for_policy(&hybrid).mlkem1024);
        // Not enforced (non-FIPS build): everything is offered.
        let open = FipsPolicy::from_vars(false, None).unwrap();
        assert_eq!(PqOffer::for_policy(&open), ALL);
    }

    #[test]
    fn ensure_installed_is_idempotent() {
        ensure_installed();
        ensure_installed();
        assert!(CryptoProvider::get_default().is_some());
    }

    #[test]
    fn fips_self_check_accepts_only_fips_providers() {
        // The build's own provider passes exactly in a fips build.
        assert_eq!(check_client_fips(&provider(NONE)).is_ok(), fips::compiled());
        // X25519 is not approved, so a provider offering it is refused.
        let mut p = provider(NONE);
        p.kx_groups.insert(0, kx_group::X25519);
        let e = check_client_fips(&p).unwrap_err().to_string();
        assert!(e.contains("not FIPS-approved"), "{e}");
    }

    #[test]
    fn a_different_installed_provider_is_refused() {
        reconcile_existing(&provider(NONE), &provider(NONE)).unwrap();
        let e = reconcile_existing(&provider(NONE), &provider(ALL))
            .unwrap_err()
            .to_string();
        assert!(e.contains("already installed"), "{e}");
    }

    #[test]
    fn offered_group_names_follow_the_policy() {
        let off = FipsPolicy::from_vars(true, None).unwrap();
        let names = offered_group_names(&off);
        let first = if fips::compiled() {
            "secp384r1"
        } else {
            "X25519"
        };
        assert_eq!(names.first().map(String::as_str), Some(first));
        let on = FipsPolicy::from_vars(true, Some("X25519MLKEM768")).unwrap();
        assert_eq!(
            offered_group_names(&on).first().map(String::as_str),
            Some("X25519MLKEM768")
        );
    }

    #[test]
    fn install_self_check_accepts_the_build_provider() {
        let policy = FipsPolicy::from_vars(fips::compiled(), None).unwrap();
        // Already installed by another test is fine: same group list.
        install(&policy).unwrap();
    }

    /// Runtime-generated self-signed cert for `localhost`.
    fn test_cert() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        (
            CertificateDer::from(ck.cert.der().to_vec()),
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der())),
        )
    }

    fn server_config(
        groups: Vec<Group>,
        cert: CertificateDer<'static>,
        key: PrivateKeyDer<'static>,
    ) -> Arc<rustls::ServerConfig> {
        let p = CryptoProvider {
            kx_groups: groups,
            ..lc::default_provider()
        };
        Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(p))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![cert], key)
                .unwrap(),
        )
    }

    type Negotiated = Result<(Option<String>, Option<HandshakeKind>), String>;

    /// Serve one connection; `serve` runs the application protocol over TLS.
    fn spawn_tls_server(
        cfg: Arc<rustls::ServerConfig>,
        pre_tls: impl FnOnce(&mut TcpStream) + Send + 'static,
        app: impl FnOnce(&mut dyn ReadWrite) + Send + 'static,
    ) -> (SocketAddr, std::thread::JoinHandle<Negotiated>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let h = std::thread::spawn(move || {
            let (mut tcp, _) = l.accept().map_err(|e| e.to_string())?;
            let _ = tcp.set_read_timeout(Some(Duration::from_secs(10)));
            pre_tls(&mut tcp);
            let mut conn = rustls::ServerConnection::new(cfg).map_err(|e| e.to_string())?;
            let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
            // Drives the handshake; an incompatible peer fails here.
            tls.flush().map_err(|e| format!("handshake: {e}"))?;
            while tls.conn.is_handshaking() {
                tls.conn
                    .complete_io(tls.sock)
                    .map_err(|e| format!("handshake: {e}"))?;
            }
            app(&mut tls);
            tls.conn.send_close_notify();
            let _ = tls.conn.complete_io(tls.sock);
            let g = conn
                .negotiated_key_exchange_group()
                .map(|g| format!("{:?}", g.name()));
            Ok((g, conn.handshake_kind()))
        });
        (addr, h)
    }

    trait ReadWrite: Read + Write {}
    impl<T: Read + Write> ReadWrite for T {}

    fn http_app(s: &mut dyn ReadWrite) {
        let mut buf = [0u8; 2048];
        let _ = s.read(&mut buf);
        let _ = s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok");
    }

    /// Client result (status or error) and the server's view.
    async fn https_get(server_groups: Vec<Group>) -> (Result<u16, String>, Negotiated) {
        let (cert, key) = test_cert();
        let cfg = server_config(server_groups, cert.clone(), key);
        let (addr, h) = spawn_tls_server(cfg, |_| {}, http_app);
        let client = http_client_builder()
            .add_root_certificate(reqwest::Certificate::from_der(&cert).unwrap())
            .resolve("localhost", addr)
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        let r = client
            .get(format!("https://localhost:{}/", addr.port()))
            .send()
            .await
            .map(|r| r.status().as_u16())
            .map_err(|e| format!("{e:?}"));
        let server = tokio::task::spawn_blocking(move || h.join().unwrap())
            .await
            .unwrap();
        (r, server)
    }

    #[tokio::test]
    async fn hybrid_only_server_negotiates_the_hybrid_when_offered() {
        let (client, server) = https_get(vec![kx_group::X25519MLKEM768]).await;
        if PqOffer::for_policy(&current_policy()).hybrid_x25519_mlkem768 {
            assert_eq!(client, Ok(200));
            let (g, kind) = server.unwrap();
            assert_eq!(g.as_deref(), Some("X25519MLKEM768"));
            assert_eq!(kind, Some(HandshakeKind::Full));
        } else {
            // FIPS build without the opt-in: no hybrid in the ClientHello.
            assert!(client.is_err());
            assert!(server.is_err());
        }
    }

    fn current_policy() -> FipsPolicy {
        let raw = std::env::var(fips::PENDING_ALGS_ENV).ok();
        FipsPolicy::from_vars(fips::compiled(), raw.as_deref())
            .unwrap_or_else(|_| FipsPolicy::from_vars(fips::compiled(), None).unwrap())
    }

    #[tokio::test]
    async fn mlkem1024_only_server_needs_a_retry_but_works_when_offered() {
        let (client, server) = https_get(vec![kx_group::MLKEM1024]).await;
        if PqOffer::for_policy(&current_policy()).mlkem1024 {
            assert_eq!(client, Ok(200));
            let (g, kind) = server.unwrap();
            assert_eq!(g.as_deref(), Some("MLKEM1024"));
            assert_eq!(kind, Some(HandshakeKind::FullWithHelloRetryRequest));
        } else {
            assert!(client.is_err());
        }
    }

    #[tokio::test]
    async fn p384_only_server_works_after_a_retry() {
        let (client, server) = https_get(vec![kx_group::SECP384R1]).await;
        assert_eq!(client, Ok(200));
        let (g, kind) = server.unwrap();
        assert_eq!(g.as_deref(), Some("secp384r1"));
        // The first key share is a post-quantum group when one is offered, so
        // the server must ask for P-384; with none offered P-384 goes first.
        let pq_first = PqOffer::for_policy(&current_policy()) != NONE;
        let expected = if pq_first {
            HandshakeKind::FullWithHelloRetryRequest
        } else {
            HandshakeKind::Full
        };
        assert_eq!(kind, Some(expected));
    }

    #[tokio::test]
    async fn x25519_only_server_works_outside_fips_and_fails_in_fips() {
        let (client, server) = https_get(vec![kx_group::X25519]).await;
        if fips::compiled() {
            assert!(client.is_err());
            assert!(server.unwrap_err().contains("NoKxGroupsInCommon"));
        } else {
            assert_eq!(client, Ok(200));
            assert_eq!(server.unwrap().0.as_deref(), Some("X25519"));
        }
    }

    /// lettre STARTTLS against a fake SMTP server: the upgrade uses the
    /// installed provider and its group list.
    #[test]
    fn smtp_starttls_uses_the_installed_provider() {
        use lettre::transport::smtp::client::{Certificate, Tls, TlsParameters};
        use lettre::SmtpTransport;

        ensure_installed();
        let offered = PqOffer::for_policy(&current_policy());
        let server_group: Group = if offered.hybrid_x25519_mlkem768 {
            kx_group::X25519MLKEM768
        } else {
            kx_group::SECP384R1
        };
        let expect = if offered.hybrid_x25519_mlkem768 {
            "X25519MLKEM768"
        } else {
            "secp384r1"
        };
        // The installed provider leads with the group this test expects: the
        // P-384 fallback when no PQ group is offered (a fips build with an
        // empty pending list), the hybrid otherwise.
        let installed = CryptoProvider::get_default().unwrap();
        assert_eq!(format!("{:?}", installed.kx_groups[0].name()), expect);
        let (cert, key) = test_cert();
        let cfg = server_config(vec![server_group], cert.clone(), key);
        let (addr, h) = spawn_tls_server(
            cfg,
            |tcp| {
                tcp.write_all(b"220 fake smtp\r\n").unwrap();
                let mut r = BufReader::new(tcp.try_clone().unwrap());
                let mut line = String::new();
                r.read_line(&mut line).unwrap(); // EHLO
                tcp.write_all(b"250-localhost\r\n250 STARTTLS\r\n").unwrap();
                line.clear();
                r.read_line(&mut line).unwrap(); // STARTTLS
                tcp.write_all(b"220 go ahead\r\n").unwrap();
            },
            |tls| {
                let mut r = BufReader::new(tls);
                let mut line = String::new();
                loop {
                    line.clear();
                    if r.read_line(&mut line).unwrap_or(0) == 0 {
                        break;
                    }
                    let reply: &[u8] = if line.starts_with("QUIT") {
                        b"221 bye\r\n"
                    } else {
                        b"250 localhost\r\n"
                    };
                    let _ = r.get_mut().write_all(reply);
                    if line.starts_with("QUIT") {
                        break;
                    }
                }
            },
        );
        let params = TlsParameters::builder("localhost".to_string())
            .add_root_certificate(Certificate::from_der(cert.as_ref().to_vec()).unwrap())
            .build_rustls()
            .unwrap();
        let t = SmtpTransport::builder_dangerous("localhost")
            .port(addr.port())
            .tls(Tls::Required(params))
            .timeout(Some(Duration::from_secs(10)))
            .build();
        assert!(t.test_connection().unwrap());
        let (g, _) = h.join().unwrap().unwrap();
        assert_eq!(g.as_deref(), Some(expect));
    }
}
