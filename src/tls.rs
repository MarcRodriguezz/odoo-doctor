//! TLS helpers: inspecting certificates we do not trust yet, and connecting to Postgres.
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use std::io::Write;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Once};
use std::time::Duration;

pub fn install_crypto() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Accepts any certificate. Used only to read a certificate's dates, and for Postgres
/// `sslmode=require`, which by libpq's definition encrypts without verifying identity.
#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn roots() -> rustls::RootCertStore {
    rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    }
}

pub fn verified_config() -> ClientConfig {
    install_crypto();
    ClientConfig::builder()
        .with_root_certificates(roots())
        .with_no_client_auth()
}

pub fn unverified_config() -> ClientConfig {
    install_crypto();
    ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth()
}

#[derive(Debug, Clone)]
pub struct CertInfo {
    pub days_left: i64,
    pub subject: String,
}

/// Tries every address of a host. `localhost` often resolves to IPv6 first, while the service
/// listens only on IPv4.
pub fn connect(host: &str, port: u16, timeout: Duration) -> Result<TcpStream, String> {
    let addresses = (host, port).to_socket_addrs().map_err(|e| e.to_string())?;
    let mut last_error = "no address".to_string();
    for address in addresses {
        match TcpStream::connect_timeout(&address, timeout) {
            Ok(stream) => return Ok(stream),
            Err(e) => last_error = e.to_string(),
        }
    }
    Err(last_error)
}

/// Reads the certificate a server presents, whether or not we trust it.
pub fn peer_certificate(host: &str, port: u16) -> Result<CertInfo, String> {
    install_crypto();
    let name = ServerName::try_from(host.to_string()).map_err(|e| e.to_string())?;
    let mut client = rustls::ClientConnection::new(Arc::new(unverified_config()), name)
        .map_err(|e| e.to_string())?;
    let mut tcp = connect(host, port, Duration::from_secs(5))?;
    tcp.set_read_timeout(Some(Duration::from_secs(5))).ok();
    tcp.set_write_timeout(Some(Duration::from_secs(5))).ok();
    while client.is_handshaking() {
        client.complete_io(&mut tcp).map_err(|e| e.to_string())?;
    }
    let _ = tcp.flush();
    let certs = client.peer_certificates().ok_or("no certificate")?;
    let first = certs.first().ok_or("no certificate")?;
    let (_, cert) =
        x509_parser::parse_x509_certificate(first.as_ref()).map_err(|e| e.to_string())?;
    let not_after = cert.validity().not_after.timestamp();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    Ok(CertInfo {
        days_left: (not_after - now) / 86_400,
        subject: cert.subject().to_string(),
    })
}
