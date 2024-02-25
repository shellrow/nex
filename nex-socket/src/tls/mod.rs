pub mod danger;

use std::io;
use std::net::TcpStream;
use std::sync::Arc;
use rustls::client::danger::DangerousClientConfig;
use rustls::{ClientConfig, ClientConnection};
use rustls::crypto::CryptoProvider;

use self::danger::NoCertificateVerification;

/// Get the native certificates from the system. return rustls::RootCertStore
pub fn get_native_certs() -> io::Result<rustls::RootCertStore> {
    let mut root_store = rustls::RootCertStore::empty();
    match rustls_native_certs::load_native_certs() {
        Ok(certs) => {
            for cert in certs {
                match root_store.add(cert) {
                    Ok(_) => {}
                    Err(_) => {},
                }
            }
            Ok(root_store)
        }
        Err(e) => return Err(e),
    }
}

/// Get the dangerous client config. Return rustls::ClientConfig
pub fn get_dangerous_client_config(
    root_store: rustls::RootCertStore,
    provider: CryptoProvider,
) -> ClientConfig {
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let mut dangerous_config: DangerousClientConfig = rustls::ClientConfig::dangerous(&mut config);
    // Disable certificate verification
    dangerous_config.set_certificate_verifier(Arc::new(NoCertificateVerification::new(provider)));
    config
}

/// Disable certificate verification
pub fn disable_certificate_verification(
    config: &mut ClientConfig,
    provider: CryptoProvider,
) {
    let mut dangerous_config: DangerousClientConfig = rustls::ClientConfig::dangerous(config);
    dangerous_config.set_certificate_verifier(Arc::new(NoCertificateVerification::new(provider)));
}

/// Get TLS Stream. Return rustls::StreamOwned<ClientConnection, TcpStream>
pub fn get_tls_stream(
    hostname: String,
    socket: TcpStream,
    config: rustls::ClientConfig,
) -> io::Result<rustls::StreamOwned<ClientConnection, TcpStream>> {
    let tls_connection: rustls::ClientConnection =
        rustls::ClientConnection::new(Arc::new(config), hostname.try_into().unwrap())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let stream = rustls::StreamOwned::new(tls_connection, socket);
    Ok(stream)
}
