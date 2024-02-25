use rustls::client::danger::{
    DangerousClientConfig, HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::ClientConfig;
use rustls::DigitallySignedStruct;
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use std::sync::Arc;

/// A certificate verifier that does not perform any verification.
#[derive(Debug, Clone)]
pub struct NoCertificateVerification(CryptoProvider);

impl NoCertificateVerification {
    pub fn new(provider: CryptoProvider) -> Self {
        Self(provider)
    }
}

impl ServerCertVerifier for NoCertificateVerification {
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
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
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
pub fn disable_certificate_verification(config: &mut ClientConfig, provider: CryptoProvider) {
    let mut dangerous_config: DangerousClientConfig = rustls::ClientConfig::dangerous(config);
    dangerous_config.set_certificate_verifier(Arc::new(NoCertificateVerification::new(provider)));
}
