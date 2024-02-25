use std::io;

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
