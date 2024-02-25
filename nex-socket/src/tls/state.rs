#[derive(Debug)]
pub enum TlsState {
    #[cfg(feature = "early-data")]
    EarlyData(usize, Vec<u8>),
    Stream,
    ReadShutdown,
    WriteShutdown,
    FullyShutdown,
}

impl TlsState {
    #[inline]
    pub fn shutdown_read(&mut self) {
        match *self {
            TlsState::WriteShutdown | TlsState::FullyShutdown => *self = TlsState::FullyShutdown,
            _ => *self = TlsState::ReadShutdown,
        }
    }

    #[inline]
    pub fn shutdown_write(&mut self) {
        match *self {
            TlsState::ReadShutdown | TlsState::FullyShutdown => *self = TlsState::FullyShutdown,
            _ => *self = TlsState::WriteShutdown,
        }
    }

    #[inline]
    pub fn writeable(&self) -> bool {
        !matches!(*self, TlsState::WriteShutdown | TlsState::FullyShutdown)
    }

    #[inline]
    pub fn readable(&self) -> bool {
        !matches!(*self, TlsState::ReadShutdown | TlsState::FullyShutdown)
    }

    #[inline]
    #[cfg(feature = "early-data")]
    pub fn is_early_data(&self) -> bool {
        matches!(self, TlsState::EarlyData(..))
    }

    #[inline]
    #[cfg(not(feature = "early-data"))]
    pub const fn is_early_data(&self) -> bool {
        false
    }
}
