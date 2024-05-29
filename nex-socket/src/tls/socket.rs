use super::client;
use super::server;
use super::session::MidHandshake;
use super::state;
use super::stream::{SyncReadAdapter, SyncWriteAdapter};

use futures_io::{AsyncRead, AsyncWrite};
use rustls::ConnectionCommon;
use rustls::{ClientConfig, ClientConnection, CommonState, ServerConfig, ServerConnection};
use rustls::server::AcceptedAlert;
use state::TlsState;
use std::future::Future;
use std::io;
use std::net::TcpStream;
use std::ops::Deref;
use std::ops::DerefMut;
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, RawSocket};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use super::pki_types;

/// Get TLS Client. Return rustls::StreamOwned<ClientConnection, TcpStream>
fn get_tls_client(
    hostname: String,
    socket: TcpStream,
    config: ClientConfig,
) -> io::Result<rustls::StreamOwned<ClientConnection, TcpStream>> {
    let server_name = match pki_types::ServerName::try_from(hostname) {
        Ok(s) => s,
        Err(e) => return Err(io::Error::new(io::ErrorKind::Other, e)),
    };
    let tls_connection: rustls::ClientConnection =
        rustls::ClientConnection::new(Arc::new(config), server_name)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let stream = rustls::StreamOwned::new(tls_connection, socket);
    Ok(stream)
}

/// Get TLS Server. Return rustls::StreamOwned<ServerConnection, TcpStream>
fn get_tls_server(
    socket: TcpStream,
    config: ServerConfig,
) -> io::Result<rustls::StreamOwned<ServerConnection, TcpStream>> {
    let tls_connection: rustls::ServerConnection = rustls::ServerConnection::new(Arc::new(config))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let stream = rustls::StreamOwned::new(tls_connection, socket);
    Ok(stream)
}

pub struct TlsStream<C, T, S>
where
    C: DerefMut + Deref<Target = ConnectionCommon<S>>,
    T: io::Read + io::Write,
{
    pub(crate) stream: rustls::StreamOwned<C, T>,
}

impl<C, T, S> io::Read for TlsStream<C, T, S>
where
    C: DerefMut + Deref<Target = ConnectionCommon<S>>,
    T: io::Read + io::Write,
{
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.sock.read(buf)
    }
}

impl<C, T, S> io::Write for TlsStream<C, T, S>
where
    C: DerefMut + Deref<Target = ConnectionCommon<S>>,
    T: io::Read + io::Write,
{
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.sock.write(buf)
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        self.stream.sock.flush()
    }
}

impl<C, T, S> TlsStream<C, T, S>
where
    C: DerefMut + Deref<Target = ConnectionCommon<S>>,
    T: io::Read + io::Write,
{
    pub fn new(stream: rustls::StreamOwned<C, T>) -> TlsStream<C, T, S> {
        TlsStream { stream }
    }
}

/// Wrapper around a `rustls::StreamOwned<ClientConnection, TcpStream>`
pub struct TlsClient {
    pub(crate) stream: rustls::StreamOwned<ClientConnection, TcpStream>,
}

impl io::Read for TlsClient {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buf)
    }
}

impl io::Write for TlsClient {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.write(buf)
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

impl TlsClient {
    pub fn new(hostname: String, socket: TcpStream, config: ClientConfig) -> io::Result<TlsClient> {
        match get_tls_client(hostname, socket, config) {
            Ok(stream) => Ok(TlsClient { stream }),
            Err(e) => Err(e),
        }
    }
}

/// Wrapper around a `rustls::StreamOwned<ServerConnection, TcpStream>`
pub struct TlsServer {
    pub(crate) stream: rustls::StreamOwned<ServerConnection, TcpStream>,
}

impl io::Read for TlsServer {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buf)
    }
}

impl io::Write for TlsServer {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.write(buf)
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

impl TlsServer {
    pub fn new(socket: TcpStream, config: ServerConfig) -> io::Result<TlsServer> {
        match get_tls_server(socket, config) {
            Ok(stream) => Ok(TlsServer { stream }),
            Err(e) => Err(e),
        }
    }
}

/// Async TLS connector.
/// A wrapper around a `rustls::ClientConfig`
#[derive(Clone)]
pub struct AsyncTlsConnector {
    inner: Arc<ClientConfig>,
    #[cfg(feature = "early-data")]
    early_data: bool,
}
/// Async TLS acceptor.
/// A wrapper around a `rustls::ServerConfig`
#[derive(Clone)]
pub struct AsyncTlsAcceptor {
    inner: Arc<ServerConfig>,
}

impl From<Arc<ClientConfig>> for AsyncTlsConnector {
    fn from(inner: Arc<ClientConfig>) -> AsyncTlsConnector {
        AsyncTlsConnector {
            inner,
            #[cfg(feature = "early-data")]
            early_data: false,
        }
    }
}

impl From<Arc<ServerConfig>> for AsyncTlsAcceptor {
    fn from(inner: Arc<ServerConfig>) -> AsyncTlsAcceptor {
        AsyncTlsAcceptor { inner }
    }
}

impl AsyncTlsConnector {
    #[cfg(feature = "early-data")]
    pub fn early_data(mut self, flag: bool) -> TlsConnector {
        self.early_data = flag;
        self
    }

    #[inline]
    pub fn connect<IO>(
        &self,
        server_name: pki_types::ServerName<'static>,
        stream: IO,
    ) -> Connect<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        self.connect_with(server_name, stream, |_| ())
    }

    pub fn connect_with<IO, F>(
        &self,
        server_name: pki_types::ServerName<'static>,
        stream: IO,
        f: F,
    ) -> Connect<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
        F: FnOnce(&mut ClientConnection),
    {
        let mut session = match ClientConnection::new(self.inner.clone(), server_name) {
            Ok(session) => session,
            Err(error) => {
                return Connect(MidHandshake::Error {
                    io: stream,
                    error: io::Error::new(io::ErrorKind::Other, error),
                });
            }
        };
        f(&mut session);

        Connect(MidHandshake::Handshaking(client::TlsStream {
            io: stream,

            #[cfg(not(feature = "early-data"))]
            state: TlsState::Stream,

            #[cfg(feature = "early-data")]
            state: if self.early_data && session.early_data().is_some() {
                TlsState::EarlyData(0, Vec::new())
            } else {
                TlsState::Stream
            },

            #[cfg(feature = "early-data")]
            early_waker: None,

            session,
        }))
    }
}

impl AsyncTlsAcceptor {
    #[inline]
    pub fn accept<IO>(&self, stream: IO) -> Accept<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        self.accept_with(stream, |_| ())
    }

    pub fn accept_with<IO, F>(&self, stream: IO, f: F) -> Accept<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
        F: FnOnce(&mut ServerConnection),
    {
        let mut session = match ServerConnection::new(self.inner.clone()) {
            Ok(session) => session,
            Err(error) => {
                return Accept(MidHandshake::Error {
                    io: stream,
                    error: io::Error::new(io::ErrorKind::Other, error),
                });
            }
        };
        f(&mut session);

        Accept(MidHandshake::Handshaking(server::TlsStream {
            session,
            io: stream,
            state: TlsState::Stream,
        }))
    }
}

pub struct LazyConfigAcceptor<IO> {
    acceptor: rustls::server::Acceptor,
    io: Option<IO>,
    alert: Option<(rustls::Error, AcceptedAlert)>,
}

impl<IO> LazyConfigAcceptor<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    #[inline]
    pub fn new(acceptor: rustls::server::Acceptor, io: IO) -> Self {
        Self {
            acceptor,
            io: Some(io),
            alert: None,
        }
    }
}

impl<IO> Future for LazyConfigAcceptor<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    type Output = Result<StartHandshake<IO>, io::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        loop {
            let io = match this.io.as_mut() {
                Some(io) => io,
                None => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::Other,
                        "acceptor cannot be polled after acceptance",
                    )))
                }
            };

            if let Some((err, mut alert)) = this.alert.take() {
                match alert.write(&mut SyncWriteAdapter { io, cx }) {
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        this.alert = Some((err, alert));
                        return Poll::Pending;
                    }
                    Ok(0) | Err(_) => {
                        return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, err)))
                    }
                    Ok(_) => {
                        this.alert = Some((err, alert));
                        continue;
                    }
                };
            }

            let mut reader = SyncReadAdapter { io, cx };
            match this.acceptor.read_tls(&mut reader) {
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()).into(),
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
                Err(e) => return Err(e).into(),
            }

            match this.acceptor.accept() {
                Ok(Some(accepted)) => {
                    let io = this.io.take().unwrap();
                    return Poll::Ready(Ok(StartHandshake { accepted, io }));
                }
                Ok(None) => {}
                Err((err, alert)) => {
                    this.alert = Some((err, alert));
                }
            }
        }
    }
}

pub struct StartHandshake<IO> {
    accepted: rustls::server::Accepted,
    io: IO,
}

impl<IO> StartHandshake<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    pub fn client_hello(&self) -> rustls::server::ClientHello<'_> {
        self.accepted.client_hello()
    }

    pub fn into_stream(self, config: Arc<ServerConfig>) -> Accept<IO> {
        self.into_stream_with(config, |_| ())
    }

    pub fn into_stream_with<F>(self, config: Arc<ServerConfig>, f: F) -> Accept<IO>
    where
        F: FnOnce(&mut ServerConnection),
    {
        let mut conn = match self.accepted.into_connection(config) {
            Ok(conn) => conn,
            Err((error, alert)) => {
                return Accept(MidHandshake::SendAlert {
                    io: self.io,
                    error: io::Error::new(io::ErrorKind::Other, error),
                    alert,
                });
            }
        };
        f(&mut conn);

        Accept(MidHandshake::Handshaking(server::TlsStream {
            session: conn,
            io: self.io,
            state: TlsState::Stream,
        }))
    }
}

/// Future returned from `TlsConnector::connect` which will resolve
/// once the connection handshake has finished.
pub struct Connect<IO>(MidHandshake<client::TlsStream<IO>>);

/// Future returned from `TlsAcceptor::accept` which will resolve
/// once the accept handshake has finished.
pub struct Accept<IO>(MidHandshake<server::TlsStream<IO>>);

/// Connect future that resolves to a `TlsStream` on success.
/// If the handshake fails, the IO is returned.
pub struct FallibleConnect<IO>(MidHandshake<client::TlsStream<IO>>);

/// Accept future that resolves to a `TlsStream` on success.
/// If the handshake fails, the IO is returned.
pub struct FallibleAccept<IO>(MidHandshake<server::TlsStream<IO>>);

impl<IO> Connect<IO> {
    #[inline]
    pub fn into_fallible(self) -> FallibleConnect<IO> {
        FallibleConnect(self.0)
    }
}

impl<IO> Accept<IO> {
    #[inline]
    pub fn into_fallible(self) -> FallibleAccept<IO> {
        FallibleAccept(self.0)
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Future for Connect<IO> {
    type Output = io::Result<client::TlsStream<IO>>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx).map_err(|(err, _)| err)
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Future for Accept<IO> {
    type Output = io::Result<server::TlsStream<IO>>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx).map_err(|(err, _)| err)
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Future for FallibleConnect<IO> {
    type Output = Result<client::TlsStream<IO>, (io::Error, IO)>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx)
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Future for FallibleAccept<IO> {
    type Output = Result<server::TlsStream<IO>, (io::Error, IO)>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx)
    }
}

/// Abstructed TLS stream.
///
/// Abstruction over the different types of TLS streams that can be created by
/// the `TlsConnector` and `TlsAcceptor`.
#[derive(Debug)]
pub enum AsyncTlsStream<T> {
    Client(client::TlsStream<T>),
    Server(server::TlsStream<T>),
}

impl<T> AsyncTlsStream<T> {
    pub fn get_ref(&self) -> (&T, &CommonState) {
        use AsyncTlsStream::*;
        match self {
            Client(io) => {
                let (io, session) = io.get_ref();
                (io, &*session)
            }
            Server(io) => {
                let (io, session) = io.get_ref();
                (io, &*session)
            }
        }
    }

    pub fn get_mut(&mut self) -> (&mut T, &mut CommonState) {
        use AsyncTlsStream::*;
        match self {
            Client(io) => {
                let (io, session) = io.get_mut();
                (io, &mut *session)
            }
            Server(io) => {
                let (io, session) = io.get_mut();
                (io, &mut *session)
            }
        }
    }
}

impl<T> From<client::TlsStream<T>> for AsyncTlsStream<T> {
    fn from(s: client::TlsStream<T>) -> Self {
        Self::Client(s)
    }
}

impl<T> From<server::TlsStream<T>> for AsyncTlsStream<T> {
    fn from(s: server::TlsStream<T>) -> Self {
        Self::Server(s)
    }
}

#[cfg(unix)]
impl<S> AsRawFd for AsyncTlsStream<S>
where
    S: AsRawFd,
{
    fn as_raw_fd(&self) -> RawFd {
        self.get_ref().0.as_raw_fd()
    }
}

#[cfg(windows)]
impl<S> AsRawSocket for AsyncTlsStream<S>
where
    S: AsRawSocket,
{
    fn as_raw_socket(&self) -> RawSocket {
        self.get_ref().0.as_raw_socket()
    }
}

impl<T> AsyncRead for AsyncTlsStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            AsyncTlsStream::Client(x) => Pin::new(x).poll_read(cx, buf),
            AsyncTlsStream::Server(x) => Pin::new(x).poll_read(cx, buf),
        }
    }
}

impl<T> AsyncWrite for AsyncTlsStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            AsyncTlsStream::Client(x) => Pin::new(x).poll_write(cx, buf),
            AsyncTlsStream::Server(x) => Pin::new(x).poll_write(cx, buf),
        }
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            AsyncTlsStream::Client(x) => Pin::new(x).poll_flush(cx),
            AsyncTlsStream::Server(x) => Pin::new(x).poll_flush(cx),
        }
    }

    #[inline]
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            AsyncTlsStream::Client(x) => Pin::new(x).poll_close(cx),
            AsyncTlsStream::Server(x) => Pin::new(x).poll_close(cx),
        }
    }
}
