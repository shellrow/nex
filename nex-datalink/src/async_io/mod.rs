//! Asynchronous data link layer I/O operations.

#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod linux;

#[cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "illumos",
    target_os = "solaris",
    target_os = "macos",
    target_os = "ios",
))]
pub mod bpf;

#[cfg(windows)]
pub mod wpcap;

use std::io;
use std::task::{Context, Poll};

use futures_core::stream::Stream;

use crate::Config;

/// Trait for asynchronously sending raw packets.
pub trait AsyncRawSender: Send {
    /// Attempt to send a packet asynchronously.
    ///
    /// The method returns `Poll::Ready` once the packet has been
    /// transmitted or an error has occurred. If the socket is not
    /// currently writable, it will return `Poll::Pending` and arrange for
    /// the current task to be woken once progress can be made.
    fn poll_send(&mut self, cx: &mut Context<'_>, packet: &[u8]) -> Poll<io::Result<()>>;
}

/// Trait for asynchronously receiving raw packets.
///
/// This is implemented for any type implementing [`Stream`] with
/// `Item = io::Result<Vec<u8>>`.
pub trait AsyncRawReceiver: Stream<Item = io::Result<Vec<u8>>> + Send + Unpin {}

impl<T> AsyncRawReceiver for T where T: Stream<Item = io::Result<Vec<u8>>> + Send + Unpin {}

/// An asynchronous channel for sending and receiving at the data link layer.
#[non_exhaustive]
pub enum AsyncChannel {
    /// An asynchronous datalink channel which sends and receives Ethernet packets.
    Ethernet(Box<dyn AsyncRawSender>, Box<dyn AsyncRawReceiver>),
}

/// Creates a new asynchronous datalink channel for sending and receiving raw packets.
#[inline]
pub fn async_channel(
    network_interface: &nex_core::interface::Interface,
    configuration: Config,
) -> io::Result<AsyncChannel> {
    #[cfg(all(any(target_os = "linux", target_os = "android")))]
    {
        linux::channel(network_interface, configuration)
    }
    #[cfg(all(any(
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "illumos",
        target_os = "solaris",
        target_os = "macos",
        target_os = "ios",
    )))]
    {
        bpf::channel(network_interface, configuration)
    }
    #[cfg(windows)]
    {
        wpcap::channel(network_interface, configuration)
    }
}
