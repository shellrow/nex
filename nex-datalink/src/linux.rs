//! Support for sending and receiving data link layer packets using Linux's `AF_PACKET`.

extern crate libc;

use crate::bindings::linux;
use crate::{RawReceiver, RawSender};
use nex_core::interface::Interface;
use nex_core::mac::MacAddr;
use std::io;
use std::mem;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn network_addr_to_sockaddr(
    ni: &Interface,
    storage: *mut libc::sockaddr_storage,
    proto: libc::c_int,
) -> usize {
    // SAFETY: `storage` points to writable `sockaddr_storage`, whose size and
    // alignment are sufficient for `sockaddr_ll`; the pointer is used only
    // during this call.
    unsafe {
        let sll: *mut libc::sockaddr_ll = mem::transmute(storage);
        (*sll).sll_family = libc::AF_PACKET as libc::sa_family_t;
        if let Some(MacAddr(a, b, c, d, e, f)) = ni.mac_addr {
            (*sll).sll_addr = [a, b, c, d, e, f, 0, 0];
        }
        (*sll).sll_protocol = (proto as u16).to_be();
        (*sll).sll_halen = 6;
        (*sll).sll_ifindex = ni.index as i32;
        mem::size_of::<libc::sockaddr_ll>()
    }
}

/// Configuration for the Linux datalink backend.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct Config {
    /// The size of buffer to use when writing packets. Defaults to 4096.
    pub write_buffer_size: usize,

    /// The size of buffer to use when reading packets. Defaults to 4096.
    pub read_buffer_size: usize,

    /// The read timeout. Defaults to None.
    pub read_timeout: Option<Duration>,

    /// The write timeout. Defaults to None.
    pub write_timeout: Option<Duration>,

    /// Selects the socket mode: datalink (Layer2) or network (Layer3).
    /// This setting is only consulted when the socket is created.
    /// Defaults to Layer2.
    pub channel_type: super::ChannelType,

    /// Specifies packet fanout option, if desired. Defaults to None.
    pub fanout: Option<super::FanoutOption>,

    /// Promiscuous mode.
    pub promiscuous: bool,

    pub suppress_loopback_duplicates: bool,
}

#[inline]
fn poll_timeout_ms(timeout: Option<libc::timespec>) -> libc::c_int {
    timeout
        .map(|to| {
            let ms = i128::from(to.tv_sec) * 1000 + i128::from(to.tv_nsec) / 1_000_000;
            ms.clamp(i128::from(libc::c_int::MIN), i128::from(libc::c_int::MAX)) as libc::c_int
        })
        .unwrap_or(-1)
}

impl From<&super::Config> for Config {
    fn from(config: &super::Config) -> Config {
        Config {
            write_buffer_size: config.write_buffer_size,
            read_buffer_size: config.read_buffer_size,
            channel_type: config.channel_type,
            read_timeout: config.read_timeout,
            write_timeout: config.write_timeout,
            fanout: config.linux_fanout,
            promiscuous: config.promiscuous,
            suppress_loopback_duplicates: config.linux_suppress_loopback_duplicates,
        }
    }
}

impl Default for Config {
    fn default() -> Config {
        Config {
            write_buffer_size: 4096,
            read_buffer_size: 4096,
            read_timeout: None,
            write_timeout: None,
            channel_type: super::ChannelType::Layer2,
            fanout: None,
            promiscuous: true,
            suppress_loopback_duplicates: false,
        }
    }
}

/// Create a data link channel using the Linux's `AF_PACKET` socket type.
#[inline]
pub(crate) fn channel(network_interface: &Interface, config: Config) -> io::Result<super::Channel> {
    let eth_p_all = 0x0003;
    let (typ, proto) = match config.channel_type {
        super::ChannelType::Layer2 => (libc::SOCK_RAW, eth_p_all),
        super::ChannelType::Layer3(proto) => (libc::SOCK_DGRAM, proto),
    };
    // SAFETY: `socket` receives only valid AF_PACKET domain/type/protocol
    // integer values and retains no borrowed pointers.
    let raw_socket = unsafe { libc::socket(libc::AF_PACKET, typ, proto.to_be() as i32) };
    if raw_socket == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw_socket` was just created and exclusive ownership is
    // transferred exactly once to this guard.
    let socket = unsafe { nex_sys::FileDesc::from_raw(raw_socket) };
    // SAFETY: A zero bit pattern is a valid initial socket address storage.
    let mut addr: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let len = network_addr_to_sockaddr(network_interface, &mut addr, proto as i32);

    let send_addr = (&addr as *const libc::sockaddr_storage) as *const libc::sockaddr;

    // Bind to interface
    // SAFETY: `send_addr` points into live address storage and `len` is the
    // initialized sockaddr_ll size.
    if unsafe { libc::bind(socket.as_raw(), send_addr, len as libc::socklen_t) } == -1 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: A zero bit pattern is a valid initial packet membership request.
    let mut pmr: linux::packet_mreq = unsafe { mem::zeroed() };
    pmr.mr_ifindex = network_interface.index as i32;
    pmr.mr_type = linux::PACKET_MR_PROMISC as u16;

    // Enable promiscuous capture
    if config.promiscuous {
        // SAFETY: The descriptor is open and `pmr` remains readable with the
        // exact length supplied for the duration of setsockopt.
        if unsafe {
            libc::setsockopt(
                socket.as_raw(),
                linux::SOL_PACKET,
                linux::PACKET_ADD_MEMBERSHIP,
                (&pmr as *const linux::packet_mreq) as *const libc::c_void,
                mem::size_of::<linux::packet_mreq>() as libc::socklen_t,
            )
        } == -1
        {
            return Err(io::Error::last_os_error());
        }
    }

    // Enable packet fanout
    if let Some(fanout) = config.fanout {
        use super::FanoutType;
        let mut typ = match fanout.fanout_type {
            FanoutType::Hash => linux::PACKET_FANOUT_HASH,
            FanoutType::LoadBalance => linux::PACKET_FANOUT_LB,
            FanoutType::Cpu => linux::PACKET_FANOUT_CPU,
            FanoutType::Rollover => linux::PACKET_FANOUT_ROLLOVER,
            FanoutType::Random => linux::PACKET_FANOUT_RND,
            FanoutType::QueueMapping => linux::PACKET_FANOUT_QM,
            FanoutType::ClassicBpf => linux::PACKET_FANOUT_CBPF,
            FanoutType::ExtendedBpf => linux::PACKET_FANOUT_EBPF,
        } as u32;
        // set defrag flag
        if fanout.defrag {
            typ |= linux::PACKET_FANOUT_FLAG_DEFRAG;
        }
        // set rollover flag
        if fanout.rollover {
            typ |= linux::PACKET_FANOUT_FLAG_ROLLOVER;
        }
        // set uniqueid flag -- probably not needed atm.
        // PACKET_FANOUT_FLAG_UNIQUEID
        // https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=4a69a864209e9ab436d4a58e8028ac96cc873d15
        let arg: libc::c_uint = fanout.group_id as u32 | (typ << 16);

        // SAFETY: The descriptor is open and `arg` remains readable with the
        // exact length supplied for the duration of setsockopt.
        if unsafe {
            libc::setsockopt(
                socket.as_raw(),
                linux::SOL_PACKET,
                linux::PACKET_FANOUT,
                (&arg as *const libc::c_uint) as *const libc::c_void,
                mem::size_of::<libc::c_uint>() as libc::socklen_t,
            )
        } == -1
        {
            return Err(io::Error::last_os_error());
        }
    }

    // Enable nonblocking
    // SAFETY: The descriptor is open and F_SETFL retains no borrowed pointers.
    if unsafe { libc::fcntl(socket.as_raw(), libc::F_SETFL, libc::O_NONBLOCK) } == -1 {
        return Err(io::Error::last_os_error());
    }

    let fd = Arc::new(socket);
    let sender = Box::new(RawSenderImpl {
        socket: fd.clone(),
        write_buffer: vec![0; config.write_buffer_size],
        // SAFETY: `addr` was initialized as a sockaddr_ll above and remains
        // live while this same-sized value is copied.
        send_addr: unsafe { *(send_addr as *const libc::sockaddr_ll) },
        send_addr_len: len,
        timeout: config.write_timeout.map(nex_sys::duration_to_timespec),
    });
    let receiver = Box::new(RawReceiverImpl {
        socket: fd.clone(),
        read_buffer: vec![0; config.read_buffer_size],
        timeout: config.read_timeout,
        filter: LoopbackFilter::new(network_interface, config.suppress_loopback_duplicates),
    });

    Ok(super::Channel::Ethernet(sender, receiver))
}

struct RawSenderImpl {
    socket: Arc<nex_sys::FileDesc>,
    write_buffer: Vec<u8>,
    send_addr: libc::sockaddr_ll,
    send_addr_len: usize,
    timeout: Option<libc::timespec>,
}

impl RawSender for RawSenderImpl {
    #[inline]
    fn build_and_send(
        &mut self,
        num_packets: usize,
        packet_size: usize,
        func: &mut dyn FnMut(&mut [u8]),
    ) -> Option<io::Result<()>> {
        if packet_size == 0 {
            return Some(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "packet_size must be greater than zero",
            )));
        }
        let len = num_packets.checked_mul(packet_size)?;
        if len <= self.write_buffer.len() {
            let min = std::cmp::min(self.write_buffer.len(), len);
            let mut_slice = &mut self.write_buffer;

            let mut pollfd = libc::pollfd {
                fd: self.socket.as_raw(),
                events: libc::POLLOUT,
                revents: 0,
            };

            // poll timeout in milliseconds
            // -1: wait indefinitely
            let timeout_ms = poll_timeout_ms(self.timeout);

            for chunk in mut_slice[..min].chunks_mut(packet_size) {
                func(chunk);
                let send_addr =
                    (&self.send_addr as *const libc::sockaddr_ll) as *const libc::sockaddr;

                // SAFETY: `pollfd` points to one initialized descriptor for the
                // duration of poll.
                let ret = unsafe {
                    libc::poll(
                        &mut pollfd as *mut libc::pollfd,
                        1,
                        timeout_ms as libc::c_int,
                    )
                };

                if ret == -1 {
                    return Some(Err(io::Error::last_os_error()));
                } else if ret == 0 {
                    return Some(Err(io::Error::new(io::ErrorKind::TimedOut, "Timed out")));
                } else if pollfd.revents & libc::POLLOUT != 0 {
                    // SAFETY: `send_addr` points to `self.send_addr`, which
                    // remains alive and has the supplied `sockaddr_ll` length.
                    let send_result = unsafe {
                        nex_sys::send_to(
                            self.socket.as_raw(),
                            chunk,
                            send_addr,
                            self.send_addr_len as libc::socklen_t,
                        )
                    };
                    if let Err(e) = send_result {
                        return Some(Err(e));
                    }
                } else {
                    return Some(Err(io::Error::other("Unexpected poll event")));
                }
            }

            Some(Ok(()))
        } else {
            None
        }
    }

    #[inline]
    fn send(&mut self, packet: &[u8]) -> Option<io::Result<()>> {
        let mut pollfd = libc::pollfd {
            fd: self.socket.as_raw(),
            events: libc::POLLOUT,
            revents: 0,
        };

        // poll timeout in milliseconds
        // -1: wait indefinitely
        let timeout_ms = poll_timeout_ms(self.timeout);

        // SAFETY: `pollfd` points to one initialized descriptor for the
        // duration of poll.
        let ret = unsafe {
            libc::poll(
                &mut pollfd as *mut libc::pollfd,
                1,
                timeout_ms as libc::c_int,
            )
        };

        if ret == -1 {
            Some(Err(io::Error::last_os_error()))
        } else if ret == 0 {
            Some(Err(io::Error::new(io::ErrorKind::TimedOut, "Timed out")))
        } else if pollfd.revents & libc::POLLOUT != 0 {
            // Socket is ready for writing
            let send_addr = (&self.send_addr as *const libc::sockaddr_ll).cast();
            // SAFETY: `send_addr` points to `self.send_addr`, which remains
            // alive and has the supplied `sockaddr_ll` length.
            match unsafe {
                nex_sys::send_to(
                    self.socket.as_raw(),
                    packet,
                    send_addr,
                    self.send_addr_len as libc::socklen_t,
                )
            } {
                Err(e) => Some(Err(e)),
                Ok(_) => Some(Ok(())),
            }
        } else {
            Some(Err(io::Error::other("Unexpected poll event")))
        }
    }
}

/// Only metadata from the bound loopback interface may suppress a copy.
#[derive(Clone, Copy, Debug)]
pub(crate) struct LoopbackFilter {
    index: Option<i32>,
}

impl LoopbackFilter {
    pub(crate) fn new(interface: &Interface, enabled: bool) -> Self {
        Self {
            index: if enabled && interface.is_loopback() {
                i32::try_from(interface.index)
                    .ok()
                    .filter(|index| *index > 0)
            } else {
                None
            },
        }
    }

    fn suppress(&self, address: &libc::sockaddr_ll, length: libc::socklen_t) -> bool {
        // Reject incomplete or oversized metadata before interpreting its fields.
        length as usize == mem::size_of::<libc::sockaddr_ll>()
            && address.sll_family == libc::AF_PACKET as libc::sa_family_t
            && self.index == Some(address.sll_ifindex)
            && address.sll_pkttype == libc::PACKET_OUTGOING
    }
}

/// Receive bytes and validated direction metadata without changing packet data.
pub(crate) fn receive_packet(
    fd: libc::c_int,
    buffer: &mut [u8],
    filter: LoopbackFilter,
) -> io::Result<(usize, bool)> {
    // SAFETY: All-zero sockaddr_ll is valid initialized storage. Using its
    // concrete type supplies the required alignment without pointer dereferences.
    let mut address: libc::sockaddr_ll = unsafe { mem::zeroed() };
    let mut length = mem::size_of_val(&address) as libc::socklen_t;
    // SAFETY: Both output buffers are writable for their supplied lengths;
    // length is initialized and writable, and no pointers outlive this call.
    let received = unsafe {
        libc::recvfrom(
            fd,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            libc::MSG_DONTWAIT,
            (&mut address as *mut libc::sockaddr_ll).cast(),
            &mut length,
        )
    };
    if received < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok((received as usize, filter.suppress(&address, length)))
    }
}

// The injected clock and receive operation keep timeout regressions testable
// without privileged sockets or timing-sensitive sleeps.
fn receive_filtered(
    timeout: Option<Duration>,
    mut now: impl FnMut() -> Instant,
    mut receive: impl FnMut(Option<Duration>) -> io::Result<(usize, bool)>,
) -> io::Result<usize> {
    let start = now();
    let mut remaining = timeout;
    loop {
        let (length, suppressed) = receive(remaining)?;
        if !suppressed {
            return Ok(length);
        }
        remaining = match timeout {
            Some(timeout) => {
                let elapsed = now().saturating_duration_since(start);
                if elapsed >= timeout {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "Timed out"));
                }
                Some(timeout - elapsed)
            }
            None => None,
        };
    }
}

struct RawReceiverImpl {
    socket: Arc<nex_sys::FileDesc>,
    read_buffer: Vec<u8>,
    timeout: Option<Duration>,
    filter: LoopbackFilter,
}

impl RawReceiver for RawReceiverImpl {
    fn next(&mut self) -> io::Result<&[u8]> {
        let length = receive_filtered(self.timeout, Instant::now, |remaining| {
            let mut pollfd = libc::pollfd {
                fd: self.socket.as_raw(),
                events: libc::POLLIN,
                revents: 0,
            };
            let timeout_ms = poll_timeout_ms(remaining.map(nex_sys::duration_to_timespec));
            // SAFETY: pollfd is writable storage for one initialized descriptor.
            let ret = unsafe { libc::poll(&mut pollfd, 1, timeout_ms) };
            if ret == -1 {
                Err(io::Error::last_os_error())
            } else if ret == 0 {
                Err(io::Error::new(io::ErrorKind::TimedOut, "Timed out"))
            } else if pollfd.revents & libc::POLLIN != 0 {
                receive_packet(self.socket.as_raw(), &mut self.read_buffer, self.filter)
            } else {
                Err(io::Error::other("Unexpected poll event"))
            }
        })?;
        Ok(&self.read_buffer[..length])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_filter_metadata_matrix() {
        assert!(!super::super::Config::default().linux_suppress_loopback_duplicates);
        for enabled in [false, true] {
            for loopback in [false, true] {
                let mut interface = Interface::dummy();
                interface.index = 73;
                interface.name = "arbitrary-name".into();
                interface.flags = if loopback {
                    nex_core::interface::IFF_LOOPBACK
                } else {
                    0
                };
                let public = super::super::Config::default()
                    .with_linux_suppress_loopback_duplicates(enabled);
                let config = Config::from(&public);
                assert_eq!(config.suppress_loopback_duplicates, enabled);
                let filter = LoopbackFilter::new(&interface, config.suppress_loopback_duplicates);
                for index in [0, 1, 73, 74, -1] {
                    for packet_type in [
                        libc::PACKET_OUTGOING,
                        libc::PACKET_HOST,
                        libc::PACKET_BROADCAST,
                        libc::PACKET_MULTICAST,
                        libc::PACKET_OTHERHOST,
                    ] {
                        // SAFETY: Zero is valid for every sockaddr_ll field.
                        let mut address: libc::sockaddr_ll = unsafe { mem::zeroed() };
                        address.sll_family = libc::AF_PACKET as _;
                        address.sll_ifindex = index;
                        address.sll_pkttype = packet_type;
                        let size = mem::size_of_val(&address) as libc::socklen_t;
                        let expected = enabled
                            && loopback
                            && index == 73
                            && packet_type == libc::PACKET_OUTGOING;
                        assert_eq!(filter.suppress(&address, size), expected);
                        for length in [0, size - 1, size + 1, libc::socklen_t::MAX] {
                            assert!(!filter.suppress(&address, length));
                        }
                        address.sll_family = libc::AF_INET as _;
                        assert!(!filter.suppress(&address, size));
                    }
                }
            }
        }
    }

    #[test]
    fn suppressed_packets_do_not_restart_timeout() {
        let start = Instant::now();
        let mut ticks = 0;
        let mut waits = Vec::new();
        let error = receive_filtered(
            Some(Duration::from_millis(3)),
            || {
                let instant = start + Duration::from_millis(ticks);
                ticks += 1;
                instant
            },
            |remaining| {
                waits.push(remaining.unwrap().as_millis());
                assert!(waits.len() <= 3, "timeout restarted");
                Ok((52, true))
            },
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(waits, [3, 2, 1]);
    }

    #[test]
    fn receive_control_flow_preserves_lengths_and_errors() {
        for timeout in [None, Some(Duration::from_secs(1))] {
            let mut calls = 0;
            let length = receive_filtered(timeout, Instant::now, |_| {
                calls += 1;
                Ok((if calls == 3 { 17 } else { 52 }, calls < 3))
            })
            .unwrap();
            assert_eq!((length, calls), (17, 3));
            for kind in [
                io::ErrorKind::WouldBlock,
                io::ErrorKind::Interrupted,
                io::ErrorKind::TimedOut,
                io::ErrorKind::Other,
            ] {
                let mut calls = 0;
                let error = receive_filtered(timeout, Instant::now, |_| {
                    calls += 1;
                    if calls == 1 {
                        Ok((52, true))
                    } else {
                        Err(io::Error::from(kind))
                    }
                })
                .unwrap_err();
                assert_eq!(error.kind(), kind);
                assert_eq!(calls, 2);
            }
        }
        let mut calls = 0;
        assert_eq!(
            receive_filtered(Some(Duration::ZERO), Instant::now, |_| {
                calls += 1;
                Ok((52, true))
            })
            .unwrap_err()
            .kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(calls, 1);
        // An immediate poll may still return a ready packet with a zero timeout.
        assert_eq!(
            receive_filtered(Some(Duration::ZERO), Instant::now, |_| Ok((7, false))).unwrap(),
            7
        );
    }

    #[test]
    fn receive_packet_propagates_os_errors() {
        let error = receive_packet(-1, &mut [0; 64], LoopbackFilter { index: None }).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EBADF));
    }
}
