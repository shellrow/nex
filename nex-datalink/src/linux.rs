//! Support for sending and receiving data link layer packets using Linux's `AF_PACKET`.

extern crate libc;

use crate::bindings::linux;
use crate::{RawReceiver, RawSender};
use nex_core::interface::Interface;
use nex_core::mac::MacAddr;
use nex_sys;
use std::io;
use std::mem;
use std::sync::Arc;
use std::time::Duration;

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
}

#[inline]
fn poll_timeout_ms(timeout: Option<libc::timespec>) -> libc::c_int {
    timeout
        .map(|to| {
            let ms = (to.tv_sec as i64 * 1000) + (to.tv_nsec as i64 / 1_000_000);
            ms.clamp(i64::from(libc::c_int::MIN), i64::from(libc::c_int::MAX)) as libc::c_int
        })
        .unwrap_or(-1)
}

impl<'a> From<&'a super::Config> for Config {
    fn from(config: &super::Config) -> Config {
        Config {
            write_buffer_size: config.write_buffer_size,
            read_buffer_size: config.read_buffer_size,
            channel_type: config.channel_type,
            read_timeout: config.read_timeout,
            write_timeout: config.write_timeout,
            fanout: config.linux_fanout,
            promiscuous: config.promiscuous,
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
            typ = typ | linux::PACKET_FANOUT_FLAG_DEFRAG;
        }
        // set rollover flag
        if fanout.rollover {
            typ = typ | linux::PACKET_FANOUT_FLAG_ROLLOVER;
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
        timeout: config
            .write_timeout
            .map(|to| nex_sys::duration_to_timespec(to)),
    });
    let receiver = Box::new(RawReceiverImpl {
        socket: fd.clone(),
        read_buffer: vec![0; config.read_buffer_size],
        timeout: config
            .read_timeout
            .map(|to| nex_sys::duration_to_timespec(to)),
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

struct RawReceiverImpl {
    socket: Arc<nex_sys::FileDesc>,
    read_buffer: Vec<u8>,
    timeout: Option<libc::timespec>,
}

impl RawReceiver for RawReceiverImpl {
    fn next(&mut self) -> io::Result<&[u8]> {
        // SAFETY: A zero bit pattern is valid initial socket address storage.
        let mut caddr: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let mut pollfd = libc::pollfd {
            fd: self.socket.as_raw(),
            events: libc::POLLIN,
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
            Err(io::Error::last_os_error())
        } else if ret == 0 {
            Err(io::Error::new(io::ErrorKind::TimedOut, "Timed out"))
        } else if pollfd.revents & libc::POLLIN != 0 {
            // Socket is ready for reading
            // SAFETY: `caddr` is writable `sockaddr_storage` for the duration
            // of the call.
            let res = unsafe {
                nex_sys::recv_from(self.socket.as_raw(), &mut self.read_buffer, &mut caddr)
            };
            match res {
                Ok(len) => Ok(&self.read_buffer[0..len]),
                Err(e) => Err(e),
            }
        } else {
            Err(io::Error::other("Unexpected poll event"))
        }
    }
}
