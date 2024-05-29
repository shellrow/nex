//! Support for sending and receiving data link layer packets using Linux's `AF_PACKET`.

extern crate libc;

use crate::bindings::linux;
use nex_core::interface::Interface;
use crate::{FrameReceiver, FrameSender};
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
pub struct Config {
    /// The size of buffer to use when writing packets. Defaults to 4096.
    pub write_buffer_size: usize,

    /// The size of buffer to use when reading packets. Defaults to 4096.
    pub read_buffer_size: usize,

    /// The read timeout. Defaults to None.
    pub read_timeout: Option<Duration>,

    /// The write timeout. Defaults to None.
    pub write_timeout: Option<Duration>,

    /// Specifies whether to read packets at the datalink layer or network layer.
    /// NOTE FIXME Currently ignored.
    /// Defaults to Layer2.
    pub channel_type: super::ChannelType,

    /// Specifies packet fanout option, if desired. Defaults to None.
    pub fanout: Option<super::FanoutOption>,

    /// Promiscuous mode.
    pub promiscuous: bool,
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
pub fn channel(network_interface: &Interface, config: Config) -> io::Result<super::Channel> {
    let eth_p_all = 0x0003;
    let (typ, proto) = match config.channel_type {
        super::ChannelType::Layer2 => (libc::SOCK_RAW, eth_p_all),
        super::ChannelType::Layer3(proto) => (libc::SOCK_DGRAM, proto),
    };
    let socket = unsafe { libc::socket(libc::AF_PACKET, typ, proto.to_be() as i32) };
    if socket == -1 {
        return Err(io::Error::last_os_error());
    }
    let mut addr: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let len = network_addr_to_sockaddr(network_interface, &mut addr, proto as i32);

    let send_addr = (&addr as *const libc::sockaddr_storage) as *const libc::sockaddr;

    // Bind to interface
    if unsafe { libc::bind(socket, send_addr, len as libc::socklen_t) } == -1 {
        let err = io::Error::last_os_error();
        unsafe {
            nex_sys::close(socket);
        }
        return Err(err);
    }

    let mut pmr: linux::packet_mreq = unsafe { mem::zeroed() };
    pmr.mr_ifindex = network_interface.index as i32;
    pmr.mr_type = linux::PACKET_MR_PROMISC as u16;

    // Enable promiscuous capture
    if config.promiscuous {
        if unsafe {
            libc::setsockopt(
                socket,
                linux::SOL_PACKET,
                linux::PACKET_ADD_MEMBERSHIP,
                (&pmr as *const linux::packet_mreq) as *const libc::c_void,
                mem::size_of::<linux::packet_mreq>() as libc::socklen_t,
            )
        } == -1
        {
            let err = io::Error::last_os_error();
            unsafe {
                nex_sys::close(socket);
            }
            return Err(err);
        }
    }

    // Enable packet fanout
    if let Some(fanout) = config.fanout {
        use super::FanoutType;
        let mut typ = match fanout.fanout_type {
            FanoutType::HASH => linux::PACKET_FANOUT_HASH,
            FanoutType::LB => linux::PACKET_FANOUT_LB,
            FanoutType::CPU => linux::PACKET_FANOUT_CPU,
            FanoutType::ROLLOVER => linux::PACKET_FANOUT_ROLLOVER,
            FanoutType::RND => linux::PACKET_FANOUT_RND,
            FanoutType::QM => linux::PACKET_FANOUT_QM,
            FanoutType::CBPF => linux::PACKET_FANOUT_CBPF,
            FanoutType::EBPF => linux::PACKET_FANOUT_EBPF,
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

        if unsafe {
            libc::setsockopt(
                socket,
                linux::SOL_PACKET,
                linux::PACKET_FANOUT,
                (&arg as *const libc::c_uint) as *const libc::c_void,
                mem::size_of::<libc::c_uint>() as libc::socklen_t,
            )
        } == -1
        {
            let err = io::Error::last_os_error();
            unsafe {
                nex_sys::close(socket);
            }
            return Err(err);
        }
    }

    // Enable nonblocking
    if unsafe { libc::fcntl(socket, libc::F_SETFL, libc::O_NONBLOCK) } == -1 {
        let err = io::Error::last_os_error();
        unsafe {
            nex_sys::close(socket);
        }
        return Err(err);
    }

    let fd = Arc::new(nex_sys::FileDesc { fd: socket });
    let sender = Box::new(FrameSenderImpl {
        socket: fd.clone(),
        write_buffer: vec![0; config.write_buffer_size],
        _channel_type: config.channel_type,
        send_addr: unsafe { *(send_addr as *const libc::sockaddr_ll) },
        send_addr_len: len,
        timeout: config
            .write_timeout
            .map(|to| nex_sys::duration_to_timespec(to)),
    });
    let receiver = Box::new(FrameReceiverImpl {
        socket: fd.clone(),
        read_buffer: vec![0; config.read_buffer_size],
        _channel_type: config.channel_type,
        timeout: config
            .read_timeout
            .map(|to| nex_sys::duration_to_timespec(to)),
    });

    Ok(super::Channel::Ethernet(sender, receiver))
}

struct FrameSenderImpl {
    socket: Arc<nex_sys::FileDesc>,
    write_buffer: Vec<u8>,
    _channel_type: super::ChannelType,
    send_addr: libc::sockaddr_ll,
    send_addr_len: usize,
    timeout: Option<libc::timespec>,
}

impl FrameSender for FrameSenderImpl {
    #[inline]
    fn build_and_send(
        &mut self,
        num_packets: usize,
        packet_size: usize,
        func: &mut dyn FnMut(&mut [u8]),
    ) -> Option<io::Result<()>> {
        let len = num_packets * packet_size;
        if len <= self.write_buffer.len() {
            let min = std::cmp::min(self.write_buffer.len(), len);
            let mut_slice = &mut self.write_buffer;

            let mut pollfd = libc::pollfd {
                fd: self.socket.fd,
                events: libc::POLLOUT,
                revents: 0,
            };

            // poll timeout in milliseconds
            // -1: wait indefinitely
            let timeout_ms = self
                .timeout
                .as_ref()
                .map(|to| (to.tv_sec as i64 * 1000) + (to.tv_nsec as i64 / 1_000_000))
                .unwrap_or(-1);

            for chunk in mut_slice[..min].chunks_mut(packet_size) {
                func(chunk);
                let send_addr =
                    (&self.send_addr as *const libc::sockaddr_ll) as *const libc::sockaddr;

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
                    if let Err(e) = nex_sys::send_to(
                        self.socket.fd,
                        chunk,
                        send_addr,
                        self.send_addr_len as libc::socklen_t,
                    ) {
                        return Some(Err(e));
                    }
                } else {
                    return Some(Err(io::Error::new(
                        io::ErrorKind::Other,
                        "Unexpected poll event",
                    )));
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
            fd: self.socket.fd,
            events: libc::POLLOUT,
            revents: 0,
        };

        // poll timeout in milliseconds
        // -1: wait indefinitely
        let timeout_ms = self
            .timeout
            .as_ref()
            .map(|to| (to.tv_sec as i64 * 1000) + (to.tv_nsec as i64 / 1_000_000))
            .unwrap_or(-1);

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
            match nex_sys::send_to(
                self.socket.fd,
                packet,
                (&self.send_addr as *const libc::sockaddr_ll) as *const _,
                self.send_addr_len as libc::socklen_t,
            ) {
                Err(e) => Some(Err(e)),
                Ok(_) => Some(Ok(())),
            }
        } else {
            Some(Err(io::Error::new(
                io::ErrorKind::Other,
                "Unexpected poll event",
            )))
        }
    }
}

struct FrameReceiverImpl {
    socket: Arc<nex_sys::FileDesc>,
    read_buffer: Vec<u8>,
    _channel_type: super::ChannelType,
    timeout: Option<libc::timespec>,
}

impl FrameReceiver for FrameReceiverImpl {
    fn next(&mut self) -> io::Result<&[u8]> {
        let mut caddr: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let mut pollfd = libc::pollfd {
            fd: self.socket.fd,
            events: libc::POLLIN,
            revents: 0,
        };

        // poll timeout in milliseconds
        // -1: wait indefinitely
        let timeout_ms = self
            .timeout
            .as_ref()
            .map(|to| (to.tv_sec as i64 * 1000) + (to.tv_nsec as i64 / 1_000_000))
            .unwrap_or(-1);

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
            let res = nex_sys::recv_from(self.socket.fd, &mut self.read_buffer, &mut caddr);
            match res {
                Ok(len) => Ok(&self.read_buffer[0..len]),
                Err(e) => Err(e),
            }
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "Unexpected poll event",
            ))
        }
    }
}
