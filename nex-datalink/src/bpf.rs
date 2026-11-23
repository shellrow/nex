//! Support for sending and receiving data link layer packets using the /dev/bpf device.

use crate::bindings::bpf;
use crate::{RawReceiver, RawSender};
use nex_core::interface::Interface;

use std::collections::VecDeque;
use std::ffi::CString;
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use std::time::Duration;

mod records;
pub(crate) use bpf::parse_records;
#[cfg(test)]
use bpf::validate_record_lengths;
#[cfg(test)]
pub(crate) use records::test_ip_frame;
pub(crate) use records::{LinkType, write_packet};

/// The BPF-specific configuration.
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

    /// The number of /dev/bpf* file descriptors to attempt before failing.
    ///
    /// This setting is only used on OS X - FreeBSD uses a single /dev/bpf rather than creating a
    /// new descriptor each time one is opened.
    ///
    /// Defaults to: 1000.
    pub bpf_fd_attempts: usize,
}

impl From<&super::Config> for Config {
    fn from(config: &super::Config) -> Config {
        Config {
            write_buffer_size: config.write_buffer_size,
            read_buffer_size: config.read_buffer_size,
            bpf_fd_attempts: config.bpf_fd_attempts,
            read_timeout: config.read_timeout,
            write_timeout: config.write_timeout,
        }
    }
}

impl Default for Config {
    fn default() -> Config {
        Config {
            write_buffer_size: 4096,
            read_buffer_size: 4096,
            bpf_fd_attempts: 1000,
            read_timeout: None,
            write_timeout: None,
        }
    }
}

pub(crate) fn open_device(
    network_interface: &Interface,
    config: Config,
) -> io::Result<(OwnedFd, LinkType, usize)> {
    #[cfg(any(
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "illumos",
        target_os = "solaris"
    ))]
    fn get_fd(_attempts: usize) -> io::Result<libc::c_int> {
        let c_file_name = CString::new(&b"/dev/bpf"[..])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid bpf device path"))?;
        // SAFETY: `c_file_name` is a live, NUL-terminated path and the flags
        // require no variadic mode argument.
        let fd = unsafe {
            libc::open(
                c_file_name.as_ptr(),
                libc::O_RDWR | libc::O_CLOEXEC | libc::O_NONBLOCK,
                0,
            )
        };
        if fd == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(fd)
        }
    }

    #[cfg(any(target_os = "openbsd", target_os = "macos", target_os = "ios"))]
    fn get_fd(attempts: usize) -> io::Result<libc::c_int> {
        for i in 0..attempts {
            let file_name = format!("/dev/bpf{}", i);
            let c_file_name = CString::new(file_name.as_bytes()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid bpf device path")
            })?;
            // SAFETY: `c_file_name` is a live, NUL-terminated path and the flags
            // require no variadic mode argument.
            let fd = unsafe {
                libc::open(
                    c_file_name.as_ptr(),
                    libc::O_RDWR | libc::O_CLOEXEC | libc::O_NONBLOCK,
                    0,
                )
            };
            if fd != -1 {
                return Ok(fd);
            }
        }
        Err(io::Error::last_os_error())
    }

    #[cfg(any(
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "illumos",
        target_os = "solaris"
    ))]
    fn set_feedback(fd: libc::c_int) -> io::Result<()> {
        // SAFETY: `fd` is an open BPF descriptor and the ioctl reads the
        // correctly typed integer argument for the duration of the call.
        if unsafe { bpf::ioctl(fd, bpf::BIOCFEEDBACK, &1) } == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    #[cfg(any(target_os = "macos", target_os = "openbsd", target_os = "ios"))]
    fn set_feedback(_fd: libc::c_int) -> io::Result<()> {
        Ok(())
    }

    // Zero termination is required by BIOCSETIF.
    let name = network_interface.name.as_bytes();
    let mut iface: bpf::ifreq = unsafe { mem::zeroed() };
    if name.len() >= iface.ifr_name.len() || name.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid BPF interface name",
        ));
    }
    for (dest, &byte) in iface.ifr_name.iter_mut().zip(name) {
        *dest = byte as libc::c_char;
    }
    let mut buflen = u32::try_from(config.read_buffer_size)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "BPF buffer size exceeds u32"))?;
    let raw_fd = get_fd(config.bpf_fd_attempts)?;
    // SAFETY: get_fd transfers ownership of a newly opened descriptor.
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    // NOTE Buffer length must be set before binding to an interface
    //      otherwise this will return Invalid Argument
    // SAFETY: The descriptor is open and `buflen` has the exact argument type
    // expected by BIOCSBLEN.
    if unsafe { bpf::ioctl(fd.as_raw_fd(), bpf::BIOCSBLEN, &mut buflen) } == -1 {
        return Err(io::Error::last_os_error());
    }

    // Set the interface to use
    // SAFETY: The descriptor is open and `iface` remains readable throughout
    // the ioctl call.
    if unsafe { bpf::ioctl(fd.as_raw_fd(), bpf::BIOCSETIF, &iface) } == -1 {
        return Err(io::Error::last_os_error());
    }

    // Return from read as soon as packets are available - don't wait to fill the
    // buffer
    // SAFETY: The descriptor is open and the integer argument is valid for
    // BIOCIMMEDIATE.
    if unsafe { bpf::ioctl(fd.as_raw_fd(), bpf::BIOCIMMEDIATE, &1) } == -1 {
        return Err(io::Error::last_os_error());
    }

    // Get the device type
    let mut dlt: libc::c_uint = 0;
    // SAFETY: `dlt` is writable for the result and the descriptor is open.
    if unsafe { bpf::ioctl(fd.as_raw_fd(), bpf::BIOCGDLT, &mut dlt) } == -1 {
        return Err(io::Error::last_os_error());
    }

    let link_type = LinkType::from_dlt(dlt)?;
    if link_type.is_ip() {
        set_feedback(fd.as_raw_fd())?;
    }
    if link_type.header_complete() {
        // SAFETY: The descriptor is open and the ioctl reads an integer.
        if unsafe { bpf::ioctl(fd.as_raw_fd(), bpf::BIOCSHDRCMPLT, &1) } == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok((fd, link_type, buflen as usize))
}

pub(crate) fn channel(network_interface: &Interface, config: Config) -> io::Result<super::Channel> {
    let (fd, link_type, read_size) = open_device(network_interface, config)?;
    let fd = Arc::new(fd);
    let sender = Box::new(RawSenderImpl {
        fd: fd.clone(),
        write_buffer: vec![0; config.write_buffer_size],
        link_type,
        timeout: config.write_timeout,
    });
    let receiver = Box::new(RawReceiverImpl {
        fd,
        read_buffer: vec![0; read_size],
        link_type,
        normalized: Vec::new(),
        timeout: config.read_timeout,
        packets: VecDeque::with_capacity(read_size / 64),
    });
    Ok(super::Channel::Ethernet(sender, receiver))
}

struct RawSenderImpl {
    fd: Arc<OwnedFd>,
    write_buffer: Vec<u8>,
    link_type: LinkType,
    timeout: Option<Duration>,
}

fn send_frame(
    fd: libc::c_int,
    timeout: Option<Duration>,
    link_type: LinkType,
    packet: &[u8],
) -> io::Result<()> {
    let prepared = link_type.prepare_send(packet)?;
    wait_for(fd, libc::POLLOUT, timeout)?;
    write_packet(fd, &prepared)
}

fn wait_for(fd: libc::c_int, events: libc::c_short, timeout: Option<Duration>) -> io::Result<()> {
    let mut pfd = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    let millis = timeout.map_or(-1, |duration| {
        duration
            .as_nanos()
            .div_ceil(1_000_000)
            .min(i32::MAX as u128) as i32
    });
    // SAFETY: poll receives one initialized pollfd for the duration of the call.
    match unsafe { libc::poll(&mut pfd, 1, millis) } {
        -1 => Err(io::Error::last_os_error()),
        0 => Err(io::ErrorKind::TimedOut.into()),
        _ => Ok(()),
    }
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
        if len > self.write_buffer.len() {
            return None;
        }
        for chunk in self.write_buffer[..len].chunks_mut(packet_size) {
            func(chunk);
            if let Err(error) = send_frame(self.fd.as_raw_fd(), self.timeout, self.link_type, chunk)
            {
                return Some(Err(error));
            }
        }
        Some(Ok(()))
    }

    #[inline]
    fn send(&mut self, packet: &[u8]) -> Option<io::Result<()>> {
        Some(send_frame(
            self.fd.as_raw_fd(),
            self.timeout,
            self.link_type,
            packet,
        ))
    }
}

struct RawReceiverImpl {
    fd: Arc<OwnedFd>,
    read_buffer: Vec<u8>,
    link_type: LinkType,
    normalized: Vec<u8>,
    timeout: Option<Duration>,
    packets: VecDeque<(usize, usize)>,
}

impl RawReceiver for RawReceiverImpl {
    fn next(&mut self) -> io::Result<&[u8]> {
        if self.packets.is_empty() {
            let buffer = &mut self.read_buffer[..];
            wait_for(self.fd.as_raw_fd(), libc::POLLIN, self.timeout)?;
            // SAFETY: buffer is writable for its full length and the descriptor is open.
            let len = unsafe {
                libc::read(
                    self.fd.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                )
            };
            if len < 0 {
                return Err(io::Error::last_os_error());
            }
            self.packets = parse_records(&buffer[..len as usize])?;
        }
        let (start, len) = self.packets.pop_front().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "packet queue unexpectedly empty",
            )
        })?;
        let packet = &self.read_buffer[start..start + len];
        if self.link_type == LinkType::Ethernet {
            return Ok(packet);
        }
        self.link_type.normalize(packet, &mut self.normalized)?;
        Ok(&self.normalized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_and_build_use_link_framing() {
        use std::os::unix::net::UnixDatagram;
        let (writer, reader) = UnixDatagram::pair().unwrap();
        reader
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let fd = Arc::new(writer.into());
        let mut sender = RawSenderImpl {
            fd,
            write_buffer: vec![0; 108],
            link_type: LinkType::Null,
            timeout: Some(Duration::from_secs(1)),
        };
        let mut buffer = [0; 128];
        for version in [4, 6] {
            let packet = test_ip_frame(version);
            let expected = LinkType::Null.prepare_send(&packet).unwrap();
            sender.send(&packet).unwrap().unwrap();
            let n = reader.recv(&mut buffer).unwrap();
            assert_eq!(&buffer[..n], &*expected);
            sender
                .build_and_send(2, packet.len(), &mut |out| out.copy_from_slice(&packet))
                .unwrap()
                .unwrap();
            for _ in 0..2 {
                let n = reader.recv(&mut buffer).unwrap();
                assert_eq!(&buffer[..n], &*expected);
            }
        }
        reader.set_nonblocking(true).unwrap();
        assert_eq!(
            sender.send(&[0; 13]).unwrap().unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            sender
                .build_and_send(1, 13, &mut |_| {})
                .unwrap()
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            reader.recv(&mut buffer).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn accepts_header_without_repr_c_trailing_padding() {
        let header_len = bpf::BPF_HDR_FIELD_LEN;
        let captured_len = 86;

        assert_eq!(
            validate_record_lengths(header_len, captured_len, header_len + captured_len).unwrap(),
            header_len + captured_len
        );
    }

    #[test]
    fn rejects_header_that_cannot_contain_all_fields() {
        let header_len = bpf::BPF_HDR_FIELD_LEN - 1;
        let err = validate_record_lengths(header_len, 86, header_len + 86).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[cfg(all(
        any(target_os = "macos", target_os = "ios"),
        target_pointer_width = "64"
    ))]
    #[test]
    fn apple_bpf_header_has_two_bytes_of_trailing_padding() {
        assert_eq!(bpf::BPF_HDR_FIELD_LEN, 18);
        assert_eq!(mem::size_of::<bpf::bpf_hdr>(), 20);
    }
}
