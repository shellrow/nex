#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "illumos",
    target_os = "solaris",
    target_os = "macos",
    target_os = "ios",
    windows
))]
pub mod bpf;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod linux;

#[cfg(windows)]
pub mod windows;
