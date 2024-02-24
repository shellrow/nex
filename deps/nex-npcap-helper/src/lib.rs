#[cfg(not(target_os = "windows"))]
mod unix;
#[cfg(not(target_os = "windows"))]
pub use self::unix::*;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use self::windows::*;

#[cfg(target_os = "windows")]
#[cfg(test)]
mod tests {
    use crate::npcap;
    #[test]
    fn test_check_npcap() {
        if npcap::npcap_installed() {
            println!("npcap installed");
        } else {
            println!("npcap not installed");
        }
    }
    #[test]
    fn test_check_npcap_sdk() {
        if npcap::npcap_sdk_installed() {
            println!("npcap SDK installed");
        } else {
            println!("npcap SDK not installed");
        }
    }
}
