//! Receive Ethernet frames without installing Npcap.
#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use nex::datalink::{RawReceiver, winptap};
    use std::time::{Duration, Instant};

    let interface = nex::net::interface::get_default_interface()?;
    let mut config = winptap::Config::default();
    config.read_timeout = Some(Duration::from_millis(500));
    let mut receiver = winptap::open(&interface, config)?;
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        match receiver.next() {
            Ok(frame) => println!("Ethernet frame: {} bytes", frame.len()),
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(error) => return Err(error.into()),
        }
    }
    receiver.stop()?;
    println!("{:?}", receiver.statistics());
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("winptap is available only on Windows");
}
