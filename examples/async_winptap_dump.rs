//! Runtime-independent asynchronous Ethernet reception without Npcap.
#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use futures::{StreamExt, executor::block_on};
    use nex::datalink::winptap;
    use std::time::Duration;

    let interface = nex::net::interface::get_default_interface()?;
    let mut receiver = winptap::open_async(&interface, winptap::Config::default())?;
    let token = receiver.cancellation_token();
    let (done, finished) = std::sync::mpsc::channel();
    let timer = std::thread::spawn(move || {
        if matches!(
            finished.recv_timeout(Duration::from_secs(10)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ) {
            token.cancel();
        }
    });
    let result: std::io::Result<()> = block_on(async {
        while let Some(frame) = receiver.next().await {
            match frame {
                Ok(frame) => println!("Ethernet frame: {} bytes", frame.len()),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => break,
                Err(error) => return Err(error),
            }
        }
        Ok(())
    });
    let _ = done.send(());
    timer.join().expect("deadline thread");
    receiver.close()?;
    result?;
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("winptap is available only on Windows");
}
