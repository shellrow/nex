mod sys;
pub mod app;
pub mod npcap;

#[cfg(feature = "interactive")]
use inquire::Confirm;

#[cfg(feature = "download")]
/// Setup npcap and npcap SDK.
/// This function will install npcap and npcap SDK if they are not installed.
pub fn setup_npcap() -> Result<(), String> {
    // Check if npcap is installed
    if !npcap::npcap_installed() {
        println!("Installing Npcap...");
        match npcap::install_npcap() {
            Ok(_) => println!("Npcap installed successfully !"),
            Err(e) => println!("{}", e),
        }
    } else {
        println!("Npcap is already installed !");
    }
    // Check if npcap sdk is installed
    if !npcap::npcap_sdk_installed() {
        println!("Installing Npcap SDK...");
        match npcap::install_npcap_sdk() {
            Ok(_) => println!("Npcap SDK installed successfully !"),
            Err(e) => println!("{}", e),
        }
    } else {
        println!("Npcap SDK is already installed !");
    }
    Ok(())
}

#[cfg(feature = "interactive")]
#[cfg(feature = "download")]
/// Setup npcap and npcap SDK.
/// This function will prompt the user to install npcap and npcap SDK if they are not installed.
pub fn setup_npcap_interactive() -> bool {
    // Check if npcap is installed
    if !npcap::npcap_installed() {
        let ans: bool = Confirm::new("Npcap is not installed, would you like to install it ?")
        .prompt()
        .unwrap();
        if ans == false {
            println!("Exiting...");
            return false;
        }
        println!("Installing Npcap...");
        match npcap::install_npcap() {
            Ok(_) => println!("Npcap installed successfully !"),
            Err(e) => println!("{}", e),
        }
    } else {
        println!("Npcap is already installed !");
    }
    // Check if npcap sdk is installed
    if !npcap::npcap_sdk_installed() {
        let ans: bool = Confirm::new("Npcap SDK is not installed, would you like to install it ?")
        .prompt()
        .unwrap();
        if ans == false {
            println!("Exiting...");
            return false;
        }
        println!("Installing Npcap SDK...");
        match npcap::install_npcap_sdk() {
            Ok(_) => println!("Npcap SDK installed successfully !"),
            Err(e) => println!("{}", e),
        }
    } else {
        println!("Npcap SDK is already installed !");
    }
    true
}