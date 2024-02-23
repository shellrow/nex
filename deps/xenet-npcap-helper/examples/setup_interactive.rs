use nex_npcap_helper::npcap;
use inquire::Confirm;

fn main() {
    // Check if npcap is installed
    if !npcap::npcap_installed() {
        let ans: bool = Confirm::new("Npcap is not installed, would you like to install it ?")
            .prompt()
            .unwrap();
        if ans == false {
            println!("Exiting...");
            std::process::exit(0);
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
            std::process::exit(0);
        }
        println!("Installing Npcap SDK...");
        match npcap::install_npcap_sdk() {
            Ok(_) => println!("Npcap SDK installed successfully !"),
            Err(e) => println!("{}", e),
        }
    } else {
        println!("Npcap SDK is already installed !");
    }
}
