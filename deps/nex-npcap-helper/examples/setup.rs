use nex_npcap_helper::npcap;
use std::{env, path::PathBuf};
use inquire::Confirm;

const USAGE: &str = "Usage: ./setup <dst_dir_path> dst_dir_path: Directory path to download npcap installer and npcap SDK";

fn main() {
    let dst_dir_path: PathBuf = match env::args().nth(1) {
        Some(n) => {
            // Check directory path exists
            let dst_dir_path = PathBuf::from(n);
            if !dst_dir_path.exists() {
                panic!("Directory path does not exist");
            }
            dst_dir_path
        }
        None => {
            println!("Please provide a directory path to download npcap installer and npcap SDK");
            println!("{}", USAGE);
            return;
        }
    };
    // Check if npcap is installed
    if !npcap::npcap_installed() {
        let ans: bool = Confirm::new("Npcap is not installed, would you like to install it ?")
            .prompt()
            .unwrap();
        if ans == false {
            println!("Exiting...");
            return;
        }
    } else {
        let ans: bool = Confirm::new("Npcap is already installed. Would you like to reinstall (or update) Npcap ?")
            .prompt()
            .unwrap();
        if ans == false {
            println!("Exiting...");
            return;
        }
    }
    // Download the latest release of npcap installer
    let installer_path = match npcap::download_npcap_with_progress(&dst_dir_path) {
        Ok(path) => {
            println!("Npcap installer downloaded successfully !");
            path
        },
        Err(e) => {
            println!("{}", e);
            return;
        },
    };
    // Verify the checksum of the downloaded npcap installer
    match npcap::verify_installer_checksum(&installer_path) {
        Ok(_) => println!("Npcap installer checksum is correct !"),
        Err(e) => {
            println!("{}", e);
            return;
        },
    }
    // Install npcap
    match npcap::run_npcap_installer(&installer_path) {
        Ok(_) => println!("Npcap installed successfully !"),
        Err(e) => {
            println!("{}", e);
            return;
        },
    }
    // Check if npcap SDK is installed
    if !npcap::npcap_sdk_installed() {
        let ans: bool = Confirm::new("Npcap SDK is not installed, would you like to install it ?")
            .prompt()
            .unwrap();
        if ans == false {
            println!("Exiting...");
            return;
        }
    } else {
        let ans: bool = Confirm::new("Npcap SDK is already installed. Would you like to reinstall (or update) Npcap SDK ?")
            .prompt()
            .unwrap();
        if ans == false {
            println!("Exiting...");
            return;
        }
    }
    // Download the latest release of npcap sdk
    let sdk_path = match npcap::download_npcap_sdk_with_progress(&dst_dir_path) {
        Ok(path) => {
            println!("Npcap SDK downloaded successfully !");
            path
        },
        Err(e) => {
            println!("{}", e);
            return;
        },
    };
    // Verify the checksum of the downloaded npcap sdk
    match npcap::verify_sdk_checksum(&sdk_path) {
        Ok(_) => println!("Npcap SDK checksum is correct !"),
        Err(e) => {
            println!("{}", e);
            return;
        },
    }
    // Extract npcap sdk
    let sdk_dir = match npcap::extract_npcap_sdk(&sdk_path) {
        Ok(dir) => {
            println!("Npcap SDK extracted successfully !");
            println!("Npcap SDK extracted to {:?}", dir);
            dir
        },
        Err(e) => {
            println!("{}", e);
            return;
        },
    };
    // Add npcap SDK to LIB env var
    match npcap::add_npcap_sdk_to_lib(sdk_dir) {
        Ok(_) => println!("Npcap SDK added to LIB env var successfully !"),
        Err(e) => {
            println!("{}", e);
            return;
        },
    }
    // Remove downloaded npcap installer and sdk
    let ans: bool = Confirm::new("Would you like to remove the downloaded npcap installer and npcap SDK ?")
            .prompt()
            .unwrap();
    if ans {
        println!("Removing downloaded npcap installer and npcap SDK...");
        std::fs::remove_file(&installer_path).unwrap();
        std::fs::remove_file(&sdk_path).unwrap();
        println!("Downloaded npcap installer and npcap SDK removed successfully !");
    }
    println!("Npcap setup completed successfully !");
}
