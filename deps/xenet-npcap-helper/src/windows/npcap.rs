use super::sys;
use privilege::runas::Command as RunasCommand;
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fs::File;

pub(crate) const NPCAP_SOFTWARE_NAME: &str = "Npcap";
pub(crate) const NPCAP_INSTALL_DIR_NAME: &str = "npcap";
pub(crate) const NPCAP_SDK_DIR_NAME: &str = "npcap-sdk-1.13";
pub const NPCAP_INSTALLER_FILENAME: &str = "npcap-1.76.exe";
pub const NPCAP_SDK_FILENAME: &str = "npcap-sdk-1.13.zip";
pub(crate) const NPCAP_INSTALLER_HASH: &str =
    "3C846F5F62A217E3CF2052749CDE159E946248022781097C58815386DA6B9C46";
pub(crate) const NPCAP_SDK_HASH: &str =
    "DAD1F2BF1B02B787BE08CA4862F99E39A876C1F274BAC4AC0CEDC9BBC58F94FD";
#[allow(dead_code)]
pub(crate) const NPCAP_DIST_BASE_URL: &str = "https://npcap.com/dist/";
pub(crate) const NPCAP_LIB_NAME: &str = "Packet.lib";

/// Check if npcap is installed.
/// This function only check if npcap is installed, not check version.
pub fn npcap_installed() -> bool {
    sys::software_installed(NPCAP_SOFTWARE_NAME.to_owned())
}

/// Check if npcap SDK is installed.
/// This function only check if npcap SDK is installed, not check version.
pub fn npcap_sdk_installed() -> bool {
    let env_lib_value: String = sys::get_env_lib();
    if env_lib_value.is_empty() {
        return false;
    }
    // Split env_lib_value by ;
    let lib_path_list: Vec<&str> = env_lib_value.split(";").collect();
    // Check if npcap sdk is in env_lib_value
    // Search for Packet.lib
    for lib_path in lib_path_list {
        let packet_lib_path: String = format!("{}\\{}", lib_path, NPCAP_LIB_NAME);
        if std::path::Path::new(&packet_lib_path).exists() {
            return true;
        }
    }
    false
}

#[cfg(feature = "download")]
/// Download and Run npcap installer
pub fn install_npcap() -> Result<(), Box<dyn Error>> {
    let npcap_installer_url = format!("{}{}", NPCAP_DIST_BASE_URL, NPCAP_INSTALLER_FILENAME);
    // Check and create install dir
    let install_dir: String = sys::get_install_path(NPCAP_INSTALL_DIR_NAME);
    if !std::path::Path::new(&install_dir).exists() {
        std::fs::create_dir_all(&install_dir)?;
    }
    let npcap_target_path: String = format!(
        "{}\\{}",
        sys::get_install_path(NPCAP_INSTALL_DIR_NAME),
        NPCAP_INSTALLER_FILENAME
    );
    // Download npcap installer if not exists
    // After download, wait for virus scan to complete.
    if !std::path::Path::new(&npcap_target_path).exists() {
        let mut response: reqwest::blocking::Response =
            reqwest::blocking::get(&npcap_installer_url)?;
        let mut file: File = File::create(&npcap_target_path)?;
        response.copy_to(&mut file)?;
        //println!("Waiting for virus scan to complete (10 seconds) ...");
        std::thread::sleep(std::time::Duration::from_secs(10));
    }
    // Checksum
    let mut file: File = File::open(&npcap_target_path)?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)?;
    let hash_result = hasher.finalize();
    let hash_result: String = format!("{:X}", hash_result);

    if hash_result != NPCAP_INSTALLER_HASH {
        return Err("Error: checksum failed...".into());
    }

    // Run npcap installer
    let exit_status: std::process::ExitStatus = RunasCommand::new(&npcap_target_path)
        .arg("/loopback_support=yes")
        .arg("/winpcap_mode=yes")
        .run()?;
    if !exit_status.success() {
        return Err("Error: Npcap installation failed !".into());
    }

    // Remove npcap installer
    std::fs::remove_file(&npcap_target_path)?;

    Ok(())
}

#[cfg(feature = "download")]
/// Download npcap installer
pub fn download_npcap(dst_dir_path: String) -> Result<(), Box<dyn Error>> {
    let npcap_installer_url = format!("{}{}", NPCAP_DIST_BASE_URL, NPCAP_INSTALLER_FILENAME);
    // Check and create download dir
    let dir_path = std::path::Path::new(&dst_dir_path);
    if !dir_path.exists() {
        std::fs::create_dir_all(dir_path)?;
    }
    let npcap_target_path: std::path::PathBuf = dir_path.join(NPCAP_INSTALLER_FILENAME);
    // Download npcap installer if not exists
    if !std::path::Path::new(&npcap_target_path).exists() {
        let mut response: reqwest::blocking::Response =
            reqwest::blocking::get(&npcap_installer_url)?;
        let mut file: File = File::create(&npcap_target_path)?;
        response.copy_to(&mut file)?;
    }
    Ok(())
}

/// Verify npcap installer SHA256 checksum
pub fn verify_installer_checksum(file_path: String) -> Result<(), Box<dyn Error>> {
    let mut file: File = File::open(&file_path)?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)?;
    let hash_result = hasher.finalize();
    let hash_result: String = format!("{:X}", hash_result);

    if hash_result != NPCAP_INSTALLER_HASH {
        return Err("Error: checksum failed...".into());
    }
    Ok(())
}

/// Run npcap installer.
///
/// Warning: This function will run npcap installer with admin privileges.
///
/// This function only run verified npcap installer.
pub fn run_npcap_installer(file_path: String) -> Result<(), Box<dyn Error>> {
    // Check file exists
    if !std::path::Path::new(&file_path).exists() {
        return Err("Error: file not found...".into());
    }
    // Verify checksum
    verify_installer_checksum(file_path.clone())?;
    let exit_status: std::process::ExitStatus = RunasCommand::new(&file_path)
        .arg("/loopback_support=yes")
        .arg("/winpcap_mode=yes")
        .run()?;
    if !exit_status.success() {
        return Err("Error: Npcap installation failed !".into());
    }
    Ok(())
}

#[cfg(feature = "download")]
/// Download, extract and add npcap SDK to LIB env var
pub fn install_npcap_sdk() -> Result<(), Box<dyn Error>> {
    let npcap_sdk_url = format!("{}{}", NPCAP_DIST_BASE_URL, NPCAP_SDK_FILENAME);
    // Check and create install dir
    let install_dir: String = sys::get_install_path(NPCAP_INSTALL_DIR_NAME);
    if !std::path::Path::new(&install_dir).exists() {
        std::fs::create_dir_all(&install_dir)?;
    }
    let npcap_sdk_target_path: String = format!(
        "{}\\{}",
        sys::get_install_path(NPCAP_INSTALL_DIR_NAME),
        NPCAP_SDK_FILENAME
    );
    // Download npcap sdk if not exists
    if !std::path::Path::new(&npcap_sdk_target_path).exists() {
        let mut response: reqwest::blocking::Response = reqwest::blocking::get(&npcap_sdk_url)?;
        let mut file: File = File::create(&npcap_sdk_target_path)?;
        response.copy_to(&mut file)?;
    }
    // Checksum
    let mut file: File = File::open(&npcap_sdk_target_path)?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)?;
    let hash_result = hasher.finalize();
    let hash_result: String = format!("{:X}", hash_result);

    if hash_result != NPCAP_SDK_HASH {
        return Err("Error: checksum failed...".into());
    }

    // Extract npcap SDK
    let npcap_sdk_extract_dir: String = format!(
        "{}\\{}",
        sys::get_install_path(NPCAP_INSTALL_DIR_NAME),
        NPCAP_SDK_DIR_NAME
    );
    let mut archive: zip::ZipArchive<File> =
        zip::ZipArchive::new(File::open(&npcap_sdk_target_path)?)?;
    for i in 0..archive.len() {
        let mut file: zip::read::ZipFile = archive.by_index(i)?;
        let outpath: std::path::PathBuf =
            format!("{}\\{}", npcap_sdk_extract_dir, file.name()).into();
        if (&*file.name()).ends_with('/') {
            std::fs::create_dir_all(&outpath)?;
        } else {
            if let Some(p) = outpath.parent() {
                if !p.exists() {
                    std::fs::create_dir_all(&p)?;
                }
            }
            let mut outfile: File = std::fs::File::create(&outpath)?;
            std::io::copy(&mut file, &mut outfile)?;
        }
    }

    // Add npcap SDK to LIB env var
    let os_bit: String = sys::get_os_bit();
    let lib_dir_path: String = if os_bit == "32-bit" {
        format!("{}\\{}", npcap_sdk_extract_dir, "Lib")
    } else {
        format!("{}\\{}", npcap_sdk_extract_dir, "Lib\\x64")
    };
    if !sys::check_env_lib_path(&lib_dir_path) {
        match sys::add_env_lib_path(&lib_dir_path) {
            Ok(_) => {}
            Err(e) => Err(e)?,
        }
    }

    // Remove npcap SDK zip
    std::fs::remove_file(&npcap_sdk_target_path)?;

    Ok(())
}

#[cfg(feature = "download")]
/// Download npcap SDK
pub fn download_npcap_sdk(dst_dir_path: String) -> Result<(), Box<dyn Error>> {
    let npcap_sdk_url = format!("{}{}", NPCAP_DIST_BASE_URL, NPCAP_SDK_FILENAME);
    // Check and create download dir
    let dir_path = std::path::Path::new(&dst_dir_path);
    if !dir_path.exists() {
        std::fs::create_dir_all(dir_path)?;
    }
    let npcap_sdk_target_path: std::path::PathBuf = dir_path.join(NPCAP_SDK_FILENAME);
    // Download npcap sdk if not exists
    if !std::path::Path::new(&npcap_sdk_target_path).exists() {
        let mut response: reqwest::blocking::Response = reqwest::blocking::get(&npcap_sdk_url)?;
        let mut file: File = File::create(&npcap_sdk_target_path)?;
        response.copy_to(&mut file)?;
    }
    Ok(())
}

/// Verify npcap SDK SHA256 checksum
pub fn verify_sdk_checksum(file_path: String) -> Result<(), Box<dyn Error>> {
    let mut file: File = File::open(&file_path)?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)?;
    let hash_result = hasher.finalize();
    let hash_result: String = format!("{:X}", hash_result);

    if hash_result != NPCAP_SDK_HASH {
        return Err("Error: checksum failed...".into());
    }
    Ok(())
}

/// Extract npcap SDK
pub fn extract_npcap_sdk(file_path: String) -> Result<(), Box<dyn Error>> {
    // Check file exists
    if !std::path::Path::new(&file_path).exists() {
        return Err("Error: file not found...".into());
    }
    // Verify checksum
    verify_sdk_checksum(file_path.clone())?;
    // Extract npcap SDK
    let npcap_sdk_extract_dir: String = format!(
        "{}\\{}",
        sys::get_install_path(NPCAP_INSTALL_DIR_NAME),
        NPCAP_SDK_DIR_NAME
    );
    let mut archive: zip::ZipArchive<File> = zip::ZipArchive::new(File::open(&file_path)?)?;
    for i in 0..archive.len() {
        let mut file: zip::read::ZipFile = archive.by_index(i)?;
        let outpath: std::path::PathBuf =
            format!("{}\\{}", npcap_sdk_extract_dir, file.name()).into();
        if (&*file.name()).ends_with('/') {
            std::fs::create_dir_all(&outpath)?;
        } else {
            if let Some(p) = outpath.parent() {
                if !p.exists() {
                    std::fs::create_dir_all(&p)?;
                }
            }
            let mut outfile: File = std::fs::File::create(&outpath)?;
            std::io::copy(&mut file, &mut outfile)?;
        }
    }
    Ok(())
}

/// Add npcap SDK to LIB env var
pub fn add_npcap_sdk_to_lib(lib_dir_path: String) -> Result<(), Box<dyn Error>> {
    // Check lib dir exists
    if !std::path::Path::new(&lib_dir_path).exists() {
        return Err("Error: lib dir not found...".into());
    }
    if !sys::check_env_lib_path(&lib_dir_path) {
        match sys::add_env_lib_path(&lib_dir_path) {
            Ok(_) => {}
            Err(e) => Err(e)?,
        }
    }
    Ok(())
}
