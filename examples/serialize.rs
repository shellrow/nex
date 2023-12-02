//! Basic packet capture using xenet
//!
//! Parse packet as Frame and print it as JSON format

use std::env;
use std::process;
use xenet::datalink;
use xenet::net::interface::Interface;
use xenet::packet::frame::Frame;
use xenet::packet::frame::ParseOption;

fn main() {
    use xenet::datalink::Channel::Ethernet;
    let interface: Interface = match env::args().nth(1) {
        Some(n) => {
            // Use interface specified by user
            let interfaces: Vec<Interface> = xenet::net::interface::get_interfaces();
            let interface: Interface = interfaces
                .into_iter()
                .find(|interface| interface.name == n)
                .expect("Failed to get interface information");
            interface
        }
        None => {
            // Use default interface
            match Interface::default() {
                Ok(interface) => interface,
                Err(e) => {
                    println!("Failed to get default interface: {}", e);
                    process::exit(1);
                }
            }
        }
    };

    // Create a channel to receive packet
    let (mut _tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("parse_frame: unhandled channel type"),
        Err(e) => panic!("parse_frame: unable to create channel: {}", e),
    };
    let mut capture_no: usize = 0;
    loop {
        match rx.next() {
            Ok(packet) => {
                capture_no += 1;
                println!(
                    "---- Interface: {}, No.: {}, Total Length: {} bytes ----",
                    interface.name,
                    capture_no,
                    packet.len()
                );
                let mut parse_option: ParseOption = ParseOption::default();
                if interface.is_tun() {
                    let payload_offset;
                    if interface.is_loopback() {
                        payload_offset = 14;
                    } else {
                        payload_offset = 0;
                    }
                    parse_option.from_ip_packet = true;
                    parse_option.offset = payload_offset;
                }
                let frame: Frame = Frame::from_bytes(&packet, parse_option);
                match serde_json::to_string(&frame) {
                    Ok(json) => {
                        println!("{}", json);
                    }
                    Err(e) => {
                        println!("Serialization Error: {}", e);
                    }
                }
                
            }
            Err(e) => panic!("parse_frame: unable to receive packet: {}", e),
        }
    }
}