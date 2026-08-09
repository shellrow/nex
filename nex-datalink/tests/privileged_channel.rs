use nex_core::interface::{Interface, get_interfaces};
#[cfg(any(target_os = "linux", target_os = "android"))]
use nex_datalink::ChannelType;
use nex_datalink::{Config, channel};

fn test_interface() -> Interface {
    let requested =
        std::env::var("NEX_TEST_INTERFACE").expect("set NEX_TEST_INTERFACE to a test interface");
    get_interfaces()
        .into_iter()
        .find(|interface| interface.name == requested)
        .unwrap_or_else(|| panic!("interface {requested:?} was not found"))
}

#[test]
#[ignore = "requires NEX_TEST_INTERFACE and raw-packet privileges"]
fn open_and_close_platform_channel() {
    let interface = test_interface();
    let config = Config::default()
        .with_promiscuous(false)
        .with_read_timeout(Some(std::time::Duration::from_millis(100)))
        .with_write_timeout(Some(std::time::Duration::from_millis(100)));

    let opened = channel(&interface, config).expect("open privileged datalink channel");
    drop(opened);
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
#[ignore = "requires NEX_TEST_INTERFACE and raw-packet privileges"]
fn open_linux_layer3_channel() {
    let interface = test_interface();
    let config = Config::default()
        .with_promiscuous(false)
        .with_channel_type(ChannelType::Layer3(0x0800));

    let opened = channel(&interface, config).expect("open Linux Layer3 channel");
    drop(opened);
}

#[cfg(feature = "async")]
#[test]
#[ignore = "requires NEX_TEST_INTERFACE and raw-packet privileges"]
fn open_and_close_async_platform_channel() {
    let interface = test_interface();
    let opened = nex_datalink::async_io::async_channel(
        &interface,
        Config::default().with_promiscuous(false),
    )
    .expect("open privileged async datalink channel");
    drop(opened);
}
