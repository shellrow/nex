#![no_main]

use libfuzzer_sys::fuzz_target;
use nex_packet::frame::{Frame, FrameSlice, FrameView, ParseOption};
use nex_packet::parse::ParseMode;

fuzz_target!(|data: &[u8]| {
    let _ = Frame::try_from_buf(data, ParseOption::default());
    let _ = Frame::try_from_buf_with_mode(data, ParseOption::default(), ParseMode::Strict);
    let _ = FrameView::try_from_buf(data, ParseOption::default());
    let _ = FrameSlice::try_from_buf(data, ParseOption::default());
    let option = ParseOption {
        from_ip_packet: true,
        offset: 0,
    };
    let _ = FrameSlice::try_from_buf(data, option.clone());
    let _ = FrameView::try_from_buf(data, option);
});
