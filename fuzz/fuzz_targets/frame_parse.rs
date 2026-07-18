#![no_main]

use libfuzzer_sys::fuzz_target;
use nex_packet::frame::{Frame, FrameView, ParseOption};
use nex_packet::parse::ParseMode;

fuzz_target!(|data: &[u8]| {
    let _ = Frame::from_buf(data, ParseOption::default());
    let _ = Frame::try_from_buf(data, ParseOption::default());
    let _ = Frame::try_from_buf_with_mode(data, ParseOption::default(), ParseMode::Strict);
    let _ = FrameView::from_buf(data, ParseOption::default());
});
