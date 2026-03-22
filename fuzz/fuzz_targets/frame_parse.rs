#![no_main]

use libfuzzer_sys::fuzz_target;
use nex_packet::frame::{Frame, FrameView, ParseOption};

fuzz_target!(|data: &[u8]| {
    let _ = Frame::from_buf(data, ParseOption::default());
    let _ = Frame::try_from_buf(data, ParseOption::default());
    let _ = Frame::try_from_buf_strict(data, ParseOption::default());
    let _ = FrameView::from_buf(data, ParseOption::default());
});
