use nex_packet::frame::{FrameSlice, ParseOption};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

struct CountingAllocator;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

// SAFETY: Every operation is forwarded to `System` with the original pointer
// and layout. The counter does not affect allocation semantics.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: The caller supplies the layout required by GlobalAlloc.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: The pointer and layout came from the matching System allocation.
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: The pointer/layout pair came from System and `size` is the
        // requested replacement size.
        unsafe { System.realloc(pointer, layout, size) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

#[test]
fn frame_slice_parsing_does_not_allocate() {
    let packet = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, 0x45, 0, 0, 44, 0, 0, 0, 0, 64, 6, 0, 0,
        192, 0, 2, 1, 198, 51, 100, 2, 0, 80, 0x04, 0xd2, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x18, 0, 0,
        0, 0, 0, 0, b'd', b'a', b't', b'a',
    ];
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    let parsed = std::hint::black_box(FrameSlice::try_from_buf(
        std::hint::black_box(&packet),
        ParseOption::default(),
    ));
    let after = ALLOCATIONS.load(Ordering::Relaxed);

    assert!(parsed.is_ok());
    assert_eq!(after, before);
}
