#![no_main]
use libfuzzer_sys::fuzz_target;
use rshc::payload::Payload;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    // Fuzz the trailer-based payload reading — should never panic or OOM
    if data.len() < 8 {
        return;
    }
    let mut cursor = Cursor::new(data);
    let _ = Payload::read_from_exe(&mut cursor);
});
