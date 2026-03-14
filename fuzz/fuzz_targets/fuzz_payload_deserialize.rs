#![no_main]
use libfuzzer_sys::fuzz_target;
use rshc::payload::Payload;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    // Fuzz the payload deserialization — should never panic or OOM
    let mut cursor = Cursor::new(data);
    let _ = Payload::deserialize(&mut cursor);
});
