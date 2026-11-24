#![no_main]

use libfuzzer_sys::fuzz_target;
use radperf_rs::packet::Packet;

fuzz_target!(|bytes: &[u8]| {
    if let Ok(packet) = Packet::decode(bytes) {
        assert_eq!(packet.encode(), bytes[..packet.len()]);
    }
});
