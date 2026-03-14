#![no_main]
use libfuzzer_sys::fuzz_target;
use rshc::rc4::Rc4;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    // Split input: first byte = key length separator, rest = key + plaintext
    let split = (data[0] as usize % (data.len() - 1)) + 1;
    let key = &data[1..=split.min(data.len() - 1)];
    let plaintext = &data[split.min(data.len() - 1)..];

    // Encrypt
    let mut rc4_enc = Rc4::new();
    rc4_enc.reset();
    rc4_enc.key(key);
    let mut ciphertext = plaintext.to_vec();
    rc4_enc.arc4(&mut ciphertext);

    // Decrypt — must recover original plaintext
    let mut rc4_dec = Rc4::new();
    rc4_dec.reset();
    rc4_dec.key(key);
    rc4_dec.arc4(&mut ciphertext);
    assert_eq!(&ciphertext[..], plaintext);
});
