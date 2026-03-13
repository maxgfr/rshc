#![allow(dead_code)]

use rand::Rng;

/// Uniform random in [0, modulus) without bias.
/// Matches rand_mod() in shc.c:1116-1126.
pub fn rand_mod(rng: &mut impl Rng, modulus: u32) -> u32 {
    if modulus == 0 {
        return 0;
    }
    rng.gen_range(0..modulus)
}

/// Random byte.
/// Matches rand_chr() in shc.c:1128-1131.
pub fn rand_chr(rng: &mut impl Rng) -> u8 {
    rng.gen()
}

/// Generate random noise bytes.
/// Matches noise() in shc.c:1133-1143.
/// Returns a Vec of `min + rand(0..xtra)` bytes.
/// If is_str, bytes are alphanumeric and a NUL terminator is appended.
pub fn noise(rng: &mut impl Rng, min: usize, xtra: usize, is_str: bool) -> Vec<u8> {
    let extra = if xtra > 0 {
        rand_mod(rng, xtra as u32) as usize
    } else {
        0
    };
    let total = min + extra;
    let mut result = Vec::with_capacity(total + if is_str { 1 } else { 0 });
    for _ in 0..total {
        if is_str {
            loop {
                let c = rand_chr(rng);
                if c.is_ascii_alphanumeric() {
                    result.push(c);
                    break;
                }
            }
        } else {
            result.push(rand_chr(rng));
        }
    }
    if is_str {
        result.push(0);
    }
    result
}
