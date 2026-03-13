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
