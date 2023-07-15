use rand::{rngs::StdRng, RngCore, SeedableRng};

/// Generates a hard to guess random hex-encoded ID of length `L`.
#[inline]
pub fn generate_id<const L: usize>() -> String {
    let mut rng = rand::thread_rng();

    let mut bytes = [0u8; L];
    rng.fill_bytes(&mut bytes);

    base16ct::lower::encode_string(bytes.as_ref())
}

/// Generates a random secret of length `L`.
#[inline]
pub fn generate_secret<const L: usize>() -> [u8; L] {
    let mut rng = StdRng::from_entropy();

    let mut bytes = [0u8; L];
    rng.fill_bytes(&mut bytes);

    bytes
}
