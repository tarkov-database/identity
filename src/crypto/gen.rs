use rand::{rngs::StdRng, RngCore, SeedableRng};

/// Generates a hard to guess random hex-encoded ID of length `LEN`.
#[inline]
pub fn generate_id<const LEN: usize>() -> String {
    let mut rng = rand::thread_rng();

    let mut bytes = [0u8; LEN];
    rng.fill_bytes(&mut bytes);

    base16ct::lower::encode_string(bytes.as_ref())
}

/// Generates a random secret of length `LEN`.
#[inline]
pub fn generate_secret<const LEN: usize>() -> [u8; LEN] {
    let mut rng = StdRng::from_entropy();

    let mut bytes = [0u8; LEN];
    rng.fill_bytes(&mut bytes);

    bytes
}
