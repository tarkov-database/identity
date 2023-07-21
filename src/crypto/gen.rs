use rand::{rngs::StdRng, RngCore, SeedableRng};

#[inline]
pub fn random_bytes<const LEN: usize>() -> [u8; LEN] {
    let mut rng = rand::thread_rng();

    let mut bytes = [0u8; LEN];
    rng.fill_bytes(&mut bytes);

    bytes
}

/// Generates a random secret of length `LEN` with fresh entropy.
#[inline]
pub fn generate_secret<const LEN: usize>() -> [u8; LEN] {
    let mut rng = StdRng::from_entropy();

    let mut bytes = [0u8; LEN];
    rng.fill_bytes(&mut bytes);

    bytes
}
