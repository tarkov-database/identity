use crate::AppState;

use aes_gcm_siv::{aead::Aead, Aes256GcmSiv, KeyInit, Nonce};
use axum::extract::FromRef;
use rand::{distributions::Alphanumeric, Rng};

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("key has an invalid size")]
    InvalidKeySize,
}

#[derive(Clone)]
pub struct Aead256 {
    cipher: Aes256GcmSiv,
}

impl Aead256 {
    const KEY_SIZE: usize = 256 / 8;
    const NONCE_SIZE: usize = 96 / 8;

    pub fn new<K>(key: K) -> Result<Self, CryptoError>
    where
        K: AsRef<[u8]>,
    {
        let cipher =
            Aes256GcmSiv::new_from_slice(key.as_ref()).map_err(|_| CryptoError::InvalidKeySize)?;

        Ok(Self { cipher })
    }

    pub fn encrypt<P>(&self, plaintext: P) -> Vec<u8>
    where
        P: AsRef<[u8]>,
    {
        let nonce = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(Self::NONCE_SIZE)
            .map(char::from)
            .collect::<String>();

        let mut ciphertext: Vec<u8> = self
            .cipher
            .encrypt(Nonce::from_slice(nonce.as_bytes()), plaintext.as_ref())
            .expect("encyrption failed");

        let mut nc = Vec::with_capacity(nonce.len() + ciphertext.len());
        nc.extend_from_slice(nonce.as_bytes());
        nc.append(&mut ciphertext);

        nc
    }

    pub fn decrypt<C>(&self, nonce_ciphertext: C) -> Vec<u8>
    where
        C: AsRef<[u8]>,
    {
        let nc = nonce_ciphertext.as_ref();
        let nonce = Nonce::from_slice(&nc[..Self::NONCE_SIZE]);

        self.cipher.decrypt(nonce, &nc[Self::NONCE_SIZE..]).unwrap()
    }
}

impl FromRef<AppState> for Aead256 {
    fn from_ref(state: &AppState) -> Self {
        state.aead.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AEAD_KEY: &str = "Dhh0uAQDDQO90882bbZbyz1jWf4MrxI2";

    #[test]
    fn encrypt_decrypt() {
        let aead = Aead256::new(AEAD_KEY).unwrap();

        let input = "foo bar";

        let nonce_cipher = aead.encrypt(input);

        let plaintext = aead.decrypt(nonce_cipher);

        assert_eq!(input.as_bytes(), plaintext);
    }
}
