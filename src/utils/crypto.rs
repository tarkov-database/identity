use crate::{AppState, Result};

use aes_gcm_siv::{aead::Aead, Aes256GcmSiv, KeyInit, Nonce};
use axum::extract::FromRef;
use base64ct::{Base64, Encoding};
use rand::{distributions::Alphanumeric, Rng};

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("key has an invalid size")]
    InvalidKeySize,
    #[error("decoding error: {0}")]
    Decode(#[from] base64ct::Error),
}

#[derive(Clone)]
pub struct Aead256 {
    cipher: Aes256GcmSiv,
}

impl Aead256 {
    const KEY_SIZE: usize = 256 / 8;
    const NONCE_SIZE: usize = 96 / 8;

    pub fn new_from_b64<S: AsRef<str>>(key: S) -> Result<Self> {
        let key = Base64::decode_vec(key.as_ref()).map_err(CryptoError::from)?;

        Self::new(&key)
    }

    pub fn new(key: &[u8]) -> Result<Self> {
        let cipher = Aes256GcmSiv::new_from_slice(key).map_err(|_| CryptoError::InvalidKeySize)?;

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
            .expect("encryption failed");

        let mut nc = Vec::with_capacity(nonce.len() + ciphertext.len());
        nc.extend_from_slice(nonce.as_bytes());
        nc.append(&mut ciphertext);

        nc
    }

    pub fn encrypt_b64<P>(&self, plaintext: P) -> String
    where
        P: AsRef<[u8]>,
    {
        let output = self.encrypt(plaintext);

        Base64::encode_string(&output)
    }

    pub fn decrypt<C>(&self, nonce_ciphertext: C) -> Vec<u8>
    where
        C: AsRef<[u8]>,
    {
        let nc = nonce_ciphertext.as_ref();
        let nonce = Nonce::from_slice(&nc[..Self::NONCE_SIZE]);

        self.cipher.decrypt(nonce, &nc[Self::NONCE_SIZE..]).unwrap()
    }

    pub fn decrypt_b64<S>(&self, input: S) -> Result<Vec<u8>>
    where
        S: AsRef<str>,
    {
        let nc = Base64::decode_vec(input.as_ref()).map_err(CryptoError::from)?;
        let output = self.decrypt(nc);

        Ok(output)
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

    const AEAD_KEY: &str = "gTLabrRRRBtAdO5MiBMaK/R6kajGHXbYgjjwJ0/NoxE=";

    #[test]
    fn encrypt_decrypt() {
        let aead = Aead256::new_from_b64(AEAD_KEY).unwrap();

        let input = "foo bar";

        let nonce_cipher = aead.encrypt(input);

        let plaintext = aead.decrypt(nonce_cipher);

        assert_eq!(input.as_bytes(), plaintext);
    }
}
