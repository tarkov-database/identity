pub mod aead;
pub mod cert;
pub mod gen;
pub mod hash;

use base64ct::{Base64UrlUnpadded, Encoding};
use rand::rngs::StdRng;
use rand_core::{CryptoRngCore, SeedableRng};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Debug)]
pub struct InvalidSize;

impl std::fmt::Display for InvalidSize {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid size")
    }
}

impl std::error::Error for InvalidSize {}

pub struct Secret<const SIZE: usize>([u8; SIZE]);

impl<const SIZE: usize> Secret<SIZE> {
    pub fn new() -> Self {
        let mut rng = StdRng::from_entropy();
        Self::generate(&mut rng)
    }

    pub fn generate(mut rng: impl CryptoRngCore) -> Self {
        let mut secret = [0u8; SIZE];
        rng.fill_bytes(&mut secret);

        Self(secret)
    }

    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub const fn len(&self) -> usize {
        self.0.len()
    }
}

impl<const SIZE: usize> Clone for Secret<SIZE> {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl<const SIZE: usize> From<[u8; SIZE]> for Secret<SIZE> {
    fn from(bytes: [u8; SIZE]) -> Self {
        Self(bytes)
    }
}

impl<const SIZE: usize> TryFrom<&[u8]> for Secret<SIZE> {
    type Error = InvalidSize;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != SIZE {
            return Err(InvalidSize);
        }

        let mut secret = [0u8; SIZE];
        secret.copy_from_slice(bytes);

        Ok(Self(secret))
    }
}

impl<const SIZE: usize> AsRef<[u8]> for Secret<SIZE> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const SIZE: usize> Zeroize for Secret<SIZE> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<const SIZE: usize> ZeroizeOnDrop for Secret<SIZE> {}

impl<const SIZE: usize> Drop for Secret<SIZE> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

pub struct SecretVisitor<const SIZE: usize>;

impl<'de, const SIZE: usize> serde::de::Visitor<'de> for SecretVisitor<SIZE> {
    type Value = Secret<SIZE>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a base64url unpadded string or a byte array with a compatible length")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let mut bytes = [0u8; SIZE];
        if let Err(err) = Base64UrlUnpadded::decode(v.as_bytes(), &mut bytes) {
            let err = match err {
                base64ct::Error::InvalidEncoding => {
                    E::invalid_value(serde::de::Unexpected::Str(v), &self)
                }
                base64ct::Error::InvalidLength => E::invalid_length(v.len(), &self),
            };
            return Err(err);
        }

        Ok(Secret(bytes))
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let bytes = v
            .try_into()
            .map_err(|_| E::invalid_length(v.len(), &"a byte array with a compatible length"))?;

        Ok(Secret(bytes))
    }
}

impl<'de, const SIZE: usize> serde::Deserialize<'de> for Secret<SIZE> {
    fn deserialize<D>(deserializer: D) -> Result<Secret<SIZE>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            deserializer.deserialize_str(SecretVisitor)
        } else {
            deserializer.deserialize_bytes(SecretVisitor)
        }
    }
}

impl<const SIZE: usize> serde::Serialize for Secret<SIZE> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            let len = match SIZE.checked_mul(4) {
                Some(v) => (v / 3) + (v % 3 != 0) as usize,
                None => return Err(serde::ser::Error::custom("invalid secret size")),
            };

            let mut buf = Zeroizing::new(vec![0u8; len]);

            let str = Base64UrlUnpadded::encode(&self.0, &mut buf).map_err(|_| {
                serde::ser::Error::custom("failed to serialize secret as base64url unpadded string")
            })?;

            serializer.serialize_str(str)
        } else {
            serializer.serialize_bytes(&self.0)
        }
    }
}
