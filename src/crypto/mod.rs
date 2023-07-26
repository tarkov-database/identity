pub mod aead;
pub mod cert;
pub mod gen;
pub mod hash;

use std::marker::PhantomData;

use base64ct::{Base64UrlUnpadded, Encoding};
use rand::{distributions::Alphanumeric, rngs::StdRng, Rng};
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

#[non_exhaustive]
pub struct Secret<T: Zeroize>(T);

impl<const SIZE: usize> Secret<[u8; SIZE]> {
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

impl<const SIZE: usize> From<[u8; SIZE]> for Secret<[u8; SIZE]> {
    fn from(bytes: [u8; SIZE]) -> Self {
        Self(bytes)
    }
}

impl<const SIZE: usize> TryFrom<&[u8]> for Secret<[u8; SIZE]> {
    type Error = InvalidSize;

    #[inline(always)]
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        bytes.try_into().map(Self).map_err(|_| InvalidSize)
    }
}

impl<const SIZE: usize> TryFrom<Vec<u8>> for Secret<[u8; SIZE]> {
    type Error = InvalidSize;

    #[inline(always)]
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        bytes.try_into().map(Self).map_err(|_| InvalidSize)
    }
}

impl Secret<Vec<u8>> {
    pub fn new(len: usize) -> Self {
        let mut rng = StdRng::from_entropy();
        Self::generate(&mut rng, len)
    }

    pub fn generate(mut rng: impl CryptoRngCore, len: usize) -> Self {
        let mut secret = vec![0u8; len];
        rng.fill_bytes(&mut secret);

        Self(secret)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl From<Vec<u8>> for Secret<Vec<u8>> {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl From<&[u8]> for Secret<Vec<u8>> {
    fn from(bytes: &[u8]) -> Self {
        Self(bytes.to_owned())
    }
}

impl Secret<String> {
    pub fn new(len: usize) -> Self {
        let mut rng = StdRng::from_entropy();
        Self::generate(&mut rng, len)
    }

    pub fn generate(rng: impl CryptoRngCore, len: usize) -> Self {
        let secret = rng
            .sample_iter(&Alphanumeric)
            .take(len)
            .map(char::from)
            .collect::<String>();

        Self(secret)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl From<String> for Secret<String> {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl<T: Zeroize + Clone> Clone for Secret<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T, U> AsRef<U> for Secret<T>
where
    U: ?Sized,
    T: AsRef<U> + Zeroize,
{
    #[inline(always)]
    fn as_ref(&self) -> &U {
        self.0.as_ref()
    }
}

impl<T: Zeroize> Zeroize for Secret<T> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize> ZeroizeOnDrop for Secret<T> {}

impl<T: Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.0.zeroize()
    }
}

pub struct SecretVisitor<T>(PhantomData<T>);

impl<T> SecretVisitor<T> {
    pub fn new() -> Self {
        Self(PhantomData)
    }
}

impl<'de, const SIZE: usize> serde::de::Visitor<'de> for SecretVisitor<[u8; SIZE]> {
    type Value = Secret<[u8; SIZE]>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a base64url unpadded string or a byte array with a compatible length")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let mut bytes = [0u8; SIZE];
        if let Err(err) = Base64UrlUnpadded::decode(v, &mut bytes) {
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

    fn visit_string<E>(self, mut v: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let mut bytes = [0u8; SIZE];
        if let Err(err) = Base64UrlUnpadded::decode(&v, &mut bytes) {
            let err = match err {
                base64ct::Error::InvalidEncoding => {
                    E::invalid_value(serde::de::Unexpected::Str(&v), &self)
                }
                base64ct::Error::InvalidLength => E::invalid_length(v.len(), &self),
            };
            return Err(err);
        }

        v.zeroize();

        Ok(Secret(bytes))
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let bytes = v
            .try_into()
            .map_err(|_| E::invalid_length(v.len(), &self))?;

        Ok(Secret(bytes))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let bytes = v.try_into().map_err(|mut e: Vec<u8>| {
            let len = e.len();
            e.zeroize();
            E::invalid_length(len, &self)
        })?;

        Ok(Secret(bytes))
    }
}

impl<'de, const SIZE: usize> serde::Deserialize<'de> for Secret<[u8; SIZE]> {
    fn deserialize<D>(deserializer: D) -> Result<Secret<[u8; SIZE]>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            deserializer.deserialize_string(SecretVisitor::<[u8; SIZE]>::new())
        } else {
            deserializer.deserialize_byte_buf(SecretVisitor::<[u8; SIZE]>::new())
        }
    }
}

impl<const SIZE: usize> serde::Serialize for Secret<[u8; SIZE]> {
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

impl<'de> serde::de::Visitor<'de> for SecretVisitor<Vec<u8>> {
    type Value = Secret<Vec<u8>>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a base64url unpadded string or a byte array")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let bytes = match Base64UrlUnpadded::decode_vec(v) {
            Ok(v) => v,
            Err(base64ct::Error::InvalidEncoding) => {
                return Err(E::invalid_value(serde::de::Unexpected::Str(v), &self));
            }
            Err(base64ct::Error::InvalidLength) => {
                return Err(E::invalid_length(v.len(), &self));
            }
        };

        Ok(Secret(bytes))
    }

    fn visit_string<E>(self, mut v: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let bytes = match Base64UrlUnpadded::decode_vec(&v) {
            Ok(v) => v,
            Err(base64ct::Error::InvalidEncoding) => {
                return Err(E::invalid_value(serde::de::Unexpected::Str(&v), &self));
            }
            Err(base64ct::Error::InvalidLength) => {
                return Err(E::invalid_length(v.len(), &self));
            }
        };

        v.zeroize();

        Ok(Secret(bytes))
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(v.into())
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Secret(v))
    }
}

impl<'de> serde::Deserialize<'de> for Secret<Vec<u8>> {
    fn deserialize<D>(deserializer: D) -> Result<Secret<Vec<u8>>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            deserializer.deserialize_string(SecretVisitor::<Vec<u8>>::new())
        } else {
            deserializer.deserialize_byte_buf(SecretVisitor::<Vec<u8>>::new())
        }
    }
}

impl serde::Serialize for Secret<Vec<u8>> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            let len = match self.0.len().checked_mul(4) {
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

impl<'de> serde::de::Visitor<'de> for SecretVisitor<String> {
    type Value = Secret<String>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a utf-8 string or a byte array")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Secret(v.to_owned()))
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Secret(v))
    }
}

impl<'de> serde::Deserialize<'de> for Secret<String> {
    fn deserialize<D>(deserializer: D) -> Result<Secret<String>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_string(SecretVisitor::<String>::new())
    }
}

impl serde::Serialize for Secret<String> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}
