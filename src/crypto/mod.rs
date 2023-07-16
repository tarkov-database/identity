pub mod aead;
pub mod certificate;
pub mod gen;

use base64ct::{Base64UrlUnpadded, Encoding};

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
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl<const SIZE: usize> Clone for Secret<SIZE> {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl<const SIZE: usize> Copy for Secret<SIZE> {}

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
            let str = Base64UrlUnpadded::encode_string(&self.0);
            serializer.serialize_str(&str)
        } else {
            serializer.serialize_bytes(&self.0)
        }
    }
}
