use argon2::Argon2;
use password_hash::{PasswordHash, PasswordVerifier, SaltString};
use rand::rngs::OsRng;

#[derive(Clone)]
pub struct PasswordHasher<T> {
    context: T,
}

impl<T> PasswordHasher<T>
where
    T: password_hash::PasswordHasher,
{
    #[inline]
    pub fn hash(&self, password: impl AsRef<[u8]>) -> Result<String, password_hash::Error> {
        let salt = SaltString::generate(&mut OsRng);
        let hash = self.context.hash_password(password.as_ref(), &salt)?;

        Ok(hash.to_string())
    }

    #[inline]
    pub fn verify(
        &self,
        password: impl AsRef<[u8]>,
        hash: impl AsRef<str>,
    ) -> Result<(), password_hash::Error> {
        let hash = PasswordHash::new(hash.as_ref())?;
        self.context.verify_password(password.as_ref(), &hash)?;

        Ok(())
    }
}

impl Default for PasswordHasher<Argon2<'_>> {
    fn default() -> Self {
        Self::from(argon2::Params::DEFAULT)
    }
}

impl From<argon2::Params> for PasswordHasher<Argon2<'_>> {
    fn from(params: argon2::Params) -> Self {
        let context = Argon2::from(params);

        Self { context }
    }
}
