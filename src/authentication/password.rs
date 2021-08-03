use argon2::{
    password_hash::{
        PasswordHash, PasswordHasher, PasswordVerifier, Result as A2Result, SaltString,
    },
    Argon2, Version,
};
use passwords::{analyzer, scorer};
use rand::rngs::OsRng;

/// Minimum password score
const SCORE_MIN: f64 = 85.0;

// Argon2 parameters
const M_COST: u32 = 4 << 10;
const T_COST: u32 = 3;
const P_COST: u32 = 2;
const VERSION: Version = Version::V0x13;

#[derive(Debug, thiserror::Error)]
pub enum PasswordError {
    #[error("password is invalid: {0}")]
    InvalidPassword(String),
    #[error("password is too weak")]
    BadScore,
}

pub fn hash_password<S: AsRef<[u8]>>(password: S) -> A2Result<String> {
    let salt = SaltString::generate(&mut OsRng);

    let argon2 = Argon2::new(None, T_COST, M_COST, P_COST, VERSION).unwrap();

    let hash = argon2.hash_password_simple(password.as_ref(), salt.as_ref())?;

    Ok(hash.to_string())
}

pub fn verify_password<S, H>(password: S, hash: H) -> A2Result<()>
where
    S: AsRef<[u8]>,
    H: AsRef<str>,
{
    let argon2 = Argon2::new(None, T_COST, M_COST, P_COST, VERSION).unwrap();

    let parsed_hash = PasswordHash::new(hash.as_ref())?;

    argon2.verify_password(password.as_ref(), &parsed_hash)?;

    Ok(())
}

pub fn validate_password(password: &str) -> Result<(), PasswordError> {
    if !password.is_ascii() {
        return Err(PasswordError::InvalidPassword(
            "password has invalid characters".to_string(),
        ));
    }

    let analysis = analyzer::analyze(password);

    if analysis.length() < 16 {
        return Err(PasswordError::InvalidPassword(
            "password must have at least 16 characters".to_string(),
        ));
    }
    if analysis.length() > 80 {
        return Err(PasswordError::InvalidPassword(
            "password cannot exceed 80 characters".to_string(),
        ));
    }
    if analysis.uppercase_letters_count() < 1 {
        return Err(PasswordError::InvalidPassword(
            "password must have at least one uppercase character".to_string(),
        ));
    }
    if analysis.lowercase_letters_count() < 1 {
        return Err(PasswordError::InvalidPassword(
            "password must have at least one lowercase character".to_string(),
        ));
    }
    if analysis.lowercase_letters_count() < 1 {
        return Err(PasswordError::InvalidPassword(
            "password must have at least one lowercase character".to_string(),
        ));
    }
    if analysis.numbers_count() < 1 {
        return Err(PasswordError::InvalidPassword(
            "password must have at least one digit".to_string(),
        ));
    }

    if scorer::score(&analysis) < SCORE_MIN {
        return Err(PasswordError::BadScore);
    }

    Ok(())
}
