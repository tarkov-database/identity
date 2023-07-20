use crate::{crypto::cert::CertificateStore, state::AppState};

use super::{HeaderExt, Token, TokenError, TokenValidation};

use std::sync::Arc;

use axum::extract::FromRef;
use jsonwebtoken::{Algorithm, DecodingKey, Header};
use serde::de::DeserializeOwned;

#[derive(Clone)]
pub struct TokenVerifier {
    store: CertificateStore,
}

impl TokenVerifier {
    pub fn new(store: CertificateStore) -> Self {
        Self { store }
    }

    pub async fn verify<T>(&self, token: &str) -> Result<(Header, T), TokenError>
    where
        T: Token + TokenValidation + DeserializeOwned,
    {
        let header = jsonwebtoken::decode_header(token).map_err(TokenError::from)?;

        let typ = header.token_type()?;
        if typ != T::TYPE {
            return Err(TokenError::Invalid);
        }

        let fingerprint = header.x5t_s256.as_deref().ok_or(TokenError::Invalid)?;

        let (chain, is_stored) = if let Some(chain) = self.store.get(fingerprint).await {
            self.store.trust_anchor().validate_period()?;
            chain.validate_period().map_err(|_| TokenError::Invalid)?;
            (chain, true)
        } else {
            let chain = header.get_certificates()?.ok_or(TokenError::Invalid)?;
            let trust_anchor = self.store.trust_anchor();
            chain
                .validate_path(trust_anchor)
                .map_err(|_| TokenError::Invalid)?;
            (Arc::new(chain), false)
        };

        // TODO: Implement decoding key by reference
        let key = DecodingKey::from_ed_der(chain.leaf().public_key_bytes()?);

        // TODO: Handle different algorithms
        let alg = Algorithm::EdDSA;
        let validation = T::validation(alg);

        let data = jsonwebtoken::decode::<T>(token, &key, &validation)?;

        if !is_stored {
            self.store.add(chain).await?;
        }

        Ok((data.header, data.claims))
    }
}

impl FromRef<AppState> for TokenVerifier {
    fn from_ref(state: &AppState) -> Self {
        state.token_verifier.clone()
    }
}
