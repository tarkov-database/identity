use crate::{
    crypto::{cert::CertificateStore, Secret},
    state::AppState,
    utils,
};

use super::{Token, TokenError};

use std::path::PathBuf;

use axum::extract::FromRef;
use base64ct::{Base64, Encoding};
use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use pki_rs::certificate::{Certificate, CertificateChain};
use serde::Serialize;

#[derive(Clone)]
pub struct TokenSigner {
    alg: Algorithm,
    key: EncodingKey,
    chain_base64: Vec<String>,
    cert_fingerprint: String,
    cert_store: CertificateStore,
}

impl TokenSigner {
    pub fn builder() -> TokenSignerBuilder<WantsKey> {
        TokenSignerBuilder::default()
    }

    pub async fn sign<T>(&self, claims: &T) -> Result<Secret<String>, TokenError>
    where
        T: Token + Serialize,
    {
        self.cert_store.trust_anchor().validate_period()?;
        let chain = self
            .cert_store
            .get(&self.cert_fingerprint)
            .await
            .expect("bug: certificate not found");
        chain.validate_period()?;

        let not_after = DateTime::<Utc>::from(chain.leaf().validity().not_after.to_system_time());
        if claims.expires_at() > not_after {
            return Err(TokenError::CertLifetimeExceeded);
        }

        let mut header = Header::new(self.alg);
        header.typ = Some(T::TYPE.to_string());
        header.x5c = Some(self.chain_base64.clone());
        header.x5t_s256 = Some(self.cert_fingerprint.clone());

        let token = jsonwebtoken::encode(&header, claims, &self.key)
            .map_err(TokenError::Encoding)?
            .into();

        Ok(token)
    }
}

impl FromRef<AppState> for TokenSigner {
    fn from_ref(state: &AppState) -> Self {
        state.token_signer.clone()
    }
}

#[derive(thiserror::Error, Debug)]
pub enum BuilderError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("pki error: {0}")]
    Pki(#[from] pki_rs::error::Error),
}

pub struct TokenSignerBuilder<State>(State);

impl Default for TokenSignerBuilder<WantsKey> {
    fn default() -> Self {
        Self(WantsKey(()))
    }
}

pub struct WantsKey(());

impl TokenSignerBuilder<WantsKey> {
    pub fn set_key_path(self, key_path: PathBuf) -> TokenSignerBuilder<WantsChain> {
        TokenSignerBuilder(WantsChain { key_path })
    }
}

pub struct WantsChain {
    key_path: PathBuf,
}

impl TokenSignerBuilder<WantsChain> {
    pub fn set_chain_path(self, chain_path: PathBuf) -> TokenSignerBuilder<WantsStore> {
        TokenSignerBuilder(WantsStore {
            key_path: self.0.key_path,
            chain_path,
        })
    }
}

pub struct WantsStore {
    key_path: PathBuf,
    chain_path: PathBuf,
}

impl TokenSignerBuilder<WantsStore> {
    pub fn set_store(self, store: CertificateStore) -> TokenSignerBuilder<Params> {
        TokenSignerBuilder(Params {
            key_path: self.0.key_path,
            chain_path: self.0.chain_path,
            store,
        })
    }
}

pub struct Params {
    key_path: PathBuf,
    chain_path: PathBuf,
    store: CertificateStore,
}

impl TokenSignerBuilder<Params> {
    pub async fn build(self) -> Result<TokenSigner, BuilderError> {
        let Params {
            key_path,
            chain_path,
            store,
        } = self.0;

        let key_der = {
            let file = tokio::fs::read(&key_path).await?;
            utils::pem::read_key(&file[..])?
        };

        let key = EncodingKey::from_ed_der(&key_der);

        let chain_der = {
            let file = tokio::fs::read(&chain_path).await?;
            utils::pem::read_certs(&file[..])?
        };

        let mut chain_certs = chain_der
            .iter()
            .map(Certificate::from_der)
            .collect::<Result<Vec<_>, _>>()?;

        let leaf = chain_certs.pop().unwrap();
        let intermediates = chain_certs;

        let fingerprint = leaf.fingerprint_base64()?;

        if !leaf
            .get_key_usage()
            .map(|usage| usage.digital_signature())
            .unwrap_or_default()
        {
            return Err(pki_rs::error::Error::from(
                pki_rs::certificate::Error::KeyUsageViolation,
            ))?;
        }

        let chain = CertificateChain::new(intermediates, leaf);

        store.add(chain).await?;

        let chain_base64 = chain_der
            .iter()
            .rev()
            .map(|c| Base64::encode_string(c))
            .collect::<Vec<_>>();

        Ok(TokenSigner {
            alg: Algorithm::EdDSA,
            key,
            chain_base64,
            cert_fingerprint: fingerprint,
            cert_store: store,
        })
    }
}
