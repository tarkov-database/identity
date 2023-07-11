use std::{collections::HashMap, sync::Arc};

use pki_rs::certificate::{Certificate, CertificateChain};
use tokio::sync::RwLock;

pub type CertificateMap = HashMap<String, Arc<CertificateChain>>;

#[derive(Clone)]
pub struct CertificateStore {
    trust_anchor: Arc<Certificate>,
    trusted_chains: Arc<RwLock<CertificateMap>>,
}

impl CertificateStore {
    pub fn new(trust_anchor: Certificate) -> Self {
        Self {
            trust_anchor: Arc::new(trust_anchor),
            trusted_chains: Arc::new(RwLock::new(CertificateMap::with_capacity(3))),
        }
    }

    pub fn trust_anchor(&self) -> &Certificate {
        &self.trust_anchor
    }

    pub async fn add<C>(&self, chain: C) -> Result<(), pki_rs::error::Error>
    where
        C: Into<Arc<CertificateChain>>,
    {
        let chain = chain.into();
        chain.validate_path(&self.trust_anchor)?;

        let fingerprint = chain.leaf().fingerprint_base64()?;
        self.trusted_chains.write().await.insert(fingerprint, chain);

        Ok(())
    }

    pub fn blocking_add<C>(&self, chain: C) -> Result<(), pki_rs::error::Error>
    where
        C: Into<Arc<CertificateChain>>,
    {
        let chain = chain.into();
        chain.validate_path(&self.trust_anchor)?;

        let fingerprint = chain.leaf().fingerprint_base64()?;
        self.trusted_chains
            .blocking_write()
            .insert(fingerprint, chain);

        Ok(())
    }

    pub async fn get(&self, fingerprint: &str) -> Option<Arc<CertificateChain>> {
        self.trusted_chains.read().await.get(fingerprint).cloned()
    }

    pub fn blocking_get(&self, fingerprint: &str) -> Option<Arc<CertificateChain>> {
        self.trusted_chains
            .blocking_read()
            .get(fingerprint)
            .cloned()
    }
}
