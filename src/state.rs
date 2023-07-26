use crate::{
    auth::{
        password::{hibp::HibpClient, PasswordHasher, PasswordValidator},
        token::{sign::TokenSigner, verify::TokenVerifier},
    },
    config::{AppConfig, GlobalConfig},
    crypto::cert::CertificateStore,
    database::Database,
    http::HttpClient,
    mail::Client as MailClient,
    services::sso::GitHub,
    utils,
};

use mongodb::options::{ClientOptions, Tls, TlsOptions};
use pki_rs::certificate::Certificate;
use tokio::fs;

#[derive(Clone)]
pub struct AppState {
    pub database: Database,
    pub password_validator: PasswordValidator,
    pub password_hasher: PasswordHasher,
    pub token_signer: TokenSigner,
    pub token_verifier: TokenVerifier,
    pub mail_client: MailClient,
    pub github_client: GitHub,
    pub global_config: GlobalConfig,
}

impl AppState {
    pub async fn from_config(config: AppConfig) -> crate::Result<Self> {
        let cert_store = {
            let trust_anchor_file = fs::read(config.token_trust_anchor).await?;
            let trust_anchor =
                utils::pem::read_cert(&trust_anchor_file[..]).map(Certificate::from_der)??;

            CertificateStore::new(trust_anchor)
        };

        let token_signer = TokenSigner::builder()
            .set_key_path(config.token_key)
            .set_chain_path(config.token_certs)
            .set_store(cert_store.clone())
            .build()
            .await?;

        let token_verifier = TokenVerifier::new(cert_store);

        let database = {
            let mut opts = ClientOptions::parse(config.mongo_uri).await?;

            if config.mongo_tls {
                let tls = TlsOptions::builder()
                    .cert_key_file_path(config.mongo_cert_key)
                    .ca_file_path(config.mongo_ca)
                    .build();

                opts.tls = Some(Tls::Enabled(tls));
            }

            Database::new(config.mongo_db, opts)?
        };

        let http_client = HttpClient::default();

        let hibp_client = HibpClient::with_client(http_client.clone());

        let password_validator = PasswordValidator::new(hibp_client, config.hibp_check);
        let password_hasher = PasswordHasher::default();

        let mail_client = MailClient::new(
            config.mg_key,
            config.mg_region,
            config.mg_domain,
            config.mail_from,
            http_client.clone(),
        )?;

        let sso_github = GitHub::new(
            config.gh_client_id,
            config.gh_client_secret,
            config.gh_redirect_uri,
            http_client,
        )?;

        let global_config = GlobalConfig {
            allowed_domains: config.allowed_domains,
            editor_mail_addrs: config.editor_mail_address,
        };

        Ok(Self {
            mail_client,
            database,
            password_validator,
            password_hasher,
            token_signer,
            token_verifier,
            github_client: sso_github,
            global_config,
        })
    }
}
