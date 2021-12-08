use crate::Result;

use mongodb::{options::ClientOptions, Client, Collection};

#[derive(Debug, Clone)]
pub struct Database {
    client: Client,
    db_name: String,
}

impl Database {
    pub fn new(opts: ClientOptions, db: &str) -> Result<Self> {
        let client = Client::with_options(opts)?;

        Ok(Self {
            client,
            db_name: db.to_string(),
        })
    }

    pub fn collection<T>(&self, name: &str) -> Collection<T> {
        self.client.database(&self.db_name).collection(name)
    }
}
