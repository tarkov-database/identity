use crate::{
    database::{Collection, DatabaseModel},
    Result,
};

use super::ClientError;

use chrono::{DateTime, Utc};
use mongodb::{
    bson::{self, doc, oid::ObjectId, serde_helpers::chrono_datetime_as_bson_datetime, Document},
    options::{FindOneAndUpdateOptions, FindOptions, ReturnDocument},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientDocument {
    #[serde(rename = "_id")]
    pub id: ObjectId,
    pub user: ObjectId,
    pub service: ObjectId,
    pub name: String,
    pub scope: Vec<String>,
    pub locked: bool,
    pub token: Option<TokenDocument>,
    #[serde(with = "chrono_datetime_as_bson_datetime")]
    pub last_modified: DateTime<Utc>,
    #[serde(with = "chrono_datetime_as_bson_datetime")]
    pub created: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenDocument {
    pub id: bson::Uuid,
    #[serde(default, with = "chrono_datetime_as_bson_datetime")]
    pub last_seen: DateTime<Utc>,
    #[serde(with = "chrono_datetime_as_bson_datetime")]
    pub expires: DateTime<Utc>,
    #[serde(with = "chrono_datetime_as_bson_datetime")]
    pub issued: DateTime<Utc>,
}

impl TokenDocument {
    pub fn new(expires: DateTime<Utc>) -> Self {
        Self {
            id: Uuid::new_v4().into(),
            last_seen: Default::default(),
            expires,
            issued: Utc::now(),
        }
    }
}

impl DatabaseModel for ClientDocument {
    const COLLECTION_NAME: &'static str = "clients";
}

impl Collection<ClientDocument> {
    pub async fn get_by_id(&self, id: ObjectId) -> Result<ClientDocument> {
        let filter = doc! { "_id": id };

        let item = self
            .get_one(filter, None)
            .await?
            .ok_or(ClientError::NotFound)?;

        Ok(item)
    }

    pub async fn get_by_id_and_user(
        &self,
        id: ObjectId,
        user_id: ObjectId,
    ) -> Result<ClientDocument> {
        let filter = doc! { "_id": id, "user": user_id };

        let item = self
            .get_one(filter, None)
            .await?
            .ok_or(ClientError::NotFound)?;

        Ok(item)
    }

    pub async fn get_by_user(&self, user_id: ObjectId) -> Result<Vec<ClientDocument>> {
        let filter = doc! { "user": user_id };
        let sort = doc! { "created": 1 };

        let opts = FindOptions::builder().sort(sort).build();

        let items = self.get_many(filter, opts).await?;

        Ok(items)
    }

    pub async fn get_by_service(&self, service_id: ObjectId) -> Result<Vec<ClientDocument>> {
        let filter = doc! { "service": service_id };
        let sort = doc! { "created": 1 };

        let opts = FindOptions::builder().sort(sort).build();

        let items = self.get_many(filter, opts).await?;

        Ok(items)
    }

    pub async fn get_by_user_and_service(
        &self,
        user_id: ObjectId,
        service_id: ObjectId,
    ) -> Result<Vec<ClientDocument>> {
        let filter = doc! { "user": user_id, "service": service_id };
        let sort = doc! { "created": 1 };

        let opts = FindOptions::builder().sort(sort).build();

        let items = self.get_many(filter, opts).await?;

        Ok(items)
    }

    pub async fn get_by_token(
        &self,
        token_id: impl Into<bson::Uuid>,
    ) -> Result<Option<ClientDocument>> {
        let filter = doc! { "token.id": token_id.into() };

        let item = self.get_one(filter, None).await?;

        Ok(item)
    }

    pub async fn insert(&self, doc: &ClientDocument) -> Result<ObjectId> {
        let id = self.insert_one(doc, None).await?.as_object_id().unwrap();

        Ok(id)
    }

    pub async fn update(
        &self,
        id: ObjectId,
        user_id: impl Into<Option<ObjectId>>,
        update: Document,
    ) -> Result<ClientDocument> {
        let mut filter = doc! { "_id": id };
        if let Some(user_id) = user_id.into() {
            filter.insert("user", user_id);
        }

        let doc = doc! {
            "$currentDate": { "lastModified": true },
            "$set": update,
        };

        let opts = FindOneAndUpdateOptions::builder()
            .return_document(ReturnDocument::After)
            .build();

        let item = self
            .update_one(filter, doc, opts)
            .await?
            .ok_or(ClientError::NotFound)?;

        Ok(item)
    }

    pub async fn delete(&self, id: ObjectId) -> Result<()> {
        let filter = doc! { "_id": id };

        if !self.delete_one(filter, None).await? {
            return Err(ClientError::NotFound)?;
        }

        Ok(())
    }

    pub async fn delete_by_user(&self, user_id: ObjectId) -> Result<u64> {
        let filter = doc! { "user": user_id };

        let count = self.delete_many(filter, None).await?;

        Ok(count)
    }

    pub async fn delete_by_service(&self, service_id: ObjectId) -> Result<u64> {
        let filter = doc! { "service": service_id };

        let count = self.delete_many(filter, None).await?;

        Ok(count)
    }

    pub async fn set_token(&self, client_id: ObjectId, doc: TokenDocument) -> Result<()> {
        let filter = doc! { "_id": client_id };

        let doc = doc! {
            "$currentDate": { "lastModified": true },
            "$set": { "token": bson::to_bson(&doc).unwrap() },
        };

        self.update_one(filter, doc, None)
            .await?
            .ok_or(ClientError::NotFound)?;

        Ok(())
    }

    pub async fn set_token_as_seen(&self, client_id: ObjectId) -> Result<()> {
        let filter = doc! { "_id": client_id };

        let doc = doc! {
            "$currentDate": { "lastModified": true },
            "$currentDate": { "token.lastSeen": true },
        };

        self.update_one(filter, doc, None)
            .await?
            .ok_or(ClientError::NotFound)?;

        Ok(())
    }
}
