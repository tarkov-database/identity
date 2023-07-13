use crate::{
    database::{Collection, DatabaseModel},
    Result,
};

use super::ServiceError;

use chrono::{DateTime, Utc};
use mongodb::{
    bson::{doc, oid::ObjectId, serde_helpers::chrono_datetime_as_bson_datetime, Document},
    options::{FindOneAndUpdateOptions, ReturnDocument},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceDocument {
    #[serde(rename = "_id")]
    pub id: ObjectId,
    pub name: String,
    pub audience: Vec<String>,
    pub scope: Vec<String>,
    pub scope_default: Vec<String>,
    #[serde(with = "chrono_datetime_as_bson_datetime")]
    pub last_modified: DateTime<Utc>,
    #[serde(with = "chrono_datetime_as_bson_datetime")]
    pub created: DateTime<Utc>,
}

impl DatabaseModel for ServiceDocument {
    const COLLECTION_NAME: &'static str = "services";
}

impl Collection<ServiceDocument> {
    pub async fn get_by_id(&self, id: ObjectId) -> Result<ServiceDocument> {
        let filter = doc! { "_id": id };

        let item = self
            .get_one(filter, None)
            .await?
            .ok_or(ServiceError::NotFound)?;

        Ok(item)
    }

    pub async fn get_by_name(&self, name: &str) -> Result<ServiceDocument> {
        let filter = doc! { "name": name };

        let item = self
            .get_one(filter, None)
            .await?
            .ok_or(ServiceError::NotFound)?;

        Ok(item)
    }

    pub async fn get_by_audience(&self, audience: &str) -> Result<ServiceDocument> {
        let filter = doc! { "audience": audience };

        let item = self
            .get_one(filter, None)
            .await?
            .ok_or(ServiceError::NotFound)?;

        Ok(item)
    }

    pub async fn insert(&self, item: &ServiceDocument) -> Result<ObjectId> {
        let id = self.insert_one(item, None).await?.as_object_id().unwrap();

        Ok(id)
    }

    pub async fn update(&self, id: ObjectId, update: Document) -> Result<ServiceDocument> {
        let filter = doc! { "_id": id };

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
            .ok_or(ServiceError::NotFound)?;

        Ok(item)
    }

    pub async fn delete(&self, id: ObjectId) -> Result<()> {
        let filter = doc! { "_id": id };

        if self.delete_one(filter, None).await? {
            return Err(ServiceError::NotFound)?;
        }

        Ok(())
    }
}
