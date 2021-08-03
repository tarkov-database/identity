mod filter;
mod handler;

use crate::{
    database::Database,
    error,
    model::{ListOptions, Status},
    service::ServiceError,
    Result,
};

use chrono::{DateTime, Utc};
use futures::stream::TryStreamExt;
use mongodb::{
    bson::{doc, oid::ObjectId, serde_helpers::chrono_datetime_as_bson_datetime, Document},
    options::{FindOneAndUpdateOptions, FindOptions, ReturnDocument},
};
use serde::{Deserialize, Serialize};
use warp::hyper::StatusCode;

pub use filter::filters;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("client not found")]
    NotFound,
    #[error("client id is invalid")]
    InvalidId,
}

impl warp::reject::Reject for ClientError {}

impl error::ErrorResponse for ClientError {
    type Response = Status;

    fn status_code(&self) -> StatusCode {
        match self {
            ClientError::NotFound => StatusCode::NOT_FOUND,
            ClientError::InvalidId => StatusCode::BAD_REQUEST,
        }
    }

    fn error_response(&self) -> Self::Response {
        Status::new(self.status_code(), self.to_string())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientDocument {
    #[serde(rename = "_id")]
    pub id: ObjectId,
    pub user: ObjectId,
    pub service: ObjectId,
    pub name: String,
    pub scope: Vec<String>,
    pub unlocked: bool,
    #[serde(with = "chrono_datetime_as_bson_datetime")]
    pub last_issued: DateTime<Utc>,
    #[serde(with = "chrono_datetime_as_bson_datetime")]
    pub last_modified: DateTime<Utc>,
}

const COLLECTION: &str = "clients";

impl Database {
    async fn get_clients<F>(
        &self,
        filter: F,
        opts: ListOptions,
    ) -> Result<(Vec<ClientDocument>, u64)>
    where
        F: Into<Option<Document>>,
    {
        let filter = filter.into();
        let coll = self.collection::<ClientDocument>(COLLECTION);

        let total = if filter.is_some() {
            coll.count_documents(filter.clone(), None).await?
        } else {
            coll.estimated_document_count(None).await?
        };

        if total == 0 {
            return Ok((Vec::new(), 0));
        }

        let opts = FindOptions::builder()
            .batch_size(opts.limit as u32)
            .skip(opts.offset)
            .limit(opts.limit)
            .sort(opts.sort)
            .build();

        let cursor = coll.find(filter, opts).await?;

        let clients = cursor.try_collect().await?;

        Ok((clients, total))
    }

    pub async fn get_client(&self, filter: Document) -> Result<ClientDocument> {
        let client = self
            .collection::<ClientDocument>(COLLECTION)
            .find_one(filter, None)
            .await?;

        if client.is_none() {
            return Err(ClientError::NotFound.into());
        }

        Ok(client.unwrap())
    }

    async fn insert_client(&self, doc: &ClientDocument) -> Result<()> {
        self.get_user(doc! { "_id": doc.user }).await?;

        self.collection::<ClientDocument>(COLLECTION)
            .insert_one(doc, None)
            .await?;

        Ok(())
    }

    async fn update_client(
        &self,
        id: ObjectId,
        with_user: Option<ObjectId>,
        update: Document,
    ) -> Result<ClientDocument> {
        if let Ok(id) = update.get_object_id("user") {
            self.get_user(doc! { "_id": id }).await?;
        }

        if let Ok(v) = update.get_array("scope") {
            let svc = self.get_service(doc! { "_id": id }).await?;
            if !v.iter().all(|s| svc.scope.contains(&s.to_string())) {
                return Err(ServiceError::UndefinedScope.into());
            }
        }

        let mut filter = doc! { "_id": id };
        if let Some(id) = with_user {
            filter.insert("user", id);
        }

        let doc = doc! {
            "$currentDate": { "lastModified": true },
            "$set": update,
        };

        let opts = FindOneAndUpdateOptions::builder()
            .return_document(ReturnDocument::After)
            .build();

        let result = self
            .collection::<ClientDocument>(COLLECTION)
            .find_one_and_update(filter, doc, opts)
            .await?;

        if result.is_none() {
            return Err(ClientError::NotFound.into());
        }

        Ok(result.unwrap())
    }

    async fn delete_client(&self, id: ObjectId) -> Result<()> {
        let result = self
            .collection::<ClientDocument>(COLLECTION)
            .delete_one(doc! { "_id": id }, None)
            .await?;

        if result.deleted_count == 0 {
            return Err(ClientError::NotFound.into());
        }

        Ok(())
    }

    pub async fn set_client_issued(&self, id: ObjectId) -> Result<()> {
        let doc = doc! {
            "$currentDate": { "lastIssued": true },
        };

        let result = self
            .collection::<ClientDocument>(COLLECTION)
            .update_one(doc! { "_id": id }, doc, None)
            .await?;

        if result.matched_count == 0 {
            return Err(ClientError::NotFound.into());
        }

        Ok(())
    }
}
