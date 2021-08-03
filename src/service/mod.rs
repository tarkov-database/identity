mod filter;
mod handler;

use crate::{
    database::Database,
    error,
    model::{ListOptions, Status},
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
pub enum ServiceError {
    #[error("service not found")]
    NotFound,
    #[error("service id is invalid")]
    InvalidId,
    #[error("scope is not defined")]
    UndefinedScope,
}

impl warp::reject::Reject for ServiceError {}

impl error::ErrorResponse for ServiceError {
    type Response = Status;

    fn status_code(&self) -> StatusCode {
        match self {
            ServiceError::NotFound => StatusCode::NOT_FOUND,
            ServiceError::InvalidId | ServiceError::UndefinedScope => StatusCode::BAD_REQUEST,
        }
    }

    fn error_response(&self) -> Self::Response {
        Status::new(self.status_code(), self.to_string())
    }
}

// TODO: add algorithm
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceDocument {
    #[serde(rename = "_id")]
    pub id: ObjectId,
    pub name: String,
    pub audience: Vec<String>,
    pub scope: Vec<String>,
    pub scope_default: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    #[serde(with = "chrono_datetime_as_bson_datetime")]
    pub last_modified: DateTime<Utc>,
}

const COLLECTION: &str = "services";

impl Database {
    async fn get_services<F>(
        &self,
        filter: F,
        opts: ListOptions,
    ) -> Result<(Vec<ServiceDocument>, u64)>
    where
        F: Into<Option<Document>>,
    {
        let filter = filter.into();
        let coll = self.collection::<ServiceDocument>(COLLECTION);

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

        let services = cursor.try_collect().await?;

        Ok((services, total))
    }

    pub async fn get_service(&self, filter: Document) -> Result<ServiceDocument> {
        let service = self
            .collection::<ServiceDocument>(COLLECTION)
            .find_one(filter, None)
            .await?;

        if service.is_none() {
            return Err(ServiceError::NotFound.into());
        }

        Ok(service.unwrap())
    }

    async fn insert_service(&self, doc: &ServiceDocument) -> Result<()> {
        if !doc.scope_default.iter().all(|s| doc.scope.contains(s)) {
            return Err(ServiceError::UndefinedScope.into());
        }

        self.collection::<ServiceDocument>(COLLECTION)
            .insert_one(doc, None)
            .await?;

        Ok(())
    }

    async fn update_service(&self, id: ObjectId, update: Document) -> Result<ServiceDocument> {
        let doc = doc! {
            "$currentDate": { "lastModified": true },
            "$set": update,
        };

        let opts = FindOneAndUpdateOptions::builder()
            .return_document(ReturnDocument::After)
            .build();

        let result = self
            .collection::<ServiceDocument>(COLLECTION)
            .find_one_and_update(doc! { "_id": id }, doc, opts)
            .await?;

        if result.is_none() {
            return Err(ServiceError::NotFound.into());
        }

        Ok(result.unwrap())
    }

    async fn delete_service(&self, id: ObjectId) -> Result<()> {
        let result = self
            .collection::<ServiceDocument>(COLLECTION)
            .delete_one(doc! { "_id": id }, None)
            .await?;

        if result.deleted_count == 0 {
            return Err(ServiceError::NotFound.into());
        }

        Ok(())
    }
}
