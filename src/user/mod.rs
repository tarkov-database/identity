mod handler;
mod routes;

use crate::{
    database::Database,
    error,
    model::{ListOptions, Status},
    Result,
};

use chrono::{DateTime, Utc};
use futures::stream::TryStreamExt;
use hyper::StatusCode;
use mongodb::{
    bson::{doc, oid::ObjectId, serde_helpers::chrono_datetime_as_bson_datetime, Document},
    options::{FindOneAndUpdateOptions, FindOptions, ReturnDocument},
};
use serde::{Deserialize, Serialize};

pub use routes::routes;

#[derive(Debug, thiserror::Error)]
pub enum UserError {
    #[error("user not found")]
    NotFound,
    #[error("user already exists")]
    AlreadyExists,
    #[error("user id is invalid")]
    InvalidId,
    #[error("email address invalid")]
    InvalidAddr,
    #[error("email address not allowed")]
    DomainNotAllowed,
}

impl error::ErrorResponse for UserError {
    type Response = Status;

    fn status_code(&self) -> StatusCode {
        match self {
            UserError::NotFound => StatusCode::NOT_FOUND,
            UserError::AlreadyExists | UserError::InvalidAddr | UserError::InvalidId => {
                StatusCode::BAD_REQUEST
            }
            UserError::DomainNotAllowed => StatusCode::UNPROCESSABLE_ENTITY,
        }
    }

    fn error_response(&self) -> Self::Response {
        Status::new(self.status_code(), self.to_string())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Role {
    UserEditor,
    UserViewer,
    ClientEditor,
    ClientViewer,
    ServiceEditor,
    ServiceViewer,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserDocument {
    #[serde(rename = "_id")]
    pub id: ObjectId,
    pub email: String,
    pub password: String,
    pub roles: Vec<Role>,
    pub verified: bool,
    pub can_login: bool,
    #[serde(with = "chrono_datetime_as_bson_datetime")]
    pub last_session: DateTime<Utc>,
    #[serde(with = "chrono_datetime_as_bson_datetime")]
    pub last_modified: DateTime<Utc>,
}

const COLLECTION: &str = "users";

impl Database {
    async fn get_users<F>(&self, filter: F, opts: ListOptions) -> Result<(Vec<UserDocument>, u64)>
    where
        F: Into<Option<Document>>,
    {
        let filter = filter.into();
        let coll = self.collection::<UserDocument>(COLLECTION);

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

        let users = cursor.try_collect().await?;

        Ok((users, total))
    }

    pub async fn get_user(&self, filter: Document) -> Result<UserDocument> {
        let user = self
            .collection::<UserDocument>(COLLECTION)
            .find_one(filter, None)
            .await?;

        if user.is_none() {
            return Err(UserError::NotFound.into());
        }

        Ok(user.unwrap())
    }

    pub async fn insert_user(&self, doc: &UserDocument) -> Result<()> {
        self.collection::<UserDocument>(COLLECTION)
            .insert_one(doc, None)
            .await?;

        Ok(())
    }

    pub async fn update_user(&self, id: ObjectId, update: Document) -> Result<UserDocument> {
        let doc = doc! {
            "$currentDate": { "lastModified": true },
            "$set": update,
        };

        let opts = FindOneAndUpdateOptions::builder()
            .return_document(ReturnDocument::After)
            .build();

        let result = self
            .collection::<UserDocument>(COLLECTION)
            .find_one_and_update(doc! { "_id": id }, doc, opts)
            .await?;

        if result.is_none() {
            return Err(UserError::NotFound.into());
        }

        Ok(result.unwrap())
    }

    async fn delete_user(&self, id: ObjectId) -> Result<()> {
        let result = self
            .collection::<UserDocument>(COLLECTION)
            .delete_one(doc! { "_id": id }, None)
            .await?;

        if result.deleted_count == 0 {
            return Err(UserError::NotFound.into());
        }

        Ok(())
    }

    pub async fn set_user_session(&self, id: ObjectId) -> Result<()> {
        let doc = doc! {
            "$currentDate": { "lastSession": true },
        };

        let result = self
            .collection::<UserDocument>(COLLECTION)
            .update_one(doc! { "_id": id }, doc, None)
            .await?;

        if result.matched_count == 0 {
            return Err(UserError::NotFound.into());
        }

        Ok(())
    }
}
