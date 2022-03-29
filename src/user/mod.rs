mod handler;
mod routes;

use crate::{
    database::Database,
    error,
    model::{ListOptions, Status},
    Result,
};

use chrono::{DateTime, TimeZone, Utc};
use futures::stream::TryStreamExt;
use hyper::StatusCode;
use mongodb::{
    bson::{
        doc, oid::ObjectId, serde_helpers::chrono_datetime_as_bson_datetime, to_bson, Document,
    },
    options::{FindOneAndUpdateOptions, FindOptions, ReturnDocument},
};
use serde::{Deserialize, Serialize};

pub use routes::routes;

#[derive(Debug, PartialEq, thiserror::Error)]
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
    pub password: Option<String>,
    pub roles: Vec<Role>,
    pub verified: bool,
    pub can_login: bool,
    pub connections: Vec<Connection>,
    #[serde(with = "chrono_datetime_as_bson_datetime")]
    pub last_session: DateTime<Utc>,
    #[serde(with = "chrono_datetime_as_bson_datetime")]
    pub last_modified: DateTime<Utc>,
}

impl Default for UserDocument {
    fn default() -> Self {
        Self {
            id: Default::default(),
            email: Default::default(),
            password: Default::default(),
            roles: Default::default(),
            verified: false,
            can_login: true,
            connections: Default::default(),
            last_session: Utc.timestamp(0, 0),
            last_modified: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase", tag = "type")]
pub enum Connection {
    #[serde(rename_all = "camelCase")]
    GitHub {
        user_id: i64,
        login: String,
        two_factor_enabled: bool,
    },
}

impl Connection {
    pub fn type_name(&self) -> &'static str {
        match self {
            Connection::GitHub { .. } => "github",
        }
    }

    /// Returns `true` if the connection is [`GitHub`].
    ///
    /// [`GitHub`]: Connection::GitHub
    pub fn is_github(&self) -> bool {
        matches!(self, Self::GitHub { .. })
    }
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

    pub async fn update_user(&self, filter: Document, update: Document) -> Result<UserDocument> {
        let doc = doc! {
            "$currentDate": { "lastModified": true },
            "$set": update
        };

        let opts = FindOneAndUpdateOptions::builder()
            .return_document(ReturnDocument::After)
            .build();

        let result = self
            .collection::<UserDocument>(COLLECTION)
            .find_one_and_update(filter, doc, opts)
            .await?;

        if result.is_none() {
            return Err(UserError::NotFound.into());
        }

        Ok(result.unwrap())
    }

    pub async fn update_user_by_id(
        &self,
        user_id: ObjectId,
        update: Document,
    ) -> Result<UserDocument> {
        self.update_user(doc! { "_id": user_id }, update).await
    }

    pub async fn insert_user_connection(
        &self,
        user_id: ObjectId,
        connection: Connection,
    ) -> Result<UserDocument> {
        let filter = doc! { "_id": user_id };
        let update = doc! {"$push": {"connections": to_bson(&connection).unwrap() } };

        self.update_user(filter, update).await
    }

    pub async fn update_user_connection(
        &self,
        user_id: ObjectId,
        connection: Connection,
    ) -> Result<UserDocument> {
        let filter = doc! { "_id": user_id, "connections.type": connection.type_name() };
        let update = doc! { "$set": { "connections.$": to_bson(&connection).unwrap() } };

        self.update_user(filter, update).await
    }

    async fn delete_user(&self, user_id: ObjectId) -> Result<()> {
        let result = self
            .collection::<UserDocument>(COLLECTION)
            .delete_one(doc! { "_id": user_id }, None)
            .await?;

        if result.deleted_count == 0 {
            return Err(UserError::NotFound.into());
        }

        Ok(())
    }

    pub async fn set_user_session(&self, user_id: ObjectId) -> Result<()> {
        let doc = doc! {
            "$currentDate": { "lastSession": true },
        };

        let result = self
            .collection::<UserDocument>(COLLECTION)
            .update_one(doc! { "_id": user_id }, doc, None)
            .await?;

        if result.matched_count == 0 {
            return Err(UserError::NotFound.into());
        }

        Ok(())
    }
}
