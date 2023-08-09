use std::collections::VecDeque;

use crate::{
    database::{Collection, DatabaseModel},
    services::{model::EmailAddr, ServiceResult},
};

use super::UserError;

use chrono::{DateTime, Utc};
use mongodb::{
    bson::{self, doc, oid::ObjectId, serde_helpers::chrono_datetime_as_bson_datetime, Document},
    options::{FindOneAndUpdateOptions, ReturnDocument},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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
    pub email: EmailAddr,
    pub password: Option<String>,
    pub roles: Vec<Role>,
    pub verified: bool,
    pub can_login: bool,
    pub locked: bool,
    pub connections: Vec<Connection>,
    pub sessions: Vec<SessionDocument>,
    #[serde(with = "chrono_datetime_as_bson_datetime")]
    pub last_modified: DateTime<Utc>,
    #[serde(with = "chrono_datetime_as_bson_datetime")]
    pub created: DateTime<Utc>,
}

impl UserDocument {
    pub fn find_session(&self, id: &bson::Uuid) -> Option<&SessionDocument> {
        self.sessions.iter().find(|s| &s.id == id)
    }
}

impl DatabaseModel for UserDocument {
    const COLLECTION_NAME: &'static str = "users";
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionDocument {
    pub id: bson::Uuid,
    #[serde(with = "chrono_datetime_as_bson_datetime")]
    pub last_seen: DateTime<Utc>,
    #[serde(with = "chrono_datetime_as_bson_datetime")]
    pub issued: DateTime<Utc>,
}

impl SessionDocument {
    pub fn new() -> Self {
        Self {
            id: Uuid::new_v4().into(),
            last_seen: Utc::now(),
            issued: Utc::now(),
        }
    }

    pub fn with_id(id: impl Into<bson::Uuid>) -> Self {
        Self {
            id: id.into(),
            last_seen: Utc::now(),
            issued: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
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

impl Collection<UserDocument> {
    pub async fn get_by_id(&self, id: ObjectId) -> ServiceResult<UserDocument> {
        let filter = doc! { "_id": id };

        let item = self
            .get_one(filter, None)
            .await?
            .ok_or(UserError::NotFound)?;

        Ok(item)
    }

    pub async fn get_by_email(&self, addr: impl AsRef<str>) -> ServiceResult<UserDocument> {
        let filter = doc! { "email": addr.as_ref() };

        let item = self
            .get_one(filter, None)
            .await?
            .ok_or(UserError::NotFound)?;

        Ok(item)
    }

    pub async fn get_by_session(
        &self,
        session_id: impl Into<bson::Uuid>,
    ) -> ServiceResult<UserDocument> {
        let filter = doc! { "sessions.id": session_id.into() };

        let item = self
            .get_one(filter, None)
            .await?
            .ok_or(UserError::NotFound)?;

        Ok(item)
    }

    pub async fn insert(&self, doc: &UserDocument) -> ServiceResult<ObjectId> {
        let id = self.insert_one(doc, None).await?.as_object_id().unwrap();

        Ok(id)
    }

    pub async fn update(&self, id: ObjectId, update: Document) -> ServiceResult<UserDocument> {
        let filter = doc! { "_id": id };

        let doc = doc! {
            "$currentDate": { "lastModified": true },
            "$set": update
        };

        let options = FindOneAndUpdateOptions::builder()
            .return_document(ReturnDocument::After)
            .build();

        let item = self
            .update_one(filter, doc, options)
            .await?
            .ok_or(UserError::NotFound)?;

        Ok(item)
    }

    pub async fn delete(&self, id: ObjectId) -> ServiceResult<()> {
        let filter = doc! { "_id": id };

        if !self.delete_one(filter, None).await? {
            return Err(UserError::NotFound)?;
        }

        Ok(())
    }

    pub async fn insert_connection(
        &self,
        user_id: ObjectId,
        connection: Connection,
    ) -> ServiceResult<UserDocument> {
        let filter = doc! { "_id": user_id };

        let doc = doc! {
            "$currentDate": { "lastModified": true },
            "$push": { "connections": bson::to_bson(&connection).unwrap() }
        };

        let options = FindOneAndUpdateOptions::builder()
            .return_document(ReturnDocument::After)
            .build();

        let item = self
            .update_one(filter, doc, options)
            .await?
            .ok_or(UserError::NotFound)?;

        Ok(item)
    }

    pub async fn update_connection(
        &self,
        user_id: ObjectId,
        connection: Connection,
    ) -> ServiceResult<UserDocument> {
        let filter = doc! {
            "_id": user_id,
            "connections.type": connection.type_name()
        };

        let doc = doc! {
            "$currentDate": { "lastModified": true },
            "$set": { "connections.$": bson::to_bson(&connection).unwrap() }
        };

        let options = FindOneAndUpdateOptions::builder()
            .return_document(ReturnDocument::After)
            .build();

        let item = self
            .update_one(filter, doc, options)
            .await?
            .ok_or(UserError::NotFound)?;

        Ok(item)
    }

    pub async fn remove_connection(
        &self,
        user_id: ObjectId,
        connection: Connection,
    ) -> ServiceResult<UserDocument> {
        let filter = doc! {
            "_id": user_id,
            "connections.type": connection.type_name()
        };

        let doc = doc! {
            "$currentDate": { "lastModified": true },
            "$pull": { "connections": bson::to_bson(&connection).unwrap() }
        };

        let options = FindOneAndUpdateOptions::builder()
            .return_document(ReturnDocument::After)
            .build();

        let item = self
            .update_one(filter, doc, options)
            .await?
            .ok_or(UserError::NotFound)?;

        Ok(item)
    }

    pub async fn set_session(
        &self,
        user_id: ObjectId,
        doc: SessionDocument,
    ) -> ServiceResult<UserDocument> {
        let user = self.get_by_id(user_id).await?;

        let mut sessions = VecDeque::from(user.sessions);

        if let Some(index) = sessions.iter().position(|e| e.id == doc.id) {
            let mut element = sessions.remove(index).unwrap();
            element.last_seen = doc.last_seen;
            sessions.push_back(element);
        } else {
            sessions.push_back(doc);
        }

        if sessions.len() > 10 {
            sessions.pop_front();
        }

        let filter = doc! { "_id": user_id };

        let doc = doc! {
           "$currentDate": { "lastModified": true },
           "$set": { "sessions": bson::to_bson(&sessions).unwrap() },
        };

        let options = FindOneAndUpdateOptions::builder()
            .return_document(ReturnDocument::After)
            .build();

        let item = self
            .update_one(filter, doc, options)
            .await?
            .ok_or(UserError::NotFound)?;

        Ok(item)
    }
}
