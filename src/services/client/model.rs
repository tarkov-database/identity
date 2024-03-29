use crate::{
    database::{Collection, DatabaseModel},
    services::ServiceResult,
};

use super::ClientError;

use std::sync::OnceLock;

use chrono::{DateTime, Utc};
use mongodb::{
    bson::{self, doc, oid::ObjectId, serde_helpers::chrono_datetime_as_bson_datetime, Document},
    options::{FindOneAndUpdateOptions, FindOptions, ReturnDocument},
};
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientDocument {
    #[serde(rename = "_id")]
    pub id: ObjectId,
    pub user: ObjectId,
    pub service: ObjectId,
    pub name: ClientName,
    pub scope: Vec<String>,
    pub locked: bool,
    pub oauth: Option<OauthDocument>,
    #[serde(with = "chrono_datetime_as_bson_datetime")]
    pub last_modified: DateTime<Utc>,
    #[serde(with = "chrono_datetime_as_bson_datetime")]
    pub created: DateTime<Utc>,
}

impl DatabaseModel for ClientDocument {
    const COLLECTION_NAME: &'static str = "clients";
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OauthDocument {
    pub id: bson::Uuid,
    pub secret: String,
    #[serde(default, with = "chrono_datetime_as_bson_datetime")]
    pub last_seen: DateTime<Utc>,
    #[serde(with = "chrono_datetime_as_bson_datetime")]
    pub expires: DateTime<Utc>,
    #[serde(with = "chrono_datetime_as_bson_datetime")]
    pub issued: DateTime<Utc>,
}

impl OauthDocument {
    pub fn is_expired(&self) -> bool {
        self.expires < Utc::now()
    }
}

#[derive(Debug, Clone)]
pub struct InvalidClientName;

impl std::fmt::Display for InvalidClientName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid client name")
    }
}

impl std::error::Error for InvalidClientName {}

#[derive(Debug, Clone)]
pub struct ClientName(String);

impl ClientName {
    pub fn new(name: impl Into<String>) -> Result<Self, InvalidClientName> {
        name.into().try_into()
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ClientName {
    type Error = InvalidClientName;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.len() < 6 || value.len() > 32 {
            return Err(InvalidClientName);
        }

        let re = {
            static RE: OnceLock<Regex> = OnceLock::new();
            RE.get_or_init(|| {
                Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9\-_\/\#\*\+\(\)\\&\s]*[a-zA-Z0-9]$").unwrap()
            })
        };

        if !re.is_match(&value) {
            return Err(InvalidClientName);
        }

        Ok(Self(value))
    }
}

impl std::fmt::Display for ClientName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl AsRef<str> for ClientName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl PartialEq for ClientName {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

impl Serialize for ClientName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ClientName {
    fn deserialize<D>(deserializer: D) -> Result<ClientName, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.try_into().map_err(serde::de::Error::custom)
    }
}

impl Collection<ClientDocument> {
    pub async fn get_by_id(&self, id: ObjectId) -> ServiceResult<ClientDocument> {
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
    ) -> ServiceResult<ClientDocument> {
        let filter = doc! { "_id": id, "user": user_id };

        let item = self
            .get_one(filter, None)
            .await?
            .ok_or(ClientError::NotFound)?;

        Ok(item)
    }

    pub async fn get_by_user(&self, user_id: ObjectId) -> ServiceResult<Vec<ClientDocument>> {
        let filter = doc! { "user": user_id };
        let sort = doc! { "created": 1 };

        let opts = FindOptions::builder().sort(sort).build();

        let items = self.get_many(filter, opts).await?;

        Ok(items)
    }

    pub async fn get_by_user_and_name(
        &self,
        user_id: ObjectId,
        name: &str,
    ) -> ServiceResult<Option<ClientDocument>> {
        let filter = doc! { "user": user_id, "name": name };

        let item = self.get_one(filter, None).await?;

        Ok(item)
    }

    pub async fn get_by_service(&self, service_id: ObjectId) -> ServiceResult<Vec<ClientDocument>> {
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
    ) -> ServiceResult<Vec<ClientDocument>> {
        let filter = doc! { "user": user_id, "service": service_id };
        let sort = doc! { "created": 1 };

        let opts = FindOptions::builder().sort(sort).build();

        let items = self.get_many(filter, opts).await?;

        Ok(items)
    }

    pub async fn get_by_oauth_id(
        &self,
        oauth_id: impl Into<bson::Uuid>,
    ) -> ServiceResult<Option<ClientDocument>> {
        let filter = doc! { "oauth.id": oauth_id.into() };

        let item = self.get_one(filter, None).await?;

        Ok(item)
    }

    pub async fn insert(&self, doc: &ClientDocument) -> ServiceResult<ObjectId> {
        let id = self.insert_one(doc, None).await?.as_object_id().unwrap();

        Ok(id)
    }

    pub async fn update(
        &self,
        id: ObjectId,
        user_id: impl Into<Option<ObjectId>>,
        update: Document,
    ) -> ServiceResult<ClientDocument> {
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

    pub async fn delete(
        &self,
        id: ObjectId,
        user_id: impl Into<Option<ObjectId>>,
    ) -> ServiceResult<()> {
        let mut filter = doc! { "_id": id };
        if let Some(user_id) = user_id.into() {
            filter.insert("user", user_id);
        }

        if !self.delete_one(filter, None).await? {
            return Err(ClientError::NotFound)?;
        }

        Ok(())
    }

    pub async fn delete_by_user(&self, user_id: ObjectId) -> ServiceResult<u64> {
        let filter = doc! { "user": user_id };

        let count = self.delete_many(filter, None).await?;

        Ok(count)
    }

    pub async fn delete_by_service(&self, service_id: ObjectId) -> ServiceResult<u64> {
        let filter = doc! { "service": service_id };

        let count = self.delete_many(filter, None).await?;

        Ok(count)
    }

    pub async fn set_oauth(&self, client_id: ObjectId, doc: OauthDocument) -> ServiceResult<()> {
        let filter = doc! { "_id": client_id };

        let doc = doc! {
            "$currentDate": { "lastModified": true },
            "$set": { "oauth": bson::to_bson(&doc).unwrap() },
        };

        self.update_one(filter, doc, None)
            .await?
            .ok_or(ClientError::NotFound)?;

        Ok(())
    }

    pub async fn set_oauth_as_seen(&self, oauth_id: impl Into<bson::Uuid>) -> ServiceResult<()> {
        let filter = doc! { "oauth.id": oauth_id.into() };

        let doc = doc! {
            "$currentDate": { "lastModified": true },
            "$currentDate": { "oauth.lastSeen": true },
        };

        self.update_one(filter, doc, None)
            .await?
            .ok_or(ClientError::NotFound)?;

        Ok(())
    }
}
