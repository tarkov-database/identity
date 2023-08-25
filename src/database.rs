use crate::{state::AppState, Result};

use std::{borrow::Borrow, time::Duration};

use axum::extract::FromRef;
use futures::TryStreamExt;
use mongodb::{
    bson::{self, Bson, Document},
    options::{
        AggregateOptions, ClientOptions, DeleteOptions, FindOneAndUpdateOptions, FindOneOptions,
        FindOptions, InsertManyOptions, InsertOneOptions, UpdateOptions,
    },
    Client,
};
use serde::{de::DeserializeOwned, Serialize};

#[derive(Debug, Clone)]
pub struct Database {
    client: Client,
    db_name: String,
}

impl Database {
    pub fn new(db_name: impl Into<String>, opts: ClientOptions) -> Result<Self> {
        Ok(Self {
            client: Client::with_options(opts)?,
            db_name: db_name.into(),
        })
    }

    pub fn collection<T>(&self) -> Collection<T>
    where
        T: DatabaseModel,
    {
        let db = self.client.database(&self.db_name);
        Collection {
            inner: db.collection::<T>(T::COLLECTION_NAME),
            db,
        }
    }

    pub async fn ping(&self) -> Result<Duration> {
        let start = tokio::time::Instant::now();

        self.client
            .database(&self.db_name)
            .run_command(
                bson::doc! {
                    "ping": 1
                },
                None,
            )
            .await?;

        let end = tokio::time::Instant::now();

        Ok(end - start)
    }
}

impl FromRef<AppState> for Database {
    fn from_ref(state: &AppState) -> Self {
        state.database.clone()
    }
}

#[derive(Debug, Clone)]
pub struct Collection<T> {
    inner: mongodb::Collection<T>,
    db: mongodb::Database,
}

impl<T> Collection<T>
where
    T: DatabaseModel,
{
    pub fn collection<U>(&self) -> Collection<U>
    where
        U: DatabaseModel,
    {
        Collection {
            inner: self.db.collection::<U>(U::COLLECTION_NAME),
            db: self.db.clone(),
        }
    }

    pub async fn get_all(
        &self,
        filter: impl Into<Option<Document>>,
        options: impl Into<Option<FindOptions>>,
    ) -> Result<(Vec<T>, u64)> {
        let filter = filter.into();

        let total = if filter.is_some() {
            self.inner.count_documents(filter.clone(), None).await?
        } else {
            self.inner.estimated_document_count(None).await?
        };

        if total == 0 {
            return Ok((Vec::new(), 0));
        }

        let cursor = self.inner.find(filter, options.into()).await?;

        let items = cursor.try_collect().await?;

        Ok((items, total))
    }

    #[inline]
    pub async fn get_one(
        &self,
        filter: impl Into<Document>,
        options: impl Into<Option<FindOneOptions>>,
    ) -> Result<Option<T>> {
        let filter = filter.into();
        let options = options.into();

        let item = self.inner.find_one(filter, options).await?;

        Ok(item)
    }

    #[inline]
    pub async fn get_many(
        &self,
        filter: impl Into<Document>,
        options: impl Into<Option<FindOptions>>,
    ) -> Result<Vec<T>> {
        let filter = filter.into();
        let options = options.into();

        let cursor = self.inner.find(filter, options).await?;

        let items = cursor.try_collect().await?;

        Ok(items)
    }

    #[inline]
    pub async fn insert_one(
        &self,
        item: impl Borrow<T>,
        options: impl Into<Option<InsertOneOptions>>,
    ) -> Result<Bson> {
        let item = self.inner.insert_one(item, options).await?;

        Ok(item.inserted_id)
    }

    #[inline]
    pub async fn insert_many(
        &self,
        items: impl IntoIterator<Item = impl Borrow<T>>,
        options: impl Into<Option<InsertManyOptions>>,
    ) -> Result<Vec<Bson>> {
        let items = self.inner.insert_many(items, options).await?;

        let mut ids = Vec::from_iter(items.inserted_ids);
        ids.sort_unstable_by_key(|(k, _)| *k);

        let ids = ids.into_iter().map(|(_, v)| v).collect();

        Ok(ids)
    }

    #[inline]
    pub async fn update_one(
        &self,
        filter: impl Into<Document>,
        update: impl Into<Document>,
        options: impl Into<Option<FindOneAndUpdateOptions>>,
    ) -> Result<Option<T>> {
        let filter = filter.into();
        let update = update.into();
        let options = options.into();

        let item = self
            .inner
            .find_one_and_update(filter, update, options)
            .await?;

        Ok(item)
    }

    #[inline]
    pub async fn update_many(
        &self,
        filter: impl Into<Document>,
        update: impl Into<Document>,
        options: impl Into<Option<UpdateOptions>>,
    ) -> Result<u64> {
        let filter = filter.into();
        let update = update.into();
        let options = options.into();

        let result = self.inner.update_many(filter, update, options).await?;

        Ok(result.modified_count)
    }

    #[inline]
    pub async fn delete_one(
        &self,
        filter: impl Into<Document>,
        options: impl Into<Option<DeleteOptions>>,
    ) -> Result<bool> {
        let filter = filter.into();
        let options = options.into();

        let result = self.inner.delete_one(filter, options).await?;

        Ok(result.deleted_count == 1)
    }

    #[inline]
    pub async fn delete_many(
        &self,
        filter: impl Into<Document>,
        options: impl Into<Option<DeleteOptions>>,
    ) -> Result<u64> {
        let filter = filter.into();
        let options = options.into();

        let result = self.inner.delete_many(filter, options).await?;

        Ok(result.deleted_count)
    }

    #[inline]
    pub async fn aggregate(
        &self,
        pipeline: impl IntoIterator<Item = Document>,
        options: impl Into<Option<AggregateOptions>>,
    ) -> Result<Vec<Document>> {
        let cursor = self.inner.aggregate(pipeline, options).await?;

        let items = cursor.try_collect().await?;

        Ok(items)
    }
}

impl<T> FromRef<AppState> for Collection<T>
where
    T: DatabaseModel,
{
    fn from_ref(state: &AppState) -> Self {
        state.database.collection()
    }
}

pub trait DatabaseModel
where
    Self: DeserializeOwned + Serialize + Send + Sync + Unpin,
{
    const COLLECTION_NAME: &'static str;
}
