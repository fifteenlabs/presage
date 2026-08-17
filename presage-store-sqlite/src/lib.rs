use std::str::FromStr;

use presage::{
    backup::TransferArchive,
    libsignal_service::{
        BackupKey, libsignal_account_keys::AccountEntropyPool, prelude::MasterKey,
        protocol::SenderCertificate,
    },
    store::{StateStore, Store},
};
use protocol::{IdentityType, SqliteProtocolStore};
use sqlx::{
    SqlitePool, query, query_scalar,
    sqlite::{SqliteJournalMode, SqliteSynchronous},
};

mod content;
mod data;
mod error;
mod protocol;

pub use error::SqliteStoreError;
pub use presage::model::identity::OnNewIdentity;
pub use sqlx::sqlite::SqliteConnectOptions;

use crate::error::SqlxErrorExt;

#[derive(Debug, Clone)]
pub struct SqliteStore {
    pub(crate) db: SqlitePool,
    pub(crate) trust_new_identities: OnNewIdentity,
}

impl SqliteStore {
    pub async fn open(
        url: &str,
        trust_new_identities: OnNewIdentity,
    ) -> Result<Self, SqliteStoreError> {
        Self::open_with_passphrase(url, None, trust_new_identities).await
    }

    pub async fn open_with_passphrase(
        url: &str,
        passphrase: Option<&str>,
        trust_new_identities: OnNewIdentity,
    ) -> Result<Self, SqliteStoreError> {
        // Escape the passphrase.
        let passphrase = passphrase.map(|p| p.replace("'", "''"));

        let options: SqliteConnectOptions = url.parse()?;
        let options = options.create_if_missing(true).foreign_keys(true);
        let options = if let Some(passphrase) = &passphrase {
            options.pragma("key", format!("'{passphrase}'"))
        } else {
            options
        };
        Self::open_with_options(options.clone(), trust_new_identities.clone()).await
    }

    pub async fn open_with_options(
        options: SqliteConnectOptions,
        trust_new_identities: OnNewIdentity,
    ) -> Result<Self, SqliteStoreError> {
        let options = options
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Full);
        let db = SqlitePool::connect_with(options).await?;

        sqlx::migrate!().run(&db).await?;
        Ok(Self {
            db,
            trust_new_identities,
        })
    }

    /// One-shot backfill of `groups.group_id` for rows that predate the
    /// `add_group_id_to_groups` migration. Idempotent; returns the number
    /// of rows touched (0 in steady state).
    ///
    /// Until the row is backfilled, `group_by_group_id` falls through to
    /// the trait default's O(N) zkgroup-derivation iteration on every
    /// sync `call_event` for the affected group. After backfill, the
    /// lookup hits the partial UNIQUE INDEX in O(log N).
    ///
    /// Callers should invoke this once per process start (or per account
    /// boot) after `open*()`. Safe to call repeatedly.
    pub async fn backfill_group_ids(&self) -> Result<usize, SqliteStoreError> {
        use presage::libsignal_service::zkgroup::groups::{GroupMasterKey, GroupSecretParams};

        let rows: Vec<Vec<u8>> =
            query_scalar!("SELECT master_key FROM groups WHERE group_id IS NULL")
                .fetch_all(&self.db)
                .await?;

        if rows.is_empty() {
            return Ok(0);
        }
        let count = rows.len();

        let mut tx = self.db.begin().await?;
        for master_key_bytes in rows {
            let master_key: [u8; 32] = match master_key_bytes.as_slice().try_into() {
                Ok(k) => k,
                Err(_) => {
                    tracing::warn!(
                        "presage: skipping group with invalid master_key length during backfill"
                    );
                    continue;
                }
            };
            let group_id: [u8; 32] =
                GroupSecretParams::derive_from_master_key(GroupMasterKey::new(master_key))
                    .get_group_identifier();
            let group_id_slice: &[u8] = &group_id;
            let master_key_slice: &[u8] = &master_key;
            query!(
                "UPDATE groups SET group_id = ?1 WHERE master_key = ?2",
                group_id_slice,
                master_key_slice,
            )
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;

        Ok(count)
    }
}

impl Store for SqliteStore {
    type Error = SqliteStoreError;

    type AciStore = SqliteProtocolStore;

    type PniStore = SqliteProtocolStore;

    async fn clear(&mut self) -> Result<(), SqliteStoreError> {
        query!("DELETE FROM kv").execute(&self.db).await?;
        Ok(())
    }

    fn aci_protocol_store(&self) -> Self::AciStore {
        SqliteProtocolStore {
            store: self.clone(),
            identity: IdentityType::Aci,
        }
    }

    fn pni_protocol_store(&self) -> Self::PniStore {
        SqliteProtocolStore {
            store: self.clone(),
            identity: IdentityType::Pni,
        }
    }
}

impl StateStore for SqliteStore {
    type StateStoreError = SqliteStoreError;

    async fn load_registration_data(
        &self,
    ) -> Result<Option<presage::manager::RegistrationData>, Self::StateStoreError> {
        query_scalar!("SELECT value FROM kv WHERE key = 'registration'")
            .fetch_optional(&self.db)
            .await?
            .map(|value| serde_json::from_slice(&value))
            .transpose()
            .map_err(From::from)
    }

    async fn save_registration_data(
        &mut self,
        state: &presage::manager::RegistrationData,
    ) -> Result<(), Self::StateStoreError> {
        let value = serde_json::to_string(state)?;
        query!(
            "INSERT OR REPLACE INTO kv (key, value) VALUES ('registration', ?)",
            value
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }

    async fn is_registered(&self) -> bool {
        self.load_registration_data().await.ok().flatten().is_some()
    }

    async fn clear_registration(&mut self) -> Result<(), Self::StateStoreError> {
        let mut transaction = self.db.begin().await.into_protocol_error()?;
        query!("DELETE FROM kv WHERE key = 'registration'")
            .execute(&mut *transaction)
            .await?;
        query!("DELETE FROM sessions")
            .execute(&mut *transaction)
            .await?;
        query!("DELETE FROM identities")
            .execute(&mut *transaction)
            .await?;
        query!("DELETE FROM pre_keys")
            .execute(&mut *transaction)
            .await?;
        query!("DELETE FROM signed_pre_keys")
            .execute(&mut *transaction)
            .await?;
        query!("DELETE FROM kyber_pre_keys")
            .execute(&mut *transaction)
            .await?;
        query!("DELETE FROM sender_keys")
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await.into_protocol_error()?;
        Ok(())
    }

    async fn set_aci_identity_key_pair(
        &self,
        key_pair: presage::libsignal_service::protocol::IdentityKeyPair,
    ) -> Result<(), Self::StateStoreError> {
        let key = IdentityType::Aci.identity_key_pair_key();
        let value = key_pair.serialize();
        query!(
            "INSERT OR REPLACE INTO kv (key, value) VALUES (?, ?)",
            key,
            value
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }

    async fn set_pni_identity_key_pair(
        &self,
        key_pair: presage::libsignal_service::protocol::IdentityKeyPair,
    ) -> Result<(), Self::StateStoreError> {
        let key = IdentityType::Pni.identity_key_pair_key();
        let value = key_pair.serialize();
        query!(
            "INSERT OR REPLACE INTO kv (key, value) VALUES (?, ?)",
            key,
            value
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }

    async fn sender_certificate(&self) -> Result<Option<SenderCertificate>, Self::StateStoreError> {
        query_scalar!("SELECT value FROM kv WHERE key = 'sender_certificate' LIMIT 1")
            .fetch_optional(&self.db)
            .await?
            .map(|value| SenderCertificate::deserialize(&value))
            .transpose()
            .map_err(From::from)
    }

    async fn save_sender_certificate(
        &self,
        certificate: &SenderCertificate,
    ) -> Result<(), Self::StateStoreError> {
        let value = certificate.serialized()?;
        query!(
            "INSERT OR REPLACE INTO kv (key, value) VALUES ('sender_certificate', ?)",
            value
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }

    async fn fetch_master_key(&self) -> Result<Option<MasterKey>, Self::StateStoreError> {
        query_scalar!("SELECT value FROM kv WHERE key = 'master_key' LIMIT 1")
            .fetch_optional(&self.db)
            .await?
            .map(|value| MasterKey::from_slice(&value))
            .transpose()
            .map_err(|_| SqliteStoreError::InvalidFormat)
    }

    async fn store_master_key(
        &self,
        master_key: Option<&MasterKey>,
    ) -> Result<(), Self::StateStoreError> {
        let value = master_key.map(|k| &k.inner[..]);
        if let Some(value) = value {
            query!(
                "INSERT OR REPLACE INTO kv (key, value) VALUES ('master_key', ?)",
                value
            )
            .execute(&self.db)
            .await?;
        } else {
            query!("DELETE FROM kv WHERE key = 'master_key'")
                .execute(&self.db)
                .await?;
        }
        Ok(())
    }

    async fn fetch_account_entropy_pool(
        &self,
    ) -> Result<Option<AccountEntropyPool>, Self::StateStoreError> {
        query_scalar!("SELECT value FROM kv WHERE key = 'account_entropy_pool' LIMIT 1")
            .fetch_optional(&self.db)
            .await?
            .map(|value| {
                AccountEntropyPool::from_str(
                    str::from_utf8(&value).map_err(|_| SqliteStoreError::InvalidFormat)?,
                )
                .map_err(|_| SqliteStoreError::InvalidFormat)
            })
            .transpose()
            .map_err(|_| SqliteStoreError::InvalidFormat)
    }

    async fn store_account_entropy_pool(
        &self,
        aep: Option<&AccountEntropyPool>,
    ) -> Result<(), Self::StateStoreError> {
        let value = aep.map(|k| k.to_string().into_bytes());
        if let Some(value) = value {
            query!(
                "INSERT OR REPLACE INTO kv (key, value) VALUES ('account_entropy_pool', ?)",
                value
            )
            .execute(&self.db)
            .await?;
        } else {
            query!("DELETE FROM kv WHERE key = 'account_entropy_pool'")
                .execute(&self.db)
                .await?;
        }
        Ok(())
    }

    async fn fetch_storage_manifest_version(&self) -> Result<u64, Self::StateStoreError> {
        let value: Option<Vec<u8>> =
            query_scalar!("SELECT value FROM kv WHERE key = 'storage_manifest_version' LIMIT 1")
                .fetch_optional(&self.db)
                .await?;
        Ok(match value {
            None => 0,
            Some(bytes) => u64::from_le_bytes(
                bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| SqliteStoreError::InvalidFormat)?,
            ),
        })
    }

    async fn store_storage_manifest_version(
        &self,
        version: u64,
    ) -> Result<(), Self::StateStoreError> {
        let value = version.to_le_bytes().to_vec();
        query!(
            "INSERT OR REPLACE INTO kv (key, value) VALUES ('storage_manifest_version', ?)",
            value
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }

    async fn fetch_backup_key(&self) -> Result<Option<BackupKey>, Self::StateStoreError> {
        query_scalar!("SELECT value FROM kv WHERE key = 'backup_key' LIMIT 1")
            .fetch_optional(&self.db)
            .await?
            .map(|value: Vec<u8>| value.try_into().map(BackupKey))
            .transpose()
            .map_err(|_| SqliteStoreError::InvalidFormat)
    }

    async fn store_backup_key(&self, key: Option<&BackupKey>) -> Result<(), Self::StateStoreError> {
        match key {
            Some(k) => {
                let value = &k.0[..];
                query!(
                    "INSERT OR REPLACE INTO kv (key, value) VALUES ('backup_key', ?)",
                    value
                )
                .execute(&self.db)
                .await?;
            }
            None => {
                query!("DELETE FROM kv WHERE key = 'backup_key'")
                    .execute(&self.db)
                    .await?;
            }
        }
        Ok(())
    }

    async fn fetch_transfer_archive(
        &self,
    ) -> Result<Option<TransferArchive>, Self::StateStoreError> {
        query_scalar!("SELECT value FROM kv WHERE key = 'transfer_archive' LIMIT 1")
            .fetch_optional(&self.db)
            .await?
            .map(|bytes: Vec<u8>| {
                serde_json::from_slice(&bytes).map_err(|_| SqliteStoreError::InvalidFormat)
            })
            .transpose()
    }

    async fn store_transfer_archive(
        &self,
        archive: Option<&TransferArchive>,
    ) -> Result<(), Self::StateStoreError> {
        match archive {
            Some(a) => {
                let value = serde_json::to_vec(a).map_err(|_| SqliteStoreError::InvalidFormat)?;
                query!(
                    "INSERT OR REPLACE INTO kv (key, value) VALUES ('transfer_archive', ?)",
                    value
                )
                .execute(&self.db)
                .await?;
            }
            None => {
                query!("DELETE FROM kv WHERE key = 'transfer_archive'")
                    .execute(&self.db)
                    .await?;
            }
        }
        Ok(())
    }
}
