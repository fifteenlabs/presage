//! The storage service: reading the account's manifest, and writing to it.
//!
//! Signal's storage service holds an encrypted, server-side record of the
//! account — contacts, groups, settings — that every device syncs from. This
//! module owns both directions: [`sync_storage_service`] pulls it down, and the
//! `*_storage_record` methods below publish changes back.
//!
//! A record is immutable under its identifier, so changing one is an insert
//! under a fresh id plus a delete of the old, in a single write. That shape is
//! why an update needs to remember where a record lives, and why the retry
//! policy here is stricter than a plain "try again": a conflict means the
//! account moved, so the write has to be rebuilt rather than resent.
//!
//! Callers must serialise everything in this module. The manifest is one
//! mutable document with a version and a resume cursor, so two concurrent
//! operations interleave checkpoints and silently skip records.

use std::time::Duration;

use libsignal_service::{
    master_key::StorageServiceKey,
    prelude::{ProfileKey, ProtobufMessage},
    proto::{
        manifest_record, storage_record, sync_message, ManifestRecord, StorageRecord, SyncMessage,
    },
    protocol::{Aci, ServiceId},
    push_service::PushService,
    zkgroup::GroupMasterKeyBytes,
    StorageService,
};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use tracing::{debug, info, warn};

use crate::model::contacts::Contact;
use crate::model::groups::Group;
use crate::storage_record::{
    contact_blocked, contact_muted_until, group_muted_until, set_contact_blocked,
    set_contact_muted_until, set_group_muted_until, StorageRecordEditError,
};
use crate::store::{StorageRecordIdentity, StorageRecordKey, StorageSyncCursor, Store};
use crate::{Error, Manager};

use super::Registered;

/// Maximum number of storage-service keys to request in a single `ReadOperation`.
/// Signal Desktop uses 2500; the server's hard limit is ~5120.
const STORAGE_SERVICE_BATCH_SIZE: usize = 2500;

/// How many times to attempt a manifest write before giving up.
///
/// The phone writes to this manifest too, so a conflict is routine rather than
/// exceptional. Three matches Signal-Android's `StorageSyncJob`
/// (`setMaxAttempts(3)`); Signal-Desktop effectively allows two before latching
/// off for the rest of the process.
const MANIFEST_WRITE_ATTEMPTS: usize = 3;

/// Delays between those attempts, roughly Signal-Desktop's 1s/5s and
/// Signal-Android's ~2s/4s jittered.
///
/// A conflict means another writer is active *right now*, so retrying
/// immediately just loses again. Sized off [`MANIFEST_WRITE_ATTEMPTS`] so the
/// two cannot drift: there is one delay between each pair of attempts.
const MANIFEST_WRITE_BACKOFF: [Duration; MANIFEST_WRITE_ATTEMPTS - 1] =
    [Duration::from_secs(1), Duration::from_secs(4)];

impl<S: Store> Manager<S, Registered> {
    /// Tell our other devices to re-read the manifest — the same `FetchLatest`
    /// the app listens for.
    ///
    /// Best-effort by design: the record is already written, so a failure here
    /// costs propagation delay, not correctness.
    async fn notify_storage_manifest_written(&mut self) {
        let mut sender = match self.new_message_sender().await {
            Ok(sender) => sender,
            Err(e) => {
                warn!(%e, "storage manifest written but building the sync sender failed");
                return;
            }
        };

        if let Err(e) = sender
            .send_sync_message(SyncMessage {
                content: Some(sync_message::Content::FetchLatest(
                    sync_message::FetchLatest {
                        r#type: Some(sync_message::fetch_latest::Type::StorageManifest.into()),
                    },
                )),
                ..SyncMessage::with_padding(&mut rand::rng())
            })
            .await
        {
            warn!(%e, "storage manifest written but notifying other devices failed");
        }
    }

    /// An authenticated storage-service handle for this account.
    async fn storage_service(&mut self) -> Result<StorageService, Error<S::Error>> {
        let master_key = self
            .master_key()
            .await?
            .ok_or_else(|| Error::MissingKeyError("master_key".into()))?;
        Ok(StorageService::new(
            self.identified_push_service(),
            StorageServiceKey::from_master_key(&master_key),
        )
        .await?)
    }

    /// Append one record to the account's storage manifest.
    ///
    /// Every existing identifier is copied through **verbatim**, including record types
    /// presage does not model (account, story distribution lists, call links, chat
    /// folders, notification profiles). The server treats the manifest as the complete
    /// index of the account, so anything dropped here would be deleted from every device
    /// the user owns — which is why this appends rather than regenerating the way
    /// Signal-Desktop's `generateManifest` does.
    ///
    /// Deliberately offers no way to express an update or a delete: those require
    /// re-encoding records we cannot decode.
    pub(super) async fn append_storage_record(
        &mut self,
        item_type: manifest_record::identifier::Type,
        record: Vec<u8>,
    ) -> Result<Vec<u8>, Error<S::Error>> {
        let storage_service = self.storage_service().await?;

        for attempt in 1..=MANIFEST_WRITE_ATTEMPTS {
            let current = storage_service.manifest().await?;
            let version = current.version + 1;

            // Storage IDs are 16 random bytes, and a record is only ever addressed by the
            // id it was inserted under.
            let mut raw_id = vec![0u8; 16];
            StdRng::from_os_rng().fill_bytes(&mut raw_id);

            let mut identifiers = current.identifiers.clone();
            identifiers.push(manifest_record::Identifier {
                raw: raw_id.clone(),
                r#type: item_type.into(),
            });

            // `record_ikm` must be carried forward unchanged: item keys derive from it, so
            // dropping it would make every existing item undecryptable. `write_items`
            // encrypts the record with whatever this manifest declares, so the two cannot
            // disagree.
            let new_manifest = ManifestRecord {
                version,
                source_device: self.state.device_id().into(),
                identifiers,
                record_ikm: current.record_ikm.clone(),
            };

            match storage_service
                // Encoding here is lossless: this record was just built, so it
                // has no unknown fields for prost to drop. An *edit* of a record
                // read from the server must never do this — see
                // [`crate::storage_record`].
                .write_items(
                    new_manifest,
                    vec![(raw_id.clone(), record.clone())],
                    Vec::new(),
                )
                .await
            {
                Ok(()) => {
                    self.store.store_storage_manifest_version(version).await?;
                    debug!(version, "storage manifest: appended record");

                    self.notify_storage_manifest_written().await;
                    return Ok(raw_id);
                }
                // A conflict means another device wrote in between; the next iteration
                // re-reads the manifest and rebuilds on top of it.
                Err(libsignal_service::StorageServiceError::Conflict) => {
                    debug!(
                        attempt,
                        our_version = version,
                        "storage manifest: version conflict, retrying"
                    );
                    if let Some(backoff) = MANIFEST_WRITE_BACKOFF.get(attempt - 1) {
                        tokio::time::sleep(*backoff).await;
                    }
                }
                Err(e) => return Err(e.into()),
            }
        }

        Err(Error::StorageManifestConflict)
    }

    /// Build and write a manifest that replaces one record with another: the new
    /// bytes go in under a fresh identifier and the old identifier is deleted, in
    /// a single write.
    ///
    /// A record is immutable under its identifier, so this is the only shape an
    /// update can take. `new_record` is an encoded `StorageRecord` and is written
    /// byte-for-byte — build it with [`crate::storage_record`], not by re-encoding
    /// a decoded record.
    ///
    /// `current` must be the manifest as the server holds it *now*, and the caller
    /// must already be caught up to it. Both are the caller's job because the
    /// recovery for either being untrue is a sync, which this layer cannot do
    /// without knowing what it was editing.
    async fn write_replacing_storage_record(
        &self,
        storage_service: &StorageService,
        current: &ManifestRecord,
        item_type: manifest_record::identifier::Type,
        old_raw_id: &[u8],
        new_record: Vec<u8>,
    ) -> Result<Vec<u8>, Error<S::Error>> {
        let mut new_raw_id = vec![0u8; 16];
        StdRng::from_os_rng().fill_bytes(&mut new_raw_id);
        if new_raw_id == old_raw_id {
            // 2^-128, but inserting and deleting the same key in one write is
            // the one shape the server is entitled to interpret either way.
            warn!("storage manifest: generated identifier collided with the old one");
            return Err(Error::StorageManifestConflict);
        }

        // Substitute in place: every other identifier keeps its bytes, its type
        // and its position. The server treats the manifest as the complete index
        // of the account, so an identifier dropped here is deleted from every
        // device the user owns — including the record types presage cannot model.
        let mut identifiers = Vec::with_capacity(current.identifiers.len());
        let mut replaced = 0usize;
        for id in &current.identifiers {
            if id.raw == old_raw_id {
                replaced += 1;
                identifiers.push(manifest_record::Identifier {
                    raw: new_raw_id.clone(),
                    r#type: item_type.into(),
                });
            } else {
                if id.raw == new_raw_id {
                    warn!("storage manifest: generated identifier already in use");
                    return Err(Error::StorageManifestConflict);
                }
                identifiers.push(id.clone());
            }
        }

        // Being caught up should make this unreachable: our identifier was in the
        // manifest at the version we synced, and we are still at that version. It
        // survives as a guard against a peer that rewrites records in place.
        if replaced != 1 {
            debug!(
                replaced,
                "storage manifest: record is not at the identifier we hold"
            );
            return Err(Error::StorageRecordMoved);
        }

        // A substitution changes no counts. If it did, we would be about to orphan
        // or duplicate a record on every device the user owns — Signal-Desktop and
        // Signal-Android both validate the insert/delete sets against the id-set
        // delta at runtime, so this is checked in release too, not just asserted.
        if identifiers.len() != current.identifiers.len() {
            warn!("storage manifest: identifier count changed under a substitution");
            return Err(Error::StorageManifestConflict);
        }

        let new_manifest = ManifestRecord {
            version: current.version + 1,
            source_device: self.state.device_id().into(),
            identifiers,
            record_ikm: current.record_ikm.clone(),
        };

        match storage_service
            .write_items(
                new_manifest,
                vec![(new_raw_id.clone(), new_record)],
                vec![old_raw_id.to_vec()],
            )
            .await
        {
            Ok(()) => Ok(new_raw_id),
            Err(libsignal_service::StorageServiceError::Conflict) => {
                Err(Error::StorageManifestConflict)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Apply `edit` to a storage-service record and publish the result.
    ///
    /// `edit` receives the record as the server last gave it to us and returns the
    /// bytes to write, or `None` when the record already says what we want — which
    /// skips the write entirely rather than republishing an identical record.
    ///
    /// The caller supplies the *edit* rather than a finished record on purpose. A
    /// conflict means another device rewrote the account, so the retry has to
    /// re-read that contact and re-apply the change to whatever it now says;
    /// resending bytes derived from a stale snapshot is exactly what
    /// [`StorageServiceError::Conflict`] warns against.
    ///
    /// ## Only ever writing while caught up
    ///
    /// Each pass compares our stored manifest version against the server's, and
    /// syncs first if they differ. Two things follow, and they are why the check is
    /// here rather than a conditional further down:
    ///
    /// - The stored record bytes are provably current. A record is immutable under
    ///   its identifier, so if we are at the server's version, what we hold under
    ///   that identifier *is* what the server holds. No read is needed to confirm
    ///   it — which is why this does not fetch the record it is about to edit.
    /// - Recording `version + 1` after the write is unconditionally safe. Writing
    ///   while behind would claim a version whose records we never read, and the
    ///   next `manifest_if_changed` would answer 204 and skip them for good.
    ///
    /// On a conflict the local edit wins: it is re-applied over the freshly synced
    /// record. Signal-Desktop and Signal-Android both drop the local change here
    /// instead, but a block the user asked for a moment ago should not evaporate
    /// because an unrelated device touched the same contact.
    ///
    /// The record is marked as needing a storage sync before the first attempt and
    /// unmarked only once the server has taken the write, so an exhausted retry or
    /// a crash leaves a durable record of what still needs publishing.
    ///
    /// Note the syncs here apply remote state to the local row, which can revert
    /// the very field being published. The published *bytes* stay correct — they
    /// are rebuilt from the edit — but keeping the local row in step needs the
    /// pending-change guard in the sync merge.
    ///
    /// Callers must hold the storage-service lock.
    pub async fn update_storage_record(
        &mut self,
        key: &StorageRecordKey,
        edit: impl Fn(&[u8]) -> Result<Option<Vec<u8>>, StorageRecordEditError>,
    ) -> Result<(), Error<S::Error>> {
        /// Catching up does not consume a write attempt, so the loop needs its own
        /// ceiling. Reaching it means we lost the race to sync repeatedly, which is
        /// the same outcome as losing it at the write.
        const MAX_PASSES: usize = MANIFEST_WRITE_ATTEMPTS * 2;

        self.set_needs_storage_sync(key, true).await?;

        let storage_service = self.storage_service().await?;
        let mut write_attempts = 0usize;

        for _ in 0..MAX_PASSES {
            let local_version = self.store.fetch_storage_manifest_version().await?;
            let current = storage_service.manifest().await?;

            if current.version != local_version {
                debug!(
                    local_version,
                    remote_version = current.version,
                    "storage manifest: behind the server, syncing before writing"
                );
                // Also refreshes this contact's stored identifier and bytes, so the
                // next pass edits what the server actually holds.
                self.sync_storage_service().await?;
                continue;
            }

            let Some(identity) = self.storage_identity(key).await? else {
                return Err(Error::StorageRecordUnknown);
            };

            let Some(new_record) = edit(&identity.record)? else {
                debug!("storage manifest: record already current, skipping write");
                self.set_needs_storage_sync(key, false).await?;
                return Ok(());
            };

            match self
                .write_replacing_storage_record(
                    &storage_service,
                    &current,
                    key.item_type(),
                    &identity.storage_id,
                    new_record.clone(),
                )
                .await
            {
                Ok(new_raw_id) => {
                    let version = current.version + 1;
                    self.store.store_storage_manifest_version(version).await?;
                    // Only now is the write real. Committing earlier would leave us
                    // pointing at an identifier the server never accepted.
                    self.save_storage_identity(
                        key,
                        &StorageRecordIdentity {
                            storage_id: new_raw_id,
                            storage_version: version,
                            record: new_record,
                        },
                    )
                    .await?;
                    self.set_needs_storage_sync(key, false).await?;
                    debug!(version, "storage manifest: replaced storage record");
                    self.notify_storage_manifest_written().await;
                    return Ok(());
                }
                Err(Error::StorageManifestConflict) | Err(Error::StorageRecordMoved) => {
                    write_attempts += 1;
                    let Some(backoff) = MANIFEST_WRITE_BACKOFF.get(write_attempts - 1) else {
                        break;
                    };
                    debug!(
                        write_attempts,
                        backoff_ms = backoff.as_millis() as u64,
                        "storage manifest: conflict, backing off before retry"
                    );
                    tokio::time::sleep(*backoff).await;
                }
                Err(e) => return Err(e),
            }
        }

        // The flag stays set: the change is still pending, and a later storage
        // operation is expected to flush it.
        warn!("storage manifest: gave up publishing storage record after conflicts");
        Err(Error::StorageManifestConflict)
    }

    /// The three store calls [`update_storage_record`](Self::update_storage_record)
    /// makes on the record it is publishing, each dispatched on the record type.
    /// Keeping the match here rather than inline leaves that function one shape
    /// for every key, and leaves a new `StorageRecordKey` variant three compile
    /// errors in one place.
    async fn set_needs_storage_sync(
        &mut self,
        key: &StorageRecordKey,
        needs_sync: bool,
    ) -> Result<(), Error<S::Error>> {
        match key {
            StorageRecordKey::Contact(service_id) => {
                self.store
                    .set_contact_needs_storage_sync(service_id, needs_sync)
                    .await?
            }
            StorageRecordKey::GroupV2(master_key) => {
                self.store
                    .set_group_needs_storage_sync(*master_key, needs_sync)
                    .await?
            }
        }
        Ok(())
    }

    async fn storage_identity(
        &self,
        key: &StorageRecordKey,
    ) -> Result<Option<StorageRecordIdentity>, Error<S::Error>> {
        Ok(match key {
            StorageRecordKey::Contact(service_id) => {
                self.store.contact_storage_identity(service_id).await?
            }
            StorageRecordKey::GroupV2(master_key) => {
                self.store.group_storage_identity(*master_key).await?
            }
        })
    }

    async fn save_storage_identity(
        &mut self,
        key: &StorageRecordKey,
        identity: &StorageRecordIdentity,
    ) -> Result<(), Error<S::Error>> {
        match key {
            StorageRecordKey::Contact(service_id) => {
                self.store
                    .save_contact_storage_identity(service_id, identity)
                    .await?
            }
            StorageRecordKey::GroupV2(master_key) => {
                self.store
                    .save_group_storage_identity(*master_key, identity)
                    .await?
            }
        }
        Ok(())
    }

    /// Publish every contact whose local state has not reached the storage service.
    ///
    /// Takes no argument on purpose. The work list is the store — every contact
    /// flagged by [`set_blocked`](Self::set_blocked) — not something a caller
    /// passes in, so a coalesced or dropped request costs latency and never data.
    /// It is safe to call at any time, and doing so after every sync is what gives
    /// an interrupted or failed publish another chance without a retry timer.
    ///
    /// The edit is derived from the local row rather than carried, which is only
    /// sound because a sync cannot revert a row with a publish outstanding — see
    /// the `has_pending_publish` guard in `merge_contact_from_snapshot`.
    ///
    /// One contact's failure does not stop the rest: its flag stays set and the
    /// next call tries again.
    ///
    /// Callers must hold the storage-service lock.
    pub async fn push_pending_contact_records(&mut self) -> Result<(), Error<S::Error>> {
        let pending = self.store.contacts_needing_storage_sync().await?;
        if pending.is_empty() {
            return Ok(());
        }
        debug!(
            count = pending.len(),
            "storage manifest: publishing pending contact records"
        );

        for service_id in pending {
            if let Err(e) = self.push_contact_record(&service_id).await {
                warn!(%e, "storage manifest: failed to publish a contact record");
            }
        }
        Ok(())
    }

    /// Bring one contact's storage-service record in line with the local row.
    async fn push_contact_record(&mut self, service_id: &ServiceId) -> Result<(), Error<S::Error>> {
        let Some(contact) = self.store.contact_by_id(service_id).await? else {
            // Flagged but gone: nothing to publish, and leaving the flag set
            // would make every future drain retry a contact that cannot exist.
            warn!("storage manifest: pending contact is no longer in the store");
            self.store
                .set_contact_needs_storage_sync(service_id, false)
                .await?;
            return Ok(());
        };
        match self
            .update_storage_record(&StorageRecordKey::Contact(*service_id), |record| {
                // One closure settles every publishable field — the pending
                // flag is per contact, so a drain that fixed only one could
                // clear the flag another still needs. `PendingPublish::diff`
                // is the shared enumeration of those fields, so this writes
                // exactly what the merge guard protects.
                let diff = PendingPublish::diff(record, &contact)?;
                if !diff.any() {
                    return Ok(None);
                }
                let mut edited: Option<Vec<u8>> = None;
                if diff.blocked {
                    edited = Some(set_contact_blocked(record, contact.blocked)?);
                }
                if diff.muted {
                    let current = edited.as_deref().unwrap_or(record);
                    edited = Some(set_contact_muted_until(
                        current,
                        contact.muted_until_timestamp,
                    )?);
                }
                Ok(edited)
            })
            .await
        {
            // The account holds no record for this contact, so there is nothing to
            // edit. Creating one cannot clobber anything, which is the only reason
            // building it from our lossy `Contact` is sound here.
            Err(Error::StorageRecordUnknown) => {
                self.append_contact_record(service_id, &contact).await?
            }
            other => other?,
        }

        // The row was read before a manifest fetch, a write, and possibly two
        // backoff sleeps — seconds, in which the user may have toggled again. The
        // publish path clears the pending flag on success, so without this the
        // newer value would be left unflagged and never republished: the local row
        // and the server would disagree permanently. Re-raise the flag instead and
        // let the next drain carry the newer value.
        if let Some(current) = self.store.contact_by_id(service_id).await? {
            if PendingPublish::between(&current, &contact).any() {
                debug!("storage manifest: contact changed while publishing, re-flagging");
                self.store
                    .set_contact_needs_storage_sync(service_id, true)
                    .await?;
            }
        }
        Ok(())
    }

    /// Add a first storage-service record for a contact the account has never had one for.
    async fn append_contact_record(
        &mut self,
        service_id: &ServiceId,
        contact: &Contact,
    ) -> Result<(), Error<S::Error>> {
        debug!("storage manifest: contact has no record yet, appending one");

        let record = StorageRecord {
            record: Some(storage_record::Record::Contact(
                contact.to_new_storage_record(),
            )),
        };
        self.append_record(&StorageRecordKey::Contact(*service_id), record)
            .await
    }

    /// Publish every group whose local state has not reached the storage service.
    ///
    /// The group twin of
    /// [`push_pending_contact_records`](Self::push_pending_contact_records), and
    /// the same contract: no argument, the work list is the store, safe to call
    /// at any time, and one group's failure never stops the rest.
    ///
    /// Callers must hold the storage-service lock.
    pub async fn push_pending_group_records(&mut self) -> Result<(), Error<S::Error>> {
        let pending = self.store.groups_needing_storage_sync().await?;
        if pending.is_empty() {
            return Ok(());
        }
        debug!(
            count = pending.len(),
            "storage manifest: publishing pending group records"
        );

        for master_key in pending {
            if let Err(e) = self.push_group_record(master_key).await {
                warn!(%e, "storage manifest: failed to publish a group record");
            }
        }
        Ok(())
    }

    /// Bring one group's storage-service record in line with the local row.
    async fn push_group_record(
        &mut self,
        master_key: GroupMasterKeyBytes,
    ) -> Result<(), Error<S::Error>> {
        let Some(group) = self.store.group(master_key).await? else {
            // Flagged but gone: nothing to publish, and leaving the flag set
            // would make every future drain retry a group that cannot exist.
            warn!("storage manifest: pending group is no longer in the store");
            self.store
                .set_group_needs_storage_sync(master_key, false)
                .await?;
            return Ok(());
        };

        match self
            .update_storage_record(&StorageRecordKey::GroupV2(master_key), |record| {
                // One closure settles every publishable field, for the same
                // reason as the contact path: the pending flag is per group, so
                // a drain that fixed only one could clear a flag another still
                // needs.
                let diff = GroupPendingPublish::diff(record, &group)?;
                if !diff.muted {
                    return Ok(None);
                }
                Ok(Some(set_group_muted_until(
                    record,
                    group.muted_until_timestamp,
                )?))
            })
            .await
        {
            // The account holds no record for this group, so there is nothing to
            // edit. Creating one cannot clobber anything, which is the only reason
            // building it from our lossy `Group` is sound here.
            Err(Error::StorageRecordUnknown) => {
                self.append_group_record(master_key, &group).await?
            }
            other => other?,
        }

        // The row was read before a manifest fetch, a write, and possibly two
        // backoff sleeps — seconds, in which the user may have toggled again. See
        // `push_contact_record` for why the flag has to go back up rather than the
        // newer value being left unflagged.
        if let Some(current) = self.store.group(master_key).await? {
            if GroupPendingPublish::between(&current, &group).any() {
                debug!("storage manifest: group changed while publishing, re-flagging");
                self.store
                    .set_group_needs_storage_sync(master_key, true)
                    .await?;
            }
        }
        Ok(())
    }

    /// Add a first storage-service record for a group the account has never had one for.
    ///
    /// [`Group::to_new_storage_record`] cannot fill `avatar_color` or
    /// `verified_name_hash` — presage does not model either. Only reached when the
    /// account holds no GroupV2 record for this group at all, where there is
    /// nothing to clobber; an *edit* must never be built this way.
    async fn append_group_record(
        &mut self,
        master_key: GroupMasterKeyBytes,
        group: &Group,
    ) -> Result<(), Error<S::Error>> {
        debug!("storage manifest: group has no record yet, appending one");

        let record = StorageRecord {
            record: Some(storage_record::Record::GroupV2(
                group.to_new_storage_record(master_key),
            )),
        };
        self.append_record(&StorageRecordKey::GroupV2(master_key), record)
            .await
    }

    /// Insert a freshly-built record under a new identifier and record where it
    /// landed.
    ///
    /// Routed through the same three key helpers as
    /// [`update_storage_record`](Self::update_storage_record), so the promise
    /// they carry — that a new [`StorageRecordKey`] variant is a compile error
    /// in one place — holds for the append paths too.
    async fn append_record(
        &mut self,
        key: &StorageRecordKey,
        record: StorageRecord,
    ) -> Result<(), Error<S::Error>> {
        let encoded = record.encode_to_vec();
        let storage_id = self
            .append_storage_record(key.item_type(), encoded.clone())
            .await?;

        let version = self.store.fetch_storage_manifest_version().await?;
        self.save_storage_identity(
            key,
            &StorageRecordIdentity {
                storage_id,
                storage_version: version,
                record: encoded,
            },
        )
        .await?;
        self.set_needs_storage_sync(key, false).await?;
        Ok(())
    }

    pub async fn sync_storage_service(&mut self) -> Result<(), Error<S::Error>> {
        let master_key = self
            .master_key()
            .await?
            .ok_or_else(|| Error::MissingKeyError("master_key".into()))?;
        let storage_key = StorageServiceKey::from_master_key(&master_key);
        let push_service = self.identified_push_service();
        sync_storage_service(&mut self.store, &push_service, storage_key).await
    }
}

/// Parse a [`Contact`]'s raw profile-key bytes into a [`ProfileKey`].
///
/// The field is a `Vec<u8>` that is legitimately empty — `Contact::minimal` and a
/// `ContactRecord` carrying no key both produce one — so anything that isn't exactly
/// 32 bytes is treated as absent.
pub(super) fn contact_profile_key(contact: &Contact) -> Option<ProfileKey> {
    <[u8; 32]>::try_from(contact.profile_key.as_slice())
        .ok()
        .map(ProfileKey::create)
}

/// Merge the locally-stored contact into one rebuilt from a remote snapshot, and report
/// which at-risk fields were protected.
///
/// Applies to both snapshot sources: a storage-service `ContactRecord` and a backup
/// `Recipient` frame. Each is a full snapshot, but only of what the *writing* device knew —
/// and proto3 gives these scalars no presence, so an empty value is indistinguishable from
/// an unset one and carries no information. Letting one overwrite local data loses the
/// contact's name, profile key, phone number, PNI or username for nothing. Neither source
/// carries the locally-derived fields below, so both want them restored verbatim.
///
/// A *non-empty* remote value still wins. Storage sync is the only channel that delivers a
/// renamed contact to the app — presage only re-fetches a profile on first sight or a
/// profile-key rotation — so remote stays authoritative whenever it has something to say.
///
/// `pending` is the exception to that. A contact whose local change has not yet reached the
/// storage service must keep it: the record we are merging *from* is the one we are about
/// to overwrite, so letting it win would discard the user's action and then publish the
/// discarded value back. The protection is per field, not per contact — the
/// [`ContentsStore::set_contact_needs_storage_sync`] flag only says *a* change is owed, and
/// blanket-preserving every publishable field under it would keep stale local values for
/// fields nobody edited, which the next publish would then push over a remote change. See
/// [`pending_publish_intent`] for how the per-field intent is derived.
pub(super) fn merge_contact_from_snapshot(
    contact: &mut Contact,
    existing: Contact,
    pending: PendingPublish,
) -> Vec<&'static str> {
    // Not carried by either snapshot source at all — always local.
    contact.expire_timer = existing.expire_timer;
    contact.expire_timer_version = existing.expire_timer_version;
    contact.inbox_position = existing.inbox_position;
    contact.avatar = existing.avatar;
    contact.verified = existing.verified;

    let mut preserved = Vec::new();
    if contact.name.is_empty() && !existing.name.is_empty() {
        contact.name = existing.name;
        preserved.push("name");
    }
    if contact.profile_key.is_empty() && !existing.profile_key.is_empty() {
        contact.profile_key = existing.profile_key;
        preserved.push("profile_key");
    }
    if contact.phone_number.is_none() && existing.phone_number.is_some() {
        contact.phone_number = existing.phone_number;
        preserved.push("phone_number");
    }
    if contact.pni.is_none() && existing.pni.is_some() {
        contact.pni = existing.pni;
        preserved.push("pni");
    }
    if contact.username.is_none() && existing.username.is_some() {
        contact.username = existing.username;
        preserved.push("username");
    }
    if pending.blocked && contact.blocked != existing.blocked {
        contact.blocked = existing.blocked;
        preserved.push("blocked");
    }
    if pending.muted && contact.muted_until_timestamp != existing.muted_until_timestamp {
        contact.muted_until_timestamp = existing.muted_until_timestamp;
        preserved.push("muted_until_timestamp");
    }
    preserved
}

/// The set of storage-service-publishable contact fields, as a "which ones"
/// bitmap. Doubles as the pending-publish intent the merge guard consumes.
///
/// Derived rather than stored: a field is pending iff the whole-contact
/// [`ContentsStore::set_contact_needs_storage_sync`] flag is raised *and* the
/// local row disagrees with the last-published record bytes. [`Self::diff`] is
/// that comparison, and [`Manager::push_contact_record`] publishes off the same
/// diff — so the merge protects exactly what the publish will write, and a new
/// publishable field is one field here plus its arm in `diff`/`between` and in
/// the publish closure next door.
#[derive(Clone, Copy, Default)]
pub(super) struct PendingPublish {
    pub blocked: bool,
    pub muted: bool,
}

impl PendingPublish {
    /// The publishable fields on which `local` disagrees with the published
    /// record bytes.
    fn diff(record: &[u8], local: &Contact) -> Result<Self, StorageRecordEditError> {
        Ok(Self {
            blocked: contact_blocked(record)? != local.blocked,
            muted: contact_muted_until(record)? != local.muted_until_timestamp,
        })
    }

    /// The publishable fields on which two contact rows disagree.
    fn between(a: &Contact, b: &Contact) -> Self {
        Self {
            blocked: a.blocked != b.blocked,
            muted: a.muted_until_timestamp != b.muted_until_timestamp,
        }
    }

    fn any(&self) -> bool {
        self.blocked || self.muted
    }
}

/// Apply a storage-service `GroupV2Record` to the stored group, keeping what
/// only this device knows.
///
/// The group analogue of [`merge_contact_from_snapshot`], and simpler for one
/// reason: every field a `GroupV2Record` carries is storage-service-owned, so
/// there is no "an empty remote value must not overwrite local data" rule here —
/// the locally-derived fields (title, members, revision, avatar, timer) are not
/// in the record at all and are simply left alone.
///
/// `pending` is the same exception it is for contacts. A group whose local mute
/// has not reached the storage service must keep it: the record we are merging
/// *from* is the one we are about to overwrite, and `update_storage_record` calls
/// `sync_storage_service` whenever it finds itself behind — so the publish path
/// triggers the very sync that would revert it.
pub(super) fn merge_group_from_snapshot(
    existing: &mut Group,
    remote: &libsignal_service::proto::GroupV2Record,
    pending: GroupPendingPublish,
) {
    existing.blocked = remote.blocked;
    existing.whitelisted = remote.whitelisted;
    existing.archived = remote.archived;
    existing.marked_unread = remote.marked_unread;
    if !pending.muted {
        existing.muted_until_timestamp = remote.muted_until_timestamp;
    }
    existing.dont_notify_for_mentions_if_muted = remote.dont_notify_for_mentions_if_muted;
    existing.hide_story = remote.hide_story;
    existing.story_send_mode = remote.story_send_mode.into();
}

/// The set of storage-service-publishable group fields, as a "which ones"
/// bitmap. The group twin of [`PendingPublish`], and the same contract: a field
/// is pending iff the whole-group
/// [`ContentsStore::set_group_needs_storage_sync`] flag is raised *and* the local
/// row disagrees with the last-published record bytes.
///
/// One field today. `blocked` joins it the way `muted` joined the contact twin:
/// one field here, one arm in `diff` and `between`, one in the publish closure
/// next door.
#[derive(Clone, Copy, Default)]
pub(super) struct GroupPendingPublish {
    pub muted: bool,
}

impl GroupPendingPublish {
    /// The publishable fields on which `local` disagrees with the published
    /// record bytes.
    fn diff(record: &[u8], local: &Group) -> Result<Self, StorageRecordEditError> {
        Ok(Self {
            muted: group_muted_until(record)? != local.muted_until_timestamp,
        })
    }

    /// The publishable fields on which two group rows disagree.
    fn between(a: &Group, b: &Group) -> Self {
        Self {
            muted: a.muted_until_timestamp != b.muted_until_timestamp,
        }
    }

    fn any(&self) -> bool {
        self.muted
    }
}

/// Compute [`GroupPendingPublish`] for a group. The contact twin's contract
/// applies unchanged — see [`pending_publish_intent`], including why this must
/// run *before* the fresh identity from an in-flight sync overwrites the stored
/// bytes.
pub(super) async fn group_pending_publish_intent<S: Store>(
    store: &S,
    master_key: GroupMasterKeyBytes,
    local: &Group,
    flagged: bool,
) -> GroupPendingPublish {
    if !flagged {
        return GroupPendingPublish::default();
    }
    let all = GroupPendingPublish { muted: true };
    match store.group_storage_identity(master_key).await {
        Ok(Some(identity)) => GroupPendingPublish::diff(&identity.record, local).unwrap_or(all),
        _ => all,
    }
}

/// Compute [`PendingPublish`] for a contact. `flagged` is the contact's
/// whole-contact needs-sync flag — without it nothing is pending, and folding
/// the guard in here means no caller can forget it. Call this *before* the
/// fresh identity from an in-flight sync overwrites the stored bytes. No
/// record to diff against — never published, unreadable, or malformed — means
/// everything local is intent.
pub(super) async fn pending_publish_intent<S: Store>(
    store: &S,
    service_id: &ServiceId,
    local: &Contact,
    flagged: bool,
) -> PendingPublish {
    if !flagged {
        return PendingPublish::default();
    }
    let all = PendingPublish {
        blocked: true,
        muted: true,
    };
    match store.contact_storage_identity(service_id).await {
        Ok(Some(identity)) => PendingPublish::diff(&identity.record, local).unwrap_or(all),
        _ => all,
    }
}

async fn sync_storage_service<S: Store>(
    store: &mut S,
    push_service: &PushService,
    storage_key: StorageServiceKey,
) -> Result<(), Error<S::Error>> {
    use libsignal_service::{
        proto::manifest_record::identifier::Type as StorageType, StorageService,
    };

    debug!("storage sync: authenticating with storage service");
    let storage_service = StorageService::new(push_service.clone(), storage_key).await?;

    let local_version = store.fetch_storage_manifest_version().await?;
    debug!(local_version, "storage sync: fetching manifest");
    let Some(manifest_record) = storage_service.manifest_if_changed(local_version).await? else {
        debug!(
            local_version,
            "storage sync: server version unchanged (204), skipping"
        );
        // Server reports no change — a leftover cursor would be stale.
        store.clear_storage_sync_cursor().await.ok();
        return Ok(());
    };
    let manifest_version = manifest_record.version;
    debug!(
        version = manifest_version,
        local_version,
        identifiers = manifest_record.identifiers.len(),
        has_record_ikm = !manifest_record.record_ikm.is_empty(),
        "storage sync: got and decrypted manifest"
    );

    let record_ikm: Option<Vec<u8>> = if manifest_record.record_ikm.is_empty() {
        None
    } else {
        Some(manifest_record.record_ikm.clone())
    };

    let mut contact_keys: Vec<Vec<u8>> = Vec::new();
    let mut group_keys: Vec<Vec<u8>> = Vec::new();
    for id in &manifest_record.identifiers {
        match id.r#type() {
            StorageType::Contact => contact_keys.push(id.raw.clone()),
            StorageType::Groupv2 => group_keys.push(id.raw.clone()),
            _ => {}
        }
    }
    debug!(
        count = contact_keys.len(),
        "storage sync: contact keys in manifest"
    );
    debug!(
        count = group_keys.len(),
        "storage sync: group keys in manifest"
    );

    if contact_keys.is_empty() && group_keys.is_empty() {
        debug!("storage sync: nothing to sync");
        return Ok(());
    }

    let all_keys: Vec<Vec<u8>> = contact_keys.into_iter().chain(group_keys).collect();
    let total = all_keys.len();
    debug!(total, "storage sync: fetching storage records in batches");

    // Read once for the whole sync rather than per record. These contacts hold a
    // local change the server has not taken yet, so the record we are about to
    // merge is the one we are about to overwrite — letting it win would discard
    // the user's action and then publish the discarded value back.
    let contact_pending: std::collections::HashSet<ServiceId> = store
        .contacts_needing_storage_sync()
        .await
        .unwrap_or_default()
        .into_iter()
        .collect();
    let group_pending: std::collections::HashSet<GroupMasterKeyBytes> = store
        .groups_needing_storage_sync()
        .await
        .unwrap_or_default()
        .into_iter()
        .collect();
    if !contact_pending.is_empty() || !group_pending.is_empty() {
        debug!(
            contacts = contact_pending.len(),
            groups = group_pending.len(),
            "storage sync: subjects with an unpublished local change"
        );
    }

    // If we have a saved cursor that targets this same manifest version,
    // skip the batches already completed in the prior attempt. A cursor
    // for any other version is stale — discard and start fresh.
    let resume_from = match store.fetch_storage_sync_cursor().await? {
        Some(cursor) if cursor.target_version == manifest_version => {
            debug!(
                target_version = cursor.target_version,
                next_batch_index = cursor.next_batch_index,
                "storage sync: resuming from saved cursor"
            );
            cursor.next_batch_index as usize
        }
        Some(stale) => {
            debug!(
                stale_version = stale.target_version,
                current_version = manifest_version,
                "storage sync: stale cursor for old manifest version, discarding"
            );
            store.clear_storage_sync_cursor().await.ok();
            0
        }
        None => 0,
    };

    let mut total_processed = 0usize;
    for (i, batch) in all_keys
        .chunks(STORAGE_SERVICE_BATCH_SIZE)
        .enumerate()
        .skip(resume_from)
    {
        debug!(
            batch = i,
            size = batch.len(),
            "storage sync: fetching batch"
        );
        let records = storage_service
            .read_items(batch.to_vec(), record_ikm.as_deref())
            .await?;
        debug!(count = records.len(), "storage sync: got storage records");
        total_processed += records.len();

        for item in records {
            match item.record.record {
                Some(libsignal_service::proto::storage_record::Record::Contact(cr)) => {
                    debug!(aci = %cr.aci, name = %cr.given_name, "storage sync: saving contact");
                    let mut contact: Contact = match Contact::try_from(cr) {
                        Ok(c) => c,
                        Err(e) => {
                            warn!("storage sync: skipping contact record: {e}");
                            continue;
                        }
                    };

                    // Merge the stored contact into the one rebuilt from the record:
                    // restore what the record cannot carry, and refuse to let an empty
                    // record field overwrite local data.
                    let service_id = ServiceId::Aci(Aci::from(contact.uuid));
                    if let Some(existing) = store.contact_by_id(&service_id).await.ok().flatten() {
                        // Derived from the identity we are about to replace, so
                        // it has to be read before the save below.
                        let pending = pending_publish_intent(
                            store,
                            &service_id,
                            &existing,
                            contact_pending.contains(&service_id),
                        )
                        .await;
                        merge_contact_from_snapshot(&mut contact, existing, pending);
                    }
                    if let Err(e) = store.save_contact(&contact).await {
                        warn!(%e, "storage sync: failed to save contact");
                    }
                    // Remember where this record lives so it can be updated later. The
                    // plaintext is stored as read: an update edits these bytes rather
                    // than re-encoding a lossy `Contact`.
                    let identity = StorageRecordIdentity {
                        storage_id: item.key,
                        storage_version: manifest_version,
                        record: item.plaintext,
                    };
                    if let Err(e) = store
                        .save_contact_storage_identity(&service_id, &identity)
                        .await
                    {
                        warn!(%e, "storage sync: failed to save contact storage identity");
                    }
                    // Keep `profile_keys` in step with the contact row — it is the
                    // table `ContentsStore::profile_key` reads, and until now only the
                    // first-sight message path wrote to it.
                    if let Some(profile_key) = contact_profile_key(&contact) {
                        if let Err(e) = store.upsert_profile_key(&contact.uuid, profile_key).await {
                            warn!(%e, "storage sync: failed to upsert profile key");
                        }
                    }
                }
                Some(libsignal_service::proto::storage_record::Record::GroupV2(gr)) => {
                    let master_key: GroupMasterKeyBytes = match gr.master_key.as_slice().try_into()
                    {
                        Ok(mk) => mk,
                        Err(_) => {
                            warn!("storage sync: invalid group master key length, skipping");
                            continue;
                        }
                    };
                    let group = match store.group(master_key).await {
                        Ok(Some(mut existing)) => {
                            // Derived from the identity we are about to replace, so
                            // it has to be read before the save below.
                            let pending = group_pending_publish_intent(
                                store,
                                master_key,
                                &existing,
                                group_pending.contains(&master_key),
                            )
                            .await;
                            merge_group_from_snapshot(&mut existing, &gr, pending);
                            existing
                        }
                        _ => {
                            debug!("storage sync: saving group stub");
                            let mut stub = Group {
                                needs_hydration: true,
                                ..Default::default()
                            };
                            merge_group_from_snapshot(
                                &mut stub,
                                &gr,
                                GroupPendingPublish::default(),
                            );
                            stub
                        }
                    };
                    if let Err(e) = store.save_group(master_key, group).await {
                        warn!(%e, "storage sync: failed to save group");
                    }
                    // Remember where this record lives so it can be updated later.
                    // The plaintext is stored as read: an update edits these bytes
                    // rather than re-encoding a `Group`, which carries neither
                    // `avatar_color` nor `verified_name_hash`.
                    let identity = StorageRecordIdentity {
                        storage_id: item.key,
                        storage_version: manifest_version,
                        record: item.plaintext,
                    };
                    if let Err(e) = store
                        .save_group_storage_identity(master_key, &identity)
                        .await
                    {
                        warn!(%e, "storage sync: failed to save group storage identity");
                    }
                }
                Some(other) => {
                    debug!(?other, "storage sync: skipping non-contact/group record");
                }
                None => {
                    debug!("storage sync: empty record, skipping");
                }
            }
        }

        // Per-batch checkpoint: every record in batches 0..=i has been
        // attempted (successes are persisted via INSERT OR REPLACE in the
        // store impls; failures were warn-logged and skipped). If the app
        // dies after this point, the next sync targeting this same manifest
        // version will resume at batch i+1.
        let cursor = StorageSyncCursor {
            target_version: manifest_version,
            next_batch_index: (i + 1) as u32,
        };
        if let Err(e) = store.store_storage_sync_cursor(&cursor).await {
            warn!(%e, "storage sync: failed to persist sync cursor, continuing");
        }
    }

    store
        .store_storage_manifest_version(manifest_version)
        .await?;
    // Sync completed end-to-end — clear the cursor so it doesn't survive
    // as a stale entry on the next call.
    store.clear_storage_sync_cursor().await.ok();
    info!(
        count = total_processed,
        version = manifest_version,
        "storage service sync complete"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use libsignal_service::prelude::Uuid;

    fn contact_with_profile_key(bytes: Vec<u8>) -> Contact {
        let mut contact = Contact::minimal(Uuid::nil());
        contact.profile_key = bytes;
        contact
    }

    #[test]
    fn contact_profile_key_accepts_32_bytes() {
        let bytes = vec![7u8; 32];
        let key = contact_profile_key(&contact_with_profile_key(bytes.clone()))
            .expect("32 bytes is a profile key");
        assert_eq!(key.bytes.as_slice(), bytes.as_slice());
    }

    #[test]
    fn contact_profile_key_rejects_empty() {
        // What `Contact::minimal` and a `ContactRecord` with no key both produce.
        assert!(contact_profile_key(&Contact::minimal(Uuid::nil())).is_none());
    }

    #[test]
    fn contact_profile_key_rejects_wrong_length() {
        assert!(contact_profile_key(&contact_with_profile_key(vec![7u8; 31])).is_none());
    }

    /// A contact as the store holds it: everything populated.
    fn stored_contact() -> Contact {
        let mut c = Contact::minimal(Uuid::nil());
        c.name = "Local Name".into();
        c.profile_key = vec![7u8; 32];
        c.phone_number = Some(
            libsignal_service::prelude::phonenumber::parse(None, "+15555550123").expect("valid"),
        );
        c.pni = Some(Uuid::from_u128(1));
        c.username = Some("local.42".into());
        c.expire_timer = 3600;
        c.expire_timer_version = 9;
        c.inbox_position = 5;
        c
    }

    /// A contact as rebuilt from a `ContactRecord` that carried nothing but an ACI —
    /// the "whitelisted-only stub" shape observed in real storage-service data.
    fn empty_record_contact() -> Contact {
        Contact::minimal(Uuid::nil())
    }

    /// The window this exists for: the user blocked someone, the write has not
    /// reached the server, and a sync arrives carrying the pre-block record. The
    /// record we are merging is the one we are about to overwrite, so letting it
    /// win would discard the block — and, because publishing derives the edit
    /// from this row, then publish the discarded value back as an *unblock*.
    #[test]
    fn a_pending_block_survives_the_record_it_is_about_to_replace() {
        let mut local = stored_contact();
        local.blocked = true;

        let mut incoming = empty_record_contact();
        incoming.blocked = false;

        let preserved = merge_contact_from_snapshot(
            &mut incoming,
            local,
            PendingPublish {
                blocked: true,
                muted: false,
            },
        );

        assert!(incoming.blocked, "the pending block was reverted");
        assert!(preserved.contains(&"blocked"));
    }

    /// Without a pending change the remote value is authoritative, so a block or
    /// unblock made on another device still lands here.
    #[test]
    fn a_remote_unblock_wins_when_nothing_is_pending() {
        let mut local = stored_contact();
        local.blocked = true;

        let mut incoming = empty_record_contact();
        incoming.blocked = false;

        let preserved =
            merge_contact_from_snapshot(&mut incoming, local, PendingPublish::default());

        assert!(!incoming.blocked);
        assert!(!preserved.contains(&"blocked"));
    }

    /// The guard is about *disagreement*, not about the flag. A pending contact
    /// whose remote record already agrees needs no protection and should not be
    /// reported as protected.
    #[test]
    fn agreement_is_not_reported_as_preserved() {
        let mut local = stored_contact();
        local.blocked = true;

        let mut incoming = empty_record_contact();
        incoming.blocked = true;

        let preserved = merge_contact_from_snapshot(
            &mut incoming,
            local,
            PendingPublish {
                blocked: true,
                muted: false,
            },
        );

        assert!(incoming.blocked);
        assert!(!preserved.contains(&"blocked"));
    }

    /// The point of per-field intent: a pending *block* must not shield the
    /// mute field, or a mute made on another device would be preserved away
    /// here and then overwritten by our next publish.
    #[test]
    fn a_pending_block_still_takes_a_remote_mute() {
        let mut local = stored_contact();
        local.blocked = true;
        local.muted_until_timestamp = 0;

        let mut incoming = empty_record_contact();
        incoming.blocked = false;
        incoming.muted_until_timestamp = 1_700_000_000_000;

        let preserved = merge_contact_from_snapshot(
            &mut incoming,
            local,
            PendingPublish {
                blocked: true,
                muted: false,
            },
        );

        assert!(incoming.blocked, "the pending block was reverted");
        assert_eq!(
            incoming.muted_until_timestamp, 1_700_000_000_000,
            "the remote mute was preserved away by an unrelated pending block"
        );
        assert!(preserved.contains(&"blocked"));
        assert!(!preserved.contains(&"muted_until_timestamp"));
    }

    fn local_group() -> Group {
        Group {
            title: Some("Book club".into()),
            revision: 7,
            whitelisted: true,
            ..Default::default()
        }
    }

    fn empty_group_record() -> libsignal_service::proto::GroupV2Record {
        libsignal_service::proto::GroupV2Record {
            master_key: vec![7u8; 32],
            ..Default::default()
        }
    }

    /// With nothing pending, remote wins — the same rule every official client
    /// applies, and the reason a mute made on the phone reaches us at all.
    #[test]
    fn a_group_with_nothing_pending_takes_the_remote_mute() {
        let mut local = local_group();
        local.muted_until_timestamp = i64::MAX as u64;

        let mut remote = empty_group_record();
        remote.muted_until_timestamp = 0;
        merge_group_from_snapshot(&mut local, &remote, GroupPendingPublish::default());

        assert_eq!(local.muted_until_timestamp, 0);
    }

    /// The guard exists because `update_storage_record` syncs when it finds
    /// itself behind, so the publish path triggers the sync that would revert
    /// the mute it is publishing. It is per field, not per group: a pending mute
    /// must not shield anything else, or a change made on another device would
    /// be preserved away here and then overwritten by our next publish.
    #[test]
    fn a_pending_group_mute_shields_only_the_mute() {
        let mut local = local_group();
        local.muted_until_timestamp = i64::MAX as u64;
        local.blocked = false;
        local.archived = false;

        let mut remote = empty_group_record();
        remote.blocked = true;
        remote.archived = true;
        merge_group_from_snapshot(&mut local, &remote, GroupPendingPublish { muted: true });

        assert_eq!(local.muted_until_timestamp, i64::MAX as u64);
        assert!(local.blocked, "the remote block was preserved away");
        assert!(local.archived, "the remote archive was preserved away");
    }

    /// The locally-derived fields are not in the record at all, so a merge must
    /// leave them alone rather than zeroing them.
    #[test]
    fn merging_a_group_record_leaves_local_fields_alone() {
        let mut local = local_group();
        merge_group_from_snapshot(
            &mut local,
            &empty_group_record(),
            GroupPendingPublish::default(),
        );

        assert_eq!(local.title.as_deref(), Some("Book club"));
        assert_eq!(local.revision, 7);
        assert!(!local.needs_hydration);
    }

    /// The intent is derived, not stored: without the flag nothing is pending,
    /// however far the local row has drifted.
    /// The intent is derived from the published bytes, not stored: a row that
    /// disagrees with its record is what makes the field pending.
    #[test]
    fn group_publish_intent_diffs_against_the_record() {
        let mut local = local_group();
        local.muted_until_timestamp = i64::MAX as u64;

        let record = StorageRecord {
            record: Some(storage_record::Record::GroupV2(empty_group_record())),
        }
        .encode_to_vec();

        assert!(GroupPendingPublish::diff(&record, &local).unwrap().muted);

        local.muted_until_timestamp = 0;
        assert!(!GroupPendingPublish::diff(&record, &local).unwrap().muted);
    }

    /// And the mirror image: a pending mute survives the pre-mute record,
    /// while a block made on another device still lands.
    #[test]
    fn a_pending_mute_survives_but_takes_a_remote_block() {
        let mut local = stored_contact();
        local.blocked = false;
        local.muted_until_timestamp = i64::MAX as u64;

        let mut incoming = empty_record_contact();
        incoming.blocked = true;
        incoming.muted_until_timestamp = 0;

        let preserved = merge_contact_from_snapshot(
            &mut incoming,
            local,
            PendingPublish {
                blocked: false,
                muted: true,
            },
        );

        assert_eq!(
            incoming.muted_until_timestamp,
            i64::MAX as u64,
            "the pending mute was reverted"
        );
        assert!(incoming.blocked, "the remote block was preserved away");
        assert!(preserved.contains(&"muted_until_timestamp"));
        assert!(!preserved.contains(&"blocked"));
    }

    #[test]
    fn empty_record_does_not_wipe_local_fields() {
        let mut incoming = empty_record_contact();
        let preserved =
            merge_contact_from_snapshot(&mut incoming, stored_contact(), PendingPublish::default());

        assert_eq!(incoming.name, "Local Name");
        assert_eq!(incoming.profile_key, vec![7u8; 32]);
        assert!(incoming.phone_number.is_some());
        assert_eq!(incoming.pni, Some(Uuid::from_u128(1)));
        assert_eq!(incoming.username.as_deref(), Some("local.42"));
        assert_eq!(
            preserved,
            ["name", "profile_key", "phone_number", "pni", "username"]
        );
    }

    #[test]
    fn non_empty_record_still_wins() {
        // The decision not to follow Signal-Desktop's second condition: storage sync is
        // the only channel that delivers a rename, so a record with something to say must
        // overwrite the local value.
        let mut incoming = empty_record_contact();
        incoming.name = "Renamed Remotely".into();
        incoming.profile_key = vec![9u8; 32];
        incoming.username = Some("remote.99".into());

        let preserved =
            merge_contact_from_snapshot(&mut incoming, stored_contact(), PendingPublish::default());

        assert_eq!(incoming.name, "Renamed Remotely");
        assert_eq!(incoming.profile_key, vec![9u8; 32]);
        assert_eq!(incoming.username.as_deref(), Some("remote.99"));
        // Only the fields the record left empty were protected.
        assert_eq!(preserved, ["phone_number", "pni"]);
    }

    #[test]
    fn fields_absent_from_the_record_are_always_restored() {
        let mut incoming = empty_record_contact();
        incoming.name = "Renamed Remotely".into();

        merge_contact_from_snapshot(&mut incoming, stored_contact(), PendingPublish::default());

        assert_eq!(incoming.expire_timer, 3600);
        assert_eq!(incoming.expire_timer_version, 9);
        assert_eq!(incoming.inbox_position, 5);
        assert!(incoming.avatar.is_none());
    }

    #[test]
    fn nothing_is_preserved_when_the_store_is_also_empty() {
        let mut incoming = empty_record_contact();
        let preserved = merge_contact_from_snapshot(
            &mut incoming,
            empty_record_contact(),
            PendingPublish::default(),
        );

        assert!(preserved.is_empty());
        assert!(incoming.name.is_empty());
    }
}
