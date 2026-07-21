//! Traits that are used by the manager for storing the data.

use std::{fmt, future::Future, ops::RangeBounds};

use libsignal_service::{
    content::{ContentBody, Metadata},
    groups_v2::Timer,
    libsignal_account_keys::AccountEntropyPool,
    pre_keys::PreKeysStore,
    prelude::{Content, MasterKey, ProfileKey, Uuid},
    proto::{
        sync_message::{self, Sent},
        verified, DataMessage, EditMessage, GroupContextV2, SyncMessage, Verified,
    },
    protocol::{
        IdentityKey, IdentityKeyPair, ProtocolAddress, ProtocolStore, SenderCertificate,
        SenderKeyStore, ServiceId,
    },
    push_service::DEFAULT_DEVICE_ID,
    session_store::SessionStoreExt,
    zkgroup::GroupMasterKeyBytes,
    BackupKey, Profile,
};
use serde::{Deserialize, Serialize};
use tracing::trace;

use crate::{
    manager::RegistrationData,
    model::{
        calls::{transition_call_history, CallEventInfo, CallHistoryEntry, CallPeer},
        contacts::Contact,
        groups::Group,
    },
    AvatarBytes,
};

/// An error trait implemented by store error types
pub trait StoreError: std::error::Error + Sync + Send {}

/// A resumable checkpoint inside `sync_storage_service`.
///
/// After each batch of records is successfully fetched and persisted, the sync
/// writes one of these to the state store. On the next sync attempt, if the
/// server's current manifest version equals `target_version`, the loop skips
/// the first `next_batch_index` batches.
///
/// If `target_version` doesn't match the server's current version (because the
/// server moved on while we were offline), the cursor is discarded and sync
/// restarts at batch 0.
#[derive(Debug, Clone, Copy)]
pub struct StorageSyncCursor {
    pub target_version: u64,
    pub next_batch_index: u32,
}

/// Stores the registered state of the manager
pub trait StateStore {
    type StateStoreError: StoreError;

    /// Load registered (or linked) state
    fn load_registration_data(
        &self,
    ) -> impl Future<Output = Result<Option<RegistrationData>, Self::StateStoreError>>;

    fn set_aci_identity_key_pair(
        &self,
        key_pair: IdentityKeyPair,
    ) -> impl Future<Output = Result<(), Self::StateStoreError>>;

    fn set_pni_identity_key_pair(
        &self,
        key_pair: IdentityKeyPair,
    ) -> impl Future<Output = Result<(), Self::StateStoreError>>;

    /// Save registered (or linked) state
    fn save_registration_data(
        &mut self,
        state: &RegistrationData,
    ) -> impl Future<Output = Result<(), Self::StateStoreError>> + Send;

    fn sender_certificate(
        &self,
    ) -> impl Future<Output = Result<Option<SenderCertificate>, Self::StateStoreError>>;

    fn save_sender_certificate(
        &self,
        certificate: &SenderCertificate,
    ) -> impl Future<Output = Result<(), Self::StateStoreError>>;

    /// Returns whether this store contains registration data or not
    fn is_registered(&self) -> impl Future<Output = bool>;

    /// Clear registration data (including keys), but keep received messages, groups and contacts.
    fn clear_registration(&mut self) -> impl Future<Output = Result<(), Self::StateStoreError>>;

    fn fetch_master_key(
        &self,
    ) -> impl Future<Output = Result<Option<MasterKey>, Self::StateStoreError>>;

    fn store_master_key(
        &self,
        master_key: Option<&MasterKey>,
    ) -> impl Future<Output = Result<(), Self::StateStoreError>>;

    fn fetch_account_entropy_pool(
        &self,
    ) -> impl Future<Output = Result<Option<AccountEntropyPool>, Self::StateStoreError>>;

    fn store_account_entropy_pool(
        &self,
        aep: Option<&AccountEntropyPool>,
    ) -> impl Future<Output = Result<(), Self::StateStoreError>>;

    fn fetch_storage_manifest_version(
        &self,
    ) -> impl Future<Output = Result<u64, Self::StateStoreError>>;

    fn store_storage_manifest_version(
        &self,
        version: u64,
    ) -> impl Future<Output = Result<(), Self::StateStoreError>>;

    /// Fetch the in-progress storage-service sync cursor, if any.
    ///
    /// Stores that don't implement resume can leave the default no-op
    /// returning `Ok(None)` — the sync will always start from batch 0.
    fn fetch_storage_sync_cursor(
        &self,
    ) -> impl Future<Output = Result<Option<StorageSyncCursor>, Self::StateStoreError>> {
        async { Ok(None) }
    }

    /// Persist the in-progress storage-service sync cursor. Called once
    /// after each batch of records is successfully fetched + applied.
    fn store_storage_sync_cursor(
        &self,
        _cursor: &StorageSyncCursor,
    ) -> impl Future<Output = Result<(), Self::StateStoreError>> {
        async { Ok(()) }
    }

    /// Clear the in-progress cursor. Called when sync completes
    /// successfully, when the saved cursor's target_version is stale,
    /// or when the server reports no change (204).
    fn clear_storage_sync_cursor(&self) -> impl Future<Output = Result<(), Self::StateStoreError>> {
        async { Ok(()) }
    }

    fn fetch_backup_key(
        &self,
    ) -> impl Future<Output = Result<Option<BackupKey>, Self::StateStoreError>>;

    fn store_backup_key(
        &self,
        key: Option<&BackupKey>,
    ) -> impl Future<Output = Result<(), Self::StateStoreError>>;

    fn fetch_transfer_archive(
        &self,
    ) -> impl Future<Output = Result<Option<crate::backup::TransferArchive>, Self::StateStoreError>>
    {
        async { Ok(None) }
    }

    fn store_transfer_archive(
        &self,
        _archive: Option<&crate::backup::TransferArchive>,
    ) -> impl Future<Output = Result<(), Self::StateStoreError>> {
        async { Ok(()) }
    }
}

/// Per-recipient send progress carried by a backup `SendStatus` for an outgoing
/// message. Ordinals follow Signal (Sent < Delivered < Read < Viewed); stores
/// map them to their own representation.
#[derive(Clone, Copy, Debug)]
pub enum BackupSendStatus {
    Sent,
    Delivered,
    Read,
    Viewed,
}

/// Stores messages, contacts, groups and profiles
pub trait ContentsStore: Send + Sync {
    type ContentsStoreError: StoreError;

    /// Iterator over the contacts
    type ContactsIter: Iterator<Item = Result<Contact, Self::ContentsStoreError>>;

    /// Iterator over all stored groups
    ///
    /// Each items is a tuple consisting of the group master key and its corresponding data.
    type GroupsIter: Iterator<Item = Result<(GroupMasterKeyBytes, Group), Self::ContentsStoreError>>;

    /// Iterator over all stored messages
    type MessagesIter: Iterator<Item = Result<Content, Self::ContentsStoreError>>;

    /// Iterator over all stored sticker packs
    type StickerPacksIter: Iterator<Item = Result<StickerPack, Self::ContentsStoreError>>;

    // Clear all profiles
    fn clear_profiles(&mut self) -> impl Future<Output = Result<(), Self::ContentsStoreError>>;

    // Clear all stored messages
    fn clear_contents(&mut self) -> impl Future<Output = Result<(), Self::ContentsStoreError>>;

    // Messages

    /// Clear all stored messages.
    fn clear_messages(&mut self) -> impl Future<Output = Result<(), Self::ContentsStoreError>>;

    /// Clear the messages in a thread.
    fn clear_thread(
        &mut self,
        thread: &Thread,
    ) -> impl Future<Output = Result<(), Self::ContentsStoreError>>;

    /// Save a message in a [Thread] identified by a timestamp.
    fn save_message(
        &self,
        thread: &Thread,
        message: Content,
    ) -> impl Future<Output = Result<(), Self::ContentsStoreError>>;

    /// Delete a single message, identified by its received timestamp from a thread.
    /// Useful when you want to delete a message locally only.
    fn delete_message(
        &mut self,
        thread: &Thread,
        timestamp: u64,
    ) -> impl Future<Output = Result<bool, Self::ContentsStoreError>>;

    /// Retrieve a message from a [Thread] by its timestamp.
    fn message(
        &self,
        thread: &Thread,
        timestamp: u64,
    ) -> impl Future<Output = Result<Option<Content>, Self::ContentsStoreError>>;

    /// Retrieve a message [Thread] from its sender and timestamp.
    fn thread_for_sender_and_timestamp(
        &self,
        sender: &ServiceId,
        timestamp: u64,
    ) -> impl Future<Output = Result<Option<Thread>, Self::ContentsStoreError>>;

    /// Retrieve all messages from a [Thread] within a range in time
    fn messages(
        &self,
        thread: &Thread,
        range: impl RangeBounds<u64>,
    ) -> impl Future<Output = Result<Self::MessagesIter, Self::ContentsStoreError>>;

    /// Persist a canonical call history entry produced by
    /// [`crate::model::calls::transition_call_history`].
    ///
    /// Stores keep the post-merge state separate from the per-event sync rows
    /// written by [`Self::save_message`]. The default impl is a no-op so stores
    /// that don't yet model call history (e.g. presage's in-memory store) can
    /// still compile; persistent stores override it.
    fn save_call_history(
        &self,
        _entry: &CallHistoryEntry,
    ) -> impl Future<Output = Result<(), Self::ContentsStoreError>> + Send {
        async { Ok(()) }
    }

    /// Restore per-message read / delivery state decoded from a linked-device
    /// backup `ChatItem` (the wire `Content` produced by the converter can't
    /// carry it). `read` is `Some` for incoming (was it read on the primary
    /// device), `None` for outgoing. `send_states` is the per-recipient
    /// `(recipient_service_id, status, updated_at_ms)` for outgoing (empty for
    /// incoming). Called once per ChatItem just after `save_message`. Default
    /// no-op so stores that don't model this still compile; persistent stores
    /// override it.
    fn restore_backup_message_state(
        &self,
        _thread: &Thread,
        _ts: u64,
        _read: Option<bool>,
        _send_states: &[(String, BackupSendStatus, u64)],
    ) -> impl Future<Output = Result<(), Self::ContentsStoreError>> + Send {
        async { Ok(()) }
    }

    /// Look up the canonical call history entry for a given `call_id`.
    /// Returns `None` when no entry exists for this id.
    ///
    /// Default impl returns `None` so stores that don't model call history
    /// still compile; persistent stores override it.
    fn get_call_history(
        &self,
        _call_id: u64,
    ) -> impl Future<Output = Result<Option<CallHistoryEntry>, Self::ContentsStoreError>> + Send
    {
        async { Ok(None) }
    }

    /// Merge a freshly-decoded sync `call_event` into the canonical call
    /// history: load any prior entry, run the state machine, save the
    /// result. Returns the merged entry, or `None` when the state machine
    /// rejects the event (currently Adhoc / Unknown mode).
    ///
    /// Default impl chains `get_call_history` → `transition_call_history` →
    /// `save_call_history`, so any store overriding the two underlying
    /// methods gets ingestion for free.
    fn ingest_call_event(
        &self,
        info: &CallEventInfo,
        peer: &CallPeer,
    ) -> impl Future<Output = Result<Option<CallHistoryEntry>, Self::ContentsStoreError>> + Send
    {
        async move {
            let prev = self.get_call_history(info.call_id).await?;
            let Some(entry) = transition_call_history(prev.as_ref(), info, peer.peer_id()) else {
                return Ok(None);
            };
            self.save_call_history(&entry).await?;
            Ok(Some(entry))
        }
    }

    /// Get the expire timer from a [Thread], which corresponds to either [Contact::expire_timer]
    /// or [Group::disappearing_messages_timer].
    fn expire_timer(
        &self,
        thread: &Thread,
    ) -> impl Future<Output = Result<Option<(u32, u32)>, Self::ContentsStoreError>> {
        async move {
            match thread {
                Thread::Contact(service_id) => Ok(self
                    .contact_by_id(service_id)
                    .await?
                    .map(|c| (c.expire_timer, c.expire_timer_version))),
                Thread::Group(key) => Ok(self
                    .group(*key)
                    .await?
                    .and_then(|g| g.disappearing_messages_timer)
                    // TODO: most likely we can have versions here
                    .map(|t| (t.duration, 1))), // Groups do not have expire_timer_version
            }
        }
    }

    /// Update the expire timer from a [Thread], which corresponds to either [Contact::expire_timer]
    /// or [Group::disappearing_messages_timer].
    fn update_expire_timer(
        &mut self,
        thread: &Thread,
        timer: u32,
        version: u32,
    ) -> impl Future<Output = Result<(), Self::ContentsStoreError>> {
        async move {
            trace!(%thread, timer, version, "updating expire timer");
            match thread {
                Thread::Contact(uuid) => {
                    let contact = self.contact_by_id(uuid).await?;
                    if let Some(mut contact) = contact {
                        let current_version = contact.expire_timer_version;
                        if version <= current_version {
                            return Ok(());
                        }
                        contact.expire_timer_version = version;
                        contact.expire_timer = timer;
                        self.save_contact(&contact).await?;
                    }
                    Ok(())
                }
                Thread::Group(key) => {
                    let group = self.group(*key).await?;
                    if let Some(mut g) = group {
                        // Convert timer=0 to None for groups (disable disappearing messages)
                        g.disappearing_messages_timer = if timer == 0 {
                            None
                        } else {
                            Some(Timer { duration: timer })
                        };
                        self.save_group(*key, g).await?;
                    }
                    Ok(())
                }
            }
        }
    }

    // Contacts

    /// Clear all saved synchronized contact data
    fn clear_contacts(&mut self) -> impl Future<Output = Result<(), Self::ContentsStoreError>>;

    /// Save a contact
    fn save_contact(
        &mut self,
        contacts: &Contact,
    ) -> impl Future<Output = Result<(), Self::ContentsStoreError>> + Send;

    /// Get an iterator on all stored (synchronized) contacts
    fn contacts(
        &self,
    ) -> impl Future<Output = Result<Self::ContactsIter, Self::ContentsStoreError>>;

    /// Get contact data for a single user by its [ServiceId].
    fn contact_by_id(
        &self,
        id: &ServiceId,
    ) -> impl Future<Output = Result<Option<Contact>, Self::ContentsStoreError>> + Send;

    /// Delete all cached group data
    fn clear_groups(&mut self) -> impl Future<Output = Result<(), Self::ContentsStoreError>>;

    /// Save a group in the cache
    fn save_group(
        &self,
        master_key: GroupMasterKeyBytes,
        group: impl Into<Group>,
    ) -> impl Future<Output = Result<(), Self::ContentsStoreError>>;

    /// Get an iterator on all cached groups
    fn groups(&self) -> impl Future<Output = Result<Self::GroupsIter, Self::ContentsStoreError>>;

    /// Retrieve a single unencrypted group indexed by its `[GroupMasterKeyBytes]`
    fn group(
        &self,
        master_key: GroupMasterKeyBytes,
    ) -> impl Future<Output = Result<Option<Group>, Self::ContentsStoreError>>;

    /// Look up a stored group by its derived 32-byte `group_id` (the public
    /// protocol identifier carried in sync `call_event` payloads). Returns
    /// the matching `master_key` when the group is known.
    ///
    /// Default impl iterates `groups()` and derives each row's `group_id`
    /// via `GroupSecretParams::get_group_identifier()` — O(N) per lookup
    /// with one zkgroup derivation per row. Persistent stores should
    /// override with an indexed lookup (O(log N), no crypto).
    fn group_by_group_id(
        &self,
        group_id: &[u8; 32],
    ) -> impl Future<Output = Result<Option<GroupMasterKeyBytes>, Self::ContentsStoreError>> {
        async move {
            use libsignal_service::zkgroup::groups::{GroupMasterKey, GroupSecretParams};
            let iter = self.groups().await?;
            for result in iter {
                let (master_key, _group) = result?;
                let secret_params =
                    GroupSecretParams::derive_from_master_key(GroupMasterKey::new(master_key));
                if &secret_params.get_group_identifier() == group_id {
                    return Ok(Some(master_key));
                }
            }
            Ok(None)
        }
    }

    /// Save a group avatar in the cache
    fn save_group_avatar(
        &self,
        master_key: GroupMasterKeyBytes,
        avatar: &AvatarBytes,
    ) -> impl Future<Output = Result<(), Self::ContentsStoreError>>;

    /// Retrieve a group avatar from the cache.
    fn group_avatar(
        &self,
        master_key: GroupMasterKeyBytes,
    ) -> impl Future<Output = Result<Option<AvatarBytes>, Self::ContentsStoreError>>;

    // Profiles

    /// Insert or update the profile key of a contact
    fn upsert_profile_key(
        &mut self,
        uuid: &Uuid,
        key: ProfileKey,
    ) -> impl Future<Output = Result<bool, Self::ContentsStoreError>> + Send;

    /// Get the profile key for a contact
    fn profile_key(
        &self,
        service_id: &ServiceId,
    ) -> impl Future<Output = Result<Option<ProfileKey>, Self::ContentsStoreError>> + Send;

    /// Save a profile by [Uuid] and [ProfileKey].
    fn save_profile(
        &mut self,
        uuid: Uuid,
        key: ProfileKey,
        profile: Profile,
    ) -> impl Future<Output = Result<(), Self::ContentsStoreError>>;

    /// Retrieve a profile by [Uuid] and [ProfileKey].
    fn profile(
        &self,
        uuid: Uuid,
        key: ProfileKey,
    ) -> impl Future<Output = Result<Option<Profile>, Self::ContentsStoreError>>;

    /// Save a profile avatar by [Uuid] and [ProfileKey], storing the server URL alongside the bytes.
    fn save_profile_avatar(
        &mut self,
        uuid: Uuid,
        key: ProfileKey,
        profile: &AvatarBytes,
        url: Option<&str>,
    ) -> impl Future<Output = Result<(), Self::ContentsStoreError>>;

    /// Retrieve a profile avatar by [Uuid] and [ProfileKey].
    /// Returns `(url, bytes)` where `url` is the server-side avatar path stored at last download.
    fn profile_avatar(
        &self,
        uuid: Uuid,
        key: ProfileKey,
    ) -> impl Future<Output = Result<Option<(Option<String>, AvatarBytes)>, Self::ContentsStoreError>>;

    // Stickers

    /// Add a sticker pack
    fn add_sticker_pack(
        &mut self,
        pack: &StickerPack,
    ) -> impl Future<Output = Result<(), Self::ContentsStoreError>> + Send;

    /// Gets a cached sticker pack
    fn sticker_pack(
        &self,
        id: &[u8],
    ) -> impl Future<Output = Result<Option<StickerPack>, Self::ContentsStoreError>>;

    /// Removes a sticker pack
    fn remove_sticker_pack(
        &mut self,
        id: &[u8],
    ) -> impl Future<Output = Result<bool, Self::ContentsStoreError>>;

    /// Get an iterator on all installed stickerpacks
    fn sticker_packs(
        &self,
    ) -> impl Future<Output = Result<Self::StickerPacksIter, Self::ContentsStoreError>>;
}

/// The manager store trait combining all other stores into a single one
pub trait Store:
    StateStore<StateStoreError = Self::Error>
    + ContentsStore<ContentsStoreError = Self::Error>
    + Send
    + Sync
    + Clone
    + 'static
{
    type Error: StoreError;
    type AciStore: ProtocolStore
        + PreKeysStore
        + SenderKeyStore
        + SessionStoreExt
        + Send
        + Sync
        + Clone;
    type PniStore: ProtocolStore
        + PreKeysStore
        + SenderKeyStore
        + SessionStoreExt
        + Send
        + Sync
        + Clone;

    /// Clear the entire store
    ///
    /// This can be useful when resetting an existing client.
    fn clear(
        &mut self,
    ) -> impl Future<Output = Result<(), <Self as StateStore>::StateStoreError>> + Send;

    fn aci_protocol_store(&self) -> Self::AciStore;

    fn pni_protocol_store(&self) -> Self::PniStore;
}

/// A thread specifies where a message was sent, either to or from a contact or in a group.
#[derive(Debug, Hash, Eq, PartialEq, Clone)]
pub enum Thread {
    /// The message was sent inside a contact-chat.
    Contact(ServiceId),
    // Cannot use GroupMasterKey as unable to extract the bytes.
    /// The message was sent inside a groups-chat with the [`GroupMasterKeyBytes`] (specified as bytes).
    Group(GroupMasterKeyBytes),
}

impl fmt::Display for Thread {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Thread::Contact(service_id) => {
                write!(f, "Thread(contact={})", service_id.service_id_string())
            }
            Thread::Group(master_key_bytes) => {
                write!(f, "Thread(group={:x?})", &master_key_bytes[..4])
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ThreadError {
    #[error("invalid service ID")]
    InvalidServiceId,
}

impl TryFrom<&Content> for Thread {
    type Error = ThreadError;

    fn try_from(content: &Content) -> Result<Self, Self::Error> {
        match &content.body {
            // [1-1] Message sent by us with another device (with string service ID)
            ContentBody::SynchronizeMessage(SyncMessage {
                sent:
                    Some(sent @ Sent {
                        destination_service_id: Some(_),
                        ..
                    }),
                ..
            }) | ContentBody::SynchronizeMessage(SyncMessage {
                sent:
                    Some(sent @ Sent {
                        destination_service_id_binary: Some(_),
                        ..
                    }),
                ..
            })=> {
                let parsed_service_id = sent.parse_destination_service_id().ok_or(ThreadError::InvalidServiceId)?;
                Ok(Self::Contact(parsed_service_id))
            },
            // [Group] message from somebody else
            ContentBody::DataMessage(DataMessage {
                group_v2:
                    Some(GroupContextV2 {
                        master_key: Some(key),
                        ..
                    }),
                ..
            })
            // [Group] message sent by us with another device
            | ContentBody::SynchronizeMessage(SyncMessage {
                sent:
                    Some(Sent {
                        message:
                            Some(DataMessage {
                                group_v2:
                                    Some(GroupContextV2 {
                                        master_key: Some(key),
                                        ..
                                    }),
                                ..
                            }),
                        ..
                    }),
                ..
            })
            // [Group] message edit sent by us with another device
            | ContentBody::SynchronizeMessage(SyncMessage {
                sent:
                    Some(Sent {
                        edit_message:
                            Some(EditMessage {
                                data_message:
                                    Some(DataMessage {
                                        group_v2:
                                            Some(GroupContextV2 {
                                                master_key: Some(key),
                                                ..
                                            }),
                                        ..
                                    }),
                                ..
                            }),
                        ..
                    }),
                ..
            })
            // [Group] Message edit sent by somebody else
            | ContentBody::EditMessage(EditMessage {
                data_message:
                    Some(DataMessage {
                        group_v2:
                            Some(GroupContextV2 {
                                master_key: Some(key),
                                ..
                            }),
                        ..
                    }),
                ..
            }) => Ok(Self::Group(
                key.clone()
                    .try_into()
                    .expect("Group master key to have 32 bytes"),
            )),
            // [1-1] Any other message directly to us.
            // Sync `call_event` content is routed via the async
            // `resolve_call_thread` resolver (see `save_message`) — it
            // handles both 1:1 (UUID conversation_id) and group
            // (derived group_id → master_key lookup).
            _ => Ok(Thread::Contact(content.metadata.sender)),
        }
    }
}

/// Extension trait of [`Content`]
pub trait ContentExt {
    fn timestamp(&self) -> u64;
}

impl ContentExt for Content {
    /// The original timestamp of the message.
    fn timestamp(&self) -> u64 {
        match self.body {
            ContentBody::SynchronizeMessage(SyncMessage {
                sent:
                    Some(sync_message::Sent {
                        timestamp: Some(ts),
                        ..
                    }),
                ..
            }) => ts,
            ContentBody::SynchronizeMessage(SyncMessage {
                sent:
                    Some(sync_message::Sent {
                        edit_message:
                            Some(EditMessage {
                                target_sent_timestamp: Some(ts),
                                ..
                            }),
                        ..
                    }),
                ..
            }) => ts,
            ContentBody::EditMessage(EditMessage {
                target_sent_timestamp: Some(ts),
                ..
            }) => ts,
            _ => self.metadata.timestamp.timestamp_millis() as u64,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StickerPack {
    pub id: Vec<u8>,
    pub key: Vec<u8>,
    pub manifest: StickerPackManifest,
}

/// equivalent to [Pack](crate::proto::Pack)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StickerPackManifest {
    pub title: String,
    pub author: String,
    pub cover: Option<Sticker>,
    pub stickers: Vec<Sticker>,
}

impl From<libsignal_service::proto::Pack> for StickerPackManifest {
    fn from(value: libsignal_service::proto::Pack) -> Self {
        Self {
            title: value.title().to_owned(),
            author: value.author().to_owned(),
            cover: value.cover.map(Into::into),
            stickers: value.stickers.into_iter().map(|s| s.into()).collect(),
        }
    }
}

/// equivalent to [Sticker](crate::proto::pack::Sticker)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sticker {
    pub id: u32,
    pub emoji: Option<String>,
    pub content_type: Option<String>,
    pub bytes: Option<Vec<u8>>,
}

impl From<libsignal_service::proto::pack::Sticker> for Sticker {
    fn from(value: libsignal_service::proto::pack::Sticker) -> Self {
        Self {
            id: value.id(),
            emoji: value.emoji,
            content_type: value.content_type,
            bytes: None,
        }
    }
}

/// Saves a message that can show users when the identity of a contact has changed
/// On Signal Android, this is usually displayed as: "Your safety number with XYZ has changed."
pub async fn save_trusted_identity_message<S: Store>(
    store: &S,
    protocol_address: &ProtocolAddress,
    right_identity_key: IdentityKey,
    verified_state: verified::State,
) -> Result<(), S::Error> {
    let Some(sender) = ServiceId::parse_from_service_id_string(protocol_address.name()) else {
        return Ok(());
    };

    // TODO: this is a hack to save a message showing that the verification status changed
    // It is possibly ok to do it like this, but rebuidling the metadata and content body feels dirty
    let thread = Thread::Contact(sender);
    let verified_sync_message = Content {
        metadata: Metadata {
            sender,
            destination: sender,
            sender_device: *DEFAULT_DEVICE_ID,
            server_guid: None,
            timestamp: chrono::Utc::now(),
            // No messages were sent, just use the current time as the server timestamp.
            server_timestamp: chrono::Utc::now(),
            needs_receipt: false,
            unidentified_sender: false,
            was_plaintext: false,
            report_spam_token: None,
        },
        body: SyncMessage {
            verified: Some(Verified {
                destination_aci: None,
                destination_aci_binary: None,
                identity_key: Some(right_identity_key.public_key().serialize().to_vec()),
                state: Some(verified_state.into()),
                null_message: None,
            }),
            ..Default::default()
        }
        .into(),
    };

    store.save_message(&thread, verified_sync_message).await
}
