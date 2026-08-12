use std::collections::HashMap;
use std::fmt;
use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::TimeZone;
use futures::{future, AsyncReadExt, Stream, StreamExt};
use libsignal_service::proto::addressable_message::Author;
use libsignal_service::protocol::ProtocolAddress;
use libsignal_service::session_lock::SessionLocks;
use libsignal_service::{
    attachment_cipher::decrypt_in_place,
    backup::{FileReaderFactory, FramesReader, MessageBackupKey, VarintDelimitedReader},
    cipher,
    configuration::{ServiceConfiguration, SignalServers},
    content::{Content, ContentBody, DataMessageFlags, Metadata},
    encrypt_device_name,
    groups_v2::{
        decrypt_group, AccessControl, AccessRequired, GroupMemberCandidate, GroupOperations,
        GroupsManager, InMemoryCredentialsCache, Timer,
    },
    libsignal_account_keys::AccountEntropyPool,
    master_key::StorageServiceKey,
    messagepipe::{Incoming, MessagePipe, ServiceCredentials},
    prelude::{phonenumber::PhoneNumber, MasterKey, MessageSenderError, ProtobufMessage, Uuid},
    profile_cipher::ProfileCipher,
    proto::{
        data_message::Delete,
        manifest_record, storage_record,
        sync_message::{self, sticker_pack_operation, StickerPackOperation},
        AttachmentPointer, DataMessage, EditMessage, GroupContextV2, GroupV2Record, ManifestRecord,
        StorageRecord, SyncMessage, Verified,
    },
    protocol::{
        Aci, DeviceId, IdentityKeyStore, SenderCertificate, ServiceId, ServiceIdKind, Username,
    },
    provisioning::{ProvisioningError, ProvisioningSecrets},
    push_service::linking::{TransferArchiveError, TransferArchiveResult},
    push_service::{PushService, ServiceIds, DEFAULT_DEVICE_ID},
    sender::{AttachmentSpec, AttachmentUploadError},
    sticker_cipher::derive_key,
    unidentified_access::UnidentifiedAccess,
    utils::TryIntoE164,
    websocket::{
        self,
        account::{AccountAttributes, DeviceCapabilities, DeviceInfo, WhoAmIResponse},
        SignalWebSocket,
    },
    zkgroup::{
        groups::{GroupMasterKey, GroupSecretParams},
        profiles::{ExpiringProfileKeyCredential, ProfileKey},
        GroupMasterKeyBytes, ServerPublicParams,
    },
    AccountManager, Profile, ProfileCredentialRequest, ServiceIdExt, StorageService,
};
use rand::{rng, rngs::StdRng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tracing::{debug, error, info, trace, warn};
use url::Url;

use crate::backup::{
    convert::{self, RecipientInfo},
    BackupImportProgress, Frame, FrameItem, TransferArchive,
};
use crate::model::calls::{extract_call_event, CallPeer};
use crate::model::contacts::Contact;
use crate::serde::serde_profile_key;
use crate::store::{
    ContactStorageIdentity, ContentsStore, Sticker, StickerPack, StickerPackManifest,
    StorageSyncCursor, Store, Thread,
};
use crate::{model::groups::Group, AvatarBytes, Error, Manager};

pub use crate::model::messages::Received;

type ServiceCipher<S> = cipher::ServiceCipher<S>;
type MessageSender<S> = libsignal_service::prelude::MessageSender<S>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegistrationType {
    Primary,
    Secondary,
}

/// Manager state when the client is registered and can send and receive messages from Signal
pub struct Registered {
    pub(crate) identified_push_service: OnceLock<PushService>,
    pub(crate) unidentified_push_service: OnceLock<PushService>,
    pub(crate) identified_websocket: Arc<Mutex<Option<SignalWebSocket<websocket::Identified>>>>,
    pub(crate) unidentified_websocket: Arc<Mutex<Option<SignalWebSocket<websocket::Unidentified>>>>,
    pub(crate) unidentified_sender_certificate: Arc<Mutex<Option<SenderCertificate>>>,
    /// Shared by every cipher and sender this manager builds — and, since
    /// `Manager` clones share `state`, by every clone of it. That sharing is
    /// what keeps a send and a concurrent decrypt off the same session.
    ///
    /// One map covers both the ACI and PNI stores. Their session records are
    /// distinct, so this is marginally stricter than needed, but PNI sessions
    /// are rare and the alternative is two maps to keep in step.
    pub(crate) session_locks: SessionLocks,

    pub(crate) data: RegistrationData,
}

impl fmt::Debug for Registered {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Registered").finish_non_exhaustive()
    }
}

impl Registered {
    pub(crate) fn with_data(data: RegistrationData) -> Self {
        Self {
            identified_push_service: Default::default(),
            unidentified_push_service: Default::default(),
            identified_websocket: Default::default(),
            unidentified_websocket: Default::default(),
            unidentified_sender_certificate: Default::default(),
            session_locks: Default::default(),
            data,
        }
    }

    fn servers(&self) -> SignalServers {
        self.data.signal_servers
    }

    fn service_configuration(&self) -> ServiceConfiguration {
        self.servers().into()
    }

    pub fn device_id(&self) -> DeviceId {
        self.data
            .device_id
            .and_then(|d| d.try_into().ok())
            .unwrap_or(*DEFAULT_DEVICE_ID)
    }

    pub(crate) fn identified_push_service(&self) -> PushService {
        self.identified_push_service
            .get_or_init(|| {
                PushService::new(self.servers(), Some(self.credentials()), crate::USER_AGENT)
            })
            .clone()
    }

    pub(crate) fn credentials(&self) -> ServiceCredentials {
        ServiceCredentials {
            aci: Some(self.data.service_ids.aci),
            pni: Some(self.data.service_ids.pni),
            phonenumber: (&self.data.phone_number)
                .try_into_e164()
                .expect("valid phone number"),
            password: Some(self.data.password.clone()),
            device_id: self.data.device_id.and_then(|d| d.try_into().ok()),
        }
    }
}

/// Registration data like device name, and credentials to connect to Signal
#[derive(Serialize, Deserialize, Clone)]
pub struct RegistrationData {
    pub signal_servers: SignalServers,
    pub device_name: Option<String>,
    pub phone_number: PhoneNumber,
    #[serde(flatten)]
    pub service_ids: ServiceIds,
    pub(crate) password: String,
    pub device_id: Option<u32>,
    pub registration_id: u32,
    #[serde(default)]
    pub pni_registration_id: Option<u32>,
    #[serde(with = "serde_profile_key")]
    pub(crate) profile_key: ProfileKey,
}

impl RegistrationData {
    /// Our own profile key
    pub fn profile_key(&self) -> ProfileKey {
        self.profile_key
    }

    /// The name of the device (if linked as secondary)
    pub fn device_name(&self) -> Option<&str> {
        self.device_name.as_deref()
    }
}

impl<S: Store> Manager<S, Registered> {
    /// Loads a previously registered account from the implemented [Store].
    ///
    /// Returns a instance of [Manager] you can use to send & receive messages.
    pub async fn load_registered(store: S) -> Result<Self, Error<S::Error>> {
        let registration_data = store
            .load_registration_data()
            .await?
            .ok_or(Error::NotYetRegisteredError)?;

        let registered = Registered::with_data(registration_data);

        if let Some(sender_certificate) = store.sender_certificate().await? {
            registered
                .unidentified_sender_certificate
                .lock()
                .await
                .replace(sender_certificate);
        }

        Ok(Self {
            store,
            state: Arc::new(registered),
        })
    }

    /// Returns a handle to the [Store] implementation.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Returns a handle on the [RegistrationData].
    pub fn registration_data(&self) -> &RegistrationData {
        &self.state.data
    }

    /// Returns a clone of a cached push service (with credentials).
    ///
    /// If no service is yet cached, it will create and cache one.
    fn identified_push_service(&self) -> PushService {
        self.state.identified_push_service()
    }

    /// Returns a clone of a cached push service (without credentials).
    ///
    /// If no service is yet cached, it will create and cache one.
    fn unidentified_push_service(&self) -> PushService {
        self.state
            .unidentified_push_service
            .get_or_init(|| PushService::new(self.state.servers(), None, crate::USER_AGENT))
            .clone()
    }

    /// Returns the current identified websocket, or creates a new one
    ///
    /// A new one is created if the current websocket is closed, or if there is none yet.
    async fn identified_websocket(
        &self,
        require_unused: bool,
    ) -> Result<SignalWebSocket<websocket::Identified>, Error<S::Error>> {
        let mut identified_ws = self.state.identified_websocket.lock().await;
        match identified_ws
            .as_ref()
            .filter(|ws| !ws.is_closed())
            .filter(|ws| !(require_unused && ws.is_used()))
        {
            Some(ws) => Ok(ws.clone()),
            None => {
                let headers = &[("X-Signal-Receive-Stories", "false")];
                let ws = self
                    .identified_push_service()
                    .ws(
                        "/v1/websocket/",
                        "/v1/keepalive",
                        headers,
                        Some(self.credentials()),
                    )
                    .await?;
                identified_ws.replace(ws.clone());
                debug!("initialized identified websocket");

                Ok(ws)
            }
        }
    }

    /// Returns the current unidentified websocket, or creates a new one
    ///
    /// A new one is created if the current websocket is closed, or if there is none yet.
    async fn unidentified_websocket(
        &self,
    ) -> Result<SignalWebSocket<websocket::Unidentified>, Error<S::Error>> {
        let mut unidentified_ws = self.state.unidentified_websocket.lock().await;
        match unidentified_ws.as_ref().filter(|ws| !ws.is_closed()) {
            Some(ws) => Ok(ws.clone()),
            None => {
                let ws = self
                    .unidentified_push_service()
                    .ws("/v1/websocket/", "/v1/keepalive", &[], None)
                    .await?;
                unidentified_ws.replace(ws.clone());
                debug!("initialized unidentified websocket");

                Ok(ws)
            }
        }
    }

    /// Request the primary device to encrypt & send all of its contacts.
    ///
    /// **Note**: If successful, the contacts are not yet received and stored, but will only be
    /// processed when they're received after polling on the
    pub async fn request_contacts(&mut self) -> Result<(), Error<S::Error>> {
        trace!("requesting contacts sync");
        let sync_message = SyncMessage {
            request: Some(sync_message::Request {
                r#type: Some(sync_message::request::Type::Contacts.into()),
            }),
            ..SyncMessage::with_padding(&mut rand::rng())
        };

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as u64;

        self.send_message(self.state.data.service_ids.aci(), sync_message, timestamp)
            .await?;

        Ok(())
    }

    async fn sender_certificate(&self) -> Result<SenderCertificate, Error<S::Error>> {
        let needs_renewal = |sender_certificate: Option<&SenderCertificate>| -> bool {
            if sender_certificate.is_none() {
                return true;
            }

            let seconds_since_epoch = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs();

            if let Some(expiration) = sender_certificate.and_then(|s| s.expiration().ok()) {
                expiration.epoch_millis() / 1000 <= seconds_since_epoch + 600
            } else {
                true
            }
        };

        let mut unidentified_sender_certificate =
            self.state.unidentified_sender_certificate.lock().await;
        if needs_renewal(unidentified_sender_certificate.as_ref()) {
            let sender_certificate = self
                .identified_websocket(false)
                .await?
                .get_uuid_only_sender_certificate()
                .await?;
            self.store
                .save_sender_certificate(&sender_certificate)
                .await?;
            unidentified_sender_certificate.replace(sender_certificate);
        }

        Ok(unidentified_sender_certificate
            .clone()
            .expect("logic error"))
    }

    async fn master_key(&self) -> Result<Option<MasterKey>, Error<S::Error>> {
        let from_store = self.store().fetch_master_key().await?;

        if let Some(key) = from_store {
            Ok(Some(key))
        } else {
            let aep = self.account_entropy_pool().await?;
            Ok(aep.map(|aep| {
                MasterKey::from_slice(aep.derive_svr_key().as_slice())
                    .expect("Derived SVR key from account entropy pool to be a valid master key")
            }))
        }
    }

    async fn account_entropy_pool(&self) -> Result<Option<AccountEntropyPool>, Error<S::Error>> {
        let from_store = self.store().fetch_account_entropy_pool().await?;

        if let Some(key) = from_store {
            Ok(Some(key))
        } else if self.registration_type() == RegistrationType::Primary {
            let key = AccountEntropyPool::generate(&mut rand::rng());
            self.store().store_account_entropy_pool(Some(&key)).await?;
            Ok(Some(key))
        } else {
            Ok(None)
        }
    }

    pub async fn submit_recaptcha_challenge(
        &self,
        token: &str,
        captcha: &str,
    ) -> Result<(), Error<S::Error>> {
        let mut account_manager = AccountManager::new(
            self.identified_push_service(),
            self.identified_websocket(false).await?,
            None,
        );
        account_manager
            .submit_recaptcha_challenge(token, captcha)
            .await?;
        Ok(())
    }

    /// Fetches basic information on the registered device.
    pub async fn whoami(&self) -> Result<WhoAmIResponse, Error<S::Error>> {
        Ok(self.identified_websocket(false).await?.whoami().await?)
    }

    pub fn device_id(&self) -> DeviceId {
        self.state.device_id()
    }

    /// Fetches the profile (name, about, status emoji) of the registered user.
    pub async fn retrieve_profile(&mut self) -> Result<Profile, Error<S::Error>> {
        self.retrieve_profile_by_uuid(self.state.data.service_ids.aci, self.state.data.profile_key)
            .await
    }

    /// Fetches the profile of the provided user by UUID and profile key.
    pub async fn retrieve_profile_by_uuid(
        &mut self,
        aci: impl Into<Aci>,
        profile_key: ProfileKey,
    ) -> Result<Profile, Error<S::Error>> {
        let aci = aci.into();

        let mut account_manager = AccountManager::new(
            self.identified_push_service(),
            self.identified_websocket(false).await?,
            Some(profile_key),
        );

        let profile = account_manager.retrieve_profile(aci).await?;

        let _ = self
            .store
            .save_profile(aci.into(), profile_key, profile.clone())
            .await;
        Ok(profile)
    }

    /// Fetch our own expiring profile key credential.
    ///
    /// Required — and non-optional — to create a group: the creator is always a full
    /// member, so a failure here is fatal rather than a downgrade to a pending invite.
    ///
    /// Uses the authenticated socket, as Signal-Desktop does for self.
    pub async fn own_profile_key_credential(
        &mut self,
    ) -> Result<ExpiringProfileKeyCredential, Error<S::Error>> {
        let aci = self.state.data.service_ids.aci();
        let profile_key = self.state.data.profile_key;
        let server_public_params = self
            .state
            .service_configuration()
            .zkgroup_server_public_params;

        // See the note in `upsert_group`: a `ThreadRng` temporary living across the
        // await below would make this future `!Send` for no reason.
        let mut csprng = StdRng::from_os_rng();
        let request =
            ProfileCredentialRequest::new(&mut csprng, &server_public_params, aci, profile_key);

        let response = self
            .identified_websocket(false)
            .await?
            .retrieve_own_profile_key_credential(&request)
            .await?;

        Ok(request.receive(&response, SystemTime::now())?)
    }

    /// Resolve group member candidates for the given service IDs.
    ///
    /// Returns exactly what `GroupOperations::encrypt_group_with_credentials` consumes:
    /// a candidate carrying a credential joins as a full member, one without joins as a
    /// pending invite. Three things collapse to `credential: None`, all of them normal —
    /// no profile key on file, a PNI-only contact (credentials are ACI-only), or a failed
    /// fetch. None of them is fatal, mirroring Signal-Desktop, which downgrades the member
    /// rather than failing the whole group.
    pub async fn group_member_candidates(
        &mut self,
        members: &[ServiceId],
    ) -> Result<Vec<GroupMemberCandidate>, Error<S::Error>> {
        let server_public_params = self
            .state
            .service_configuration()
            .zkgroup_server_public_params;

        let mut candidates = Vec::with_capacity(members.len());
        for service_id in members {
            let credential = self
                .member_profile_key_credential(*service_id, &server_public_params)
                .await;
            candidates.push(GroupMemberCandidate {
                service_id: *service_id,
                credential,
            });
        }
        Ok(candidates)
    }

    /// Create a group, returning its master key.
    ///
    /// The master key is generated locally — the group id derives from it, so the server
    /// assigns nothing and only validates the member presentations. Members whose profile
    /// key credential could not be obtained join as pending invites rather than failing the
    /// creation, matching Signal-Desktop.
    ///
    /// Unlike Desktop, the disappearing-messages timer goes into the create proto rather
    /// than a follow-up group change, so creation stays a single operation.
    pub async fn create_group(
        &mut self,
        title: &str,
        description: Option<&str>,
        expire_timer: Option<Timer>,
        members: &[ServiceId],
    ) -> Result<GroupMasterKeyBytes, Error<S::Error>> {
        // See `upsert_group`: a `ThreadRng` temporary across the awaits below would make
        // this future `!Send` for no reason.
        let mut csprng = StdRng::from_os_rng();
        let mut master_key_bytes: GroupMasterKeyBytes = [0u8; 32];
        csprng.fill_bytes(&mut master_key_bytes);
        let group_secret_params =
            GroupSecretParams::derive_from_master_key(GroupMasterKey::new(master_key_bytes));

        let self_credential = self.own_profile_key_credential().await?;
        let candidates = self.group_member_candidates(members).await?;

        // Signal-Desktop's create-time defaults. `add_from_invite_link` is deliberately
        // unsatisfiable: a new group has no invite link until one is explicitly created.
        let access_control = AccessControl {
            attributes: AccessRequired::Member,
            members: AccessRequired::Member,
            add_from_invite_link: AccessRequired::Unsatisfiable,
            member_label: AccessRequired::Member,
        };

        let server_public_params = self
            .state
            .service_configuration()
            .zkgroup_server_public_params;

        let encrypted_group = GroupOperations::new(group_secret_params)
            .encrypt_group_with_credentials(
                title,
                description,
                expire_timer.as_ref(),
                Some(&access_control),
                &self_credential,
                &candidates,
                &server_public_params,
                // Avatars are not supported yet: there is no group-avatar upload endpoint.
                String::new(),
                &mut csprng,
            )?;

        let mut groups_manager = Box::pin(self.groups_manager()).await?;
        groups_manager
            .create_group(&mut csprng, &master_key_bytes, encrypted_group)
            .await?;

        // Read back rather than trusting the write's response body, whose shape differs
        // between endpoint versions. This also makes the local copy canonically the
        // server's, revision included.
        let group = decrypt_group(
            &master_key_bytes,
            groups_manager
                .fetch_encrypted_group(&mut csprng, &master_key_bytes)
                .await?,
        )?;
        self.store.save_group(master_key_bytes, group).await?;

        // Our own linked devices learn about the group from the storage manifest, not from
        // the fan-out below, which excludes self. Non-fatal for the same reason as the
        // fan-out: the group already exists, and surfacing an error here would invite a
        // retry that creates a second one.
        let storage_record = StorageRecord {
            record: Some(storage_record::Record::GroupV2(GroupV2Record {
                master_key: master_key_bytes.to_vec(),
                // Desktop sets `profileSharing: true` at create, which is this field.
                whitelisted: true,
                ..Default::default()
            })),
        };
        if let Err(e) = self
            .append_storage_record(manifest_record::identifier::Type::Groupv2, storage_record)
            .await
        {
            warn!(%e, "group created but adding it to the storage manifest failed");
        }

        // The members are NOT notified here. The server tells nobody about a new group;
        // the creator has to announce it with an otherwise-empty message carrying only the
        // group context, exactly as Signal-Desktop's `sendGroupUpdate` does.
        //
        // That announcement is a plain message send, so it belongs on the caller's durable
        // send queue rather than inline here: Desktop enqueues its `GroupUpdate` on the
        // DB-backed `conversationJobQueue` and retries it for a day, while keeping the
        // `PUT` itself inline. Doing it inline meant a failure could only be logged — the
        // group already exists, so returning an error would invite a retry that creates a
        // second one — which silently cost the members their invite.
        //
        // Callers must send a `DataMessage` whose only payload is `group_v2` at revision 0
        // to this group. `Manager::send_message_to_group` saves it locally as it sends, so
        // that is also what gives the creator its own "created the group" row.
        Ok(master_key_bytes)
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
    async fn append_storage_record(
        &mut self,
        item_type: manifest_record::identifier::Type,
        record: StorageRecord,
    ) -> Result<(), Error<S::Error>> {
        /// The phone writes to this manifest too, so a conflict is routine rather than
        /// exceptional; retry a few times before giving up.
        const MAX_ATTEMPTS: usize = 3;

        let master_key = self
            .master_key()
            .await?
            .ok_or_else(|| Error::MissingKeyError("master_key".into()))?;
        let storage_service = StorageService::new(
            self.identified_push_service(),
            StorageServiceKey::from_master_key(&master_key),
        )
        .await?;

        for attempt in 1..=MAX_ATTEMPTS {
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
                .write_items(new_manifest, vec![(raw_id, record.clone())], Vec::new())
                .await
            {
                Ok(()) => {
                    self.store.store_storage_manifest_version(version).await?;
                    debug!(version, "storage manifest: appended record");

                    // Tell the other devices to sync — the same FetchLatest that appv2
                    // listens for. Best-effort: the record is already written.
                    if let Err(e) = self
                        .new_message_sender()
                        .await?
                        .send_sync_message(SyncMessage {
                            fetch_latest: Some(sync_message::FetchLatest {
                                r#type: Some(
                                    sync_message::fetch_latest::Type::StorageManifest.into(),
                                ),
                            }),
                            ..SyncMessage::with_padding(&mut rand::rng())
                        })
                        .await
                    {
                        warn!(%e, "storage manifest written but notifying other devices failed");
                    }
                    return Ok(());
                }
                // A conflict means another device wrote in between; the next iteration
                // re-reads the manifest and rebuilds on top of it.
                Err(libsignal_service::StorageServiceError::Conflict) => {
                    debug!(
                        attempt,
                        our_version = version,
                        "storage manifest: version conflict, retrying"
                    );
                }
                Err(e) => return Err(e.into()),
            }
        }

        Err(Error::StorageManifestConflict)
    }

    /// One member's credential, or `None` with a reason logged. Never fails the caller.
    async fn member_profile_key_credential(
        &mut self,
        service_id: ServiceId,
        server_public_params: &ServerPublicParams,
    ) -> Option<ExpiringProfileKeyCredential> {
        // Credentials are ACI-only, so a PNI-only contact can only ever be invited.
        let Some(aci) = service_id.aci() else {
            debug!(service_id = %service_id.service_id_string(), "no credential: PNI-only contact");
            return None;
        };
        let profile_key = match self.store.profile_key(&service_id).await {
            Ok(Some(key)) => key,
            Ok(None) => {
                debug!(service_id = %service_id.service_id_string(), "no credential: no profile key on file");
                return None;
            }
            Err(e) => {
                warn!(service_id = %service_id.service_id_string(), %e, "no credential: profile key lookup failed");
                return None;
            }
        };

        let mut csprng = StdRng::from_os_rng();
        let request =
            ProfileCredentialRequest::new(&mut csprng, server_public_params, aci, profile_key);

        let mut websocket = match self.unidentified_websocket().await {
            Ok(ws) => ws,
            Err(e) => {
                warn!(service_id = %service_id.service_id_string(), %e, "no credential: unidentified websocket unavailable");
                return None;
            }
        };
        let response = match websocket.retrieve_profile_key_credential(&request).await {
            Ok(response) => response,
            // 401/403 means our profile key is stale; 404 that the version is unknown.
            Err(e) => {
                warn!(service_id = %service_id.service_id_string(), %e, "no credential: fetch failed");
                return None;
            }
        };

        match request.receive(&response, SystemTime::now()) {
            Ok(credential) => Some(credential),
            Err(e) => {
                warn!(service_id = %service_id.service_id_string(), %e, "no credential: response did not verify");
                None
            }
        }
    }

    /// Updates the user's profile information.
    pub async fn update_profile(
        &mut self,
        name: libsignal_service::profile_name::ProfileName<String>,
        about: Option<String>,
        emoji: Option<String>,
    ) -> Result<(), Error<S::Error>> {
        let aci = self.state.data.service_ids.aci();
        let mut account_manager = AccountManager::new(
            self.identified_push_service(),
            self.identified_websocket(false).await?,
            Some(self.state.data.profile_key),
        );

        account_manager
            .upload_versioned_profile_without_avatar::<_, String>(
                aci,
                name,
                about,
                emoji,
                true, // retain_avatar
                &mut rand::rng(),
            )
            .await?;

        // Retrieve and save locally so we have the updated version
        let profile = account_manager.retrieve_profile(aci).await?;
        let _ = self
            .store
            .save_profile(aci.into(), self.state.data.profile_key, profile)
            .await;

        Ok(())
    }

    pub async fn retrieve_group_avatar(
        &mut self,
        context: GroupContextV2,
    ) -> Result<Option<AvatarBytes>, Error<S::Error>> {
        let master_key_bytes = context
            .master_key()
            .try_into()
            .expect("Master key bytes to be of size 32.");

        // Check if group avatar is cached.
        // TODO: Is there some way to know if this is outdated?
        if let Some(avatar) = self
            .store
            .group_avatar(master_key_bytes)
            .await
            .ok()
            .flatten()
        {
            return Ok(Some(avatar));
        }

        let mut gm = Box::pin(self.groups_manager()).await?;
        let Some(group) = upsert_group(
            &self.store,
            &mut gm,
            context.master_key(),
            &context.revision(),
        )
        .await?
        else {
            return Ok(None);
        };

        // Empty path means no avatar was set.
        let Some(avatar_path) = group.avatar.as_deref().filter(|s| !s.is_empty()) else {
            return Ok(None);
        };

        let avatar = gm
            .retrieve_avatar(
                avatar_path,
                GroupSecretParams::derive_from_master_key(GroupMasterKey::new(master_key_bytes)),
            )
            .await?;
        if let Some(avatar) = &avatar {
            let _ = self.store.save_group_avatar(master_key_bytes, avatar).await;
        }
        Ok(avatar)
    }

    pub async fn retrieve_profile_avatar_by_uuid(
        &mut self,
        uuid: Uuid,
        profile_key: ProfileKey,
    ) -> Result<Option<AvatarBytes>, Error<S::Error>> {
        // Always fetch a fresh profile from the network to get the current avatar URL.
        // The server-side URL acts as the version identifier — if it changed, the
        // avatar changed. Mirrors Signal Desktop's existingProfileAvatar.url === avatarUrl check.
        let profile = self.retrieve_profile_by_uuid(uuid, profile_key).await?;

        let Some(avatar_url) = profile.avatar.as_deref() else {
            return Ok(None);
        };

        // Return cached bytes if the URL matches — no re-download needed.
        if let Ok(Some((cached_url, cached_bytes))) =
            self.store.profile_avatar(uuid, profile_key).await
        {
            if cached_url.as_deref() == Some(avatar_url) {
                return Ok(Some(cached_bytes));
            }
        }

        // URL changed or no cache — download, decrypt, save, and return.
        let mut websocket = self.unidentified_websocket().await?;
        let mut avatar_stream = websocket.retrieve_profile_avatar(avatar_url).await?;
        // 10MB is what Signal Android allocates
        let mut contents = Vec::with_capacity(10 * 1024 * 1024);
        let len = avatar_stream.read_to_end(&mut contents).await?;
        contents.truncate(len);

        let cipher = ProfileCipher::new(profile_key);
        let avatar = cipher.decrypt_avatar(&contents)?;
        let _ = self
            .store
            .save_profile_avatar(uuid, profile_key, &avatar, Some(avatar_url))
            .await;
        Ok(Some(avatar))
    }

    async fn groups_manager(
        &self,
    ) -> Result<GroupsManager<InMemoryCredentialsCache>, Error<S::Error>> {
        let service_configuration = self.state.service_configuration();
        let server_public_params = service_configuration.zkgroup_server_public_params;

        let groups_credentials_cache = InMemoryCredentialsCache::default();
        let groups_manager = GroupsManager::new(
            self.state.data.service_ids.clone(),
            self.identified_push_service(),
            self.unidentified_websocket().await?,
            groups_credentials_cache,
            server_public_params,
        );

        Ok(groups_manager)
    }

    /// Starts receiving and storing messages.
    ///
    /// As a client, it is heavily recommended to process incoming messages and wait for the `Received::QueueEmpty` messages
    /// until giving the ability for users to send messages. That way, all possible updates (sessions, profile keys, sender keys)
    /// are processed _before_ trying to encrypt and send messages, which might get rejected by recipients otherwise.
    ///
    /// Returns a [futures::Stream] of messages to consume. Messages will also be stored by the implementation of the [Store].
    pub async fn receive_messages(
        &mut self,
    ) -> Result<impl Stream<Item = Received>, Error<S::Error>> {
        struct StreamState<Receiver, Store, AciStore, PniStore> {
            store: Store,
            identified_websocket: SignalWebSocket<websocket::Identified>,
            unidentified_websocket: SignalWebSocket<websocket::Unidentified>,
            encrypted_messages: Receiver,
            service_cipher_aci: ServiceCipher<AciStore>,
            service_cipher_pni: ServiceCipher<PniStore>,
            groups_manager: GroupsManager<InMemoryCredentialsCache>,
            service_ids: ServiceIds,
            device_id: DeviceId,
            message_sender: MessageSender<AciStore>,
            master_key: Option<MasterKey>,
            account_entropy_pool: Option<AccountEntropyPool>,
            registration_type: RegistrationType,
        }

        let identified_push_service = self.identified_push_service();
        // NB: here, we initialise a *fresh* Signal websocket, which means any other use of the previous one will go into nirvana
        let identified_websocket = self.identified_websocket(true).await?;

        let mut account_manager = AccountManager::new(
            identified_push_service.clone(),
            identified_websocket.clone(),
            None,
        );

        let store_inner = self.store.clone();
        let registration_data_inner = self.registration_data().clone();

        // We make a task to update the account attributes and refresh pre keys as needed that will
        // only yield a value if one of the two operations fail (stop signal).
        //
        // This is necessary because in this context, we can't do the classic tokio::spawn with a
        // oneshot::channel() or CancellationToken because of !Send constraints in the Store.
        let refresh_registration_task = async move {
            if let Err(error) =
                set_account_attributes(&mut account_manager, &store_inner, &registration_data_inner)
                    .await
            {
                error!(%error, "failed to set account attributes, this is problematic and should never happen!");
            }

            if let Err(error) = register_pre_keys(&store_inner, &mut account_manager).await {
                error!(%error, "failed to register pre-keys, this is problematic and should never happen!");
            }

            // Never return, which keeps the messages stream alive.
            future::pending::<()>().await
        };

        let encrypted_messages = MessagePipe::from_socket(identified_websocket.clone());

        let init = StreamState {
            store: self.store.clone(),
            identified_websocket,
            unidentified_websocket: self.unidentified_websocket().await?,
            encrypted_messages: Box::pin(encrypted_messages.stream()),
            service_cipher_aci: self.new_service_cipher_aci(),
            service_cipher_pni: self.new_service_cipher_pni(),
            groups_manager: Box::pin(self.groups_manager()).await?,
            service_ids: self.state.data.service_ids.clone(),
            device_id: self.state.device_id(),
            message_sender: self.new_message_sender().await?,
            master_key: self.master_key().await?,
            account_entropy_pool: self.account_entropy_pool().await?,
            registration_type: self.registration_type(),
        };

        debug!("starting to consume incoming message stream");

        let incoming_messages_stream = futures::stream::unfold(init, |mut state| {
            async move {
                loop {
                    match state.encrypted_messages.next().await {
                        Some(Ok(Incoming::Envelope(envelope))) => {
                            let envelope = {
                                // the permit is released at the end of the block (impl Drop)
                                match ServiceId::parse_from_service_id_string(
                                    envelope.destination_service_id(),
                                ) {
                                    None | Some(ServiceId::Aci(_)) => {
                                        state
                                            .service_cipher_aci
                                            .open_envelope(envelope, &mut rng())
                                            .await
                                    }
                                    Some(ServiceId::Pni(pni)) => {
                                        if pni == state.service_ids.pni()
                                            && envelope.source_service_id.is_none()
                                        {
                                            warn!("Got a sealed sender message to our PNI? Invalid message, ignoring.");
                                            continue;
                                        }
                                        state
                                            .service_cipher_pni
                                            .open_envelope(envelope, &mut rng())
                                            .await
                                    }
                                }
                            };
                            match envelope {
                                Ok(Some(content)) => {
                                    if let ContentBody::DecryptionErrorMessage(e) = &content.body {
                                        error!(
                                            error = ?e,
                                            "got error decrypting a message"
                                        );
                                        continue;
                                    }

                                    if let ContentBody::SynchronizeMessage(SyncMessage {
                                        request: Some(request),
                                        ..
                                    }) = &content.body
                                    {
                                        use libsignal_service::content::sync_message::request::Type as RequestType;

                                        match request.r#type() {
                                            RequestType::Contacts => {
                                                // Ignore contacts requests that originated from
                                                // our own device — these are echoes of the sync
                                                // request we just sent to ourselves. Responding
                                                // with our local (possibly empty) store would
                                                // overwrite the real contacts on all devices.
                                                if content.metadata.sender_device == state.device_id
                                                {
                                                    trace!("ignoring contacts request echoed from our own device");
                                                } else {
                                                    let contacts = state
                                                        .store
                                                        .contacts()
                                                        .await
                                                        .map(|i| {
                                                            i.collect::<Result<Vec<_>, _>>()
                                                                .unwrap_or_default()
                                                        })
                                                        .unwrap_or_default();

                                                    let mut message_sender =
                                                        state.message_sender.clone();
                                                    let aci = state.service_ids.aci();
                                                    tokio::task::spawn_local(async move {
                                                        let result = message_sender
                                                        .send_contact_details(
                                                            &ServiceId::Aci(aci),
                                                            None,
                                                            contacts.into_iter().map(|c| libsignal_service::sender::ContactDetails {
                                                                number: c.phone_number.map(|p| p.to_string()),
                                                                aci: Some(c.uuid.to_string()),
                                                                aci_binary: Some(c.uuid.into_bytes().into()),
                                                                name: Some(c.name),
                                                                avatar: c.avatar.map(|a| libsignal_service::proto::contact_details::Avatar {
                                                                    content_type: Some(a.content_type),
                                                                    length: a.reader.len().try_into().ok(),
                                                                }),
                                                                expire_timer: Some(c.expire_timer),
                                                                expire_timer_version: Some(c.expire_timer_version),
                                                                inbox_position: None,
                                                            }),
                                                            false,
                                                            true,
                                                        )
                                                        .await;

                                                        if let Err(error) = result {
                                                            warn!(%error, "Error sending contact details to other devices");
                                                        }
                                                    });
                                                }
                                            }
                                            RequestType::Keys => {
                                                let mut message_sender =
                                                    state.message_sender.clone();
                                                let account_entropy_pool = state
                                                    .account_entropy_pool
                                                    .as_ref()
                                                    .map(|aep| aep.to_string());
                                                let master = state
                                                    .master_key
                                                    .as_ref()
                                                    .map(|m| m.inner.to_vec());
                                                tokio::task::spawn_local(async move {
                                                    let result = message_sender.send_sync_message(SyncMessage {
                                                        keys: Some(libsignal_service::content::sync_message::Keys {
                                                            master,
                                                            account_entropy_pool,
                                                            media_root_backup_key: None,
                                                        }),
                                                        ..SyncMessage::with_padding(&mut rand::rng())
                                                    }).await;

                                                    if let Err(error) = result {
                                                        warn!(%error, "Error sending keys to other devices");
                                                    }
                                                });
                                            }
                                            RequestType::Blocked => {
                                                let blocked =
                                                    collect_blocked_contacts(&state.store).await;
                                                let mut message_sender =
                                                    state.message_sender.clone();
                                                tokio::task::spawn_local(async move {
                                                    let result = message_sender.send_sync_message(SyncMessage {
                                                    blocked: Some(blocked),
                                                    ..SyncMessage::with_padding(&mut rand::rng())
                                                }).await;

                                                    if let Err(error) = result {
                                                        warn!(%error, "Error sending blocked contacts to other devices");
                                                    }
                                                });
                                            }
                                            t => {
                                                info!(type = ?t, "Got sync request of currently unhandled type")
                                            }
                                        }
                                    }

                                    // contacts synchronization sent from the primary device (happens after linking, or on demand)
                                    if let ContentBody::SynchronizeMessage(SyncMessage {
                                        contacts: Some(contacts),
                                        ..
                                    }) = &content.body
                                    {
                                        debug!(
                                            "received contacts sync: blob={}, complete={:?}",
                                            contacts.blob.is_some(),
                                            contacts.complete
                                        );
                                        return Some((Received::Contacts, state));
                                    }

                                    // sticker pack operations
                                    if let ContentBody::SynchronizeMessage(SyncMessage {
                                        sticker_pack_operation,
                                        ..
                                    }) = &content.body
                                    {
                                        for operation in sticker_pack_operation {
                                            match operation.r#type() {
                                                sticker_pack_operation::Type::Install => {
                                                    let store = state.store.clone();
                                                    let unidentified_websocket =
                                                        state.unidentified_websocket.clone();
                                                    let operation = operation.clone();

                                                    // download stickers in the background
                                                    tokio::spawn(async move {
                                                        match download_sticker_pack(
                                                            store,
                                                            unidentified_websocket,
                                                            &operation,
                                                        )
                                                        .await
                                                        {
                                                            Ok(sticker_pack) => {
                                                                debug!(
                                                                "downloaded sticker pack: {} made by {}",
                                                                sticker_pack.manifest.title,
                                                                sticker_pack.manifest.author
                                                            );
                                                            }
                                                            Err(error) => error!(
                                                                %error,
                                                                "failed to download sticker pack"
                                                            ),
                                                        }
                                                    });
                                                }
                                                sticker_pack_operation::Type::Remove => match state
                                                    .store
                                                    .remove_sticker_pack(operation.pack_id())
                                                    .await
                                                {
                                                    Ok(was_present) => {
                                                        debug!(was_present, "removed stick pack")
                                                    }
                                                    Err(error) => {
                                                        error!(
                                                            %error,
                                                            "failed to remove sticker pack"
                                                        )
                                                    }
                                                },
                                            }
                                        }
                                    }

                                    // keys sync — update stored master key when primary device sends it
                                    // key synchronization sent from the primary device
                                    if let ContentBody::SynchronizeMessage(SyncMessage {
                                        keys: Some(keys),
                                        ..
                                    }) = &content.body
                                    {
                                        debug!("received key sync message");
                                        if state.registration_type == RegistrationType::Primary {
                                            warn!("received a key sync message as a primary device; ignoring")
                                        } else {
                                            match keys
                                                .account_entropy_pool
                                                .as_ref()
                                                .map(|s| AccountEntropyPool::from_str(s))
                                            {
                                                Some(Ok(aep)) => {
                                                    if let Err(error) = state
                                                        .store
                                                        .store_account_entropy_pool(Some(&aep))
                                                        .await
                                                    {
                                                        error!(%error, "failed to store account entropy pool");
                                                    }
                                                    state.account_entropy_pool = Some(aep);
                                                }
                                                Some(Err(error)) => {
                                                    warn!(%error, "cannot convert account entropy pool from string")
                                                }
                                                None => {}
                                            }
                                            match keys
                                                .master
                                                .as_ref()
                                                .map(|m| MasterKey::from_slice(m.as_slice()))
                                            {
                                                Some(Ok(master)) => {
                                                    if let Err(error) = state
                                                        .store
                                                        .store_master_key(Some(&master))
                                                        .await
                                                    {
                                                        error!(%error, "failed to store master key");
                                                    }
                                                    state.master_key = Some(master);
                                                }
                                                Some(Err(error)) => {
                                                    warn!(%error, "cannot convert master key from bytes; trying to populate from account entropy pool");
                                                    if let Some(aep) =
                                                        state.account_entropy_pool.as_ref()
                                                    {
                                                        state.master_key = Some(MasterKey::from_slice(aep.derive_svr_key().as_slice()).expect("svr key derived from account entropy pool to be a master key"));
                                                    }
                                                }
                                                None => {
                                                    trace!("master key not given in the sync message; trying to populate from account entropy pool");
                                                    if let Some(aep) =
                                                        state.account_entropy_pool.as_ref()
                                                    {
                                                        state.master_key = Some(MasterKey::from_slice(aep.derive_svr_key().as_slice()).expect("svr key derived from account entropy pool to be a master key"));
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    // NB: `FetchLatest { StorageManifest }` is intentionally NOT
                                    // handled here. It is delivered to the app as
                                    // `Received::Content`; the client drives the storage sync +
                                    // its own UI refresh (keeps storage-service orchestration in
                                    // the client layer, matching Signal Desktop).

                                    // group update
                                    if let ContentBody::DataMessage(DataMessage {
                                        group_v2:
                                            Some(GroupContextV2 {
                                                master_key: Some(master_key_bytes),
                                                revision: Some(revision),
                                                ..
                                            }),
                                        ..
                                    })
                                    | ContentBody::SynchronizeMessage(SyncMessage {
                                        sent:
                                            Some(sync_message::Sent {
                                                message:
                                                    Some(DataMessage {
                                                        group_v2:
                                                            Some(GroupContextV2 {
                                                                master_key: Some(master_key_bytes),
                                                                revision: Some(revision),
                                                                ..
                                                            }),
                                                        ..
                                                    }),
                                                ..
                                            }),
                                        ..
                                    }) = &content.body
                                    {
                                        // there's two things to implement: the group metadata (fetched from HTTP API)
                                        // and the group changes, which are part of the protobuf messages
                                        // this means we kinda need our own internal representation of groups inside of presage?
                                        if let Ok(Some(group)) = upsert_group(
                                            &state.store,
                                            &mut state.groups_manager,
                                            master_key_bytes,
                                            revision,
                                        )
                                        .await
                                        {
                                            trace!(?group, "upserted group");
                                        }
                                    }

                                    if let Err(error) = save_message(
                                        &mut state.store,
                                        &mut state.identified_websocket,
                                        content.clone(),
                                        None,
                                    )
                                    .await
                                    {
                                        error!(%error, "error saving message to store");
                                    }

                                    return Some((Received::Content(Box::new(content)), state));
                                }
                                Ok(None) => {
                                    debug!("empty envelope, message will be skipped!")
                                }
                                Err(error) => {
                                    error!(%error, "error opening envelope, message will be skipped!");
                                }
                            }
                        }
                        Some(Ok(Incoming::QueueEmpty)) => {
                            debug!("got empty queue");
                            if state.account_entropy_pool.is_none() {
                                debug!("device does not have the needed keys; requesting from primary device");

                                let mut message_sender = state.message_sender.clone();
                                tokio::task::spawn_local(async move {
                                    let result = message_sender
                                        .send_sync_message(SyncMessage {
                                            request: Some(sync_message::Request {
                                                r#type: Some(
                                                    sync_message::request::Type::Keys.into(),
                                                ),
                                            }),
                                            ..SyncMessage::with_padding(&mut rand::rng())
                                        })
                                        .await;

                                    if let Err(error) = result {
                                        warn!(%error, "Error requesting keys from primary device");
                                    }
                                });
                            }
                            return Some((Received::QueueEmpty, state));
                        }
                        Some(Ok(Incoming::Disconnected(reason))) => {
                            return Some((Received::Disconnected(reason), state));
                        }
                        Some(Err(error)) => {
                            error!(%error, "unexpected error in message receiving loop")
                        }
                        None => return None,
                    }
                }
            }
        });

        Ok(Box::pin(
            // We use the returning of the async closure in take_until as a stop signal
            // if the future resolves *anything* the stream will end.
            incoming_messages_stream.take_until(refresh_registration_task),
        ))
    }

    /// Uses Signal's SGX contact discovery service to resolve a phone number to its matching account identity
    #[cfg(feature = "cdsi")]
    pub async fn discover_contacts_by_phone_number<P: TryIntoE164>(
        &mut self,
        phone_numbers: impl IntoIterator<Item = P>,
    ) -> Result<Vec<(PhoneNumber, Option<ServiceId>)>, Error<S::Error>> {
        use libsignal_service::websocket::directory::LookupRequest;

        let mut ws = self.identified_websocket(false).await?;

        let lookup_request = LookupRequest {
            new_e164s: phone_numbers
                .into_iter()
                .filter_map(|p| p.try_into_e164().ok())
                .collect(),
            ..Default::default()
        };

        Ok(ws
            .discover_contacts(lookup_request)
            .await?
            .into_iter()
            .map(|(e164, service_id)| {
                use libsignal_service::utils::phonenumber_from_signal;
                (phonenumber_from_signal(&e164), service_id)
            })
            .collect())
    }

    /// Resolves a username (which has a text part and an additional random number) to its account identity
    /// for sending messages.
    pub async fn lookup_username(
        &mut self,
        username: &str,
    ) -> Result<Option<Aci>, Error<S::Error>> {
        let username = Username::new(username)?;
        let mut ws = self.unidentified_websocket().await?;
        let resolved_username = ws.look_up_username(&username).await?;
        Ok(resolved_username)
    }

    /// Sends a messages to the provided [ServiceId].
    /// The timestamp should be set to now and is used by Signal mobile apps
    /// to order messages later, and apply reactions.
    ///
    /// This method will automatically update the [DataMessage::expire_timer] if it is set to
    /// [None] such that the chat will keep the current expire timer. If the expire timer is set,
    /// it will be used as is, and the expire timer version will be incremented.
    pub async fn send_message(
        &mut self,
        recipient: impl Into<ServiceId>,
        message: impl Into<ContentBody>,
        timestamp: u64,
    ) -> Result<(), Error<S::Error>> {
        let mut sender = self.new_message_sender().await?;
        let recipient = recipient.into();

        let online_only = false;
        // TODO: Populate this flag based on the recipient information
        //
        // Issue <https://github.com/whisperfish/presage/issues/252>
        let include_pni_signature = false;
        let thread = Thread::Contact(recipient);
        let mut content_body: ContentBody = message.into();

        self.restore_thread_timer(&thread, &mut content_body).await;

        let sender_certificate = self.sender_certificate().await?;
        let unidentified_access = self
            .store
            .profile_key(&recipient)
            .await?
            .map(|profile_key| UnidentifiedAccess {
                key: profile_key.derive_access_key().to_vec(),
                certificate: sender_certificate.clone(),
            });

        // we need to put our profile key in DataMessage
        if let ContentBody::DataMessage(message) = &mut content_body {
            message
                .profile_key
                .get_or_insert(self.state.data.profile_key().get_bytes().to_vec());
            message.required_protocol_version = Some(0);
        }

        ensure_data_message_timestamp(&mut content_body, timestamp);

        sender
            .send_message(
                &recipient,
                unidentified_access,
                content_body.clone(),
                timestamp,
                include_pni_signature,
                online_only,
            )
            .await?;

        // save the message
        let content = Content {
            metadata: Metadata {
                sender: self.state.data.service_ids.aci().into(),
                sender_device: self.state.device_id(),
                destination: recipient,
                server_guid: None,
                timestamp: chrono::Utc.timestamp_millis_opt(timestamp as i64).unwrap(),
                // Note: Currently no way to get the timestamp the server received the message; just use our timestamp as a fallback.
                server_timestamp: chrono::Utc.timestamp_millis_opt(timestamp as i64).unwrap(),
                needs_receipt: false,
                unidentified_sender: false,
                was_plaintext: false,
                report_spam_token: None,
            },
            body: content_body,
        };

        let mut identified_websocket = self.identified_websocket(false).await?;
        save_message(
            &mut self.store,
            &mut identified_websocket,
            content,
            Some(thread),
        )
        .await?;

        Ok(())
    }

    /// Block or unblock a recipient. Persists the flag locally, then syncs the
    /// full blocked list to our own linked devices via a `Blocked` sync message.
    /// A recipient not yet in the contact list is stored as a minimal blocked
    /// record so the block still takes effect.
    pub async fn set_blocked(
        &mut self,
        service_id: ServiceId,
        blocked: bool,
    ) -> Result<(), Error<S::Error>> {
        let mut contact = match self.store.contact_by_id(&service_id).await? {
            Some(contact) => contact,
            None => Contact::minimal(service_id.raw_uuid()),
        };
        contact.blocked = blocked;
        self.store.save_contact(&contact).await?;
        self.send_blocked_sync().await
    }

    /// Broadcast the current blocked list to our own linked devices.
    async fn send_blocked_sync(&mut self) -> Result<(), Error<S::Error>> {
        let blocked = collect_blocked_contacts(&self.store).await;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as u64;
        let sync_message = SyncMessage {
            blocked: Some(blocked),
            ..SyncMessage::with_padding(&mut rand::rng())
        };
        self.send_message(self.state.data.service_ids.aci(), sync_message, timestamp)
            .await
    }

    /// Report a received message as spam to the Signal servers. `server_guid`
    /// identifies the offending message and `token` is its `report_spam_token`
    /// from the envelope, if any (see [`Metadata`]).
    pub async fn report_spam(
        &self,
        sender: ServiceId,
        server_guid: Uuid,
        token: Option<Vec<u8>>,
    ) -> Result<(), Error<S::Error>> {
        self.identified_push_service()
            .report_spam(&sender, server_guid, token)
            .await?;
        Ok(())
    }

    /// Uploads one attachment prior to linking them in a message.
    pub async fn upload_attachment(
        &self,
        spec: AttachmentSpec,
        contents: Vec<u8>,
    ) -> Result<Result<AttachmentPointer, AttachmentUploadError>, Error<S::Error>> {
        Ok(self
            .new_message_sender()
            .await?
            .upload_attachment(spec, contents, &mut rng())
            .await)
    }

    /// Uploads attachments prior to linking them in a message.
    pub async fn upload_attachments(
        &self,
        attachments: Vec<(AttachmentSpec, Vec<u8>)>,
    ) -> Result<Vec<Result<AttachmentPointer, AttachmentUploadError>>, Error<S::Error>> {
        if attachments.is_empty() {
            return Ok(Vec::new());
        }
        let sender = self.new_message_sender().await?;
        let upload = future::join_all(attachments.into_iter().map(move |(spec, contents)| {
            let mut sender = sender.clone();
            async move { sender.upload_attachment(spec, contents, &mut rng()).await }
        }));
        Ok(upload.await)
    }

    /// Sends one message in a group (v2). The `master_key_bytes` is required to have 32 elements.
    ///
    /// This method will automatically update the [DataMessage::expire_timer] if it is set to
    /// [None] such that the chat will keep the current expire timer.
    pub async fn send_message_to_group(
        &mut self,
        master_key_bytes: &[u8],
        message: impl Into<ContentBody>,
        timestamp: u64,
    ) -> Result<(), Error<S::Error>> {
        let mut content_body = message.into();
        let master_key_bytes = master_key_bytes
            .try_into()
            .expect("Master key bytes to be of size 32.");
        let thread = Thread::Group(master_key_bytes);

        self.restore_thread_timer(&thread, &mut content_body).await;
        ensure_data_message_timestamp(&mut content_body, timestamp);

        let mut sender = self.new_message_sender().await?;

        let mut groups_manager = Box::pin(self.groups_manager()).await?;
        let Some(group) =
            upsert_group(&self.store, &mut groups_manager, &master_key_bytes, &0).await?
        else {
            return Err(Error::UnknownGroup);
        };

        let sender_certificate = self.sender_certificate().await?;
        let mut recipients = Vec::new();
        for member in group
            .members
            .into_iter()
            .filter(|m| m.aci != self.state.data.service_ids.aci())
        {
            let unidentified_access =
                self.store
                    .profile_key(&member.aci.into())
                    .await?
                    .map(|profile_key| UnidentifiedAccess {
                        key: profile_key.derive_access_key().to_vec(),
                        certificate: sender_certificate.clone(),
                    });
            let include_pni_signature = false;
            recipients.push((
                member.aci.into(),
                unidentified_access,
                include_pni_signature,
            ));
        }

        let online_only = false;
        let results = sender
            .send_message_to_group(recipients, content_body.clone(), timestamp, online_only)
            .await;

        // TODO: Handle the NotFound error in the future by removing all sessions to this UUID and marking it as unregistered, not sending any messages to this contact anymore.
        results
            .into_iter()
            .find(|res| match res {
                Ok(_) => false,
                // Ignore any NotFound errors, those mean that e.g. some contact in a group deleted his account.
                Err(MessageSenderError::NotFound { service_id }) => {
                    debug!(service_id = %service_id.service_id_string(), "recipient not found, skipping sent message result");
                    false
                }
                // return first error if any
                Err(_) => true,
            })
            .transpose()?;

        let content = Content {
            metadata: Metadata {
                sender: self.state.data.service_ids.aci().into(),
                destination: self.state.data.service_ids.aci().into(),
                sender_device: self.state.device_id(),
                server_guid: None,
                timestamp: chrono::Utc.timestamp_millis_opt(timestamp as i64).unwrap(),
                // Note: Currently no way to get the timestamp the server received the message; just use our timestamp as a fallback.
                server_timestamp: chrono::Utc.timestamp_millis_opt(timestamp as i64).unwrap(),
                needs_receipt: false, // TODO: this is just wrong
                unidentified_sender: false,
                was_plaintext: false,
                report_spam_token: None,
            },
            body: content_body,
        };

        let mut identified_websocket = self.identified_websocket(false).await?;
        save_message(
            &mut self.store,
            &mut identified_websocket,
            content,
            Some(thread),
        )
        .await?;

        Ok(())
    }

    async fn restore_thread_timer(&mut self, thread: &Thread, content_body: &mut ContentBody) {
        let store_expire_timer = self.store.expire_timer(thread).await.unwrap_or_default();

        if let ContentBody::DataMessage(DataMessage {
            expire_timer: ref mut timer,
            expire_timer_version: ref mut version,
            ..
        }) = content_body
        {
            if timer.is_none() {
                *timer = store_expire_timer.and_then(|(t, _)| if t == 0 { None } else { Some(t) });
                *version = Some(store_expire_timer.map(|(_, v)| v).unwrap_or_default());
            } else {
                *version = Some(store_expire_timer.map(|(_, v)| v).unwrap_or_default() + 1);
            }
        }
    }

    /// Clears all sessions established with [recipient](ServiceId).
    pub async fn clear_sessions(&self, recipient: &ServiceId) -> Result<(), Error<S::Error>> {
        use libsignal_service::session_store::SessionStoreExt;
        self.store
            .aci_protocol_store()
            .delete_all_sessions(recipient)
            .await?;
        self.store
            .pni_protocol_store()
            .delete_all_sessions(recipient)
            .await?;
        Ok(())
    }

    /// Downloads and decrypts a single attachment.
    pub async fn get_attachment(
        &self,
        attachment_pointer: &AttachmentPointer,
    ) -> Result<Vec<u8>, Error<S::Error>> {
        let expected_digest = attachment_pointer.digest.as_ref();

        let mut service = self.identified_push_service();
        let mut attachment_stream = service.get_attachment(attachment_pointer).await?;

        let plaintext_len = attachment_pointer.size.and_then(|len| len.try_into().ok());

        // We need the whole file for the crypto to check out
        let mut ciphertext = Vec::with_capacity(plaintext_len.unwrap_or(0));
        let size_bytes = attachment_stream.read_to_end(&mut ciphertext).await?;
        trace!(size_bytes, "downloaded encrypted attachment");

        // Verify ciphertext digest when present. Backup-imported attachments may carry only
        // a plaintextHash (no encryptedDigest), so digest can be absent — the HMAC inside
        // decrypt_in_place still provides integrity verification.
        if let Some(expected) = expected_digest {
            let digest = sha2::Sha256::digest(&ciphertext);
            if &digest[..] != expected {
                return Err(Error::UnexpectedAttachmentChecksum);
            }
        }

        let key: [u8; 64] = attachment_pointer.key().try_into()?;

        // Offload decryption of large attachments to another thread.
        // Chose arbitrary threshold here.
        const DECRYPT_IN_THREAD_THRESHOLD: usize = 100 * 1024;
        if ciphertext.len() > DECRYPT_IN_THREAD_THRESHOLD {
            ciphertext = tokio::task::spawn_blocking(move || {
                decrypt_in_place(key, &mut ciphertext).map(|_| ciphertext)
            })
            .await
            .expect("decryption in another thread")?;
        } else {
            decrypt_in_place(key, &mut ciphertext)?;
        };

        if let Some(len) = plaintext_len {
            if len < ciphertext.len() {
                // remove padding
                ciphertext.truncate(len);
            }
        }

        Ok(ciphertext)
    }

    /// Gets the metadata of a sticker
    pub async fn sticker_metadata(
        &mut self,
        pack_id: &[u8],
        sticker_id: u32,
    ) -> Result<Option<Sticker>, Error<S::Error>> {
        Ok(self.store.sticker_pack(pack_id).await?.and_then(|pack| {
            pack.manifest
                .stickers
                .iter()
                .find(|&x| x.id == sticker_id)
                .cloned()
        }))
    }

    /// Downloads and decrypts a single sticker's image bytes straight from the
    /// sticker CDN (`/stickers/{pack_id}/full/{sticker_id}`) — no manifest, no
    /// whole-pack download, and no "install" sync to other devices. Only
    /// `pack_id`/`pack_key`/`sticker_id` are needed, so this can render a
    /// received sticker whose per-message `data` attachment is unavailable
    /// (e.g. dropped on backup import).
    pub async fn download_sticker(
        &self,
        pack_id: &[u8],
        pack_key: &[u8],
        sticker_id: u32,
    ) -> Result<Vec<u8>, Error<S::Error>> {
        let mut unidentified_websocket = self.unidentified_websocket().await?;
        download_sticker::<S>(&mut unidentified_websocket, pack_id, pack_key, sticker_id).await
    }

    /// Installs a sticker pack and notifies other registered devices
    pub async fn install_sticker_pack(
        &mut self,
        pack_id: &[u8],
        pack_key: &[u8],
    ) -> Result<(), Error<S::Error>> {
        let sticker_pack_operation = StickerPackOperation {
            pack_id: Some(pack_id.to_vec()),
            pack_key: Some(pack_key.to_vec()),
            r#type: Some(sticker_pack_operation::Type::Install as i32),
        };

        let unidentified_websocket = self.unidentified_websocket().await?;
        download_sticker_pack(
            self.store.clone(),
            unidentified_websocket,
            &sticker_pack_operation,
        )
        .await?;

        // Sync the change with the other devices
        let sync_message = SyncMessage {
            sticker_pack_operation: vec![sticker_pack_operation],
            ..Default::default()
        };

        let timestamp = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as u64;

        self.send_message(self.state.data.service_ids.aci(), sync_message, timestamp)
            .await?;

        Ok(())
    }

    /// Removes an installed sticker pack
    pub async fn remove_sticker_pack(
        &mut self,
        pack_id: &[u8],
        pack_key: &[u8],
    ) -> Result<(), Error<S::Error>> {
        // Sync the change with the other clients
        let sync_message = SyncMessage {
            sticker_pack_operation: vec![StickerPackOperation {
                pack_id: Some(pack_id.to_vec()),
                pack_key: Some(pack_key.to_vec()), // The pack key might not be neccesary in the message
                r#type: Some(sticker_pack_operation::Type::Remove as i32),
            }],
            ..Default::default()
        };

        let timestamp = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as u64;

        self.send_message(self.state.data.service_ids.aci(), sync_message, timestamp)
            .await?;

        self.store.remove_sticker_pack(pack_id).await?;

        Ok(())
    }

    pub async fn send_session_reset(
        &mut self,
        recipient: &ServiceId,
        timestamp: u64,
    ) -> Result<(), Error<S::Error>> {
        trace!(recipient = %recipient.service_id_string(), "resetting session for address");
        let message = DataMessage {
            flags: Some(DataMessageFlags::EndSession as u32),
            ..Default::default()
        };

        self.send_message(*recipient, message, timestamp).await?;

        Ok(())
    }

    fn credentials(&self) -> ServiceCredentials {
        self.state.credentials()
    }

    /// Creates a new message sender.
    async fn new_message_sender(&self) -> Result<MessageSender<S::AciStore>, Error<S::Error>> {
        let identified_websocket = self.identified_websocket(false).await?;
        let unidentified_websocket = self.unidentified_websocket().await?;

        let aci_protocol_store = self.store.aci_protocol_store();
        let aci_identity_keypair = aci_protocol_store.get_identity_key_pair().await?;
        let pni_identity_keypair = self
            .store
            .pni_protocol_store()
            .get_identity_key_pair()
            .await?;

        Ok(MessageSender::new(
            identified_websocket,
            unidentified_websocket,
            self.identified_push_service(),
            self.new_service_cipher_aci(),
            aci_protocol_store,
            self.state.data.service_ids.aci,
            self.state.data.service_ids.pni,
            aci_identity_keypair,
            Some(pni_identity_keypair),
            self.state.device_id(),
        ))
    }

    fn new_service_cipher_aci(&self) -> ServiceCipher<S::AciStore> {
        ServiceCipher::new(
            self.store.aci_protocol_store(),
            self.state
                .service_configuration()
                .unidentified_sender_trust_roots,
            ProtocolAddress::new(
                self.state.data.service_ids.aci.to_string(),
                self.state.device_id(),
            ),
            self.state.session_locks.clone(),
        )
    }

    fn new_service_cipher_pni(&self) -> ServiceCipher<S::PniStore> {
        ServiceCipher::new(
            self.store.pni_protocol_store(),
            self.state
                .service_configuration()
                .unidentified_sender_trust_roots,
            ProtocolAddress::new(
                self.state.data.service_ids.pni.to_string(),
                self.state.device_id(),
            ),
            self.state.session_locks.clone(),
        )
    }

    /// Returns the title of a thread (contact or group).
    pub async fn thread_title(&self, thread: &Thread) -> Result<String, Error<S::Error>> {
        match thread {
            Thread::Contact(service_id) => {
                let contact = match self.store.contact_by_id(service_id).await {
                    Ok(contact) => contact,
                    Err(error) => {
                        info!(%error, service_id =% service_id.service_id_string(), "error getting contact by id");
                        None
                    }
                };
                Ok(match contact {
                    Some(contact) => contact.name,
                    None => service_id.service_id_string(),
                })
            }
            Thread::Group(id) => match self.store.group(*id).await? {
                Some(group) => Ok(group.title.unwrap_or_default()),
                None => Ok("".to_string()),
            },
        }
    }

    /// Returns how this client was registered, either as a primary or secondary device.
    pub fn registration_type(&self) -> RegistrationType {
        if self.state.data.device_name.is_some() {
            RegistrationType::Secondary
        } else {
            RegistrationType::Primary
        }
    }

    /// As a primary device, link a secondary device.
    pub async fn link_secondary(&mut self, secondary: Url) -> Result<(), Error<S::Error>> {
        // XXX: What happens if secondary device? Possible to use static typing to make this method call impossible in that case?
        if self.registration_type() != RegistrationType::Primary {
            return Err(Error::NotPrimaryDevice);
        }

        let credentials = self.credentials();
        let mut account_manager = AccountManager::new(
            self.identified_push_service(),
            self.identified_websocket(false).await?,
            Some(self.state.data.profile_key),
        );

        account_manager
            .link_device(
                &mut rand::rng(),
                secondary,
                &self.store.aci_protocol_store(),
                &self.store.pni_protocol_store(),
                ProvisioningSecrets {
                    credentials,
                    account_entropy_pool: self
                        .account_entropy_pool()
                        .await?
                        .expect("Primary device to always have an account entropy pool"),
                    master_key: self.master_key().await?,
                    ephemeral_backup_key: None,
                    media_root_backup_key: None,
                },
            )
            .await?;
        Ok(())
    }

    /// As a primary device, unlink a secondary device.
    pub async fn unlink_secondary(
        &self,
        device_id: impl TryInto<DeviceId>,
    ) -> Result<(), Error<S::Error>> {
        // secondary devices cannot unlink themselves or other devices, it will fail with an unauthorized error
        if self.registration_type() != RegistrationType::Primary {
            return Err(Error::NotPrimaryDevice);
        }
        self.identified_websocket(false)
            .await?
            .unlink_device(device_id.try_into().map_err(|_| Error::InvalidDeviceId)?)
            .await?;
        Ok(())
    }

    /// As a primary device, list all the devices (including the current device).
    pub async fn devices(&self) -> Result<Vec<DeviceInfo>, Error<S::Error>> {
        let aci_protocol_store = self.store.aci_protocol_store();
        let mut account_manager = AccountManager::new(
            self.identified_push_service(),
            self.identified_websocket(false).await?,
            Some(self.state.data.profile_key),
        );

        Ok(account_manager.linked_devices(&aci_protocol_store).await?)
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

    pub async fn hydrate_groups(&mut self) -> Result<(), Error<S::Error>> {
        let stubs: Vec<libsignal_service::zkgroup::GroupMasterKeyBytes> = self
            .store
            .groups()
            .await?
            .filter_map(|r| {
                r.map_err(|e| warn!(%e, "failed to load group, skipping"))
                    .ok()
            })
            .filter(|(_, g)| g.needs_hydration)
            .map(|(mk, _)| mk)
            .collect();

        info!(count = stubs.len(), "hydrating groups");
        let mut groups_manager = Box::pin(self.groups_manager()).await?;

        for master_key in stubs {
            if let Err(e) = hydrate_group(&mut self.store, &mut groups_manager, master_key).await {
                warn!(%e, "failed to hydrate group, continuing");
            }
        }
        Ok(())
    }

    /// Fetches the stored `BackupKey` and derives the `MessageBackupKey` for this account.
    pub async fn backup_message_key(&self) -> Result<Option<MessageBackupKey>, Error<S::Error>> {
        let backup_key = match self.store.fetch_backup_key().await? {
            Some(k) => k,
            None => return Ok(None),
        };
        let aci = Aci::from_uuid_bytes(self.state.data.service_ids.aci.into_bytes());
        let backup_id = backup_key.derive_backup_id(&aci);
        Ok(Some(MessageBackupKey::derive(
            &backup_key,
            &backup_id,
            None,
        )))
    }

    /// Download and import a Signal backup after device linking (Link & Sync).
    pub async fn download_and_import_backup<F: Fn(BackupImportProgress)>(
        &mut self,
        ephemeral_key: Option<MessageBackupKey>,
        on_progress: F,
    ) -> Result<bool, Error<S::Error>> {
        let aci = Aci::from_uuid_bytes(self.state.data.service_ids.aci.into_bytes());

        let (stream, total_bytes, path, download_offset, message_backup_key) =
            if let Some(message_backup_key) = ephemeral_key {
                let archive = match self.store.fetch_transfer_archive().await? {
                    Some(cached) => cached,
                    None => {
                        on_progress(BackupImportProgress::WaitingForUpload);
                        let mut svc = self.state.identified_push_service();
                        match svc
                            .get_transfer_archive(std::time::Duration::from_secs(3600))
                            .await?
                        {
                            TransferArchiveResult::Available { cdn, key } => {
                                let archive = TransferArchive {
                                    cdn,
                                    key,
                                    path: crate::backup::random_backup_path(),
                                };
                                self.store.store_transfer_archive(Some(&archive)).await?;
                                archive
                            }
                            TransferArchiveResult::Error {
                                error: TransferArchiveError::RelinkRequested,
                            } => return Err(Error::BackupRelinkRequested),
                            TransferArchiveResult::Error {
                                error: TransferArchiveError::ContinueWithoutUpload,
                            } => return Ok(false),
                        }
                    }
                };
                let download_offset = match tokio::fs::metadata(&archive.path).await {
                    Ok(m) => m.len(),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
                    Err(e) => return Err(e.into()),
                };
                let mut svc = self.state.identified_push_service();
                let (stream, total_bytes) = svc
                    .download_transfer_archive(archive.cdn, &archive.key, download_offset)
                    .await?;
                (
                    stream,
                    total_bytes,
                    archive.path,
                    download_offset,
                    message_backup_key,
                )
            } else {
                // Regular backup restore needs a different download path — equivalent
                // to Signal Desktop's api.download() with ZKP credentials, not
                // api.downloadEphemeral() which is used for Link & Sync.
                warn!("regular (non-ephemeral) backup restore is not yet implemented");
                return Ok(false);
            };

        self.write_archive_to_file(&path, stream, total_bytes, download_offset, &on_progress)
            .await?;

        on_progress(BackupImportProgress::Processing);

        let import_result = self.import_from_file(&path, &message_backup_key, aci).await;
        if let Err(e) = tokio::fs::remove_file(&path).await {
            warn!(%e, path = %path.display(), "failed to remove backup temp file");
        }
        import_result?;

        self.store.store_transfer_archive(None).await?;
        on_progress(BackupImportProgress::Done);
        Ok(true)
    }

    /// Streams `stream` into `path` in 64 KB chunks, appending to resume interrupted downloads.
    /// Reports progress via `on_progress` after each chunk. Times out if a chunk stalls for 10s.
    async fn write_archive_to_file<R, F>(
        &self,
        path: &Path,
        mut stream: R,
        total_bytes: u64,
        download_offset: u64,
        on_progress: &F,
    ) -> Result<(), Error<S::Error>>
    where
        R: futures::io::AsyncRead + Unpin,
        F: Fn(BackupImportProgress),
    {
        // Matches Signal Desktop's GET_ATTACHMENT_CHUNK_TIMEOUT.
        const CHUNK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

        on_progress(BackupImportProgress::Downloading {
            bytes_received: download_offset,
            total: total_bytes,
        });

        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await?;

        let mut bytes_received = download_offset;
        let mut buf = vec![0u8; 65536];
        loop {
            let n = tokio::time::timeout(CHUNK_TIMEOUT, stream.read(&mut buf))
                .await
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "transfer archive download stalled",
                    )
                })??;
            if n == 0 {
                break;
            }
            file.write_all(&buf[..n]).await?;
            bytes_received += n as u64;
            on_progress(BackupImportProgress::Downloading {
                bytes_received,
                total: total_bytes,
            });
        }
        file.flush().await?;
        Ok(())
    }

    /// Decrypts and parses a Backups v2 file, saving each `ChatItem` frame as a `Content` message.
    /// The first frame (AccountData) is intentionally skipped — settings are synced via other means.
    async fn import_from_file(
        &mut self,
        path: &Path,
        message_backup_key: &MessageBackupKey,
        aci: libsignal_service::protocol::Aci,
    ) -> Result<(), Error<S::Error>> {
        let factory = FileReaderFactory {
            path: path.to_owned(),
        };
        let frames_reader = FramesReader::new(message_backup_key, factory)
            .await
            .map_err(|e| Error::BackupImportFailed(e.to_string()))?;
        let mut reader = VarintDelimitedReader::new(frames_reader);

        // The first frame is always AccountData (profile name/about/avatar, account
        // settings like read receipts, typing indicators, link previews, phone number
        // sharing mode, preferred reaction emoji, etc.). We intentionally skip it for
        // now: profile data arrives via network fetches on message receipt and storage
        // service sync, and presage has no settings storage layer yet. This mirrors
        // Signal Desktop's "no backup" path behaviour.
        //
        // TODO: implement AccountData restore — in particular the preferences are
        // interesting to carry over from the backup rather than waiting for a sync
        // message from the primary device.
        reader
            .read_next()
            .await
            .map_err(|e| Error::BackupImportFailed(e.to_string()))?;

        let mut recipients: HashMap<u64, RecipientInfo> = HashMap::new();
        let mut chats: HashMap<u64, Thread> = HashMap::new();

        while let Some(bytes) = reader
            .read_next()
            .await
            .map_err(|e| Error::BackupImportFailed(e.to_string()))?
        {
            let frame = Frame::decode_bytes(bytes.as_ref())
                .map_err(|e| Error::BackupImportFailed(e.to_string()))?;
            match frame.item {
                Some(FrameItem::Recipient(r)) => {
                    if let Some((id, info)) = convert::recipient_info(&r, aci) {
                        recipients.insert(id, info);
                    }
                    // Persist the recipient's display data (contact name / group
                    // title) as we see it — Recipient frames precede the Chat and
                    // ChatItem frames that reference them, so by the time
                    // `save_message` runs the store can title the conversation
                    // immediately instead of falling back to the id until a later
                    // storage-service sync / group hydration completes.
                    if let Some(mut contact) = convert::recipient_to_contact(&r) {
                        // Same guard as the storage-sync path, for the same reason: a
                        // Recipient frame is a snapshot of what the exporting device
                        // knew, so an empty field in it must not wipe a populated row.
                        // Reachable when a contact already exists — a storage sync that
                        // beat the import, or a re-import over a live store.
                        if let Some(existing) = self
                            .store
                            .contact_by_id(&ServiceId::Aci(Aci::from(contact.uuid)))
                            .await
                            .ok()
                            .flatten()
                        {
                            merge_contact_from_snapshot(&mut contact, existing);
                        }
                        if let Err(e) = self.store.save_contact(&contact).await {
                            warn!(%e, "backup import: failed to save contact");
                        }
                        // Same reason as the storage-sync path: the backup carries the
                        // profile key, so record it where `profile_key()` will find it.
                        if let Some(profile_key) = contact_profile_key(&contact) {
                            if let Err(e) = self
                                .store
                                .upsert_profile_key(&contact.uuid, profile_key)
                                .await
                            {
                                warn!(%e, "backup import: failed to upsert profile key");
                            }
                        }
                    } else if let Some((master_key, group)) = convert::recipient_to_group(&r) {
                        if let Err(e) = self.store.save_group(master_key, group).await {
                            warn!(%e, "backup import: failed to save group");
                        }
                    }
                }
                Some(FrameItem::Chat(c)) => {
                    if let Some((id, thread)) = convert::chat_to_thread(&c, &recipients) {
                        chats.insert(id, thread);
                    }
                }
                Some(FrameItem::ChatItem(ci)) => {
                    for (content, thread) in
                        convert::chat_item_to_contents(&ci, &recipients, &chats, aci)
                    {
                        // Synthesised sync `call_event` rows route through
                        // `ingest_call_event` so the same load + state machine +
                        // save pipeline runs for backup and live events alike.
                        // The converter built this proto upstream from typed
                        // backup data — `extract_call_event` reverses that to
                        // hand the state machine its `CallEventInfo`.
                        let call_info = extract_call_event(&content.body);
                        let call_peer = CallPeer::from_thread(&thread);
                        self.store.save_message(&thread, content).await?;
                        if let (Some(info), Some(peer)) = (call_info, call_peer) {
                            self.store.ingest_call_event(&info, &peer).await?;
                        }
                    }
                    // Restore read / delivery state and arrival time — none of
                    // which the wire `Content` can carry — so linked history
                    // shows correct unread badges, outgoing ticks, and the same
                    // ordering the primary device had.
                    if let Some(state) = convert::chat_item_backup_state(&ci, &recipients, &chats) {
                        if let Err(e) = self
                            .store
                            .restore_backup_message_state(
                                &state.thread,
                                state.ts,
                                state.read,
                                &state.send_states,
                                state.date_received,
                            )
                            .await
                        {
                            warn!(%e, "backup import: failed to restore message state");
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
}

/// Build the `Blocked` sync payload from locally-stored blocked contacts.
///
/// Group blocking is deferred (this covers 1:1 contacts), so `group_ids` is
/// always empty. Blocking is keyed by ACI; `numbers` is left empty as modern
/// Signal identifies blocked recipients by service id. Store-read errors are
/// logged and treated as "nothing blocked" rather than propagated.
async fn collect_blocked_contacts<S: Store>(
    store: &S,
) -> libsignal_service::content::sync_message::Blocked {
    let mut acis = Vec::new();
    let mut acis_binary = Vec::new();
    match store.contacts().await {
        Ok(iter) => {
            for contact in iter.flatten() {
                if contact.blocked {
                    acis.push(contact.uuid.to_string());
                    acis_binary.push(contact.uuid.as_bytes().to_vec());
                }
            }
        }
        Err(error) => {
            warn!(%error, "failed to read contacts while building blocked list");
        }
    }
    libsignal_service::content::sync_message::Blocked {
        numbers: Vec::new(),
        acis,
        acis_binary,
        group_ids: Vec::new(),
    }
}

/// Set the timestamp in any DataMessage so it matches its envelope's
fn ensure_data_message_timestamp(content_body: &mut ContentBody, timestamp: u64) {
    match content_body {
        ContentBody::DataMessage(message) => {
            message.timestamp = Some(timestamp);
        }
        ContentBody::EditMessage(EditMessage {
            data_message: Some(data_message),
            ..
        }) => {
            data_message.timestamp = Some(timestamp);
        }
        ContentBody::SynchronizeMessage(SyncMessage {
            sent:
                Some(sync_message::Sent {
                    message: Some(data_message),
                    ..
                }),
            ..
        }) => {
            data_message.timestamp = Some(timestamp);
        }
        _ => (),
    }
}

async fn upsert_group<S: Store>(
    store: &S,
    groups_manager: &mut GroupsManager<InMemoryCredentialsCache>,
    master_key_bytes: &[u8],
    revision: &u32,
) -> Result<Option<Group>, Error<S::Error>> {
    let upsert_group = match store.group(master_key_bytes.try_into()?).await {
        Ok(Some(group)) => {
            debug!(group_name =? group.title, "loaded group from local db");
            group.revision < *revision
        }
        Ok(None) => true,
        Err(error) => {
            warn!(%error, "failed to retrieve group from local db");
            true
        }
    };

    if upsert_group {
        debug!("fetching and saving group");
        // `rand::rng()` hands back a `ThreadRng` (`Rc<UnsafeCell<..>>`), and the
        // temporary lives across the await below — which would make this future,
        // and everything calling it, `!Send` for no reason. Seed a `StdRng`
        // instead: same CSPRNG guarantees, and the future stays `Send`.
        let mut csprng = StdRng::from_os_rng();
        match groups_manager
            .fetch_encrypted_group(&mut csprng, master_key_bytes)
            .await
        {
            Ok(encrypted_group) => {
                let group = decrypt_group(master_key_bytes, encrypted_group)?;
                if let Err(error) = store.save_group(master_key_bytes.try_into()?, group).await {
                    error!(%error, "failed to save group");
                }
            }
            Err(error) => {
                warn!(%error, "failed to fetch encrypted group")
            }
        }
    }

    Ok(store.group(master_key_bytes.try_into()?).await?)
}

async fn hydrate_group<S: Store>(
    store: &mut S,
    groups_manager: &mut GroupsManager<InMemoryCredentialsCache>,
    master_key: libsignal_service::zkgroup::GroupMasterKeyBytes,
) -> Result<(), Error<S::Error>> {
    // Seeded from the OS rather than `rand::rng()` so the future stays `Send`
    // — see the note in `upsert_group`.
    let mut csprng = StdRng::from_os_rng();
    match groups_manager
        .fetch_encrypted_group(&mut csprng, master_key.as_ref())
        .await
    {
        Ok(encrypted_group) => {
            let mut group: Group = decrypt_group(master_key.as_ref(), encrypted_group)?.into();
            group.needs_hydration = false;
            if let Err(e) = store.save_group(master_key, group).await {
                error!(%e, "hydrate_group: failed to save group");
            }
        }
        Err(e) => {
            warn!(%e, "hydrate_group: failed to fetch from group server, skipping");
        }
    }
    Ok(())
}

/// Download and decrypt a sticker manifest
async fn download_sticker_pack<C: ContentsStore>(
    mut store: C,
    mut unidentified_websocket: SignalWebSocket<websocket::Unidentified>,
    operation: &StickerPackOperation,
) -> Result<StickerPack, Error<C::ContentsStoreError>> {
    debug!("downloading sticker pack");
    let pack_key = operation.pack_key();
    let pack_id = operation.pack_id();
    let key = derive_key(pack_key)?;

    let mut ciphertext = Vec::new();

    let size_bytes = unidentified_websocket
        .get_sticker_pack_manifest(&hex::encode(pack_id))
        .await?
        .read_to_end(&mut ciphertext)
        .await?;

    trace!(size_bytes, "downloaded encrypted sticker pack manifest");

    decrypt_in_place(key, &mut ciphertext)?;

    let mut sticker_pack_manifest: StickerPackManifest =
        libsignal_service::proto::Pack::decode(ciphertext.as_slice())
            .map_err(ProvisioningError::from)?
            .into();

    for sticker in &mut sticker_pack_manifest.stickers {
        match download_sticker::<C>(&mut unidentified_websocket, pack_id, pack_key, sticker.id)
            .await
        {
            Ok(decrypted_sticker_bytes) => {
                debug!(id = sticker.id, "downloaded sticker");
                sticker.bytes = Some(decrypted_sticker_bytes);
            }
            Err(error) => error!(sticker.id, %error,"failed to download sticker"),
        }
    }

    let sticker_pack = StickerPack {
        id: pack_id.to_vec(),
        key: pack_key.to_vec(),
        manifest: sticker_pack_manifest,
    };

    // save everything in store
    store.add_sticker_pack(&sticker_pack).await?;

    Ok(sticker_pack)
}

/// Downloads and decrypts a single sticker
async fn download_sticker<C: ContentsStore>(
    unidentified_websocket: &mut SignalWebSocket<websocket::Unidentified>,
    pack_id: &[u8],
    pack_key: &[u8],
    sticker_id: u32,
) -> Result<Vec<u8>, Error<C::ContentsStoreError>> {
    let key = derive_key(pack_key)?;

    let mut sticker_stream = unidentified_websocket
        .get_sticker(&hex::encode(pack_id), sticker_id)
        .await?;

    let mut ciphertext = Vec::new();
    let size_bytes = sticker_stream.read_to_end(&mut ciphertext).await?;

    trace!(size_bytes, "downloaded encrypted sticker");

    decrypt_in_place(key, &mut ciphertext)?;

    Ok(ciphertext)
}

/// Save a message into the store.
/// Note that `override_thread` can be used to specify the thread the message will be stored in.
/// This is required when storing outgoing messages, as in this case the appropriate storage place cannot be derived from the message itself.
async fn save_message<S: Store>(
    store: &mut S,
    identified_websocket: &mut websocket::SignalWebSocket<websocket::Identified>,
    message: Content,
    override_thread: Option<Thread>,
) -> Result<(), Error<S::Error>> {
    // derive the thread from the message type. For sync group call_events,
    // the wire-format `conversation_id` is the 32-byte derived group_id; we
    // ask the store to translate it back to a Thread::Group via the master_key
    // index. Falls back to Thread::try_from for non-call content and for
    // unresolved/adhoc cases (which still land in sync-self for now).
    let thread = match override_thread {
        Some(t) => t,
        None => match crate::model::calls::resolve_call_thread(&message, store).await? {
            Some(t) => t,
            None => Thread::try_from(&message)?,
        },
    };

    // only save DataMessage and SynchronizeMessage (sent)
    let message = match message.body {
        ContentBody::DecryptionErrorMessage(e) => {
            warn!(error = ?e, "was asked to save a DecryptionErrorMessage; this should not happen");
            None
        }
        ContentBody::NullMessage(_) => Some(message),
        ContentBody::DataMessage(
            ref data_message @ DataMessage {
                ref profile_key, ..
            },
        )
        | ContentBody::SynchronizeMessage(SyncMessage {
            sent:
                Some(sync_message::Sent {
                    message:
                        Some(
                            ref data_message @ DataMessage {
                                ref profile_key, ..
                            },
                        ),
                    ..
                }),
            ..
        }) => {
            // update recipient profile key if changed
            if let Some(profile_key_bytes) = profile_key.clone().and_then(|p| p.try_into().ok()) {
                let sender = message.metadata.sender;
                let profile_key = ProfileKey::create(profile_key_bytes);
                debug!(sender = %sender.service_id_string(), "inserting profile key for");

                // Either:
                // - insert a new contact with the profile information
                // - update the contact if the profile key has changed
                // TODO: mark this contact as "created by us" maybe to know whether we should update it or not
                // NOTE: this needs to happen in the background!
                let store_inner = store.clone();
                let websocket_inner = identified_websocket.clone();
                let data_message_inner = data_message.clone();
                tokio::spawn(async move {
                    if let Err(error) = upsert_contact_from_profile(
                        store_inner,
                        websocket_inner,
                        &data_message_inner,
                        sender,
                        profile_key,
                    )
                    .await
                    {
                        error!(%error, "failed to upsert newly seen contact!");
                    }
                });
            }

            // Note: The expire timer fields of data messages are only for contacts.
            // Expire timers are handled for groups via upsert_group due to a revision change.
            if let Thread::Contact(_) = thread {
                let version = data_message.expire_timer_version.unwrap_or(1);
                store
                    .update_expire_timer(
                        &thread,
                        data_message.expire_timer.unwrap_or_default(),
                        version,
                    )
                    .await?;
            }

            match data_message {
                DataMessage {
                    delete:
                        Some(Delete {
                            target_sent_timestamp: Some(ts),
                        }),
                    ..
                } => {
                    // Soft-delete is handled by the app layer; preserve the original content.
                    if let Some(_existing_msg) = store.message(&thread, *ts).await? {
                        debug!(%thread, ts, "message in thread deleted (soft-delete handled by app)");
                        None
                    } else {
                        warn!(%thread, ts, "could not find message to delete in thread");
                        None
                    }
                }
                _ => Some(message),
            }
        }
        ContentBody::SynchronizeMessage(SyncMessage {
            delete_for_me: Some(ref delete),
            ..
        }) => {
            // TODO: Conversations, local-only deletes, attachments
            for d in delete.message_deletes.iter().flat_map(|m| &m.messages) {
                let sender = match &d.author {
                    Some(Author::AuthorServiceId(id)) => {
                        ServiceId::parse_from_service_id_string(id)
                    }
                    Some(Author::AuthorServiceIdBinary(id)) => {
                        ServiceId::parse_from_service_id_binary(id)
                    }
                    Some(Author::AuthorE164(_)) => None,
                    None => None,
                };
                let Some(sender) = sender else {
                    tracing::warn!("Could not parse author of delete-for-self message; ignoring.");
                    continue;
                };
                let Some(timestamp) = d.sent_timestamp else {
                    tracing::warn!("Timestamp of delete-for-self message not given; ignoring.");
                    continue;
                };
                let Ok(Some(thread)) = store
                    .thread_for_sender_and_timestamp(&sender, timestamp)
                    .await
                else {
                    tracing::warn!(
                        "Message referenced by delete-for-self message not found; ignoring."
                    );
                    continue;
                };
                // Note: Not marking the message as deleted, like when receiving deletion requests by others.
                // This matches the behavior of Signal Desktop, where the message completely disappears from the timeline.
                let result = store.delete_message(&thread, timestamp).await;
                if !result.is_ok_and(|d| d) {
                    tracing::warn!(
                        "Could not delete message referenced by delete-for-self message; ignoring."
                    );
                }
            }
            None
        }
        ContentBody::EditMessage(EditMessage {
            target_sent_timestamp: Some(ts),
            data_message: Some(data_message),
        })
        | ContentBody::SynchronizeMessage(SyncMessage {
            sent:
                Some(sync_message::Sent {
                    edit_message:
                        Some(EditMessage {
                            target_sent_timestamp: Some(ts),
                            data_message: Some(data_message),
                        }),
                    ..
                }),
            ..
        }) => {
            if let Some(mut existing_msg) = store.message(&thread, ts).await? {
                existing_msg.metadata = message.metadata;
                existing_msg.body = ContentBody::EditMessage(EditMessage {
                    target_sent_timestamp: Some(ts),
                    data_message: Some(data_message),
                });
                trace!(%thread, ts, "message in thread edited");
                Some(existing_msg)
            } else {
                warn!(%thread, ts, "could not find edited message");
                None
            }
        }
        ContentBody::CallMessage(_)
        | ContentBody::SynchronizeMessage(SyncMessage {
            call_event: Some(_),
            ..
        }) => Some(message),
        ContentBody::SynchronizeMessage(msg) => {
            debug!(
                ?msg,
                "skipping saving sync message without interesting fields"
            );
            None
        }
        ContentBody::ReceiptMessage(_) => Some(message),
        ContentBody::TypingMessage(msg) => {
            debug!(?msg, "skipping saving typing message");
            None
        }
        ContentBody::StoryMessage(msg) => {
            debug!(?msg, "skipping story message");
            None
        }
        ContentBody::PniSignatureMessage(msg) => {
            debug!(?msg, "skipping PNI signature message");
            None
        }
        ContentBody::EditMessage(msg) => {
            debug!(?msg, "invalid edited");
            None
        }
    };

    if let Some(message) = message {
        store.save_message(&thread, message).await?;
    }

    Ok(())
}

async fn upsert_contact_from_profile<S: Store>(
    mut store: S,
    mut identified_websocket: SignalWebSocket<websocket::Identified>,
    data_message: &DataMessage,
    sender: ServiceId,
    profile_key: ProfileKey,
) -> Result<(), Error<<S as Store>::Error>> {
    let existing_contact = store.contact_by_id(&sender).await?;
    if existing_contact.is_none()
        || store
            .profile_key(&sender)
            .await?
            .is_none_or(|p| p.bytes != profile_key.bytes)
    {
        if let Some(aci) = sender.aci() {
            let sender_uuid: Uuid = aci.into();
            let encrypted_profile = identified_websocket
                .retrieve_profile_by_id(aci, Some(profile_key))
                .await?;
            let profile_cipher = ProfileCipher::new(profile_key);
            let decrypted_profile = profile_cipher.decrypt(encrypted_profile).unwrap();

            let mut contact = existing_contact.unwrap_or(Contact {
                uuid: sender_uuid,
                phone_number: None,
                name: String::new(),
                verified: Verified::default(),
                profile_key: Vec::new(),
                expire_timer: 0,
                expire_timer_version: 2,
                inbox_position: 0,
                avatar: None,
                pni: None,
                username: None,
                blocked: false,
                whitelisted: false,
                archived: false,
                marked_unread: false,
                muted_until_timestamp: 0,
                hide_story: false,
                hidden: false,
                unregistered_at_timestamp: 0,
                pni_signature_verified: false,
                system_given_name: String::new(),
                system_family_name: String::new(),
                system_nickname: String::new(),
                nickname_given_name: String::new(),
                nickname_family_name: String::new(),
                note: String::new(),
            });

            // A profile with no name says nothing about what this contact is called:
            // the profile name proper lives in `signal_profiles` (written by
            // `save_profile` on the same fetch), and `Contact::name` is the weaker
            // fallback *below* it in display order. Blanking it on a nameless profile
            // dropped that fallback for nothing — the same reasoning as
            // `merge_contact_from_snapshot`, on the receive path instead of a sync.
            let fetched_name = decrypted_profile
                .name
                .map(|pn| pn.to_string())
                .unwrap_or_default();
            if !fetched_name.is_empty() {
                contact.name = fetched_name;
            }
            contact.profile_key = profile_key.bytes.to_vec();
            contact.expire_timer = data_message.expire_timer.unwrap_or_default();
            contact.expire_timer_version = merged_expire_timer_version(
                data_message.expire_timer_version,
                contact.expire_timer_version,
            );

            info!(%sender_uuid, "saved contact on first sight");

            store.save_contact(&contact).await?;
            store.upsert_profile_key(&sender_uuid, profile_key).await?;
        } else {
            debug!("not storing profile for PNI contact");
        }
    }
    Ok(())
}

async fn set_account_attributes<S: Store>(
    account_manager: &mut AccountManager,
    store: &S,
    data: &RegistrationData,
) -> Result<(), Error<S::Error>> {
    trace!("setting account attributes");

    let pni_registration_id = data.pni_registration_id.ok_or(Error::RelinkNecessary)?;

    let name = if let Some(device_name) = data.device_name() {
        let aci_key_pair = store.aci_protocol_store().get_identity_key_pair().await?;
        let mut rng = rng();
        Some(encrypt_device_name(
            &mut rng,
            device_name,
            aci_key_pair.identity_key(),
        )?)
    } else {
        None
    };

    account_manager
        .set_account_attributes(AccountAttributes {
            fetches_messages: true,
            registration_id: data.registration_id,
            pni_registration_id,
            name,
            registration_lock: None,
            unidentified_access_key: Some(data.profile_key.derive_access_key().to_vec()),
            unrestricted_unidentified_access: false,
            capabilities: Some(DeviceCapabilities {
                storage: true,
                transfer: false,
                attachment_backfill: false,
                spqr: true,
                profiles_v2: false,
                username_change_sync_message: true,
            }),
            discoverable_by_phone_number: true,
            voice: false,
            video: false,
            recovery_password: None,
        })
        .await?;

    trace!("done setting account attributes");
    Ok(())
}

async fn register_pre_keys<S: Store>(
    store: &S,
    account_manager: &mut AccountManager,
) -> Result<(), Error<S::Error>> {
    trace!("registering pre keys");

    account_manager
        .update_pre_key_bundle(&mut store.aci_protocol_store(), ServiceIdKind::Aci, true)
        .await?;

    account_manager
        .update_pre_key_bundle(&mut store.pni_protocol_store(), ServiceIdKind::Pni, true)
        .await?;

    trace!("registered pre keys");
    Ok(())
}

/// Maximum number of storage-service keys to request in a single `ReadOperation`.
/// Signal Desktop uses 2500; the server's hard limit is ~5120.
const STORAGE_SERVICE_BATCH_SIZE: usize = 2500;

/// Parse a [`Contact`]'s raw profile-key bytes into a [`ProfileKey`].
///
/// The field is a `Vec<u8>` that is legitimately empty — `Contact::minimal` and a
/// `ContactRecord` carrying no key both produce one — so anything that isn't exactly
/// 32 bytes is treated as absent.
fn contact_profile_key(contact: &Contact) -> Option<ProfileKey> {
    <[u8; 32]>::try_from(contact.profile_key.as_slice())
        .ok()
        .map(ProfileKey::create)
}

/// The `expire_timer_version` to keep after a first-sight profile fetch: the incoming one
/// when it is newer, otherwise whatever is already stored. Never lower than `stored`.
///
/// `Store::update_expire_timer` resolves conflicts with `version <= current_version`, so
/// writing a smaller number here lets a stale update win later. Signal-Desktop hands the
/// incoming version straight to its version-gated setter (`handleDataMessage`) rather than
/// substituting a default; presage defaulted an absent version to 1, which downgraded every
/// contact whose stored version had already moved past it.
fn merged_expire_timer_version(incoming: Option<u32>, stored: u32) -> u32 {
    match incoming {
        Some(incoming) => incoming.max(stored),
        None => stored,
    }
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
fn merge_contact_from_snapshot(contact: &mut Contact, existing: Contact) -> Vec<&'static str> {
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
    preserved
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
    let storage_service =
        StorageService::new(push_service.clone(), storage_key).await?;

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
                        merge_contact_from_snapshot(&mut contact, existing);
                    }
                    if let Err(e) = store.save_contact(&contact).await {
                        warn!(%e, "storage sync: failed to save contact");
                    }
                    // Remember where this record lives so it can be updated later. The
                    // plaintext is stored as read: an update edits these bytes rather
                    // than re-encoding a lossy `Contact`.
                    let identity = ContactStorageIdentity {
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
                    let master_key: libsignal_service::zkgroup::GroupMasterKeyBytes =
                        match gr.master_key.as_slice().try_into() {
                            Ok(mk) => mk,
                            Err(_) => {
                                warn!("storage sync: invalid group master key length, skipping");
                                continue;
                            }
                        };
                    let group = match store.group(master_key).await {
                        Ok(Some(mut existing)) => {
                            // Preserve locally-derived fields; update storage-service-owned fields
                            existing.blocked = gr.blocked;
                            existing.whitelisted = gr.whitelisted;
                            existing.archived = gr.archived;
                            existing.marked_unread = gr.marked_unread;
                            existing.muted_until_timestamp = gr.muted_until_timestamp;
                            existing.dont_notify_for_mentions_if_muted =
                                gr.dont_notify_for_mentions_if_muted;
                            existing.hide_story = gr.hide_story;
                            existing.story_send_mode = gr.story_send_mode.into();
                            existing
                        }
                        _ => {
                            debug!("storage sync: saving group stub");
                            Group {
                                title: None,
                                avatar: None,
                                disappearing_messages_timer: None,
                                access_control: None,
                                revision: 0,
                                members: Vec::new(),
                                pending_members: Vec::new(),
                                requesting_members: Vec::new(),
                                invite_link_password: Vec::new(),
                                description: None,
                                needs_hydration: true,
                                blocked: gr.blocked,
                                whitelisted: gr.whitelisted,
                                archived: gr.archived,
                                marked_unread: gr.marked_unread,
                                muted_until_timestamp: gr.muted_until_timestamp,
                                dont_notify_for_mentions_if_muted: gr
                                    .dont_notify_for_mentions_if_muted,
                                hide_story: gr.hide_story,
                                story_send_mode: gr.story_send_mode.into(),
                            }
                        }
                    };
                    if let Err(e) = store.save_group(master_key, group).await {
                        warn!(%e, "storage sync: failed to save group");
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

    #[test]
    fn empty_record_does_not_wipe_local_fields() {
        let mut incoming = empty_record_contact();
        let preserved = merge_contact_from_snapshot(&mut incoming, stored_contact());

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

        let preserved = merge_contact_from_snapshot(&mut incoming, stored_contact());

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

        merge_contact_from_snapshot(&mut incoming, stored_contact());

        assert_eq!(incoming.expire_timer, 3600);
        assert_eq!(incoming.expire_timer_version, 9);
        assert_eq!(incoming.inbox_position, 5);
        assert!(incoming.avatar.is_none());
    }

    #[test]
    fn nothing_is_preserved_when_the_store_is_also_empty() {
        let mut incoming = empty_record_contact();
        let preserved = merge_contact_from_snapshot(&mut incoming, empty_record_contact());

        assert!(preserved.is_empty());
        assert!(incoming.name.is_empty());
    }

    #[test]
    fn newer_expire_timer_version_wins() {
        assert_eq!(merged_expire_timer_version(Some(9), 4), 9);
    }

    #[test]
    fn stale_expire_timer_version_is_ignored() {
        // The downgrade that broke `update_expire_timer`'s `version <= current_version`
        // conflict resolution: a later stale update would have been accepted over this.
        assert_eq!(merged_expire_timer_version(Some(2), 7), 7);
    }

    #[test]
    fn absent_expire_timer_version_leaves_the_stored_one() {
        // Previously defaulted to 1, clobbering whatever the contact had reached.
        assert_eq!(merged_expire_timer_version(None, 7), 7);
    }
}
