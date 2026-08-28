use std::borrow::Cow;

use libsignal_service::prelude::MessageSenderError;
use libsignal_service::protocol::UsernameError;
use libsignal_service::websocket::registration::RegistrationSessionMetadataResponse;
use libsignal_service::{models::ParseContactError, protocol::SignalProtocolError};

use crate::store::{StoreError, ThreadError};

/// The error type of Signal manager
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error<S: std::error::Error> {
    #[error("captcha from https://signalcaptchas.org/registration/generate.html required")]
    CaptchaRequired,
    #[error("input/output error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("error decoding base64 data: {0}")]
    Base64Error(#[from] base64::DecodeError),
    #[error("wrong slice size: {0}")]
    TryFromSliceError(#[from] std::array::TryFromSliceError),
    #[error("phone number parsing error: {0}")]
    PhoneNumberError(#[from] libsignal_service::prelude::phonenumber::ParseError),
    #[error("UUID decoding error: {0}")]
    UuidError(#[from] libsignal_service::prelude::UuidError),
    #[error("Invalid thread: {0}")]
    InvalidThread(#[from] ThreadError),
    #[error("libsignal-protocol error: {0}")]
    ProtocolError(#[from] SignalProtocolError),
    #[error("libsignal-service error: {0}")]
    ServiceError(#[from] libsignal_service::prelude::ServiceError),
    #[error("storage service error: {0}")]
    StorageServiceError(#[from] libsignal_service::StorageServiceError),
    #[error("libsignal-service error: {0}")]
    ProfileManagerError(#[from] libsignal_service::ProfileManagerError),
    #[error("profile key credential error: {0}")]
    ProfileCredentialError(#[from] libsignal_service::ProfileCredentialError),
    #[error("group encoding/decoding error: {0}")]
    GroupDecodingError(#[from] libsignal_service::groups_v2::GroupDecodingError),
    /// Another device kept winning the race to write the storage manifest. Distinct from a
    /// transport failure: the write was well-formed, we just never got a turn.
    #[error("gave up writing the storage manifest after repeated version conflicts")]
    StorageManifestConflict,
    /// The identifier we believed a record lived under is no longer in the manifest, so the
    /// copy we hold is stale: another device rewrote that record under a new identifier.
    /// Recoverable by re-syncing and rebuilding the edit from what comes back.
    #[error("storage record is no longer at the identifier we hold")]
    StorageRecordMoved,
    /// We have never read this contact's storage record, so there is nothing to edit. Not a
    /// failure on its own — the caller decides between syncing first and writing a new record.
    #[error("no storage record stored for this contact")]
    StorageRecordUnknown,
    #[error("could not edit stored storage record: {0}")]
    StorageRecordEdit(#[from] crate::storage_record::StorageRecordEditError),
    #[error("libsignal-service sending error: {0}")]
    MessageSenderError(Box<MessageSenderError>),
    #[error("this client is already registered with Signal")]
    AlreadyRegisteredError,
    #[error("this client is not yet registered, please register or link as a secondary device")]
    NotYetRegisteredError,
    #[error("failed to provision device: {0}")]
    ProvisioningError(#[from] libsignal_service::provisioning::ProvisioningError),
    #[error("no provisioning message received")]
    NoProvisioningMessageReceived,
    #[error("qr code error")]
    LinkingError,
    #[error("please relink your client")]
    RelinkNecessary,
    #[error("missing key {0} in config DB")]
    MissingKeyError(Cow<'static, str>),
    #[error("message pipe not started, you need to start receiving messages before you can send anything back")]
    MessagePipeNotStarted,
    #[error("receiving pipe was interrupted")]
    MessagePipeInterruptedError,
    #[error("failed to parse contact information: {0}")]
    ParseContactError(#[from] ParseContactError),
    #[error("failed to decrypt attachment: {0}")]
    AttachmentCipherError(#[from] libsignal_service::attachment_cipher::AttachmentCipherError),
    #[error("unknown group")]
    UnknownGroup,
    #[error("group update carries no change")]
    EmptyGroupUpdate,
    #[error("group membership update carries no change")]
    EmptyGroupMembersUpdate,
    #[error("this account is not in the group")]
    NotAGroupMember,
    #[error("leaving would leave the group without an administrator; promote someone first")]
    LastAdminMustPromote,
    #[error("unknown recipient")]
    UnknownRecipient,
    #[error("timeout: {0}")]
    Timeout(#[from] tokio::time::error::Elapsed),
    #[error("store error: {0}")]
    Store(S),
    #[error("push challenge required (not implemented)")]
    PushChallengeRequired,
    #[error("Not allowed to request verification code, reason unknown: {0:?}")]
    RequestingCodeForbidden(RegistrationSessionMetadataResponse),
    #[error("attachment sha256 checksum did not match")]
    UnexpectedAttachmentChecksum,
    #[error("Unverified registration session (i.e. wrong verification code)")]
    UnverifiedRegistrationSession,
    #[error("profile cipher error")]
    ProfileCipherError(#[from] libsignal_service::profile_cipher::ProfileCipherError),
    #[error("An operation was requested that requires the registration to be primary, but it was only secondary")]
    NotPrimaryDevice,
    #[error("Failed to get initial messages after uploading pre-keys")]
    UpdatePreKeyFailure,
    #[error("invalid device ID (out of bounds)")]
    InvalidDeviceId,
    #[error("invalid Signal username: {0}")]
    InvalidUsername(#[from] UsernameError),
    #[error("primary device requested re-link during backup transfer")]
    BackupRelinkRequested,
    #[error("backup import failed: {0}")]
    BackupImportFailed(String),
}

impl<S: std::error::Error> From<MessageSenderError> for Error<S> {
    fn from(v: MessageSenderError) -> Self {
        Self::MessageSenderError(Box::new(v))
    }
}

impl<S: StoreError> From<S> for Error<S> {
    fn from(e: S) -> Self {
        Self::Store(e)
    }
}
