//! Chat folders as the storage service holds them.
//!
//! A folder is a `ChatFolderRecord`: a name, a position, four rule flags and
//! two recipient lists. This module is the model half; the sync and publish
//! halves live in [`crate::manager::storage`], and the byte-level encoding in
//! [`crate::storage_record`].

use libsignal_service::{
    prelude::Uuid,
    proto::{self, chat_folder_record::FolderType, recipient},
    protocol::ServiceId,
    zkgroup::GroupMasterKeyBytes,
};
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;
use unicode_segmentation::UnicodeSegmentation;

/// `ChatFolderRecord.position` on a tombstone, from `StorageService.proto`:
/// "when `deletedAtTimestampMs` is non-zero, `position` should be set to
/// 4294967295 (2^32-1)".
pub const CHAT_FOLDER_DELETED_POSITION: u32 = u32::MAX;

/// Signal-Desktop's `CHAT_FOLDER_NAME_MAX_CHAR_LENGTH`, counted in graphemes.
pub const CHAT_FOLDER_NAME_MAX_GRAPHEMES: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChatFolderType {
    Unknown,
    /// The one "All chats" folder every account carries. Its name and rules are
    /// fixed — see [`ChatFolder::all_chats`] — and it cannot be deleted.
    All,
    Custom,
}

impl From<FolderType> for ChatFolderType {
    fn from(t: FolderType) -> Self {
        match t {
            FolderType::Unknown => Self::Unknown,
            FolderType::All => Self::All,
            FolderType::Custom => Self::Custom,
        }
    }
}

impl From<ChatFolderType> for FolderType {
    fn from(t: ChatFolderType) -> Self {
        match t {
            ChatFolderType::Unknown => Self::Unknown,
            ChatFolderType::All => Self::All,
            ChatFolderType::Custom => Self::Custom,
        }
    }
}

/// One entry of `includedRecipients` / `excludedRecipients`.
///
/// Kept as the identifiers the record carries rather than resolved to a local
/// row, so a recipient this device has never met still round-trips intact.
/// Signal-Desktop drops those on merge and loses them from the folder on its
/// next upload; keeping them costs nothing here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FolderRecipient {
    Contact {
        /// `Recipient.Contact.serviceId` in its string form (`ACI` bare, `PNI:`
        /// prefixed), when the record carried one that parses.
        service_id: Option<String>,
        e164: Option<String>,
    },
    GroupMasterKey(GroupMasterKeyBytes),
    LegacyGroupId(Vec<u8>),
}

impl FolderRecipient {
    pub fn contact(service_id: ServiceId) -> Self {
        Self::Contact {
            service_id: Some(service_id.service_id_string()),
            e164: None,
        }
    }

    pub fn service_id(&self) -> Option<ServiceId> {
        match self {
            Self::Contact { service_id, .. } => service_id
                .as_deref()
                .and_then(ServiceId::parse_from_service_id_string),
            _ => None,
        }
    }

    /// `None` for an identifier variant this build does not know.
    pub fn from_proto(r: proto::Recipient) -> Option<Self> {
        match r.identifier? {
            recipient::Identifier::Contact(c) => {
                let service_id = ServiceId::parse_from_service_id_binary(&c.service_id_binary)
                    .or_else(|| ServiceId::parse_from_service_id_string(&c.service_id))
                    .map(|s| s.service_id_string());
                let e164 = (!c.e164.is_empty()).then_some(c.e164);
                Some(Self::Contact { service_id, e164 })
            }
            recipient::Identifier::LegacyGroupId(id) => Some(Self::LegacyGroupId(id)),
            recipient::Identifier::GroupMasterKey(key) => {
                Some(Self::GroupMasterKey(key.as_slice().try_into().ok()?))
            }
        }
    }

    pub fn to_proto(&self) -> proto::Recipient {
        let identifier = match self {
            Self::Contact { service_id, e164 } => {
                let parsed = service_id
                    .as_deref()
                    .and_then(ServiceId::parse_from_service_id_string);
                recipient::Identifier::Contact(recipient::Contact {
                    service_id: parsed
                        .map(|s| s.service_id_string())
                        .unwrap_or_default(),
                    e164: e164.clone().unwrap_or_default(),
                    service_id_binary: parsed.map(|s| s.service_id_binary()).unwrap_or_default(),
                })
            }
            Self::LegacyGroupId(id) => recipient::Identifier::LegacyGroupId(id.clone()),
            Self::GroupMasterKey(key) => recipient::Identifier::GroupMasterKey(key.to_vec()),
        };
        proto::Recipient {
            identifier: Some(identifier),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatFolder {
    /// `ChatFolderRecord.identifier`, 16 bytes. Also the local primary key.
    pub id: Uuid,
    pub folder_type: ChatFolderType,
    pub name: String,
    pub position: u32,
    pub show_only_unread: bool,
    pub show_muted_chats: bool,
    pub include_all_individual_chats: bool,
    pub include_all_group_chats: bool,
    pub included_recipients: Vec<FolderRecipient>,
    pub excluded_recipients: Vec<FolderRecipient>,
    /// `0` is live; anything else is a tombstone other devices must honour.
    pub deleted_at_timestamp_ms: u64,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ChatFolderRecordError {
    #[error("chat folder record has no 16-byte identifier")]
    MissingIdentifier,
}

impl ChatFolder {
    pub fn is_live(&self) -> bool {
        self.deleted_at_timestamp_ms == 0
    }

    /// Signal-Desktop's `ALL_CHATS_FOLDER_REQUIRED_PARAMS`.
    pub fn all_chats(id: Uuid) -> Self {
        Self {
            id,
            folder_type: ChatFolderType::All,
            name: String::new(),
            position: 0,
            show_only_unread: false,
            show_muted_chats: true,
            include_all_individual_chats: true,
            include_all_group_chats: true,
            included_recipients: Vec::new(),
            excluded_recipients: Vec::new(),
            deleted_at_timestamp_ms: 0,
        }
    }

    /// A custom folder with Signal-Desktop's `CHAT_FOLDER_DEFAULTS` and the
    /// given name. Callers fill in rules and recipients; `position` is
    /// assigned on save.
    pub fn custom(id: Uuid, name: impl Into<String>) -> Self {
        Self {
            id,
            folder_type: ChatFolderType::Custom,
            name: name.into(),
            position: 0,
            show_only_unread: false,
            show_muted_chats: true,
            include_all_individual_chats: false,
            include_all_group_chats: false,
            included_recipients: Vec::new(),
            excluded_recipients: Vec::new(),
            deleted_at_timestamp_ms: 0,
        }
    }

    /// Signal-Desktop's `markChatFolderDeleted`: the record stays in the
    /// manifest as a tombstone, stripped of everything but its identity.
    pub fn tombstone(&mut self, deleted_at_ms: u64) {
        self.deleted_at_timestamp_ms = deleted_at_ms;
        self.position = CHAT_FOLDER_DELETED_POSITION;
        self.included_recipients.clear();
        self.excluded_recipients.clear();
    }

    /// Signal-Desktop's `ChatFolderParamsSchema` name transform: NFC, trimmed.
    pub fn normalized_name(name: &str) -> String {
        name.nfc().collect::<String>().trim().to_owned()
    }

    /// Signal-Desktop's `validateChatFolderParams`, on an already-normalized name.
    pub fn is_valid_name(name: &str) -> bool {
        !name.is_empty() && name.graphemes(true).count() <= CHAT_FOLDER_NAME_MAX_GRAPHEMES
    }

    pub fn to_record(&self) -> proto::ChatFolderRecord {
        proto::ChatFolderRecord {
            identifier: self.id.as_bytes().to_vec(),
            name: self.name.clone(),
            position: self.position,
            show_only_unread: self.show_only_unread,
            show_muted_chats: self.show_muted_chats,
            include_all_individual_chats: self.include_all_individual_chats,
            include_all_group_chats: self.include_all_group_chats,
            folder_type: FolderType::from(self.folder_type).into(),
            included_recipients: self
                .included_recipients
                .iter()
                .map(FolderRecipient::to_proto)
                .collect(),
            excluded_recipients: self
                .excluded_recipients
                .iter()
                .map(FolderRecipient::to_proto)
                .collect(),
            deleted_at_timestamp_ms: self.deleted_at_timestamp_ms,
        }
    }
}

impl TryFrom<proto::ChatFolderRecord> for ChatFolder {
    type Error = ChatFolderRecordError;

    /// A record without a 16-byte identifier is unaddressable and is dropped,
    /// as Signal-Desktop does. Every other field takes its proto3 default when
    /// absent, so a record from a client that predates `showMutedChats` reads
    /// as "hide muted", exactly as it does on Desktop.
    fn try_from(r: proto::ChatFolderRecord) -> Result<Self, Self::Error> {
        let id = Uuid::from_slice(&r.identifier).map_err(|_| ChatFolderRecordError::MissingIdentifier)?;
        let folder_type = r.folder_type().into();
        Ok(Self {
            id,
            folder_type,
            name: r.name,
            position: r.position,
            show_only_unread: r.show_only_unread,
            show_muted_chats: r.show_muted_chats,
            include_all_individual_chats: r.include_all_individual_chats,
            include_all_group_chats: r.include_all_group_chats,
            included_recipients: r
                .included_recipients
                .into_iter()
                .filter_map(FolderRecipient::from_proto)
                .collect(),
            excluded_recipients: r
                .excluded_recipients
                .into_iter()
                .filter_map(FolderRecipient::from_proto)
                .collect(),
            deleted_at_timestamp_ms: r.deleted_at_timestamp_ms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn folder() -> ChatFolder {
        let mut f = ChatFolder::custom(Uuid::from_u128(42), "Work");
        f.position = 3;
        f.show_only_unread = true;
        f.include_all_group_chats = true;
        f.included_recipients = vec![
            FolderRecipient::contact(ServiceId::Aci(Uuid::from_u128(7).into())),
            FolderRecipient::GroupMasterKey([9u8; 32]),
        ];
        f.excluded_recipients = vec![FolderRecipient::Contact {
            service_id: None,
            e164: Some("+15555550123".into()),
        }];
        f
    }

    #[test]
    fn record_round_trips() {
        let original = folder();
        let back = ChatFolder::try_from(original.to_record()).expect("has an identifier");
        assert_eq!(back, original);
    }

    #[test]
    fn a_contact_recipient_writes_both_service_id_forms() {
        let aci = ServiceId::Aci(Uuid::from_u128(7).into());
        let proto = FolderRecipient::contact(aci).to_proto();
        let Some(recipient::Identifier::Contact(c)) = proto.identifier else {
            panic!("not a contact");
        };
        assert_eq!(c.service_id, aci.service_id_string());
        assert_eq!(c.service_id_binary, aci.service_id_binary());
    }

    #[test]
    fn a_record_without_an_identifier_is_dropped() {
        let mut r = folder().to_record();
        r.identifier = vec![1, 2, 3];
        assert_eq!(
            ChatFolder::try_from(r),
            Err(ChatFolderRecordError::MissingIdentifier)
        );
    }

    #[test]
    fn a_tombstone_keeps_only_its_identity() {
        let mut f = folder();
        f.tombstone(1_000);
        assert_eq!(f.deleted_at_timestamp_ms, 1_000);
        assert_eq!(f.position, CHAT_FOLDER_DELETED_POSITION);
        assert!(f.included_recipients.is_empty());
        assert!(f.excluded_recipients.is_empty());
        assert_eq!(f.name, "Work");
    }

    #[test]
    fn names_are_counted_in_graphemes() {
        assert!(ChatFolder::is_valid_name(&"👨‍👩‍👧‍👦".repeat(32)));
        assert!(!ChatFolder::is_valid_name(&"a".repeat(33)));
        assert!(!ChatFolder::is_valid_name(""));
        assert_eq!(ChatFolder::normalized_name("  Work \u{0301} "), "Work \u{0301}".nfc().collect::<String>().trim().to_owned());
    }
}
