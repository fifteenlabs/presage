//! Account-wide state from the storage service's `AccountRecord`.
//!
//! The record holds far more than presage models: profile, payments, backup
//! settings and more. Two parts are read here. [`AccountChatState`] decides
//! how the chat list looks: which chats are pinned, whether Note to Self is
//! archived, and whether a muted chat stays archived when a message arrives.
//! [`AccountSettings`] is the privacy a linked device can honour and change.
//! Publishing edits those fields in the stored record bytes (see
//! [`crate::storage_record`]); the record is never rebuilt from either.

use libsignal_service::prelude::ProtobufMessage;
use libsignal_service::proto::account_record::{
    pinned_conversation, PinnedConversation as PinnedConversationProto,
};
use libsignal_service::protocol::ServiceId;

use crate::storage_record::{
    account_keep_muted_chats_archived, account_note_to_self_archived, account_phone_number_sharing,
    account_pinned_conversations, account_read_receipts, account_story_view_receipts,
    account_typing_indicators, account_unlisted_phone_number, StorageRecordEditError,
};
use crate::store::Thread;

/// One `AccountRecord.pinnedConversations` entry, kept as the bytes the record
/// carried.
///
/// Signal-Desktop resolves every entry to a conversation and drops the ones it
/// cannot, so its next upload unpins them on every device. Keeping the bytes
/// means an entry this build cannot map to a [`Thread`] — the release-notes
/// chat, a legacy group, a contact known only by phone number — round-trips
/// untouched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedConversation(Vec<u8>);

impl PinnedConversation {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// A new entry for `thread`. A contact carries its service id in both the
    /// string and the binary form, so clients that read either find it.
    pub fn for_thread(thread: &Thread) -> Self {
        let identifier = match thread {
            Thread::Contact(service_id) => {
                pinned_conversation::Identifier::Contact(pinned_conversation::Contact {
                    service_id: service_id.service_id_string(),
                    e164: String::new(),
                    service_id_binary: service_id.service_id_binary(),
                })
            }
            Thread::Group(master_key) => {
                pinned_conversation::Identifier::GroupMasterKey(master_key.to_vec())
            }
        };
        Self(
            PinnedConversationProto {
                identifier: Some(identifier),
            }
            .encode_to_vec(),
        )
    }

    /// The chat this entry pins, or `None` for one presage has no thread for.
    /// The binary service id wins over the string form, as on Signal-Desktop.
    pub fn thread(&self) -> Option<Thread> {
        match PinnedConversationProto::decode(self.0.as_slice())
            .ok()?
            .identifier?
        {
            pinned_conversation::Identifier::Contact(contact) => {
                ServiceId::parse_from_service_id_binary(&contact.service_id_binary)
                    .or_else(|| ServiceId::parse_from_service_id_string(&contact.service_id))
                    .map(Thread::Contact)
            }
            pinned_conversation::Identifier::GroupMasterKey(key) => {
                key.as_slice().try_into().ok().map(Thread::Group)
            }
            pinned_conversation::Identifier::LegacyGroupId(_)
            | pinned_conversation::Identifier::ReleaseNotes(_) => None,
        }
    }
}

/// The chat-list part of the `AccountRecord`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccountChatState {
    /// `noteToSelfArchived`. Note to Self has no `ContactRecord` of its own, so
    /// its archive state lives here.
    pub note_to_self_archived: bool,
    /// `keepMutedChatsArchived`: an archived chat that is muted stays archived
    /// when a message arrives. Never edited here, only read.
    pub keep_muted_chats_archived: bool,
    /// `pinnedConversations`, in pin order.
    pub pinned: Vec<PinnedConversation>,
}

impl AccountChatState {
    /// What an encoded `StorageRecord { account }` says.
    pub fn from_record(record: &[u8]) -> Result<Self, StorageRecordEditError> {
        Ok(Self {
            note_to_self_archived: account_note_to_self_archived(record)?,
            keep_muted_chats_archived: account_keep_muted_chats_archived(record)?,
            pinned: account_pinned_conversations(record)?,
        })
    }

    /// The pinned chats presage has a thread for, in pin order.
    pub fn pinned_threads(&self) -> impl Iterator<Item = Thread> + '_ {
        self.pinned.iter().filter_map(PinnedConversation::thread)
    }

    pub fn is_pinned(&self, thread: &Thread) -> bool {
        self.pinned_threads().any(|pinned| &pinned == thread)
    }

    /// Pin `thread` after the chats already pinned, unless it already is.
    pub fn pin(&mut self, thread: &Thread) {
        if !self.is_pinned(thread) {
            self.pinned.push(PinnedConversation::for_thread(thread));
        }
    }

    /// Unpin `thread`, leaving every other entry as it was.
    pub fn unpin(&mut self, thread: &Thread) {
        self.pinned
            .retain(|entry| entry.thread().as_ref() != Some(thread));
    }
}

/// The account's privacy settings that every device shares, as the
/// `AccountRecord` holds them.
///
/// Only settings a linked device can both honour and change. The registration
/// lock and sealed sender from anyone also live on the account, but only the
/// primary may set them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountSettings {
    /// `readReceipts`. Off, no read or viewed receipt is sent, and none
    /// received is shown.
    pub read_receipts: bool,
    /// `typingIndicators`. Off, no typing indicator is sent, and none
    /// received is shown.
    pub typing_indicators: bool,
    /// "Who can see my number" is everybody: `phoneNumberSharingMode` is
    /// `EVERYBODY`. Contacts' clients read our profile's copy of this flag.
    pub phone_number_sharing: bool,
    /// "Who can find me by number" is everybody: `unlistedPhoneNumber` is
    /// unset. The chat server keeps its own copy, which is what the
    /// contact-discovery service consults.
    pub discoverable_by_phone_number: bool,
    /// Whether viewing a story sends its author a viewed receipt. The story
    /// settings' own `storyViewReceiptsEnabled` when set, and read receipts
    /// otherwise, as Signal-Desktop's `areStoryViewReceiptsEnabled` resolves
    /// it. Read only: the story settings are not offered here.
    pub story_view_receipts: bool,
}

impl AccountSettings {
    /// What an encoded `StorageRecord { account }` says.
    pub fn from_record(record: &[u8]) -> Result<Self, StorageRecordEditError> {
        let read_receipts = account_read_receipts(record)?;
        Ok(Self {
            read_receipts,
            typing_indicators: account_typing_indicators(record)?,
            phone_number_sharing: account_phone_number_sharing(record)?,
            discoverable_by_phone_number: !account_unlisted_phone_number(record)?,
            story_view_receipts: account_story_view_receipts(record)?.unwrap_or(read_receipts),
        })
    }
}

/// One change to [`AccountSettings`], for
/// [`Manager::update_account_setting`](crate::Manager::update_account_setting).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountSetting {
    ReadReceipts(bool),
    TypingIndicators(bool),
    /// Share the number with everybody (`true`) or nobody.
    PhoneNumberSharing(bool),
    /// Let everybody (`true`) or nobody find the account by its number.
    DiscoverableByPhoneNumber(bool),
}

#[cfg(test)]
mod tests {
    use libsignal_service::prelude::Uuid;
    use libsignal_service::protocol::Aci;

    use super::*;

    fn contact(n: u128) -> Thread {
        Thread::Contact(ServiceId::Aci(Aci::from(Uuid::from_u128(n))))
    }

    fn release_notes() -> PinnedConversation {
        PinnedConversation::from_bytes(
            PinnedConversationProto {
                identifier: Some(pinned_conversation::Identifier::ReleaseNotes(
                    pinned_conversation::ReleaseNotes {},
                )),
            }
            .encode_to_vec(),
        )
    }

    #[test]
    fn a_new_entry_reads_back_as_its_thread() {
        for thread in [contact(1), Thread::Group([9u8; 32])] {
            assert_eq!(
                PinnedConversation::for_thread(&thread).thread(),
                Some(thread)
            );
        }
    }

    #[test]
    fn a_contact_known_only_by_its_string_service_id_still_resolves() {
        let thread = contact(2);
        let Thread::Contact(service_id) = &thread else {
            unreachable!()
        };
        let entry = PinnedConversation::from_bytes(
            PinnedConversationProto {
                identifier: Some(pinned_conversation::Identifier::Contact(
                    pinned_conversation::Contact {
                        service_id: service_id.service_id_string(),
                        ..Default::default()
                    },
                )),
            }
            .encode_to_vec(),
        );
        assert_eq!(entry.thread(), Some(thread));
    }

    #[test]
    fn pinning_appends_and_unpinning_keeps_the_entries_it_cannot_read() {
        let mut state = AccountChatState {
            pinned: vec![release_notes()],
            ..Default::default()
        };

        state.pin(&contact(1));
        state.pin(&contact(1));
        state.pin(&Thread::Group([3u8; 32]));
        assert_eq!(
            state.pinned_threads().collect::<Vec<_>>(),
            vec![contact(1), Thread::Group([3u8; 32])],
            "pinning twice pins once"
        );

        state.unpin(&contact(1));
        state.unpin(&contact(1));
        assert_eq!(
            state.pinned,
            vec![
                release_notes(),
                PinnedConversation::for_thread(&Thread::Group([3u8; 32]))
            ]
        );
    }

    #[test]
    fn an_account_that_never_chose_is_findable_and_shares_nothing() {
        use libsignal_service::proto::{storage_record::Record, AccountRecord, StorageRecord};

        let record = StorageRecord {
            record: Some(Record::Account(AccountRecord::default())),
        }
        .encode_to_vec();
        assert_eq!(
            AccountSettings::from_record(&record).unwrap(),
            AccountSettings {
                read_receipts: false,
                typing_indicators: false,
                phone_number_sharing: false,
                discoverable_by_phone_number: true,
                story_view_receipts: false,
            }
        );
    }

    #[test]
    fn story_view_receipts_follow_read_receipts_until_set() {
        use libsignal_service::proto::{
            storage_record::Record, AccountRecord, OptionalBool, StorageRecord,
        };

        let settings = |read_receipts, story: OptionalBool| {
            let record = StorageRecord {
                record: Some(Record::Account(AccountRecord {
                    read_receipts,
                    story_view_receipts_enabled: story.into(),
                    ..Default::default()
                })),
            }
            .encode_to_vec();
            AccountSettings::from_record(&record)
                .unwrap()
                .story_view_receipts
        };
        assert!(settings(true, OptionalBool::Unset));
        assert!(!settings(false, OptionalBool::Unset));
        assert!(settings(false, OptionalBool::Enabled));
        assert!(!settings(true, OptionalBool::Disabled));
    }
}
