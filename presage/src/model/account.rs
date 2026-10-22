//! Account-wide chat state from the storage service's `AccountRecord`.
//!
//! The record holds far more than this — profile, privacy, payments, backup
//! settings — and presage models none of it. [`AccountChatState`] is only the
//! part that decides how the chat list looks: which chats are pinned, whether
//! Note to Self is archived, and whether a muted chat stays archived when a
//! message arrives. Publishing edits those fields in the stored record bytes
//! (see [`crate::storage_record`]); the record is never rebuilt from this.

use libsignal_service::prelude::ProtobufMessage;
use libsignal_service::proto::account_record::{
    pinned_conversation, PinnedConversation as PinnedConversationProto,
};
use libsignal_service::protocol::ServiceId;

use crate::storage_record::{
    account_keep_muted_chats_archived, account_note_to_self_archived, account_pinned_conversations,
    StorageRecordEditError,
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

    /// Pin `thread` after the chats already pinned. `false` if it already was.
    pub fn pin(&mut self, thread: &Thread) -> bool {
        if self.is_pinned(thread) {
            return false;
        }
        self.pinned.push(PinnedConversation::for_thread(thread));
        true
    }

    /// Unpin `thread`, leaving every other entry as it was. `false` if it was
    /// not pinned.
    pub fn unpin(&mut self, thread: &Thread) -> bool {
        let before = self.pinned.len();
        self.pinned
            .retain(|entry| entry.thread().as_ref() != Some(thread));
        self.pinned.len() != before
    }
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

        assert!(state.pin(&contact(1)));
        assert!(!state.pin(&contact(1)), "already pinned");
        assert!(state.pin(&Thread::Group([3u8; 32])));
        assert_eq!(
            state.pinned_threads().collect::<Vec<_>>(),
            vec![contact(1), Thread::Group([3u8; 32])]
        );

        assert!(state.unpin(&contact(1)));
        assert!(!state.unpin(&contact(1)), "already unpinned");
        assert_eq!(
            state.pinned,
            vec![
                release_notes(),
                PinnedConversation::for_thread(&Thread::Group([3u8; 32]))
            ]
        );
    }
}
