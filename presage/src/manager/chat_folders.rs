//! Chat folders: the local half of create, edit and delete.
//!
//! The shape is the mute path's: the local write and the storage-sync mark are
//! one step, publishing is
//! [`push_pending_chat_folder_records`](Manager::push_pending_chat_folder_records),
//! and there is no sync message because Signal has none for folders — the
//! storage service is the only cross-device channel, and every manifest write
//! already nudges the other devices via `FetchLatest`.

use libsignal_service::prelude::Uuid;

use crate::model::chat_folders::{ChatFolder, ChatFolderType};
use crate::store::Store;
use crate::{Error, Manager};

use super::Registered;

impl<S: Store> Manager<S, Registered> {
    /// Live folders in position order, the all-chats folder included.
    pub async fn chat_folders(&self) -> Result<Vec<ChatFolder>, Error<S::Error>> {
        let mut folders: Vec<ChatFolder> = self
            .store
            .chat_folders()
            .await?
            .into_iter()
            .filter(|f| f.is_live() && f.folder_type != ChatFolderType::Unknown)
            .collect();
        folders.sort_by_key(|f| f.position);
        Ok(folders)
    }

    /// Create or replace a folder and mark it for publishing.
    ///
    /// A new folder takes the next position; an existing one keeps the position
    /// it has, so an edit never reorders the list. The name is normalized the
    /// way Signal-Desktop does before it is validated.
    pub async fn save_chat_folder(&mut self, mut folder: ChatFolder) -> Result<(), Error<S::Error>> {
        if folder.folder_type == ChatFolderType::Custom {
            folder.name = ChatFolder::normalized_name(&folder.name);
            if !ChatFolder::is_valid_name(&folder.name) {
                return Err(Error::ChatFolderInvalidName);
            }
        }
        match self.store.chat_folder(folder.id).await? {
            Some(existing) => folder.position = existing.position,
            None => folder.position = self.chat_folders().await?.len() as u32,
        }
        self.store.save_chat_folder(&folder).await?;
        self.store
            .set_chat_folder_needs_storage_sync(folder.id, true)
            .await?;
        Ok(())
    }

    /// Signal-Desktop's `deleteChatFolder`: tombstone the record so every other
    /// device drops it, then renumber the live folders from 0 and flag each one.
    /// The tombstone itself expires from the manifest after thirty days, in
    /// [`push_pending_chat_folder_records`](Self::push_pending_chat_folder_records).
    pub async fn delete_chat_folder(&mut self, id: Uuid) -> Result<(), Error<S::Error>> {
        let mut folder = self
            .store
            .chat_folder(id)
            .await?
            .ok_or(Error::ChatFolderUnknown)?;
        if folder.folder_type == ChatFolderType::All {
            return Err(Error::ChatFolderUndeletable);
        }
        folder.tombstone(chrono::Utc::now().timestamp_millis() as u64);
        self.store.save_chat_folder(&folder).await?;
        self.store
            .set_chat_folder_needs_storage_sync(id, true)
            .await?;
        self.renumber_chat_folders().await
    }

    async fn renumber_chat_folders(&mut self) -> Result<(), Error<S::Error>> {
        for (i, mut folder) in self.chat_folders().await?.into_iter().enumerate() {
            if folder.position == i as u32 {
                continue;
            }
            folder.position = i as u32;
            self.store.save_chat_folder(&folder).await?;
            self.store
                .set_chat_folder_needs_storage_sync(folder.id, true)
                .await?;
        }
        Ok(())
    }
}
