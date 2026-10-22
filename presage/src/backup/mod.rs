pub mod convert;
mod group_change;

use std::io;
use std::path::Path;

use futures::AsyncRead;
use libsignal_service::backup::{
    FileReaderFactory, FramesReader, MessageBackupKey, VarintDelimitedReader,
};

pub use libsignal_service::proto::backup::{
    frame::Item as FrameItem, Chat, ChatItem, Frame, Recipient,
};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TransferArchive {
    pub cdn: u32,
    pub key: String,
    #[serde(default = "random_backup_path")]
    pub path: std::path::PathBuf,
}

#[derive(Debug, Clone)]
pub enum BackupImportProgress {
    WaitingForUpload,
    Downloading { bytes_received: u64, total: u64 },
    Processing,
    Done,
}

pub(crate) fn random_backup_path() -> std::path::PathBuf {
    use rand::RngCore;
    let id = rand::rng().next_u64();
    std::env::temp_dir().join(format!("signal-backup-{id:016x}.bin"))
}

/// A Backups v2 file's frames, read in order after its `BackupInfo` header.
pub(crate) struct BackupFrames<R: AsyncRead + Unpin> {
    reader: VarintDelimitedReader<R>,
}

/// Opens and authenticates the backup at `path`, and reads past its header:
/// the first record of a backup is a `BackupInfo`, not a `Frame`.
pub(crate) async fn open_frames(
    path: &Path,
    key: &MessageBackupKey,
) -> io::Result<BackupFrames<impl AsyncRead + Unpin>> {
    let factory = FileReaderFactory {
        path: path.to_owned(),
    };
    let frames = FramesReader::new(key, factory)
        .await
        .map_err(io::Error::other)?;
    let mut reader = VarintDelimitedReader::new(frames);
    reader
        .read_next()
        .await?
        .ok_or_else(|| io::Error::other("backup has no BackupInfo header"))?;
    Ok(BackupFrames { reader })
}

impl<R: AsyncRead + Unpin> BackupFrames<R> {
    pub(crate) async fn next(&mut self) -> io::Result<Option<Frame>> {
        let Some(bytes) = self.reader.read_next().await? else {
            return Ok(None);
        };
        Frame::decode_bytes(bytes.as_ref())
            .map(Some)
            .map_err(io::Error::other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libsignal_service::libsignal_account_keys::{AccountEntropyPool, BackupKey};
    use libsignal_service::protocol::Aci;

    /// A real encrypted backup from libsignal's own fixtures
    /// (`rust/message-backup/tests/res/test-cases/valid-encrypted`, v0.99.0),
    /// under the key those tests derive. Its source is the `.source.jsonproto`
    /// beside it.
    #[tokio::test]
    async fn a_backup_file_reads_as_its_frames_after_the_header() {
        let pool: AccountEntropyPool = "m".repeat(64).parse().expect("valid pool");
        let backup_key = BackupKey::derive_from_account_entropy_pool(&pool);
        let aci = Aci::from_uuid_bytes([0x11; 16]);
        let key = MessageBackupKey::derive(&backup_key, &backup_key.derive_backup_id(&aci), None);
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/res/legacy-account.binproto.encrypted");

        let mut frames = open_frames(&path, &key).await.expect("opens");
        let mut kinds = Vec::new();
        while let Some(frame) = frames.next().await.expect("decodes") {
            kinds.push(match frame.item {
                Some(FrameItem::Account(_)) => "account",
                Some(FrameItem::Recipient(_)) => "recipient",
                Some(FrameItem::Chat(_)) => "chat",
                _ => "other",
            });
        }
        assert_eq!(kinds, ["account", "recipient", "chat"]);
    }
}
