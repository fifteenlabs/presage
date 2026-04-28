pub mod convert;

pub use libsignal_service::proto::backup::{
    frame::Item as FrameItem, Chat, ChatItem, Frame, Recipient, StandardMessage,
};

pub(crate) fn random_backup_path() -> std::path::PathBuf {
    use rand::RngCore;
    let id = rand::rng().next_u64();
    std::env::temp_dir().join(format!("signal-backup-{id:016x}.bin"))
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TransferArchive {
    pub cdn: u32,
    pub key: String,
    /// Random path generated once per link attempt; ensures a re-link never
    /// resumes from a previous device's partial download.
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
