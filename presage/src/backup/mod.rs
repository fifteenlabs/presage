pub mod convert;

pub use libsignal_service::proto::backup::{
    frame::Item as FrameItem, Chat, ChatItem, Frame, Recipient, StandardMessage,
};

#[derive(Debug, Clone)]
pub enum BackupImportProgress {
    WaitingForUpload,
    Downloading {
        bytes_received: u64,
        total: Option<u64>,
    },
    Processing,
    Done,
}
