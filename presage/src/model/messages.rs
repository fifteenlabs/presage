use libsignal_service::{
    prelude::Content,
    protocol::{CiphertextMessageType, DeviceId, ServiceId},
};

#[derive(Debug)]
pub enum Received {
    /// when the receive loop is empty, happens when opening the websocket for the first time
    /// once you're done synchronizing all pending messages for this registered client.
    QueueEmpty,

    /// Got contacts (only applies if linked to a primary device
    /// Contacts can be later queried in the store.
    Contacts,

    /// We failed to decrypt a message from the specified service ID.
    ///
    /// Carries what a retry receipt needs: the failed message's timestamp, the
    /// sending device, and the original ciphertext with its type. The type is
    /// what distinguishes the two repairs — `Whisper`/`PreKey` mean the 1:1
    /// session is broken and must be archived, `SenderKey` means the group's
    /// sender key must be redistributed — and libsignal derives that from the
    /// ciphertext, so both cases travel the same way.
    ///
    /// `original` is absent when decryption failed before the payload was
    /// reached, in which case no receipt can be built.
    DecryptionError {
        sender: ServiceId,
        sender_device: DeviceId,
        timestamp: u64,
        original: Option<(CiphertextMessageType, Vec<u8>)>,
    },

    /// A peer failed to decrypt a message *we* sent, and told us so with a
    /// `DecryptionErrorMessage`.
    ///
    /// The opposite of [`Received::DecryptionError`]: the repair here is to
    /// resend to them, never to ask them to resend to us.
    PeerDecryptionError { sender: ServiceId },

    /// Incoming decrypted message with metadata and content
    Content(Box<Content>),

    /// The identified websocket closed. Carries the typed reason so the client
    /// can classify the drop (unlink / connected-elsewhere / transient) and
    /// decide whether to reconnect. Yielded once, as the final stream item.
    Disconnected(libsignal_service::websocket::DisconnectReason),
}
