use std::collections::HashMap;

use libsignal_service::{
    content::{Content, ContentBody, Metadata},
    proto::{sync_message, DataMessage, SyncMessage},
    protocol::{Aci, ServiceId},
    push_service::DEFAULT_DEVICE_ID,
};

use super::{ChatItem, Recipient};
use crate::store::Thread;

pub struct RecipientInfo {
    pub service_id: Option<ServiceId>,
    pub group_master_key: Option<[u8; 32]>,
}

pub fn recipient_info(r: &Recipient) -> Option<(u64, RecipientInfo)> {
    use libsignal_service::proto::backup::recipient::Destination;
    let info = match r.destination.as_ref()? {
        Destination::Contact(c) => RecipientInfo {
            service_id: c
                .aci
                .as_ref()
                .and_then(|b| b.as_slice().try_into().ok())
                .map(|bytes: [u8; 16]| ServiceId::Aci(Aci::from_uuid_bytes(bytes))),
            group_master_key: None,
        },
        Destination::Group(g) if g.master_key.len() == 32 => RecipientInfo {
            service_id: None,
            group_master_key: g.master_key.as_slice().try_into().ok(),
        },
        _ => return None,
    };
    Some((r.id, info))
}

pub fn chat_to_thread(
    chat: &libsignal_service::proto::backup::Chat,
    recipients: &HashMap<u64, RecipientInfo>,
) -> Option<(u64, Thread)> {
    let ri = recipients.get(&chat.recipient_id)?;
    let thread = if let Some(key) = ri.group_master_key {
        Thread::Group(key)
    } else {
        Thread::Contact(ri.service_id?)
    };
    Some((chat.id, thread))
}

pub fn chat_item_to_content(
    item: &ChatItem,
    recipients: &HashMap<u64, RecipientInfo>,
    chats: &HashMap<u64, Thread>,
    our_aci: Aci,
) -> Option<(Content, Thread)> {
    use libsignal_service::proto::backup::{
        chat_item::{DirectionalDetails, Item},
        StandardMessage, Text,
    };

    let thread = chats.get(&item.chat_id)?.clone();
    let text = match item.item.as_ref()? {
        Item::StandardMessage(StandardMessage {
            text: Some(Text { body, .. }),
            ..
        }) => body.clone(),
        _ => return None,
    };
    let timestamp = item.date_sent;

    let (body, sender, destination) = match item.directional_details.as_ref()? {
        DirectionalDetails::Incoming(_) => {
            let sender = recipients.get(&item.author_id)?.service_id?;
            let data = DataMessage {
                body: Some(text),
                timestamp: Some(timestamp),
                ..Default::default()
            };
            (
                ContentBody::DataMessage(data),
                sender,
                ServiceId::Aci(our_aci),
            )
        }
        DirectionalDetails::Outgoing(_) => {
            let dest_str = match &thread {
                Thread::Contact(sid) => Some(sid.service_id_string()),
                Thread::Group(_) => None,
            };
            let destination = match &thread {
                Thread::Contact(sid) => *sid,
                Thread::Group(_) => ServiceId::Aci(our_aci),
            };
            let data = DataMessage {
                body: Some(text),
                timestamp: Some(timestamp),
                ..Default::default()
            };
            let sent = sync_message::Sent {
                destination_service_id: dest_str,
                timestamp: Some(timestamp),
                message: Some(data),
                ..Default::default()
            };
            let sync = SyncMessage {
                sent: Some(sent),
                ..Default::default()
            };
            (
                ContentBody::SynchronizeMessage(sync),
                ServiceId::Aci(our_aci),
                destination,
            )
        }
        DirectionalDetails::Directionless(_) => return None,
    };

    Some((
        Content {
            metadata: Metadata {
                sender,
                destination,
                sender_device: *DEFAULT_DEVICE_ID,
                server_guid: None,
                timestamp,
                needs_receipt: false,
                unidentified_sender: false,
                was_plaintext: false,
            },
            body,
        },
        thread,
    ))
}
