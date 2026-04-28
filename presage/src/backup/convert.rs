use std::collections::HashMap;

use libsignal_service::{
    content::{Content, ContentBody, Metadata},
    prelude::Uuid,
    proto::{
        attachment_pointer::{AttachmentIdentifier, Flags as AttachPointerFlags},
        backup::{
            self,
            chat_item::{DirectionalDetails, Item},
            file_pointer::locator_info::IntegrityCheck,
            message_attachment::Flag as AttachmentFlag,
        },
        data_message, sync_message, AttachmentPointer, DataMessage, Preview, SyncMessage,
    },
    protocol::{Aci, ServiceId},
    push_service::DEFAULT_DEVICE_ID,
    ServiceIdExt,
};

use super::ChatItem;
use crate::store::Thread;

/// Resolved identity of a backup recipient — either a contact's ACI or a group's master key.
pub struct RecipientInfo {
    pub service_id: Option<ServiceId>,
    pub group_master_key: Option<[u8; 32]>,
}

/// Extracts the identity of a backup `Recipient`, returning `(recipient_id, info)` or `None`
/// for unsupported destination types (e.g. distribution lists, release notes channel).
pub fn recipient_info(r: &backup::Recipient, our_aci: Aci) -> Option<(u64, RecipientInfo)> {
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
        Destination::Self_(_) => RecipientInfo {
            service_id: Some(ServiceId::Aci(our_aci)),
            group_master_key: None,
        },
        _ => return None,
    };
    Some((r.id, info))
}

/// Maps a backup `Chat` to a presage `Thread`, returning `(chat_id, thread)` or `None`
/// if the chat's recipient hasn't been resolved yet (e.g. unsupported destination type).
pub fn chat_to_thread(
    chat: &backup::Chat,
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

/// Converts a backup `FilePointer` (CDN-hosted attachment) to a wire-format `AttachmentPointer`.
/// Returns `None` if no transit CDN location is available (local-only backup attachment).
fn file_pointer_to_attachment_pointer(
    fp: &backup::FilePointer,
    flags: Option<u32>,
) -> Option<AttachmentPointer> {
    let locator = fp.locator_info.as_ref()?;
    let cdn_key = locator.transit_cdn_key.clone()?;

    let digest = match &locator.integrity_check {
        Some(IntegrityCheck::EncryptedDigest(d)) => Some(d.clone()),
        Some(IntegrityCheck::PlaintextHash(_)) | None => None,
    };

    let key = if locator.key.is_empty() {
        None
    } else {
        Some(locator.key.clone())
    };

    Some(AttachmentPointer {
        attachment_identifier: Some(AttachmentIdentifier::CdnKey(cdn_key)),
        cdn_number: locator.transit_cdn_number,
        content_type: fp.content_type.clone(),
        key,
        size: Some(locator.size),
        digest,
        file_name: fp.file_name.clone(),
        flags,
        width: fp.width,
        height: fp.height,
        caption: fp.caption.clone(),
        blur_hash: fp.blur_hash.clone(),
        upload_timestamp: locator.transit_tier_upload_timestamp,
        incremental_mac: fp.incremental_mac.clone(),
        chunk_size: fp.incremental_mac_chunk_size,
        ..Default::default()
    })
}

/// Converts a `MessageAttachment` to a wire-format `AttachmentPointer`, mapping backup flag
/// values to their wire equivalents (they differ — e.g. backup Gif = 3, wire Gif = 8).
fn message_attachment_to_pointer(ma: &backup::MessageAttachment) -> Option<AttachmentPointer> {
    let fp = ma.pointer.as_ref()?;
    // Backup Gif = 3, wire Gif = 8 — values differ, so we map explicitly.
    let flags = match AttachmentFlag::try_from(ma.flag).unwrap_or(AttachmentFlag::None) {
        AttachmentFlag::None => None,
        AttachmentFlag::VoiceMessage => Some(AttachPointerFlags::VoiceMessage as u32),
        AttachmentFlag::Borderless => Some(AttachPointerFlags::Borderless as u32),
        AttachmentFlag::Gif => Some(AttachPointerFlags::Gif as u32),
    };
    file_pointer_to_attachment_pointer(fp, flags)
}

/// Converts a backup `Quote` to a wire-format `DataMessage::Quote`. Returns `None` if the
/// quoted author can't be resolved to an ACI (required by the wire format).
fn backup_quote_to_dm_quote(
    q: &backup::Quote,
    recipients: &HashMap<u64, RecipientInfo>,
) -> Option<data_message::Quote> {
    let author_aci = recipients.get(&q.author_id)?.service_id?.aci()?;
    let author_aci_bytes = Into::<Uuid>::into(author_aci).into_bytes();

    let dm_type = match q.r#type() {
        backup::quote::Type::GiftBadge => data_message::quote::Type::GiftBadge as i32,
        backup::quote::Type::Poll => data_message::quote::Type::Poll as i32,
        _ => data_message::quote::Type::Normal as i32,
    };

    Some(data_message::Quote {
        id: q.target_sent_timestamp,
        author_aci: Some(author_aci.service_id_string()),
        author_aci_binary: Some(author_aci_bytes.to_vec()),
        text: q.text.as_ref().map(|t| t.body.clone()),
        r#type: Some(dm_type),
        ..Default::default()
    })
}

/// Converts a backup `LinkPreview` to a wire-format `Preview`, resolving the thumbnail image
/// via `file_pointer_to_attachment_pointer` (returns `None` image if not CDN-hosted).
fn backup_link_preview_to_preview(lp: &backup::LinkPreview) -> Preview {
    Preview {
        url: Some(lp.url.clone()),
        title: lp.title.clone(),
        image: lp
            .image
            .as_ref()
            .and_then(|fp| file_pointer_to_attachment_pointer(fp, None)),
        description: lp.description.clone(),
        date: lp.date,
    }
}

/// Converts a backup `Sticker` to a wire-format `DataMessage::Sticker`.
fn backup_sticker_to_dm_sticker(s: &backup::Sticker) -> data_message::Sticker {
    data_message::Sticker {
        pack_id: Some(s.pack_id.clone()),
        pack_key: Some(s.pack_key.clone()),
        sticker_id: Some(s.sticker_id),
        data: s
            .data
            .as_ref()
            .and_then(|fp| file_pointer_to_attachment_pointer(fp, None)),
        emoji: s.emoji.clone(),
    }
}

/// Converts backup reactions (stored as a list on the parent message) into individual
/// `Content` objects matching Signal's wire format, where each reaction is its own envelope.
fn reactions_to_contents(
    reactions: &[backup::Reaction],
    parent_item: &ChatItem,
    recipients: &HashMap<u64, RecipientInfo>,
    thread: &Thread,
    our_aci: Aci,
) -> Vec<(Content, Thread)> {
    let parent_author_aci = recipients
        .get(&parent_item.author_id)
        .and_then(|r| r.service_id)
        .and_then(|s| s.aci())
        .unwrap_or(our_aci);
    let parent_author_aci_bytes = Into::<Uuid>::into(parent_author_aci).into_bytes();

    reactions
        .iter()
        .filter_map(|reaction| {
            let author_service_id = recipients.get(&reaction.author_id)?.service_id?;
            let is_outgoing = author_service_id.aci() == Some(our_aci);

            let dm_reaction = DataMessage {
                reaction: Some(data_message::Reaction {
                    emoji: Some(reaction.emoji.clone()),
                    remove: Some(false),
                    target_author_aci: Some(parent_author_aci.service_id_string()),
                    target_author_aci_binary: Some(parent_author_aci_bytes.to_vec()),
                    target_sent_timestamp: Some(parent_item.date_sent),
                }),
                timestamp: Some(reaction.sent_timestamp),
                ..Default::default()
            };

            let (body, sender, destination) = if is_outgoing {
                let dest_str = match thread {
                    Thread::Contact(sid) => Some(sid.service_id_string()),
                    Thread::Group(_) => None,
                };
                let destination = match thread {
                    Thread::Contact(sid) => *sid,
                    Thread::Group(_) => ServiceId::Aci(our_aci),
                };
                let sent = sync_message::Sent {
                    destination_service_id: dest_str,
                    timestamp: Some(reaction.sent_timestamp),
                    message: Some(dm_reaction),
                    ..Default::default()
                };
                (
                    ContentBody::SynchronizeMessage(SyncMessage {
                        sent: Some(sent),
                        ..Default::default()
                    }),
                    ServiceId::Aci(our_aci),
                    destination,
                )
            } else {
                (
                    ContentBody::DataMessage(dm_reaction),
                    author_service_id,
                    ServiceId::Aci(our_aci),
                )
            };

            Some((
                Content {
                    metadata: Metadata {
                        sender,
                        destination,
                        sender_device: *DEFAULT_DEVICE_ID,
                        server_guid: None,
                        timestamp: reaction.sent_timestamp,
                        needs_receipt: false,
                        unidentified_sender: false,
                        was_plaintext: false,
                    },
                    body,
                },
                thread.clone(),
            ))
        })
        .collect()
}

/// Converts a single backup `ChatItem` into zero or more `(Content, Thread)` pairs.
///
/// Returns the main message first, followed by one entry per reaction (each reconstructed
/// as its own `DataMessage::reaction` envelope, matching Signal's wire format).
pub fn chat_item_to_contents(
    item: &ChatItem,
    recipients: &HashMap<u64, RecipientInfo>,
    chats: &HashMap<u64, Thread>,
    our_aci: Aci,
) -> Vec<(Content, Thread)> {
    let Some(thread) = chats.get(&item.chat_id).cloned() else {
        return vec![];
    };
    let timestamp = item.date_sent;

    let is_outgoing = match item.directional_details.as_ref() {
        Some(DirectionalDetails::Outgoing(_)) => true,
        Some(DirectionalDetails::Incoming(_)) => false,
        _ => return vec![],
    };

    let incoming_sender = if !is_outgoing {
        match recipients.get(&item.author_id).and_then(|r| r.service_id) {
            Some(s) => Some(s),
            None => return vec![],
        }
    } else {
        None
    };

    let (dm, reactions): (DataMessage, &[backup::Reaction]) = match item.item.as_ref() {
        Some(Item::StandardMessage(sm)) => {
            let dm = DataMessage {
                body: sm.text.as_ref().map(|t| t.body.clone()),
                attachments: sm
                    .attachments
                    .iter()
                    .filter_map(message_attachment_to_pointer)
                    .collect(),
                quote: sm
                    .quote
                    .as_ref()
                    .and_then(|q| backup_quote_to_dm_quote(q, recipients)),
                preview: sm
                    .link_preview
                    .iter()
                    .map(backup_link_preview_to_preview)
                    .collect(),
                timestamp: Some(timestamp),
                ..Default::default()
            };
            (dm, &sm.reactions)
        }
        Some(Item::StickerMessage(sm)) => {
            let dm = DataMessage {
                sticker: sm.sticker.as_ref().map(backup_sticker_to_dm_sticker),
                timestamp: Some(timestamp),
                ..Default::default()
            };
            (dm, &sm.reactions)
        }
        _ => return vec![],
    };

    let (body, sender, destination) = if is_outgoing {
        let dest_str = match &thread {
            Thread::Contact(sid) => Some(sid.service_id_string()),
            Thread::Group(_) => None,
        };
        let destination = match &thread {
            Thread::Contact(sid) => *sid,
            Thread::Group(_) => ServiceId::Aci(our_aci),
        };
        let sent = sync_message::Sent {
            destination_service_id: dest_str,
            timestamp: Some(timestamp),
            message: Some(dm),
            ..Default::default()
        };
        (
            ContentBody::SynchronizeMessage(SyncMessage {
                sent: Some(sent),
                ..Default::default()
            }),
            ServiceId::Aci(our_aci),
            destination,
        )
    } else {
        (
            ContentBody::DataMessage(dm),
            incoming_sender.expect("checked above"),
            ServiceId::Aci(our_aci),
        )
    };

    let main_content = Content {
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
    };

    let mut results = vec![(main_content, thread.clone())];
    results.extend(reactions_to_contents(
        reactions, item, recipients, &thread, our_aci,
    ));
    results
}
