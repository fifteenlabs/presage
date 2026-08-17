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
        body_range::AssociatedValue,
        data_message, sync_message, AttachmentPointer, BodyRange, DataMessage, Preview,
        SyncMessage,
    },
    protocol::{Aci, ServiceId},
    push_service::DEFAULT_DEVICE_ID,
    ServiceIdExt,
};

use super::ChatItem;
use crate::store::{BackupSendStatus, Thread};

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

/// Converts a backup `Text`'s body ranges — @-mentions and text styles — to their
/// wire form. Without this the body keeps its U+FFFC placeholder per mention but
/// loses the target, so imported history renders a blank gap where the `@Name`
/// should be.
///
/// Backup makes `start`/`length` required and carries the mentioned ACI as raw
/// bytes, where the wire form has them optional and takes those bytes as-is in its
/// binary field. The `Style` values are identical. A range with no associated value
/// is dropped, as the backup spec requires.
fn backup_body_ranges_to_wire(text: Option<&backup::Text>) -> Vec<BodyRange> {
    let Some(text) = text else {
        return Vec::new();
    };
    text.body_ranges
        .iter()
        .filter_map(|br| {
            let associated_value = match br.associated_value.as_ref()? {
                backup::body_range::AssociatedValue::MentionAci(aci) => {
                    AssociatedValue::MentionAciBinary(aci.clone())
                }
                backup::body_range::AssociatedValue::Style(style) => AssociatedValue::Style(*style),
            };
            Some(BodyRange {
                start: Some(br.start),
                length: Some(br.length),
                associated_value: Some(associated_value),
            })
        })
        .collect()
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
        body_ranges: backup_body_ranges_to_wire(q.text.as_ref()),
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
                        content: Some(sync_message::Content::Sent(sent)),
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
                        client_timestamp: chrono::DateTime::from_timestamp_millis(
                            reaction.sent_timestamp as i64,
                        )
                        .unwrap_or_default(),
                        server_timestamp: chrono::DateTime::from_timestamp_millis(
                            reaction.sent_timestamp as i64,
                        )
                        .unwrap_or_default(),
                        needs_receipt: false,
                        unidentified_sender: false,
                        was_plaintext: false,
                        report_spam_token: None,
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
///
/// Pure dispatcher: each item kind has its own helper. `SimpleUpdate`
/// block/unblock rows are reconstructed into `MessageRequestResponse` sync
/// Contents; unknown item kinds and other `UpdateMessage` sub-variants drop
/// silently (empty vec).
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

    match item.item.as_ref() {
        Some(Item::StandardMessage(sm)) => {
            standard_message_to_contents(sm, item, &thread, recipients, our_aci, timestamp)
        }
        Some(Item::StickerMessage(sm)) => {
            sticker_message_to_contents(sm, item, &thread, recipients, our_aci, timestamp)
        }
        Some(Item::UpdateMessage(cu)) => match cu.update.as_ref() {
            Some(backup::chat_update_message::Update::IndividualCall(_)) => {
                individual_call_to_contents(cu, &thread, our_aci, timestamp)
            }
            Some(backup::chat_update_message::Update::GroupCall(_)) => {
                group_call_to_contents(cu, &thread, recipients, our_aci, timestamp)
            }
            Some(backup::chat_update_message::Update::SimpleUpdate(_)) => {
                simple_update_to_contents(cu, &thread, our_aci, timestamp)
            }
            _ => vec![],
        },
        _ => vec![],
    }
}

/// Restored state for a backup message row that the wire `Content` cannot
/// carry: read state, per-recipient send status, and when the message reached
/// the device that made the backup.
pub struct BackupMessageState {
    pub thread: Thread,
    /// The message's sent timestamp — how the row is addressed.
    pub ts: u64,
    /// `Some` for incoming rows, `None` for outgoing.
    pub read: Option<bool>,
    pub send_states: Vec<(String, BackupSendStatus, u64)>,
    /// `dateReceived` from the backup: when the exporting device learned of this
    /// message. Restoring it keeps imported history in the order the primary
    /// device showed it, rather than re-deriving an order from send timestamps.
    /// `None` when the backup omitted it.
    pub date_received: Option<u64>,
}

/// Extract read / per-recipient send state and arrival time from a backup
/// `ChatItem` so the store can restore them after the row is saved — the wire
/// `Content` the converter produces carries none of it. Returns `None` when the
/// chat is unknown or directional details are absent.
pub fn chat_item_backup_state(
    item: &ChatItem,
    recipients: &HashMap<u64, RecipientInfo>,
    chats: &HashMap<u64, Thread>,
) -> Option<BackupMessageState> {
    let thread = chats.get(&item.chat_id).cloned()?;
    let ts = item.date_sent;
    match item.directional_details.as_ref()? {
        DirectionalDetails::Incoming(inc) => Some(BackupMessageState {
            thread,
            ts,
            read: Some(inc.read),
            send_states: Vec::new(),
            date_received: Some(inc.date_received),
        }),
        DirectionalDetails::Outgoing(out) => {
            let send_states = out
                .send_status
                .iter()
                .filter_map(|s| {
                    let recipient = recipients
                        .get(&s.recipient_id)
                        .and_then(|r| r.service_id)
                        .map(|sid| sid.service_id_string())?;
                    let status = match s.delivery_status.as_ref()? {
                        backup::send_status::DeliveryStatus::Sent(_) => BackupSendStatus::Sent,
                        backup::send_status::DeliveryStatus::Delivered(_) => {
                            BackupSendStatus::Delivered
                        }
                        backup::send_status::DeliveryStatus::Read(_) => BackupSendStatus::Read,
                        backup::send_status::DeliveryStatus::Viewed(_) => BackupSendStatus::Viewed,
                        // Pending / Skipped / Failed → no tick (Sent fallback).
                        _ => return None,
                    };
                    Some((recipient, status, s.timestamp))
                })
                .collect();
            Some(BackupMessageState {
                thread,
                ts,
                read: None,
                send_states,
                date_received: Some(out.date_received),
            })
        }
        _ => None, // Directionless
    }
}

/// Build a `DataMessage` for a backup `StandardMessage` (text + attachments +
/// quote + link previews), then hand off to the shared envelope/reactions
/// wrapper.
fn standard_message_to_contents(
    sm: &backup::StandardMessage,
    item: &ChatItem,
    thread: &Thread,
    recipients: &HashMap<u64, RecipientInfo>,
    our_aci: Aci,
    timestamp: u64,
) -> Vec<(Content, Thread)> {
    let dm = DataMessage {
        body: sm.text.as_ref().map(|t| t.body.clone()),
        body_ranges: backup_body_ranges_to_wire(sm.text.as_ref()),
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
    wrap_dm_with_reactions(
        dm,
        &sm.reactions,
        item,
        thread,
        recipients,
        our_aci,
        timestamp,
    )
}

/// Build a `DataMessage` for a backup `StickerMessage`, then hand off to the
/// shared envelope/reactions wrapper.
fn sticker_message_to_contents(
    sm: &backup::StickerMessage,
    item: &ChatItem,
    thread: &Thread,
    recipients: &HashMap<u64, RecipientInfo>,
    our_aci: Aci,
    timestamp: u64,
) -> Vec<(Content, Thread)> {
    let dm = DataMessage {
        sticker: sm.sticker.as_ref().map(backup_sticker_to_dm_sticker),
        timestamp: Some(timestamp),
        ..Default::default()
    };
    wrap_dm_with_reactions(
        dm,
        &sm.reactions,
        item,
        thread,
        recipients,
        our_aci,
        timestamp,
    )
}

/// Wrap a `DataMessage` into a sync (outgoing) or direct (incoming) envelope,
/// then append per-reaction Contents. Returns `vec![]` for missing
/// directional details, or for incoming items whose author can't be resolved
/// to a ServiceId — same drop-cases as the original inline implementation.
fn wrap_dm_with_reactions(
    dm: DataMessage,
    reactions: &[backup::Reaction],
    item: &ChatItem,
    thread: &Thread,
    recipients: &HashMap<u64, RecipientInfo>,
    our_aci: Aci,
    timestamp: u64,
) -> Vec<(Content, Thread)> {
    let is_outgoing = match item.directional_details.as_ref() {
        Some(DirectionalDetails::Outgoing(_)) => true,
        Some(DirectionalDetails::Incoming(_)) => false,
        _ => return vec![],
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
            timestamp: Some(timestamp),
            message: Some(dm),
            ..Default::default()
        };
        (
            ContentBody::SynchronizeMessage(SyncMessage {
                content: Some(sync_message::Content::Sent(sent)),
                ..Default::default()
            }),
            ServiceId::Aci(our_aci),
            destination,
        )
    } else {
        let Some(sender) = recipients.get(&item.author_id).and_then(|r| r.service_id) else {
            return vec![];
        };
        (
            ContentBody::DataMessage(dm),
            sender,
            ServiceId::Aci(our_aci),
        )
    };

    let main_content = Content {
        metadata: Metadata {
            sender,
            destination,
            sender_device: *DEFAULT_DEVICE_ID,
            server_guid: None,
            client_timestamp: chrono::DateTime::from_timestamp_millis(timestamp as i64)
                .unwrap_or_default(),
            server_timestamp: chrono::DateTime::from_timestamp_millis(timestamp as i64)
                .unwrap_or_default(),
            needs_receipt: false,
            unidentified_sender: false,
            was_plaintext: false,
            report_spam_token: None,
        },
        body,
    };

    let mut results = vec![(main_content, thread.clone())];
    results.extend(reactions_to_contents(
        reactions, item, recipients, thread, our_aci,
    ));
    results
}

/// Convert a backup `ChatUpdateMessage` carrying an `IndividualCall` into a
/// synthetic sync `call_event` Content, so it flows through the normal
/// `save_message` path. Group/adhoc updates and non-call ChatUpdates return
/// empty — they require resolution that v1 doesn't provide.
fn individual_call_to_contents(
    cu: &backup::ChatUpdateMessage,
    thread: &Thread,
    our_aci: Aci,
    fallback_ts: u64,
) -> Vec<(Content, Thread)> {
    use backup::chat_update_message::Update;
    use backup::individual_call;
    use sync_message::call_event::{Direction as WireDir, Event as WireEvent, Type as WireType};

    let Some(Update::IndividualCall(call)) = cu.update.as_ref() else {
        return vec![];
    };

    // Only 1:1 calls are modelled. A non-Contact thread here would mean the
    // backup put an IndividualCall on a group chat — out of spec; drop.
    let Thread::Contact(peer) = thread else {
        return vec![];
    };
    let conv_id: Vec<u8> = peer.raw_uuid().as_bytes().to_vec();

    // Proto defaults follow the comments in Backup.proto:
    //   UNKNOWN_TYPE      → Audio
    //   UNKNOWN_DIRECTION → Incoming
    //   UNKNOWN_STATE     → Accepted
    let wire_type = match individual_call::Type::try_from(call.r#type) {
        Ok(individual_call::Type::VideoCall) => WireType::VideoCall,
        _ => WireType::AudioCall,
    };
    let wire_dir = match individual_call::Direction::try_from(call.direction) {
        Ok(individual_call::Direction::Outgoing) => WireDir::Outgoing,
        _ => WireDir::Incoming,
    };
    // The backup carries the final state, so we synthesise a single event that
    // collapses through `transition_call_history` to the right canonical
    // status: Accepted → Accepted; Missed / MissedNotificationProfile /
    // NotAccepted → NotAccepted (state machine resolves to `Missed`; the UI
    // layer applies the Missed/Declined label based on direction).
    let wire_event = match individual_call::State::try_from(call.state) {
        Ok(individual_call::State::Missed)
        | Ok(individual_call::State::MissedNotificationProfile)
        | Ok(individual_call::State::NotAccepted) => WireEvent::NotAccepted,
        _ => WireEvent::Accepted,
    };

    let call_ts = if call.started_call_timestamp != 0 {
        call.started_call_timestamp
    } else {
        fallback_ts
    };

    let call_event = sync_message::CallEvent {
        conversation_id: Some(conv_id),
        call_id: call.call_id,
        timestamp: Some(call_ts),
        r#type: Some(wire_type as i32),
        direction: Some(wire_dir as i32),
        event: Some(wire_event as i32),
    };

    let body = ContentBody::SynchronizeMessage(SyncMessage {
        content: Some(sync_message::Content::CallEvent(call_event)),
        ..Default::default()
    });

    let main_content = Content {
        metadata: Metadata {
            sender: ServiceId::Aci(our_aci),
            destination: ServiceId::Aci(our_aci),
            sender_device: *DEFAULT_DEVICE_ID,
            server_guid: None,
            client_timestamp: chrono::DateTime::from_timestamp_millis(call_ts as i64)
                .unwrap_or_default(),
            server_timestamp: chrono::DateTime::from_timestamp_millis(call_ts as i64)
                .unwrap_or_default(),
            needs_receipt: false,
            unidentified_sender: false,
            was_plaintext: false,
            report_spam_token: None,
        },
        body,
    };

    vec![(main_content, thread.clone())]
}

/// Convert a backup `ChatUpdateMessage` carrying a `SimpleChatUpdate` of type
/// `BLOCKED`/`UNBLOCKED` into the same `SyncMessage.message_request_response`
/// Content the app synthesises live, so it flows through `save_message` and is
/// rendered as a "You blocked/unblocked X" system row. Other `SimpleChatUpdate`
/// types (identity, spam-report, etc.) and non-Contact threads drop — block
/// history is 1:1-only, matching the rest of the block/unblock feature.
fn simple_update_to_contents(
    cu: &backup::ChatUpdateMessage,
    thread: &Thread,
    our_aci: Aci,
    timestamp: u64,
) -> Vec<(Content, Thread)> {
    use backup::chat_update_message::Update;
    use backup::simple_chat_update::Type as SimpleType;
    use sync_message::message_request_response::Type as MrrType;
    use sync_message::MessageRequestResponse;

    let Some(Update::SimpleUpdate(su)) = cu.update.as_ref() else {
        return vec![];
    };
    // Block/unblock rows live on the 1:1 chat with the blocked contact; a
    // SimpleUpdate on a group chat is out of scope (group blocking deferred).
    let Thread::Contact(peer) = thread else {
        return vec![];
    };
    let mrr_type = match su.r#type() {
        SimpleType::Blocked => MrrType::Block,
        SimpleType::Unblocked => MrrType::Accept,
        _ => return vec![],
    };

    let body = ContentBody::SynchronizeMessage(SyncMessage {
        content: Some(sync_message::Content::MessageRequestResponse(
            MessageRequestResponse {
                thread_aci_binary: Some(peer.raw_uuid().as_bytes().to_vec()),
                r#type: Some(mrr_type as i32),
                ..Default::default()
            },
        )),
        ..Default::default()
    });
    let ts = chrono::DateTime::from_timestamp_millis(timestamp as i64).unwrap_or_default();
    let main_content = Content {
        metadata: Metadata {
            sender: ServiceId::Aci(our_aci),
            destination: *peer,
            sender_device: *DEFAULT_DEVICE_ID,
            server_guid: None,
            client_timestamp: ts,
            server_timestamp: ts,
            needs_receipt: false,
            unidentified_sender: false,
            was_plaintext: false,
            report_spam_token: None,
        },
        body,
    };

    vec![(main_content, thread.clone())]
}

/// Convert a backup `ChatUpdateMessage` carrying a `GroupCall` into a synthetic
/// sync `call_event` Content, so it flows through the normal `save_message` +
/// `save_call_history` pipeline. The 8-variant backup `group_call::State`
/// collapses through the 4-value wire `Event` surface our state machine
/// consumes — same shape as `individual_call_to_contents`, but with
/// state→event and direction-derivation logic specific to groups.
fn group_call_to_contents(
    cu: &backup::ChatUpdateMessage,
    thread: &Thread,
    recipients: &HashMap<u64, RecipientInfo>,
    our_aci: Aci,
    fallback_ts: u64,
) -> Vec<(Content, Thread)> {
    use backup::chat_update_message::Update;
    use backup::group_call;
    use libsignal_service::zkgroup::groups::{GroupMasterKey, GroupSecretParams};
    use sync_message::call_event::{Direction as WireDir, Event as WireEvent, Type as WireType};

    let Some(Update::GroupCall(call)) = cu.update.as_ref() else {
        return vec![];
    };

    // Only group threads are modelled. A non-Group thread here would mean the
    // backup put a GroupCall on a 1:1 chat — out of spec; drop.
    let Thread::Group(master_key) = thread else {
        return vec![];
    };

    // conversation_id for a group call is the 32-byte derived group_id, not
    // the master_key. Derive it the same way live sync would emit it so the
    // downstream `resolve_call_peer` lookup matches.
    let group_id: [u8; 32] =
        GroupSecretParams::derive_from_master_key(GroupMasterKey::new(*master_key))
            .get_group_identifier();
    let conv_id: Vec<u8> = group_id.to_vec();

    let state = group_call::State::try_from(call.state).unwrap_or(group_call::State::Generic);

    // Direction: backup tells us who started the call. Compare the recipient's
    // ACI to ours. OUTGOING_RING implies us regardless (the state alone is
    // proof we initiated).
    let started_by_us = call
        .started_call_recipient_id
        .and_then(|id| recipients.get(&id))
        .and_then(|r| r.service_id)
        .and_then(|s| s.aci())
        .map(|a| a == our_aci)
        .unwrap_or(matches!(state, group_call::State::OutgoingRing));
    let wire_dir = if started_by_us {
        WireDir::Outgoing
    } else {
        WireDir::Incoming
    };

    // 8 backup states → 4 wire events. `transition_group` then resolves to
    // the final GroupCallStatus:
    //   JOINED | ACCEPTED                              → Accepted    → Joined
    //   MISSED | MISSED_NOTIFICATION_PROFILE | DECLINED → NotAccepted → Missed
    //   GENERIC | RINGING | OUTGOING_RING | UNKNOWN    → Observed    → Generic
    //
    // DECLINED collapses to Missed for v1 — the state machine has no Declined
    // path for groups from wire events, and the renderer applies the
    // Declined/Missed labelling at render time based on direction anyway.
    let wire_event = match state {
        group_call::State::Joined | group_call::State::Accepted => WireEvent::Accepted,
        group_call::State::Missed
        | group_call::State::MissedNotificationProfile
        | group_call::State::Declined => WireEvent::NotAccepted,
        _ => WireEvent::Observed,
    };

    let call_ts = if call.started_call_timestamp != 0 {
        call.started_call_timestamp
    } else {
        fallback_ts
    };

    let call_event = sync_message::CallEvent {
        conversation_id: Some(conv_id),
        call_id: call.call_id,
        timestamp: Some(call_ts),
        r#type: Some(WireType::GroupCall as i32),
        direction: Some(wire_dir as i32),
        event: Some(wire_event as i32),
    };

    let body = ContentBody::SynchronizeMessage(SyncMessage {
        content: Some(sync_message::Content::CallEvent(call_event)),
        ..Default::default()
    });

    let main_content = Content {
        metadata: Metadata {
            sender: ServiceId::Aci(our_aci),
            destination: ServiceId::Aci(our_aci),
            sender_device: *DEFAULT_DEVICE_ID,
            server_guid: None,
            client_timestamp: chrono::DateTime::from_timestamp_millis(call_ts as i64)
                .unwrap_or_default(),
            server_timestamp: chrono::DateTime::from_timestamp_millis(call_ts as i64)
                .unwrap_or_default(),
            needs_receipt: false,
            unidentified_sender: false,
            was_plaintext: false,
            report_spam_token: None,
        },
        body,
    };

    vec![(main_content, thread.clone())]
}

/// Build a presage `Contact` from a backup `Recipient` whose destination is a
/// contact. Returns `None` for any other destination (self, group, distribution
/// list, …) or when the ACI is missing/invalid.
///
/// The display `name` is composed exactly like the storage-service sync derives
/// it (`Contact::try_from(ContactRecord)` in `model/contacts.rs`) — from the
/// profile given/family name via `ProfileName` — so when the later storage sync
/// re-saves the same contact it writes an identical string and the title never
/// visibly changes.
pub fn recipient_to_contact(r: &backup::Recipient) -> Option<crate::model::contacts::Contact> {
    use libsignal_service::profile_name::ProfileName;
    use libsignal_service::proto::backup::recipient::Destination;
    use libsignal_service::utils::{phonenumber_from_signal, TryIntoE164};

    let Some(Destination::Contact(c)) = r.destination.as_ref() else {
        return None;
    };

    let uuid = c
        .aci
        .as_ref()
        .and_then(|b| <[u8; 16]>::try_from(b.as_slice()).ok())
        .map(Uuid::from_bytes)?;

    let pni = c
        .pni
        .as_ref()
        .and_then(|b| <[u8; 16]>::try_from(b.as_slice()).ok())
        .map(Uuid::from_bytes);

    // Backup stores e164 as a numeric; ContactRecord stores it as a string. Render
    // it back to "+<digits>" so the same `try_into_e164`/`phonenumber_from_signal`
    // path as the storage-sync conversion applies.
    let phone_number = c
        .e164
        .filter(|n| *n != 0)
        .and_then(|n| format!("+{n}").as_str().try_into_e164().ok())
        .map(|e| phonenumber_from_signal(&e));

    let name = ProfileName {
        given_name: c.profile_given_name.clone().unwrap_or_default(),
        family_name: c.profile_family_name.clone().filter(|s| !s.is_empty()),
    }
    .to_string();

    let (nickname_given_name, nickname_family_name) = c
        .nickname
        .as_ref()
        .map(|n| (n.given.clone(), n.family.clone()))
        .unwrap_or_default();

    Some(crate::model::contacts::Contact {
        uuid,
        phone_number,
        name,
        verified: Default::default(),
        profile_key: c.profile_key.clone().unwrap_or_default(),
        expire_timer: 0,
        // Matches the model's serde default (`default_expire_timer_version`).
        expire_timer_version: 2,
        inbox_position: 0,
        avatar: None,
        pni,
        username: c.username.clone().filter(|s| !s.is_empty()),
        blocked: c.blocked,
        whitelisted: false,
        archived: false,
        marked_unread: false,
        muted_until_timestamp: 0,
        hide_story: c.hide_story,
        hidden: false,
        unregistered_at_timestamp: 0,
        pni_signature_verified: false,
        system_given_name: c.system_given_name.clone(),
        system_family_name: c.system_family_name.clone(),
        system_nickname: c.system_nickname.clone(),
        nickname_given_name,
        nickname_family_name,
        note: c.note.clone(),
    })
}

/// Build a presage `Group` stub from a backup `Recipient` whose destination is a
/// group, taking the title straight from the plaintext backup snapshot. Returns
/// `None` for any other destination or a malformed master key.
///
/// `needs_hydration` stays `true` so the existing group-hydration path still
/// enriches members/avatar from the network later — this only sources the
/// *title* from the backup so the sidebar can render it without a round-trip.
pub fn recipient_to_group(
    r: &backup::Recipient,
) -> Option<(
    libsignal_service::zkgroup::GroupMasterKeyBytes,
    crate::model::groups::Group,
)> {
    use libsignal_service::proto::backup::group::group_attribute_blob::Content;
    use libsignal_service::proto::backup::recipient::Destination;

    let Some(Destination::Group(g)) = r.destination.as_ref() else {
        return None;
    };
    let master_key: libsignal_service::zkgroup::GroupMasterKeyBytes =
        g.master_key.as_slice().try_into().ok()?;

    let title = g
        .snapshot
        .as_ref()
        .and_then(|s| s.title.as_ref())
        .and_then(|blob| blob.content.as_ref())
        .and_then(|content| match content {
            Content::Title(t) => Some(t.clone()),
            _ => None,
        })
        .filter(|t| !t.is_empty());

    let group = crate::model::groups::Group {
        title,
        avatar: None,
        disappearing_messages_timer: None,
        access_control: None,
        revision: 0,
        members: Vec::new(),
        pending_members: Vec::new(),
        requesting_members: Vec::new(),
        invite_link_password: Vec::new(),
        description: None,
        needs_hydration: true,
        blocked: g.blocked,
        whitelisted: g.whitelisted,
        archived: false,
        marked_unread: false,
        muted_until_timestamp: 0,
        dont_notify_for_mentions_if_muted: false,
        hide_story: g.hide_story,
        story_send_mode: i64::from(g.story_send_mode),
    };
    Some((master_key, group))
}

#[cfg(test)]
mod tests {
    use super::*;
    use libsignal_service::proto::backup::{self, recipient::Destination};

    fn contact_recipient() -> backup::Recipient {
        backup::Recipient {
            id: 1,
            destination: Some(Destination::Contact(backup::Contact {
                aci: Some(vec![1u8; 16]),
                e164: Some(15551234567),
                profile_given_name: Some("Ada".to_string()),
                profile_family_name: Some("Lovelace".to_string()),
                ..Default::default()
            })),
        }
    }

    fn group_recipient() -> backup::Recipient {
        backup::Recipient {
            id: 2,
            destination: Some(Destination::Group(backup::Group {
                master_key: vec![2u8; 32],
                snapshot: Some(backup::group::GroupSnapshot {
                    title: Some(backup::group::GroupAttributeBlob {
                        content: Some(backup::group::group_attribute_blob::Content::Title(
                            "Team Lovelace".to_string(),
                        )),
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            })),
        }
    }

    #[test]
    fn recipient_to_contact_extracts_identity_and_name() {
        let contact = recipient_to_contact(&contact_recipient()).expect("contact");
        assert_eq!(contact.uuid, Uuid::from_bytes([1u8; 16]));
        assert_eq!(contact.name, "Ada Lovelace");
        assert!(contact.phone_number.is_some());
    }

    #[test]
    fn recipient_to_group_extracts_master_key_and_title() {
        let (master_key, group) = recipient_to_group(&group_recipient()).expect("group");
        assert_eq!(master_key, [2u8; 32]);
        assert_eq!(group.title.as_deref(), Some("Team Lovelace"));
        assert!(group.needs_hydration);
    }

    /// A mentioning body: one U+FFFC placeholder, with the target carried
    /// out-of-band in a body range — Signal's on-the-wire shape for `@Ada hi`.
    fn mention_text() -> backup::Text {
        backup::Text {
            body: "\u{FFFC} hi".to_string(),
            body_ranges: vec![backup::BodyRange {
                start: 0,
                length: 1,
                associated_value: Some(backup::body_range::AssociatedValue::MentionAci(vec![
                    1u8; 16
                ])),
            }],
        }
    }

    /// An incoming ChatItem in chat 10 authored by recipient 1.
    fn incoming_item() -> ChatItem {
        ChatItem {
            chat_id: 10,
            author_id: 1,
            date_sent: 1700000000000,
            directional_details: Some(DirectionalDetails::Incoming(
                backup::chat_item::IncomingMessageDetails {
                    date_received: 1700000000001,
                    read: true,
                    ..Default::default()
                },
            )),
            ..Default::default()
        }
    }

    fn sender_recipients() -> HashMap<u64, RecipientInfo> {
        HashMap::from([(
            1,
            RecipientInfo {
                service_id: Some(ServiceId::Aci(Aci::from(Uuid::from_bytes([9u8; 16])))),
                group_master_key: None,
            },
        )])
    }

    fn incoming_data_message(sm: &backup::StandardMessage) -> DataMessage {
        let our_aci = Aci::from(Uuid::from_bytes([7u8; 16]));
        let thread = Thread::Contact(ServiceId::Aci(Aci::from(Uuid::from_bytes([9u8; 16]))));
        let item = incoming_item();
        let contents = standard_message_to_contents(
            sm,
            &item,
            &thread,
            &sender_recipients(),
            our_aci,
            item.date_sent,
        );
        match contents.into_iter().next().expect("one content").0.body {
            ContentBody::DataMessage(dm) => dm,
            other => panic!("expected a DataMessage, got {other:?}"),
        }
    }

    #[test]
    fn standard_message_carries_mention_body_ranges() {
        let sm = backup::StandardMessage {
            text: Some(mention_text()),
            ..Default::default()
        };
        let dm = incoming_data_message(&sm);

        // Without the range the body is just a placeholder, and the app has
        // nothing to resolve it against — it renders as a blank gap.
        assert_eq!(dm.body.as_deref(), Some("\u{FFFC} hi"));
        assert_eq!(dm.body_ranges.len(), 1);
        let range = &dm.body_ranges[0];
        assert_eq!(range.start, Some(0));
        assert_eq!(range.length, Some(1));
        assert_eq!(
            range.associated_value,
            Some(AssociatedValue::MentionAciBinary(vec![1u8; 16]))
        );
    }

    #[test]
    fn quote_carries_mention_body_ranges() {
        let sm = backup::StandardMessage {
            text: Some(backup::Text {
                body: "agreed".to_string(),
                body_ranges: Vec::new(),
            }),
            quote: Some(backup::Quote {
                target_sent_timestamp: Some(1699999999000),
                author_id: 1,
                text: Some(mention_text()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let quote = incoming_data_message(&sm).quote.expect("quote");

        // The reply preview renders the quoted text, so it needs the ranges too.
        assert_eq!(quote.text.as_deref(), Some("\u{FFFC} hi"));
        assert_eq!(quote.body_ranges.len(), 1);
        assert_eq!(
            quote.body_ranges[0].associated_value,
            Some(AssociatedValue::MentionAciBinary(vec![1u8; 16]))
        );
    }

    #[test]
    fn styles_carry_and_valueless_body_ranges_are_dropped() {
        let sm = backup::StandardMessage {
            text: Some(backup::Text {
                body: "bold text".to_string(),
                body_ranges: vec![
                    backup::BodyRange {
                        start: 0,
                        length: 4,
                        associated_value: Some(backup::body_range::AssociatedValue::Style(
                            backup::body_range::Style::Bold as i32,
                        )),
                    },
                    // The backup spec: importers ignore these rather than erroring.
                    backup::BodyRange {
                        start: 5,
                        length: 4,
                        associated_value: None,
                    },
                ],
            }),
            ..Default::default()
        };
        let dm = incoming_data_message(&sm);

        assert_eq!(dm.body_ranges.len(), 1);
        assert_eq!(
            dm.body_ranges[0].associated_value,
            Some(AssociatedValue::Style(
                backup::body_range::Style::Bold as i32
            ))
        );
    }

    #[test]
    fn converters_reject_mismatched_or_unsupported_destinations() {
        // Wrong kind for each converter.
        assert!(recipient_to_group(&contact_recipient()).is_none());
        assert!(recipient_to_contact(&group_recipient()).is_none());

        // Self / empty destinations yield nothing for either converter.
        let self_recipient = backup::Recipient {
            id: 3,
            destination: Some(Destination::Self_(backup::Self_::default())),
        };
        assert!(recipient_to_contact(&self_recipient).is_none());
        assert!(recipient_to_group(&self_recipient).is_none());

        let empty = backup::Recipient {
            id: 4,
            destination: None,
        };
        assert!(recipient_to_contact(&empty).is_none());
        assert!(recipient_to_group(&empty).is_none());
    }
}
