use std::borrow::Cow;

use bytes::Bytes;
use presage::{
    libsignal_service::{
        Profile,
        content::Metadata,
        models::Attachment,
        prelude::{AccessControl, Content, phonenumber},
        profile_name::ProfileName,
        protocol::{Aci, ServiceId},
        zkgroup::GroupMasterKeyBytes,
    },
    model::{
        contacts::Contact,
        groups::{Group, Member, PendingMember, RequestingMember},
    },
    proto::{self, Verified, verified},
    store::{StickerPack, StickerPackManifest},
};
use sqlx::types::Json;
use uuid::Uuid;

use crate::SqliteStoreError;

#[derive(Debug)]
pub struct SqlContact {
    pub uuid: Uuid,
    pub phone_number: Option<String>,
    pub name: String,
    pub profile_key: Vec<u8>,
    pub expire_timer: i64,
    pub expire_timer_version: i64,
    pub inbox_position: i64,
    pub avatar: Option<Vec<u8>>,
    // from contacts_verification_state join
    pub destination_aci: Option<String>,
    pub identity_key: Option<Vec<u8>>,
    pub is_verified: Option<bool>,
    // storage service fields
    pub pni: Option<String>,
    pub username: Option<String>,
    pub blocked: bool,
    pub whitelisted: bool,
    pub archived: bool,
    pub marked_unread: bool,
    pub muted_until_timestamp: i64,
    pub hide_story: bool,
    pub hidden: bool,
    pub unregistered_at_timestamp: i64,
    pub pni_signature_verified: bool,
    pub system_given_name: Option<String>,
    pub system_family_name: Option<String>,
    pub system_nickname: Option<String>,
    pub nickname_given_name: Option<String>,
    pub nickname_family_name: Option<String>,
    pub note: Option<String>,
}

impl TryInto<Contact> for SqlContact {
    type Error = SqliteStoreError;

    #[tracing::instrument]
    fn try_into(self) -> Result<Contact, Self::Error> {
        Ok(Contact {
            uuid: self.uuid,
            phone_number: self
                .phone_number
                .map(|p| phonenumber::parse(None, &p))
                .transpose()?,
            name: self.name,
            verified: Verified {
                destination_aci_binary: self
                    .destination_aci
                    .as_deref()
                    .and_then(Aci::parse_from_service_id_string)
                    .map(|aci| aci.service_id_binary()),
                destination_aci: self.destination_aci,
                identity_key: self.identity_key,
                state: self.is_verified.map(|v| {
                    match v {
                        true => verified::State::Verified,
                        false => verified::State::Unverified,
                    }
                    .into()
                }),
                null_message: None,
            },
            profile_key: self.profile_key,
            expire_timer: self.expire_timer as u32,
            expire_timer_version: self.expire_timer_version as u32,
            inbox_position: self.inbox_position as u32,
            avatar: self.avatar.map(|b| Attachment {
                content_type: "application/octet-stream".to_owned(),
                reader: Bytes::from(b),
            }),
            pni: self.pni.and_then(|p| {
                p.parse()
                    .map_err(|e| tracing::warn!("failed to parse stored PNI {p:?}: {e}"))
                    .ok()
            }),
            username: self.username,
            blocked: self.blocked,
            whitelisted: self.whitelisted,
            archived: self.archived,
            marked_unread: self.marked_unread,
            muted_until_timestamp: self.muted_until_timestamp as u64,
            hide_story: self.hide_story,
            hidden: self.hidden,
            unregistered_at_timestamp: self.unregistered_at_timestamp as u64,
            pni_signature_verified: self.pni_signature_verified,
            system_given_name: self.system_given_name.unwrap_or_default(),
            system_family_name: self.system_family_name.unwrap_or_default(),
            system_nickname: self.system_nickname.unwrap_or_default(),
            nickname_given_name: self.nickname_given_name.unwrap_or_default(),
            nickname_family_name: self.nickname_family_name.unwrap_or_default(),
            note: self.note.unwrap_or_default(),
        })
    }
}

#[derive(Debug)]
pub struct SqlProfile {
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub about: Option<String>,
    pub about_emoji: Option<String>,
    pub avatar: Option<String>,
    pub unrestricted_unidentified_access: bool,
}

impl From<SqlProfile> for Profile {
    fn from(
        SqlProfile {
            given_name,
            family_name,
            about,
            about_emoji,
            avatar,
            unrestricted_unidentified_access,
        }: SqlProfile,
    ) -> Self {
        Profile {
            name: given_name.map(|gn| ProfileName {
                given_name: gn,
                family_name,
            }),
            about,
            about_emoji,
            avatar,
            unrestricted_unidentified_access,
        }
    }
}

#[derive(Debug)]
pub(crate) struct SqlGroup<'a> {
    pub(crate) master_key: Cow<'a, [u8]>,
    pub(crate) title: Option<String>,
    pub(crate) revision: u32,
    pub(crate) invite_link_password: Option<Vec<u8>>,
    pub(crate) access_control: Option<Json<AccessControl>>,
    pub(crate) avatar: Option<String>,
    pub(crate) description: Option<String>,
    pub(crate) members: Json<Vec<Member>>,
    pub(crate) pending_members: Json<Vec<PendingMember>>,
    pub(crate) requesting_members: Json<Vec<RequestingMember>>,
    pub(crate) needs_hydration: bool,
    pub(crate) blocked: bool,
    pub(crate) whitelisted: bool,
    pub(crate) archived: bool,
    pub(crate) marked_unread: bool,
    pub(crate) muted_until_timestamp: i64,
    pub(crate) dont_notify_for_mentions_if_muted: bool,
    pub(crate) hide_story: bool,
    pub(crate) story_send_mode: i64,
}

impl SqlGroup<'_> {
    #[tracing::instrument]
    pub fn from_group(master_key: &GroupMasterKeyBytes, group: Group) -> SqlGroup<'_> {
        SqlGroup {
            master_key: Cow::Borrowed(master_key.as_slice()),
            title: group.title,
            revision: group.revision,
            invite_link_password: Some(group.invite_link_password),
            access_control: group.access_control.map(Json),
            avatar: group.avatar,
            description: group.description,
            members: Json(group.members),
            pending_members: Json(group.pending_members),
            requesting_members: Json(group.requesting_members),
            needs_hydration: group.needs_hydration,
            blocked: group.blocked,
            whitelisted: group.whitelisted,
            archived: group.archived,
            marked_unread: group.marked_unread,
            muted_until_timestamp: group.muted_until_timestamp as i64,
            dont_notify_for_mentions_if_muted: group.dont_notify_for_mentions_if_muted,
            hide_story: group.hide_story,
            story_send_mode: group.story_send_mode,
        }
    }

    #[tracing::instrument]
    pub fn into_group(self) -> Result<(GroupMasterKeyBytes, Group), SqliteStoreError> {
        let Self {
            master_key,
            title,
            revision,
            invite_link_password,
            access_control,
            avatar,
            description,
            members: Json(members),
            pending_members: Json(pending_members),
            requesting_members: Json(requesting_members),
            needs_hydration,
            blocked,
            whitelisted,
            archived,
            marked_unread,
            muted_until_timestamp,
            dont_notify_for_mentions_if_muted,
            hide_story,
            story_send_mode,
        } = self;
        let master_key = master_key
            .as_ref()
            .try_into()
            .map_err(|_| SqliteStoreError::InvalidFormat)?;
        let access_control = access_control.map(|Json(x)| x);
        let group = Group {
            title,
            avatar,
            disappearing_messages_timer: None,
            access_control,
            revision,
            members,
            pending_members,
            requesting_members,
            invite_link_password: invite_link_password.unwrap_or_default(),
            description,
            needs_hydration,
            blocked,
            whitelisted,
            archived,
            marked_unread,
            muted_until_timestamp: muted_until_timestamp as u64,
            dont_notify_for_mentions_if_muted,
            hide_story,
            story_send_mode,
        };
        Ok((master_key, group))
    }
}

#[derive(Debug)]
pub struct SqlMessage {
    pub ts: u64,

    pub sender_service_id: String,
    pub sender_device_id: u8,
    pub destination_service_id: String,
    pub needs_receipt: bool,
    pub unidentified_sender: bool,

    pub content_body: Vec<u8>,
    pub was_plaintext: bool,
}

impl TryInto<Content> for SqlMessage {
    type Error = SqliteStoreError;

    #[tracing::instrument(skip(self), fields(self.ts = %self.ts, self.sender_service_id = %self.sender_service_id, self.sender_device_id = %self.sender_device_id, self.destination_service_id = %self.destination_service_id, self.needs_receipt = %self.needs_receipt, self.unidentified_sender = %self.unidentified_sender, self.was_plaintext = %self.was_plaintext, self.content_body = "[...]"))]
    fn try_into(self) -> Result<Content, Self::Error> {
        let Self {
            ts,
            sender_service_id,
            sender_device_id,
            destination_service_id,
            needs_receipt,
            unidentified_sender,
            content_body,
            was_plaintext,
        } = self;
        let body: proto::Content =
            prost::Message::decode(&*content_body).map_err(|_| SqliteStoreError::InvalidFormat)?;
        let sender = ServiceId::parse_from_service_id_string(&sender_service_id)
            .ok_or_else(|| SqliteStoreError::InvalidFormat)?;
        let destination = ServiceId::parse_from_service_id_string(&destination_service_id)
            .ok_or_else(|| SqliteStoreError::InvalidFormat)?;
        let metadata = Metadata {
            sender,
            destination,
            sender_device: sender_device_id.try_into()?,
            timestamp: ts,
            needs_receipt,
            unidentified_sender,
            server_guid: None,
            was_plaintext,
        };
        Content::from_proto(body, metadata).map_err(|_| SqliteStoreError::InvalidFormat)
    }
}

pub(crate) struct SqlStickerPack {
    pub(crate) id: Vec<u8>,
    pub(crate) key: Vec<u8>,
    pub(crate) manifest: Json<StickerPackManifest>,
}

impl From<SqlStickerPack> for StickerPack {
    fn from(
        SqlStickerPack {
            id,
            key,
            manifest: Json(manifest),
        }: SqlStickerPack,
    ) -> Self {
        StickerPack { id, key, manifest }
    }
}
