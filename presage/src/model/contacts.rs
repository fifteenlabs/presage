use bytes::Bytes;
use libsignal_service::{
    models::Attachment,
    prelude::{phonenumber::PhoneNumber, Uuid},
    proto::Verified,
    utils::{phonenumber_from_signal, TryIntoE164},
};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

const fn default_expire_timer_version() -> u32 {
    2
}

/// Mirror of the protobuf ContactDetails message
/// but with stronger types (e.g. `ServiceAddress` instead of optional uuid and string phone numbers)
/// and some helper functions
#[derive(Debug, Serialize, Deserialize)]
pub struct Contact {
    pub uuid: Uuid,
    pub phone_number: Option<PhoneNumber>,
    pub name: String,
    #[serde(skip)]
    pub verified: Verified,
    pub profile_key: Vec<u8>,
    pub expire_timer: u32,
    #[serde(default = "default_expire_timer_version")]
    pub expire_timer_version: u32,
    pub inbox_position: u32,
    #[serde(skip)]
    pub avatar: Option<Attachment<Bytes>>,
    // storage service fields
    #[serde(default)]
    pub pni: Option<Uuid>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub blocked: bool,
    #[serde(default)]
    pub whitelisted: bool,
    #[serde(default)]
    pub archived: bool,
    #[serde(default)]
    pub marked_unread: bool,
    #[serde(default)]
    pub muted_until_timestamp: u64,
    #[serde(default)]
    pub hide_story: bool,
    #[serde(default)]
    pub hidden: bool,
    #[serde(default)]
    pub unregistered_at_timestamp: u64,
    #[serde(default)]
    pub pni_signature_verified: bool,
    #[serde(default)]
    pub system_given_name: String,
    #[serde(default)]
    pub system_family_name: String,
    #[serde(default)]
    pub system_nickname: String,
    #[serde(default)]
    pub nickname_given_name: String,
    #[serde(default)]
    pub nickname_family_name: String,
    #[serde(default)]
    pub note: String,
}

impl From<libsignal_service::models::Contact> for Contact {
    fn from(c: libsignal_service::models::Contact) -> Self {
        Self {
            uuid: c.uuid,
            phone_number: c.phone_number.as_ref().map(phonenumber_from_signal),
            name: c.name,
            verified: Default::default(),
            profile_key: Default::default(),
            expire_timer: c.expire_timer,
            expire_timer_version: c.expire_timer_version,
            inbox_position: c.inbox_position,
            avatar: c.avatar,
            pni: None,
            username: None,
            blocked: false,
            whitelisted: false,
            archived: false,
            marked_unread: false,
            muted_until_timestamp: 0,
            hide_story: false,
            hidden: false,
            unregistered_at_timestamp: 0,
            pni_signature_verified: false,
            system_given_name: String::new(),
            system_family_name: String::new(),
            system_nickname: String::new(),
            nickname_given_name: String::new(),
            nickname_family_name: String::new(),
            note: String::new(),
        }
    }
}

impl Contact {
    /// Build a bare contact record for a recipient we've never synced, keyed
    /// only by its ACI. Used when blocking someone who isn't in the contact
    /// list yet — every other field takes its default.
    pub fn minimal(uuid: Uuid) -> Self {
        libsignal_service::models::Contact {
            uuid,
            phone_number: None,
            name: String::new(),
            expire_timer: 0,
            expire_timer_version: default_expire_timer_version(),
            inbox_position: 0,
            avatar: None,
        }
        .into()
    }
}

impl TryFrom<libsignal_service::proto::ContactRecord> for Contact {
    type Error = &'static str;

    fn try_from(r: libsignal_service::proto::ContactRecord) -> Result<Self, Self::Error> {
        let uuid = if !r.aci_binary.is_empty() {
            r.aci_binary
                .as_slice()
                .try_into()
                .ok()
                .map(Uuid::from_bytes)
        } else {
            r.aci.parse().ok()
        }
        .ok_or("missing or invalid ACI")?;

        let pni = if !r.pni_binary.is_empty() {
            r.pni_binary
                .as_slice()
                .try_into()
                .ok()
                .map(Uuid::from_bytes)
        } else if !r.pni.is_empty() {
            r.pni.parse().ok()
        } else {
            None
        };

        let phone_number = r
            .e164
            .as_str()
            .try_into_e164()
            .ok()
            .map(|e| phonenumber_from_signal(&e));

        let name = libsignal_service::profile_name::ProfileName {
            given_name: r.given_name,
            family_name: if r.family_name.is_empty() {
                None
            } else {
                Some(r.family_name)
            },
        }
        .to_string();

        let username = if r.username.is_empty() {
            None
        } else {
            Some(r.username)
        };

        Ok(Self {
            uuid,
            phone_number,
            name,
            verified: Verified::default(),
            profile_key: r.profile_key,
            expire_timer: 0,
            expire_timer_version: default_expire_timer_version(),
            inbox_position: 0,
            avatar: None,
            pni,
            username,
            blocked: r.blocked,
            whitelisted: r.whitelisted,
            archived: r.archived,
            marked_unread: r.marked_unread,
            muted_until_timestamp: r.muted_until_timestamp,
            hide_story: r.hide_story,
            hidden: r.hidden,
            unregistered_at_timestamp: r.unregistered_at_timestamp,
            pni_signature_verified: r.pni_signature_verified,
            system_given_name: r.system_given_name,
            system_family_name: r.system_family_name,
            system_nickname: r.system_nickname,
            nickname_given_name: r
                .nickname
                .as_ref()
                .map(|n| n.given.clone())
                .unwrap_or_default(),
            nickname_family_name: r
                .nickname
                .as_ref()
                .map(|n| n.family.clone())
                .unwrap_or_default(),
            note: r.note,
        })
    }
}
