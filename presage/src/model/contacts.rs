use bytes::Bytes;
use libsignal_service::{
    models::Attachment,
    prelude::{phonenumber::PhoneNumber, Uuid},
    proto::Verified,
    utils::{phonenumber_from_signal, TryIntoE164},
};
use serde::{Deserialize, Serialize};

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
    pub blocked: bool,
    #[serde(default)]
    pub archived: bool,
    #[serde(default)]
    pub muted_until_timestamp: u64,
    #[serde(default)]
    pub hidden: bool,
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
            blocked: false,
            archived: false,
            muted_until_timestamp: 0,
            hidden: false,
        }
    }
}

impl From<libsignal_service::proto::ContactRecord> for Contact {
    fn from(r: libsignal_service::proto::ContactRecord) -> Self {
        let uuid = if !r.aci_binary.is_empty() {
            r.aci_binary
                .as_slice()
                .try_into()
                .ok()
                .map(Uuid::from_bytes)
        } else {
            r.aci.parse().ok()
        }
        .unwrap_or_else(Uuid::nil);

        let phone_number = r
            .e164
            .as_str()
            .try_into_e164()
            .ok()
            .map(|e| phonenumber_from_signal(&e));

        let name = match (r.given_name.is_empty(), r.family_name.is_empty()) {
            (false, false) => format!("{} {}", r.given_name, r.family_name),
            (false, true) => r.given_name,
            (true, false) => r.family_name,
            (true, true) => String::new(),
        };

        Self {
            uuid,
            phone_number,
            name,
            verified: Default::default(),
            profile_key: r.profile_key,
            expire_timer: 0,
            expire_timer_version: default_expire_timer_version(),
            inbox_position: 0,
            avatar: None,
            blocked: r.blocked,
            archived: r.archived,
            muted_until_timestamp: r.muted_until_timestamp,
            hidden: r.hidden,
        }
    }
}
