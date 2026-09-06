use libsignal_service::{
    groups_v2::{AccessRequired, Role},
    prelude::{ProfileKey, Timer, Uuid},
    protocol::{Aci, Pni, ServiceId},
    zkgroup::GroupMasterKeyBytes,
};
use serde::{Deserialize, Serialize};

use super::ServiceIdType;
use libsignal_service::utils::serde_aci;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccessControl {
    pub attributes: AccessRequired,
    pub members: AccessRequired,
    pub add_from_invite_link: AccessRequired,
    #[serde(default = "default_access_required")]
    pub member_label: AccessRequired,
}

/// According to https://github.com/signalapp/Signal-Desktop/blob/9c246150585a65b6c3be324e2c214cb4f62c6102/ts/groups.preload.ts#L503.
fn default_access_required() -> AccessRequired {
    AccessRequired::Member
}

/// Who a group lets do something: any member, or only its administrators.
///
/// The narrow form of [`AccessRequired`] for the attribute and membership rules; the
/// other variants belong to the invite-link rule, and the server rejects them here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GroupAccess {
    Members,
    Administrators,
}

impl From<GroupAccess> for AccessRequired {
    fn from(access: GroupAccess) -> Self {
        match access {
            GroupAccess::Members => AccessRequired::Member,
            GroupAccess::Administrators => AccessRequired::Administrator,
        }
    }
}

/// The attributes a group change can carry, for [`Manager::update_group`](crate::Manager::update_group).
///
/// `None` leaves a field as it is. An empty description clears it; a zero timer turns
/// disappearing messages off. `announcements_only` is the membership rule for sending:
/// set, only administrators may send to the group.
///
/// Setting `member_label_access` to [`GroupAccess::Administrators`] is not only a
/// rule change: it also clears the labels that rule takes away, in the same change —
/// see [`Group::members_losing_labels`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GroupUpdate {
    pub title: Option<String>,
    pub description: Option<String>,
    pub expire_timer_seconds: Option<u32>,
    pub attributes_access: Option<GroupAccess>,
    pub members_access: Option<GroupAccess>,
    pub member_label_access: Option<GroupAccess>,
    pub announcements_only: Option<bool>,
}

impl GroupUpdate {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// The membership changes one group change can carry, for
/// [`Manager::update_group_members`](crate::Manager::update_group_members).
///
/// `add` takes any service id: someone whose profile key this account holds joins
/// outright, anyone else — a PNI-only contact included — is invited and joins when
/// they accept. `remove` and the role changes are for full members; an invitation
/// is withdrawn with `remove_pending`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GroupMembersUpdate {
    pub add: Vec<ServiceId>,
    pub remove: Vec<Aci>,
    pub remove_pending: Vec<ServiceId>,
    pub promote: Vec<Aci>,
    pub demote: Vec<Aci>,
}

impl GroupMembersUpdate {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Group {
    pub title: Option<String>,
    pub avatar: Option<String>,
    pub disappearing_messages_timer: Option<Timer>,
    pub access_control: Option<AccessControl>,
    pub revision: u32,
    pub members: Vec<Member>,
    pub pending_members: Vec<PendingMember>,
    pub requesting_members: Vec<RequestingMember>,
    pub invite_link_password: Vec<u8>,
    pub description: Option<String>,
    #[serde(default)]
    pub announcements_only: bool,
    #[serde(default)]
    pub needs_hydration: bool,
    // storage service fields
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
    pub dont_notify_for_mentions_if_muted: bool,
    #[serde(default)]
    pub hide_story: bool,
    #[serde(default)]
    pub story_send_mode: i64, // 0=Default, 1=Disabled, 2=Enabled
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Member {
    #[serde(alias = "uuid", with = "serde_aci")]
    pub aci: Aci,
    pub role: Role,
    pub profile_key: ProfileKey,
    pub joined_at_revision: u32,
    pub label: Option<String>,
    pub label_emoji: Option<String>,
}

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct PendingMember {
    // for backwards compatibility
    pub uuid: Uuid,
    #[serde(default)]
    pub service_id_type: ServiceIdType,
    pub role: Role,
    #[serde(alias = "added_by_uuid", with = "serde_aci")]
    pub added_by_aci: Aci,
    pub timestamp: u64,
}

impl PendingMember {
    pub fn service_id(&self) -> ServiceId {
        match self.service_id_type {
            ServiceIdType::AccountIdentity => ServiceId::from(Aci::from(self.uuid)),
            ServiceIdType::PhoneNumberIdentity => ServiceId::from(Pni::from(self.uuid)),
        }
    }
}

#[derive(derive_more::Debug, Clone, Deserialize, Serialize)]
pub struct RequestingMember {
    #[serde(alias = "uuid", with = "serde_aci")]
    pub aci: Aci,
    #[debug(ignore)]
    pub profile_key: ProfileKey,
    pub timestamp: u64,
}

impl Group {
    pub fn is_member(&self, aci: Aci) -> bool {
        self.members.iter().any(|m| m.aci == aci)
    }

    pub fn is_pending(&self, service_id: ServiceId) -> bool {
        self.pending_members
            .iter()
            .any(|p| p.service_id() == service_id)
    }

    /// Whether this account is still in the group, as a member or an invitee.
    /// Leaving, or being removed, is what makes this false — there is no flag.
    pub fn is_active(&self, self_aci: Aci) -> bool {
        self.is_member(self_aci) || self.is_pending(ServiceId::from(self_aci))
    }

    /// The members whose labels handing member labels to administrators takes
    /// away. Signal-Desktop's `buildAccessControlMemberLabelChange` and
    /// Signal-Android's `updateMemberLabelRights` clear these in the same change;
    /// a label a member may no longer set would otherwise stay on the group forever.
    ///
    /// Empty unless the rule is actually tightening — loosening it, or restating a
    /// restriction already in force, takes nothing away.
    pub fn members_losing_labels(&self, new_access: GroupAccess) -> Vec<Aci> {
        let already_restricted = self
            .access_control
            .as_ref()
            .is_some_and(|ac| ac.member_label == AccessRequired::Administrator);
        if new_access != GroupAccess::Administrators || already_restricted {
            return Vec::new();
        }
        self.members
            .iter()
            .filter(|m| m.role != Role::Administrator)
            .filter(|m| m.label.is_some() || m.label_emoji.is_some())
            .map(|m| m.aci)
            .collect()
    }

    /// What the stored copy becomes once this account has left at `revision`,
    /// with `promoted` made administrators on the way out — the server will not
    /// tell this account any more, so the change is applied by hand.
    pub(crate) fn mark_left(&mut self, self_aci: Aci, promoted: &[Aci], revision: u32) {
        self.members.retain(|m| m.aci != self_aci);
        self.pending_members
            .retain(|p| p.service_id() != ServiceId::from(self_aci));
        for member in &mut self.members {
            if promoted.contains(&member.aci) {
                member.role = Role::Administrator;
            }
        }
        self.revision = revision;
    }

    /// The server's copy of a group, keeping what only this device knows.
    ///
    /// The storage-service flags — blocked, muted, archived and the rest — never come
    /// from the group server, so `From<libsignal_service::groups_v2::Group>` has to zero
    /// them. Saving that over a stored group would silently un-mute or un-block it;
    /// this carries them across from `local` instead.
    pub fn from_server(server: libsignal_service::groups_v2::Group, local: Option<&Group>) -> Self {
        let mut group: Group = server.into();
        if let Some(local) = local {
            group.blocked = local.blocked;
            group.whitelisted = local.whitelisted;
            group.archived = local.archived;
            group.marked_unread = local.marked_unread;
            group.muted_until_timestamp = local.muted_until_timestamp;
            group.dont_notify_for_mentions_if_muted = local.dont_notify_for_mentions_if_muted;
            group.hide_story = local.hide_story;
            group.story_send_mode = local.story_send_mode;
        }
        group
    }

    /// Build a `GroupV2Record` for a group the account has no storage-service
    /// record for yet.
    ///
    /// Lossy, and only sound because of where it is used. `Group` carries no
    /// `avatar_color` and no `verified_name_hash`, so both come out unset — and
    /// `avatarColor` has explicit presence, meaning "unset" is a value another
    /// client can tell apart from the default. Appending a record where none
    /// exists cannot clobber anything, which is what makes this narrow use safe;
    /// an *edit* must go through [`crate::storage_record`] instead.
    pub fn to_new_storage_record(
        &self,
        master_key: GroupMasterKeyBytes,
    ) -> libsignal_service::proto::GroupV2Record {
        libsignal_service::proto::GroupV2Record {
            master_key: master_key.to_vec(),
            blocked: self.blocked,
            whitelisted: self.whitelisted,
            archived: self.archived,
            marked_unread: self.marked_unread,
            muted_until_timestamp: self.muted_until_timestamp,
            dont_notify_for_mentions_if_muted: self.dont_notify_for_mentions_if_muted,
            hide_story: self.hide_story,
            story_send_mode: self.story_send_mode as i32,
            ..Default::default()
        }
    }
}

impl From<libsignal_service::groups_v2::Group> for Group {
    fn from(val: libsignal_service::groups_v2::Group) -> Self {
        Group {
            title: Some(val.title),
            avatar: if val.avatar.is_empty() {
                None
            } else {
                Some(val.avatar)
            },
            disappearing_messages_timer: val.disappearing_messages_timer,
            access_control: val.access_control.map(Into::into),
            revision: val.version,
            members: val.members.into_iter().map(Into::into).collect(),
            pending_members: val
                .members_pending_profile_key
                .into_iter()
                .map(Into::into)
                .collect(),
            requesting_members: val
                .members_pending_admin_approval
                .into_iter()
                .map(Into::into)
                .collect(),
            invite_link_password: val.invite_link_password,
            description: val.description_text,
            announcements_only: val.announcements_only,
            needs_hydration: false,
            blocked: false,
            whitelisted: false,
            archived: false,
            marked_unread: false,
            muted_until_timestamp: 0,
            dont_notify_for_mentions_if_muted: false,
            hide_story: false,
            story_send_mode: 0,
        }
    }
}

impl From<libsignal_service::groups_v2::Member> for Member {
    fn from(val: libsignal_service::groups_v2::Member) -> Self {
        Member {
            aci: val.aci,
            role: val.role,
            profile_key: val.profile_key,
            joined_at_revision: val.joined_at_version,
            label: val.label,
            label_emoji: val.label_emoji,
        }
    }
}

impl From<libsignal_service::groups_v2::PendingMember> for PendingMember {
    fn from(val: libsignal_service::groups_v2::PendingMember) -> Self {
        PendingMember {
            uuid: val.address.raw_uuid(),
            service_id_type: val.address.kind().into(),
            role: val.role,
            added_by_aci: val.added_by_aci,
            timestamp: val.timestamp,
        }
    }
}

impl From<libsignal_service::groups_v2::RequestingMember> for RequestingMember {
    fn from(val: libsignal_service::groups_v2::RequestingMember) -> Self {
        RequestingMember {
            aci: val.aci,
            profile_key: val.profile_key,
            timestamp: val.timestamp,
        }
    }
}

impl From<libsignal_service::groups_v2::AccessControl> for AccessControl {
    fn from(val: libsignal_service::groups_v2::AccessControl) -> Self {
        Self {
            attributes: val.attributes,
            members: val.members,
            add_from_invite_link: val.add_from_invite_link,
            member_label: val.member_label,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server_group(version: u32) -> libsignal_service::groups_v2::Group {
        libsignal_service::groups_v2::Group {
            title: "Renamed".into(),
            avatar: String::new(),
            disappearing_messages_timer: None,
            access_control: None,
            version,
            members: vec![],
            members_pending_profile_key: vec![],
            members_pending_admin_approval: vec![],
            invite_link_password: vec![],
            description_text: None,
            announcements_only: false,
            members_banned: vec![],
            terminated: false,
        }
    }

    #[test]
    fn from_server_keeps_the_flags_only_this_device_knows() {
        let mut local: Group = server_group(3).into();
        local.needs_hydration = true;
        local.blocked = true;
        local.archived = true;
        local.muted_until_timestamp = 1_700_000_000_000;

        let merged = Group::from_server(server_group(4), Some(&local));

        assert_eq!(merged.revision, 4);
        assert_eq!(merged.title.as_deref(), Some("Renamed"));
        assert!(!merged.needs_hydration);
        assert!(merged.blocked);
        assert!(merged.archived);
        assert_eq!(merged.muted_until_timestamp, 1_700_000_000_000);
    }

    #[test]
    fn from_server_without_a_local_copy_is_the_plain_conversion() {
        let merged = Group::from_server(server_group(1), None);
        assert!(!merged.blocked);
        assert_eq!(merged.muted_until_timestamp, 0);
    }

    #[test]
    fn a_pending_member_addresses_by_its_identity_kind() {
        let uuid = Uuid::from_u128(7);
        let aci_pending = PendingMember {
            uuid,
            service_id_type: ServiceIdType::AccountIdentity,
            role: Role::Default,
            added_by_aci: Aci::from(Uuid::from_u128(1)),
            timestamp: 0,
        };
        let pni_pending = PendingMember {
            service_id_type: ServiceIdType::PhoneNumberIdentity,
            ..PendingMember {
                uuid,
                service_id_type: ServiceIdType::AccountIdentity,
                role: Role::Default,
                added_by_aci: Aci::from(Uuid::from_u128(1)),
                timestamp: 0,
            }
        };
        assert_eq!(aci_pending.service_id(), ServiceId::from(Aci::from(uuid)));
        assert_eq!(pni_pending.service_id(), ServiceId::from(Pni::from(uuid)));
    }

    #[test]
    fn active_means_member_or_invitee() {
        let me = Aci::from(Uuid::from_u128(9));
        let mut group: Group = server_group(1).into();
        assert!(!group.is_active(me));
        group.pending_members.push(PendingMember {
            uuid: me.into(),
            service_id_type: ServiceIdType::AccountIdentity,
            role: Role::Default,
            added_by_aci: Aci::from(Uuid::from_u128(1)),
            timestamp: 0,
        });
        assert!(group.is_active(me));
        assert!(!group.is_member(me));
    }

    #[test]
    fn a_members_update_with_nothing_set_is_empty() {
        assert!(GroupMembersUpdate::default().is_empty());
        assert!(!GroupMembersUpdate {
            remove: vec![Aci::from(Uuid::from_u128(2))],
            ..Default::default()
        }
        .is_empty());
    }

    #[test]
    fn an_update_with_nothing_set_is_empty() {
        assert!(GroupUpdate::default().is_empty());
        assert!(!GroupUpdate {
            expire_timer_seconds: Some(0),
            ..Default::default()
        }
        .is_empty());
    }
}
