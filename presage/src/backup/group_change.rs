//! Rebuilds a backup `GroupChangeChatUpdate` as the encrypted `GroupChange`
//! the group server would have attached to the live message.
//!
//! A backup stores group history in plaintext, already resolved; the wire form
//! stores it as `GroupChange.Actions` encrypted under the group's secret
//! params. Decryption needs only the master key — the server signature is not
//! checked — so the import can encrypt the plaintext back and store exactly
//! what the live receive path would have stored. Every reader of stored group
//! history then works unchanged. The actions and the change are built by
//! libsignal-service's own `GroupOperations`, next to the decoder that reads
//! them back; this module only maps backup update kinds onto them.
//!
//! Member actions carry a profile-key ciphertext the decoder insists on; the
//! backup has no profile key for them, so a random one is encrypted in its
//! place. It has to be random: the decryptor lizard-decodes the plaintext
//! and rejects anything that does not decode to exactly one candidate, which
//! a constant such as all zeros does not. Nothing downstream reads the key
//! of a member named by a system row.

use libsignal_service::{
    groups_v2::{AccessRequired, GroupOperations, Role, Timer},
    prelude::ProtobufMessage as _,
    proto::{
        backup::{self, group_change_chat_update::update::Update},
        group_change::Actions,
    },
    protocol::{Aci, Pni, ServiceId},
    zkgroup::{
        groups::{GroupMasterKey, GroupSecretParams},
        profiles::ProfileKey,
    },
};

/// What a single backup group update becomes on the wire.
pub enum GroupUpdate {
    /// `GroupContextV2 { revision: 0 }` with no change — how a live client
    /// signals group creation.
    Created,
    /// An encrypted `GroupChange` for the group context. Never empty: a
    /// change with no actions still encrypts to a blob, and it must, because
    /// the app's `is_silent_group_update` drops a context whose change bytes
    /// are empty and keeps one that decrypts to zero changes, which then
    /// renders as a generic "updated the group" row.
    Change(Vec<u8>),
}

/// The group operations for one master key. Deriving the secret params
/// costs four scalar multiplications, and a backup holds many items per
/// group, so the import keeps one of these per group rather than per item.
pub fn group_operations(master_key: [u8; 32]) -> GroupOperations {
    GroupOperations::new(GroupSecretParams::derive_from_master_key(
        GroupMasterKey::new(master_key),
    ))
}

/// Maps one backup group update to its wire form and the member who made
/// it. Every update maps to something: the kinds the wire cannot express
/// become a change with no actions, and an update whose participant the
/// backup left out keeps its editor and loses only the actions.
///
/// The editor is the person whose act the row describes: the updater where
/// the backup names one, and the member themself for the events a member
/// performs on their own behalf (leaving, joining, requesting, declining) —
/// that distinction is what lets a row read "You left the group" rather
/// than name a stranger. `fallback_editor` stands in when the backup names
/// nobody.
pub fn plan_group_update(
    update: &backup::group_change_chat_update::Update,
    ops: &GroupOperations,
    our_aci: Aci,
    fallback_editor: Aci,
) -> Option<(Aci, GroupUpdate)> {
    if let Some(Update::GroupCreationUpdate(u)) = update.update.as_ref() {
        return Some((
            aci(&u.updater_aci).unwrap_or(fallback_editor),
            GroupUpdate::Created,
        ));
    }
    let (editor, actions) = match update.update.as_ref() {
        Some(update) => plan(update, ops, our_aci),
        None => (None, None),
    };
    let editor = editor.unwrap_or(fallback_editor);
    let change = ops
        .encrypt_group_change(editor, actions.unwrap_or_default())
        .ok()?
        .encode_to_vec();
    Some((editor, GroupUpdate::Change(change)))
}

/// The editor the backup names, if any, and the actions of the change —
/// `None` when the backup left out a participant the actions need.
fn plan(update: &Update, ops: &GroupOperations, our_aci: Aci) -> (Option<Aci>, Option<Actions>) {
    let actions = |editor: Option<Aci>, actions: Option<Actions>| (editor, actions);
    let mut rng = rand::rng();

    match update {
        Update::GenericGroupUpdate(u) => actions(aci(&u.updater_aci), None),
        // Handled before the actions are planned: creation has no change.
        Update::GroupCreationUpdate(u) => actions(aci(&u.updater_aci), None),
        Update::GroupNameUpdate(u) => actions(
            aci(&u.updater_aci),
            Some(Actions {
                modify_title: Some(ops.build_modify_title_action(
                    u.new_group_name.as_deref().unwrap_or(""),
                    &mut rng,
                )),
                ..Default::default()
            }),
        ),
        Update::GroupAvatarUpdate(u) => actions(
            aci(&u.updater_aci),
            Some(Actions {
                modify_avatar: Some(ops.build_modify_avatar_action(if u.was_removed {
                    String::new()
                } else {
                    BACKUP_AVATAR_PATH.to_string()
                })),
                ..Default::default()
            }),
        ),
        Update::GroupDescriptionUpdate(u) => actions(
            aci(&u.updater_aci),
            Some(Actions {
                modify_description: Some(ops.build_modify_description_action(
                    u.new_description.as_deref().unwrap_or(""),
                    &mut rng,
                )),
                ..Default::default()
            }),
        ),
        Update::GroupMembershipAccessLevelChangeUpdate(u) => actions(
            aci(&u.updater_aci),
            access_level(u.access_level).map(|access| Actions {
                modify_member_access: Some(ops.build_modify_members_access_action(access)),
                ..Default::default()
            }),
        ),
        Update::GroupAttributesAccessLevelChangeUpdate(u) => actions(
            aci(&u.updater_aci),
            access_level(u.access_level).map(|access| Actions {
                modify_attributes_access: Some(ops.build_modify_attributes_access_action(access)),
                ..Default::default()
            }),
        ),
        Update::GroupAnnouncementOnlyChangeUpdate(u) => actions(
            aci(&u.updater_aci),
            Some(Actions {
                modify_announcements_only: Some(
                    ops.build_modify_announcements_only_action(u.is_announcement_only),
                ),
                ..Default::default()
            }),
        ),
        Update::GroupAdminStatusUpdate(u) => {
            let role = if u.was_admin_status_granted {
                Role::Administrator
            } else {
                Role::Default
            };
            actions(
                aci(&u.updater_aci),
                aci_bytes(&u.member_aci)
                    .and_then(|member| ops.build_modify_member_role_action(member, role).ok())
                    .map(|role| Actions {
                        modify_member_roles: vec![role],
                        ..Default::default()
                    }),
            )
        }
        Update::GroupMemberLeftUpdate(u) => {
            let leaver = aci_bytes(&u.aci);
            actions(leaver, leaver.and_then(|leaver| remove_member(ops, leaver)))
        }
        Update::GroupMemberRemovedUpdate(u) => actions(
            aci(&u.remover_aci),
            aci_bytes(&u.removed_aci).and_then(|removed| remove_member(ops, removed)),
        ),
        Update::SelfInvitedToGroupUpdate(u) => {
            let inviter = aci(&u.inviter_aci);
            actions(
                inviter,
                add_pending_member(ops, our_aci.into(), inviter.unwrap_or(our_aci)),
            )
        }
        Update::SelfInvitedOtherUserToGroupUpdate(u) => actions(
            Some(our_aci),
            ServiceId::parse_from_service_id_binary(&u.invitee_service_id)
                .and_then(|invitee| add_pending_member(ops, invitee, our_aci)),
        ),
        Update::GroupUnknownInviteeUpdate(u) => actions(aci(&u.inviter_aci), None),
        Update::GroupInvitationAcceptedUpdate(u) => {
            let joiner = aci_bytes(&u.new_member_aci);
            actions(
                joiner,
                joiner.and_then(|joiner| {
                    Some(Actions {
                        promote_members_pending_profile_key: vec![ops
                            .build_promote_pending_member_action(joiner, placeholder_profile_key())
                            .ok()?],
                        ..Default::default()
                    })
                }),
            )
        }
        Update::GroupInvitationDeclinedUpdate(u) => match aci(&u.invitee_aci) {
            Some(invitee) => actions(Some(invitee), remove_pending_member(ops, invitee.into())),
            None => actions(aci(&u.inviter_aci), None),
        },
        Update::GroupMemberJoinedUpdate(u) => {
            let joiner = aci_bytes(&u.new_member_aci);
            actions(
                joiner,
                joiner.and_then(|joiner| add_member(ops, joiner, false)),
            )
        }
        Update::GroupMemberJoinedByLinkUpdate(u) => {
            let joiner = aci_bytes(&u.new_member_aci);
            actions(
                joiner,
                joiner.and_then(|joiner| add_member(ops, joiner, true)),
            )
        }
        Update::GroupMemberAddedUpdate(u) => actions(
            aci(&u.updater_aci),
            aci_bytes(&u.new_member_aci).and_then(|added| add_member(ops, added, false)),
        ),
        Update::GroupSelfInvitationRevokedUpdate(u) => actions(
            aci(&u.revoker_aci),
            remove_pending_member(ops, our_aci.into()),
        ),
        Update::GroupInvitationRevokedUpdate(u) => {
            let invitee = u.invitees.iter().find_map(|invitee| {
                aci(&invitee.invitee_aci)
                    .map(ServiceId::from)
                    .or_else(|| pni(&invitee.invitee_pni).map(ServiceId::from))
            });
            actions(
                aci(&u.updater_aci),
                invitee.and_then(|invitee| remove_pending_member(ops, invitee)),
            )
        }
        Update::GroupJoinRequestUpdate(u) => {
            let requester = aci_bytes(&u.requestor_aci);
            actions(
                requester,
                requester.and_then(|requester| {
                    Some(Actions {
                        add_members_pending_admin_approval: vec![ops
                            .build_add_requesting_member_action(
                                requester,
                                placeholder_profile_key(),
                            )
                            .ok()?],
                        ..Default::default()
                    })
                }),
            )
        }
        Update::GroupJoinRequestApprovalUpdate(u) => actions(
            aci(&u.updater_aci),
            aci_bytes(&u.requestor_aci).and_then(|requester| {
                if u.was_approved {
                    Some(Actions {
                        promote_members_pending_admin_approval: vec![ops
                            .build_promote_requesting_member_action(requester, Role::Default)
                            .ok()?],
                        ..Default::default()
                    })
                } else {
                    remove_requesting_member(ops, requester)
                }
            }),
        ),
        Update::GroupJoinRequestCanceledUpdate(u) => {
            let requester = aci_bytes(&u.requestor_aci);
            actions(
                requester,
                requester.and_then(|requester| remove_requesting_member(ops, requester)),
            )
        }
        Update::GroupSequenceOfRequestsAndCancelsUpdate(u) => {
            let requester = aci_bytes(&u.requestor_aci);
            actions(
                requester,
                requester.and_then(|requester| remove_requesting_member(ops, requester)),
            )
        }
        Update::GroupInviteLinkResetUpdate(u) => actions(
            aci(&u.updater_aci),
            Some(Actions {
                modify_invite_link_password: Some(
                    ops.build_modify_invite_link_password_action(Vec::new()),
                ),
                ..Default::default()
            }),
        ),
        Update::GroupInviteLinkEnabledUpdate(u) => actions(
            aci(&u.updater_aci),
            Some(invite_link_access(
                ops,
                link_access(u.link_requires_admin_approval),
            )),
        ),
        Update::GroupInviteLinkAdminApprovalUpdate(u) => actions(
            aci(&u.updater_aci),
            Some(invite_link_access(
                ops,
                link_access(u.link_requires_admin_approval),
            )),
        ),
        Update::GroupInviteLinkDisabledUpdate(u) => actions(
            aci(&u.updater_aci),
            Some(invite_link_access(ops, AccessRequired::Unsatisfiable)),
        ),
        Update::GroupV2MigrationUpdate(_)
        | Update::GroupV2MigrationSelfInvitedUpdate(_)
        | Update::GroupV2MigrationInvitedMembersUpdate(_)
        | Update::GroupV2MigrationDroppedMembersUpdate(_) => actions(None, None),
        Update::GroupExpirationTimerUpdate(u) => {
            let timer = Timer {
                duration: (u.expires_in_ms / 1000) as u32,
            };
            actions(
                aci(&u.updater_aci),
                Some(Actions {
                    modify_disappearing_message_timer: Some(
                        ops.build_modify_disappearing_messages_timer_action(&timer, &mut rng),
                    ),
                    ..Default::default()
                }),
            )
        }
    }
}

fn placeholder_profile_key() -> ProfileKey {
    ProfileKey::generate(rand::random())
}

fn add_member(ops: &GroupOperations, aci: Aci, join_from_invite_link: bool) -> Option<Actions> {
    let added = ops
        .build_add_member_action(aci, placeholder_profile_key(), Role::Default)
        .ok()?;
    Some(Actions {
        add_members: vec![
            libsignal_service::proto::group_change::actions::AddMemberAction {
                join_from_invite_link,
                ..added
            },
        ],
        ..Default::default()
    })
}

fn remove_member(ops: &GroupOperations, aci: Aci) -> Option<Actions> {
    Some(Actions {
        delete_members: vec![ops.build_remove_member_action(aci).ok()?],
        ..Default::default()
    })
}

fn add_pending_member(ops: &GroupOperations, invitee: ServiceId, inviter: Aci) -> Option<Actions> {
    Some(Actions {
        add_members_pending_profile_key: vec![ops
            .build_add_pending_member_action(invitee, inviter, Role::Default)
            .ok()?],
        ..Default::default()
    })
}

fn remove_pending_member(ops: &GroupOperations, invitee: ServiceId) -> Option<Actions> {
    Some(Actions {
        delete_members_pending_profile_key: vec![ops
            .build_remove_pending_member_action(invitee)
            .ok()?],
        ..Default::default()
    })
}

fn remove_requesting_member(ops: &GroupOperations, aci: Aci) -> Option<Actions> {
    Some(Actions {
        delete_members_pending_admin_approval: vec![ops
            .build_remove_requesting_member_action(aci)
            .ok()?],
        ..Default::default()
    })
}

fn invite_link_access(ops: &GroupOperations, access: AccessRequired) -> Actions {
    Actions {
        modify_add_from_invite_link_access: Some(
            ops.build_modify_invite_link_access_action(access),
        ),
        ..Default::default()
    }
}

fn link_access(requires_admin_approval: bool) -> AccessRequired {
    if requires_admin_approval {
        AccessRequired::Administrator
    } else {
        AccessRequired::Any
    }
}

/// A backup `GroupV2AccessLevel` has the wire `AccessRequired`'s numbering.
fn access_level(level: i32) -> Option<AccessRequired> {
    AccessRequired::try_from(level).ok()
}

/// A group avatar change on the wire names the new avatar's server path;
/// the backup does not keep it. Readers of the row only ask whether the path
/// is empty (removed) or not (changed), and the avatar itself is hydrated
/// from the group state, never from this row.
const BACKUP_AVATAR_PATH: &str = "backup";

pub(super) fn aci_bytes(bytes: &[u8]) -> Option<Aci> {
    <[u8; 16]>::try_from(bytes).ok().map(Aci::from_uuid_bytes)
}

fn aci(bytes: &Option<Vec<u8>>) -> Option<Aci> {
    bytes.as_deref().and_then(aci_bytes)
}

fn pni(bytes: &Option<Vec<u8>>) -> Option<Pni> {
    bytes
        .as_deref()
        .and_then(|b| <[u8; 16]>::try_from(b).ok())
        .map(Pni::from_uuid_bytes)
}
