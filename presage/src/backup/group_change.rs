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

/// Maps one backup group change — a batch of one or more updates that came
/// from a single group state change — to its wire form and the member who
/// made it. Every update maps to something: the kinds the wire cannot
/// express become a change with no actions, and an update whose participant
/// the backup left out keeps its editor and loses only the actions. The
/// batch encrypts as one change carrying every update's actions, which the
/// decoder reads back as one change per action, so an add of three people
/// renders as three rows, as it does live.
///
/// The editor is the person whose act the row describes: the updater where
/// the backup names one, and the member themself for the events a member
/// performs on their own behalf (leaving, joining, requesting, declining) —
/// that distinction is what lets a row read "You left the group" rather
/// than name a stranger. A batch has one editor: the last update that names
/// one, as Desktop's own importer picks it. `fallback_editor` stands in when
/// the backup names nobody.
pub fn plan_group_update(
    updates: &[backup::group_change_chat_update::Update],
    ops: &GroupOperations,
    our_aci: Aci,
    fallback_editor: Aci,
) -> Option<(Aci, GroupUpdate)> {
    let creation = updates
        .iter()
        .find_map(|update| match update.update.as_ref() {
            Some(Update::GroupCreationUpdate(u)) => Some(u),
            _ => None,
        });
    if let Some(u) = creation {
        return Some((
            aci(&u.updater_aci).unwrap_or(fallback_editor),
            GroupUpdate::Created,
        ));
    }
    let mut editor = None;
    let mut merged = Actions::default();
    for update in updates.iter().filter_map(|update| update.update.as_ref()) {
        let (update_editor, actions) = plan(update, ops, our_aci);
        editor = update_editor.or(editor);
        if let Some(actions) = actions {
            merge_actions(&mut merged, actions);
        }
    }
    let editor = editor.unwrap_or(fallback_editor);
    let change = ops
        .encrypt_group_change(editor, merged)
        .ok()?
        .encode_to_vec();
    Some((editor, GroupUpdate::Change(change)))
}

/// Folds one update's actions into the batch's. Repeated fields
/// concatenate; a singular field takes the later value, as the wire would
/// after two edits. Every field is named so a new one fails to compile here
/// rather than being dropped. `source_user_id` and `group_id` are stamped
/// by `encrypt_group_change`, and `version` stays at its default.
fn merge_actions(into: &mut Actions, from: Actions) {
    let Actions {
        source_user_id: _,
        group_id: _,
        version: _,
        add_members,
        delete_members,
        modify_member_roles,
        modify_member_profile_keys,
        add_members_pending_profile_key,
        delete_members_pending_profile_key,
        promote_members_pending_profile_key,
        modify_title,
        modify_avatar,
        modify_disappearing_message_timer,
        modify_attributes_access,
        modify_member_access,
        modify_add_from_invite_link_access,
        add_members_pending_admin_approval,
        delete_members_pending_admin_approval,
        promote_members_pending_admin_approval,
        modify_invite_link_password,
        modify_description,
        modify_announcements_only,
        add_members_banned,
        delete_members_banned,
        promote_members_pending_pni_aci_profile_key,
        modify_member_labels,
        modify_member_label_access,
        terminate_group,
    } = from;
    into.add_members.extend(add_members);
    into.delete_members.extend(delete_members);
    into.modify_member_roles.extend(modify_member_roles);
    into.modify_member_profile_keys
        .extend(modify_member_profile_keys);
    into.add_members_pending_profile_key
        .extend(add_members_pending_profile_key);
    into.delete_members_pending_profile_key
        .extend(delete_members_pending_profile_key);
    into.promote_members_pending_profile_key
        .extend(promote_members_pending_profile_key);
    into.add_members_pending_admin_approval
        .extend(add_members_pending_admin_approval);
    into.delete_members_pending_admin_approval
        .extend(delete_members_pending_admin_approval);
    into.promote_members_pending_admin_approval
        .extend(promote_members_pending_admin_approval);
    into.add_members_banned.extend(add_members_banned);
    into.delete_members_banned.extend(delete_members_banned);
    into.promote_members_pending_pni_aci_profile_key
        .extend(promote_members_pending_pni_aci_profile_key);
    into.modify_member_labels.extend(modify_member_labels);
    into.modify_title = modify_title.or(into.modify_title.take());
    into.modify_avatar = modify_avatar.or(into.modify_avatar.take());
    into.modify_disappearing_message_timer =
        modify_disappearing_message_timer.or(into.modify_disappearing_message_timer.take());
    into.modify_attributes_access =
        modify_attributes_access.or(into.modify_attributes_access.take());
    into.modify_member_access = modify_member_access.or(into.modify_member_access.take());
    into.modify_add_from_invite_link_access =
        modify_add_from_invite_link_access.or(into.modify_add_from_invite_link_access.take());
    into.modify_invite_link_password =
        modify_invite_link_password.or(into.modify_invite_link_password.take());
    into.modify_description = modify_description.or(into.modify_description.take());
    into.modify_announcements_only =
        modify_announcements_only.or(into.modify_announcements_only.take());
    into.modify_member_label_access =
        modify_member_label_access.or(into.modify_member_label_access.take());
    into.terminate_group = terminate_group.or(into.terminate_group.take());
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
            let mut invitees = u.invitees.iter().filter_map(|invitee| {
                aci(&invitee.invitee_aci)
                    .map(ServiceId::from)
                    .or_else(|| pni(&invitee.invitee_pni).map(ServiceId::from))
            });
            actions(
                aci(&u.updater_aci),
                invitees.try_fold(Actions::default(), |mut all, invitee| {
                    merge_actions(&mut all, remove_pending_member(ops, invitee)?);
                    Some(all)
                }),
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
