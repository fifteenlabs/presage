//! Rebuilds a backup `GroupChangeChatUpdate` as the encrypted `GroupChange`
//! the group server would have attached to the live message.
//!
//! A backup stores group history in plaintext, already resolved; the wire form
//! stores it as `GroupChange.Actions` encrypted under the group's secret
//! params. Decryption needs only the master key — the server signature is not
//! checked — so the import can encrypt the plaintext back and store exactly
//! what the live receive path would have stored. Every reader of stored group
//! history then works unchanged.
//!
//! Member actions carry a profile-key ciphertext the decoder insists on; the
//! backup has no profile key for them, so a random one is encrypted in its
//! place. It has to be random: the decryptor lizard-decodes the plaintext
//! and rejects anything that does not decode to exactly one candidate, which
//! a constant such as all zeros does not. Nothing downstream reads the key
//! of a member named by a system row.

use libsignal_service::{
    prelude::ProtobufMessage as _,
    proto::{
        access_control::AccessRequired,
        backup::{self, group_change_chat_update::update::Update},
        group_attribute_blob::Content as Blob,
        group_change::{actions, Actions},
        member::Role,
        GroupAttributeBlob, GroupChange, Member, MemberPendingAdminApproval,
        MemberPendingProfileKey,
    },
    protocol::{Aci, Pni, ServiceId},
    zkgroup::{
        groups::{GroupMasterKey, GroupSecretParams},
        serialize,
    },
};

/// What a single backup group update becomes on the wire.
pub enum GroupUpdate {
    /// `GroupContextV2 { revision: 0 }` with no change — how a live client
    /// signals group creation.
    Created,
    /// A disappearing-timer change. Sent as the `EXPIRATION_TIMER_UPDATE`
    /// flag rather than an encrypted timer blob; that is how live clients
    /// announce it, and the flag is read before the group change is.
    Timer { expires_in_ms: u64 },
    /// Plaintext actions for the group context, encrypted by
    /// [`GroupCipher::change`] once the editor is settled. Empty actions
    /// still encrypt to a non-empty blob — an empty blob is what a silent
    /// group update looks like, and those are never stored.
    Change(Box<Actions>),
}

pub struct GroupUpdatePlan {
    /// Who made the change — the sender of the synthesised message. `None`
    /// when the backup does not say, so the caller falls back to the item's
    /// author.
    pub editor: Option<Aci>,
    pub update: GroupUpdate,
}

/// Encrypts plaintext group-change values under a group's secret params.
pub struct GroupCipher {
    params: GroupSecretParams,
}

impl GroupCipher {
    pub fn new(master_key: [u8; 32]) -> Self {
        Self {
            params: GroupSecretParams::derive_from_master_key(GroupMasterKey::new(master_key)),
        }
    }

    fn service_id(&self, service_id: ServiceId) -> Vec<u8> {
        serialize(&self.params.encrypt_service_id(service_id))
    }

    fn placeholder_profile_key(&self, aci: Aci) -> Vec<u8> {
        serialize(&self.params.encrypt_profile_key_bytes(rand::random(), aci))
    }

    fn member(&self, aci: Aci, role: Role) -> Member {
        Member {
            user_id: self.service_id(aci.into()),
            role: role as i32,
            profile_key: self.placeholder_profile_key(aci),
            ..Default::default()
        }
    }

    fn pending_member(&self, invitee: ServiceId, inviter: Aci) -> MemberPendingProfileKey {
        MemberPendingProfileKey {
            member: Some(Member {
                user_id: self.service_id(invitee),
                role: Role::Default as i32,
                ..Default::default()
            }),
            added_by_user_id: self.service_id(inviter.into()),
            timestamp: 0,
        }
    }

    fn requesting_member(&self, aci: Aci) -> MemberPendingAdminApproval {
        MemberPendingAdminApproval {
            user_id: self.service_id(aci.into()),
            profile_key: self.placeholder_profile_key(aci),
            presentation: Vec::new(),
            timestamp: 0,
        }
    }

    fn blob(&self, content: Blob) -> Vec<u8> {
        let plaintext = GroupAttributeBlob {
            content: Some(content),
        }
        .encode_to_vec();
        self.params
            .encrypt_blob_with_padding(rand::random(), &plaintext, 0)
    }

    /// The encrypted `GroupChange` for `actions` as made by `editor`. The
    /// decoder requires the 32-byte group identifier, which the server would
    /// have stamped in; it is derived from the same master key here.
    pub fn change(&self, editor: Aci, actions: Actions) -> Vec<u8> {
        let actions = Actions {
            source_user_id: self.service_id(editor.into()),
            group_id: self.params.get_group_identifier().to_vec(),
            ..actions
        };
        GroupChange {
            actions: actions.encode_to_vec(),
            server_signature: Vec::new(),
            change_epoch: 0,
        }
        .encode_to_vec()
    }
}

/// Maps one backup group update to its wire form. Every update maps to
/// something: the kinds the wire cannot express, and any whose required
/// participant the backup left out, become a change with no actions, which
/// renders as a generic "updated the group" row.
///
/// The editor is the person whose action the row describes: the updater
/// where the backup names one, and the member themself for the events a
/// member performs on their own behalf (leaving, joining, requesting,
/// declining) — that distinction is what lets a row read "You left the
/// group" rather than name a stranger.
pub fn plan_group_update(
    update: &backup::group_change_chat_update::Update,
    cipher: &GroupCipher,
    our_aci: Aci,
) -> GroupUpdatePlan {
    typed_plan(update, cipher, our_aci).unwrap_or_else(|| generic(None))
}

fn generic(editor: Option<Aci>) -> GroupUpdatePlan {
    GroupUpdatePlan {
        editor,
        update: GroupUpdate::Change(Box::default()),
    }
}

fn typed_plan(
    update: &backup::group_change_chat_update::Update,
    cipher: &GroupCipher,
    our_aci: Aci,
) -> Option<GroupUpdatePlan> {
    let change = |editor: Option<Aci>, actions: Actions| {
        Some(GroupUpdatePlan {
            editor,
            update: GroupUpdate::Change(Box::new(actions)),
        })
    };
    let delete_member = |aci: Aci| Actions {
        delete_members: vec![actions::DeleteMemberAction {
            deleted_user_id: cipher.service_id(aci.into()),
        }],
        ..Default::default()
    };
    let add_member = |aci: Aci, join_from_invite_link: bool| Actions {
        add_members: vec![actions::AddMemberAction {
            added: Some(cipher.member(aci, Role::Default)),
            join_from_invite_link,
        }],
        ..Default::default()
    };
    let delete_pending = |invitee: ServiceId| Actions {
        delete_members_pending_profile_key: vec![actions::DeleteMemberPendingProfileKeyAction {
            deleted_user_id: cipher.service_id(invitee),
        }],
        ..Default::default()
    };
    let delete_requesting = |aci: Aci| Actions {
        delete_members_pending_admin_approval: vec![
            actions::DeleteMemberPendingAdminApprovalAction {
                deleted_user_id: cipher.service_id(aci.into()),
            },
        ],
        ..Default::default()
    };
    let invite_link_access = |editor: &Option<Vec<u8>>, access: AccessRequired| {
        change(
            aci(editor),
            Actions {
                modify_add_from_invite_link_access: Some(
                    actions::ModifyAddFromInviteLinkAccessControlAction {
                        add_from_invite_link_access: access as i32,
                    },
                ),
                ..Default::default()
            },
        )
    };
    let link_access = |requires_admin_approval: bool| {
        if requires_admin_approval {
            AccessRequired::Administrator
        } else {
            AccessRequired::Any
        }
    };

    match update.update.as_ref()? {
        Update::GenericGroupUpdate(u) => Some(generic(aci(&u.updater_aci))),
        Update::GroupCreationUpdate(u) => Some(GroupUpdatePlan {
            editor: aci(&u.updater_aci),
            update: GroupUpdate::Created,
        }),
        Update::GroupNameUpdate(u) => change(
            aci(&u.updater_aci),
            Actions {
                modify_title: Some(actions::ModifyTitleAction {
                    title: cipher.blob(Blob::Title(u.new_group_name.clone().unwrap_or_default())),
                }),
                ..Default::default()
            },
        ),
        Update::GroupAvatarUpdate(u) => change(
            aci(&u.updater_aci),
            Actions {
                modify_avatar: Some(actions::ModifyAvatarAction {
                    avatar: if u.was_removed {
                        String::new()
                    } else {
                        BACKUP_AVATAR_PATH.to_string()
                    },
                }),
                ..Default::default()
            },
        ),
        Update::GroupDescriptionUpdate(u) => change(
            aci(&u.updater_aci),
            Actions {
                modify_description: Some(actions::ModifyDescriptionAction {
                    description: cipher.blob(Blob::DescriptionText(
                        u.new_description.clone().unwrap_or_default(),
                    )),
                }),
                ..Default::default()
            },
        ),
        Update::GroupMembershipAccessLevelChangeUpdate(u) => change(
            aci(&u.updater_aci),
            Actions {
                modify_member_access: Some(actions::ModifyMembersAccessControlAction {
                    members_access: u.access_level,
                }),
                ..Default::default()
            },
        ),
        Update::GroupAttributesAccessLevelChangeUpdate(u) => change(
            aci(&u.updater_aci),
            Actions {
                modify_attributes_access: Some(actions::ModifyAttributesAccessControlAction {
                    attributes_access: u.access_level,
                }),
                ..Default::default()
            },
        ),
        Update::GroupAnnouncementOnlyChangeUpdate(u) => change(
            aci(&u.updater_aci),
            Actions {
                modify_announcements_only: Some(actions::ModifyAnnouncementsOnlyAction {
                    announcements_only: u.is_announcement_only,
                }),
                ..Default::default()
            },
        ),
        Update::GroupAdminStatusUpdate(u) => {
            let role = if u.was_admin_status_granted {
                Role::Administrator
            } else {
                Role::Default
            };
            change(
                aci(&u.updater_aci),
                Actions {
                    modify_member_roles: vec![actions::ModifyMemberRoleAction {
                        user_id: cipher.service_id(aci_bytes(&u.member_aci)?.into()),
                        role: role as i32,
                    }],
                    ..Default::default()
                },
            )
        }
        Update::GroupMemberLeftUpdate(u) => {
            let leaver = aci_bytes(&u.aci)?;
            change(Some(leaver), delete_member(leaver))
        }
        Update::GroupMemberRemovedUpdate(u) => change(
            aci(&u.remover_aci),
            delete_member(aci_bytes(&u.removed_aci)?),
        ),
        Update::SelfInvitedToGroupUpdate(u) => {
            let inviter = aci(&u.inviter_aci);
            change(
                inviter,
                Actions {
                    add_members_pending_profile_key: vec![
                        actions::AddMemberPendingProfileKeyAction {
                            added: Some(
                                cipher.pending_member(our_aci.into(), inviter.unwrap_or(our_aci)),
                            ),
                        },
                    ],
                    ..Default::default()
                },
            )
        }
        Update::SelfInvitedOtherUserToGroupUpdate(u) => {
            let invitee = ServiceId::parse_from_service_id_binary(&u.invitee_service_id)?;
            change(
                Some(our_aci),
                Actions {
                    add_members_pending_profile_key: vec![
                        actions::AddMemberPendingProfileKeyAction {
                            added: Some(cipher.pending_member(invitee, our_aci)),
                        },
                    ],
                    ..Default::default()
                },
            )
        }
        Update::GroupUnknownInviteeUpdate(u) => Some(generic(aci(&u.inviter_aci))),
        Update::GroupInvitationAcceptedUpdate(u) => {
            let joiner = aci_bytes(&u.new_member_aci)?;
            change(
                Some(joiner),
                Actions {
                    promote_members_pending_profile_key: vec![
                        actions::PromoteMemberPendingProfileKeyAction {
                            user_id: cipher.service_id(joiner.into()),
                            profile_key: cipher.placeholder_profile_key(joiner),
                            presentation: Vec::new(),
                        },
                    ],
                    ..Default::default()
                },
            )
        }
        Update::GroupInvitationDeclinedUpdate(u) => match aci(&u.invitee_aci) {
            Some(invitee) => change(Some(invitee), delete_pending(invitee.into())),
            None => Some(generic(aci(&u.inviter_aci))),
        },
        Update::GroupMemberJoinedUpdate(u) => {
            let joiner = aci_bytes(&u.new_member_aci)?;
            change(Some(joiner), add_member(joiner, false))
        }
        Update::GroupMemberJoinedByLinkUpdate(u) => {
            let joiner = aci_bytes(&u.new_member_aci)?;
            change(Some(joiner), add_member(joiner, true))
        }
        Update::GroupMemberAddedUpdate(u) => change(
            aci(&u.updater_aci),
            add_member(aci_bytes(&u.new_member_aci)?, false),
        ),
        Update::GroupSelfInvitationRevokedUpdate(u) => {
            change(aci(&u.revoker_aci), delete_pending(our_aci.into()))
        }
        Update::GroupInvitationRevokedUpdate(u) => {
            let invitee = u.invitees.iter().find_map(|invitee| {
                aci(&invitee.invitee_aci)
                    .map(ServiceId::from)
                    .or_else(|| pni(&invitee.invitee_pni).map(ServiceId::from))
            });
            match invitee {
                Some(invitee) => change(aci(&u.updater_aci), delete_pending(invitee)),
                None => Some(generic(aci(&u.updater_aci))),
            }
        }
        Update::GroupJoinRequestUpdate(u) => {
            let requester = aci_bytes(&u.requestor_aci)?;
            change(
                Some(requester),
                Actions {
                    add_members_pending_admin_approval: vec![
                        actions::AddMemberPendingAdminApprovalAction {
                            added: Some(cipher.requesting_member(requester)),
                        },
                    ],
                    ..Default::default()
                },
            )
        }
        Update::GroupJoinRequestApprovalUpdate(u) => {
            let requester = aci_bytes(&u.requestor_aci)?;
            let actions = if u.was_approved {
                Actions {
                    promote_members_pending_admin_approval: vec![
                        actions::PromoteMemberPendingAdminApprovalAction {
                            user_id: cipher.service_id(requester.into()),
                            role: Role::Default as i32,
                        },
                    ],
                    ..Default::default()
                }
            } else {
                delete_requesting(requester)
            };
            change(aci(&u.updater_aci), actions)
        }
        Update::GroupJoinRequestCanceledUpdate(u) => {
            let requester = aci_bytes(&u.requestor_aci)?;
            change(Some(requester), delete_requesting(requester))
        }
        Update::GroupSequenceOfRequestsAndCancelsUpdate(u) => {
            let requester = aci_bytes(&u.requestor_aci)?;
            change(Some(requester), delete_requesting(requester))
        }
        Update::GroupInviteLinkResetUpdate(u) => change(
            aci(&u.updater_aci),
            Actions {
                modify_invite_link_password: Some(actions::ModifyInviteLinkPasswordAction {
                    invite_link_password: Vec::new(),
                }),
                ..Default::default()
            },
        ),
        Update::GroupInviteLinkEnabledUpdate(u) => {
            invite_link_access(&u.updater_aci, link_access(u.link_requires_admin_approval))
        }
        Update::GroupInviteLinkAdminApprovalUpdate(u) => {
            invite_link_access(&u.updater_aci, link_access(u.link_requires_admin_approval))
        }
        Update::GroupInviteLinkDisabledUpdate(u) => {
            invite_link_access(&u.updater_aci, AccessRequired::Unsatisfiable)
        }
        Update::GroupV2MigrationUpdate(_)
        | Update::GroupV2MigrationSelfInvitedUpdate(_)
        | Update::GroupV2MigrationInvitedMembersUpdate(_)
        | Update::GroupV2MigrationDroppedMembersUpdate(_) => Some(generic(None)),
        Update::GroupExpirationTimerUpdate(u) => Some(GroupUpdatePlan {
            editor: aci(&u.updater_aci),
            update: GroupUpdate::Timer {
                expires_in_ms: u.expires_in_ms,
            },
        }),
    }
}

/// A group avatar change on the wire names the new avatar's server path;
/// the backup does not keep it. Readers of the row only ask whether the path
/// is empty (removed) or not (changed), and the avatar itself is hydrated
/// from the group state, never from this row.
const BACKUP_AVATAR_PATH: &str = "backup";

fn aci_bytes(bytes: &[u8]) -> Option<Aci> {
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
