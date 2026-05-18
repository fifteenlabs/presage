//! Sync `call_event` payload model.
//!
//! Decodes the per-event protobuf record that Signal's linked devices sync to
//! each other as a call progresses (`Observed` → `Accepted`/`NotAccepted`,
//! optionally `Delete`) and provides the pure state-machine merge that
//! collapses those events into a single canonical [`CallHistoryEntry`].
//!
//! Live `CallMessage` signaling is intentionally not modelled here — only the
//! sync record that another linked device emits.

use libsignal_service::content::{Content, ContentBody};
use libsignal_service::prelude::Uuid;
use libsignal_service::proto::sync_message::call_event::{Direction, Event, Type};
use libsignal_service::protocol::{Aci, ServiceId};
use libsignal_service::zkgroup::GroupMasterKeyBytes;

use crate::store::{ContentsStore, Thread};

/// Direct (1:1), Group, or Adhoc (call link).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallMode {
    Direct,
    Group,
    Adhoc,
    Unknown,
}

impl CallMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "Direct",
            Self::Group => "Group",
            Self::Adhoc => "Adhoc",
            Self::Unknown => "Unknown",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "Direct" => Self::Direct,
            "Group" => Self::Group,
            "Adhoc" => Self::Adhoc,
            _ => Self::Unknown,
        }
    }
}

/// Audio / Video / Group / Adhoc.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallType {
    Audio,
    Video,
    Group,
    Adhoc,
    Unknown,
}

impl CallType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Audio => "Audio",
            Self::Video => "Video",
            Self::Group => "Group",
            Self::Adhoc => "Adhoc",
            Self::Unknown => "Unknown",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "Audio" => Self::Audio,
            "Video" => Self::Video,
            "Group" => Self::Group,
            "Adhoc" => Self::Adhoc,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallDirection {
    Incoming,
    Outgoing,
    Unknown,
}

impl CallDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Incoming => "Incoming",
            Self::Outgoing => "Outgoing",
            Self::Unknown => "Unknown",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "Incoming" => Self::Incoming,
            "Outgoing" => Self::Outgoing,
            _ => Self::Unknown,
        }
    }
}

/// Raw `event` value from a single sync `call_event` protobuf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallEventKind {
    Accepted,
    NotAccepted,
    Delete,
    Observed,
    Unknown,
}

/// Status of a direct (1:1) call. Mirrors Signal Desktop's
/// `DirectCallStatus`. `MissedNotificationProfile` is intentionally collapsed
/// into `Missed` for v1 (Desktop has a `TODO: DESKTOP-3483 — not generated
/// locally` note on the variant).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectCallStatus {
    Pending,
    Accepted,
    Missed,
    Declined,
    Deleted,
    Unknown,
}

impl DirectCallStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "Pending",
            Self::Accepted => "Accepted",
            Self::Missed => "Missed",
            Self::Declined => "Declined",
            Self::Deleted => "Deleted",
            Self::Unknown => "Unknown",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "Pending" => Self::Pending,
            "Accepted" => Self::Accepted,
            "Missed" => Self::Missed,
            "Declined" => Self::Declined,
            "Deleted" => Self::Deleted,
            _ => Self::Unknown,
        }
    }
}

/// Status of a group call. Mirrors Signal Desktop's `GroupCallStatus`.
///
/// `Generic` is "observed but no specific local outcome" (Desktop calls it
/// `GenericGroupCall`; we drop the prefix since our mode is on a separate
/// field). `Joined` and `Accepted` are deliberately distinct — Desktop uses
/// `Joined` for "we joined the call" and `Accepted` for "we accepted an
/// incoming ring without necessarily joining".
///
/// Wire sync events (PR 3) can only produce: `Generic`, `Joined`, `Missed`,
/// `Declined`, `Deleted`. Backup import (PR 5) will reach the full set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupCallStatus {
    Generic,
    OutgoingRing,
    Ringing,
    Joined,
    Accepted,
    Missed,
    Declined,
    Deleted,
    Unknown,
}

impl GroupCallStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Generic => "GenericGroupCall",
            Self::OutgoingRing => "OutgoingRing",
            Self::Ringing => "Ringing",
            Self::Joined => "Joined",
            Self::Accepted => "Accepted",
            Self::Missed => "Missed",
            Self::Declined => "Declined",
            Self::Deleted => "Deleted",
            Self::Unknown => "Unknown",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "GenericGroupCall" => Self::Generic,
            "OutgoingRing" => Self::OutgoingRing,
            "Ringing" => Self::Ringing,
            "Joined" => Self::Joined,
            "Accepted" => Self::Accepted,
            "Missed" => Self::Missed,
            "Declined" => Self::Declined,
            "Deleted" => Self::Deleted,
            _ => Self::Unknown,
        }
    }
}

/// Mode-typed status carried by [`CallHistoryEntry`].
///
/// Composite over [`DirectCallStatus`] and [`GroupCallStatus`]. Adhoc is
/// reserved for PR 6.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallStatus {
    Direct(DirectCallStatus),
    Group(GroupCallStatus),
}

impl CallStatus {
    /// String form for schema serialization. Direct and group string spaces
    /// overlap (`Accepted`, `Missed`, …) — readers disambiguate via the
    /// `mode` column.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Direct(s) => s.as_str(),
            Self::Group(s) => s.as_str(),
        }
    }

    /// Parse a stored status string in the context of a known `mode`.
    pub fn parse(mode: CallMode, s: &str) -> Self {
        match mode {
            CallMode::Direct => Self::Direct(DirectCallStatus::parse(s)),
            CallMode::Group => Self::Group(GroupCallStatus::parse(s)),
            // Adhoc/Unknown fall through to Direct::Unknown for now.
            _ => Self::Direct(DirectCallStatus::Unknown),
        }
    }
}

/// Decoded view of a single sync `call_event` protobuf — one record per event,
/// before the state machine merges them by `call_id`.
#[derive(Clone, Debug)]
pub struct CallEventInfo {
    pub call_id: u64,
    pub conversation_id: Vec<u8>,
    pub timestamp_ms: u64,
    pub mode: CallMode,
    pub call_type: CallType,
    pub direction: CallDirection,
    pub event: CallEventKind,
}

/// Canonical merged call log entry — one per `(call_id, peer_id)`.
#[derive(Clone, Debug)]
pub struct CallHistoryEntry {
    pub call_id: u64,
    /// Peer identity: UUID string for `Direct` mode (1:1). Group/Adhoc use
    /// other encodings (group_id / room_id) — not handled by the v1 state machine.
    pub peer_id: String,
    pub mode: CallMode,
    pub call_type: CallType,
    pub direction: CallDirection,
    pub status: CallStatus,
    /// Timestamp of the first event observed for this call. Stays anchored at
    /// the first event so the entry's chronological position doesn't shift as
    /// later events arrive.
    pub timestamp_ms: u64,
}

/// Extract a typed [`CallEventInfo`] from a `SynchronizeMessage` carrying a
/// `call_event`. Returns `None` for any other content body or for a
/// malformed/partial event payload.
pub fn extract_call_event(body: &ContentBody) -> Option<CallEventInfo> {
    let sm = match body {
        ContentBody::SynchronizeMessage(sm) => sm,
        _ => return None,
    };
    let ce = sm.call_event.as_ref()?;

    let call_type = match Type::try_from(ce.r#type.unwrap_or(0)).ok() {
        Some(Type::AudioCall) => CallType::Audio,
        Some(Type::VideoCall) => CallType::Video,
        Some(Type::GroupCall) => CallType::Group,
        Some(Type::AdHocCall) => CallType::Adhoc,
        _ => CallType::Unknown,
    };
    let mode = match call_type {
        CallType::Audio | CallType::Video => CallMode::Direct,
        CallType::Group => CallMode::Group,
        CallType::Adhoc => CallMode::Adhoc,
        CallType::Unknown => CallMode::Unknown,
    };
    let direction = match Direction::try_from(ce.direction.unwrap_or(0)).ok() {
        Some(Direction::Incoming) => CallDirection::Incoming,
        Some(Direction::Outgoing) => CallDirection::Outgoing,
        _ => CallDirection::Unknown,
    };
    let event = match Event::try_from(ce.event.unwrap_or(0)).ok() {
        Some(Event::Accepted) => CallEventKind::Accepted,
        Some(Event::NotAccepted) => CallEventKind::NotAccepted,
        Some(Event::Delete) => CallEventKind::Delete,
        Some(Event::Observed) => CallEventKind::Observed,
        _ => CallEventKind::Unknown,
    };

    Some(CallEventInfo {
        call_id: ce.call_id?,
        conversation_id: ce.conversation_id.clone()?,
        timestamp_ms: ce.timestamp?,
        mode,
        call_type,
        direction,
        event,
    })
}

/// Derive the `call_id` (u64) from a group call's `era_id` (string).
///
/// Mirrors RingRTC's `RingId::from_era_id` (`signalapp/ringrtc`,
/// `src/rust/src/core/group_call.rs`). Used to correlate the in-band
/// `DataMessage.group_call_update` (carries `era_id`) with the
/// `SyncMessage.call_event` (carries `call_id`) for the same group call —
/// render-time dedup uses it to suppress whichever surface is overshadowed.
///
/// Happy path: a 16-hex-char `era_id` parses directly as a u64. RingRTC
/// reserves `0` as an invalid id and remaps it to `-1` (cast to `u64::MAX`).
/// Otherwise SHA-256 the bytes and interpret the first 8 little-endian as i64.
pub fn call_id_from_era_id(era_id: &str) -> u64 {
    use sha2::{Digest, Sha256};
    if era_id.len() == 16 {
        if let Ok(i) = u64::from_str_radix(era_id, 16) {
            if i == 0 {
                return (-1i64) as u64;
            }
            return i;
        }
    }
    let hash = Sha256::digest(era_id.as_bytes());
    let bytes: [u8; 8] = hash[..8].try_into().expect("sha256 digest is 32 bytes");
    i64::from_le_bytes(bytes) as u64
}

/// Typed peer for a call event.
///
/// `Direct` carries the peer's ACI (1:1); `Group` carries the group's
/// master_key (resolved via the store from the wire-format 32-byte group_id).
/// Adhoc/call-link rooms are not yet modelled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallPeer {
    Direct(Uuid),
    Group(GroupMasterKeyBytes),
}

impl CallPeer {
    /// Stable string form used as `peer_id` in [`CallHistoryEntry`].
    /// 1:1 uses the UUID display form; groups use lowercase hex of the
    /// 32-byte master_key (matches the thread_id convention elsewhere).
    pub fn peer_id(&self) -> String {
        match self {
            Self::Direct(uuid) => uuid.to_string(),
            Self::Group(mk) => hex::encode(mk),
        }
    }

    /// The [`Thread`] this peer routes to.
    pub fn to_thread(&self) -> Thread {
        match self {
            Self::Direct(uuid) => {
                let aci = Aci::from_uuid_bytes(uuid.into_bytes());
                Thread::Contact(ServiceId::from(aci))
            }
            Self::Group(mk) => Thread::Group(*mk),
        }
    }

    /// Reverse of [`Self::to_thread`]. Returns the typed peer for a
    /// `Direct` or `Group` thread. The `Option` return reserves room for
    /// future thread variants (Adhoc / CallLink) that don't map to a
    /// `CallPeer`; today this never returns `None`.
    pub fn from_thread(thread: &Thread) -> Option<Self> {
        match thread {
            Thread::Contact(sid) => Some(CallPeer::Direct(sid.raw_uuid())),
            Thread::Group(master_key) => Some(CallPeer::Group(*master_key)),
        }
    }
}

/// Find the `master_key` whose derived `group_id` matches `target_group_id`.
///
/// Sync `call_event.conversation_id` for group calls carries the 32-byte
/// derived `group_id`, but the rest of presage indexes groups by `master_key`.
/// The derivation is one-way (SHO hash). Stores that index `group_id` as a
/// column implement the lookup in O(log N) via SQL; the trait default falls
/// back to iteration + per-row zkgroup derivation.
pub async fn resolve_group_master_key_from_group_id<S: ContentsStore>(
    store: &S,
    target_group_id: &[u8; 32],
) -> Result<Option<GroupMasterKeyBytes>, S::ContentsStoreError> {
    store.group_by_group_id(target_group_id).await
}

/// Resolve a [`CallEventInfo`] to its typed peer.
///
/// Returns `Ok(None)` for adhoc (not yet supported) and for group calls whose
/// derived `group_id` doesn't match any stored group (e.g. a call event that
/// arrived before the group was synced).
pub async fn resolve_call_peer<S: ContentsStore>(
    info: &CallEventInfo,
    store: &S,
) -> Result<Option<CallPeer>, S::ContentsStoreError> {
    match info.mode {
        CallMode::Direct => {
            let uuid_bytes: [u8; 16] = match info.conversation_id.as_slice().try_into() {
                Ok(b) => b,
                Err(_) => return Ok(None),
            };
            Ok(Some(CallPeer::Direct(Uuid::from_bytes(uuid_bytes))))
        }
        CallMode::Group => {
            let group_id: [u8; 32] = match info.conversation_id.as_slice().try_into() {
                Ok(b) => b,
                Err(_) => return Ok(None),
            };
            Ok(resolve_group_master_key_from_group_id(store, &group_id)
                .await?
                .map(CallPeer::Group))
        }
        CallMode::Adhoc | CallMode::Unknown => Ok(None),
    }
}

/// Resolve the [`Thread`] for a `Content` carrying a sync `call_event`, using
/// the store to translate group call `group_id` into a `Thread::Group`.
///
/// Returns `Ok(None)` when the content is not a sync call_event, or when it
/// is but can't be resolved (adhoc, malformed, unknown group). Callers fall
/// back to [`Thread::try_from`] in that case.
pub async fn resolve_call_thread<S: ContentsStore>(
    content: &Content,
    store: &S,
) -> Result<Option<Thread>, S::ContentsStoreError> {
    let Some(info) = extract_call_event(&content.body) else {
        return Ok(None);
    };
    Ok(resolve_call_peer(&info, store)
        .await?
        .map(|peer| peer.to_thread()))
}

/// Merge a freshly-arrived sync call event into the prior canonical entry,
/// returning the new entry. Dispatches by mode. Adhoc returns `None` (PR 6).
pub fn transition_call_history(
    prev: Option<&CallHistoryEntry>,
    info: &CallEventInfo,
    peer_id: String,
) -> Option<CallHistoryEntry> {
    match info.mode {
        CallMode::Direct => transition_direct(prev, info, peer_id),
        CallMode::Group => transition_group(prev, info, peer_id),
        CallMode::Adhoc | CallMode::Unknown => None,
    }
}

/// State machine for 1:1 (direct) calls.
///
/// Rules:
/// - `Delete` is terminal — any prior status flips to `Deleted` and stays.
/// - `Accepted` is sticky — once accepted, no other event downgrades it.
/// - `NotAccepted` → `Missed` (UI applies the asymmetric Declined/Missed
///   labelling at render time based on direction).
/// - `Observed` → `Pending`.
/// - Timestamp anchored at the first observed event.
fn transition_direct(
    prev: Option<&CallHistoryEntry>,
    info: &CallEventInfo,
    peer_id: String,
) -> Option<CallHistoryEntry> {
    let prev_direct = prev.and_then(|p| match p.status {
        CallStatus::Direct(s) => Some(s),
        _ => None,
    });
    let anchored_ts = prev.map(|p| p.timestamp_ms).unwrap_or(info.timestamp_ms);

    let entry = |status: DirectCallStatus| CallHistoryEntry {
        call_id: info.call_id,
        peer_id: peer_id.clone(),
        mode: info.mode,
        call_type: info.call_type,
        direction: info.direction,
        status: CallStatus::Direct(status),
        timestamp_ms: anchored_ts,
    };

    if info.event == CallEventKind::Delete || prev_direct == Some(DirectCallStatus::Deleted) {
        return Some(entry(DirectCallStatus::Deleted));
    }
    if prev_direct == Some(DirectCallStatus::Accepted) || info.event == CallEventKind::Accepted {
        return Some(entry(DirectCallStatus::Accepted));
    }

    let status = match (info.event, info.direction) {
        (CallEventKind::NotAccepted, _) => DirectCallStatus::Missed,
        (CallEventKind::Observed, _) => DirectCallStatus::Pending,
        _ => prev_direct.unwrap_or(DirectCallStatus::Pending),
    };
    Some(entry(status))
}

/// State machine for group calls.
///
/// Rules (mirror Signal Desktop's group `transitionCallHistoryStatus`):
/// - `Delete` is terminal.
/// - `Joined` is sticky — wire `Accepted` lands as `Joined` (we joined the
///   call) and stays joined against later non-Delete events.
/// - `Observed` → `Generic` (call exists; no specific local outcome).
/// - `NotAccepted + Incoming` → `Missed` (incoming ring not answered).
/// - `NotAccepted + Outgoing` → `Generic` (outgoing ring with no join; group
///   semantics have no symmetric "declined" outcome — Desktop drops it into
///   the generic bucket too).
/// - Other → keep prior or `Generic`.
/// - Timestamp anchored at the first observed event.
fn transition_group(
    prev: Option<&CallHistoryEntry>,
    info: &CallEventInfo,
    peer_id: String,
) -> Option<CallHistoryEntry> {
    let prev_group = prev.and_then(|p| match p.status {
        CallStatus::Group(s) => Some(s),
        _ => None,
    });
    let anchored_ts = prev.map(|p| p.timestamp_ms).unwrap_or(info.timestamp_ms);

    let entry = |status: GroupCallStatus| CallHistoryEntry {
        call_id: info.call_id,
        peer_id: peer_id.clone(),
        mode: info.mode,
        call_type: info.call_type,
        direction: info.direction,
        status: CallStatus::Group(status),
        timestamp_ms: anchored_ts,
    };

    if info.event == CallEventKind::Delete || prev_group == Some(GroupCallStatus::Deleted) {
        return Some(entry(GroupCallStatus::Deleted));
    }
    if prev_group == Some(GroupCallStatus::Joined) || info.event == CallEventKind::Accepted {
        return Some(entry(GroupCallStatus::Joined));
    }

    let status = match (info.event, info.direction) {
        (CallEventKind::Observed, _) => GroupCallStatus::Generic,
        (CallEventKind::NotAccepted, CallDirection::Incoming) => GroupCallStatus::Missed,
        (CallEventKind::NotAccepted, _) => GroupCallStatus::Generic,
        _ => prev_group.unwrap_or(GroupCallStatus::Generic),
    };
    Some(entry(status))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(event: CallEventKind, direction: CallDirection, ts: u64) -> CallEventInfo {
        CallEventInfo {
            call_id: 42,
            conversation_id: vec![0; 16],
            timestamp_ms: ts,
            mode: CallMode::Direct,
            call_type: CallType::Audio,
            direction,
            event,
        }
    }

    fn group_info(event: CallEventKind, direction: CallDirection, ts: u64) -> CallEventInfo {
        CallEventInfo {
            call_id: 42,
            conversation_id: vec![0; 32],
            timestamp_ms: ts,
            mode: CallMode::Group,
            call_type: CallType::Group,
            direction,
            event,
        }
    }

    fn peer() -> String {
        "00000000-0000-0000-0000-000000000001".to_string()
    }

    // ---- direct ----

    #[test]
    fn direct_observed_fresh_becomes_pending() {
        let out = transition_call_history(
            None,
            &info(CallEventKind::Observed, CallDirection::Incoming, 100),
            peer(),
        )
        .unwrap();
        assert_eq!(out.status, CallStatus::Direct(DirectCallStatus::Pending));
        assert_eq!(out.timestamp_ms, 100);
    }

    #[test]
    fn direct_not_accepted_incoming_is_missed() {
        let prev = transition_call_history(
            None,
            &info(CallEventKind::Observed, CallDirection::Incoming, 100),
            peer(),
        );
        let out = transition_call_history(
            prev.as_ref(),
            &info(CallEventKind::NotAccepted, CallDirection::Incoming, 200),
            peer(),
        )
        .unwrap();
        assert_eq!(out.status, CallStatus::Direct(DirectCallStatus::Missed));
    }

    #[test]
    fn direct_not_accepted_outgoing_is_missed() {
        let prev = transition_call_history(
            None,
            &info(CallEventKind::Observed, CallDirection::Outgoing, 100),
            peer(),
        );
        let out = transition_call_history(
            prev.as_ref(),
            &info(CallEventKind::NotAccepted, CallDirection::Outgoing, 200),
            peer(),
        )
        .unwrap();
        assert_eq!(out.status, CallStatus::Direct(DirectCallStatus::Missed));
    }

    #[test]
    fn direct_accepted_is_sticky_against_later_not_accepted() {
        let prev = transition_call_history(
            None,
            &info(CallEventKind::Accepted, CallDirection::Incoming, 100),
            peer(),
        );
        assert_eq!(
            prev.as_ref().unwrap().status,
            CallStatus::Direct(DirectCallStatus::Accepted)
        );
        let out = transition_call_history(
            prev.as_ref(),
            &info(CallEventKind::NotAccepted, CallDirection::Incoming, 200),
            peer(),
        )
        .unwrap();
        assert_eq!(out.status, CallStatus::Direct(DirectCallStatus::Accepted));
    }

    #[test]
    fn direct_delete_is_terminal_over_accepted() {
        let prev = transition_call_history(
            None,
            &info(CallEventKind::Accepted, CallDirection::Incoming, 100),
            peer(),
        );
        let out = transition_call_history(
            prev.as_ref(),
            &info(CallEventKind::Delete, CallDirection::Incoming, 200),
            peer(),
        )
        .unwrap();
        assert_eq!(out.status, CallStatus::Direct(DirectCallStatus::Deleted));
    }

    #[test]
    fn direct_delete_is_terminal_even_against_later_events() {
        let prev = transition_call_history(
            None,
            &info(CallEventKind::Delete, CallDirection::Incoming, 100),
            peer(),
        );
        let out = transition_call_history(
            prev.as_ref(),
            &info(CallEventKind::Accepted, CallDirection::Incoming, 200),
            peer(),
        )
        .unwrap();
        assert_eq!(out.status, CallStatus::Direct(DirectCallStatus::Deleted));
    }

    #[test]
    fn direct_timestamp_anchored_at_first_event() {
        let prev = transition_call_history(
            None,
            &info(CallEventKind::Observed, CallDirection::Incoming, 100),
            peer(),
        );
        let out = transition_call_history(
            prev.as_ref(),
            &info(CallEventKind::Accepted, CallDirection::Incoming, 500),
            peer(),
        )
        .unwrap();
        assert_eq!(out.timestamp_ms, 100);
    }

    // ---- group ----

    #[test]
    fn group_observed_fresh_becomes_generic() {
        let out = transition_call_history(
            None,
            &group_info(CallEventKind::Observed, CallDirection::Incoming, 100),
            peer(),
        )
        .unwrap();
        assert_eq!(out.status, CallStatus::Group(GroupCallStatus::Generic));
        assert_eq!(out.timestamp_ms, 100);
    }

    #[test]
    fn group_accepted_lands_as_joined() {
        let out = transition_call_history(
            None,
            &group_info(CallEventKind::Accepted, CallDirection::Incoming, 100),
            peer(),
        )
        .unwrap();
        assert_eq!(out.status, CallStatus::Group(GroupCallStatus::Joined));
    }

    #[test]
    fn group_joined_is_sticky_against_later_not_accepted() {
        let prev = transition_call_history(
            None,
            &group_info(CallEventKind::Accepted, CallDirection::Incoming, 100),
            peer(),
        );
        let out = transition_call_history(
            prev.as_ref(),
            &group_info(CallEventKind::NotAccepted, CallDirection::Incoming, 200),
            peer(),
        )
        .unwrap();
        assert_eq!(out.status, CallStatus::Group(GroupCallStatus::Joined));
    }

    #[test]
    fn group_not_accepted_incoming_is_missed() {
        let prev = transition_call_history(
            None,
            &group_info(CallEventKind::Observed, CallDirection::Incoming, 100),
            peer(),
        );
        let out = transition_call_history(
            prev.as_ref(),
            &group_info(CallEventKind::NotAccepted, CallDirection::Incoming, 200),
            peer(),
        )
        .unwrap();
        assert_eq!(out.status, CallStatus::Group(GroupCallStatus::Missed));
    }

    #[test]
    fn group_not_accepted_outgoing_is_generic() {
        // Group calls have no symmetric "declined-outgoing" semantic; an
        // outgoing ring without a join collapses into the generic bucket.
        let out = transition_call_history(
            None,
            &group_info(CallEventKind::NotAccepted, CallDirection::Outgoing, 100),
            peer(),
        )
        .unwrap();
        assert_eq!(out.status, CallStatus::Group(GroupCallStatus::Generic));
    }

    #[test]
    fn group_delete_is_terminal_over_joined() {
        let prev = transition_call_history(
            None,
            &group_info(CallEventKind::Accepted, CallDirection::Incoming, 100),
            peer(),
        );
        let out = transition_call_history(
            prev.as_ref(),
            &group_info(CallEventKind::Delete, CallDirection::Incoming, 200),
            peer(),
        )
        .unwrap();
        assert_eq!(out.status, CallStatus::Group(GroupCallStatus::Deleted));
    }

    #[test]
    fn group_timestamp_anchored_at_first_event() {
        let prev = transition_call_history(
            None,
            &group_info(CallEventKind::Observed, CallDirection::Incoming, 100),
            peer(),
        );
        let out = transition_call_history(
            prev.as_ref(),
            &group_info(CallEventKind::Accepted, CallDirection::Incoming, 500),
            peer(),
        )
        .unwrap();
        assert_eq!(out.timestamp_ms, 100);
    }

    // ---- adhoc / unknown ----

    #[test]
    fn adhoc_mode_drops() {
        let mut i = info(CallEventKind::Observed, CallDirection::Incoming, 100);
        i.mode = CallMode::Adhoc;
        assert!(transition_call_history(None, &i, peer()).is_none());
        i.mode = CallMode::Unknown;
        assert!(transition_call_history(None, &i, peer()).is_none());
    }

    // ---- helpers ----

    #[test]
    fn call_id_from_era_id_hex_happy_path() {
        // 16 hex chars parse directly as u64.
        assert_eq!(
            call_id_from_era_id("445aa0d4d45926be"),
            0x445a_a0d4_d459_26be
        );
        // RingRTC reserves 0 → remaps to -1 (cast to u64).
        assert_eq!(call_id_from_era_id("0000000000000000"), u64::MAX);
    }

    #[test]
    fn call_id_from_era_id_sha_fallback() {
        // Non-hex era_id falls through to SHA-256-truncate-LE.
        // Verifies the algorithm is deterministic and non-zero for "abc".
        let id = call_id_from_era_id("abc");
        assert_ne!(id, 0);
        // Same input → same output (deterministic).
        assert_eq!(id, call_id_from_era_id("abc"));
        // Different inputs → different outputs (no collision in this trivial case).
        assert_ne!(id, call_id_from_era_id("xyz"));
    }
}
