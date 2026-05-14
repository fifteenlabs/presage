//! Sync `call_event` payload model.
//!
//! Decodes the per-event protobuf record that Signal's linked devices sync to
//! each other as a call progresses (`Observed` → `Accepted`/`NotAccepted`,
//! optionally `Delete`) and provides the pure state-machine merge that
//! collapses those events into a single canonical [`CallHistoryEntry`].
//!
//! Live `CallMessage` signaling is intentionally not modelled here — only the
//! sync record that another linked device emits.

use libsignal_service::content::ContentBody;
use libsignal_service::prelude::Uuid;
use libsignal_service::protocol::{Aci, ServiceId};
use libsignal_service::proto::sync_message::call_event::{Direction, Event, Type};

use crate::store::Thread;

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

/// Resolved status after merging events through [`transition_call_history`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallStatus {
    Pending,
    Accepted,
    Missed,
    Declined,
    Deleted,
    Unknown,
}

impl CallStatus {
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

/// Returns the peer UUID string for a 1:1 `conversation_id` (16 raw UUID bytes).
/// Returns `None` for group (32-byte group_id) and adhoc (room_id) payloads.
pub fn call_conversation_id_to_peer_uuid(bytes: &[u8]) -> Option<String> {
    if bytes.len() == 16 {
        let uuid_bytes: [u8; 16] = bytes.try_into().ok()?;
        Some(Uuid::from_bytes(uuid_bytes).to_string())
    } else {
        None
    }
}

/// Convert a 1:1 `conversation_id` (16 raw UUID bytes) into a [`Thread::Contact`].
/// Returns `None` for group/adhoc payloads.
pub fn call_conversation_id_to_thread(bytes: &[u8]) -> Option<Thread> {
    if bytes.len() == 16 {
        let uuid_bytes: [u8; 16] = bytes.try_into().ok()?;
        let aci = Aci::from_uuid_bytes(uuid_bytes);
        Some(Thread::Contact(ServiceId::from(aci)))
    } else {
        None
    }
}

/// Merge a freshly-arrived sync call event into the prior canonical entry,
/// returning the new entry. Mode-specific transitions; v1 only handles Direct.
///
/// Rules (Direct):
/// - `Delete` is terminal — any prior status flips to `Deleted` and stays.
/// - `Accepted` is sticky — once accepted, no other event downgrades it.
/// - `NotAccepted` → `Missed` (incoming) or `Declined` (outgoing peer declined).
/// - `Observed` → `Pending` (call observed but no outcome yet).
/// - Timestamp stays anchored at the first observed event (chronological stability).
pub fn transition_call_history(
    prev: Option<&CallHistoryEntry>,
    info: &CallEventInfo,
    peer_id: String,
) -> Option<CallHistoryEntry> {
    if info.mode != CallMode::Direct {
        return None;
    }

    let prev_status = prev.map(|p| p.status);
    let anchored_ts = prev.map(|p| p.timestamp_ms).unwrap_or(info.timestamp_ms);

    if info.event == CallEventKind::Delete || prev_status == Some(CallStatus::Deleted) {
        return Some(CallHistoryEntry {
            call_id: info.call_id,
            peer_id,
            mode: info.mode,
            call_type: info.call_type,
            direction: info.direction,
            status: CallStatus::Deleted,
            timestamp_ms: anchored_ts,
        });
    }

    if prev_status == Some(CallStatus::Accepted) || info.event == CallEventKind::Accepted {
        return Some(CallHistoryEntry {
            call_id: info.call_id,
            peer_id,
            mode: info.mode,
            call_type: info.call_type,
            direction: info.direction,
            status: CallStatus::Accepted,
            timestamp_ms: anchored_ts,
        });
    }

    let status = match (info.event, info.direction) {
        (CallEventKind::NotAccepted, CallDirection::Incoming) => CallStatus::Missed,
        (CallEventKind::NotAccepted, CallDirection::Outgoing) => CallStatus::Declined,
        (CallEventKind::NotAccepted, CallDirection::Unknown) => CallStatus::Missed,
        (CallEventKind::Observed, _) => CallStatus::Pending,
        _ => prev_status.unwrap_or(CallStatus::Pending),
    };

    Some(CallHistoryEntry {
        call_id: info.call_id,
        peer_id,
        mode: info.mode,
        call_type: info.call_type,
        direction: info.direction,
        status,
        timestamp_ms: anchored_ts,
    })
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

    fn peer() -> String {
        "00000000-0000-0000-0000-000000000001".to_string()
    }

    #[test]
    fn observed_fresh_becomes_pending() {
        let out = transition_call_history(None, &info(CallEventKind::Observed, CallDirection::Incoming, 100), peer()).unwrap();
        assert_eq!(out.status, CallStatus::Pending);
        assert_eq!(out.timestamp_ms, 100);
    }

    #[test]
    fn not_accepted_incoming_is_missed() {
        let prev = transition_call_history(None, &info(CallEventKind::Observed, CallDirection::Incoming, 100), peer());
        let out = transition_call_history(prev.as_ref(), &info(CallEventKind::NotAccepted, CallDirection::Incoming, 200), peer()).unwrap();
        assert_eq!(out.status, CallStatus::Missed);
    }

    #[test]
    fn not_accepted_outgoing_is_declined() {
        let prev = transition_call_history(None, &info(CallEventKind::Observed, CallDirection::Outgoing, 100), peer());
        let out = transition_call_history(prev.as_ref(), &info(CallEventKind::NotAccepted, CallDirection::Outgoing, 200), peer()).unwrap();
        assert_eq!(out.status, CallStatus::Declined);
    }

    #[test]
    fn accepted_is_sticky_against_later_not_accepted() {
        let prev = transition_call_history(None, &info(CallEventKind::Accepted, CallDirection::Incoming, 100), peer());
        assert_eq!(prev.as_ref().unwrap().status, CallStatus::Accepted);
        let out = transition_call_history(prev.as_ref(), &info(CallEventKind::NotAccepted, CallDirection::Incoming, 200), peer()).unwrap();
        assert_eq!(out.status, CallStatus::Accepted);
    }

    #[test]
    fn delete_is_terminal_over_accepted() {
        let prev = transition_call_history(None, &info(CallEventKind::Accepted, CallDirection::Incoming, 100), peer());
        let out = transition_call_history(prev.as_ref(), &info(CallEventKind::Delete, CallDirection::Incoming, 200), peer()).unwrap();
        assert_eq!(out.status, CallStatus::Deleted);
    }

    #[test]
    fn delete_is_terminal_even_against_later_events() {
        let prev = transition_call_history(None, &info(CallEventKind::Delete, CallDirection::Incoming, 100), peer());
        let out = transition_call_history(prev.as_ref(), &info(CallEventKind::Accepted, CallDirection::Incoming, 200), peer()).unwrap();
        assert_eq!(out.status, CallStatus::Deleted);
    }

    #[test]
    fn non_direct_mode_drops() {
        let mut i = info(CallEventKind::Observed, CallDirection::Incoming, 100);
        i.mode = CallMode::Group;
        assert!(transition_call_history(None, &i, peer()).is_none());
        i.mode = CallMode::Adhoc;
        assert!(transition_call_history(None, &i, peer()).is_none());
    }

    #[test]
    fn timestamp_anchored_at_first_event() {
        let prev = transition_call_history(None, &info(CallEventKind::Observed, CallDirection::Incoming, 100), peer());
        let out = transition_call_history(prev.as_ref(), &info(CallEventKind::Accepted, CallDirection::Incoming, 500), peer()).unwrap();
        assert_eq!(out.timestamp_ms, 100);
    }

    #[test]
    fn conversation_id_helpers_only_match_16_bytes() {
        let bytes16 = [0u8; 16];
        let bytes32 = [0u8; 32];
        assert!(call_conversation_id_to_peer_uuid(&bytes16).is_some());
        assert!(call_conversation_id_to_peer_uuid(&bytes32).is_none());
        assert!(call_conversation_id_to_thread(&bytes16).is_some());
        assert!(call_conversation_id_to_thread(&bytes32).is_none());
    }
}
