//! Editing storage-service records without re-encoding them.
//!
//! A storage-service record must be republished byte-for-byte apart from the
//! field being changed. Decoding one into a prost struct and encoding it back
//! would drop every field prost does not model, deleting whatever a newer iOS or
//! Android client wrote. Signal-Desktop avoids this by stashing the unknown
//! fields separately and rebuilding the known ones from its conversation model —
//! which only works because its model is a faithful superset of the record.
//! presage's [`Contact`](crate::model::contacts::Contact) is not, so we edit the
//! bytes the server gave us instead.
//!
//! The operations here are therefore deliberately dumb: walk the wire format,
//! copy every field through verbatim, and touch exactly one.

use std::ops::Range;

/// `StorageRecord.contact`, from `StorageService.proto`.
const STORAGE_RECORD_CONTACT: u32 = 1;
/// `ContactRecord.blocked`.
const CONTACT_RECORD_BLOCKED: u32 = 9;
/// `ContactRecord.mutedUntilTimestamp`.
const CONTACT_RECORD_MUTED_UNTIL: u32 = 13;

const WIRE_VARINT: u8 = 0;
const WIRE_I64: u8 = 1;
const WIRE_LEN: u8 = 2;
const WIRE_I32: u8 = 5;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum StorageRecordEditError {
    #[error("malformed protobuf in stored storage record")]
    Malformed,
    #[error("stored storage record does not hold a contact")]
    NotAContact,
    /// Signal never emits a record with the same submessage twice, and picking
    /// one would silently discard the other, so refuse rather than guess.
    #[error("stored storage record holds more than one contact")]
    AmbiguousContact,
}

use StorageRecordEditError as EditError;

/// One field as it appears on the wire.
struct FieldSpan {
    number: u32,
    wire_type: u8,
    /// Tag and payload together — what gets copied through verbatim.
    whole: Range<usize>,
    /// Payload only; for length-delimited fields this excludes the length prefix.
    payload: Range<usize>,
}

fn read_varint(msg: &[u8], pos: &mut usize) -> Result<u64, EditError> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let byte = *msg.get(*pos).ok_or(EditError::Malformed)?;
        *pos += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(EditError::Malformed)
}

fn advance(pos: &mut usize, by: usize, len: usize) -> Result<usize, EditError> {
    let end = pos.checked_add(by).ok_or(EditError::Malformed)?;
    if end > len {
        return Err(EditError::Malformed);
    }
    let start = *pos;
    *pos = end;
    Ok(start)
}

/// Split a message into its fields, in wire order.
fn scan(msg: &[u8]) -> Result<Vec<FieldSpan>, EditError> {
    let mut spans = Vec::new();
    let mut pos = 0;

    while pos < msg.len() {
        let start = pos;
        let tag = read_varint(msg, &mut pos)?;
        let number = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;
        if number == 0 {
            return Err(EditError::Malformed);
        }

        let payload = match wire_type {
            WIRE_VARINT => {
                let from = pos;
                read_varint(msg, &mut pos)?;
                from..pos
            }
            WIRE_I64 => {
                let from = advance(&mut pos, 8, msg.len())?;
                from..pos
            }
            WIRE_LEN => {
                let len = read_varint(msg, &mut pos)? as usize;
                let from = advance(&mut pos, len, msg.len())?;
                from..pos
            }
            WIRE_I32 => {
                let from = advance(&mut pos, 4, msg.len())?;
                from..pos
            }
            // Groups (3, 4) were removed in proto3 and Signal never emits them.
            _ => return Err(EditError::Malformed),
        };

        spans.push(FieldSpan {
            number,
            wire_type,
            whole: start..pos,
            payload,
        });
    }

    Ok(spans)
}

/// Rewrite `msg` so that field `number` occurs exactly as `replacement` says:
/// once, in the position the first existing occurrence held, or not at all.
///
/// Every other field keeps its bytes and its position. A field that was absent
/// is appended, which is where a protobuf encoder would have put it anyway.
fn set_field(msg: &[u8], number: u32, replacement: Option<&[u8]>) -> Result<Vec<u8>, EditError> {
    let spans = scan(msg)?;
    let mut out = Vec::with_capacity(msg.len() + replacement.map_or(0, <[u8]>::len));
    let mut placed = false;

    for span in &spans {
        if span.number == number {
            // Duplicates of a scalar are legal and last-wins, so collapsing them
            // to the single value we are writing is the correct reading.
            if let Some(bytes) = replacement {
                if !placed {
                    out.extend_from_slice(bytes);
                    placed = true;
                }
            }
        } else {
            out.extend_from_slice(&msg[span.whole.clone()]);
        }
    }

    if !placed {
        if let Some(bytes) = replacement {
            out.extend_from_slice(bytes);
        }
    }

    Ok(out)
}

fn encode_varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn encode_tag(number: u32, wire_type: u8, out: &mut Vec<u8>) {
    encode_varint((u64::from(number) << 3) | u64::from(wire_type), out);
}

fn encode_varint_field(number: u32, value: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(11);
    encode_tag(number, WIRE_VARINT, &mut out);
    encode_varint(value, &mut out);
    out
}

fn encode_len_delimited(number: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 8);
    encode_tag(number, WIRE_LEN, &mut out);
    encode_varint(payload.len() as u64, &mut out);
    out.extend_from_slice(payload);
    out
}

/// The single `StorageRecord.contact` payload, or an error saying why not.
fn contact_payload(record: &[u8]) -> Result<Range<usize>, EditError> {
    let spans = scan(record)?;
    let mut found = spans.iter().filter(|s| s.number == STORAGE_RECORD_CONTACT);
    let first = found.next().ok_or(EditError::NotAContact)?;
    if found.next().is_some() {
        return Err(EditError::AmbiguousContact);
    }
    Ok(first.payload.clone())
}

/// The last-wins varint value of field `number` inside the contact payload,
/// or `0` when the field is absent (proto3 implicit presence).
fn contact_varint_field(record: &[u8], number: u32) -> Result<u64, EditError> {
    let payload = contact_payload(record)?;
    let contact = &record[payload];
    let spans = scan(contact)?;

    // Repeated scalars are last-wins.
    let Some(span) = spans.iter().rev().find(|s| s.number == number) else {
        return Ok(0);
    };

    if span.wire_type != WIRE_VARINT {
        // Field numbers are stable, so this is not a newer client's copy of
        // the field — it is a record we should not be drawing conclusions
        // from.
        return Err(EditError::Malformed);
    }

    // Decode rather than look for a non-zero byte: `0x80 0x00` is a legal,
    // non-canonical encoding of zero, and its continuation bit would otherwise
    // read as a value.
    let mut pos = span.payload.start;
    read_varint(contact, &mut pos)
}

/// Replace — or, with `None`, remove — one field inside the contact payload,
/// preserving every other byte of both messages.
fn set_contact_field(
    record: &[u8],
    number: u32,
    replacement: Option<&[u8]>,
) -> Result<Vec<u8>, EditError> {
    let payload = contact_payload(record)?;
    let contact = &record[payload];
    let new_contact = set_field(contact, number, replacement)?;

    // Splice the wrapper rather than rebuilding it. `StorageRecord` is a oneof,
    // so there is nothing else in there today — but reconstructing it would drop
    // any field a future client adds, which is the whole failure this module
    // exists to prevent.
    set_field(
        record,
        STORAGE_RECORD_CONTACT,
        Some(&encode_len_delimited(STORAGE_RECORD_CONTACT, &new_contact)),
    )
}

/// Read `ContactRecord.blocked` out of an encoded `StorageRecord`.
pub fn contact_blocked(record: &[u8]) -> Result<bool, EditError> {
    Ok(contact_varint_field(record, CONTACT_RECORD_BLOCKED)? != 0)
}

/// Set `ContactRecord.blocked` on an encoded `StorageRecord`, preserving every
/// other byte of both messages.
///
/// `blocked = false` **removes** the field rather than writing an explicit zero.
/// `blocked` has proto3 implicit presence, so its default is its absence, and
/// removal is what Signal-Desktop and Signal-Android emit. An explicit zero is
/// wire-legal and decodes identically, but no official client produces one.
pub fn set_contact_blocked(record: &[u8], blocked: bool) -> Result<Vec<u8>, EditError> {
    let replacement = blocked.then(|| encode_varint_field(CONTACT_RECORD_BLOCKED, 1));
    set_contact_field(record, CONTACT_RECORD_BLOCKED, replacement.as_deref())
}

/// Read `ContactRecord.mutedUntilTimestamp` out of an encoded `StorageRecord`.
/// Absent means not muted and reads as 0.
pub fn contact_muted_until(record: &[u8]) -> Result<u64, EditError> {
    contact_varint_field(record, CONTACT_RECORD_MUTED_UNTIL)
}

/// Set `ContactRecord.mutedUntilTimestamp` on an encoded `StorageRecord`,
/// preserving every other byte of both messages.
///
/// `0` (not muted) **removes** the field rather than writing an explicit zero —
/// the same proto3 implicit-presence convention as [`set_contact_blocked`], and
/// what Signal-Desktop serializes on unmute. "Muted forever" is `i64::MAX`, a
/// ten-byte varint.
pub fn set_contact_muted_until(record: &[u8], muted_until: u64) -> Result<Vec<u8>, EditError> {
    let replacement =
        (muted_until != 0).then(|| encode_varint_field(CONTACT_RECORD_MUTED_UNTIL, muted_until));
    set_contact_field(record, CONTACT_RECORD_MUTED_UNTIL, replacement.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `ContactRecord` with an ACI (field 1), a name (field 6), and a field
    /// number no version of the proto we compile against defines.
    fn contact_with_unknown_field() -> Vec<u8> {
        let mut contact = Vec::new();
        contact.extend_from_slice(&encode_len_delimited(1, b"aci-bytes"));
        contact.extend_from_slice(&encode_len_delimited(6, b"Ada"));
        contact.extend_from_slice(&encode_len_delimited(250, b"from the future"));
        contact
    }

    fn storage_record(contact: &[u8]) -> Vec<u8> {
        encode_len_delimited(STORAGE_RECORD_CONTACT, contact)
    }

    #[test]
    fn blocking_preserves_every_other_field() {
        let record = storage_record(&contact_with_unknown_field());
        let blocked = set_contact_blocked(&record, true).unwrap();

        assert!(contact_blocked(&blocked).unwrap());

        let payload = contact_payload(&blocked).unwrap();
        let contact = &blocked[payload];
        assert!(
            contact.windows(15).any(|w| w == b"from the future"),
            "unknown field was dropped"
        );
        assert!(contact.windows(9).any(|w| w == b"aci-bytes"));
        assert!(contact.windows(3).any(|w| w == b"Ada"));
    }

    #[test]
    fn block_then_unblock_restores_the_original_bytes() {
        let record = storage_record(&contact_with_unknown_field());

        let blocked = set_contact_blocked(&record, true).unwrap();
        assert_ne!(blocked, record);

        let unblocked = set_contact_blocked(&blocked, false).unwrap();
        assert_eq!(
            unblocked, record,
            "toggling must not accumulate bytes or reorder fields"
        );
    }

    #[test]
    fn unblocking_removes_the_field_rather_than_zeroing_it() {
        let mut contact = contact_with_unknown_field();
        contact.extend_from_slice(&encode_varint_field(CONTACT_RECORD_BLOCKED, 1));
        let record = storage_record(&contact);

        let unblocked = set_contact_blocked(&record, false).unwrap();
        let payload = contact_payload(&unblocked).unwrap();
        let inner = scan(&unblocked[payload]).unwrap();

        assert!(
            !inner.iter().any(|s| s.number == CONTACT_RECORD_BLOCKED),
            "field 9 should be absent, not present-and-false"
        );
        assert!(!contact_blocked(&unblocked).unwrap());
    }

    #[test]
    fn duplicate_blocked_fields_collapse_to_one() {
        let mut contact = contact_with_unknown_field();
        contact.extend_from_slice(&encode_varint_field(CONTACT_RECORD_BLOCKED, 0));
        contact.extend_from_slice(&encode_varint_field(CONTACT_RECORD_BLOCKED, 1));
        let record = storage_record(&contact);

        // Last-wins, so the record currently reads as blocked.
        assert!(contact_blocked(&record).unwrap());

        let blocked = set_contact_blocked(&record, true).unwrap();
        let payload = contact_payload(&blocked).unwrap();
        let inner = scan(&blocked[payload]).unwrap();
        assert_eq!(
            inner
                .iter()
                .filter(|s| s.number == CONTACT_RECORD_BLOCKED)
                .count(),
            1
        );
        assert!(contact_blocked(&blocked).unwrap());
    }

    #[test]
    fn setting_blocked_on_a_record_without_it_appends() {
        let record = storage_record(&contact_with_unknown_field());
        assert!(!contact_blocked(&record).unwrap());

        let blocked = set_contact_blocked(&record, true).unwrap();
        assert!(contact_blocked(&blocked).unwrap());
    }

    #[test]
    fn unblocking_an_already_unblocked_record_is_a_no_op() {
        let record = storage_record(&contact_with_unknown_field());
        assert_eq!(set_contact_blocked(&record, false).unwrap(), record);
    }

    /// "Muted forever" is `i64::MAX` — a ten-byte varint, the encoder's and
    /// decoder's worst case.
    #[test]
    fn mute_round_trips_including_forever() {
        let record = storage_record(&contact_with_unknown_field());
        assert_eq!(contact_muted_until(&record).unwrap(), 0);

        let muted = set_contact_muted_until(&record, i64::MAX as u64).unwrap();
        assert_eq!(contact_muted_until(&muted).unwrap(), i64::MAX as u64);

        let payload = contact_payload(&muted).unwrap();
        let contact = &muted[payload];
        assert!(
            contact.windows(15).any(|w| w == b"from the future"),
            "unknown field was dropped"
        );
    }

    #[test]
    fn mute_then_unmute_restores_the_original_bytes() {
        let record = storage_record(&contact_with_unknown_field());

        let muted = set_contact_muted_until(&record, 1_700_000_000_000).unwrap();
        assert_ne!(muted, record);

        let unmuted = set_contact_muted_until(&muted, 0).unwrap();
        assert_eq!(
            unmuted, record,
            "toggling must not accumulate bytes or reorder fields"
        );
    }

    #[test]
    fn unmuting_removes_the_field_rather_than_zeroing_it() {
        let mut contact = contact_with_unknown_field();
        contact.extend_from_slice(&encode_varint_field(
            CONTACT_RECORD_MUTED_UNTIL,
            1_700_000_000_000,
        ));
        let record = storage_record(&contact);

        let unmuted = set_contact_muted_until(&record, 0).unwrap();
        let payload = contact_payload(&unmuted).unwrap();
        let inner = scan(&unmuted[payload]).unwrap();

        assert!(
            !inner.iter().any(|s| s.number == CONTACT_RECORD_MUTED_UNTIL),
            "field 13 should be absent, not present-and-zero"
        );
        assert_eq!(contact_muted_until(&unmuted).unwrap(), 0);
    }

    #[test]
    fn mute_with_the_wrong_wire_type_is_rejected() {
        let mut contact = contact_with_unknown_field();
        contact.extend_from_slice(&encode_len_delimited(
            CONTACT_RECORD_MUTED_UNTIL,
            b"not a varint",
        ));
        let record = storage_record(&contact);

        assert_eq!(contact_muted_until(&record), Err(EditError::Malformed));
    }

    /// Editing one field must not disturb the other — block and mute share the
    /// record and the publish path settles both in one write.
    #[test]
    fn block_and_mute_edits_compose() {
        let record = storage_record(&contact_with_unknown_field());

        let blocked = set_contact_blocked(&record, true).unwrap();
        let both = set_contact_muted_until(&blocked, 42).unwrap();

        assert!(contact_blocked(&both).unwrap());
        assert_eq!(contact_muted_until(&both).unwrap(), 42);
    }

    #[test]
    fn outer_unknown_fields_survive() {
        let mut record = storage_record(&contact_with_unknown_field());
        record.extend_from_slice(&encode_len_delimited(99, b"outer"));

        let blocked = set_contact_blocked(&record, true).unwrap();
        assert!(
            blocked.windows(5).any(|w| w == b"outer"),
            "a field outside the oneof was dropped"
        );
    }

    /// `0x80 0x00` is zero written the long way. Testing for a non-zero byte
    /// would see the continuation bit and call it `true`.
    #[test]
    fn a_non_canonical_zero_reads_as_unblocked() {
        let mut contact = contact_with_unknown_field();
        encode_tag(CONTACT_RECORD_BLOCKED, WIRE_VARINT, &mut contact);
        contact.extend_from_slice(&[0x80, 0x00]);
        let record = storage_record(&contact);

        assert!(!contact_blocked(&record).unwrap());
    }

    /// The same encoding applied to a one: still `true`, decoded properly.
    #[test]
    fn a_non_canonical_one_reads_as_blocked() {
        let mut contact = contact_with_unknown_field();
        encode_tag(CONTACT_RECORD_BLOCKED, WIRE_VARINT, &mut contact);
        contact.extend_from_slice(&[0x81, 0x00]);
        let record = storage_record(&contact);

        assert!(contact_blocked(&record).unwrap());
    }

    #[test]
    fn blocked_with_the_wrong_wire_type_is_rejected() {
        let mut contact = contact_with_unknown_field();
        contact.extend_from_slice(&encode_len_delimited(
            CONTACT_RECORD_BLOCKED,
            b"not a varint",
        ));
        let record = storage_record(&contact);

        assert_eq!(contact_blocked(&record), Err(EditError::Malformed));
    }

    #[test]
    fn a_non_contact_record_is_rejected() {
        // `StorageRecord.groupV2` is field 3.
        let record = encode_len_delimited(3, b"group");
        assert_eq!(
            set_contact_blocked(&record, true),
            Err(EditError::NotAContact)
        );
    }

    #[test]
    fn two_contacts_are_rejected_rather_than_guessed() {
        let mut record = storage_record(&contact_with_unknown_field());
        record.extend_from_slice(&storage_record(&contact_with_unknown_field()));
        assert_eq!(
            set_contact_blocked(&record, true),
            Err(EditError::AmbiguousContact)
        );
    }

    #[test]
    fn truncated_input_is_rejected() {
        let record = storage_record(&contact_with_unknown_field());
        for cut in 1..record.len() {
            let _ = set_contact_blocked(&record[..cut], true);
        }
        // A length prefix that runs past the end must not panic or over-read.
        let mut lying = Vec::new();
        encode_tag(STORAGE_RECORD_CONTACT, WIRE_LEN, &mut lying);
        encode_varint(200, &mut lying);
        lying.extend_from_slice(b"short");
        assert_eq!(set_contact_blocked(&lying, true), Err(EditError::Malformed));
    }

    #[test]
    fn every_wire_type_round_trips_untouched() {
        let mut contact = Vec::new();
        contact.extend_from_slice(&encode_varint_field(2, 1)); // varint
        contact.push(0x11); // field 2, wire type 1 (i64)
        contact.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        contact.extend_from_slice(&encode_len_delimited(6, b"Ada"));
        contact.push(0x25); // field 4, wire type 5 (i32)
        contact.extend_from_slice(&[9, 9, 9, 9]);
        let record = storage_record(&contact);

        let blocked = set_contact_blocked(&record, true).unwrap();
        let unblocked = set_contact_blocked(&blocked, false).unwrap();
        assert_eq!(unblocked, record);
    }
}
