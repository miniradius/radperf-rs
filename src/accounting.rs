//! Accounting flow: after an Access-Accept, emit Accounting-Requests.
//!
//! Builds Start, Interim-Update and Stop packets for the `-A delay,lifetime`
//! scheduler in the client.
//!
//! Attribute handling follows RFC 2866 and the manual:
//! * NAS/identity attributes are copied from the Access-Request;
//! * `Class` and any `-C` attributes are copied from the Access-Accept;
//! * `NAS-Port` is generated when the request did not carry one.

use crate::crypto;
use crate::packet::{self, Packet};
use std::time::Duration;

/// Attribute numbers used by the accounting flow.
pub const ATTR_USER_NAME: u8 = 1;
pub const ATTR_NAS_IP_ADDRESS: u8 = 4;
pub const ATTR_NAS_PORT: u8 = 5;
pub const ATTR_FRAMED_IP_ADDRESS: u8 = 8;
pub const ATTR_CLASS: u8 = 25;
pub const ATTR_SESSION_TIMEOUT: u8 = 27;
pub const ATTR_CALLED_STATION_ID: u8 = 30;
pub const ATTR_CALLING_STATION_ID: u8 = 31;
pub const ATTR_NAS_IDENTIFIER: u8 = 32;
pub const ATTR_ACCT_STATUS_TYPE: u8 = 40;
pub const ATTR_ACCT_SESSION_ID: u8 = 44;
pub const ATTR_NAS_PORT_TYPE: u8 = 61;

/// `Acct-Status-Type` values (RFC 2866).
pub const STATUS_START: u8 = 1;
pub const STATUS_STOP: u8 = 2;
pub const STATUS_INTERIM: u8 = 3;

/// Request attributes copied into every Accounting-Request.
const COPY_FROM_REQUEST: &[u8] = &[
    ATTR_USER_NAME,
    ATTR_NAS_IP_ADDRESS,
    ATTR_NAS_PORT,
    ATTR_CALLED_STATION_ID,
    ATTR_CALLING_STATION_ID,
    ATTR_NAS_IDENTIFIER,
    ATTR_NAS_PORT_TYPE,
];

/// Accounting behaviour configured with `-A` and `-F`.
#[derive(Clone)]
pub struct AcctConfig {
    pub delay: Duration,
    pub lifetime: Duration,
    pub framed_ip: bool,
}

/// Extract the attributes copied from an Access-Request into its accounting
/// packets.
pub fn base_attributes(request_attributes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for (typ, value) in RawIter::new(request_attributes) {
        if COPY_FROM_REQUEST.contains(&typ) {
            out.push(typ);
            out.push((value.len() + 2) as u8);
            out.extend_from_slice(value);
        }
    }
    out
}

/// Copy the selected attribute types out of a received packet as raw TLVs.
pub fn copy_from_packet(packet: &Packet, types: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    for (typ, value) in packet.iter_raw() {
        if types.contains(&typ) {
            out.push((typ, value.to_vec()));
        }
    }
    out
}

/// Read a 32-bit integer attribute from a packet, if present.
pub fn read_uint_attribute(packet: &Packet, typ: u8) -> Option<u32> {
    packet
        .iter_raw()
        .find(|(t, _)| *t == typ)
        .and_then(|(_, v)| {
            if v.len() == 4 {
                Some(u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
            } else {
                None
            }
        })
}

/// Build an Accounting-Request into `out`, returning its length.
#[allow(clippy::too_many_arguments)]
pub fn build_accounting(
    out: &mut Vec<u8>,
    id: u8,
    secret: &[u8],
    base_attrs: &[u8],
    status: u8,
    session_id: &[u8],
    nas_port: u32,
    copied: &[(u8, Vec<u8>)],
) -> usize {
    out.clear();
    out.push(packet::ACCOUNTING_REQUEST);
    out.push(id);
    out.push(0);
    out.push(0);
    out.extend_from_slice(&[0u8; 16]);
    out.extend_from_slice(base_attrs);

    push_uint(out, ATTR_ACCT_STATUS_TYPE, status as u32, 4);
    push_string(out, ATTR_ACCT_SESSION_ID, session_id);
    if !contains_attr(base_attrs, ATTR_NAS_PORT) {
        push_uint(out, ATTR_NAS_PORT, nas_port, 4);
    }
    for (typ, value) in copied {
        out.push(*typ);
        out.push((value.len() + 2) as u8);
        out.extend_from_slice(value);
    }

    // FreeRADIUS (and radclient) do not put a Message-Authenticator in
    // Accounting-Requests, so none is added here.
    let total = out.len();
    let authenticator =
        crypto::request_authenticator_raw(packet::ACCOUNTING_REQUEST, id, &out[20..total], secret);
    out[4..20].copy_from_slice(&authenticator);
    out[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    total
}

fn contains_attr(attributes: &[u8], typ: u8) -> bool {
    RawIter::new(attributes).any(|(t, _)| t == typ)
}

fn push_uint(out: &mut Vec<u8>, typ: u8, value: u32, width: usize) {
    out.push(typ);
    out.push((width + 2) as u8);
    let bytes = value.to_be_bytes();
    out.extend_from_slice(&bytes[4 - width..]);
}

fn push_string(out: &mut Vec<u8>, typ: u8, value: &[u8]) {
    out.push(typ);
    out.push((value.len() + 2) as u8);
    out.extend_from_slice(value);
}

/// Minimal raw TLV iterator.
struct RawIter<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> RawIter<'a> {
    fn new(bytes: &'a [u8]) -> RawIter<'a> {
        RawIter { bytes, offset: 0 }
    }
}

impl<'a> Iterator for RawIter<'a> {
    type Item = (u8, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset + 2 > self.bytes.len() {
            return None;
        }
        let typ = self.bytes[self.offset];
        let len = self.bytes[self.offset + 1] as usize;
        if len < 2 || self.offset + len > self.bytes.len() {
            return None;
        }
        let value = &self.bytes[self.offset + 2..self.offset + len];
        self.offset += len;
        Some((typ, value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copies_request_attributes() {
        let mut p = Packet::new(packet::ACCESS_REQUEST, 1);
        p.push_raw(ATTR_USER_NAME, b"alice").unwrap();
        p.push_raw(ATTR_NAS_IP_ADDRESS, &[10, 0, 0, 1]).unwrap();
        p.push_raw(ATTR_NAS_PORT_TYPE, &[0, 0, 0, 5]).unwrap();
        p.push_raw(ATTR_ACCT_SESSION_ID, b"ignored").unwrap();
        let base = base_attributes(&p.attributes);
        assert!(contains_attr(&base, ATTR_USER_NAME));
        assert!(contains_attr(&base, ATTR_NAS_IP_ADDRESS));
        assert!(contains_attr(&base, ATTR_NAS_PORT_TYPE));
        // Not copied.
        assert!(!contains_attr(&base, ATTR_ACCT_SESSION_ID));
    }

    #[test]
    fn builds_signed_accounting_request() {
        let secret = b"secret";
        let base = {
            let mut p = Packet::new(packet::ACCESS_REQUEST, 1);
            p.push_raw(ATTR_USER_NAME, b"bob").unwrap();
            p.attributes
        };
        let copied = vec![(ATTR_CLASS, b"vip".to_vec())];
        let mut out = Vec::new();
        let len = build_accounting(
            &mut out,
            7,
            secret,
            &base,
            STATUS_START,
            b"sess-1",
            42,
            &copied,
        );
        assert_eq!(len, out.len());
        let pkt = Packet::decode(&out).unwrap();
        assert_eq!(pkt.code, packet::ACCOUNTING_REQUEST);
        assert_eq!(pkt.id, 7);
        // Authenticator verifies with the shared secret.
        assert_eq!(
            pkt.authenticator,
            crypto::request_authenticator(&pkt, secret)
        );
        // Status, session id, NAS-Port and copied Class are present.
        assert_eq!(read_uint_attribute(&pkt, ATTR_ACCT_STATUS_TYPE), Some(1));
        assert!(pkt
            .iter_raw()
            .any(|(t, v)| t == ATTR_ACCT_SESSION_ID && v == b"sess-1"));
        assert_eq!(read_uint_attribute(&pkt, ATTR_NAS_PORT), Some(42));
        assert!(pkt.iter_raw().any(|(t, v)| t == ATTR_CLASS && v == b"vip"));
    }

    #[test]
    fn keeps_request_nas_port_when_present() {
        let base = {
            let mut p = Packet::new(packet::ACCESS_REQUEST, 1);
            p.push_raw(ATTR_NAS_PORT, &[0, 0, 0, 9]).unwrap();
            p.attributes
        };
        let mut out = Vec::new();
        build_accounting(&mut out, 1, b"s", &base, STATUS_START, b"x", 42, &[]);
        let pkt = Packet::decode(&out).unwrap();
        let ports: Vec<u32> = pkt
            .iter_raw()
            .filter(|(t, _)| *t == ATTR_NAS_PORT)
            .map(|(_, v)| u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
            .collect();
        assert_eq!(
            ports,
            vec![9],
            "request NAS-Port must be preserved, not duplicated"
        );
    }
}
