//! RADIUS packet framing (RFC 2865 section 3): 20-byte header plus a TLV attribute
//! stream. This module deals in raw attribute bytes; typed (dictionary-driven)
//! values live in [`crate::value`].

use std::fmt;

/// Fixed RADIUS header size.
pub const HEADER_LEN: usize = 20;
/// Largest packet we will emit or accept.
pub const MAX_PACKET_LEN: usize = 4096;
/// Attribute type that must never appear.
const ATTR_RESERVED: u8 = 0;
/// `Vendor-Specific` attribute type (RFC 2865 section 5.26).
pub const ATTR_VENDOR_SPECIFIC: u8 = 26;

// Packet codes (RFC 2865, 2866, 3576, 5997).
pub const ACCESS_REQUEST: u8 = 1;
pub const ACCESS_ACCEPT: u8 = 2;
pub const ACCESS_REJECT: u8 = 3;
pub const ACCOUNTING_REQUEST: u8 = 4;
pub const ACCOUNTING_RESPONSE: u8 = 5;
pub const ACCESS_CHALLENGE: u8 = 11;
pub const STATUS_SERVER: u8 = 12;
pub const STATUS_CLIENT: u8 = 13;
pub const DISCONNECT_REQUEST: u8 = 40;
pub const DISCONNECT_ACK: u8 = 41;
pub const DISCONNECT_NAK: u8 = 42;
pub const COA_REQUEST: u8 = 43;
pub const COA_ACK: u8 = 44;
pub const COA_NAK: u8 = 45;

/// Human-readable name for a packet code.
pub fn code_name(code: u8) -> &'static str {
    match code {
        ACCESS_REQUEST => "Access-Request",
        ACCESS_ACCEPT => "Access-Accept",
        ACCESS_REJECT => "Access-Reject",
        ACCOUNTING_REQUEST => "Accounting-Request",
        ACCOUNTING_RESPONSE => "Accounting-Response",
        ACCESS_CHALLENGE => "Access-Challenge",
        STATUS_SERVER => "Status-Server",
        STATUS_CLIENT => "Status-Client",
        DISCONNECT_REQUEST => "Disconnect-Request",
        DISCONNECT_ACK => "Disconnect-ACK",
        DISCONNECT_NAK => "Disconnect-NAK",
        COA_REQUEST => "CoA-Request",
        COA_ACK => "CoA-ACK",
        COA_NAK => "CoA-NAK",
        _ => "Unknown",
    }
}

/// Packet framing error.
#[derive(Debug, PartialEq, Eq)]
pub enum PacketError {
    TooShort { len: usize },
    BadLength { declared: usize, available: usize },
    BadAttributeLength { offset: usize, len: u8 },
    ReservedAttributeType { offset: usize },
    AttributeOverflow { offset: usize },
    TooLong { len: usize },
}

impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PacketError::TooShort { len } => {
                write!(f, "packet too short: {len} bytes (need {HEADER_LEN})")
            }
            PacketError::BadLength {
                declared,
                available,
            } => write!(
                f,
                "declared length {declared} exceeds available {available} bytes"
            ),
            PacketError::BadAttributeLength { offset, len } => {
                write!(f, "attribute at offset {offset} has invalid length {len}")
            }
            PacketError::ReservedAttributeType { offset } => {
                write!(f, "attribute at offset {offset} uses reserved type 0")
            }
            PacketError::AttributeOverflow { offset } => {
                write!(f, "attribute at offset {offset} overruns the packet")
            }
            PacketError::TooLong { len } => {
                write!(f, "packet length {len} exceeds {MAX_PACKET_LEN}")
            }
        }
    }
}

impl std::error::Error for PacketError {}

/// A RADIUS packet with raw attribute bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct Packet {
    pub code: u8,
    pub id: u8,
    pub authenticator: [u8; 16],
    /// Concatenated attribute TLVs (no header).
    pub attributes: Vec<u8>,
}

impl fmt::Debug for Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Packet")
            .field("code", &code_name(self.code))
            .field("id", &self.id)
            .field("authenticator", &hex16(&self.authenticator))
            .field("attributes", &self.attributes.len())
            .finish()
    }
}

impl Packet {
    /// Create a packet with a zero authenticator.
    pub fn new(code: u8, id: u8) -> Packet {
        Packet {
            code,
            id,
            authenticator: [0u8; 16],
            attributes: Vec::new(),
        }
    }

    /// Total on-the-wire length.
    pub fn len(&self) -> usize {
        HEADER_LEN + self.attributes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Append a raw TLV attribute. Returns an error if it cannot fit.
    pub fn push_raw(&mut self, typ: u8, value: &[u8]) -> Result<(), PacketError> {
        if typ == ATTR_RESERVED {
            return Err(PacketError::ReservedAttributeType {
                offset: self.attributes.len(),
            });
        }
        let attr_len = value.len() + 2;
        if attr_len > u8::MAX as usize {
            return Err(PacketError::BadAttributeLength {
                offset: self.attributes.len(),
                len: attr_len as u8,
            });
        }
        if self.len() + attr_len > MAX_PACKET_LEN {
            return Err(PacketError::TooLong {
                len: self.len() + attr_len,
            });
        }
        self.attributes.push(typ);
        self.attributes.push(attr_len as u8);
        self.attributes.extend_from_slice(value);
        Ok(())
    }

    /// Iterate the raw attributes as `(type, value)` pairs.
    pub fn iter_raw(&self) -> RawAttributeIter<'_> {
        RawAttributeIter {
            bytes: &self.attributes,
            offset: 0,
        }
    }

    /// Serialize header plus attributes into `buf`, returning the byte count.
    pub fn encode_into(&self, buf: &mut [u8]) -> Result<usize, PacketError> {
        let total = self.len();
        if total > MAX_PACKET_LEN {
            return Err(PacketError::TooLong { len: total });
        }
        if buf.len() < total {
            return Err(PacketError::BadLength {
                declared: total,
                available: buf.len(),
            });
        }
        buf[0] = self.code;
        buf[1] = self.id;
        buf[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        buf[4..20].copy_from_slice(&self.authenticator);
        buf[20..total].copy_from_slice(&self.attributes);
        Ok(total)
    }

    /// Serialize into a freshly allocated buffer.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = vec![0u8; self.len()];
        // Length was checked against MAX_PACKET_LEN by construction.
        self.encode_into(&mut buf).expect("packet fits");
        buf
    }

    /// Parse a packet from a buffer, honoring the declared length.
    pub fn decode(buf: &[u8]) -> Result<Packet, PacketError> {
        if buf.len() < HEADER_LEN {
            return Err(PacketError::TooShort { len: buf.len() });
        }
        let declared = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        if declared < HEADER_LEN {
            return Err(PacketError::BadLength {
                declared,
                available: buf.len(),
            });
        }
        if declared > buf.len() {
            return Err(PacketError::BadLength {
                declared,
                available: buf.len(),
            });
        }
        if declared > MAX_PACKET_LEN {
            return Err(PacketError::TooLong { len: declared });
        }
        let mut authenticator = [0u8; 16];
        authenticator.copy_from_slice(&buf[4..20]);
        let body = &buf[HEADER_LEN..declared];

        // Validate the attribute stream eagerly.
        let mut offset = 0usize;
        while offset < body.len() {
            let typ = body[offset];
            if typ == ATTR_RESERVED {
                return Err(PacketError::ReservedAttributeType { offset });
            }
            if offset + 2 > body.len() {
                return Err(PacketError::AttributeOverflow { offset });
            }
            let alen = body[offset + 1] as usize;
            if alen < 2 {
                return Err(PacketError::BadAttributeLength {
                    offset,
                    len: alen as u8,
                });
            }
            if offset + alen > body.len() {
                return Err(PacketError::AttributeOverflow { offset });
            }
            offset += alen;
        }

        Ok(Packet {
            code: buf[0],
            id: buf[1],
            authenticator,
            attributes: body.to_vec(),
        })
    }
}

/// Iterator over raw `(type, value)` attributes.
pub struct RawAttributeIter<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for RawAttributeIter<'a> {
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

fn hex16(bytes: &[u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_packet() {
        let mut p = Packet::new(ACCESS_REQUEST, 7);
        p.authenticator = [0xab; 16];
        p.push_raw(1, b"alice").unwrap();
        p.push_raw(4, &[10, 0, 0, 1]).unwrap();
        let bytes = p.encode();
        assert_eq!(bytes[0], ACCESS_REQUEST);
        assert_eq!(bytes[1], 7);
        assert_eq!(
            u16::from_be_bytes([bytes[2], bytes[3]]) as usize,
            bytes.len()
        );
        let back = Packet::decode(&bytes).unwrap();
        assert_eq!(back, p);
        let attrs: Vec<_> = back.iter_raw().collect();
        assert_eq!(attrs[0], (1, &b"alice"[..]));
        assert_eq!(attrs[1], (4, &[10, 0, 0, 1][..]));
    }

    #[test]
    fn rejects_truncated_header() {
        assert_eq!(
            Packet::decode(&[1, 2, 3]),
            Err(PacketError::TooShort { len: 3 })
        );
    }

    #[test]
    fn rejects_bad_declared_length() {
        let mut bytes = vec![0u8; HEADER_LEN];
        bytes[0] = ACCESS_REQUEST;
        bytes[2..4].copy_from_slice(&100u16.to_be_bytes());
        assert!(matches!(
            Packet::decode(&bytes),
            Err(PacketError::BadLength { .. })
        ));
    }

    #[test]
    fn rejects_zero_length_attribute() {
        let mut bytes = vec![0u8; HEADER_LEN];
        bytes[2..4].copy_from_slice(&(HEADER_LEN as u16 + 2).to_be_bytes());
        bytes.extend_from_slice(&[1, 0]); // length 0 is invalid
        assert!(matches!(
            Packet::decode(&bytes),
            Err(PacketError::BadAttributeLength { .. })
        ));
    }

    #[test]
    fn ignores_trailing_bytes_past_declared_length() {
        let mut p = Packet::new(STATUS_SERVER, 1);
        p.push_raw(80, &[0u8; 16]).unwrap();
        let mut bytes = p.encode();
        bytes.extend_from_slice(&[0xff, 0xff]); // stray bytes
        let back = Packet::decode(&bytes).unwrap();
        assert_eq!(back.attributes, p.attributes);
    }
}
