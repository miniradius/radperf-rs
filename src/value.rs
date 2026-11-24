//! Typed attribute values: convert textual input into wire bytes using the
//! dictionary, and format wire bytes back into text.
//!
//! Encoding happens once while preparing request templates, never on the
//! per-packet hot path, so clarity is preferred here over micro-optimisation.

use crate::dict::{Attribute, DataType, Dictionary, VendorFormat};
use crate::packet::ATTR_VENDOR_SPECIFIC;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Value encoding/decoding error.
#[derive(Debug, PartialEq, Eq)]
pub struct ValueError {
    pub message: String,
}

impl ValueError {
    fn new(message: impl Into<String>) -> Self {
        ValueError {
            message: message.into(),
        }
    }
}

impl fmt::Display for ValueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ValueError {}

/// Encode a textual value for one attribute and return the top-level wire
/// attribute `(type, value)` to append to a packet.
///
/// Vendor attributes are wrapped in a `Vendor-Specific` (26) attribute and
/// RFC 6929 extended attributes are prefixed with their extended type.
pub fn encode_attribute(
    dict: &Dictionary,
    attr: &Attribute,
    raw: &str,
) -> Result<(u8, Vec<u8>), ValueError> {
    encode_attribute_tagged(dict, attr, raw, None)
}

/// Encode a textual value for one attribute with an optional tag
/// (`Name:tag = value`). The tag is only valid for attributes flagged
/// `has_tag`; for integer-like attributes it replaces the most significant
/// octet (RFC 2868). A nonzero tag is prepended to other values.
pub fn encode_attribute_tagged(
    dict: &Dictionary,
    attr: &Attribute,
    raw: &str,
    tag: Option<u8>,
) -> Result<(u8, Vec<u8>), ValueError> {
    let mut scalar = encode_scalar(attr, raw)?;
    if let Some(t) = tag {
        if !attr.flags.has_tag {
            return Err(ValueError::new(format!(
                "attribute '{}' does not take a tag",
                attr.name
            )));
        }
        if t > 31 {
            return Err(ValueError::new(format!(
                "tag {t} is out of range for '{}' (0..31)",
                attr.name
            )));
        }
        if attr.ty.is_integer_like() && scalar.len() == 4 {
            scalar[0] = t;
        } else if t != 0 {
            scalar.insert(0, t);
        }
    }
    if attr.vendor != 0 {
        let format = dict.vendor_format(attr.vendor);
        let value = wrap_vendor(attr.vendor, format, attr.number, &scalar)?;
        Ok((ATTR_VENDOR_SPECIFIC, value))
    } else if (241..=246).contains(&attr.number) && attr.extended().is_some() {
        let ext = attr.extended().unwrap() as u8;
        let mut value = Vec::with_capacity(scalar.len() + 1);
        value.push(ext);
        value.extend_from_slice(&scalar);
        Ok((attr.number as u8, value))
    } else {
        Ok((attr.number as u8, scalar))
    }
}

/// Encode only the attribute's own payload (no vendor/extended wrapper).
pub fn encode_scalar(attr: &Attribute, raw: &str) -> Result<Vec<u8>, ValueError> {
    let text = raw.trim();
    match attr.ty {
        DataType::String => Ok(text.as_bytes().to_vec()),
        DataType::Octets => parse_octets(text),
        DataType::Integer | DataType::Date | DataType::Signed => {
            let v = parse_integer(attr, text)?;
            Ok((v as u32).to_be_bytes().to_vec())
        }
        DataType::Integer64 => {
            let v = parse_integer(attr, text)?;
            Ok((v as u64).to_be_bytes().to_vec())
        }
        DataType::Short => {
            let v = parse_integer(attr, text)?;
            Ok((v as u16).to_be_bytes().to_vec())
        }
        DataType::Byte => {
            let v = parse_integer(attr, text)?;
            Ok(vec![v as u8])
        }
        DataType::Bool => {
            let v = parse_integer(attr, text)?;
            Ok(vec![(v != 0) as u8])
        }
        DataType::IpAddr => {
            let ip: Ipv4Addr = text
                .parse()
                .map_err(|_| ValueError::new(format!("invalid IPv4 address '{text}'")))?;
            Ok(ip.octets().to_vec())
        }
        DataType::ComboIp => {
            if let Ok(v4) = text.parse::<Ipv4Addr>() {
                Ok(v4.octets().to_vec())
            } else if let Ok(v6) = text.parse::<Ipv6Addr>() {
                Ok(v6.octets().to_vec())
            } else {
                Err(ValueError::new(format!("invalid IP address '{text}'")))
            }
        }
        DataType::Ipv6Addr => {
            let ip: Ipv6Addr = text
                .parse()
                .map_err(|_| ValueError::new(format!("invalid IPv6 address '{text}'")))?;
            Ok(ip.octets().to_vec())
        }
        DataType::Ifid => {
            let bytes = parse_hex_bytes(text)?;
            if bytes.len() != 8 {
                return Err(ValueError::new(format!(
                    "IFID must be 8 octets, got {}",
                    bytes.len()
                )));
            }
            Ok(bytes)
        }
        DataType::Ether => {
            let bytes = parse_hex_bytes(&text.replace([':', '-'], ""))?;
            if bytes.len() != 6 {
                return Err(ValueError::new(format!(
                    "Ethernet address must be 6 octets, got {}",
                    bytes.len()
                )));
            }
            Ok(bytes)
        }
        DataType::Tlv => {
            // A TLV's own value is assembled from its children elsewhere.
            Err(ValueError::new(format!(
                "attribute '{}' is a TLV container",
                attr.name
            )))
        }
        other => Err(ValueError::new(format!(
            "unsupported attribute type {other:?} for '{}'",
            attr.name
        ))),
    }
}

/// Wrap a vendor payload according to the vendor's declared format.
pub fn wrap_vendor(
    vendor_id: u32,
    format: VendorFormat,
    vendor_type: u32,
    scalar: &[u8],
) -> Result<Vec<u8>, ValueError> {
    let type_len = format.type_len as usize;
    let length_len = format.length_len as usize;
    let mut out = Vec::with_capacity(4 + type_len + length_len + scalar.len());
    out.extend_from_slice(&vendor_id.to_be_bytes());
    write_uint_be(&mut out, vendor_type as u64, type_len)?;
    if length_len > 0 {
        let total = type_len + length_len + scalar.len();
        write_uint_be(&mut out, total as u64, length_len)?;
    }
    out.extend_from_slice(scalar);
    Ok(out)
}

/// Write the low `width` bytes of `value` in big-endian order.
fn write_uint_be(out: &mut Vec<u8>, value: u64, width: usize) -> Result<(), ValueError> {
    if width == 0 || width > 8 {
        return Err(ValueError::new(format!("invalid integer width {width}")));
    }
    let bytes = value.to_be_bytes();
    out.extend_from_slice(&bytes[8 - width..]);
    Ok(())
}

/// Parse an integer literal (decimal, `0x` hex) or an enum name.
fn parse_integer(attr: &Attribute, text: &str) -> Result<i64, ValueError> {
    if let Some(v) = parse_int_literal(text) {
        return Ok(v);
    }
    if let Some(v) = attr.value_of(text) {
        return Ok(v);
    }
    Err(ValueError::new(format!(
        "invalid value '{text}' for attribute '{}'",
        attr.name
    )))
}

fn parse_int_literal(text: &str) -> Option<i64> {
    let t = text.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16).ok()
    } else {
        t.parse::<i64>().ok()
    }
}

/// Parse a hex string with an optional `0x` prefix, ignoring whitespace,
/// `:` and `-` separators.
fn parse_octets(text: &str) -> Result<Vec<u8>, ValueError> {
    parse_hex_bytes(text)
}

fn parse_hex_bytes(text: &str) -> Result<Vec<u8>, ValueError> {
    let cleaned: String = text
        .trim()
        .strip_prefix("0x")
        .or_else(|| text.trim().strip_prefix("0X"))
        .unwrap_or(text.trim())
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':' && *c != '-')
        .collect();
    if cleaned.len() % 2 != 0 {
        return Err(ValueError::new(format!(
            "hex string has odd length: '{text}'"
        )));
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    let bytes = cleaned.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_val(bytes[i])?;
        let lo = hex_val(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_val(c: u8) -> Result<u8, ValueError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(ValueError::new(format!(
            "invalid hex digit '{}'",
            c as char
        ))),
    }
}

/// Format a wire value as text for display, using the dictionary type and any
/// enum names.
pub fn decode_to_string(attr: &Attribute, bytes: &[u8]) -> String {
    match attr.ty {
        DataType::String => String::from_utf8_lossy(bytes).into_owned(),
        DataType::Octets => format!("0x{}", hex(bytes)),
        DataType::Integer | DataType::Date => {
            let v = read_uint_be(bytes);
            if let Some(name) = attr.name_of(v) {
                name.to_string()
            } else {
                v.to_string()
            }
        }
        DataType::Signed => (read_uint_be(bytes) as u32 as i32).to_string(),
        DataType::Short => {
            let v = read_uint_be(bytes);
            attr.name_of(v)
                .map(str::to_string)
                .unwrap_or_else(|| v.to_string())
        }
        DataType::Byte => read_uint_be(bytes).to_string(),
        DataType::Integer64 => read_uint_be(bytes).to_string(),
        DataType::IpAddr if bytes.len() == 4 => {
            Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string()
        }
        DataType::Ipv6Addr if bytes.len() == 16 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(bytes);
            Ipv6Addr::from(o).to_string()
        }
        DataType::Ether => bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
        _ => format!("0x{}", hex(bytes)),
    }
}

fn read_uint_be(bytes: &[u8]) -> i64 {
    let mut v: i64 = 0;
    for &b in bytes.iter().take(8) {
        v = (v << 8) | b as i64;
    }
    v
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dict::Dictionary;
    use std::io::Write;

    fn dict() -> Dictionary {
        let text = "\
ATTRIBUTE\tUser-Name\t1\tstring\n\
ATTRIBUTE\tNAS-IP-Address\t4\tipaddr\n\
ATTRIBUTE\tService-Type\t6\tinteger\n\
VALUE\tService-Type\tLogin-User\t1\n\
VALUE\tService-Type\tFramed-User\t2\n\
ATTRIBUTE\tAcct-Session-Id\t44\tstring\n\
ATTRIBUTE\tFramed-IPv6-Address\t168\tipv6addr\n\
VENDOR\tCisco\t9\n\
BEGIN-VENDOR\tCisco\n\
ATTRIBUTE\tCisco-AVPair\t1\tstring\n\
END-VENDOR\tCisco\n\
VENDOR\tWiMAX\t24757\tformat=2,1\n\
BEGIN-VENDOR\tWiMAX\n\
ATTRIBUTE\tWiMAX-Capability\t1\tstring\n\
END-VENDOR\tWiMAX\n";
        let mut f = tempfile::Builder::new().suffix(".dict").tempfile().unwrap();
        f.write_all(text.as_bytes()).unwrap();
        f.flush().unwrap();
        Dictionary::load_file(f.path()).unwrap()
    }

    #[test]
    fn encodes_string() {
        let d = dict();
        let a = d.attr_by_name("User-Name").unwrap();
        assert_eq!(
            encode_attribute(&d, a, "alice").unwrap(),
            (1, b"alice".to_vec())
        );
    }

    #[test]
    fn encodes_ipv4() {
        let d = dict();
        let a = d.attr_by_name("NAS-IP-Address").unwrap();
        assert_eq!(
            encode_attribute(&d, a, "10.0.0.1").unwrap(),
            (4, vec![10, 0, 0, 1])
        );
    }

    #[test]
    fn encodes_integer_by_name_and_number() {
        let d = dict();
        let a = d.attr_by_name("Service-Type").unwrap();
        assert_eq!(
            encode_attribute(&d, a, "Framed-User").unwrap(),
            (6, vec![0, 0, 0, 2])
        );
        assert_eq!(encode_attribute(&d, a, "2").unwrap(), (6, vec![0, 0, 0, 2]));
        assert_eq!(
            encode_attribute(&d, a, "0x2").unwrap(),
            (6, vec![0, 0, 0, 2])
        );
    }

    #[test]
    fn encodes_ipv6() {
        let d = dict();
        let a = d.attr_by_name("Framed-IPv6-Address").unwrap();
        let (typ, val) = encode_attribute(&d, a, "2001:db8::1").unwrap();
        assert_eq!(typ, 168);
        assert_eq!(
            val,
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)
                .octets()
                .to_vec()
        );
    }

    #[test]
    fn wraps_cisco_vsa_default_format() {
        let d = dict();
        let a = d.attr_by_name("Cisco-AVPair").unwrap();
        let (typ, val) = encode_attribute(&d, a, "shell:priv-lvl=15").unwrap();
        assert_eq!(typ, ATTR_VENDOR_SPECIFIC);
        assert_eq!(&val[..4], &9u32.to_be_bytes()); // vendor id
        assert_eq!(val[4], 1); // vendor type
        assert_eq!(val[5] as usize, val.len() - 4); // vendor length covers type+len+value
        assert_eq!(&val[6..], b"shell:priv-lvl=15");
    }

    #[test]
    fn wraps_wimax_vsa_format_2_1() {
        let d = dict();
        let a = d.attr_by_name("WiMAX-Capability").unwrap();
        let (_typ, val) = encode_attribute(&d, a, "abc").unwrap();
        assert_eq!(&val[..4], &24757u32.to_be_bytes());
        assert_eq!(&val[4..6], &[0x00, 0x01]); // 2-byte vendor type
        assert_eq!(val[6] as usize, 3 + 3); // 1-byte length = type(2)+len(1)+value(3)
        assert_eq!(&val[7..], b"abc");
    }

    #[test]
    fn decodes_enum_and_ip() {
        let d = dict();
        let st = d.attr_by_name("Service-Type").unwrap();
        assert_eq!(decode_to_string(st, &[0, 0, 0, 2]), "Framed-User");
        let ip = d.attr_by_name("NAS-IP-Address").unwrap();
        assert_eq!(decode_to_string(ip, &[192, 168, 0, 1]), "192.168.0.1");
    }

    #[test]
    fn rejects_bad_values() {
        let d = dict();
        let a = d.attr_by_name("NAS-IP-Address").unwrap();
        assert!(encode_attribute(&d, a, "not-an-ip").is_err());
    }
}
