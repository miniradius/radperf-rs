//! Request templates: attribute bytes encoded once, then materialized into
//! packets on the hot path by patching only the identifier and authenticator.
//!
//! Keeping the expensive work (dictionary lookups, value encoding, attribute
//! layout) in [`Template::from_pairs`] means the per-packet path is a few
//! `memcpy`s plus the unavoidable MD5 for the authenticator.

use crate::crypto;
use crate::dict::Dictionary;
use crate::packet::{ACCOUNTING_REQUEST, COA_REQUEST, DISCONNECT_REQUEST, HEADER_LEN};
use crate::rng::Rng;
use crate::value::encode_attribute_tagged;
use std::fmt;

/// How the Request Authenticator is derived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthKind {
    /// Random 16 bytes (Access-Request, Status-Server).
    Random,
    /// `MD5(...)` over the packet (Accounting, CoA, Disconnect).
    Computed,
}

fn auth_kind(code: u8) -> AuthKind {
    match code {
        ACCOUNTING_REQUEST | COA_REQUEST | DISCONNECT_REQUEST => AuthKind::Computed,
        _ => AuthKind::Random,
    }
}

/// Authentication method for the Access-Request phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    /// PAP: encrypt User-Password with the Request Authenticator.
    Pap,
    /// CHAP: derive a CHAP-Password from a random identifier and the RA.
    Chap,
}

/// CHAP-Password attribute type (RFC 2865 section 5.3).
const ATTR_CHAP_PASSWORD: u8 = 3;

/// When to add a Message-Authenticator (BlastRADIUS mitigation, RFC 3579).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgAuthMode {
    /// Add to every request type when absent (default).
    Auto,
    /// Never add automatically (CoA/Disconnect still require it).
    Never,
}

/// Template construction error.
#[derive(Debug)]
pub struct TemplateError {
    pub message: String,
}

impl TemplateError {
    fn new(message: impl Into<String>) -> Self {
        TemplateError {
            message: message.into(),
        }
    }
}

impl fmt::Display for TemplateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for TemplateError {}

#[derive(Clone)]
struct PasswordSlot {
    padded: Vec<u8>,
    offset: usize,
    len: usize,
}

/// A CHAP-Password slot filled in per packet (identifier + MD5 digest).
#[derive(Clone)]
struct ChapSlot {
    password: Vec<u8>,
    /// Offset of the 17-byte CHAP-Password value within `attributes`.
    offset: usize,
}
/// A pre-encoded request template.
#[derive(Clone)]
pub struct Template {
    pub code: u8,
    attributes: Vec<u8>,
    password: Option<PasswordSlot>,
    chap: Option<ChapSlot>,
    has_message_authenticator: bool,
    auth: AuthKind,
}

impl Template {
    /// Encode a list of `(attribute-name, raw-value)` pairs into a template
    /// using PAP for any encrypted password.
    pub fn from_pairs(
        dict: &Dictionary,
        code: u8,
        pairs: &[(String, String)],
    ) -> Result<Template, TemplateError> {
        Template::from_pairs_with_auth(dict, code, pairs, AuthMode::Pap)
    }

    /// Encode a list of `(attribute-name, raw-value)` pairs into a template,
    /// choosing how a supplied User-Password is turned into an Access-Request.
    pub fn from_pairs_with_auth(
        dict: &Dictionary,
        code: u8,
        pairs: &[(String, String)],
        auth_mode: AuthMode,
    ) -> Result<Template, TemplateError> {
        let mut attributes = Vec::new();
        let mut password = None;
        let mut chap = None;
        let auth = auth_kind(code);

        for (name, raw) in pairs {
            // An attribute may carry a tag: `Name:tag = value`.
            let (base_name, tag) = match name.split_once(':') {
                Some((base, value)) => {
                    let tag = value.parse::<u8>().map_err(|_| {
                        TemplateError::new(format!("invalid tag in '{name}' (expected 0..31)"))
                    })?;
                    (base, Some(tag))
                }
                None => (name.as_str(), None),
            };
            let attr = dict
                .attr_by_name(base_name)
                .ok_or_else(|| TemplateError::new(format!("unknown attribute '{base_name}'")))?;

            if attr.vendor == 0 && attr.flags.encrypt == 1 {
                if tag.is_some() {
                    return Err(TemplateError::new(format!(
                        "tagged encrypted attribute '{base_name}' is not supported"
                    )));
                }
                if auth == AuthKind::Computed {
                    return Err(TemplateError::new(format!(
                        "encrypted attribute '{name}' is only supported for Access-Request"
                    )));
                }
                if password.is_some() || chap.is_some() {
                    return Err(TemplateError::new(
                        "a request can contain only one encrypted password",
                    ));
                }
                let plaintext = raw.as_bytes();
                if plaintext.len() > 128 {
                    return Err(TemplateError::new(format!(
                        "password for '{name}' is longer than 128 bytes"
                    )));
                }
                if auth_mode == AuthMode::Chap {
                    // CHAP-Password = ident(1) || MD5(ident||password||challenge);
                    // the value is filled in per packet once the RA is known.
                    let offset = attributes.len() + 2;
                    attributes.push(ATTR_CHAP_PASSWORD);
                    attributes.push(19); // 1-byte ident + 16-byte digest + 2
                    attributes.extend_from_slice(&[0u8; 17]);
                    chap = Some(ChapSlot {
                        password: plaintext.to_vec(),
                        offset,
                    });
                    continue;
                }
                let blocks = plaintext.len().div_ceil(16).max(1);
                let len = blocks * 16;
                let mut padded = vec![0u8; len];
                padded[..plaintext.len()].copy_from_slice(plaintext);
                let offset = attributes.len() + 2;
                attributes.push(attr.number as u8);
                attributes.push((len + 2) as u8);
                attributes.extend_from_slice(&padded);
                password = Some(PasswordSlot {
                    padded,
                    offset,
                    len,
                });
                continue;
            }

            let (typ, value) = encode_attribute_tagged(dict, attr, raw, tag)
                .map_err(|e| TemplateError::new(format!("{name}: {e}")))?;
            attributes.push(typ);
            attributes.push((value.len() + 2) as u8);
            attributes.extend_from_slice(&value);
        }

        let mut has_message_authenticator = attributes.windows(2).any(|w| w[0] == 80);

        // RFC 3576 requires a Message-Authenticator in CoA/Disconnect requests.
        // Other request types are handled by the caller via `-m`.
        if matches!(code, COA_REQUEST | DISCONNECT_REQUEST) && !has_message_authenticator {
            attributes.push(80);
            attributes.push(18);
            attributes.extend_from_slice(&[0u8; 16]);
            has_message_authenticator = true;
        }

        Ok(Template {
            code,
            attributes,
            password,
            chap,
            has_message_authenticator,
            auth,
        })
    }

    /// Append a zeroed Message-Authenticator if the template does not have one.
    pub fn ensure_message_authenticator(&mut self) {
        if !self.has_message_authenticator {
            self.attributes.push(80);
            self.attributes.push(18);
            self.attributes.extend_from_slice(&[0u8; 16]);
            self.has_message_authenticator = true;
        }
    }

    /// Size of a materialized packet.
    pub fn wire_len(&self) -> usize {
        HEADER_LEN + self.attributes.len()
    }

    /// Raw attribute bytes (used to derive accounting base attributes).
    pub fn attributes(&self) -> &[u8] {
        &self.attributes
    }

    /// Materialize a packet for `id` into `out`, returning its length.
    #[inline]
    pub fn build_into(&self, id: u8, secret: &[u8], rng: &mut Rng, out: &mut Vec<u8>) -> usize {
        out.clear();
        let total = HEADER_LEN + self.attributes.len();
        out.reserve(total);
        out.push(self.code);
        out.push(id);
        out.push(0);
        out.push(0);
        out.extend_from_slice(&[0u8; 16]);
        out.extend_from_slice(&self.attributes);

        if self.auth == AuthKind::Random {
            let mut ra = [0u8; 16];
            rng.fill(&mut ra);
            out[4..20].copy_from_slice(&ra);
        }

        if let Some(c) = &self.chap {
            let ra: [u8; 16] = out[4..20].try_into().unwrap();
            let ident = self.rng_ident(rng);
            let digest = crypto::chap_response(ident, &c.password, &ra);
            let start = HEADER_LEN + c.offset;
            out[start] = ident;
            out[start + 1..start + 17].copy_from_slice(&digest);
        }

        if let Some(p) = &self.password {
            let ra: [u8; 16] = out[4..20].try_into().unwrap();
            let start = HEADER_LEN + p.offset;
            out[start..start + p.len].copy_from_slice(&p.padded);
            crypto::pap_encrypt_in_place(&mut out[start..start + p.len], secret, &ra);
        }

        if self.auth == AuthKind::Computed {
            let ra =
                crypto::request_authenticator_raw(self.code, id, &out[HEADER_LEN..total], secret);
            out[4..20].copy_from_slice(&ra);
        }

        out[2..4].copy_from_slice(&(total as u16).to_be_bytes());

        if self.has_message_authenticator {
            crypto::fill_message_authenticator(&mut out[..total], secret);
        }
        total
    }

    #[inline]
    fn rng_ident(&self, rng: &mut Rng) -> u8 {
        (rng.next_u64() as u8) | 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{Packet, ACCESS_REQUEST, STATUS_SERVER};
    use std::io::Write;

    fn dict() -> Dictionary {
        let text = "\
ATTRIBUTE\tUser-Name\t1\tstring\n\
ATTRIBUTE\tUser-Password\t2\tstring\tencrypt=1\n\
ATTRIBUTE\tAcct-Session-Id\t44\tstring\n\
ATTRIBUTE\tAcct-Status-Type\t40\tinteger\n\
VALUE\tAcct-Status-Type\tStart\t1\n\
ATTRIBUTE\tMessage-Authenticator\t80\toctets\n\
ATTRIBUTE\tTunnel-Type\t64\tinteger\thas_tag\n\
VALUE\tTunnel-Type\tVLAN\t13\n";
        let mut f = tempfile::Builder::new().suffix(".dict").tempfile().unwrap();
        f.write_all(text.as_bytes()).unwrap();
        f.flush().unwrap();
        Dictionary::load_file(f.path()).unwrap()
    }

    fn pairs(items: &[(&str, &str)]) -> Vec<(String, String)> {
        items
            .iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect()
    }

    #[test]
    fn access_request_encrypts_password_and_is_verifiable() {
        let d = dict();
        let t = Template::from_pairs(
            &d,
            ACCESS_REQUEST,
            &pairs(&[("User-Name", "alice"), ("User-Password", "secret")]),
        )
        .unwrap();
        let mut rng = Rng::from_seed(1, 2);
        let mut out = Vec::new();
        let len = t.build_into(7, b"shared", &mut rng, &mut out);
        assert_eq!(len, out.len());
        let pkt = Packet::decode(&out).unwrap();
        assert_eq!(pkt.code, ACCESS_REQUEST);
        assert_eq!(pkt.id, 7);
        // Recover the User-Password using the packet's authenticator.
        let up = pkt.iter_raw().find(|(t, _)| *t == 2).unwrap().1;
        let ra: [u8; 16] = pkt.authenticator;
        let pt = crypto::pap_decrypt(up, b"shared", &ra).unwrap();
        assert_eq!(&pt[..6], b"secret");
    }

    #[test]
    fn accounting_request_authenticator_is_computed() {
        let d = dict();
        let t = Template::from_pairs(
            &d,
            ACCOUNTING_REQUEST,
            &pairs(&[("User-Name", "bob"), ("Acct-Status-Type", "Start")]),
        )
        .unwrap();
        let mut rng = Rng::from_seed(3, 4);
        let mut out = Vec::new();
        t.build_into(9, b"secret", &mut rng, &mut out);
        let pkt = Packet::decode(&out).unwrap();
        let expected = crypto::request_authenticator(&pkt, b"secret");
        assert_eq!(pkt.authenticator, expected);
    }

    #[test]
    fn message_authenticator_is_filled_and_verifies() {
        let d = dict();
        let t = Template::from_pairs(
            &d,
            STATUS_SERVER,
            &pairs(&[(
                "Message-Authenticator",
                "0x00000000000000000000000000000000",
            )]),
        )
        .unwrap();
        let mut rng = Rng::from_seed(5, 6);
        let mut out = Vec::new();
        t.build_into(1, b"secret", &mut rng, &mut out);
        assert!(crypto::verify_message_authenticator(&out, b"secret"));
        assert!(!crypto::verify_message_authenticator(&out, b"other"));
    }

    #[test]
    fn coa_request_gets_message_authenticator_automatically() {
        let d = dict();
        let t = Template::from_pairs(
            &d,
            crate::packet::COA_REQUEST,
            &pairs(&[("User-Name", "alice")]),
        )
        .unwrap();
        let mut rng = Rng::from_seed(7, 8);
        let mut out = Vec::new();
        t.build_into(3, b"secret", &mut rng, &mut out);
        assert!(crypto::verify_message_authenticator(&out, b"secret"));
    }

    #[test]
    fn chap_request_computes_digest_from_ra() {
        let d = dict();
        let t = Template::from_pairs_with_auth(
            &d,
            ACCESS_REQUEST,
            &pairs(&[("User-Name", "alice"), ("User-Password", "secret")]),
            AuthMode::Chap,
        )
        .unwrap();
        let mut rng = Rng::from_seed(11, 12);
        let mut out = Vec::new();
        t.build_into(4, b"shared", &mut rng, &mut out);
        let pkt = Packet::decode(&out).unwrap();
        // CHAP-Password is present and no cleartext User-Password is emitted.
        let chap = pkt.iter_raw().find(|(t, _)| *t == 3).unwrap().1;
        assert!(pkt.iter_raw().all(|(t, _)| t != 2));
        assert_eq!(chap.len(), 17);
        let ident = chap[0];
        let expected = crypto::chap_response(ident, b"secret", &pkt.authenticator);
        assert_eq!(&chap[1..], &expected[..]);
    }

    #[test]
    fn tagged_integer_attribute_encodes_the_tag_octet() {
        let d = dict();
        let t =
            Template::from_pairs(&d, ACCESS_REQUEST, &pairs(&[("Tunnel-Type:1", "VLAN")])).unwrap();
        let mut rng = Rng::from_seed(1, 2);
        let mut out = Vec::new();
        t.build_into(1, b"secret", &mut rng, &mut out);
        let pkt = Packet::decode(&out).unwrap();
        let value = pkt.iter_raw().find(|(t, _)| *t == 64).unwrap().1;
        // tag 1 in the most significant octet, value 13 in the low three.
        assert_eq!(value, &[1, 0, 0, 13]);
    }

    #[test]
    fn rejects_tag_on_untagged_attribute() {
        let d = dict();
        let err = Template::from_pairs(&d, ACCESS_REQUEST, &pairs(&[("User-Name:1", "bob")]));
        assert!(err.is_err());
    }

    #[test]
    fn rejects_out_of_range_tags() {
        let d = dict();
        for attribute in ["Tunnel-Type:32", "Tunnel-Type:256"] {
            let Err(error) =
                Template::from_pairs(&d, ACCESS_REQUEST, &pairs(&[(attribute, "VLAN")]))
            else {
                panic!("accepted {attribute}");
            };
            assert!(error.to_string().contains("0..31"));
        }
    }

    #[test]
    fn rejects_repeated_encrypted_passwords() {
        let d = dict();
        let attributes = pairs(&[("User-Password", "first"), ("User-Password", "second")]);
        for mode in [AuthMode::Pap, AuthMode::Chap] {
            let result = Template::from_pairs_with_auth(&d, ACCESS_REQUEST, &attributes, mode);
            assert!(result.is_err());
        }
    }

    #[test]
    fn rejects_unknown_attribute() {
        let d = dict();
        let err = Template::from_pairs(&d, ACCESS_REQUEST, &pairs(&[("No-Such-Attr", "x")]));
        assert!(err.is_err());
    }

    #[test]
    fn rejects_encrypted_attribute_on_accounting() {
        let d = dict();
        let err = Template::from_pairs(&d, ACCOUNTING_REQUEST, &pairs(&[("User-Password", "x")]));
        assert!(err.is_err());
    }
}
