//! RADIUS cryptography: MD5 authenticators, HMAC-MD5, PAP and CHAP.
//!
//! All formulas follow the public RFCs: RFC 2865 (section 3, section 5.2, section 5.3),
//! RFC 2866 (section 3), RFC 3576 (section 3), RFC 2104 (HMAC) and RFC 3579 (section 3.2).

use crate::packet::{Packet, HEADER_LEN};

/// Raw MD5 digest.
pub fn md5(data: &[u8]) -> [u8; 16] {
    md5::compute(data).0
}

/// MD5 over a sequence of slices, without concatenating into one buffer.
pub fn md5_multi(parts: &[&[u8]]) -> [u8; 16] {
    let mut ctx = md5::Context::new();
    for part in parts {
        ctx.consume(part);
    }
    ctx.compute().0
}

/// HMAC-MD5 (RFC 2104) over a sequence of slices.
pub fn hmac_md5(key: &[u8], parts: &[&[u8]]) -> [u8; 16] {
    const BLOCK: usize = 64;
    let mut key_block = [0u8; BLOCK];
    if key.len() > BLOCK {
        key_block[..16].copy_from_slice(&md5(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }
    let mut inner = md5::Context::new();
    inner.consume(ipad);
    for part in parts {
        inner.consume(part);
    }
    let inner_digest = inner.compute().0;
    md5_multi(&[&opad, &inner_digest])
}

/// 4-byte big-endian header prefix `Code | Identifier | Length`.
fn header_prefix(code: u8, id: u8, length: usize) -> [u8; 4] {
    let l = length as u16;
    [code, id, l.to_be_bytes()[0], l.to_be_bytes()[1]]
}

/// Request Authenticator for Accounting-Request (RFC 2866 section 3) and
/// CoA/Disconnect-Request (RFC 3576 section 3):
/// `MD5(Code+ID+Length+16 zero octets+Attributes+Secret)`.
pub fn request_authenticator(packet: &Packet, secret: &[u8]) -> [u8; 16] {
    request_authenticator_raw(packet.code, packet.id, &packet.attributes, secret)
}

/// As [`request_authenticator`], operating on raw attribute bytes (no `Packet`
/// allocation).
pub fn request_authenticator_raw(code: u8, id: u8, attributes: &[u8], secret: &[u8]) -> [u8; 16] {
    let prefix = header_prefix(code, id, HEADER_LEN + attributes.len());
    let zeros = [0u8; 16];
    md5_multi(&[&prefix, &zeros, attributes, secret])
}

/// Response Authenticator (RFC 2865 section 3):
/// `MD5(Code+ID+Length+RequestAuth+Attributes+Secret)`.
pub fn response_authenticator(
    response: &Packet,
    request_authenticator: &[u8; 16],
    secret: &[u8],
) -> [u8; 16] {
    let prefix = header_prefix(response.code, response.id, response.len());
    md5_multi(&[&prefix, request_authenticator, &response.attributes, secret])
}

/// Verify a received response against the request's authenticator.
pub fn verify_response_authenticator(
    response: &Packet,
    request_authenticator: &[u8; 16],
    secret: &[u8],
) -> bool {
    let expected = response_authenticator(response, request_authenticator, secret);
    constant_time_eq(&expected, &response.authenticator)
}

/// Error from a crypto operation with invalid input sizes.
#[derive(Debug, PartialEq, Eq)]
pub enum CryptoError {
    PasswordTooLong(usize),
    NotBlockAligned(usize),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::PasswordTooLong(n) => write!(f, "password too long: {n} bytes (max 128)"),
            CryptoError::NotBlockAligned(n) => {
                write!(f, "ciphertext length {n} is not a multiple of 16")
            }
        }
    }
}

impl std::error::Error for CryptoError {}

/// Encrypt a User-Password for a PAP Access-Request (RFC 2865 section 5.2).
pub fn pap_encrypt(
    password: &[u8],
    secret: &[u8],
    request_authenticator: &[u8; 16],
) -> Result<Vec<u8>, CryptoError> {
    if password.len() > 128 {
        return Err(CryptoError::PasswordTooLong(password.len()));
    }
    let blocks = password.len().div_ceil(16).max(1);
    let mut out = vec![0u8; blocks * 16];
    out[..password.len()].copy_from_slice(password);
    pap_encrypt_in_place(&mut out, secret, request_authenticator);
    Ok(out)
}

/// In-place PAP encryption. `padded` must be a multiple of 16 bytes and hold
/// the zero-padded plaintext; it is replaced by the ciphertext. Allocation-free
/// so the per-packet path can reuse a buffer.
pub fn pap_encrypt_in_place(padded: &mut [u8], secret: &[u8], request_authenticator: &[u8; 16]) {
    let mut prev = *request_authenticator;
    for chunk in padded.chunks_mut(16) {
        let b = md5_multi(&[secret, &prev]);
        for (x, k) in chunk.iter_mut().zip(b.iter()) {
            *x ^= k;
        }
        prev.copy_from_slice(chunk);
    }
}

/// Decrypt a PAP User-Password (RFC 2865 section 5.2). The result is NUL-padded to a
/// block boundary; callers trim trailing NULs.
pub fn pap_decrypt(
    ciphertext: &[u8],
    secret: &[u8],
    request_authenticator: &[u8; 16],
) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.len() % 16 != 0 {
        return Err(CryptoError::NotBlockAligned(ciphertext.len()));
    }
    let mut out = Vec::with_capacity(ciphertext.len());
    let mut prev: Vec<u8> = request_authenticator.to_vec();
    for chunk in ciphertext.chunks(16) {
        let b = md5_multi(&[secret, &prev]);
        let p: Vec<u8> = chunk.iter().zip(b.iter()).map(|(c, k)| c ^ k).collect();
        out.extend_from_slice(&p);
        prev = chunk.to_vec();
    }
    Ok(out)
}

/// Compute a CHAP-Password value (RFC 2865 section 5.3):
/// `CHAP-Ident || MD5(CHAP-Ident || password || challenge)`.
pub fn chap_response(ident: u8, password: &[u8], challenge: &[u8]) -> [u8; 16] {
    md5_multi(&[&[ident], password, challenge])
}

/// Fill in the Message-Authenticator (type 80) attribute of an already encoded
/// packet (RFC 3579 section 3.2). The packet must contain a zero-valued 18-byte
/// Message-Authenticator. Returns false when it is absent.
pub fn fill_message_authenticator(encoded: &mut [u8], secret: &[u8]) -> bool {
    let Some(value_pos) = find_attribute(encoded, 80) else {
        return false;
    };
    if value_pos + 16 > encoded.len() {
        return false;
    }
    encoded[value_pos..value_pos + 16].fill(0);
    let digest = hmac_md5(secret, &[&encoded[..]]);
    encoded[value_pos..value_pos + 16].copy_from_slice(&digest);
    true
}

/// Verify the Message-Authenticator of a received packet.
pub fn verify_message_authenticator(encoded: &[u8], secret: &[u8]) -> bool {
    let Some(value_pos) = find_attribute(encoded, 80) else {
        return false;
    };
    if value_pos + 16 > encoded.len() {
        return false;
    }
    let received = &encoded[value_pos..value_pos + 16];
    let mut copy = encoded.to_vec();
    copy[value_pos..value_pos + 16].fill(0);
    let expected = hmac_md5(secret, &[&copy[..]]);
    constant_time_eq(&expected, received)
}

/// Return the byte offset of the first attribute value with `typ`.
fn find_attribute(encoded: &[u8], typ: u8) -> Option<usize> {
    if encoded.len() < HEADER_LEN {
        return None;
    }
    let mut offset = HEADER_LEN;
    while offset + 2 <= encoded.len() {
        let t = encoded[offset];
        let len = encoded[offset + 1] as usize;
        if len < 2 || offset + len > encoded.len() {
            return None;
        }
        if t == typ {
            return Some(offset + 2);
        }
        offset += len;
    }
    None
}

/// Constant-time byte-slice comparison.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{Packet, ACCOUNTING_REQUEST, ACCOUNTING_RESPONSE, STATUS_SERVER};

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn md5_known_answer() {
        assert_eq!(hex(&md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn hmac_md5_known_answer() {
        assert_eq!(
            hex(&hmac_md5(b"key", &[b"message"])),
            "4e4748e62b463521f6775fbf921234b5"
        );
    }

    #[test]
    fn pap_known_answer() {
        let ct = pap_encrypt(b"password", b"shared secret", &[0u8; 16]).unwrap();
        assert_eq!(hex(&ct), "32c70008d810aa5c67bf2ea5532fc14a");
        let pt = pap_decrypt(&ct, b"shared secret", &[0u8; 16]).unwrap();
        assert_eq!(&pt[..8], b"password");
        assert!(pt[8..].iter().all(|&b| b == 0));
    }

    #[test]
    fn chap_known_answer() {
        assert_eq!(
            hex(&chap_response(1, b"password", &[0u8; 16])),
            "ae88b6c2fe68bc923ae994f652508d12"
        );
    }

    #[test]
    fn accounting_request_authenticator_known_answer() {
        let mut p = Packet::new(ACCOUNTING_REQUEST, 7);
        p.push_raw(1, b"alice").unwrap();
        assert_eq!(
            hex(&request_authenticator(&p, b"secret")),
            "2a75d71652d59bd87dcdf4f89399c4c1"
        );
    }

    #[test]
    fn response_authenticator_round_trip() {
        let mut req = Packet::new(ACCOUNTING_REQUEST, 7);
        req.push_raw(1, b"alice").unwrap();
        let ra = request_authenticator(&req, b"secret");

        let mut resp = Packet::new(ACCOUNTING_RESPONSE, 7);
        resp.authenticator = response_authenticator(&resp, &ra, b"secret");
        assert_eq!(hex(&resp.authenticator), "367d93bc726835a187e0ac964f137ea4");
        assert!(verify_response_authenticator(&resp, &ra, b"secret"));
        // Wrong secret must fail.
        assert!(!verify_response_authenticator(&resp, &ra, b"other"));
    }

    #[test]
    fn message_authenticator_known_answer() {
        let mut p = Packet::new(STATUS_SERVER, 1);
        p.push_raw(80, &[0u8; 16]).unwrap();
        let mut bytes = p.encode();
        assert!(fill_message_authenticator(&mut bytes, b"secret"));
        let value = &bytes[bytes.len() - 16..];
        assert_eq!(hex(value), "86b9bb6d65d6fd7304f2a19ad3cf1424");
        assert!(verify_message_authenticator(&bytes, b"secret"));
        assert!(!verify_message_authenticator(&bytes, b"nope"));
    }
}
