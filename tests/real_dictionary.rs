//! Integration test against the RADIUS dictionary shipped with the reference
//! distribution. It is skipped when that data is not present, so the crate
//! builds standalone.
//!
//! The dictionary data itself is CC-BY-4.0 (FreeRADIUS project) and is *not*
//! bundled with this crate; the test only reads a user-provided copy.

use radperf_rs::dict::{DataType, Dictionary};
use std::path::PathBuf;

fn shipped_share_dir() -> Option<PathBuf> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../radperf/linux/opt/networkradius/radperf/share");
    if dir.join("dictionary").is_file() {
        Some(dir)
    } else {
        None
    }
}

#[test]
fn loads_shipped_dictionary_and_resolves_rfc2865() {
    let Some(dir) = shipped_share_dir() else {
        eprintln!("shipped dictionary not present; skipping");
        return;
    };
    let d = Dictionary::load_dir(&dir).expect("dictionary must load");
    assert!(
        d.attribute_count() > 5000,
        "expected thousands of attributes"
    );
    assert!(d.vendors.len() > 100, "expected many vendors");

    // Core RFC 2865 / 2866 attributes.
    let un = d.attr_by_name("User-Name").unwrap();
    assert_eq!((un.number, un.ty, un.vendor), (1, DataType::String, 0));

    let up = d.attr_by_name("User-Password").unwrap();
    assert_eq!((up.number, up.ty), (2, DataType::String));
    assert_eq!(up.flags.encrypt, 1, "User-Password is encrypted");

    let chap = d.attr_by_name("CHAP-Password").unwrap();
    assert_eq!((chap.number, chap.ty), (3, DataType::Octets));

    let nas_ip = d.attr_by_name("NAS-IP-Address").unwrap();
    assert_eq!((nas_ip.number, nas_ip.ty), (4, DataType::IpAddr));

    let svc = d.attr_by_name("Service-Type").unwrap();
    assert_eq!(svc.value_of("Login-User"), Some(1));
    assert_eq!(svc.value_of("Framed-User"), Some(2));
    // Several aliases may share a numeric value; decode must still resolve one.
    assert!(svc.name_of(1).is_some());

    let acct_status = d.attr_by_name("Acct-Status-Type").unwrap();
    assert_eq!(
        (acct_status.number, acct_status.ty),
        (40, DataType::Integer)
    );
    assert_eq!(acct_status.value_of("Start"), Some(1));
    assert_eq!(acct_status.value_of("Stop"), Some(2));

    let msg_auth = d.attr_by_name("Message-Authenticator").unwrap();
    assert_eq!((msg_auth.number, msg_auth.ty), (80, DataType::Octets));

    // Top-level lookup by (vendor, type).
    assert_eq!(d.attr_by_key(0, 1).unwrap().name, "User-Name");

    // Vendor-specific attribute (Cisco vendor id 9).
    let cisco = d.vendor_by_name("Cisco").expect("Cisco vendor");
    assert_eq!(cisco.id, 9);
    let avpair = d.attr_by_name("Cisco-AVPair").unwrap();
    assert_eq!((avpair.vendor, avpair.number), (9, 1));
    assert!(d.attr_by_key(9, 1).is_some());
}

#[test]
fn loads_shipped_dictionary_is_deterministic() {
    let Some(dir) = shipped_share_dir() else {
        eprintln!("shipped dictionary not present; skipping");
        return;
    };
    let a = Dictionary::load_dir(&dir).unwrap();
    let b = Dictionary::load_dir(&dir).unwrap();
    assert_eq!(a.attribute_count(), b.attribute_count());
    assert_eq!(a.vendors.len(), b.vendors.len());
}
