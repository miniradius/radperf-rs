//! End-to-end test: run the engine against a small in-process RADIUS server
//! that answers Access-Requests with correctly signed Access-Accepts.

use radperf_rs::client::{Client, ClientConfig};
use radperf_rs::crypto;
use radperf_rs::dict::Dictionary;
use radperf_rs::packet::{Packet, ACCESS_ACCEPT, ACCESS_REQUEST};
use radperf_rs::request::Template;
use radperf_rs::{accounting, packet};
use std::collections::HashMap;
use std::io::Write;
use std::net::UdpSocket;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn dictionary() -> Dictionary {
    let text = "\
ATTRIBUTE\tUser-Name\t1\tstring\n\
ATTRIBUTE\tUser-Password\t2\tstring\tencrypt=1\n";
    let mut f = tempfile::Builder::new().suffix(".dict").tempfile().unwrap();
    f.write_all(text.as_bytes()).unwrap();
    f.flush().unwrap();
    Dictionary::load_file(f.path()).unwrap()
}

#[test]
fn version_identifies_the_rust_implementation() {
    let expected = format!("radperf {} (miniradius/radperf-rs)\n", radperf_rs::VERSION);
    for flag in ["-v", "--version"] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_radperf"))
            .arg(flag)
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, expected.as_bytes());
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn access_request_gets_signed_response() {
    const N: usize = 20;
    let secret = b"shared-secret".to_vec();

    // Mock server.
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let addr = server.local_addr().unwrap();
    let seen = Arc::new(AtomicUsize::new(0));
    let seen_srv = seen.clone();
    let secret_srv = secret.clone();
    let server_thread = thread::spawn(move || {
        let mut buf = [0u8; 4096];
        for _ in 0..N {
            let (n, peer) = match server.recv_from(&mut buf) {
                Ok(v) => v,
                Err(_) => break,
            };
            let req = Packet::decode(&buf[..n]).unwrap();
            assert_eq!(req.code, ACCESS_REQUEST);
            let mut resp = Packet::new(ACCESS_ACCEPT, req.id);
            resp.authenticator =
                crypto::response_authenticator(&resp, &req.authenticator, &secret_srv);
            let _ = server.send_to(&resp.encode(), peer);
            seen_srv.fetch_add(1, Ordering::SeqCst);
        }
    });

    // Client.
    let dict = dictionary();
    let pairs = vec![("User-Name".to_string(), "alice".to_string())];
    let template = Template::from_pairs(&dict, ACCESS_REQUEST, &pairs).unwrap();
    let jobs: Vec<u32> = vec![0; N];
    let config = ClientConfig {
        server: addr,
        secret,
        parallel: 1,
        rate: 0,
        retries: 1,
        timeout: Duration::from_millis(500),
        quiet: true,
        debug: 0,
        collect_stats: true,
        json_summary: false,
        print_summary: false,
        delays: None,
        persec: false,
        accounting: None,
        accounting_direct: false,
        acct_server: None,
        acct_copy_types: Vec::new(),
        acct_bases: Vec::new(),
    };
    let mut client = Client::new(config, vec![template], jobs).unwrap();
    let stats = client.run().unwrap();
    server_thread.join().unwrap();

    assert_eq!(stats.requests_sent, N as u64);
    assert_eq!(
        stats.responses_received, N as u64,
        "all responses must verify"
    );
    assert_eq!(stats.timeouts, 0);
    assert_eq!(seen.load(Ordering::SeqCst), N);
    assert_eq!(stats.rtt.count(), N as u64);
}

#[test]
fn responses_with_wrong_secret_are_rejected() {
    let server_secret = b"wrong-secret";
    let client_secret = b"right-secret".to_vec();

    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let addr = server.local_addr().unwrap();
    let server_thread = thread::spawn(move || {
        let mut buf = [0u8; 4096];
        if let Ok((n, peer)) = server.recv_from(&mut buf) {
            let req = Packet::decode(&buf[..n]).unwrap();
            let mut resp = Packet::new(ACCESS_ACCEPT, req.id);
            resp.authenticator =
                crypto::response_authenticator(&resp, &req.authenticator, server_secret);
            let _ = server.send_to(&resp.encode(), peer);
        }
    });

    let dict = dictionary();
    let pairs = vec![("User-Name".to_string(), "alice".to_string())];
    let template = Template::from_pairs(&dict, ACCESS_REQUEST, &pairs).unwrap();
    let config = ClientConfig {
        server: addr,
        secret: client_secret,
        parallel: 1,
        rate: 0,
        retries: 0,
        timeout: Duration::from_millis(300),
        quiet: true,
        debug: 0,
        collect_stats: false,
        json_summary: false,
        print_summary: false,
        delays: None,
        persec: false,
        accounting: None,
        accounting_direct: false,
        acct_server: None,
        acct_copy_types: Vec::new(),
        acct_bases: Vec::new(),
    };
    let mut client = Client::new(config, vec![template], vec![0]).unwrap();
    let stats = client.run().unwrap();
    server_thread.join().unwrap();

    assert_eq!(stats.requests_sent, 1);
    assert_eq!(stats.responses_received, 0);
    assert_eq!(
        stats.unmatched, 1,
        "wrong-secret response must not count as accepted"
    );
    assert_eq!(stats.timeouts, 1);
}

#[test]
fn generated_users_append_to_files_and_share_the_template() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input");
    let template = dir.path().join("template");
    std::fs::write(
        dir.path().join("dictionary"),
        "\
ATTRIBUTE User-Name 1 string\n\
ATTRIBUTE User-Password 2 string encrypt=1\n\
ATTRIBUTE Class 25 octets\n\
ATTRIBUTE Tunnel-Type 64 integer has_tag\n\
ATTRIBUTE Tunnel-Private-Group-Id 81 string has_tag\n",
    )
    .unwrap();
    std::fs::write(
        &input,
        "\
User-Name = alice\n\
User-Password = custom\n\
Class = 0x6669727374\n\
Class += 0x7365636f6e64\n\
Class := 0x7468697264\n\
Class == 0x666f75727468\n\
Tunnel-Type:0 = 13\n\
Tunnel-Type:31 = 13\n\
Tunnel-Private-Group-Id:0 = zero\n\
Tunnel-Private-Group-Id:31 = last\n\n\
User-Name = bob\n",
    )
    .unwrap();
    std::fs::write(&template, "Class == 0x74656d706c617465\n").unwrap();

    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let addr = server.local_addr().unwrap();
    let server_thread = thread::spawn(move || {
        let secret = b"shared-secret";
        let mut buf = [0u8; 4096];
        (0..4)
            .map(|_| {
                let (len, peer) = server.recv_from(&mut buf).unwrap();
                let request = Packet::decode(&buf[..len]).unwrap();
                assert_eq!(request.code, ACCESS_REQUEST);
                let mut reply = Packet::new(ACCESS_ACCEPT, request.id);
                reply.authenticator =
                    crypto::response_authenticator(&reply, &request.authenticator, secret);
                server.send_to(&reply.encode(), peer).unwrap();
                request
                    .iter_raw()
                    .filter(|(typ, _)| *typ != 80)
                    .map(|(typ, value)| {
                        let value = if typ == 2 {
                            let mut clear =
                                crypto::pap_decrypt(value, secret, &request.authenticator).unwrap();
                            clear.truncate(
                                clear.iter().position(|&b| b == 0).unwrap_or(clear.len()),
                            );
                            clear
                        } else {
                            value.to_vec()
                        };
                        (typ, value)
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>()
    });

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_radperf"))
        .arg("-d")
        .arg(dir.path())
        .arg("-f")
        .arg(input)
        .arg("-T")
        .arg(template)
        .args(["-u", "2", "-R", "example.test", "-r", "0", "-t", "0.5"])
        .arg(addr.to_string())
        .args(["auth", "shared-secret"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let packets = server_thread.join().unwrap();
    let expected: [&[(u8, &[u8])]; 4] = [
        &[
            (1, b"alice@example.test"),
            (2, b"custom"),
            (25, b"first"),
            (25, b"second"),
            (25, b"third"),
            (25, b"fourth"),
            (64, &[0, 0, 0, 13]),
            (64, &[31, 0, 0, 13]),
            (81, b"zero"),
            (81, b"\x1flast"),
            (25, b"template"),
        ],
        &[(1, b"bob@example.test"), (25, b"template")],
        &[
            (1, b"user1example.test"),
            (2, b"user1example.test"),
            (25, b"template"),
        ],
        &[
            (1, b"user2example.test"),
            (2, b"user2example.test"),
            (25, b"template"),
        ],
    ];
    for (packet, expected) in packets.iter().zip(expected) {
        let attributes: Vec<_> = packet
            .iter()
            .map(|(typ, value)| (*typ, value.as_slice()))
            .collect();
        assert_eq!(attributes, expected);
    }
}

#[test]
fn accounting_sessions_overlap_with_independent_responses() {
    check_accounting_overlap(false);
}

#[test]
fn direct_accounting_sessions_overlap() {
    check_accounting_overlap(true);
}

fn check_accounting_overlap(direct: bool) {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let addr = server.local_addr().unwrap();
    let server_thread = thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let mut pending_start = None;
        let mut sessions = HashMap::<Vec<u8>, Vec<u8>>::new();
        let mut stopped = 0;
        let mut accepted = 0;
        while stopped < 2 {
            let (len, peer) = server.recv_from(&mut buf).unwrap();
            let request = Packet::decode(&buf[..len]).unwrap();
            let mut response = Packet::new(
                if request.code == ACCESS_REQUEST {
                    ACCESS_ACCEPT
                } else {
                    packet::ACCOUNTING_RESPONSE
                },
                request.id,
            );
            response.authenticator =
                crypto::response_authenticator(&response, &request.authenticator, b"shared-secret");
            let response = response.encode();
            if request.code == ACCESS_REQUEST {
                accepted += 1;
                server.send_to(&response, peer).unwrap();
                continue;
            }

            assert_eq!(request.code, packet::ACCOUNTING_REQUEST);
            assert_eq!(accepted, if direct { 0 } else { 2 });
            let session_id = request
                .iter_raw()
                .find(|(typ, _)| *typ == accounting::ATTR_ACCT_SESSION_ID)
                .unwrap()
                .1
                .to_vec();
            let phase = accounting::read_uint_attribute(&request, accounting::ATTR_ACCT_STATUS_TYPE)
                .unwrap() as u8;
            let phases = sessions.entry(session_id).or_default();
            phases.push(phase);
            if sessions.len() == 1 {
                assert_eq!(phase, accounting::STATUS_START);
                assert!(pending_start.is_none());
                // The second Start must arrive before the first is acknowledged.
                pending_start = Some((response, peer));
                continue;
            }
            server.send_to(&response, peer).unwrap();
            if let Some((response, peer)) = pending_start.take() {
                assert_eq!(phase, accounting::STATUS_START);
                server.send_to(&response, peer).unwrap();
            }
            if phase == accounting::STATUS_STOP {
                stopped += 1;
            }
        }

        assert_eq!(sessions.len(), 2);
        for phases in sessions.values() {
            assert!(phases.len() >= 3, "{phases:?}");
            assert_eq!(phases.first(), Some(&accounting::STATUS_START));
            assert_eq!(phases.last(), Some(&accounting::STATUS_STOP));
            assert!(phases[1..phases.len() - 1]
                .iter()
                .all(|&phase| phase == accounting::STATUS_INTERIM));
        }
    });

    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("dictionary"),
        "ATTRIBUTE User-Name 1 string\nATTRIBUTE User-Password 2 string encrypt=1\n",
    )
    .unwrap();
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_radperf"));
    if direct {
        command.args(["-a", "none"]);
    }
    let output = command
        .args(["-d"])
        .arg(dir.path())
        .args([
            "-u", "2", "-p", "2", "-A", "0.1,0.4", "-r", "0", "-t", "1", "-j",
        ])
        .arg(addr.to_string())
        .args(["auth", "shared-secret"])
        .output()
        .unwrap();
    server_thread.join().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains(r#""total_no_reply":"0""#), "{stdout}");
}

#[cfg(target_os = "linux")]
#[test]
fn closed_udp_port_reports_error_and_prints_partial_summary() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = server.local_addr().unwrap();
    drop(server);

    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("dictionary"),
        "ATTRIBUTE User-Name 1 string\nATTRIBUTE User-Password 2 string encrypt=1\n",
    )
    .unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_radperf"))
        .args(["-d"])
        .arg(dir.path())
        .args(["-u", "1", "-r", "0", "-t", "0.5", "-j"])
        .arg(addr.to_string())
        .args(["auth", "shared-secret"])
        .output()
        .unwrap();

    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(!output.status.success(), "{stderr}");
    assert!(
        stderr.contains(&format!("UDP receive ({addr})")),
        "{stderr}"
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains(r#""total_sent":"1""#), "{stdout}");
    assert!(stdout.contains(r#""total_no_reply":"0""#), "{stdout}");
}
