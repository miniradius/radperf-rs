use radperf_rs::accounting::AcctConfig;
use radperf_rs::client::{Client, ClientConfig};
use radperf_rs::crypto;
use radperf_rs::dict::Dictionary;
use radperf_rs::packet::{self, Packet};
use radperf_rs::request::Template;
use std::net::{SocketAddr, UdpSocket};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

const SECRET: &str = "shared-secret";
const DICTIONARY: &str =
    "ATTRIBUTE User-Name 1 string\nATTRIBUTE User-Password 2 string encrypt=1\n";

fn receiver() -> UdpSocket {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    socket
}

fn receive(socket: &UdpSocket) -> (Vec<u8>, SocketAddr, Instant) {
    let mut buf = [0u8; 4096];
    let (len, peer) = socket.recv_from(&mut buf).unwrap();
    (buf[..len].to_vec(), peer, Instant::now())
}

fn respond(socket: &UdpSocket, bytes: &[u8], peer: SocketAddr, code: u8) {
    let request = Packet::decode(bytes).unwrap();
    let mut response = Packet::new(code, request.id);
    response.authenticator =
        crypto::response_authenticator(&response, &request.authenticator, SECRET.as_bytes());
    socket.send_to(&response.encode(), peer).unwrap();
}

fn username(bytes: &[u8]) -> Vec<u8> {
    let request = Packet::decode(bytes).unwrap();
    request
        .iter_raw()
        .find(|(typ, _)| *typ == 1)
        .unwrap()
        .1
        .to_vec()
}

fn summary_field<'a>(summary: &'a str, field: &str) -> &'a str {
    summary
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(key, _)| key.trim_matches(['{', ' ', '"']) == field)
        .unwrap()
        .1
        .trim_matches(['"', ',', ' '])
}

#[test]
fn rate_and_parallelism_under_loss() {
    let server = receiver();
    let addr = server.local_addr().unwrap();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("dictionary"), DICTIONARY).unwrap();
    let delays = dir.path().join("delays");

    let capture = thread::spawn(move || {
        let (first, peer, first_at) = receive(&server);
        assert_eq!(username(&first), b"user1");
        let (second, _, second_at) = receive(&server);
        assert_eq!(username(&second), b"user2");
        assert!(second_at.duration_since(first_at) >= Duration::from_millis(200));

        // With both slots occupied, user3 has to wait even after its
        // nominal send time. A retransmission reuses the first slot.
        let (retry, _, retry_at) = receive(&server);
        assert_eq!(retry, first);
        assert!(retry_at.duration_since(first_at) >= Duration::from_millis(560));
        respond(&server, &retry, peer, packet::ACCESS_ACCEPT);

        let (third, peer, third_at) = receive(&server);
        assert_eq!(username(&third), b"user3");
        // The retry did not consume a place in the 250 ms pacing grid.
        assert!(third_at.duration_since(retry_at) < Duration::from_millis(240));
        respond(&server, &third, peer, packet::ACCESS_REJECT);

        let (retry, _, _) = receive(&server);
        assert_eq!(retry, second);
        // Keep the socket open while user2 exhausts its response timeout.
        server
    });

    let output = Command::new(env!("CARGO_BIN_EXE_radperf"))
        .arg("-d")
        .arg(dir.path())
        .arg("-D")
        .arg(&delays)
        .args([
            "-u", "3", "-p", "2", "-n", "4", "-r", "1", "-t", "0.6", "-j",
        ])
        .arg(addr.to_string())
        .args(["auth", SECRET])
        .output()
        .unwrap();
    let _server = capture.join().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let summary = String::from_utf8(output.stdout).unwrap();
    for (field, expected) in [
        ("total_sent", "3"),
        ("total_retransmits", "2"),
        ("total_succeeded", "1"),
        ("total_failed", "1"),
        ("total_no_reply", "1"),
    ] {
        assert_eq!(summary_field(&summary, field), expected);
    }
    let elapsed: f64 = summary_field(&summary, "total_time").parse().unwrap();
    let packets_per_second: f64 = summary_field(&summary, "packets_per_second")
        .parse()
        .unwrap();
    assert!((packets_per_second - 1.0 / elapsed).abs() <= 0.051);

    let rows = std::fs::read_to_string(delays).unwrap();
    let records: Vec<_> = rows
        .lines()
        .map(|line| {
            let fields: Vec<_> = line.split(' ').collect();
            assert_eq!(fields.len(), 3, "{line}");
            let parse_time = |value: &str| {
                let (seconds, micros) = value.split_once('.').unwrap();
                assert_eq!(micros.len(), 6, "{value}");
                seconds.parse::<u64>().unwrap() * 1_000_000 + micros.parse::<u64>().unwrap()
            };
            (fields[0], parse_time(fields[1]), parse_time(fields[2]))
        })
        .collect();
    let [("1", first_sent, time_to_accept), ("3", third_sent, _)] = records.as_slice() else {
        panic!("unexpected delay rows: {rows}");
    };
    assert!(*first_sent < 60_000_000, "{rows}");
    assert!(third_sent - first_sent >= 600_000, "{rows}");
    assert!(*time_to_accept >= 600_000, "{rows}");
}

#[test]
fn accounting_retries_use_the_same_counter_and_latency_definitions() {
    let server = receiver();
    let addr = server.local_addr().unwrap();
    let capture = thread::spawn(move || {
        let (start, _, _) = receive(&server);
        let (retry, peer, _) = receive(&server);
        assert_eq!(retry, start);
        respond(&server, &retry, peer, packet::ACCOUNTING_RESPONSE);
        let (stop, peer, _) = receive(&server);
        assert_ne!(start, stop);
        respond(&server, &stop, peer, packet::ACCOUNTING_RESPONSE);
        (start.len() + retry.len() + stop.len()) as u64
    });

    let dir = tempfile::tempdir().unwrap();
    let dict = dir.path().join("dictionary");
    std::fs::write(&dict, DICTIONARY).unwrap();
    let dict = Dictionary::load_file(&dict).unwrap();
    let template = Template::from_pairs(&dict, packet::ACCESS_REQUEST, &[]).unwrap();
    let timeout = Duration::from_millis(200);
    let config = ClientConfig {
        server: addr,
        secret: SECRET.as_bytes().to_vec(),
        parallel: 2,
        rate: 0,
        retries: 1,
        timeout,
        quiet: true,
        debug: 0,
        collect_stats: true,
        json_summary: false,
        print_summary: false,
        delays: None,
        persec: false,
        accounting: Some(AcctConfig {
            delay: Duration::from_millis(50),
            lifetime: Duration::ZERO,
            framed_ip: false,
        }),
        accounting_direct: true,
        acct_server: Some(addr),
        acct_copy_types: Vec::new(),
        acct_bases: Vec::new(),
    };
    let stats = Client::new(config, vec![template], Vec::new())
        .unwrap()
        .run()
        .unwrap();
    assert_eq!(stats.bytes_sent, capture.join().unwrap());
    assert_eq!(stats.requests_sent, 2);
    assert_eq!(stats.retransmits, 1);
    assert_eq!(stats.responses_received, 2);
    assert_eq!(stats.timeouts, 0);
    assert_eq!(stats.rtt.count(), 2);
    assert!(stats.rtt.max() >= timeout.as_micros() as u64);
}
