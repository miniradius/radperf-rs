# Validation

`radperf-rs` is validated at three levels, from unit-level known-answer tests
up to interoperability with a production RADIUS server.

## 1. Known-answer tests (unit)

Deterministic vectors computed with an independent implementation (Python
`hashlib`/`hmac`) are hard-coded in `src/crypto.rs` and checked by `cargo test`:

* `MD5("abc")`
* `HMAC-MD5(key="key", msg="message")`
* PAP encryption of `"password"` with a zero Request Authenticator
* CHAP digest for a known identity/password/challenge
* Accounting-Request authenticator for a fixed packet
* Response authenticator
* Message-Authenticator (HMAC-MD5 over the packet)

## 2. End-to-end tests (`tests/end_to_end.rs`)

An in-process RADIUS server answers Access-Requests with correctly signed
Access-Accepts:

* all responses are accepted and counted when the shared secret matches;
* a response signed with the wrong secret is rejected and counted as
  `unmatched` (never as an accepted response).

`tests/retries.rs` uses a local UDP server that drops selected attempts.
The client runs with `-p 2 -n 4 -r 1 -t 0.6`. The server observes three
first attempts and two retransmissions. The third request waits for one
of the two occupied slots, while the first retry leaves the pacing
schedule for new requests untouched. The summary reports one success,
one rejection and one exhausted request. A second test verifies that the
accounting flow uses the same counter and latency definitions.

The overlapping and direct accounting tests in `tests/end_to_end.rs` also
check that `-D` records every verified response, including those generated
by `-A`.

## 3. Interoperability with FreeRADIUS

Run the current interoperability check with a local FreeRADIUS 3 installation
that uses the Debian configuration layout, Python 3, and `sudo`:

```sh
scripts/interop_freeradius.sh ./target/release/radperf /usr/share/freeradius
```

The script starts a temporary FreeRADIUS instance from a copy of the installed
configuration. It requires `Message-Authenticator` on the loopback client.
Ports 1812 and 1813 and any additional listeners in that configuration must
be free. It checks 500 successes each for PAP, CHAP,
and standalone accounting, 20 expected CHAP rejects, and eight successful
replies from two overlapping accounting sessions with `-A 1,2`. Every
scenario requires zero retransmissions and zero unanswered requests.

Earlier validation on **FreeRADIUS 3.2.8** produced these results:

| Scenario | Result |
| --- | --- |
| Access-Request + PAP -> Access-Accept | 500/500, 0 % loss |
| Access-Request + CHAP -> Access-Accept | 500/500, 0 % loss |
| Accounting-Request (Start) -> Accounting-Response | 500/500, 0 % loss |
| CHAP with a wrong password -> Access-Reject | 200/200 rejected |
| Auth + accounting flow (`-A 1,2`) | Start, Interim-Update, Stop all answered |

This exercises, against an independent implementation:

* the RADIUS header and TLV attribute framing;
* PAP User-Password encryption (the server decrypts and authenticates);
* CHAP-Password generation (the server recomputes the MD5 digest);
* the computed Request Authenticator for Accounting-Requests;
* the accounting state machine (`Acct-Status-Type` Start/Interim-Update/Stop);
* the Response Authenticator verification on the client side;
* response-code accounting (`access-accept` / `access-reject`).

`radperf` automatically adds a `Message-Authenticator` to Access-Requests
with the default `-m auto`. Use `-m no` to disable automatic insertion.
The client omits it by default for Accounting-Requests.

The 0.1.0 candidate was also tested against FreeRADIUS 3.2.7 with
`require_message_authenticator = yes` on the localhost client. PAP, CHAP
and standalone accounting each returned 500 successful replies. A CHAP
run with a wrong password returned 20 Access-Rejects. The two-session
`-A 0.2,0.5` run returned two Access-Accepts and eight Accounting-Responses.
All five runs had zero retransmissions and zero unanswered requests.

## Comparison with RadPerf 2.0.1

The x86_64 reference binary for RadPerf 2.0.1, written in C, ran in an
emulated amd64 Linux guest. A local UDP server recorded request codes and
attributes and returned signed RADIUS
responses. The tests compared observable behavior of the shipped binary
against the Rust implementation.

The verified output formats include the `-s` summary layout and its eight
response-time buckets and the `-j` JSON keys and string value types.
For `-D`, both implementations write the packet number and two time values
in `seconds.microseconds`, separated by spaces. RadPerf records absolute
send and receive timestamps. radperf-rs records the offset from the
start of the run and the round-trip delay. `Packets/s` counts successful replies
per second.
radperf-rs calculates the JSON values for `total_time` and
`packets_per_second`. radperf-rs sends the default per-response log to
stderr. RadPerf sent it to stdout.

| Case | RadPerf 2.0.1 | radperf-rs |
| --- | --- | --- |
| `-u` | Generated names start at `user1` and double as PAP passwords. The `-R` text is a literal suffix for both fields. Generated records did not inherit attributes from file records, and `-T` applied to both. With two file records and `-u 2`, the reference sent two file records and one generated record. With three file records and `-u 1`, it sent only the first two file records. | Preserves every file record and appends exactly the requested number of generated records. `-R` also qualifies unqualified file and stdin names. |
| Attribute operators | Repeated `Class` values were sent in order with `=`, `+=`, `:=`, and `==`, both within one record and with `-T`. | Preserves order and multiplicity. The Rust input format expects hexadecimal for octet attributes such as `Class`. |
| Tagged attributes | For tags 1 and 31, the tag occupied the first octet of `Tunnel-Type` and preceded the value of `Tunnel-Private-Group-Id`. Tag 0 had no prefix in the string and set the integer's high octet to zero. The reference aborted for tag 32 and encoded tag 256 as tag 0. | Matches the observed encoding for tags 0, 1 and 31 and rejects out-of-range tags. |
| `auto` | Sent code 255 for authentication, accounting and mixed input. | Uses Accounting-Request if any input record has `Acct-Status-Type`, and Access-Request otherwise. |
| `-P` | With `-n 2 -c 6`, the control invocation sent six requests and exited successfully. Adding only `-P` printed usage, returned exit status 1 and sent no packets. | Prints per-second progress on stderr. |

The overlapping accounting scheduler is covered by local integration tests.
Its timing has not been compared against RadPerf.

The reference distribution is supplied separately. To reproduce the quick
CLI and debug captures, run `scripts/capture_reference.sh` with
`RADPERF_ORIG` pointing to the extracted directory containing `bin/`,
`lib/`, and `share/`. The script writes to the ignored `reference/` directory
and needs a Docker or Podman runtime that can execute Linux amd64 binaries.

## Client process scaling

The [scaling measurements and follow-up plan](scaling.md) cover the Linux
arm64 sandbox benchmark with one, two, and four client processes.

## Local maintenance checks

Run `cargo deny --locked check` with `deny.toml` to check dependencies.
The packet decoder has a separate fuzz target. Install the nightly toolchain
and `cargo-fuzz`, then run:

```sh
cargo +nightly fuzz run packet_decode -- -max_len=8192 -max_total_time=30
```
