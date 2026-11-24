# Changelog

## 0.1.0

First release of `radperf-rs`, an independent Rust RADIUS load-testing client.

- Test PAP, CHAP, and accounting, including overlapping accounting sessions.
- Load attribute files or CSV, apply request templates, or generate test users
  with `-u`.
- Report throughput, latency, and retransmissions in text or JSON. The `-D`
  output records relative send time and round-trip delay. The original
  `radperf` 2.0.1 records absolute send and receive timestamps.
- Standalone binaries for Linux amd64, Linux arm64, and macOS arm64 require
  an external FreeRADIUS dictionary. The Debian Trixie slim Docker image for
  Linux amd64 and arm64 includes the dictionary.

See [Compatibility](README.md#compatibility) and
[Dictionary lookup](README.md#dictionary-lookup).
