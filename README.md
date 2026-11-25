# radperf-rs

[![Release binaries](https://github.com/miniradius/radperf-rs/actions/workflows/release.yml/badge.svg)](https://github.com/miniradius/radperf-rs/actions/workflows/release.yml)

An independent Rust implementation of [RadPerf](https://www.networkradius.com/radius-performance-testing/),
the RADIUS load-testing client developed in C by Network RADIUS SARL.
radperf-rs generates PAP, CHAP, and accounting traffic and reports throughput,
latency, and loss. The executable is named `radperf`.

## Install

### GitHub Releases

Download the binary for Linux amd64, Linux arm64, or macOS arm64. Make it
executable and place it on your `PATH` as `radperf`. Releases include
`SHA256SUMS`. Standalone binaries
require an external FreeRADIUS dictionary. [Releases](https://github.com/miniradius/radperf-rs/releases) · [Dictionary lookup](#dictionary-lookup)

### Docker

The Debian Trixie slim image includes the dictionary and runs as an
unprivileged user.

```sh
docker build -t radperf .
docker run --rm radperf -u 1000000 radius.example.test:1812 auth testing123
```

Mount input files or custom dictionaries and pass their paths inside the
container. For `-D` output, mount a directory writable by the container user.

### All-in-one RADIUS tools image

[docker-radius-tools](https://github.com/miniradius/docker-radius-tools)
bundles RADIUS utilities, including `eapol_test`, `radclient`, `radcrypt`,
`radeapclient`, `radlast`, `radperf`, `radsecret`, `radsniff`, `radsqlrelay`,
`radtest`, `radwho`, `radzap`.

```sh
docker run --rm ghcr.io/miniradius/docker-radius-tools:latest radperf -v
```

### From source

Requires Rust 1.85 or newer. Run `cargo build --locked --release` to build
`target/release/radperf`. Run `make help` for cross-build targets and dependencies.

## Quick start

```sh
# Generate 1,000,000 test users.
radperf -d /usr/share/freeradius -u 1000000 -s 127.0.0.1:1812 auth testing123

# Read users from an attribute file or a CSV file.
radperf -d /usr/share/freeradius -f users.txt -p 16 -j 127.0.0.1:1812 auth testing123
radperf -d /usr/share/freeradius -f users.csv -p 16 -j 127.0.0.1:1812 auth testing123
```

`-u 1000000` generates `user1` through `user1000000`, using each name as its password.
Configure the server to accept those credentials if you want successful test
logins. When combined with `-f`, generated users are appended to the file
records. Without `-f` or `-u`, the client reads requests from stdin.

### Input files

Both radperf-rs and RadPerf 2.0.1 select the input format from the filename.
Use a lowercase `.csv` suffix for CSV files that work with both clients.
radperf-rs also accepts uppercase suffixes such as `.CSV`. Both clients read
`.txt` files as attribute files.

**`users.txt`** uses one `Name = value` per line. A blank line separates
requests.

```text
User-Name = "alice"
User-Password = "alice-test-password"

User-Name = "bob"
User-Password = "bob-test-password"
```

**`users.csv`** contains one user per line and two comma-separated fields,
`name,password`. Omit the header. If your spreadsheet exports semicolons,
select a comma as the delimiter.

```csv
alice,alice-test-password
bob,bob-test-password
```

The general form is `radperf [options] server[:port] <command> [secret]`.
If no port is given, Accounting-Requests use 1813 and other requests use
1812. `-S` reads the shared secret from a file and takes precedence over the
positional argument.

### Options

| Option | Effect |
| --- | --- |
| `-p N` | Maximum outstanding requests. Retransmissions retain their slots. |
| `-n N` | Pace new requests per second. Retransmissions follow their own timeouts. |
| `-r N` | Maximum retransmissions per request. Use `0` to disable them. |
| `-s` / `-j` | Text or JSON summary. `Packets/s` counts successful replies per second of the run. |
| `-D file` | Record the request number, relative time of first send, and elapsed time until the verified reply. |
| `-A d,l` | Start accounting sessions with interim updates every `d` seconds for up to `l` seconds. |

Run `radperf --help` or read the [manual page](radperf.1) for the full CLI.

### Dictionary lookup

The client searches in this order:

1. The directory supplied with `-d`.
2. The directory in `FREERADIUS_DICTIONARY_PATH`.
3. `../share` relative to the executable directory.

The directory must contain `dictionary` and any files it includes. This
also applies to generated users. The Docker image sets
`FREERADIUS_DICTIONARY_PATH=/usr/share/freeradius`.

## Compatibility

PAP, CHAP, and accounting were tested against FreeRADIUS. The text summary
layout and JSON keys follow RadPerf 2.0.1 (C). Differences that matter to scripts
include:

- The `-D` time columns are relative send time and round-trip delay. RadPerf (C)
  writes absolute send and receive timestamps.
- Per-response logs go to stderr. RadPerf (C) logs them to stdout.
- `auto` selects a standard request code for the run. RadPerf (C) sent 255
  in the tested cases. `-P` reports progress and `-r 0` disables retries.
- `-u N` preserves all supplied records and appends exactly `N` users.
- On a UDP socket error, the client exits nonzero and prints the partial
  summary when enabled.

See [validation](docs/validation.md) for the tested cases and
[the changelog](CHANGELOG.md) for release notes.

## Rust vs. C benchmark

RadPerf 2.0.1 (C) and radperf-rs 0.1.1 (Rust) ran in a QEMU Linux amd64
guest against the same local UDP responder. Each cell reports one completed
run of 1,000,000 PAP requests sent with the same credentials. Both clients
ran in quiet mode with `-D` enabled and no rate cap. radperf-rs used
`-m no` to match the 45-byte packets of RadPerf (C). Throughput is measured
from first send to last reply. All completed runs received 1,000,000 replies
without retransmissions.

| `-p` | C replies/s | Rust replies/s | Rust / C | C p95 (µs) | Rust p95 (µs) |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 5,688 | 9,837 | 1.73× | 168 | 134 |
| 16 | 9,187 | 66,008 | 7.19× | 1,895 | 227 |
| 64 | 8,961 | 68,128 | 7.60× | 7,702 | 647 |

This benchmark compares the C and Rust implementations under the same
test conditions. Measuring peak throughput requires a
separate bare-metal benchmark, where both implementations may achieve
substantially higher throughput.

Separate
[scaling measurements](docs/scaling.md) cover multiple client processes
in the arm64 sandbox.

## Development

Run `cargo test --locked`. FreeRADIUS interoperability, dependency checks,
and fuzzing instructions are in [validation](docs/validation.md).

Publishing a GitHub Release runs the [release workflow](.github/workflows/release.yml),
which attaches the three standalone binaries and `SHA256SUMS`.

## License

The project code uses the [MIT license](LICENSE). The Docker image includes
separately licensed FreeRADIUS dictionary data and its copyright notice.
See [NOTICE.md](NOTICE.md).
