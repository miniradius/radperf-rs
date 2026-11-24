# radperf-rs

[![Release binaries](https://github.com/miniradius/radperf-rs/actions/workflows/release.yml/badge.svg)](https://github.com/miniradius/radperf-rs/actions/workflows/release.yml)

An independent Rust implementation of the `radperf` RADIUS load-testing
client. It generates PAP, CHAP, and accounting traffic and reports throughput,
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
docker build -t radperf-rs .
docker run --rm radperf-rs -u 3 radius.example.test:1812 auth testing123
```

Replace the example endpoint with a RADIUS server reachable from the container.
For an external dictionary or input file, mount the directory and use its
container path. For `-D` output, mount a directory writable by the container
user.

To export a local archive for both architectures:

```sh
docker buildx build --platform linux/amd64,linux/arm64 \
  --output type=oci,dest=radperf-rs.oci .
```

### From source

Requires Rust 1.85 or newer. Run `cargo build --locked --release` to build
`target/release/radperf`. Run `make help` for cross-build targets and dependencies.

## Quick start

```sh
# Generate three test users.
radperf -d /usr/share/freeradius -u 3 -s 127.0.0.1:1812 auth testing123

# Send requests from a file with up to 16 outstanding.
radperf -d /usr/share/freeradius -f users.txt -p 16 -j 127.0.0.1:1812 auth testing123
```

`-u 3` generates `user1` through `user3`, using each name as its password.
Configure the server to accept those credentials if you want successful test
logins. When combined with `-f`, generated users are appended to the file
records. An attribute file uses one `Name = value` per line, with blank lines
between requests. A `.csv` file uses `name,password` rows. Without `-f` or `-u`,
the client reads requests from stdin.

```text
User-Name = "alice"
User-Password = "test-password"
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
layout and JSON keys follow the original `radperf` 2.0.1. Differences that
matter to scripts include:

- The `-D` time columns are relative send time and round-trip delay. The
  original writes absolute send and receive timestamps.
- Per-response logs go to stderr. The original logs them to stdout.
- `auto` selects a standard request code for the run. The original sent 255
  in the tested cases. `-P` reports progress and `-r 0` disables retries.
- `-u N` preserves all supplied records and appends exactly `N` users.
- On a UDP socket error, the client exits nonzero and prints the partial
  summary when enabled.

See [validation](docs/validation.md) for the tested cases and
[the changelog](CHANGELOG.md) for release notes.

## Sandbox benchmark

Both clients ran in the same QEMU Linux amd64 guest against the same local
UDP responder. Each row is the median of five runs of 20,000 PAP requests per
client, in quiet mode with `-D` enabled and no rate cap. The Rust client used
`-m no` to match the original packet size. All 600,000 requests received
replies without retransmission. Throughput is measured from first send to
last reply.

| `-p` | Original replies/s | Rust replies/s | Rust / original | Original p95 (µs) | Rust p95 (µs) |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 5,611 | 9,748 | 1.74× | 181 | 149 |
| 16 | 9,233 | 67,293 | 7.29× | 1,901 | 212 |
| 64 | 9,249 | 70,607 | 7.63× | 7,552 | 704 |

The figures apply to this emulated loopback workload. Separate
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
