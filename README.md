# radperf-rs

```text
                _                  __
  _ __ __ _  __| |_ __   ___ _ __ / _|      _ __ ___
 | '__/ _` |/ _` | '_ \ / _ \ '__| |_ _____| '__/ __|
 | | | (_| | (_| | |_) |  __/ |  |  _|_____| |  \__ \
 |_|  \__,_|\__,_| .__/ \___|_|  |_|       |_|  |___/
                 |_|
```

An independent Rust implementation of the `radperf` RADIUS
performance-testing client. It sends RADIUS requests, waits for replies, and
reports throughput and latency.

The original C `radperf` is distributed without a license specification, so its
terms are unclear. This project is therefore an independent reimplementation;
see [NOTICE.md](NOTICE.md) for the provenance statement. It is released under
the MIT license.

The Cargo package is `radperf-rs` and the installed binary is named **`radperf`**.
Verified behavior and differences from the original are listed under
[Compatibility](#compatibility). See the [changelog](CHANGELOG.md) for release
notes and the [manual page](radperf.1) for a CLI reference.

## Compatibility

| Area | Verified behavior and differences |
| --- | --- |
| RADIUS wire protocol | PAP, CHAP and accounting were tested against FreeRADIUS 3.2.8. The overlapping accounting sessions are covered by local integration tests. |
| Output formats | The `-s` layout and the `-j` keys and value types follow the original. The `-D` columns have different time semantics. The Rust version calculates `total_time` and `packets_per_second` in JSON. |
| Response log | The Rust version prints the per-response log to stderr. The original printed it to stdout. |
| Input attributes | `=`, `+=`, `:=` and `==` append values in input order, including those supplied by `-T`. Tagged attributes accept tags 0–31. |
| User generation | `-u N` appends exactly N generated users after any file records. In testing, the original sometimes reduced the generated count or sent only part of the file. |
| Commands and options | `auto` selects Access-Request or Accounting-Request for the run. The original sent code 255 in the tested cases. `-P` reports progress in the Rust version. The original printed usage in the tested invocation. `-r 0` disables retransmissions in the Rust version. |
| UDP errors | The Rust version reports a socket error, exits with a nonzero status, and prints the partial summary when enabled. |

Reference version and test details are in [Validation](docs/validation.md).

## Sandbox benchmark

In an emulated Linux amd64 loopback benchmark, the `radperf-rs` 0.1.0
candidate processed **1.74× to 7.63× as many successful replies per second**
as the original `radperf` 2.0.1.

| Parallel requests (`-p`) | Original replies/s | Rust replies/s | Rust / original | Original p95 (µs) | Rust p95 (µs) |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 5,611 | 9,748 | 1.74× | 181 | 149 |
| 16 | 9,233 | 67,293 | 7.29× | 1,901 | 212 |
| 64 | 9,249 | 70,607 | 7.63× | 7,552 | 704 |

Both clients used the same QEMU amd64 guest on an arm64 host and the same
local UDP responder returning signed Access-Accepts. Each result is the
median of five runs of 20,000 PAP requests, with the client order alternated.
Both clients ran in quiet mode with per-response recording enabled (`-D`)
and no rate cap. The Rust client used `-m no` to match the original's
45-byte requests. All 600,000 measured requests received a reply without
retransmission.

Throughput uses the interval from the first send to the last reply.
The figures describe this emulated loopback workload with per-response
recording enabled.

Separate [client scaling measurements](docs/scaling.md) cover one, two, and
four processes in the arm64 sandbox.

## Requirements

* Rust 1.85 or later (edition 2021). CI tests the minimum version and current
  stable Rust.
* A RADIUS dictionary directory (FreeRADIUS format). For native builds, see
  [dictionary lookup](#dictionary-lookup). The Docker image includes the
  dictionary.

## Build

Native release build:

```sh
cargo build --release
```

The release profile uses fat LTO, a single codegen unit, `panic = "abort"` and
symbol stripping for throughput. The binary is `target/release/radperf`.

### GitHub Releases

Publishing a GitHub Release for a version tag such as `v0.1.0` starts the
[release workflow](.github/workflows/release.yml). It tests and builds the
tagged commit on native runners. Once all three builds pass, it attaches
`radperf-linux-amd64`, `radperf-linux-arm64`, `radperf-darwin-arm64`, and
`SHA256SUMS` to the release.

### Docker

The Debian Trixie slim image includes the FreeRADIUS dictionary and runs
`radperf` as an unprivileged user. Build and run the image for your platform:

```sh
docker build -t radperf-rs .
docker run --rm radperf-rs --version
docker run --rm radperf-rs -u 3 radius.example.test:1812 auth testing123
```

To export both Linux architectures to a local OCI archive, use Buildx:

```sh
docker buildx build --platform linux/amd64,linux/arm64 \
  --output type=oci,dest=radperf-rs.oci .
```

To use a different dictionary, mount its directory and pass `-d` with the
container path. Mount a writable directory and use a path inside it with
`-D` to keep per-packet output on the host.

### Cross-compiled binaries

The `Makefile` wraps the cross builds. Running `make` with no target prints
the help; a target is chosen explicitly. Binaries are written to `dist/` with
a target suffix.

The Makefile detects the host OS. On macOS the darwin target is built natively
(`cargo build`, no zig), while the Linux targets are cross-linked with zig. On
Linux the darwin target is cross-linked with zig and the Linux x86_64 target
uses the gcc cross linker.

| Target | Description |
| --- | --- |
| `make all` | build all three binaries |
| `make linux-arm64` | native Linux aarch64 (`aarch64-unknown-linux-gnu`) |
| `make linux-amd64` | cross-compiled Linux x86_64 (`x86_64-unknown-linux-gnu`) |
| `make darwin-arm64` | cross-compiled macOS Apple Silicon (`aarch64-apple-darwin`) |
| `make deps` | install the Rust targets and cross tools |
| `make deps-rust` | `rustup target add` for the three targets |
| `make deps-linux-amd64` | install the Linux x86_64 cross linker |
| `make deps-darwin` | install `zig` and `cargo-zigbuild` |
| `make test` | run the test suite |
| `make clean` | remove `target/` and `dist/` |
| `make help` | list the targets |

Outputs:

| File | Target |
| --- | --- |
| `dist/radperf-linux-arm64` | `aarch64-unknown-linux-gnu` |
| `dist/radperf-linux-amd64` | `x86_64-unknown-linux-gnu` |
| `dist/radperf-darwin-arm64` | `aarch64-apple-darwin` |

Override the output directory with `make DIST=. all` to write to the project
root.

#### Prerequisites per target

| Target | Needs |
| --- | --- |
| `linux-arm64` | only the Rust toolchain (system linker and libc) |
| `linux-amd64` | `rustup target add x86_64-unknown-linux-gnu` and the `gcc-x86-64-linux-gnu` cross linker |
| `darwin-arm64` | `rustup target add aarch64-apple-darwin`, `zig`, and `cargo-zigbuild` |

`make deps` installs all of the above (it uses `apt-get` and `cargo install`,
so it may prompt for `sudo`).

#### macOS (darwin) notes

On macOS, `make darwin-arm64` builds natively with the Apple toolchain
(`cargo build --target aarch64-apple-darwin`); no zig or SDK warning is
involved.

Cross-linking a Mach-O binary **on Linux** needs a Mach-O linker and the macOS
system libraries. Apple's SDK is not redistributable, so on a Linux host the
Makefile uses `zig` (through `cargo-zigbuild`), which ships a Mach-O linker and
the required `libSystem` stubs. `zig` is only a local build tool: it is not a
dependency of the crate, and the native Linux build never uses it.

Because no macOS SDK is present on Linux, the darwin build there prints this
warning:

```
warning: invoking `"xcrun" "--sdk" "macosx" "--show-sdk-path"` to find
MacOSX.sdk failed: No such file or directory (os error 2)
```

This is harmless. It is `rustc` looking for an Xcode SDK path that is not
needed when zig supplies the system libraries. The build completes and produces
a valid Mach-O executable (verified as a Mach-O 64-bit arm64 image linked
against `/usr/lib/libSystem.B.dylib`). The warning disappears if a real macOS
SDK is available (`SDKROOT` or `DEVELOPER_DIR`). It does not appear when the
darwin target is built natively on macOS.

To produce the darwin binary natively on a Mac instead, install the Xcode
command line tools and run:

```sh
rustup target add aarch64-apple-darwin
cargo build --release --target aarch64-apple-darwin
```

## Usage

```sh
radperf [options] server[:port] <command> [<secret>]
```

* `server[:port]` is the RADIUS server. Without a port, `1813` is used for
  Accounting-Requests and `1812` for other request codes. IPv6 literals may be written
  as `[::1]:1812`.
* `secret` is the shared secret. Use a positional argument or `-S`. The file
  takes precedence when both are supplied.
* If neither `-f` nor `-u` is given, input packets are read from standard input.

### Commands

| Command | Packet sent |
| --- | --- |
| `auth` | Access-Request |
| `acct` | Accounting-Request |
| `status` | Status-Server |
| `coa` | CoA-Request |
| `disconnect` | Disconnect-Request |
| `auto` | Access-Request, or Accounting-Request when the input has `Acct-Status-Type` |
| `1..255` | that decimal RADIUS code |

### Options

Defaults are shown in parentheses.

| Option | Meaning |
| --- | --- |
| `-a type` | authentication method: `pap` (default), `chap`, `none` |
| `-A d,l` | after Access-Accept, send accounting every `d` s for `l` s |
| `-c count` | send each input packet `count` times (default 1) |
| `-C attr[,..]` | copy these attributes from the Access-Accept to the Accounting-Request |
| `-d dir` | dictionary directory |
| `-D file` | write per-packet lines (`num time delay`) |
| `-f file` | read packets from a file (repeatable; a `.csv` name selects the CSV form) |
| `-F` | also update `Framed-IP-Address` in the accounting flow |
| `-h`, `--help` | usage |
| `-j`, `--json` | print a JSON summary |
| `-m mode` | Message-Authenticator: `auto` (default), `yes` or `no` |
| `-n num` | pace new requests at this many per second (default 0 = unlimited) |
| `-p num` | maximum outstanding requests, including requests awaiting a retry (default 1) |
| `-P` | print per-second progress statistics to stderr |
| `-q` | suppress the default per-response log and final summary |
| `-r retries` | retransmit a request up to this many times (default 5) |
| `-R realm` | append `@realm` to unqualified input names and use the supplied text as a literal suffix for generated names and passwords |
| `-s` | print a summary of results |
| `-S file` | read the shared secret from a file |
| `-t timeout` | retransmit timeout in seconds (default 5, fractional allowed) |
| `-T file` | template file whose attributes are added to every request |
| `-u number` | append requests for `user1` through `userN`, using each name as its password |
| `-v`, `--version` | version |
| `-x` | increase debug output (repeatable) |
| `-4` / `-6` | prefer the IPv4 / IPv6 server address |

`-a none` requires `-A` and skips the authentication phase.

### Retransmissions and measurements

Retransmissions reuse the original request and its slot under `-p`. They are
sent when the response timeout expires, independently of `-n`. The datagram
rate seen by the server can therefore exceed the configured rate for new
requests.

In the summary, `Total sent` counts first attempts, `Total retransmits`
counts additional datagrams sent, and `Total no reply` counts requests that
exhausted all attempts. The latency buckets and `-D` response delays measure
from the first send to the verified reply, including time spent waiting for
retries. `Packets/s` divides successful replies by the elapsed run time.

### Input formats

An attribute file uses the FreeRADIUS form: one `Name = value` per line,
`#` comments, and a blank line between packets. Values may be quoted with `"`
and support `\"`, `\\`, `\n`, `\r`, `\t` and a doubled `""`. An attribute may
carry a tag from 0 to 31 as `Name:tag = value` for attributes flagged
`has_tag` (for example `Tunnel-Type:1 = VLAN`). A tag of 0 has no leading
tag octet in a string and sets the high octet to zero in a tagged integer.
An authentication request can carry one encrypted password, including any
password supplied by a template file.

```
# one packet
User-Name = "bob"
User-Password = "hello"

# another packet
User-Name = "alice"
NAS-IP-Address = 10.0.0.1
```

A file whose name ends in `.csv` is read as two columns, `name,password`; each
row becomes a `User-Name` / `User-Password` pair. Fields may be quoted and use a
doubled `""` for a literal quote.

```
bob,hello
"carol","pa,ss"
```

### Dictionary lookup

The dictionary directory is chosen from `-d`, then the
`FREERADIUS_DICTIONARY_PATH` environment variable, then `../share` next to the
executable. The loader follows `$INCLUDE` directives and understands
`ATTRIBUTE`, `VALUE`, `VENDOR`, `BEGIN-VENDOR`/`END-VENDOR`,
`BEGIN-TLV`/`END-TLV`, RFC 6929 extended attributes and `octets[N]`.

## Output

The summary and JSON layouts match the original tool, so scripts that parse
them keep working.

* **Summary** (`-s`): the reference format, with one leading tab per line:

  ```
  \t     Total sent        :  1000
  \t     Total retransmits :  0
  \t     Total succeeded   :  1000
  \t     Total failed      :  0
  \t     Total no reply    :  0
  \t     Total time (s)    :  0.003
  \t     Packets/s         :  264082
  \t     Response times:
  \t\t< 10 usec  : 0
  \t\t< 100 usec : 991
  \t\t< msec     : 9
  \t\t< 10 msec  : 0
  \t\t< 0.1s     : 0
  \t\t< s        : 0
  \t\t< 10s      : 0
  \t\t< 100s     : 0
  ```

  `Total succeeded` counts Accept/Response/ACK replies, `Total failed` counts
  Reject/NAK replies, and `Total no reply` counts timeouts. `Packets/s` is
  successful replies per second (one decimal below 10, none above). The
  response-time histogram has eight buckets.

* **JSON** (`-j`): a single object mirroring the summary, with the fields
  `total_sent`, `total_retransmits`, `total_succeeded`, `total_failed`,
  `total_no_reply`, `total_time`, `packets_per_second` and `response_times`.
  Scalar values are JSON strings. The histogram is an array of strings.

  ```json
  { "total_sent":"1000",
   "total_retransmits":"0",
   "total_succeeded":"1000",
   "total_failed":"0",
   "total_no_reply":"0",
   "total_time":"0.003",
   "packets_per_second":"267219",
   "response_times":["0","991","9","0","0","0","0","0"]}
  ```

* **Per-packet output** (`-D file`): one line per response,
  `num time delay`, where `num` is the packet number, `time` is the send time
  as seconds since the start, and `delay` is the round trip; both times are
  `seconds.microseconds` (space separated). The original Linux radperf 2.0.1
  uses absolute send and receive timestamps for the last two columns.

  ```
  1 0.000003 0.000062
  2 0.000070 0.000037
  ```

* **Per-second progress** (`-P`): a line per second on stderr with the interval
  send/receive counts, loss and rate.

## Accounting flow

With `-A delay,lifetime`, each accepted Access-Request starts an accounting
session: an `Acct-Status-Type=Start` packet, `Interim-Update` packets every
`delay` seconds, and a final `Stop` after `lifetime` seconds (bounded by any
`Session-Timeout` in the Access-Accept). NAS/identity attributes are copied
from the Access-Request; `Class` and any `-C` attributes are copied from the
Access-Accept; a `NAS-Port` is generated when the request did not carry one.
`-F` also copies `Framed-IP-Address` from the Access-Accept. The interval must
be positive.

The accounting phase begins after the authentication phase. Sessions overlap,
with each lifetime measured from its own Start. The `-p` and `-n` limits apply
to accounting requests as well.

With `-a none` the authentication phase is skipped and an accounting session is
started for every input packet instead (the accounting server port is used).

## Message-Authenticator

`-m auto` (the default) adds a Message-Authenticator (HMAC-MD5, RFC 3579) to
requests that need one under the BlastRADIUS mitigation (CVE-2024-3596):
Access-Request, Status-Server, CoA and Disconnect. Accounting-Requests do not
carry one, matching `radclient`. Use `-m no` to disable the automatic addition
(an explicit `Message-Authenticator` in the input is always honored), or
`-m yes` as an alias for `auto`.

## Exit codes

* `0` - success (including `-h` and `-v`).
* `1` - a configuration, input, dictionary or runtime error.

## Examples

```sh
# PAP authentication load test
radperf -d /usr/share/freeradius -f users.txt -c 100000 -p 64 -s 10.0.0.1 auth secret

# CHAP with a paced rate and a JSON summary
radperf -a chap -f users.txt -n 5000 -p 32 -j 10.0.0.1 auth secret

# Access-Request followed by the accounting flow
radperf -f users.txt -c 1 -A 30,600 -s 10.0.0.1 auth secret

# Read the secret from a file and emit per-packet delays
radperf -S /etc/radius.secret -D delays.csv -f users.txt 10.0.0.1 auth
```

## Design

* Single-threaded `mio` (epoll/kqueue) event loop; no async runtime, so the hot
  path has no scheduler or future overhead.
* O(1) response matching: a per-socket 256-entry array indexed by the RADIUS
  identifier, with no hash map on the hot path.
* No allocation in the steady state: templates are pre-encoded once and each
  slot reuses its packet buffer.
* Timeouts in a binary min-heap; latency recorded into a fixed-size,
  allocation-free histogram.
* Rate limiting uses a fixed time grid so bursts compensate for the
  millisecond granularity of the poll timeout.
* `SIGINT` (Ctrl+C) stops the run and still prints the summary.

## Testing

```sh
cargo test
```

The suite covers the dictionary loader, the packet codec, the crypto
known-answer vectors (MD5, HMAC-MD5, PAP, CHAP, authenticators), the value and
input parsers, the histogram, the template builder and an in-process
end-to-end run.

Interoperability against a real FreeRADIUS server (PAP, CHAP, accounting and
the accounting flow) is described in [docs/validation.md](docs/validation.md)
and can be re-run with:

```sh
scripts/interop_freeradius.sh ./target/release/radperf /usr/share/freeradius
```

The script needs FreeRADIUS and root (to configure a test client).

## Project layout

```
src/
  main.rs        CLI entry and orchestration
  cli.rs         argument parsing
  dict.rs        FreeRADIUS dictionary parser
  packet.rs      RADIUS framing
  crypto.rs      MD5/HMAC-MD5 authenticators, PAP, CHAP
  value.rs       typed attribute encode/decode
  input.rs       attribute-file and CSV parsing
  request.rs     pre-encoded request templates
  client.rs      the mio event loop
  accounting.rs  the accounting flow
  stats.rs       counters and latency histogram
  rng.rs         authenticator randomness
  signals.rs     SIGINT handling
  output.rs      summary, JSON and usage text
tests/
  real_dictionary.rs   loads the shipped dictionary
  end_to_end.rs        runs against an in-process server
docs/validation.md
docs/scaling.md
scripts/interop_freeradius.sh
scripts/capture_reference.sh
radperf.1            man page
LICENSE              MIT license
Makefile             cross-build targets
.github/workflows/ci.yml
.github/workflows/release.yml
Dockerfile
CHANGELOG.md, NOTICE.md, README.md, TODO.md
```

## License

This project's code is released under the [MIT license](LICENSE). The Docker
image includes separately licensed FreeRADIUS dictionary data and its copyright
notice. See [NOTICE.md](NOTICE.md).
