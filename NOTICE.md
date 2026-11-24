# radperf-rs - provenance and clean-room statement

`radperf-rs` is an independent, clean-room reimplementation of a RADIUS
performance-testing client ("radperf"). It is **not** a fork and contains **no
source code, no strings, and no documentation text copied from the original
program or its distribution**.

## Sources used

The implementation is derived only from:

1. **Public protocol standards** - IETF RFCs describing RADIUS and its
   extensions (e.g. RFC 2865, 2866, 2867, 2868, 2869, 3576, 5997, 6929).
2. **Observed black-box behaviour** - the original binary is executed in a
   controlled sandbox to record inputs, outputs, and on-the-wire packets. Only
   observable behaviour is used, never its implementation.
3. **Its published user documentation** - the option/command surface is a
   functional interface (an API), which is not copyrightable. Help text in this
   project is written independently and is not a copy of the original text.

The original `radperf` distribution ships FreeRADIUS RADIUS dictionary data
files. Native builds use a dictionary directory at runtime. The Docker image
ships the dictionary from Debian's `freeradius-common` package and includes
its copyright notice. Dictionary parsing is implemented from scratch against
the documented file format. See [dictionary lookup](README.md#dictionary-lookup).

## Licensing

The original `radperf` license is unknown and assumed to be non-free. To avoid
any derivation, this project deliberately does not link against, embed, or
translate any part of it. This project's own code is offered under
MIT.

## Third-party crates

- `mio` - readiness notifications (epoll/kqueue).
- `md5` - MD5 hashing for RADIUS authenticators and CHAP.
- `libc` - low-level OS interfaces.
- `signal-hook` - SIGINT handling.
- `tempfile` - temporary files and directories in tests.
