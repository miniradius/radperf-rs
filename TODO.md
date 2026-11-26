# TODO

## Diagnostics and packaging

- [ ] Decode vendor-specific, TLV, and RFC 6929 attributes in debug output
      (`-x`).
- [ ] Add Bash and Zsh completions.

## Performance

See [scaling measurements and follow-up plan](docs/scaling.md).

- [ ] Repeat the sandbox scaling benchmark with an independent RADIUS server
      that has spare capacity.
- [ ] Use the scaling results to decide whether to add one `mio` event loop
      per worker thread or investigate Linux batching and `SO_REUSEPORT`.

See [README.md](README.md) for supported usage and intentional differences
from RadPerf 2.0.1. See [docs/validation.md](docs/validation.md) for verification
and [CHANGELOG.md](CHANGELOG.md) for changes intended for release.
