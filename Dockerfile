# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM debian:trixie-slim AS build
ARG BUILDARCH
ARG TARGETARCH
ARG RUST_VERSION=1.85.1

ENV CARGO_HOME=/opt/cargo \
    RUSTUP_HOME=/opt/rustup \
    PATH=/opt/cargo/bin:$PATH

RUN set -eux; \
    set -- ca-certificates curl freeradius-common gcc libc6-dev; \
    case "${BUILDARCH}/${TARGETARCH}" in \
        amd64/arm64) set -- "$@" gcc-aarch64-linux-gnu libc6-dev-arm64-cross ;; \
        arm64/amd64) set -- "$@" gcc-x86-64-linux-gnu libc6-dev-amd64-cross ;; \
        amd64/amd64|arm64/arm64) : ;; \
        *) echo "Unsupported platform: ${BUILDARCH}/${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    apt-get update; \
    apt-get install -y --no-install-recommends "$@"; \
    rm -rf /var/lib/apt/lists/*; \
    curl -fsSL https://sh.rustup.rs -o /tmp/rustup-init.sh; \
    sh /tmp/rustup-init.sh -y --profile minimal --default-toolchain "$RUST_VERSION" --no-modify-path; \
    rm /tmp/rustup-init.sh

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src/ src/

RUN set -eux; \
    case "$TARGETARCH" in \
        amd64) target=x86_64-unknown-linux-gnu; export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc ;; \
        arm64) target=aarch64-unknown-linux-gnu; export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc ;; \
        *) exit 1 ;; \
    esac; \
    rustup target add "$target"; \
    cargo build --locked --release --bin radperf --target "$target"; \
    install -m 0755 "target/$target/release/radperf" /usr/local/bin/radperf

FROM debian:trixie-slim
COPY --from=build /usr/local/bin/radperf /usr/local/bin/radperf
COPY --from=build /usr/share/freeradius/ /usr/share/freeradius/
COPY --from=build /usr/share/doc/freeradius-common/copyright /usr/share/doc/freeradius-common/copyright
COPY LICENSE /usr/share/doc/radperf-rs/copyright

ENV FREERADIUS_DICTIONARY_PATH=/usr/share/freeradius
USER 65534:65534
ENTRYPOINT ["/usr/local/bin/radperf"]
CMD ["--help"]
