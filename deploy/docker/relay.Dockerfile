# Secwet relay image. Build from the repository root:
#   docker build -f deploy/docker/relay.Dockerfile -t secwet-relay .
#
# Stage 1 compiles only the relay binary from the Cargo workspace; stage 2 is
# a distroless runtime with no shell or package manager, running as a
# non-root user.

FROM rust:1.99-slim-bookworm AS build
WORKDIR /src
# The workspace manifests plus the crates the relay is built from. Cargo reads
# every workspace member's manifest, so the desktop crate's sources come too,
# but only the relay and its dependencies are compiled.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY apps/desktop/src-tauri ./apps/desktop/src-tauri
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p secwet-relay \
    && install -D target/release/secwet-relay /out/secwet-relay

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /out/secwet-relay /usr/local/bin/secwet-relay
# Listen on every interface inside the container; only the reverse proxy on
# the private network reaches it.
ENV SECWET_RELAY_ADDR=0.0.0.0:8080 \
    RUST_LOG=secwet_relay=info,tower_http=info
EXPOSE 8080
USER nonroot
ENTRYPOINT ["/usr/local/bin/secwet-relay"]
CMD ["serve"]
