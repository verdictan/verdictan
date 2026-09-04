# SPDX-License-Identifier: BUSL-1.1
ARG RUST_VERSION=1.98.0

FROM rust:${RUST_VERSION}-bookworm AS chef

RUN apt-get update \
    && apt-get install -y --no-install-recommends mold clang \
    && rm -rf /var/lib/apt/lists/*

ENV RUSTFLAGS="-C linker=clang -C link-arg=-fuse-ld=mold"
ENV CARGO_PROFILE_RELEASE_LTO=thin
ENV CARGO_PROFILE_RELEASE_CODEGEN_UNITS=4

RUN cargo install cargo-chef --locked

FROM chef AS planner

WORKDIR /app

COPY Cargo.toml Cargo.lock ./

RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS deps

WORKDIR /app

COPY --from=planner /app/recipe.json ./recipe.json

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo chef cook --release --features distributed --recipe-path recipe.json

FROM deps AS builder-src

WORKDIR /app

COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo build --release --features distributed --bin verdictan \
    && cp target/release/verdictan /usr/local/bin/verdictan

FROM debian:bookworm-slim AS runtime

ARG VERDICTAN_COMMIT_SHA=unknown

LABEL org.opencontainers.image.licenses="BUSL-1.1" \
    org.opencontainers.image.revision="${VERDICTAN_COMMIT_SHA}" \
    org.opencontainers.image.source="https://github.com/verdictan/verdictan" \
    org.opencontainers.image.title="Verdictan Gateway CLI"

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 verdictan-gateway \
    && useradd --uid 10001 --gid verdictan-gateway --home-dir /nonexistent \
        --no-create-home --shell /usr/sbin/nologin verdictan-gateway \
    && install -d -o 10001 -g 10001 /var/lib/verdictan/gateway

WORKDIR /app

COPY LICENSE THIRD_PARTY_NOTICES.md /licenses/
COPY --from=builder-src /usr/local/bin/verdictan /usr/local/bin/verdictan

ENV HOME=/tmp
USER 10001:10001

ENTRYPOINT ["verdictan"]
CMD ["--help"]
