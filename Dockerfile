# Stage 1: Build
FROM rust:1.86-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    cmake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

RUN cargo build --release --bin rdg-server \
    && strip /src/target/release/rdg-server

# Stage 2: Runtime
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/rdg-gateway /var/lib/rdg-gateway

COPY --from=builder /src/target/release/rdg-server /usr/local/bin/rdg-server
COPY rdg-gateway.toml /etc/rdg-gateway/rdg-gateway.toml

ENV RDG_CONFIG=/etc/rdg-gateway/rdg-gateway.toml
EXPOSE 443

ENTRYPOINT ["/usr/local/bin/rdg-server"]
