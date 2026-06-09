# Copilot Instructions for RDGatewayRS

## Architecture

Workspace with 3 crates:

- **`rdg-proto`** — Protocol layer: RPC/HTTP, NTLM, TSG message parsing, WebSocket framing. No I/O, pure serialization/deserialization.
- **`rdg-core`** — Domain logic: config (`ServerConfig`), database (SQLite via `sqlx`), session management, ACLs, Kerberos/NTLM negotiation.
- **`rdg-server`** — Application: Axum HTTP server, WebSocket upgrade, TLS (rustls), TCP relay, TUI management interface, telemetry. Binary name: `rdg-server`.

Config-driven design: all runtime behavior is controlled by `rdg-gateway.toml` parsed into `rdg_core::config::ServerConfig`. New features should add a config section with `#[serde(default)]` for backwards compatibility.

## Build & Test

```bash
cargo build                    # full workspace
cargo build -p rdg-server      # just the server binary
cargo test --workspace         # all tests
cargo test -p rdg-proto        # single crate
cargo run                      # runs rdg-server with rdg-gateway.toml in cwd
```

CI runs `cargo test --workspace` on Ubuntu, builds release binaries for Windows + Linux, and publishes a Docker image.

## Runtime Environment

- **Port 443 is unavailable on Windows Server dev machines** — HTTP.sys (native RD Gateway role) binds port 443 at the kernel level. Use `listen_port = 3443` (or any port > 1024) in `rdg-gateway.toml` for development.
- The gateway requires a TLS certificate. Set `auto_generate = true` under `[tls]` for local dev (generates self-signed cert in `certs/`).
- Cross-platform: use `cross-krb5` for Kerberos authentication (not Windows-specific APIs).

## OpenTelemetry

The telemetry stack uses the **0.29.x** family of OpenTelemetry crates:
- `opentelemetry` 0.29, `opentelemetry_sdk` 0.29, `opentelemetry-otlp` 0.29
- `opentelemetry-appender-tracing` 0.29 (bridges `tracing` events → OTel LogRecords)
- `tracing-opentelemetry` 0.30 (bridges `tracing` spans → OTel Spans)

All three signals (traces, logs, metrics) must be configured together — do not add one without the others. The `telemetry.rs` module owns all OTel initialization.

The Aspire Dashboard is the default local collector: `scripts/start-aspire.ps1` launches it on port 18888 (UI) with OTLP gRPC on port 4317.

## Files to Never Commit

These are local dev artifacts — do not stage them:
- `*.cer`, `*.log`, `*.err` — runtime output files
- `*.db` — SQLite database
- `certs/` — auto-generated TLS certificates
- `test_*.py` — ad-hoc test scripts

## Conventions

- Logging: use `tracing` macros (`tracing::info!`, `tracing::debug!`, etc.) everywhere. Never use `println!` or `eprintln!`.
- Error handling: `anyhow::Result` for application code, `thiserror` for library error types in `rdg-proto`/`rdg-core`.
- Config additions: add new fields with `#[serde(default)]` or `Option<T>` to avoid breaking existing `rdg-gateway.toml` files.
- Metrics: define in `metrics.rs` using the `opentelemetry::global::meter()` API, instrument at call sites.
