# RDG Gateway RS

A lightweight, cross-platform Remote Desktop Gateway implemented in Rust. Compatible with both **mstsc** (Windows RDP client) and **FreeRDP** clients.

## Features

- **Dual transport support**: WebSocket (FreeRDP) and RPC-over-HTTP v2 (mstsc)
- **NTLM & Kerberos authentication** via SPNEGO Negotiate
- **TLS with auto-generated certificates** (self-signed, persisted across restarts)
- **TCP relay** to backend RDP hosts with NLA/TLS passthrough
- **OpenTelemetry observability**: traces, logs, and metrics via OTLP to Aspire Dashboard
- **TUI management interface** for configuration and certificate inspection
- **Cross-platform**: runs on Windows and Linux (uses `cross-krb5` for Kerberos)

## Quick Start

```bash
# Build
cargo build

# Run (uses rdg-gateway.toml in current directory)
cargo run

# Or run in release mode
cargo run --release
```

### Configuration

Copy and edit `rdg-gateway.toml`:

```toml
listen_addr = "0.0.0.0"
listen_port = 3443
server_name = "my-gateway"

[tls]
auto_generate = true

[database]
url = "sqlite://rdg-gateway.db?mode=rwc"

[auth]
open_mode = true  # Testing only! Accepts any NTLM without validation

[telemetry]
otlp_endpoint = "http://localhost:4317"
service_name = "rdg-gateway"
enabled = true
```

### Observability with Aspire Dashboard

```powershell
# Install and launch Aspire Dashboard (receives OTel data)
.\scripts\start-aspire.ps1

# Then start the gateway — traces, logs, and metrics flow automatically
cargo run
```

Dashboard UI: http://localhost:18888

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full protocol breakdown, transport details, and implementation notes.

### Crate Structure

```
crates/
├── rdg-proto    # Wire protocol: TSG messages, NTLM, RPC/RPCH, WebSocket framing
├── rdg-core     # Domain: config, database, sessions, auth negotiation, ACLs
└── rdg-server   # Application: HTTP server, handlers, relay, TUI, telemetry
```

## Testing

```bash
cargo test --workspace       # All tests
cargo test -p rdg-proto      # Protocol crate only
cargo test -p rdg-core       # Core crate only
```

## Building Releases

CI (GitHub Actions) builds Windows and Linux binaries and publishes a Docker image on every tag:

```bash
git tag -a v0.x.0 -m "Release v0.x.0"
git push origin --tags
```

## License

MIT
