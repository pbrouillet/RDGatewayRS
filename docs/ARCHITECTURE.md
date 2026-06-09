# Architecture

## Overview

RDG Gateway RS implements the Microsoft RD Gateway (TSGateway) protocol, enabling Remote Desktop clients to connect to backend RDP hosts through HTTPS. The gateway terminates TLS, authenticates clients, then establishes a bidirectional TCP relay to the target RDP server.

```
┌─────────┐     HTTPS/WSS      ┌─────────────┐      TCP/3389      ┌──────────┐
│  Client  │ ───────────────── │  RDG Gateway │ ─────────────────── │ RDP Host │
│(mstsc/   │  WebSocket or     │   (this)     │   Raw RDP/NLA/TLS  │          │
│ FreeRDP) │  RPC-over-HTTP    └─────────────┘                     └──────────┘
└─────────┘
```

## Transport Protocols

The gateway supports two distinct transport mechanisms, depending on the client:

### WebSocket Transport (FreeRDP)

FreeRDP connects via WebSocket on `/remoteDesktopGateway/`.

**Connection flow:**
```
Client                              Gateway
  │                                    │
  │── RDG_OUT_DATA (no auth) ─────────→│  ← 401 + WWW-Authenticate: Negotiate
  │                                    │
  │── RDG_OUT_DATA + NTLM Type1 ─────→│  ← 401 + Negotiate <Type2 challenge>
  │                                    │
  │── RDG_OUT_DATA + NTLM Type3 ─────→│  ← 101 Switching Protocols (WebSocket)
  │                                    │
  │══ WebSocket Binary Frames ════════ │  ← TSG message exchange
  │   (TSG handshake then relay)       │
```

**Key gotcha: Non-standard HTTP method.** FreeRDP uses the custom HTTP method `RDG_OUT_DATA`, not `GET`. This means Axum's built-in `WebSocketUpgrade` extractor doesn't work — it requires `GET`. The gateway performs a **manual WebSocket upgrade** using `hyper::upgrade::on()` and wraps the raw I/O with `tokio-tungstenite`.

### RPC-over-HTTP v2 Transport (mstsc)

mstsc (Windows native client) uses MS-RPCH — two long-lived HTTP channels:

- **OUT channel** (`RPC_OUT_DATA`): server → client data (long-lived response body)
- **IN channel** (`RPC_IN_DATA`): client → server data (long-lived request body)

**Connection flow:**
```
Client                              Gateway
  │                                    │
  │── RPC_OUT_DATA (CONN/A1 RTS) ─────→│  ← (hold connection open)
  │── RPC_IN_DATA  (CONN/B1 RTS) ─────→│  ← CONN/C2 RTS on OUT channel
  │                                    │
  │── DCE/RPC Bind (IN) ──────────────→│  ← Bind Ack (OUT)
  │── RPC Request (TSG opnums) ────────→│  ← RPC Response (OUT)
  │                                    │
  │   ... TSG handshake via RPC ...    │
  │                                    │
  │══ Data relay mode ════════════════ │
```

**Key gotcha: Virtual connection correlation.** The IN and OUT channels arrive as separate HTTP requests. They are correlated by a shared `VirtualConnectionCookie` (UUID) sent in the initial RTS commands. The gateway must hold the OUT channel open and match the IN channel to the same virtual connection.

## TSG Protocol (MS-TSGU)

Both transports carry the same TSG message protocol on top. Each message has an 8-byte header:

```
[type: u16_le][reserved: u16_le][length: u32_le][payload...]
```

Where `length` includes the 8-byte header itself.

### TSG Handshake State Machine

```
AwaitingHandshake
    │ ← HandshakeRequest (0x01)
    │ → HandshakeResponse (0x02)
    ▼
AwaitingTunnelCreate
    │ ← TunnelCreate (0x04)
    │ → TunnelResponse (0x05)
    ▼
AwaitingTunnelAuth
    │ ← TunnelAuth (0x06)    [contains client machine name]
    │ → TunnelAuthResponse (0x07)
    ▼
AwaitingChannelCreate
    │ ← ChannelCreate (0x08)  [contains target host:port]
    │ → ChannelResponse (0x09)
    ▼
DataTransfer
    │ ← Data (0x0A) messages ↔ TCP relay to backend
    │ ← Keepalive (0x0D)      → echo back Keepalive
    │ ← CloseChannel (0x0E)   → CloseChannelResponse (0x0F)
```

Implementation: `crates/rdg-core/src/session.rs` (`GatewaySession` state machine)

### Data Messages and cbDataLength

Data messages (type 0x0A) wrap the actual RDP/NLA bytes:

```
[TSG header (8 bytes)][cbDataLength: u16_le][RDP payload (cbDataLength bytes)]
```

**Key gotcha:** The 2-byte `cbDataLength` prefix must be **stripped** before forwarding to the backend TCP socket, and **added** when wrapping backend data for the client. This is a frequent source of relay failures if missed.

## Authentication

### NTLM (WebSocket transport)

Three-step challenge-response over HTTP headers before WebSocket upgrade:

1. **No auth** → 401 with `WWW-Authenticate: Negotiate`
2. **Type1 (Negotiate)** → Gateway generates challenge, stores per-connection, returns Type2
3. **Type3 (Authenticate)** → Validate credentials, extract username, upgrade to WebSocket

The `NtlmAuthContext` stores the server challenge keyed by client `SocketAddr`. In `open_mode` (testing), Type3 is accepted without cryptographic validation.

### SPNEGO / Negotiate

The gateway detects token type by inspecting the first bytes:
- `NTLMSSP\0` prefix → NTLM flow
- SPNEGO OID (1.3.6.1.5.5.2) → Kerberos via `cross-krb5`

Implementation: `crates/rdg-core/src/negotiate.rs`

### KdcProxy

mstsc may POST to `/KdcProxy` for Kerberos ticket acquisition. The gateway returns 503 to force NTLM fallback when not domain-joined.

## TCP Relay

Once the TSG handshake completes and the first Data message arrives:

1. Gateway connects to `target_host:target_port` (from ChannelCreate)
2. Sets `TCP_NODELAY` on the backend socket (critical for NLA/TLS handshake latency)
3. Strips `cbDataLength` from client → backend direction
4. Adds TSG Data framing from backend → client direction
5. Handles interleaved control messages during relay

### Protocol Gotchas in the Relay

#### TCP_NODELAY is critical

Without `TCP_NODELAY`, the NLA/TLS handshake between client and backend RDP server fails or stalls. The handshake involves many small packets that Nagle's algorithm would delay. Always set `nodelay(true)` on the backend `TcpStream`.

#### Keepalive messages during relay

The client sends TSG Keepalive (type 0x0D) messages periodically during an active session. These must be echoed back immediately on the WebSocket — they are NOT forwarded to the backend TCP. Failure to respond causes the client to disconnect.

#### Unknown control messages (type 0x10)

mstsc sends undocumented message type 0x10 during long sessions. The gateway echoes these back verbatim. Dropping them causes connection resets.

#### Interleaved control and data

During relay, the WS→TCP direction must parse each WebSocket frame to distinguish:
- **Data (0x0A)** → strip cbDataLength, forward to TCP
- **Keepalive (0x0D)** → respond on WebSocket, do NOT forward to TCP
- **CloseChannel (0x0E)** → respond with 0x0F, terminate relay
- **Unknown types** → echo back, do NOT forward to TCP

A dedicated `ctrl_tx` channel sends control responses back to the TCP→WS task for serialized sending on the WebSocket sink.

#### Initial data handling

The first Data message after ChannelResponse contains the start of the NLA handshake (Client Hello). It must be forwarded to the backend TCP socket before entering the relay loop. This data is already stripped of its cbDataLength prefix.

## Crate Responsibilities

### `rdg-proto` (Protocol)

Pure serialization/deserialization — no I/O, no async:
- `messages.rs` — TSG message types, parse/write
- `ntlm.rs` — NTLM Type1/Type2/Type3 parsing and generation
- `rpc.rs` — DCE/RPC PDU framing (Bind, BindAck, Request, Response)
- `rpch.rs` — RPC-over-HTTP v2 RTS commands, virtual connections
- `websocket.rs` — TSG-over-WebSocket framing helpers

### `rdg-core` (Domain)

Business logic and state:
- `config.rs` — `ServerConfig` and all sub-configs (TLS, auth, telemetry, database)
- `session.rs` — `GatewaySession` state machine
- `negotiate.rs` — SPNEGO token detection, NTLM/Kerberos routing
- `auth.rs` — `NtlmAuthContext` challenge/response management
- `db/` — SQLite via `sqlx`, migrations, certificate storage
- `acl.rs` — Connection Authorization Policies (CAP)

### `rdg-server` (Application)

Axum HTTP server, handlers, and runtime:
- `handlers/websocket.rs` — FreeRDP WebSocket transport (NTLM auth + relay)
- `handlers/rpch.rs` — mstsc RPC-over-HTTP transport
- `handlers/health.rs` — Health check endpoint
- `relay.rs` — Generic bidirectional WebSocket↔TCP relay (unused, superseded by inline relay in websocket.rs)
- `telemetry.rs` — OpenTelemetry init (OTLP gRPC exporter for traces/logs/metrics)
- `metrics.rs` — Application metrics (connections, requests, durations)
- `tui/` — Ratatui-based management TUI
- `main.rs` — CLI, config loading, TLS setup, server startup

## Lessons Learned (from frame captures)

These insights were discovered by comparing Wireshark captures of real Windows RD Gateway (TSGateway) traffic with FreeRDP and mstsc clients:

1. **FreeRDP's `RDG_OUT_DATA` method breaks standard frameworks.** No HTTP framework expects custom methods for WebSocket upgrade. Manual upgrade via `hyper::upgrade` is the only path.

2. **The TSG header `length` field includes itself.** A common off-by-one: the 8-byte header is counted in the total length. Payload size = `length - 8`.

3. **`ext_auth` in HandshakeResponse must be 0x0007** (not 0 or 0xFFFF). FreeRDP checks this to decide capabilities. A mismatch causes it to skip tunnel auth or fail silently.

4. **TunnelResponse `caps` field matters.** Setting `0x0d` (NAP + CONSENT_SIGN + SERVICE_MSG) matches real Windows Server behavior. Wrong values cause mstsc to abort.

5. **cbDataLength is redundant but mandatory.** The TSG header already has a length field, but Data messages add a u16 `cbDataLength` before the actual payload. Both mstsc and FreeRDP expect this. The relay must strip it outbound and add it inbound.

6. **TCP_NODELAY or NLA dies.** NLA (CredSSP/SPNEGO) involves multiple small round-trips. Without NODELAY, Nagle delays these by up to 200ms each direction, causing TLS handshake timeouts.

7. **Keepalive echoing is not optional.** Clients send keepalives every 30-60s. If the gateway doesn't echo within a few seconds, the client closes the connection assuming the tunnel is dead.

8. **RPC-over-HTTP requires virtual connection bookkeeping.** The IN and OUT channels are separate TCP connections with separate HTTP requests. They share a `VirtualConnectionCookie` UUID. The OUT channel must be held open (via long-lived response body / chunked transfer) while the IN channel feeds data.
