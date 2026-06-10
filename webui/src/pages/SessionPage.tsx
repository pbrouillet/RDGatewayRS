import { useParams, useNavigate } from "react-router-dom";
import { useEffect, useRef, useState, useCallback } from "react";
import {
  Button,
  Input,
  Card,
  CardHeader,
  Body1,
  Caption1,
  Spinner,
  makeStyles,
  tokens,
  MessageBar,
  MessageBarBody,
  Field,
} from "@fluentui/react-components";
import {
  PlugConnectedRegular,
  PlugDisconnectedRegular,
  ArrowLeftRegular,
} from "@fluentui/react-icons";
import type { Connection } from "../types";
import { createSessionToken } from "../api";

const useStyles = makeStyles({
  container: {
    display: "flex",
    flexDirection: "column",
    height: "100vh",
    backgroundColor: tokens.colorNeutralBackground2,
  },
  toolbar: {
    display: "flex",
    alignItems: "center",
    gap: "12px",
    padding: "8px 16px",
    backgroundColor: tokens.colorNeutralBackground1,
    borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
  },
  content: {
    display: "flex",
    flex: 1,
    overflow: "hidden",
  },
  sidebar: {
    width: "300px",
    padding: "16px",
    borderRight: `1px solid ${tokens.colorNeutralStroke1}`,
    backgroundColor: tokens.colorNeutralBackground1,
    overflowY: "auto",
  },
  canvas: {
    flex: 1,
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: "#1e1e1e",
    position: "relative",
  },
  canvasElement: {
    maxWidth: "100%",
    maxHeight: "100%",
    objectFit: "contain",
  },
  statusBar: {
    display: "flex",
    alignItems: "center",
    gap: "8px",
    padding: "4px 16px",
    backgroundColor: tokens.colorNeutralBackground1,
    borderTop: `1px solid ${tokens.colorNeutralStroke1}`,
    fontSize: "12px",
  },
  statusDot: {
    width: "8px",
    height: "8px",
    borderRadius: "50%",
  },
  formField: {
    marginBottom: "12px",
  },
  placeholder: {
    color: tokens.colorNeutralForegroundDisabled,
    textAlign: "center" as const,
  },
});

type ConnectionStatus = "disconnected" | "connecting" | "connected" | "error";

export function SessionPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const styles = useStyles();
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const wsRef = useRef<WebSocket | null>(null);

  const [connection, setConnection] = useState<Connection | null>(null);
  const [status, setStatus] = useState<ConnectionStatus>("disconnected");
  const [error, setError] = useState<string | null>(null);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [bytesReceived, setBytesReceived] = useState(0);
  const [bytesSent, setBytesSent] = useState(0);

  // Fetch connection details
  useEffect(() => {
    fetch(`/api/connections/${id}`)
      .then((res) => {
        if (!res.ok) throw new Error("Connection not found");
        return res.json();
      })
      .then(setConnection)
      .catch((e) => setError(e.message));
  }, [id]);

  // Placeholder rendering: show connection activity on the canvas
  const renderActivity = useCallback((bytes: number) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    // Visualize data flowing — simple activity indicator
    const x = Math.random() * canvas.width;
    const y = Math.random() * canvas.height;
    const size = Math.min(bytes / 100, 20);
    ctx.fillStyle = `rgba(0, 120, 212, ${Math.min(bytes / 1000, 0.8)})`;
    ctx.fillRect(x, y, size, size);
  }, []);

  const handleConnect = useCallback(async () => {
    if (!connection) return;
    setStatus("connecting");
    setError(null);
    setBytesReceived(0);
    setBytesSent(0);

    // Obtain a session token before opening the WebSocket
    let token: string;
    try {
      const session = await createSessionToken(connection.id);
      token = session.token;
    } catch (e) {
      setStatus("error");
      setError(e instanceof Error ? e.message : "Failed to create session");
      return;
    }

    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/api/connections/${connection.id}/ws?token=${encodeURIComponent(token)}`;

    const ws = new WebSocket(wsUrl);
    ws.binaryType = "arraybuffer";
    wsRef.current = ws;

    ws.onopen = () => {
      setStatus("connected");
      // No credentials are sent — RDP auth will be handled by IronRDP WASM
      // when integrated. The relay is a pure byte bridge.
    };

    ws.onmessage = (event) => {
      if (event.data instanceof ArrayBuffer) {
        setBytesReceived((prev) => prev + event.data.byteLength);
        renderActivity(event.data.byteLength);
      }
    };

    ws.onerror = () => {
      setStatus("error");
      setError("WebSocket connection error");
    };

    ws.onclose = (event) => {
      setStatus("disconnected");
      if (event.reason) {
        setError(`Disconnected: ${event.reason}`);
      }
      wsRef.current = null;
    };
  }, [connection, renderActivity]);

  const handleDisconnect = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    setStatus("disconnected");
  }, []);

  // Initialize canvas
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    canvas.width = 1024;
    canvas.height = 768;
    const ctx = canvas.getContext("2d");
    if (ctx) {
      ctx.fillStyle = "#1e1e1e";
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.fillStyle = "#555";
      ctx.font = "16px sans-serif";
      ctx.textAlign = "center";
      ctx.fillText(
        "Connect to start the RDP session",
        canvas.width / 2,
        canvas.height / 2
      );
    }
  }, []);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, []);

  const statusColor =
    status === "connected"
      ? tokens.colorPaletteGreenForeground1
      : status === "connecting"
        ? tokens.colorPaletteYellowForeground1
        : status === "error"
          ? tokens.colorPaletteRedForeground1
          : tokens.colorNeutralForegroundDisabled;

  return (
    <div className={styles.container}>
      {/* Toolbar */}
      <div className={styles.toolbar}>
        <Button
          icon={<ArrowLeftRegular />}
          appearance="subtle"
          onClick={() => navigate("/")}
        >
          Back
        </Button>
        <Body1>
          <b>{connection?.name ?? "Loading..."}</b>
        </Body1>
        {connection && (
          <Caption1>
            {connection.host}:{connection.port}
          </Caption1>
        )}
      </div>

      {/* Main content */}
      <div className={styles.content}>
        {/* Sidebar with credentials */}
        <div className={styles.sidebar}>
          <Card>
            <CardHeader header={<Body1><b>Connection</b></Body1>} />
            <div style={{ padding: "0 16px 16px" }}>
              {error && (
                <MessageBar intent="error" style={{ marginBottom: "12px" }}>
                  <MessageBarBody>{error}</MessageBarBody>
                </MessageBar>
              )}

              <Field label="Username (for RDP auth)" className={styles.formField}>
                <Input
                  value={username}
                  onChange={(_, data) => setUsername(data.value)}
                  placeholder="DOMAIN\\user or user@domain"
                  disabled={status === "connected" || status === "connecting"}
                />
              </Field>

              <Field label="Password (for RDP auth)" className={styles.formField}>
                <Input
                  type="password"
                  value={password}
                  onChange={(_, data) => setPassword(data.value)}
                  disabled={status === "connected" || status === "connecting"}
                />
              </Field>

              <Caption1 style={{ display: "block", marginBottom: "12px", color: tokens.colorNeutralForeground3 }}>
                Credentials stay in your browser — used locally by the RDP client.
              </Caption1>

              {status === "disconnected" || status === "error" ? (
                <Button
                  appearance="primary"
                  icon={<PlugConnectedRegular />}
                  onClick={handleConnect}
                  disabled={!connection}
                  style={{ width: "100%" }}
                >
                  Connect
                </Button>
              ) : status === "connecting" ? (
                <Button
                  appearance="secondary"
                  disabled
                  style={{ width: "100%" }}
                >
                  <Spinner size="tiny" /> Connecting...
                </Button>
              ) : (
                <Button
                  appearance="secondary"
                  icon={<PlugDisconnectedRegular />}
                  onClick={handleDisconnect}
                  style={{ width: "100%" }}
                >
                  Disconnect
                </Button>
              )}
            </div>
          </Card>
        </div>

        {/* Canvas area */}
        <div className={styles.canvas}>
          <canvas ref={canvasRef} className={styles.canvasElement} />
        </div>
      </div>

      {/* Status bar */}
      <div className={styles.statusBar}>
        <div
          className={styles.statusDot}
          style={{ backgroundColor: statusColor }}
        />
        <span>
          {status === "connected"
            ? "Connected"
            : status === "connecting"
              ? "Connecting..."
              : status === "error"
                ? "Error"
                : "Disconnected"}
        </span>
        {status === "connected" && (
          <>
            <span>|</span>
            <span>↓ {formatBytes(bytesReceived)}</span>
            <span>↑ {formatBytes(bytesSent)}</span>
          </>
        )}
      </div>
    </div>
  );
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
