import { useEffect, useRef, useState } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import {
  makeStyles,
  Button,
  Spinner,
  MessageBar,
  tokens,
} from "@fluentui/react-components";
import { ArrowLeftRegular } from "@fluentui/react-icons";
import Guacamole from "guacamole-common-js";

const useStyles = makeStyles({
  container: {
    display: "flex",
    flexDirection: "column",
    height: "100vh",
    backgroundColor: "#000",
  },
  toolbar: {
    display: "flex",
    alignItems: "center",
    gap: "8px",
    padding: "4px 12px",
    backgroundColor: tokens.colorNeutralBackground3,
    borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
  },
  display: {
    flex: 1,
    overflow: "hidden",
    position: "relative",
  },
  center: {
    display: "flex",
    justifyContent: "center",
    alignItems: "center",
    height: "100%",
  },
});

export function SessionPage() {
  const styles = useStyles();
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const displayRef = useRef<HTMLDivElement>(null);
  const clientRef = useRef<Guacamole.Client | null>(null);
  const [status, setStatus] = useState<"connecting" | "connected" | "error">(
    "connecting"
  );
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const host = searchParams.get("host") || "";
  const port = searchParams.get("port") || "3389";
  const name = searchParams.get("name") || host;

  useEffect(() => {
    if (!host || !displayRef.current) return;

    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/api/guacamole/connect?host=${encodeURIComponent(host)}&port=${encodeURIComponent(port)}&width=${window.innerWidth}&height=${window.innerHeight - 40}&dpi=${window.devicePixelRatio * 96}&security=any&ignore_cert=true`;

    const tunnel = new Guacamole.WebSocketTunnel(wsUrl);
    const client = new Guacamole.Client(tunnel);
    clientRef.current = client;

    tunnel.onerror = (error) => {
      setStatus("error");
      setErrorMsg(error.message || "Tunnel error - is guacd running?");
    };

    client.onerror = (error) => {
      setStatus("error");
      setErrorMsg(error.message || "Connection error");
    };

    client.onstatechange = (state) => {
      switch (state) {
        case Guacamole.Client.State.CONNECTED:
          setStatus("connected");
          break;
        case Guacamole.Client.State.DISCONNECTED:
          if (status !== "error") {
            setStatus("error");
            setErrorMsg("Disconnected");
          }
          break;
      }
    };

    // Attach display
    const display = client.getDisplay();
    const element = display.getElement();
    displayRef.current.appendChild(element);

    // Connect (empty string = no additional connection params since they're in the WS URL)
    client.connect("");

    // Input handling
    const mouse = new Guacamole.Mouse(element);
    mouse.onEach(["mousedown", "mouseup", "mousemove"], (e: unknown) => {
      const evt = e as Guacamole.Mouse.Event;
      client.sendMouseState(evt.state);
    });

    const keyboard = new Guacamole.Keyboard(document);
    keyboard.onkeydown = (keysym: number) => {
      client.sendKeyEvent(1, keysym);
    };
    keyboard.onkeyup = (keysym: number) => {
      client.sendKeyEvent(0, keysym);
    };

    // Handle resize
    const handleResize = () => {
      const width = displayRef.current?.clientWidth || window.innerWidth;
      const height = displayRef.current?.clientHeight || window.innerHeight - 40;
      display.scale(Math.min(width / display.getWidth(), height / display.getHeight()));
    };
    window.addEventListener("resize", handleResize);

    return () => {
      window.removeEventListener("resize", handleResize);
      keyboard.onkeydown = null;
      keyboard.onkeyup = null;
      client.disconnect();
    };
  }, [host, port]);

  return (
    <div className={styles.container}>
      <div className={styles.toolbar}>
        <Button
          icon={<ArrowLeftRegular />}
          appearance="subtle"
          onClick={() => navigate("/")}
        >
          Back
        </Button>
        <span style={{ color: tokens.colorNeutralForeground1 }}>{name}</span>
        {status === "connecting" && <Spinner size="tiny" />}
      </div>
      <div className={styles.display} ref={displayRef}>
        {status === "error" && (
          <div className={styles.center}>
            <MessageBar intent="error">{errorMsg || "Connection failed"}</MessageBar>
          </div>
        )}
        {status === "connecting" && (
          <div className={styles.center}>
            <Spinner label="Connecting..." />
          </div>
        )}
      </div>
    </div>
  );
}
