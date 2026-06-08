use std::{
    env,
    io::Cursor,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Once},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, bail, ensure, Context, Result};
use base64::Engine;
use bytes::BytesMut;
use futures::{SinkExt, StreamExt};
use rcgen::generate_simple_self_signed;
use reqwest::{
    header::{
        AUTHORIZATION, CONNECTION, SEC_WEBSOCKET_KEY, SEC_WEBSOCKET_VERSION, UPGRADE,
        WWW_AUTHENTICATE,
    },
    Certificate, StatusCode,
};
use rustls::{ClientConfig, RootCertStore};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    net::TcpStream,
    process::{Child, Command},
    sync::Mutex,
    task::JoinHandle,
    time::{sleep, timeout},
};
use tokio_tungstenite::{
    connect_async_tls_with_config,
    tungstenite::{client::IntoClientRequest, http::HeaderValue, Message},
    Connector, MaybeTlsStream, WebSocketStream,
};

use rdg_proto::messages::{
    parse_message, ChannelCreate, HandshakeRequest, TsgMessage, TunnelAuth, TunnelCreate,
};

const TEST_PORT: u16 = 9443;
const TEST_PATH: &str = "/remoteDesktopGateway/";
const TEST_SERVER_NAME: &str = "localhost";
const TEST_CLIENT_NAME: &str = "FREERDP-TEST";

#[tokio::test]
async fn test_websocket_gateway_handshake() -> Result<()> {
    install_crypto_provider();
    let mut server = TestServer::spawn().await?;

    let test_result = async {
        wait_for_server(TEST_PORT, &mut server).await?;

        let client = reqwest_client(&server.cert_pem)?;
        let challenge = fetch_ntlm_challenge(&client).await?;
        ensure!(challenge.len() >= 12, "NTLM challenge was too short");
        ensure!(
            &challenge[..8] == b"NTLMSSP\0",
            "challenge did not use NTLMSSP"
        );
        ensure!(
            u32::from_le_bytes(challenge[8..12].try_into().unwrap()) == 2,
            "expected NTLM Type2 challenge"
        );

        let mut websocket = connect_gateway_websocket(&server.cert_pem).await?;

        let handshake_response = send_and_expect(
            &mut websocket,
            encode_message(|buf| {
                HandshakeRequest {
                    major_version: 1,
                    minor_version: 0,
                    client_version: 1,
                    ext_auth: 0,
                }
                .write(buf)
            }),
        )
        .await?;
        match handshake_response {
            TsgMessage::HandshakeResponse(response) => {
                ensure!(response.error_code == 0, "handshake failed: {:?}", response);
                ensure!(
                    response.ext_auth == 0x0007,
                    "unexpected ext auth: {:?}",
                    response
                );
            }
            other => bail!("expected HandshakeResponse, got {other:?}"),
        }

        let tunnel_response = send_and_expect(
            &mut websocket,
            encode_message(|buf| {
                TunnelCreate {
                    caps_flags: 0,
                    fields_present: 0,
                    reserved: 0,
                    paa_cookie: None,
                }
                .write(buf)
            }),
        )
        .await?;
        let tunnel_id = match tunnel_response {
            TsgMessage::TunnelResponse(response) => {
                ensure!(
                    response.status_code == 0,
                    "tunnel create failed: {:?}",
                    response
                );
                ensure!(response.tunnel_id != 0, "server returned tunnel_id 0");
                response.tunnel_id
            }
            other => bail!("expected TunnelResponse, got {other:?}"),
        };

        let tunnel_auth_response = send_and_expect(
            &mut websocket,
            encode_message(|buf| {
                TunnelAuth {
                    fields_present: 0,
                    client_name: TEST_CLIENT_NAME.to_string(),
                }
                .write(buf)
            }),
        )
        .await?;
        match tunnel_auth_response {
            TsgMessage::TunnelAuthResponse(response) => {
                ensure!(
                    response.error_code == 0,
                    "tunnel auth failed: {:?}",
                    response
                );
            }
            other => bail!("expected TunnelAuthResponse, got {other:?}"),
        }

        let channel_response = send_and_expect(
            &mut websocket,
            encode_message(|buf| {
                ChannelCreate {
                    num_resources: 1,
                    num_alt_resources: 0,
                    port: 3389,
                    protocol: 0,
                    server_name: TEST_SERVER_NAME.to_string(),
                }
                .write(buf)
            }),
        )
        .await?;
        match channel_response {
            TsgMessage::ChannelResponse(response) => {
                ensure!(
                    response.error_code == 0,
                    "channel create failed: {:?}",
                    response
                );
                ensure!(response.channel_id != 0, "server returned channel_id 0");
                ensure!(
                    response.flags == 0x0007,
                    "unexpected channel flags: {:?}",
                    response
                );
            }
            other => bail!("expected ChannelResponse, got {other:?}"),
        }

        sleep(Duration::from_millis(250)).await;
        let logs = server.logs().await;
        ensure!(
            logs.contains("TSG handshake complete, awaiting data for relay to localhost:3389"),
            "server never reached data transfer state after tunnel {tunnel_id}; logs:\n{logs}"
        );

        websocket.close(None).await.context("close websocket")?;
        Ok::<(), anyhow::Error>(())
    }
    .await;

    let logs = server.shutdown().await;
    match test_result {
        Ok(()) => Ok(()),
        Err(error) => Err(anyhow!("{error}\nserver logs:\n{logs}")),
    }
}

struct TestServer {
    child: Child,
    stdout_task: JoinHandle<()>,
    stderr_task: JoinHandle<()>,
    logs: Arc<Mutex<String>>,
    artifact_dir: PathBuf,
    cert_pem: Vec<u8>,
}

impl TestServer {
    async fn spawn() -> Result<Self> {
        let artifact_dir = artifact_dir()?;
        std::fs::create_dir_all(&artifact_dir)
            .with_context(|| format!("create {}", artifact_dir.display()))?;

        let certified = generate_simple_self_signed(vec![
            TEST_SERVER_NAME.to_string(),
            "127.0.0.1".to_string(),
        ])?;
        let cert_pem = certified.cert.pem();
        let key_pem = certified.key_pair.serialize_pem();

        let cert_path = artifact_dir.join("gateway-cert.pem");
        let key_path = artifact_dir.join("gateway-key.pem");
        let config_path = artifact_dir.join("rdg-gateway.toml");
        let db_path = artifact_dir.join("rdg-gateway-test.db");

        std::fs::write(&cert_path, cert_pem.as_bytes())
            .with_context(|| format!("write {}", cert_path.display()))?;
        std::fs::write(&key_path, key_pem.as_bytes())
            .with_context(|| format!("write {}", key_path.display()))?;
        std::fs::write(
            &config_path,
            format!(
                r#"listen_addr = "127.0.0.1"
listen_port = {TEST_PORT}
server_name = "{TEST_SERVER_NAME}"

[tls]
cert_path = "gateway-cert.pem"
key_path = "gateway-key.pem"
auto_generate = false

[database]
url = "sqlite://rdg-gateway-test.db?mode=rwc"

[auth]
open_mode = true
"#
            ),
        )
        .with_context(|| format!("write {}", config_path.display()))?;

        if db_path.exists() {
            std::fs::remove_file(&db_path)
                .with_context(|| format!("remove {}", db_path.display()))?;
        }

        let mut child = Command::new(server_binary()?)
            .current_dir(&artifact_dir)
            .env("RDG_CONFIG", &config_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("spawn rdg-server")?;

        let logs = Arc::new(Mutex::new(String::new()));
        let stdout = child.stdout.take().context("take stdout")?;
        let stderr = child.stderr.take().context("take stderr")?;

        let stdout_task = spawn_log_task(stdout, Arc::clone(&logs));
        let stderr_task = spawn_log_task(stderr, Arc::clone(&logs));

        Ok(Self {
            child,
            stdout_task,
            stderr_task,
            logs,
            artifact_dir,
            cert_pem: cert_pem.into_bytes(),
        })
    }

    async fn logs(&self) -> String {
        self.logs.lock().await.clone()
    }

    async fn shutdown(mut self) -> String {
        let _ = self.child.start_kill();
        let _ = timeout(Duration::from_secs(5), self.child.wait()).await;
        let _ = self.stdout_task.await;
        let _ = self.stderr_task.await;
        let logs = self.logs.lock().await.clone();
        let _ = std::fs::remove_dir_all(&self.artifact_dir);
        logs
    }
}

fn spawn_log_task<R>(reader: R, logs: Arc<Mutex<String>>) -> JoinHandle<()>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut lines = BufReader::new(reader).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let mut collected = logs.lock().await;
            collected.push_str(&line);
            collected.push('\n');
        }
    })
}

async fn wait_for_server(port: u16, server: &mut TestServer) -> Result<()> {
    for _ in 0..100 {
        match TcpStream::connect(("127.0.0.1", port)).await {
            Ok(stream) => {
                drop(stream);
                return Ok(());
            }
            Err(_) => {
                if let Some(status) = server.child.try_wait().context("check server status")? {
                    let logs = server.logs().await;
                    bail!("rdg-server exited early with {status}; logs:\n{logs}");
                }
                sleep(Duration::from_millis(100)).await;
            }
        }
    }

    let logs = server.logs().await;
    bail!("timed out waiting for rdg-server to listen on {port}; logs:\n{logs}")
}

fn reqwest_client(cert_pem: &[u8]) -> Result<reqwest::Client> {
    let cert = Certificate::from_pem(cert_pem).context("parse reqwest test certificate")?;
    reqwest::Client::builder()
        .add_root_certificate(cert)
        .build()
        .context("build reqwest client")
}

async fn fetch_ntlm_challenge(client: &reqwest::Client) -> Result<Vec<u8>> {
    // Axum's WebSocketUpgrade extractor validates RFC 6455 headers before the handler runs,
    // so the NTLM bootstrap request needs to look like a WebSocket upgrade attempt.
    let response = client
        .get(format!("https://{TEST_SERVER_NAME}:{TEST_PORT}{TEST_PATH}"))
        .header(CONNECTION, "Upgrade")
        .header(UPGRADE, "websocket")
        .header(SEC_WEBSOCKET_VERSION, "13")
        .header(SEC_WEBSOCKET_KEY, "dGVzdGtleXRlc3RrZXkxMg==")
        .header(AUTHORIZATION, format!("Negotiate {}", type1_token()))
        .send()
        .await
        .context("send NTLM negotiate request")?;

    ensure!(
        response.status() == StatusCode::UNAUTHORIZED,
        "expected 401 for NTLM challenge, got {}",
        response.status()
    );

    let header = response
        .headers()
        .get(WWW_AUTHENTICATE)
        .context("missing WWW-Authenticate header")?
        .to_str()
        .context("invalid WWW-Authenticate header")?;
    let token = header
        .strip_prefix("Negotiate ")
        .context("WWW-Authenticate did not contain Negotiate challenge")?;

    base64::engine::general_purpose::STANDARD
        .decode(token)
        .context("decode NTLM challenge")
}

async fn connect_gateway_websocket(
    cert_pem: &[u8],
) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>> {
    let mut roots = RootCertStore::empty();
    for certificate in rustls_pemfile::certs(&mut Cursor::new(cert_pem)) {
        roots
            .add(certificate.context("parse PEM certificate")?)
            .context("add test certificate to root store")?;
    }

    let tls = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let mut request =
        format!("wss://{TEST_SERVER_NAME}:{TEST_PORT}{TEST_PATH}").into_client_request()?;
    request.headers_mut().insert(
        "Authorization",
        HeaderValue::from_str(&format!("Negotiate {}", type3_token("rdg-test-user")))?,
    );

    // Axum's HTTP/1.1 WebSocket upgrade extractor only accepts GET requests.
    let (websocket, response) =
        connect_async_tls_with_config(request, None, false, Some(Connector::Rustls(Arc::new(tls))))
            .await
            .context("perform websocket upgrade")?;

    ensure!(
        response.status() == StatusCode::SWITCHING_PROTOCOLS,
        "expected websocket upgrade, got {}",
        response.status()
    );

    Ok(websocket)
}

async fn send_and_expect(
    websocket: &mut WebSocketStream<MaybeTlsStream<TcpStream>>,
    payload: Vec<u8>,
) -> Result<TsgMessage> {
    websocket
        .send(Message::Binary(payload.into()))
        .await
        .context("send websocket binary frame")?;

    let frame = timeout(Duration::from_secs(5), websocket.next())
        .await
        .context("timed out waiting for websocket response")?
        .context("websocket closed before response")?
        .context("websocket read failed")?;

    let Message::Binary(data) = frame else {
        bail!("expected binary websocket response, got {frame:?}");
    };

    parse_message(&data).context("parse TSG response")
}

fn encode_message(write: impl FnOnce(&mut BytesMut)) -> Vec<u8> {
    let mut buf = BytesMut::new();
    write(&mut buf);
    buf.to_vec()
}

fn type1_token() -> String {
    base64::engine::general_purpose::STANDARD.encode([
        0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x01, 0x00, 0x00, 0x00, 0xb7, 0x82, 0x08,
        0x62, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x0a, 0x00, 0xf4, 0x65, 0x00, 0x00, 0x00, 0x0f,
    ])
}

fn type3_token(username: &str) -> String {
    let username_utf16: Vec<u8> = username
        .encode_utf16()
        .flat_map(|ch| ch.to_le_bytes())
        .collect();
    let payload_offset = 64u32;

    let mut message = Vec::with_capacity(payload_offset as usize + username_utf16.len());
    message.extend_from_slice(b"NTLMSSP\0");
    message.extend_from_slice(&3u32.to_le_bytes());
    message.extend_from_slice(&security_buffer(0, payload_offset));
    message.extend_from_slice(&security_buffer(0, payload_offset));
    message.extend_from_slice(&security_buffer(0, payload_offset));
    message.extend_from_slice(&security_buffer(
        username_utf16.len() as u16,
        payload_offset,
    ));
    message.extend_from_slice(&security_buffer(0, payload_offset));
    message.extend_from_slice(&security_buffer(0, payload_offset));
    message.extend_from_slice(&0x0000_0001u32.to_le_bytes());
    message.extend_from_slice(&username_utf16);

    base64::engine::general_purpose::STANDARD.encode(message)
}

fn security_buffer(length: u16, offset: u32) -> [u8; 8] {
    let mut buffer = [0u8; 8];
    buffer[0..2].copy_from_slice(&length.to_le_bytes());
    buffer[2..4].copy_from_slice(&length.to_le_bytes());
    buffer[4..8].copy_from_slice(&offset.to_le_bytes());
    buffer
}

fn artifact_dir() -> Result<PathBuf> {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .context("resolve workspace root")?;
    let unique = format!(
        "websocket-gateway-handshake-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("read system clock")?
            .as_millis()
    );
    Ok(workspace_root
        .join("target")
        .join("integration-tests")
        .join(unique))
}

fn server_binary() -> Result<PathBuf> {
    if let Some(path) = env::var_os("CARGO_BIN_EXE_rdg-server") {
        return Ok(PathBuf::from(path));
    }

    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .context("resolve workspace root")?;

    for candidate in [
        workspace_root
            .join("target")
            .join("release")
            .join("rdg-server.exe"),
        workspace_root
            .join("target")
            .join("debug")
            .join("rdg-server.exe"),
    ] {
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    bail!("rdg-server binary not found")
}

fn install_crypto_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}
