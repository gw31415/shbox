//! WebSocket transport integration tests (`ws` feature).
//!
//! Each test starts the real daemon binary on a `ws://` listener and drives
//! it with a real WebSocket client: the upgrade must select the `ssh`
//! subprotocol, frames must be binary only, and the SSH byte stream (here
//! observed as the server identification banner) must flow through the
//! endpoint transparently. The daemon's own XDG tree is disposable.

#![cfg(feature = "ws")]

use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};

/// Start the daemon on a WebSocket listener at the chosen port and wait
/// until it accepts TCP connections.
fn start_daemon_ws(port: u16) -> Child {
    let home = tempfile::TempDir::new().expect("tempdir");
    // The daemon refuses to start without accepted keys; install a
    // throwaway one in the disposable HOME.
    let key_dir = home.path().join(".ssh");
    std::fs::create_dir_all(&key_dir).expect("create .ssh");
    let key = key_dir.join("id_ed25519");
    let status = Command::new("ssh-keygen")
        .arg("-q")
        .arg("-t")
        .arg("ed25519")
        .arg("-N")
        .arg("")
        .arg("-f")
        .arg(&key)
        .status()
        .expect("ssh-keygen runs");
    assert!(status.success(), "ssh-keygen failed");
    std::fs::copy(key.with_extension("pub"), key_dir.join("authorized_keys"))
        .expect("install authorized_keys");
    let mut child = Command::new(env!("CARGO_BIN_EXE_shbox"))
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join("config"))
        .env("XDG_DATA_HOME", home.path().join("data"))
        .env("XDG_STATE_HOME", home.path().join("state"))
        .arg("--listen")
        .arg(format!("ws://127.0.0.1:{port}/ssh"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("daemon starts");
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if std::net::TcpStream::connect_timeout(
            &SocketAddr::from(([127, 0, 0, 1], port)),
            Duration::from_millis(200),
        )
        .is_ok()
        {
            return child;
        }
        if let Ok(Some(status)) = child.try_wait() {
            panic!("daemon exited before listening: {status}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("daemon did not start listening");
}

fn free_port() -> u16 {
    std::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .expect("bind :0")
        .local_addr()
        .expect("local addr")
        .port()
}

async fn connect_ssh_ws(
    port: u16,
    path: &str,
    subprotocol: Option<&str>,
) -> Result<WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>, String> {
    let url = format!("ws://127.0.0.1:{port}{path}");
    let mut request = url
        .as_str()
        .into_client_request()
        .map_err(|err| format!("client request: {err}"))?;
    if let Some(subprotocol) = subprotocol {
        request.headers_mut().insert(
            "sec-websocket-protocol",
            subprotocol
                .parse()
                .expect("static subprotocol header value"),
        );
    }
    let (stream, response) = connect_async(request)
        .await
        .map_err(|err| format!("{err}"))?;
    assert_eq!(
        response
            .headers()
            .get("sec-websocket-protocol")
            .and_then(|value| value.to_str().ok()),
        // A successful upgrade always confirms `ssh`; a client that asked
        // for nothing or something else must not get this far.
        if subprotocol.is_some() && subprotocol != Some("chatv2") {
            Some("ssh")
        } else {
            None
        }
    );
    Ok(stream)
}

#[tokio::test]
async fn ws_upgrade_and_banner_roundtrip() {
    // Bind the daemon, then find its port from the outside by connecting to
    // the port we chose before starting it.
    let port = free_port();
    let mut child = start_daemon_ws(port);

    let mut stream = connect_ssh_ws(port, "/ssh", Some("ssh"))
        .await
        .expect("upgrade with the ssh subprotocol");

    // Open the SSH version exchange with a client identification string;
    // the server's reply must arrive as a binary frame.
    stream
        .send(Message::Binary(
            b"SSH-2.0-ws_transport_test\r\n".to_vec().into(),
        ))
        .await
        .expect("client banner frame");
    let banner = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("banner within timeout")
        .expect("stream stays open")
        .expect("banner frame");
    match banner {
        Message::Binary(bytes) => {
            let text = String::from_utf8_lossy(&bytes).to_string();
            assert!(text.starts_with("SSH-2.0-"), "banner: {text}");
        }
        other => panic!("banner must be a binary frame, got {other:?}"),
    }

    // A client text frame is not part of the transport and must be refused:
    // the server errors the SSH stream once it reads the frame, which the
    // follow-up binary frame prompts.
    stream.send(Message::Text("not ssh".into())).await.unwrap();
    stream
        .send(Message::Binary(b"prompt-read\r\n".to_vec().into()))
        .await
        .unwrap();
    // The server may emit queued binary frames before it reads the text
    // frame; keep reading until the stream errors or closes.
    let deadline = Duration::from_secs(5);
    let started = Instant::now();
    loop {
        let frame = tokio::time::timeout(deadline.saturating_sub(started.elapsed()), stream.next())
            .await
            .expect("text frame was ignored");
        match frame {
            None | Some(Err(_)) | Some(Ok(Message::Close(_))) => break,
            Some(Ok(Message::Binary(_))) => continue,
            Some(Ok(other)) => panic!("unexpected frame after text: {other:?}"),
        }
    }

    let _ = child.kill();
    let _ = child.wait();
}

#[tokio::test]
async fn ws_upgrade_rejects_wrong_path_and_missing_subprotocol() {
    let port = free_port();
    let mut child = start_daemon_ws(port);

    // Wrong path with the right subprotocol.
    let wrong_path = connect_ssh_ws(port, "/other", Some("ssh")).await;
    assert!(wrong_path.is_err(), "wrong path must not upgrade");
    // Right path without any subprotocol.
    let no_protocol = connect_ssh_ws(port, "/ssh", None).await;
    assert!(no_protocol.is_err(), "missing subprotocol must not upgrade");
    // Right path with an unrelated subprotocol.
    let wrong_protocol = connect_ssh_ws(port, "/ssh", Some("chatv2")).await;
    assert!(
        wrong_protocol.is_err(),
        "unrelated subprotocol must not upgrade"
    );

    let _ = child.kill();
    let _ = child.wait();
}
