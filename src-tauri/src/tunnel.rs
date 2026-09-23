//! 内置 SSH 隧道（等效 ssh -L）：本地监听 127.0.0.1:local_port，
//! 每条连接经 SSH 跳板机开一个 direct-tcpip 通道转发到 remote_host:remote_port。
//! 断线自动重连（5s 间隔），直到任务被 abort。

use serde::Serialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::copy_bidirectional;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::{push_log, LogBuf};

/// 已解析的服务器连接信息（来自「SSH 服务器」配置，可与多条隧道复用）
#[derive(Clone)]
pub struct ServerConn {
    pub host: String,
    pub port: u16,
    pub user: String,
    /// "password" | "key"
    pub auth_method: String,
    pub password: String,
    pub key_path: String,
    pub key_passphrase: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelInfo {
    pub id: String,
    /// stopped | connecting | connected | error
    pub state: String,
    pub error: Option<String>,
}

pub type TunnelStates = Arc<Mutex<HashMap<String, TunnelInfo>>>;

pub fn set_state(states: &TunnelStates, id: &str, state: &str, error: Option<String>) {
    states.lock().unwrap().insert(
        id.to_string(),
        TunnelInfo {
            id: id.to_string(),
            state: state.to_string(),
            error,
        },
    );
}

struct SshHandler {
    logs: LogBuf,
    name: String,
}

impl russh::client::Handler for SshHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        use russh::keys::PublicKeyOrCertificate;
        // 接受任意主机密钥，但把指纹打进日志供人工核对
        let desc = match key {
            PublicKeyOrCertificate::PublicKey { key, .. } => {
                key.fingerprint(russh::keys::ssh_key::HashAlg::Sha256).to_string()
            }
            PublicKeyOrCertificate::Certificate(_) => "OpenSSH 证书".to_string(),
        };
        push_log(&self.logs, format!("隧道「{}」服务器主机密钥指纹: {}", self.name, desc));
        Ok(true)
    }
}

/// 启动一条隧道的守护任务：连接 → 监听转发；断开后 5 秒自动重连，直到任务被 abort
#[allow(clippy::too_many_arguments)]
pub fn spawn(
    id: String,
    name: String,
    server: ServerConn,
    local_port: u16,
    remote_host: String,
    remote_port: u16,
    logs: LogBuf,
    states: TunnelStates,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            set_state(&states, &id, "connecting", None);
            match run(&id, &name, &server, local_port, &remote_host, remote_port, &logs, &states).await {
                Ok(()) => break,
                Err(e) => {
                    set_state(&states, &id, "error", Some(e.clone()));
                    push_log(&logs, format!("隧道「{}」: {e}，5 秒后重连…", name));
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
        set_state(&states, &id, "stopped", None);
    })
}

#[allow(clippy::too_many_arguments)]
async fn run(
    id: &str,
    name: &str,
    server: &ServerConn,
    local_port: u16,
    remote_host: &str,
    remote_port: u16,
    logs: &LogBuf,
    states: &TunnelStates,
) -> Result<(), String> {
    let config = Arc::new(russh::client::Config {
        nodelay: true,
        keepalive_interval: Some(Duration::from_secs(15)),
        ..Default::default()
    });
    let handler = SshHandler {
        logs: logs.clone(),
        name: name.to_string(),
    };
    let mut session = russh::client::connect(config, (server.host.as_str(), server.port), handler)
        .await
        .map_err(|e| format!("连接 SSH 服务器 {}:{} 失败: {e}", server.host, server.port))?;

    let auth = if server.auth_method == "key" {
        let pass = if server.key_passphrase.is_empty() {
            None
        } else {
            Some(server.key_passphrase.as_str())
        };
        let key = russh::keys::load_secret_key(&server.key_path, pass)
            .map_err(|e| format!("读取密钥文件失败: {e}"))?;
        let hash = session
            .best_supported_rsa_hash()
            .await
            .map_err(|e| format!("协商 RSA 哈希算法失败: {e}"))?
            .flatten();
        session
            .authenticate_publickey(
                &server.user,
                russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), hash),
            )
            .await
            .map_err(|e| format!("密钥认证失败: {e}"))?
    } else {
        session
            .authenticate_password(&server.user, &server.password)
            .await
            .map_err(|e| format!("密码认证失败: {e}"))?
    };
    if !auth.success() {
        return Err("认证被拒绝（请检查用户名 / 密码 / 密钥）".into());
    }
    // channel_open_direct_tcpip 只需 &self，用 Arc 共享给各连接任务
    let session = Arc::new(session);

    let listener = TcpListener::bind(("127.0.0.1", local_port)).await.map_err(|e| {
        format!("本地端口 {local_port} 监听失败: {e}（端口被占用？请先关闭占用它的程序，如 XTerminal 的转发）")
    })?;

    let _ = id;
    set_state(states, id, "connected", None);
    push_log(
        logs,
        format!(
            "隧道「{}」已连接: 127.0.0.1:{} →（{}@{}:{}）→ {}:{}",
            name, local_port, server.user, server.host, server.port, remote_host, remote_port
        ),
    );

    loop {
        let (mut inbound, peer) = tokio::select! {
            r = listener.accept() => r.map_err(|e| format!("监听出错: {e}"))?,
            // 周期性检查会话存活（无流量时也能发现断线）
            _ = tokio::time::sleep(Duration::from_secs(30)) => {
                if session.is_closed() {
                    return Err("SSH 会话已断开".into());
                }
                continue;
            }
        };
        if session.is_closed() {
            return Err("SSH 会话已断开".into());
        }

        let h = session.clone();
        let logs = logs.clone();
        let name = name.to_string();
        let remote_host = remote_host.to_string();
        tokio::spawn(async move {
            match h
                .channel_open_direct_tcpip(remote_host, remote_port as u32, "127.0.0.1".to_string(), 0u32)
                .await
            {
                Ok(channel) => {
                    push_log(&logs, format!("隧道「{name}」转发连接 {peer}"));
                    let mut stream = channel.into_stream();
                    if let Err(e) = copy_bidirectional(&mut inbound, &mut stream).await {
                        push_log(&logs, format!("隧道「{name}」连接 {peer} 中断: {e}"));
                    }
                }
                Err(e) => push_log(&logs, format!("隧道「{name}」打开转发通道失败: {e}")),
            }
        });
    }
}
