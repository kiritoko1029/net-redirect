#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tauri::{Manager, State};
use tokio::task::JoinHandle;

#[cfg(target_os = "macos")]
use tokio::io::copy_bidirectional;
#[cfg(target_os = "macos")]
use tokio::net::{TcpListener, TcpStream};

mod tunnel;
use tunnel::{ServerConn, TunnelInfo, TunnelStates};

/// 一条重定向规则：访问 src_ip:src_port 的系统流量会被转发到 dst_host:dst_port
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Rule {
    id: String,
    name: String,
    src_ip: String,
    src_port: u16,
    dst_host: String,
    dst_port: u16,
    enabled: bool,
}

/// SSH 服务器连接（可被多条隧道复用）
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SshServer {
    id: String,
    name: String,
    host: String,
    port: u16,
    user: String,
    /// "password" | "key"
    auth_method: String,
    password: String,
    key_path: String,
    key_passphrase: String,
}

/// 一条 SSH 隧道：127.0.0.1:local_port →（server_id 指定的服务器）→ remote_host:remote_port
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Tunnel {
    id: String,
    name: String,
    server_id: String,
    local_port: u16,
    remote_host: String,
    remote_port: u16,
    enabled: bool,
}

/// v0.5.0 旧版隧道格式（内嵌服务器字段），用于配置迁移
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyTunnel {
    id: String,
    name: String,
    ssh_host: String,
    ssh_port: u16,
    ssh_user: String,
    auth_method: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    key_path: String,
    #[serde(default)]
    key_passphrase: String,
    local_port: u16,
    remote_host: String,
    remote_port: u16,
    enabled: bool,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ActiveRule {
    id: String,
    src_ip: String,
    src_port: u16,
    local_port: u16,
    /// true = 系统直接改写/转发，不占用本 App 的本地代理端口
    direct: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Status {
    running: bool,
    active: Vec<ActiveRule>,
    tunnels: Vec<TunnelInfo>,
    tunnels_running: bool,
}

type LogBuf = Arc<Mutex<VecDeque<String>>>;

struct AppState {
    rules: Mutex<Vec<Rule>>,
    running: Mutex<bool>,
    active: Mutex<Vec<ActiveRule>>,
    /// 仅 macOS 代理模式的规则在此有条目（直通规则及 Windows 平台没有本地监听器）
    listeners: Mutex<HashMap<String, JoinHandle<()>>>,
    servers: Mutex<Vec<SshServer>>,
    tunnels: Mutex<Vec<Tunnel>>,
    tunnel_tasks: Mutex<HashMap<String, JoinHandle<()>>>,
    tunnel_states: TunnelStates,
    logs: LogBuf,
    rules_path: PathBuf,
    servers_path: PathBuf,
    tunnels_path: PathBuf,
    /// 仅 macOS 使用（pf anchor 规则文件）
    #[allow(dead_code)]
    anchor_path: PathBuf,
}

fn push_log(logs: &LogBuf, msg: impl AsRef<str>) {
    let mut buf = logs.lock().unwrap();
    buf.push_back(format!(
        "[{}] {}",
        chrono::Local::now().format("%H:%M:%S"),
        msg.as_ref()
    ));
    while buf.len() > 500 {
        buf.pop_front();
    }
}

fn validate_rule(rule: &Rule) -> Result<(), String> {
    rule.src_ip
        .parse::<Ipv4Addr>()
        .map_err(|_| format!("源 IP「{}」不是有效的 IPv4 地址", rule.src_ip))?;
    if rule.src_port == 0 || rule.dst_port == 0 {
        return Err("端口必须在 1-65535 之间".into());
    }
    if rule.dst_host.trim().is_empty() {
        return Err("目标地址不能为空".into());
    }
    Ok(())
}

fn validate_server(s: &SshServer) -> Result<(), String> {
    if s.host.trim().is_empty() {
        return Err("SSH 主机不能为空".into());
    }
    if s.user.trim().is_empty() {
        return Err("用户名不能为空".into());
    }
    if s.port == 0 {
        return Err("端口必须在 1-65535 之间".into());
    }
    if s.auth_method == "key" && s.key_path.trim().is_empty() {
        return Err("密钥认证需要填写密钥文件路径".into());
    }
    if s.auth_method == "password" && s.password.is_empty() {
        return Err("密码认证需要填写密码".into());
    }
    Ok(())
}

fn validate_tunnel(t: &Tunnel, state: &AppState) -> Result<(), String> {
    if t.local_port == 0 || t.remote_port == 0 {
        return Err("端口必须在 1-65535 之间".into());
    }
    if t.remote_host.trim().is_empty() {
        return Err("远端地址不能为空".into());
    }
    if t.server_id.is_empty() || !state.servers.lock().unwrap().iter().any(|s| s.id == t.server_id) {
        return Err("请选择一个 SSH 服务器连接（没有的话先在上方添加）".into());
    }
    Ok(())
}

impl From<&SshServer> for ServerConn {
    fn from(s: &SshServer) -> Self {
        ServerConn {
            host: s.host.clone(),
            port: s.port,
            user: s.user.clone(),
            auth_method: s.auth_method.clone(),
            password: s.password.clone(),
            key_path: s.key_path.clone(),
            key_passphrase: s.key_passphrase.clone(),
        }
    }
}

/// 启动所有启用的隧道（失败只记日志，不阻断）
fn start_tunnels(state: &AppState) {
    let tunnels: Vec<Tunnel> = {
        let list = state.tunnels.lock().unwrap();
        list.iter().filter(|t| t.enabled).cloned().collect()
    };
    let servers: Vec<SshServer> = state.servers.lock().unwrap().clone();
    let mut tasks = state.tunnel_tasks.lock().unwrap();
    for t in tunnels {
        if tasks.contains_key(&t.id) {
            continue;
        }
        let Some(server) = servers.iter().find(|s| s.id == t.server_id) else {
            tunnel::set_state(&state.tunnel_states, &t.id, "error", Some("引用的服务器连接不存在".into()));
            push_log(&state.logs, format!("隧道「{}」引用的服务器连接不存在，已跳过", t.name));
            continue;
        };
        tunnel::set_state(&state.tunnel_states, &t.id, "connecting", None);
        let handle = tunnel::spawn(
            t.id.clone(),
            t.name.clone(),
            ServerConn::from(server),
            t.local_port,
            t.remote_host.clone(),
            t.remote_port,
            state.logs.clone(),
            state.tunnel_states.clone(),
        );
        tasks.insert(t.id.clone(), handle);
    }
}

fn stop_tunnels(state: &AppState) {
    {
        let mut tasks = state.tunnel_tasks.lock().unwrap();
        for (_, h) in tasks.drain() {
            h.abort();
        }
    }
    let mut states = state.tunnel_states.lock().unwrap();
    for (_, s) in states.iter_mut() {
        s.state = "stopped".into();
        s.error = None;
    }
}

// ============================ macOS (pf + 本地代理/直通) ============================

#[cfg(target_os = "macos")]
mod imp {
    use super::*;

    /// pf anchor 名称：必须挂在主规则集已引用的 com.apple/* 命名空间下，
    /// 否则 anchor 只是加载了却不会被评估（pf 只评估主规则集中 anchor/rdr-anchor 引用的规则集）
    const PF_ANCHOR: &str = "com.apple/netredirect";

    /// 目标为本机回环地址时返回 Some(目标端口)：pf 可以直接改写目的地，无需本地代理
    fn direct_target(rule: &Rule) -> Option<u16> {
        let host = rule.dst_host.trim();
        if host.eq_ignore_ascii_case("localhost") {
            return Some(rule.dst_port);
        }
        match host.parse::<Ipv4Addr>() {
            Ok(ip) if ip.is_loopback() => Some(rule.dst_port),
            _ => None,
        }
    }

    /// 启动重定向所需的 root 命令（与 sudoers 免密条目一一对应）
    fn privileged_start_cmds(anchor_path: &std::path::Path) -> Vec<Vec<String>> {
        vec![
            vec![
                "/usr/sbin/sysctl".into(),
                "-w".into(),
                "net.inet.ip.forwarding=1".into(),
            ],
            vec![
                "/sbin/pfctl".into(),
                "-a".into(),
                PF_ANCHOR.into(),
                "-f".into(),
                anchor_path.to_string_lossy().into_owned(),
            ],
            vec!["/sbin/pfctl".into(), "-E".into()],
        ]
    }

    fn privileged_stop_cmds() -> Vec<Vec<String>> {
        vec![vec![
            "/sbin/pfctl".into(),
            "-a".into(),
            PF_ANCHOR.into(),
            "-F".into(),
            "all".into(),
        ]]
    }

    /// 以管理员权限执行 shell 命令（macOS 弹出授权对话框，不会缓存授权）
    fn run_privileged(shell: &str) -> Result<(), String> {
        let escaped = shell.replace('\\', "\\\\").replace('"', "\\\"");
        let script = format!("do shell script \"{escaped}\" with administrator privileges");
        let output = std::process::Command::new("osascript")
            .arg("-e")
            .arg(&script)
            .output()
            .map_err(|e| format!("无法请求管理员权限: {e}"))?;
        if output.status.success() {
            Ok(())
        } else {
            let err = String::from_utf8_lossy(&output.stderr).trim().to_string();
            if err.contains("User canceled") {
                Err("用户取消了授权".into())
            } else {
                Err(format!("系统命令执行失败: {err}"))
            }
        }
    }

    /// 检查这些命令是否已配置 sudo 免密（sudo -n -l 纯查询，无副作用）
    fn sudo_nopass_available(cmds: &[Vec<String>]) -> bool {
        cmds.iter().all(|cmd| {
            let mut args = vec!["-n".to_string(), "-l".to_string()];
            args.extend(cmd.iter().cloned());
            std::process::Command::new("/usr/bin/sudo")
                .args(&args)
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        })
    }

    /// 优先走 sudo 免密；未配置（或执行失败且 strict）时回退到 osascript 弹窗授权。
    /// strict=false 时忽略命令本身的退出码（与 shell 版 `|| true` 语义一致）。
    fn run_privileged_auto(
        cmds: &[Vec<String>],
        shell: &str,
        logs: &LogBuf,
        strict: bool,
    ) -> Result<(), String> {
        if sudo_nopass_available(cmds) {
            for cmd in cmds {
                match std::process::Command::new("/usr/bin/sudo")
                    .arg("-n")
                    .args(cmd)
                    .output()
                {
                    Ok(out) if out.status.success() => {}
                    Ok(out) => {
                        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
                        // pf 已启用时 pfctl -E 报错属正常
                        if stderr.contains("already enabled") {
                            continue;
                        }
                        if strict {
                            push_log(logs, format!("sudo 免密执行失败，回退到授权弹窗: {stderr}"));
                            return run_privileged(shell);
                        }
                    }
                    Err(e) => {
                        if strict {
                            push_log(logs, format!("无法执行 sudo，回退到授权弹窗: {e}"));
                            return run_privileged(shell);
                        }
                    }
                }
            }
            return Ok(());
        }
        run_privileged(shell)
    }

    pub fn nopass_configured(state: &AppState) -> bool {
        let mut cmds = privileged_start_cmds(&state.anchor_path);
        cmds.extend(privileged_stop_cmds());
        sudo_nopass_available(&cmds)
    }

    /// 写入 /etc/sudoers.d/netredirect：仅放行加载/清除 pf 规则所需的固定命令。
    pub fn setup_nopass(state: &AppState) -> Result<(), String> {
        let user = std::env::var("USER").map_err(|_| "无法获取当前用户名".to_string())?;
        let content = format!(
            "# Net Redirect: 允许无密码执行加载/清除重定向规则所需的命令\n{user} ALL=(root) NOPASSWD: /usr/sbin/sysctl -w net.inet.ip.forwarding=1, /sbin/pfctl -a {PF_ANCHOR} -f *, /sbin/pfctl -a {PF_ANCHOR} -F all, /sbin/pfctl -E\n"
        );
        let tmp = std::env::temp_dir().join("netredirect-sudoers");
        std::fs::write(&tmp, content).map_err(|e| format!("写入临时文件失败: {e}"))?;
        let shell = format!(
            "/usr/sbin/visudo -c -f '{}' >/dev/null && /usr/bin/install -o root -g wheel -m 0440 '{}' /etc/sudoers.d/netredirect",
            tmp.display(),
            tmp.display()
        );
        push_log(
            &state.logs,
            "请求管理员权限以写入 /etc/sudoers.d/netredirect（仅此一次）…",
        );
        run_privileged(&shell)?;
        if nopass_configured(state) {
            push_log(&state.logs, "免密配置成功，之后启动/停止/退出不再弹窗");
            Ok(())
        } else {
            Err("sudoers 已写入但验证未通过，请检查 /etc/sudoers.d/netredirect".into())
        }
    }

    pub async fn platform_start(state: &AppState, rules: &[Rule]) -> Result<Vec<ActiveRule>, String> {
        // 1. 目标为本机回环地址的规则由 pf 直接改写目的地（直通）；
        //    其余规则各绑定一个本地监听端口，由内置 TCP 代理转发
        let mut bindings = Vec::new();
        for r in rules {
            match direct_target(r) {
                Some(port) => bindings.push((r.clone(), None, port)),
                None => {
                    let listener = TcpListener::bind(("127.0.0.1", 0))
                        .await
                        .map_err(|e| format!("本地监听失败: {e}"))?;
                    let local_port = listener.local_addr().map_err(|e| e.to_string())?.port();
                    bindings.push((r.clone(), Some(listener), local_port));
                }
            }
        }

        // 2. 生成 pf anchor 规则：
        //    - route-to 把发往源地址的流量强行送进 lo0（quick 确保不被其他 anchor 覆盖）
        //    - rdr 在 lo0 上把目的地改写到本地端口（直通时为 127.0.0.1:目标端口）
        let mut anchor = String::new();
        for (r, _, local_port) in &bindings {
            anchor.push_str(&format!(
                "rdr pass on lo0 inet proto tcp from any to {} port {} -> 127.0.0.1 port {}\npass out quick route-to (lo0 127.0.0.1) inet proto tcp from any to {} port {} keep state\n",
                r.src_ip, r.src_port, local_port, r.src_ip, r.src_port
            ));
        }
        std::fs::write(&state.anchor_path, &anchor).map_err(|e| format!("写入 pf 规则文件失败: {e}"))?;

        // 3. 提权加载 pf 规则并开启转发（已配置免密时不弹窗）
        let cmds = privileged_start_cmds(&state.anchor_path);
        let shell = format!(
            "/usr/sbin/sysctl -w net.inet.ip.forwarding=1 >/dev/null && /sbin/pfctl -a '{PF_ANCHOR}' -f '{}' && (/sbin/pfctl -E >/dev/null 2>&1 || true)",
            state.anchor_path.display()
        );
        let nopass = sudo_nopass_available(&cmds);
        push_log(
            &state.logs,
            if nopass {
                "通过 sudo 免密加载系统重定向规则 (pf)…"
            } else {
                "请求管理员权限以加载系统重定向规则 (pf)…"
            },
        );
        if let Err(e) = run_privileged_auto(&cmds, &shell, &state.logs, true) {
            push_log(&state.logs, format!("加载系统规则失败: {e}"));
            return Err(format!("加载系统规则失败: {e}"));
        }
        push_log(&state.logs, "系统规则加载成功");

        // 4. 启动代理模式的转发循环，登记所有已生效规则
        let mut active = Vec::new();
        for (r, listener, local_port) in bindings {
            let direct = listener.is_none();
            if let Some(listener) = listener {
                let handle = tokio::spawn(accept_loop(
                    listener,
                    r.dst_host.clone(),
                    r.dst_port,
                    state.logs.clone(),
                    r.name.clone(),
                ));
                state.listeners.lock().unwrap().insert(r.id.clone(), handle);
                push_log(
                    &state.logs,
                    format!(
                        "规则「{}」已生效: {}:{} → {}:{}（本地端口 {}）",
                        r.name, r.src_ip, r.src_port, r.dst_host, r.dst_port, local_port
                    ),
                );
            } else {
                push_log(
                    &state.logs,
                    format!(
                        "规则「{}」已生效（直通模式，无本地代理端口）: {}:{} → 127.0.0.1:{}",
                        r.name, r.src_ip, r.src_port, local_port
                    ),
                );
            }
            active.push(ActiveRule {
                id: r.id.clone(),
                src_ip: r.src_ip.clone(),
                src_port: r.src_port,
                local_port,
                direct,
            });
        }
        Ok(active)
    }

    async fn accept_loop(listener: TcpListener, dst_host: String, dst_port: u16, logs: LogBuf, name: String) {
        loop {
            let (mut inbound, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    push_log(&logs, format!("规则「{name}」监听出错: {e}"));
                    break;
                }
            };
            let logs = logs.clone();
            let dst_host = dst_host.clone();
            let name = name.clone();
            tokio::spawn(async move {
                push_log(
                    &logs,
                    format!("规则「{name}」收到连接 {peer}，转发到 {dst_host}:{dst_port}"),
                );
                match TcpStream::connect((dst_host.as_str(), dst_port)).await {
                    Ok(mut outbound) => {
                        if let Err(e) = copy_bidirectional(&mut inbound, &mut outbound).await {
                            push_log(&logs, format!("规则「{name}」的连接 {peer} 中断: {e}"));
                        }
                    }
                    Err(e) => push_log(
                        &logs,
                        format!("规则「{name}」连接目标 {dst_host}:{dst_port} 失败: {e}"),
                    ),
                }
            });
        }
    }

    pub fn platform_stop(state: &AppState) -> Result<(), String> {
        let shell = "/sbin/pfctl -a 'com.apple/netredirect' -F all >/dev/null 2>&1 || true";
        run_privileged_auto(&privileged_stop_cmds(), shell, &state.logs, false)
    }
}

// ============================ Windows (回环别名 + netsh portproxy) ============================

#[cfg(target_os = "windows")]
mod imp {
    use super::*;
    use std::os::windows::process::CommandExt;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    fn run_hidden(program: &str, args: &[&str]) -> Result<std::process::Output, String> {
        std::process::Command::new(program)
            .args(args)
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| format!("无法执行 {program}: {e}"))
    }

    /// App 启动时自我提权（UAC 弹一次），之后所有 netsh/PowerShell 操作无需再弹窗
    pub fn ensure_elevated() {
        // net session 需要管理员权限，用来探测当前是否已提权
        let elevated = run_hidden("net", &["session"])
            .map(|o| o.status.success())
            .unwrap_or(false);
        if elevated {
            return;
        }
        if let Ok(exe) = std::env::current_exe() {
            let script = format!("Start-Process -FilePath '{}' -Verb RunAs", exe.display());
            let _ = run_hidden("powershell", &["-NoProfile", "-Command", &script]);
        }
        std::process::exit(0);
    }

    /// 把源 IP 以 /32 加到回环接口，使发往该 IP 的流量落到本机。
    /// SkipAsSource 防止 Windows 把它当作出站连接的源地址。
    fn add_loopback_alias(ip: &str) -> Result<(), String> {
        let script = format!(
            "$idx = (Get-NetIPAddress -IPAddress 127.0.0.1 -AddressFamily IPv4).InterfaceIndex; \
             if (-not (Get-NetIPAddress -InterfaceIndex $idx -IPAddress {ip} -ErrorAction SilentlyContinue)) {{ \
               New-NetIPAddress -InterfaceIndex $idx -IPAddress {ip} -PrefixLength 32 -SkipAsSource $true | Out-Null \
             }}"
        );
        let out = run_hidden("powershell", &["-NoProfile", "-NonInteractive", "-Command", &script])?;
        if out.status.success() {
            Ok(())
        } else {
            Err(format!(
                "添加回环地址 {ip} 失败: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        }
    }

    fn remove_loopback_alias(ip: &str) -> Result<(), String> {
        let script = format!(
            "$idx = (Get-NetIPAddress -IPAddress 127.0.0.1 -AddressFamily IPv4).InterfaceIndex; \
             Remove-NetIPAddress -InterfaceIndex $idx -IPAddress {ip} -Confirm:$false -ErrorAction SilentlyContinue"
        );
        let out = run_hidden("powershell", &["-NoProfile", "-NonInteractive", "-Command", &script])?;
        if out.status.success() {
            Ok(())
        } else {
            Err(format!(
                "删除回环地址 {ip} 失败: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        }
    }

    fn portproxy_add(r: &Rule) -> Result<(), String> {
        let out = run_hidden(
            "netsh",
            &[
                "interface",
                "portproxy",
                "add",
                "v4tov4",
                &format!("listenaddress={}", r.src_ip),
                &format!("listenport={}", r.src_port),
                &format!("connectaddress={}", r.dst_host),
                &format!("connectport={}", r.dst_port),
            ],
        )?;
        if out.status.success() {
            Ok(())
        } else {
            Err(format!(
                "portproxy 规则添加失败（{}:{} → {}:{}）: {}{}",
                r.src_ip,
                r.src_port,
                r.dst_host,
                r.dst_port,
                String::from_utf8_lossy(&out.stdout).trim(),
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        }
    }

    fn portproxy_delete(src_ip: &str, src_port: u16) {
        let _ = run_hidden(
            "netsh",
            &[
                "interface",
                "portproxy",
                "delete",
                "v4tov4",
                &format!("listenaddress={src_ip}"),
                &format!("listenport={src_port}"),
            ],
        );
    }

    pub fn nopass_configured(_state: &AppState) -> bool {
        // Windows 版启动时已整体提权（UAC），无需免密配置
        true
    }

    pub fn setup_nopass(_state: &AppState) -> Result<(), String> {
        Ok(())
    }

    pub async fn platform_start(state: &AppState, rules: &[Rule]) -> Result<Vec<ActiveRule>, String> {
        // portproxy 依赖 IP Helper 服务
        let _ = run_hidden("net", &["start", "iphlpsvc"]);

        let mut active: Vec<ActiveRule> = Vec::new();
        for r in rules {
            let applied = (|| {
                add_loopback_alias(&r.src_ip)?;
                portproxy_add(r)
            })();
            if let Err(e) = applied {
                // 回滚本次已添加的内容
                for a in &active {
                    portproxy_delete(&a.src_ip, a.src_port);
                    if !rules.iter().any(|x| x.src_ip == a.src_ip && x.id != a.id) {
                        let _ = remove_loopback_alias(&a.src_ip);
                    }
                }
                return Err(e);
            }
            push_log(
                &state.logs,
                format!(
                    "规则「{}」已生效（系统 portproxy 转发）: {}:{} → {}:{}",
                    r.name, r.src_ip, r.src_port, r.dst_host, r.dst_port
                ),
            );
            active.push(ActiveRule {
                id: r.id.clone(),
                src_ip: r.src_ip.clone(),
                src_port: r.src_port,
                local_port: r.dst_port,
                direct: true,
            });
        }
        Ok(active)
    }

    pub fn platform_stop(state: &AppState) -> Result<(), String> {
        let actives = state.active.lock().unwrap().clone();
        let mut errors = Vec::new();
        for a in &actives {
            portproxy_delete(&a.src_ip, a.src_port);
            // 同一源 IP 可能被多条规则使用，只有最后一条删除时才移除回环别名
            if !actives.iter().any(|x| x.src_ip == a.src_ip && x.id != a.id) {
                if let Err(e) = remove_loopback_alias(&a.src_ip) {
                    errors.push(e);
                }
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("；"))
        }
    }
}

// ============================ 共享命令 ============================

#[tauri::command]
fn list_rules(state: State<AppState>) -> Vec<Rule> {
    state.rules.lock().unwrap().clone()
}

#[tauri::command]
fn save_rule(state: State<AppState>, mut rule: Rule) -> Result<Rule, String> {
    validate_rule(&rule)?;
    if *state.running.lock().unwrap() {
        return Err("重定向运行中，请先停止再修改规则".into());
    }
    if rule.id.is_empty() {
        rule.id = uuid::Uuid::new_v4().to_string();
    }
    {
        let mut rules = state.rules.lock().unwrap();
        if let Some(slot) = rules.iter_mut().find(|r| r.id == rule.id) {
            *slot = rule.clone();
        } else {
            rules.push(rule.clone());
        }
    }
    persist_rules(&state)?;
    push_log(
        &state.logs,
        format!(
            "已保存规则「{}」: {}:{} → {}:{}",
            rule.name, rule.src_ip, rule.src_port, rule.dst_host, rule.dst_port
        ),
    );
    Ok(rule)
}

#[tauri::command]
fn delete_rule(state: State<AppState>, id: String) -> Result<(), String> {
    if *state.running.lock().unwrap() {
        return Err("重定向运行中，请先停止再修改规则".into());
    }
    {
        let mut rules = state.rules.lock().unwrap();
        rules.retain(|r| r.id != id);
    }
    persist_rules(&state)
}

fn persist_rules(state: &AppState) -> Result<(), String> {
    let rules = state.rules.lock().unwrap();
    let json = serde_json::to_string_pretty(&*rules).map_err(|e| e.to_string())?;
    std::fs::write(&state.rules_path, json).map_err(|e| format!("保存规则文件失败: {e}"))
}

#[tauri::command]
fn list_servers(state: State<AppState>) -> Vec<SshServer> {
    state.servers.lock().unwrap().clone()
}

#[tauri::command]
fn save_server(state: State<AppState>, mut server: SshServer) -> Result<SshServer, String> {
    validate_server(&server)?;
    if *state.running.lock().unwrap() {
        return Err("重定向运行中，请先停止再修改服务器".into());
    }
    if server.id.is_empty() {
        server.id = uuid::Uuid::new_v4().to_string();
    }
    {
        let mut servers = state.servers.lock().unwrap();
        if let Some(slot) = servers.iter_mut().find(|s| s.id == server.id) {
            *slot = server.clone();
        } else {
            servers.push(server.clone());
        }
    }
    persist_servers(&state)?;
    push_log(
        &state.logs,
        format!("已保存服务器「{}」: {}@{}:{}", server.name, server.user, server.host, server.port),
    );
    Ok(server)
}

#[tauri::command]
fn delete_server(state: State<AppState>, id: String) -> Result<(), String> {
    if *state.running.lock().unwrap() {
        return Err("重定向运行中，请先停止再修改服务器".into());
    }
    let refs = state.tunnels.lock().unwrap().iter().filter(|t| t.server_id == id).count();
    if refs > 0 {
        return Err(format!("该服务器正被 {refs} 条隧道引用，请先删除或修改这些隧道"));
    }
    {
        let mut servers = state.servers.lock().unwrap();
        servers.retain(|s| s.id != id);
    }
    persist_servers(&state)
}

fn persist_servers(state: &AppState) -> Result<(), String> {
    let servers = state.servers.lock().unwrap();
    let json = serde_json::to_string_pretty(&*servers).map_err(|e| e.to_string())?;
    std::fs::write(&state.servers_path, json).map_err(|e| format!("保存服务器配置失败: {e}"))?;
    restrict_perms(&state.servers_path);
    Ok(())
}

#[tauri::command]
fn list_tunnels(state: State<AppState>) -> Vec<Tunnel> {
    state.tunnels.lock().unwrap().clone()
}

#[tauri::command]
fn save_tunnel(state: State<AppState>, mut tunnel: Tunnel) -> Result<Tunnel, String> {
    validate_tunnel(&tunnel, &state)?;
    if *state.running.lock().unwrap() {
        return Err("重定向运行中，请先停止再修改隧道".into());
    }
    if tunnel.id.is_empty() {
        tunnel.id = uuid::Uuid::new_v4().to_string();
    }
    {
        let mut tunnels = state.tunnels.lock().unwrap();
        if let Some(slot) = tunnels.iter_mut().find(|t| t.id == tunnel.id) {
            *slot = tunnel.clone();
        } else {
            tunnels.push(tunnel.clone());
        }
    }
    persist_tunnels(&state)?;
    push_log(
        &state.logs,
        format!(
            "已保存隧道「{}」: 127.0.0.1:{} → {}:{}",
            tunnel.name, tunnel.local_port, tunnel.remote_host, tunnel.remote_port
        ),
    );
    Ok(tunnel)
}

#[tauri::command]
fn delete_tunnel(state: State<AppState>, id: String) -> Result<(), String> {
    if *state.running.lock().unwrap() {
        return Err("重定向运行中，请先停止再修改隧道".into());
    }
    {
        let mut tunnels = state.tunnels.lock().unwrap();
        tunnels.retain(|t| t.id != id);
    }
    persist_tunnels(&state)
}

fn persist_tunnels(state: &AppState) -> Result<(), String> {
    let tunnels = state.tunnels.lock().unwrap();
    let json = serde_json::to_string_pretty(&*tunnels).map_err(|e| e.to_string())?;
    std::fs::write(&state.tunnels_path, json).map_err(|e| format!("保存隧道配置失败: {e}"))?;
    restrict_perms(&state.tunnels_path);
    Ok(())
}

/// 配置里可能含有 SSH 密码，收紧文件权限
fn restrict_perms(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
}

#[tauri::command]
fn get_status(state: State<AppState>) -> Status {
    Status {
        running: *state.running.lock().unwrap(),
        active: state.active.lock().unwrap().clone(),
        tunnels: state.tunnel_states.lock().unwrap().values().cloned().collect(),
        tunnels_running: !state.tunnel_tasks.lock().unwrap().is_empty(),
    }
}

#[tauri::command]
async fn start_tunnels_cmd(state: State<'_, AppState>) -> Result<(), String> {
    if !state.tunnels.lock().unwrap().iter().any(|t| t.enabled) {
        return Err("没有已启用的隧道，请先添加".into());
    }
    start_tunnels(&state);
    Ok(())
}

#[tauri::command]
fn stop_tunnels_cmd(state: State<AppState>) -> Result<(), String> {
    stop_tunnels(&state);
    push_log(&state.logs, "已停止全部隧道");
    Ok(())
}

#[tauri::command]
fn get_logs(state: State<AppState>) -> Vec<String> {
    state.logs.lock().unwrap().iter().cloned().collect()
}

#[tauri::command]
fn get_platform() -> &'static str {
    std::env::consts::OS
}

#[tauri::command]
fn passwordless_status(state: State<AppState>) -> bool {
    imp::nopass_configured(&state)
}

#[tauri::command]
fn setup_passwordless(state: State<AppState>) -> Result<(), String> {
    imp::setup_nopass(&state)
}

#[tauri::command]
async fn start_redirect(state: State<'_, AppState>) -> Result<Vec<ActiveRule>, String> {
    let rules: Vec<Rule> = {
        let rules = state.rules.lock().unwrap();
        rules.iter().filter(|r| r.enabled).cloned().collect()
    };
    if rules.is_empty() {
        return Err("没有已启用的规则，请先添加并启用至少一条规则".into());
    }
    if *state.running.lock().unwrap() {
        return Err("重定向已在运行中".into());
    }
    for r in &rules {
        validate_rule(r)?;
    }

    let active = imp::platform_start(&state, &rules).await?;
    *state.active.lock().unwrap() = active.clone();
    *state.running.lock().unwrap() = true;
    Ok(active)
}

#[tauri::command]
fn stop_redirect(state: State<AppState>) -> Result<(), String> {
    let was_running = {
        let mut running = state.running.lock().unwrap();
        let was = *running;
        *running = false;
        was
    };
    if !was_running {
        return Ok(());
    }
    {
        let mut map = state.listeners.lock().unwrap();
        for (_, h) in map.drain() {
            h.abort();
        }
    }
    state.active.lock().unwrap().clear();
    let result = imp::platform_stop(&state);
    result.map_err(|e| {
        push_log(&state.logs, format!("清除系统规则失败: {e}"));
        format!("清除系统规则失败: {e}（系统规则可能仍然生效，请重试停止）")
    })?;
    push_log(&state.logs, "已停止全部重定向并清除系统规则");
    Ok(())
}

/// 退出时若仍在运行，尽量清除系统规则，避免残留导致目标地址不可达
fn cleanup_on_exit(app: &tauri::AppHandle) {
    let state = app.state::<AppState>();
    let was_running = {
        let mut running = state.running.lock().unwrap();
        let was = *running;
        *running = false;
        was
    };
    if !was_running {
        return;
    }
    {
        let mut map = state.listeners.lock().unwrap();
        for (_, h) in map.drain() {
            h.abort();
        }
    }
    // cleanup 需要 active 列表（Windows 据此删除 portproxy 规则），此处不清空
    let _ = imp::platform_stop(&state);
    stop_tunnels(&state);
}

/// 读取隧道配置；旧版（内嵌 ssh 字段）自动迁移为「服务器 + 引用」格式
fn load_tunnels(
    tunnels_path: &std::path::Path,
    servers: &mut Vec<SshServer>,
    servers_path: &std::path::Path,
) -> Vec<Tunnel> {
    let Ok(raw) = std::fs::read_to_string(tunnels_path) else {
        return Vec::new();
    };
    let Ok(values) = serde_json::from_str::<Vec<serde_json::Value>>(&raw) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut migrated = false;
    for v in values {
        if v.get("serverId").is_some() {
            if let Ok(t) = serde_json::from_value::<Tunnel>(v) {
                out.push(t);
            }
        } else if v.get("sshHost").is_some() {
            if let Ok(lt) = serde_json::from_value::<LegacyTunnel>(v) {
                let server_id = servers
                    .iter()
                    .find(|s| s.host == lt.ssh_host && s.port == lt.ssh_port && s.user == lt.ssh_user)
                    .map(|s| s.id.clone())
                    .unwrap_or_else(|| {
                        let s = SshServer {
                            id: uuid::Uuid::new_v4().to_string(),
                            name: format!("{}@{}:{}", lt.ssh_user, lt.ssh_host, lt.ssh_port),
                            host: lt.ssh_host.clone(),
                            port: lt.ssh_port,
                            user: lt.ssh_user.clone(),
                            auth_method: lt.auth_method.clone(),
                            password: lt.password.clone(),
                            key_path: lt.key_path.clone(),
                            key_passphrase: lt.key_passphrase.clone(),
                        };
                        let id = s.id.clone();
                        servers.push(s);
                        id
                    });
                out.push(Tunnel {
                    id: lt.id,
                    name: lt.name,
                    server_id,
                    local_port: lt.local_port,
                    remote_host: lt.remote_host,
                    remote_port: lt.remote_port,
                    enabled: lt.enabled,
                });
                migrated = true;
            }
        }
    }
    if migrated {
        // 立即落盘新格式
        if let Ok(json) = serde_json::to_string_pretty(&out) {
            let _ = std::fs::write(tunnels_path, json);
            restrict_perms(tunnels_path);
        }
        if let Ok(json) = serde_json::to_string_pretty(&*servers) {
            let _ = std::fs::write(servers_path, json);
            restrict_perms(servers_path);
        }
    }
    out
}

fn main() {
    // Windows：先提权再初始化（避免单实例锁被未提权进程占用）
    #[cfg(target_os = "windows")]
    imp::ensure_elevated();

    tauri::Builder::default()
        // 单实例：系统规则全局共享，多开会互相干扰；再次启动时聚焦已有窗口
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.unminimize();
                let _ = w.set_focus();
            }
        }))
        .setup(|app| {
            let config_dir = app
                .path()
                .app_config_dir()
                .map_err(|e| format!("无法获取配置目录: {e}"))?;
            std::fs::create_dir_all(&config_dir).map_err(|e| format!("无法创建配置目录: {e}"))?;
            let rules_path = config_dir.join("rules.json");
            let rules = std::fs::read_to_string(&rules_path)
                .ok()
                .and_then(|s| serde_json::from_str::<Vec<Rule>>(&s).ok())
                .unwrap_or_default();
            let servers_path = config_dir.join("servers.json");
            let mut servers: Vec<SshServer> = std::fs::read_to_string(&servers_path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();
            let tunnels_path = config_dir.join("tunnels.json");
            let tunnels = load_tunnels(&tunnels_path, &mut servers, &servers_path);
            app.manage(AppState {
                rules: Mutex::new(rules),
                running: Mutex::new(false),
                active: Mutex::new(Vec::new()),
                listeners: Mutex::new(HashMap::new()),
                servers: Mutex::new(servers),
                tunnels: Mutex::new(tunnels),
                tunnel_tasks: Mutex::new(HashMap::new()),
                tunnel_states: Arc::new(Mutex::new(HashMap::new())),
                logs: Arc::new(Mutex::new(VecDeque::new())),
                rules_path,
                servers_path,
                tunnels_path,
                anchor_path: std::env::temp_dir().join("netredirect-anchor.conf"),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            list_rules,
            save_rule,
            delete_rule,
            list_servers,
            save_server,
            delete_server,
            list_tunnels,
            save_tunnel,
            delete_tunnel,
            start_redirect,
            stop_redirect,
            start_tunnels_cmd,
            stop_tunnels_cmd,
            get_status,
            get_logs,
            passwordless_status,
            setup_passwordless,
            get_platform
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app, event| {
            if let tauri::RunEvent::ExitRequested { .. } = event {
                cleanup_on_exit(app);
            }
        });
}
