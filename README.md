# Net Redirect

系统级 TCP 流量重定向工具（macOS / Windows），Tauri 2 桌面应用。

把「访问 特定IP:端口」的系统流量透明转发到另一个 地址:端口 —— 项目代码不用改任何配置。内置 SSH 隧道（等效 `ssh -L`），可彻底替代 XTerminal 等工具做本地端口转发。

## 功能

- **转发规则**：访问 `源IP:端口` → 转发到 `目标地址:端口`，支持多条规则
  - 目标为本机回环地址（127.0.0.1 / localhost）时自动**直通模式**：由系统防火墙直接改写目的地，零代理开销
- **SSH 隧道**：服务器连接独立配置、可被多条隧道复用；密码 / 密钥认证；断线 5 秒自动重连
- **流量走向页**：全链路实时流向动画（规则 → 改写 → 隧道 → 目标）
- 重定向与隧道**独立开关**；规则持久化在系统配置目录

## 工作原理

| 平台 | 实现 |
|------|------|
| macOS | `pf` 防火墙：`route-to` 把流量送进 lo0 + `rdr` 改写目的地（anchor 挂在 `com.apple/netredirect`，免密可选配 sudoers） |
| Windows | 回环接口加 `/32` 别名 + `netsh interface portproxy`（IP Helper 服务转发，启动时 UAC 提权一次） |
| SSH 隧道 | 纯 Rust 实现（[russh](https://github.com/Eugeny/russh)），direct-tcpip 通道转发 |

## 构建

```bash
# 依赖：Rust + Node.js
npx @tauri-apps/cli@latest dev      # 开发调试
npx @tauri-apps/cli@latest build    # macOS .app

# 在 macOS 上交叉编译 Windows amd64 安装包（需 cargo install cargo-xwin）
npx @tauri-apps/cli@latest build --runner cargo-xwin --target x86_64-pc-windows-msvc --bundles nsis
```

## 发布

```bash
git tag v0.x.x && git push origin v0.x.x
```

推送版本标签后，GitHub Actions 会在 macOS / Windows 原生 runner 上自动构建并创建 Release（含 dmg / nsis 安装包）。

## 安全说明

- macOS 下加载/清除 pf 规则需要管理员权限（弹授权框）；点一次「配置免密」后写入 `/etc/sudoers.d/netredirect`（仅放行所需固定命令），之后不再弹窗。删除该文件即可还原
- SSH 密码明文保存在本机配置目录（文件权限 0600），介意请用密钥认证
- 隧道接受任意服务器主机密钥，指纹会写入运行日志供人工核对

## 许可

仅供内部学习/工作使用。
