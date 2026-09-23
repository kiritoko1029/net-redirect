const invoke = window.__TAURI__.core.invoke;

const $ = (id) => document.getElementById(id);
const els = {
  statusDot: $('statusDot'),
  statusText: $('statusText'),
  toggleBtn: $('toggleBtn'),
  logs: $('logs'),
  errorBox: $('errorBox'),
  nopassBtn: $('nopassBtn'),
  rulesBody: $('rulesBody'),
  emptyHint: $('emptyHint'),
  addRuleBtn: $('addRuleBtn'),
  ruleModal: $('ruleModal'),
  ruleModalTitle: $('ruleModalTitle'),
  form: $('ruleForm'),
  ruleId: $('ruleId'),
  name: $('name'),
  srcIp: $('srcIp'),
  srcPort: $('srcPort'),
  dstHost: $('dstHost'),
  dstPort: $('dstPort'),
  enabled: $('enabled'),
  saveBtn: $('saveBtn'),
  cancelEdit: $('cancelEdit'),
  directHint: $('directHint'),
  serverForm: $('serverForm'),
  serverModal: $('serverModal'),
  serverModalTitle: $('serverModalTitle'),
  addServerBtn: $('addServerBtn'),
  srvId: $('srvId'),
  srvName: $('srvName'),
  srvHost: $('srvHost'),
  srvPort: $('srvPort'),
  srvUser: $('srvUser'),
  srvAuth: $('srvAuth'),
  srvPass: $('srvPass'),
  srvPassWrap: $('srvPassWrap'),
  srvKeyPath: $('srvKeyPath'),
  srvKeyWrap: $('srvKeyWrap'),
  srvKeyPass: $('srvKeyPass'),
  srvKeyPassWrap: $('srvKeyPassWrap'),
  srvSaveBtn: $('srvSaveBtn'),
  srvCancelEdit: $('srvCancelEdit'),
  serversBody: $('serversBody'),
  serversEmptyHint: $('serversEmptyHint'),
  tunnelForm: $('tunnelForm'),
  tunnelModal: $('tunnelModal'),
  tunnelModalTitle: $('tunnelModalTitle'),
  addTunnelBtn: $('addTunnelBtn'),
  tunnelToggleBtn: $('tunnelToggleBtn'),
  tunnelStatusText: $('tunnelStatusText'),
  tunId: $('tunId'),
  tunName: $('tunName'),
  tunServer: $('tunServer'),
  tunLocalPort: $('tunLocalPort'),
  tunRemoteHost: $('tunRemoteHost'),
  tunRemotePort: $('tunRemotePort'),
  tunEnabled: $('tunEnabled'),
  tunSaveBtn: $('tunSaveBtn'),
  tunCancelEdit: $('tunCancelEdit'),
  tunnelsBody: $('tunnelsBody'),
  tunnelsEmptyHint: $('tunnelsEmptyHint'),
};

let rules = [];
let tunnels = [];
let servers = [];
let status = { running: false, active: [], tunnels: [], tunnelsRunning: false };
let lastLogText = '';
let platform = '';
let lastServersKey = null;

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  }[c]));
}

function showError(msg) {
  els.errorBox.textContent = msg;
  els.errorBox.classList.remove('hidden');
  clearTimeout(showError._t);
  showError._t = setTimeout(() => els.errorBox.classList.add('hidden'), 8000);
}

function isLoopbackHost(v) {
  const host = String(v).trim().toLowerCase();
  return host === 'localhost' || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host);
}

function updateDirectHint() {
  els.directHint.classList.toggle('hidden', !isLoopbackHost(els.dstHost.value));
}

function serverById(id) {
  return servers.find((s) => s.id === id) || null;
}

// ===================== 模态框 =====================

function openModal(el) {
  el.classList.remove('hidden');
}

function closeModals() {
  document.querySelectorAll('.modal-mask').forEach((m) => m.classList.add('hidden'));
}

document.querySelectorAll('.modal-mask').forEach((m) => {
  m.addEventListener('click', (e) => {
    if (e.target === m) closeModals();
  });
});
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeModals();
});

// ===================== 数据与渲染 =====================

async function refreshAll() {
  try {
    [rules, status, tunnels, servers] = await Promise.all([
      invoke('list_rules'),
      invoke('get_status'),
      invoke('list_tunnels'),
      invoke('list_servers'),
    ]);
    render();
  } catch (e) {
    showError(String(e));
  }
}

function activeFor(id) {
  return status.active.find((x) => x.id === id) || null;
}

function render() {
  els.statusDot.className = 'dot ' + (status.running ? 'running' : 'stopped');
  els.statusText.textContent = status.running
    ? `运行中 · ${status.active.length} 条规则生效`
    : '已停止';
  els.toggleBtn.textContent = status.running ? '停止重定向' : '启动重定向';
  els.toggleBtn.classList.toggle('danger', status.running);
  els.addRuleBtn.disabled = status.running;
  els.addServerBtn.disabled = status.running;
  els.addTunnelBtn.disabled = status.running;

  // 隧道独立开关
  const tstates = status.tunnels || [];
  if (status.tunnelsRunning) {
    const connected = tstates.filter((t) => t.state === 'connected').length;
    const failed = tstates.filter((t) => t.state === 'error').length;
    els.tunnelStatusText.textContent =
      `隧道运行中 · ${connected} 已连接` + (failed ? ` · ${failed} 失败` : '');
  } else {
    els.tunnelStatusText.textContent = '隧道未启动';
  }
  els.tunnelToggleBtn.textContent = status.tunnelsRunning ? '停止隧道' : '启动隧道';
  els.tunnelToggleBtn.classList.toggle('danger', status.tunnelsRunning);

  renderRules();
  renderServers();
  renderTunnels();
}

function renderRules() {
  els.rulesBody.innerHTML = rules.map((r) => {
    const a = activeFor(r.id);
    const portCell = !a
      ? '<span class="muted">—</span>'
      : a.direct
        ? '<span class="badge">直通</span>'
        : `<code>${a.localPort}</code>`;
    return `<tr>
      <td>${esc(r.name)}</td>
      <td><code>${esc(r.srcIp)}:${r.srcPort}</code></td>
      <td><code>${esc(r.dstHost)}:${r.dstPort}</code></td>
      <td>${portCell}</td>
      <td><input type="checkbox" data-act="toggle" data-id="${r.id}" ${r.enabled ? 'checked' : ''} ${status.running ? 'disabled' : ''} /></td>
      <td class="col-actions">
        <button class="small" data-act="edit" data-id="${r.id}" ${status.running ? 'disabled' : ''}>编辑</button>
        <button class="small danger-text" data-act="del" data-id="${r.id}" ${status.running ? 'disabled' : ''}>删除</button>
      </td>
    </tr>`;
  }).join('');
  els.emptyHint.classList.toggle('hidden', rules.length > 0);
}

els.rulesBody.addEventListener('click', async (e) => {
  const btn = e.target.closest('[data-act]');
  if (!btn || btn.tagName !== 'BUTTON') return;
  const rule = rules.find((r) => r.id === btn.dataset.id);
  if (!rule) return;
  if (btn.dataset.act === 'edit') {
    els.ruleId.value = rule.id;
    els.name.value = rule.name;
    els.srcIp.value = rule.srcIp;
    els.srcPort.value = rule.srcPort;
    els.dstHost.value = rule.dstHost;
    els.dstPort.value = rule.dstPort;
    els.enabled.checked = rule.enabled;
    els.ruleModalTitle.textContent = '编辑规则';
    updateDirectHint();
    openModal(els.ruleModal);
    els.name.focus();
  } else if (btn.dataset.act === 'del') {
    try {
      await invoke('delete_rule', { id: rule.id });
      await refreshAll();
    } catch (err) {
      showError(String(err));
    }
  }
});

els.rulesBody.addEventListener('change', async (e) => {
  const box = e.target.closest('input[data-act="toggle"]');
  if (!box) return;
  const rule = rules.find((r) => r.id === box.dataset.id);
  if (!rule) return;
  try {
    await invoke('save_rule', { rule: { ...rule, enabled: box.checked } });
    await refreshAll();
  } catch (err) {
    showError(String(err));
    box.checked = !box.checked;
  }
});

els.addRuleBtn.addEventListener('click', () => {
  resetForm();
  els.ruleModalTitle.textContent = '添加规则';
  openModal(els.ruleModal);
});

els.form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const rule = {
    id: els.ruleId.value || '',
    name: els.name.value.trim() || `${els.srcIp.value.trim()}:${els.srcPort.value}`,
    srcIp: els.srcIp.value.trim(),
    srcPort: Number(els.srcPort.value),
    dstHost: els.dstHost.value.trim(),
    dstPort: Number(els.dstPort.value),
    enabled: els.enabled.checked,
  };
  try {
    await invoke('save_rule', { rule });
    closeModals();
    await refreshAll();
  } catch (err) {
    showError(String(err));
  }
});

els.dstHost.addEventListener('input', updateDirectHint);

function resetForm() {
  els.form.reset();
  els.ruleId.value = '';
  els.enabled.checked = true;
  updateDirectHint();
}
els.cancelEdit.addEventListener('click', closeModals);

els.toggleBtn.addEventListener('click', async () => {
  els.toggleBtn.disabled = true;
  try {
    if (status.running) {
      await invoke('stop_redirect');
    } else {
      await invoke('start_redirect');
    }
    await refreshAll();
  } catch (err) {
    showError(String(err));
  } finally {
    els.toggleBtn.disabled = false;
  }
});

async function pollLogs() {
  try {
    const logs = await invoke('get_logs');
    const text = logs.join('\n');
    if (text !== lastLogText) {
      lastLogText = text;
      els.logs.textContent = text || '（暂无日志）';
      els.logs.scrollTop = els.logs.scrollHeight;
    }
  } catch (_) {}
}

async function refreshNopass() {
  if (platform !== 'macos') {
    els.nopassBtn.classList.add('hidden');
    return;
  }
  try {
    const ok = await invoke('passwordless_status');
    els.nopassBtn.classList.toggle('hidden', ok);
  } catch (_) {}
}

els.nopassBtn.addEventListener('click', async () => {
  els.nopassBtn.disabled = true;
  try {
    await invoke('setup_passwordless');
    els.nopassBtn.classList.add('hidden');
  } catch (err) {
    showError(String(err));
  } finally {
    els.nopassBtn.disabled = false;
  }
});

// ===================== SSH 隧道开关 =====================

els.tunnelToggleBtn.addEventListener('click', async () => {
  els.tunnelToggleBtn.disabled = true;
  try {
    if (status.tunnelsRunning) {
      await invoke('stop_tunnels_cmd');
    } else {
      await invoke('start_tunnels_cmd');
    }
    await refreshAll();
  } catch (err) {
    showError(String(err));
  } finally {
    els.tunnelToggleBtn.disabled = false;
  }
});

// ===================== SSH 服务器 =====================

function updateSrvAuthFields() {
  const isKey = els.srvAuth.value === 'key';
  els.srvPassWrap.classList.toggle('hidden', isKey);
  els.srvKeyWrap.classList.toggle('hidden', !isKey);
  els.srvKeyPassWrap.classList.toggle('hidden', !isKey);
}
els.srvAuth.addEventListener('change', updateSrvAuthFields);

function renderServers() {
  els.serversBody.innerHTML = servers.map((s) => {
    const refs = tunnels.filter((t) => t.serverId === s.id).length;
    return `<tr>
      <td>${esc(s.name)}</td>
      <td><code>${esc(s.host)}:${s.port}</code></td>
      <td>${esc(s.user)}</td>
      <td>${s.authMethod === 'key' ? '密钥' : '密码'}</td>
      <td>${refs}</td>
      <td class="col-actions">
        <button class="small" data-sact="edit" data-id="${s.id}" ${status.running ? 'disabled' : ''}>编辑</button>
        <button class="small danger-text" data-sact="del" data-id="${s.id}" ${status.running ? 'disabled' : ''}>删除</button>
      </td>
    </tr>`;
  }).join('');
  els.serversEmptyHint.classList.toggle('hidden', servers.length > 0);

  // 隧道表单的服务器下拉：只在列表变化时重建，避免打断正在进行的编辑
  const key = JSON.stringify(servers.map((s) => [s.id, s.name, s.host, s.port]));
  if (key !== lastServersKey) {
    lastServersKey = key;
    const prev = els.tunServer.value;
    els.tunServer.innerHTML = servers.length
      ? servers.map((s) => `<option value="${s.id}">${esc(s.name)}（${esc(s.host)}:${s.port}）</option>`).join('')
      : '<option value="">（请先在上方添加服务器）</option>';
    if (servers.some((s) => s.id === prev)) els.tunServer.value = prev;
  }
}

els.addServerBtn.addEventListener('click', () => {
  resetServerForm();
  els.serverModalTitle.textContent = '添加服务器';
  openModal(els.serverModal);
});

els.serverForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const server = {
    id: els.srvId.value || '',
    name: els.srvName.value.trim() || `${els.srvUser.value.trim()}@${els.srvHost.value.trim()}:${els.srvPort.value}`,
    host: els.srvHost.value.trim(),
    port: Number(els.srvPort.value) || 22,
    user: els.srvUser.value.trim(),
    authMethod: els.srvAuth.value,
    password: els.srvPass.value,
    keyPath: els.srvKeyPath.value.trim(),
    keyPassphrase: els.srvKeyPass.value,
  };
  try {
    await invoke('save_server', { server });
    closeModals();
    await refreshAll();
  } catch (err) {
    showError(String(err));
  }
});

function resetServerForm() {
  els.serverForm.reset();
  els.srvId.value = '';
  els.srvPort.value = 22;
  updateSrvAuthFields();
}
els.srvCancelEdit.addEventListener('click', closeModals);

els.serversBody.addEventListener('click', async (e) => {
  const btn = e.target.closest('[data-sact]');
  if (!btn) return;
  const s = servers.find((x) => x.id === btn.dataset.id);
  if (!s) return;
  if (btn.dataset.sact === 'edit') {
    els.srvId.value = s.id;
    els.srvName.value = s.name;
    els.srvHost.value = s.host;
    els.srvPort.value = s.port;
    els.srvUser.value = s.user;
    els.srvAuth.value = s.authMethod;
    els.srvPass.value = s.password || '';
    els.srvKeyPath.value = s.keyPath || '';
    els.srvKeyPass.value = s.keyPassphrase || '';
    els.serverModalTitle.textContent = '编辑服务器';
    updateSrvAuthFields();
    openModal(els.serverModal);
    els.srvName.focus();
  } else if (btn.dataset.sact === 'del') {
    try {
      await invoke('delete_server', { id: s.id });
      await refreshAll();
    } catch (err) {
      showError(String(err));
    }
  }
});

// ===================== SSH 隧道列表 =====================

function tunnelStateInfo(id) {
  return (status.tunnels || []).find((x) => x.id === id) || null;
}

function tunnelBadge(id) {
  const info = tunnelStateInfo(id);
  if (!status.tunnelsRunning || !info || info.state === 'stopped') {
    return '<span class="badge gray">未连接</span>';
  }
  if (info.state === 'connected') return '<span class="badge">已连接</span>';
  if (info.state === 'connecting') return '<span class="badge yellow">连接中…</span>';
  return `<span class="badge red" title="${esc(info.error || '')}">连接失败</span>`;
}

function renderTunnels() {
  els.tunnelsBody.innerHTML = tunnels.map((t) => {
    const s = serverById(t.serverId);
    return `<tr>
      <td>${esc(t.name)}</td>
      <td><code>127.0.0.1:${t.localPort}</code></td>
      <td><code>${esc(t.remoteHost)}:${t.remotePort}</code></td>
      <td>${s ? `${esc(s.name)}` : '<span class="muted">（服务器已删除）</span>'}</td>
      <td>${tunnelBadge(t.id)}</td>
      <td><input type="checkbox" data-tact="toggle" data-id="${t.id}" ${t.enabled ? 'checked' : ''} ${status.running ? 'disabled' : ''} /></td>
      <td class="col-actions">
        <button class="small" data-tact="edit" data-id="${t.id}" ${status.running ? 'disabled' : ''}>编辑</button>
        <button class="small danger-text" data-tact="del" data-id="${t.id}" ${status.running ? 'disabled' : ''}>删除</button>
      </td>
    </tr>`;
  }).join('');
  els.tunnelsEmptyHint.classList.toggle('hidden', tunnels.length > 0);
}

els.addTunnelBtn.addEventListener('click', () => {
  resetTunnelForm();
  els.tunnelModalTitle.textContent = '添加隧道';
  openModal(els.tunnelModal);
});

els.tunnelForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const tunnel = {
    id: els.tunId.value || '',
    name: els.tunName.value.trim() || `127.0.0.1:${els.tunLocalPort.value} → ${els.tunRemoteHost.value.trim()}:${els.tunRemotePort.value}`,
    serverId: els.tunServer.value,
    localPort: Number(els.tunLocalPort.value),
    remoteHost: els.tunRemoteHost.value.trim(),
    remotePort: Number(els.tunRemotePort.value),
    enabled: els.tunEnabled.checked,
  };
  try {
    await invoke('save_tunnel', { tunnel });
    closeModals();
    await refreshAll();
  } catch (err) {
    showError(String(err));
  }
});

function resetTunnelForm() {
  els.tunnelForm.reset();
  els.tunId.value = '';
  els.tunEnabled.checked = true;
}
els.tunCancelEdit.addEventListener('click', closeModals);

els.tunnelsBody.addEventListener('click', async (e) => {
  const btn = e.target.closest('[data-tact]');
  if (!btn || btn.tagName !== 'BUTTON') return;
  const t = tunnels.find((x) => x.id === btn.dataset.id);
  if (!t) return;
  if (btn.dataset.tact === 'edit') {
    els.tunId.value = t.id;
    els.tunName.value = t.name;
    els.tunServer.value = t.serverId;
    els.tunLocalPort.value = t.localPort;
    els.tunRemoteHost.value = t.remoteHost;
    els.tunRemotePort.value = t.remotePort;
    els.tunEnabled.checked = t.enabled;
    els.tunnelModalTitle.textContent = '编辑隧道';
    openModal(els.tunnelModal);
    els.tunName.focus();
  } else if (btn.dataset.tact === 'del') {
    try {
      await invoke('delete_tunnel', { id: t.id });
      await refreshAll();
    } catch (err) {
      showError(String(err));
    }
  }
});

els.tunnelsBody.addEventListener('change', async (e) => {
  const box = e.target.closest('input[data-tact="toggle"]');
  if (!box) return;
  const t = tunnels.find((x) => x.id === box.dataset.id);
  if (!t) return;
  try {
    await invoke('save_tunnel', { tunnel: { ...t, enabled: box.checked } });
    await refreshAll();
  } catch (err) {
    showError(String(err));
    box.checked = !box.checked;
  }
});

// ===================== 侧边栏页面切换 =====================
const VIEWS = ['rules', 'tunnels', 'flow'];
document.querySelectorAll('.side-item').forEach((btn) => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.side-item').forEach((b) => b.classList.toggle('active', b === btn));
    VIEWS.forEach((v) => $('view-' + v).classList.toggle('hidden', btn.dataset.view !== v));
  });
});

// ===================== 流量走向动画 =====================
const flowCanvas = $('flowCanvas');
const flowCtx = flowCanvas.getContext('2d');

const FLOW_COLORS = {
  bg: '#0d1117',
  border: '#2b333d',
  text: '#e6e9ee',
  muted: '#8b949e',
  accent: '#4f8cff',
  green: '#3fb950',
  teal: '#39d0c4',
  red: '#f85149',
};

function flowPill(ctx, x, y, w, h, text, color, dim) {
  const r = h / 2;
  ctx.beginPath();
  ctx.moveTo(x + r, y);
  ctx.arcTo(x + w, y, x + w, y + h, r);
  ctx.arcTo(x + w, y + h, x, y + h, r);
  ctx.arcTo(x, y + h, x, y, r);
  ctx.arcTo(x, y, x + w, y, r);
  ctx.closePath();
  ctx.fillStyle = FLOW_COLORS.bg;
  ctx.fill();
  ctx.strokeStyle = dim ? FLOW_COLORS.border : color;
  ctx.lineWidth = 1.5;
  ctx.stroke();
  ctx.fillStyle = dim ? FLOW_COLORS.muted : FLOW_COLORS.text;
  ctx.font = '12.5px "SF Mono", Menlo, monospace';
  ctx.textAlign = 'center';
  ctx.fillText(text, x + w / 2, y + h / 2 + 4.5);
  ctx.textAlign = 'left';
}

// 规则目标指向某个已启用隧道的本地端口时，流向图追加隧道一跳
function tunnelForRule(rule) {
  if (!isLoopbackHost(rule.dstHost)) return null;
  return tunnels.find((t) => t.enabled && t.localPort === rule.dstPort) || null;
}

function drawFlowRow(ctx, rule, idx, width, rowH, t) {
  const cy = idx * rowH + rowH / 2 + 12;
  const leftX = 14;
  const active = activeFor(rule.id);
  const isActive = !!(status.running && active);
  const tun = tunnelForRule(rule);
  const tunInfo = tun ? tunnelStateInfo(tun.id) : null;
  const tunUp = !!(tun && tunInfo && tunInfo.state === 'connected');
  const chainActive = isActive && (!tun || tunUp);
  const tunServer = tun ? serverById(tun.serverId) : null;

  ctx.font = '12.5px "SF Mono", Menlo, monospace';
  const srcText = `${rule.srcIp}:${rule.srcPort}`;
  const dstText = tun ? `${tun.remoteHost}:${tun.remotePort}` : `${rule.dstHost}:${rule.dstPort}`;
  const srcW = ctx.measureText(srcText).width + 30;
  const dstW = ctx.measureText(dstText).width + 30;
  const midW = 112;
  const tunText = tun ? `隧道 ${tunServer ? tunServer.host : '?'}` : '';
  const tunW = tun ? ctx.measureText(tunText).width + 34 : 0;

  const hop2Label = isActive ? (active.direct ? '系统改写' : '本地代理转发') : '转发到目标';
  let chain;
  let segLabels;
  if (tun) {
    const gap = Math.max(18, (width - 28 - srcW - midW - tunW - dstW) / 3);
    chain = [
      { x: leftX, w: srcW, text: srcText, color: FLOW_COLORS.accent, dim: !chainActive },
      { x: leftX + srcW + gap, w: midW, text: 'Net Redirect', color: FLOW_COLORS.green, dim: !isActive },
      { x: leftX + srcW + gap + midW + gap, w: tunW, text: tunText, color: tunUp ? FLOW_COLORS.teal : FLOW_COLORS.red, dim: !chainActive },
      { x: leftX + srcW + gap + midW + gap + tunW + gap, w: dstW, text: dstText, color: FLOW_COLORS.accent, dim: !chainActive },
    ];
    segLabels = ['系统访问', hop2Label, '隧道传输'];
  } else {
    const midX = Math.max(leftX + srcW + 56, Math.min(width / 2 - midW / 2, width - 14 - dstW - midW - 56));
    chain = [
      { x: leftX, w: srcW, text: srcText, color: FLOW_COLORS.accent, dim: !chainActive },
      { x: midX, w: midW, text: 'Net Redirect', color: FLOW_COLORS.green, dim: !isActive },
      { x: width - 14 - dstW, w: dstW, text: dstText, color: FLOW_COLORS.teal, dim: !chainActive },
    ];
    segLabels = ['系统访问', hop2Label];
  }

  const lineColor = chainActive ? 'rgba(79,140,255,0.5)' : FLOW_COLORS.border;
  for (let i = 0; i < chain.length - 1; i++) {
    const x0 = chain[i].x + chain[i].w + 8;
    const x1 = chain[i + 1].x - 8;
    ctx.strokeStyle = lineColor;
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.moveTo(x0, cy);
    ctx.lineTo(x1, cy);
    ctx.stroke();
    ctx.fillStyle = chainActive ? FLOW_COLORS.accent : FLOW_COLORS.border;
    ctx.beginPath();
    ctx.moveTo(x1 + 8, cy);
    ctx.lineTo(x1, cy - 5);
    ctx.lineTo(x1, cy + 5);
    ctx.closePath();
    ctx.fill();

    ctx.textAlign = 'center';
    ctx.font = '11px -apple-system, "PingFang SC", sans-serif';
    ctx.fillStyle = FLOW_COLORS.muted;
    ctx.fillText(segLabels[i], (x0 + x1) / 2, cy - 13);
    ctx.textAlign = 'left';

    if (chainActive && x1 > x0) {
      for (let k = 0; k < 2; k++) {
        const p = (t * 0.00045 + k * 0.5 + i * 0.25 + idx * 0.17) % 1;
        const x = x0 + p * (x1 - x0);
        ctx.fillStyle = 'rgba(79,140,255,0.2)';
        ctx.beginPath();
        ctx.arc(x, cy, 7, 0, Math.PI * 2);
        ctx.fill();
        ctx.fillStyle = '#7fb0ff';
        ctx.beginPath();
        ctx.arc(x, cy, 3.2, 0, Math.PI * 2);
        ctx.fill();
      }
    }
  }

  ctx.font = '11.5px -apple-system, "PingFang SC", sans-serif';
  ctx.fillStyle = FLOW_COLORS.muted;
  ctx.fillText(rule.name, leftX + 2, cy - 24);

  for (const n of chain) {
    flowPill(ctx, n.x, cy - 17, n.w, n.text === 'Net Redirect' ? 36 : 34, n.text, n.color, n.dim);
  }
}

function drawFlow(t) {
  if ($('view-flow').classList.contains('hidden')) return;
  const dpr = window.devicePixelRatio || 1;
  const width = flowCanvas.clientWidth || 600;
  const rows = rules.filter((r) => r.enabled);
  const rowH = 84;
  const height = rows.length ? rows.length * rowH + 16 : 72;
  const pxW = Math.round(width * dpr);
  const pxH = Math.round(height * dpr);
  if (flowCanvas.width !== pxW || flowCanvas.height !== pxH) {
    flowCanvas.width = pxW;
    flowCanvas.height = pxH;
    flowCanvas.style.height = height + 'px';
  }
  const ctx = flowCtx;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, width, height);

  if (!rows.length) {
    ctx.fillStyle = FLOW_COLORS.muted;
    ctx.font = '13px -apple-system, "PingFang SC", sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('添加并启用规则后，这里会实时展示流量走向', width / 2, height / 2 + 5);
    ctx.textAlign = 'left';
    return;
  }
  rows.forEach((r, i) => drawFlowRow(ctx, r, i, width, rowH, t));
}

function flowLoop(t) {
  try {
    drawFlow(t || 0);
  } catch (_) {}
  requestAnimationFrame(flowLoop);
}
requestAnimationFrame(flowLoop);

// ===================== 启动 =====================
async function initPlatform() {
  try {
    platform = await invoke('get_platform');
    document.body.dataset.platform = platform;
  } catch (_) {}
}

// 窗口拖拽：隐藏标题栏后，页头/侧边栏顶部承担拖动；双击缩放
(function setupWindowDrag() {
  const win = window.__TAURI__?.window?.getCurrentWindow?.();
  if (!win) return;
  document.querySelectorAll('.page-header, .side-top, .brand').forEach((el) => {
    el.addEventListener('mousedown', (e) => {
      if (e.button === 0 && !e.target.closest('button, input, select, a, .controls')) {
        win.startDragging();
      }
    });
    el.addEventListener('dblclick', (e) => {
      if (!e.target.closest('button, input, select, a, .controls')) {
        win.toggleMaximize();
      }
    });
  });
})();

initPlatform().then(refreshNopass);
updateSrvAuthFields();
refreshAll();
pollLogs();
setInterval(refreshAll, 2000);
setInterval(pollLogs, 1500);
