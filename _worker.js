const encoder = new TextEncoder();
const COOKIE = "dam_session";
const SESSION_TTL = 7 * 24 * 60 * 60;
const CF_API = "https://api.cloudflare.com/client/v4";

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers },
  });
}
function html(body) {
  return new Response(body, { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } });
}
function randomId() { return crypto.randomUUID(); }
function b64url(bytes) {
  let s = ""; for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function unb64url(s) {
  const b = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
  return Uint8Array.from(b, c => c.charCodeAt(0));
}
function hexBytes(hex) {
  if (!/^[0-9a-f]{64}$/i.test(hex || "")) throw new Error("ENCRYPTION_KEY must be 64 hexadecimal characters");
  return Uint8Array.from(hex.match(/.{2}/g), x => parseInt(x, 16));
}
async function encryptionKey(env) {
  return crypto.subtle.importKey("raw", hexBytes(env.ENCRYPTION_KEY), "AES-GCM", false, ["encrypt", "decrypt"]);
}
async function encryptSecret(env, value) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await encryptionKey(env), encoder.encode(value));
  return b64url(iv) + "." + b64url(new Uint8Array(cipher));
}
async function decryptSecret(env, value) {
  const [iv, cipher] = value.split(".");
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64url(iv) }, await encryptionKey(env), unb64url(cipher));
  return new TextDecoder().decode(plain);
}
async function hmac(value, secret) {
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(value)));
}
function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0; for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
function cookieValue(request) {
  const raw = request.headers.get("Cookie") || "";
  const m = raw.match(new RegExp("(?:^|;\\s*)" + COOKIE + "=([^;]+)"));
  return m ? m[1] : "";
}
function cookieHeader(value, maxAge) {
  return COOKIE + "=" + value + "; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=" + maxAge;
}
async function makeSession(env) {
  const payload = b64url(encoder.encode(JSON.stringify({ exp: Math.floor(Date.now() / 1000) + SESSION_TTL, nonce: b64url(crypto.getRandomValues(new Uint8Array(16))) })));
  return payload + "." + b64url(await hmac(payload, env.SESSION_SECRET));
}
async function checkSession(env, token) {
  try {
    const [payload, signature] = token.split(".");
    if (!payload || !signature) return false;
    const expected = await hmac(payload, env.SESSION_SECRET);
    if (!constantTimeEqual(expected, unb64url(signature))) return false;
    const data = JSON.parse(new TextDecoder().decode(unb64url(payload)));
    return Number(data.exp) > Math.floor(Date.now() / 1000);
  } catch { return false; }
}
async function sha256(text) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(text)));
}
async function loginAllowed(env, ip) {
  const key = b64url(await sha256(ip || "unknown"));
  const row = await env.DOMAIN_DB.prepare("SELECT failures, locked_until FROM login_attempts WHERE ip_hash=?").bind(key).first();
  return !row || Number(row.locked_until) < Date.now();
}
async function recordLoginFailure(env, ip) {
  const key = b64url(await sha256(ip || "unknown"));
  const row = await env.DOMAIN_DB.prepare("SELECT failures FROM login_attempts WHERE ip_hash=?").bind(key).first();
  const failures = Math.min(12, Number(row?.failures || 0) + 1);
  const lock = failures >= 5 ? Date.now() + Math.min(30, failures * 3) * 60_000 : 0;
  await env.DOMAIN_DB.prepare("INSERT INTO login_attempts(ip_hash,failures,locked_until,updated_at) VALUES(?,?,?,?) ON CONFLICT(ip_hash) DO UPDATE SET failures=excluded.failures,locked_until=excluded.locked_until,updated_at=excluded.updated_at")
    .bind(key, failures, lock, Date.now()).run();
}
async function clearLoginFailures(env, ip) {
  const key = b64url(await sha256(ip || "unknown"));
  await env.DOMAIN_DB.prepare("DELETE FROM login_attempts WHERE ip_hash=?").bind(key).run();
}
async function cfRequest(token, path, method = "GET", body) {
  const response = await fetch(CF_API + path, {
    method,
    headers: { authorization: "Bearer " + token, "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok || !payload.success) {
    const message = (payload.errors || []).map(x => x.message).filter(Boolean).join("; ") || "Cloudflare API HTTP " + response.status;
    throw new Error(message);
  }
  return payload.result;
}
async function discoverZones(token) {
  const zones = [];
  for (let page = 1; page <= 20; page++) {
    const part = await cfRequest(token, "/zones?per_page=50&page=" + page);
    zones.push(...part.map(z => ({ id: z.id, name: z.name, status: z.status, accountName: z.account?.name || "" })));
    if (part.length < 50) break;
  }
  return zones;
}
function safeName(value) {
  const name = String(value || "").trim();
  if (!name || name.length > 80) throw new Error("名称不能为空且不能超过 80 个字符");
  return name;
}
function safeBaseUrl(value) {
  const url = new URL(String(value || ""));
  if (url.protocol !== "https:" || url.username || url.password) throw new Error("1Panel 地址必须使用 HTTPS，且不能包含用户名或密码");
  return url.origin;
}
async function log(env, operation, type, id, status, message, details = {}) {
  await env.DOMAIN_DB.prepare("INSERT INTO operation_logs(id,operation,resource_type,resource_id,status,message,details_json,created_at) VALUES(?,?,?,?,?,?,?,?)")
    .bind(randomId(), operation, type, id || null, status, message.slice(0, 500), JSON.stringify(details), new Date().toISOString()).run();
}
async function api(request, env, path) {
  const body = await request.json().catch(() => ({}));
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";

  if (path === "/api/login" && request.method === "POST") {
    if (!await loginAllowed(env, ip)) return json({ error: "登录尝试过多，请稍后再试" }, 429);
    const supplied = await sha256(String(body.password || ""));
    const expected = await sha256(String(env.PASSWORD || "not-configured"));
    if (!env.PASSWORD || !constantTimeEqual(supplied, expected)) {
      await recordLoginFailure(env, ip);
      await new Promise(resolve => setTimeout(resolve, 500));
      return json({ error: "密码错误" }, 401);
    }
    await clearLoginFailures(env, ip);
    return json({ ok: true }, 200, { "set-cookie": cookieHeader(await makeSession(env), SESSION_TTL) });
  }
  if (path === "/api/logout" && request.method === "POST") {
    return json({ ok: true }, 200, { "set-cookie": cookieHeader("", 0) });
  }
  if (!await checkSession(env, cookieValue(request))) return json({ error: "请先登录" }, 401);

  if (path === "/api/me") return json({ ok: true, app: env.APP_NAME || "Domain Access Manager" });

  if (path === "/api/cloudflare" && request.method === "GET") {
    const { results } = await env.DOMAIN_DB.prepare("SELECT id,name,zones_json,zone_count,token_status,created_at,updated_at,last_verified_at FROM cloudflare_credentials ORDER BY created_at DESC").all();
    return json({ items: results.map(x => ({ ...x, zones: JSON.parse(x.zones_json || "[]") })) });
  }
  if (path === "/api/cloudflare/verify" && request.method === "POST") {
    const name = safeName(body.name);
    const token = String(body.token || "").trim();
    if (!token || token.length > 4096) return json({ error: "请填写有效的 API Token" }, 400);
    try {
      const verify = await cfRequest(token, "/user/tokens/verify");
      if (verify.status !== "active") throw new Error("Cloudflare Token 状态不是 active");
      const zones = await discoverZones(token);
      if (!zones.length) throw new Error("Token 有效，但没有发现可访问的 Zone。请检查 Zone Read 权限。");
      const id = randomId();
      const encrypted = await encryptSecret(env, token);
      const now = new Date().toISOString();
      await env.DOMAIN_DB.prepare("INSERT INTO cloudflare_credentials(id,name,token_ciphertext,zones_json,zone_count,token_status,created_at,updated_at,last_verified_at) VALUES(?,?,?,?,?,?,?,?,?)")
        .bind(id, name, encrypted, JSON.stringify(zones), zones.length, "active", now, now, now).run();
      await log(env, "credential.add", "cloudflare", id, "success", "Cloudflare Token 验证成功并发现 " + zones.length + " 个 Zone");
      return json({ ok: true, item: { id, name, zones, zoneCount: zones.length, tokenStatus: "active" } });
    } catch (error) {
      await log(env, "credential.verify", "cloudflare", null, "failed", error.message);
      return json({ error: error.message }, 400);
    }
  }
  const cfDelete = path.match(/^\/api\/cloudflare\/([0-9a-f-]+)$/);
  if (cfDelete && request.method === "DELETE") {
    const id = cfDelete[1];
    const linked = await env.DOMAIN_DB.prepare("SELECT COUNT(*) AS count FROM managed_sites WHERE cloudflare_credential_id=?").bind(id).first();
    if (Number(linked?.count || 0)) return json({ error: "该凭据仍被网站使用，不能删除" }, 409);
    await env.DOMAIN_DB.prepare("DELETE FROM cloudflare_credentials WHERE id=?").bind(id).run();
    await log(env, "credential.delete", "cloudflare", id, "success", "Cloudflare 凭据已删除");
    return json({ ok: true });
  }
  if (path === "/api/nodes" && request.method === "GET") {
    const { results } = await env.DOMAIN_DB.prepare("SELECT id,name,base_url,panel_version,server_info_json,connection_status,created_at,updated_at,last_checked_at FROM panel_nodes ORDER BY created_at DESC").all();
    return json({ items: results.map(x => ({ ...x, serverInfo: JSON.parse(x.server_info_json || "{}") })) });
  }
  if (path === "/api/nodes/test" && request.method === "POST") {
    const name = safeName(body.name);
    const baseUrl = safeBaseUrl(body.baseUrl);
    const apiKey = String(body.apiKey || "").trim();
    if (!apiKey || apiKey.length > 4096) return json({ error: "请填写 1Panel API Key" }, 400);
    try {
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const signature = await hmac("1panel:" + timestamp, apiKey);
      const token = Array.from(signature, b => b.toString(16).padStart(2, "0")).join("");
      const response = await fetch(baseUrl + "/api/v2/dashboard/base/os", {
        headers: { "1Panel-Token": token, "1Panel-Timestamp": timestamp, "1Panel-Signature-Version": "hmac-sha256" },
        signal: AbortSignal.timeout(15000),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok || (data.code && data.code !== 200)) throw new Error(data.message || "1Panel API HTTP " + response.status);
      const id = randomId();
      const encrypted = await encryptSecret(env, apiKey);
      const now = new Date().toISOString();
      const info = data.data || data;
      const version = info.version || info.panelVersion || "";
      await env.DOMAIN_DB.prepare("INSERT INTO panel_nodes(id,name,base_url,api_key_ciphertext,panel_version,server_info_json,connection_status,created_at,updated_at,last_checked_at) VALUES(?,?,?,?,?,?,?,?,?,?)")
        .bind(id, name, baseUrl, encrypted, version, JSON.stringify({ os: info.os || "", platform: info.platform || "", platformFamily: info.platformFamily || "", distro: info.prettyDistro || "", kernelArch: info.kernelArch || "", kernelVersion: info.kernelVersion || "" }), "connected", now, now, now).run();
      await log(env, "node.add", "1panel", id, "success", "1Panel 节点连接成功");
      return json({ ok: true, item: { id, name, baseUrl, panelVersion: version, status: "connected" } });
    } catch (error) {
      await log(env, "node.test", "1panel", null, "failed", error.message);
      return json({ error: error.message }, 400);
    }
  }
  if (path === "/api/dns/records" && request.method === "GET") {
    const query = new URL(request.url).searchParams;
    const credentialId = String(query.get("credentialId") || "");
    const zoneId = String(query.get("zoneId") || "");
    if (!credentialId || !zoneId) return json({ error: "请选择 Cloudflare 凭据和域名 Zone" }, 400);
    const row = await env.DOMAIN_DB.prepare("SELECT token_ciphertext,zones_json FROM cloudflare_credentials WHERE id=?").bind(credentialId).first();
    if (!row) return json({ error: "Cloudflare 凭据不存在" }, 404);
    const zones = JSON.parse(row.zones_json || "[]");
    const zone = zones.find(z => z.id === zoneId);
    if (!zone) return json({ error: "该 Zone 不在此 Token 的授权范围内" }, 403);
    const token = await decryptSecret(env, row.token_ciphertext);
    const records = await cfRequest(token, "/zones/" + encodeURIComponent(zoneId) + "/dns_records?per_page=100");
    return json({ items: records.map(r => ({ id:r.id,type:r.type,name:r.name,content:r.content,ttl:r.ttl,proxied:r.proxied,comment:r.comment })) });
  }
  if (path === "/api/dns/records" && request.method === "POST") {
    const credentialId = String(body.credentialId || "");
    const zoneId = String(body.zoneId || "");
    const type = String(body.type || "").toUpperCase();
    const name = String(body.name || "").trim().toLowerCase();
    const content = String(body.content || "").trim();
    const ttl = Number(body.ttl || 1);
    const proxied = Boolean(body.proxied);
    if (!credentialId || !zoneId || !name || !content || !["A","AAAA","CNAME","TXT"].includes(type)) return json({ error: "请填写有效的 DNS 记录信息" }, 400);
    if (type === "A" && !/^\\d{1,3}(\\.\\d{1,3}){3}$/.test(content)) return json({ error: "A 记录必须填写 IPv4 地址" }, 400);
    if (type === "AAAA" && !content.includes(":")) return json({ error: "AAAA 记录必须填写 IPv6 地址" }, 400);
    if (type === "CNAME" && proxied && !content) return json({ error: "CNAME 目标不能为空" }, 400);
    const row = await env.DOMAIN_DB.prepare("SELECT token_ciphertext,zones_json FROM cloudflare_credentials WHERE id=?").bind(credentialId).first();
    if (!row) return json({ error: "Cloudflare 凭据不存在" }, 404);
    const zone = JSON.parse(row.zones_json || "[]").find(z => z.id === zoneId);
    if (!zone) return json({ error: "该 Zone 不在此 Token 的授权范围内" }, 403);
    const token = await decryptSecret(env, row.token_ciphertext);
    const record = await cfRequest(token, "/zones/" + encodeURIComponent(zoneId) + "/dns_records", "POST", { type,name,content,ttl,proxied: type === "TXT" ? false : proxied });
    await log(env, "dns.create", "dns_record", record.id, "success", "DNS 记录已创建", {zone:zone.name,type,name});
    return json({ ok:true, item:{id:record.id,type:record.type,name:record.name,content:record.content,ttl:record.ttl,proxied:record.proxied} });
  }
  const dnsDelete = path.match(/^\\/api\\/dns\\/records\\/([0-9a-f-]+)$/);
  if (dnsDelete && request.method === "DELETE") {
    const credentialId = String(body.credentialId || "");
    const zoneId = String(body.zoneId || "");
    const recordId = dnsDelete[1];
    const row = await env.DOMAIN_DB.prepare("SELECT token_ciphertext,zones_json FROM cloudflare_credentials WHERE id=?").bind(credentialId).first();
    if (!row) return json({ error: "Cloudflare 凭据不存在" }, 404);
    const zone = JSON.parse(row.zones_json || "[]").find(z => z.id === zoneId);
    if (!zone) return json({ error: "该 Zone 不在此 Token 的授权范围内" }, 403);
    const token = await decryptSecret(env, row.token_ciphertext);
    await cfRequest(token, "/zones/" + encodeURIComponent(zoneId) + "/dns_records/" + encodeURIComponent(recordId), "DELETE");
    await log(env, "dns.delete", "dns_record", recordId, "success", "DNS 记录已删除", {zone:zone.name});
    return json({ok:true});
  }
  const nodeDelete = path.match(/^\/api\/nodes\/([0-9a-f-]+)$/);
  if (nodeDelete && request.method === "DELETE") {
    const id = nodeDelete[1];
    const linked = await env.DOMAIN_DB.prepare("SELECT COUNT(*) AS count FROM managed_sites WHERE panel_node_id=?").bind(id).first();
    if (Number(linked?.count || 0)) return json({ error: "该节点仍有关联网站，不能删除" }, 409);
    await env.DOMAIN_DB.prepare("DELETE FROM panel_nodes WHERE id=?").bind(id).run();
    await log(env, "node.delete", "1panel", id, "success", "1Panel 节点已删除");
    return json({ ok: true });
  }
  if (path === "/api/logs" && request.method === "GET") {
    const { results } = await env.DOMAIN_DB.prepare("SELECT id,operation,resource_type,resource_id,status,message,created_at FROM operation_logs ORDER BY created_at DESC LIMIT 100").all();
    return json({ items: results });
  }
  return json({ error: "Not found" }, 404);
}

const PAGE = `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Domain Access Manager</title>
<style>
:root{color-scheme:dark;--bg:#0b1020;--panel:#121a2b;--panel2:#182338;--line:#26344b;--text:#edf3ff;--muted:#93a4bd;--accent:#6aa7ff;--green:#45c58a;--red:#ff7777}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}button,input{font:inherit}button{cursor:pointer;border:1px solid var(--line);background:var(--panel2);color:var(--text);border-radius:9px;padding:9px 13px}button.primary{background:#2767c8;border-color:#3478dc}button.danger{color:#ff9999}input{width:100%;padding:11px 12px;background:#0c1424;border:1px solid var(--line);border-radius:9px;color:var(--text);outline:none}input:focus{border-color:var(--accent)}.wrap{max-width:1120px;margin:auto;padding:28px 22px}.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px}.brand{font-size:19px;font-weight:700}.muted{color:var(--muted)}.tabs{display:flex;gap:8px;margin-bottom:20px;flex-wrap:wrap}.tabs button.active{background:#1e3d68;border-color:#477fc8}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:15px}.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px}.card h3{margin:0 0 14px;font-size:16px}.field{margin:12px 0}.field label{display:block;margin-bottom:6px;color:var(--muted);font-size:12px}.actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.item{padding:14px 0;border-top:1px solid var(--line)}.item:first-child{border-top:0}.row{display:flex;justify-content:space-between;gap:12px;align-items:center}.pill{font-size:11px;color:var(--green);background:#16382e;padding:3px 8px;border-radius:20px}.pill.bad{color:#ff9d9d;background:#3a2228}.zone{display:inline-block;border:1px solid var(--line);border-radius:20px;padding:3px 8px;margin:5px 4px 0 0;font-size:11px;color:var(--muted)}.hidden{display:none!important}.notice{padding:10px 12px;border-radius:9px;background:#1a2b43;color:#a9caff;margin:12px 0}.error{background:#3b2027;color:#ffaaaa}.login{max-width:390px;margin:12vh auto;padding:26px}.login h1{margin:0 0 5px}.empty{padding:22px;text-align:center;color:var(--muted)}small{color:var(--muted)}@media(max-width:600px){.wrap{padding:18px 13px}.top{align-items:flex-start}.row{align-items:flex-start}}
</style></head><body><div id="login" class="card login"><h1>Domain Access Manager</h1><p class="muted">Cloudflare DNS · 1Panel · Reverse Proxy</p><form id="loginForm"><div class="field"><label>管理员密码</label><input name="password" type="password" required autofocus autocomplete="current-password"></div><button class="primary" style="width:100%">登录</button></form><div id="loginMsg"></div></div>
<div id="app" class="wrap hidden"><header class="top"><div><div class="brand">Domain Access Manager</div><small>Cloudflare DNS & 1Panel 管理</small></div><button id="logout">退出登录</button></header>
<nav class="tabs"><button data-tab="overview" class="active">概览</button><button data-tab="cloudflare">Cloudflare</button><button data-tab="nodes">VPS / 1Panel</button><button data-tab="dns">DNS 记录</button><button data-tab="logs">操作记录</button></nav>
<section id="overview" class="tab grid"><div class="card"><h3>Cloudflare 凭据</h3><div id="countCf">-</div><small>多个 Token，自动发现 Zone</small></div><div class="card"><h3>1Panel 节点</h3><div id="countNodes">-</div><small>多个 VPS，独立 API 凭据</small></div><div class="card"><h3>下一步</h3><p class="muted">先添加 Cloudflare Token 和 1Panel 节点，随后即可建设 DNS → SSL → 反向代理的一键发布流程。</p></div></section>
<section id="cloudflare" class="tab hidden grid"><div class="card"><h3>添加 Cloudflare 凭据</h3><form id="cfForm"><div class="field"><label>配置名称</label><input name="name" placeholder="例如：个人域名" required></div><div class="field"><label>API Token</label><input name="token" type="password" autocomplete="off" required></div><button class="primary">验证 Token 并自动获取域名</button></form><div id="cfMsg"></div></div><div class="card"><h3>已保存的 Cloudflare 账号</h3><div id="cfList" class="muted">加载中...</div></div></section>
<section id="nodes" class="tab hidden grid"><div class="card"><h3>添加 1Panel 节点</h3><form id="nodeForm"><div class="field"><label>节点名称</label><input name="name" placeholder="例如：日本 VPS" required></div><div class="field"><label>1Panel HTTPS 地址</label><input name="baseUrl" placeholder="https://panel.example.com:端口" required></div><div class="field"><label>1Panel API Key</label><input name="apiKey" type="password" autocomplete="off" required></div><button class="primary">测试连接并保存</button></form><div id="nodeMsg"></div><div class="notice">请确保 1Panel API 可从 Worker 网络通过 HTTPS 访问。建议使用 Cloudflare Access Service Auth 或 IP 白名单保护面板。</div></div><div class="card"><h3>已保存的 VPS 节点</h3><div id="nodeList" class="muted">加载中...</div></div></section>
<section id="dns" class="tab hidden grid">
<div class="card"><h3>Cloudflare DNS 记录</h3>
<div class="field"><label>Cloudflare 凭据</label><select id="dnsCredential" style="width:100%;padding:10px;background:#0c1424;color:var(--text);border:1px solid var(--line);border-radius:9px"></select></div>
<div class="field"><label>域名 Zone</label><select id="dnsZone" style="width:100%;padding:10px;background:#0c1424;color:var(--text);border:1px solid var(--line);border-radius:9px"></select></div>
<button id="loadDns" class="primary">读取 DNS 记录</button><div id="dnsMsg"></div><div id="dnsList" class="muted" style="margin-top:12px">请选择账号和域名</div></div>
<div class="card"><h3>新增 DNS 记录</h3><form id="dnsForm">
<div class="field"><label>类型</label><select name="type" style="width:100%;padding:10px;background:#0c1424;color:var(--text);border:1px solid var(--line);border-radius:9px"><option>A</option><option>AAAA</option><option>CNAME</option><option>TXT</option></select></div>
<div class="field"><label>记录名称（可填写 @ 或完整域名）</label><input name="name" placeholder="app" required></div>
<div class="field"><label>记录内容</label><input name="content" placeholder="IPv4 / IPv6 / 目标域名 / TXT 内容" required></div>
<div class="field"><label>TTL（1 表示自动）</label><input name="ttl" type="number" min="1" value="1"></div>
<div class="field"><label><input name="proxied" type="checkbox" style="width:auto"> Cloudflare 代理（橙色云）</label></div>
<button class="primary">创建 DNS 记录</button></form><div id="dnsCreateMsg"></div></div></section><section id="logs" class="tab hidden"><div class="card"><h3>最近操作</h3><div id="logList">加载中...</div></div></section></div>
<script>
const $=s=>document.querySelector(s);const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
async function api(path,opts={}){const r=await fetch(path,{...opts,headers:{"content-type":"application/json",...(opts.headers||{})}});const d=await r.json().catch(()=>({error:"服务器响应无法解析"}));if(r.status===401){showLogin();throw new Error(d.error||"登录已过期")}if(!r.ok)throw new Error(d.error||"请求失败");return d}
function msg(el,text,bad=false){el.innerHTML='<div class="notice '+(bad?'error':'')+'">'+esc(text)+'</div>'}
function showLogin(){$("#login").classList.remove("hidden");$("#app").classList.add("hidden")}
function showApp(){$("#login").classList.add("hidden");$("#app").classList.remove("hidden");refresh()}
async function refresh(){await Promise.all([loadCf(),loadNodes(),loadLogs()]);try{await loadDnsCredentials()}catch(e){}}
document.querySelectorAll("[data-tab]").forEach(b=>b.onclick=()=>{document.querySelectorAll("[data-tab]").forEach(x=>x.classList.toggle("active",x===b));document.querySelectorAll(".tab").forEach(x=>x.classList.toggle("hidden",x.id!==b.dataset.tab))});
$("#loginForm").onsubmit=async e=>{e.preventDefault();const p=new FormData(e.target).get("password");try{await api("/api/login",{method:"POST",body:JSON.stringify({password:p})});e.target.reset();$("#loginMsg").innerHTML="";showApp()}catch(err){msg($("#loginMsg"),err.message,true)}};
$("#logout").onclick=async()=>{await api("/api/logout",{method:"POST",body:"{}"});showLogin()};
$("#cfForm").onsubmit=async e=>{e.preventDefault();const f=new FormData(e.target);const b=e.target.querySelector("button");b.disabled=true;b.textContent="验证中...";try{const d=await api("/api/cloudflare/verify",{method:"POST",body:JSON.stringify({name:f.get("name"),token:f.get("token")})});e.target.reset();msg($("#cfMsg"),"验证成功，发现 "+d.item.zoneCount+" 个域名");await loadCf()}catch(err){msg($("#cfMsg"),err.message,true)}finally{b.disabled=false;b.textContent="验证 Token 并自动获取域名"}};
$("#nodeForm").onsubmit=async e=>{e.preventDefault();const f=new FormData(e.target);const b=e.target.querySelector("button");b.disabled=true;b.textContent="连接测试中...";try{const d=await api("/api/nodes/test",{method:"POST",body:JSON.stringify({name:f.get("name"),baseUrl:f.get("baseUrl"),apiKey:f.get("apiKey")})});e.target.reset();msg($("#nodeMsg"),"连接成功"+(d.item.panelVersion?" · 版本 "+d.item.panelVersion:""));await loadNodes()}catch(err){msg($("#nodeMsg"),err.message,true)}finally{b.disabled=false;b.textContent="测试连接并保存"}};
async function loadCf(){try{const d=await api("/api/cloudflare");window.__cfItems=d.items;$("#countCf").textContent=d.items.length+" 个凭据";$("#cfList").innerHTML=d.items.length?d.items.map(x=>'<div class="item"><div class="row"><b>'+esc(x.name)+'</b><button class="danger" data-del-cf="'+esc(x.id)+'">删除</button></div><small>'+x.zone_count+' 个 Zone · Token '+esc(x.token_status)+'</small><div>'+x.zones.map(z=>'<span class="zone">'+esc(z.name)+'</span>').join("")+'</div></div>').join(""):'<div class="empty">尚未添加 Cloudflare 凭据</div>';document.querySelectorAll("[data-del-cf]").forEach(b=>b.onclick=async()=>{if(confirm("确定删除该凭据？")){try{await api("/api/cloudflare/"+b.dataset.delCf,{method:"DELETE"});loadCf()}catch(e){alert(e.message)}}})}catch(e){$("#cfList").textContent=e.message}}
async function loadNodes(){try{const d=await api("/api/nodes");$("#countNodes").textContent=d.items.length+" 台 VPS";$("#nodeList").innerHTML=d.items.length?d.items.map(x=>'<div class="item"><div class="row"><b>'+esc(x.name)+'</b><span class="pill">'+esc(x.connection_status)+'</span></div><small>'+esc(x.base_url)+(x.panel_version?' · '+esc(x.panel_version):'')+'</small><div class="actions" style="margin-top:8px"><button class="danger" data-del-node="'+esc(x.id)+'">删除</button></div></div>').join(""):'<div class="empty">尚未添加 1Panel 节点</div>';document.querySelectorAll("[data-del-node]").forEach(b=>b.onclick=async()=>{if(confirm("确定删除该节点？")){try{await api("/api/nodes/"+b.dataset.delNode,{method:"DELETE"});loadNodes()}catch(e){alert(e.message)}}})}catch(e){$("#nodeList").textContent=e.message}}
async function loadDnsCredentials(){const d=await api("/api/cloudflare");window.__cfItems=d.items;const sel=$("#dnsCredential");sel.innerHTML=d.items.map(x=>'<option value="'+esc(x.id)+'">'+esc(x.name)+'</option>').join("");updateDnsZones();sel.onchange=updateDnsZones}
function updateDnsZones(){const d=$("#dnsCredential").selectedOptions[0];const cfListCache=window.__cfItems||[];const item=cfListCache.find(x=>x.id===d?.value);$("#dnsZone").innerHTML=(item?.zones||[]).map(z=>'<option value="'+esc(z.id)+'">'+esc(z.name)+'</option>').join("")}
async function loadDns(){try{const cred=$("#dnsCredential").value,zone=$("#dnsZone").value;if(!cred||!zone)throw new Error("请先添加 Cloudflare 凭据并选择域名");const d=await api("/api/dns/records?credentialId="+encodeURIComponent(cred)+"&zoneId="+encodeURIComponent(zone));$("#dnsList").innerHTML=d.items.length?d.items.map(x=>'<div class="item"><div class="row"><b>'+esc(x.name)+'</b><button class="danger" data-dns-del="'+esc(x.id)+'">删除</button></div><small>'+esc(x.type)+' · '+esc(x.content)+' · TTL '+esc(x.ttl)+(x.proxied?' · 代理开启':'')+'</small></div>').join(""):'<div class="empty">该域名暂无 DNS 记录</div>';document.querySelectorAll("[data-dns-del]").forEach(b=>b.onclick=async()=>{if(confirm("确定删除这条 DNS 记录？")){try{await api("/api/dns/records/"+b.dataset.dnsDel,{method:"DELETE",body:JSON.stringify({credentialId:cred,zoneId:zone})});await loadDns()}catch(e){alert(e.message)}}})}catch(e){msg($("#dnsMsg"),e.message,true)}}
$("#loadDns").onclick=loadDns;
$("#dnsForm").onsubmit=async e=>{e.preventDefault();const f=new FormData(e.target);try{const d=await api("/api/dns/records",{method:"POST",body:JSON.stringify({credentialId:$("#dnsCredential").value,zoneId:$("#dnsZone").value,type:f.get("type"),name:f.get("name"),content:f.get("content"),ttl:Number(f.get("ttl")||1),proxied:f.get("proxied")==="on"})});msg($("#dnsCreateMsg"),"DNS 记录已创建："+d.item.name);e.target.reset();await loadDns()}catch(err){msg($("#dnsCreateMsg"),err.message,true)}};
async function loadLogs(){try{const d=await api("/api/logs");$("#logList").innerHTML=d.items.length?d.items.map(x=>'<div class="item"><div class="row"><b>'+esc(x.operation)+'</b><span class="pill '+(x.status==="success"?"":"bad")+'">'+esc(x.status)+'</span></div><small>'+esc(x.created_at)+' · '+esc(x.message)+'</small></div>').join(""):'<div class="empty">暂无操作记录</div>'}catch(e){$("#logList").textContent=e.message}}
api("/api/me").then(showApp).catch(showLogin);
</script></body></html>`;

export default {
  async fetch(request, env) {
    try {
      if (!env.DOMAIN_DB) return json({ error: "Missing D1 binding DOMAIN_DB" }, 500);
      if (!env.PASSWORD || !env.SESSION_SECRET || !env.ENCRYPTION_KEY) return json({ error: "请配置 PASSWORD、SESSION_SECRET、ENCRYPTION_KEY 三个 Worker Secrets" }, 500);
      const url = new URL(request.url);
      if (url.pathname.startsWith("/api/")) {
        if (["POST", "PUT", "PATCH", "DELETE"].includes(request.method)) {
          const origin = request.headers.get("Origin");
          if (!origin || new URL(origin).origin !== url.origin) return json({ error: "Cross-origin request rejected" }, 403);
        }
        return await api(request, env, url.pathname);
      }
      if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) return html(PAGE);
      return json({ error: "Not found" }, 404);
    } catch (error) {
      console.error("request failed:", error?.message || "unknown error");
      return json({ error: error?.message || "Internal Server Error" }, 500);
    }
  },
};
