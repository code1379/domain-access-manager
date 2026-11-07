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
    zones.push(...part.map(z => ({ id: z.id, name: z.name, status: z.status, accountId: z.account?.id || "", accountName: z.account?.name || "" })));
    if (part.length < 50) break;
  }
  return zones;
}
async function getTunnelAccountContext(env, credentialId) {
  const row = await env.DOMAIN_DB.prepare("SELECT id,name,account_id,token_ciphertext,zones_json FROM cloudflare_credentials WHERE id=?").bind(credentialId).first();
  if (!row) throw new Error("Cloudflare 凭据不存在");
  const accountId = String(row.account_id || "").trim().toLowerCase();
  if (!/^[0-9a-f]{32}$/.test(accountId)) throw new Error("该凭据缺少有效 Account ID");
  const zones = JSON.parse(row.zones_json || "[]");
  const token = await decryptSecret(env, row.token_ciphertext);
  return { row, zones, token, accountId };
}
async function getTunnelContext(env, credentialId, zoneId) {
  const row = await env.DOMAIN_DB.prepare("SELECT id,name,account_id,token_ciphertext,zones_json FROM cloudflare_credentials WHERE id=?").bind(credentialId).first();
  if (!row) throw new Error("Cloudflare 凭据不存在");
  const accountId = String(row.account_id || "").trim().toLowerCase();
  if (!/^[0-9a-f]{32}$/.test(accountId)) throw new Error("该凭据尚未配置有效的 Account ID，请在 Cloudflare 凭据页面更新为账户 API Token");
  const zones = JSON.parse(row.zones_json || "[]");
  const zone = zones.find(x => x.id === zoneId);
  if (!zone) throw new Error("所选 Zone 不属于此 Cloudflare 账户凭据");
  const token = await decryptSecret(env, row.token_ciphertext);
  let zoneInfo;
  try {
    zoneInfo = await cfRequest(token, "/zones/" + encodeURIComponent(zoneId));
  } catch (error) {
    throw new Error("读取 Cloudflare Zone 账户信息失败，请确认 Token 有 Zone Read 权限：" + (error?.message || String(error)));
  }
  const liveAccountId = String(zoneInfo?.account?.id || "").toLowerCase();
  if (liveAccountId !== accountId) throw new Error("所选 Zone 实际所属 Account ID 与凭据保存的 Account ID 不一致，请检查账号和 Zone");
  return { row, zones, zone, token, accountId };
}
function tunnelApiPath(accountId, tunnelId = "") {
  const base = "/accounts/" + encodeURIComponent(accountId) + "/cfd_tunnel";
  if (!tunnelId) return base;
  if (!/^(?:[0-9a-f]{32}|[0-9a-f-]{36})$/i.test(String(tunnelId))) throw new Error("Tunnel ID 格式无效");
  return base + "/" + encodeURIComponent(tunnelId);
}
async function tunnelRequest(token, path, method = "GET", body) {
  try {
    return await cfRequest(token, path, method, body);
  } catch (error) {
    const message = error?.message || String(error);
    if (/403|forbidden|permission|not authorized|10000/i.test(message)) {
      throw new Error("Cloudflare Tunnel API 权限不足。请在该 Token 的 Account 权限中增加 Cloudflare Tunnel → Edit（至少需要 Tunnel Read/Write）：" + message);
    }
    throw error;
  }
}
async function listAccountTunnels(token, accountId) {
  const all = [];
  const base = tunnelApiPath(accountId);
  for (let page = 1; page <= 20; page++) {
    const items = await tunnelRequest(token, base + "?is_deleted=false&per_page=100&page=" + page);
    if (!Array.isArray(items)) throw new Error("Cloudflare 返回的 Tunnel 列表格式异常");
    all.push(...items);
    if (items.length < 100) break;
  }
  return all;
}
function normalizeTunnelService(value) {
  const service = String(value || "").trim();
  if (!service || service.length > 512) throw new Error("请填写有效的后端服务地址（最多 512 个字符）");
  if (/^https?:\/\//i.test(service)) {
    let url;
    try { url = new URL(service); } catch { throw new Error("后端服务地址格式无效"); }
    if (!url.hostname || url.username || url.password) throw new Error("后端服务地址不能包含用户名或密码");
    return service;
  }
  if (/^(ssh|tcp|rdp|smb):\/\/[^\s]+$/i.test(service)) return service;
  if (/^unix:\/\/.+$/i.test(service)) return service;
  throw new Error("支持 http://、https://、ssh://、tcp://、rdp://、smb:// 或 unix:// 服务地址");
}
function normalizeTunnelHostname(sub, zoneName) {
  let prefix = String(sub || "").trim().toLowerCase().replace(/\.$/, "");
  if (prefix === "@" || prefix === zoneName) prefix = "";
  if (prefix && prefix.endsWith("." + zoneName)) prefix = prefix.slice(0, -(zoneName.length + 1));
  if (prefix && !/^(?=.{1,200}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$/.test(prefix)) {
    throw new Error("子域名前缀格式无效，只能使用字母、数字、连字符和点");
  }
  const hostname = prefix ? prefix + "." + zoneName : zoneName;
  if (hostname.length > 253) throw new Error("完整域名过长");
  return hostname;
}
async function ensureTunnelCname(token, zoneId, hostname, tunnelId) {
  const target = tunnelId + ".cfargotunnel.com";
  const path = "/zones/" + encodeURIComponent(zoneId) + "/dns_records?name=" + encodeURIComponent(hostname) + "&per_page=100";
  const records = await cfRequest(token, path);
  const existing = records.find(x => x.type === "CNAME" && String(x.content || "").toLowerCase() === target.toLowerCase());
  const conflicts = records.filter(x => x.id !== existing?.id);
  if (conflicts.length) {
    const detail = conflicts.map(x => x.type + " → " + x.content).join(", ");
    throw new Error("域名 " + hostname + " 已有其他 DNS 记录：" + detail + "。为避免覆盖，未修改 DNS");
  }
  if (existing) return { created: false, recordId: existing.id };
  const created = await cfRequest(token, "/zones/" + encodeURIComponent(zoneId) + "/dns_records", "POST", {
    type: "CNAME", name: hostname, content: target, ttl: 1, proxied: true,
    comment: "Managed by Domain Access Manager · Cloudflare Tunnel"
  });
  return { created: true, recordId: created?.id || "" };
}
function findTunnelZone(zones, hostname) {
  return (zones || []).filter(z => hostname === z.name || hostname.endsWith("." + z.name)).sort((a,b) => b.name.length - a.name.length)[0] || null;
}
async function cleanupTunnelCnames(token, zones, tunnelId, hostnames) {
  const target = tunnelId + ".cfargotunnel.com";
  const removed = [];
  const warnings = [];
  for (const hostname of [...new Set(hostnames)].filter(Boolean)) {
    const zone = findTunnelZone(zones, hostname);
    if (!zone) { warnings.push("找不到域名所属 Zone：" + hostname); continue; }
    try {
      const records = await cfRequest(token, "/zones/" + encodeURIComponent(zone.id) + "/dns_records?type=CNAME&name=" + encodeURIComponent(hostname) + "&per_page=100");
      for (const record of records) {
        if (record.type === "CNAME" && String(record.content || "").toLowerCase() === target.toLowerCase()) {
          await cfRequest(token, "/zones/" + encodeURIComponent(zone.id) + "/dns_records/" + encodeURIComponent(record.id), "DELETE");
          removed.push(hostname);
        }
      }
    } catch (error) {
      warnings.push(hostname + "： " + (error?.message || String(error)));
    }
  }
  return { removed, warnings };
}
async function getTunnelConfiguration(token, accountId, tunnelId) {
  const result = await tunnelRequest(token, tunnelApiPath(accountId, tunnelId) + "/configurations");
  const config = result?.config || {};
  return { config, ingress: Array.isArray(config.ingress) ? config.ingress.slice() : [] };
}
async function putTunnelConfiguration(token, accountId, tunnelId, config, ingress) {
  let rules = ingress.slice();
  if (!rules.some(x => !x.hostname && !x.path)) rules.push({ service: "http_status:404" });
  const lastCatchAll = rules.findIndex(x => !x.hostname && !x.path);
  if (lastCatchAll !== rules.length - 1) {
    const catchAll = rules.splice(lastCatchAll, 1)[0];
    rules.push(catchAll);
  }
  await tunnelRequest(token, tunnelApiPath(accountId, tunnelId) + "/configurations", "PUT", {
    config: { ...config, ingress: rules }
  });
  return rules;
}

function safeName(value) {
  const name = String(value || "").trim();
  if (!name || name.length > 80) throw new Error("名称不能为空且不能超过 80 个字符");
  return name;
}
function safeBaseUrl(value) {
  const url = new URL(String(value || ""));
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.search || url.hash) {
    throw new Error("1Panel 地址必须使用 HTTP 或 HTTPS，且不能包含用户名、密码、查询参数或片段");
  }
  return url.origin + url.pathname.replace(/\/+$/, "");
}
async function panelRequest(baseUrl, apiKey, method, apiPath, body) {
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const signature = await hmac("1panel:" + timestamp, apiKey);
  const token = Array.from(signature, b => b.toString(16).padStart(2, "0")).join("");
  const url = baseUrl.replace(/\/+$/, "") + "/api/v2" + apiPath;
  let response;
  try {
    response = await fetch(url, {
      method,
      headers: {
        "1Panel-Token": token,
        "1Panel-Timestamp": timestamp,
        "1Panel-Signature-Version": "hmac-sha256",
        "content-type": "application/json"
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(25000)
    });
  } catch (error) {
    throw new Error("Worker Fetch 请求失败：" + (error?.message || String(error)));
  }
  const raw = await response.text();
  let payload = {};
  try { payload = raw ? JSON.parse(raw) : {}; } catch {}
  if (!response.ok || (payload.code !== undefined && Number(payload.code) !== 200)) {
    const contentType = response.headers.get("content-type") || "unknown";
    const server = response.headers.get("server") || "unknown";
    const ray = response.headers.get("cf-ray") || "";
    const bodySummary = String(payload.message || payload.msg || raw || "").replace(/\\s+/g, " ").slice(0, 500);
    throw new Error([
      "1Panel API HTTP " + response.status,
      "content-type=" + contentType,
      "server=" + server,
      ray ? "cf-ray=" + ray : "",
      "request=" + method + " " + apiPath,
      bodySummary ? "response=" + bodySummary : "response body empty"
    ].filter(Boolean).join("; "));
  }
  return payload.data !== undefined ? payload.data : payload;
}
async function getPanelNode(env, nodeId) {
  const node = await env.DOMAIN_DB.prepare("SELECT * FROM panel_nodes WHERE id=?").bind(nodeId).first();
  if (!node) throw new Error("1Panel 节点不存在");
  return { node, apiKey: await decryptSecret(env, node.api_key_ciphertext) };
}
function isIPv4(value) {
  const parts = String(value || "").split(".");
  return parts.length === 4 && parts.every(p => /^\d{1,3}$/.test(p) && Number(p) >= 0 && Number(p) <= 255);
}
function normalizeHostname(value, zoneName) {
  const hostname = String(value || "").trim().toLowerCase().replace(/\.$/, "");
  if (!/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(hostname)) throw new Error("请输入有效的完整域名");
  if (hostname !== zoneName && !hostname.endsWith("." + zoneName)) throw new Error("域名必须属于所选 Cloudflare Zone：" + zoneName);
  return hostname;
}
function normalizeUpstream(value) {
  const raw = String(value || "").trim();
  const url = new URL(raw);
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.search || url.hash) throw new Error("反向代理地址必须是 http:// 或 https:// 地址，且不能包含账号、查询参数或片段");
  return url.origin + url.pathname.replace(/\/$/, "");
}
async function panelPageItems(baseUrl, apiKey, path, body) {
  const data = await panelRequest(baseUrl, apiKey, "POST", path, body || { page: 1, pageSize: 100 });
  if (Array.isArray(data)) return data;
  if (Array.isArray(data.items)) return data.items;
  if (Array.isArray(data.list)) return data.list;
  return [];
}
async function ensurePanelAccounts(env, node, apiKey, credentialId, credentialName, cloudflareToken, email) {
  const existing = await env.DOMAIN_DB.prepare("SELECT * FROM panel_cloudflare_dns_accounts WHERE panel_node_id=? AND cloudflare_credential_id=?").bind(node.id, credentialId).first();
  const dnsName = "DAM-CF-" + credentialId.slice(0, 8);
  const dnsAccounts = await panelPageItems(node.base_url, apiKey, "/websites/dns/search", { page: 1, pageSize: 100 });
  let dnsAccount = dnsAccounts.find(x => Number(x.id) === Number(existing?.dns_account_id) && x.type === "CloudFlare");
  if (!dnsAccount) dnsAccount = dnsAccounts.find(x => x.name === dnsName && x.type === "CloudFlare");
  if (!dnsAccount) {
    await panelRequest(node.base_url, apiKey, "POST", "/websites/dns", {
      name: dnsName,
      type: "CloudFlare",
      authorization: { email: "", apiKey: cloudflareToken }
    });
    const refreshed = await panelPageItems(node.base_url, apiKey, "/websites/dns/search", { page: 1, pageSize: 100 });
    dnsAccount = refreshed.find(x => x.name === dnsName && x.type === "CloudFlare");
  }
  if (!dnsAccount?.id) throw new Error("1Panel Cloudflare DNS 账户不存在或创建后无法读取，请检查网站设置中的 DNS 账户列表");
  const dnsAccountId = Number(dnsAccount.id);
  // Refresh the 1Panel DNS account authorization so rotating from a deleted
  // User API Token to an Account API Token does not leave a stale credential.
  await panelRequest(node.base_url, apiKey, "POST", "/websites/dns/update", {
    id: dnsAccountId,
    name: dnsName,
    type: "CloudFlare",
    authorization: { email: "", apiKey: cloudflareToken }
  });

  const acmeAccounts = await panelPageItems(node.base_url, apiKey, "/websites/acme/search", { page: 1, pageSize: 100 });
  let acmeAccount = acmeAccounts.find(x => Number(x.id) === Number(existing?.acme_account_id) && String(x.email || "").toLowerCase() === email.toLowerCase() && x.type === "letsencrypt");
  if (!acmeAccount) acmeAccount = acmeAccounts.find(x => String(x.email || "").toLowerCase() === email.toLowerCase() && x.type === "letsencrypt");
  if (!acmeAccount) {
    const created = await panelRequest(node.base_url, apiKey, "POST", "/websites/acme", {
      email, type: "letsencrypt", keyType: "EC256", useProxy: false
    });
    const createdId = Number(created.id || created.ID || created.data?.id || 0);
    if (createdId) acmeAccount = { id: createdId, email, type: "letsencrypt" };
    if (!acmeAccount) {
      const refreshed = await panelPageItems(node.base_url, apiKey, "/websites/acme/search", { page: 1, pageSize: 100 });
      acmeAccount = refreshed.find(x => String(x.email || "").toLowerCase() === email.toLowerCase() && x.type === "letsencrypt");
    }
  }
  if (!acmeAccount?.id) throw new Error("Let's Encrypt 账户不存在或创建后无法读取，请检查 1Panel ACME 账户列表");
  const acmeAccountId = Number(acmeAccount.id);

  const now = new Date().toISOString();
  const id = existing?.id || randomId();
  await env.DOMAIN_DB.prepare("INSERT INTO panel_cloudflare_dns_accounts(id,panel_node_id,cloudflare_credential_id,dns_account_id,acme_account_id,acme_email,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(panel_node_id,cloudflare_credential_id) DO UPDATE SET dns_account_id=excluded.dns_account_id,acme_account_id=excluded.acme_account_id,acme_email=excluded.acme_email,updated_at=excluded.updated_at")
    .bind(id, node.id, credentialId, dnsAccountId, acmeAccountId, email, now, now).run();
  return { dnsAccountId, acmeAccountId };
}
async function findCloudflareARecord(token, zoneId, hostname) {
  const records = await cfRequest(token, "/zones/" + encodeURIComponent(zoneId) + "/dns_records?type=A&name=" + encodeURIComponent(hostname) + "&per_page=100");
  return records;
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
    const { results } = await env.DOMAIN_DB.prepare("SELECT id,name,account_id,zones_json,zone_count,token_status,created_at,updated_at,last_verified_at FROM cloudflare_credentials ORDER BY created_at DESC").all();
    return json({ items: results.map(x => ({ ...x, zones: JSON.parse(x.zones_json || "[]") })) });
  }
  if (path === "/api/cloudflare/verify" && request.method === "POST") {
    const name = safeName(body.name);
    const accountId = String(body.accountId || "").trim().toLowerCase();
    const credentialId = String(body.credentialId || "").trim();
    const token = String(body.token || "").trim();
    if (!/^[0-9a-f]{32}$/.test(accountId)) return json({ error: "Account ID 必须是 32 位十六进制字符串" }, 400);
    if (!token || token.length > 4096) return json({ error: "请填写账户 API Token" }, 400);
    try {
      const verify = await cfRequest(token, "/accounts/" + encodeURIComponent(accountId) + "/tokens/verify");
      if (verify.status !== "active") throw new Error("Cloudflare 账户 API Token 状态不是 active");
      const discoveredZones = await discoverZones(token);
      const zones = discoveredZones.filter(z => String(z.accountId || "").toLowerCase() === accountId);
      if (!zones.length) throw new Error("账户 API Token 有效，但没有发现该 Account 下可访问的 Zone。请检查 Account ID，以及 Zone → Read 权限。");
      const encrypted = await encryptSecret(env, token);
      const now = new Date().toISOString();
      let id = credentialId;
      if (credentialId) {
        const existing = await env.DOMAIN_DB.prepare("SELECT id FROM cloudflare_credentials WHERE id=?").bind(credentialId).first();
        if (!existing) return json({ error: "要更新的 Cloudflare 凭据不存在，请刷新页面后重试" }, 404);
        const linked = await env.DOMAIN_DB.prepare("SELECT hostname,zone_id FROM managed_sites WHERE cloudflare_credential_id=?").bind(credentialId).all();
        const missingZones = (linked.results || []).filter(site => !zones.some(z => z.id === site.zone_id));
        if (missingZones.length) throw new Error("新 Token 无法访问这些已接入域名所属的 Zone：" + missingZones.map(x => x.hostname).join(", ") + "。为保护现有域名，请使用包含这些 Zone 的 Account API Token。");
        await env.DOMAIN_DB.prepare("UPDATE cloudflare_credentials SET name=?,account_id=?,token_ciphertext=?,zones_json=?,zone_count=?,token_status='active',updated_at=?,last_verified_at=? WHERE id=?")
          .bind(name, accountId, encrypted, JSON.stringify(zones), zones.length, now, now, credentialId).run();
      } else {
        id = randomId();
        await env.DOMAIN_DB.prepare("INSERT INTO cloudflare_credentials(id,name,account_id,token_ciphertext,zones_json,zone_count,token_status,created_at,updated_at,last_verified_at) VALUES(?,?,?,?,?,?,?,?,?,?)")
          .bind(id, name, accountId, encrypted, JSON.stringify(zones), zones.length, "active", now, now, now).run();
      }
      await log(env, credentialId ? "credential.update" : "credential.add", "cloudflare", id, "success", "Cloudflare 账户 API Token 验证成功并发现 " + zones.length + " 个 Zone", { accountId });
      return json({ ok: true, item: { id, name, accountId, zones, zoneCount: zones.length, tokenStatus: "active" } });
    } catch (error) {
      await log(env, credentialId ? "credential.update" : "credential.verify", "cloudflare", credentialId || null, "failed", error.message, { accountId });
      return json({ error: error.message }, 400);
    }
  }
  const cfDelete = path.match(/^\/api\/cloudflare\/([0-9a-f-]+)$/);
  if (cfDelete && request.method === "DELETE") {
    const id = cfDelete[1];
    const linked = await env.DOMAIN_DB.prepare("SELECT COUNT(*) AS count FROM managed_sites WHERE cloudflare_credential_id=?").bind(id).first();
    if (Number(linked?.count || 0)) return json({ error: "该凭据仍被域名接入任务使用，请先在「域名管理」中删除这些域名，再删除 Cloudflare 凭据" }, 409);
    const panelMappings = await env.DOMAIN_DB.prepare("SELECT COUNT(*) AS count FROM panel_cloudflare_dns_accounts WHERE cloudflare_credential_id=?").bind(id).first();
    // These rows only map this DAM credential to DNS/ACME account IDs in 1Panel.
    // Remove the local mapping before deleting the credential; do NOT delete the
    // actual 1Panel DNS or ACME accounts because certificates outside DAM may use them.
    await env.DOMAIN_DB.batch([
      env.DOMAIN_DB.prepare("DELETE FROM panel_cloudflare_dns_accounts WHERE cloudflare_credential_id=?").bind(id),
      env.DOMAIN_DB.prepare("DELETE FROM cloudflare_credentials WHERE id=?").bind(id)
    ]);
    await log(env, "credential.delete", "cloudflare", id, "success", "Cloudflare 凭据已删除；本地 1Panel DNS/ACME 关联缓存已清理，1Panel 中的账户本身予以保留", {
      removedPanelMappings: Number(panelMappings?.count || 0),
      panelAccountsPreserved: true
    });
    return json({ ok: true, removedPanelMappings: Number(panelMappings?.count || 0), panelAccountsPreserved: true });
  }
  if (path === "/api/nodes" && request.method === "GET") {
    const { results } = await env.DOMAIN_DB.prepare("SELECT id,name,base_url,panel_version,server_info_json,connection_status,created_at,updated_at,last_checked_at FROM panel_nodes ORDER BY created_at DESC").all();
    return json({ items: results.map(x => ({ ...x, serverInfo: JSON.parse(x.server_info_json || "{}") })) });
  }
  if (path === "/api/nodes/dns" && request.method === "POST") {
    const credentialId=String(body.credentialId||"");
    const zoneId=String(body.zoneId||"");
    const prefix=String(body.prefix||"").trim().toLowerCase();
    const sourceUrl=new URL(String(body.baseUrl||""));
    const ip=sourceUrl.hostname;
    if(!credentialId||!zoneId||!prefix||!isIPv4(ip)) return json({error:"请先填写 IPv4 格式的 1Panel 地址，并选择 Cloudflare 凭据、域名和记录前缀"},400);
    if(!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(prefix)) return json({error:"DNS 前缀只能包含字母、数字和连字符"},400);
    const row=await env.DOMAIN_DB.prepare("SELECT token_ciphertext,zones_json FROM cloudflare_credentials WHERE id=?").bind(credentialId).first();
    if(!row) return json({error:"Cloudflare 凭据不存在"},404);
    const zone=JSON.parse(row.zones_json||"[]").find(z=>z.id===zoneId);
    if(!zone) return json({error:"所选 Zone 不属于此 Cloudflare Token"},403);
    const hostname=prefix+"."+zone.name;
    const token=await decryptSecret(env,row.token_ciphertext);
    const existing=await cfRequest(token,"/zones/"+encodeURIComponent(zoneId)+"/dns_records?type=A&name="+encodeURIComponent(hostname)+"&per_page=100");
    let record=existing.find(x=>x.name===hostname);
    if(record && record.content!==ip) return json({error:"该 DNS 名称已存在，但指向不同 IP："+record.content+"。请更换前缀或先处理原记录"},409);
    if(!record) {
      const created=await cfRequest(token,"/zones/"+encodeURIComponent(zoneId)+"/dns_records","POST",{type:"A",name:hostname,content:ip,ttl:1,proxied:false,comment:"Managed by Domain Access Manager"});
      record=created;
    }
    const baseUrl=sourceUrl.protocol+"//"+hostname+(sourceUrl.port?":"+sourceUrl.port:"");
    await log(env,"dns.panel_alias","dns_record",record.id,"success","1Panel 管理地址 DNS-only 记录已准备",{hostname,ip,port:sourceUrl.port||"",zone:zone.name});
    return json({ok:true,item:{hostname,ip,recordId:record.id,baseUrl,proxied:false,created:existing.length===0}});
  }
  if (path === "/api/nodes/test" && request.method === "POST") {
    const name = safeName(body.name);
    const baseUrl = safeBaseUrl(body.baseUrl);
    const apiKey = String(body.apiKey || "").trim();
    if (!apiKey || apiKey.length > 4096) return json({ error: "请填写 1Panel API Key" }, 400);
    try {
      const info = await panelRequest(baseUrl, apiKey, "GET", "/dashboard/base/os");
      const id = randomId();
      const encrypted = await encryptSecret(env, apiKey);
      const now = new Date().toISOString();
      const version = info.version || info.panelVersion || "";
      const serverInfo = {
        hostname: info.hostname || "",
        os: info.os || "",
        platform: info.platform || "",
        platformFamily: info.platformFamily || "",
        distro: info.prettyDistro || "",
        kernelArch: info.kernelArch || "",
        kernelVersion: info.kernelVersion || "",
        ipV4Addr: info.ipV4Addr || ""
      };
      await env.DOMAIN_DB.prepare("INSERT INTO panel_nodes(id,name,base_url,api_key_ciphertext,panel_version,server_info_json,connection_status,created_at,updated_at,last_checked_at) VALUES(?,?,?,?,?,?,?,?,?,?)")
        .bind(id, name, baseUrl, encrypted, version, JSON.stringify(serverInfo), "connected", now, now, now).run();
      await log(env, "node.add", "1panel", id, "success", "1Panel 节点连接成功");
      return json({ ok: true, item: { id, name, baseUrl, panelVersion: version, serverInfo, status: "connected" } });
    } catch (error) {
      await log(env, "node.test", "1panel", null, "failed", error.message);
      return json({ error: error.message }, 400);
    }
  }
  if (path === "/api/publish" && request.method === "POST") {
    const credentialId = String(body.credentialId || "");
    const zoneId = String(body.zoneId || "");
    const nodeId = String(body.nodeId || "");
    const email = String(body.email || "").trim().toLowerCase();
    const hostnameInput = String(body.hostname || "");
    const upstream = normalizeUpstream(body.upstream);
    if (!credentialId || !zoneId || !nodeId || !email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({error:"请选择 Cloudflare Zone、1Panel 节点，并填写有效的 ACME 邮箱"},400);
    const cfRow = await env.DOMAIN_DB.prepare("SELECT * FROM cloudflare_credentials WHERE id=?").bind(credentialId).first();
    if (!cfRow) return json({error:"Cloudflare 凭据不存在"},404);
    const zone = JSON.parse(cfRow.zones_json || "[]").find(z=>z.id===zoneId);
    if (!zone) return json({error:"所选 Zone 不属于此 Cloudflare Token"},403);
    const hostname = normalizeHostname(hostnameInput,zone.name);
    const {node,apiKey} = await getPanelNode(env,nodeId);
    if (node.connection_status !== "connected") return json({error:"1Panel 节点当前未连接，请先重新测试连接"},409);
    const info = JSON.parse(node.server_info_json || "{}");
    const ip = String(body.ipv4 || info.ipV4Addr || "").trim();
    if (!isIPv4(ip)) return json({error:"无法从 1Panel 获取有效公网 IPv4，请手动填写服务器 IPv4 地址"},400);
    const token = await decryptSecret(env,cfRow.token_ciphertext);
    const existingSites = await env.DOMAIN_DB.prepare("SELECT id,status FROM managed_sites WHERE hostname=?").bind(hostname).first();
    if (existingSites) return json({error:"该域名已在本工具中登记，当前状态："+existingSites.status+"。请在域名管理中查看或恢复任务，不能重复创建"},409);
    const existingRecords = await findCloudflareARecord(token,zoneId,hostname);
    if (existingRecords.length && existingRecords.some(r=>r.content!==ip)) return json({error:"Cloudflare 已存在不同 IP 的 A 记录，本工具不会覆盖现有记录。请先检查 DNS 后再接入"},409);
    const dnsCreated = existingRecords.length === 0;
    let dnsRecordId = existingRecords[0]?.id || null;
    if (dnsCreated) {
      const createdRecord = await cfRequest(token,"/zones/"+encodeURIComponent(zoneId)+"/dns_records","POST",{type:"A",name:hostname,content:ip,ttl:1,proxied:Boolean(body.proxied)});
      dnsRecordId = createdRecord?.id || null;
    }
    const siteId = randomId();
    const now = new Date().toISOString();
    const meta = {stage:"provisioning",zoneName:zone.name,zoneId,ipv4:ip,upstream,email,proxied:Boolean(body.proxied),dnsCreated,createdDnsRecordId:dnsCreated?dnsRecordId:null,sslCreatedByDam:false};
    await env.DOMAIN_DB.prepare("INSERT INTO managed_sites(id,hostname,zone_id,cloudflare_credential_id,panel_node_id,upstream_url,dns_record_id,status,metadata_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)")
      .bind(siteId,hostname,zoneId,credentialId,nodeId,upstream,dnsRecordId,"provisioning",JSON.stringify(meta),now,now).run();
    try {
      const accounts = await ensurePanelAccounts(env,node,apiKey,credentialId,cfRow.name,token,email);
      meta.dnsAccountId=accounts.dnsAccountId;
      meta.acmeAccountId=accounts.acmeAccountId;
      const ssl = await panelRequest(node.base_url,apiKey,"POST","/websites/ssl",{
        primaryDomain:hostname,otherDomains:"",provider:"dnsAccount",acmeAccountId:accounts.acmeAccountId,dnsAccountId:accounts.dnsAccountId,autoRenew:true,keyType:"EC256",disableCNAME:false,skipDNS:false,apply:true,description:"Domain Access Manager"
      });
      const sslId=Number(ssl.id||ssl.ID||ssl.data?.id||0);
      if(!sslId) throw new Error("1Panel 已提交证书申请，但未返回证书 ID");
      meta.sslId=sslId;
      meta.sslCreatedByDam=true;
      meta.stage="certificate_pending";
      await env.DOMAIN_DB.prepare("UPDATE managed_sites SET ssl_id=?,status=?,metadata_json=?,updated_at=? WHERE id=?")
        .bind(String(sslId), "certificate_pending",JSON.stringify(meta),new Date().toISOString(),siteId).run();
      await log(env,"publish.start","managed_site",siteId,"success","已创建 DNS 并提交 1Panel DNS-01 证书申请",{hostname,zone:zone.name,node:node.name,sslId});
      return json({ok:true,item:{id:siteId,hostname,status:"certificate_pending",stage:meta.stage,sslId}});
    } catch(error) {
      meta.stage="failed";
      meta.error=error.message;
      await env.DOMAIN_DB.prepare("UPDATE managed_sites SET status='failed',last_error=?,metadata_json=?,updated_at=? WHERE id=?")
        .bind(error.message,JSON.stringify(meta),new Date().toISOString(),siteId).run();
      await log(env,"publish.start","managed_site",siteId,"failed",error.message,{hostname});
      return json({error:error.message,siteId},400);
    }
  }
  if (path === "/api/domains" && request.method === "GET") {
    const {results}=await env.DOMAIN_DB.prepare("SELECT s.id,s.hostname,s.upstream_url,s.status,s.last_error,s.metadata_json,s.created_at,s.updated_at,n.name AS node_name FROM managed_sites s LEFT JOIN panel_nodes n ON n.id=s.panel_node_id ORDER BY s.created_at DESC LIMIT 200").all();
    return json({items:results.map(x=>({id:x.id,hostname:x.hostname,upstream:x.upstream_url,nodeName:x.node_name||"未知 VPS",status:x.status,lastError:x.last_error,metadata:JSON.parse(x.metadata_json||"{}"),createdAt:x.created_at,updatedAt:x.updated_at}))});
  }
  const domainDelete = path.match(new RegExp("^/api/domains/([0-9a-f-]+)$"));
  if (domainDelete && request.method === "DELETE") {
    const id=domainDelete[1];
    const site=await env.DOMAIN_DB.prepare("SELECT * FROM managed_sites WHERE id=?").bind(id).first();
    if(!site) return json({ok:true,alreadyDeleted:true});
    const meta=JSON.parse(site.metadata_json||"{}");
    const {node,apiKey}=await getPanelNode(env,site.panel_node_id);
    const cleanup={...(meta.cleanup||{})};
    const saveCleanup=async(status="deleting",error=null)=>{
      meta.cleanup=cleanup;
      await env.DOMAIN_DB.prepare("UPDATE managed_sites SET status=?,last_error=?,metadata_json=?,updated_at=? WHERE id=?")
        .bind(status,error,JSON.stringify(meta),new Date().toISOString(),id).run();
    };
    try {
      await saveCleanup("deleting",null);

      const websiteId=Number(meta.websiteId||site.panel_website_id||0);
      if(websiteId&&!cleanup.websiteDeleted){
        let website=null;
        try{website=await panelRequest(node.base_url,apiKey,"GET","/websites/"+encodeURIComponent(websiteId));}
        catch(error){if(!/record not found|not found|HTTP 404/i.test(error.message||""))throw new Error("检查 1Panel 网站失败："+error.message);}
        const websiteData=website?.website||website;
        if(websiteData){
          const actualDomain=String(websiteData.primaryDomain||"").toLowerCase();
          if(actualDomain&&actualDomain!==site.hostname.toLowerCase())throw new Error("1Panel 网站 ID 与域名不匹配，已停止删除以保护其他网站");
          await panelRequest(node.base_url,apiKey,"POST","/websites/del",{id:websiteId,deleteApp:false,deleteBackup:false,forceDelete:false,deleteDB:false});
        }
        cleanup.websiteDeleted=true;
        await saveCleanup();
      }

      const sslId=Number(meta.sslId||site.ssl_id||0);
      if(sslId&&!cleanup.sslDeleted){
        if(meta.sslCreatedByDam===false){
          cleanup.sslPreserved=true;
        }else{
          let sslRecord=null;
          try{sslRecord=await panelRequest(node.base_url,apiKey,"GET","/websites/ssl/"+encodeURIComponent(sslId));}
          catch(error){if(!/record not found|not found|HTTP 404/i.test(error.message||""))throw new Error("检查 1Panel SSL 证书失败："+error.message);}
          const sslData=sslRecord?.websiteSSL||sslRecord;
          if(sslData){
            const sslDomain=String(sslData.primaryDomain||"").toLowerCase();
            if(sslDomain&&sslDomain!==site.hostname.toLowerCase())throw new Error("SSL 证书 ID 与域名不匹配，已停止删除以保护其他证书");
            const owned=meta.sslCreatedByDam===true||sslData.description==="Domain Access Manager";
            if(owned){
              await panelRequest(node.base_url,apiKey,"POST","/websites/ssl/del",{ids:[sslId]});
            }else{
              cleanup.sslPreserved=true;
            }
          }
        }
        cleanup.sslDeleted=true;
        await saveCleanup();
      }

      if(meta.dnsCreated&&!cleanup.dnsDeleted){
        const cfRow=await env.DOMAIN_DB.prepare("SELECT token_ciphertext FROM cloudflare_credentials WHERE id=?").bind(site.cloudflare_credential_id).first();
        if(!cfRow)throw new Error("Cloudflare 凭据不存在，无法清理本工具创建的 DNS 记录");
        const cloudflareToken=await decryptSecret(env,cfRow.token_ciphertext);
        const records=await cfRequest(cloudflareToken,"/zones/"+encodeURIComponent(site.zone_id)+"/dns_records?type=A&name="+encodeURIComponent(site.hostname)+"&per_page=100");
        let record=null;
        if(meta.createdDnsRecordId){
          record=records.find(x=>x.id===meta.createdDnsRecordId)||null;
        }else{
          const matching=records.filter(x=>x.content===String(meta.ipv4||""));
          if(matching.length===1)record=matching[0];
          else if(matching.length>1)throw new Error("找到多条相同 IP 的 A 记录，无法确认哪条由本工具创建；为安全起见未删除 DNS");
        }
        if(record&&record.content===String(meta.ipv4||"")){
          await cfRequest(cloudflareToken,"/zones/"+encodeURIComponent(site.zone_id)+"/dns_records/"+encodeURIComponent(record.id),"DELETE");
          cleanup.dnsDeleted=true;
        }else{
          cleanup.dnsPreserved=true;
          cleanup.dnsDeleted=true;
        }
        await saveCleanup();
      }else if(!meta.dnsCreated){
        cleanup.dnsPreserved=true;
        cleanup.dnsDeleted=true;
        await saveCleanup();
      }

      await env.DOMAIN_DB.prepare("DELETE FROM managed_sites WHERE id=?").bind(id).run();
      try{await log(env,"domain.delete","managed_site",id,"success","域名接入及其托管资源已清理",{hostname:site.hostname,cleanup});}catch{}
      return json({ok:true,item:{id,hostname:site.hostname,cleanup}});
    }catch(error){
      const message=error?.message||String(error);
      await saveCleanup("delete_failed",message);
      await log(env,"domain.delete","managed_site",id,"failed",message,{hostname:site.hostname,cleanup});
      return json({error:message,item:{id,hostname:site.hostname,status:"delete_failed",cleanup}},400);
    }
  }
  if (path === "/api/publish" && request.method === "GET") {
    const {results}=await env.DOMAIN_DB.prepare("SELECT id,hostname,status,last_error,metadata_json,created_at,updated_at FROM managed_sites ORDER BY created_at DESC LIMIT 100").all();
    return json({items:results.map(x=>({id:x.id,hostname:x.hostname,status:x.status,lastError:x.last_error,metadata:JSON.parse(x.metadata_json||"{}"),createdAt:x.created_at,updatedAt:x.updated_at}))});
  }
  const publishProgress = path.match(/^\/api\/publish\/([0-9a-f-]+)\/progress$/);
  if (publishProgress && request.method === "POST") {
    const id=publishProgress[1];
    const site=await env.DOMAIN_DB.prepare("SELECT * FROM managed_sites WHERE id=?").bind(id).first();
    if(!site) return json({error:"域名任务不存在"},404);
    const meta=JSON.parse(site.metadata_json||"{}");
    if(site.status==="ready") return json({ok:true,item:{id,hostname:site.hostname,status:site.status,websiteId:meta.websiteId,sslId:site.ssl_id}});
    const {node,apiKey}=await getPanelNode(env,site.panel_node_id);
    try {
      if(!meta.sslId) {
        const cfRow=await env.DOMAIN_DB.prepare("SELECT name,token_ciphertext FROM cloudflare_credentials WHERE id=?").bind(site.cloudflare_credential_id).first();
        if(!cfRow) throw new Error("Cloudflare 凭据不存在，无法恢复证书申请");
        const cloudflareToken=await decryptSecret(env,cfRow.token_ciphertext);
        const accounts=await ensurePanelAccounts(env,node,apiKey,site.cloudflare_credential_id,cfRow.name,cloudflareToken,meta.email);
        const sslMatches=await panelPageItems(node.base_url,apiKey,"/websites/ssl/search",{
          page:1,pageSize:100,domain:site.hostname,orderBy:"created_at",order:"descending"
        });
        const sameDomain=sslMatches.filter(x=>String(x.primaryDomain||"").toLowerCase()===site.hostname.toLowerCase());
        const reusable=sameDomain.find(x=>Number(x.acmeAccountId)===accounts.acmeAccountId&&Number(x.dnsAccountId)===accounts.dnsAccountId);
        if(reusable?.id) {
          meta.sslId=Number(reusable.id);
          meta.sslCreatedByDam=false;
        } else if(sameDomain.length) {
          throw new Error("1Panel 已存在该域名的 SSL 记录，但使用了其他 ACME 或 DNS 账户。为避免重复申请，请先在 1Panel 检查该域名证书");
        } else {
          const createdSSL=await panelRequest(node.base_url,apiKey,"POST","/websites/ssl",{
            primaryDomain:site.hostname,otherDomains:"",provider:"dnsAccount",acmeAccountId:accounts.acmeAccountId,dnsAccountId:accounts.dnsAccountId,autoRenew:true,keyType:"EC256",disableCNAME:false,skipDNS:false,apply:true,description:"Domain Access Manager"
          });
          meta.sslId=Number(createdSSL.id||createdSSL.ID||createdSSL.data?.id||0);
          meta.sslCreatedByDam=true;
          if(!meta.sslId) {
            const refreshed=await panelPageItems(node.base_url,apiKey,"/websites/ssl/search",{
              page:1,pageSize:100,domain:site.hostname,orderBy:"created_at",order:"descending"
            });
            const found=refreshed.find(x=>String(x.primaryDomain||"").toLowerCase()===site.hostname.toLowerCase()&&Number(x.acmeAccountId)===accounts.acmeAccountId&&Number(x.dnsAccountId)===accounts.dnsAccountId);
            meta.sslId=Number(found?.id||0);
            if(meta.sslId) meta.sslCreatedByDam=true;
          }
          if(!meta.sslId) throw new Error("1Panel 未返回 SSL ID，且无法通过域名查询到新建的证书记录");
        }
        meta.stage="certificate_pending";
        delete meta.error;
        await env.DOMAIN_DB.prepare("UPDATE managed_sites SET ssl_id=?,status='certificate_pending',last_error=NULL,metadata_json=?,updated_at=? WHERE id=?")
          .bind(String(meta.sslId),JSON.stringify(meta),new Date().toISOString(),id).run();
      } else if(site.status==="failed") {
        meta.stage="certificate_pending";
        delete meta.error;
        await env.DOMAIN_DB.prepare("UPDATE managed_sites SET status='certificate_pending',last_error=NULL,metadata_json=?,updated_at=? WHERE id=?")
          .bind(JSON.stringify(meta),new Date().toISOString(),id).run();
      }
      const ssl=await panelRequest(node.base_url,apiKey,"GET","/websites/ssl/"+encodeURIComponent(meta.sslId));
      const sslData=ssl.websiteSSL||ssl;
      const status=String(sslData.status||"").toLowerCase();
      if(status==="error"||status==="applyerror") throw new Error(sslData.message||"1Panel 证书申请失败");
      if(status!=="ready" || !sslData.pem || !sslData.privateKey) {
        return json({ok:true,item:{id,hostname:site.hostname,status:"certificate_pending",certificateStatus:status||"pending",message:sslData.message||"正在等待 Let's Encrypt 完成 DNS-01 验证"}});
      }
      if(!meta.websiteId) {
        const groups=await panelPageItems(node.base_url,apiKey,"/groups/search",{type:"website"});
        const group=groups.find(x=>x.isDefault)||groups[0];
        if(!group?.id) throw new Error("1Panel 没有可用的网站分组，无法创建反向代理网站");
        const alias=site.hostname.replace(/[^a-z0-9.-]/g,"-").replace(/\\./g,"-").slice(0,60);
        const existing=await panelPageItems(node.base_url,apiKey,"/websites/search",{page:1,pageSize:100,orderBy:"created_at",order:"descending"});
        const matched=existing.find(x=>x.primaryDomain===site.hostname||x.alias===alias);
        if(matched?.id) throw new Error("1Panel 已存在同名网站（ID "+matched.id+"），为避免接管或覆盖，本工具停止自动创建");
        const taskId=randomId();
        await panelRequest(node.base_url,apiKey,"POST","/websites",{
          type:"proxy",appType:"installed",alias,remark:"Created by Domain Access Manager",proxy:site.upstream_url,webSiteGroupID:Number(group.id),IPV6:false,
          domains:[{domain:site.hostname,port:80,ssl:false}],enableSSL:true,websiteSSLID:Number(meta.sslId),taskID:taskId
        });
        const created=await panelPageItems(node.base_url,apiKey,"/websites/search",{page:1,pageSize:100,orderBy:"created_at",order:"descending"});
        const website=created.find(x=>x.primaryDomain===site.hostname||x.alias===alias);
        if(!website?.id) throw new Error("1Panel 已提交网站创建任务，但暂时未能读取网站 ID；请在 1Panel 网站列表确认结果后再重试");
        meta.websiteId=Number(website.id);
      }
      meta.stage="ready";
      await env.DOMAIN_DB.prepare("UPDATE managed_sites SET panel_website_id=?,status='ready',metadata_json=?,last_error=NULL,updated_at=? WHERE id=?")
        .bind(String(meta.websiteId),JSON.stringify(meta),new Date().toISOString(),id).run();
      await log(env,"publish.complete","managed_site",id,"success","证书已签发并创建 HTTPS 反向代理网站",{hostname:site.hostname,websiteId:meta.websiteId,sslId:meta.sslId});
      return json({ok:true,item:{id,hostname:site.hostname,status:"ready",websiteId:meta.websiteId,sslId:meta.sslId}});
    } catch(error) {
      await env.DOMAIN_DB.prepare("UPDATE managed_sites SET status='failed',last_error=?,metadata_json=?,updated_at=? WHERE id=?")
        .bind(error.message,JSON.stringify({...meta,stage:"failed",error:error.message}),new Date().toISOString(),id).run();
      await log(env,"publish.progress","managed_site",id,"failed",error.message,{hostname:site.hostname});
      return json({error:error.message,item:{id,hostname:site.hostname,status:"failed"}},400);
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
    if (type === "A" && !/^\d{1,3}(\.\d{1,3}){3}$/.test(content)) return json({ error: "A 记录必须填写 IPv4 地址" }, 400);
    if (type === "AAAA" && !content.includes(":")) return json({ error: "AAAA 记录必须填写 IPv6 地址" }, 400);
    if (type === "CNAME" && proxied && !content) return json({ error: "CNAME 目标不能为空" }, 400);
    const row = await env.DOMAIN_DB.prepare("SELECT token_ciphertext,zones_json FROM cloudflare_credentials WHERE id=?").bind(credentialId).first();
    if (!row) return json({ error: "Cloudflare 凭据不存在" }, 404);
    const zone = JSON.parse(row.zones_json || "[]").find(z => z.id === zoneId);
    if (!zone) return json({ error: "该 Zone 不在此 Token 的授权范围内" }, 403);
    const token = await decryptSecret(env, row.token_ciphertext);
    const normalizedName = name === "@" ? zone.name : (name === zone.name || name.endsWith("." + zone.name) ? name : name + "." + zone.name);
    const record = await cfRequest(token, "/zones/" + encodeURIComponent(zoneId) + "/dns_records", "POST", { type,name:normalizedName,content,ttl:proxied ? 1 : ttl,proxied: type === "TXT" ? false : proxied });
    await log(env, "dns.create", "dns_record", record.id, "success", "DNS 记录已创建", {zone:zone.name,type,name});
    return json({ ok:true, item:{id:record.id,type:record.type,name:record.name,content:record.content,ttl:record.ttl,proxied:record.proxied} });
  }
  const dnsProxy = path.match(/^\/api\/dns\/records\/([0-9a-f-]+)\/proxy$/);
  if (dnsProxy && request.method === "PATCH") {
    const credentialId = String(body.credentialId || "");
    const zoneId = String(body.zoneId || "");
    if (typeof body.proxied !== "boolean") return json({ error: "代理状态必须是 true 或 false" }, 400);
    const row = await env.DOMAIN_DB.prepare("SELECT token_ciphertext,zones_json FROM cloudflare_credentials WHERE id=?").bind(credentialId).first();
    if (!row) return json({ error: "Cloudflare 凭据不存在" }, 404);
    const zone = JSON.parse(row.zones_json || "[]").find(z => z.id === zoneId);
    if (!zone) return json({ error: "该 Zone 不在此 Token 的授权范围内" }, 403);
    const token = await decryptSecret(env, row.token_ciphertext);
    const recordPath = "/zones/" + encodeURIComponent(zoneId) + "/dns_records/" + encodeURIComponent(dnsProxy[1]);
    const current = await cfRequest(token, recordPath);
    if (!current || !current.id) return json({ error: "DNS 记录不存在" }, 404);
    if (!["A", "AAAA", "CNAME"].includes(String(current.type || "").toUpperCase())) return json({ error: "Cloudflare 代理仅支持 A、AAAA 和 CNAME 记录" }, 400);
    if (Boolean(current.proxied) !== body.proxied) await cfRequest(token, recordPath, "PATCH", { proxied: body.proxied });
    const updated = await cfRequest(token, recordPath);
    await log(env, "dns.proxy", "dns_record", updated.id, "success", body.proxied ? "Cloudflare 橙色云代理已开启" : "Cloudflare 代理已关闭", { zone: zone.name, name: updated.name, proxied: updated.proxied });
    return json({ ok: true, item: { id: updated.id, type: updated.type, name: updated.name, content: updated.content, ttl: updated.ttl, proxied: updated.proxied } });
  }
  const dnsDelete = path.match(/^\/api\/dns\/records\/([0-9a-f-]+)$/);
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
  if (path === "/api/tunnels" && request.method === "GET") {
    const credentialId = String(new URL(request.url).searchParams.get("credentialId") || "");
    if (!credentialId) return json({ error: "请选择 Cloudflare 账户" }, 400);
    const row = await env.DOMAIN_DB.prepare("SELECT id,name,account_id,token_ciphertext,zones_json FROM cloudflare_credentials WHERE id=?").bind(credentialId).first();
    if (!row) return json({ error: "Cloudflare 凭据不存在" }, 404);
    const accountId = String(row.account_id || "").trim().toLowerCase();
    if (!/^[0-9a-f]{32}$/.test(accountId)) return json({ error: "该凭据缺少有效 Account ID" }, 400);
    const token = await decryptSecret(env, row.token_ciphertext);
    const tunnels = await listAccountTunnels(token, accountId);
    const items = await Promise.all(tunnels.map(async t => {
      let ingress = [];
      let configError = "";
      try { ingress = (await getTunnelConfiguration(token, accountId, t.id)).ingress; }
      catch (error) { configError = error?.message || String(error); }
      const routes = ingress.filter(x => x.hostname).map(x => ({ hostname:x.hostname, path:x.path || "", service:x.service || "" }));
      return { id:t.id,name:t.name,status:t.status,createdAt:t.created_at,connections:t.connections||[],routes,routeCount:routes.length,configError };
    }));
    return json({ items, accountId, accountName:row.name, zones:JSON.parse(row.zones_json || "[]") });
  }
  if (path === "/api/tunnels" && request.method === "POST") {
    const credentialId = String(body.credentialId || "");
    const zoneId = String(body.zoneId || "");
    const name = safeName(body.name);
    const service = normalizeTunnelService(body.service);
    const hostname = normalizeTunnelHostname(body.sub, (await getTunnelContext(env,credentialId,zoneId)).zone.name);
    const ctx = await getTunnelContext(env,credentialId,zoneId);
    const tunnelSecret = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
    const tunnel = await tunnelRequest(ctx.token,tunnelApiPath(ctx.accountId),"POST",{name,tunnel_secret:tunnelSecret,config_src:"cloudflare"});
    let dnsResult = {created:false,recordId:""};
    try {
      await tunnelRequest(ctx.token,tunnelApiPath(ctx.accountId,tunnel.id)+"/configurations","PUT",{config:{ingress:[{hostname,service},{service:"http_status:404"}]}});
      dnsResult = await ensureTunnelCname(ctx.token,zoneId,hostname,tunnel.id);
    } catch(error) {
      await tunnelRequest(ctx.token,tunnelApiPath(ctx.accountId,tunnel.id),"DELETE").catch(()=>{});
      throw error;
    }
    await log(env,"tunnel.create","cloudflare_tunnel",tunnel.id,"success","Cloudflare Tunnel 已创建",{name,hostname,service,zone:ctx.zone.name});
    return json({ok:true,item:{id:tunnel.id,name,hostname,service,dnsCreated:dnsResult.created}});
  }
  const tunnelRoute = path.match(/^\/api\/tunnels\/([0-9a-f]{32}|[0-9a-f-]{36})(?:\/(detail|token|routes))?$/i);
  if (tunnelRoute) {
    const tunnelId = tunnelRoute[1];
    const action = tunnelRoute[2] || "";
    const credentialId = String(body.credentialId || new URL(request.url).searchParams.get("credentialId") || "");
    const ctx = await getTunnelAccountContext(env,credentialId);
    const base = tunnelApiPath(ctx.accountId,tunnelId);
    if (action === "detail" && request.method === "GET") {
      const [tunnel,config] = await Promise.all([tunnelRequest(ctx.token,base),getTunnelConfiguration(ctx.token,ctx.accountId,tunnelId)]);
      return json({item:{id:tunnel.id,name:tunnel.name,status:tunnel.status,createdAt:tunnel.created_at,connections:tunnel.connections||[]},ingress:config.ingress});
    }
    if (action === "token" && request.method === "GET") {
      const result = await tunnelRequest(ctx.token,base+"/token");
      return json({token:result.token||result});
    }
    if (action === "routes" && request.method === "POST") {
      const {config,ingress}=await getTunnelConfiguration(ctx.token,ctx.accountId,tunnelId);
      const operation=String(body.action||"add");
      if(operation==="add"){
        const service=normalizeTunnelService(body.service);
        const zoneId=String(body.zoneId||"");
        const zone=ctx.zones.find(z=>z.id===zoneId);
        if(!zone)return json({error:"请选择属于当前 Cloudflare 账户的 Zone"},400);
        const hostname=normalizeTunnelHostname(body.sub,zone.name);
        const rulePath=String(body.path||"").trim();
        if(rulePath && (!rulePath.startsWith("/") || rulePath.length>200))return json({error:"路径必须以 / 开头且不超过 200 个字符"},400);
        if(ingress.some(r=>r.hostname===hostname&&(r.path||"")===rulePath))return json({error:"该域名和路径规则已存在"},409);
        if(ingress.length>=60)return json({error:"单条 Tunnel 最多支持 60 条入口规则"},400);
        const dns=await ensureTunnelCname(ctx.token,zoneId,hostname,tunnelId);
        const next=ingress.filter(r=>r.hostname||r.path);next.push({hostname,service,...(rulePath?{path:rulePath}:{})});
        try{await putTunnelConfiguration(ctx.token,ctx.accountId,tunnelId,config,next)}catch(error){if(dns.created)await cleanupTunnelCnames(ctx.token,ctx.zones,tunnelId,[hostname]);throw error}
      }else if(operation==="delete"){
        const hostname=String(body.hostname||"");const rulePath=String(body.path||"");
        const index=ingress.findIndex(r=>r.hostname===hostname&&(r.path||"")===rulePath);
        if(index<0)return json({error:"入口规则不存在"},404);
        const next=ingress.filter((r,i)=>i!==index);
        await putTunnelConfiguration(ctx.token,ctx.accountId,tunnelId,config,next);
        if(!next.some(r=>r.hostname===hostname))await cleanupTunnelCnames(ctx.token,ctx.zones,tunnelId,[hostname]);
      }else return json({error:"未知入口规则操作"},400);
      const refreshed=await getTunnelConfiguration(ctx.token,ctx.accountId,tunnelId);
      return json({ok:true,ingress:refreshed.ingress});
    }
    if (!action && request.method === "PATCH") {
      const name=safeName(body.name);
      const updated=await tunnelRequest(ctx.token,base,"PATCH",{name});
      return json({ok:true,item:{id:updated.id,name:updated.name}});
    }
    if (!action && request.method === "DELETE") {
      const [tunnel,config]=await Promise.all([tunnelRequest(ctx.token,base),getTunnelConfiguration(ctx.token,ctx.accountId,tunnelId)]);
      const connections=await tunnelRequest(ctx.token,base+"/connections").catch(()=>[]);
      if(Array.isArray(connections)&&connections.length)return json({error:"该 Tunnel 仍有活动连接器，请先在运行 cloudflared 的设备上停止连接器，再删除隧道"},409);
      await tunnelRequest(ctx.token,base,"DELETE");
      const hosts=config.ingress.map(r=>r.hostname).filter(Boolean);
      const cleanup=await cleanupTunnelCnames(ctx.token,ctx.zones,tunnelId,hosts);
      await log(env,"tunnel.delete","cloudflare_tunnel",tunnelId,"success","Cloudflare Tunnel 已删除",{name:tunnel.name,cleanup});
      return json({ok:true,cleanup});
    }
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
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}button,input{font:inherit}button{cursor:pointer;border:1px solid var(--line);background:var(--panel2);color:var(--text);border-radius:9px;padding:9px 13px}button.primary{background:#2767c8;border-color:#3478dc}button.danger{color:#ff9999}input{width:100%;padding:11px 12px;background:#0c1424;border:1px solid var(--line);border-radius:9px;color:var(--text);outline:none}input:focus{border-color:var(--accent)}.wrap{max-width:1120px;margin:auto;padding:28px 22px}.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px}.brand{font-size:19px;font-weight:700}.muted{color:var(--muted)}.tabs{display:flex;gap:8px;margin-bottom:20px;flex-wrap:wrap}.tabs button.active{background:#1e3d68;border-color:#477fc8}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:15px}.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px}.card h3{margin:0 0 14px;font-size:16px}.field{margin:12px 0}.field label{display:block;margin-bottom:6px;color:var(--muted);font-size:12px}.actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.dns-toggle{width:42px;height:24px;padding:2px;border-radius:20px;background:#3b4659;border:1px solid #52617a;display:inline-flex;align-items:center;justify-content:flex-start;transition:background .15s,border-color .15s;vertical-align:middle}.dns-toggle span{width:18px;height:18px;background:#e9eef7;border-radius:50%;display:block;transition:transform .15s}.dns-toggle[aria-checked="true"]{background:#e78a20;border-color:#f5a33c}.dns-toggle[aria-checked="true"] span{transform:translateX(18px)}.dns-toggle:disabled{opacity:.5;cursor:not-allowed}.proxy-state{font-size:11px;color:var(--muted)}.proxy-state.on{color:#ffb34d}.item{padding:14px 0;border-top:1px solid var(--line)}.item:first-child{border-top:0}.row{display:flex;justify-content:space-between;gap:12px;align-items:center}.domain-main{min-width:0;flex:1}.domain-main b{overflow-wrap:anywhere}.domain-side{display:flex;align-items:center;justify-content:flex-end;gap:10px;flex-shrink:0;white-space:nowrap}.pill{font-size:11px;color:var(--green);background:#16382e;padding:3px 8px;border-radius:20px}.pill.bad{color:#ff9d9d;background:#3a2228}.zone{display:inline-block;border:1px solid var(--line);border-radius:20px;padding:3px 8px;margin:5px 4px 0 0;font-size:11px;color:var(--muted)}.hidden{display:none!important}.notice{padding:10px 12px;border-radius:9px;background:#1a2b43;color:#a9caff;margin:12px 0}.error{background:#3b2027;color:#ffaaaa}.login{max-width:390px;margin:12vh auto;padding:26px}.login h1{margin:0 0 5px}.empty{padding:22px;text-align:center;color:var(--muted)}small{color:var(--muted)}@media(max-width:600px){.wrap{padding:18px 13px}.top{align-items:flex-start}.row{align-items:flex-start}}
.tunnel-page-head{display:flex;justify-content:space-between;align-items:flex-end;gap:18px;flex-wrap:wrap}
.tunnel-page-head>div:first-child{min-width:220px;flex:1}
.tunnel-page-head p{margin:6px 0 0;max-width:650px;line-height:1.6}
.tunnel-controls{display:flex;align-items:flex-end;gap:10px;flex-wrap:wrap}
.tunnel-controls .field{margin:0;min-width:170px}
.tunnel-controls select{width:100%;min-width:170px;max-width:220px;padding:10px;background:#0c1424;color:var(--text);border:1px solid var(--line);border-radius:9px}
.tunnel-table-head,.tunnel-row{display:grid;grid-template-columns:minmax(0,1fr) 120px minmax(320px,auto);align-items:center;gap:16px}
.tunnel-table-head{padding:11px 12px;color:var(--muted);font-size:12px;border-bottom:1px solid var(--line);font-weight:600}
.tunnel-row{padding:14px 12px;border-bottom:1px solid var(--line);min-height:68px}
.tunnel-row:last-child{border-bottom:0}
.tunnel-info{min-width:0}
.tunnel-info b{display:block;overflow-wrap:anywhere}
.tunnel-info small{display:block;margin-top:4px;overflow-wrap:anywhere;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11px}
.tunnel-actions{display:flex;align-items:center;justify-content:flex-end;gap:8px;flex-wrap:wrap}
.tunnel-actions button{white-space:nowrap}
.tunnel-modal-backdrop{position:fixed;inset:0;z-index:100;background:rgba(5,8,16,.68);backdrop-filter:blur(4px);-webkit-backdrop-filter:blur(4px);display:none}
.tunnel-modal-backdrop.show{display:block}
.tunnel-modal{position:fixed;left:50%;top:50%;transform:translate(-50%,-48%) scale(.98);z-index:101;width:min(560px,calc(100% - 28px));max-height:calc(100vh - 40px);overflow-y:auto;padding:22px;background:var(--panel);border:1px solid var(--line);border-radius:16px;box-shadow:0 24px 70px rgba(0,0,0,.48);display:none;opacity:0}
.tunnel-modal.show{display:block;animation:tunnelModalIn .18s ease forwards}
@keyframes tunnelModalIn{to{transform:translate(-50%,-50%) scale(1);opacity:1}}
.tunnel-modal-head{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;margin-bottom:18px}
.tunnel-modal-head h3{margin:0 0 5px}
.tunnel-modal-head p{margin:0;font-size:13px}
.tunnel-modal-close{font-size:24px;line-height:1;width:34px;height:34px;padding:0;display:flex;align-items:center;justify-content:center;color:var(--muted);background:transparent;border:0}
.tunnel-modal-actions{display:flex;justify-content:flex-end;gap:10px;margin-top:18px;padding-top:16px;border-top:1px solid var(--line)}
@media(max-width:850px){.tunnel-controls{width:100%}.tunnel-controls .field{flex:1}.tunnel-controls select{max-width:none}}
@media(max-width:700px){.tunnel-table-head{display:none}.tunnel-row{grid-template-columns:minmax(0,1fr) auto;gap:10px}.tunnel-row .tunnel-actions{grid-column:1/-1;justify-content:flex-start}.tunnel-controls{align-items:stretch}.tunnel-controls .field{min-width:100%;}.tunnel-modal{padding:18px}}
.tunnel-page-head{display:flex;justify-content:space-between;align-items:flex-end;gap:18px;flex-wrap:wrap}.tunnel-page-head>div:first-child{min-width:220px;flex:1}.tunnel-page-head p{margin:6px 0 0;line-height:1.6}.tunnel-controls{display:flex;align-items:flex-end;gap:10px;flex-wrap:wrap}.tunnel-controls .field{margin:0;min-width:220px}.tunnel-controls select{width:100%;padding:10px;background:#0c1424;color:var(--text);border:1px solid var(--line);border-radius:9px}
.tunnel-table-head,.tunnel-row{display:grid;grid-template-columns:minmax(0,1fr) 95px 70px minmax(290px,auto);align-items:center;gap:14px}.tunnel-table-head{padding:12px;color:var(--muted);font-size:12px;border-bottom:1px solid var(--line);font-weight:600}.tunnel-row{padding:15px 12px;border-bottom:1px solid var(--line)}.tunnel-row:last-child{border-bottom:0}.tunnel-info{min-width:0}.tunnel-info b{display:block;overflow-wrap:anywhere}.tunnel-info small{display:block;margin-top:4px;overflow-wrap:anywhere}.tunnel-route-summary{margin-top:7px;font-size:12px;color:var(--muted);display:grid;gap:3px}.tunnel-route-summary span{overflow-wrap:anywhere}.tunnel-actions{display:flex;align-items:center;justify-content:flex-end;gap:7px;flex-wrap:wrap}.tunnel-actions button{white-space:nowrap}.tunnel-modal-backdrop{position:fixed;inset:0;z-index:100;background:rgba(5,8,16,.7);backdrop-filter:blur(4px);display:none}.tunnel-modal-backdrop.show{display:block}.tunnel-modal{position:fixed;left:50%;top:50%;transform:translate(-50%,-48%) scale(.98);z-index:101;width:min(590px,calc(100% - 28px));max-height:calc(100vh - 40px);overflow-y:auto;padding:22px;background:var(--panel);border:1px solid var(--line);border-radius:16px;box-shadow:0 24px 70px rgba(0,0,0,.48);display:none;opacity:0}.tunnel-modal.show{display:block;animation:tunnelModalIn .18s ease forwards}@keyframes tunnelModalIn{to{transform:translate(-50%,-50%) scale(1);opacity:1}}.tunnel-modal-head{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;margin-bottom:18px}.tunnel-modal-head h3{margin:0 0 5px}.tunnel-modal-head p{margin:0;font-size:13px}.tunnel-modal-close{font-size:24px;line-height:1;width:34px;height:34px;padding:0;display:flex;align-items:center;justify-content:center;color:var(--muted);background:transparent;border:0}.tunnel-modal-actions{display:flex;justify-content:flex-end;gap:10px;margin-top:18px;padding-top:16px;border-top:1px solid var(--line)}.tunnel-token-block{margin:14px 0}.tunnel-token-block label{display:block;color:var(--muted);font-size:12px;margin-bottom:6px}.tunnel-token-line{display:flex;gap:8px;align-items:stretch}.tunnel-token-line textarea{flex:1;min-width:0;min-height:76px;resize:vertical;font-family:ui-monospace,monospace;font-size:12px}.tunnel-route-item{padding:12px 0;border-bottom:1px solid var(--line)}.tunnel-route-item:last-child{border-bottom:0}.tunnel-route-item .row{align-items:center}.tunnel-route-item small{display:block;margin-top:4px;overflow-wrap:anywhere}@media(max-width:900px){.tunnel-table-head{display:none}.tunnel-row{grid-template-columns:minmax(0,1fr) auto;gap:10px}.tunnel-row .tunnel-route-summary{grid-column:1/-1}.tunnel-row .tunnel-actions{grid-column:1/-1;justify-content:flex-start}.tunnel-controls .field{min-width:100%}}
</style></head><body><div id="login" class="card login"><h1>Domain Access Manager</h1><p class="muted">Cloudflare DNS · 1Panel · Reverse Proxy</p><form id="loginForm"><div class="field"><label>管理员密码</label><input name="password" type="password" required autofocus autocomplete="current-password"></div><button class="primary" style="width:100%">登录</button></form><div id="loginMsg"></div></div>
<div id="app" class="wrap hidden"><header class="top"><div><div class="brand">Domain Access Manager</div><small>Cloudflare DNS & 1Panel 管理</small></div><button id="logout">退出登录</button></header>
<nav class="tabs"><button data-tab="overview" class="active">概览</button><button data-tab="cloudflare">Cloudflare</button><button data-tab="nodes">VPS / 1Panel</button><button data-tab="dns">DNS 记录</button><button data-tab="publish">域名接入</button><button data-tab="domains">域名管理</button><button data-tab="tunnels">Tunnel 管理</button><button data-tab="logs">操作记录</button></nav>
<section id="overview" class="tab grid"><div class="card"><h3>Cloudflare 凭据</h3><div id="countCf">-</div><small>多个 Token，自动发现 Zone</small></div><div class="card"><h3>1Panel 节点</h3><div id="countNodes">-</div><small>多个 VPS，独立 API 凭据</small></div><div class="card"><h3>下一步</h3><p class="muted">先添加 Cloudflare Token 和 1Panel 节点，随后即可建设 DNS → SSL → 反向代理的一键发布流程。</p></div></section>
<section id="cloudflare" class="tab hidden grid"><div class="card"><h3>添加 Cloudflare 账户 API Token</h3><p class="muted">仅支持 Account API Token。请填写 Cloudflare 账户 ID（32 位），Token 将加密保存在 D1，不会返回到页面。</p><form id="cfForm"><input id="cfCredentialId" name="credentialId" type="hidden"><div class="field"><label>配置名称</label><input name="name" placeholder="例如：主账号" required></div><div class="field"><label>Cloudflare Account ID（32 位）</label><input name="accountId" placeholder="从 dash.cloudflare.com/ 后的 32 位账户 ID 获取" minlength="32" maxlength="32" pattern="[a-fA-F0-9]{32}" required></div><div class="field"><label>账户 API Token</label><input name="token" type="password" autocomplete="off" placeholder="粘贴账户 API Token" required></div><button class="primary" id="cfSubmitButton">验证并添加账户 API Token</button><button type="button" id="cfCancelEdit" class="hidden">取消更新</button></form><div class="notice">权限至少需要 Account → Cloudflare Tunnel → Edit，以及 Zone → DNS → Edit、Zone → Read。更新已有凭据会保留关联的域名任务和 1Panel 账户映射。</div><div id="cfMsg"></div></div><div class="card"><h3>已保存的 Cloudflare 账号</h3><div id="cfList" class="muted">加载中...</div></div></section>
<section id="nodes" class="tab hidden grid"><div class="card"><h3>添加 1Panel 节点</h3><form id="nodeForm"><div class="field"><label>节点名称</label><input name="name" placeholder="例如：日本 VPS" required></div><div class="field"><label>1Panel 地址（HTTP / HTTPS）</label><input id="nodeBaseUrl" name="baseUrl" placeholder="http://104.233.209.110:32666 或 https://panel.example.com" required></div><div class="field"><label>1Panel API Key</label><input name="apiKey" type="password" autocomplete="off" required></div><button type="submit" class="primary">测试连接并保存</button></form><div id="nodeMsg"></div><div class="notice">支持 HTTP 和 HTTPS，也支持 IP 地址。若 Worker 无法直连 IP，会引导你到 DNS 记录页面创建 DNS-only A 记录，再返回此处使用域名连接。HTTP 不加密 API Key 和请求内容，建议仅临时使用并尽快配置 HTTPS。</div></div><div class="card"><h3>已保存的 VPS 节点</h3><div id="nodeList" class="muted">加载中...</div></div></section>
<section id="dns" class="tab hidden grid">
<div id="panelDnsAssist" class="card hidden"><h3>为 1Panel 创建管理地址 DNS</h3><div id="panelDnsAssistText" class="notice"></div><div class="muted" style="margin:8px 0">已自动带入 VPS 公网 IP。选择 Cloudflare 凭据和 Zone，填写记录前缀后创建 A 记录；请保持 DNS Only（灰色云）。</div></div>
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
<button class="primary">创建 DNS 记录</button></form><div id="dnsCreateMsg"></div></div></section><section id="publish" class="tab hidden grid">
<div class="card"><h3>一键接入域名</h3><p class="muted">自动创建 DNS A 记录、配置 1Panel Cloudflare DNS-01 账户、申请 Let's Encrypt 证书，并创建 HTTPS 反向代理网站。</p>
<form id="publishForm">
<div class="field"><label>Cloudflare 凭据</label><select id="publishCredential" name="credentialId" required style="width:100%;padding:10px;background:#0c1424;color:var(--text);border:1px solid var(--line);border-radius:9px"></select></div>
<div class="field"><label>域名 Zone</label><select id="publishZone" name="zoneId" required style="width:100%;padding:10px;background:#0c1424;color:var(--text);border:1px solid var(--line);border-radius:9px"></select></div>
<div class="field"><label>完整域名</label><input name="hostname" placeholder="app.example.com" required></div>
<div class="field"><label>1Panel VPS 节点</label><select id="publishNode" name="nodeId" required style="width:100%;padding:10px;background:#0c1424;color:var(--text);border:1px solid var(--line);border-radius:9px"></select></div>
<div class="field"><label>后端服务地址</label><input name="upstream" placeholder="http://127.0.0.1:3000" required></div>
<div class="field"><label>Let's Encrypt 联系邮箱</label><input name="email" type="email" placeholder="admin@example.com" required></div>
<div class="field"><label>服务器 IPv4（自动读取失败时填写）</label><input name="ipv4" placeholder="自动读取 1Panel 节点公网 IPv4"></div>
<div class="field"><label><input name="proxied" type="checkbox" style="width:auto"> 开启 Cloudflare 橙色云代理</label></div>
<button class="primary" id="publishButton">开始一键接入</button>
</form><div id="publishMsg"></div></div>
<div class="card"><h3>域名接入任务</h3><button id="refreshPublish">刷新任务</button><div id="publishList" style="margin-top:12px">加载中...</div></div></section><section id="domains" class="tab hidden"><div class="card"><h3>已接入域名</h3><p class="muted">统一管理通过本工具接入的域名。删除会清理本工具创建的网站、证书和 DNS 记录；共享账户及原本已存在的 DNS 记录会保留。</p><div class="actions"><button id="refreshDomains">刷新列表</button></div><div id="domainList" style="margin-top:12px">加载中...</div><div id="domainMsg"></div></div></section><section id="tunnels" class="tab hidden">
 <div class="card">
  <div class="tunnel-page-head">
   <div><h3>Cloudflare Tunnel</h3><p class="muted">按 Cloudflare 账户查看全部 Tunnel。域名 Zone 仅在新建或添加入口路由时选择。</p></div>
   <div class="tunnel-controls"><div class="field"><label>Cloudflare 账户</label><select id="tunnelCredential"></select></div><button id="refreshTunnels">刷新</button><button id="openTunnelModal" class="primary">＋ 新建隧道</button></div>
  </div>
  <div id="tunnelMsg"></div>
  <div class="tunnel-table-head"><span>隧道 / 域名 / 后端</span><span>状态</span><span>路由</span><span>操作</span></div>
  <div id="tunnelList"><div class="empty">请选择 Cloudflare 账户</div></div>
 </div>
</section>
<div id="tunnelModalBackdrop" class="tunnel-modal-backdrop"></div>
<div id="tunnelModal" class="tunnel-modal" role="dialog" aria-modal="true"><div class="tunnel-modal-head"><div><h3>新建 Cloudflare Tunnel</h3><p class="muted">创建隧道并设置第一条入口路由。</p></div><button type="button" class="tunnel-modal-close" data-close-modal>×</button></div>
 <form id="tunnelForm"><div class="field"><label>隧道名称</label><input name="name" placeholder="例如：aws-jp" required maxlength="64"></div>
 <div class="field"><label>域名 Zone</label><select name="zoneId" id="tunnelCreateZone" required></select></div>
 <div class="field"><label>子域名前缀（留空使用主域名）</label><input name="sub" placeholder="例如：app"></div>
 <div class="field"><label>入口路径（可选）</label><input name="path" placeholder="/api，留空匹配全部"></div>
 <div class="field"><label>后端服务地址</label><input name="service" placeholder="http://localhost:3000" required></div>
 <div class="notice">创建后需要在 VPS 上运行 cloudflared 连接器。Token 可在列表中单独复制。</div>
 <div class="tunnel-modal-actions"><button type="button" data-close-modal>取消</button><button type="submit" class="primary" id="createTunnelButton">创建隧道</button></div></form></div>
<div id="tunnelEditModal" class="tunnel-modal" role="dialog" aria-modal="true"><div class="tunnel-modal-head"><div><h3>编辑隧道</h3><p class="muted">修改 Tunnel 名称；入口配置请在路由管理中编辑。</p></div><button type="button" class="tunnel-modal-close" data-close-modal>×</button></div><form id="tunnelEditForm"><input type="hidden" name="id"><div class="field"><label>隧道名称</label><input name="name" required maxlength="64"></div><div class="tunnel-modal-actions"><button type="button" data-close-modal>取消</button><button class="primary">保存</button></div></form></div>
<div id="tunnelTokenModal" class="tunnel-modal" role="dialog" aria-modal="true"><div class="tunnel-modal-head"><div><h3>Tunnel Token</h3><p class="muted" id="tunnelTokenName"></p></div><button type="button" class="tunnel-modal-close" data-close-modal>×</button></div><div id="tunnelTokenFields"></div></div>
<div id="tunnelRoutesModal" class="tunnel-modal" role="dialog" aria-modal="true"><div class="tunnel-modal-head"><div><h3 id="tunnelRoutesTitle">路由管理</h3><p class="muted">一个 Tunnel 可以配置多个域名和路径，每条路由指向一个后端服务。</p></div><button type="button" class="tunnel-modal-close" data-close-modal>×</button></div><div id="tunnelRoutesList"></div><form id="tunnelRouteForm"><input type="hidden" name="operation" value="add"><input type="hidden" name="oldHostname"><input type="hidden" name="oldPath"><div class="field"><label>域名 Zone</label><select name="zoneId" id="tunnelRouteZone"></select></div><div class="field"><label>子域名前缀</label><input name="sub" placeholder="例如 api；留空使用主域名"></div><div class="field"><label>路径（可选）</label><input name="path" placeholder="/api"></div><div class="field"><label>后端服务地址</label><input name="service" placeholder="http://localhost:3000" required></div><div class="tunnel-modal-actions"><button type="button" id="cancelRouteEdit" class="hidden">取消编辑</button><button class="primary" id="saveTunnelRoute">添加路由</button></div></form></div>
<section id="logs" class="tab hidden"><div class="card"><h3>最近操作</h3><div id="logList">加载中...</div></div></section></div>
<script>
const $=s=>document.querySelector(s);const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
async function api(path,opts={}){const r=await fetch(path,{...opts,headers:{"content-type":"application/json",...(opts.headers||{})}});const d=await r.json().catch(()=>({error:"服务器响应无法解析"}));if(r.status===401){showLogin();throw new Error(d.error||"登录已过期")}if(!r.ok)throw new Error(d.error||"请求失败");return d}
function msg(el,text,bad=false){el.innerHTML='<div class="notice '+(bad?'error':'')+'">'+esc(text)+'</div>'}
function showLogin(){$("#login").classList.remove("hidden");$("#app").classList.add("hidden")}
function showApp(){$("#login").classList.add("hidden");$("#app").classList.remove("hidden");refresh()}
async function refresh(){await Promise.all([loadCf(),loadNodes(),loadLogs()]);try{await loadDnsCredentials();await loadPublishOptions();await loadPublishList();await loadDomains()}catch(e){}}
document.querySelectorAll("[data-tab]").forEach(b=>b.onclick=()=>{document.querySelectorAll("[data-tab]").forEach(x=>x.classList.toggle("active",x===b));document.querySelectorAll(".tab").forEach(x=>x.classList.toggle("hidden",x.id!==b.dataset.tab));if(b.dataset.tab==="tunnels")initTunnelPage()});
$("#loginForm").onsubmit=async e=>{e.preventDefault();const p=new FormData(e.target).get("password");try{await api("/api/login",{method:"POST",body:JSON.stringify({password:p})});e.target.reset();$("#loginMsg").innerHTML="";showApp()}catch(err){msg($("#loginMsg"),err.message,true)}};
$("#logout").onclick=async()=>{await api("/api/logout",{method:"POST",body:"{}"});showLogin()};
function resetCfCredentialForm(){const form=$("#cfForm");form.reset();$("#cfCredentialId").value="";$("#cfSubmitButton").textContent="验证并添加账户 API Token";$("#cfCancelEdit").classList.add("hidden")}
$("#cfCancelEdit").onclick=resetCfCredentialForm;
$("#cfForm").onsubmit=async e=>{e.preventDefault();const f=new FormData(e.target);const b=$("#cfSubmitButton");b.disabled=true;b.textContent="验证账户 Token...";try{const d=await api("/api/cloudflare/verify",{method:"POST",body:JSON.stringify({credentialId:f.get("credentialId"),name:f.get("name"),accountId:f.get("accountId"),token:f.get("token")})});resetCfCredentialForm();msg($("#cfMsg"),(f.get("credentialId")?"账户凭据已更新":"账户 API Token 验证成功并添加")+"，发现 "+d.item.zoneCount+" 个 Zone");await loadCf();await loadDnsCredentials();await loadPublishOptions()}catch(err){msg($("#cfMsg"),err.message,true)}finally{b.disabled=false;if(!$("#cfCredentialId").value)b.textContent="验证并添加账户 API Token";else b.textContent="验证并更新账户 API Token"}};
function editCfCredential(id){const item=(window.__allCfItems||[]).find(x=>x.id===id);if(!item)return;$("#cfCredentialId").value=item.id;$("#cfForm").elements.namedItem("name").value=item.name;$("#cfForm").elements.namedItem("accountId").value=item.account_id||"";$("#cfForm").elements.namedItem("token").value="";$("#cfSubmitButton").textContent="验证并更新账户 API Token";$("#cfCancelEdit").classList.remove("hidden");$("#cfMsg").textContent="正在更新 "+item.name+"。输入新的账户 API Token；现有域名关联将保留。";$("#cfForm").scrollIntoView({behavior:"smooth",block:"start"})}
function activateTab(tab){document.querySelectorAll("[data-tab]").forEach(x=>x.classList.toggle("active",x.dataset.tab===tab));document.querySelectorAll(".tab").forEach(x=>x.classList.toggle("hidden",x.id!==tab));}
function isIPv4Address(value){return /^(?:\\d{1,3}\\.){3}\\d{1,3}$/.test(value||"")&&value.split(".").every(x=>Number(x)>=0&&Number(x)<=255);}
function showPanelDnsRedirect(baseUrl,errorText){
  let parsed;try{parsed=new URL(baseUrl)}catch{return false}
  if(!isIPv4Address(parsed.hostname))return false;
  window.__pendingPanelDns={ip:parsed.hostname,port:parsed.port,protocol:parsed.protocol,pathname:parsed.pathname==="/"?"":parsed.pathname,baseUrl};
  msg($("#nodeMsg"),errorText+"。检测到你填写的是 IP 地址，请先创建一个 DNS A 记录，再使用域名连接。",true);
  const button=document.createElement("button");button.type="button";button.className="primary";button.style.marginTop="10px";button.textContent="前往 DNS 记录";
  button.onclick=async()=>{activateTab("dns");$("#panelDnsAssist").classList.remove("hidden");$("#panelDnsAssistText").textContent="待添加的 VPS IP："+parsed.hostname+"；端口："+(parsed.port||(parsed.protocol==="https:"?"443":"80"))+"。DNS 记录只负责解析 IP，不包含端口。";$("#dnsForm").elements.namedItem("type").value="A";$("#dnsForm").elements.namedItem("name").value="panel-api";$("#dnsForm").elements.namedItem("content").value=parsed.hostname;$("#dnsForm").elements.namedItem("ttl").value="1";$("#dnsForm").elements.namedItem("proxied").checked=false;};
  $("#nodeMsg").appendChild(button);
  return true;
}
$("#nodeForm").onsubmit=async e=>{e.preventDefault();const f=new FormData(e.target);const b=e.submitter||e.target.querySelector('button[type="submit"]')||e.target.querySelector("button");if(b){b.disabled=true;b.textContent="连接测试中...";}try{const d=await api("/api/nodes/test",{method:"POST",body:JSON.stringify({name:f.get("name"),baseUrl:f.get("baseUrl"),apiKey:f.get("apiKey")})});e.target.reset();msg($("#nodeMsg"),"连接成功"+(d.item.panelVersion?" · 版本 "+d.item.panelVersion:""));await loadNodes();await loadPublishOptions()}catch(err){const redirected=showPanelDnsRedirect(f.get("baseUrl"),err.message);if(!redirected)msg($("#nodeMsg"),err.message,true)}finally{if(b){b.disabled=false;b.textContent="测试连接并保存";}}};
async function loadCf(){try{const d=await api("/api/cloudflare");window.__allCfItems=d.items;const active=d.items.filter(x=>x.account_id);window.__cfItems=active;$("#countCf").textContent=active.length+" 个账户 API 凭据";$("#cfList").innerHTML=d.items.length?d.items.map(x=>'<div class="item"><div class="row"><b>'+esc(x.name)+'</b><div class="actions"><button data-edit-cf="'+esc(x.id)+'">更新</button><button class="danger" data-del-cf="'+esc(x.id)+'">删除</button></div></div><small>'+(x.account_id?'Account ID · '+esc(x.account_id):'旧版用户 Token · 请更新为账户 API Token')+' · '+esc(x.token_status)+'</small><div>'+x.zones.map(z=>'<span class="zone">'+esc(z.name)+'</span>').join("")+'</div></div>').join(""):'<div class="empty">尚未添加 Cloudflare 账户 API Token</div>';document.querySelectorAll("[data-edit-cf]").forEach(b=>b.onclick=()=>editCfCredential(b.dataset.editCf));document.querySelectorAll("[data-del-cf]").forEach(b=>b.onclick=async()=>{if(confirm("确定删除该凭据？如果仍被域名接入任务使用，需要先更新或清理关联域名。")){try{await api("/api/cloudflare/"+b.dataset.delCf,{method:"DELETE"});await loadCf()}catch(e){alert(e.message)}}})}catch(e){$("#cfList").textContent=e.message}}
async function loadNodes(){try{const d=await api("/api/nodes");$("#countNodes").textContent=d.items.length+" 台 VPS";$("#nodeList").innerHTML=d.items.length?d.items.map(x=>'<div class="item"><div class="row"><b>'+esc(x.name)+'</b><span class="pill">'+esc(x.connection_status)+'</span></div><small>'+esc(x.base_url)+(x.panel_version?' · '+esc(x.panel_version):'')+'</small><div class="actions" style="margin-top:8px"><button class="danger" data-del-node="'+esc(x.id)+'">删除</button></div></div>').join(""):'<div class="empty">尚未添加 1Panel 节点</div>';document.querySelectorAll("[data-del-node]").forEach(b=>b.onclick=async()=>{if(confirm("确定删除该节点？")){try{await api("/api/nodes/"+b.dataset.delNode,{method:"DELETE"});loadNodes()}catch(e){alert(e.message)}}})}catch(e){$("#nodeList").textContent=e.message}}
async function loadDnsCredentials(){const d=await api("/api/cloudflare");const items=d.items.filter(x=>x.account_id);window.__cfItems=items;const sel=$("#dnsCredential");sel.innerHTML=items.length?items.map(x=>'<option value="'+esc(x.id)+'">'+esc(x.name)+'</option>').join(""):'<option value="">请先添加账户 API Token</option>';updateDnsZones();sel.onchange=updateDnsZones}
function updateDnsZones(){const d=$("#dnsCredential").selectedOptions[0];const cfListCache=window.__cfItems||[];const item=cfListCache.find(x=>x.id===d?.value);$("#dnsZone").innerHTML=(item?.zones||[]).map(z=>'<option value="'+esc(z.id)+'">'+esc(z.name)+'</option>').join("")}
async function loadDns(){
 try{
  const cred=$("#dnsCredential").value,zone=$("#dnsZone").value;
  if(!cred||!zone)throw new Error("请先添加 Cloudflare 凭据并选择域名");
  const d=await api("/api/dns/records?credentialId="+encodeURIComponent(cred)+"&zoneId="+encodeURIComponent(zone));
  $("#dnsList").innerHTML=d.items.length?d.items.map(x=>{
   const proxyable=["A","AAAA","CNAME"].includes(String(x.type).toUpperCase());
   return '<div class="item"><div class="row"><b>'+esc(x.name)+'</b><div class="actions">'+
    (proxyable?'<span class="proxy-state '+(x.proxied?'on':'')+'">'+(x.proxied?'橙色云':'仅 DNS')+'</span><button type="button" class="dns-toggle" role="switch" aria-checked="'+String(Boolean(x.proxied))+'" data-dns-proxy="'+esc(x.id)+'" title="'+(x.proxied?'关闭 Cloudflare 代理':'开启 Cloudflare 橙色云代理')+'"><span></span></button>':'<span class="proxy-state">此类型不支持代理</span>')+
    '<button class="danger" data-dns-del="'+esc(x.id)+'">删除</button></div></div><small>'+esc(x.type)+' · '+esc(x.content)+' · TTL '+esc(x.ttl)+'</small></div>';
  }).join(""):'<div class="empty">该域名暂无 DNS 记录</div>';
  document.querySelectorAll("[data-dns-proxy]").forEach(b=>b.onclick=async()=>{
   const desired=b.getAttribute("aria-checked")!=="true";
   b.disabled=true;
   try{
    await api("/api/dns/records/"+b.dataset.dnsProxy+"/proxy",{method:"PATCH",body:JSON.stringify({credentialId:cred,zoneId:zone,proxied:desired})});
    await loadDns();
    msg($("#dnsMsg"),desired?"Cloudflare 橙色云代理已开启":"Cloudflare 代理已关闭，当前为仅 DNS");
   }catch(e){
    await loadDns();
    msg($("#dnsMsg"),e.message,true);
   }
  });
  document.querySelectorAll("[data-dns-del]").forEach(b=>b.onclick=async()=>{
   if(confirm("确定删除这条 DNS 记录？")){
    try{await api("/api/dns/records/"+b.dataset.dnsDel,{method:"DELETE",body:JSON.stringify({credentialId:cred,zoneId:zone})});await loadDns()}
    catch(e){alert(e.message)}
   }
  });
 }catch(e){msg($("#dnsMsg"),e.message,true)}
}
$("#loadDns").onclick=loadDns;
$("#dnsForm").onsubmit=async e=>{e.preventDefault();const f=new FormData(e.target);try{const zoneName=$("#dnsZone").selectedOptions[0]?.textContent||"";const recordName=String(f.get("name")||"").trim().toLowerCase();const type=String(f.get("type")||"").toUpperCase();const content=String(f.get("content")||"").trim();const d=await api("/api/dns/records",{method:"POST",body:JSON.stringify({credentialId:$("#dnsCredential").value,zoneId:$("#dnsZone").value,type,name:recordName,content,ttl:Number(f.get("ttl")||1),proxied:window.__pendingPanelDns?false:f.get("proxied")==="on"})});msg($("#dnsCreateMsg"),"DNS 记录已创建："+d.item.name);if(window.__pendingPanelDns&&type==="A"&&content===window.__pendingPanelDns.ip){const pending=window.__pendingPanelDns;const hostname=recordName==="@"?zoneName:(recordName===zoneName||recordName.endsWith("."+zoneName)?recordName:recordName+"."+zoneName);const address=pending.protocol+"//"+hostname+(pending.port?":"+pending.port:"")+pending.pathname;const done=document.createElement("div");done.className="notice";done.style.marginTop="10px";done.textContent="管理地址已生成："+address+"。DNS 不包含端口，端口已保留在管理地址中。";const back=document.createElement("button");back.type="button";back.className="primary";back.style.marginTop="10px";back.textContent="返回 VPS / 1Panel";back.onclick=()=>{activateTab("nodes");$("#nodeBaseUrl").value=address;$("#panelDnsAssist").classList.add("hidden");window.__pendingPanelDns=null;};done.appendChild(document.createElement("br"));done.appendChild(back);$("#dnsCreateMsg").appendChild(done);}e.target.reset();await loadDns()}catch(err){msg($("#dnsCreateMsg"),err.message,true)}};
async function loadPublishOptions(){
 const [cf,nodes]=await Promise.all([api("/api/cloudflare"),api("/api/nodes")]);
 const accountCredentials=cf.items.filter(x=>x.account_id);
 window.__publishCf=accountCredentials;window.__publishNodes=nodes.items;
 $("#publishCredential").innerHTML=accountCredentials.length?accountCredentials.map(x=>'<option value="'+esc(x.id)+'">'+esc(x.name)+'</option>').join(""):'<option value="">请先添加账户 API Token</option>';
 updatePublishZones();
 $("#publishCredential").onchange=updatePublishZones;
 $("#publishNode").innerHTML=nodes.items.map(x=>'<option value="'+esc(x.id)+'">'+esc(x.name)+' · '+esc(x.connection_status)+'</option>').join("");
}
function updatePublishZones(){
 const cred=$("#publishCredential").value;
 const item=(window.__publishCf||[]).find(x=>x.id===cred);
 $("#publishZone").innerHTML=(item?.zones||[]).map(z=>'<option value="'+esc(z.id)+'">'+esc(z.name)+'</option>').join("");
}
async function loadDomains(){
 try{
  const d=await api("/api/domains");
  $("#domainList").innerHTML=d.items.length?d.items.map(x=>'<div class="item"><div class="row"><div class="domain-main"><b>'+esc(x.hostname)+'</b><div><small>'+esc(x.nodeName)+' · '+esc(x.upstream)+'</small></div></div><div class="domain-side"><span class="pill '+(x.status==="ready"?"":x.status==="failed"||x.status==="delete_failed"?"bad":"")+'">'+esc(x.status)+'</span><button class="danger" data-domain-delete="'+esc(x.id)+'">删除</button></div></div>'+(x.lastError?'<small class="error">'+esc(x.lastError)+'</small>':'')+'</div>').join(""):'<div class="empty">暂无已接入域名</div>';
  document.querySelectorAll("[data-domain-delete]").forEach(b=>b.onclick=async()=>{
   const item=d.items.find(x=>x.id===b.dataset.domainDelete);
   if(!item)return;
   const ok=confirm("确定删除 "+item.hostname+" 的接入配置？\\n\\n将清理本工具创建的 1Panel 反向代理网站、SSL 证书和 Cloudflare A 记录。\\n共享 DNS/ACME 账户及接入前已存在的 DNS 记录会保留。");
   if(!ok)return;
   b.disabled=true;b.textContent="删除中...";
   try{
    const result=await api("/api/domains/"+encodeURIComponent(item.id),{method:"DELETE",body:"{}"});
    const clean=result.item?.cleanup||{};
    const kept=[];
    if(clean.dnsPreserved)kept.push("原有 DNS 记录已保留");
    if(clean.sslPreserved)kept.push("非本工具创建的证书已保留");
    msg($("#domainMsg"),"已删除 "+item.hostname+(kept.length?"；"+kept.join("；"):""));
    await Promise.all([loadDomains(),loadPublishList()]);
   }catch(e){msg($("#domainMsg"),e.message,true);await loadDomains()}
  });
 }catch(e){$("#domainList").textContent=e.message}
}
$("#refreshDomains").onclick=loadDomains;
async function loadPublishList(){
 try{const d=await api("/api/publish");$("#publishList").innerHTML=d.items.length?d.items.map(x=>'<div class="item"><div class="row"><b>'+esc(x.hostname)+'</b><span class="pill '+(x.status==="ready"?"":x.status==="failed"?"bad":"")+'">'+esc(x.status)+'</span></div><small>'+esc(x.lastError||x.metadata?.stage||"")+' · '+esc(x.updatedAt)+'</small><div class="actions" style="margin-top:8px">'+(x.status==="certificate_pending"||x.status==="provisioning"?'<button data-progress="'+esc(x.id)+'">检查进度</button>':x.status==="failed"?'<button data-progress="'+esc(x.id)+'">重试接入</button>':'')+'</div></div>').join(""):'<div class="empty">尚未接入域名</div>';document.querySelectorAll("[data-progress]").forEach(b=>b.onclick=()=>checkPublishProgress(b.dataset.progress,true))}catch(e){$("#publishList").textContent=e.message}
}
async function checkPublishProgress(id,showMessage){
 try{const d=await api("/api/publish/"+id+"/progress",{method:"POST",body:"{}"});const item=d.item||{};if(showMessage)msg($("#publishMsg"),item.status==="ready"?"域名接入完成："+item.hostname:(item.message||"当前状态："+item.status));await loadPublishList();return item}catch(e){if(showMessage)msg($("#publishMsg"),e.message,true);await loadPublishList();return {status:"failed",error:e.message}}
}
async function runPublishPolling(id){
 for(let i=0;i<45;i++){
  await new Promise(resolve=>setTimeout(resolve,8000));
  const item=await checkPublishProgress(id,false);
  if(item.status==="ready"){msg($("#publishMsg"),"域名接入成功："+item.hostname);return}
  if(item.status==="failed"){msg($("#publishMsg"),item.error||"接入失败，请查看任务记录",true);return}
  msg($("#publishMsg"),"证书申请中，已等待 "+((i+1)*8)+" 秒；可以关闭页面，稍后在任务列表继续检查");
 }
 msg($("#publishMsg"),"证书仍在申请中。任务已保存，可稍后点击「检查进度」继续。");
}
$("#publishForm").onsubmit=async e=>{
 e.preventDefault();const f=new FormData(e.target);const b=$("#publishButton");b.disabled=true;b.textContent="正在配置 DNS 和证书...";
 try{
  const d=await api("/api/publish",{method:"POST",body:JSON.stringify({credentialId:f.get("credentialId"),zoneId:f.get("zoneId"),nodeId:f.get("nodeId"),hostname:f.get("hostname"),upstream:f.get("upstream"),email:f.get("email"),ipv4:f.get("ipv4"),proxied:f.get("proxied")==="on"})});
  msg($("#publishMsg"),"DNS 已处理，1Panel 已提交证书申请。正在等待签发...");
  await loadPublishList();runPublishPolling(d.item.id);
 }catch(err){msg($("#publishMsg"),err.message,true);await loadPublishList()}
 finally{b.disabled=false;b.textContent="开始一键接入"}
};
$("#refreshPublish").onclick=loadPublishList;
let activeTunnelId="",activeTunnelName="",tunnelCache=[];
function tunnelQuery(id,tail=""){return "/api/tunnels/"+encodeURIComponent(id)+(tail?"/"+tail:"")+"?credentialId="+encodeURIComponent($("#tunnelCredential").value)}
function showTunnelModal(id){$("#tunnelModalBackdrop").classList.add("show");$("#"+id).classList.add("show");document.body.style.overflow="hidden"}
function closeTunnelModals(){document.querySelectorAll(".tunnel-modal.show").forEach(x=>x.classList.remove("show"));$("#tunnelModalBackdrop").classList.remove("show");document.body.style.overflow=""}
function updateTunnelZoneOptions(){const items=window.__cfItems||[];const options=items.flatMap(x=>(x.zones||[]).map(z=>({id:z.id,name:z.name,account:x.name})));const html=options.map(z=>'<option value="'+esc(z.id)+'">'+esc(z.name)+'</option>').join("");$("#tunnelCreateZone").innerHTML=html;$("#tunnelRouteZone").innerHTML=html}
async function loadTunnelList(){try{const credentialId=$("#tunnelCredential").value;if(!credentialId){$("#tunnelList").innerHTML='<div class="empty">请先添加 Cloudflare 账户 API Token</div>';return}$("#tunnelList").innerHTML='<div class="empty">正在读取 Tunnel...</div>';const d=await api("/api/tunnels?credentialId="+encodeURIComponent(credentialId));tunnelCache=d.items||[];$("#tunnelList").innerHTML=tunnelCache.length?tunnelCache.map(t=>{const routes=t.routes||[];return '<div class="tunnel-row"><div class="tunnel-info"><b>'+esc(t.name)+'</b><small>'+esc(t.id)+'</small><div class="tunnel-route-summary">'+(routes.length?routes.map(r=>'<span>'+esc(r.hostname)+(r.path?esc(r.path):"")+" → "+esc(r.service)+'</span>').join(""):'<span>暂无入口路由</span>')+'</div></div><div><span class="pill '+(t.status==="healthy"?"":t.status==="down"||t.status==="inactive"?"bad":"")+'">'+esc(t.status||"unknown")+'</span></div><div><span class="pill">'+routes.length+' 条</span></div><div class="tunnel-actions"><button data-tunnel-edit="'+esc(t.id)+'">编辑</button><button data-tunnel-routes="'+esc(t.id)+'">路由</button><button data-tunnel-token="'+esc(t.id)+'">Token</button><button class="danger" data-tunnel-delete="'+esc(t.id)+'">删除</button></div></div>'}).join(""):'<div class="empty">当前 Cloudflare 账户暂无 Tunnel</div>';document.querySelectorAll("[data-tunnel-edit]").forEach(b=>b.onclick=()=>editTunnel(b.dataset.tunnelEdit));document.querySelectorAll("[data-tunnel-routes]").forEach(b=>b.onclick=()=>openTunnelRoutes(b.dataset.tunnelRoutes));document.querySelectorAll("[data-tunnel-token]").forEach(b=>b.onclick=()=>showTunnelToken(b.dataset.tunnelToken));document.querySelectorAll("[data-tunnel-delete]").forEach(b=>b.onclick=()=>deleteTunnel(b.dataset.tunnelDelete))}catch(e){msg($("#tunnelMsg"),e.message,true);$("#tunnelList").innerHTML='<div class="empty">加载失败</div>'}}
async function initTunnelPage(){try{const d=await api("/api/cloudflare");window.__cfItems=d.items.filter(x=>x.account_id);$("#tunnelCredential").innerHTML=window.__cfItems.map(x=>'<option value="'+esc(x.id)+'">'+esc(x.name)+'</option>').join("")||'<option value="">请先添加账户 API Token</option>';updateTunnelZoneOptions();$("#tunnelCredential").onchange=loadTunnelList;await loadTunnelList()}catch(e){msg($("#tunnelMsg"),e.message,true)}}
async function editTunnel(id){const t=tunnelCache.find(x=>x.id===id);if(!t)return;activeTunnelId=id;$("#tunnelEditForm").elements.namedItem("id").value=id;$("#tunnelEditForm").elements.namedItem("name").value=t.name;showTunnelModal("tunnelEditModal")}
$("#tunnelEditForm").onsubmit=async e=>{e.preventDefault();const f=new FormData(e.target);try{await api(tunnelQuery(f.get("id")),{method:"PATCH",body:JSON.stringify({name:f.get("name")})});closeTunnelModals();msg($("#tunnelMsg"),"Tunnel 已更新");await loadTunnelList()}catch(err){msg($("#tunnelMsg"),err.message,true)}};
async function showTunnelToken(id){try{const t=tunnelCache.find(x=>x.id===id);const d=await api(tunnelQuery(id,"token"));const token=typeof d.token==="string"?d.token:JSON.stringify(d.token);const linux="cloudflared tunnel run --token "+token;const docker="docker run -d --name cloudflared --restart unless-stopped --network host cloudflare/cloudflared:latest tunnel --no-autoupdate run --token "+token;$("#tunnelTokenName").textContent=t?.name||id;const blocks=[["Tunnel Token",token],["Linux 运行命令",linux],["Docker 运行命令",docker]];$("#tunnelTokenFields").innerHTML=blocks.map((x,i)=>'<div class="tunnel-token-block"><label>'+x[0]+'</label><div class="tunnel-token-line"><textarea readonly id="tunnelTokenValue'+i+'">'+esc(x[1])+'</textarea><button type="button" data-copy-tunnel-token="'+i+'">复制</button></div></div>').join("");document.querySelectorAll("[data-copy-tunnel-token]").forEach(b=>b.onclick=async()=>{const value=$("#tunnelTokenValue"+b.dataset.copyTunnelToken).value;try{await navigator.clipboard.writeText(value);b.textContent="已复制";setTimeout(()=>b.textContent="复制",1200)}catch{msg($("#tunnelMsg"),"复制失败，请手动复制",true)}});showTunnelModal("tunnelTokenModal")}catch(e){msg($("#tunnelMsg"),e.message,true)}}
async function openTunnelRoutes(id){activeTunnelId=id;const t=tunnelCache.find(x=>x.id===id);activeTunnelName=t?.name||id;$("#tunnelRoutesTitle").textContent="路由管理 · "+activeTunnelName;$("#tunnelRouteForm").reset();$("#tunnelRouteForm").elements.namedItem("operation").value="add";$("#saveTunnelRoute").textContent="添加路由";$("#cancelRouteEdit").classList.add("hidden");updateTunnelZoneOptions();await renderTunnelRoutes();showTunnelModal("tunnelRoutesModal")}
async function renderTunnelRoutes(){try{const d=await api(tunnelQuery(activeTunnelId,"detail"));const routes=d.ingress.filter(x=>x.hostname);$("#tunnelRoutesList").innerHTML=routes.length?routes.map((r,i)=>'<div class="tunnel-route-item"><div class="row"><div class="domain-main"><b>'+esc(r.hostname)+(r.path?esc(r.path):"") +'</b><small>→ '+esc(r.service)+'</small></div><div class="tunnel-actions"><button data-route-edit="'+i+'">编辑</button><button class="danger" data-route-delete="'+i+'">删除</button></div></div></div>').join(""):'<div class="empty">暂无入口路由</div>';routes.forEach((r,i)=>{const eb=document.querySelector('[data-route-edit="'+i+'"]');const db=document.querySelector('[data-route-delete="'+i+'"]');if(eb)eb.onclick=()=>{const f=$("#tunnelRouteForm");f.elements.namedItem("operation").value="update";f.elements.namedItem("oldHostname").value=r.hostname;f.elements.namedItem("oldPath").value=r.path||"";f.elements.namedItem("sub").value=r.hostname;f.elements.namedItem("path").value=r.path||"";f.elements.namedItem("service").value=r.service||"";const zone=(window.__cfItems||[]).flatMap(x=>x.zones||[]).find(z=>r.hostname===z.name||r.hostname.endsWith("."+z.name));if(zone)f.elements.namedItem("zoneId").value=zone.id;$("#saveTunnelRoute").textContent="保存路由";$("#cancelRouteEdit").classList.remove("hidden")};if(db)db.onclick=()=>deleteTunnelRoute(r.hostname,r.path||"")})}catch(e){msg($("#tunnelMsg"),e.message,true)}}
$("#cancelRouteEdit").onclick=()=>{const f=$("#tunnelRouteForm");f.reset();f.elements.namedItem("operation").value="add";$("#saveTunnelRoute").textContent="添加路由";$("#cancelRouteEdit").classList.add("hidden")};
async function deleteTunnelRoute(hostname,path){if(!confirm("确定删除路由 "+hostname+(path||"")+"？"))return;try{await api(tunnelQuery(activeTunnelId,"routes"),{method:"POST",body:JSON.stringify({action:"delete",hostname,path})});await renderTunnelRoutes();await loadTunnelList()}catch(e){msg($("#tunnelMsg"),e.message,true)}}
$("#tunnelRouteForm").onsubmit=async e=>{e.preventDefault();const f=new FormData(e.target);const operation=f.get("operation");const payload={action:operation==="update"?"update":"add",zoneId:f.get("zoneId"),sub:f.get("sub"),path:f.get("path"),service:f.get("service"),oldHostname:f.get("oldHostname"),oldPath:f.get("oldPath")};try{await api(tunnelQuery(activeTunnelId,"routes"),{method:"POST",body:JSON.stringify(payload)});f.reset();f.elements.namedItem("operation").value="add";$("#saveTunnelRoute").textContent="添加路由";$("#cancelRouteEdit").classList.add("hidden");await renderTunnelRoutes();await loadTunnelList()}catch(err){msg($("#tunnelMsg"),err.message,true)}};
async function deleteTunnel(id){if(!confirm("确定删除这个 Cloudflare Tunnel？将删除 Tunnel 本身及其指向该 Tunnel 的 CNAME 记录。活动连接器必须先在 VPS 上停止。"))return;try{const d=await api(tunnelQuery(id),{method:"DELETE",body:"{}"});msg($("#tunnelMsg"),d.cleanup?.warnings?.length?"Tunnel 已删除，但 DNS 清理有警告："+d.cleanup.warnings.join("；"):"Tunnel 和关联 CNAME 已删除");await loadTunnelList()}catch(e){msg($("#tunnelMsg"),e.message,true)}}
function openTunnelModal(){if(!$("#tunnelCredential").value){msg($("#tunnelMsg"),"请先选择 Cloudflare 账户",true);return}updateTunnelZoneOptions();showTunnelModal("tunnelModal")}
function closeTunnelModals(){document.querySelectorAll(".tunnel-modal.show").forEach(x=>x.classList.remove("show"));$("#tunnelModalBackdrop").classList.remove("show");document.body.style.overflow=""}
$("#refreshTunnels").onclick=loadTunnelList;$("#openTunnelModal").onclick=openTunnelModal;$("#tunnelModalBackdrop").onclick=closeTunnelModals;document.querySelectorAll("[data-close-modal]").forEach(b=>b.onclick=closeTunnelModals);document.addEventListener("keydown",e=>{if(e.key==="Escape")closeTunnelModals()});
$("#tunnelForm").onsubmit=async e=>{e.preventDefault();const f=new FormData(e.target),b=$("#createTunnelButton");b.disabled=true;b.textContent="正在创建...";try{const d=await api("/api/tunnels",{method:"POST",body:JSON.stringify({credentialId:$("#tunnelCredential").value,zoneId:f.get("zoneId"),name:f.get("name"),sub:f.get("sub"),path:f.get("path"),service:f.get("service")})});closeTunnelModals();e.target.reset();msg($("#tunnelMsg"),"Tunnel 已创建："+d.item.hostname+"；请在 VPS 上启动 cloudflared 连接器");await loadTunnelList()}catch(err){msg($("#tunnelMsg"),err.message,true)}finally{b.disabled=false;b.textContent="创建隧道"}};
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
