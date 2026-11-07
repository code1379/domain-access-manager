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
    if (existingRecords.length) {
      if (existingRecords.some(r=>r.content!==ip)) return json({error:"Cloudflare 已存在不同 IP 的 A 记录，本工具不会覆盖现有记录。请先检查 DNS 后再接入"},409);
    } else {
      await cfRequest(token,"/zones/"+encodeURIComponent(zoneId)+"/dns_records","POST",{type:"A",name:hostname,content:ip,ttl:1,proxied:Boolean(body.proxied)});
    }
    const siteId = randomId();
    const now = new Date().toISOString();
    const meta = {stage:"provisioning",zoneName:zone.name,zoneId,ipv4:ip,upstream,email,proxied:Boolean(body.proxied),dnsCreated:existingRecords.length===0,createdDnsRecordId:existingRecords[0]?.id||null};
    await env.DOMAIN_DB.prepare("INSERT INTO managed_sites(id,hostname,zone_id,cloudflare_credential_id,panel_node_id,upstream_url,status,metadata_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)")
      .bind(siteId,hostname,zoneId,credentialId,nodeId,upstream,"provisioning",JSON.stringify(meta),now,now).run();
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
    if(site.status==="failed" && !meta.sslId) return json({ok:false,item:{id,hostname:site.hostname,status:site.status,error:site.last_error}});
    if(site.status==="failed" && meta.sslId) {
      meta.stage="certificate_pending";
      delete meta.error;
      await env.DOMAIN_DB.prepare("UPDATE managed_sites SET status='certificate_pending',last_error=NULL,metadata_json=?,updated_at=? WHERE id=?")
        .bind(JSON.stringify(meta),new Date().toISOString(),id).run();
    }
    const {node,apiKey}=await getPanelNode(env,site.panel_node_id);
    try {
      if(!meta.sslId) throw new Error("证书任务缺少 1Panel SSL ID");
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
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}button,input{font:inherit}button{cursor:pointer;border:1px solid var(--line);background:var(--panel2);color:var(--text);border-radius:9px;padding:9px 13px}button.primary{background:#2767c8;border-color:#3478dc}button.danger{color:#ff9999}input{width:100%;padding:11px 12px;background:#0c1424;border:1px solid var(--line);border-radius:9px;color:var(--text);outline:none}input:focus{border-color:var(--accent)}.wrap{max-width:1120px;margin:auto;padding:28px 22px}.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px}.brand{font-size:19px;font-weight:700}.muted{color:var(--muted)}.tabs{display:flex;gap:8px;margin-bottom:20px;flex-wrap:wrap}.tabs button.active{background:#1e3d68;border-color:#477fc8}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:15px}.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px}.card h3{margin:0 0 14px;font-size:16px}.field{margin:12px 0}.field label{display:block;margin-bottom:6px;color:var(--muted);font-size:12px}.actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.dns-toggle{width:42px;height:24px;padding:2px;border-radius:20px;background:#3b4659;border:1px solid #52617a;display:inline-flex;align-items:center;justify-content:flex-start;transition:background .15s,border-color .15s;vertical-align:middle}.dns-toggle span{width:18px;height:18px;background:#e9eef7;border-radius:50%;display:block;transition:transform .15s}.dns-toggle[aria-checked="true"]{background:#e78a20;border-color:#f5a33c}.dns-toggle[aria-checked="true"] span{transform:translateX(18px)}.dns-toggle:disabled{opacity:.5;cursor:not-allowed}.proxy-state{font-size:11px;color:var(--muted)}.proxy-state.on{color:#ffb34d}.item{padding:14px 0;border-top:1px solid var(--line)}.item:first-child{border-top:0}.row{display:flex;justify-content:space-between;gap:12px;align-items:center}.pill{font-size:11px;color:var(--green);background:#16382e;padding:3px 8px;border-radius:20px}.pill.bad{color:#ff9d9d;background:#3a2228}.zone{display:inline-block;border:1px solid var(--line);border-radius:20px;padding:3px 8px;margin:5px 4px 0 0;font-size:11px;color:var(--muted)}.hidden{display:none!important}.notice{padding:10px 12px;border-radius:9px;background:#1a2b43;color:#a9caff;margin:12px 0}.error{background:#3b2027;color:#ffaaaa}.login{max-width:390px;margin:12vh auto;padding:26px}.login h1{margin:0 0 5px}.empty{padding:22px;text-align:center;color:var(--muted)}small{color:var(--muted)}@media(max-width:600px){.wrap{padding:18px 13px}.top{align-items:flex-start}.row{align-items:flex-start}}
</style></head><body><div id="login" class="card login"><h1>Domain Access Manager</h1><p class="muted">Cloudflare DNS · 1Panel · Reverse Proxy</p><form id="loginForm"><div class="field"><label>管理员密码</label><input name="password" type="password" required autofocus autocomplete="current-password"></div><button class="primary" style="width:100%">登录</button></form><div id="loginMsg"></div></div>
<div id="app" class="wrap hidden"><header class="top"><div><div class="brand">Domain Access Manager</div><small>Cloudflare DNS & 1Panel 管理</small></div><button id="logout">退出登录</button></header>
<nav class="tabs"><button data-tab="overview" class="active">概览</button><button data-tab="cloudflare">Cloudflare</button><button data-tab="nodes">VPS / 1Panel</button><button data-tab="dns">DNS 记录</button><button data-tab="publish">域名接入</button><button data-tab="logs">操作记录</button></nav>
<section id="overview" class="tab grid"><div class="card"><h3>Cloudflare 凭据</h3><div id="countCf">-</div><small>多个 Token，自动发现 Zone</small></div><div class="card"><h3>1Panel 节点</h3><div id="countNodes">-</div><small>多个 VPS，独立 API 凭据</small></div><div class="card"><h3>下一步</h3><p class="muted">先添加 Cloudflare Token 和 1Panel 节点，随后即可建设 DNS → SSL → 反向代理的一键发布流程。</p></div></section>
<section id="cloudflare" class="tab hidden grid"><div class="card"><h3>添加 Cloudflare 凭据</h3><form id="cfForm"><div class="field"><label>配置名称</label><input name="name" placeholder="例如：个人域名" required></div><div class="field"><label>API Token</label><input name="token" type="password" autocomplete="off" required></div><button class="primary">验证 Token 并自动获取域名</button></form><div id="cfMsg"></div></div><div class="card"><h3>已保存的 Cloudflare 账号</h3><div id="cfList" class="muted">加载中...</div></div></section>
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
<div class="field"><label><input name="proxied" type="checkbox" checked style="width:auto"> 开启 Cloudflare 橙色云代理</label></div>
<button class="primary" id="publishButton">开始一键接入</button>
</form><div id="publishMsg"></div></div>
<div class="card"><h3>域名接入任务</h3><button id="refreshPublish">刷新任务</button><div id="publishList" style="margin-top:12px">加载中...</div></div></section><section id="logs" class="tab hidden"><div class="card"><h3>最近操作</h3><div id="logList">加载中...</div></div></section></div>
<script>
const $=s=>document.querySelector(s);const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
async function api(path,opts={}){const r=await fetch(path,{...opts,headers:{"content-type":"application/json",...(opts.headers||{})}});const d=await r.json().catch(()=>({error:"服务器响应无法解析"}));if(r.status===401){showLogin();throw new Error(d.error||"登录已过期")}if(!r.ok)throw new Error(d.error||"请求失败");return d}
function msg(el,text,bad=false){el.innerHTML='<div class="notice '+(bad?'error':'')+'">'+esc(text)+'</div>'}
function showLogin(){$("#login").classList.remove("hidden");$("#app").classList.add("hidden")}
function showApp(){$("#login").classList.add("hidden");$("#app").classList.remove("hidden");refresh()}
async function refresh(){await Promise.all([loadCf(),loadNodes(),loadLogs()]);try{await loadDnsCredentials();await loadPublishOptions();await loadPublishList()}catch(e){}}
document.querySelectorAll("[data-tab]").forEach(b=>b.onclick=()=>{document.querySelectorAll("[data-tab]").forEach(x=>x.classList.toggle("active",x===b));document.querySelectorAll(".tab").forEach(x=>x.classList.toggle("hidden",x.id!==b.dataset.tab))});
$("#loginForm").onsubmit=async e=>{e.preventDefault();const p=new FormData(e.target).get("password");try{await api("/api/login",{method:"POST",body:JSON.stringify({password:p})});e.target.reset();$("#loginMsg").innerHTML="";showApp()}catch(err){msg($("#loginMsg"),err.message,true)}};
$("#logout").onclick=async()=>{await api("/api/logout",{method:"POST",body:"{}"});showLogin()};
$("#cfForm").onsubmit=async e=>{e.preventDefault();const f=new FormData(e.target);const b=e.target.querySelector("button");b.disabled=true;b.textContent="验证中...";try{const d=await api("/api/cloudflare/verify",{method:"POST",body:JSON.stringify({name:f.get("name"),token:f.get("token")})});e.target.reset();msg($("#cfMsg"),"验证成功，发现 "+d.item.zoneCount+" 个域名");await loadCf();await loadPublishOptions()}catch(err){msg($("#cfMsg"),err.message,true)}finally{b.disabled=false;b.textContent="验证 Token 并自动获取域名"}};
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
async function loadCf(){try{const d=await api("/api/cloudflare");window.__cfItems=d.items;$("#countCf").textContent=d.items.length+" 个凭据";$("#cfList").innerHTML=d.items.length?d.items.map(x=>'<div class="item"><div class="row"><b>'+esc(x.name)+'</b><button class="danger" data-del-cf="'+esc(x.id)+'">删除</button></div><small>'+x.zone_count+' 个 Zone · Token '+esc(x.token_status)+'</small><div>'+x.zones.map(z=>'<span class="zone">'+esc(z.name)+'</span>').join("")+'</div></div>').join(""):'<div class="empty">尚未添加 Cloudflare 凭据</div>';document.querySelectorAll("[data-del-cf]").forEach(b=>b.onclick=async()=>{if(confirm("确定删除该凭据？")){try{await api("/api/cloudflare/"+b.dataset.delCf,{method:"DELETE"});loadCf()}catch(e){alert(e.message)}}})}catch(e){$("#cfList").textContent=e.message}}
async function loadNodes(){try{const d=await api("/api/nodes");$("#countNodes").textContent=d.items.length+" 台 VPS";$("#nodeList").innerHTML=d.items.length?d.items.map(x=>'<div class="item"><div class="row"><b>'+esc(x.name)+'</b><span class="pill">'+esc(x.connection_status)+'</span></div><small>'+esc(x.base_url)+(x.panel_version?' · '+esc(x.panel_version):'')+'</small><div class="actions" style="margin-top:8px"><button class="danger" data-del-node="'+esc(x.id)+'">删除</button></div></div>').join(""):'<div class="empty">尚未添加 1Panel 节点</div>';document.querySelectorAll("[data-del-node]").forEach(b=>b.onclick=async()=>{if(confirm("确定删除该节点？")){try{await api("/api/nodes/"+b.dataset.delNode,{method:"DELETE"});loadNodes()}catch(e){alert(e.message)}}})}catch(e){$("#nodeList").textContent=e.message}}
async function loadDnsCredentials(){const d=await api("/api/cloudflare");window.__cfItems=d.items;const sel=$("#dnsCredential");sel.innerHTML=d.items.map(x=>'<option value="'+esc(x.id)+'">'+esc(x.name)+'</option>').join("");updateDnsZones();sel.onchange=updateDnsZones}
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
 window.__publishCf=cf.items;window.__publishNodes=nodes.items;
 $("#publishCredential").innerHTML=cf.items.map(x=>'<option value="'+esc(x.id)+'">'+esc(x.name)+'</option>').join("");
 updatePublishZones();
 $("#publishCredential").onchange=updatePublishZones;
 $("#publishNode").innerHTML=nodes.items.map(x=>'<option value="'+esc(x.id)+'">'+esc(x.name)+' · '+esc(x.connection_status)+'</option>').join("");
}
function updatePublishZones(){
 const cred=$("#publishCredential").value;
 const item=(window.__publishCf||[]).find(x=>x.id===cred);
 $("#publishZone").innerHTML=(item?.zones||[]).map(z=>'<option value="'+esc(z.id)+'">'+esc(z.name)+'</option>').join("");
}
async function loadPublishList(){
 try{const d=await api("/api/publish");$("#publishList").innerHTML=d.items.length?d.items.map(x=>'<div class="item"><div class="row"><b>'+esc(x.hostname)+'</b><span class="pill '+(x.status==="ready"?"":x.status==="failed"?"bad":"")+'">'+esc(x.status)+'</span></div><small>'+esc(x.lastError||x.metadata?.stage||"")+' · '+esc(x.updatedAt)+'</small><div class="actions" style="margin-top:8px">'+(x.status==="certificate_pending"||x.status==="provisioning"?'<button data-progress="'+esc(x.id)+'">检查进度</button>':x.status==="failed"&&x.metadata?.sslId?'<button data-progress="'+esc(x.id)+'">重试后续步骤</button>':'')+'</div></div>').join(""):'<div class="empty">尚未接入域名</div>';document.querySelectorAll("[data-progress]").forEach(b=>b.onclick=()=>checkPublishProgress(b.dataset.progress,true))}catch(e){$("#publishList").textContent=e.message}
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
