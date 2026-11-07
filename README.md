# Domain Access Manager

Cloudflare Worker-based control panel for managing Cloudflare DNS credentials and 1Panel VPS nodes, with a one-click reverse-proxy publishing workflow planned.

## Product scope

- Single administrator login (password configured as a Worker Secret).
- Multiple named Cloudflare API tokens. The Worker verifies each token and discovers accessible zones automatically.
- Multiple named 1Panel v2 nodes. The Worker verifies each node using 1Panel's signed API-key authentication.
- Cloudflare credentials and 1Panel API keys are encrypted before they are stored in D1.
- No token or API key is returned to the browser after saving.
- Designed for deployment as a Cloudflare Worker with a D1 binding; no VPS-side agent is required.

## Current implementation status

**Milestone 0.1 is a working foundation, not yet the complete domain-publishing product.**

Implemented:
- Password-only administrator login, signed HttpOnly/Secure/SameSite session cookie, seven-day expiry and D1-backed login throttling.
- Same-origin checks for state-changing API requests.
- D1 schema for credentials, nodes, managed sites, operation logs and login attempts.
- AES-256-GCM encryption for stored Cloudflare tokens and 1Panel API keys.
- Cloudflare token verification and automatic Zone discovery.
- 1Panel v2 node connection test using HMAC-SHA256 API-key signing.
- Basic responsive UI for credentials, nodes and operation logs.

Not implemented yet:
- DNS record creation/update/deletion.
- ACME/Cloudflare DNS-01 certificate issuance through 1Panel.
- 1Panel reverse-proxy website creation and HTTPS binding.
- End-to-end publishing workflow, idempotency/retry and rollback.

## Deploy with Wrangler

Requirements: Node.js 22+ and a Cloudflare account with Workers and D1 enabled.

```bash
npm install
npx wrangler d1 create domain-access-manager
```

Copy the returned database ID into `wrangler.toml`, then initialize the remote database:

```bash
npm run db:remote
```

Configure the three required secrets (never put real values in source control):

```bash
npx wrangler secret put PASSWORD
npx wrangler secret put SESSION_SECRET
npx wrangler secret put ENCRYPTION_KEY
```

- `PASSWORD`: administrator login password (use at least 12 characters).
- `SESSION_SECRET`: random signing secret (32+ random bytes recommended).
- `ENCRYPTION_KEY`: exactly 32 random bytes encoded as 64 hexadecimal characters.

Deploy:

```bash
npm run deploy
```

Open the Worker URL and sign in with the `PASSWORD` secret.

## Deploy from Cloudflare Dashboard

1. Create a D1 database named `domain-access-manager`.
2. Open the D1 console and execute [schema/0001_init.sql](schema/0001_init.sql).
3. Create a Worker named `domain-access-manager`.
4. Paste the complete contents of `_worker.js` into the Worker's editor.
5. Under **Settings → Bindings**, add the D1 database binding named `DOMAIN_DB`.
6. Under **Settings → Variables and Secrets**, add the three secrets `PASSWORD`, `SESSION_SECRET` and `ENCRYPTION_KEY`.
7. Deploy and open the Worker URL.

## 1Panel connectivity and API authentication

The Worker calls each 1Panel HTTPS API endpoint from Cloudflare's network. Each node must expose a reachable HTTPS API endpoint. Do not expose an unrestricted panel API to the public Internet.

The current node test uses the current 1Panel v2 HMAC-SHA256 format:

`hex(HMAC-SHA256(API_KEY, "1panel:" + UnixTimestamp))`

Headers:
- `1Panel-Token`: calculated signature (never the raw API key).
- `1Panel-Timestamp`: Unix timestamp in seconds.
- `1Panel-Signature-Version: hmac-sha256`.

1Panel's API IP allowlist, if enabled, must also permit the request source. Cloudflare Workers do not provide a fixed egress IP by default; this needs a deliberate network-access design before production deployment (for example, an authenticated access gateway or a supported static-egress arrangement).

## Cloudflare Token permissions

Create narrowly scoped API tokens. The initial discovery flow needs:
- Zone → Read, to list accessible zones.
- DNS → Read and DNS → Edit, for the planned DNS management milestone.

The application verifies the token and displays the zones it can access. It does not ask users to type Zone names or IDs manually.

## Security notes

- Use HTTPS for every 1Panel endpoint.
- D1 stores encrypted credentials; the encryption key stays in Worker Secrets.
- Tokens and API keys are never returned in list responses and must never be written to logs.
- Keep `PASSWORD`, `SESSION_SECRET`, and `ENCRYPTION_KEY` out of source control.
- Back up D1 before production use.
- Restrict access to the Worker URL; consider Cloudflare Access as an additional access layer.

## Development

```bash
npm run dev
npm run check
```

`npm run check` validates JavaScript syntax and Wrangler's dry-run deployment.

## License

MIT
