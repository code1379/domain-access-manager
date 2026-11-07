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

Implemented in the current branch:
- Cloudflare DNS record listing, creation and deletion, with zone authorization checks.

Not implemented yet:
- DNS record editing/update.
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
2. Open the D1 console and execute `schema/0001_init.sql`, `schema/0002_publish_workflow.sql`, then `schema/0003_account_api_tokens.sql` in order.
3. Create a Worker named `domain-access-manager`.
4. Paste the complete contents of `_worker.js` into the Worker's editor.
5. Under **Settings → Bindings**, add the D1 database binding named `DOMAIN_DB`.
6. Under **Settings → Variables and Secrets**, add the three secrets `PASSWORD`, `SESSION_SECRET` and `ENCRYPTION_KEY`.
7. Deploy and open the Worker URL.

## 1Panel connectivity and API authentication

The Worker calls each 1Panel API endpoint from Cloudflare's network. Both HTTP and HTTPS endpoint URLs are supported so a panel can be onboarded before HTTPS is configured. Prefer HTTPS whenever available. HTTP provides no transport encryption or server authentication: API signatures do not protect request confidentiality or prevent response tampering, and Cloudflare DNS credentials passed to 1Panel may be exposed on the network. Use HTTP only on a trusted network or temporarily while enabling HTTPS; do not expose an unrestricted panel API to the public Internet.

The current node test uses the current 1Panel v2 HMAC-SHA256 format:

`hex(HMAC-SHA256(API_KEY, "1panel:" + UnixTimestamp))`

Headers:
- `1Panel-Token`: calculated signature (never the raw API key).
- `1Panel-Timestamp`: Unix timestamp in seconds.
- `1Panel-Signature-Version: hmac-sha256`.

1Panel's API IP allowlist, if enabled, must also permit the request source. Cloudflare Workers do not provide a fixed egress IP by default; this needs a deliberate network-access design before production deployment (for example, an authenticated access gateway or a supported static-egress arrangement).

## Cloudflare Token permissions

Create an **Account API Token** under Manage Account → API Tokens. The application stores the Account ID (32 hexadecimal characters) with the token and verifies it through `GET /accounts/{account_id}/tokens/verify`. User API Tokens are not supported.

The application needs:
- Account → Cloudflare Tunnel → Read and Edit, to list, create, update, inspect and delete tunnels.
- Zone → Read, to discover zones and verify their owning Account ID.
- Zone → DNS → Read and Edit, to list, create, update and remove DNS records.

The application verifies the token against the supplied Account ID, then lists only zones belonging to that account. Existing legacy credential rows remain in D1 but have no Account ID; edit/update them with an Account API Token before using them. Updating a credential preserves managed-site references and the existing 1Panel DNS/ACME mapping rows.

## One-click publishing workflow

The publish form asks for the Cloudflare credential, Zone, hostname, 1Panel node, upstream URL, and Let's Encrypt contact email. The server IPv4 is taken from the node's 1Panel dashboard metadata when available; otherwise it must be entered manually.

The workflow deliberately refuses to overwrite an existing A record with a different IP and refuses to take over an existing 1Panel website. The DNS-01 certificate request is asynchronous; the UI polls the saved task and creates the website only after the certificate status is `ready`. A failed or interrupted job may need manual inspection in 1Panel before retry support is used.

1Panel DNS credential mapping is stored by (node, Cloudflare credential). The 1Panel DNS provider uses the Cloudflare Token as its `authorization.apiKey` under provider type `CloudFlare`; the provider implementation accepts API Token authentication without a legacy Global API Key.

## Security notes

- Prefer HTTPS for every 1Panel endpoint. HTTP is supported for bootstrap/temporary use, but must be restricted to a trusted network because API keys, Cloudflare DNS credentials and responses are not transport-encrypted.
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


## Upgrade existing D1 database for Account API Tokens

After deploying the Account API Token version, run this migration exactly once:

```bash
npm run db:account-token-migration
```

Or execute `schema/0003_account_api_tokens.sql` in the D1 console. Do not rerun it after the `account_id` column has been added. Then open Cloudflare credentials, choose **Update** on each legacy credential, enter the 32-character Account ID and the new Account API Token, and verify/save. This updates the existing credential row so managed domains and 1Panel mappings keep their references.
