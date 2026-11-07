# Domain Access Manager

Cloudflare Worker-based control panel for managing Cloudflare DNS credentials and 1Panel VPS nodes, with a one-click reverse-proxy publishing workflow planned.

## Product scope

- Single administrator login (password configured as a Worker secret).
- Multiple named Cloudflare API tokens. The Worker verifies each token and discovers accessible zones automatically.
- Multiple named 1Panel v2 nodes. The Worker verifies each node using 1Panel's signed API-key authentication.
- Cloudflare credentials and 1Panel API keys are encrypted before they are stored in D1.
- No token or API key is returned to the browser after saving.
- Designed for deployment as a Cloudflare Worker with a D1 binding; no VPS-side agent is required.

## Current implementation status

The first milestone focuses on secure login, D1 persistence, Cloudflare credential discovery, and 1Panel node connection checks. DNS record mutation, certificate issuance, website creation, and the end-to-end publishing workflow are subsequent milestones.

## Deploy

1. Create a D1 database in Cloudflare.
2. Execute [schema/0001_init.sql](schema/0001_init.sql) against that database.
3. Create a Worker and bind the D1 database using the binding name `DOMAIN_DB`.
4. Configure these Worker secrets:
   - `PASSWORD`: administrator login password (at least 12 characters recommended).
   - `SESSION_SECRET`: random secret used to sign login sessions.
   - `ENCRYPTION_KEY`: random 32-byte key encoded as 64 hexadecimal characters.
5. Deploy the contents of `_worker.js` as the Worker entry point.
6. Open the Worker URL and sign in with `PASSWORD`.

For Wrangler deployments, see [wrangler.toml](wrangler.toml). Do not commit real secrets or API credentials.

## 1Panel connectivity

The Worker calls the 1Panel HTTPS API from Cloudflare's network. Each node must expose a reachable HTTPS API endpoint. Use a restricted access path (for example, Cloudflare Access Service Auth or an IP allowlist where practical); do not expose an unrestricted panel API to the public Internet.

The node connection test uses the signed API-key format documented by 1Panel:
`md5("1panel" + API_KEY + UnixTimestamp)`, sent in `1Panel-Token` with `1Panel-Timestamp`.

## Security notes

- Use HTTPS for every 1Panel endpoint.
- Use narrowly scoped Cloudflare API tokens with Zone Read and DNS Edit permissions only for the zones you intend to manage.
- D1 stores encrypted credentials; the encryption key stays in Worker Secrets.
- Keep `PASSWORD`, `SESSION_SECRET`, and `ENCRYPTION_KEY` out of source control.
- Back up D1 before production use.

## License

MIT
