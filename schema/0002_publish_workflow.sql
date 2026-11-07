ALTER TABLE managed_sites ADD COLUMN metadata_json TEXT NOT NULL DEFAULT '{}';
ALTER TABLE managed_sites ADD COLUMN last_error TEXT;

CREATE TABLE IF NOT EXISTS panel_cloudflare_dns_accounts (
  id TEXT PRIMARY KEY,
  panel_node_id TEXT NOT NULL,
  cloudflare_credential_id TEXT NOT NULL,
  dns_account_id INTEGER NOT NULL,
  acme_account_id INTEGER,
  acme_email TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(panel_node_id, cloudflare_credential_id),
  FOREIGN KEY (panel_node_id) REFERENCES panel_nodes(id) ON DELETE RESTRICT,
  FOREIGN KEY (cloudflare_credential_id) REFERENCES cloudflare_credentials(id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_managed_sites_status ON managed_sites(status);
CREATE INDEX IF NOT EXISTS idx_panel_cf_dns_accounts_node ON panel_cloudflare_dns_accounts(panel_node_id);
