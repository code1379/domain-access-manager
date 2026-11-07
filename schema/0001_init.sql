PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS cloudflare_credentials (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  token_ciphertext TEXT NOT NULL,
  zones_json TEXT NOT NULL DEFAULT '[]',
  zone_count INTEGER NOT NULL DEFAULT 0,
  token_status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  last_verified_at TEXT
);

CREATE TABLE IF NOT EXISTS panel_nodes (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  base_url TEXT NOT NULL,
  api_key_ciphertext TEXT NOT NULL,
  panel_version TEXT,
  server_info_json TEXT NOT NULL DEFAULT '{}',
  connection_status TEXT NOT NULL DEFAULT 'unknown',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  last_checked_at TEXT
);

CREATE TABLE IF NOT EXISTS managed_sites (
  id TEXT PRIMARY KEY,
  hostname TEXT NOT NULL UNIQUE,
  zone_id TEXT NOT NULL,
  cloudflare_credential_id TEXT NOT NULL,
  panel_node_id TEXT NOT NULL,
  upstream_url TEXT NOT NULL,
  dns_record_id TEXT,
  panel_website_id TEXT,
  ssl_id TEXT,
  status TEXT NOT NULL DEFAULT 'draft',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (cloudflare_credential_id) REFERENCES cloudflare_credentials(id) ON DELETE RESTRICT,
  FOREIGN KEY (panel_node_id) REFERENCES panel_nodes(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS operation_logs (
  id TEXT PRIMARY KEY,
  operation TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id TEXT,
  status TEXT NOT NULL,
  message TEXT NOT NULL,
  details_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_operation_logs_created_at ON operation_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_managed_sites_node ON managed_sites(panel_node_id);
CREATE INDEX IF NOT EXISTS idx_managed_sites_cf ON managed_sites(cloudflare_credential_id);
