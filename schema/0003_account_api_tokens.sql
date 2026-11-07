ALTER TABLE cloudflare_credentials ADD COLUMN account_id TEXT;

CREATE INDEX IF NOT EXISTS idx_cloudflare_credentials_account
  ON cloudflare_credentials(account_id);
