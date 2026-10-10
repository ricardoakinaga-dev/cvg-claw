-- Deployment-owned pre-authentication metadata, without bodies or raw IPs.
-- Runtime needs SELECT/INSERT/UPDATE/DELETE; migration authority owns the DDL.
CREATE TABLE IF NOT EXISTS api_rate_limit_buckets (
  namespace text NOT NULL CHECK (namespace ~ '^[a-zA-Z0-9_.:-]{1,64}$'),
  bucket_key text NOT NULL CHECK (bucket_key ~ '^[0-9a-f]{64}$'),
  request_count integer NOT NULL CHECK (request_count BETWEEN 1 AND 1000001),
  reset_at timestamptz NOT NULL,
  PRIMARY KEY (namespace, bucket_key)
);

CREATE INDEX IF NOT EXISTS api_rate_limit_buckets_expiry
  ON api_rate_limit_buckets (namespace, reset_at);
