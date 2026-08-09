-- 134: ASKWay entitlement-scoped inference credentials and observations.
-- Secrets are never stored in these tables. The legacy api_keys.key column is
-- populated with a unique, non-secret sentinel while key_hash authenticates.

CREATE TABLE askway_entitlement_keys (
  id TEXT PRIMARY KEY,
  external_entitlement_id TEXT NOT NULL UNIQUE,
  api_key_id TEXT NOT NULL UNIQUE REFERENCES api_keys(id),
  display_name TEXT NOT NULL,
  policy_json TEXT NOT NULL,
  policy_version INTEGER NOT NULL DEFAULT 1,
  lifetime_token_limit INTEGER NOT NULL,
  observed_tokens INTEGER NOT NULL DEFAULT 0,
  key_version INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  revoked_at TEXT
);

CREATE INDEX idx_askway_entitlement_keys_status
  ON askway_entitlement_keys(status);

CREATE TABLE askway_entitlement_commands (
  idempotency_key TEXT PRIMARY KEY,
  command_type TEXT NOT NULL CHECK (command_type IN ('provision', 'rotate', 'revoke')),
  entitlement_key_id TEXT NOT NULL REFERENCES askway_entitlement_keys(id),
  completed_at TEXT NOT NULL
);

CREATE TABLE askway_request_usage (
  request_id TEXT PRIMARY KEY,
  entitlement_key_id TEXT NOT NULL REFERENCES askway_entitlement_keys(id),
  api_key_id TEXT NOT NULL REFERENCES api_keys(id),
  input_tokens INTEGER NOT NULL DEFAULT 0,
  output_tokens INTEGER NOT NULL DEFAULT 0,
  cached_tokens INTEGER NOT NULL DEFAULT 0,
  reasoning_tokens INTEGER NOT NULL DEFAULT 0,
  delivered_output_tokens INTEGER,
  usage_quality TEXT NOT NULL,
  usage_disposition TEXT NOT NULL,
  provider TEXT,
  model TEXT,
  latency_ms INTEGER,
  fallback_count INTEGER NOT NULL DEFAULT 0,
  route_trace_reference TEXT,
  cost_microunits TEXT,
  cost_currency TEXT,
  cost_quality TEXT,
  pricing_version TEXT,
  observed_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX idx_askway_request_usage_entitlement
  ON askway_request_usage(entitlement_key_id, observed_at);

CREATE TABLE askway_route_traces (
  reference TEXT PRIMARY KEY,
  request_id TEXT NOT NULL,
  attempts_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX idx_askway_route_traces_request
  ON askway_route_traces(request_id);
